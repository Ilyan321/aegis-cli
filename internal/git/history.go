package git

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ilyan321/aegis-cli/internal/analyzer"
	"github.com/Ilyan321/aegis-cli/internal/config"
	"github.com/Ilyan321/aegis-cli/pkg/models"
)

// GitObject maps an object SHA to its relative repository path.
type GitObject struct {
	SHA  string
	Path string
}

var (
	commitCache   = make(map[string]*models.CommitInfo)
	commitCacheMu sync.RWMutex
)

// ListAllReachableObjects returns all objects reachable from all git refs.
func ListAllReachableObjects() ([]GitObject, error) {
	cmd := exec.Command("git", "rev-list", "--all", "--objects")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git rev-list failed: %w", err)
	}

	var objects []GitObject
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 {
			path := strings.TrimSpace(parts[1])
			if path != "" {
				objects = append(objects, GitObject{
					SHA:  parts[0],
					Path: path,
				})
			}
		}
	}

	return objects, scanner.Err()
}

// GetCommitInfoForObject retrieves the commit metadata that introduced or modified the given object.
func GetCommitInfoForObject(objectSHA, filePath string) *models.CommitInfo {
	cacheKey := objectSHA + ":" + filePath
	commitCacheMu.RLock()
	if cached, ok := commitCache[cacheKey]; ok {
		commitCacheMu.RUnlock()
		return cached
	}
	commitCacheMu.RUnlock()

	cmd := exec.Command("git", "log", "-n", "1", fmt.Sprintf("--find-object=%s", objectSHA), "--format=%H\x1f%an\x1f%aI\x1f%s")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		// Fallback: query by file path if object-finder yields nothing
		cmd = exec.Command("git", "log", "-n", "1", "--format=%H\x1f%an\x1f%aI\x1f%s", "--", filePath)
		out, err = cmd.Output()
		if err != nil || len(out) == 0 {
			return nil
		}
	}

	parts := strings.Split(strings.TrimSpace(string(out)), "\x1f")
	if len(parts) < 4 {
		return nil
	}

	parsedDate, _ := time.Parse(time.RFC3339, parts[2])

	info := &models.CommitInfo{
		Hash:    parts[0],
		Author:  parts[1],
		Date:    parsedDate,
		Message: parts[3],
	}

	commitCacheMu.Lock()
	commitCache[cacheKey] = info
	commitCacheMu.Unlock()

	return info
}

// ScanHistory traverses the entire Git DAG using native git cat-file streaming.
func ScanHistory(engine *analyzer.Engine) ([]models.Finding, error) {
	findings, _, _, err := ScanHistoryWithStats(engine)
	return findings, err
}

// ScanHistoryWithStats traverses Git DAG, returning findings, total blobs scanned, and lines scanned.
func ScanHistoryWithStats(engine *analyzer.Engine) ([]models.Finding, int, int, error) {
	objects, err := ListAllReachableObjects()
	if err != nil {
		return nil, 0, 0, err
	}

	if len(objects) == 0 {
		return nil, 0, 0, nil
	}

	matcher := config.LoadIgnoreMatcher(".")

	// Map SHA to path synchronously before launching background worker to prevent data race
	shaToPath := make(map[string]string, len(objects))
	for _, obj := range objects {
		shaToPath[obj.SHA] = obj.Path
	}

	cmd := exec.Command("git", "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to open cat-file stdin: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("failed to open cat-file stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, 0, 0, fmt.Errorf("failed to start git cat-file: %w", err)
	}

	go func() {
		defer stdin.Close()
		for _, obj := range objects {
			_, _ = io.WriteString(stdin, obj.SHA+"\n")
		}
	}()

	var allFindings []models.Finding
	seenFindingIDs := make(map[string]struct{})
	reader := bufio.NewReader(stdout)

	blobsScanned := 0
	linesScanned := 0

	for {
		headerLine, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return allFindings, blobsScanned, linesScanned, fmt.Errorf("cat-file read error: %w", err)
		}

		headerLine = strings.TrimSpace(headerLine)
		if strings.HasSuffix(headerLine, "missing") {
			continue
		}

		parts := strings.Split(headerLine, " ")
		if len(parts) < 3 {
			continue
		}

		sha := parts[0]
		objType := parts[1]
		size, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			continue
		}

		// Read exactly size bytes plus the trailing newline
		limitedReader := io.LimitReader(reader, size)
		buf := make([]byte, size)
		_, err = io.ReadFull(limitedReader, buf)
		if err != nil {
			return allFindings, blobsScanned, linesScanned, fmt.Errorf("error reading object %s content: %w", sha, err)
		}
		// Consume trailing newline after object payload in cat-file --batch
		_, _ = reader.ReadByte()

		// Only inspect blob objects
		if objType != "blob" {
			continue
		}

		filePath := shaToPath[sha]
		if filePath == "" {
			filePath = fmt.Sprintf("blob/%s", sha[:8])
		}

		// Check .aegisignore
		if matcher != nil && matcher.ShouldIgnore(filePath) {
			continue
		}

		// Skip oversized blobs > 25MB
		if size > analyzer.MaxFileSize {
			continue
		}

		// Skip binary blobs
		inspectLen := len(buf)
		if inspectLen > analyzer.BinaryInspectBytes {
			inspectLen = analyzer.BinaryInspectBytes
		}
		if analyzer.IsBinary(buf[:inspectLen]) {
			continue
		}

		blobsScanned++

		// Scan blob lines
		scanner := bufio.NewScanner(bytes.NewReader(buf))
		lineNum := 0
		var blobFindings []models.Finding
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			linesScanned++
			findings := engine.ScanLine(filePath, lineNum, line)
			if len(findings) > 0 {
				blobFindings = append(blobFindings, findings...)
			}
		}

		if len(blobFindings) > 0 {
			commitInfo := GetCommitInfoForObject(sha, filePath)
			for _, f := range blobFindings {
				f.Commit = commitInfo
				if _, seen := seenFindingIDs[f.ID]; !seen {
					seenFindingIDs[f.ID] = struct{}{}
					allFindings = append(allFindings, f)
				}
			}
		}
	}

	_ = cmd.Wait()
	return allFindings, blobsScanned, linesScanned, nil
}
