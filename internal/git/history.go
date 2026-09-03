package git

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"aegis-cli/internal/analyzer"
	"aegis-cli/pkg/models"
)

// GitObject maps an object SHA to its relative repository path.
type GitObject struct {
	SHA  string
	Path string
}

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
	cmd := exec.Command("git", "log", "-n", "1", fmt.Sprintf("--find-object=%s", objectSHA), "--format=%H\x1f%an\x1f%ad\x1f%s")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		// Fallback: query by file path if object-finder yields nothing
		cmd = exec.Command("git", "log", "-n", "1", "--format=%H\x1f%an\x1f%ad\x1f%s", "--", filePath)
		out, err = cmd.Output()
		if err != nil || len(out) == 0 {
			return nil
		}
	}

	parts := strings.Split(strings.TrimSpace(string(out)), "\x1f")
	if len(parts) < 4 {
		return nil
	}

	parsedDate, _ := time.Parse("Mon Jan 2 15:04:05 2006 -0700", parts[2])

	return &models.CommitInfo{
		Hash:    parts[0],
		Author:  parts[1],
		Date:    parsedDate,
		Message: parts[3],
	}
}

// ScanHistory traverses the entire Git DAG using native git cat-file streaming.
func ScanHistory(engine *analyzer.Engine) ([]models.Finding, error) {
	objects, err := ListAllReachableObjects()
	if err != nil {
		return nil, err
	}

	if len(objects) == 0 {
		return nil, nil
	}

	cmd := exec.Command("git", "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open cat-file stdin: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open cat-file stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start git cat-file: %w", err)
	}

	// Map SHA to path
	shaToPath := make(map[string]string, len(objects))
	go func() {
		defer stdin.Close()
		for _, obj := range objects {
			shaToPath[obj.SHA] = obj.Path
			_, _ = io.WriteString(stdin, obj.SHA+"\n")
		}
	}()

	var allFindings []models.Finding
	seenFindingIDs := make(map[string]struct{})
	reader := bufio.NewReader(stdout)

	for {
		headerLine, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return allFindings, fmt.Errorf("cat-file read error: %w", err)
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
			return allFindings, fmt.Errorf("error reading object %s content: %w", sha, err)
		}
		// Consume trailing newline after object payload in cat-file --batch
		_, _ = reader.ReadByte()

		// Only inspect blob objects
		if objType != "blob" {
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

		filePath := shaToPath[sha]
		if filePath == "" {
			filePath = fmt.Sprintf("blob/%s", sha[:8])
		}

		// Scan blob lines
		scanner := bufio.NewScanner(bytes.NewReader(buf))
		lineNum := 0
		var blobFindings []models.Finding
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
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
	return allFindings, nil
}
