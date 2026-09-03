package git

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"aegis-cli/internal/analyzer"
	"aegis-cli/pkg/models"
)

// HunkHeaderRegex matches unified diff hunk headers: @@ -start,len +start,len @@
var HunkHeaderRegex = regexp.MustCompile(`^@@\s+-(?:[0-9]+)(?:,[0-9]+)?\s+\+([0-9]+)(?:,([0-9]+))?\s+@@`)

// StagedLine represents an added or modified line in git staging buffer.
type StagedLine struct {
	FilePath   string
	LineNumber int
	Content    string
}

// ParseUnifiedDiff parses unified diff stream (e.g. from git diff -U0) and extracts newly added lines.
func ParseUnifiedDiff(r io.Reader) ([]StagedLine, error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 2*1024*1024)

	var lines []StagedLine
	var currentFile string
	currentLineNum := 0

	for scanner.Scan() {
		text := scanner.Text()

		// File header in unified diff
		if strings.HasPrefix(text, "+++ ") {
			target := strings.TrimPrefix(text, "+++ ")
			target = strings.TrimSpace(target)
			if target == "/dev/null" {
				currentFile = "" // Deleted file
			} else {
				// Strip leading "b/" or "a/" prefix standard in git diff
				currentFile = strings.TrimPrefix(target, "b/")
				currentFile = strings.TrimPrefix(currentFile, "a/")
			}
			continue
		}

		if strings.HasPrefix(text, "--- ") {
			// Preceding old file header, ignore
			continue
		}

		// Check for hunk header: @@ -oldStart,oldLen +newStart,newLen @@
		if strings.HasPrefix(text, "@@") {
			matches := HunkHeaderRegex.FindStringSubmatch(text)
			if len(matches) >= 2 {
				startLine, err := strconv.Atoi(matches[1])
				if err == nil {
					currentLineNum = startLine
				}
			}
			continue
		}

		// New line added
		if strings.HasPrefix(text, "+") {
			if currentFile != "" {
				addedContent := strings.TrimPrefix(text, "+")
				lines = append(lines, StagedLine{
					FilePath:   currentFile,
					LineNumber: currentLineNum,
					Content:    addedContent,
				})
			}
			currentLineNum++
			continue
		}

		// Context line (if any)
		if strings.HasPrefix(text, " ") {
			currentLineNum++
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("diff parse error: %w", err)
	}

	return lines, nil
}

// GetStagedDiffOutput runs git diff --cached --no-color -U0.
func GetStagedDiffOutput() (io.Reader, error) {
	cmd := exec.Command("git", "diff", "--cached", "--no-color", "-U0")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff --cached failed: %v: %s", err, stderr.String())
	}

	return &stdout, nil
}

// GetRangeDiffOutput runs git diff <base>...<head> --no-color -U0 for CI/CD merge-base scans.
func GetRangeDiffOutput(baseRef, headRef string) (io.Reader, error) {
	diffTarget := fmt.Sprintf("%s...%s", baseRef, headRef)
	cmd := exec.Command("git", "diff", diffTarget, "--no-color", "-U0")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff %s failed: %v: %s", diffTarget, err, stderr.String())
	}

	return &stdout, nil
}

// ScanStaged parses staged changes and scans each line through the Aegis analyzer engine.
func ScanStaged(engine *analyzer.Engine) ([]models.Finding, error) {
	diffReader, err := GetStagedDiffOutput()
	if err != nil {
		return nil, err
	}

	stagedLines, err := ParseUnifiedDiff(diffReader)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding
	for _, sl := range stagedLines {
		lineFindings := engine.ScanLine(sl.FilePath, sl.LineNumber, sl.Content)
		if len(lineFindings) > 0 {
			findings = append(findings, lineFindings...)
		}
	}

	return findings, nil
}

// ScanRange parses merge-base PR diffs and scans each line through the Aegis analyzer engine.
func ScanRange(engine *analyzer.Engine, baseRef, headRef string) ([]models.Finding, error) {
	diffReader, err := GetRangeDiffOutput(baseRef, headRef)
	if err != nil {
		return nil, err
	}

	stagedLines, err := ParseUnifiedDiff(diffReader)
	if err != nil {
		return nil, err
	}

	var findings []models.Finding
	for _, sl := range stagedLines {
		lineFindings := engine.ScanLine(sl.FilePath, sl.LineNumber, sl.Content)
		if len(lineFindings) > 0 {
			findings = append(findings, lineFindings...)
		}
	}

	return findings, nil
}
