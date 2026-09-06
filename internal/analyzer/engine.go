package analyzer

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

const (
	MaxFileSize         = 25 * 1024 * 1024 // 25 MB max file size threshold (PRD Section 6)
	BinaryInspectBytes  = 1024
	LineLengthThreshold = 1200
)

// Engine is the central secret detection engine.
type Engine struct {
	rules []Rule
}

// NewEngine initializes an engine configured with default rules.
func NewEngine() *Engine {
	return &Engine{
		rules: DefaultRules,
	}
}

// IsBinary determines if a byte buffer contains binary data rather than text.
// Mitigates UTF-16 false negatives by detecting BOMs.
func IsBinary(header []byte) bool {
	if len(header) == 0 {
		return false
	}

	// Check UTF-16 BOMs (Little Endian: FF FE, Big Endian: FE FF)
	if len(header) >= 2 {
		if (header[0] == 0xFF && header[1] == 0xFE) || (header[0] == 0xFE && header[1] == 0xFF) {
			return false // UTF-16 text
		}
	}
	// Check UTF-8 BOM (EF BB BF)
	if len(header) >= 3 && header[0] == 0xEF && header[1] == 0xBB && header[2] == 0xBF {
		return false
	}

	nullCount := 0
	nonPrintableCount := 0
	for _, b := range header {
		if b == 0x00 {
			nullCount++
		} else if b < 0x09 || (b > 0x0D && b < 0x20) || b == 0x7F {
			nonPrintableCount++
		}
	}

	// Any null byte in non-BOM file or > 25% non-printable ASCII means binary
	if nullCount > 0 {
		return true
	}
	if float64(nonPrintableCount)/float64(len(header)) > 0.25 {
		return true
	}

	return false
}

// ScanFile scans an individual file path from disk.
func (e *Engine) ScanFile(filePath string) ([]models.Finding, error) {
	findings, _, err := e.ScanFileWithStats(filePath)
	return findings, err
}

// ScanFileWithStats scans an individual file path from disk and returns findings and total lines scanned.
func (e *Engine) ScanFileWithStats(filePath string) ([]models.Finding, int, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, 0, err
	}

	// Skip files exceeding max size limit (PRD Section 6)
	if fileInfo.Size() > MaxFileSize {
		return nil, 0, nil
	}

	// Skip directories and symlinks to directories
	if fileInfo.IsDir() {
		return nil, 0, nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	return e.ScanReaderWithStats(filePath, f)
}

// ScanReader streams content through Tier 1 rejection and Tier 2 DFA/entropy analysis.
func (e *Engine) ScanReader(filePath string, r io.Reader) ([]models.Finding, error) {
	findings, _, err := e.ScanReaderWithStats(filePath, r)
	return findings, err
}

// ScanReaderWithStats streams content through Tier 1 rejection and Tier 2 DFA/entropy analysis, returning findings and lines count.
func (e *Engine) ScanReaderWithStats(filePath string, r io.Reader) ([]models.Finding, int, error) {
	bufReader := bufio.NewReader(r)

	// Tier 1 Gatekeeper: Binary inspection
	header, err := bufReader.Peek(BinaryInspectBytes)
	if err != nil && err != io.EOF && len(header) == 0 {
		return nil, 0, err
	}
	if IsBinary(header) {
		return nil, 0, nil // Silently skip binary files
	}

	var findings []models.Finding
	lineNum := 0
	for {
		line, readErr := bufReader.ReadString('\n')
		if len(line) > 0 {
			lineNum++
			line = strings.TrimRight(line, "\r\n")
			lineFindings := e.ScanLine(filePath, lineNum, line)
			if len(lineFindings) > 0 {
				findings = append(findings, lineFindings...)
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return findings, lineNum, fmt.Errorf("error reading %s: %w", filePath, readErr)
		}
	}

	return findings, lineNum, nil
}

// ScanLine evaluates an individual line of text against all configured rules and heuristics.
func (e *Engine) ScanLine(filePath string, lineNum int, line string) []models.Finding {
	// Fast-Rejection: Skip empty lines
	if len(strings.TrimSpace(line)) == 0 {
		return nil
	}

	// Fast-Rejection: Check inline ignore directive
	if HasIgnoreDirective(line) {
		return nil
	}

	// Tier 1 Gatekeeper: Long line protection for minified bundles (e.g. bundle.min.js > 1200 chars)
	// Do NOT truncate; bypass heavy regexes and scan directly with fast prefix byte searching
	if len(line) > LineLengthThreshold {
		return e.scanLongLinePrefixSampling(filePath, lineNum, line)
	}

	var findings []models.Finding
	seenFindingIDs := make(map[string]struct{})

	for _, rule := range e.rules {
		// Known-Prefix Pre-Filter Gate: If rule defines prefixes, line must contain at least one
		if len(rule.Prefixes) > 0 {
			matchedPrefix := false
			for _, prefix := range rule.Prefixes {
				if strings.Contains(line, prefix) {
					matchedPrefix = true
					break
				}
			}
			if !matchedPrefix {
				continue // Abort expensive regex evaluation
			}
		}

		// Tier 2: RE2 linear-time DFA pattern matching
		matches := rule.Pattern.FindAllStringSubmatchIndex(line, -1)
		for _, matchIndices := range matches {
			if len(matchIndices) < 2 {
				continue
			}

			startCol := matchIndices[0]
			var token string
			// If rule has capture groups, take group 1, otherwise take entire match
			if len(matchIndices) >= 4 && matchIndices[2] >= 0 {
				token = line[matchIndices[2]:matchIndices[3]]
				startCol = matchIndices[2]
			} else {
				token = line[matchIndices[0]:matchIndices[1]]
			}

			token = CleanToken(token)
			if len(token) == 0 || IsObviousPlaceholder(token) {
				continue
			}

			// Check entropy if required by rule
			var entropy float64
			var alphabet AlphabetType
			if rule.RequiresEntropy {
				meets, alph, ent := MeetsEntropyThreshold(token)
				if !meets && (rule.EntropyMin == 0 || ent < rule.EntropyMin) {
					continue
				}
				if HasLowVarianceOrSequential(token) {
					continue
				}
				entropy = ent
				alphabet = alph
			} else {
				entropy = CalculateShannonEntropy(token)
				alphabet = DetectAlphabet(token)
			}

			findingID := models.ComputeFindingHash(filePath, lineNum, rule.ID, token)
			if _, seen := seenFindingIDs[findingID]; seen {
				continue
			}
			seenFindingIDs[findingID] = struct{}{}

			confidence := AssessConfidence(filePath, line, token)
			finding := models.Finding{
				ID:              findingID,
				RuleID:          rule.ID,
				RuleDescription: rule.Description,
				Category:        rule.Category,
				FilePath:        filePath,
				LineNumber:      lineNum,
				Column:          startCol + 1,
				MaskedValue:     models.MaskSecret(token),
				RawSecret:       token,
				Entropy:         entropy,
				EntropyAlphabet: string(alphabet),
				Severity:        rule.Severity,
				Confidence:      confidence,
				Verification: models.VerificationResult{
					Status: models.StatusUnverified,
				},
				Remediation: rule.Remediation,
			}

			findings = append(findings, finding)
		}
	}

	// Filter out duplicate findings where a generic fallback rule matched the exact same token as a specific provider rule
	var deduplicated []models.Finding
	specificTokens := make(map[string]bool)
	for _, f := range findings {
		if f.RuleID != "AEGIS-GEN-001" && f.RuleID != "AEGIS-GCP-001" {
			specificTokens[f.RawSecret] = true
		}
	}
	for _, f := range findings {
		if (f.RuleID == "AEGIS-GEN-001" || f.RuleID == "AEGIS-GCP-001") && specificTokens[f.RawSecret] {
			continue
		}
		deduplicated = append(deduplicated, f)
	}

	return deduplicated
}

// scanLongLinePrefixSampling handles lines exceeding 1,200 characters using narrow windowed analysis.
func (e *Engine) scanLongLinePrefixSampling(filePath string, lineNum int, line string) []models.Finding {
	var findings []models.Finding
	seenFindingIDs := make(map[string]struct{})

	for _, rule := range e.rules {
		if len(rule.Prefixes) == 0 {
			continue
		}

		for _, prefix := range rule.Prefixes {
			idx := 0
			for {
				pos := strings.Index(line[idx:], prefix)
				if pos == -1 {
					break
				}
				absPos := idx + pos

				// Extract a narrow window around the match (e.g. 40 chars before prefix, 160 chars after)
				windowStart := absPos - 40
				if windowStart < 0 {
					windowStart = 0
				}
				windowEnd := absPos + len(prefix) + 160
				if windowEnd > len(line) {
					windowEnd = len(line)
				}
				window := line[windowStart:windowEnd]

				matches := rule.Pattern.FindAllStringSubmatchIndex(window, -1)
				for _, matchIndices := range matches {
					if len(matchIndices) < 2 {
						continue
					}

					var token string
					startCol := windowStart + matchIndices[0]
					if len(matchIndices) >= 4 && matchIndices[2] >= 0 {
						token = window[matchIndices[2]:matchIndices[3]]
						startCol = windowStart + matchIndices[2]
					} else {
						token = window[matchIndices[0]:matchIndices[1]]
					}

					token = CleanToken(token)
					if len(token) == 0 || IsObviousPlaceholder(token) {
						continue
					}

					var entropy float64
					var alphabet AlphabetType
					if rule.RequiresEntropy {
						meets, alph, ent := MeetsEntropyThreshold(token)
						if !meets && (rule.EntropyMin == 0 || ent < rule.EntropyMin) {
							continue
						}
						if HasLowVarianceOrSequential(token) {
							continue
						}
						entropy = ent
						alphabet = alph
					} else {
						entropy = CalculateShannonEntropy(token)
						alphabet = DetectAlphabet(token)
					}

					findingID := models.ComputeFindingHash(filePath, lineNum, rule.ID, token)
					if _, seen := seenFindingIDs[findingID]; seen {
						continue
					}
					seenFindingIDs[findingID] = struct{}{}

					confidence := AssessConfidence(filePath, line, token)
					findings = append(findings, models.Finding{
						ID:              findingID,
						RuleID:          rule.ID,
						RuleDescription: rule.Description,
						Category:        rule.Category,
						FilePath:        filePath,
						LineNumber:      lineNum,
						Column:          startCol + 1,
						MaskedValue:     models.MaskSecret(token),
						RawSecret:       token,
						Entropy:         entropy,
						EntropyAlphabet: string(alphabet),
						Severity:        rule.Severity,
						Confidence:      confidence,
						Verification: models.VerificationResult{
							Status: models.StatusUnverified,
						},
						Remediation: rule.Remediation,
					})
				}

				idx = absPos + len(prefix)
			}
		}
	}

	// Filter out duplicate findings where a generic fallback rule matched the exact same token as a specific provider rule
	var deduplicated []models.Finding
	specificTokens := make(map[string]bool)
	for _, f := range findings {
		if f.RuleID != "AEGIS-GEN-001" && f.RuleID != "AEGIS-GCP-001" {
			specificTokens[f.RawSecret] = true
		}
	}
	for _, f := range findings {
		if (f.RuleID == "AEGIS-GEN-001" || f.RuleID == "AEGIS-GCP-001") && specificTokens[f.RawSecret] {
			continue
		}
		deduplicated = append(deduplicated, f)
	}

	return deduplicated
}
