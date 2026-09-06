package reporter

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

// ANSI color codes for terminal rendering.
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31;1m"
	ColorYellow  = "\033[33;1m"
	ColorGreen   = "\033[32;1m"
	ColorCyan    = "\033[36;1m"
	ColorBlue    = "\033[34;1m"
	ColorMagenta = "\033[35;1m"
	ColorBold    = "\033[1m"
	ColorDim     = "\033[2m"
)

// PrintConsoleReport renders findings and summary statistics directly to an output stream.
func PrintConsoleReport(w io.Writer, report *models.ScanReport, noColor bool) {
	cRed := ColorRed
	cYellow := ColorYellow
	cGreen := ColorGreen
	cCyan := ColorCyan
	cBold := ColorBold
	cDim := ColorDim
	cReset := ColorReset

	if noColor {
		cRed, cYellow, cGreen, cCyan, cBold, cDim, cReset = "", "", "", "", "", "", ""
	}

	if len(report.Findings) == 0 {
		fmt.Fprintf(w, "\n%s%s[AEGIS] SCAN PASSED: No secrets detected.%s\n", cGreen, cBold, cReset)
		fmt.Fprintf(w, "%sScanned %d files (%d lines) in %dms%s\n\n", cDim, report.TotalFilesScanned, report.TotalLinesScanned, report.DurationMs, cReset)
		return
	}

	fmt.Fprintf(w, "\n%s%s[AEGIS] DETECTED %d SECRET LEAK(S)%s\n", cRed, cBold, len(report.Findings), cReset)
	fmt.Fprintf(w, "%s----------------------------------------------------------------------%s\n", cDim, cReset)

	for i, f := range report.Findings {
		sevColor := cYellow
		if f.Severity == models.SeverityCritical {
			sevColor = cRed
		} else if f.Severity == models.SeverityMedium {
			sevColor = cCyan
		}

		fmt.Fprintf(w, "\n%s#%d [%s] %s: %s%s\n", sevColor, i+1, f.Severity, f.RuleID, f.RuleDescription, cReset)
		fmt.Fprintf(w, "  %sLocation:%s   %s:%d:%d\n", cBold, cReset, f.FilePath, f.LineNumber, f.Column)
		fmt.Fprintf(w, "  %sDetected:%s   %s\n", cBold, cReset, f.MaskedValue)
		if f.Entropy > 0 {
			fmt.Fprintf(w, "  %sEntropy:%s    %.2f (%s)\n", cDim, cReset, f.Entropy, f.EntropyAlphabet)
		}

		// Active Verification Badge
		if f.Verification.Status == models.StatusActive {
			fmt.Fprintf(w, "  %sStatus:%s     %s%s[ACTIVE LEAK - VERIFIED LIVE]%s (%s)\n", cBold, cReset, cRed, cBold, cReset, f.Verification.Details)
		} else if f.Verification.Status == models.StatusRevoked {
			fmt.Fprintf(w, "  %sStatus:%s     %s[REVOKED / INACTIVE]%s (%s)\n", cBold, cReset, cYellow, cReset, f.Verification.Details)
		} else if f.Verification.Status == models.StatusError {
			fmt.Fprintf(w, "  %sStatus:%s     %s[VERIFICATION ERROR]%s (%s)\n", cBold, cReset, cDim, cReset, f.Verification.Details)
		}

		// Historical commit metadata if present
		if f.Commit != nil {
			fmt.Fprintf(w, "  %sCommit:%s     %s by %s (%s)\n", cDim, cReset, f.Commit.Hash[:8], f.Commit.Author, f.Commit.Date.Format(time.RFC3339))
			if f.Commit.Message != "" {
				fmt.Fprintf(w, "  %sMessage:%s    %s\n", cDim, cReset, strings.TrimSpace(f.Commit.Message))
			}
		}

		// Blast radius and remediation
		if f.Remediation.BlastRadius.Impact != "" {
			fmt.Fprintf(w, "  %sImpact:%s     %s\n", cBold, cReset, f.Remediation.BlastRadius.Impact)
		}
		if f.Remediation.ActionRequired != "" {
			fmt.Fprintf(w, "  %sRemediation:%s %s\n", cBold, cReset, f.Remediation.ActionRequired)
		}
		if len(f.Remediation.SuggestedCommands) > 0 {
			for _, cmd := range f.Remediation.SuggestedCommands {
				fmt.Fprintf(w, "    %s$ %s%s\n", cCyan, cmd, cReset)
			}
		}
	}

	fmt.Fprintf(w, "\n%s----------------------------------------------------------------------%s\n", cDim, cReset)
	fmt.Fprintf(w, "%sScan Summary:%s\n", cBold, cReset)
	fmt.Fprintf(w, "  Target:       %s (%s)\n", report.ScanTarget, report.ScanType)
	fmt.Fprintf(w, "  Files/Lines:  %d files / %d lines\n", report.TotalFilesScanned, report.TotalLinesScanned)
	fmt.Fprintf(w, "  Latency:      %d ms\n", report.DurationMs)
	fmt.Fprintf(w, "  Severity:     %sCritical: %d%s | %sHigh: %d%s | Medium: %d | Low: %d\n", cRed, report.CriticalCount, cReset, cYellow, report.HighCount, cReset, report.MediumCount, report.LowCount)
	if report.ActiveLeaksCount > 0 {
		fmt.Fprintf(w, "  %sActive Leaks:%s %s%d CONFIRMED LIVE%s\n", cBold, cReset, cRed, report.ActiveLeaksCount, cReset)
	}
	fmt.Fprintf(w, "  Report Hash:  %s%s%s (Deterministic)\n\n", cDim, report.FindingsHash, cReset)
}
