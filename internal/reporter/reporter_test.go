package reporter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aegis-cli/pkg/models"
)

func TestPrintConsoleReportClean(t *testing.T) {
	report := &models.ScanReport{
		ScanTarget:        ".",
		ScanType:          "staged",
		TotalFilesScanned: 5,
		TotalLinesScanned: 100,
		DurationMs:        12,
		Findings:          nil,
	}

	var buf bytes.Buffer
	PrintConsoleReport(&buf, report, true)
	out := buf.String()

	if !strings.Contains(out, "SCAN PASSED") {
		t.Errorf("expected clean scan to report passed, got: %s", out)
	}
}

func TestPrintConsoleReportWithFindings(t *testing.T) {
	report := &models.ScanReport{
		ScanTarget:        ".",
		ScanType:          "path",
		TotalFilesScanned: 2,
		TotalLinesScanned: 50,
		DurationMs:        25,
		CriticalCount:     1,
		ActiveLeaksCount:  1,
		Findings: []models.Finding{
			{
				ID:              "f-1",
				RuleID:          "AEGIS-AWS-001",
				RuleDescription: "AWS Access Key",
				FilePath:        "app.env",
				LineNumber:      5,
				Column:          10,
				MaskedValue:     "AKIA****************",
				Severity:        models.SeverityCritical,
				Verification: models.VerificationResult{
					Status:  models.StatusActive,
					Details: "Active AWS IAM key",
				},
				Remediation: models.Remediation{
					ActionRequired: "Revoke IAM user key",
					SuggestedCommands: []string{
						"aws iam delete-access-key",
					},
				},
			},
		},
		FindingsHash: "test-hash-123",
	}

	var buf bytes.Buffer
	PrintConsoleReport(&buf, report, true)
	out := buf.String()

	if !strings.Contains(out, "DETECTED 1 SECRET LEAK(S)") {
		t.Errorf("expected detected banner, got: %s", out)
	}
	if !strings.Contains(out, "[ACTIVE LEAK - VERIFIED LIVE]") {
		t.Errorf("expected active leak badge, got: %s", out)
	}
	if !strings.Contains(out, "aws iam delete-access-key") {
		t.Errorf("expected suggested command, got: %s", out)
	}
}

func TestWriteJSONReport(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "aegis-reporter-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	report := &models.ScanReport{
		Version:       "1.0.0",
		Timestamp:     time.Now(),
		TotalFindings: 0,
	}

	jsonPath := filepath.Join(tempDir, "report.json")
	var stdout bytes.Buffer
	if err := WriteJSONReport(report, jsonPath, &stdout); err != nil {
		t.Fatalf("WriteJSONReport failed: %v", err)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read written json: %v", err)
	}

	var parsed models.ScanReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to parse generated json: %v", err)
	}

	if parsed.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", parsed.Version)
	}
}
