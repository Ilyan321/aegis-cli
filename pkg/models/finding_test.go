package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"short token", "abc", "***"},
		{"exact 4 chars", "abcd", "****"},
		{"longer token", "AK"+"IAIOSFODNN7EXAMPLE", "AKIA****************"},
		{"stripe token", "sk_"+"live_1234567890abcdef", "sk_l********************"},
		{"utf-8 token", "секретный_токен", "секр***********"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskSecret(tt.input)
			if got != tt.expected {
				t.Errorf("MaskSecret(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestComputeFindingHash(t *testing.T) {
	hash1 := ComputeFindingHash("config.env", 12, "AWS_ACCESS_KEY", "AK"+"IAIOSFODNN7EXAMPLE")
	hash2 := ComputeFindingHash("./config.env", 12, "AWS_ACCESS_KEY", "AK"+"IAIOSFODNN7EXAMPLE")
	hash3 := ComputeFindingHash("config.env", 13, "AWS_ACCESS_KEY", "AK"+"IAIOSFODNN7EXAMPLE")

	if hash1 != hash2 {
		t.Errorf("expected deterministic hash output across normalized paths, got %s != %s", hash1, hash2)
	}
	if hash1 == hash3 {
		t.Errorf("expected different hash for different line, got identical %s", hash1)
	}
	if len(hash1) != 64 {
		t.Errorf("expected SHA256 hex string of length 64, got %d", len(hash1))
	}
}

func TestComputeReportHash(t *testing.T) {
	findings := []Finding{
		{ID: "hash-b"},
		{ID: "hash-a"},
		{ID: "hash-c"},
	}

	reportHash1 := ComputeReportHash(findings)

	// Reverse slice order to test sorting independence
	findingsReversed := []Finding{
		{ID: "hash-c"},
		{ID: "hash-a"},
		{ID: "hash-b"},
	}
	reportHash2 := ComputeReportHash(findingsReversed)

	if reportHash1 != reportHash2 {
		t.Errorf("expected report hash to be order-independent, got %s != %s", reportHash1, reportHash2)
	}

	if emptyHash := ComputeReportHash(nil); emptyHash != "" {
		t.Errorf("expected empty string for nil findings, got %s", emptyHash)
	}
}

func TestFindingJSONSerializationNeverExposesRawSecret(t *testing.T) {
	rawSecret := "super-sensitive-raw-api-token"
	finding := Finding{
		ID:          "finding-1",
		RuleID:      "TEST_RULE",
		FilePath:    "main.go",
		LineNumber:  10,
		MaskedValue: "supe*************************",
		RawSecret:   rawSecret,
		Severity:    SeverityCritical,
		Confidence:  ConfidenceHigh,
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("failed to marshal finding: %v", err)
	}

	jsonStr := string(data)
	if strings.Contains(jsonStr, rawSecret) {
		t.Fatalf("CRITICAL SECURITY FLAW: raw secret was leaked in JSON output: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, finding.MaskedValue) {
		t.Errorf("expected JSON to contain masked value, got: %s", jsonStr)
	}
}
