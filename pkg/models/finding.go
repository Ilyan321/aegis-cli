package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity represents the criticality level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Confidence represents the likelihood of the finding being a true secret rather than mock/test data.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// VerificationStatus represents the live active verification state of a detected credential.
type VerificationStatus string

const (
	StatusUnverified VerificationStatus = "UNVERIFIED"
	StatusActive     VerificationStatus = "ACTIVE_LEAK"
	StatusRevoked    VerificationStatus = "REVOKED_DEAD"
	StatusError      VerificationStatus = "VERIFICATION_ERROR"
	StatusSkipped    VerificationStatus = "SKIPPED"
)

// TokenCategory classifies the provider or type of the credential.
type TokenCategory string

const (
	CategoryAWS      TokenCategory = "AWS"
	CategoryGitHub   TokenCategory = "GitHub"
	CategoryStripe   TokenCategory = "Stripe"
	CategoryOpenAI   TokenCategory = "OpenAI"
	CategorySlack    TokenCategory = "Slack"
	CategoryDatabase TokenCategory = "Database"
	CategoryGeneric  TokenCategory = "Generic High-Entropy"
)

// BlastRadius details the operational and security impact if the token is compromised.
type BlastRadius struct {
	Scope          string   `json:"scope"`
	Impact         string   `json:"impact"`
	TargetServices []string `json:"target_services,omitempty"`
}

// Remediation provides clear, actionable instructions and automated diffs to resolve the secret leak.
type Remediation struct {
	BlastRadius       BlastRadius `json:"blast_radius"`
	ActionRequired    string      `json:"action_required"`
	SuggestedCommands []string    `json:"suggested_commands,omitempty"`
	AutomatedDiff     string      `json:"automated_diff,omitempty"`
}

// VerificationResult details live verification pings performed against provider APIs.
type VerificationResult struct {
	Status     VerificationStatus `json:"status"`
	Provider   string             `json:"provider"`
	CheckedAt  time.Time          `json:"checked_at,omitempty"`
	Details    string             `json:"details,omitempty"`
	LatencyMs  int64              `json:"latency_ms,omitempty"`
}

// CommitInfo provides metadata about git commits when scanning historical DAG objects.
type CommitInfo struct {
	Hash    string    `json:"hash"`
	Author  string    `json:"author,omitempty"`
	Date    time.Time `json:"date,omitempty"`
	Message string    `json:"message,omitempty"`
}

// Finding represents an individual detected secret.
type Finding struct {
	ID              string             `json:"id"`
	RuleID          string             `json:"rule_id"`
	RuleDescription string             `json:"rule_description"`
	Category        TokenCategory      `json:"category"`
	FilePath        string             `json:"file_path"`
	LineNumber      int                `json:"line_number"`
	Column          int                `json:"column"`
	MaskedValue     string             `json:"masked_value"`
	Entropy         float64            `json:"entropy"`
	EntropyAlphabet string             `json:"entropy_alphabet,omitempty"`
	Severity        Severity           `json:"severity"`
	Confidence      Confidence         `json:"confidence"`
	Verification    VerificationResult `json:"verification"`
	Remediation     Remediation        `json:"remediation"`
	Commit          *CommitInfo        `json:"commit,omitempty"`
	RawSecret       string             `json:"-"` // Never serialized in JSON output to protect secret values
}

// ScanReport represents the full structured report produced by an Aegis scan.
type ScanReport struct {
	Version           string    `json:"version"`
	ScanTarget        string    `json:"scan_target"`
	ScanType          string    `json:"scan_type"`
	Timestamp         time.Time `json:"timestamp"`
	DurationMs        int64     `json:"duration_ms"`
	TotalFilesScanned int       `json:"total_files_scanned"`
	TotalLinesScanned int       `json:"total_lines_scanned"`
	TotalFindings     int       `json:"total_findings"`
	CriticalCount     int       `json:"critical_count"`
	HighCount         int       `json:"high_count"`
	MediumCount       int       `json:"medium_count"`
	LowCount          int       `json:"low_count"`
	ActiveLeaksCount  int       `json:"active_leaks_count"`
	Findings          []Finding `json:"findings"`
	FindingsHash      string    `json:"findings_hash"`
}

// MaskSecret masks the sensitive characters of a secret while preserving prefix structure for identification.
func MaskSecret(secret string) string {
	length := len(secret)
	if length == 0 {
		return ""
	}
	if length <= 4 {
		return strings.Repeat("*", length)
	}
	// Preserve up to 4 leading chars, mask the rest
	prefix := secret[:4]
	return prefix + strings.Repeat("*", length-4)
}

// ComputeFindingHash computes a deterministic SHA256 hex string for a single finding.
func ComputeFindingHash(filePath string, lineNumber int, ruleID string, rawSecret string) string {
	hasher := sha256.New()
	hasher.Write([]byte(fmt.Sprintf("%s:%d:%s:%s", filePath, lineNumber, ruleID, rawSecret)))
	return hex.EncodeToString(hasher.Sum(nil))
}

// ComputeReportHash computes a deterministic SHA256 hash across all finding IDs for reproducibility check.
func ComputeReportHash(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	sort.Strings(ids)

	hasher := sha256.New()
	for _, id := range ids {
		hasher.Write([]byte(id))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}
