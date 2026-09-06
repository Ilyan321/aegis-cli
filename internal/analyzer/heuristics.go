package analyzer

import (
	"path/filepath"
	"strings"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

// IgnoreDirectives defines the supported inline comments that suppress findings on a line.
var IgnoreDirectives = []string{
	"// aegis:ignore",
	"# aegis:ignore",
	"/* aegis:ignore",
	"<!-- aegis:ignore",
	"; aegis:ignore",
	"-- aegis:ignore",
}

// MockKeywords are substrings in variable names or values that indicate mock/test context.
var MockKeywords = []string{
	"test",
	"mock",
	"dummy",
	"example",
	"placeholder",
	"sample",
	"fake",
	"fixture",
	"demo",
	"changeme",
	"replace_me",
	"your_api_key",
}

// HasIgnoreDirective returns true if the line contains an explicit inline ignore comment.
func HasIgnoreDirective(line string) bool {
	lineLower := strings.ToLower(line)
	if strings.Contains(lineLower, "aegis:ignore") || strings.Contains(lineLower, "aegis: ignore") {
		return true
	}
	if strings.Contains(lineLower, "nolint:aegis") || strings.Contains(lineLower, "pragma: allowlist") {
		return true
	}
	for _, dir := range IgnoreDirectives {
		if strings.Contains(lineLower, dir) {
			return true
		}
	}
	return false
}

// IsTestPath checks if the given file path is likely a unit test, mock, or fixture file.
func IsTestPath(filePath string) bool {
	normalized := strings.ToLower(filepath.ToSlash(filePath))
	normalized = strings.TrimPrefix(normalized, "./")
	normalized = strings.TrimPrefix(normalized, "/")

	testDirs := []string{
		"/test/",
		"/tests/",
		"/testing/",
		"/mock/",
		"/mocks/",
		"/fixture/",
		"/fixtures/",
		"/testdata/",
		"/spec/",
		"/__tests__/",
	}
	for _, dir := range testDirs {
		if strings.Contains(normalized, dir) || strings.HasPrefix(normalized, strings.TrimPrefix(dir, "/")) {
			return true
		}
	}

	base := filepath.Base(normalized)
	if strings.HasPrefix(base, "test_") {
		return true
	}

	testSuffixes := []string{
		"_test.go",
		".test.js",
		".test.ts",
		".test.jsx",
		".test.tsx",
		".spec.js",
		".spec.ts",
		".spec.jsx",
		".spec.tsx",
		"_spec.rb",
		"test.py",
		"_test.py",
	}
	for _, suffix := range testSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}

	return false
}

// AssessConfidence calculates finding confidence based on line semantics, mock keywords, and file context.
func AssessConfidence(filePath string, line string, token string) models.Confidence {
	lineLower := strings.ToLower(line)
	tokenLower := strings.ToLower(token)

	// Remove the token from the line to avoid false positives when high-entropy token contains a mock keyword
	contextLine := strings.Replace(lineLower, tokenLower, "", 1)

	// Check if surrounding line context contains known mock/test keywords in variable name or context
	for _, kw := range MockKeywords {
		if strings.Contains(contextLine, kw) {
			return models.ConfidenceLow
		}
		if tokenLower == kw || strings.HasPrefix(tokenLower, kw+"_") || strings.HasPrefix(tokenLower, kw+"-") {
			return models.ConfidenceLow
		}
	}

	// If file is located in test directory or has test suffix, confidence is lowered
	if IsTestPath(filePath) {
		return models.ConfidenceLow
	}

	return models.ConfidenceHigh
}

// IsObviousPlaceholder checks if a string is a standard documentation placeholder.
func IsObviousPlaceholder(token string) bool {
	tokenLower := strings.ToLower(token)

	// Exact matches for trivial dummy values
	trivialExact := []string{
		"12345678",
		"1234567890",
		"password",
		"admin",
		"root",
		"changeme",
		"your_token",
		"your_key",
		"your_api_key",
		"your_secret_key",
		"todo",
		"fixme",
		"xxxx",
		"xxxxx",
		"xxxxxx",
		"example",
		"examplekey",
	}
	for _, p := range trivialExact {
		if tokenLower == p {
			return true
		}
	}

	// Prefixes indicating placeholders
	placeholderPrefixes := []string{
		"your_",
		"replace_",
		"insert_",
		"change_me",
		"todo_",
		"sample_",
		"fake_",
		"dummy_",
		"test_dummy",
		"example_",
	}
	for _, prefix := range placeholderPrefixes {
		if strings.HasPrefix(tokenLower, prefix) {
			return true
		}
	}

	// Explicit dummy or placeholder substrings
	if strings.Contains(tokenLower, "placeholder") || strings.Contains(tokenLower, "dummy") {
		return true
	}

	// AWS documentation specifically uses AKIA...EXAMPLE for testing; allow it
	if strings.HasPrefix(token, "AKIA") && strings.HasSuffix(token, "EXAMPLE") {
		return false
	}

	if strings.HasSuffix(strings.ToUpper(token), "EXAMPLE") ||
		strings.HasSuffix(strings.ToUpper(token), "EXAMPLEKEY") {
		return true
	}

	return false
}
