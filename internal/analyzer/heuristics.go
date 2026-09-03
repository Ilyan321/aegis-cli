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

	// Check if line or token itself contains known mock/test keywords
	for _, kw := range MockKeywords {
		if strings.Contains(lineLower, kw) || strings.Contains(tokenLower, kw) {
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
	}
	for _, p := range trivialExact {
		if tokenLower == p {
			return true
		}
	}

	if strings.HasPrefix(tokenLower, "your_") ||
		strings.HasPrefix(tokenLower, "replace_") ||
		strings.HasSuffix(strings.ToUpper(token), "EXAMPLE") ||
		strings.HasSuffix(strings.ToUpper(token), "EXAMPLEKEY") {
		// Note: Don't mark AWS keys ending in EXAMPLE as placeholder if we want to test them,
		// but AWS docs specifically use AKIAIOSFODNN7EXAMPLE. We let AKIAIOSFODNN7EXAMPLE be detected
		// so tests and verification work unless it's pure "EXAMPLE"
		if tokenLower == "example" || tokenLower == "examplekey" {
			return true
		}
	}

	return false
}
