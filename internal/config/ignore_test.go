package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIgnoreMatcherDefaults(t *testing.T) {
	matcher := &IgnoreMatcher{patterns: DefaultIgnorePatterns()}

	ignoredPaths := []string{
		".git/objects/pack/pack-1.pack",
		"node_modules/express/index.js",
		"vendor/github.com/pkg/errors/errors.go",
		"package-lock.json",
		"Cargo.lock",
		"assets/logo.png",
		"fonts/inter.woff2",
	}

	for _, path := range ignoredPaths {
		if !matcher.ShouldIgnore(path) {
			t.Errorf("expected path %q to be ignored by default", path)
		}
	}

	allowedPaths := []string{
		"cmd/aegis/main.go",
		"internal/analyzer/engine.go",
		"src/api/auth.py",
		"config/database.yml",
		".env.production",
	}

	for _, path := range allowedPaths {
		if matcher.ShouldIgnore(path) {
			t.Errorf("expected path %q to be allowed, but was ignored", path)
		}
	}
}

func TestCustomAegisIgnoreLoading(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "aegis-config-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ignoreContent := "# Custom ignore file\ncustom_secrets_mock.json\ntmp_scratch/\n"
	if err := os.WriteFile(filepath.Join(tempDir, ".aegisignore"), []byte(ignoreContent), 0644); err != nil {
		t.Fatalf("failed to write .aegisignore: %v", err)
	}

	matcher := LoadIgnoreMatcher(tempDir)
	if !matcher.ShouldIgnore("custom_secrets_mock.json") {
		t.Errorf("expected custom_secrets_mock.json to be ignored")
	}
	if !matcher.ShouldIgnore("tmp_scratch/data.txt") {
		t.Errorf("expected tmp_scratch/data.txt to be ignored")
	}
}
