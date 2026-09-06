package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// IgnoreMatcher evaluates file and directory paths against glob ignore patterns.
type IgnoreMatcher struct {
	patterns []string
}

// LoadIgnoreMatcher loads ignore rules from .aegisignore, falling back to defaults if not present.
// If .aegisignore is not in dir, it searches upward to repository root.
func LoadIgnoreMatcher(dir string) *IgnoreMatcher {
	patterns := DefaultIgnorePatterns()
	if dir == "" {
		dir = "."
	}

	var ignorePath string
	candidate := filepath.Join(dir, ".aegisignore")
	if _, err := os.Stat(candidate); err == nil {
		ignorePath = candidate
	} else if absDir, err := filepath.Abs(dir); err == nil {
		d := absDir
		for {
			c := filepath.Join(d, ".aegisignore")
			if _, err := os.Stat(c); err == nil {
				ignorePath = c
				break
			}
			if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
				break
			}
			parent := filepath.Dir(d)
			if parent == d {
				break
			}
			d = parent
		}
	}

	if ignorePath != "" {
		file, err := os.Open(ignorePath)
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				patterns = append(patterns, line)
			}
		}
	}

	return &IgnoreMatcher{patterns: patterns}
}

// DefaultIgnorePatterns returns standard patterns that should always be bypassed.
func DefaultIgnorePatterns() []string {
	return []string{
		".git",
		".git/*",
		"node_modules",
		"node_modules/*",
		"vendor",
		"vendor/*",
		".venv",
		".venv/*",
		"target",
		"target/*",
		"dist",
		"dist/*",
		"bin",
		"bin/*",
		"*.lock",
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
		"Cargo.lock",
		"go.sum",
		"poetry.lock",
		"composer.lock",
		"Gemfile.lock",
		"*.png",
		"*.jpg",
		"*.jpeg",
		"*.gif",
		"*.svg",
		"*.ico",
		"*.pdf",
		"*.zip",
		"*.tar.gz",
		"*.woff",
		"*.woff2",
	}
}

// ShouldIgnore tests if a file or directory path matches any configured ignore pattern.
func (m *IgnoreMatcher) ShouldIgnore(path string) bool {
	normalized := filepath.ToSlash(path)
	normalized = strings.TrimPrefix(normalized, "./")
	normalized = strings.TrimPrefix(normalized, "/")

	base := filepath.Base(normalized)

	for _, pattern := range m.patterns {
		pattern = filepath.ToSlash(pattern)
		pattern = strings.TrimPrefix(pattern, "./")
		pattern = strings.TrimPrefix(pattern, "/")

		// Exact match
		if normalized == pattern || base == pattern {
			return true
		}

		// Directory match (e.g. node_modules or .git/)
		cleanPattern := strings.TrimSuffix(pattern, "/*")
		cleanPattern = strings.TrimSuffix(cleanPattern, "/")
		if cleanPattern != "" {
			if strings.HasPrefix(normalized, cleanPattern+"/") ||
				strings.Contains(normalized, "/"+cleanPattern+"/") ||
				base == cleanPattern {
				return true
			}
		}

		// Glob match (e.g. *.lock, *.png, *_test.go)
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, normalized); matched {
			return true
		}
	}

	return false
}
