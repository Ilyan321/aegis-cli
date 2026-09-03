package git

import (
	"strings"
	"testing"

	"aegis-cli/internal/analyzer"
	"aegis-cli/pkg/models"
)

func TestParseUnifiedDiff(t *testing.T) {
	awsKey := "AK" + "IA" + "IOSFODNN7EXAMPLE"
	ghKey := "gh" + "p_" + "111122223333444455556666777788889999"

	diffData := `diff --git a/src/config.py b/src/config.py
index e69de29..d95f3ad 100644
--- a/src/config.py
+++ b/src/config.py
@@ -0,0 +1,3 @@
+import os
+API_KEY = "` + awsKey + `"
+DATABASE_URL = "postgres://user:pass@localhost:5432/db"
diff --git a/deleted.txt b/deleted.txt
deleted file mode 100644
index e69de29..0000000
--- a/deleted.txt
+++ /dev/null
@@ -1,2 +0,0 @@
-old_line_1
-old_line_2
diff --git a/src/auth.go b/src/auth.go
index 1111111..2222222 100644
--- a/src/auth.go
+++ b/src/auth.go
@@ -40,0 +45,2 @@
+	// Added authentication token
+	token := "` + ghKey + `"
`

	lines, err := ParseUnifiedDiff(strings.NewReader(diffData))
	if err != nil {
		t.Fatalf("ParseUnifiedDiff failed: %v", err)
	}

	if len(lines) != 5 {
		t.Fatalf("expected 5 added lines, got %d", len(lines))
	}

	// Verify line 1
	if lines[0].FilePath != "src/config.py" || lines[0].LineNumber != 1 || lines[0].Content != "import os" {
		t.Errorf("line 0 mismatch: %+v", lines[0])
	}
	// Verify line 2
	if lines[1].FilePath != "src/config.py" || lines[1].LineNumber != 2 {
		t.Errorf("line 1 mismatch: %+v", lines[1])
	}
	// Verify line in auth.go
	if lines[3].FilePath != "src/auth.go" || lines[3].LineNumber != 45 {
		t.Errorf("line 3 mismatch: %+v", lines[3])
	}
	if lines[4].FilePath != "src/auth.go" || lines[4].LineNumber != 46 {
		t.Errorf("line 4 mismatch: %+v", lines[4])
	}
}

func TestScanStagedUnifiedDiffIntegration(t *testing.T) {
	engine := analyzer.NewEngine()
	awsKey := "AK" + "IA" + "IOSFODNN7EXAMPLE"
	diffData := `diff --git a/.env b/.env
new file mode 100644
--- /dev/null
+++ b/.env
@@ -0,0 +1,2 @@
+AWS_KEY=` + awsKey + `
+SAFE_VAR=hello_world
`

	stagedLines, err := ParseUnifiedDiff(strings.NewReader(diffData))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	var findings []models.Finding
	for _, sl := range stagedLines {
		findings = append(findings, engine.ScanLine(sl.FilePath, sl.LineNumber, sl.Content)...)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Category != models.CategoryAWS {
		t.Errorf("expected AWS finding, got %s", findings[0].Category)
	}
	if findings[0].FilePath != ".env" || findings[0].LineNumber != 1 {
		t.Errorf("expected .env line 1, got %s line %d", findings[0].FilePath, findings[0].LineNumber)
	}
}
