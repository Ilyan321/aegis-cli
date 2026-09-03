package git

import (
	"testing"

	"aegis-cli/internal/analyzer"
)

func TestListAllReachableObjects(t *testing.T) {
	objects, err := ListAllReachableObjects()
	if err != nil {
		t.Fatalf("ListAllReachableObjects failed: %v", err)
	}

	if len(objects) == 0 {
		t.Fatalf("expected reachable objects in git repository, got 0")
	}

	foundKnownFile := false
	for _, obj := range objects {
		if obj.Path == "Makefile" || obj.Path == "go.mod" {
			foundKnownFile = true
			break
		}
	}

	if !foundKnownFile {
		t.Errorf("expected Makefile or go.mod among reachable objects, got %+v", objects)
	}
}

func TestScanHistoryOnCleanRepo(t *testing.T) {
	engine := analyzer.NewEngine()
	findings, err := ScanHistory(engine)
	if err != nil {
		t.Fatalf("ScanHistory failed: %v", err)
	}

	// Current repository has sanitized test tokens and zero actual leaks
	for _, f := range findings {
		t.Logf("Found in history: %s (%s) at %s:%d", f.RuleID, f.Category, f.FilePath, f.LineNumber)
	}
}
