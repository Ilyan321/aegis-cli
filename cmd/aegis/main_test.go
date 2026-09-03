package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestCLIVersion(t *testing.T) {
	cmd := exec.Command("go", "run", "main.go", "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v, output: %s", err, string(out))
	}
	if !strings.Contains(string(out), "aegis-cli version 1.0.0") {
		t.Errorf("expected version output, got: %s", string(out))
	}
}

func TestCLIHelp(t *testing.T) {
	cmd := exec.Command("go", "run", "main.go", "--help")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("help command failed: %v, output: %s", err, string(out))
	}
	if !strings.Contains(string(out), "Usage:") {
		t.Errorf("expected usage output, got: %s", string(out))
	}
}

func TestCLIScanJSON(t *testing.T) {
	cmd := exec.Command("go", "run", "main.go", "scan", "--format=json", "--staged")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scan staged json failed: %v, output: %s", err, string(out))
	}
	if !strings.Contains(string(out), `"version": "1.0.0"`) {
		t.Errorf("expected valid JSON report, got: %s", string(out))
	}
}
