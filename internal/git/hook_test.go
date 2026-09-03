package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookInstallAndUninstall(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "aegis-hook-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test 1: Hook not installed initially
	installed, err := IsHookInstalled(tempDir)
	if err != nil {
		t.Fatalf("unexpected error checking hook: %v", err)
	}
	if installed {
		t.Errorf("expected hook to not be installed")
	}

	// Test 2: Install hook
	if err := InstallHook(tempDir); err != nil {
		t.Fatalf("InstallHook failed: %v", err)
	}

	installed, err = IsHookInstalled(tempDir)
	if err != nil || !installed {
		t.Fatalf("expected hook to be installed, got %v (err: %v)", installed, err)
	}

	// Verify file permissions
	hookPath := filepath.Join(tempDir, "pre-commit")
	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("failed to stat hook: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Errorf("expected hook to be executable, mode is %v", info.Mode())
	}

	// Test 3: Idempotent reinstall
	if err := InstallHook(tempDir); err != nil {
		t.Fatalf("reinstall failed: %v", err)
	}

	// Test 4: Uninstall hook
	if err := UninstallHook(tempDir); err != nil {
		t.Fatalf("UninstallHook failed: %v", err)
	}

	installed, _ = IsHookInstalled(tempDir)
	if installed {
		t.Errorf("expected hook to be uninstalled")
	}
}

func TestHookBackupAndRestore(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "aegis-hook-backup-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	foreignHook := "#!/bin/sh\necho 'foreign linter'\n"
	hookPath := filepath.Join(tempDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte(foreignHook), 0755); err != nil {
		t.Fatalf("failed to write foreign hook: %v", err)
	}

	// Installing Aegis hook should backup the foreign hook
	if err := InstallHook(tempDir); err != nil {
		t.Fatalf("InstallHook over existing hook failed: %v", err)
	}

	backupPath := filepath.Join(tempDir, "pre-commit.backup")
	backupContent, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("expected backup to exist, err: %v", err)
	}
	if string(backupContent) != foreignHook {
		t.Errorf("backup content mismatch: got %q, want %q", string(backupContent), foreignHook)
	}

	// Uninstalling Aegis hook should restore the foreign hook
	if err := UninstallHook(tempDir); err != nil {
		t.Fatalf("UninstallHook failed: %v", err)
	}

	restoredContent, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("expected restored hook to exist: %v", err)
	}
	if string(restoredContent) != foreignHook {
		t.Errorf("restored content mismatch: got %q, want %q", string(restoredContent), foreignHook)
	}
}

func TestRefuseToUninstallForeignHook(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "aegis-hook-foreign-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	foreignHook := "#!/bin/sh\necho 'custom team hook'\n"
	hookPath := filepath.Join(tempDir, "pre-commit")
	if err := os.WriteFile(hookPath, []byte(foreignHook), 0755); err != nil {
		t.Fatalf("failed to write foreign hook: %v", err)
	}

	err = UninstallHook(tempDir)
	if err == nil {
		t.Fatalf("expected error refusing to uninstall non-Aegis hook, got nil")
	}
	if !strings.Contains(err.Error(), "protect foreign hooks") {
		t.Errorf("unexpected error message: %v", err)
	}
}
