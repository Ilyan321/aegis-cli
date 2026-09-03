package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	AegisHookMarker = "# Aegis CLI Pre-Commit Hook"
	HookScript      = `#!/usr/bin/env bash
# Aegis CLI Pre-Commit Hook
# Deterministic local-first secret scanning

if command -v aegis >/dev/null 2>&1; then
    aegis staged
    EXIT_CODE=$?
elif [ -f "./bin/aegis" ]; then
    ./bin/aegis staged
    EXIT_CODE=$?
else
    echo "[Aegis] Warning: aegis binary not found in PATH or ./bin/aegis. Skipping pre-commit secret scan."
    exit 0
fi

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "[Aegis] Commit rejected: Uncommitted secrets detected in staging buffer."
    echo "[Aegis] Run 'aegis staged' for remediation instructions or add '// aegis:ignore' for false-positives."
    exit 1
fi
exit 0
`
)

// GetGitHooksDir resolves the active repository hooks directory.
func GetGitHooksDir() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--git-path", "hooks")
	out, err := cmd.Output()
	if err != nil {
		// Fallback to local .git/hooks directory
		candidate := filepath.Join(".git", "hooks")
		if info, statErr := os.Stat(".git"); statErr == nil && info.IsDir() {
			return candidate, nil
		}
		return "", fmt.Errorf("not a git repository or git rev-parse failed: %w", err)
	}

	hooksPath := strings.TrimSpace(string(out))
	if hooksPath == "" {
		hooksPath = filepath.Join(".git", "hooks")
	}

	return hooksPath, nil
}

// InstallHook installs the Aegis pre-commit hook into the specified hooks directory.
func InstallHook(hooksDir string) error {
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	hookPath := filepath.Join(hooksDir, "pre-commit")

	// Check if hook already exists
	if content, err := os.ReadFile(hookPath); err == nil {
		if strings.Contains(string(content), AegisHookMarker) {
			return nil // Already installed, idempotent
		}
		// Create a backup of existing non-aegis hook
		backupPath := filepath.Join(hooksDir, "pre-commit.backup")
		if err := os.WriteFile(backupPath, content, 0755); err != nil {
			return fmt.Errorf("failed to backup existing pre-commit hook: %w", err)
		}
	}

	// Write new hook script with executable permissions
	if err := os.WriteFile(hookPath, []byte(HookScript), 0755); err != nil {
		return fmt.Errorf("failed to write pre-commit hook: %w", err)
	}

	return nil
}

// UninstallHook removes the Aegis pre-commit hook, restoring any previous backup.
func UninstallHook(hooksDir string) error {
	hookPath := filepath.Join(hooksDir, "pre-commit")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Nothing to uninstall
		}
		return err
	}

	if !strings.Contains(string(content), AegisHookMarker) {
		return fmt.Errorf("pre-commit hook exists but was not installed by Aegis; aborting removal to protect foreign hooks")
	}

	backupPath := filepath.Join(hooksDir, "pre-commit.backup")
	if backupContent, err := os.ReadFile(backupPath); err == nil {
		// Restore previous backup
		if err := os.WriteFile(hookPath, backupContent, 0755); err != nil {
			return fmt.Errorf("failed to restore pre-commit backup: %w", err)
		}
		_ = os.Remove(backupPath)
		return nil
	}

	// No backup exists, safely remove aegis hook
	if err := os.Remove(hookPath); err != nil {
		return fmt.Errorf("failed to remove pre-commit hook: %w", err)
	}

	return nil
}

// IsHookInstalled checks if the Aegis pre-commit hook is active in the repository.
func IsHookInstalled(hooksDir string) (bool, error) {
	hookPath := filepath.Join(hooksDir, "pre-commit")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return strings.Contains(string(content), AegisHookMarker), nil
}
