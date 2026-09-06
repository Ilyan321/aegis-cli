package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

const (
	DefaultPlatformURL = "https://aegis-platform-wwgp.onrender.com"
	ConfigDirName      = ".aegis"
	ConfigFileName     = "config.json"
)

// CloudConfig stores the authenticated CLI credentials.
type CloudConfig struct {
	APIURL    string `json:"api_url"`
	APIToken  string `json:"api_token"`
	UserEmail string `json:"user_email,omitempty"`
}

// GetConfigPath returns ~/.aegis/config.json.
func GetConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ConfigDirName, ConfigFileName), nil
}

// LoadCloudConfig reads ~/.aegis/config.json with environment variable overrides.
func LoadCloudConfig() (*CloudConfig, error) {
	cfg := &CloudConfig{
		APIURL:   os.Getenv("AEGIS_API_URL"),
		APIToken: os.Getenv("AEGIS_API_TOKEN"),
	}
	if cfg.APIURL == "" {
		cfg.APIURL = DefaultPlatformURL
	}

	path, err := GetConfigPath()
	if err == nil {
		data, err := os.ReadFile(path)
		if err == nil {
			var fileCfg CloudConfig
			if err := json.Unmarshal(data, &fileCfg); err == nil {
				if cfg.APIToken == "" {
					cfg.APIToken = fileCfg.APIToken
				}
				if fileCfg.APIURL != "" && os.Getenv("AEGIS_API_URL") == "" {
					cfg.APIURL = fileCfg.APIURL
				}
				cfg.UserEmail = fileCfg.UserEmail
			}
		}
	}

	cfg.APIURL = strings.TrimRight(cfg.APIURL, "/")
	return cfg, nil
}

// SaveCloudConfig writes ~/.aegis/config.json.
func SaveCloudConfig(cfg *CloudConfig) error {
	path, err := GetConfigPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// SyncReportToPlatform streams the scan report to Aegis Platform backend.
func SyncReportToPlatform(report *models.ScanReport, targetDir string) (string, error) {
	cfg, err := LoadCloudConfig()
	if err != nil || cfg.APIToken == "" {
		return "", fmt.Errorf("not logged in. Run 'aegis login' to connect your terminal to the Aegis Platform")
	}

	repoName := getGitRepoName(targetDir)
	branch := getGitBranch(targetDir)
	commitSHA := getGitCommitSHA(targetDir)

	payload := map[string]interface{}{
		"repository_name":     repoName,
		"commit_sha":          commitSHA,
		"branch":              branch,
		"version":             report.Version,
		"scan_target":         report.ScanTarget,
		"scan_type":           report.ScanType,
		"duration_ms":         report.DurationMs,
		"total_files_scanned": report.TotalFilesScanned,
		"total_lines_scanned": report.TotalLinesScanned,
		"total_findings":      report.TotalFindings,
		"critical_count":      report.CriticalCount,
		"high_count":          report.HighCount,
		"medium_count":        report.MediumCount,
		"low_count":           report.LowCount,
		"active_leaks_count":  report.ActiveLeaksCount,
		"findings":            report.Findings,
		"findings_hash":       report.FindingsHash,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	endpoint := fmt.Sprintf("%s/api/v1/scans/cli", cfg.APIURL)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cfg.APIToken))

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to reach Aegis API (%s): %w", cfg.APIURL, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("platform returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var resData struct {
		ScanRunID string `json:"scan_run_id"`
		Message   string `json:"message"`
	}
	_ = json.Unmarshal(respBody, &resData)

	return resData.ScanRunID, nil
}

func getGitRepoName(dir string) string {
	cmd := exec.Command("git", "config", "--get", "remote.origin.url")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err == nil {
		url := strings.TrimSpace(string(out))
		url = strings.TrimSuffix(url, ".git")
		if strings.Contains(url, "github.com/") {
			parts := strings.Split(url, "github.com/")
			return parts[len(parts)-1]
		}
		if strings.Contains(url, "github.com:") {
			parts := strings.Split(url, "github.com:")
			return parts[len(parts)-1]
		}
	}
	abs, err := filepath.Abs(dir)
	if err == nil {
		return filepath.Base(abs)
	}
	return "local-project"
}

func getGitBranch(dir string) string {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err == nil {
		val := strings.TrimSpace(string(out))
		if val != "" {
			return val
		}
	}
	return "main"
}

func getGitCommitSHA(dir string) string {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err == nil {
		val := strings.TrimSpace(string(out))
		if val != "" {
			return val
		}
	}
	return "LOCAL_DEV"
}
