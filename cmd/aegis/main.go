package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aegis-cli/internal/analyzer"
	"aegis-cli/internal/config"
	"aegis-cli/internal/git"
	"aegis-cli/internal/reporter"
	"aegis-cli/internal/validator"
	"aegis-cli/pkg/models"
)

const (
	Version = "1.0.0"
	Banner  = `
    ___    ______ _____  ____ _____ 
   /   |  / ____// ___/ /  _// ___/ 
  / /| | / __/  / (_ /  / /  \__ \  
 / ___ |/ /___  / /_//_/ /  ___/ /  
/_/  |_/_____/  \___//___/ /____/   
Aegis CLI - Zero-Dependency Secret Scanner (v%s)
`
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	command := os.Args[1]

	switch command {
	case "version", "-v", "--version":
		fmt.Printf("aegis-cli version %s\n", Version)
		os.Exit(0)

	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)

	case "hook":
		runHookCommand(os.Args[2:])

	case "scan":
		runScanCommand(os.Args[2:])

	default:
		// Check if user directly ran `aegis [path]`
		if !strings.HasPrefix(command, "-") {
			runScanCommand(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nRun 'aegis --help' for usage.\n", command)
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Printf(Banner, Version)
	fmt.Println("\nUsage:")
	fmt.Println("  aegis scan [path] [flags]     Scan path or repository for secret leaks")
	fmt.Println("  aegis scan --staged           Scan staged git changes (pre-commit)")
	fmt.Println("  aegis scan --history          Scan deep git DAG commit history")
	fmt.Println("  aegis hook install            Install git pre-commit hook")
	fmt.Println("  aegis hook uninstall          Remove git pre-commit hook")
	fmt.Println("  aegis version                 Print version information")
	fmt.Println("\nScan Flags:")
	fmt.Println("  --staged                      Scan git staging buffer (default: false)")
	fmt.Println("  --history                     Scan entire git commit DAG history (default: false)")
	fmt.Println("  --verify                      Actively verify candidate tokens against provider APIs (default: false)")
	fmt.Println("  --format=console|json         Output format (default: console)")
	fmt.Println("  --output=<path>               Write structured report to file")
	fmt.Println("  --no-color                    Disable ANSI color codes")
}

func runHookCommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: aegis hook [install|uninstall]\n")
		os.Exit(2)
	}

	action := args[0]
	hooksDir, err := git.GetGitHooksDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[Aegis Error] %v\n", err)
		os.Exit(2)
	}

	switch action {
	case "install":
		if err := git.InstallHook(hooksDir); err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Failed to install hook: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("✅ Pre-commit hook installed successfully in %s\n", hooksDir)
		os.Exit(0)

	case "uninstall":
		if err := git.UninstallHook(hooksDir); err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Failed to uninstall hook: %v\n", err)
			os.Exit(2)
		}
		fmt.Println("✅ Pre-commit hook removed successfully.")
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "Unknown hook action: %s. Expected 'install' or 'uninstall'.\n", action)
		os.Exit(2)
	}
}

func runScanCommand(args []string) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)

	stagedFlag := fs.Bool("staged", false, "Scan staged changes in git index")
	historyFlag := fs.Bool("history", false, "Scan full git DAG commit history")
	verifyFlag := fs.Bool("verify", false, "Perform live zero-privilege token verification")
	formatFlag := fs.String("format", "console", "Output report format (console or json)")
	outputFlag := fs.String("output", "", "Output file path for report")
	noColorFlag := fs.Bool("no-color", false, "Disable color output")

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	targetPath := "."
	if fs.NArg() > 0 {
		targetPath = fs.Arg(0)
	}

	startTime := time.Now()
	engine := analyzer.NewEngine()

	var findings []models.Finding
	var totalFilesScanned int
	var totalLinesScanned int
	var scanType string
	var scanTarget string

	if *stagedFlag {
		scanType = "staged"
		scanTarget = "Git Staging Buffer"
		stagedFindings, err := git.ScanStaged(engine)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Failed to scan staged git index: %v\n", err)
			os.Exit(2)
		}
		findings = stagedFindings
		totalFilesScanned = 1
	} else if *historyFlag {
		scanType = "history"
		scanTarget = "Git Commit DAG History"
		historyFindings, err := git.ScanHistory(engine)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Failed to scan git history: %v\n", err)
			os.Exit(2)
		}
		findings = historyFindings
		totalFilesScanned = len(findings)
	} else {
		scanType = "path"
		scanTarget = targetPath
		matcher := config.LoadIgnoreMatcher(targetPath)

		stat, err := os.Stat(targetPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Target path error: %v\n", err)
			os.Exit(2)
		}

		if !stat.IsDir() {
			totalFilesScanned = 1
			fileFindings, err := engine.ScanFile(targetPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[Aegis Error] File scan error: %v\n", err)
				os.Exit(2)
			}
			findings = fileFindings
		} else {
			err = filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil // Skip unreadable paths
				}

				if info.IsDir() {
					if matcher.ShouldIgnore(path) && path != targetPath {
						return filepath.SkipDir
					}
					return nil
				}

				if matcher.ShouldIgnore(path) {
					return nil
				}

				totalFilesScanned++
				fileFindings, err := engine.ScanFile(path)
				if err == nil && len(fileFindings) > 0 {
					findings = append(findings, fileFindings...)
				}
				return nil
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "[Aegis Error] Directory traversal error: %v\n", err)
				os.Exit(2)
			}
		}
	}

	// Active Verification (Opt-In)
	if *verifyFlag && len(findings) > 0 {
		registry := validator.NewRegistry()
		findings = registry.VerifyAll(context.Background(), findings)
	}

	duration := time.Since(startTime).Milliseconds()

	// Compile Structured ScanReport
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	activeLeaks := 0

	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			criticalCount++
		case models.SeverityHigh:
			highCount++
		case models.SeverityMedium:
			mediumCount++
		case models.SeverityLow:
			lowCount++
		}
		if f.Verification.Status == models.StatusActive {
			activeLeaks++
		}
	}

	report := &models.ScanReport{
		Version:           Version,
		ScanTarget:        scanTarget,
		ScanType:          scanType,
		Timestamp:         time.Now(),
		DurationMs:        duration,
		TotalFilesScanned: totalFilesScanned,
		TotalLinesScanned: totalLinesScanned,
		TotalFindings:     len(findings),
		CriticalCount:     criticalCount,
		HighCount:         highCount,
		MediumCount:       mediumCount,
		LowCount:          lowCount,
		ActiveLeaksCount:  activeLeaks,
		Findings:          findings,
		FindingsHash:      models.ComputeReportHash(findings),
	}

	// Render Report
	if strings.ToLower(*formatFlag) == "json" {
		if err := reporter.WriteJSONReport(report, *outputFlag, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Failed to output JSON: %v\n", err)
			os.Exit(2)
		}
	} else {
		reporter.PrintConsoleReport(os.Stdout, report, *noColorFlag)
		if *outputFlag != "" {
			_ = reporter.WriteJSONReport(report, *outputFlag, ioDiscard{})
		}
	}

	// Deterministic Exit Codes:
	// 0: Clean / No critical secrets
	// 1: Critical or High secrets detected
	blockingCount := 0
	for _, f := range findings {
		if f.Confidence != models.ConfidenceLow && (f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh) {
			blockingCount++
		}
	}
	if blockingCount > 0 {
		os.Exit(1)
	}

	os.Exit(0)
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (n int, err error) {
	return len(p), nil
}
