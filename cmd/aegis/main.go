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
		// Check if user directly ran `aegis [path]` or `aegis --flags`
		if strings.HasPrefix(command, "-") {
			runScanCommand(os.Args[1:])
			return
		}
		// Positional path passed directly: aegis [path]
		runScanCommand(os.Args[1:])
	}
}

func printUsage() {
	fmt.Printf(Banner, Version)
	fmt.Println("\nUsage:")
	fmt.Println("  aegis scan [path] [flags]     Scan path or repository for secret leaks")
	fmt.Println("  aegis scan --staged           Scan staged git changes (pre-commit)")
	fmt.Println("  aegis scan --history          Scan deep git DAG commit history")
	fmt.Println("  aegis scan --range=BASE...HEAD Scan PR merge-base range (CI/CD)")
	fmt.Println("  aegis hook install            Install git pre-commit hook")
	fmt.Println("  aegis hook uninstall          Remove git pre-commit hook")
	fmt.Println("  aegis version                 Print version information")
	fmt.Println("\nScan Flags:")
	fmt.Println("  --staged                      Scan git staging buffer (default: false)")
	fmt.Println("  --history                     Scan entire git commit DAG history (default: false)")
	fmt.Println("  --range=<base>...<head>       Scan git commit range diff")
	fmt.Println("  --verify                      Actively verify candidate tokens against provider APIs (default: false)")
	fmt.Println("  --format=console|json         Output format (default: console)")
	fmt.Println("  --output=<path>               Write structured report to file")
	fmt.Println("  --fail-on=critical|high|medium Fail threshold for exit code 1 (default: critical)")
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
	rangeFlag := fs.String("range", "", "Scan git diff range e.g. origin/main...HEAD")
	verifyFlag := fs.Bool("verify", false, "Perform live zero-privilege token verification")
	formatFlag := fs.String("format", "console", "Output report format (console or json)")
	outputFlag := fs.String("output", "", "Output file path for report")
	failOnFlag := fs.String("fail-on", "critical", "Failure threshold for exit code: critical, high, medium, low")
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
		stagedFindings, filesCount, linesCount, err := git.ScanStagedWithStats(engine)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Failed to scan staged git index: %v\n", err)
			os.Exit(2)
		}
		findings = stagedFindings
		totalFilesScanned = filesCount
		totalLinesScanned = linesCount
	} else if *rangeFlag != "" {
		scanType = "range"
		scanTarget = *rangeFlag
		parts := strings.Split(*rangeFlag, "...")
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Invalid range format %q. Expected BASE...HEAD\n", *rangeFlag)
			os.Exit(2)
		}
		rangeFindings, filesCount, linesCount, err := git.ScanRangeWithStats(engine, parts[0], parts[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Failed to scan range diff: %v\n", err)
			os.Exit(2)
		}
		findings = rangeFindings
		totalFilesScanned = filesCount
		totalLinesScanned = linesCount
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
			fileFindings, lines, err := engine.ScanFileWithStats(targetPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[Aegis Error] File scan error: %v\n", err)
				os.Exit(2)
			}
			totalFilesScanned = 1
			totalLinesScanned = lines
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

				fileFindings, lines, err := engine.ScanFileWithStats(path)
				if err == nil {
					totalFilesScanned++
					totalLinesScanned += lines
					if len(fileFindings) > 0 {
						findings = append(findings, fileFindings...)
					}
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
	// Evaluate failure threshold (PRD Section 5.2)
	threshold := strings.ToUpper(*failOnFlag)
	blockingCount := 0
	for _, f := range findings {
		if f.Confidence == models.ConfidenceLow {
			continue // Non-blocking false-alarm suppression (PRD Section 4.2)
		}

		switch threshold {
		case "LOW":
			blockingCount++
		case "MEDIUM":
			if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh || f.Severity == models.SeverityMedium {
				blockingCount++
			}
		case "HIGH":
			if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh {
				blockingCount++
			}
		default: // "CRITICAL"
			if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh {
				blockingCount++
			}
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
