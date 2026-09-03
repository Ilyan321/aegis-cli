package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ilyan321/aegis-cli/internal/analyzer"
	"github.com/Ilyan321/aegis-cli/internal/config"
	"github.com/Ilyan321/aegis-cli/internal/git"
	"github.com/Ilyan321/aegis-cli/internal/reporter"
	"github.com/Ilyan321/aegis-cli/internal/validator"
	"github.com/Ilyan321/aegis-cli/pkg/models"
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
		os.Exit(0)
	}

	command := os.Args[1]

	switch command {
	case "version", "-v", "--version":
		fmt.Printf("aegis-cli version %s\n", Version)
		os.Exit(0)

	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)

	case "init":
		runInitCommand()

	case "uninit":
		runUninitCommand()

	case "status":
		runStatusCommand()

	case "check":
		runCheckCommand(os.Args[2:])

	case "staged":
		runScanCommand(append([]string{"--staged"}, os.Args[2:]...))

	case "audit":
		runAuditCommand(os.Args[2:])

	case "history":
		runScanCommand(append([]string{"--history"}, os.Args[2:]...))

	case "hook":
		runHookCommand(os.Args[2:])

	case "scan":
		runScanCommand(os.Args[2:])

	default:
		// Check if user passed flags directly: aegis --flags
		if strings.HasPrefix(command, "-") {
			runScanCommand(os.Args[1:])
			return
		}
		// If command matches an existing file or folder, scan it directly
		if _, err := os.Stat(command); err == nil {
			runScanCommand(os.Args[1:])
			return
		}
		// Otherwise report unrecognized command cleanly (Git UX pattern)
		fmt.Fprintf(os.Stderr, "aegis: '%s' is not an aegis command. Run 'aegis --help' to see available commands.\n", command)
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Printf(Banner, Version)
	fmt.Println("\nPrimary Commands:")
	fmt.Println("  aegis init                    Initialize Aegis: install pre-commit hook and create .aegisignore")
	fmt.Println("  aegis scan [path]             Scan workspace or directory (defaults to current directory)")
	fmt.Println("  aegis staged                  Scan staged changes in git index before committing")
	fmt.Println("  aegis audit history           Deep-audit full git commit DAG history for past leaks")
	fmt.Println("  aegis check \"<string>\"        Instantly inspect a secret string or token from the terminal")
	fmt.Println("  aegis status                  Show repository protection status and staged security state")
	fmt.Println("  aegis uninit                  Remove Aegis pre-commit protection from current repository")
	fmt.Println("  aegis version                 Print version information")
	fmt.Println("\nAdvanced Flags for 'scan' / 'staged' / 'audit':")
	fmt.Println("  --verify                      Actively verify candidate tokens against live provider APIs")
	fmt.Println("  --range=<base>...<head>       Scan PR merge-base range (CI/CD)")
	fmt.Println("  --format=console|json         Output report format (default: console)")
	fmt.Println("  --output=<path>               Write structured report to file")
	fmt.Println("  --fail-on=critical|high|med   Failure threshold for exit code 1 (default: critical)")
	fmt.Println("  --no-color                    Disable ANSI color formatting")
}

func runInitCommand() {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	fmt.Printf("🛡️  Initializing Aegis in %s...\n", cwd)

	hooksDir, hookErr := git.GetGitHooksDir()
	if hookErr != nil {
		fmt.Fprintf(os.Stderr, "  ⚠️  Not a git repository (run 'git init' first to enable automatic pre-commit protection)\n")
	} else {
		if err := git.InstallHook(hooksDir); err != nil {
			fmt.Fprintf(os.Stderr, "  ❌ Failed to install git pre-commit hook: %v\n", err)
			os.Exit(2)
		}
		fmt.Println("  ✅ Installed git pre-commit hook (.git/hooks/pre-commit)")
	}

	// Create starter .aegisignore if not present
	ignoreFile := filepath.Join(cwd, ".aegisignore")
	if _, err := os.Stat(ignoreFile); os.IsNotExist(err) {
		starterIgnore := `# Aegis CLI Ignore File
# Add patterns, paths, or file extensions to bypass during scans.

.git/
node_modules/
vendor/
target/
dist/
bin/
*.lock
*.png
*.jpg
*.jpeg
*.svg
*.pdf
*.zip
`
		if err := os.WriteFile(ignoreFile, []byte(starterIgnore), 0644); err == nil {
			fmt.Println("  ✅ Created starter .aegisignore file")
		}
	} else {
		fmt.Println("  ℹ️  Existing .aegisignore preserved")
	}

	if hookErr == nil {
		fmt.Println("\n🎉 Repository is protected! Aegis will automatically scan commits in <10ms.")
	} else {
		fmt.Println("\nℹ️  Starter configuration ready. Run 'git init' followed by 'aegis init' to activate pre-commit scanning.")
	}
	os.Exit(0)
}

func runUninitCommand() {
	hooksDir, err := git.GetGitHooksDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
		os.Exit(2)
	}

	if err := git.UninstallHook(hooksDir); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error removing pre-commit hook: %v\n", err)
		os.Exit(2)
	}

	fmt.Println("✅ Aegis pre-commit hook uninstalled successfully.")
	os.Exit(0)
}

func runStatusCommand() {
	fmt.Println("🛡️  Aegis Repository Status")
	fmt.Println("----------------------------------------")

	// Hook status
	hooksDir, err := git.GetGitHooksDir()
	if err == nil {
		hookPath := filepath.Join(hooksDir, "pre-commit")
		content, readErr := os.ReadFile(hookPath)
		if readErr == nil && strings.Contains(string(content), git.AegisHookMarker) {
			fmt.Println("  Git Pre-Commit Hook:  ✅ Active (.git/hooks/pre-commit)")
		} else {
			fmt.Println("  Git Pre-Commit Hook:  ⚠️  Not installed (run 'aegis init' to activate)")
		}
	} else {
		fmt.Println("  Git Repository:       ⚠️  Not inside a git repository")
	}

	// Ignore file status
	if _, err := os.Stat(".aegisignore"); err == nil {
		fmt.Println("  Ignore Rules:         ✅ .aegisignore configured")
	} else {
		fmt.Println("  Ignore Rules:         ℹ️  Using standard defaults (.aegisignore missing)")
	}

	// Quick staged buffer inspection
	engine := analyzer.NewEngine()
	stagedFindings, _, _, err := git.ScanStagedWithStats(engine)
	if err == nil {
		if len(stagedFindings) == 0 {
			fmt.Println("  Staged Git Buffer:    ✅ Clean (0 secrets staged)")
		} else {
			fmt.Printf("  Staged Git Buffer:    🚨 %d secret(s) detected! (run 'aegis staged' for details)\n", len(stagedFindings))
		}
	}

	fmt.Println("----------------------------------------")
	os.Exit(0)
}

func runCheckCommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: aegis check \"<string_to_inspect>\" [--verify]\n")
		os.Exit(2)
	}

	verify := false
	var tokenInput string
	for _, arg := range args {
		if arg == "--verify" || arg == "-v" {
			verify = true
		} else if !strings.HasPrefix(arg, "-") && tokenInput == "" {
			tokenInput = arg
		}
	}

	if tokenInput == "" {
		fmt.Fprintf(os.Stderr, "Error: No secret string provided to inspect.\n")
		os.Exit(2)
	}

	engine := analyzer.NewEngine()
	findings := engine.ScanLine("terminal-input", 1, tokenInput)

	if len(findings) == 0 {
		fmt.Println("\n✅ No secret pattern or high-entropy credential detected in input.")
		os.Exit(0)
	}

	if verify {
		registry := validator.NewRegistry()
		defer registry.Close()
		findings = registry.VerifyAll(context.Background(), findings)
	}

	report := &models.ScanReport{
		Version:           Version,
		ScanTarget:        "Terminal Input String",
		ScanType:          "check",
		Timestamp:         time.Now(),
		DurationMs:        1,
		TotalFilesScanned: 1,
		TotalLinesScanned: 1,
		TotalFindings:     len(findings),
		Findings:          findings,
		FindingsHash:      models.ComputeReportHash(findings),
	}

	reporter.PrintConsoleReport(os.Stdout, report, false)
	os.Exit(1)
}

func runAuditCommand(args []string) {
	var subArgs []string
	isHistory := false

	for _, arg := range args {
		if arg == "history" {
			isHistory = true
		} else {
			subArgs = append(subArgs, arg)
		}
	}

	if isHistory || len(args) == 0 {
		runScanCommand(append([]string{"--history"}, subArgs...))
		return
	}

	// Default fallback to history audit
	runScanCommand(append([]string{"--history"}, args...))
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

	opts := &config.ScanOptions{
		TargetDirectory: targetPath,
		ScanStaged:      *stagedFlag,
		ScanHistory:     *historyFlag,
		Verify:          *verifyFlag,
		Format:          *formatFlag,
		OutputFile:      *outputFlag,
		FailOnSeverity:  *failOnFlag,
	}

	startTime := time.Now()
	engine := analyzer.NewEngine()

	var findings []models.Finding
	var totalFilesScanned int
	var totalLinesScanned int
	var scanType string
	var scanTarget string

	if opts.ScanStaged {
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
	} else if opts.ScanHistory {
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
		scanTarget = opts.TargetDirectory
		matcher := config.LoadIgnoreMatcher(opts.TargetDirectory)

		stat, err := os.Stat(opts.TargetDirectory)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Target path error: %v\n", err)
			os.Exit(2)
		}

		if !stat.IsDir() {
			fileFindings, lines, err := engine.ScanFileWithStats(opts.TargetDirectory)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[Aegis Error] File scan error: %v\n", err)
				os.Exit(2)
			}
			totalFilesScanned = 1
			totalLinesScanned = lines
			findings = fileFindings
		} else {
			err = filepath.Walk(opts.TargetDirectory, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}

				if info.IsDir() {
					if matcher.ShouldIgnore(path) && path != opts.TargetDirectory {
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
	if opts.Verify && len(findings) > 0 {
		registry := validator.NewRegistry()
		defer registry.Close()
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
	if strings.ToLower(opts.Format) == "json" {
		if err := reporter.WriteJSONReport(report, opts.OutputFile, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Failed to output JSON: %v\n", err)
			os.Exit(2)
		}
	} else {
		reporter.PrintConsoleReport(os.Stdout, report, *noColorFlag)
		if opts.OutputFile != "" {
			_ = reporter.WriteJSONReport(report, opts.OutputFile, ioDiscard{})
		}
	}

	// Deterministic Exit Codes
	threshold := strings.ToUpper(opts.FailOnSeverity)
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
