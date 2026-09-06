package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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

	case "completion":
		runCompletionCommand(os.Args[2:])

	case "login":
		runLoginCommand(os.Args[2:])

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
	fmt.Println("  aegis completion [shell]      Generate shell tab autocompletion (bash, zsh, fish)")
	fmt.Println("  aegis login                   Authenticate CLI with Aegis Platform dashboard")
	fmt.Println("  aegis uninit                  Remove Aegis pre-commit protection from current repository")
	fmt.Println("  aegis version                 Print version information")
	fmt.Println("\nAdvanced Flags for 'scan' / 'staged' / 'audit':")
	fmt.Println("  --sync                        Stream and publish scan findings to Aegis Platform dashboard")
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

	fmt.Printf("[Aegis] Initializing in %s...\n", cwd)

	hooksDir, hookErr := git.GetGitHooksDir()
	if hookErr != nil {
		fmt.Fprintf(os.Stderr, "  [WARN] Not a git repository (run 'git init' first to enable pre-commit protection)\n")
	} else {
		if err := git.InstallHook(hooksDir); err != nil {
			fmt.Fprintf(os.Stderr, "  [ERROR] Failed to install git pre-commit hook: %v\n", err)
			os.Exit(2)
		}
		fmt.Println("  [OK] Installed git pre-commit hook (.git/hooks/pre-commit)")
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
			fmt.Println("  [OK] Created starter .aegisignore file")
		}
	} else {
		fmt.Println("  [INFO] Existing .aegisignore preserved")
	}

	if hookErr == nil {
		fmt.Println("\n[Aegis] Repository protection enabled. Pre-commit hook active.")
	} else {
		fmt.Println("\n[Aegis] Starter configuration ready. Run 'git init' followed by 'aegis init' to activate pre-commit scanning.")
	}
	os.Exit(0)
}

func runUninitCommand() {
	hooksDir, err := git.GetGitHooksDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(2)
	}

	if err := git.UninstallHook(hooksDir); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to remove pre-commit hook: %v\n", err)
		os.Exit(2)
	}

	fmt.Println("[Aegis] Pre-commit hook uninstalled successfully.")
	os.Exit(0)
}

func runStatusCommand() {
	fmt.Println("[Aegis] Repository Status")
	fmt.Println("----------------------------------------")

	// Hook status
	hooksDir, err := git.GetGitHooksDir()
	if err == nil {
		hookPath := filepath.Join(hooksDir, "pre-commit")
		content, readErr := os.ReadFile(hookPath)
		if readErr == nil && strings.Contains(string(content), git.AegisHookMarker) {
			fmt.Println("  Git Pre-Commit Hook:  Active (.git/hooks/pre-commit)")
		} else {
			fmt.Println("  Git Pre-Commit Hook:  Not installed (run 'aegis init' to activate)")
		}
	} else {
		fmt.Println("  Git Repository:       Not inside a git repository")
	}

	// Ignore file status
	if _, err := os.Stat(".aegisignore"); err == nil {
		fmt.Println("  Ignore Rules:         Configured (.aegisignore)")
	} else {
		fmt.Println("  Ignore Rules:         Using standard defaults (.aegisignore missing)")
	}

	// Quick staged buffer inspection (only inside git repository)
	if err == nil {
		engine := analyzer.NewEngine()
		stagedFindings, _, _, err := git.ScanStagedWithStats(engine)
		if err == nil {
			if len(stagedFindings) == 0 {
				fmt.Println("  Staged Git Buffer:    Clean (0 secrets staged)")
			} else {
				fmt.Printf("  Staged Git Buffer:    LEAK DETECTED (%d secret(s) found! Run 'aegis staged' for details)\n", len(stagedFindings))
			}
		}
	}

	fmt.Println("----------------------------------------")
	os.Exit(0)
}

func runCheckCommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: aegis check \"<string_to_inspect>\" [--verify] [--no-color] [--format=json]\n")
		os.Exit(2)
	}

	verify := false
	noColor := false
	format := "console"
	var tokenInput string

	for _, arg := range args {
		if arg == "--verify" || arg == "-v" {
			verify = true
		} else if arg == "--no-color" {
			noColor = true
		} else if arg == "--format=json" || arg == "-format=json" {
			format = "json"
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
		if format == "json" {
			report := &models.ScanReport{
				Version:           Version,
				ScanTarget:        "Terminal Input String",
				ScanType:          "check",
				Timestamp:         time.Now(),
				TotalFilesScanned: 1,
				TotalLinesScanned: 1,
				Findings:          make([]models.Finding, 0),
			}
			_ = reporter.WriteJSONReport(report, "", os.Stdout)
		} else {
			fmt.Println("\n[OK] No secret pattern or high-entropy credential detected in input.")
		}
		os.Exit(0)
	}

	if verify {
		registry := validator.NewRegistry()
		defer registry.Close()
		findings = registry.VerifyAll(context.Background(), findings)
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	activeLeaks := 0
	blockingCount := 0

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
		if f.Confidence != models.ConfidenceLow {
			blockingCount++
		}
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
		CriticalCount:     criticalCount,
		HighCount:         highCount,
		MediumCount:       mediumCount,
		LowCount:          lowCount,
		ActiveLeaksCount:  activeLeaks,
		Findings:          findings,
		FindingsHash:      models.ComputeReportHash(findings),
	}

	if format == "json" {
		_ = reporter.WriteJSONReport(report, "", os.Stdout)
	} else {
		reporter.PrintConsoleReport(os.Stdout, report, noColor)
	}

	if blockingCount > 0 {
		os.Exit(1)
	}
	os.Exit(0)
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
		fmt.Printf("[OK] Pre-commit hook installed successfully in %s\n", hooksDir)
		os.Exit(0)

	case "uninstall":
		if err := git.UninstallHook(hooksDir); err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Failed to uninstall hook: %v\n", err)
			os.Exit(2)
		}
		fmt.Println("[OK] Pre-commit hook removed successfully.")
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "Unknown hook action: %s. Expected 'install' or 'uninstall'.\n", action)
		os.Exit(2)
	}
}

func rearrangeArgs(args []string) []string {
	var flags []string
	var positionals []string

	flagWithArg := map[string]bool{
		"range": true, "-range": true,
		"format": true, "-format": true,
		"output": true, "-output": true,
		"fail-on": true, "-fail-on": true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			flagName := strings.TrimLeft(arg, "-")
			if flagWithArg[flagName] && !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
		} else {
			positionals = append(positionals, arg)
		}
	}
	return append(flags, positionals...)
}

func runScanCommand(args []string) {
	args = rearrangeArgs(args)

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)

	stagedFlag := fs.Bool("staged", false, "Scan staged changes in git index")
	historyFlag := fs.Bool("history", false, "Scan full git DAG commit history")
	rangeFlag := fs.String("range", "", "Scan git diff range e.g. origin/main...HEAD")
	verifyFlag := fs.Bool("verify", false, "Perform live zero-privilege token verification")
	formatFlag := fs.String("format", "console", "Output report format (console or json)")
	outputFlag := fs.String("output", "", "Output file path for report")
	failOnFlag := fs.String("fail-on", "critical", "Failure threshold for exit code: critical, high, medium, low")
	noColorFlag := fs.Bool("no-color", false, "Disable color output")
	syncFlag := fs.Bool("sync", false, "Sync and stream scan findings to Aegis Platform dashboard")

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

	findings := make([]models.Finding, 0)
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
		historyFindings, filesCount, linesCount, err := git.ScanHistoryWithStats(engine)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[Aegis Error] Failed to scan git history: %v\n", err)
			os.Exit(2)
		}
		findings = historyFindings
		totalFilesScanned = filesCount
		totalLinesScanned = linesCount
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
			var filesToScan []string
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

				filesToScan = append(filesToScan, path)
				return nil
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "[Aegis Error] Directory traversal error: %v\n", err)
				os.Exit(2)
			}

			// Bounded worker pool concurrency using runtime.NumCPU() (PRD Section 6)
			numWorkers := runtime.NumCPU()
			if numWorkers < 1 {
				numWorkers = 1
			}
			if numWorkers > len(filesToScan) && len(filesToScan) > 0 {
				numWorkers = len(filesToScan)
			}

			jobs := make(chan string, len(filesToScan))
			for _, file := range filesToScan {
				jobs <- file
			}
			close(jobs)

			var wg sync.WaitGroup
			var mu sync.Mutex

			for w := 0; w < numWorkers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for path := range jobs {
						fileFindings, lines, err := engine.ScanFileWithStats(path)
						if err == nil {
							mu.Lock()
							totalFilesScanned++
							totalLinesScanned += lines
							if len(fileFindings) > 0 {
								findings = append(findings, fileFindings...)
							}
							mu.Unlock()
						}
					}
				}()
			}
			wg.Wait()
		}
	}

	// Active Verification (Opt-In)
	if opts.Verify && len(findings) > 0 {
		registry := validator.NewRegistry()
		defer registry.Close()
		findings = registry.VerifyAll(context.Background(), findings)
	}

	if findings == nil {
		findings = make([]models.Finding, 0)
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

	// Cloud Dashboard Sync (Optional)
	if *syncFlag {
		if strings.ToLower(opts.Format) != "json" {
			fmt.Println("\n[Aegis Cloud] Streaming findings to Aegis Platform Control Plane...")
		}
		scanID, syncErr := config.SyncReportToPlatform(report, targetPath)
		if strings.ToLower(opts.Format) != "json" {
			if syncErr != nil {
				fmt.Fprintf(os.Stderr, "  [WARN] Cloud sync failed: %v\n", syncErr)
			} else {
				fmt.Printf("  [OK] Scan synchronized to dashboard (Scan ID: %s)\n", scanID)
			}
		}
	}

	// Deterministic Exit Codes
	threshold := strings.ToUpper(strings.TrimSpace(opts.FailOnSeverity))
	blockingCount := 0
	for _, f := range findings {
		if f.Confidence == models.ConfidenceLow {
			continue // Non-blocking false-alarm suppression (PRD Section 4.2)
		}

		switch threshold {
		case "LOW":
			blockingCount++
		case "MED", "MEDIUM":
			if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh || f.Severity == models.SeverityMedium {
				blockingCount++
			}
		case "HIGH":
			if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh {
				blockingCount++
			}
		case "CRIT", "CRITICAL":
			if f.Severity == models.SeverityCritical {
				blockingCount++
			}
		default:
			if f.Severity == models.SeverityCritical {
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

func runCompletionCommand(args []string) {
	shell := "bash"
	if len(args) > 0 {
		shell = strings.ToLower(args[0])
	}

	switch shell {
	case "bash":
		fmt.Print(`# bash completion for aegis
_aegis_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    commands="init scan staged audit check status uninit version completion hook"
    flags="--staged --history --range= --verify --format= --output= --fail-on= --no-color -v --help"

    if [[ ${COMP_CWORD} -eq 1 ]] ; then
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
        return 0
    fi

    case "${prev}" in
        audit)
            COMPREPLY=( $(compgen -W "history" -- ${cur}) )
            return 0
            ;;
        hook)
            COMPREPLY=( $(compgen -W "install uninstall" -- ${cur}) )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- ${cur}) )
            return 0
            ;;
        --format)
            COMPREPLY=( $(compgen -W "console json" -- ${cur}) )
            return 0
            ;;
        --fail-on)
            COMPREPLY=( $(compgen -W "critical high medium low" -- ${cur}) )
            return 0
            ;;
        *)
            COMPREPLY=( $(compgen -W "${flags}" -- ${cur}) )
            return 0
            ;;
    esac
}
complete -F _aegis_completions aegis
`)
	case "zsh":
		fmt.Print(`#compdef aegis

_aegis() {
    local -a commands
    commands=(
        'init:Initialize Aegis pre-commit hook and .aegisignore'
        'scan:Scan workspace or directory for secret leaks'
        'staged:Scan staged changes in git index'
        'audit:Deep-audit full git commit DAG history'
        'check:Inspect a raw secret string or token'
        'status:Show repository protection status'
        'uninit:Remove Aegis pre-commit hook'
        'version:Print version information'
        'completion:Generate shell autocompletion script'
    )

    if (( CURRENT == 2 )); then
        _describe -t commands 'aegis command' commands
    else
        case "$words[2]" in
            audit)
                _values 'audit target' 'history[Deep-audit git commit DAG history]'
                ;;
            hook)
                _values 'hook action' 'install[Install pre-commit hook]' 'uninstall[Remove pre-commit hook]'
                ;;
            completion)
                _values 'shell' 'bash' 'zsh' 'fish'
                ;;
            *)
                _arguments \
                    '--staged[Scan git staging buffer]' \
                    '--history[Scan git DAG commit history]' \
                    '--verify[Actively verify candidate tokens]' \
                    '--format=[Output report format]:format:(console json)' \
                    '--fail-on=[Failure threshold]:severity:(critical high medium low)' \
                    '--output=[Write report to file]:file:_files' \
                    '--no-color[Disable ANSI colors]'
                ;;
        esac
    fi
}

_aegis "$@"
`)
	case "fish":
		fmt.Print(`# fish completion for aegis
complete -c aegis -f -n '__fish_use_subcommand' -a init -d 'Initialize Aegis pre-commit hook'
complete -c aegis -f -n '__fish_use_subcommand' -a scan -d 'Scan directory or repository'
complete -c aegis -f -n '__fish_use_subcommand' -a staged -d 'Scan staged git changes'
complete -c aegis -f -n '__fish_use_subcommand' -a audit -d 'Audit git commit DAG history'
complete -c aegis -f -n '__fish_use_subcommand' -a check -d 'Inspect a candidate token string'
complete -c aegis -f -n '__fish_use_subcommand' -a status -d 'Show repository security status'
complete -c aegis -f -n '__fish_use_subcommand' -a uninit -d 'Remove pre-commit hook'
complete -c aegis -f -n '__fish_use_subcommand' -a version -d 'Print version information'
complete -c aegis -f -n '__fish_use_subcommand' -a completion -d 'Generate shell completion script'
`)
	default:
		fmt.Fprintf(os.Stderr, "Unsupported shell '%s'. Supported shells: bash, zsh, fish\n", shell)
		os.Exit(2)
	}
	os.Exit(0)
}

func runLoginCommand(args []string) {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	tokenFlag := fs.String("token", "", "Aegis platform personal access token")
	apiURLFlag := fs.String("api-url", "", "Custom Aegis API base URL")

	_ = fs.Parse(args)

	token := *tokenFlag
	apiURL := *apiURLFlag
	if apiURL == "" {
		apiURL = os.Getenv("AEGIS_API_URL")
		if apiURL == "" {
			apiURL = config.DefaultPlatformURL
		}
	}
	apiURL = strings.TrimRight(apiURL, "/")

	if token == "" {
		fmt.Printf("[Aegis Login] Connect your terminal to Aegis Platform (%s)\n", apiURL)
		fmt.Println("Generate your CLI token from the web console under Profile -> CLI Authentication.")
		fmt.Print("Enter CLI Token: ")
		_, _ = fmt.Scanln(&token)
		token = strings.TrimSpace(token)
	}

	if token == "" {
		fmt.Fprintf(os.Stderr, "[ERROR] No token provided. Login aborted.\n")
		os.Exit(2)
	}

	// Validate token with GET /api/v1/auth/me
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/auth/me", apiURL), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Invalid request: %v\n", err)
		os.Exit(2)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to reach Aegis API (%s): %v\n", apiURL, err)
		os.Exit(2)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "[ERROR] Authentication failed (HTTP %d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var user struct {
		Email    string `json:"email"`
		FullName string `json:"full_name"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&user)

	cfg := &config.CloudConfig{
		APIURL:    apiURL,
		APIToken:  token,
		UserEmail: user.Email,
	}
	if err := config.SaveCloudConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to save config: %v\n", err)
		os.Exit(2)
	}

	path, _ := config.GetConfigPath()
	fmt.Printf("\n[OK] Authenticated successfully as %s\n", user.Email)
	fmt.Printf("     Credentials stored in %s\n", path)
	fmt.Println("     Run 'aegis scan --sync' to stream findings to your workspace dashboard.")
	os.Exit(0)
}

