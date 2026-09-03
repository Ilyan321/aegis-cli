package main

import (
	"fmt"
	"os"
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
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v" || os.Args[1] == "version") {
		fmt.Printf("aegis-cli version %s\n", Version)
		os.Exit(0)
	}

	if len(os.Args) > 1 && (os.Args[1] == "--help" || os.Args[1] == "-h" || os.Args[1] == "help") {
		fmt.Printf(Banner, Version)
		fmt.Println("\nUsage:")
		fmt.Println("  aegis scan [path] [flags]     Scan path for secret leaks")
		fmt.Println("  aegis scan --staged           Scan staged git changes (pre-commit)")
		fmt.Println("  aegis scan --history          Scan deep git DAG commit history")
		fmt.Println("  aegis hook install            Install git pre-commit hook")
		fmt.Println("  aegis hook uninstall          Remove git pre-commit hook")
		fmt.Println("  aegis version                 Print version information")
		os.Exit(0)
	}

	fmt.Printf(Banner, Version)
	fmt.Println("\nRun 'aegis --help' for available commands.")
}
