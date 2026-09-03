# Aegis CLI (`aegis-cli`)

[![Go Version](https://img.shields.io/badge/go-1.27+-00ADD8.svg)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zero Dependency](https://img.shields.io/badge/dependencies-0-success.svg)](#)
[![Binary Size](https://img.shields.io/badge/binary_size-<15MB-brightgreen.svg)](#)

**Aegis CLI** is a high-performance, zero-dependency, local-first DevSecOps scanning binary written in Go. It operates at the earliest boundary of the software delivery lifecycle—the developer's local Git workspace and CI/CD ephemeral runners.

---

## Core Tenets

1. **Zero Latency Tax:** Hook execution terminates strictly in `<100 ms` for standard commit diffs.
2. **Deterministic Reproducibility:** Local scans and CI/CD runs produce identical byte-for-byte findings hashes.
3. **Zero Runtime Footprint:** Pure Go statically linked binary (`CGO_ENABLED=0`). No Python, Node.js, or external runtimes required.
4. **Actionable Remediation, Not Noise:** Pinpoints blast radius, token classifications, and precise commands or diffs needed to remediate leaks.

---

## Architecture & Layout

```
aegis-cli/
├── cmd/
│   └── aegis/
│       └── main.go           # CLI entrypoint and command dispatcher
├── internal/
│   ├── analyzer/             # Multi-tier scanning engine (DFA, RE2, Shannon entropy)
│   │   ├── engine.go
│   │   ├── entropy.go
│   │   ├── heuristics.go
│   │   └── rules.go
│   ├── config/               # .aegisignore and configuration loading
│   │   ├── ignore.go
│   │   └── settings.go
│   ├── git/                  # Staged diff parsing and pre-commit hook integration
│   │   ├── diff.go
│   │   └── hook.go
│   ├── reporter/             # Actionable console output and CI JSON reports
│   │   ├── console.go
│   │   └── json.go
│   └── validator/            # Zero-privilege active key verification
│       ├── aws.go
│       ├── github.go
│       ├── openai.go
│       ├── stripe.go
│       └── verifier.go
├── pkg/
│   └── models/               # Domain data structures and deterministic hashing
│       ├── finding.go
│       └── finding_test.go
├── .aegisignore
├── .golangci.yml
├── Makefile
└── PRD.md
```

---

## Build & Test

```bash
# Compile stripped, optimized static binary
make build

# Run unit tests with race detection
make test

# Run memory allocation benchmarks
make bench
```
