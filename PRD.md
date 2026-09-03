# Product Requirements Document (PRD)

**Document Title:** Aegis CLI (`aegis-cli`)
**Document Version:** `1.0.0-PROD`
**Target Release:** v1.0.0 Stable (Core Engine)
**Author / Engineering Lead:** Core Engineering Team
**Status:** ✅ Approved for Implementation via Anti-Gravity CLI Agent

---

## 1. Introduction

### 1.1 Executive Summary

`aegis-cli` is a high-performance, zero-dependency, local-first DevSecOps scanning binary written in Go (Golang). It operates at the earliest boundary of the software delivery lifecycle—the developer's local Git workspace and CI/CD ephemeral runners.

Its primary mission is the **deterministic identification, semantic verification, and pre-emptive remediation** of secret credentials, authentication tokens, cryptographic keys, and database connection strings before they reach remote repositories or persistent storage.

By combining linear-time deterministic finite automata (DFA) pattern analysis, Shannon entropy mathematics, Abstract Syntax Tree (AST) context awareness, and zero-privilege active key verification, `aegis-cli` bridges the performance-security tradeoff: **sub-100 millisecond execution times** with an **ultra-low false-positive profile**.

---

### 1.2 System Mission & Core Tenets

| # | Tenet | Definition |
|---|-------|------------|
| 1 | **Zero Latency Tax** | A developer running `git commit` must never feel human-perceptible input latency. Hook execution must strictly terminate in **<100 ms** for standard commit diffs. |
| 2 | **Deterministic Reproducibility** | A scan executed locally on a developer's workstation must produce the exact byte-for-byte findings hash as a scan executed in a GitHub Actions runner or Linux container. |
| 3 | **Zero Runtime Footprint** | Statically linked binary (`CGO_ENABLED=0`). No external interpreters (Node, Python, Ruby), no dynamically loaded shared libraries, and no background daemon processes. |
| 4 | **Actionable Remediation, Not Noise** | Detection without clear remediation breeds developer friction. The CLI must not just flag a line; it must calculate the **blast radius**, classify the token, and provide the command or automated `git diff` required to fix it. |

---

### 1.3 Target Audience & Personas

- 👨‍💻 **The Software Engineer** — Needs an invisible safety net that catches careless copy-pastes into `.env` or configuration files without blocking day-to-day workflow with false alarms on mock data or test hashes.

- 🔐 **The DevSecOps / AppSec Engineer** — Needs a standardized scanning engine deployable across distributed CI/CD pipelines (GitHub Actions, GitLab CI) with predictable exit codes and structured JSON schemas.

- 🧑‍💼 **The Technical Hiring Manager / Senior Auditor** — Evaluates the tool to verify adherence to memory efficiency, systems-level concurrent programming patterns, cryptographic principles, and production-grade engineering standards.

---

## 2. Context

### 2.1 The Modern DevSecOps Threat Vector

In contemporary microservice and cloud-native environments, modern software projects rarely fail due to broken compiler syntax; they fail due to **leaked operational contexts**.

Modern applications rely heavily on external cloud infrastructure (AWS, GCP, Azure), identity layers (Auth0, Clerk), third-party APIs (Stripe, Twilio, OpenAI, Anthropic), and managed datastores (Neon, Supabase, Redis). Developers frequently clone secrets into local configurations for rapid prototyping.

A single errant command:

```sh
git add .
git commit -m "hotfix: connect to prod database"
git push origin main
```

initiates a catastrophic cascade:

1. Public and private commit feeds are monitored by automated scrapers indexing the **GitHub Firehose API** in <15 seconds.
2. Compromised AWS or OpenAI tokens are leveraged **within minutes** to spin up distributed crypto-mining clusters or abuse enterprise LLM quota limits.
3. Standard Git history retains blobs across commits, trees, and reflogs. Merely pushing a subsequent "revert" commit leaves the secret readable in the **Git commit DAG** (Directed Acyclic Graph) **forever**.

---

### 2.2 Operational Environment

`aegis-cli` operates across three decoupled operational surfaces:

| Environment | Surface | Mechanism |
|---|---|---|
| **1** | Local Pre-Commit / Pre-Push | Intercepts files in the staging buffer (`git diff --staged`) prior to commit object creation. |
| **2** | Pull Request Gate (CI/CD) | Evaluates merge base commits (`git diff origin/main...HEAD`) in headless Linux/macOS/Windows runners. |
| **3** | Historical Repository Audit | Performs deep topological traversals across all Git object packs, loose objects, and commit histories. |

---

## 3. Problem Statement

> Current industry tools fail because of deep design compromises. Below are the precise technical problems `aegis-cli` directly solves.

### 3.1 Problem 1: Catastrophic Backtracking and ReDoS Engine Freezes

- **Root Cause:** Naive regex engines (PCRE, Python `re`, JavaScript `RegExp`) use recursive backtracking algorithms with exponential time complexity: **O(2^n)**. When a developer stages a minified JavaScript vendor bundle (`bundle.min.js`), an SVG asset with massive paths, or a compiled binary asset, standard regex patterns containing nested quantifiers cause the CPU to spike to 100%, hanging the terminal indefinitely.

- **Failure Mode:** The developer assumes their terminal has crashed, terminates the process (`Ctrl+C`), and disables the security hook using `git commit --no-verify`.

---

### 3.2 Problem 2: High Shannon Entropy False-Positive Saturation

- **Root Cause:** Many tools run Shannon entropy calculations indiscriminately across every string literal:
  ```
  H(X) = -∑(P(xᵢ) * log₂(P(xᵢ)))
  ```

- **Failure Mode:** Hexadecimal hashes (Git commit SHAs, MD5/SHA256 checksums), UUIDs, base64 CSS assets, lockfiles (`package-lock.json`, `Cargo.lock`), and high-entropy mock data in unit tests (e.g., `const testKey = "fake_stripe_98729384729384"`) trigger high-severity alarms.

- **Operational Impact:** When an engineering team sees more than **10% false positives**, they experience *"alert fatigue"* and universally ignore or uninstall the scanner.

---

### 3.3 Problem 3: The Git DAG Persistence Trap

- **Root Cause:** Git is an append-only, content-addressable object store. Creating a follow-up commit that deletes a secret file only creates a new commit object pointing to a new tree. The underlying blob containing the secret remains intact in the `.git/objects` database and reachable via `git reflogs`.

- **Failure Mode:** Junior and mid-level developers routinely run `git rm .env && git commit -m "remove secret"`, believing the vulnerability is closed. The secret remains **fully exposed** to anyone with read access to the repo or its fork graph.

---

### 3.4 Problem 4: Runtime Dependency Tax

- **Root Cause:** Many security linters are distributed as Python packages or Node.js modules.

- **Failure Mode:** Every developer on an engineering team must maintain identical Python/Node runtimes, global path variables, and package dependencies. In cross-platform teams (macOS Apple Silicon, Ubuntu x86_64, Windows WSL2), environments diverge, hooks fail to execute due to environment variable misconfigurations, and CI setups break.

---

### 3.5 Problem 5: The "Dead Secret" Ambiguity Gap

- **Root Cause:** Standard static analysis cannot determine whether a detected token is an active, live enterprise credential or a dead, revoked key from an old tutorial.

- **Failure Mode:** Security teams burn hundreds of person-hours triaging historical breaches that are actually dead keys, while live production tokens sitting in active branches are ignored due to backlog prioritization.

---

## 4. Architectural Solutions & Technical Specifications

### 4.1 Solution to 3.1: Linear DFA Pattern Matching Engine with Pre-Filter Gates

To eliminate ReDoS and achieve sub-100ms speeds, `aegis-cli` implements a **multi-tier scanning pipeline**:

#### Tier 1: The Fast-Rejection Gatekeeper

1. **Binary Check:** Inspects the first **1,024 bytes** of the target file. If a null byte (`0x00`) is detected, the file is classified as a binary asset and skipped immediately.
2. **Line-Length Threshold:** Lines exceeding **1,200 characters** are bypassed for standard regex and routed to a specialized entropy-only sampling parser. This prevents minified files from blocking the engine.
3. **Known-Prefix Pre-Filter:** Utilizes an in-memory **Aho-Corasick automaton** or fast byte-slice matching for known provider prefixes (`AKIA`, `ghp_`, `sk_live_`, `xoxb-`). If no candidate substring exists on the line, expensive evaluations are aborted.

#### Tier 2: Go `regexp` Guarantee

The engine relies on Go's native standard library `regexp` package, which is built on the **RE2 engine** (DFA/NFA). RE2 guarantees that match execution time scales **linearly** with input size: **O(n)**. It explicitly disallows backreferences and generalized lookaround assertions, eliminating the mathematical possibility of ReDoS freezes.

---

### 4.2 Solution to 3.2: Calibrated Entropy Filtering with Dual-Alphabet Heuristics

Entropy is **never evaluated in isolation**. It is computed only after a string literal candidate passes structural regex criteria.

#### Dual-Alphabet Segmentation

| Alphabet | Target Credentials | Min Length | Entropy Threshold |
|---|---|---|---|
| Hexadecimal `[0-9a-fA-F]` | Git hashes, AWS Secret Keys, API secrets | 32 chars | ≥ 3.0 |
| Base64 `[a-zA-Z0-9+/=]` | Private keys, JWT fragments, Slack tokens | 20 chars | ≥ 4.5 |
| Alpha-Numeric-Punctuation | Complex database passwords | 16 chars | ≥ 4.7 |

#### False-Positive Pruning Rules

1. **Variable Name Semantics:** If the variable name or assignment key contains substrings such as `test`, `mock`, `dummy`, `example`, `placeholder`, or `sample`, the finding is marked with low confidence and suppressed from blocking exit codes.
2. **Sequential/Low Variance Elimination:** Strings with repeating or sequential character distributions are discarded before entropy calculation.
3. **Ignore Directives:** Explicit inline comments are honored (e.g. `// aegis:ignore`).

---

### 4.3 Solution to 3.3: Native Git DAG Ingestion & Tree Traversals

1. **Staged Diff Parser** (`aegis scan --staged`): Reads directly from `git diff --cached --no-color -U0`. Parses unified diff hunks (`+` lines only) so that existing code is not flagged.
2. **Direct DAG Object Storage Traversal** (`aegis scan --history`): Traverses `.git/objects/pack/*.pack` files directly using pure Go Git primitives.

---

### 4.4 Solution to 3.4: Zero-Dependency Architecture & Distribution

1. **Static Compilation:** Built using pure Go (`CGO_ENABLED=0`) targeting Linux, macOS, and Windows.
2. **Distribution Mechanisms:** Automated cross-compilation pipeline using **GoReleaser** via GitHub Actions. Binary sizes strictly constrained to **<15 MB**.

---

### 4.5 Solution to 3.5: Zero-Privilege Active Verifier Interface

Read-only validation pings to verify active credentials — all requests enforce a hard **1.5-second timeout** and are gated behind an explicit opt-in flag (`--verify`):

| Provider | Verification Call | Method |
|---|---|---|
| **AWS Access Key** | `AWS STS GetCallerIdentity` | Zero parameters. Non-destructive. |
| **Stripe Secret Key** | `GET /v1/balance` | Bearer token authentication. |
| **GitHub PAT** | `GET /user` | Token header authentication. |
| **OpenAI API Key** | `GET /v1/models` | Bearer token authentication. |

---

## 5. Technical Specifications & File Layout

### 5.1 Command-Line Interface (CLI) Contract

```sh
aegis scan [path] [flags]                      # Scan a path
aegis scan --staged                             # Scan staged changes (pre-commit)
aegis scan --history                            # Deep historical DAG audit
aegis hook install                              # Install Git pre-commit hook
aegis hook uninstall                            # Remove Git pre-commit hook
aegis scan --staged --verify                    # Scan staged + active verification
aegis scan --format=json --output=report.json   # JSON report output
```

---

### 5.2 Deterministic Exit Codes

| Code | Meaning |
|---|---|
| `0` | ✅ Success — No secrets detected |
| `1` | 🚨 Critical Secrets Detected |
| `2` | ⚠️ Configuration / System Error |

---

### 5.3 Concrete File & Package Structure

```
aegis-cli/
├── cmd/
│   └── aegis/
│       └── main.go
├── internal/
│   ├── analyzer/
│   │   ├── engine.go
│   │   ├── entropy.go
│   │   ├── heuristics.go
│   │   └── rules.go
│   ├── config/
│   │   ├── ignore.go
│   │   └── settings.go
│   ├── git/
│   │   ├── diff.go
│   │   └── hook.go
│   ├── reporter/
│   │   ├── console.go
│   │   └── json.go
│   └── validator/
│       ├── aws.go
│       ├── github.go
│       ├── openai.go
│       ├── stripe.go
│       └── verifier.go
├── pkg/
│   └── models/
│       └── finding.go
├── .aegisignore
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

---

## 6. Risks, Edge Cases & Mitigation Strategies

| Risk | Mitigation |
|---|---|
| **Git Hook Bypass** (`git commit --no-verify`) | Paired with CI/CD PR gates as a secondary enforcement layer. |
| **Air-Gapped Networks** | Active verification is strictly opt-in via `--verify`; no network calls by default. |
| **Massive Repositories** | Worker pool pattern with bounded concurrency using `runtime.NumCPU()`. Files >25 MB are skipped automatically. |
| **Rate-Limiting** | Internal validator caps outbound HTTP calls to **3 req/sec** with exponential backoff. |

---

## 7. Future Scope *(Planned for v2.0 Platform Integration)*

- 🔄 **Automated Vault Synchronization** — AWS Secrets Manager / HashiCorp Vault integration.
- 🛠️ **Interactive Git DAG Rewriting** — via `git-filter-repo` wrapper.
- 📡 **Decentralized Cloud Dashboard** — Telemetry stream to platform backend.

---

## 8. Conclusion & Immediate Execution Steps

| Step | Action |
|---|---|
| **1** | **Repository Initialization:** `go mod init aegis-cli` |
| **2** | **Scaffold Shared Models:** `pkg/models/finding.go` |
| **3** | **Core Engine Construction:** `internal/analyzer/entropy.go` and `rules.go` |
| **4** | **Git Staging Ingestion:** `internal/git/diff.go` |
| **5** | **Entrypoint Assembly:** `cmd/aegis/main.go` |
| **6** | **Benchmark Validation:** Verify execution latency remains **<100 ms** |
