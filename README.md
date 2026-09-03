# Aegis CLI (`aegis-cli`)

[![Go Version](https://img.shields.io/badge/go-1.27+-00ADD8.svg)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zero Dependency](https://img.shields.io/badge/dependencies-0-success.svg)](#)
[![Binary Size](https://img.shields.io/badge/binary_size-6.9MB-brightgreen.svg)](#)
[![Scan Latency](https://img.shields.io/badge/hook_latency-<10ms-brightgreen.svg)](#)

**Aegis CLI** is an ultra-fast, zero-dependency, local-first DevSecOps scanning binary written in Go. Operating at the earliest boundary of the software delivery lifecycle—the developer's local Git workspace and CI/CD ephemeral runners—Aegis prevents credential leaks before commits or pushes leave developer workstations.

---

## ⚡ Core Tenets & Performance

1. **Zero Latency Tax**: Pre-commit hook evaluation terminates in **<10 ms** on staged diffs (benchmarked at ~0.048 ms per line).
2. **Deterministic Reproducibility**: Computes deterministic SHA-256 finding and report hashes for byte-for-byte reproducibility across local machines and CI.
3. **Zero Runtime Footprint**: Single statically linked binary (`CGO_ENABLED=0`, ~6.9MB). No Python, Node.js, Docker, or external daemons required.
4. **Zero-Privilege Active Verification**: Safely tests suspected credentials against provider read-only endpoints with strict structural determinism (generic passwords are never exfiltrated).
5. **Actionable Blast Radius & Remediation**: Every detected leak provides immediate impact analysis and exact terminal commands to revoke and rotate credentials.

---

## 🛡️ Supported Providers & Signatures

Aegis identifies over 20+ production service credentials and frontier AI API keys:

| Category | Provider / Pattern | Verified Endpoints |
| :--- | :--- | :--- |
| **Frontier AI** | OpenAI, Anthropic Claude, Google Gemini / AI Studio, xAI Grok, DeepSeek, Perplexity AI, Groq LPU | ✅ Live active ping |
| **Cloud & DevOps** | AWS (IAM / Secret Keys), GCP, DigitalOcean, GitLab, GitHub (Classic & Fine-Grained), NPM | ✅ Live active ping |
| **Messaging & Mail** | SendGrid, Resend, Twilio, Discord Bot Tokens, Slack Webhook / Bot | ✅ Live active ping |
| **Database & Auth** | Supabase, PostgreSQL, MySQL, MongoDB, Redis Connection URIs | ✅ Format validation |
| **Cryptographic** | RSA, EC, DSA, OpenSSH Private Keys, Generic High-Entropy Assignments | ✅ Dual-alphabet entropy |

---

## 🚀 Quick Start

### Installation

Choose any of the three simple methods below:

#### Method 1: Universal One-Line Installer (Linux / macOS / WSL)
```bash
curl -fsSL https://aegis.ilyankhan.tech | bash
```

#### Method 2: Via Go (for Go developers)
```bash
go install github.com/Ilyan321/aegis-cli/cmd/aegis@latest
```

#### Method 3: Build & Install from Source
```bash
git clone https://github.com/Ilyan321/aegis-cli.git
cd aegis-cli
make install
```

### Repository Protection Setup

Initialize protection inside any Git repository with a single command:

```bash
# Initialize Aegis: installs pre-commit hook and generates starter .aegisignore
aegis init

# Check repository protection and staged security status
aegis status

# Remove pre-commit protection
aegis uninit
```

---

## 📖 CLI Usage & Workflows

### 1. Scan Current Repository (or Subfolder)
```bash
# Scan working directory (defaults to current directory)
aegis scan

# Scan specific file or subdirectory
aegis scan src/config/
```

### 2. Scan Staged Git Buffer (Pre-Commit Mode)
Evaluates newly added or modified lines in the Git index before committing:
```bash
aegis staged
# With live active verification:
aegis staged --verify
```

### 3. Deep Historical Audit
Audit the entire Git commit DAG history across all past commits:
```bash
aegis audit history
```

### 4. Instant String Inspector
Test any token or suspicious string directly in your terminal without creating a file:
```bash
aegis check "ghp_111122223333444455556666777788889999"
```

### 5. Structured CI/CD JSON Output
Generate machine-readable reports for SARIF converters or CI/CD pipelines:
```bash
# Output JSON to stdout
aegis scan --format=json

# Write JSON report to disk
aegis scan --format=json --output=aegis-report.json
```

### 6. Shell Tab Autocompletion
Generate tab completion for your preferred shell:
```bash
# Bash (add to ~/.bashrc)
source <(aegis completion bash)

# Zsh (add to ~/.zshrc)
source <(aegis completion zsh)

# Fish (add to ~/.config/fish/completions/aegis.fish)
aegis completion fish > ~/.config/fish/completions/aegis.fish
```

---

## 🚦 Deterministic Exit Codes

Aegis follows strict POSIX exit code conventions designed for zero false-alarm pipeline breaks:

| Exit Code | Meaning | Behavior |
| :---: | :--- | :--- |
| **`0`** | **Scan Passed** | No secrets found, or only low-confidence test/mock fixtures detected. |
| **`1`** | **Leak Detected** | Critical or High severity secrets detected on non-test files. |
| **`2`** | **System Error** | Configuration error, invalid CLI flags, or file system permission failure. |

---

## 🧪 Benchmark & Verification Suite

Aegis includes an extensive automated test suite with race condition detection and micro-benchmarks:

```bash
# Run unit tests with race detection
make test

# Run micro-benchmarks
make bench

# Strict dead-code and static analysis
make lint
```

### Benchmark Results (Intel Core i5-10210U @ 1.60GHz)
* **Single Line Scan**: `~48,591 ns/op` (**0.048 ms**)
* **5,000-char Minified Bundle Line**: `~68,895 ns/op` (**0.068 ms**)
* **Staged Commit Buffer**: `< 6 ms`
* **Static Binary Size**: **6.9 MB**

---

## ⚙️ Configuration (`.aegisignore`)

Aegis respects `.aegisignore` files at repository root. You can also suppress specific false positives inline:

```go
// Suppress a test token in source code
const apiKey = "AKIAIOSFODNN7EXAMPLE" // aegis:ignore
```

---

## 📜 License

Distributed under the MIT License.
