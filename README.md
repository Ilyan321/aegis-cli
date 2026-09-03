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

```bash
# Clone and build
git clone https://github.com/Ilyan321/aegis-cli.git
cd aegis-cli
make build

# Install binary to system path
sudo cp bin/aegis /usr/local/bin/
```

### Git Pre-Commit Hook Setup

Install native pre-commit hook protection into your current repository with a single command:

```bash
# Install pre-commit hook (automatically backs up existing hooks)
aegis hook install

# Remove pre-commit hook (automatically restores previous backup)
aegis hook uninstall
```

---

## 📖 CLI Usage & Commands

### 1. Scan Current Directory or Specific Path
```bash
# Scan working directory
aegis scan .

# Scan specific file or subdirectory
aegis scan src/config/
```

### 2. Scan Staged Git Buffer (Pre-Commit Mode)
Evaluates newly added or modified lines in the Git index before committing:
```bash
aegis scan --staged
```

### 3. Scan Entire Git Commit DAG History
Streams objects directly from git revision trees via streaming pipes:
```bash
aegis scan --history
```

### 4. Opt-In Live Active Verification
Ping provider APIs with zero-privilege non-destructive calls:
```bash
aegis scan --staged --verify
```

### 5. Structured CI/CD JSON Output
Generate machine-readable reports for SARIF converters or CI pipelines:
```bash
# Output JSON to stdout
aegis scan --format=json

# Write JSON report to disk
aegis scan --format=json --output=aegis-report.json
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
