# Aegis CLI (`aegis-cli`) — Platform Integration Specification

> **Audience:** AI Agents, backend services, and platform engineers developing the **Aegis Platform** (cloud dashboard, policy engine, and centralized DevSecOps orchestrator).
>
> **Purpose:** This document provides the complete interface specification, architectural boundaries, data contract (JSON schema), exit codes, and operational behavior of `aegis-cli` so the Aegis Platform can seamlessly invoke, orchestrate, and ingest data from the CLI.

---

## 1. Executive Summary & Ecosystem Role

`aegis-cli` is an ultra-fast, zero-dependency, local-first credential security scanner written in pure Go (standard library only).

Within the larger **Aegis Ecosystem**:
* **`aegis-cli` (The Edge / Local Agent):** Runs on developer workstations (Git pre-commit hooks), local terminals, and ephemeral CI/CD pipelines (GitHub Actions, GitLab CI). It intercepts secrets at the source *before* code is pushed.
* **Aegis Platform (The Central Hub):** Aggregates findings, tracks secret lifecycles across repositories, coordinates automated rotation/revocation, manages organization-wide policies, and displays security posture dashboards.

```
+-------------------------------------------------------------+
|                     DEVELOPER / WORKSTATION                 |
|  git commit -> [ aegis pre-commit hook ] (<10ms)           |
|  terminal   -> [ aegis scan / check / audit ]               |
+------------------------------+------------------------------+
                               |
                               | (JSON Report / Exit Code)
                               v
+-------------------------------------------------------------+
|                      CI/CD RUNNER                           |
|  [ aegis scan --format=json --verify ]                     |
+------------------------------+------------------------------+
                               |
                               | Ingests JSON Payload
                               v
+-------------------------------------------------------------+
|                     AEGIS PLATFORM                          |
|  * Findings Database & Deduplication (findings_hash, id)     |
|  * Live Leak Alerts (Slack, PagerDuty, Webhooks)            |
|  * Automated Remediation & Rotation Playbooks               |
|  * Compliance & Audit Dashboard (SOC2, ISO27001)            |
+-------------------------------------------------------------+
```

---

## 2. Core Operational Guarantees

When designing the platform or instructing an AI agent to build platform integrations, rely on these strict guarantees:

1. **Zero Runtime Dependencies:**
   * Single static binary (`CGO_ENABLED=0`, ~7MB).
   * Requires no runtime daemons, Docker, Node.js, or Python.
2. **Sub-100ms Execution:**
   * Line scanning latency is ~0.05ms per line.
   * Git staged index evaluation finishes in <10ms.
   * Minified asset scanning bounded via prefix windows (~0.11ms for 10KB+ lines).
3. **Privacy & Zero Secret Exfiltration:**
   * **Raw secrets are NEVER written to disk, output to JSON, or exposed in standard reports.**
   * Secrets are masked preserving only the first 4 characters (e.g., `AKIA****************`).
   * Generic passwords and connection strings are **strictly excluded** from external network calls.
4. **Zero-Privilege Active Verification:**
   * When `--verify` is enabled, only known provider credentials (AWS STS, Stripe, GitHub, OpenAI, Gemini, etc.) undergo read-only ping requests.
   * Requests use an internal rate limiter (3 req/sec) and a hard 1.5s network timeout.
5. **Deterministic Hashing & Idempotency:**
   * Individual findings compute a deterministic SHA-256 hash: `SHA256(filepath:lineno:ruleid:rawsecret)`.
   * Normalized relative paths (`/` separators, stripped `./`) ensure identical findings produce identical hashes on Windows, macOS, and Linux.
   * Reports produce a sorted, order-independent `findings_hash`.

---

## 3. CLI Command Matrix

| Command | Usage | Platform Ingestion Use-Case |
| :--- | :--- | :--- |
| `aegis scan [path]` | Scans files/directories recursively | Scans uploaded repositories or workspace archives |
| `aegis scan --staged` | Evaluates Git staging index | Pre-commit check or local developer tooling |
| `aegis scan --range=A..B` | Scans commit range diff | PR / Merge Request delta analysis in CI runners |
| `aegis scan --history` | Scans full reachable Git DAG blobs | Deep repository onboarding & history audits |
| `aegis check "<string>"` | Evaluates raw text from arg or stdin | Ephemeral token verification, API gateway scanning |
| `aegis status` | Inspects hook status & staged buffer | Health checks and developer environment diagnostics |
| `aegis hook install` | Installs Git pre-commit hook | Workstation onboarding scripts |
| `aegis completion [shell]` | Outputs shell autocompletion script | Developer developer experience |

### Key Flags for Platform Orchestration

* `--format=json`: Emits strict, parseable JSON report to stdout (or `--output=path.json`).
* `--verify`: Enables live token verification against provider endpoints.
* `--fail-on=CRITICAL|HIGH|MED|LOW`: Sets exit code threshold. Defaults to `LOW` (fails on any finding).
* `--no-color`: Disables ANSI escape sequences (recommended for machine logs).
* `--concurrency=N`: Bounds worker pool concurrency (defaults to `runtime.NumCPU()`).

---

## 4. Exit Code Contract

Your platform ingestion workers, background runners, and CI checks should inspect exit codes as follows:

| Exit Code | Meaning | Platform Action |
| :--- | :--- | :--- |
| **`0`** | **Clean / Passed** | No policy-violating secrets found. Allow pipeline / commit to proceed. |
| **`1`** | **Security Violation** | Active or unmitigated secrets detected meeting or exceeding `--fail-on`. Block pipeline / PR and create findings incident in platform. |
| **`2`** | **Runtime / System Error** | Execution failed due to invalid arguments, missing Git repository, unreadable files, or fatal OS error. |

---

## 5. Machine-Readable Data Contract (JSON Schema)

When invoked with `--format=json`, `aegis-cli` returns the following payload:

### 5.1 Scan Report Structure

```json
{
  "version": "1.0.0",
  "scan_target": ".",
  "scan_type": "path",
  "timestamp": "2026-09-05T19:38:56.771598961+05:00",
  "duration_ms": 15,
  "total_files_scanned": 40,
  "total_lines_scanned": 5295,
  "total_findings": 1,
  "critical_count": 1,
  "high_count": 0,
  "medium_count": 0,
  "low_count": 0,
  "active_leaks_count": 1,
  "findings": [
    {
      "id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "rule_id": "AEGIS-STRIPE-001",
      "category": "Stripe",
      "title": "Stripe Live Secret Key",
      "description": "Live secret key for Stripe payment gateway API",
      "file_path": "backend/config.py",
      "line_number": 42,
      "masked_value": "sk_l********************",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "verification": {
        "status": "ACTIVE",
        "verified_at": "2026-09-05T19:38:56.800000000Z",
        "details": "Authenticated as Stripe account acct_12345 (balance checked)"
      }
    }
  ],
  "findings_hash": "a1b2c3d4e5f6... (order-independent 64-char hex SHA-256)"
}
```

### 5.2 Field Specifications

#### Root Object (`models.ScanReport`)
* `version` (*string*): CLI specification version (`1.0.0`).
* `scan_target` (*string*): Target path or commit ref.
* `scan_type` (*string*): One of `"path"`, `"staged"`, `"range"`, `"history"`, or `"check"`.
* `timestamp` (*string*): ISO-8601 (RFC3339) execution timestamp.
* `duration_ms` (*integer*): Wall-clock duration in milliseconds.
* `total_files_scanned` (*integer*): Number of unique non-ignored files or Git blobs evaluated.
* `total_lines_scanned` (*integer*): Count of lines parsed.
* `total_findings` (*integer*): Total secrets detected.
* `critical_count`, `high_count`, `medium_count`, `low_count` (*integer*): Severity breakdown.
* `active_leaks_count` (*integer*): Count of findings where `verification.status == "ACTIVE"`.
* `findings` (*array*): List of finding objects. Always non-null (returns `[]` when 0 findings).
* `findings_hash` (*string*): SHA-256 hash of all sorted finding IDs. Empty string `""` if clean.

#### Finding Object (`models.Finding`)
* `id` (*string*): Deterministic 64-character SHA-256 hex string. Unique per `filePath + lineNumber + ruleID + rawSecret`.
* `rule_id` (*string*): Aegis signature identifier (e.g. `AEGIS-AWS-001`, `AEGIS-OPENAI-001`, `AEGIS-GEN-001`).
* `category` (*string*): Provider taxonomy (`"AWS"`, `"GitHub"`, `"OpenAI"`, `"Anthropic"`, `"Gemini"`, `"Stripe"`, `"Database"`, etc.).
* `title` (*string*): Human-readable secret title.
* `description` (*string*): Finding explanation and risks.
* `file_path` (*string*): Normalized relative file path (POSIX slash).
* `line_number` (*integer*): 1-indexed line number where the match occurred.
* `masked_value` (*string*): Sanitized token (first 4 characters retained, remainder replaced by `*`).
* `severity` (*string*): `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, or `"LOW"`.
* `confidence` (*string*): `"HIGH"` (direct provider prefix or high entropy in prod context) or `"LOW"` (test files, mock prefixes, docs).
* `verification` (*object*):
  * `status` (*string*):
    * `"NOT_VERIFIED"`: Scan ran without `--verify`.
    * `"ACTIVE"`: Confirmed valid and responsive credential (CRITICAL risk).
    * `"REVOKED"`: Explicitly rejected by provider endpoint (401/403 Invalid Key).
    * `"UNVERIFIABLE"`: Provider has no unprivileged read-only ping endpoint.
    * `"SKIPPED"`: Safe fallback (e.g., generic passwords never sent to external servers).
    * `"ERROR"`: Network timeout (1.5s) or HTTP 5xx.
  * `verified_at` (*string*): RFC3339 timestamp of the ping.
  * `details` (*string*): Contextual metadata (e.g. OAuth scopes, account identity, error reasons).

---

## 6. Supported Providers & Rule Registry

The platform can group and handle remediation based on `rule_id` and `category`:

| Rule ID | Category | Target Secret | Verification Endpoint |
| :--- | :--- | :--- | :--- |
| `AEGIS-AWS-001` | AWS | AWS IAM Access Key ID (`AKIA...`) | AWS STS `GetCallerIdentity` (SigV4) |
| `AEGIS-AWS-002` | AWS | AWS Secret Access Key (40-char Base64) | Skipped (requires Key ID) |
| `AEGIS-GH-001` | GitHub | GitHub Personal Access Token (`ghp_...`, `gho_...`) | `https://api.github.com/user` |
| `AEGIS-STRIPE-001` | Stripe | Stripe Live Secret Key (`sk_live_...`, `rk_live_...`) | `https://api.stripe.com/v1/balance` |
| `AEGIS-OPENAI-001` | OpenAI | OpenAI API Key (`sk-proj-...`, `sk-...`) | `https://api.openai.com/v1/models` |
| `AEGIS-ANTHROPIC-001` | Anthropic | Anthropic Claude API Key (`sk-ant-api03-...`) | `https://api.anthropic.com/v1/messages` (probe) |
| `AEGIS-GEMINI-001` | Gemini | Google Gemini / AI Studio API Key (`AIzaSy...`) | Google Generative Language API probe |
| `AEGIS-GROK-001` | Grok | xAI Grok Key (`xai-...`) | `https://api.x.ai/v1/models` |
| `AEGIS-GROQ-001` | Groq | Groq Cloud LPU Key (`gsk_...`) | `https://api.groq.com/openai/v1/models` |
| `AEGIS-PPLX-001` | Perplexity | Perplexity AI Key (`pplx-...`) | Perplexity Models API |
| `AEGIS-DEEPSEEK-001`| DeepSeek | DeepSeek API Key (`sk-...` 32-hex) | `https://api.deepseek.com/models` |
| `AEGIS-RESEND-001` | Resend | Resend API Key (`re_...`) | `https://api.resend.com/api-keys` |
| `AEGIS-LINEAR-001` | Linear | Linear API Key (`lin_api_...`) | Linear GraphQL API probe |
| `AEGIS-SENTRY-001` | Sentry | Sentry Auth Token (`sntrys_...`) | Sentry User API |
| `AEGIS-HF-001` | HuggingFace| Hugging Face Token (`hf_...`) | `https://huggingface.co/api/whoami-v2` |
| `AEGIS-GCP-001` | GCP | Google Cloud API Key (`AIzaSy...`) | GCP API Discovery probe |
| `AEGIS-DO-001` | DigitalOcean | DigitalOcean Personal Token (`dop_v1_...`) | DigitalOcean Account API |
| `AEGIS-GITLAB-001` | GitLab | GitLab PAT (`glpat-...`) | `https://gitlab.com/api/v4/user` |
| `AEGIS-NPM-001` | NPM | NPM Access Token (`npm_...`) | NPM Registry `/-/whoami` |
| `AEGIS-TWILIO-001` | Twilio | Twilio Account SID (`AC...`) | Twilio Accounts API |
| `AEGIS-SENDGRID-001`| SendGrid | SendGrid API Key (`SG....`) | SendGrid Scopes API |
| `AEGIS-SUPABASE-001`| Supabase | Supabase Project Token (`sbp_...`) | Supabase Projects API |
| `AEGIS-DB-001` | Database | Postgres/MySQL/Mongo/Redis URI | Format validation only (never dialed) |
| `AEGIS-KEY-001` | PrivateKey | RSA, EC, DSA, OpenSSH Private Keys | Format validation only |
| `AEGIS-GEN-001` | Generic | High-Shannon-Entropy credential assignment | Structural determinism (never verified) |

---

## 7. Platform Integration Patterns & Recipes

### Pattern A: CI/CD Ingestion Runner (Node.js / TypeScript Example)

Platform worker executing `aegis-cli` inside a container or VM:

```typescript
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

interface AegisReport {
  version: string;
  scan_target: string;
  duration_ms: number;
  total_findings: number;
  active_leaks_count: number;
  findings: Array<{
    id: string;
    rule_id: string;
    category: string;
    file_path: string;
    line_number: number;
    masked_value: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    confidence: "HIGH" | "LOW";
    verification: {
      status: "ACTIVE" | "REVOKED" | "UNVERIFIABLE" | "SKIPPED" | "ERROR" | "NOT_VERIFIED";
      details: string;
    };
  }>;
  findings_hash: string;
}

export async function runAegisScan(repoPath: string, verify: boolean = true): Promise<AegisReport> {
  const args = ["scan", repoPath, "--format=json", "--no-color"];
  if (verify) args.push("--verify");

  try {
    const { stdout } = await execFileAsync("aegis", args);
    return JSON.parse(stdout) as AegisReport;
  } catch (error: any) {
    // Exit code 1 means secrets were detected meeting --fail-on
    if (error.code === 1 && error.stdout) {
      return JSON.parse(error.stdout) as AegisReport;
    }
    // Exit code 2 or unexpected failure
    throw new Error(`Aegis CLI execution failed (code ${error.code}): ${error.stderr || error.message}`);
  }
}
```

### Pattern B: Lifecycle & Deduplication in Platform Database

1. **Unique Fingerprinting:** Index findings in your platform database on `finding.id`. If a developer moves code or updates branches, the deterministic hash `SHA256(filePath:lineNumber:ruleID:rawSecret)` prevents duplicate tickets.
2. **Commit Range Delta Scanning:** In Pull Request workflows, invoke:
   ```bash
   aegis scan --range=origin/main..HEAD --format=json
   ```
   This restricts detection solely to modified lines in the pull request, preventing legacy repository secrets from blocking urgent hotfixes.
3. **Automated Incident Triage:**
   * If `verification.status === "ACTIVE"`, escalate severity to P0 / Immediate Alert (Slack, PagerDuty, automated key revocation webhook).
   * If `confidence === "LOW"`, route to a non-blocking review queue or mark as potential test mock.

---

## 8. Suppressions & Allowlisting Contract

Aegis supports inline ignore directives. When users suppress a line, the CLI completely ignores it and will not output a finding:

* `// aegis:ignore` or `//aegis:ignore`
* `# aegis:ignore`
* `/* aegis:ignore */`
* `<!-- aegis:ignore -->`
* `; aegis:ignore`
* `-- aegis:ignore`
* `// nolint:aegis`
* `// pragma: allowlist secret`

Additionally, files or patterns listed in `.aegisignore` at the repository root are ignored across directory, staged, and historical scans.
