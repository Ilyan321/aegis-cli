package analyzer

import (
	"regexp"

	"aegis-cli/pkg/models"
)

// Rule represents a detection rule for a specific secret category or pattern.
type Rule struct {
	ID             string
	Description    string
	Category       models.TokenCategory
	Severity       models.Severity
	Prefixes       []string // Fast-rejection gate prefixes; empty if rule must scan all lines
	Pattern        *regexp.Regexp
	RequiresEntropy bool
	EntropyMin     float64
	Remediation    models.Remediation
}

var DefaultRules []Rule

func init() {
	DefaultRules = []Rule{
		{
			ID:          "AEGIS-AWS-001",
			Description: "AWS Access Key ID",
			Category:    models.CategoryAWS,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"AKIA"},
			Pattern:     regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "AWS Cloud Infrastructure Compromise",
					Impact:         "Unrestricted access to AWS resources and potential data exfiltration or resource hijacking.",
					TargetServices: []string{"EC2", "S3", "IAM", "RDS", "Lambda"},
				},
				ActionRequired: "Revoke key immediately in AWS IAM console and rotate credentials.",
				SuggestedCommands: []string{
					"aws iam delete-access-key --access-key-id <KEY_ID>",
					"git reset HEAD~1 # if not pushed yet",
				},
			},
		},
		{
			ID:          "AEGIS-AWS-002",
			Description: "AWS Secret Access Key Assignment",
			Category:    models.CategoryAWS,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"aws", "AWS"},
			Pattern:     regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['"]([0-9a-zA-Z/+]{40})['"]`),
			RequiresEntropy: true,
			EntropyMin:  3.2,
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "AWS Full Identity Compromise",
					Impact:         "Direct authentication pair with AWS Access Key.",
					TargetServices: []string{"AWS STS", "All AWS APIs"},
				},
				ActionRequired: "Immediately rotate the IAM user secret credentials.",
				SuggestedCommands: []string{
					"aws iam create-access-key --user-name <USER>",
				},
			},
		},
		{
			ID:          "AEGIS-GH-001",
			Description: "GitHub Personal Access Token (Classic)",
			Category:    models.CategoryGitHub,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"ghp_"},
			Pattern:     regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "GitHub Account & Repository Access",
					Impact:         "Read and write permissions to public and private code repositories, releases, and packages.",
					TargetServices: []string{"GitHub Repositories", "GitHub Actions", "GitHub Packages"},
				},
				ActionRequired: "Revoke token immediately at github.com/settings/tokens.",
				SuggestedCommands: []string{
					"gh auth logout",
				},
			},
		},
		{
			ID:          "AEGIS-GH-002",
			Description: "GitHub Personal Access Token (Fine-Grained)",
			Category:    models.CategoryGitHub,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"github_pat_"},
			Pattern:     regexp.MustCompile(`\b(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "GitHub Fine-Grained Resource Access",
					Impact:         "Granular repository and organization level write/admin access.",
					TargetServices: []string{"GitHub Repositories", "Organization Resources"},
				},
				ActionRequired: "Revoke the fine-grained token in GitHub Developer Settings.",
			},
		},
		{
			ID:          "AEGIS-STRIPE-001",
			Description: "Stripe Live Secret Key",
			Category:    models.CategoryStripe,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"sk_live_"},
			Pattern:     regexp.MustCompile(`\b(sk_live_[0-9a-zA-Z]{24,99})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Stripe Payment Infrastructure Access",
					Impact:         "Full administrative control over charges, payouts, customer financial records, and disputes.",
					TargetServices: []string{"Stripe Charges", "Stripe Customers", "Stripe Payouts"},
				},
				ActionRequired: "Roll the secret key immediately in Stripe Dashboard (Developers > API keys).",
			},
		},
		{
			ID:          "AEGIS-STRIPE-002",
			Description: "Stripe Live Restricted Key",
			Category:    models.CategoryStripe,
			Severity:    models.SeverityHigh,
			Prefixes:    []string{"rk_live_"},
			Pattern:     regexp.MustCompile(`\b(rk_live_[0-9a-zA-Z]{24,99})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Stripe Restricted Scope Access",
					Impact:         "Execution of operations within defined restricted permissions.",
					TargetServices: []string{"Stripe API"},
				},
				ActionRequired: "Revoke key in Stripe Dashboard.",
			},
		},
		{
			ID:          "AEGIS-OPENAI-001",
			Description: "OpenAI Secret API Key",
			Category:    models.CategoryOpenAI,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"sk-"},
			Pattern:     regexp.MustCompile(`\b(sk-(?:proj-)?[a-zA-Z0-9_-]{48,128})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "OpenAI Platform & Model Quotas",
					Impact:         "Unauthorized LLM queries, quota exhaustion, fine-tuning tampering, and billed expenses.",
					TargetServices: []string{"OpenAI Completions", "Embeddings", "Fine-Tuning"},
				},
				ActionRequired: "Revoke key immediately at platform.openai.com/api-keys.",
			},
		},
		{
			ID:          "AEGIS-SLACK-001",
			Description: "Slack Bot Token",
			Category:    models.CategorySlack,
			Severity:    models.SeverityHigh,
			Prefixes:    []string{"xoxb-"},
			Pattern:     regexp.MustCompile(`\b(xoxb-[0-9]{10,14}-[0-9]{10,14}-[a-zA-Z0-9]{24})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Slack Workspace Bot Impersonation",
					Impact:         "Read/write workspace messages, file access, and channel manipulation.",
					TargetServices: []string{"Slack Web API", "Chat", "Conversations"},
				},
				ActionRequired: "Revoke the token in the Slack App Management console.",
			},
		},
		{
			ID:          "AEGIS-KEY-001",
			Description: "Private Cryptographic Key",
			Category:    models.CategoryGeneric,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"-----BEGIN"},
			Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Cryptographic Identity Impersonation",
					Impact:         "SSH server compromise, TLS certificate interception, or digital signature forgery.",
					TargetServices: []string{"SSH Servers", "TLS Infrastructure", "Code Signing"},
				},
				ActionRequired: "Remove key, generate a new cryptographic pair, and remove the public key from authorized_keys.",
			},
		},
		{
			ID:          "AEGIS-DB-001",
			Description: "Database Connection URI with Credentials",
			Category:    models.CategoryDatabase,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"://"},
			Pattern:     regexp.MustCompile(`(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:]+:([^@/\s]+)@[a-zA-Z0-9.\-_]+(?::[0-9]+)?/[a-zA-Z0-9._\-]+`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Persistent Database Full Access",
					Impact:         "Direct arbitrary SQL/NoSQL read/write/drop permissions on production data stores.",
					TargetServices: []string{"PostgreSQL", "MySQL", "MongoDB", "Redis"},
				},
				ActionRequired: "Rotate database user password immediately and restrict network access via firewalls / VPC.",
			},
		},
		{
			ID:          "AEGIS-GEN-001",
			Description: "Generic High-Entropy Credential Assignment",
			Category:    models.CategoryGeneric,
			Severity:    models.SeverityHigh,
			Prefixes:    nil, // Evaluated on candidate lines
			Pattern:     regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|app[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.\+/=]{16,128})['"]`),
			RequiresEntropy: true,
			EntropyMin:  4.2,
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Application Authentication Bypass",
					Impact:         "Potential access to protected backend services or microservice APIs.",
					TargetServices: []string{"Internal APIs", "Authentication Gateways"},
				},
				ActionRequired: "Move hardcoded secret to environment variables or secret manager.",
			},
		},
	}
}
