package analyzer

import (
	"regexp"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

// Rule represents a detection rule for a specific secret category or pattern.
type Rule struct {
	ID              string
	Description     string
	Category        models.TokenCategory
	Severity        models.Severity
	Prefixes        []string // Fast-rejection gate prefixes; empty if rule must scan all lines
	Pattern         *regexp.Regexp
	RequiresEntropy bool
	EntropyMin      float64
	Remediation     models.Remediation
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
			ID:              "AEGIS-AWS-002",
			Description:     "AWS Secret Access Key Assignment",
			Category:        models.CategoryAWS,
			Severity:        models.SeverityCritical,
			Prefixes:        []string{"aws", "AWS"},
			Pattern:         regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['"]?([0-9a-zA-Z/+]{40})['"]?`),
			RequiresEntropy: true,
			EntropyMin:      3.2,
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
			ID:          "AEGIS-ANTHROPIC-001",
			Description: "Anthropic Claude API Key",
			Category:    models.CategoryAnthropic,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"sk-ant-api03-"},
			Pattern:     regexp.MustCompile(`\b(sk-ant-api03-[a-zA-Z0-9_\-]{80,128})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Anthropic Platform & Model Access",
					Impact:         "Unauthorized Claude model querying, credit drain, and potential prompt leakage.",
					TargetServices: []string{"Anthropic Messages API", "Claude 3 / 3.5 Models"},
				},
				ActionRequired: "Revoke key immediately at console.anthropic.com/settings/keys.",
			},
		},
		{
			ID:          "AEGIS-DEEPSEEK-001",
			Description: "DeepSeek API Key",
			Category:    models.CategoryDeepSeek,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"sk-"},
			Pattern:     regexp.MustCompile(`\b(sk-[a-f0-9]{32})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "DeepSeek LLM Platform Access",
					Impact:         "Unauthorized DeepSeek-V3/R1 model querying, quota consumption, and account balance drainage.",
					TargetServices: []string{"DeepSeek Chat API", "Inference Platform"},
				},
				ActionRequired: "Revoke key immediately in DeepSeek Platform > API Keys.",
			},
		},
		{
			ID:          "AEGIS-OPENAI-001",
			Description: "OpenAI Secret API Key",
			Category:    models.CategoryOpenAI,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"sk-"},
			Pattern:     regexp.MustCompile(`\b(sk-(?:proj-[a-zA-Z0-9_-]{48,128}|admin-[a-zA-Z0-9_-]{48,128}|[a-zA-Z0-9]{48}))\b`),
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
			ID:          "AEGIS-GROK-001",
			Description: "xAI Grok API Key",
			Category:    models.CategoryGrok,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"xai-"},
			Pattern:     regexp.MustCompile(`\b(xai-[a-zA-Z0-9]{32,80})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "xAI Grok Platform Access",
					Impact:         "Unauthorized Grok-2/Grok-Vision API requests and organization billing drain.",
					TargetServices: []string{"xAI API", "Grok Models"},
				},
				ActionRequired: "Revoke key at console.x.ai.",
			},
		},
		{
			ID:          "AEGIS-GROQ-001",
			Description: "Groq Fast Inference API Key",
			Category:    models.CategoryGroq,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"gsk_"},
			Pattern:     regexp.MustCompile(`\b(gsk_[a-zA-Z0-9]{52})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Groq High-Speed LPU Platform",
					Impact:         "Compute quota exhaustion, unauthorized high-throughput LLM inference.",
					TargetServices: []string{"GroqCloud API", "LPU Inference Engine"},
				},
				ActionRequired: "Revoke key at console.groq.com/keys.",
			},
		},
		{
			ID:          "AEGIS-PPLX-001",
			Description: "Perplexity AI API Key",
			Category:    models.CategoryPerplexity,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"pplx-"},
			Pattern:     regexp.MustCompile(`\b(pplx-[a-zA-Z0-9]{48})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Perplexity AI Search & Sonar Models",
					Impact:         "Unauthorized web-grounded LLM inference, API credit drainage.",
					TargetServices: []string{"Perplexity API", "Sonar Models"},
				},
				ActionRequired: "Rotate key in Perplexity Settings > API.",
			},
		},
		{
			ID:          "AEGIS-GEMINI-001",
			Description: "Google Gemini / Google AI Studio API Key",
			Category:    models.CategoryGemini,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"AIzaSy"},
			Pattern:     regexp.MustCompile(`(?i)(?:gemini|google_ai|generative_language).*['"](AIzaSy[a-zA-Z0-9_\-]{33})['"]`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Google Gemini Generative AI Platform",
					Impact:         "Unauthorized Gemini 1.5 Pro / Flash inferences, rate-limit depletion, and Google Cloud billing.",
					TargetServices: []string{"Google AI Studio", "Gemini APIs", "Vertex AI"},
				},
				ActionRequired: "Delete or rotate API key at aistudio.google.com/app/apikey.",
			},
		},
		{
			ID:          "AEGIS-GCP-001",
			Description: "Google Cloud Platform (GCP) API Key",
			Category:    models.CategoryGCP,
			Severity:    models.SeverityHigh,
			Prefixes:    []string{"AIzaSy"},
			Pattern:     regexp.MustCompile(`\b(AIzaSy[a-zA-Z0-9_\-]{33})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Google Cloud Enabled Services",
					Impact:         "Direct consumption of enabled GCP APIs (Maps, Firebase, Translate, etc.).",
					TargetServices: []string{"GCP APIs", "Firebase", "Google Maps"},
				},
				ActionRequired: "Restrict or delete key in Google Cloud Console > Credentials.",
			},
		},
		{
			ID:          "AEGIS-HF-001",
			Description: "Hugging Face User Access Token",
			Category:    models.CategoryHuggingFace,
			Severity:    models.SeverityHigh,
			Prefixes:    []string{"hf_"},
			Pattern:     regexp.MustCompile(`\b(hf_[a-zA-Z0-9]{34})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Hugging Face Model Hub Access",
					Impact:         "Read/write access to private models, datasets, spaces, and inference endpoints.",
					TargetServices: []string{"Hugging Face Hub", "Inference API"},
				},
				ActionRequired: "Revoke token at huggingface.co/settings/tokens.",
			},
		},
		{
			ID:          "AEGIS-DO-001",
			Description: "DigitalOcean Personal Access Token",
			Category:    models.CategoryDigitalOcean,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"dop_v1_"},
			Pattern:     regexp.MustCompile(`\b(dop_v1_[a-f0-9]{64})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "DigitalOcean Cloud Infrastructure",
					Impact:         "Full provisioning and deletion access to Droplets, Volumes, Kubernetes clusters, and DNS.",
					TargetServices: []string{"Droplets", "Kubernetes", "Databases", "Spaces"},
				},
				ActionRequired: "Revoke token at cloud.digitalocean.com/account/api/tokens.",
			},
		},
		{
			ID:          "AEGIS-GITLAB-001",
			Description: "GitLab Personal Access Token",
			Category:    models.CategoryGitLab,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"glpat-"},
			Pattern:     regexp.MustCompile(`\b(glpat-[a-zA-Z0-9_\-]{20})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "GitLab Repositories & CI/CD Pipelines",
					Impact:         "Read/write access to private code, pipeline variable modification, and runner execution.",
					TargetServices: []string{"GitLab Repositories", "GitLab CI/CD"},
				},
				ActionRequired: "Revoke token in GitLab User Settings > Access Tokens.",
			},
		},
		{
			ID:          "AEGIS-NPM-001",
			Description: "NPM Access Token",
			Category:    models.CategoryNPM,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"npm_"},
			Pattern:     regexp.MustCompile(`\b(npm_[a-zA-Z0-9]{36})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "NPM Package Registry Supply Chain",
					Impact:         "Publishing unauthorized package releases, software supply chain injection.",
					TargetServices: []string{"npmjs.com Package Registry"},
				},
				ActionRequired: "Revoke token at npmjs.com/settings/tokens and check published package versions.",
			},
		},
		{
			ID:          "AEGIS-RESEND-001",
			Description: "Resend Email API Key",
			Category:    models.CategoryResend,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"re_"},
			Pattern:     regexp.MustCompile(`\b(re_[a-zA-Z0-9]{32,36})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Resend Email Infrastructure",
					Impact:         "Unauthorized email dispatch from verified company domains.",
					TargetServices: []string{"Resend Mail API", "Domain DNS"},
				},
				ActionRequired: "Delete and rotate API key at resend.com/api-keys.",
			},
		},
		{
			ID:          "AEGIS-LINEAR-001",
			Description: "Linear API Key",
			Category:    models.CategoryLinear,
			Severity:    models.SeverityHigh,
			Prefixes:    []string{"lin_api_"},
			Pattern:     regexp.MustCompile(`\b(lin_api_[a-zA-Z0-9]{40})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Linear Project Management & Issue Tracker",
					Impact:         "Read/write project issues, roadmaps, customer bug disclosures.",
					TargetServices: []string{"Linear GraphQL API"},
				},
				ActionRequired: "Revoke key in Linear Settings > API.",
			},
		},
		{
			ID:          "AEGIS-SENTRY-001",
			Description: "Sentry Auth Token",
			Category:    models.CategorySentry,
			Severity:    models.SeverityHigh,
			Prefixes:    []string{"sntrys_"},
			Pattern:     regexp.MustCompile(`\b(sntrys_[a-zA-Z0-9]{64})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Sentry Error Monitoring Platform",
					Impact:         "Exfiltration of production crash dumps, stack traces, and debug symbols.",
					TargetServices: []string{"Sentry Organization API", "Releases"},
				},
				ActionRequired: "Revoke token at sentry.io/settings/account/api/auth-tokens.",
			},
		},
		{
			ID:          "AEGIS-DISCORD-001",
			Description: "Discord Bot Token",
			Category:    models.CategoryDiscord,
			Severity:    models.SeverityHigh,
			Prefixes:    nil,
			Pattern:     regexp.MustCompile(`\b([MNO][a-zA-Z0-9_\-.]{23,26}\.[a-zA-Z0-9_\-.]{6}\.[a-zA-Z0-9_\-.]{27,38})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Discord Bot & Guild Impersonation",
					Impact:         "Send messages, administrative guild actions, webhook abuse.",
					TargetServices: []string{"Discord Gateway API", "Guild Channels"},
				},
				ActionRequired: "Reset bot token in Discord Developer Portal > Bot.",
			},
		},
		{
			ID:          "AEGIS-TWILIO-001",
			Description: "Twilio Account SID",
			Category:    models.CategoryTwilio,
			Severity:    models.SeverityMedium,
			Prefixes:    []string{"AC"},
			Pattern:     regexp.MustCompile(`\b(AC[a-f0-9]{32})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Twilio Telephony & Messaging Account",
					Impact:         "Used with auth tokens to dispatch SMS, voice calls, and verify services.",
					TargetServices: []string{"Twilio Programmable SMS", "Twilio Voice"},
				},
				ActionRequired: "Rotate Twilio Auth Token associated with this SID in Twilio Console.",
			},
		},
		{
			ID:          "AEGIS-SENDGRID-001",
			Description: "SendGrid API Key",
			Category:    models.CategorySendGrid,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"SG."},
			Pattern:     regexp.MustCompile(`\b(SG\.[a-zA-Z0-9_\-\.]{66,})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "SendGrid Email Delivery Infrastructure",
					Impact:         "Dispatch phishing campaigns, read marketing lists, exhaust sending quota.",
					TargetServices: []string{"SendGrid Mail Send API", "Marketing Campaigns"},
				},
				ActionRequired: "Delete and regenerate API key in SendGrid Settings > API Keys.",
			},
		},
		{
			ID:          "AEGIS-SUPABASE-001",
			Description: "Supabase Personal Access Token",
			Category:    models.CategorySupabase,
			Severity:    models.SeverityCritical,
			Prefixes:    []string{"sbp_"},
			Pattern:     regexp.MustCompile(`\b(sbp_[a-f0-9]{40})\b`),
			Remediation: models.Remediation{
				BlastRadius: models.BlastRadius{
					Scope:          "Supabase Cloud Infrastructure",
					Impact:         "Administrative access to all Supabase projects, databases, auth, and storage buckets.",
					TargetServices: []string{"Supabase Management API", "Postgres Databases"},
				},
				ActionRequired: "Revoke token in Supabase Dashboard > Account > Access Tokens.",
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
			Pattern:     regexp.MustCompile(`(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:]+:([^@/\s]+)@[a-zA-Z0-9.\-_]+(?::[0-9]+)?(?:/[a-zA-Z0-9._\-]*)?`),
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
			Pattern:     regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer[_-]?token|app[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9_\-\.\+/=]{16,128})['"]?`),
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
