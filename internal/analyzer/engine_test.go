package analyzer

import (
	"strings"
	"testing"
	"time"

	"aegis-cli/pkg/models"
)

func TestEngineRuleDetections(t *testing.T) {
	engine := NewEngine()

	awsKey := "AK" + "IA" + "IOSFODNN7EXAMPLE"
	ghKey := "gh" + "p_" + "111122223333444455556666777788889999"
	stripeKey := "sk_" + "live_" + "51A9999999999999999999999999"
	openaiKey := "sk-" + "proj-" + "111122223333444455556666777788889999000011112222333344445555"
	anthropicKey := "sk-" + "ant-" + "api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_abcdefghijklmnopqrstuvwx"
	hfKey := "h" + "f_" + "abcdefghijklmnopqrstuvwxyz01234567"
	gcpKey := "AI" + "za" + "SyD1234567890abcdefghijklmnopqrstuv"
	doKey := "dop" + "_v1_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	gitlabKey := "gl" + "pat-" + "1234567890abcdefghij"
	npmKey := "np" + "m_" + "1234567890abcdefghijklmnopqrstuvwxyz"
	twilioKey := "A" + "C" + "0123456789abcdef0123456789abcdef"
	sendgridKey := "S" + "G." + "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	supabaseKey := "sb" + "p_" + "0123456789abcdef0123456789abcdef01234567"

	// New frontier AI and modern tools
	geminiKey := "AI" + "za" + "SyC1234567890abcdefghijklmnopqrstuv"
	grokKey := "xa" + "i-" + "1234567890abcdef1234567890abcdef12345678"
	groqKey := "gs" + "k_" + "1234567890abcdef1234567890abcdef1234567890abcdef1234"
	pplxKey := "pp" + "lx-" + "1234567890abcdef1234567890abcdef1234567890abcdef"
	deepseekKey := "sk" + "-" + "0123456789abcdef0123456789abcdef"
	resendKey := "re" + "_" + "1234567890abcdefghijklmnopqrstuv"
	linearKey := "lin" + "_api_" + "1234567890abcdef1234567890abcdef12345678"
	sentryKey := "snt" + "rys_" + "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

	tests := []struct {
		name         string
		line         string
		expectedRule string
		expectedCat  models.TokenCategory
		shouldMatch  bool
	}{
		{
			name:         "AWS Access Key ID",
			line:         `export AWS_ACCESS_KEY_ID="` + awsKey + `"`,
			expectedRule: "AEGIS-AWS-001",
			expectedCat:  models.CategoryAWS,
			shouldMatch:  true,
		},
		{
			name:         "GitHub Classic PAT",
			line:         `const token = "` + ghKey + `";`,
			expectedRule: "AEGIS-GH-001",
			expectedCat:  models.CategoryGitHub,
			shouldMatch:  true,
		},
		{
			name:         "Stripe Live Key",
			line:         `STRIPE_KEY=` + stripeKey,
			expectedRule: "AEGIS-STRIPE-001",
			expectedCat:  models.CategoryStripe,
			shouldMatch:  true,
		},
		{
			name:         "OpenAI API Key",
			line:         `openai.api_key = "` + openaiKey + `"`,
			expectedRule: "AEGIS-OPENAI-001",
			expectedCat:  models.CategoryOpenAI,
			shouldMatch:  true,
		},
		{
			name:         "Anthropic Claude Key",
			line:         `ANTHROPIC_API_KEY="` + anthropicKey + `"`,
			expectedRule: "AEGIS-ANTHROPIC-001",
			expectedCat:  models.CategoryAnthropic,
			shouldMatch:  true,
		},
		{
			name:         "Google Gemini AI Key",
			line:         `gemini_api_key = "` + geminiKey + `"`,
			expectedRule: "AEGIS-GEMINI-001",
			expectedCat:  models.CategoryGemini,
			shouldMatch:  true,
		},
		{
			name:         "xAI Grok Key",
			line:         `XAI_API_KEY = "` + grokKey + `"`,
			expectedRule: "AEGIS-GROK-001",
			expectedCat:  models.CategoryGrok,
			shouldMatch:  true,
		},
		{
			name:         "Groq Key",
			line:         `GROQ_API_KEY = "` + groqKey + `"`,
			expectedRule: "AEGIS-GROQ-001",
			expectedCat:  models.CategoryGroq,
			shouldMatch:  true,
		},
		{
			name:         "Perplexity AI Key",
			line:         `PERPLEXITY_KEY = "` + pplxKey + `"`,
			expectedRule: "AEGIS-PPLX-001",
			expectedCat:  models.CategoryPerplexity,
			shouldMatch:  true,
		},
		{
			name:         "DeepSeek Key",
			line:         `DEEPSEEK_API_KEY = "` + deepseekKey + `"`,
			expectedRule: "AEGIS-DEEPSEEK-001",
			expectedCat:  models.CategoryDeepSeek,
			shouldMatch:  true,
		},
		{
			name:         "Resend Email Key",
			line:         `RESEND_KEY = "` + resendKey + `"`,
			expectedRule: "AEGIS-RESEND-001",
			expectedCat:  models.CategoryResend,
			shouldMatch:  true,
		},
		{
			name:         "Linear API Key",
			line:         `LINEAR_API_KEY = "` + linearKey + `"`,
			expectedRule: "AEGIS-LINEAR-001",
			expectedCat:  models.CategoryLinear,
			shouldMatch:  true,
		},
		{
			name:         "Sentry Auth Token",
			line:         `SENTRY_AUTH_TOKEN = "` + sentryKey + `"`,
			expectedRule: "AEGIS-SENTRY-001",
			expectedCat:  models.CategorySentry,
			shouldMatch:  true,
		},
		{
			name:         "Hugging Face Token",
			line:         `HF_TOKEN="` + hfKey + `"`,
			expectedRule: "AEGIS-HF-001",
			expectedCat:  models.CategoryHuggingFace,
			shouldMatch:  true,
		},
		{
			name:         "GCP API Key",
			line:         `google_maps_key = "` + gcpKey + `"`,
			expectedRule: "AEGIS-GCP-001",
			expectedCat:  models.CategoryGCP,
			shouldMatch:  true,
		},
		{
			name:         "DigitalOcean Token",
			line:         `DO_TOKEN="` + doKey + `"`,
			expectedRule: "AEGIS-DO-001",
			expectedCat:  models.CategoryDigitalOcean,
			shouldMatch:  true,
		},
		{
			name:         "GitLab Token",
			line:         `GITLAB_TOKEN="` + gitlabKey + `"`,
			expectedRule: "AEGIS-GITLAB-001",
			expectedCat:  models.CategoryGitLab,
			shouldMatch:  true,
		},
		{
			name:         "NPM Token",
			line:         `//registry.npmjs.org/:_authToken="` + npmKey + `"`,
			expectedRule: "AEGIS-NPM-001",
			expectedCat:  models.CategoryNPM,
			shouldMatch:  true,
		},
		{
			name:         "Twilio Account SID",
			line:         `TWILIO_ACCOUNT_SID="` + twilioKey + `"`,
			expectedRule: "AEGIS-TWILIO-001",
			expectedCat:  models.CategoryTwilio,
			shouldMatch:  true,
		},
		{
			name:         "SendGrid API Key",
			line:         `SENDGRID_API_KEY="` + sendgridKey + `"`,
			expectedRule: "AEGIS-SENDGRID-001",
			expectedCat:  models.CategorySendGrid,
			shouldMatch:  true,
		},
		{
			name:         "Supabase Project Token",
			line:         `SUPABASE_TOKEN="` + supabaseKey + `"`,
			expectedRule: "AEGIS-SUPABASE-001",
			expectedCat:  models.CategorySupabase,
			shouldMatch:  true,
		},
		{
			name:         "Database Connection String",
			line:         `DATABASE_URL="postgres://dbuser:s3cr3tPassword123!@db.internal:5432/proddb"`,
			expectedRule: "AEGIS-DB-001",
			expectedCat:  models.CategoryDatabase,
			shouldMatch:  true,
		},
		{
			name:         "Inline Ignore Directive Suppresses Secret",
			line:         `export AWS_ACCESS_KEY_ID="` + awsKey + `" // aegis:ignore`,
			expectedRule: "AEGIS-AWS-001",
			expectedCat:  models.CategoryAWS,
			shouldMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := engine.ScanLine("app/config.go", 1, tt.line)
			if !tt.shouldMatch {
				if len(findings) > 0 {
					t.Errorf("expected 0 findings for line %q, got %d", tt.line, len(findings))
				}
				return
			}

			if len(findings) == 0 {
				t.Fatalf("expected finding for line %q, got 0", tt.line)
			}

			found := false
			for _, f := range findings {
				if f.RuleID == tt.expectedRule && f.Category == tt.expectedCat {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected finding with RuleID %s and Category %s, got: %+v", tt.expectedRule, tt.expectedCat, findings)
			}
		})
	}
}

func TestBinaryDetectionWithUTF16Mitigation(t *testing.T) {
	elfBinary := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00}
	if !IsBinary(elfBinary) {
		t.Errorf("expected standard binary to be identified as binary")
	}

	utf16LE := []byte{0xFF, 0xFE, 'A', 0x00, 'W', 0x00, 'S', 0x00}
	if IsBinary(utf16LE) {
		t.Errorf("UTF-16 Little Endian text with BOM was falsely flagged as binary")
	}

	utf16BE := []byte{0xFE, 0xFF, 0x00, 'A', 0x00, 'W', 0x00, 'S'}
	if IsBinary(utf16BE) {
		t.Errorf("UTF-16 Big Endian text with BOM was falsely flagged as binary")
	}
}

func TestMinifiedLongLinePrefixScanning(t *testing.T) {
	engine := NewEngine()

	padding := strings.Repeat("var a=1;function f(){return 42;}", 150)
	secret := "sk_" + "live_" + "51A9999999999999999999999999"
	longLine := padding + `var stripeKey="` + secret + `";` + padding

	if len(longLine) < 5000 {
		t.Fatalf("expected test line to be > 5000 characters, got %d", len(longLine))
	}

	start := time.Now()
	findings := engine.ScanLine("bundle.min.js", 1, longLine)
	duration := time.Since(start)

	if duration > 50*time.Millisecond {
		t.Errorf("long line scan took too long: %v (expected < 50ms)", duration)
	}

	if len(findings) == 0 {
		t.Fatalf("expected secret to be found in minified bundle line, got 0 findings")
	}

	if findings[0].Category != models.CategoryStripe {
		t.Errorf("expected Stripe secret, got %s", findings[0].Category)
	}
}

func BenchmarkEngineScanLine(b *testing.B) {
	engine := NewEngine()
	awsKey := "AK" + "IA" + "IOSFODNN7EXAMPLE"
	line := `const awsKey = "` + awsKey + `"; const db = "postgres://root:pass@localhost:5432/db";`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.ScanLine("config.js", 42, line)
	}
}

func BenchmarkMinifiedLongLineScan(b *testing.B) {
	engine := NewEngine()
	awsKey := "AK" + "IA" + "IOSFODNN7EXAMPLE"
	padding := strings.Repeat("a=1+2;b=3+4;c=true;", 100)
	line := padding + `var key = "` + awsKey + `";` + padding

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.ScanLine("vendor.min.js", 1, line)
	}
}
