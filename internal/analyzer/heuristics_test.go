package analyzer

import (
	"testing"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

func TestIsObviousPlaceholder(t *testing.T) {
	tests := []struct {
		token    string
		expected bool
	}{
		{"your_api_key_here", true},
		{"YOUR_CLIENT_SECRET", true},
		{"replace_me_12345", true},
		{"REPLACE_WITH_KEY", true},
		{"insert_token_here", true},
		{"INSERT_PASSWORD", true},
		{"my_dummy_secret", true},
		{"fake_token_12345", true},
		{"example_key_value", true},
		{"sample_password_str", true},
		{"change_me_please", true},
		{"TODO_ADD_KEY_NOW", true},
		{"test_dummy_creds", true},
		// Unit test exception for standard AWS documentation example
		{"AKIAIOSFODNN7EXAMPLE", false},
		// Legitimate looking tokens
		{"sk_test_51MockStripeKeyForTestingOnlyXYZ", false},
		{"ghp_MockGitHubTokenForTestingOnlyXYZ12", false},
	}

	for _, tt := range tests {
		t.Run(tt.token, func(t *testing.T) {
			got := IsObviousPlaceholder(tt.token)
			if got != tt.expected {
				t.Errorf("IsObviousPlaceholder(%q) = %v, want %v", tt.token, got, tt.expected)
			}
		})
	}
}

func TestIsTestPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"./tests/test_auth.py", true},
		{"test_login.py", true},
		{"src/components/auth_test.go", true},
		{"spec/requests/user_spec.rb", true},
		{"__tests__/api.test.ts", true},
		{"fixtures/sample_payload.json", true},
		{"mocks/client.go", true},
		{"testdata/keys.env", true},
		{"src/test/resources/application.properties", true},
		// Production code paths
		{"src/config.py", false},
		{"cmd/aegis/main.go", false},
		{"internal/validator/aws.go", false},
		{"app/controllers/user_controller.rb", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := IsTestPath(tt.path)
			if got != tt.expected {
				t.Errorf("IsTestPath(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestAssessConfidence(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		lineContent string
		token       string
		expected    models.Confidence
	}{
		{
			name:        "Deterministic provider rule in prod file",
			filePath:    "src/auth.ts",
			lineContent: `const token = "ghp_111122223333444455556666777788889999";`,
			token:       "ghp_111122223333444455556666777788889999",
			expected:    models.ConfidenceHigh,
		},
		{
			name:        "Test file path downgrades to Low",
			filePath:    "internal/git/diff_test.go",
			lineContent: `awsKey := "AKIAIOSFODNN7EXAMPLE"`,
			token:       "AKIAIOSFODNN7EXAMPLE",
			expected:    models.ConfidenceLow,
		},
		{
			name:        "Line containing test variable downgrades to Low",
			filePath:    "src/config.py",
			lineContent: `mock_test_token = "r4nd0mH1gh3ntr0pyK3yV4lu3!#9"`,
			token:       "r4nd0mH1gh3ntr0pyK3yV4lu3!#9",
			expected:    models.ConfidenceLow,
		},
		{
			name:        "Random token containing 'test' substring without test context retains High",
			filePath:    "src/prod.go",
			lineContent: `prodToken := "ghp_test1234567890abcdefghijklmnopqrstuv"`,
			token:       "ghp_test1234567890abcdefghijklmnopqrstuv",
			expected:    models.ConfidenceHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AssessConfidence(tt.filePath, tt.lineContent, tt.token)
			if got != tt.expected {
				t.Errorf("AssessConfidence() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHasIgnoreDirective(t *testing.T) {
	tests := []struct {
		line     string
		expected bool
	}{
		{`AWS_KEY = "AKIA1234" // aegis:ignore`, true},
		{`AWS_KEY = "AKIA1234" //aegis:ignore`, true},
		{`AWS_KEY = "AKIA1234" # aegis:ignore`, true},
		{`AWS_KEY = "AKIA1234" #aegis:ignore`, true},
		{`AWS_KEY = "AKIA1234" /* aegis:ignore */`, true},
		{`AWS_KEY = "AKIA1234" // nolint:aegis`, true},
		{`AWS_KEY = "AKIA1234" // pragma: allowlist secret`, true},
		{`AWS_KEY = "AKIA1234"`, false},
		{`AWS_KEY = "AKIA1234" // normal comment`, false},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := HasIgnoreDirective(tt.line)
			if got != tt.expected {
				t.Errorf("HasIgnoreDirective(%q) = %v, want %v", tt.line, got, tt.expected)
			}
		})
	}
}
