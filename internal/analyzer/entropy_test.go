package analyzer

import (
	"math"
	"testing"
)

func TestCalculateShannonEntropy(t *testing.T) {
	// Monotonous string has zero entropy
	zeroEntropy := CalculateShannonEntropy("aaaaaaaaaaaa")
	if zeroEntropy != 0.0 {
		t.Errorf("expected 0.0 entropy for monotonous string, got %f", zeroEntropy)
	}

	// Two equal frequency characters has entropy of 1.0 (log2(2))
	oneEntropy := CalculateShannonEntropy("abababab")
	if math.Abs(oneEntropy-1.0) > 0.0001 {
		t.Errorf("expected 1.0 entropy for equal two-char distribution, got %f", oneEntropy)
	}

	// High entropy random string
	highEntropy := CalculateShannonEntropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	if highEntropy < 4.5 {
		t.Errorf("expected high entropy (>4.5) for base64 key, got %f", highEntropy)
	}
}

func TestDetectAlphabet(t *testing.T) {
	tests := []struct {
		input    string
		expected AlphabetType
	}{
		{"4f53a29b01c38d7e6f8a9b0c1d2e3f4a", AlphabetHex},
		{"dGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ==", AlphabetBase64},
		{"P@$$w0rd!#%^&*()_+=1234", AlphabetAlphaNumPunct},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := DetectAlphabet(tt.input)
			if got != tt.expected {
				t.Errorf("DetectAlphabet(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestMeetsEntropyThresholdAndGitSHAMitigation(t *testing.T) {
	// Standard 40-char Git SHA (should be suppressed by mitigation rule)
	gitSHA := "64ccb2beca9ce9b761559ca5f2b17711eff2a091"
	meets, alphabet, entropy := MeetsEntropyThreshold(gitSHA)
	if alphabet != AlphabetHex {
		t.Fatalf("expected hex alphabet, got %s", alphabet)
	}
	if meets {
		t.Errorf("Git SHA %s with entropy %f should have been filtered out by mitigation", gitSHA, entropy)
	}

	// Real AWS secret key (40 chars base64)
	awsSecret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	meetsAWS, alphabetAWS, _ := MeetsEntropyThreshold(awsSecret)
	if !meetsAWS || alphabetAWS != AlphabetBase64 {
		t.Errorf("AWS secret key should meet entropy threshold: got meets=%v, alphabet=%s", meetsAWS, alphabetAWS)
	}
}

func TestHasLowVarianceOrSequential(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"012345678901234567890123456789", true},
		{"abcdefghijklmnopqrstuvwxyz1234", true},
		{"qW8$mP2!zL9#vR4@kX1%jN7^tY3&bC", false}, // High variance random
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := HasLowVarianceOrSequential(tt.input)
			if got != tt.expected {
				t.Errorf("HasLowVarianceOrSequential(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCleanToken(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`"my-secret-token";`, "my-secret-token"},
		{`'sk_live_123456789'`, "sk_live_123456789"},
		{"`postgres://root:pass@localhost:5432/db`", "postgres://root:pass@localhost:5432/db"},
		{"   unquoted_token   ", "unquoted_token"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := CleanToken(tt.input)
			if got != tt.expected {
				t.Errorf("CleanToken(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
