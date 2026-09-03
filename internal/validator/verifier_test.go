package validator

import (
	"strings"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aegis-cli/pkg/models"
)

func TestStructuralDeterminismNeverExfiltratesGenericPasswords(t *testing.T) {
	reg := NewRegistry()

	genericFinding := models.Finding{
		Category:  models.CategoryGeneric,
		RawSecret: "super-secret-production-password-123!",
	}

	reg.VerifyFinding(context.Background(), &genericFinding)

	if genericFinding.Verification.Status != models.StatusSkipped {
		t.Errorf("CRITICAL SECURITY FLAW: generic secret was not skipped: %+v", genericFinding.Verification)
	}
}

func TestStripeVerifierResponses(t *testing.T) {
	// Active mock
	activeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer sk_live_valid" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"object": "balance"}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": {"message": "Invalid API Key"}}`))
		}
	}))
	defer activeServer.Close()

	verifier := &StripeVerifier{endpoint: activeServer.URL}
	client := activeServer.Client()

	// 1. Test active key
	resActive, err := verifier.Verify(context.Background(), client, "sk_live_valid")
	if err != nil || resActive.Status != models.StatusActive {
		t.Errorf("expected active status, got: %+v (err: %v)", resActive, err)
	}

	// 2. Test revoked key
	resRevoked, err := verifier.Verify(context.Background(), client, "sk_live_revoked")
	if err != nil || resRevoked.Status != models.StatusRevoked {
		t.Errorf("expected revoked status, got: %+v (err: %v)", resRevoked, err)
	}
}

func TestGitHubVerifierResponses(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "Bearer ghp_valid" {
			w.Header().Set("X-OAuth-Scopes", "repo, read:org")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"login": "octocat"}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message": "Bad credentials"}`))
		}
	}))
	defer mockServer.Close()

	verifier := &GitHubVerifier{endpoint: mockServer.URL}
	client := mockServer.Client()

	// 1. Test active token
	resActive, err := verifier.Verify(context.Background(), client, "ghp_valid")
	if err != nil || resActive.Status != models.StatusActive {
		t.Errorf("expected active status, got: %+v (err: %v)", resActive, err)
	}
	if resActive.Details == "" {
		t.Errorf("expected scope details, got empty")
	}

	// 2. Test revoked token
	resRevoked, err := verifier.Verify(context.Background(), client, "ghp_revoked")
	if err != nil || resRevoked.Status != models.StatusRevoked {
		t.Errorf("expected revoked status, got: %+v (err: %v)", resRevoked, err)
	}
}

func TestOpenAIVerifierQuotaHandling(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error": {"code": "insufficient_quota", "message": "You exceeded your current quota"}}`))
	}))
	defer mockServer.Close()

	verifier := &OpenAIVerifier{endpoint: mockServer.URL}
	client := mockServer.Client()

	res, err := verifier.Verify(context.Background(), client, "sk-proj-test")
	if err != nil || res.Status != models.StatusActive {
		t.Errorf("expected insufficient_quota to be marked as StatusActive, got: %+v (err: %v)", res, err)
	}
}

func TestAWSVerifierXMLResponses(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "" && strings.Contains(auth, "EXIST") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>`))
		} else {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`))
		}
	}))
	defer mockServer.Close()

	verifier := &AWSVerifier{endpoint: mockServer.URL}
	client := mockServer.Client()

	// 1. Existing key recognized by AWS
	resActive, err := verifier.Verify(context.Background(), client, "AKIA00000000000EXIST")
	if err != nil || resActive.Status != models.StatusActive {
		t.Errorf("expected SignatureDoesNotMatch to be recognized as active key, got: %+v (err: %v)", resActive, err)
	}

	// 2. Non-existent key
	resRevoked, err := verifier.Verify(context.Background(), client, "AKIA0000000000000000")
	if err != nil || resRevoked.Status != models.StatusRevoked {
		t.Errorf("expected InvalidClientTokenId to be recognized as revoked key, got: %+v (err: %v)", resRevoked, err)
	}
}

func TestVerificationHardTimeout(t *testing.T) {
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	verifier := &StripeVerifier{endpoint: slowServer.URL}
	client := slowServer.Client()

	// Enforce 50ms context
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := verifier.Verify(ctx, client, "sk_live_test")
	if err == nil {
		t.Errorf("expected timeout error, got nil")
	}
}
