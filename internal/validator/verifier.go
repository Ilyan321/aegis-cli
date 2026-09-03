package validator

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

const (
	// DefaultTimeout is the hard 1.5-second timeout enforced for all verification calls (PRD Section 4.5).
	DefaultTimeout = 1500 * time.Millisecond
	// RateLimitInterval enforces the 3 requests/second rate limit cap (PRD Section 6).
	RateLimitInterval = 334 * time.Millisecond
)

// ProviderVerifier defines the contract for verifying live token credentials.
type ProviderVerifier interface {
	Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error)
	Supports(category models.TokenCategory, token string) bool
}

// Registry manages registered provider verifiers and enforces rate limiting and timeouts.
type Registry struct {
	client    *http.Client
	verifiers []ProviderVerifier
	ticker    *time.Ticker
	limiter   <-chan time.Time
	mu        sync.Mutex
}

// NewRegistry initializes the verifier registry with standard providers.
func NewRegistry() *Registry {
	transport := &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   DefaultTimeout,
	}

	// Rate limiter ticker: ~3 requests/second
	ticker := time.NewTicker(RateLimitInterval)

	reg := &Registry{
		client:  client,
		ticker:  ticker,
		limiter: ticker.C,
	}

	// Register all active providers
	reg.verifiers = []ProviderVerifier{
		NewStripeVerifier(),
		NewGitHubVerifier(),
		NewOpenAIVerifier(),
		NewAWSVerifier(),
		NewHuggingFaceVerifier(),
		NewGitLabVerifier(),
		NewNPMVerifier(),
		NewDigitalOceanVerifier(),
		NewSendGridVerifier(),
		NewSupabaseVerifier(),
		NewGroqVerifier(),
		NewResendVerifier(),
		NewGrokVerifier(),
	}

	return reg
}

// VerifyFinding checks an individual finding against active provider APIs.
// Strictly enforces structural determinism to avoid leaking generic passwords.
func (r *Registry) VerifyFinding(ctx context.Context, finding *models.Finding) {
	// If finding is not category-specific or has no raw secret, mark skipped
	if finding.RawSecret == "" {
		finding.Verification = models.VerificationResult{
			Status:  models.StatusSkipped,
			Details: "No raw token available for verification",
		}
		return
	}

	var targetVerifier ProviderVerifier
	for _, v := range r.verifiers {
		if v.Supports(finding.Category, finding.RawSecret) {
			targetVerifier = v
			break
		}
	}

	// If no provider supports this exact token structure, skip active verification
	if targetVerifier == nil {
		finding.Verification = models.VerificationResult{
			Status:  models.StatusSkipped,
			Details: "No active verifier for token structure (protected against generic credential exfiltration)",
		}
		return
	}

	// Enforce 3 req/sec rate limit
	r.mu.Lock()
	select {
	case <-r.limiter:
	case <-ctx.Done():
		r.mu.Unlock()
		finding.Verification = models.VerificationResult{
			Status:  models.StatusError,
			Details: "Verification cancelled: " + ctx.Err().Error(),
		}
		return
	}
	r.mu.Unlock()

	// Enforce hard 1.5s timeout context
	verifyCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	start := time.Now()
	result, err := targetVerifier.Verify(verifyCtx, r.client, finding.RawSecret)
	result.LatencyMs = time.Since(start).Milliseconds()
	result.CheckedAt = time.Now()

	if err != nil && result.Status == "" {
		result.Status = models.StatusError
		result.Details = err.Error()
	}

	finding.Verification = result
}

// VerifyAll scans and enriches a slice of findings concurrently with bounded workers.
func (r *Registry) VerifyAll(ctx context.Context, findings []models.Finding) []models.Finding {
	if len(findings) == 0 {
		return findings
	}

	enriched := make([]models.Finding, len(findings))
	copy(enriched, findings)

	for i := range enriched {
		select {
		case <-ctx.Done():
			enriched[i].Verification = models.VerificationResult{
				Status:  models.StatusSkipped,
				Details: "Context cancelled",
			}
		default:
			r.VerifyFinding(ctx, &enriched[i])
		}
	}

	return enriched
}

// IsValidTokenFormat checks if the token is structurally valid before dispatching.
func IsValidTokenFormat(token string, prefix string, minLen int) bool {
	token = strings.TrimSpace(token)
	return strings.HasPrefix(token, prefix) && len(token) >= minLen
}

// Close gracefully terminates the registry rate-limiting ticker.
func (r *Registry) Close() {
	if r.ticker != nil {
		r.ticker.Stop()
	}
}
