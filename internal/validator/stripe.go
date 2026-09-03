package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"aegis-cli/pkg/models"
)

type StripeVerifier struct {
	endpoint string
}

func NewStripeVerifier() *StripeVerifier {
	return &StripeVerifier{
		endpoint: "https://api.stripe.com/v1/balance",
	}
}

func (s *StripeVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategoryStripe {
		return false
	}
	return strings.HasPrefix(token, "sk_live_") || strings.HasPrefix(token, "rk_live_")
}

func (s *StripeVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "Stripe",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "Stripe",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return models.VerificationResult{
			Provider: "Stripe",
			Status:   models.StatusActive,
			Details:  "Active Stripe live credential verified with balance read capability",
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "Stripe",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked Stripe key (HTTP 401 Unauthorized)",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "Stripe",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Unexpected response from Stripe: HTTP %d", resp.StatusCode),
		}, nil
	}
}
