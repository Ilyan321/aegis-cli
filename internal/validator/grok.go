package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

type GrokVerifier struct {
	endpoint string
}

func NewGrokVerifier() *GrokVerifier {
	return &GrokVerifier{
		endpoint: "https://api.x.ai/v1/models",
	}
}

func (g *GrokVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategoryGrok {
		return false
	}
	return strings.HasPrefix(token, "xai-") && len(token) >= 36
}

func (g *GrokVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "Grok",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "github.com/Ilyan321/aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "Grok",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return models.VerificationResult{
			Provider: "Grok",
			Status:   models.StatusActive,
			Details:  "Active xAI (Grok) API key verified with model access",
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "Grok",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked xAI (Grok) API key (HTTP 401 Unauthorized)",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "Grok",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("xAI API returned HTTP %d", resp.StatusCode),
		}, nil
	}
}
