package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"aegis-cli/pkg/models"
)

type GroqVerifier struct {
	endpoint string
}

func NewGroqVerifier() *GroqVerifier {
	return &GroqVerifier{
		endpoint: "https://api.groq.com/openai/v1/models",
	}
}

func (g *GroqVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategoryGroq {
		return false
	}
	return strings.HasPrefix(token, "gsk_") && len(token) == 56
}

func (g *GroqVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "Groq",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "Groq",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return models.VerificationResult{
			Provider: "Groq",
			Status:   models.StatusActive,
			Details:  "Active Groq LPU API key verified with model access",
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "Groq",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked Groq API key (HTTP 401 Unauthorized)",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "Groq",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Groq API returned HTTP %d", resp.StatusCode),
		}, nil
	}
}
