package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

type OpenAIVerifier struct {
	endpoint string
}

func NewOpenAIVerifier() *OpenAIVerifier {
	return &OpenAIVerifier{
		endpoint: "https://api.openai.com/v1/models",
	}
}

func (o *OpenAIVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategoryOpenAI {
		return false
	}
	return strings.HasPrefix(token, "sk-")
}

func (o *OpenAIVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "OpenAI",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "github.com/Ilyan321/aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "OpenAI",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	bodyStr := string(body)

	switch resp.StatusCode {
	case http.StatusOK:
		return models.VerificationResult{
			Provider: "OpenAI",
			Status:   models.StatusActive,
			Details:  "Active OpenAI API key verified with model access",
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "OpenAI",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked OpenAI API key (HTTP 401 Unauthorized)",
		}, nil
	case http.StatusTooManyRequests:
		if strings.Contains(bodyStr, "insufficient_quota") {
			return models.VerificationResult{
				Provider: "OpenAI",
				Status:   models.StatusActive,
				Details:  "Valid OpenAI key (Quota exceeded / insufficient credits)",
			}, nil
		}
		return models.VerificationResult{
			Provider: "OpenAI",
			Status:   models.StatusError,
			Details:  "OpenAI rate limit exceeded during verification",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "OpenAI",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("OpenAI API returned HTTP %d", resp.StatusCode),
		}, nil
	}
}
