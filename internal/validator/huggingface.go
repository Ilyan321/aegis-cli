package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

type HuggingFaceVerifier struct {
	endpoint string
}

func NewHuggingFaceVerifier() *HuggingFaceVerifier {
	return &HuggingFaceVerifier{
		endpoint: "https://huggingface.co/api/whoami-v2",
	}
}

func (h *HuggingFaceVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategoryHuggingFace {
		return false
	}
	return strings.HasPrefix(token, "hf_") && len(token) == 37
}

func (h *HuggingFaceVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "HuggingFace",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "github.com/Ilyan321/aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "HuggingFace",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return models.VerificationResult{
			Provider: "HuggingFace",
			Status:   models.StatusActive,
			Details:  "Active Hugging Face user token verified",
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "HuggingFace",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked Hugging Face token (HTTP 401 Unauthorized)",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "HuggingFace",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Hugging Face API returned HTTP %d", resp.StatusCode),
		}, nil
	}
}
