package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

type ResendVerifier struct {
	endpoint string
}

func NewResendVerifier() *ResendVerifier {
	return &ResendVerifier{
		endpoint: "https://api.resend.com/api-keys",
	}
}

func (r *ResendVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategoryResend {
		return false
	}
	return strings.HasPrefix(token, "re_") && len(token) >= 35
}

func (r *ResendVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "Resend",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "github.com/Ilyan321/aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "Resend",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return models.VerificationResult{
			Provider: "Resend",
			Status:   models.StatusActive,
			Details:  "Active Resend email API key verified",
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "Resend",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked Resend API key (HTTP 401 Unauthorized)",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "Resend",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Resend API returned HTTP %d", resp.StatusCode),
		}, nil
	}
}
