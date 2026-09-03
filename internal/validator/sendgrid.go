package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

type SendGridVerifier struct {
	endpoint string
}

func NewSendGridVerifier() *SendGridVerifier {
	return &SendGridVerifier{
		endpoint: "https://api.sendgrid.com/v3/scopes",
	}
}

func (s *SendGridVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategorySendGrid {
		return false
	}
	return strings.HasPrefix(token, "SG.") && len(token) >= 69
}

func (s *SendGridVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "SendGrid",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "github.com/Ilyan321/aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "SendGrid",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return models.VerificationResult{
			Provider: "SendGrid",
			Status:   models.StatusActive,
			Details:  "Active SendGrid API key verified with scope access",
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "SendGrid",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked SendGrid API key (HTTP 401 Unauthorized)",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "SendGrid",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("SendGrid API returned HTTP %d", resp.StatusCode),
		}, nil
	}
}
