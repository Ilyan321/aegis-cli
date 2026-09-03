package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

type NPMVerifier struct {
	endpoint string
}

func NewNPMVerifier() *NPMVerifier {
	return &NPMVerifier{
		endpoint: "https://registry.npmjs.org/-/whoami",
	}
}

func (n *NPMVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategoryNPM {
		return false
	}
	return strings.HasPrefix(token, "npm_") && len(token) == 40
}

func (n *NPMVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "NPM",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "github.com/Ilyan321/aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "NPM",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return models.VerificationResult{
			Provider: "NPM",
			Status:   models.StatusActive,
			Details:  "Active NPM publishing access token verified",
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "NPM",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked NPM token (HTTP 401 Unauthorized)",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "NPM",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("NPM registry returned HTTP %d", resp.StatusCode),
		}, nil
	}
}
