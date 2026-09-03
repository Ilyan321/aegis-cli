package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

type DigitalOceanVerifier struct {
	endpoint string
}

func NewDigitalOceanVerifier() *DigitalOceanVerifier {
	return &DigitalOceanVerifier{
		endpoint: "https://api.digitalocean.com/v2/account",
	}
}

func (d *DigitalOceanVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategoryDigitalOcean {
		return false
	}
	return strings.HasPrefix(token, "dop_v1_") && len(token) == 71
}

func (d *DigitalOceanVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "DigitalOcean",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "github.com/Ilyan321/aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "DigitalOcean",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return models.VerificationResult{
			Provider: "DigitalOcean",
			Status:   models.StatusActive,
			Details:  "Active DigitalOcean API token verified with account read capability",
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "DigitalOcean",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked DigitalOcean token (HTTP 401 Unauthorized)",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "DigitalOcean",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("DigitalOcean API returned HTTP %d", resp.StatusCode),
		}, nil
	}
}
