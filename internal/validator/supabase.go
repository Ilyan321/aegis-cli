package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

type SupabaseVerifier struct {
	endpoint string
}

func NewSupabaseVerifier() *SupabaseVerifier {
	return &SupabaseVerifier{
		endpoint: "https://api.supabase.com/v1/projects",
	}
}

func (s *SupabaseVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategorySupabase {
		return false
	}
	return strings.HasPrefix(token, "sbp_") && len(token) == 44
}

func (s *SupabaseVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "Supabase",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "github.com/Ilyan321/aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "Supabase",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return models.VerificationResult{
			Provider: "Supabase",
			Status:   models.StatusActive,
			Details:  "Active Supabase personal access token verified",
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "Supabase",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked Supabase token (HTTP 401 Unauthorized)",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "Supabase",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Supabase API returned HTTP %d", resp.StatusCode),
		}, nil
	}
}
