package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"aegis-cli/pkg/models"
)

type GitLabVerifier struct {
	endpoint string
}

func NewGitLabVerifier() *GitLabVerifier {
	return &GitLabVerifier{
		endpoint: "https://gitlab.com/api/v4/user",
	}
}

func (g *GitLabVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategoryGitLab {
		return false
	}
	return strings.HasPrefix(token, "glpat-") && len(token) == 26
}

func (g *GitLabVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "GitLab",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "GitLab",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return models.VerificationResult{
			Provider: "GitLab",
			Status:   models.StatusActive,
			Details:  "Active GitLab personal access token verified",
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "GitLab",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked GitLab token (HTTP 401 Unauthorized)",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "GitLab",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("GitLab API returned HTTP %d", resp.StatusCode),
		}, nil
	}
}
