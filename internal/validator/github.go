package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"aegis-cli/pkg/models"
)

type GitHubVerifier struct {
	endpoint string
}

func NewGitHubVerifier() *GitHubVerifier {
	return &GitHubVerifier{
		endpoint: "https://api.github.com/user",
	}
}

func (g *GitHubVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategoryGitHub {
		return false
	}
	return strings.HasPrefix(token, "ghp_") || strings.HasPrefix(token, "github_pat_")
}

func (g *GitHubVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "GitHub",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "aegis-cli/1.0.0")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "GitHub",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		scopes := resp.Header.Get("X-OAuth-Scopes")
		details := "Active GitHub token verified"
		if scopes != "" {
			details += fmt.Sprintf(" (Scopes: %s)", scopes)
		}
		return models.VerificationResult{
			Provider: "GitHub",
			Status:   models.StatusActive,
			Details:  details,
		}, nil
	case http.StatusUnauthorized:
		return models.VerificationResult{
			Provider: "GitHub",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked GitHub token (HTTP 401 Bad Credentials)",
		}, nil
	default:
		return models.VerificationResult{
			Provider: "GitHub",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("GitHub API returned HTTP %d", resp.StatusCode),
		}, nil
	}
}
