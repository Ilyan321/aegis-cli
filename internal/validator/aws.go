package validator

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"aegis-cli/pkg/models"
)

type AWSVerifier struct {
	endpoint string
}

func NewAWSVerifier() *AWSVerifier {
	return &AWSVerifier{
		endpoint: "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
	}
}

func (a *AWSVerifier) Supports(category models.TokenCategory, token string) bool {
	if category != models.CategoryAWS {
		return false
	}
	return strings.HasPrefix(token, "AKIA") && len(token) == 20
}

func (a *AWSVerifier) Verify(ctx context.Context, client *http.Client, token string) (models.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, nil)
	if err != nil {
		return models.VerificationResult{
			Provider: "AWS",
			Status:   models.StatusError,
			Details:  err.Error(),
		}, err
	}

	// Sign mock query header with the candidate Access Key ID
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/20260903/us-east-1/sts/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000", token))
	req.Header.Set("User-Agent", "aegis-cli/1.0.0")

	resp, err := client.Do(req)
	if err != nil {
		return models.VerificationResult{
			Provider: "AWS",
			Status:   models.StatusError,
			Details:  fmt.Sprintf("Connection error: %v", err),
		}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	bodyStr := string(body)

	// AWS STS returns specific XML error codes:
	// - InvalidClientTokenId: The key does not exist or has been permanently deleted
	// - SignatureDoesNotMatch: The key exists and is recognized by IAM, but the test signature was rejected
	// - 200 OK: Caller identity returned directly
	if strings.Contains(bodyStr, "InvalidClientTokenId") {
		return models.VerificationResult{
			Provider: "AWS",
			Status:   models.StatusRevoked,
			Details:  "Invalid or revoked AWS Access Key (AWS STS: InvalidClientTokenId)",
		}, nil
	}

	if strings.Contains(bodyStr, "SignatureDoesNotMatch") {
		return models.VerificationResult{
			Provider: "AWS",
			Status:   models.StatusActive,
			Details:  "Active AWS IAM Access Key verified (Recognized by AWS STS endpoint)",
		}, nil
	}

	if resp.StatusCode == http.StatusOK {
		return models.VerificationResult{
			Provider: "AWS",
			Status:   models.StatusActive,
			Details:  "Active AWS IAM caller identity verified",
		}, nil
	}

	return models.VerificationResult{
		Provider: "AWS",
		Status:   models.StatusError,
		Details:  fmt.Sprintf("AWS STS returned HTTP %d", resp.StatusCode),
	}, nil
}
