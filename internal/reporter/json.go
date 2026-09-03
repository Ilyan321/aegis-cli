package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Ilyan321/aegis-cli/pkg/models"
)

// GenerateJSONReport serializes the scan report to formatted JSON.
func GenerateJSONReport(report *models.ScanReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// WriteJSONReport writes the report to a destination io.Writer or file on disk.
func WriteJSONReport(report *models.ScanReport, filePath string, stdout io.Writer) error {
	data, err := GenerateJSONReport(report)
	if err != nil {
		return fmt.Errorf("failed to generate JSON report: %w", err)
	}

	if filePath != "" {
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			return fmt.Errorf("failed to write report to %s: %w", filePath, err)
		}
		return nil
	}

	_, err = stdout.Write(append(data, '\n'))
	return err
}
