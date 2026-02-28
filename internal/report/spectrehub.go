package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// SpectreHubReporter outputs the SpectreHub envelope format.
type SpectreHubReporter struct {
	Writer io.Writer
}

// Generate writes the SpectreHub report.
func (r *SpectreHubReporter) Generate(data Data) error {
	envelope := map[string]any{
		"schema":    "spectrehub/v1",
		"tool":      data.Tool,
		"version":   data.Version,
		"timestamp": data.Timestamp,
		"target":    data.Target,
		"config":    data.Config,
		"findings":  data.Findings,
		"summary":   data.Summary,
		"errors":    data.Errors,
	}
	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope); err != nil {
		return fmt.Errorf("encode SpectreHub: %w", err)
	}
	return nil
}
