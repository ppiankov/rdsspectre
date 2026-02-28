package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// JSONReporter outputs spectre/v1 JSON.
type JSONReporter struct {
	Writer io.Writer
}

// Generate writes the JSON report.
func (r *JSONReporter) Generate(data Data) error {
	envelope := map[string]any{
		"schema":    "spectre/v1",
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
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
}
