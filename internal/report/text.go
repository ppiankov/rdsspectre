package report

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
)

// TextReporter outputs human-readable text.
type TextReporter struct {
	Writer io.Writer
}

// Generate writes the text report.
func (r *TextReporter) Generate(data Data) error {
	w := tabwriter.NewWriter(r.Writer, 0, 0, 2, ' ', 0)

	r.println(w, "rdsspectre scan results")
	r.println(w, fmt.Sprintf("Provider: %s  Regions: %v", data.Config.Provider, data.Config.Regions))
	r.println(w, "")

	if len(data.Findings) == 0 {
		r.println(w, "No findings.")
		return w.Flush()
	}

	r.printf(w, "SEVERITY\tTYPE\tRESOURCE\tREGION\tWASTE/MO\tMESSAGE\n")
	for _, f := range data.Findings {
		r.printf(w, "%s\t%s\t%s\t%s\t$%.2f\t%s\n",
			f.Severity, f.ID, f.ResourceID, f.Region, f.EstimatedMonthlyWaste, f.Message)
	}

	if err := w.Flush(); err != nil {
		return err
	}

	r.println(r.Writer, "")
	writeTextSummary(r.Writer, data)
	return nil
}

func writeTextSummary(w io.Writer, data Data) {
	_, _ = fmt.Fprintf(w, "Summary:\n")
	_, _ = fmt.Fprintf(w, "  Instances scanned: %d\n", data.Summary.InstancesScanned)
	_, _ = fmt.Fprintf(w, "  Resources scanned: %d\n", data.Summary.ResourcesScanned)
	_, _ = fmt.Fprintf(w, "  Total findings:    %d\n", data.Summary.TotalFindings)
	_, _ = fmt.Fprintf(w, "  Monthly waste:     $%.2f\n", data.Summary.TotalMonthlyWaste)

	if len(data.Summary.BySeverity) > 0 {
		_, _ = fmt.Fprintf(w, "  By severity:       %s\n", formatMapSorted(data.Summary.BySeverity))
	}
	if len(data.Summary.ByFindingType) > 0 {
		_, _ = fmt.Fprintf(w, "  By finding type:   %s\n", formatMapSorted(data.Summary.ByFindingType))
	}

	if len(data.Errors) > 0 {
		_, _ = fmt.Fprintf(w, "\nErrors:\n")
		for _, e := range data.Errors {
			_, _ = fmt.Fprintf(w, "  - %s\n", e)
		}
	}
}

func (r *TextReporter) printf(w io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		_, _ = fmt.Fprintf(r.Writer, "write error: %v\n", err)
	}
}

func (r *TextReporter) println(w io.Writer, s string) {
	if _, err := fmt.Fprintln(w, s); err != nil {
		_, _ = fmt.Fprintf(r.Writer, "write error: %v\n", err)
	}
}

func formatMapSorted(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	result := ""
	for i, k := range keys {
		if i > 0 {
			result += ", "
		}
		result += fmt.Sprintf("%s=%d", k, m[k])
	}
	return result
}
