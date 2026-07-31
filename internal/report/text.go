package report

import (
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/ppiankov/rdsspectre/internal/database"
)

// WO-10: severityRank orders findings critical-first when rendering text output.
// Unranked severities (should not occur) sort last, after low.
var severityRank = map[database.Severity]int{
	database.SeverityCritical: 0,
	database.SeverityHigh:     1,
	database.SeverityMedium:   2,
	database.SeverityLow:      3,
}

func rankSeverity(s database.Severity) int {
	if rank, ok := severityRank[s]; ok {
		return rank
	}
	return len(severityRank)
}

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

	// WO-10: sort a clone by severity descending; never mutate the caller's slice.
	sorted := make([]database.Finding, len(data.Findings))
	copy(sorted, data.Findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		return rankSeverity(sorted[i].Severity) < rankSeverity(sorted[j].Severity)
	})

	r.printf(w, "SEVERITY\tTYPE\tRESOURCE\tREGION\tWASTE/MO\tMESSAGE\n")
	for _, f := range sorted {
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
