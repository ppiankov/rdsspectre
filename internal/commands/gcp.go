package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ppiankov/rdsspectre/internal/analyzer"
	"github.com/ppiankov/rdsspectre/internal/cloudsql"
	"github.com/ppiankov/rdsspectre/internal/config"
	"github.com/ppiankov/rdsspectre/internal/database"
	"github.com/ppiankov/rdsspectre/internal/report"
	"github.com/spf13/cobra"
)

var gcpFlags struct {
	project        string
	format         string
	outputFile     string
	minMonthlyCost float64
	noProgress     bool
	timeout        time.Duration
	excludeTags    []string
}

var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Audit GCP Cloud SQL instances for waste and security issues",
	Long: `Scan all Cloud SQL instances in a GCP project for unencrypted, publicly accessible,
and misconfigured databases. Each finding includes severity and estimated monthly waste.`,
	RunE: runGCP,
}

func init() {
	gcpCmd.Flags().StringVar(&gcpFlags.project, "project", "", "GCP project ID (required)")
	gcpCmd.Flags().StringVar(&gcpFlags.format, "format", "text", "Output format: text, json, sarif, spectrehub")
	gcpCmd.Flags().StringVarP(&gcpFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	gcpCmd.Flags().Float64Var(&gcpFlags.minMonthlyCost, "min-monthly-cost", 0.10, "Minimum monthly cost to report ($)")
	gcpCmd.Flags().BoolVar(&gcpFlags.noProgress, "no-progress", false, "Disable progress output")
	gcpCmd.Flags().DurationVar(&gcpFlags.timeout, "timeout", 10*time.Minute, "Scan timeout")
	gcpCmd.Flags().StringSliceVar(&gcpFlags.excludeTags, "exclude-tags", nil, "Exclude resources by label (Key=Value, comma-separated)")
}

func runGCP(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if gcpFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, gcpFlags.timeout)
		defer cancel()
	}

	// Load config and apply defaults
	cfg, err := config.Load(".")
	if err != nil {
		slog.Warn("Failed to load config file", "error", err)
	}
	applyGCPConfigDefaults(cfg)

	// Resolve project
	project := gcpFlags.project
	if project == "" {
		project = cfg.Project
	}
	if project == "" {
		return fmt.Errorf("--project is required (or set project in .rdsspectre.yaml)")
	}

	slog.Info("Scanning Cloud SQL", "project", project)

	// Initialize client
	client, err := cloudsql.NewClient(ctx, project)
	if err != nil {
		return enhanceError("initialize Cloud SQL client", err)
	}

	// Build scan config
	excludeIDs := make(map[string]bool, len(cfg.Exclude.ResourceIDs))
	for _, id := range cfg.Exclude.ResourceIDs {
		excludeIDs[id] = true
	}
	excludeTags := parseExcludeTags(cfg.Exclude.Tags, gcpFlags.excludeTags)

	scanCfg := database.ScanConfig{
		MinMonthlyCost: gcpFlags.minMonthlyCost,
		Exclude: database.ExcludeConfig{
			ResourceIDs: excludeIDs,
			Tags:        excludeTags,
		},
	}

	// Run scanner
	scanner := cloudsql.NewCloudSQLScanner(client, project)

	var progressFn func(database.ScanProgress)
	if !gcpFlags.noProgress {
		progressFn = func(p database.ScanProgress) {
			_, _ = fmt.Fprintf(os.Stderr, "[%s] %s\n", p.Region, p.Message)
		}
	}

	result := scanner.Scan(ctx, scanCfg, progressFn)

	// Analyze results
	analysis := analyzer.Analyze(result, analyzer.AnalyzerConfig{
		MinMonthlyCost: gcpFlags.minMonthlyCost,
	})

	// Build report data
	data := report.Data{
		Tool:      "rdsspectre",
		Version:   version,
		Timestamp: time.Now().UTC(),
		Target: report.Target{
			Type:    "cloudsql",
			URIHash: computeTargetHash("gcp", nil, project),
		},
		Config: report.ReportConfig{
			Provider:       "gcp",
			Regions:        []string{project},
			MinMonthlyCost: gcpFlags.minMonthlyCost,
		},
		Findings: analysis.Findings,
		Summary:  analysis.Summary,
		Errors:   analysis.Errors,
	}

	// Select and run reporter
	reporter, err := selectReporter(gcpFlags.format, gcpFlags.outputFile)
	if err != nil {
		return err
	}
	return reporter.Generate(data)
}

func applyGCPConfigDefaults(cfg config.Config) {
	if gcpFlags.format == "text" && cfg.Format != "" {
		gcpFlags.format = cfg.Format
	}
	if gcpFlags.minMonthlyCost == 0.10 && cfg.MinMonthlyCost > 0 {
		gcpFlags.minMonthlyCost = cfg.MinMonthlyCost
	}
}
