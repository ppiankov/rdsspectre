package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ppiankov/rdsspectre/internal/analyzer"
	"github.com/ppiankov/rdsspectre/internal/config"
	"github.com/ppiankov/rdsspectre/internal/database"
	"github.com/ppiankov/rdsspectre/internal/rds"
	"github.com/ppiankov/rdsspectre/internal/report"
	"github.com/spf13/cobra"
)

var awsFlags struct {
	region         string
	profile        string
	idleDays       int
	staleDays      int
	cpuThreshold   float64
	idleCPU        float64
	metricDays     int
	format         string
	outputFile     string
	minMonthlyCost float64
	noProgress     bool
	timeout        time.Duration
	excludeTags    []string
}

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Audit AWS RDS instances for waste and security issues",
	Long: `Scan all RDS instances in an AWS account for idle, oversized, unencrypted,
and misconfigured databases. Each finding includes severity and estimated monthly waste.`,
	RunE: runAWS,
}

func init() {
	awsCmd.Flags().StringVar(&awsFlags.region, "region", "", "AWS region (default: from AWS config)")
	awsCmd.Flags().StringVar(&awsFlags.profile, "profile", "", "AWS profile name")
	awsCmd.Flags().IntVar(&awsFlags.idleDays, "idle-days", 14, "Days of low activity to flag as idle")
	awsCmd.Flags().IntVar(&awsFlags.staleDays, "stale-days", 90, "Snapshot age threshold in days")
	awsCmd.Flags().Float64Var(&awsFlags.cpuThreshold, "cpu-threshold", 20.0, "Flag oversized if p95 CPU below this (%)")
	awsCmd.Flags().Float64Var(&awsFlags.idleCPU, "idle-cpu", 5.0, "Flag idle if avg CPU below this (%)")
	awsCmd.Flags().IntVar(&awsFlags.metricDays, "metric-days", 14, "CloudWatch metric lookback period (days)")
	awsCmd.Flags().StringVar(&awsFlags.format, "format", "text", "Output format: text, json, sarif, spectrehub")
	awsCmd.Flags().StringVarP(&awsFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	awsCmd.Flags().Float64Var(&awsFlags.minMonthlyCost, "min-monthly-cost", 0.10, "Minimum monthly cost to report ($)")
	awsCmd.Flags().BoolVar(&awsFlags.noProgress, "no-progress", false, "Disable progress output")
	awsCmd.Flags().DurationVar(&awsFlags.timeout, "timeout", 10*time.Minute, "Scan timeout")
	awsCmd.Flags().StringSliceVar(&awsFlags.excludeTags, "exclude-tags", nil, "Exclude resources by tag (Key=Value, comma-separated)")
}

func runAWS(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if awsFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, awsFlags.timeout)
		defer cancel()
	}

	// Load config and apply defaults
	cfg, err := config.Load(".")
	if err != nil {
		slog.Warn("Failed to load config file", "error", err)
	}
	applyAWSConfigDefaults(cfg)

	// Resolve profile and region
	profile := awsFlags.profile
	if profile == "" {
		profile = cfg.Profile
	}
	region := awsFlags.region
	if region == "" && len(cfg.Regions) > 0 {
		region = cfg.Regions[0]
	}

	// Initialize AWS client
	client, err := rds.NewClient(ctx, profile, region)
	if err != nil {
		return enhanceError("initialize AWS client", err)
	}

	resolvedRegion := client.Region()
	if resolvedRegion == "" {
		return fmt.Errorf("no AWS region configured; use --region or set AWS_REGION")
	}
	slog.Info("Scanning RDS", "region", resolvedRegion)

	// Build scan config
	excludeIDs := make(map[string]bool, len(cfg.Exclude.ResourceIDs))
	for _, id := range cfg.Exclude.ResourceIDs {
		excludeIDs[id] = true
	}
	excludeTags := parseExcludeTags(cfg.Exclude.Tags, awsFlags.excludeTags)

	scanCfg := database.ScanConfig{
		IdleDays:       awsFlags.idleDays,
		CPUThreshold:   awsFlags.cpuThreshold,
		IdleCPU:        awsFlags.idleCPU,
		MetricDays:     awsFlags.metricDays,
		StaleDays:      awsFlags.staleDays,
		MinMonthlyCost: awsFlags.minMonthlyCost,
		Exclude: database.ExcludeConfig{
			ResourceIDs: excludeIDs,
			Tags:        excludeTags,
		},
	}

	// Run scanner
	scanner := rds.NewRDSScanner(client.NewRDSClient(), client.NewCloudWatchClient(), resolvedRegion)

	var progressFn func(database.ScanProgress)
	if !awsFlags.noProgress {
		progressFn = func(p database.ScanProgress) {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", p.Region, p.Message)
		}
	}

	result := scanner.Scan(ctx, scanCfg, progressFn)

	// Analyze results
	analysis := analyzer.Analyze(result, analyzer.AnalyzerConfig{
		MinMonthlyCost: awsFlags.minMonthlyCost,
	})

	// Build report data
	data := report.Data{
		Tool:      "rdsspectre",
		Version:   version,
		Timestamp: time.Now().UTC(),
		Target: report.Target{
			Type:    "rds",
			URIHash: computeTargetHash("aws", []string{resolvedRegion}, profile),
		},
		Config: report.ReportConfig{
			Provider:       "aws",
			Regions:        []string{resolvedRegion},
			IdleDays:       awsFlags.idleDays,
			StaleDays:      awsFlags.staleDays,
			CPUThreshold:   awsFlags.cpuThreshold,
			MinMonthlyCost: awsFlags.minMonthlyCost,
		},
		Findings: analysis.Findings,
		Summary:  analysis.Summary,
		Errors:   analysis.Errors,
	}

	// Select and run reporter
	reporter, err := selectReporter(awsFlags.format, awsFlags.outputFile)
	if err != nil {
		return err
	}
	return reporter.Generate(data)
}

func applyAWSConfigDefaults(cfg config.Config) {
	if awsFlags.format == "text" && cfg.Format != "" {
		awsFlags.format = cfg.Format
	}
	if awsFlags.idleDays == 14 && cfg.IdleDays > 0 {
		awsFlags.idleDays = cfg.IdleDays
	}
	if awsFlags.staleDays == 90 && cfg.StaleDays > 0 {
		awsFlags.staleDays = cfg.StaleDays
	}
	if awsFlags.cpuThreshold == 20.0 && cfg.CPUThreshold > 0 {
		awsFlags.cpuThreshold = cfg.CPUThreshold
	}
	if awsFlags.metricDays == 14 && cfg.MetricDays > 0 {
		awsFlags.metricDays = cfg.MetricDays
	}
	if awsFlags.minMonthlyCost == 0.10 && cfg.MinMonthlyCost > 0 {
		awsFlags.minMonthlyCost = cfg.MinMonthlyCost
	}
}

func selectReporter(format, outputFile string) (report.Reporter, error) {
	w := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return nil, fmt.Errorf("create output file: %w", err)
		}
		w = f
	}

	switch format {
	case "json":
		return &report.JSONReporter{Writer: w}, nil
	case "text":
		return &report.TextReporter{Writer: w}, nil
	case "sarif":
		return &report.SARIFReporter{Writer: w}, nil
	case "spectrehub":
		return &report.SpectreHubReporter{Writer: w}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s (use text, json, sarif, or spectrehub)", format)
	}
}

func parseExcludeTags(configTags, flagTags []string) map[string]string {
	tags := make(map[string]string)
	for _, s := range configTags {
		if k, v, ok := strings.Cut(s, "="); ok {
			tags[k] = v
		} else {
			tags[s] = ""
		}
	}
	for _, s := range flagTags {
		if k, v, ok := strings.Cut(s, "="); ok {
			tags[k] = v
		} else {
			tags[s] = ""
		}
	}
	if len(tags) == 0 {
		return nil
	}
	return tags
}
