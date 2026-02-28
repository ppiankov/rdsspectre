package commands

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ppiankov/rdsspectre/internal/config"
)

func TestExecuteVersion(t *testing.T) {
	version = "1.0.0"
	commit = "abc123"
	date = "2026-02-28"

	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
}

func TestExecuteNoArgs(t *testing.T) {
	rootCmd.SetArgs([]string{})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
}

func TestVersionCommand(t *testing.T) {
	version = "0.1.0"
	commit = "abc123"
	date = "2026-02-28"

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
}

func TestEnhanceErrorWithHint(t *testing.T) {
	tests := []struct {
		errMsg string
		hint   string
	}{
		{"NoCredentialProviders: no valid providers", "Configure AWS credentials"},
		{"ExpiredToken: token expired", "session token expired"},
		{"AccessDenied: not authorized", "Insufficient permissions"},
		{"RequestExpired: request timed out", "Check system clock"},
		{"Throttling: rate exceeded", "API rate limit hit"},
		{"could not find default credentials", "gcloud auth"},
	}

	for _, tt := range tests {
		err := enhanceError("test", errors.New(tt.errMsg))
		if !strings.Contains(err.Error(), tt.hint) {
			t.Errorf("enhanceError(%q) missing hint %q, got: %s", tt.errMsg, tt.hint, err)
		}
	}
}

func TestEnhanceErrorWithoutHint(t *testing.T) {
	err := enhanceError("scan", errors.New("some random error"))
	if strings.Contains(err.Error(), "hint:") {
		t.Errorf("unexpected hint in: %s", err)
	}
	if !strings.Contains(err.Error(), "scan:") {
		t.Errorf("missing action prefix in: %s", err)
	}
}

func TestComputeTargetHash(t *testing.T) {
	h1 := computeTargetHash("aws", []string{"us-east-1"}, "")
	h2 := computeTargetHash("aws", []string{"us-east-1"}, "")
	if h1 != h2 {
		t.Error("same inputs should produce same hash")
	}

	h3 := computeTargetHash("gcp", []string{"us-central1"}, "my-project")
	if h1 == h3 {
		t.Error("different inputs should produce different hashes")
	}

	if !strings.HasPrefix(h1, "sha256:") {
		t.Errorf("hash should start with sha256:, got %q", h1)
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(origDir); err != nil {
			t.Log("failed to restore dir:", err)
		}
	})
}

func TestRunInit(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	initFlags.force = false
	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit() error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, ".rdsspectre.yaml")); err != nil {
		t.Error("config file not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "rdsspectre-policy.json")); err != nil {
		t.Error("policy file not created")
	}
}

func TestRunInitNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	if err := os.WriteFile(filepath.Join(dir, ".rdsspectre.yaml"), []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	initFlags.force = false
	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".rdsspectre.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing" {
		t.Error("config file should not be overwritten without --force")
	}
}

func TestRunInitForce(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	if err := os.WriteFile(filepath.Join(dir, ".rdsspectre.yaml"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	initFlags.force = true
	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".rdsspectre.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "old" {
		t.Error("config file should be overwritten with --force")
	}
}

func TestSelectReporter(t *testing.T) {
	tests := []struct {
		format  string
		wantErr bool
	}{
		{"text", false},
		{"json", false},
		{"sarif", false},
		{"spectrehub", false},
		{"invalid", true},
	}
	for _, tt := range tests {
		r, err := selectReporter(tt.format, "")
		if tt.wantErr {
			if err == nil {
				t.Errorf("selectReporter(%q) should error", tt.format)
			}
		} else {
			if err != nil {
				t.Errorf("selectReporter(%q) error: %v", tt.format, err)
			}
			if r == nil {
				t.Errorf("selectReporter(%q) returned nil reporter", tt.format)
			}
		}
	}
}

func TestParseExcludeTags(t *testing.T) {
	tags := parseExcludeTags(
		[]string{"env=production", "team=platform"},
		[]string{"owner=devops"},
	)

	if tags["env"] != "production" {
		t.Errorf("env = %q, want production", tags["env"])
	}
	if tags["owner"] != "devops" {
		t.Errorf("owner = %q, want devops", tags["owner"])
	}
}

func TestParseExcludeTagsEmpty(t *testing.T) {
	tags := parseExcludeTags(nil, nil)
	if tags != nil {
		t.Error("expected nil for empty tags")
	}
}

func TestApplyAWSConfigDefaults(t *testing.T) {
	awsFlags.format = "text"
	awsFlags.idleDays = 14
	awsFlags.staleDays = 90
	awsFlags.cpuThreshold = 20.0
	awsFlags.metricDays = 14
	awsFlags.minMonthlyCost = 0.10

	cfg := config.Config{
		Format:         "json",
		IdleDays:       30,
		StaleDays:      180,
		CPUThreshold:   15.0,
		MetricDays:     7,
		MinMonthlyCost: 1.0,
	}

	applyAWSConfigDefaults(cfg)

	if awsFlags.format != "json" {
		t.Errorf("format = %q, want json", awsFlags.format)
	}
	if awsFlags.idleDays != 30 {
		t.Errorf("idleDays = %d, want 30", awsFlags.idleDays)
	}
	if awsFlags.staleDays != 180 {
		t.Errorf("staleDays = %d, want 180", awsFlags.staleDays)
	}

	// Reset
	awsFlags.format = "text"
	awsFlags.idleDays = 14
	awsFlags.staleDays = 90
	awsFlags.cpuThreshold = 20.0
	awsFlags.metricDays = 14
	awsFlags.minMonthlyCost = 0.10
}

func TestSelectReporterOutputFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "out.json")
	r, err := selectReporter("json", f)
	if err != nil {
		t.Fatalf("selectReporter() error: %v", err)
	}
	if r == nil {
		t.Fatal("selectReporter() returned nil")
	}
}

func TestSelectReporterBadPath(t *testing.T) {
	_, err := selectReporter("json", "/nonexistent/dir/file.json")
	if err == nil {
		t.Error("expected error for bad output path")
	}
}

func TestParseExcludeTagsKeyOnly(t *testing.T) {
	tags := parseExcludeTags([]string{"temporary"}, nil)
	if v, ok := tags["temporary"]; !ok || v != "" {
		t.Errorf("key-only tag: got %q=%q, want empty value", "temporary", v)
	}
}

func TestApplyAWSConfigDefaultsNoOverride(t *testing.T) {
	// Defaults should not override when config has zero values
	awsFlags.format = "text"
	awsFlags.idleDays = 14
	cfg := config.Config{} // all zero
	applyAWSConfigDefaults(cfg)
	if awsFlags.format != "text" {
		t.Errorf("format should remain text, got %q", awsFlags.format)
	}
	if awsFlags.idleDays != 14 {
		t.Errorf("idleDays should remain 14, got %d", awsFlags.idleDays)
	}
}

func TestApplyGCPConfigDefaults(t *testing.T) {
	gcpFlags.format = "text"
	gcpFlags.minMonthlyCost = 0.10

	cfg := config.Config{
		Format:         "json",
		MinMonthlyCost: 5.0,
	}
	applyGCPConfigDefaults(cfg)

	if gcpFlags.format != "json" {
		t.Errorf("format = %q, want json", gcpFlags.format)
	}
	if gcpFlags.minMonthlyCost != 5.0 {
		t.Errorf("minMonthlyCost = %f, want 5.0", gcpFlags.minMonthlyCost)
	}

	// Reset
	gcpFlags.format = "text"
	gcpFlags.minMonthlyCost = 0.10
}

func TestApplyGCPConfigDefaultsNoOverride(t *testing.T) {
	gcpFlags.format = "text"
	gcpFlags.minMonthlyCost = 0.10

	cfg := config.Config{} // all zero
	applyGCPConfigDefaults(cfg)

	if gcpFlags.format != "text" {
		t.Errorf("format should remain text, got %q", gcpFlags.format)
	}
	if gcpFlags.minMonthlyCost != 0.10 {
		t.Errorf("minMonthlyCost should remain 0.10, got %f", gcpFlags.minMonthlyCost)
	}
}

func TestRunGCPMissingProject(t *testing.T) {
	gcpFlags.project = ""
	rootCmd.SetArgs([]string{"gcp"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for missing project")
	}
}

func TestGCPHelpFlags(t *testing.T) {
	rootCmd.SetArgs([]string{"gcp", "--help"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("gcp --help error: %v", err)
	}
}

func TestRunInitBothFilesExist(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	// Create both files
	if err := os.WriteFile(filepath.Join(dir, ".rdsspectre.yaml"), []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rdsspectre-policy.json"), []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}

	initFlags.force = false
	if err := runInit(nil, nil); err != nil {
		t.Fatalf("runInit() error: %v", err)
	}

	// Neither file should be modified
	data, _ := os.ReadFile(filepath.Join(dir, ".rdsspectre.yaml"))
	if string(data) != "existing" {
		t.Error("config should not be overwritten")
	}
}

func TestParseExcludeTagsFlagOnly(t *testing.T) {
	tags := parseExcludeTags(nil, []string{"env=dev", "team"})
	if tags["env"] != "dev" {
		t.Errorf("env = %q, want dev", tags["env"])
	}
	if _, ok := tags["team"]; !ok {
		t.Error("key-only flag tag should be present")
	}
}

func TestSubcommandsExist(t *testing.T) {
	for _, name := range []string{"aws", "gcp", "init", "version"} {
		cmd, _, err := rootCmd.Find([]string{name})
		if err != nil {
			t.Errorf("Find(%q) error: %v", name, err)
		}
		if cmd.Use != name {
			t.Errorf("command Use = %q, want %q", cmd.Use, name)
		}
	}
}
