package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	content := `
provider: aws
regions:
  - us-east-1
idle_days: 14
stale_days: 90
cpu_threshold: 20.0
metric_days: 14
min_monthly_cost: 1.0
format: json
timeout: "5m"
exclude:
  resource_ids:
    - mydb-prod
  tags:
    - env=production
`
	if err := os.WriteFile(filepath.Join(dir, ".rdsspectre.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Provider != "aws" {
		t.Errorf("Provider = %q, want aws", cfg.Provider)
	}
	if cfg.IdleDays != 14 {
		t.Errorf("IdleDays = %d, want 14", cfg.IdleDays)
	}
	if cfg.StaleDays != 90 {
		t.Errorf("StaleDays = %d, want 90", cfg.StaleDays)
	}
	if cfg.CPUThreshold != 20.0 {
		t.Errorf("CPUThreshold = %f, want 20.0", cfg.CPUThreshold)
	}
	if cfg.MinMonthlyCost != 1.0 {
		t.Errorf("MinMonthlyCost = %f, want 1.0", cfg.MinMonthlyCost)
	}
	if cfg.Format != "json" {
		t.Errorf("Format = %q, want json", cfg.Format)
	}
	if len(cfg.Exclude.ResourceIDs) != 1 {
		t.Errorf("Exclude.ResourceIDs len = %d, want 1", len(cfg.Exclude.ResourceIDs))
	}
}

func TestLoadYML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".rdsspectre.yml"), []byte("format: sarif\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Format != "sarif" {
		t.Errorf("Format = %q, want sarif", cfg.Format)
	}
}

func TestLoadNoFile(t *testing.T) {
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Provider != "" {
		t.Errorf("expected empty config, got provider=%q", cfg.Provider)
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".rdsspectre.yaml"), []byte(":::invalid"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestTimeoutDuration(t *testing.T) {
	cfg := Config{Timeout: "5m"}
	if cfg.TimeoutDuration().Minutes() != 5 {
		t.Errorf("TimeoutDuration = %v, want 5m", cfg.TimeoutDuration())
	}

	cfg2 := Config{Timeout: ""}
	if cfg2.TimeoutDuration() != 0 {
		t.Errorf("empty timeout should return 0")
	}

	cfg3 := Config{Timeout: "invalid"}
	if cfg3.TimeoutDuration() != 0 {
		t.Errorf("invalid timeout should return 0")
	}
}
