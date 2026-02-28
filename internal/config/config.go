package config

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents .rdsspectre.yaml settings.
type Config struct {
	Provider       string   `yaml:"provider"`
	Regions        []string `yaml:"regions"`
	Profile        string   `yaml:"profile"`
	Project        string   `yaml:"project"`
	IdleDays       int      `yaml:"idle_days"`
	StaleDays      int      `yaml:"stale_days"`
	CPUThreshold   float64  `yaml:"cpu_threshold"`
	MetricDays     int      `yaml:"metric_days"`
	MinMonthlyCost float64  `yaml:"min_monthly_cost"`
	Format         string   `yaml:"format"`
	Timeout        string   `yaml:"timeout"`
	Exclude        Exclude  `yaml:"exclude"`
}

// Exclude holds exclusion rules.
type Exclude struct {
	ResourceIDs []string `yaml:"resource_ids"`
	Tags        []string `yaml:"tags"`
}

// TimeoutDuration parses the timeout string.
func (c Config) TimeoutDuration() time.Duration {
	if c.Timeout == "" {
		return 0
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 0
	}
	return d
}

// Load reads .rdsspectre.yaml or .rdsspectre.yml from the given directory.
func Load(dir string) (Config, error) {
	var cfg Config
	for _, name := range []string{".rdsspectre.yaml", ".rdsspectre.yml"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, err
		}
		return cfg, nil
	}
	return cfg, nil
}
