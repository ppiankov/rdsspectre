package commands

import (
	"github.com/ppiankov/rdsspectre/internal/logging"
	"github.com/spf13/cobra"
)

var (
	version string
	commit  string
	date    string
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "rdsspectre",
	Short: "rdsspectre — managed database waste and security auditor",
	Long: `rdsspectre audits AWS RDS and GCP Cloud SQL for idle, oversized, and misconfigured
database instances. Each finding includes severity, estimated monthly waste, and remediation hints.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		logging.Init(verbose)
	},
}

// Execute runs the root command.
func Execute(v, c, d string) error {
	version = v
	commit = c
	date = d
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	rootCmd.AddCommand(awsCmd)
	rootCmd.AddCommand(gcpCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(versionCmd)
}
