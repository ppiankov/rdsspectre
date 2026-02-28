package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, _ []string) {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "rdsspectre %s (commit: %s, built: %s)\n", version, commit, date)
	},
}
