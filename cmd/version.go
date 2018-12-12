package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

// versionCmd prints out version and exits
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print version and exit",
	Long:  `print version, build date and commit hash. Then exit.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("keepsake\nversion:\t%s\nbuild date:\t%s\ncommit:\t\t%s\n", Version, BuildDate, Commit)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
