package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// checkCmd checks Certs validity
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Checks the certificates' validity",
	Long:  `Check for validity of certificates and exits with non-zero value if the certificates are invalid`,
	Run: func(cmd *cobra.Command, args []string) {
		errorCount := 0
		for _, cert := range Conf.Certificates {
			if err := cert.ReadFiles(); err != nil {
				log.Errorf("Error reading cert file: %s\n", err)
			}
			for _, err := range cert.RunTests() {
				log.Errorln(err)
				errorCount++
			}
		}
		os.Exit(errorCount)
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
