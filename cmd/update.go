package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

// updateCmd updates Certs from vault
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update certificates from vault",
	Long:  `Check for validity of certificates and update if needed`,
	Run: func(cmd *cobra.Command, args []string) {
		for _, cert := range Conf.Certificates.Sets {
			// TODO: implemet actual logic
			//			fmt.Printf("config: %+v\n", cert)
			if err := cert.ReadFiles(); err != nil {
				fmt.Printf("Error reading cert file: %s\n", err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)

}
