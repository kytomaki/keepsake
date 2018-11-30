package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// updateCmd updates Certs from vault
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update certificates from vault",
	Long:  `Update command runs the validity tests for the certificates and updates them if needed.`,
	Run: func(cmd *cobra.Command, args []string) {
		readInCertificates()
		for _, cert := range Conf.Certificates {
			cert.updateInvalidCertificate()
		}
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func readInCertificates() {
	for _, cconf := range Conf.Certificates {
		var err error
		if err = cconf.ReadFiles(); err != nil {
			if err == ErrFileDoesNotExist {
				log.WithField("cert", cconf.CName).Info("Files don't exist yet")
			} else {
				log.Errorf("Error reading cert file: %s\n", err)
			}
		}
	}
}

func (cconf *CertificateConf) updateInvalidCertificate() {
	var err error
	var valid bool
	if valid, err = cconf.CheckValidity(); err != nil {
		log.Error(err)
	}
	if !valid {
		if err = cconf.RetrieveFromVault(); err != nil {
			log.Errorf("Could not update cert %s: %s\n", cconf.CName, err)
		}
		var output string
		if output, err = cconf.RunCmd(); err != nil {
			log.WithError(err).Errorf("problem running command: %s, with output: %s", cconf.Cmd, output)
		} else {
			log.Infof("ran update command: %s, with output: %s", cconf.Cmd, output)
		}

		// Test the validity of the certificates after we retrieve them from vault.
		if valid, err = cconf.CheckValidity(); !valid || err != nil {
			log.Errorf("Certificate %s in vault is invalid: %s\n", cconf.CName, err)
		}
		if err = cconf.WriteFiles(); err != nil {
			log.Errorf("Could not write certificate %s to file: %s\n", cconf.CName, err)
		}
	}
}
