/*
 *   keepsake - Automatic PKI key/cert management with Vault
 *   Copyright (c) 2017 Shannon Wynter.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	vaultAPI "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	openssl "github.com/spacemonkeygo/openssl"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	// EnvVaultToken Used to authenticate the each request
	EnvVaultToken = "VAULT_TOKEN"
)

var (
	version   = "Undefined"
	buildDate = "Undefined"
	commit    = "Undefined"
)

var environmentVariables = []string{
	EnvVaultToken,
	vaultAPI.EnvVaultAddress,
	vaultAPI.EnvVaultCACert,
	vaultAPI.EnvVaultCAPath,
	vaultAPI.EnvVaultClientCert,
	vaultAPI.EnvVaultClientKey,
	vaultAPI.EnvVaultInsecure,
	vaultAPI.EnvVaultTLSServerName,
	vaultAPI.EnvVaultWrapTTL,
	vaultAPI.EnvVaultMaxRetries,
}

func renewDuration(seconds int, renewalCoefficient float64) time.Duration {
	return time.Duration(float64(time.Duration(seconds)*time.Second) * renewalCoefficient)
}

func checkCertExpiration(certFile string, pemFile string, seconds int) bool {
	if pemFile == "" {
		f, err := ioutil.ReadFile(certFile)
		if err != nil {
			log.WithError(err).WithField("file", certFile).Warn("Unable to locate certfile!")
			return true
		}
		block, _ := pem.Decode([]byte(f))
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.WithError(err).Fatal("Unable to parse cert!")
		}
		log.WithField("NotAfter", c.NotAfter).Info("Certificate Expire DateTime")
		return c.NotAfter.Add(-time.Duration(seconds) * time.Second).Before(time.Now())
	}

	block, _ := pem.Decode([]byte(pemFile))
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.WithError(err).Fatal("Unable to parse cert!")
	}
	log.WithField("NotAfter", c.NotAfter).Info("Certificate Expire DateTime")
	return c.NotAfter.Add(-time.Duration(seconds) * time.Second).Before(time.Now())

}

func main() {
	vaultPKIPath := flag.String("vault-path", "pki", "Path for pki")
	vaultRole := flag.String("vault-role", "server", "Role for pki")
	certCN := flag.String("cn", "", "Certificate common name")
	certAltNames := flag.String("alt-names", "", "Comma seperated list of alt-names")
	certIPSans := flag.String("ip-sans", "127.0.0.1", "Comma seperated list of alternate ips")
	certTTL := flag.Duration("certTTL", time.Duration(0), "TTL of the certificate issued")
	certFile := flag.String("certFile", "", "Output certificate file")
	keyFile := flag.String("keyFile", "", "Output key file")
	caFile := flag.String("caFile", "", "Output ca file")
	pemFile := flag.String("pemFile", "", "Output ca in pem file")
	bundleFile := flag.String("bundleFile", "", "Ouput a ca+cert bundle")
	command := flag.String("cmd", "", "Command to execute")
	runOnce := flag.Bool("once", false, "Run command once and exit.")
	renewalCoefficient := flag.Float64("renewal", 0.9, "Float lifespan factor to renew cert.")
	showVersion := flag.Bool("version", false, "Show version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n\n", os.Args[0])

		flag.PrintDefaults()

		fmt.Fprintln(os.Stderr, "\nRequired flags:")
		for _, f := range []string{"cn", "certFile", "keyFile", "caFile"} {
			fmt.Fprintf(os.Stderr, "\t-%s\n", f)
		}

		fmt.Fprintln(os.Stderr, "\nEnvironment variables:")
		for _, e := range environmentVariables {
			fmt.Fprintf(os.Stderr, "\t%s\n", e)
		}
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("keepsake - %s (%s)\n", version, commit)
		fmt.Printf("built: %s \n", buildDate)
		fmt.Println("https://github.com/freman/keepsake")
		return
	}
	if *certCN == "" {
		flag.Usage()
		os.Exit(1)
	}

	if !(((*pemFile != "") && (*certFile == "" && *keyFile == "" && *caFile == "")) || ((*pemFile == "") && (*certFile != "" && *keyFile != "" && *caFile != ""))) {
		fmt.Print("1")
		flag.Usage()
		os.Exit(1)
	}

	vaultPath := fmt.Sprintf("%s/issue/%s", *vaultPKIPath, *vaultRole)
	vaultArgs := map[string]interface{}{
		"common_name": *certCN,
		"ip_sans":     *certIPSans,
	}

	if *certAltNames != "" {
		vaultArgs["alt_names"] = *certAltNames
	}

	if *certTTL != 0 {
		vaultArgs["ttl"] = certTTL.String()
	}

	if *renewalCoefficient >= 1.0 {
		log.WithField("-renewal", renewalCoefficient).Fatal("Argument `-renewal` must be less than 1.0.")
	}

	token := os.Getenv(EnvVaultToken)
	if token == "" {
		log.Fatal("No token found")
	}

	vault, err := vaultAPI.NewClient(nil)
	if err != nil {
		log.WithError(err).Fatal("Unable to launch vault client")
	}
	vault.SetToken(token)

	secret, err := vault.Logical().Unwrap(token)
	if err != nil {
		if !strings.HasSuffix(err.Error(), "* wrapping token is not valid or does not exist") {
			log.WithError(err).Fatal("Unwrapping secret failed")
		}
	}

	if secret != nil {
		vault.SetToken(secret.Auth.ClientToken)
	} else {
		secret, err = vault.Auth().Token().RenewSelf(0)
		if err != nil {
			log.WithError(err).Fatal("Unable to look up token details")
		}
	}

	go func() {
		renewalInterval := renewDuration(secret.Auth.LeaseDuration, *renewalCoefficient)
		for {
			time.Sleep(renewalInterval)
			newSecret, err := vault.Auth().Token().RenewSelf(0)
			if err != nil {
				log.WithError(err).Fatal("Unable to renew token")
			}
			renewalInterval = renewDuration(newSecret.Auth.LeaseDuration, *renewalCoefficient)
			log.WithField("renewalInterval", renewalInterval).Info("Renewal of Token successful sleeping...")
		}
	}()

	certRenewalInterval := time.Duration(time.Duration(float64(certTTL.Seconds())**renewalCoefficient) * time.Second)

	pemFormat := *certFile == ""

	possibleRenew := func() bool {
		var needsRenewal bool

		if pemFormat {
			if _, err := os.Stat(*pemFile); os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, "\nPem file doesn't exist, ignoring TTL and creating one")
				needsRenewal = true
			} else {
				b, err := ioutil.ReadFile(*pemFile)
				if err != nil {
					log.WithError(err).WithField("file", *pemFile).Fatal("Failed to read pem file")
				}
				pem := openssl.SplitPEM(b)
				needsRenewal = checkCertExpiration(*certFile, (string(pem[0])), int(certRenewalInterval.Seconds()))
			}
		} else {
			needsRenewal = checkCertExpiration(*certFile, *pemFile, int(certRenewalInterval.Seconds()))
		}

		if !needsRenewal {
			fmt.Fprintln(os.Stderr, "\nNo change required due to TTL")
			return false
		}

		pkiSecret, err := vault.Logical().Write(vaultPath, vaultArgs)

		if err != nil {
			log.WithError(err).Fatal("unable to write to vault")
		}

		if pemFormat {
			if err := ioutil.WriteFile(*pemFile, []byte(pkiSecret.Data["certificate"].(string)+"\n"+pkiSecret.Data["issuing_ca"].(string)+"\n"+pkiSecret.Data["private_key"].(string)+"\n"), 0640); err != nil {
				log.WithError(err).WithField("file", *pemFile).Fatal("Failed to write pem file")
			}
		} else {
			if err := ioutil.WriteFile(*certFile, []byte(pkiSecret.Data["certificate"].(string)+"\n"), 0640); err != nil {
				log.WithError(err).WithField("file", *certFile).Fatal("Failed to write certificate")
			}
			if err := ioutil.WriteFile(*caFile, []byte(pkiSecret.Data["issuing_ca"].(string)+"\n"), 0640); err != nil {
				log.WithError(err).WithField("file", *caFile).Fatal("Failed to write ca")
			}
			if err := ioutil.WriteFile(*keyFile, []byte(pkiSecret.Data["private_key"].(string)+"\n"), 0640); err != nil {
				log.WithError(err).WithField("file", *keyFile).Fatal("Failed to write key")
			}
			if *bundleFile != "" {
				if err := ioutil.WriteFile(*bundleFile, []byte(pkiSecret.Data["certificate"].(string)+"\n"+pkiSecret.Data["issuing_ca"].(string)+"\n"), 0640); err != nil {
					log.WithError(err).WithField("file", *certFile).Fatal("Failed to write certificate")
				}
			}
		}
		if *command != "" {
			cmd := exec.Command("/bin/bash", "-c", *command)
			err := cmd.Run()
			if err != nil {
				log.WithError(err).WithField("cmd", cmd).Fatal("Unable to run cmd")
			}
		}
		fmt.Fprintln(os.Stderr, "\nCertificates and key updated")
		return true
	}

	log.WithField("certRenewalInterval", certRenewalInterval).Info("Renewal Internval of Cert")

	result := possibleRenew()
	if *runOnce {
		if result == true {
			println("\nchanged=true comment='certificates and key updated'")
		} else {
			println("\nchanged=no comment='no change required due to TTL'")
		}
		return
	}
	for {
		sleepInterval := time.Duration(time.Duration(float64(certTTL.Seconds())*
			(1.0-*renewalCoefficient)+1) * time.Second)
		time.Sleep(sleepInterval)
		result = possibleRenew()
	}

}
