package cmd

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	vaultAPI "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

var (
	vaultClient *vaultAPI.Client
	once        sync.Once
	m           = &sync.Mutex{}
)

func renewDuration(seconds int, renewalCoefficient float64) time.Duration {
	return time.Duration(float64(seconds*int(time.Second)) * renewalCoefficient)
}

// MultipliedDuration returns the Duration multiplied by float
func MultipliedDuration(duration time.Duration, multiplier float64) (multipliedDuration time.Duration) {
	return time.Duration(float64(duration) * multiplier)
}

//GetVaultClient returns an active vault client
func GetVaultClient() (vc *vaultAPI.Client, err error) {
	once.Do(func() {

		log.WithField("vault-address", Conf.Address).Info("Dialing to vault")
		if vaultClient, err = vaultAPI.NewClient(nil); err != nil {
			return
		}
		vaultClient.SetToken(Conf.Token)
		vaultClient.SetAddress(Conf.Address)

		var secret *vaultAPI.Secret
		if secret, err = vaultClient.Logical().Unwrap(Conf.Token); err != nil {
			if !strings.HasSuffix(err.Error(), "* wrapping token is not valid or does not exist") {
				log.WithError(err).Fatal("Unwrapping secret failed")
			}
		}

		if secret != nil {
			vaultClient.SetToken(secret.Auth.ClientToken)
		} else if secret, err = vaultClient.Auth().Token().RenewSelf(0); err != nil {
			log.WithError(err).Fatal("Unable to look up token details")
		}

		//TODO(ilapost): Fix this stupid lambda function. Maybe make it a proper function.
		go func() {
			renewalInterval := renewDuration(secret.Auth.LeaseDuration, Conf.RenewalCoefficient)
			for {
				log.WithField("duration", renewalInterval).Info("Sleeping until Vault Token Renewal")
				time.Sleep(renewalInterval)
				newSecret, err := vaultClient.Auth().Token().RenewSelf(0)
				if err != nil {
					log.WithError(err).Fatal("Unable to renew token")
				}
				renewalInterval = renewDuration(newSecret.Auth.LeaseDuration, Conf.RenewalCoefficient)
				log.Info("Vault Token renewed")
			}
		}()
	})
	return vaultClient, err
}

//RetrieveFromVault retrieves the certificate information from vault.
func (cert *CertificateConf) RetrieveFromVault() (err error) {
	m.Lock()
	defer m.Unlock()
	log.Debug("Getting vault client")
	var vc *vaultAPI.Client
	if vc, err = GetVaultClient(); err != nil {
		return
	}
	log.WithField("Certificate", cert.CName).Info("Updating cert from vault")
	log.WithFields(log.Fields{
		"addresses":      cert.IPAddresses,
		"role":           cert.VaultRole,
		"alt_names":      cert.AltNames,
		"vault pki path": Conf.PKIPath,
		"ttl":            cert.TTL,
	}).Debug("Generating request")

	vaultPath := fmt.Sprintf("%s/issue/%s", Conf.PKIPath, cert.VaultRole)
	vaultArgs := map[string]interface{}{
		"common_name": cert.CName,
		"ip_sans":     strings.Join(cert.IPAddresses, ","),
	}

	if len(cert.AltNames) != 0 {
		vaultArgs["alt_names"] = strings.Join(cert.AltNames, ",")
	}

	if cert.TTL != 0 {
		vaultArgs["ttl"] = cert.TTL.String()
	}
	var pkiSecret *vaultAPI.Secret
	if pkiSecret, err = vc.Logical().Write(vaultPath, vaultArgs); err != nil {
		return
	}
	if len(pkiSecret.Data) == 0 {
		return ErrEmptyCertificate
	}
	var certs []x509.Certificate
	if certs, err = certificatesFromString(pkiSecret.Data["certificate"].(string)); err != nil {
		return
	}
	cert.ClientCertificate = certs[len(certs)-1]
	log.WithField("Certificate", cert.ClientCertificate.Subject.CommonName).Debug("Updated client cert from vault")
	if certs, err = certificatesFromString(pkiSecret.Data["issuing_ca"].(string)); err != nil {
		return
	}
	cert.RootCertificate = certs
	var pkey crypto.PrivateKey
	if pkey, err = privateKeyFromString(pkiSecret.Data["private_key"].(string)); err != nil {
		return
	}
	cert.ClientKey = pkey
	return
}
