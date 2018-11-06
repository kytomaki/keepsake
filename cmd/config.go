package cmd

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"reflect"
	"time"

	"github.com/mitchellh/mapstructure"
)

// Config represents the keepsake configuration
type Config struct {
	Certificates Certificates `mapstructure:"certificates"`
}

// Certificates contain the managed certifacte sets
type Certificates struct {
	Sets []CertificateFileSetConf `mapstructure:"sets"`
}

// CertificateFileSetConf for CertificateFileSet and tests
type CertificateFileSetConf struct {
	CName                 string                   `mapstructure:"cname"`
	VaultRole             string                   `mapstructure:"vaultrole"`
	TTL                   time.Duration            `mapstructure:"ttl"`
	CertificateFile       string                   `mapstructure:"cert"`
	KeyFile               string                   `mapstructure:"key"`
	RootCertificateFile   string                   `mapstructure:"root"`
	BundleCertificateFile string                   `mapstructure:"bundle"`
	Cmd                   string                   `mapstructure:"cmd"`
	Tests                 []func(*BasicCert) error `mapstructure:"tests"`
	ClientKey             crypto.PrivateKey        `mapstructure:"-"`
	ClientCertificate     x509.Certificate         `mapstructure:"-"`
	RootCertificate       []x509.Certificate       `mapstructure:"-"`
}

// ReadFiles read the certificates from defined files
func (cfset *CertificateFileSetConf) ReadFiles() (err error) {
	// Bundle file is not set
	if cfset.BundleCertificateFile == "" {
		cfset.ClientCertificate, err = lastCertFromFile(cfset.CertificateFile)
		if err != nil {
			return
		}
		var certs []x509.Certificate
		certs, err = certificatesFromFile(cfset.RootCertificateFile)
		if err != nil {
			return
		}
		cfset.RootCertificate = certs
	} else {
		var certs []x509.Certificate
		certs, err = certificatesFromFile(cfset.BundleCertificateFile)
		if err != nil {
			return
		}
		if len(certs) < 2 {
			// we have too few certificates to work with
			return ErrEmptyCertificate
		}
		// Set the client certificate to last of the loaded certs and the rest to the
		cfset.ClientCertificate, cfset.RootCertificate = certs[len(certs)-1], certs[:len(certs)-1]
	}
	cfset.ClientKey, err = privateKeyFromFile(cfset.KeyFile)
	return
}

// WriteFiles writes the files to disk
func (cfset *CertificateFileSetConf) WriteFiles() (err error) {
	var writer *os.File
	if cfset.BundleCertificateFile == "" {
		if writer, err = os.OpenFile(cfset.CertificateFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
			return
		}
		if err = pem.Encode(writer, &pem.Block{Type: "CERTIFICATE", Bytes: cfset.ClientCertificate.Raw}); err != nil {
			return
		}
		var rootBytes []byte
		if rootBytes, err = encodeCerts(cfset.RootCertificate...); err != nil {
			return
		}
		if writer, err = os.OpenFile(cfset.RootCertificateFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
			return
		}
		if _, err = writer.Write(rootBytes); err != nil {
			return
		}
	} else {
		var bundleBytes []byte
		certs := append(cfset.RootCertificate, cfset.ClientCertificate)
		if bundleBytes, err = encodeCerts(certs...); err != nil {
			return
		}
		if writer, err = os.OpenFile(cfset.RootCertificateFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
			return
		}
		if _, err = writer.Write(bundleBytes); err != nil {
			return
		}
		if err = writer.Close(); err != nil {
			return
		}
	}
	if writer, err = os.OpenFile(cfset.KeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err != nil {
		return
	}
	var der []byte
	der, err = clientKeyDer(cfset.ClientKey)
	if err != nil {
		return
	}
	err = pem.Encode(writer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	err = writer.Close()
	return
}

// DecodeValidityFuncsHookFunc is helper function for viper to parse our validityfunctions to a slice
func DecodeValidityFuncsHookFunc() mapstructure.DecodeHookFunc {
	return func(rf reflect.Type, rt reflect.Type, data interface{}) (interface{}, error) {
		// test the data we got
		if rf != reflect.TypeOf(map[interface{}]interface{}{}) {
			return data, nil
		}
		// The slice of functions to contain results
		var tests []func(*BasicCert) error
		// test the wanted type
		if rt != reflect.TypeOf(tests) {
			return data, nil
		}
		// raw repesentation of the map
		raw := data.(map[interface{}]interface{})
		if len(raw) == 0 {
			return data, nil
		}
		for testKey, testValue := range raw {
			ks, vs := testKey.(string), testValue.(string)
			switch ks {
			case "cname":
				tests = append(tests, CheckCommonName(vs))
			case "cacname":
				tests = append(tests, CheckCACommonName(vs))
			default:
				return nil, fmt.Errorf("unknown validity function: %s", ks)
			}
		}
		return tests, nil
	}
}
