package cmd

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
	"time"

	"github.com/mitchellh/mapstructure"
)

// Config represents the keepsake configuration
type Config struct {
	Certificates []CertificateConf `mapstructure:"certificates"`
}

// CertificateConf for CertificateFileSet and tests
type CertificateConf struct {
	CName                 string                         `mapstructure:"cname"`
	VaultRole             string                         `mapstructure:"vaultrole"`
	TTL                   time.Duration                  `mapstructure:"ttl"`
	CertificateFile       string                         `mapstructure:"cert"`
	KeyFile               string                         `mapstructure:"key"`
	RootCertificateFile   string                         `mapstructure:"root"`
	BundleCertificateFile string                         `mapstructure:"bundle"`
	Cmd                   string                         `mapstructure:"cmd"`
	Tests                 []func(*CertificateConf) error `mapstructure:"tests"`
	ClientKey             crypto.PrivateKey              `mapstructure:"-"`
	ClientCertificate     x509.Certificate               `mapstructure:"-"`
	RootCertificate       []x509.Certificate             `mapstructure:"-"`
}

// ReadFiles read the certificates from defined files
func (cert *CertificateConf) ReadFiles() (err error) {
	// Bundle file is not set
	if cert.BundleCertificateFile == "" {
		cert.ClientCertificate, err = lastCertFromFile(cert.CertificateFile)
		if err != nil {
			return
		}
		var certs []x509.Certificate
		certs, err = certificatesFromFile(cert.RootCertificateFile)
		if err != nil {
			return
		}
		cert.RootCertificate = certs
	} else {
		var certs []x509.Certificate
		certs, err = certificatesFromFile(cert.BundleCertificateFile)
		if err != nil {
			return
		}
		if len(certs) < 2 {
			// we have too few certificates to work with
			return ErrEmptyCertificate
		}
		// Set the client certificate to last of the loaded certs and the rest to the
		cert.ClientCertificate, cert.RootCertificate = certs[len(certs)-1], certs[:len(certs)-1]
	}
	cert.ClientKey, err = privateKeyFromFile(cert.KeyFile)
	return
}

// WriteFiles writes the files to disk
func (cert *CertificateConf) WriteFiles() (err error) {
	var writer *os.File
	if cert.BundleCertificateFile == "" {
		if writer, err = os.OpenFile(cert.CertificateFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
			return
		}
		if err = pem.Encode(writer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.ClientCertificate.Raw}); err != nil {
			return
		}
		var rootBytes []byte
		if rootBytes, err = encodeCerts(cert.RootCertificate...); err != nil {
			return
		}
		if writer, err = os.OpenFile(cert.RootCertificateFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
			return
		}
		if _, err = writer.Write(rootBytes); err != nil {
			return
		}
	} else {
		var bundleBytes []byte
		certs := append(cert.RootCertificate, cert.ClientCertificate)
		if bundleBytes, err = encodeCerts(certs...); err != nil {
			return
		}
		if writer, err = os.OpenFile(cert.BundleCertificateFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
			return
		}
		if _, err = writer.Write(bundleBytes); err != nil {
			return
		}
		if err = writer.Close(); err != nil {
			return
		}
	}
	if writer, err = os.OpenFile(cert.KeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err != nil {
		return
	}
	var der []byte
	der, err = clientKeyDer(cert.ClientKey)
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
		var tests []func(*CertificateConf) error
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

// CheckCommonName Validates Certificates CNAME
func CheckCommonName(cname string) func(*CertificateConf) (err error) {
	return func(bCert *CertificateConf) error {
		if bCert.ClientCertificate.Subject.CommonName != cname {
			return fmt.Errorf("CNAME wanted: '%s', got: '%s'", cname, bCert.ClientCertificate.Subject.CommonName)
		}
		return nil
	}
}

// CheckCACommonName tests that the root certificate matches
func CheckCACommonName(cname string) func(*CertificateConf) (err error) {
	return func(bCert *CertificateConf) error {
		if len(bCert.RootCertificate) == 0 {
			return ErrEmptyCertificate
		}
		if bCert.RootCertificate[0].Subject.CommonName != cname {
			return fmt.Errorf("CNAME wanted: '%s', got: '%s'", cname, bCert.RootCertificate[0].Subject.CommonName)
		}
		return nil
	}
}

// CheckValidity runs all the certificate tests
func (cert *CertificateConf) CheckValidity() (errors []error) {
	for _, test := range cert.Tests {
		if err := test(cert); err != nil {
			errors = append(errors, err)
		}
	}
	return
}
