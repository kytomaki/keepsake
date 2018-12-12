package cmd

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"time"

	"github.com/mitchellh/mapstructure"
)

var (
	// Version of keepsake
	Version = "Undefined"
	// BuildDate of keepsake
	BuildDate = "Undefined"
	// Commit of build
	Commit = "Undefined"
)

// Config represents the keepsake configuration
type Config struct {
	Certificates []*CertificateConf `mapstructure:"certificates"`
	//TODO try to nest these under the vault struct
	Address            string  `mapstructure:"vault_address"`
	Token              string  `mapstructure:"vault_token"`
	PKIPath            string  `mapstructure:"vault_pki-path"`
	RenewalCoefficient float64 `mapstructure:"renewal_coefficient"`
	LogType            string  `mapstructure:"log_type"`
	LogLevel           string  `mapstructure:"log_level"`
}

// CertificateConf for Certificate and tests
type CertificateConf struct {
	CName                 string                         `mapstructure:"cname"`
	AltNames              []string                       `mapstructure:"altnames"`
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
	IPAddresses           []string                       `mapstructure:"ipaddresses"`
}

func (cconf *CertificateConf) isCertificateBundle() bool {
	return cconf.BundleCertificateFile != ""
}

// ReadFiles read the certificates from defined files
func (cconf *CertificateConf) ReadFiles() (err error) {
	// Bundle file is not set
	if cconf.isCertificateBundle() {
		var certs []x509.Certificate
		certs, err = certificatesFromFile(cconf.BundleCertificateFile)
		if err != nil {
			return
		}
		if len(certs) < 2 {
			// we have too few certificates to work with
			return ErrEmptyCertificate
		}
		// Set the client certificate to last of the loaded certs and the rest to the
		cconf.ClientCertificate, cconf.RootCertificate = certs[len(certs)-1], certs[:len(certs)-1]
	} else {
		cconf.ClientCertificate, err = lastCertFromFile(cconf.CertificateFile)
		if err != nil {
			return
		}
		var certs []x509.Certificate
		certs, err = certificatesFromFile(cconf.RootCertificateFile)
		if err != nil {
			return
		}
		cconf.RootCertificate = certs
	}
	cconf.ClientKey, err = privateKeyFromFile(cconf.KeyFile)
	return
}

// WriteFile writes contents to name with given mode
func WriteFile(name string, contents []byte, mode os.FileMode) (err error) {
	var writer *os.File
	if writer, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode); err != nil {
		return
	}
	if _, err = writer.Write(contents); err != nil {
		return
	}
	err = writer.Close()
	return
}

// WriteCertificates writes certs to name
func WriteCertificates(name string, certs ...x509.Certificate) (err error) {
	var certBytes []byte
	if certBytes, err = encodeCerts(certs...); err != nil {
		return
	}
	return WriteFile(name, certBytes, 0644)
}

// WritePrivateKey writes key to name
func WritePrivateKey(name string, key crypto.PrivateKey) (err error) {
	var keyBytes []byte
	if keyBytes, err = encodePrivateKey(key); err != nil {
		return
	}
	return WriteFile(name, keyBytes, 0600)
}

// WriteFiles writes the files to disk
func (cconf *CertificateConf) WriteFiles() (err error) {
	if cconf.isCertificateBundle() {
		certs := append(cconf.RootCertificate, cconf.ClientCertificate)
		if err = WriteCertificates(cconf.BundleCertificateFile, certs...); err != nil {
			return
		}
	} else {
		if err = WriteCertificates(cconf.CertificateFile, cconf.ClientCertificate); err != nil {
			return
		}
		if err = WriteCertificates(cconf.RootCertificateFile, cconf.RootCertificate...); err != nil {
			return
		}
	}
	err = WritePrivateKey(cconf.KeyFile, cconf.ClientKey)
	return
}

// RunCmd execs the cmd specified
func (cconf *CertificateConf) RunCmd() (output string, err error) {
	if cconf.Cmd != "" {
		cmd := exec.Command("/bin/sh", "-c", cconf.Cmd) // #nosec
		var boutput []byte
		boutput, err = cmd.CombinedOutput()
		output = string(boutput)
	}
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
				tests = append(tests, CheckCommonName())
			case "cacname":
				tests = append(tests, CheckCACommonName(vs))
			case "ttl":
				tests = append(tests, CheckTTL())
			default:
				return nil, fmt.Errorf("unknown validity function: %s", ks)
			}
		}
		return tests, nil
	}
}

// CheckCommonName Validates Certificates CNAME
func CheckCommonName() func(*CertificateConf) (err error) {
	return func(bCert *CertificateConf) error {
		if bCert.ClientCertificate.Subject.CommonName != bCert.CName {
			return RecoverableKeepsakeError(fmt.Sprintf("CNAME wanted: '%s', got: '%s'", bCert.CName, bCert.ClientCertificate.Subject.CommonName))
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
			return RecoverableKeepsakeError(fmt.Sprintf("CNAME wanted: '%s', got: '%s'", cname, bCert.RootCertificate[0].Subject.CommonName))
		}
		return nil
	}
}

// CheckTTL returns function to test if Certificate's ttl is still valid
func CheckTTL() func(*CertificateConf) (err error) {
	return func(certConf *CertificateConf) error {
		certs := append(certConf.RootCertificate, certConf.ClientCertificate)
		for _, cert := range certs {
			certDuration := cert.NotAfter.Sub(cert.NotBefore)
			thresholdTime := cert.NotBefore.Add(MultipliedDuration(certDuration, Conf.RenewalCoefficient))
			if time.Now().After(thresholdTime) {
				return RecoverableKeepsakeError(fmt.Sprintf("certificate expiration time %s, is too close to threshold %s", cert.NotAfter, thresholdTime))
			}
		}
		return nil
	}
}

// RunTests runs all the certificate tests
func (cconf *CertificateConf) RunTests() (errors []error) {
	for _, test := range cconf.Tests {
		if err := test(cconf); err != nil {
			errors = append(errors, err)
		}
	}
	return
}

// CheckValidity checks that certificates are valid
func (cconf *CertificateConf) CheckValidity() (valid bool, err error) {
	valid = true
	for _, verror := range cconf.RunTests() {
		if reflect.TypeOf(verror) == reflect.TypeOf(RecoverableKeepsakeError("")) {
			valid = false
		} else {
			return false, verror
		}
	}
	return
}
