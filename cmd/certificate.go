package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"
)

// KeepsakeError is the internal error type
type KeepsakeError string

func (e KeepsakeError) Error() string { return string(e) }

const (
	// ErrEmptyCertificate Certificate is empty
	ErrEmptyCertificate = KeepsakeError("Certificate is empty")
	// ErrFailedToParsePrivateKey happens when parsing fails
	ErrFailedToParsePrivateKey = KeepsakeError("Failed to parse private key")
)

// CertificateFileSet represents different variations of Certificate combinations
type CertificateFileSet interface {
	CheckValidity(checks ...func(*CertificateFileSet)) (errors []error)
}

// BasicCert is the building block for the rest of our structures
type BasicCert struct {
	VaultRole         string
	VaultPath         string
	TTL               time.Duration
	ClientKey         crypto.PrivateKey
	ClientCertificate x509.Certificate
	RootCertificate   []x509.Certificate
}

// BasicCertOption is type to configure BasicCert values
type BasicCertOption func(*BasicCert)

// VaultRole sets vaultrole
func VaultRole(role string) BasicCertOption {
	return func(o *BasicCert) {
		o.VaultRole = role
	}
}

// VaultPath sets vaultpath
func VaultPath(path string) BasicCertOption {
	return func(o *BasicCert) {
		o.VaultPath = path
	}
}

// TTL sets ttl
func TTL(ttl time.Duration) BasicCertOption {
	return func(o *BasicCert) {
		o.TTL = ttl
	}
}

// NewBasicCert Create new BasicCert with options
func NewBasicCert(opts ...BasicCertOption) BasicCert {
	var bCert BasicCert
	for _, option := range opts {
		option(&bCert)
	}
	return bCert
}

// CertFileSet covers the case of cert file, key file and a separate CA file
type CertFileSet struct {
	BasicCert
	CertFileName string
	KeyFileName  string
	CaFileName   string
}

// CertFileOption is used in variadic constructor
type CertFileOption func(*CertFileSet)

// CertFileName sets certfilename
func CertFileName(name string) CertFileOption {
	return func(o *CertFileSet) {
		o.CertFileName = name
	}
}

// KeyFileName sets keyfilename
func KeyFileName(name string) CertFileOption {
	return func(o *CertFileSet) {
		o.KeyFileName = name
	}
}

// CaFileName sets cafilename
func CaFileName(name string) CertFileOption {
	return func(o *CertFileSet) {
		o.CaFileName = name
	}
}

// NewCertFileSet Create new CertFileSet with options
func NewCertFileSet(bcert BasicCert, opts ...CertFileOption) CertFileSet {
	var cfset CertFileSet
	cfset.BasicCert = bcert
	for _, option := range opts {
		option(&cfset)
	}
	return cfset
}

func certificatesFromBytes(b []byte) (certs []x509.Certificate, err error) {
	for block, rest := pem.Decode(b); block != nil; block, rest = pem.Decode(rest) {
		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return
		}
		certs = append(certs, *cert)
	}
	return
}

func privateKeyFromBytes(b []byte) (key crypto.PrivateKey, err error) {
	block, _ := pem.Decode(b)
	if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return
	}
	if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return
		default:
			return nil, ErrFailedToParsePrivateKey
		}
	}
	if key, err = x509.ParseECPrivateKey(block.Bytes); err == nil {
		return
	}
	return nil, ErrFailedToParsePrivateKey
}

func certificatesFromReader(r io.Reader) (certs []x509.Certificate, err error) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	return certificatesFromBytes(buf.Bytes())
}

func certificatesFromFile(fileName string) (certs []x509.Certificate, err error) {
	reader, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	return certificatesFromReader(reader)
}

func lastCertFromFile(fileName string) (cert x509.Certificate, err error) {
	certs, err := certificatesFromFile(fileName)
	if err != nil {
		return
	}
	if len(certs) == 0 {
		err = ErrEmptyCertificate
		return
	}
	return certs[len(certs)-1], nil
}

func privateKeyFromReader(r io.Reader) (key crypto.PrivateKey, err error) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	return privateKeyFromBytes(buf.Bytes())
}

func privateKeyFromFile(fileName string) (key crypto.PrivateKey, err error) {
	var reader io.Reader
	reader, err = os.Open(fileName)
	if err != nil {
		return
	}
	return privateKeyFromReader(reader)
}

// ReadFiles reads the certificates
func (cfset *CertFileSet) ReadFiles() (err error) {
	cfset.ClientCertificate, err = lastCertFromFile(cfset.CertFileName)
	if err != nil {
		return
	}
	var certs []x509.Certificate
	certs, err = certificatesFromFile(cfset.CaFileName)
	if err != nil {
		return
	}
	cfset.RootCertificate = certs

	cfset.ClientKey, err = privateKeyFromFile(cfset.KeyFileName)
	return
}

func clientKeyDer(cKey crypto.PrivateKey) (der []byte, err error) {
	// TODO: Add support for multiple key types
	switch cKey.(type) {
	case *rsa.PrivateKey:
		rsaKey := cKey.(*rsa.PrivateKey)
		der = x509.MarshalPKCS1PrivateKey(rsaKey)
	default:
		err = fmt.Errorf("Unknown private key type: %T", cKey)
	}
	return
}

func encodeCerts(certs ...x509.Certificate) (b []byte, err error) {
	buf := new(bytes.Buffer)
	for _, cert := range certs {
		if err = pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return
		}
		b = append(b, buf.Bytes()...)
	}
	return
}

// WriteFiles writes the contained certs into files
func (cfset *CertFileSet) WriteFiles() (err error) {
	var writer *os.File
	if writer, err = os.OpenFile(cfset.CertFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
		return
	}
	if err = pem.Encode(writer, &pem.Block{Type: "CERTIFICATE", Bytes: cfset.ClientCertificate.Raw}); err != nil {
		return
	}
	if writer, err = os.OpenFile(cfset.KeyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err != nil {
		return
	}
	var der []byte
	der, err = clientKeyDer(cfset.ClientKey)
	if err != nil {
		return
	}
	// TODO: Get the key type from clientKeyDer function
	if err = pem.Encode(writer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}); err != nil {
		return
	}
	var rootBytes []byte
	if rootBytes, err = encodeCerts(cfset.RootCertificate...); err != nil {
		return
	}
	if writer, err = os.OpenFile(cfset.CaFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
		return
	}
	if _, err = writer.Write(rootBytes); err != nil {
		return
	}
	err = writer.Close()
	return
}

// CheckValidity runs the specified check and returns a slice of errors
func (bCert *BasicCert) CheckValidity(checks ...func(*BasicCert) (err error)) (errors []error) {
	for _, check := range checks {
		err := check(bCert)
		if err != nil {
			errors = append(errors, err)
		}
	}
	return errors
}

// CheckCommonName Validates Certificates CNAME
func CheckCommonName(cname string) func(*BasicCert) (err error) {
	return func(bCert *BasicCert) error {
		if bCert.ClientCertificate.Subject.CommonName != cname {
			return fmt.Errorf("CNAME wanted: '%s', got: '%s'", cname, bCert.ClientCertificate.Subject.CommonName)
		}
		return nil
	}
}

// CheckCACommonName tests that the root certificate matches
func CheckCACommonName(cname string) func(*BasicCert) (err error) {
	return func(bCert *BasicCert) error {
		if len(bCert.RootCertificate) == 0 {
			return ErrEmptyCertificate
		}
		if bCert.RootCertificate[0].Subject.CommonName != cname {
			return fmt.Errorf("CNAME wanted: '%s', got: '%s'", cname, bCert.RootCertificate[0].Subject.CommonName)
		}
		return nil
	}
}
