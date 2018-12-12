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
	"strings"
)

// RecoverableKeepsakeError are errors we shouldn't mind much and trudge along
type RecoverableKeepsakeError string

func (e RecoverableKeepsakeError) Error() string { return string(e) }

const (
	// ErrEmptyCertificate Certificate is empty
	ErrEmptyCertificate = RecoverableKeepsakeError("certificate is empty")
	// ErrFailedToParsePrivateKey happens when parsing fails
	ErrFailedToParsePrivateKey = RecoverableKeepsakeError("failed to parse private key")
	// ErrCertExpired denotes expired certificate
	ErrCertExpired = RecoverableKeepsakeError("certificate has expired")
	// ErrFileDoesNotExist is used to simplify checking validity of files
	ErrFileDoesNotExist = RecoverableKeepsakeError("no such file or directory")
)

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
	if _, err = buf.ReadFrom(r); err != nil {
		return
	}
	return certificatesFromBytes(buf.Bytes())
}

func certificatesFromString(s string) (certs []x509.Certificate, err error) {
	buf := strings.NewReader(s)
	return certificatesFromReader(buf)
}

func certificatesFromFile(fileName string) (certs []x509.Certificate, err error) {
	if _, err = os.Stat(fileName); os.IsNotExist(err) {
		return certs, ErrFileDoesNotExist
	}
	reader, err := os.Open(fileName) // #nosec
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
	if _, err = buf.ReadFrom(r); err != nil {
		return
	}
	return privateKeyFromBytes(buf.Bytes())
}

func privateKeyFromString(s string) (key crypto.PrivateKey, err error) {
	buf := strings.NewReader(s)
	return privateKeyFromReader(buf)
}

func privateKeyFromFile(fileName string) (key crypto.PrivateKey, err error) {
	if _, err = os.Stat(fileName); os.IsNotExist(err) {
		return key, ErrFileDoesNotExist
	}
	var reader io.Reader
	reader, err = os.Open(fileName) // #nosec
	if err != nil {
		return
	}
	return privateKeyFromReader(reader)
}

func pemEncode(pemType string, pemBytes []byte) (encoded []byte, err error) {
	buf := new(bytes.Buffer)
	block := &pem.Block{
		Type:  pemType,
		Bytes: pemBytes,
	}
	err = pem.Encode(buf, block)
	encoded = buf.Bytes()
	return
}

func encodePrivateKey(cKey crypto.PrivateKey) (encoded []byte, err error) {
	var der []byte
	var pemType string
	switch cKey.(type) {
	case *rsa.PrivateKey:
		pemType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		pemType = "ECDSA PRIVATE KEY"
	default:
		err = fmt.Errorf("Unknown private key type: %T", cKey)
		return
	}
	if der, err = x509.MarshalPKCS8PrivateKey(cKey); err != nil {
		return
	}
	return pemEncode(pemType, der)
}

func encodeCerts(certs ...x509.Certificate) (b []byte, err error) {
	for _, cert := range certs {
		var certBytes []byte
		if certBytes, err = pemEncode("CERTIFICATE", cert.Raw); err != nil {
			return
		}
		b = append(b, certBytes...)
	}
	return
}
