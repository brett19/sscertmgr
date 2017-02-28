package sscertmgr

import (
	"crypto/x509"
	"crypto/rsa"
	"crypto/tls"
	"crypto/rand"
	"crypto/x509/pkix"
	"time"
	"net"
	"math/big"
	"fmt"
	"io/ioutil"
	"encoding/pem"
	"os"
	"bytes"
)

type AuthorityConfig struct {
	Subject pkix.Name
	NotBefore time.Time
	NotAfter time.Time
}

type HostConfig struct {
	Subject pkix.Name
	NotBefore time.Time
	NotAfter time.Time

	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
}

type AuthorityData struct {
	Certificate *x509.Certificate
	Key *rsa.PrivateKey
}

func CreateAuthority(config *AuthorityConfig) (*AuthorityData, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: config.Subject,
		NotBefore: config.NotBefore,
		NotAfter:  config.NotAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// This is a CA
	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	caCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %s", err)
	}

	return &AuthorityData{
		Certificate: caCert,
		Key: priv,
	}, nil
}

func LoadAuthority(certPath, keyPath string) (*AuthorityData, error) {
	caCertData, err := ioutil.ReadFile(certPath)
	if err != nil {
		panic(err)
	}

	var block *pem.Block
	block, _ = pem.Decode(caCertData)
	if block == nil {
		panic("NO CERT")
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		panic("BAD CERT")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	caPrivData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}

	block, _ = pem.Decode(caPrivData)
	if block == nil {
		panic("NO KEY")
	}
	if block.Type != "RSA PRIVATE KEY" || len(block.Headers) != 0 {
		panic("BAD KEY")
	}

	caPriv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return &AuthorityData{
		Certificate: caCert,
		Key: caPriv,
	}, nil
}

func (data *AuthorityData) SaveAuthority(certPath, keyPath string) error {
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open certificate file: %s", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: data.Certificate.Raw})
	certOut.Close()

	keyOut, err := os.OpenFile("CA.key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file: %s", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(data.Key)})
	keyOut.Close()

	return nil
}

func (data *AuthorityData) CreateHostCertificate(config *HostConfig) (tls.Certificate, error) {
	caCert := data.Certificate
	caPriv := data.Key

	priv, err := rsa.GenerateKey(rand.Reader, 2048)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: config.Subject,
		NotBefore: config.NotBefore,
		NotAfter:  config.NotAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames: config.DNSNames,
		EmailAddresses: config.EmailAddresses,
		IPAddresses: config.IPAddresses,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caPriv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %s", err)
	}

	var vsCertPem bytes.Buffer
	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	if err := pem.Encode(&vsCertPem, certBlock); err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to encode certificate: %s", err)
	}

	caCertBlock := &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}
	if err := pem.Encode(&vsCertPem, caCertBlock); err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to encode root certificate: %s", err)
	}

	var vsKeyPem bytes.Buffer
	keyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}
	if err := pem.Encode(&vsKeyPem, keyBlock); err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to encode key: %s", err)
	}

	return tls.X509KeyPair(vsCertPem.Bytes(), vsKeyPem.Bytes())
}