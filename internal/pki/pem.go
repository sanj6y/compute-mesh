package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// File names under the data dir. Keys are 0600, certs 0644, dir 0700.
const (
	CACertFile    = "ca.crt"
	CAKeyFile     = "ca.key"
	NodeCertFile  = "node.crt"
	NodeKeyFile   = "node.key"
	AdminCertFile = "admin.crt"
	AdminKeyFile  = "admin.key"
)

var ErrExists = errors.New("pki: file already exists")

// EncodeCertPEM renders a certificate as PEM.
func EncodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// EncodeKeyPEM renders an ECDSA key as PKCS#8 PEM.
func EncodeKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseCertPEM decodes the first CERTIFICATE block.
func ParseCertPEM(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("pki: no CERTIFICATE block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParseKeyPEM decodes a PKCS#8 or SEC1 ECDSA key.
func ParseKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("pki: no PEM block")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("pki: key is not ECDSA")
		}
		return ec, nil
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	}
	return nil, fmt.Errorf("pki: unexpected PEM type %q", block.Type)
}

// WriteCert writes a cert PEM (0644) into dir, creating dir 0700.
func WriteCert(dir, name string, cert *x509.Certificate, overwrite bool) error {
	return writeFile(dir, name, EncodeCertPEM(cert), 0o644, overwrite)
}

// WriteKey writes a key PEM (0600) into dir, creating dir 0700.
func WriteKey(dir, name string, key *ecdsa.PrivateKey, overwrite bool) error {
	b, err := EncodeKeyPEM(key)
	if err != nil {
		return err
	}
	return writeFile(dir, name, b, 0o600, overwrite)
}

// ReadCert loads a PEM certificate from dir/name.
func ReadCert(dir, name string) (*x509.Certificate, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	return ParseCertPEM(b)
}

// ReadKey loads a PEM key from dir/name.
func ReadKey(dir, name string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	return ParseKeyPEM(b)
}

// ReadCA loads ca.crt + ca.key from dir.
func ReadCA(dir string) (*CA, error) {
	cert, err := ReadCert(dir, CACertFile)
	if err != nil {
		return nil, err
	}
	key, err := ReadKey(dir, CAKeyFile)
	if err != nil {
		return nil, err
	}
	return LoadCA(cert, key)
}

func writeFile(dir, name string, data []byte, perm os.FileMode, overwrite bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("pki: create %s: %w", dir, err)
	}
	path := filepath.Join(dir, name)
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !overwrite {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, path)
		}
		return fmt.Errorf("pki: open %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("pki: write %s: %w", path, err)
	}
	if err := f.Chmod(perm); err != nil { // O_CREATE respects umask; force it
		f.Close()
		return err
	}
	return f.Close()
}
