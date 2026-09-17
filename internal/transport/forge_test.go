package transport

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/sanj6y/compute-mesh/internal/pki"
)

// forgeLeaf signs a leaf with the CA key directly, bypassing pki.Sign's mesh
// check, to test that transports pin mesh_id independently of the chain.
func forgeLeaf(t *testing.T, ca *pki.CA, key *ecdsa.PrivateKey, p pki.Principal) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{p.Name},
		URIs:         []*url.URL{p.URI()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}
