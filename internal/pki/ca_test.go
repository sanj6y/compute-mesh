package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustCA(t *testing.T, mesh string) *CA {
	t.Helper()
	ca, err := NewCA(mesh)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNewCA(t *testing.T) {
	tests := []struct {
		mesh    string
		wantErr bool
	}{
		{"home", false},
		{"lab-2", false},
		{"", true},
		{"Home", true},
		{"-x", true},
		{"a.b", true},
	}
	for _, tt := range tests {
		t.Run(tt.mesh, func(t *testing.T) {
			ca, err := NewCA(tt.mesh)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewCA(%q) err = %v, wantErr %v", tt.mesh, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if !ca.Cert.IsCA || ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
				t.Error("CA cert lacks CA basic constraint or CertSign usage")
			}
			if ca.MeshID() != tt.mesh {
				t.Errorf("MeshID() = %q", ca.MeshID())
			}
			if err := ca.Cert.CheckSignatureFrom(ca.Cert); err != nil {
				t.Errorf("CA is not self-signed: %v", err)
			}
			if _, err := LoadCA(ca.Cert, ca.Key); err != nil {
				t.Errorf("LoadCA round trip: %v", err)
			}
		})
	}
}

func TestLoadCARejectsMismatch(t *testing.T) {
	ca := mustCA(t, "home")
	other := mustKey(t)
	if _, err := LoadCA(ca.Cert, other); !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("err = %v, want ErrKeyMismatch", err)
	}
	leaf, _ := ca.Sign(SignRequest{Principal: Principal{"home", RoleNode, "n1"}, PublicKey: &other.PublicKey, TTL: time.Hour})
	if _, err := LoadCA(leaf, other); !errors.Is(err, ErrNotCA) {
		t.Errorf("err = %v, want ErrNotCA", err)
	}
}

func TestSign(t *testing.T) {
	ca := mustCA(t, "home")
	key := mustKey(t)

	tests := []struct {
		name    string
		req     SignRequest
		wantErr error
	}{
		{"node", SignRequest{Principal{"home", RoleNode, "mac-1"}, &key.PublicKey, time.Hour}, nil},
		{"admin", SignRequest{Principal{"home", RoleAdmin, "sanjay"}, &key.PublicKey, time.Hour}, nil},
		{"foreign mesh", SignRequest{Principal{"work", RoleNode, "mac-1"}, &key.PublicKey, time.Hour}, ErrMeshMismatch},
		{"bad role", SignRequest{Principal{"home", "root", "x"}, &key.PublicKey, time.Hour}, ErrBadPrincipal},
		{"bad name", SignRequest{Principal{"home", RoleNode, "Mac 1"}, &key.PublicKey, time.Hour}, ErrInvalidNodeID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ca.Sign(tt.req)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p, err := ca.Verify(cert, time.Now())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if p != tt.req.Principal {
				t.Errorf("principal = %+v, want %+v", p, tt.req.Principal)
			}
			if cert.IsCA {
				t.Error("leaf must not be a CA")
			}
			hasServer, hasClient := false, false
			for _, u := range cert.ExtKeyUsage {
				hasServer = hasServer || u == x509.ExtKeyUsageServerAuth
				hasClient = hasClient || u == x509.ExtKeyUsageClientAuth
			}
			if !hasServer || !hasClient {
				t.Error("leaf must allow both server and client auth")
			}
			if tt.req.Principal.Role == RoleNode {
				if len(cert.DNSNames) != 1 || cert.DNSNames[0] != tt.req.Principal.Name {
					t.Errorf("node cert DNSNames = %v, want [%s]", cert.DNSNames, tt.req.Principal.Name)
				}
			} else if len(cert.DNSNames) != 0 {
				t.Errorf("admin cert must have no DNS SAN, got %v", cert.DNSNames)
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	ca := mustCA(t, "home")
	otherCA := mustCA(t, "home") // same mesh id, different key
	key := mustKey(t)
	good, _ := ca.Sign(SignRequest{Principal{"home", RoleNode, "n1"}, &key.PublicKey, time.Hour})
	fromOther, _ := otherCA.Sign(SignRequest{Principal{"home", RoleNode, "n1"}, &key.PublicKey, time.Hour})

	tests := []struct {
		name    string
		leaf    *x509.Certificate
		now     time.Time
		wantErr bool
	}{
		{"valid", good, time.Now(), false},
		{"expired", good, time.Now().Add(2 * time.Hour), true},
		{"not yet valid", good, time.Now().Add(-time.Hour), true},
		{"signed by other CA with same mesh id", fromOther, time.Now(), true},
		{"the CA itself is not a valid leaf", ca.Cert, time.Now(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ca.Verify(tt.leaf, tt.now)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyMeshPinning(t *testing.T) {
	// Adversarial: a leaf that chains to our CA but claims another mesh in
	// its URI. Only possible if the CA key leaked, but the transport must
	// still refuse it. Build it by signing directly with the CA key.
	ca := mustCA(t, "home")
	key := mustKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big1(),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{Principal{"work", RoleNode, "n1"}.URI()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	if _, err := ca.Verify(leaf, time.Now()); !errors.Is(err, ErrMeshMismatch) {
		t.Errorf("err = %v, want ErrMeshMismatch", err)
	}
}

func TestSignCSR(t *testing.T) {
	ca := mustCA(t, "home")
	key := mustKey(t)
	csr, err := NewCSR("mac-1", key)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		cert, err := ca.SignCSR(csr, Principal{"home", RoleNode, "mac-1"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if !key.PublicKey.Equal(cert.PublicKey) {
			t.Error("issued cert does not carry the CSR's public key")
		}
	})
	t.Run("tampered", func(t *testing.T) {
		bad := append([]byte{}, csr...)
		bad[len(bad)-1] ^= 0xff
		if _, err := ca.SignCSR(bad, Principal{"home", RoleNode, "mac-1"}, time.Hour); !errors.Is(err, ErrBadCSR) {
			t.Errorf("err = %v, want ErrBadCSR", err)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		if _, err := ca.SignCSR([]byte("nope"), Principal{"home", RoleNode, "mac-1"}, time.Hour); !errors.Is(err, ErrBadCSR) {
			t.Errorf("err = %v, want ErrBadCSR", err)
		}
	})
	t.Run("wrong curve", func(t *testing.T) {
		k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		csr384, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
		if _, err := ca.SignCSR(csr384, Principal{"home", RoleNode, "mac-1"}, time.Hour); !errors.Is(err, ErrBadCSR) {
			t.Errorf("err = %v, want ErrBadCSR", err)
		}
	})
	t.Run("bad node id in CSR", func(t *testing.T) {
		if _, err := NewCSR("Bad ID", key); !errors.Is(err, ErrInvalidNodeID) {
			t.Errorf("err = %v, want ErrInvalidNodeID", err)
		}
	})
}

func TestParsePrincipal(t *testing.T) {
	tests := []struct {
		uri     string
		want    Principal
		wantErr bool
	}{
		{"lcm://home/node/mac-1", Principal{"home", "node", "mac-1"}, false},
		{"lcm://home/admin/sanjay", Principal{"home", "admin", "sanjay"}, false},
		{"lcm://home/root/x", Principal{}, true},
		{"lcm://home/node", Principal{}, true},
		{"lcm://home/node/", Principal{}, true},
		{"lcm:///node/x", Principal{}, true},
		{"https://home/node/x", Principal{}, true},
		{"lcm://home/node/x/y", Principal{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			u, _ := url.Parse(tt.uri)
			got, err := ParsePrincipal(u)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
			if !tt.wantErr && got.String() != tt.uri {
				t.Errorf("round trip = %q", got.String())
			}
		})
	}
	if _, err := PrincipalFromCert(&x509.Certificate{}); !errors.Is(err, ErrNoMeshURI) {
		t.Errorf("no URI: err = %v", err)
	}
}

func TestPEMRoundTripAndPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "lcm")
	ca := mustCA(t, "home")
	if err := WriteCert(dir, CACertFile, ca.Cert, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteKey(dir, CAKeyFile, ca.Key, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteKey(dir, CAKeyFile, ca.Key, false); !errors.Is(err, ErrExists) {
		t.Errorf("overwrite without flag: err = %v, want ErrExists", err)
	}
	if err := WriteKey(dir, CAKeyFile, ca.Key, true); err != nil {
		t.Errorf("overwrite with flag: %v", err)
	}
	got, err := ReadCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Cert.Equal(ca.Cert) || !got.Key.Equal(ca.Key) {
		t.Error("ReadCA round trip mismatch")
	}
	for name, want := range map[string]os.FileMode{CACertFile: 0o644, CAKeyFile: 0o600} {
		info, _ := os.Stat(filepath.Join(dir, name))
		if info.Mode().Perm() != want {
			t.Errorf("%s perm = %o, want %o", name, info.Mode().Perm(), want)
		}
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("dir perm = %o", info.Mode().Perm())
	}
	if _, err := ParseKeyPEM([]byte("not pem")); err == nil {
		t.Error("ParseKeyPEM accepted garbage")
	}
	if _, err := ParseCertPEM(mustPEMKey(t, ca.Key)); err == nil {
		t.Error("ParseCertPEM accepted a key block")
	}
}

func TestFingerprint(t *testing.T) {
	ca := mustCA(t, "home")
	fp := Fingerprint(ca.Cert)
	if len(fp) != 64 {
		t.Errorf("fingerprint length = %d, want 64 hex chars", len(fp))
	}
	if Fingerprint(mustCA(t, "home").Cert) == fp {
		t.Error("two different certs share a fingerprint")
	}
}

func mustPEMKey(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := EncodeKeyPEM(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func big1() *big.Int { return big.NewInt(1) }
