package pki

import (
	"bytes"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

type harness struct {
	ca     *CA
	server *x509.Certificate
	p      *Pairer
	clock  *fakeClock
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ca := mustCA(t, "home")
	skey := mustKey(t)
	server, err := ca.Sign(SignRequest{Principal{"home", RoleNode, "coord"}, &skey.PublicKey, time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{t: time.Now()}
	p, err := NewPairer(PairerConfig{CA: ca, ServerCert: server, NodeTTL: time.Hour, Now: clock.now})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{ca: ca, server: server, p: p, clock: clock}
}

// join performs the client side of the protocol against h.p.
func (h *harness) join(t *testing.T, code, nodeID string, serverCert *x509.Certificate) (*Bundle, []byte, *Session, error) {
	t.Helper()
	s, err := h.p.Begin()
	if err != nil {
		return nil, nil, nil, err
	}
	key := mustKey(t)
	csr, err := NewCSR(nodeID, key)
	if err != nil {
		t.Fatal(err)
	}
	k := DeriveKey(code, s.Salt)
	mac := ClientMAC(k, s.ID, CertHash(serverCert), csr)
	b, err := h.p.Complete(s.ID, csr, mac)
	return b, k, s, err
}

func TestGenerateCode(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		c, err := GenerateCode()
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateCodeFormat(c); err != nil {
			t.Fatalf("generated code %q fails format check: %v", c, err)
		}
		seen[c] = true
	}
	if len(seen) < 99 {
		t.Errorf("only %d unique codes in 100 draws", len(seen))
	}
}

func TestValidateCodeFormat(t *testing.T) {
	tests := []struct {
		code string
		ok   bool
	}{
		{"12345678", true}, {"00000000", true},
		{"1234567", false}, {"123456789", false}, {"1234567a", false}, {"", false}, {"1234 678", false},
	}
	for _, tt := range tests {
		if err := ValidateCodeFormat(tt.code); (err == nil) != tt.ok {
			t.Errorf("ValidateCodeFormat(%q) = %v, want ok=%v", tt.code, err, tt.ok)
		}
	}
}

func TestDeriveKeyProperties(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, SaltLen)
	k1 := DeriveKey("12345678", salt)
	k2 := DeriveKey("12345678", salt)
	k3 := DeriveKey("12345679", salt)
	k4 := DeriveKey("12345678", bytes.Repeat([]byte{2}, SaltLen))
	if !bytes.Equal(k1, k2) {
		t.Error("KDF not deterministic")
	}
	if bytes.Equal(k1, k3) || bytes.Equal(k1, k4) {
		t.Error("KDF output does not depend on code and salt")
	}
	if len(k1) != argonKeyLen {
		t.Errorf("key len = %d", len(k1))
	}
	start := time.Now()
	DeriveKey("00000000", salt)
	if d := time.Since(start); d < 5*time.Millisecond {
		t.Errorf("KDF too fast to resist brute force: %v", d)
	}
}

func TestMACDomainSeparation(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	sid := bytes.Repeat([]byte{1}, SessionIDLen)
	data := []byte("x")
	if bytes.Equal(ClientMAC(key, sid, data, data), ServerMAC(key, sid, data, data)) {
		t.Error("client and server MACs collide on identical inputs")
	}
	if bytes.Equal(ClientMAC(key, sid, []byte("a"), data), ClientMAC(key, sid, []byte("b"), data)) {
		t.Error("client MAC ignores server cert hash")
	}
}

func TestPairingHappyPath(t *testing.T) {
	h := newHarness(t)
	issued, err := h.p.Issue(0)
	if err != nil {
		t.Fatal(err)
	}
	if h.p.ActiveCodes() != 1 {
		t.Fatalf("ActiveCodes = %d", h.p.ActiveCodes())
	}
	b, k, s, err := h.join(t, issued.Code, "laptop-1", h.server)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(k, s.ID, b, "laptop-1", h.clock.now()); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if b.MeshID != "home" || !b.CACert.Equal(h.ca.Cert) {
		t.Error("bundle has wrong mesh or CA")
	}
	p, _ := PrincipalFromCert(b.NodeCert)
	if p != (Principal{"home", RoleNode, "laptop-1"}) {
		t.Errorf("issued principal = %+v", p)
	}
	if h.p.ActiveCodes() != 0 {
		t.Error("code was not consumed")
	}
	// Same code cannot be used twice.
	if _, _, _, err := h.join(t, issued.Code, "laptop-2", h.server); !errors.Is(err, ErrNoActiveCode) {
		t.Errorf("reuse: err = %v, want ErrNoActiveCode", err)
	}
}

func TestPairingRejects(t *testing.T) {
	tests := []struct {
		name    string
		run     func(t *testing.T, h *harness) error
		wantErr error
	}{
		{
			name: "no active code",
			run: func(t *testing.T, h *harness) error {
				_, err := h.p.Begin()
				return err
			},
			wantErr: ErrNoActiveCode,
		},
		{
			name: "wrong code",
			run: func(t *testing.T, h *harness) error {
				issued, _ := h.p.Issue(0)
				wrong := "00000000"
				if wrong == issued.Code {
					wrong = "00000001"
				}
				_, _, _, err := h.join(t, wrong, "n", h.server)
				return err
			},
			wantErr: ErrBadCode,
		},
		{
			name: "relay: MAC bound to a different server cert",
			run: func(t *testing.T, h *harness) error {
				issued, _ := h.p.Issue(0)
				mitm := mustCA(t, "evil")
				mk := mustKey(t)
				mitmCert, _ := mitm.Sign(SignRequest{Principal{"evil", RoleNode, "mitm"}, &mk.PublicKey, time.Hour})
				_, _, _, err := h.join(t, issued.Code, "n", mitmCert)
				return err
			},
			wantErr: ErrBadCode,
		},
		{
			name: "expired code",
			run: func(t *testing.T, h *harness) error {
				issued, _ := h.p.Issue(30 * time.Second)
				h.clock.advance(31 * time.Second)
				_, _, _, err := h.join(t, issued.Code, "n", h.server)
				return err
			},
			wantErr: ErrNoActiveCode,
		},
		{
			name: "expired session",
			run: func(t *testing.T, h *harness) error {
				issued, _ := h.p.Issue(10 * time.Minute)
				s, _ := h.p.Begin()
				h.clock.advance(DefaultSessionTTL + time.Second)
				k := DeriveKey(issued.Code, s.Salt)
				csr, _ := NewCSR("n", mustKey(t))
				_, err := h.p.Complete(s.ID, csr, ClientMAC(k, s.ID, CertHash(h.server), csr))
				return err
			},
			wantErr: ErrUnknownSession,
		},
		{
			name: "unknown session",
			run: func(t *testing.T, h *harness) error {
				h.p.Issue(0)
				_, err := h.p.Complete(bytes.Repeat([]byte{9}, SessionIDLen), nil, nil)
				return err
			},
			wantErr: ErrUnknownSession,
		},
		{
			name: "session is single attempt",
			run: func(t *testing.T, h *harness) error {
				issued, _ := h.p.Issue(0)
				s, _ := h.p.Begin()
				csr, _ := NewCSR("n", mustKey(t))
				h.p.Complete(s.ID, csr, []byte("garbage")) // burns the session
				k := DeriveKey(issued.Code, s.Salt)
				_, err := h.p.Complete(s.ID, csr, ClientMAC(k, s.ID, CertHash(h.server), csr))
				return err
			},
			wantErr: ErrUnknownSession,
		},
		{
			name: "rate limited after repeated failures",
			run: func(t *testing.T, h *harness) error {
				h.p.Issue(0)
				for i := 0; i < maxFailuresPerMin; i++ {
					s, err := h.p.Begin()
					if err != nil {
						t.Fatalf("Begin %d: %v", i, err)
					}
					h.p.Complete(s.ID, []byte("x"), []byte("y"))
				}
				_, err := h.p.Begin()
				return err
			},
			wantErr: ErrTooManyAttempts,
		},
		{
			name: "rate limit resets after a minute",
			run: func(t *testing.T, h *harness) error {
				h.p.Issue(10 * time.Minute)
				for i := 0; i < maxFailuresPerMin; i++ {
					s, _ := h.p.Begin()
					h.p.Complete(s.ID, []byte("x"), []byte("y"))
				}
				h.clock.advance(failureWindowReset + time.Second)
				_, err := h.p.Begin()
				return err
			},
			wantErr: nil,
		},
		{
			name: "too many open sessions",
			run: func(t *testing.T, h *harness) error {
				h.p.Issue(0)
				for i := 0; i < maxSessions; i++ {
					if _, err := h.p.Begin(); err != nil {
						t.Fatalf("Begin %d: %v", i, err)
					}
				}
				_, err := h.p.Begin()
				return err
			},
			wantErr: ErrBusy,
		},
		{
			name: "invalid CSR with valid MAC",
			run: func(t *testing.T, h *harness) error {
				issued, _ := h.p.Issue(0)
				s, _ := h.p.Begin()
				k := DeriveKey(issued.Code, s.Salt)
				csr := []byte("not a csr")
				_, err := h.p.Complete(s.ID, csr, ClientMAC(k, s.ID, CertHash(h.server), csr))
				return err
			},
			wantErr: ErrBadCSR,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			err := tt.run(t, h)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestPairingMultipleActiveCodes(t *testing.T) {
	h := newHarness(t)
	a, _ := h.p.Issue(0)
	b, _ := h.p.Issue(0)
	if _, _, _, err := h.join(t, b.Code, "n2", h.server); err != nil {
		t.Fatalf("second code: %v", err)
	}
	if _, _, _, err := h.join(t, a.Code, "n1", h.server); err != nil {
		t.Fatalf("first code: %v", err)
	}
	if h.p.ActiveCodes() != 0 {
		t.Error("codes not consumed")
	}
}

func TestVerifyBundleRejects(t *testing.T) {
	h := newHarness(t)
	issued, _ := h.p.Issue(0)
	b, k, s, err := h.join(t, issued.Code, "laptop-1", h.server)
	if err != nil {
		t.Fatal(err)
	}
	now := h.clock.now()

	tests := []struct {
		name   string
		mutate func(b Bundle) (Bundle, []byte, string)
		want   error
	}{
		{"wrong key", func(b Bundle) (Bundle, []byte, string) { return b, bytes.Repeat([]byte{1}, 32), "laptop-1" }, ErrBadMAC},
		{"tampered mac", func(b Bundle) (Bundle, []byte, string) {
			b.ServerMAC = append([]byte{}, b.ServerMAC...)
			b.ServerMAC[0] ^= 1
			return b, k, "laptop-1"
		}, ErrBadMAC},
		{"swapped CA", func(b Bundle) (Bundle, []byte, string) { b.CACert = mustCA(t, "home").Cert; return b, k, "laptop-1" }, ErrBadMAC},
		{"wrong node id", func(b Bundle) (Bundle, []byte, string) { return b, k, "laptop-2" }, nil},
		{"mesh id lie", func(b Bundle) (Bundle, []byte, string) {
			b.MeshID = "work"
			return b, k, "laptop-1"
		}, ErrMeshMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mb, mk, id := tt.mutate(*b)
			err := VerifyBundle(mk, s.ID, &mb, id, now)
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}
