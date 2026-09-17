package pki

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// Pairing protocol constants. Changing any of these is a protocol version bump.
const (
	CodeDigits = 8
	codeSpace  = 100_000_000 // 10^CodeDigits

	SessionIDLen = 16
	SaltLen      = 16

	DefaultCodeTTL    = 60 * time.Second
	DefaultSessionTTL = 60 * time.Second

	// Argon2id parameters: ~30-60 ms per derivation on a laptop core. The
	// coordinator derives once per active code per Complete attempt, so an
	// attacker gets at most (rate limit) guesses per minute online, and
	// offline brute force of 10^8 codes costs ~10^8 × 40 ms ≈ 46 days per
	// captured handshake, against a 60 s code lifetime.
	argonTime    = 2
	argonMemory  = 32 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32

	labelClient = "lcm-pair-v1/client"
	labelServer = "lcm-pair-v1/server"

	// Limits on the server side.
	maxSessions        = 32
	maxFailuresPerMin  = 5
	failureWindowReset = time.Minute
)

var (
	ErrBadCode         = errors.New("pairing: code rejected")
	ErrNoActiveCode    = errors.New("pairing: no active pairing code; run `meshctl pair` on the coordinator")
	ErrUnknownSession  = errors.New("pairing: unknown or expired session")
	ErrTooManyAttempts = errors.New("pairing: too many failed attempts; try again in a minute")
	ErrBusy            = errors.New("pairing: too many concurrent pairing sessions")
	ErrBadMAC          = errors.New("pairing: response MAC invalid; possible relay or wrong coordinator")
	ErrBadCodeFormat   = errors.New("pairing: code must be 8 digits")
)

// GenerateCode returns a uniformly random 8-digit code, zero-padded.
func GenerateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(codeSpace))
	if err != nil {
		return "", fmt.Errorf("pairing: random: %w", err)
	}
	return fmt.Sprintf("%0*d", CodeDigits, n.Int64()), nil
}

// ValidateCodeFormat checks the shape (not the validity) of a code.
func ValidateCodeFormat(code string) error {
	if len(code) != CodeDigits {
		return ErrBadCodeFormat
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return ErrBadCodeFormat
		}
	}
	return nil
}

// DeriveKey stretches the code into a MAC key. Deliberately slow.
func DeriveKey(code string, salt []byte) []byte {
	return argon2.IDKey([]byte(code), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// ClientMAC binds the joiner's CSR to the session and to the TLS server
// certificate it actually connected to (channel binding).
func ClientMAC(key, sessionID, serverCertHash, csrDER []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(labelClient))
	m.Write(sessionID)
	m.Write(serverCertHash)
	m.Write(csrDER)
	return m.Sum(nil)
}

// ServerMAC proves the coordinator knew the code and binds the issued
// certificates to the session.
func ServerMAC(key, sessionID, caDER, nodeDER []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(labelServer))
	m.Write(sessionID)
	m.Write(caDER)
	m.Write(nodeDER)
	return m.Sum(nil)
}

// CertHash is the channel-binding value: SHA-256 of the DER.
func CertHash(cert *x509.Certificate) []byte {
	h := sha256.Sum256(cert.Raw)
	return h[:]
}

// Issued describes a code handed out by Pairer.Issue.
type Issued struct {
	Code      string
	ExpiresAt time.Time
}

// Session is an open pairing attempt from a joiner.
type Session struct {
	ID        []byte
	Salt      []byte
	ExpiresAt time.Time
}

// Bundle is what a successful pairing returns to the joiner.
type Bundle struct {
	CACert   *x509.Certificate
	NodeCert *x509.Certificate
	MeshID   string
	// ServerMAC over (session, CA, node cert) so the joiner can authenticate
	// the response before trusting the CA in it.
	ServerMAC []byte
}

// Pairer is the coordinator-side state machine: active codes, open sessions,
// and a failure rate limit. Safe for concurrent use.
type Pairer struct {
	ca         *CA
	serverCert *x509.Certificate // the TLS cert the pairing listener presents
	nodeTTL    time.Duration
	now        func() time.Time

	mu       sync.Mutex
	codes    map[string]time.Time // code -> expiry; deleted on use
	sessions map[string]*Session  // string(id) -> session
	failures []time.Time
}

// PairerConfig configures NewPairer.
type PairerConfig struct {
	CA         *CA
	ServerCert *x509.Certificate
	NodeTTL    time.Duration // default DefaultNodeCertTTL
	Now        func() time.Time
}

// NewPairer returns a Pairer with no active codes.
func NewPairer(cfg PairerConfig) (*Pairer, error) {
	if cfg.CA == nil || cfg.ServerCert == nil {
		return nil, errors.New("pairing: CA and ServerCert are required")
	}
	if cfg.NodeTTL <= 0 {
		cfg.NodeTTL = DefaultNodeCertTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Pairer{
		ca:         cfg.CA,
		serverCert: cfg.ServerCert,
		nodeTTL:    cfg.NodeTTL,
		now:        cfg.Now,
		codes:      make(map[string]time.Time),
		sessions:   make(map[string]*Session),
	}, nil
}

// Issue mints a new single-use code. ttl <= 0 uses DefaultCodeTTL.
func (p *Pairer) Issue(ttl time.Duration) (Issued, error) {
	if ttl <= 0 {
		ttl = DefaultCodeTTL
	}
	code, err := GenerateCode()
	if err != nil {
		return Issued{}, err
	}
	exp := p.now().Add(ttl)
	p.mu.Lock()
	p.gcLocked()
	p.codes[code] = exp
	p.mu.Unlock()
	return Issued{Code: code, ExpiresAt: exp}, nil
}

// ActiveCodes reports how many unexpired codes exist.
func (p *Pairer) ActiveCodes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	return len(p.codes)
}

// Begin opens a session. Refused when no code is active (so an idle
// coordinator does no Argon2 work for strangers) or when rate limited.
func (p *Pairer) Begin() (*Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	if len(p.codes) == 0 {
		return nil, ErrNoActiveCode
	}
	if len(p.failures) >= maxFailuresPerMin {
		return nil, ErrTooManyAttempts
	}
	if len(p.sessions) >= maxSessions {
		return nil, ErrBusy
	}
	id := make([]byte, SessionIDLen)
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	s := &Session{ID: id, Salt: salt, ExpiresAt: p.now().Add(DefaultSessionTTL)}
	p.sessions[string(id)] = s
	return s, nil
}

// Complete verifies the client MAC against every active code, consumes the
// matching code, signs the CSR, and returns the bundle. The session is
// consumed whether or not it succeeds: one attempt per Begin.
func (p *Pairer) Complete(sessionID, csrDER, clientMAC []byte) (*Bundle, error) {
	p.mu.Lock()
	p.gcLocked()
	s, ok := p.sessions[string(sessionID)]
	delete(p.sessions, string(sessionID))
	if !ok {
		p.mu.Unlock()
		return nil, ErrUnknownSession
	}
	if len(p.failures) >= maxFailuresPerMin {
		p.mu.Unlock()
		return nil, ErrTooManyAttempts
	}
	candidates := make([]string, 0, len(p.codes))
	for c := range p.codes {
		candidates = append(candidates, c)
	}
	p.mu.Unlock()

	// Argon2 outside the lock: it is the expensive part.
	serverHash := CertHash(p.serverCert)
	var matched string
	var key []byte
	for _, c := range candidates {
		k := DeriveKey(c, s.Salt)
		if subtle.ConstantTimeCompare(ClientMAC(k, s.ID, serverHash, csrDER), clientMAC) == 1 {
			matched, key = c, k
			break
		}
	}

	p.mu.Lock()
	if matched == "" {
		p.failures = append(p.failures, p.now())
		p.mu.Unlock()
		return nil, ErrBadCode
	}
	if _, still := p.codes[matched]; !still {
		// Raced with another joiner who used the same code first.
		p.mu.Unlock()
		return nil, ErrBadCode
	}
	delete(p.codes, matched)
	p.mu.Unlock()

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCSR, err)
	}
	nodeID := csr.Subject.CommonName
	principal := Principal{MeshID: p.ca.MeshID(), Role: RoleNode, Name: nodeID}
	nodeCert, err := p.ca.SignCSR(csrDER, principal, p.nodeTTL)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		CACert:    p.ca.Cert,
		NodeCert:  nodeCert,
		MeshID:    p.ca.MeshID(),
		ServerMAC: ServerMAC(key, s.ID, p.ca.Cert.Raw, nodeCert.Raw),
	}, nil
}

// VerifyBundle is the joiner-side check: the response MAC must be valid under
// the code-derived key, the node cert must chain to the returned CA, and it
// must carry our node_id.
func VerifyBundle(key, sessionID []byte, b *Bundle, nodeID string, now time.Time) error {
	want := ServerMAC(key, sessionID, b.CACert.Raw, b.NodeCert.Raw)
	if subtle.ConstantTimeCompare(want, b.ServerMAC) != 1 {
		return ErrBadMAC
	}
	p, err := VerifyAgainst(b.CACert, b.NodeCert, now)
	if err != nil {
		return err
	}
	if p.Role != RoleNode || p.Name != nodeID {
		return fmt.Errorf("pairing: issued cert is for %s, expected node %s", p, nodeID)
	}
	if b.MeshID != p.MeshID {
		return fmt.Errorf("%w: bundle says %q, cert says %q", ErrMeshMismatch, b.MeshID, p.MeshID)
	}
	return nil
}

// gcLocked drops expired codes, sessions, and old failures. Caller holds mu.
func (p *Pairer) gcLocked() {
	now := p.now()
	for c, exp := range p.codes {
		if now.After(exp) {
			delete(p.codes, c)
		}
	}
	for id, s := range p.sessions {
		if now.After(s.ExpiresAt) {
			delete(p.sessions, id)
		}
	}
	keep := p.failures[:0]
	for _, t := range p.failures {
		if now.Sub(t) < failureWindowReset {
			keep = append(keep, t)
		}
	}
	p.failures = keep
}
