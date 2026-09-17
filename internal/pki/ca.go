// Package pki is the mesh's certificate authority and pairing protocol.
//
// Identity model: every principal in the mesh holds a leaf cert signed by the
// mesh CA. The cert's SAN URI encodes who it is:
//
//	lcm://<mesh_id>/node/<node_id>    a meshd worker or coordinator
//	lcm://<mesh_id>/admin/<name>      a meshctl operator
//
// Transports verify the chain AND that the URI's mesh_id matches their own,
// so two meshes that somehow share a CA still refuse each other.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

const (
	// URIScheme is the scheme of the SAN URI carrying mesh id and role.
	URIScheme = "lcm"

	RoleNode  = "node"
	RoleAdmin = "admin"

	// CACertTTL is long-lived: rotating the root means re-pairing every node.
	CACertTTL = 10 * 365 * 24 * time.Hour

	// DefaultNodeCertTTL is 30 days until automatic rotation lands (week 3),
	// at which point it drops to the 24 h in the design. A 24 h cert with no
	// rotation would brick the mesh daily.
	DefaultNodeCertTTL = 30 * 24 * time.Hour

	// DefaultAdminCertTTL: the operator cert lives with the CA key on the init
	// machine; it is not the thing that gets lost with a laptop.
	DefaultAdminCertTTL = 365 * 24 * time.Hour

	// backdate tolerates clock skew between nodes when a fresh cert is used.
	backdate = 5 * time.Minute
)

var (
	ErrNoMeshURI     = errors.New("pki: certificate has no lcm:// SAN URI")
	ErrMeshMismatch  = errors.New("pki: certificate belongs to a different mesh")
	ErrBadPrincipal  = errors.New("pki: malformed lcm:// SAN URI")
	ErrBadCSR        = errors.New("pki: invalid certificate request")
	ErrNotCA         = errors.New("pki: certificate is not a CA")
	ErrKeyMismatch   = errors.New("pki: certificate does not match private key")
	ErrInvalidNodeID = errors.New("pki: node_id must match ^[a-z0-9][a-z0-9-]{0,62}$")
)

// Principal is the identity encoded in a cert's SAN URI.
type Principal struct {
	MeshID string
	Role   string // RoleNode or RoleAdmin
	Name   string // node_id for nodes, operator name for admins
}

// URI renders the principal as lcm://<mesh>/<role>/<name>.
func (p Principal) URI() *url.URL {
	return &url.URL{Scheme: URIScheme, Host: p.MeshID, Path: "/" + p.Role + "/" + p.Name}
}

func (p Principal) String() string { return p.URI().String() }

// ParsePrincipal decodes an lcm:// URI.
func ParsePrincipal(u *url.URL) (Principal, error) {
	if u == nil || u.Scheme != URIScheme || u.Host == "" {
		return Principal{}, ErrBadPrincipal
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Principal{}, fmt.Errorf("%w: %s", ErrBadPrincipal, u)
	}
	if parts[0] != RoleNode && parts[0] != RoleAdmin {
		return Principal{}, fmt.Errorf("%w: unknown role %q", ErrBadPrincipal, parts[0])
	}
	return Principal{MeshID: u.Host, Role: parts[0], Name: parts[1]}, nil
}

// PrincipalFromCert extracts the mesh principal from a leaf certificate.
func PrincipalFromCert(cert *x509.Certificate) (Principal, error) {
	for _, u := range cert.URIs {
		if u.Scheme == URIScheme {
			return ParsePrincipal(u)
		}
	}
	return Principal{}, ErrNoMeshURI
}

// CA is the mesh root: a self-signed ECDSA P-256 certificate and its key.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// MeshID is stored in the CA cert's Organization.
func (ca *CA) MeshID() string {
	if len(ca.Cert.Subject.Organization) == 0 {
		return ""
	}
	return ca.Cert.Subject.Organization[0]
}

// NewCA generates a fresh mesh CA. meshID must be a valid DNS label.
func NewCA(meshID string) (*CA, error) {
	if err := validateLabel(meshID); err != nil {
		return nil, fmt.Errorf("pki: mesh_id: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Local Compute Mesh CA",
			Organization: []string{meshID},
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(CACertTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("pki: self-sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// LoadCA reconstructs a CA from a parsed cert and key, checking they match.
func LoadCA(cert *x509.Certificate, key *ecdsa.PrivateKey) (*CA, error) {
	if !cert.IsCA {
		return nil, ErrNotCA
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, ErrKeyMismatch
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Pool returns a cert pool containing only this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// SignRequest describes the leaf certificate to issue.
type SignRequest struct {
	Principal Principal
	PublicKey *ecdsa.PublicKey
	TTL       time.Duration
}

// Sign issues a leaf certificate for a node or admin. The principal's mesh
// must equal the CA's mesh; a CA never signs for a foreign mesh.
func (ca *CA) Sign(req SignRequest) (*x509.Certificate, error) {
	if req.Principal.MeshID != ca.MeshID() {
		return nil, fmt.Errorf("%w: CA is %q, request is %q", ErrMeshMismatch, ca.MeshID(), req.Principal.MeshID)
	}
	if err := validateLabel(req.Principal.Name); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidNodeID, err)
	}
	if req.Principal.Role != RoleNode && req.Principal.Role != RoleAdmin {
		return nil, fmt.Errorf("%w: role %q", ErrBadPrincipal, req.Principal.Role)
	}
	if req.PublicKey == nil {
		return nil, errors.New("pki: public key required")
	}
	if req.TTL <= 0 {
		return nil, errors.New("pki: TTL must be positive")
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   req.Principal.Name,
			Organization: []string{req.Principal.MeshID},
		},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(req.TTL),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{req.Principal.URI()},
	}
	if req.Principal.Role == RoleNode {
		// DNS SAN = node_id so dialers use standard hostname verification with
		// ServerName = node_id learned from discovery. Admins never serve.
		tmpl.DNSNames = []string{req.Principal.Name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, req.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("pki: sign: %w", err)
	}
	return x509.ParseCertificate(der)
}

// SignCSR validates a PKCS#10 request (signature, key type) and issues a node
// cert for the given principal. The CSR's subject is ignored in favour of
// the principal the pairing flow authenticated; only the public key is used.
func (ca *CA) SignCSR(csrDER []byte, p Principal, ttl time.Duration) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: bad signature: %v", ErrBadCSR, err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: key must be ECDSA P-256", ErrBadCSR)
	}
	return ca.Sign(SignRequest{Principal: p, PublicKey: pub, TTL: ttl})
}

// Verify checks that leaf chains to this CA, is valid now, and belongs to
// this mesh. Returns the principal on success.
func (ca *CA) Verify(leaf *x509.Certificate, now time.Time) (Principal, error) {
	return VerifyAgainst(ca.Cert, leaf, now)
}

// VerifyAgainst is Verify for callers holding only the CA certificate.
func VerifyAgainst(caCert, leaf *x509.Certificate, now time.Time) (Principal, error) {
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return Principal{}, fmt.Errorf("pki: verify: %w", err)
	}
	p, err := PrincipalFromCert(leaf)
	if err != nil {
		return Principal{}, err
	}
	meshID := ""
	if len(caCert.Subject.Organization) > 0 {
		meshID = caCert.Subject.Organization[0]
	}
	if p.MeshID != meshID {
		return Principal{}, fmt.Errorf("%w: cert %q, CA %q", ErrMeshMismatch, p.MeshID, meshID)
	}
	return p, nil
}

// NewKey generates an ECDSA P-256 key for a leaf.
func NewKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// NewCSR builds a PKCS#10 request for nodeID signed by key.
func NewCSR(nodeID string, key *ecdsa.PrivateKey) ([]byte, error) {
	if err := validateLabel(nodeID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidNodeID, err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: nodeID},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	return x509.CreateCertificateRequest(rand.Reader, tmpl, key)
}

// Fingerprint is the hex SHA-256 of a certificate's DER, as advertised in
// the mDNS TXT record and shown by `meshctl status`.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func newSerial() (*big.Int, error) {
	// 128 random bits; RFC 5280 requires positive and ≤ 20 octets.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("pki: serial: %w", err)
	}
	return s.Add(s, big.NewInt(1)), nil
}

// validateLabel accepts a lowercase DNS label: what node_id and mesh_id use.
func validateLabel(s string) error {
	if len(s) == 0 || len(s) > 63 {
		return fmt.Errorf("%q length must be 1..63", s)
	}
	for i, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (r == '-' && i > 0)
		if !ok {
			return fmt.Errorf("%q contains invalid character %q", s, r)
		}
	}
	return nil
}
