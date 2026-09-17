// Package transport builds every gRPC server and client connection in the
// mesh. All of them are mTLS: both sides present a mesh-CA-signed cert, and
// both sides check the peer's SAN URI names the same mesh_id. There is no
// plaintext or server-only-auth path here; the pairing bootstrap, which is
// the one server-auth-only listener, lives in internal/pki and is documented
// in docs/adr/0002-pairing.md.
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/sanj6y/compute-mesh/internal/pki"
)

var (
	ErrNoPeerCert    = errors.New("transport: peer presented no certificate")
	ErrNotAuthorized = errors.New("transport: principal not authorized")
)

// Identity is what one process needs to speak mTLS: its own cert+key, the
// mesh CA, and the principal encoded in its cert.
type Identity struct {
	Principal pki.Principal
	CACert    *x509.Certificate
	Cert      *x509.Certificate
	Key       *ecdsa.PrivateKey
	tlsCert   tls.Certificate
	pool      *x509.CertPool
}

// NewIdentity validates that cert chains to caCert, matches key, and carries
// a mesh principal.
func NewIdentity(caCert, cert *x509.Certificate, key *ecdsa.PrivateKey) (*Identity, error) {
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, pki.ErrKeyMismatch
	}
	p, err := pki.VerifyAgainst(caCert, cert, time.Now())
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &Identity{
		Principal: p,
		CACert:    caCert,
		Cert:      cert,
		Key:       key,
		tlsCert:   tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert},
		pool:      pool,
	}, nil
}

// LoadIdentity reads ca.crt plus the named cert/key pair from dir.
func LoadIdentity(dir, certFile, keyFile string) (*Identity, error) {
	ca, err := pki.ReadCert(dir, pki.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("transport: read CA: %w", err)
	}
	cert, err := pki.ReadCert(dir, certFile)
	if err != nil {
		return nil, fmt.Errorf("transport: read cert: %w", err)
	}
	key, err := pki.ReadKey(dir, keyFile)
	if err != nil {
		return nil, fmt.Errorf("transport: read key: %w", err)
	}
	return NewIdentity(ca, cert, key)
}

// LoadNodeIdentity loads node.crt/node.key.
func LoadNodeIdentity(dir string) (*Identity, error) {
	return LoadIdentity(dir, pki.NodeCertFile, pki.NodeKeyFile)
}

// LoadAdminIdentity loads admin.crt/admin.key.
func LoadAdminIdentity(dir string) (*Identity, error) {
	return LoadIdentity(dir, pki.AdminCertFile, pki.AdminKeyFile)
}

// MeshID is the mesh this identity belongs to.
func (id *Identity) MeshID() string { return id.Principal.MeshID }

// Fingerprint of the leaf cert, for the mDNS TXT record.
func (id *Identity) Fingerprint() string { return pki.Fingerprint(id.Cert) }

// verifyPeer is the VerifyPeerCertificate hook: after the standard chain
// check, require an lcm:// URI for our mesh.
func (id *Identity) verifyPeer(_ [][]byte, chains [][]*x509.Certificate) error {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return ErrNoPeerCert
	}
	p, err := pki.PrincipalFromCert(chains[0][0])
	if err != nil {
		return err
	}
	if p.MeshID != id.MeshID() {
		return fmt.Errorf("%w: peer is in mesh %q, we are in %q", pki.ErrMeshMismatch, p.MeshID, id.MeshID())
	}
	return nil
}

// ServerTLS requires and verifies a client cert from the mesh CA.
func (id *Identity) ServerTLS() *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{id.tlsCert},
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             id.pool,
		VerifyPeerCertificate: id.verifyPeer,
	}
}

// ClientTLS verifies the server against the mesh CA with ServerName set to
// the peer's node_id (which is its DNS SAN).
func (id *Identity) ClientTLS(serverNodeID string) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{id.tlsCert},
		RootCAs:               id.pool,
		ServerName:            serverNodeID,
		VerifyPeerCertificate: id.verifyPeer,
	}
}

// NewServer returns a gRPC server that only accepts mesh mTLS connections.
// Extra options are appended after the credentials and keepalive policy.
func (id *Identity) NewServer(opts ...grpc.ServerOption) *grpc.Server {
	base := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(id.ServerTLS())),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	return grpc.NewServer(append(base, opts...)...)
}

// Dial opens an mTLS connection to addr, expecting the server's cert to name
// serverNodeID. The connection is lazy; the TLS handshake happens on first RPC.
func (id *Identity) Dial(addr, serverNodeID string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	base := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(id.ClientTLS(serverNodeID))),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	return grpc.NewClient(addr, append(base, opts...)...)
}

// PeerPrincipal returns the authenticated principal of the caller. It is
// always present on connections accepted by NewServer; the bool is false only
// for non-TLS test contexts.
func PeerPrincipal(ctx context.Context) (pki.Principal, bool) {
	pr, ok := peer.FromContext(ctx)
	if !ok {
		return pki.Principal{}, false
	}
	ti, ok := pr.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return pki.Principal{}, false
	}
	p, err := pki.PrincipalFromCert(ti.State.PeerCertificates[0])
	if err != nil {
		return pki.Principal{}, false
	}
	return p, true
}

// RequireRole returns interceptors that reject calls whose caller does not
// hold one of the roles. Apply per-service via a method prefix so a server
// can host admin and node services together.
func RequireRole(methodPrefix string, roles ...string) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	check := func(ctx context.Context, method string) error {
		if len(methodPrefix) > 0 && (len(method) < len(methodPrefix) || method[:len(methodPrefix)] != methodPrefix) {
			return nil
		}
		p, ok := PeerPrincipal(ctx)
		if !ok {
			return status.Error(codes.Unauthenticated, ErrNoPeerCert.Error())
		}
		if !allowed[p.Role] {
			return status.Errorf(codes.PermissionDenied, "%v: %s requires role %v", ErrNotAuthorized, method, roles)
		}
		return nil
	}
	unary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		if err := check(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return h(ctx, req)
	}
	stream := func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		if err := check(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return h(srv, ss)
	}
	return unary, stream
}
