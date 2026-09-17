package pairing

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/sanj6y/compute-mesh/internal/pki"
	lcmv1 "github.com/sanj6y/compute-mesh/proto/lcm/v1"
)

var ErrServerCertChanged = errors.New("pairing: server certificate changed between Begin and Complete")

// JoinResult is everything the joiner needs to persist and start meshd.
type JoinResult struct {
	Key                 *ecdsa.PrivateKey
	Bundle              *pki.Bundle
	CoordinatorNodeID   string
	CoordinatorGRPCAddr string // host:port, host taken from addr
}

// Join runs the client side of the pairing protocol against addr.
//
// The TLS connection deliberately does not verify the server certificate
// (the joiner has no CA yet). Instead the server cert is hashed into the
// client MAC, and the response MAC is checked under the code-derived key
// before anything in the response is trusted.
func Join(ctx context.Context, addr, code, nodeID string, now func() time.Time) (*JoinResult, error) {
	if err := pki.ValidateCodeFormat(code); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	key, err := pki.NewKey()
	if err != nil {
		return nil, err
	}
	csr, err := pki.NewCSR(nodeID, key)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // authenticated by the code-bound MACs, see package doc
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("pairing: dial %s: %w", addr, err)
	}
	defer conn.Close()
	client := lcmv1.NewPairingServiceClient(conn)

	var beginPeer peer.Peer
	begin, err := client.Begin(ctx, &lcmv1.BeginPairingRequest{NodeId: nodeID}, grpc.Peer(&beginPeer))
	if err != nil {
		return nil, fmt.Errorf("pairing: begin: %w", err)
	}
	serverCert, err := certFromPeer(beginPeer)
	if err != nil {
		return nil, err
	}

	k := pki.DeriveKey(code, begin.GetSalt())
	mac := pki.ClientMAC(k, begin.GetSessionId(), pki.CertHash(serverCert), csr)

	var completePeer peer.Peer
	resp, err := client.Complete(ctx, &lcmv1.CompletePairingRequest{
		SessionId: begin.GetSessionId(),
		CsrDer:    csr,
		ClientMac: mac,
	}, grpc.Peer(&completePeer))
	if err != nil {
		return nil, fmt.Errorf("pairing: complete: %w", err)
	}
	// Both RPCs must have gone to the same TLS endpoint; otherwise the MAC
	// would have been bound to a cert the responder never presented.
	if c2, err := certFromPeer(completePeer); err != nil || !bytes.Equal(c2.Raw, serverCert.Raw) {
		return nil, ErrServerCertChanged
	}

	caCert, err := x509.ParseCertificate(resp.GetCaCertDer())
	if err != nil {
		return nil, fmt.Errorf("pairing: bad CA cert in response: %w", err)
	}
	nodeCert, err := x509.ParseCertificate(resp.GetNodeCertDer())
	if err != nil {
		return nil, fmt.Errorf("pairing: bad node cert in response: %w", err)
	}
	bundle := &pki.Bundle{CACert: caCert, NodeCert: nodeCert, MeshID: resp.GetMeshId(), ServerMAC: resp.GetServerMac()}
	if err := pki.VerifyBundle(k, begin.GetSessionId(), bundle, nodeID, now()); err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(nodeCert.PublicKey) {
		return nil, errors.New("pairing: issued cert does not match our key")
	}
	// The pairing listener's cert must itself chain to the CA we were just
	// handed and belong to the coordinator named in the response.
	sp, err := pki.VerifyAgainst(caCert, serverCert, now())
	if err != nil {
		return nil, fmt.Errorf("pairing: server cert does not chain to issued CA: %w", err)
	}
	if sp.Role != pki.RoleNode || sp.Name != resp.GetCoordinatorNodeId() {
		return nil, fmt.Errorf("pairing: server cert is %s, response claims coordinator %q", sp, resp.GetCoordinatorNodeId())
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("pairing: bad addr %q: %w", addr, err)
	}
	_, port, err := net.SplitHostPort(resp.GetCoordinatorGrpcAddr())
	if err != nil {
		return nil, fmt.Errorf("pairing: bad coordinator addr %q: %w", resp.GetCoordinatorGrpcAddr(), err)
	}
	return &JoinResult{
		Key:                 key,
		Bundle:              bundle,
		CoordinatorNodeID:   resp.GetCoordinatorNodeId(),
		CoordinatorGRPCAddr: net.JoinHostPort(host, port),
	}, nil
}

func certFromPeer(p peer.Peer) (*x509.Certificate, error) {
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.PeerCertificates) == 0 {
		return nil, errors.New("pairing: no server certificate on connection")
	}
	return ti.State.PeerCertificates[0], nil
}

// Persist writes the CA cert, node cert and node key into dir.
func (r *JoinResult) Persist(dir string, overwrite bool) error {
	if err := pki.WriteCert(dir, pki.CACertFile, r.Bundle.CACert, overwrite); err != nil {
		return err
	}
	if err := pki.WriteCert(dir, pki.NodeCertFile, r.Bundle.NodeCert, overwrite); err != nil {
		return err
	}
	return pki.WriteKey(dir, pki.NodeKeyFile, r.Key, overwrite)
}
