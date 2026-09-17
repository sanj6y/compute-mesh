// Package pairing is the gRPC wire layer for the pki pairing protocol: the
// coordinator-side PairingService and the joiner-side Join client.
//
// The listener is server-auth TLS only (the joiner has no client cert yet).
// It hosts nothing but PairingService and is bound to a separate port from
// the mTLS control plane, so the "every gRPC connection is mTLS" rule holds
// for everything except this deliberately narrow bootstrap.
package pairing

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/sanj6y/compute-mesh/internal/pki"
	"github.com/sanj6y/compute-mesh/internal/transport"
	lcmv1 "github.com/sanj6y/compute-mesh/proto/lcm/v1"
)

// ServerConfig configures the pairing listener.
type ServerConfig struct {
	Identity *transport.Identity // coordinator's node identity; its cert is the TLS server cert
	CA       *pki.CA
	// GRPCPort is the coordinator's mTLS control-plane port. The joiner fills
	// in the host it connected to, so only the port is sent.
	GRPCPort int
	NodeTTL  time.Duration
	Logger   *slog.Logger
	Now      func() time.Time
}

// Server implements lcmv1.PairingServiceServer.
type Server struct {
	lcmv1.UnimplementedPairingServiceServer
	cfg    ServerConfig
	pairer *pki.Pairer
	log    *slog.Logger
	grpc   *grpc.Server
}

// NewServer builds the service. Call Serve to start it.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Identity == nil || cfg.CA == nil {
		return nil, errors.New("pairing: Identity and CA are required")
	}
	if cfg.Identity.MeshID() != cfg.CA.MeshID() {
		return nil, pki.ErrMeshMismatch
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	p, err := pki.NewPairer(pki.PairerConfig{
		CA:         cfg.CA,
		ServerCert: cfg.Identity.Cert,
		NodeTTL:    cfg.NodeTTL,
		Now:        cfg.Now,
	})
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, pairer: p, log: cfg.Logger.With("component", "pairing")}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{cfg.Identity.Cert.Raw}, PrivateKey: cfg.Identity.Key, Leaf: cfg.Identity.Cert}},
		ClientAuth:   tls.NoClientCert,
	}
	s.grpc = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	lcmv1.RegisterPairingServiceServer(s.grpc, s)
	return s, nil
}

// Pairer exposes code issuance to the AdminService.
func (s *Server) Pairer() *pki.Pairer { return s.pairer }

// Serve blocks serving lis until Stop.
func (s *Server) Serve(lis net.Listener) error { return s.grpc.Serve(lis) }

// Stop halts the listener.
func (s *Server) Stop() { s.grpc.Stop() }

func (s *Server) Begin(ctx context.Context, req *lcmv1.BeginPairingRequest) (*lcmv1.BeginPairingResponse, error) {
	sess, err := s.pairer.Begin()
	if err != nil {
		s.log.Warn("pairing begin refused", "node_id", req.GetNodeId(), "err", err)
		return nil, toStatus(err)
	}
	s.log.Info("pairing session opened", "node_id", req.GetNodeId())
	return &lcmv1.BeginPairingResponse{
		SessionId: sess.ID,
		Salt:      sess.Salt,
		MeshId:    s.cfg.CA.MeshID(),
		ExpiresAt: timestamppb.New(sess.ExpiresAt),
	}, nil
}

func (s *Server) Complete(ctx context.Context, req *lcmv1.CompletePairingRequest) (*lcmv1.CompletePairingResponse, error) {
	b, err := s.pairer.Complete(req.GetSessionId(), req.GetCsrDer(), req.GetClientMac())
	if err != nil {
		s.log.Warn("pairing failed", "err", err)
		return nil, toStatus(err)
	}
	p, _ := pki.PrincipalFromCert(b.NodeCert)
	s.log.Info("node paired", "peer", p.Name, "fingerprint", pki.Fingerprint(b.NodeCert)[:12], "expires", b.NodeCert.NotAfter)
	return &lcmv1.CompletePairingResponse{
		CaCertDer:           b.CACert.Raw,
		NodeCertDer:         b.NodeCert.Raw,
		MeshId:              b.MeshID,
		CoordinatorNodeId:   s.cfg.Identity.Principal.Name,
		CoordinatorGrpcAddr: ":" + strconv.Itoa(s.cfg.GRPCPort),
		ServerMac:           b.ServerMAC,
	}, nil
}

func toStatus(err error) error {
	switch {
	case errors.Is(err, pki.ErrNoActiveCode):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, pki.ErrTooManyAttempts), errors.Is(err, pki.ErrBusy):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, pki.ErrUnknownSession):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, pki.ErrBadCode):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, pki.ErrBadCSR), errors.Is(err, pki.ErrInvalidNodeID):
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}
