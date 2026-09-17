// Package coordinator hosts the roles only one node runs: the admin API for
// meshctl, and (in later steps) the node registry and scheduler.
package coordinator

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/sanj6y/compute-mesh/internal/pki"
	"github.com/sanj6y/compute-mesh/internal/transport"
	lcmv1 "github.com/sanj6y/compute-mesh/proto/lcm/v1"
)

// AdminServicePrefix is the gRPC method prefix guarded by the admin role.
const AdminServicePrefix = "/lcm.v1.AdminService/"

// MaxPairingCodeTTL bounds what meshctl may ask for.
const MaxPairingCodeTTL = 10 * time.Minute

// Admin implements lcmv1.AdminServiceServer.
type Admin struct {
	lcmv1.UnimplementedAdminServiceServer
	pairer   *pki.Pairer
	pairAddr string
	log      *slog.Logger
}

// NewAdmin builds the admin service. pairAddr is what meshctl prints for
// joiners (host:port of the pairing listener).
func NewAdmin(pairer *pki.Pairer, pairAddr string, log *slog.Logger) *Admin {
	if log == nil {
		log = slog.Default()
	}
	return &Admin{pairer: pairer, pairAddr: pairAddr, log: log.With("component", "admin")}
}

// Register attaches the service to srv together with the role guard.
// Returns the interceptors so the caller can chain them when building srv.
func AdminInterceptors() (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	return transport.RequireRole(AdminServicePrefix, pki.RoleAdmin)
}

func (a *Admin) CreatePairingCode(ctx context.Context, req *lcmv1.CreatePairingCodeRequest) (*lcmv1.CreatePairingCodeResponse, error) {
	ttl := time.Duration(req.GetTtlSeconds()) * time.Second
	if ttl > MaxPairingCodeTTL {
		return nil, status.Errorf(codes.InvalidArgument, "ttl_seconds must be ≤ %d", int(MaxPairingCodeTTL.Seconds()))
	}
	issued, err := a.pairer.Issue(ttl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	who, _ := transport.PeerPrincipal(ctx)
	a.log.Info("pairing code issued", "by", who.Name, "expires", issued.ExpiresAt)
	return &lcmv1.CreatePairingCodeResponse{
		Code:      issued.Code,
		ExpiresAt: timestamppb.New(issued.ExpiresAt),
		PairAddr:  a.pairAddr,
	}, nil
}
