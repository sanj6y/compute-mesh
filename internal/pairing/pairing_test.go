package pairing

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/sanj6y/compute-mesh/internal/pki"
	"github.com/sanj6y/compute-mesh/internal/transport"
)

type env struct {
	ca    *pki.CA
	coord *transport.Identity
	srv   *Server
	addr  string
}

func newEnv(t *testing.T, mesh string) *env {
	t.Helper()
	ca, err := pki.NewCA(mesh)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := pki.NewKey()
	cert, err := ca.Sign(pki.SignRequest{Principal: pki.Principal{MeshID: mesh, Role: pki.RoleNode, Name: "coord"}, PublicKey: &key.PublicKey, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	coord, err := transport.NewIdentity(ca.Cert, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(ServerConfig{Identity: coord, CA: ca, GRPCPort: 7443, NodeTTL: time.Hour, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return &env{ca: ca, coord: coord, srv: srv, addr: lis.Addr().String()}
}

func TestJoinEndToEnd(t *testing.T) {
	e := newEnv(t, "home")
	issued, err := e.srv.Pairer().Issue(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := Join(ctx, e.addr, issued.Code, "laptop-1", nil)
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if res.CoordinatorNodeID != "coord" {
		t.Errorf("CoordinatorNodeID = %q", res.CoordinatorNodeID)
	}
	if res.CoordinatorGRPCAddr != "127.0.0.1:7443" {
		t.Errorf("CoordinatorGRPCAddr = %q", res.CoordinatorGRPCAddr)
	}

	// The issued identity must actually work over the mTLS transport.
	dir := t.TempDir()
	if err := res.Persist(dir, false); err != nil {
		t.Fatal(err)
	}
	id, err := transport.LoadNodeIdentity(dir)
	if err != nil {
		t.Fatalf("persisted identity does not load: %v", err)
	}
	if id.Principal != (pki.Principal{MeshID: "home", Role: pki.RoleNode, Name: "laptop-1"}) {
		t.Errorf("principal = %+v", id.Principal)
	}
	if err := res.Persist(dir, false); !errors.Is(err, pki.ErrExists) {
		t.Errorf("second Persist without overwrite: %v", err)
	}
}

func TestJoinFailures(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T, e *env) (code string)
		nodeID   string
		wantCode codes.Code // gRPC code expected inside the error, or OK for local errors
		wantErr  error
	}{
		{
			name:     "no active code",
			setup:    func(t *testing.T, e *env) string { return "12345678" },
			nodeID:   "n",
			wantCode: codes.FailedPrecondition,
		},
		{
			name: "wrong code",
			setup: func(t *testing.T, e *env) string {
				issued, _ := e.srv.Pairer().Issue(0)
				if issued.Code == "00000000" {
					return "00000001"
				}
				return "00000000"
			},
			nodeID:   "n",
			wantCode: codes.PermissionDenied,
		},
		{
			name:    "malformed code",
			setup:   func(t *testing.T, e *env) string { return "abc" },
			nodeID:  "n",
			wantErr: pki.ErrBadCodeFormat,
		},
		{
			name: "bad node id",
			setup: func(t *testing.T, e *env) string {
				issued, _ := e.srv.Pairer().Issue(0)
				return issued.Code
			},
			nodeID:  "Bad Node",
			wantErr: pki.ErrInvalidNodeID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, "home")
			code := tt.setup(t, e)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := Join(ctx, e.addr, code, tt.nodeID, nil)
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantCode != codes.OK && status.Code(err) != tt.wantCode {
				t.Errorf("code = %v (%v), want %v", status.Code(err), err, tt.wantCode)
			}
		})
	}
}

func TestJoinAgainstWrongCoordinator(t *testing.T) {
	// A joiner given a code from mesh A but pointed at mesh B's coordinator
	// (or a rogue one) must fail: B has no matching code, so its Argon2
	// check fails and it returns PermissionDenied. Nothing is persisted.
	a := newEnv(t, "home")
	b := newEnv(t, "rogue")
	b.srv.Pairer().Issue(0) // rogue has its own active code
	issued, _ := a.srv.Pairer().Issue(0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Join(ctx, b.addr, issued.Code, "n", nil)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("err = %v, want PermissionDenied", err)
	}
}

func TestNewServerRejectsMeshMismatch(t *testing.T) {
	e := newEnv(t, "home")
	other, _ := pki.NewCA("work")
	if _, err := NewServer(ServerConfig{Identity: e.coord, CA: other}); !errors.Is(err, pki.ErrMeshMismatch) {
		t.Errorf("err = %v", err)
	}
}
