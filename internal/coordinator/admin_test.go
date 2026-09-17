package coordinator

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/sanj6y/compute-mesh/internal/pki"
	"github.com/sanj6y/compute-mesh/internal/transport"
	lcmv1 "github.com/sanj6y/compute-mesh/proto/lcm/v1"
)

func ident(t *testing.T, ca *pki.CA, role, name string) *transport.Identity {
	t.Helper()
	key, _ := pki.NewKey()
	cert, err := ca.Sign(pki.SignRequest{Principal: pki.Principal{MeshID: ca.MeshID(), Role: role, Name: name}, PublicKey: &key.PublicKey, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	id, err := transport.NewIdentity(ca.Cert, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCreatePairingCode(t *testing.T) {
	ca, _ := pki.NewCA("home")
	coord := ident(t, ca, pki.RoleNode, "coord")
	pairer, _ := pki.NewPairer(pki.PairerConfig{CA: ca, ServerCert: coord.Cert})
	admin := NewAdmin(pairer, "10.0.0.1:7444", slog.New(slog.DiscardHandler))

	u, s := AdminInterceptors()
	srv := coord.NewServer(grpc.ChainUnaryInterceptor(u), grpc.ChainStreamInterceptor(s))
	lcmv1.RegisterAdminServiceServer(srv, admin)
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	call := func(id *transport.Identity, ttl uint32) (*lcmv1.CreatePairingCodeResponse, error) {
		conn, err := id.Dial(lis.Addr().String(), "coord")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return lcmv1.NewAdminServiceClient(conn).CreatePairingCode(ctx, &lcmv1.CreatePairingCodeRequest{TtlSeconds: ttl})
	}

	t.Run("admin ok", func(t *testing.T) {
		resp, err := call(ident(t, ca, pki.RoleAdmin, "op"), 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := pki.ValidateCodeFormat(resp.Code); err != nil {
			t.Errorf("code %q: %v", resp.Code, err)
		}
		if resp.PairAddr != "10.0.0.1:7444" {
			t.Errorf("PairAddr = %q", resp.PairAddr)
		}
		if until := time.Until(resp.ExpiresAt.AsTime()); until < 50*time.Second || until > 61*time.Second {
			t.Errorf("default expiry %v from now, want ~60s", until)
		}
		if pairer.ActiveCodes() != 1 {
			t.Errorf("ActiveCodes = %d", pairer.ActiveCodes())
		}
	})
	t.Run("node denied", func(t *testing.T) {
		_, err := call(ident(t, ca, pki.RoleNode, "worker"), 0)
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("code = %v", status.Code(err))
		}
	})
	t.Run("ttl too long", func(t *testing.T) {
		_, err := call(ident(t, ca, pki.RoleAdmin, "op"), 3600)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("code = %v", status.Code(err))
		}
	})
}
