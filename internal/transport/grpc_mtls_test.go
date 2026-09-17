package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/sanj6y/compute-mesh/internal/pki"
)

// Tests use a throwaway CA per test; no plaintext anywhere.

func issue(t *testing.T, ca *pki.CA, p pki.Principal) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Sign(pki.SignRequest{Principal: p, PublicKey: &key.PublicKey, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func identity(t *testing.T, ca *pki.CA, p pki.Principal) *Identity {
	t.Helper()
	cert, key := issue(t, ca, p)
	id, err := NewIdentity(ca.Cert, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// serve starts a health server under id and returns its address.
func serve(t *testing.T, id *Identity, opts ...grpc.ServerOption) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := id.NewServer(opts...)
	grpc_health_v1.RegisterHealthServer(srv, health.NewServer())
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func ping(t *testing.T, client *Identity, addr, serverNodeID string) error {
	t.Helper()
	conn, err := client.Dial(addr, serverNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	return err
}

func TestNewIdentityRejects(t *testing.T) {
	ca, _ := pki.NewCA("home")
	cert, key := issue(t, ca, pki.Principal{MeshID: "home", Role: pki.RoleNode, Name: "n1"})
	other, _ := pki.NewKey()
	if _, err := NewIdentity(ca.Cert, cert, other); !errors.Is(err, pki.ErrKeyMismatch) {
		t.Errorf("wrong key: err = %v", err)
	}
	otherCA, _ := pki.NewCA("home")
	if _, err := NewIdentity(otherCA.Cert, cert, key); err == nil {
		t.Error("cert from another CA accepted")
	}
}

func TestMTLS(t *testing.T) {
	ca, _ := pki.NewCA("home")
	server := identity(t, ca, pki.Principal{MeshID: "home", Role: pki.RoleNode, Name: "coord"})
	addr := serve(t, server)

	foreignCA, _ := pki.NewCA("home") // same name, different key: an impostor mesh
	otherMeshCA, _ := pki.NewCA("work")

	tests := []struct {
		name         string
		client       *Identity
		serverNodeID string
		wantCode     codes.Code
	}{
		{"node to node", identity(t, ca, pki.Principal{MeshID: "home", Role: pki.RoleNode, Name: "worker"}), "coord", codes.OK},
		{"admin to node", identity(t, ca, pki.Principal{MeshID: "home", Role: pki.RoleAdmin, Name: "op"}), "coord", codes.OK},
		{"client cert from impostor CA", identity(t, foreignCA, pki.Principal{MeshID: "home", Role: pki.RoleNode, Name: "worker"}), "coord", codes.Unavailable},
		{"client from another mesh (own CA)", identity(t, otherMeshCA, pki.Principal{MeshID: "work", Role: pki.RoleNode, Name: "worker"}), "coord", codes.Unavailable},
		{"wrong expected server name", identity(t, ca, pki.Principal{MeshID: "home", Role: pki.RoleNode, Name: "worker"}), "not-coord", codes.Unavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ping(t, tt.client, addr, tt.serverNodeID)
			if got := status.Code(err); got != tt.wantCode {
				t.Errorf("code = %v (%v), want %v", got, err, tt.wantCode)
			}
		})
	}
}

func TestServerRejectsForeignMeshLeafSignedByOurCA(t *testing.T) {
	// The chain verifies, but the URI names another mesh. verifyPeer must
	// refuse it on both sides.
	ca, _ := pki.NewCA("home")
	server := identity(t, ca, pki.Principal{MeshID: "home", Role: pki.RoleNode, Name: "coord"})
	addr := serve(t, server)

	// Forge a leaf with mesh "work" using the home CA key (simulates CA key
	// misuse); NewIdentity would refuse it, so build the Identity by hand.
	key, _ := pki.NewKey()
	forged := forgeLeaf(t, ca, key, pki.Principal{MeshID: "work", Role: pki.RoleNode, Name: "x"})
	client := &Identity{Principal: pki.Principal{MeshID: "work"}, CACert: ca.Cert, Cert: forged, Key: key}
	client.tlsCert.Certificate = [][]byte{forged.Raw}
	client.tlsCert.PrivateKey = key
	client.pool = ca.Pool()

	if err := ping(t, client, addr, "coord"); status.Code(err) != codes.Unavailable {
		t.Errorf("forged-mesh client was accepted: %v", err)
	}
}

func TestRequireRole(t *testing.T) {
	ca, _ := pki.NewCA("home")
	server := identity(t, ca, pki.Principal{MeshID: "home", Role: pki.RoleNode, Name: "coord"})
	unary, stream := RequireRole("/grpc.health.v1.Health/", pki.RoleAdmin)
	addr := serve(t, server, grpc.ChainUnaryInterceptor(unary), grpc.ChainStreamInterceptor(stream))

	admin := identity(t, ca, pki.Principal{MeshID: "home", Role: pki.RoleAdmin, Name: "op"})
	node := identity(t, ca, pki.Principal{MeshID: "home", Role: pki.RoleNode, Name: "w"})

	if err := ping(t, admin, addr, "coord"); err != nil {
		t.Errorf("admin: %v", err)
	}
	if err := ping(t, node, addr, "coord"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("node: code = %v, want PermissionDenied", status.Code(err))
	}

	// Prefix mismatch: interceptor is a no-op for other services.
	unary2, _ := RequireRole("/lcm.v1.AdminService/", pki.RoleAdmin)
	addr2 := serve(t, server, grpc.UnaryInterceptor(unary2))
	if err := ping(t, node, addr2, "coord"); err != nil {
		t.Errorf("node on unguarded service: %v", err)
	}
}

func TestPeerPrincipal(t *testing.T) {
	if _, ok := PeerPrincipal(context.Background()); ok {
		t.Error("PeerPrincipal on a bare context should be false")
	}
	ca, _ := pki.NewCA("home")
	server := identity(t, ca, pki.Principal{MeshID: "home", Role: pki.RoleNode, Name: "coord"})
	var got pki.Principal
	capture := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		got, _ = PeerPrincipal(ctx)
		return h(ctx, req)
	}
	addr := serve(t, server, grpc.UnaryInterceptor(capture))
	want := pki.Principal{MeshID: "home", Role: pki.RoleAdmin, Name: "sanjay"}
	if err := ping(t, identity(t, ca, want), addr, "coord"); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("PeerPrincipal = %+v, want %+v", got, want)
	}
}

func TestLoadIdentityFromDisk(t *testing.T) {
	dir := t.TempDir()
	ca, _ := pki.NewCA("home")
	cert, key := issue(t, ca, pki.Principal{MeshID: "home", Role: pki.RoleNode, Name: "n1"})
	if err := pki.WriteCert(dir, pki.CACertFile, ca.Cert, false); err != nil {
		t.Fatal(err)
	}
	pki.WriteCert(dir, pki.NodeCertFile, cert, false)
	pki.WriteKey(dir, pki.NodeKeyFile, key, false)
	id, err := LoadNodeIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id.Principal.Name != "n1" || id.MeshID() != "home" || id.Fingerprint() != pki.Fingerprint(cert) {
		t.Errorf("loaded identity = %+v", id.Principal)
	}
	if _, err := LoadAdminIdentity(dir); err == nil {
		t.Error("missing admin cert should fail")
	}
}
