// meshctl is the operator CLI for Local Compute Mesh.
//
//	meshctl init --mesh-id home         create the mesh CA + this node's + admin identity
//	meshctl pair                        mint a one-time join code (talks to local meshd)
//	meshctl join --code 12345678        join the mesh; finds the coordinator over mDNS
//	meshctl version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/sanj6y/compute-mesh/internal/discovery"
	"github.com/sanj6y/compute-mesh/internal/identity"
	"github.com/sanj6y/compute-mesh/internal/pairing"
	"github.com/sanj6y/compute-mesh/internal/pki"
	"github.com/sanj6y/compute-mesh/internal/transport"
	lcmv1 "github.com/sanj6y/compute-mesh/proto/lcm/v1"
)

// version is set by the linker (see Makefile LDFLAGS).
var version = "dev"

const (
	defaultGRPCPort = 7443
	discoverTimeout = 5 * time.Second
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "meshctl:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		usage(stderr)
		return errors.New("no command")
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return cmdInit(rest, stdout, stderr)
	case "pair":
		return cmdPair(rest, stdout, stderr)
	case "join":
		return cmdJoin(rest, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "meshctl", version)
		return nil
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	}
	usage(stderr)
	return fmt.Errorf("unknown command %q", cmd)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage: meshctl <command> [flags]

commands:
  init     create a new mesh: CA, this node's certificate, and an admin certificate
  pair     mint a one-time code for another node to join (run on the coordinator)
  join     join an existing mesh with a code from 'meshctl pair'
  version  print version

run 'meshctl <command> -h' for flags`)
}

func defaultDataDir() string {
	if d := os.Getenv("LCM_DATA_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".lcm"
	}
	return filepath.Join(home, ".lcm")
}

// ---- init -------------------------------------------------------------------

func cmdInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("meshctl init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", defaultDataDir(), "state directory")
	meshID := fs.String("mesh-id", "", "name of the new mesh (lowercase DNS label), e.g. home")
	adminName := fs.String("admin-name", "admin", "name for the operator certificate")
	nodeIDFlag := fs.String("node-id", "", "name for this node (default: <hostname>-<random>)")
	force := fs.Bool("force", false, "overwrite an existing mesh in data-dir (invalidates every paired node)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *meshID == "" {
		return errors.New("--mesh-id is required")
	}
	if _, err := os.Stat(filepath.Join(*dataDir, pki.CAKeyFile)); err == nil && !*force {
		return fmt.Errorf("%s already contains a mesh CA; use --force to replace it", *dataDir)
	}

	nodeID, err := resolveNodeID(*dataDir, *nodeIDFlag, *force)
	if err != nil {
		return err
	}
	ca, err := pki.NewCA(*meshID)
	if err != nil {
		return err
	}
	nodeKey, err := pki.NewKey()
	if err != nil {
		return err
	}
	nodeCert, err := ca.Sign(pki.SignRequest{
		Principal: pki.Principal{MeshID: *meshID, Role: pki.RoleNode, Name: nodeID},
		PublicKey: &nodeKey.PublicKey,
		TTL:       pki.DefaultNodeCertTTL,
	})
	if err != nil {
		return err
	}
	adminKey, err := pki.NewKey()
	if err != nil {
		return err
	}
	adminCert, err := ca.Sign(pki.SignRequest{
		Principal: pki.Principal{MeshID: *meshID, Role: pki.RoleAdmin, Name: *adminName},
		PublicKey: &adminKey.PublicKey,
		TTL:       pki.DefaultAdminCertTTL,
	})
	if err != nil {
		return err
	}

	writes := []struct {
		name string
		fn   func() error
	}{
		{pki.CACertFile, func() error { return pki.WriteCert(*dataDir, pki.CACertFile, ca.Cert, *force) }},
		{pki.CAKeyFile, func() error { return pki.WriteKey(*dataDir, pki.CAKeyFile, ca.Key, *force) }},
		{pki.NodeCertFile, func() error { return pki.WriteCert(*dataDir, pki.NodeCertFile, nodeCert, *force) }},
		{pki.NodeKeyFile, func() error { return pki.WriteKey(*dataDir, pki.NodeKeyFile, nodeKey, *force) }},
		{pki.AdminCertFile, func() error { return pki.WriteCert(*dataDir, pki.AdminCertFile, adminCert, *force) }},
		{pki.AdminKeyFile, func() error { return pki.WriteKey(*dataDir, pki.AdminKeyFile, adminKey, *force) }},
	}
	for _, w := range writes {
		if err := w.fn(); err != nil {
			return fmt.Errorf("write %s: %w", w.name, err)
		}
	}

	fmt.Fprintf(stdout, "mesh %q initialised in %s\n", *meshID, *dataDir)
	fmt.Fprintf(stdout, "  node_id         %s\n", nodeID)
	fmt.Fprintf(stdout, "  CA fingerprint  %s\n", pki.Fingerprint(ca.Cert))
	fmt.Fprintf(stdout, "  node cert       expires %s\n", nodeCert.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(stdout, "  admin cert      %s, expires %s\n", *adminName, adminCert.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(stdout, "\nstart the coordinator:  meshd --coordinator\n")
	fmt.Fprintf(stdout, "then add nodes with:    meshctl pair\n")
	return nil
}

// ---- pair -------------------------------------------------------------------

func cmdPair(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("meshctl pair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", defaultDataDir(), "state directory")
	addr := fs.String("addr", fmt.Sprintf("127.0.0.1:%d", defaultGRPCPort), "coordinator gRPC address")
	ttl := fs.Duration("ttl", pki.DefaultCodeTTL, "how long the code stays valid")
	if err := fs.Parse(args); err != nil {
		return err
	}

	admin, err := transport.LoadAdminIdentity(*dataDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no admin identity in %s; `meshctl pair` runs where `meshctl init` ran", *dataDir)
		}
		return err
	}
	// The local daemon's cert names the local node_id; that is the expected
	// ServerName for the mTLS handshake.
	nodeCert, err := pki.ReadCert(*dataDir, pki.NodeCertFile)
	if err != nil {
		return fmt.Errorf("read local node cert: %w", err)
	}
	local, err := pki.PrincipalFromCert(nodeCert)
	if err != nil {
		return err
	}

	conn, err := admin.Dial(*addr, local.Name)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := lcmv1.NewAdminServiceClient(conn).CreatePairingCode(ctx, &lcmv1.CreatePairingCodeRequest{
		TtlSeconds: uint32(ttl.Seconds()),
	})
	if err != nil {
		return fmt.Errorf("is meshd --coordinator running at %s? %w", *addr, err)
	}

	fmt.Fprintf(stdout, "pairing code: %s   (valid for %s, single use)\n\n", resp.Code, ttl.Round(time.Second))
	fmt.Fprintf(stdout, "on the new node, run:\n")
	fmt.Fprintf(stdout, "  meshctl join --code %s\n", resp.Code)
	fmt.Fprintf(stdout, "or, if mDNS does not reach it:\n")
	fmt.Fprintf(stdout, "  meshctl join --code %s --coordinator %s\n", resp.Code, resp.PairAddr)
	return nil
}

// ---- join -------------------------------------------------------------------

func cmdJoin(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("meshctl join", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", defaultDataDir(), "state directory")
	code := fs.String("code", "", "8-digit code from `meshctl pair`")
	coordAddr := fs.String("coordinator", "", "pairing address host:port (default: discover over mDNS)")
	nodeIDFlag := fs.String("node-id", "", "name for this node (default: <hostname>-<random>)")
	force := fs.Bool("force", false, "replace an existing identity in data-dir")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := pki.ValidateCodeFormat(*code); err != nil {
		return fmt.Errorf("--code: %w", err)
	}
	if _, err := os.Stat(filepath.Join(*dataDir, pki.NodeKeyFile)); err == nil && !*force {
		return fmt.Errorf("%s already has a node identity; use --force to re-pair", *dataDir)
	}

	nodeID, err := resolveNodeID(*dataDir, *nodeIDFlag, *force)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	addr := *coordAddr
	if addr == "" {
		fmt.Fprintf(stdout, "looking for a coordinator on the local network...\n")
		addr, err = discoverCoordinator(ctx, nodeID)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "found coordinator at %s\n", addr)
	}

	res, err := pairing.Join(ctx, addr, *code, nodeID, nil)
	if err != nil {
		return err
	}
	if err := res.Persist(*dataDir, *force); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "joined mesh %q as %s\n", res.Bundle.MeshID, nodeID)
	fmt.Fprintf(stdout, "  coordinator     %s (%s)\n", res.CoordinatorNodeID, res.CoordinatorGRPCAddr)
	fmt.Fprintf(stdout, "  CA fingerprint  %s\n", pki.Fingerprint(res.Bundle.CACert))
	fmt.Fprintf(stdout, "  node cert       expires %s\n", res.Bundle.NodeCert.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(stdout, "\nstart the node:  meshd\n")
	return nil
}

// resolveNodeID applies --node-id if given, else loads or generates one.
func resolveNodeID(dataDir, flagValue string, overwrite bool) (string, error) {
	if flagValue != "" {
		if err := identity.Set(dataDir, flagValue, overwrite); err != nil {
			return "", err
		}
	}
	return identity.LoadOrCreate(dataDir)
}

// discoverCoordinator browses mDNS for any mesh's coordinator. Before
// pairing we have no mesh_id, so we browse with a wildcard and pick the first
// peer advertising a pair_port. The code, not the discovery, authenticates.
func discoverCoordinator(ctx context.Context, nodeID string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, discoverTimeout)
	defer cancel()
	md, err := discovery.NewMDNS(discovery.MDNSConfig{
		Advertisement: discovery.Advertisement{NodeID: nodeID, MeshID: discovery.AnyMesh, GRPCPort: 1},
		BrowseOnly:    true,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return "", err
	}
	if err := md.Start(ctx); err != nil {
		return "", err
	}
	defer md.Stop()
	for {
		select {
		case ev := <-md.Events():
			if ev.Kind == discovery.PeerAdded && ev.Peer.IsCoordinator() {
				return ev.Peer.PairAddr(), nil
			}
		case <-ctx.Done():
			return "", errors.New("no coordinator found over mDNS; pass --coordinator host:port from `meshctl pair`")
		}
	}
}
