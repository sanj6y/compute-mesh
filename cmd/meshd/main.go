// meshd is the Local Compute Mesh daemon. Every node runs it as a worker;
// --coordinator additionally enables the admin API and pairing listener.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/sanj6y/compute-mesh/internal/coordinator"
	"github.com/sanj6y/compute-mesh/internal/discovery"
	"github.com/sanj6y/compute-mesh/internal/pairing"
	"github.com/sanj6y/compute-mesh/internal/pki"
	"github.com/sanj6y/compute-mesh/internal/transport"
	lcmv1 "github.com/sanj6y/compute-mesh/proto/lcm/v1"
)

// version is set by the linker (see Makefile LDFLAGS).
var version = "dev"

const (
	defaultGRPCPort = 7443
	defaultPairPort = 7444
)

type config struct {
	dataDir       string
	grpcPort      int
	pairPort      int
	coordinator   bool
	advertiseHost string
	ifaces        string
	logLevel      string
	logFormat     string
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "meshd:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr *os.File) error {
	var cfg config
	fs := flag.NewFlagSet("meshd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.dataDir, "data-dir", defaultDataDir(), "state directory (node_id, certs)")
	fs.IntVar(&cfg.grpcPort, "grpc-port", defaultGRPCPort, "port for the mTLS gRPC listener")
	fs.IntVar(&cfg.pairPort, "pair-port", defaultPairPort, "port for the pairing listener (coordinator only)")
	fs.BoolVar(&cfg.coordinator, "coordinator", false, "run the coordinator role (admin API, pairing)")
	fs.StringVar(&cfg.advertiseHost, "advertise-host", "", "host other nodes should dial (default: first LAN IPv4)")
	fs.StringVar(&cfg.ifaces, "ifaces", "", "comma-separated interfaces for mDNS (default: all up, multicast, non-tunnel)")
	fs.StringVar(&cfg.logLevel, "log-level", "info", "debug|info|warn|error")
	fs.StringVar(&cfg.logFormat, "log-format", "json", "json|text")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintln(stdout, "meshd", version)
		return nil
	}

	log, err := newLogger(stderr, cfg.logLevel, cfg.logFormat)
	if err != nil {
		return err
	}

	// Identity is mandatory: mesh_id and node_id come from the cert, so an
	// unpaired node cannot even advertise.
	id, err := transport.LoadNodeIdentity(cfg.dataDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no node identity in %s: run `meshctl init` (first node) or `meshctl join --code ...`", cfg.dataDir)
		}
		return err
	}
	nodeID, meshID := id.Principal.Name, id.MeshID()
	log = log.With("node_id", nodeID)

	ifaces, err := parseIfaces(cfg.ifaces)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- mTLS control plane -------------------------------------------------
	lis, err := net.Listen("tcp", ":"+strconv.Itoa(cfg.grpcPort))
	if err != nil {
		return fmt.Errorf("listen grpc port: %w", err)
	}
	var serverOpts []grpc.ServerOption
	var pairSrv *pairing.Server
	if cfg.coordinator {
		u, s := coordinator.AdminInterceptors()
		serverOpts = append(serverOpts, grpc.ChainUnaryInterceptor(u), grpc.ChainStreamInterceptor(s))
	}
	srv := id.NewServer(serverOpts...)
	grpc_health_v1.RegisterHealthServer(srv, health.NewServer())

	// --- coordinator role ---------------------------------------------------
	pairPort := 0
	if cfg.coordinator {
		ca, err := pki.ReadCA(cfg.dataDir)
		if err != nil {
			return fmt.Errorf("coordinator needs the mesh CA in %s (created by `meshctl init`): %w", cfg.dataDir, err)
		}
		pairSrv, err = pairing.NewServer(pairing.ServerConfig{Identity: id, CA: ca, GRPCPort: cfg.grpcPort, Logger: log})
		if err != nil {
			return err
		}
		pairLis, err := net.Listen("tcp", ":"+strconv.Itoa(cfg.pairPort))
		if err != nil {
			return fmt.Errorf("listen pair port: %w", err)
		}
		pairPort = cfg.pairPort
		host := cfg.advertiseHost
		if host == "" {
			host = lanIPv4()
		}
		pairAddr := net.JoinHostPort(host, strconv.Itoa(cfg.pairPort))
		lcmv1.RegisterAdminServiceServer(srv, coordinator.NewAdmin(pairSrv.Pairer(), pairAddr, log))
		go func() {
			if err := pairSrv.Serve(pairLis); err != nil {
				log.Error("pairing listener stopped", "err", err)
			}
		}()
		defer pairSrv.Stop()
		log.Info("coordinator role enabled", "pair_addr", pairAddr)
	}

	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Error("grpc server stopped", "err", err)
		}
	}()
	defer srv.Stop()

	// --- discovery ----------------------------------------------------------
	md, err := discovery.NewMDNS(discovery.MDNSConfig{
		Advertisement: discovery.Advertisement{
			NodeID:      nodeID,
			MeshID:      meshID,
			GRPCPort:    cfg.grpcPort,
			PairPort:    pairPort,
			Fingerprint: id.Fingerprint(),
		},
		Interfaces: ifaces,
		Logger:     log,
	})
	if err != nil {
		return err
	}
	if err := md.Start(ctx); err != nil {
		return err
	}
	defer md.Stop()

	log.Info("meshd started",
		"version", version,
		"mesh_id", meshID,
		"grpc_addr", lis.Addr().String(),
		"coordinator", cfg.coordinator,
		"cert_expires", id.Cert.NotAfter,
		"data_dir", cfg.dataDir,
	)

	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down", "peers", len(md.Peers()))
			return nil
		case ev := <-md.Events():
			// discovery logs each event; the registry / memberlist join hooks in here.
			log.Debug("peer event", "kind", ev.Kind.String(), "peer", ev.Peer.NodeID, "addr", ev.Peer.GRPCAddr())
		}
	}
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

func newLogger(w *os.File, level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("bad --log-level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("bad --log-format %q", format)
}

// parseIfaces resolves "en0,en1" to interfaces. Empty means library default.
func parseIfaces(s string) ([]net.Interface, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []net.Interface
	for _, name := range strings.Split(s, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("--ifaces: %w", err)
		}
		out = append(out, *ifi)
	}
	if len(out) == 0 {
		return nil, errors.New("--ifaces: no interfaces given")
	}
	return out, nil
}

// lanIPv4 picks the first IPv4 on a discovery-eligible interface, for
// printing a dialable pairing address. Falls back to 127.0.0.1.
func lanIPv4() string {
	ifaces, err := discovery.DefaultInterfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, ifi := range ifaces {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				return ipn.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
