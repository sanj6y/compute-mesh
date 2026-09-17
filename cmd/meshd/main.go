// meshd is the Local Compute Mesh daemon. Every node runs it as a worker;
// the coordinator and gateway are roles enabled by flags on one of them.
//
// Weekend-1 step 1: start, advertise on mDNS, browse for peers, log them.
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

	"github.com/sanj6y/compute-mesh/internal/discovery"
	"github.com/sanj6y/compute-mesh/internal/identity"
)

// version is set by the linker (see Makefile LDFLAGS).
var version = "dev"

const defaultGRPCPort = 7443

type config struct {
	dataDir   string
	nodeID    string
	meshID    string
	grpcPort  int
	ifaces    string
	logLevel  string
	logFormat string
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
	fs.StringVar(&cfg.nodeID, "node-id", "", "override the persisted node id (testing only)")
	fs.StringVar(&cfg.meshID, "mesh-id", "default", "mesh this node belongs to; replaced by the CA's mesh id after pairing")
	fs.IntVar(&cfg.grpcPort, "grpc-port", defaultGRPCPort, "port for the mTLS gRPC listener")
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

	nodeID := cfg.nodeID
	if nodeID == "" {
		if nodeID, err = identity.LoadOrCreate(cfg.dataDir); err != nil {
			return err
		}
	} else if err := identity.Validate(nodeID); err != nil {
		return err
	}
	log = log.With("node_id", nodeID)

	ifaces, err := parseIfaces(cfg.ifaces)
	if err != nil {
		return err
	}

	// Bind the gRPC port now so a conflict fails fast and the advertised port
	// is real. The mTLS gRPC server attaches to this listener in step 3.
	lis, err := net.Listen("tcp", ":"+strconv.Itoa(cfg.grpcPort))
	if err != nil {
		return fmt.Errorf("listen grpc port: %w", err)
	}
	defer lis.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	md, err := discovery.NewMDNS(discovery.MDNSConfig{
		Advertisement: discovery.Advertisement{
			NodeID:   nodeID,
			MeshID:   cfg.meshID,
			GRPCPort: cfg.grpcPort,
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

	log.Info("meshd started", "version", version, "mesh_id", cfg.meshID, "grpc_addr", lis.Addr().String(), "data_dir", cfg.dataDir)

	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down", "peers", len(md.Peers()))
			return nil
		case ev := <-md.Events():
			// discovery already logs each event; this is where the registry
			// and memberlist join will hook in.
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
