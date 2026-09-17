package discovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

// EventKind says what changed about a peer.
type EventKind int

const (
	// PeerAdded fires the first time a node_id is seen.
	PeerAdded EventKind = iota
	// PeerUpdated fires when a known node_id re-announces with different
	// addresses, port, or fingerprint.
	PeerUpdated
	// PeerExpired fires when a peer has not been heard from for ExpireAfter.
	// memberlist will own liveness later; this is a coarse fallback so a
	// laptop that walks off the LAN eventually leaves the peer list.
	PeerExpired
)

func (k EventKind) String() string {
	switch k {
	case PeerAdded:
		return "added"
	case PeerUpdated:
		return "updated"
	case PeerExpired:
		return "expired"
	}
	return fmt.Sprintf("EventKind(%d)", int(k))
}

// PeerEvent is delivered on MDNS.Events.
type PeerEvent struct {
	Kind EventKind
	Peer Peer
}

// MDNSConfig configures an MDNS instance. Zero values are filled by defaults.
type MDNSConfig struct {
	Advertisement Advertisement
	// Interfaces restricts multicast to these NICs. nil = DefaultInterfaces().
	Interfaces []net.Interface
	// ExpireAfter is how long a peer may be silent before PeerExpired. Default 90 s
	// (zeroconf's default TTL is 3200 s, far too long; browse re-queries refresh
	// LastSeen well inside 90 s on a healthy LAN).
	ExpireAfter time.Duration
	// EventBuffer sizes the Events channel. Default 64. When full, events are
	// dropped (peer state is still updated; consumers should call Peers()).
	EventBuffer int
	// BrowseOnly skips advertising; used by meshctl to look for a coordinator.
	BrowseOnly bool
	Logger     *slog.Logger
}

// AnyMesh as Advertisement.MeshID disables the same-mesh filter. Only valid
// with BrowseOnly: a node must never advertise a wildcard mesh.
const AnyMesh = "*"

// MDNS advertises this node and tracks peers in the same mesh.
type MDNS struct {
	cfg    MDNSConfig
	log    *slog.Logger
	events chan PeerEvent

	mu    sync.RWMutex
	peers map[string]Peer // keyed by NodeID

	server *zeroconf.Server
	cancel context.CancelFunc
	done   chan struct{}
}

// NewMDNS validates cfg and returns an MDNS that is not yet running.
func NewMDNS(cfg MDNSConfig) (*MDNS, error) {
	if cfg.Advertisement.NodeID == "" {
		return nil, errors.New("discovery: NodeID is required")
	}
	if cfg.Advertisement.MeshID == "" {
		return nil, errors.New("discovery: MeshID is required")
	}
	if cfg.Advertisement.MeshID == AnyMesh && !cfg.BrowseOnly {
		return nil, errors.New("discovery: wildcard mesh is only allowed with BrowseOnly")
	}
	if cfg.Advertisement.GRPCPort < 1 || cfg.Advertisement.GRPCPort > 65535 {
		return nil, fmt.Errorf("discovery: GRPCPort %d out of range", cfg.Advertisement.GRPCPort)
	}
	if cfg.ExpireAfter <= 0 {
		cfg.ExpireAfter = 90 * time.Second
	}
	if cfg.EventBuffer <= 0 {
		cfg.EventBuffer = 64
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &MDNS{
		cfg:    cfg,
		log:    cfg.Logger.With("component", "discovery.mdns"),
		events: make(chan PeerEvent, cfg.EventBuffer),
		peers:  make(map[string]Peer),
		done:   make(chan struct{}),
	}, nil
}

// Start registers the service and begins browsing. It returns once the
// advertisement is live; browsing continues until Stop or ctx is done.
func (m *MDNS) Start(ctx context.Context) error {
	ad := m.cfg.Advertisement
	ifaces := m.cfg.Interfaces
	if ifaces == nil {
		var err error
		if ifaces, err = DefaultInterfaces(); err != nil {
			return fmt.Errorf("discovery: enumerate interfaces: %w", err)
		}
	}
	if len(ifaces) == 0 {
		return errors.New("discovery: no usable multicast interface")
	}
	if !m.cfg.BrowseOnly {
		srv, err := zeroconf.Register(ad.NodeID, ServiceType, Domain, ad.GRPCPort, ad.TXT(), ifaces)
		if err != nil {
			return fmt.Errorf("discovery: register mDNS service: %w", err)
		}
		m.server = srv
	}

	resolver, err := zeroconf.NewResolver(zeroconf.SelectIfaces(ifaces))
	if err != nil {
		m.Stop()
		return fmt.Errorf("discovery: create mDNS resolver: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	entries := make(chan *zeroconf.ServiceEntry, 32)
	if err := resolver.Browse(ctx, ServiceType, Domain, entries); err != nil {
		cancel()
		m.Stop()
		return fmt.Errorf("discovery: browse: %w", err)
	}

	m.cancel = cancel
	go m.loop(ctx, entries)
	names := make([]string, len(ifaces))
	for i, ifi := range ifaces {
		names[i] = ifi.Name
	}
	if m.cfg.BrowseOnly {
		m.log.Debug("browsing", "service", ServiceType+"."+Domain, "ifaces", names)
	} else {
		m.log.Info("advertising", "service", ServiceType+"."+Domain, "node_id", ad.NodeID, "mesh_id", ad.MeshID, "grpc_port", ad.GRPCPort, "pair_port", ad.PairPort, "ifaces", names)
	}
	return nil
}

// Stop withdraws the advertisement (sends goodbye packets) and stops browsing.
// Safe to call more than once.
func (m *MDNS) Stop() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel = nil
	}
	if m.server != nil {
		m.server.Shutdown()
		m.server = nil
	}
}

// Events returns the peer event stream. The channel is never closed.
func (m *MDNS) Events() <-chan PeerEvent { return m.events }

// Peers returns a snapshot of known peers sorted by NodeID.
func (m *MDNS) Peers() []Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Peer, 0, len(m.peers))
	for _, p := range m.peers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// SetFingerprint updates the advertised cert fingerprint in place, e.g. after
// pairing completes or a cert rotates, without re-registering the service.
func (m *MDNS) SetFingerprint(fp string) {
	m.cfg.Advertisement.Fingerprint = fp
	if m.server != nil {
		m.server.SetText(m.cfg.Advertisement.TXT())
	}
}

func (m *MDNS) loop(ctx context.Context, entries <-chan *zeroconf.ServiceEntry) {
	defer close(m.done)
	sweep := time.NewTicker(m.cfg.ExpireAfter / 3)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-entries:
			if !ok {
				return
			}
			m.handleEntry(e, time.Now())
		case now := <-sweep.C:
			m.expire(now)
		}
	}
}

// handleEntry applies one browse result. Exported for tests via mdns_export_test.
func (m *MDNS) handleEntry(e *zeroconf.ServiceEntry, now time.Time) {
	p, err := ParseTXT(e.Text)
	if err != nil {
		m.log.Debug("ignoring service with bad TXT", "instance", e.Instance, "err", err)
		return
	}
	ad := m.cfg.Advertisement
	if p.NodeID == ad.NodeID {
		return // our own announcement
	}
	if ad.MeshID != AnyMesh && p.MeshID != ad.MeshID {
		m.log.Debug("ignoring peer from foreign mesh", "peer", p.NodeID, "peer_mesh_id", p.MeshID)
		return
	}
	// Prefer the SRV port; TXT grpc_port is the fallback when a proxy/relay
	// advertises on behalf of a node.
	if e.Port > 0 {
		p.GRPCPort = e.Port
	}
	p.Hostname = normalizeHost(e.HostName)
	p.Addrs = append(append([]net.IP{}, e.AddrIPv4...), e.AddrIPv6...)
	p.LastSeen = now

	m.mu.Lock()
	prev, known := m.peers[p.NodeID]
	m.peers[p.NodeID] = p
	m.mu.Unlock()

	switch {
	case !known:
		m.log.Info("peer added", "peer", p.NodeID, "addr", p.GRPCAddr(), "host", p.Hostname, "coordinator", p.IsCoordinator(), "fingerprint", short(p.Fingerprint))
		m.emit(PeerEvent{Kind: PeerAdded, Peer: p})
	case peerChanged(prev, p):
		m.log.Info("peer updated", "peer", p.NodeID, "addr", p.GRPCAddr(), "fingerprint", short(p.Fingerprint))
		m.emit(PeerEvent{Kind: PeerUpdated, Peer: p})
	}
}

func (m *MDNS) expire(now time.Time) {
	var expired []Peer
	m.mu.Lock()
	for id, p := range m.peers {
		if now.Sub(p.LastSeen) > m.cfg.ExpireAfter {
			delete(m.peers, id)
			expired = append(expired, p)
		}
	}
	m.mu.Unlock()
	for _, p := range expired {
		m.log.Info("peer expired", "peer", p.NodeID, "last_seen", p.LastSeen)
		m.emit(PeerEvent{Kind: PeerExpired, Peer: p})
	}
}

func (m *MDNS) emit(ev PeerEvent) {
	select {
	case m.events <- ev:
	default:
		m.log.Warn("event channel full, dropping", "kind", ev.Kind, "peer", ev.Peer.NodeID)
	}
}

// peerChanged reports whether anything a dialer cares about differs.
func peerChanged(a, b Peer) bool {
	if a.GRPCPort != b.GRPCPort || a.PairPort != b.PairPort || a.Fingerprint != b.Fingerprint || a.Hostname != b.Hostname {
		return true
	}
	if len(a.Addrs) != len(b.Addrs) {
		return true
	}
	seen := make(map[string]bool, len(a.Addrs))
	for _, ip := range a.Addrs {
		seen[ip.String()] = true
	}
	for _, ip := range b.Addrs {
		if !seen[ip.String()] {
			return true
		}
	}
	return false
}

func short(fp string) string {
	if len(fp) > 12 {
		return fp[:12]
	}
	return fp
}

// normalizeHost works around grandcat/zeroconf appending the domain twice
// ("host.local.local.") and strips the trailing dot.
func normalizeHost(h string) string {
	h = strings.TrimSuffix(h, ".")
	for strings.HasSuffix(h, ".local.local") {
		h = strings.TrimSuffix(h, ".local")
	}
	return h
}
