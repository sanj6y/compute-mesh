package discovery

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/grandcat/zeroconf"
)

func newTestMDNS(t *testing.T, ad Advertisement) *MDNS {
	t.Helper()
	m, err := NewMDNS(MDNSConfig{
		Advertisement: ad,
		Interfaces:    testInterfaces(t),
		ExpireAfter:   time.Minute,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// testInterfaces prefers loopback so tests put no mDNS traffic on the LAN and
// are immune to VPN tunnel interfaces on developer machines. Linux's lo is not
// multicast-capable, so CI falls back to the daemon's default selection.
func testInterfaces(t *testing.T) []net.Interface {
	t.Helper()
	if lo := LoopbackInterface(); lo != nil {
		return []net.Interface{*lo}
	}
	ifaces, err := DefaultInterfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("no multicast-capable interface available")
	}
	return ifaces
}

func entry(nodeID, meshID string, port int, ips ...string) *zeroconf.ServiceEntry {
	e := zeroconf.NewServiceEntry(nodeID, ServiceType, Domain)
	e.HostName = nodeID + ".local.local." // reproduces grandcat's doubled-domain bug
	e.Port = port
	e.Text = Advertisement{NodeID: nodeID, MeshID: meshID, GRPCPort: port}.TXT()
	for _, s := range ips {
		e.AddrIPv4 = append(e.AddrIPv4, net.ParseIP(s))
	}
	return e
}

func drain(m *MDNS) []PeerEvent {
	var out []PeerEvent
	for {
		select {
		case ev := <-m.Events():
			out = append(out, ev)
		default:
			return out
		}
	}
}

func TestNewMDNSValidation(t *testing.T) {
	tests := []struct {
		name    string
		ad      Advertisement
		wantErr bool
	}{
		{"valid", Advertisement{NodeID: "n", MeshID: "m", GRPCPort: 7443}, false},
		{"missing node id", Advertisement{MeshID: "m", GRPCPort: 7443}, true},
		{"missing mesh id", Advertisement{NodeID: "n", GRPCPort: 7443}, true},
		{"port zero", Advertisement{NodeID: "n", MeshID: "m"}, true},
		{"port too big", Advertisement{NodeID: "n", MeshID: "m", GRPCPort: 65536}, true},
		{"wildcard mesh without browse-only", Advertisement{NodeID: "n", MeshID: AnyMesh, GRPCPort: 1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMDNS(MDNSConfig{Advertisement: tt.ad})
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMDNS() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandleEntry(t *testing.T) {
	self := Advertisement{NodeID: "self", MeshID: "home", GRPCPort: 7443}
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name       string
		entries    []*zeroconf.ServiceEntry
		wantPeers  []string
		wantEvents []EventKind
	}{
		{
			name:       "own announcement ignored",
			entries:    []*zeroconf.ServiceEntry{entry("self", "home", 7443, "10.0.0.1")},
			wantPeers:  nil,
			wantEvents: nil,
		},
		{
			name:       "foreign mesh ignored",
			entries:    []*zeroconf.ServiceEntry{entry("other", "work", 7443, "10.0.0.2")},
			wantPeers:  nil,
			wantEvents: nil,
		},
		{
			name: "bad TXT ignored",
			entries: func() []*zeroconf.ServiceEntry {
				e := entry("broken", "home", 7443, "10.0.0.2")
				e.Text = []string{"garbage"}
				return []*zeroconf.ServiceEntry{e}
			}(),
			wantPeers:  nil,
			wantEvents: nil,
		},
		{
			name:       "new peer added",
			entries:    []*zeroconf.ServiceEntry{entry("a", "home", 7443, "10.0.0.2")},
			wantPeers:  []string{"a"},
			wantEvents: []EventKind{PeerAdded},
		},
		{
			name: "re-announce without change is silent",
			entries: []*zeroconf.ServiceEntry{
				entry("a", "home", 7443, "10.0.0.2"),
				entry("a", "home", 7443, "10.0.0.2"),
			},
			wantPeers:  []string{"a"},
			wantEvents: []EventKind{PeerAdded},
		},
		{
			name: "re-announce with new address is an update",
			entries: []*zeroconf.ServiceEntry{
				entry("a", "home", 7443, "10.0.0.2"),
				entry("a", "home", 7443, "10.0.0.9"),
			},
			wantPeers:  []string{"a"},
			wantEvents: []EventKind{PeerAdded, PeerUpdated},
		},
		{
			name: "two peers sorted by node id",
			entries: []*zeroconf.ServiceEntry{
				entry("b", "home", 7443, "10.0.0.3"),
				entry("a", "home", 7443, "10.0.0.2"),
			},
			wantPeers:  []string{"a", "b"},
			wantEvents: []EventKind{PeerAdded, PeerAdded},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestMDNS(t, self)
			for _, e := range tt.entries {
				m.handleEntry(e, now)
			}
			var ids []string
			for _, p := range m.Peers() {
				ids = append(ids, p.NodeID)
			}
			if len(ids) != len(tt.wantPeers) {
				t.Fatalf("Peers() = %v, want %v", ids, tt.wantPeers)
			}
			for i := range ids {
				if ids[i] != tt.wantPeers[i] {
					t.Errorf("Peers()[%d] = %q, want %q", i, ids[i], tt.wantPeers[i])
				}
			}
			evs := drain(m)
			if len(evs) != len(tt.wantEvents) {
				t.Fatalf("got %d events %v, want %v", len(evs), evs, tt.wantEvents)
			}
			for i, ev := range evs {
				if ev.Kind != tt.wantEvents[i] {
					t.Errorf("event[%d] = %v, want %v", i, ev.Kind, tt.wantEvents[i])
				}
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct{ in, want string }{
		{"mac.local.", "mac.local"},
		{"mac.local.local.", "mac.local"},
		{"mac.local", "mac.local"},
		{"mac", "mac"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeHost(tt.in); got != tt.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHandleEntryNormalizesHostname(t *testing.T) {
	m := newTestMDNS(t, Advertisement{NodeID: "self", MeshID: "home", GRPCPort: 1})
	m.handleEntry(entry("a", "home", 7443, "10.0.0.2"), time.Now())
	if got := m.Peers()[0].Hostname; got != "a.local" {
		t.Errorf("Hostname = %q, want %q", got, "a.local")
	}
}

func TestWildcardMeshSeesEveryMesh(t *testing.T) {
	m, err := NewMDNS(MDNSConfig{
		Advertisement: Advertisement{NodeID: "ctl", MeshID: AnyMesh, GRPCPort: 1},
		BrowseOnly:    true,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	m.handleEntry(entry("a", "home", 7443, "10.0.0.2"), time.Now())
	m.handleEntry(entry("b", "work", 7443, "10.0.0.3"), time.Now())
	if got := len(m.Peers()); got != 2 {
		t.Errorf("wildcard browser saw %d peers, want 2", got)
	}
}

func TestBrowseOnlyFindsCoordinator(t *testing.T) {
	if testing.Short() {
		t.Skip("real mDNS traffic; skipped in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	mesh := "bo-" + time.Now().Format("150405.000")
	coord := newTestMDNS(t, Advertisement{NodeID: "bo-coord", MeshID: mesh, GRPCPort: 17443, PairPort: 17444})
	if err := coord.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer coord.Stop()

	ctl, err := NewMDNS(MDNSConfig{
		Advertisement: Advertisement{NodeID: "bo-ctl", MeshID: AnyMesh, GRPCPort: 1},
		BrowseOnly:    true,
		Interfaces:    testInterfaces(t),
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ctl.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer ctl.Stop()
	for {
		select {
		case ev := <-ctl.Events():
			if ev.Kind == PeerAdded && ev.Peer.NodeID == "bo-coord" {
				if !ev.Peer.IsCoordinator() || ev.Peer.PairAddr() == "" {
					t.Fatalf("coordinator peer missing pair addr: %+v", ev.Peer)
				}
				// A browse-only instance must not have been advertised: the
				// coordinator should never see it.
				for _, p := range coord.Peers() {
					if p.NodeID == "bo-ctl" {
						t.Error("browse-only instance was advertised")
					}
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("browse-only instance never saw the coordinator")
		}
	}
}

func TestHandleEntrySRVPortOverridesTXT(t *testing.T) {
	m := newTestMDNS(t, Advertisement{NodeID: "self", MeshID: "home", GRPCPort: 1})
	e := entry("a", "home", 7443, "10.0.0.2")
	e.Port = 9000 // SRV says 9000, TXT says 7443
	m.handleEntry(e, time.Now())
	if got := m.Peers()[0].GRPCAddr(); got != "10.0.0.2:9000" {
		t.Errorf("GRPCAddr() = %q, want SRV port", got)
	}
}

func TestExpire(t *testing.T) {
	m := newTestMDNS(t, Advertisement{NodeID: "self", MeshID: "home", GRPCPort: 1})
	t0 := time.Unix(1_700_000_000, 0)
	m.handleEntry(entry("stale", "home", 7443, "10.0.0.2"), t0)
	m.handleEntry(entry("fresh", "home", 7443, "10.0.0.3"), t0.Add(50*time.Second))
	drain(m)

	m.expire(t0.Add(70 * time.Second)) // stale silent 70s > 60s, fresh silent 20s

	peers := m.Peers()
	if len(peers) != 1 || peers[0].NodeID != "fresh" {
		t.Fatalf("Peers() after expire = %+v, want only fresh", peers)
	}
	evs := drain(m)
	if len(evs) != 1 || evs[0].Kind != PeerExpired || evs[0].Peer.NodeID != "stale" {
		t.Fatalf("events = %v, want one PeerExpired for stale", evs)
	}
}

func TestEmitDropsWhenFull(t *testing.T) {
	m, err := NewMDNS(MDNSConfig{
		Advertisement: Advertisement{NodeID: "self", MeshID: "home", GRPCPort: 1},
		EventBuffer:   1,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	m.handleEntry(entry("a", "home", 7443, "10.0.0.2"), now)
	m.handleEntry(entry("b", "home", 7443, "10.0.0.3"), now) // must not block
	if got := len(m.Peers()); got != 2 {
		t.Errorf("peer state should update even when events drop; got %d peers", got)
	}
	if evs := drain(m); len(evs) != 1 {
		t.Errorf("expected 1 buffered event, got %d", len(evs))
	}
}

// TestMDNSLoopback runs two real advertisers in-process and checks each sees
// the other. Needs a multicast-capable interface; skipped with -short.
func TestMDNSLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("real mDNS traffic; skipped in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mesh := "test-" + time.Now().Format("150405.000")
	a := newTestMDNS(t, Advertisement{NodeID: "loop-a", MeshID: mesh, GRPCPort: 17443, Fingerprint: "fa"})
	b := newTestMDNS(t, Advertisement{NodeID: "loop-b", MeshID: mesh, GRPCPort: 17444, Fingerprint: "fb"})
	// Same mesh naming scheme, different mesh: must be invisible to a and b.
	c := newTestMDNS(t, Advertisement{NodeID: "loop-c", MeshID: mesh + "-other", GRPCPort: 17445})

	for _, m := range []*MDNS{a, b, c} {
		if err := m.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		defer m.Stop()
	}

	waitFor := func(m *MDNS, want string) {
		t.Helper()
		for {
			select {
			case ev := <-m.Events():
				if ev.Kind == PeerAdded && ev.Peer.NodeID == want {
					if ev.Peer.GRPCAddr() == "" {
						t.Errorf("%s saw %s with no addresses", m.cfg.Advertisement.NodeID, want)
					}
					return
				}
			case <-ctx.Done():
				t.Fatalf("%s never saw %s; peers=%+v", m.cfg.Advertisement.NodeID, want, m.Peers())
			}
		}
	}
	waitFor(a, "loop-b")
	waitFor(b, "loop-a")

	for _, p := range append(a.Peers(), b.Peers()...) {
		if p.NodeID == "loop-c" {
			t.Errorf("foreign-mesh node loop-c leaked into peer list")
		}
	}
	if p := a.Peers(); len(p) != 1 || p[0].Fingerprint != "fb" || p[0].GRPCPort != 17444 {
		t.Errorf("a.Peers() = %+v, want loop-b with fp=fb port=17444", p)
	}
}
