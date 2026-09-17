package discovery

import (
	"errors"
	"net"
	"reflect"
	"testing"
)

func TestAdvertisementTXT(t *testing.T) {
	tests := []struct {
		name string
		ad   Advertisement
		want []string
	}{
		{
			name: "unpaired node omits fingerprint",
			ad:   Advertisement{NodeID: "n1", MeshID: "home", GRPCPort: 7443},
			want: []string{"node_id=n1", "mesh_id=home", "grpc_port=7443"},
		},
		{
			name: "paired node includes fingerprint",
			ad:   Advertisement{NodeID: "n1", MeshID: "home", GRPCPort: 7443, Fingerprint: "abc123"},
			want: []string{"node_id=n1", "mesh_id=home", "grpc_port=7443", "fingerprint=abc123"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ad.TXT(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TXT() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTXT(t *testing.T) {
	tests := []struct {
		name    string
		txt     []string
		want    Peer
		wantErr error
	}{
		{
			name: "full record",
			txt:  []string{"node_id=n1", "mesh_id=home", "grpc_port=7443", "fingerprint=abc"},
			want: Peer{NodeID: "n1", MeshID: "home", GRPCPort: 7443, Fingerprint: "abc"},
		},
		{
			name: "round trip",
			txt:  Advertisement{NodeID: "n2", MeshID: "m", GRPCPort: 1, Fingerprint: "ff"}.TXT(),
			want: Peer{NodeID: "n2", MeshID: "m", GRPCPort: 1, Fingerprint: "ff"},
		},
		{
			name: "unknown keys and boolean attributes ignored",
			txt:  []string{"node_id=n1", "mesh_id=home", "grpc_port=7443", "future_key=x", "flag"},
			want: Peer{NodeID: "n1", MeshID: "home", GRPCPort: 7443},
		},
		{
			name: "first occurrence wins per RFC 6763",
			txt:  []string{"node_id=n1", "node_id=evil", "mesh_id=home", "grpc_port=7443"},
			want: Peer{NodeID: "n1", MeshID: "home", GRPCPort: 7443},
		},
		{
			name: "value containing equals sign",
			txt:  []string{"node_id=n1", "mesh_id=a=b", "grpc_port=7443"},
			want: Peer{NodeID: "n1", MeshID: "a=b", GRPCPort: 7443},
		},
		{
			name:    "missing node_id",
			txt:     []string{"mesh_id=home", "grpc_port=7443"},
			wantErr: ErrMissingNodeID,
		},
		{
			name:    "empty node_id",
			txt:     []string{"node_id=", "mesh_id=home", "grpc_port=7443"},
			wantErr: ErrMissingNodeID,
		},
		{
			name:    "missing mesh_id",
			txt:     []string{"node_id=n1", "grpc_port=7443"},
			wantErr: ErrMissingMeshID,
		},
		{
			name:    "missing grpc_port",
			txt:     []string{"node_id=n1", "mesh_id=home"},
			wantErr: ErrMissingGRPCPort,
		},
		{
			name:    "non-numeric port",
			txt:     []string{"node_id=n1", "mesh_id=home", "grpc_port=abc"},
			wantErr: ErrBadGRPCPort,
		},
		{
			name:    "port zero",
			txt:     []string{"node_id=n1", "mesh_id=home", "grpc_port=0"},
			wantErr: ErrBadGRPCPort,
		},
		{
			name:    "port too large",
			txt:     []string{"node_id=n1", "mesh_id=home", "grpc_port=70000"},
			wantErr: ErrBadGRPCPort,
		},
		{
			name:    "empty record",
			txt:     nil,
			wantErr: ErrMissingNodeID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTXT(tt.txt)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseTXT() err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTXT() unexpected err: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTXT() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPeerGRPCAddr(t *testing.T) {
	tests := []struct {
		name string
		peer Peer
		want string
	}{
		{"no addrs", Peer{GRPCPort: 7443}, ""},
		{"ipv4 only", Peer{GRPCPort: 7443, Addrs: []net.IP{net.ParseIP("10.0.0.5")}}, "10.0.0.5:7443"},
		{"ipv6 only", Peer{GRPCPort: 7443, Addrs: []net.IP{net.ParseIP("fe80::1")}}, "[fe80::1]:7443"},
		{
			name: "prefers ipv4 even if listed second",
			peer: Peer{GRPCPort: 7443, Addrs: []net.IP{net.ParseIP("fe80::1"), net.ParseIP("10.0.0.5")}},
			want: "10.0.0.5:7443",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.peer.GRPCAddr(); got != tt.want {
				t.Errorf("GRPCAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPeerChanged(t *testing.T) {
	base := Peer{NodeID: "n1", GRPCPort: 7443, Fingerprint: "aa", Hostname: "h.local.", Addrs: []net.IP{net.ParseIP("10.0.0.5")}}
	with := func(f func(*Peer)) Peer { p := base; p.Addrs = append([]net.IP{}, base.Addrs...); f(&p); return p }

	tests := []struct {
		name string
		b    Peer
		want bool
	}{
		{"identical", base, false},
		{"last_seen only", with(func(p *Peer) { p.LastSeen = p.LastSeen.Add(1) }), false},
		{"same addrs different order", with(func(p *Peer) {
			p.Addrs = []net.IP{net.ParseIP("10.0.0.5")}
		}), false},
		{"port", with(func(p *Peer) { p.GRPCPort = 1 }), true},
		{"fingerprint rotated", with(func(p *Peer) { p.Fingerprint = "bb" }), true},
		{"hostname", with(func(p *Peer) { p.Hostname = "x.local." }), true},
		{"addr added", with(func(p *Peer) { p.Addrs = append(p.Addrs, net.ParseIP("10.0.0.6")) }), true},
		{"addr replaced", with(func(p *Peer) { p.Addrs = []net.IP{net.ParseIP("10.0.0.6")} }), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerChanged(base, tt.b); got != tt.want {
				t.Errorf("peerChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}
