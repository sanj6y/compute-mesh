// Package discovery finds other meshd instances. v1 is mDNS/DNS-SD on the
// local broadcast domain (this file + mdns.go); static seeds and memberlist
// gossip are added in later steps and feed the same Peer type.
package discovery

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ServiceType is the DNS-SD service every meshd advertises.
const ServiceType = "_lcm._tcp"

// Domain is the mDNS domain. Always "local." for link-local discovery.
const Domain = "local."

// TXT record keys. Kept short: the whole TXT record must fit in one 255-byte
// string per key/value pair and ideally the entire packet stays under 1500 B.
const (
	txtNodeID      = "node_id"
	txtMeshID      = "mesh_id"
	txtGRPCPort    = "grpc_port"
	txtPairPort    = "pair_port"
	txtFingerprint = "fingerprint"
)

var (
	ErrMissingNodeID   = errors.New("discovery: TXT record missing node_id")
	ErrMissingMeshID   = errors.New("discovery: TXT record missing mesh_id")
	ErrMissingGRPCPort = errors.New("discovery: TXT record missing grpc_port")
	ErrBadGRPCPort     = errors.New("discovery: TXT record grpc_port is not a valid port")
)

// Advertisement is what this node publishes about itself.
type Advertisement struct {
	NodeID string
	MeshID string
	// GRPCPort is the port the NodeService / InferenceService listener is bound to.
	GRPCPort int
	// PairPort is the PairingService listener. Only the coordinator sets it;
	// `meshctl join` uses it to find the coordinator without a flag.
	PairPort int
	// Fingerprint is the SHA-256 of the node's leaf certificate (hex). Empty
	// until the node has paired. Peers use it to detect a cert change for a
	// known node_id before they even dial.
	Fingerprint string
}

// TXT renders the advertisement as DNS-SD TXT key=value strings.
func (a Advertisement) TXT() []string {
	txt := []string{
		txtNodeID + "=" + a.NodeID,
		txtMeshID + "=" + a.MeshID,
		txtGRPCPort + "=" + strconv.Itoa(a.GRPCPort),
	}
	if a.PairPort > 0 {
		txt = append(txt, txtPairPort+"="+strconv.Itoa(a.PairPort))
	}
	if a.Fingerprint != "" {
		txt = append(txt, txtFingerprint+"="+a.Fingerprint)
	}
	return txt
}

// Peer is another meshd we have seen on the network.
type Peer struct {
	NodeID      string
	MeshID      string
	Fingerprint string
	Hostname    string
	Addrs       []net.IP
	GRPCPort    int
	PairPort    int // 0 unless the peer is a coordinator
	LastSeen    time.Time
}

// IsCoordinator reports whether the peer advertises a pairing listener.
func (p Peer) IsCoordinator() bool { return p.PairPort > 0 }

// PairAddr returns host:port of the peer's pairing listener, or "".
func (p Peer) PairAddr() string {
	if p.PairPort == 0 {
		return ""
	}
	return hostPort(p.Addrs, p.PairPort)
}

// GRPCAddr returns the first usable host:port to dial, preferring IPv4.
// Returns "" if the peer advertised no addresses.
func (p Peer) GRPCAddr() string { return hostPort(p.Addrs, p.GRPCPort) }

func hostPort(addrs []net.IP, port int) string {
	for _, ip := range addrs {
		if ip.To4() != nil {
			return net.JoinHostPort(ip.String(), strconv.Itoa(port))
		}
	}
	for _, ip := range addrs {
		return net.JoinHostPort(ip.String(), strconv.Itoa(port))
	}
	return ""
}

// ParseTXT decodes a DNS-SD TXT record into the identity fields of a Peer.
// Unknown keys are ignored so newer nodes can add fields without breaking
// older ones. Hostname/Addrs/LastSeen are filled in by the browser.
func ParseTXT(txt []string) (Peer, error) {
	kv := make(map[string]string, len(txt))
	for _, s := range txt {
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			continue // boolean-style TXT attribute; none defined
		}
		if _, dup := kv[k]; !dup {
			kv[k] = v // RFC 6763 §6.4: first occurrence wins
		}
	}

	p := Peer{
		NodeID:      kv[txtNodeID],
		MeshID:      kv[txtMeshID],
		Fingerprint: kv[txtFingerprint],
	}
	if p.NodeID == "" {
		return Peer{}, ErrMissingNodeID
	}
	if p.MeshID == "" {
		return Peer{}, ErrMissingMeshID
	}
	ps, ok := kv[txtGRPCPort]
	if !ok || ps == "" {
		return Peer{}, ErrMissingGRPCPort
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 {
		return Peer{}, fmt.Errorf("%w: %q", ErrBadGRPCPort, ps)
	}
	p.GRPCPort = port
	if ps, ok := kv[txtPairPort]; ok && ps != "" {
		pp, err := strconv.Atoi(ps)
		if err != nil || pp < 1 || pp > 65535 {
			return Peer{}, fmt.Errorf("%w: pair_port %q", ErrBadGRPCPort, ps)
		}
		p.PairPort = pp
	}
	return p, nil
}
