package discovery

import (
	"net"
)

// DefaultInterfaces returns the NICs worth doing mDNS on: up, multicast-capable,
// not loopback, not point-to-point (VPN tunnels like utun*/wg* on macOS and
// Linux), and carrying at least one unicast address. Announcing on every
// interface, which is zeroconf's default, is unreliable on laptops with a
// dozen tunnel interfaces and leaks the advertisement onto VPNs.
func DefaultInterfaces() ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []net.Interface
	for _, ifi := range all {
		if !usable(ifi) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		out = append(out, ifi)
	}
	return out, nil
}

func usable(ifi net.Interface) bool {
	const want = net.FlagUp | net.FlagMulticast
	const reject = net.FlagLoopback | net.FlagPointToPoint
	return ifi.Flags&want == want && ifi.Flags&reject == 0
}

// LoopbackInterface returns the loopback NIC, for hermetic tests that must not
// put packets on the LAN. Returns nil if none is multicast-capable.
func LoopbackInterface() *net.Interface {
	all, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range all {
		if ifi.Flags&net.FlagLoopback != 0 && ifi.Flags&net.FlagMulticast != 0 && ifi.Flags&net.FlagUp != 0 {
			return &ifi
		}
	}
	return nil
}
