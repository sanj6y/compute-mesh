package discovery

import (
	"net"
	"testing"
)

func TestUsable(t *testing.T) {
	tests := []struct {
		name  string
		flags net.Flags
		want  bool
	}{
		{"ethernet up", net.FlagUp | net.FlagBroadcast | net.FlagMulticast | net.FlagRunning, true},
		{"down", net.FlagBroadcast | net.FlagMulticast, false},
		{"no multicast", net.FlagUp | net.FlagBroadcast, false},
		{"loopback", net.FlagUp | net.FlagLoopback | net.FlagMulticast, false},
		{"vpn tunnel", net.FlagUp | net.FlagPointToPoint | net.FlagMulticast, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := usable(net.Interface{Flags: tt.flags}); got != tt.want {
				t.Errorf("usable(%v) = %v, want %v", tt.flags, got, tt.want)
			}
		})
	}
}

func TestDefaultInterfacesExcludesLoopbackAndTunnels(t *testing.T) {
	ifaces, err := DefaultInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			t.Errorf("DefaultInterfaces returned %s with flags %v", ifi.Name, ifi.Flags)
		}
		if ifi.Flags&net.FlagUp == 0 {
			t.Errorf("DefaultInterfaces returned down interface %s", ifi.Name)
		}
	}
}
