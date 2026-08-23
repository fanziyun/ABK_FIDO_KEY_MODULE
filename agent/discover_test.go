package main

import (
	"net"
	"testing"
)

// A probe sent only to 255.255.255.255 leaves through one routing-table-chosen
// interface, so discovery has to derive each interface's own broadcast address.
func TestDirectedBroadcast(t *testing.T) {
	cases := []struct {
		name    string
		network *net.IPNet
		want    string
	}{
		{
			name:    "wifi /24",
			network: &net.IPNet{IP: net.ParseIP("192.168.31.42"), Mask: net.CIDRMask(24, 32)},
			want:    "192.168.31.255",
		},
		{
			name:    "hyper-v switch /20",
			network: &net.IPNet{IP: net.ParseIP("172.28.16.1"), Mask: net.CIDRMask(20, 32)},
			want:    "172.28.31.255",
		},
		{
			name:    "sixteen byte mask",
			network: &net.IPNet{IP: net.ParseIP("10.1.2.3"), Mask: net.IPMask(net.ParseIP("255.255.0.0"))},
			want:    "10.1.255.255",
		},
		{
			name:    "point to point /32 has no broadcast",
			network: &net.IPNet{IP: net.ParseIP("10.8.0.2"), Mask: net.CIDRMask(32, 32)},
			want:    "",
		},
		{
			name:    "ipv6 is skipped",
			network: &net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
			want:    "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := directedBroadcast(c.network)
			if c.want == "" {
				if got != nil {
					t.Fatalf("directedBroadcast = %v, want nil", got)
				}
				return
			}
			if got == nil || got.String() != c.want {
				t.Fatalf("directedBroadcast = %v, want %s", got, c.want)
			}
		})
	}
}

func TestBroadcastTargets(t *testing.T) {
	targets := broadcastTargets()
	if len(targets) == 0 {
		t.Fatal("no discovery targets")
	}
	if !targets[0].IP.Equal(net.IPv4bcast) {
		t.Fatalf("first target = %v, want %v", targets[0].IP, net.IPv4bcast)
	}
	seen := map[string]bool{}
	for _, target := range targets {
		if target.Port != discoveryPort {
			t.Fatalf("target %v port = %d, want %d", target.IP, target.Port, discoveryPort)
		}
		if target.IP.To4() == nil {
			t.Fatalf("target %v is not IPv4", target.IP)
		}
		// A duplicate target would send the same probe twice and, on Windows,
		// double the number of firewall decisions for no benefit.
		if seen[target.IP.String()] {
			t.Fatalf("duplicate target %v", target.IP)
		}
		seen[target.IP.String()] = true
	}
}
