// The carve as the platforms follow it (tun_carve.go): one family at a time, and the IPv6 addresses a route may take
// off the host (QD-971).

package main

import (
	"net/netip"
	"slices"
	"testing"
)

// Each family of the carve holds its own addresses alone, an IPv4-mapped address as its IPv4 one and a zoned one with
// no zone, sorted with no repeats.
func TestTunCarvedAddrsTakeOneFamily(t *testing.T) {
	addresses := []netip.Addr{netip.MustParseAddr("203.0.113.53"), netip.MustParseAddr("2001:db8:ffff::53"),
		netip.MustParseAddr("::ffff:192.0.2.53"), netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("203.0.113.53"),
		netip.MustParseAddr("fe80::1%4"), netip.MustParseAddr("2001:db8::53"), netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("2001:db8:ffff::53"), {}}
	ipv4Addrs := urTunCarvedAddrs(addresses, true)
	if want := []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("203.0.113.53")}; !slices.Equal(ipv4Addrs, want) {
		t.Fatalf("IPv4's %v", ipv4Addrs)
	}
	ipv6Addrs := urTunCarvedAddrs(addresses, false)
	want := []netip.Addr{netip.MustParseAddr("2001:db8::53"), netip.MustParseAddr("2001:db8:ffff::53"),
		netip.MustParseAddr("fe80::1")}
	if !slices.Equal(ipv6Addrs, want) {
		t.Fatalf("IPv6's %v", ipv6Addrs)
	}
	if carvedAddrs := urTunCarvedAddrs(nil, false); carvedAddrs == nil || 0 < len(carvedAddrs) {
		t.Fatalf("none: %v", carvedAddrs)
	}
}

// A route may take a global IPv6 address off the host, an off-link resolver's above all, or the host's own on its
// prefix, which the host's routes then answer; never a link-local one, as a gateway's is, a loopback, multicast or
// unspecified one, an IPv4-mapped one or an IPv4 one.
func TestTunCarvedIpv6Leaves(t *testing.T) {
	for _, address := range []string{"2001:db8::53", "2001:db8:ffff::53", "2001:db8:fffe::53"} {
		if !urTunCarvedIpv6Leaves(netip.MustParseAddr(address)) {
			t.Errorf("%s stays", address)
		}
	}
	for _, address := range []string{"fe80::1", "::1", "ff02::1", "ff05::1:3", "::", "::ffff:192.0.2.53", "192.0.2.53"} {
		if urTunCarvedIpv6Leaves(netip.MustParseAddr(address)) {
			t.Errorf("%s leaves", address)
		}
	}
}
