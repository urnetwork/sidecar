//go:build darwin || windows

// The carved addresses' host routes as macOS and Windows share them (tun_host_routes.go; QD-869, QD-971): which
// addresses of a carve take one, of either family, which of them a clear keeps while a family's halves stand, and how a
// set of them follows what is wanted. The platforms' own tests run them through their recorders (tun_darwin_test.go,
// tun_windows_test.go).

package main

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// An IPv4 address takes a host route only where no route of the host's own reaches it, it lies in no route of the
// tun's own, and it is a host's address other than the gateway: never an unspecified, loopback, multicast or IPv6 one,
// and once however often the carve names it.
func TestTunHostRoutesChooseTheAddresses(t *testing.T) {
	gateway := netip.MustParseAddr("192.0.2.1")
	onLink := netip.MustParsePrefix("192.0.2.0/24")
	reached := func(address netip.Addr) bool {
		return onLink.Contains(address)
	}
	carvedAddrs := []netip.Addr{}
	for _, address := range []string{"0.0.0.0", "127.0.0.53", "224.0.0.251", "2001:db8::53", "192.0.2.1", "192.0.2.53",
		"100.70.0.9", "203.0.113.53", "203.0.113.53", "198.51.100.53"} {
		carvedAddrs = append(carvedAddrs, netip.MustParseAddr(address))
	}
	hostRoutes := urTunHostRoutes(carvedAddrs, true, gateway, 4, []netip.Prefix{netip.MustParsePrefix("100.70.0.0/16")}, reached)
	want := []urTunHostRoute{
		{address: netip.MustParseAddr("203.0.113.53"), gateway: gateway, link: 4},
		{address: netip.MustParseAddr("198.51.100.53"), gateway: gateway, link: 4},
	}
	if !slices.Equal(hostRoutes, want) {
		t.Fatalf("host routes %v", hostRoutes)
	}
	// a default route that names no gateway
	hostRoutes = urTunHostRoutes(carvedAddrs[7:8], true, netip.Addr{}, 7, nil, reached)
	if !slices.Equal(hostRoutes, []urTunHostRoute{{address: netip.MustParseAddr("203.0.113.53"), link: 7}}) {
		t.Fatalf("with no gateway %v", hostRoutes)
	}
}

// An IPv6 address takes a host route by the IPv6 default route's gateway only where no route of the host's own reaches
// it (QD-971): off-link resolvers, by a link-local gateway as IPv6's default routes name one; never one on the host's
// own prefix, a link-local one, the gateway's among them, a loopback, multicast or unspecified one, or an IPv4 one, and
// once however often the carve names it.
func TestTunHostRoutesChooseTheIpv6Addresses(t *testing.T) {
	gateway := netip.MustParseAddr("fe80::1")
	onLink := netip.MustParsePrefix("2001:db8::/64")
	reached := func(address netip.Addr) bool {
		return onLink.Contains(address)
	}
	carvedAddrs := []netip.Addr{}
	for _, address := range []string{"::", "::1", "ff02::1:3", "fe80::1", "fe80::53", "2001:db8::53", "2001:db8::10",
		"192.0.2.53", "203.0.113.53", "2001:db8:ffff::53", "2001:db8:ffff::53", "2001:db8:fffe::53"} {
		carvedAddrs = append(carvedAddrs, netip.MustParseAddr(address))
	}
	hostRoutes := urTunHostRoutes(carvedAddrs, false, gateway, 6, nil, reached)
	want := []urTunHostRoute{
		{address: netip.MustParseAddr("2001:db8:ffff::53"), gateway: gateway, link: 6},
		{address: netip.MustParseAddr("2001:db8:fffe::53"), gateway: gateway, link: 6},
	}
	if !slices.Equal(hostRoutes, want) {
		t.Fatalf("host routes %v", hostRoutes)
	}
	// IPv6's default route naming no gateway, as a point-to-point link's does: by that interface alone
	hostRoutes = urTunHostRoutes(carvedAddrs, false, netip.Addr{}, 7, nil, reached)
	if !slices.Equal(hostRoutes, []urTunHostRoute{{address: netip.MustParseAddr("2001:db8:ffff::53"), link: 7},
		{address: netip.MustParseAddr("2001:db8:fffe::53"), link: 7}}) {
		t.Fatalf("with no gateway %v", hostRoutes)
	}
	// IPv4's choice over the same carve takes no IPv6 address
	if hostRoutes := urTunHostRoutes(carvedAddrs, true, netip.MustParseAddr("192.0.2.1"), 4, nil, reached); !slices.Equal(hostRoutes,
		[]urTunHostRoute{{address: netip.MustParseAddr("192.0.2.53"), gateway: netip.MustParseAddr("192.0.2.1"), link: 4},
			{address: netip.MustParseAddr("203.0.113.53"), gateway: netip.MustParseAddr("192.0.2.1"), link: 4}}) {
		t.Fatalf("IPv4's over the same carve %v", hostRoutes)
	}
}

// What a clear keeps of the host routes: those of each family whose halves stand, in their order, and nothing of a
// family whose halves are off.
func TestTunStandingHostRoutesKeepEachFamilysOwn(t *testing.T) {
	ipv4Route := urTunHostRoute{address: netip.MustParseAddr("203.0.113.53"), gateway: netip.MustParseAddr("192.0.2.1"), link: 4}
	ipv6Route := urTunHostRoute{address: netip.MustParseAddr("2001:db8:ffff::53"), gateway: netip.MustParseAddr("fe80::1"), link: 4}
	ipv4Other := urTunHostRoute{address: netip.MustParseAddr("198.51.100.53"), link: 7}
	hostRoutes := []urTunHostRoute{ipv4Route, ipv6Route, ipv4Other}
	for _, c := range []struct {
		ipv4 bool
		ipv6 bool
		want []urTunHostRoute
	}{
		{ipv4: true, ipv6: true, want: hostRoutes},
		{ipv4: true, ipv6: false, want: []urTunHostRoute{ipv4Route, ipv4Other}},
		{ipv4: false, ipv6: true, want: []urTunHostRoute{ipv6Route}},
		{ipv4: false, ipv6: false, want: []urTunHostRoute{}},
	} {
		if standing := urTunStandingHostRoutes(hostRoutes, c.ipv4, c.ipv6); !slices.Equal(standing, c.want) || standing == nil {
			t.Errorf("IPv4's %t, IPv6's %t: %v", c.ipv4, c.ipv6, standing)
		}
	}
}

// The carve as the host routes follow it: both families, IPv4's then IPv6's, each as urTunCarvedAddrs gives it.
func TestTunCarvedHostAddrsTakeBothFamilies(t *testing.T) {
	carvedAddrs := urTunCarvedHostAddrs([]netip.Addr{netip.MustParseAddr("2001:db8:ffff::53"), netip.MustParseAddr("203.0.113.53"),
		netip.MustParseAddr("fe80::1%4"), netip.MustParseAddr("::ffff:192.0.2.53"), netip.MustParseAddr("2001:db8:ffff::53")})
	want := []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("203.0.113.53"),
		netip.MustParseAddr("2001:db8:ffff::53"), netip.MustParseAddr("fe80::1")}
	if !slices.Equal(carvedAddrs, want) {
		t.Fatalf("carved %v", carvedAddrs)
	}
}

// A set of host routes follows what is wanted: one that stays is not written again, one no longer wanted comes off,
// one already gone counts as off, one another route holds is not kept, one whose old route will not come off waits
// for it, and what was refused is counted with the first refusal's words and no address.
func TestTunSetHostRoutesFollowsWhatIsWanted(t *testing.T) {
	errHeld := errors.New("held")
	errGone := errors.New("gone")
	errRefused := errors.New("refused")
	gateway := netip.MustParseAddr("192.0.2.1")
	moved := netip.MustParseAddr("192.0.2.254")
	hostRoute := func(address string, gateway netip.Addr) urTunHostRoute {
		return urTunHostRoute{address: netip.MustParseAddr(address), gateway: gateway, link: 4}
	}
	calls := []string{}
	addErrs := map[urTunHostRoute]error{}
	removeErrs := map[urTunHostRoute]error{}
	platform := &urTunHostRouteCalls{
		add: func(hostRoute urTunHostRoute) error {
			calls = append(calls, "add "+hostRoute.address.String()+" by "+hostRoute.gateway.String())
			return addErrs[hostRoute]
		},
		remove: func(hostRoute urTunHostRoute) error {
			calls = append(calls, "remove "+hostRoute.address.String()+" by "+hostRoute.gateway.String())
			return removeErrs[hostRoute]
		},
		held: func(err error) bool { return errors.Is(err, errHeld) },
		gone: func(err error) bool { return errors.Is(err, errGone) },
	}
	stays := hostRoute("203.0.113.1", gateway)
	leaves := hostRoute("203.0.113.2", gateway)
	gone := hostRoute("203.0.113.3", gateway)
	stuck := hostRoute("203.0.113.4", gateway)
	stuckMoved := hostRoute("203.0.113.4", moved)
	joins := hostRoute("203.0.113.5", gateway)
	held := hostRoute("203.0.113.6", gateway)
	refused := hostRoute("203.0.113.7", gateway)
	removeErrs[gone] = errGone
	removeErrs[stuck] = errRefused
	addErrs[held] = errHeld
	addErrs[refused] = errRefused
	on, err := urTunSetHostRoutes([]urTunHostRoute{stays, leaves, gone, stuck},
		[]urTunHostRoute{stays, stuckMoved, joins, held, refused}, platform)
	if !slices.Equal(on, []urTunHostRoute{stays, stuck, joins}) {
		t.Fatalf("on %v", on)
	}
	wantCalls := []string{"remove 203.0.113.2 by 192.0.2.1", "remove 203.0.113.3 by 192.0.2.1", "remove 203.0.113.4 by 192.0.2.1",
		"add 203.0.113.5 by 192.0.2.1", "add 203.0.113.6 by 192.0.2.1", "add 203.0.113.7 by 192.0.2.1"}
	if !slices.Equal(calls, wantCalls) {
		t.Fatalf("calls %v", calls)
	}
	if err == nil || !strings.Contains(err.Error(), "1 host routes of addresses no longer carved did not come off (refused)") ||
		!strings.Contains(err.Error(), "1 host routes of carved addresses did not go on") ||
		strings.Contains(err.Error(), "203.0.113") {
		t.Fatalf("the answer: %v", err)
	}
	// the next call tries what was refused again: the old route comes off and its address goes by the new gateway
	calls = nil
	delete(removeErrs, stuck)
	delete(addErrs, refused)
	on, err = urTunSetHostRoutes(on, []urTunHostRoute{stays, stuckMoved, joins, refused}, platform)
	if err != nil || !slices.Equal(on, []urTunHostRoute{stays, joins, stuckMoved, refused}) {
		t.Fatalf("on %v: %v", on, err)
	}
	if !slices.Equal(calls, []string{"remove 203.0.113.4 by 192.0.2.1", "add 203.0.113.4 by 192.0.2.254", "add 203.0.113.7 by 192.0.2.1"}) {
		t.Fatalf("calls again %v", calls)
	}
	// nothing wanted takes them all off, and nothing on with nothing wanted writes nothing
	calls = nil
	on, err = urTunSetHostRoutes(on, nil, platform)
	if err != nil || 0 < len(on) || len(calls) != 4 {
		t.Fatalf("on %v after %v: %v", on, calls, err)
	}
	calls = nil
	if on, err = urTunSetHostRoutes(on, nil, platform); err != nil || 0 < len(on) || 0 < len(calls) {
		t.Fatalf("on %v after %v: %v", on, calls, err)
	}
}
