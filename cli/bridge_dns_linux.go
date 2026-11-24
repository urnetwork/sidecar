//go:build linux

// ur tun's names on Linux (§12.9, §17.10; BRIDGE-M4-18): the tun's link resolves the state's name zones, ~<net>.<root>,
// through <block>.0.53, where device.Bridge's resolver answers them, by systemd-resolved's bus API: SetLinkDNS, each zone
// a routing-only domain through SetLinkDomains, and SetLinkDefaultRoute false, so no other name goes to the bridge.
// resolved takes these from root or a caller holding CAP_NET_ADMIN, which ur tun's daemon has. Where resolved is absent
// or refuses, ur tun prints the step a person takes instead.
//
// The bridge's resolver passes the names its zone does not hold, a published app.<net>.<root> among them, to this
// host's own resolvers (urLinuxResolverUpstream): resolved's uplinks where it runs, else /etc/resolv.conf's, never
// resolved's stub, which would route the zone straight back to the bridge, and never an address routed into the tun.
// Its queries ride connect's dialer, so while the default route rides the tun under exits they carry connect's egress
// mark and keep the host's own route, as the daemon's transport does (QD-800).

package main

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
)

func init() {
	urBridgeResolverUpstream = urLinuxResolverUpstream
}

// systemd-resolved's bus names.
const (
	urResolvedDestination = "org.freedesktop.resolve1"
	urResolvedPath        = dbus.ObjectPath("/org/freedesktop/resolve1")
	urResolvedManager     = "org.freedesktop.resolve1.Manager"
)

// resolved's stub listeners, which route the zone back to the bridge.
var urResolvedStubAddrs = []netip.Addr{
	netip.AddrFrom4([4]byte{127, 0, 0, 53}),
	netip.AddrFrom4([4]byte{127, 0, 0, 54}),
}

// SetLinkDNS's address: (iay).
type urResolvedAddress struct {
	Family  int32
	Address []byte
}

// SetLinkDomains' domain: (sb), routing-only when RoutingOnly.
type urResolvedDomain struct {
	Domain      string
	RoutingOnly bool
}

// Points zones on the link index at resolver through resolved, within timeout. Answers "" and true when resolved took
// it; else the step a person takes, and whether resolved holds anything of the link to revert.
func urTunLinuxSetResolver(index int, name string, resolver netip.Addr, zones []string, timeout time.Duration,
	log sidecar.Logger) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	step := urTunResolverStep(name, resolver, zones)
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		if log.V(1).Enabled() {
			log.Infof("[tun]no system bus for systemd-resolved: %v", err)
		}
		return step, false
	}
	defer conn.Close()
	manager := conn.Object(urResolvedDestination, urResolvedPath)
	domains := []urResolvedDomain{}
	for _, zone := range zones {
		domains = append(domains, urResolvedDomain{Domain: strings.TrimSuffix(zone, "."), RoutingOnly: true})
	}
	resolverOctets := resolver.As4()
	calls := []struct {
		method string
		args   []any
	}{
		{method: "SetLinkDNS", args: []any{int32(index), []urResolvedAddress{{Family: unix.AF_INET, Address: resolverOctets[:]}}}},
		{method: "SetLinkDomains", args: []any{int32(index), domains}},
		{method: "SetLinkDefaultRoute", args: []any{int32(index), false}},
	}
	for i, call := range calls {
		if err := manager.CallWithContext(ctx, urResolvedManager+"."+call.method, 0, call.args...).Err; err != nil {
			if log.V(1).Enabled() {
				log.Infof("[tun]systemd-resolved refused the link's %s: %v", call.method, err)
			}
			// a resolved too old for SetLinkDefaultRoute still routes the zones by their routing-only domains
			if call.method == "SetLinkDefaultRoute" {
				return "", true
			}
			return step, 0 < i
		}
	}
	return "", true
}

// Reverts what resolved holds of the link index, within timeout; a link the kernel deleted is resolved's to forget.
func urTunLinuxRevertResolver(index int, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Object(urResolvedDestination, urResolvedPath).CallWithContext(ctx, urResolvedManager+".RevertLink", 0, int32(index))
}

// The step a person takes where resolved did not take the zones: resolvectl's, or another resolver's.
func urTunResolverStep(name string, resolver netip.Addr, zones []string) string {
	routing := []string{}
	servers := []string{}
	for _, zone := range zones {
		zone = strings.TrimSuffix(zone, ".")
		routing = append(routing, "~"+zone)
		servers = append(servers, fmt.Sprintf("server=/%s/%s", zone, resolver))
	}
	return fmt.Sprintf("with systemd-resolved, run: resolvectl dns %s %s; resolvectl domain %s %s; with dnsmasq, add %s",
		name, resolver, name, strings.Join(routing, " "), strings.Join(servers, " "))
}

// The bridge's pass-through (device.BridgeResolverUpstream) over this host's resolvers (urLinuxUpstreamServers); routed
// says which addresses the tun carries.
func urLinuxResolverUpstream(routed func(address netip.Addr) bool) device.BridgeResolverUpstream {
	return urResolverUpstream(func() []netip.Addr {
		return urLinuxUpstreamServers(routed)
	})
}

// This host's resolvers the bridge may pass to: resolved's uplinks where its file is, else /etc/resolv.conf's; never
// its stub, nor an address routed into the tun.
func urLinuxUpstreamServers(routed func(address netip.Addr) bool) []netip.Addr {
	resolvers := urReadResolvConf(urResolvedUplinkConfPath)
	if len(resolvers) == 0 {
		resolvers = urReadResolvConf(urResolvConfPath)
	}
	servers := []netip.Addr{}
	for _, resolver := range resolvers {
		if slices.Contains(urResolvedStubAddrs, resolver.Unmap()) || (routed != nil && routed(resolver)) ||
			slices.Contains(servers, resolver) {
			continue
		}
		servers = append(servers, resolver)
	}
	return servers
}

// Turns systemd-resolved's mDNS on the link index on or off (SetLinkMulticastDNS), within timeout. resolved runs it
// only where its own MulticastDNS setting allows, which is the host's choice.
func urTunLinuxSetMulticastDns(index int, on bool, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return err
	}
	defer conn.Close()
	mode := "no"
	if on {
		mode = "yes"
	}
	return conn.Object(urResolvedDestination, urResolvedPath).CallWithContext(ctx, urResolvedManager+".SetLinkMulticastDNS", 0,
		int32(index), mode).Err
}
