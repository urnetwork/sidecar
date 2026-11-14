//go:build darwin

// This host's own addresses on macOS, for Bridge.SetLocalAddresses (§17.4's carve, §18.6's SetBridgeLocalAddresses;
// BRIDGE-M6-06): connect.LocalIpv4Networks sees only interface subnets, so the carve also needs the gateways and the
// resolvers the physical path uses.
//
//	interfaces  every address of every interface but the tun's own, both families: rule 0 reads them all as this
//	            device's own (D-BRIDGE-19), and the export carves the IPv4 ones
//	gateways    every next hop of every route not through the tun, from the routing table
//	resolvers   the nameservers of /etc/resolv.conf, which configd keeps for the primary service, and of each file in
//	            /etc/resolver but the tun's own
//
// The watch is a routing socket, each address, route or link message a change; a resolver file that changes with no
// route or address is the tun's LocalPollInterval's to see.

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"

	"golang.org/x/sys/unix"
)

// This host's addresses: every interface's but name's, every gateway not through name, and every resolver, but
// exclude, sorted with no repeats.
func (self *urTunDarwinSystem) LocalAddresses(name string, exclude []netip.Addr) ([]netip.Addr, error) {
	ownIndex, _ := self.interfaceIndex(name)
	addresses := []netip.Addr{}
	add := func(address netip.Addr) {
		address = address.Unmap().WithZone("")
		if address.IsValid() && !address.IsUnspecified() && !slices.Contains(exclude, address) &&
			!slices.Contains(addresses, address) {
			addresses = append(addresses, address)
		}
	}
	links, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		if link.Name == name {
			continue
		}
		linkAddresses, err := link.Addrs()
		if err != nil {
			continue
		}
		for _, linkAddress := range linkAddresses {
			if network, ok := linkAddress.(*net.IPNet); ok {
				if address, ok := netip.AddrFromSlice(network.IP); ok {
					add(address)
				}
			}
		}
	}
	routes, err := self.kernel.Routes()
	if err != nil {
		return nil, err
	}
	for _, held := range routes {
		if ownIndex != 0 && held.index == ownIndex {
			continue
		}
		if held.gateway.IsValid() {
			add(held.gateway)
		}
	}
	for _, resolver := range urReadResolvConf(self.resolvConfPath) {
		add(resolver)
	}
	for _, resolver := range urTunDarwinScopedResolvers(self.resolverDirectory) {
		add(resolver)
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return addresses, nil
}

// Calls changed on each address, route or link message of the routing socket until ctx ends, and once as soon as it
// watches, for whatever changed before. A receive queue that overflowed lost changes, so it counts as one.
func (self *urTunDarwinSystem) WatchLocal(ctx context.Context, changed func()) error {
	fd, err := urTunDarwinSocket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	// non-blocking, so the runtime's poller reads it and a close ends a read
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return err
	}
	file := os.NewFile(uintptr(fd), "route")
	defer file.Close()
	stop := context.AfterFunc(ctx, func() {
		file.Close()
	})
	defer stop()
	changed()
	message := make([]byte, os.Getpagesize())
	for {
		n, err := file.Read(message)
		if ctx.Err() != nil {
			return nil
		}
		switch {
		case errors.Is(err, unix.ENOBUFS):
			changed()
		case err != nil:
			return err
		case urTunDarwinLocalChange(message[:n]):
			changed()
		}
	}
}

// Whether a routing message is a change of an address, a route or a link, and not a neighbor's resolution or a miss.
func urTunDarwinLocalChange(message []byte) bool {
	// rt_msghdr, ifa_msghdr and if_msghdr each begin with their length, version and type
	const typeOffset = 3
	if len(message) <= typeOffset {
		return true
	}
	switch message[typeOffset] {
	case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE, unix.RTM_NEWADDR, unix.RTM_DELADDR, unix.RTM_IFINFO:
		return true
	}
	return false
}
