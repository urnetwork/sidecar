//go:build linux

// This host's own addresses on Linux, for Bridge.SetLocalAddresses (§17.4's carve, §18.6's SetBridgeLocalAddresses;
// BRIDGE-M4-18): connect.LocalIpv4Networks sees only interface subnets, so the carve also needs the gateways and the
// resolvers the physical path uses.
//
//	interfaces  every address of every interface but the tun's own, from rtnetlink, both families: rule 0 reads them
//	            all as this device's own (D-BRIDGE-19), and the export carves the IPv4 ones
//	gateways    every next hop of every route not through the tun, in every table
//	resolvers   the nameservers of /etc/resolv.conf and of systemd-resolved's uplink file, where it runs
//
// The watch is a NETLINK_ROUTE socket on the link, address and route groups of both families, each message a change;
// a resolver file that changes with no route or address is the tun's LocalPollInterval's to see.

package main

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// The resolver files: the system's, and systemd-resolved's list of its uplinks, which its stub's own file hides.
const (
	urResolvConfPath         = "/etc/resolv.conf"
	urResolvedUplinkConfPath = "/run/systemd/resolve/resolv.conf"
)

// This host's addresses: every interface's but name's, every gateway not through name, and every resolver, but
// exclude, sorted with no repeats.
func (self *urTunLinuxSystem) LocalAddresses(name string, exclude []netip.Addr) ([]netip.Addr, error) {
	ownIndex := urTunLinuxIndex(name)
	addresses := []netip.Addr{}
	add := func(address netip.Addr) {
		address = address.Unmap()
		if address.IsValid() && !address.IsUnspecified() && !slices.Contains(exclude, address) &&
			!slices.Contains(addresses, address) {
			addresses = append(addresses, address)
		}
	}
	interfaceAddresses, err := urTunLinuxAddresses()
	if err != nil {
		return nil, err
	}
	for _, held := range interfaceAddresses {
		if held.index != ownIndex {
			add(held.address)
		}
	}
	routes, err := urTunLinuxRoutes(unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		if ownIndex != 0 && slices.Contains(route.oifs, ownIndex) {
			continue
		}
		for _, gateway := range route.gateways {
			add(gateway)
		}
	}
	for _, path := range []string{urResolvConfPath, urResolvedUplinkConfPath} {
		for _, resolver := range urReadResolvConf(path) {
			add(resolver)
		}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return addresses, nil
}

// The nameservers path lists, in its order; none for a file that is absent or unreadable.
func urReadResolvConf(path string) []netip.Addr {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	return urParseResolvConf(file)
}

// The nameserver lines' addresses, a zone kept for a link-local one.
func urParseResolvConf(file *os.File) []netip.Addr {
	nameservers := []netip.Addr{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if address, err := netip.ParseAddr(fields[1]); err == nil {
			nameservers = append(nameservers, address)
		}
	}
	return nameservers
}

// Calls changed on each link, address or route message of either family until ctx ends, and once as soon as it
// watches, for whatever changed before. A receive queue that overflowed lost changes, so it counts as one.
func (self *urTunLinuxSystem) WatchLocal(ctx context.Context, changed func()) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_IFADDR |
		unix.RTMGRP_IPV6_ROUTE)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
		return err
	}
	// non-blocking, so the runtime's poller reads it and a close ends a read
	file := os.NewFile(uintptr(fd), "netlink")
	defer file.Close()
	stop := context.AfterFunc(ctx, func() {
		file.Close()
	})
	defer stop()
	changed()
	message := make([]byte, os.Getpagesize())
	for {
		_, err := file.Read(message)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil && !errors.Is(err, unix.ENOBUFS) {
			return err
		}
		changed()
	}
}
