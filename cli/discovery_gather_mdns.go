//go:build linux || windows

// §17.7.1's gatherer on Linux and Windows (owner decision 778): the sidecar's own mDNS querier, UDP 5353 shared with
// the platform's responder, on each interface that is up, multicast-capable and not point-to-point, never loopback,
// ur tun's link or another tun. For each type of the effective list it sends RFC 6762 §5.2's continuous PTR queries,
// at intervals from QueryInterval doubling to QueryMaxInterval, at most QueryRate a second on an interface (RFC 8766
// §9.3), and takes each instance's SRV, TXT and its target's A from the answers' additional records, which responders
// send with a browse's PTR (RFC 6763 §12). What arrives keeps each record's own TTL; a goodbye, TTL 0, withdraws it at
// once (§10.1).
//
// Not built in this draft, and so not claimed: §7.1's known-answer lists in the queries, and the follow-up SRV, TXT
// and A queries for an instance whose responder left them out, which such an instance stays ungathered without.
//
// The cache (discovery_mdns_cache.go) is pure and tested apart; the sockets around it are thin. Names and TXT are the
// LAN's words, kept as they came and logged nowhere (I-13).

package main

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"

	"github.com/urnetwork/sidecar"
)

func init() {
	urDiscoveryGathererOf = func(log sidecar.Logger, settings *sidecar.BridgeDiscoverySettings) sidecar.BridgeDiscoveryGatherer {
		return &urMdnsGatherer{log: log, settings: settings, queries: defaultUrMdnsSettings()}
	}
}

// The querier. See the file's comment.
type urMdnsGatherer struct {
	log      sidecar.Logger
	settings *sidecar.BridgeDiscoverySettings
	queries  *urMdnsSettings
}

// sidecar.BridgeDiscoveryGatherer: a querier on each eligible interface until ctx ends.
func (self *urMdnsGatherer) Gather(ctx context.Context, types []string, report func(gathered []*sidecar.BridgeDiscoveryGathered)) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	caches := []*urMdnsCache{}
	var cachesLock sync.Mutex
	changed := make(chan struct{}, 1)
	var running sync.WaitGroup
	for _, iface := range interfaces {
		if !urMdnsEligible(iface) {
			continue
		}
		conn, err := net.ListenMulticastUDP("udp4", &iface, net.UDPAddrFromAddrPort(urMdnsGroup))
		if err != nil {
			continue
		}
		packetConn := ipv4.NewPacketConn(conn)
		packetConn.SetMulticastInterface(&iface)
		packetConn.SetMulticastTTL(255)
		packetConn.SetMulticastLoopback(false)
		cache := newUrMdnsCache(self.queries)
		cachesLock.Lock()
		caches = append(caches, cache)
		cachesLock.Unlock()
		running.Add(2)
		go func() {
			defer running.Done()
			self.read(ctx, conn, cache, changed)
		}()
		go func() {
			defer running.Done()
			self.query(ctx, conn, types)
		}()
		context.AfterFunc(ctx, func() { conn.Close() })
	}
	defer running.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-time.After(self.queries.QueryInterval):
		}
		local := urMdnsLocalAddresses()
		gathered := []*sidecar.BridgeDiscoveryGathered{}
		cachesLock.Lock()
		for _, cache := range caches {
			gathered = append(gathered, cache.gathered(types, time.Now(), local)...)
		}
		cachesLock.Unlock()
		report(gathered)
	}
}

// Reads responses into cache until the conn closes.
func (self *urMdnsGatherer) read(ctx context.Context, conn *net.UDPConn, cache *urMdnsCache, changed chan struct{}) {
	buffer := make([]byte, self.queries.MessageByteCount)
	for ctx.Err() == nil {
		n, _, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		if cache.take(buffer[:n], time.Now()) {
			select {
			case changed <- struct{}{}:
			default:
			}
		}
	}
}

// Sends each type's continuous queries, its interval doubling, at most QueryRate a second.
func (self *urMdnsGatherer) query(ctx context.Context, conn *net.UDPConn, types []string) {
	interval := self.queries.QueryInterval
	spacing := time.Second / time.Duration(max(1, self.settings.QueryRate))
	for ctx.Err() == nil {
		for _, serviceType := range types {
			message, err := urMdnsQuery(serviceType)
			if err == nil {
				conn.WriteToUDPAddrPort(message, urMdnsGroup)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(spacing):
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		interval = min(2*interval, self.queries.QueryMaxInterval)
	}
}

// A PTR query for a type in local.
func urMdnsQuery(serviceType string) ([]byte, error) {
	name, err := dnsmessage.NewName(serviceType + ".local.")
	if err != nil {
		return nil, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

// Whether an interface is one the gatherer queries: up, multicast-capable, not loopback, not point-to-point, and none
// of ur tun's or another tun's.
func urMdnsEligible(iface net.Interface) bool {
	flags := iface.Flags
	if flags&net.FlagUp == 0 || flags&net.FlagMulticast == 0 || flags&net.FlagLoopback != 0 || flags&net.FlagPointToPoint != 0 {
		return false
	}
	for _, prefix := range []string{"ur-", "tun", "utun", "wg", "tap"} {
		if strings.HasPrefix(iface.Name, prefix) {
			return false
		}
	}
	return true
}

// This host's own IPv4 addresses, which name an instance its own.
func urMdnsLocalAddresses() []netip.Addr {
	addresses := []netip.Addr{}
	interfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		return addresses
	}
	for _, interfaceAddress := range interfaceAddresses {
		if prefix, err := netip.ParsePrefix(interfaceAddress.String()); err == nil && prefix.Addr().Is4() {
			addresses = append(addresses, prefix.Addr())
		}
	}
	return addresses
}
