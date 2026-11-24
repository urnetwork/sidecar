//go:build linux || windows

// §17.7.1's gatherer on Linux and Windows (owner decision 778): the sidecar's own mDNS querier, UDP 5353 shared with
// the platform's responder, on each interface that is up, multicast-capable and not point-to-point, never loopback,
// ur tun's link or another tun (discovery_links.go). For each type of the effective list it sends RFC 6762 §5.2's
// continuous PTR queries, at intervals from QueryInterval doubling to QueryMaxInterval, each listing the PTRs it holds
// with more than half their TTL left as known answers (§7.1), at most QueryRate a second on an interface (RFC 8766
// §9.3), and takes each instance's SRV, TXT and its target's A from the answers and the additionals, which responders
// send with a browse's PTR (RFC 6763 §12). Where a responder left one out, the querier asks for it after each round:
// SRV and TXT by the instance's name, A by its target's. A responder's announcements bring an instance's subtype PTRs,
// which give its subtypes. What arrives keeps each record's own TTL; a goodbye, TTL 0, withdraws it at once (§10.1).
//
// The cache (discovery_mdns_cache.go) and the wire (discovery_mdns_wire.go) are pure and tested apart; the sockets
// around them are thin. Names and TXT are the LAN's words, kept as they came and logged nowhere (I-13).

package main

import (
	"context"
	"net"
	"sync"
	"time"

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
			self.query(ctx, conn, cache, types)
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

// Sends each type's continuous queries, its interval doubling, then the follow-ups the cache's instances need, at most
// QueryRate messages a second.
func (self *urMdnsGatherer) query(ctx context.Context, conn *net.UDPConn, cache *urMdnsCache, types []string) {
	interval := self.queries.QueryInterval
	spacing := time.Second / time.Duration(max(1, self.settings.QueryRate))
	send := func(messages [][]byte) bool {
		for _, message := range messages {
			conn.WriteToUDPAddrPort(message, urMdnsGroup)
			select {
			case <-ctx.Done():
				return false
			case <-time.After(spacing):
			}
		}
		return true
	}
	for ctx.Err() == nil {
		for _, serviceType := range types {
			if !send(urMdnsBrowseQuery(serviceType, cache.knownAnswers(serviceType, time.Now()), self.queries.QueryByteCount)) {
				return
			}
		}
		if !send(urMdnsFollowUps(cache.missing(types, time.Now()), self.queries.QueryByteCount)) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		interval = min(2*interval, self.queries.QueryMaxInterval)
	}
}
