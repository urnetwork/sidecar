//go:build !sidecar_http && !ios_extension

// §13.7's slow-visitor rows on one endpoint, besides the handshake and first-request bounds, which run on the clock
// where each wait is (tls_front.go, tls_http.go): one visitor, its address's /64 on IPv6 or /32 on IPv4, holds at
// most 1/8 of the endpoint's max_streams at once, and at least one stream, from TlsEdgeOpen's client_ip. A stream
// past its visitor's share resets before a byte of it is read.
//
// tlsedge's caps (§13.9) bound what reaches the device in total; this share keeps one visitor from holding the
// listener's whole max_streams, which admission's step 5 counts for every visitor alike. The counts live in this
// endpoint's memory alone and name no address anywhere else (I-13). Safe for concurrent use.

package sidecar

import (
	"net/netip"
	"sync"
)

// One endpoint's visitors and the streams each holds.
type tlsFrontVisitors struct {
	ipv4PrefixBitCount int
	ipv6PrefixBitCount int
	// at least 1
	maxPerVisitor int

	stateLock     sync.Mutex
	prefixStreams map[netip.Prefix]int
}

// The visitors of an endpoint of maxStreams, each with its share.
func newTlsFrontVisitors(settings *TlsFrontSettings, maxStreams int) *tlsFrontVisitors {
	return &tlsFrontVisitors{
		ipv4PrefixBitCount: settings.VisitorIpv4PrefixBitCount,
		ipv6PrefixBitCount: settings.VisitorIpv6PrefixBitCount,
		maxPerVisitor:      max(1, maxStreams/settings.VisitorShareDivisor),
		prefixStreams:      map[netip.Prefix]int{},
	}
}

// The visitor clientIp belongs to: its /32 or /64, an IPv4-mapped IPv6 address read as the IPv4 one.
func (self *tlsFrontVisitors) prefixOf(clientIp []byte) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(clientIp)
	if !ok {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	bitCount := self.ipv6PrefixBitCount
	if addr.Is4() {
		bitCount = self.ipv4PrefixBitCount
	}
	prefix, err := addr.Prefix(bitCount)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// Takes one stream of clientIp's visitor, false past its share or for an address that is none; release gives it
// back, once.
func (self *tlsFrontVisitors) take(clientIp []byte) (release func(), ok bool) {
	prefix, ok := self.prefixOf(clientIp)
	if !ok {
		return nil, false
	}
	taken := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.maxPerVisitor <= self.prefixStreams[prefix] {
			return false
		}
		self.prefixStreams[prefix] += 1
		return true
	}()
	if !taken {
		return nil, false
	}
	releaseOnce := sync.Once{}
	return func() {
		releaseOnce.Do(func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.prefixStreams[prefix] -= 1
			if self.prefixStreams[prefix] <= 0 {
				delete(self.prefixStreams, prefix)
			}
		})
	}, true
}

// How many streams clientIp's visitor holds, for a test.
func (self *tlsFrontVisitors) heldBy(clientIp []byte) int {
	prefix, ok := self.prefixOf(clientIp)
	if !ok {
		return 0
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.prefixStreams[prefix]
}
