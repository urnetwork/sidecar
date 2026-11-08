package dnsservice

import (
	"io"
	"net/netip"
)

// Bridges from the external tests, which reach sidecartest's fakes, to what only this package's own
// code calls.

// Serves view under keys, as FeedLoop does once SelfCheck passes.
func (self *DnsEdge) PublishForTest(view *ZoneView, keys *DnsSigningKeys) {
	self.publish(view, keys)
}

// The TCP connections being served and a channel that closes when that changes.
func (self *DnsEdge) TcpCountForTest() (int, chan struct{}) {
	return self.tcpCount.Get()
}

// The addresses edge rows answer, IPv4 then IPv6.
func (self *HealthySet) EdgeAddressesForTest() []netip.Addr {
	if self == nil {
		return nil
	}
	return append(append([]netip.Addr{}, self.edgeIpv4s...), self.edgeIpv6s...)
}

// The addresses router rows answer, IPv4 then IPv6.
func (self *HealthySet) RouterAddressesForTest() []netip.Addr {
	if self == nil {
		return nil
	}
	return append(append([]netip.Addr{}, self.routerIpv4s...), self.routerIpv6s...)
}

// The hello a probe sends for serverName.
func ProbeClientHelloForTest(serverName string) ([]byte, error) {
	return dnsProbeClientHello(serverName)
}

// Whether what reader sends back passes a probe.
func ProbeAnswerPassesForTest(reader io.Reader) bool {
	return dnsProbeAnswerPasses(reader)
}
