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

// The serial of the view root's local snapshot holds, and a channel that closes when it changes.
func (self *FeedLoop) WrittenSerialForTest(root string) (uint64, chan struct{}) {
	for _, feedRoot := range self.roots {
		if feedRoot.root == root {
			return feedRoot.writer.writtenSerial.Get()
		}
	}
	closed := make(chan struct{})
	close(closed)
	return 0, closed
}

// Whether root's loop and its writer are each parked, with a channel for each that closes when it
// changes.
func (self *FeedLoop) IdleForTest(root string) (loopIdle bool, loopChanged chan struct{}, writerIdle bool, writerChanged chan struct{}) {
	for _, feedRoot := range self.roots {
		if feedRoot.root == root {
			loopIdle, loopChanged = feedRoot.idle.Get()
			writerIdle, writerChanged = feedRoot.writer.idle.Get()
			return loopIdle, loopChanged, writerIdle, writerChanged
		}
	}
	closed := make(chan struct{})
	close(closed)
	return true, closed, true, closed
}

// Long-polls parked in their wait, and a channel that closes when that changes.
func (self *DnsApi) ParkedForTest() (int, chan struct{}) {
	return self.parkedCount.Get()
}
