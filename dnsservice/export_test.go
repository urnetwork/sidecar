package dnsservice

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
