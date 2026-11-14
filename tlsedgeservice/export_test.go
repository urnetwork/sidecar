// A bridge to private parts for tlsedgeservice_test, the package of the tests that move sidecartest's
// FakeClock. Those are a separate package because sidecartest is to hold TLS-M5-08's
// FakeTlsEdgeStore, and a test of this package importing sidecartest would then be a cycle
// (connect/CODESTYLE.md's package layering).

package tlsedgeservice

import (
	"context"
	"net"
	"time"

	"github.com/urnetwork/sidecar"
)

// Starts timeout_s's timer on conn, as a listener does at accept, and gives its end.
func NewProxyHeaderTimeoutForTest(clock sidecar.Clock, timeout time.Duration, conn net.Conn) (end func() bool) {
	return newProxyHeaderTimeout(clock, timeout, conn).end
}

// Finished reads of the label map, failed or not.
func (self *TlsEdgeService) NameLoadCountForTest() *sidecar.MonitorValue[uint64] {
	return self.nameLoadCount
}

// Finished kill reloads, failed or not.
func (self *TlsEdgeService) KillLoadCountForTest() *sidecar.MonitorValue[uint64] {
	return self.killLoadCount
}

// Changes to the kill set.
func (self *TlsEdgeService) KillChangeCountForTest() *sidecar.MonitorValue[uint64] {
	return self.killChangeCount
}

// Finished passes of the caps' loader.
func (self *TlsEdgeService) LimitsPassCountForTest() *sidecar.MonitorValue[uint64] {
	return self.limits.passCount
}

// Connections that have run to their end.
func (self *TlsEdgeService) ConnectionEndCountForTest() *sidecar.MonitorValue[uint64] {
	return self.connectionEndCount
}

// Waits armed by the connection records' loop, the first before any flush.
func (self *TlsEdgeService) RecordFlushCountForTest() *sidecar.MonitorValue[uint64] {
	return self.records.flushCount
}

// Connection records waiting for a flush.
func (self *TlsEdgeService) RecordsPendingCountForTest() int {
	return self.records.PendingCount()
}

// Spliced connections open now.
func (self *TlsEdgeService) SpliceCountForTest() int {
	return len(self.splices(nil))
}

// Sends the open usage window now, as a drain does.
func (self *TlsEdgeService) UsageDrainForTest(ctx context.Context) error {
	return self.usage.Drain(ctx)
}
