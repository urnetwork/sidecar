// A bridge to private parts for tlsedgeservice_test, the package of the tests that move sidecartest's
// FakeClock. Those are a separate package because sidecartest is to hold TLS-M5-08's
// FakeTlsEdgeStore, and a test of this package importing sidecartest would then be a cycle
// (connect/CODESTYLE.md's package layering).

package tlsedgeservice

import (
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
