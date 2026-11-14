// BenchmarkCompile at 6, 1,000 and 5,000 devices (DESIGN-DETAILS 12.6, 12.4's estimate): a network with no document,
// where every untagged sidecar reaches the host and the host reaches every one, so the output is the largest a
// network that size gives, every device addressed and bound. The effective settings and the real ledger, as a daemon
// runs it. 12.4 estimates a 5,000-device team at about 30 ms on a daemon; section 4.4's gate is 200 ms on the reference
// phone class, which this host does not stand for.

package sidecar

import (
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A compile fixture with deviceCount devices beside the owner's, one member's each, every one addressed and bound.
func newTestBridgeCompileBenchNet(b *testing.B, deviceCount int) *testBridgeCompileNet {
	b.Helper()
	ledgerNet := newTestBridgeLedgerNet(b)
	self := &testBridgeCompileNet{testBridgeLedgerNet: ledgerNet, bindings: NewBridgeBindingCache(0, 16)}
	self.blockFile = self.sign(self.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testBridgeCompileBlock())
	for i := range deviceCount {
		label := fmt.Sprint("bench member ", i)
		_, device := self.consentedMember(label)
		// lower /17 host bits from 1.1 on, never .0, .255 or the services /24
		hostBits := uint32(256 + i/250*256 + i%250 + 1)
		self.mustPost(device, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, self.bridgeAddress(device, testBridgeIpv4(100, 80, byte(hostBits>>8), byte(hostBits))))
		self.bind(device, 1)
		if i == 0 {
			self.host = device
		}
	}
	return self
}

// One compile a loop at deviceCount devices.
func benchmarkCompile(b *testing.B, deviceCount int) {
	net := newTestBridgeCompileBenchNet(b, deviceCount)
	view, local := net.view(), net.local()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := CompileBridgeState(view, local, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompileSixDevices(b *testing.B) {
	benchmarkCompile(b, 6)
}

func BenchmarkCompileThousandDevices(b *testing.B) {
	benchmarkCompile(b, 1000)
}

func BenchmarkCompileFiveThousandDevices(b *testing.B) {
	benchmarkCompile(b, 5000)
}
