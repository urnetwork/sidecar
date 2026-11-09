// The reject client (bridge_reject.go) on a fake clock: §22.5's reset bucket, at most 40 at once and 20 a second after,
// per source, another source unaffected; the rejects themselves, a reset for TCP and a prohibited unreachable for UDP;
// a flood past the bucket allocating nothing; and every packet taken, the pool balanced after.

package device_test

import (
	"bytes"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A reject client on a fake clock, keeping copies of what it writes.
type rejectTest struct {
	clock  *sidecartest.FakeClock
	client *device.BridgeRejectClient

	stateLock sync.Mutex
	written   [][]byte
}

func newRejectTest() *rejectTest {
	clock := sidecartest.NewFakeClock(time.UnixMilli(routeTestTimeMs))
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	self := &rejectTest{clock: clock}
	self.client = device.NewBridgeRejectClient(func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.written = append(self.written, bytes.Clone(packet))
	}, settings)
	return self
}

// The rejects written since the last take.
func (self *rejectTest) take() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	written := self.written
	self.written = nil
	return written
}

// Sends count packets from source, as Route hands them over.
func (self *rejectTest) send(source string, count int) {
	for range count {
		self.client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, routeTestTcp(source, "100.80.9.9", 80), time.Second)
	}
}

// At most 40 rejects at once and 20 a second after, per source, and another source's bucket is its own.
func TestBridgeRejectBucketPerSource(t *testing.T) {
	test := newRejectTest()
	test.send("100.80.1.2", 50)
	if written := test.take(); len(written) != 40 {
		t.Fatalf("%d rejects at once, want 40", len(written))
	}
	test.send("100.80.1.3", 50)
	if written := test.take(); len(written) != 40 {
		t.Fatalf("another source got %d rejects, want its own 40", len(written))
	}
	test.clock.Advance(time.Second)
	test.send("100.80.1.2", 50)
	if written := test.take(); len(written) != 20 {
		t.Fatalf("%d rejects a second later, want 20", len(written))
	}
	test.clock.Advance(500 * time.Millisecond)
	test.send("100.80.1.2", 50)
	if written := test.take(); len(written) != 10 {
		t.Fatalf("%d rejects half a second later, want 10", len(written))
	}
	sentCount, unsentCount := test.client.Counts()
	if sentCount != 110 || unsentCount != 90 {
		t.Fatalf("%d sent, %d unsent", sentCount, unsentCount)
	}
}

// A TCP segment gets a reset and a UDP datagram a prohibited unreachable, each from the destination back to the source;
// a reset gets nothing back, and counts as unsent.
func TestBridgeRejectAnswersEachProtocol(t *testing.T) {
	test := newRejectTest()
	test.client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, routeTestTcp("100.80.1.2", "100.80.9.9", 80), time.Second)
	test.client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, routeTestUdp("100.80.1.2", "100.80.9.9", 53), time.Second)
	reset := routeTestTcp("100.80.1.2", "100.80.9.9", 80)
	reset[33] = 0x04
	test.client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, reset, time.Second)
	written := test.take()
	if len(written) != 2 {
		t.Fatalf("%d rejects, want 2", len(written))
	}
	source := netip.MustParseAddr("100.80.1.2")
	destination := netip.MustParseAddr("100.80.9.9")
	for _, reject := range written {
		if netip.AddrFrom4([4]byte(reject[12:16])) != destination || netip.AddrFrom4([4]byte(reject[16:20])) != source {
			t.Fatalf("reject %x is not from the destination to the source", reject)
		}
	}
	if written[0][9] != 6 || written[0][33]&0x04 == 0 {
		t.Fatalf("the TCP reject %x is no reset", written[0])
	}
	if written[1][9] != 1 || written[1][20] != 3 || written[1][21] != 13 {
		t.Fatalf("the UDP reject %x is no prohibited unreachable", written[1])
	}
	if _, unsentCount := test.client.Counts(); unsentCount != 1 {
		t.Fatalf("%d unsent, want the reset's 1", unsentCount)
	}
}

// Past the bucket a flood allocates nothing, and every packet handed over is taken, the pool balanced after.
func TestBridgeRejectFloodAllocatesNothingPastTheBucket(t *testing.T) {
	test := newRejectTest()
	test.send("100.80.1.2", 40)
	packet := routeTestTcp("100.80.1.2", "100.80.9.9", 80)
	allocs := testing.AllocsPerRun(1000, func() {
		test.client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, packet, time.Second)
	})
	if allocs != 0 {
		t.Fatalf("%v allocations a refused reject", allocs)
	}
	takenBefore, returnedBefore, _ := connect.MessagePoolCounts()
	test.clock.Advance(time.Second)
	for range 30 {
		pooled := connect.MessagePoolGet(len(packet))
		copy(pooled, packet)
		if !test.client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, pooled, time.Second) {
			t.Fatal("the reject client refused a packet")
		}
	}
	takenAfter, returnedAfter, _ := connect.MessagePoolCounts()
	if takenAfter-takenBefore != returnedAfter-returnedBefore {
		t.Fatalf("pool: %d taken, %d returned", takenAfter-takenBefore, returnedAfter-returnedBefore)
	}
}
