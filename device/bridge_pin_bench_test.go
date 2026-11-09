// The pin probe on the packet path: a pinned pair's pick, warm, allocates nothing and takes no lock.

package device_test

import (
	"testing"

	"github.com/urnetwork/sidecar/device"
)

func BenchmarkBridgePinPick(b *testing.B) {
	_, settings := bridgePinTestSettings(8192)
	settings.Clock = device.RealClock{}
	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState(bridgePinTestLinks(1, 2, 3), settings)
	packets := make([][]byte, 0, 1024)
	for i := range cap(packets) {
		packet := bridgePinTestTcp(bridgePinTestSource(i), 50000, 443, false)
		table.Pick(entry, packet)
		packets = append(packets, packet)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		table.Pick(entry, packets[i&1023])
	}
}

// R-BRIDGE-9: a pick allocates nothing, pinned, hashed or windowed.
func TestPinPickAllocatesNothing(t *testing.T) {
	_, settings := bridgePinTestSettings(8192)
	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState(bridgePinTestLinks(1), settings)
	entry.Set(bridgePinTestLinks(1, 2, 3))
	packets := [][]byte{
		bridgePinTestTcp(bridgePinTestSource(1), 50000, 443, false),
		bridgePinTestTcp(bridgePinTestSource(2), 50000, 443, true),
		bridgePinTestUdp(bridgePinTestSource(3), 0, false),
		bridgePinTestIcmp(bridgePinTestSource(4)),
	}
	next := 5
	allocations := testing.AllocsPerRun(1000, func() {
		for _, packet := range packets {
			table.Pick(entry, packet)
		}
		// and a pair never seen
		table.Pick(entry, bridgePinTestUdpInto(packets[2], next))
		next += 1
	})
	if allocations != 0 {
		t.Fatalf("%v allocations a run", allocations)
	}
}

// Rewrites a UDP packet's source to the i-th test source, in place.
func bridgePinTestUdpInto(packet []byte, i int) []byte {
	packet[14] = byte(i >> 8)
	packet[15] = byte(i)
	return packet
}
