// §22.5's Classify budget: at most 50 ns at 1,000 prefixes and no allocation, on the table a bridge builds.

package device_test

import (
	"math/rand/v2"
	"testing"

	"github.com/urnetwork/sidecar/device"
)

func BenchmarkBridgeTableClassify(b *testing.B) {
	random := rand.New(rand.NewPCG(1000, 0x6272696467652d62))
	entries := bridgeTestRandomEntries(random, 1000)
	table, err := device.NewBridgeTable(entries)
	if err != nil {
		b.Fatal(err)
	}
	// destinations inside the entries and outside them, so a run takes every path a lookup has
	packets := make([][]byte, 0, 1024)
	for len(packets) < cap(packets) {
		address := bridgeTestAddr(random.Uint32())
		if random.IntN(2) == 0 {
			prefix := entries[random.IntN(len(entries))].Prefix
			first := bridgeTestAddress(prefix.Addr())
			address = bridgeTestAddr(first + uint32(random.Uint64N(uint64(1)<<(32-prefix.Bits()))))
		}
		packets = append(packets, bridgeTestPacket(address))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		table.Classify(packets[i&1023])
	}
}
