package dnsservice

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
)

// An edge serving the signing tests' rows, with RRL out of the way, and a packed query for name.
func newBenchEdge(b *testing.B) *DnsEdge {
	b.Helper()
	settings := signingTestSettings(b, 1000*1000*1000)
	settings.Rrl.ResponsesPerSecond = 1000 * 1000 * 1000
	host := &sidecar.ServiceHost{Metrics: &declaredMetrics{}, Clock: newTestClock(testSigningNow)}
	edge, err := NewDnsEdge(b.Context(), host, settings, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(edge.Close)
	signing := newTestSigning(b, testRoot)
	view := newTestView(b, 100, signingTestRows()...)
	edge.publish(view, signing.checked(b, view))
	edge.SetHealthySet(signingTestHealthy())
	return edge
}

func benchPacket(b *testing.B, name string, rrType uint16, signed bool) []byte {
	b.Helper()
	message := testQuery(name, rrType)
	message.SetEdns0(1232, signed)
	packet, err := message.Pack()
	if err != nil {
		b.Fatal(err)
	}
	return packet
}

// One UDP query through the edge, parse to packed reply: unsigned, then signed from the cache.
func BenchmarkAnswerUdp(b *testing.B) {
	edge := newBenchEdge(b)
	source := netip.MustParseAddr("192.0.2.1")
	for _, signed := range []bool{false, true} {
		packet := benchPacket(b, "www.net1."+testRoot, dns.TypeA, signed)
		b.Run("do="+strconv.FormatBool(signed), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if edge.answer(packet, source, false) == nil {
					b.Fatal("no answer")
				}
			}
		})
	}
}

// A random-name flood through the edge under DO: a fresh compact denial each time, as the cap meets it.
func BenchmarkAnswerUdpRandomNames(b *testing.B) {
	edge := newBenchEdge(b)
	source := netip.MustParseAddr("192.0.2.1")
	packets := make([][]byte, b.N)
	for index := range packets {
		packets[index] = benchPacket(b, "r"+strconv.Itoa(index)+"."+testRoot, dns.TypeA, true)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for _, packet := range packets {
		edge.answer(packet, source, false)
	}
}
