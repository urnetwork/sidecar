// BenchmarkBridgeRoute*: Route's cost on a bridge's effective settings, each with 0 allocations: a default packet, a
// packet to a link entry of one advertiser, and one to an entry of two whose pair holds a pin.

package device_test

import (
	"testing"
)

// Routes packet b.N times on a route test whose links are built.
func benchmarkBridgeRoute(b *testing.B, destination string) {
	test := newRouteTest(b, routeTestFixture(), nil)
	packet := routeTestUdp(routeTestSource, destination, 9)
	if destination != "203.0.113.9" {
		test.awaitLink(packet)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		test.bridge.Route(packet)
	}
}

func BenchmarkBridgeRouteDefault(b *testing.B) {
	benchmarkBridgeRoute(b, "203.0.113.9")
}

func BenchmarkBridgeRouteLink(b *testing.B) {
	benchmarkBridgeRoute(b, "100.80.1.4")
}

func BenchmarkBridgeRoutePinHit(b *testing.B) {
	benchmarkBridgeRoute(b, "100.80.1.5")
}
