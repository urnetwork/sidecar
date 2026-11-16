// §22.9's pin churn cell on the mobile sender (BRIDGE-M8-03; D-BRIDGE-7, D-BRIDGE-9, R-BRIDGE-9, R-BRIDGE-11, owner
// decision 66; §17.5's pins, full and idle rows): a device.Bridge on the phone's 1,024-slot pin table routes, through
// its own Route, live pairs past 1,024 on an entry that offers a choice, two advertisers. Every packet goes to one of
// the entry's links: none is refused, none rejected and none falls back to the default route; the excess routes by the
// hash, unpinned and counted; once pairs idle out their slots pin new pairs; and Route allocates nothing on a full
// table. The table-level twin, TestPinFullTableRefusesNoneAndMovesNoPinnedPair, holds the same of BridgePinTable alone
// and that an entry edit moves no pinned pair. The cell logs its counts in §22.9's shape, one row a round; they are a
// surrogate's figures, never evidence for a phone.

package device_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The cell's pairs: sources in 100.81/16, each a UDP pair to the entry's one destination, which two links advertise.
func pinChurnSource(i int) string {
	return netip.AddrFrom4([4]byte{100, 81, byte(i >> 8), byte(i)}).String()
}

const pinChurnDestination = "100.80.1.5"

// The routing of one round of pairs: how many went to each link, and how many went anywhere else.
type pinChurnRound struct {
	linkCounts   map[connect.Id]int
	strayCount   int
	refusedCount int
}

// Routes one UDP packet of each pair from first up to first+count through test's bridge.
func pinChurnRoute(test *routeTest, first int, count int) pinChurnRound {
	round := pinChurnRound{linkCounts: map[connect.Id]int{}}
	for i := first; i < first+count; i += 1 {
		switch client := test.bridge.Route(routeTestUdp(pinChurnSource(i), pinChurnDestination, 53)).(type) {
		case *sidecartest.FakeBridgeLink:
			round.linkCounts[client.Target] += 1
		case nil:
			round.strayCount += 1
		default:
			if _, rejected := client.(*device.BridgeRejectClient); rejected {
				round.strayCount += 1
			} else {
				round.refusedCount += 1
			}
		}
	}
	return round
}

// Routes pairs until both of the entry's links are open, so every later packet has a link to take.
func pinChurnAwaitLinks(t *testing.T, test *routeTest) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for i := 0; ; i += 1 {
		pinChurnRoute(test, 60000+i%1000, 1)
		if openCount, _ := test.bridge.LinksForTest().CountsForTest(); openCount == 2 {
			return
		}
		select {
		case <-test.passes:
		case <-ctx.Done():
			t.Fatal("the entry's two links never opened")
		default:
		}
	}
}

// §22.9: the mobile sender's 1,024-slot pin table, churned past 1,024 live pairs, routes the excess unpinned and refuses
// none, and its slots go to new pairs once the old ones idle out.
func TestPinChurnCellOnTheMobileSender(t *testing.T) {
	mobile := device.MobileBridgeSettings()
	test := newRouteTest(t, routeTestFixture(), func(settings *device.BridgeSettings) {
		settings.PinSlotCount = mobile.PinSlotCount
		settings.LinkCountMax = mobile.LinkCountMax
	})
	pinChurnAwaitLinks(t, test)
	links := []connect.Id{sidecartest.BridgeFixtureClientId(5), sidecartest.BridgeFixtureClientId(6)}

	const pairCount = 1536
	report := func(name string, round pinChurnRound) {
		t.Helper()
		status := test.bridge.Status()
		t.Logf("cell=pin_churn round=%s slots=%d live_pairs=%d pinned=%d unpinned_picks=%d link_a=%d link_b=%d refused=%d stray=%d",
			name, mobile.PinSlotCount, pairCount, status.PinnedPairCount, status.UnpinnedPickCount, round.linkCounts[links[0]],
			round.linkCounts[links[1]], round.refusedCount, round.strayCount)
		if round.refusedCount != 0 || round.strayCount != 0 {
			t.Errorf("%s: %d refused and %d routed off the entry's links", name, round.refusedCount, round.strayCount)
		}
		if round.linkCounts[links[0]]+round.linkCounts[links[1]] != pairCount || round.linkCounts[links[0]] == 0 || round.linkCounts[links[1]] == 0 {
			t.Errorf("%s: the links took %v", name, round.linkCounts)
		}
		if mobile.PinSlotCount < status.PinnedPairCount {
			t.Errorf("%s: %d pins in %d slots", name, status.PinnedPairCount, mobile.PinSlotCount)
		}
	}

	// past the table: the excess unpinned, none refused
	report("fill", pinChurnRoute(test, 0, pairCount))
	full := test.bridge.Status()
	if full.UnpinnedPickCount == 0 || full.PinnedPairCount < mobile.PinSlotCount/2 {
		t.Fatalf("a full table pinned %d and routed %d unpinned", full.PinnedPairCount, full.UnpinnedPickCount)
	}
	// the same live pairs again, each on the link it took
	again := pinChurnRoute(test, 0, pairCount)
	report("again", again)
	// Route on a full table allocates nothing, pinned or not
	packet := routeTestUdp(pinChurnSource(pairCount+1), pinChurnDestination, 53)
	if allocs := testing.AllocsPerRun(1000, func() { test.bridge.Route(packet) }); allocs != 0 {
		t.Errorf("Route on a full table allocates %v a packet", allocs)
	}

	// every pair idles out (§17.5's idle row: 5 min for UDP), and a new set of live pairs takes the slots
	test.clock.Advance(mobile.PinIdleTimeout + time.Second)
	if pinned := test.bridge.Status().PinnedPairCount; pinned != 0 {
		t.Errorf("%d pins outlived their idle", pinned)
	}
	unpinnedBefore := test.bridge.Status().UnpinnedPickCount
	report("churn", pinChurnRoute(test, pairCount, pairCount))
	churned := test.bridge.Status()
	if churned.PinnedPairCount < mobile.PinSlotCount/2 || churned.UnpinnedPickCount == unpinnedBefore {
		t.Errorf("after the churn %d pinned, %d unpinned picks", churned.PinnedPairCount, churned.UnpinnedPickCount-unpinnedBefore)
	}
}
