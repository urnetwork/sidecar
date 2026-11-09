// §17.5's pins row by row, and §22.7's and §22.9's pin cases, on the injected clock: links here are integers.

package device_test

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A fake clock and settings on it, with the pin table's slots as given.
func bridgePinTestSettings(slotCount int) (*sidecartest.FakeClock, *device.BridgeSettings) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	settings.PinSlotCount = slotCount
	return clock, settings
}

// Live links of weight 1.
func bridgePinTestLinks(links ...device.BridgeLinkId) []device.BridgeEntryLink {
	entryLinks := []device.BridgeEntryLink{}
	for _, link := range links {
		entryLinks = append(entryLinks, device.BridgeEntryLink{Link: link, Weight: 1})
	}
	return entryLinks
}

// The i-th source of a test's pairs, all to one destination.
func bridgePinTestSource(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{100, 80, byte(i >> 8), byte(i)})
}

var bridgePinTestDestination = netip.MustParseAddr("198.51.100.20")

// An IPv4 header of protocol from source to the test destination, then transport bytes.
func bridgePinTestPacket(protocol byte, source netip.Addr, transport []byte) []byte {
	packet := make([]byte, 20+len(transport))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = protocol
	sourceOctets := source.As4()
	copy(packet[12:16], sourceOctets[:])
	destinationOctets := bridgePinTestDestination.As4()
	copy(packet[16:20], destinationOctets[:])
	copy(packet[20:], transport)
	return packet
}

// A TCP segment between the ports, a SYN or a segment of an open connection.
func bridgePinTestTcp(source netip.Addr, sourcePort uint16, destinationPort uint16, syn bool) []byte {
	transport := make([]byte, 20)
	binary.BigEndian.PutUint16(transport[0:2], sourcePort)
	binary.BigEndian.PutUint16(transport[2:4], destinationPort)
	transport[12] = 0x50
	transport[13] = 0x10
	if syn {
		transport[13] = 0x02
	}
	return bridgePinTestPacket(6, source, transport)
}

// A UDP datagram, or one of its fragments at offset eight-byte units, with more to follow or not.
func bridgePinTestUdp(source netip.Addr, offset uint16, more bool) []byte {
	transport := make([]byte, 16)
	binary.BigEndian.PutUint16(transport[0:2], 40000)
	binary.BigEndian.PutUint16(transport[2:4], 53)
	packet := bridgePinTestPacket(17, source, transport)
	flags := offset
	if more {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(packet[6:8], flags)
	return packet
}

// An ICMP echo request.
func bridgePinTestIcmp(source netip.Addr) []byte {
	return bridgePinTestPacket(1, source, []byte{8, 0, 0, 0, 0, 1, 0, 1})
}

// Of pairs from count sources, the first whose TCP packets pick want with the entry as it is.
func bridgePinTestPairOn(t *testing.T, table *device.BridgePinTable, entry *device.BridgeEntryState, want device.BridgeLinkId, from int) netip.Addr {
	t.Helper()
	for i := from; i < from+4096; i += 1 {
		source := bridgePinTestSource(i)
		if table.PairPinForTest(entry, bridgePinTestTcp(source, 50000, 443, false)) != 0 {
			continue
		}
		if table.Pick(entry, bridgePinTestTcp(source, 50000, 443, false)) == want {
			return source
		}
	}
	t.Fatalf("no pair picks link %d", want)
	return netip.Addr{}
}

// An entry with one link routes over it and records nothing.
func TestPinNoChoiceRecordsNothing(t *testing.T) {
	_, settings := bridgePinTestSettings(1024)
	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState(bridgePinTestLinks(7), settings)
	for i := range 100 {
		if link := table.Pick(entry, bridgePinTestUdp(bridgePinTestSource(i), 0, false)); link != 7 {
			t.Fatalf("pair %d: link %d", i, link)
		}
	}
	if table.PinnedCount() != 0 || table.WriteCountForTest() != 0 {
		t.Fatalf("%d pins, %d writes", table.PinnedCount(), table.WriteCountForTest())
	}
	empty := device.NewBridgeEntryState(nil, settings)
	if link := table.Pick(empty, bridgePinTestUdp(bridgePinTestSource(1), 0, false)); link != 0 {
		t.Fatalf("an entry with no link picked %d", link)
	}
}

// §22.7: a TCP flow idle 300 to 600 s keeps its link across a withdraw.
func TestPinTcpFlowIdleKeepsItsLinkAcrossAWithdraw(t *testing.T) {
	for _, idle := range []time.Duration{300 * time.Second, 450 * time.Second, 599 * time.Second} {
		clock, settings := bridgePinTestSettings(1024)
		table := device.NewBridgePinTable(settings)
		entry := device.NewBridgeEntryState(bridgePinTestLinks(1, 2), settings)
		source := bridgePinTestPairOn(t, table, entry, 1, 0)
		clock.Advance(idle)
		entry.Withdraw(1, clock.Now().Add(300*time.Second))
		if link := table.Pick(entry, bridgePinTestTcp(source, 50000, 443, false)); link != 1 {
			t.Fatalf("idle %v: the flow moved to %d", idle, link)
		}
		// while a new pair never takes the draining link
		for i := 5000; i < 5100; i += 1 {
			if link := table.Pick(entry, bridgePinTestTcp(bridgePinTestSource(i), 50000, 443, false)); link != 2 {
				t.Fatalf("a new pair took link %d", link)
			}
		}
	}
}

// §22.7: a long-lived flow keeps its link across an advertiser join, and through the hours after.
func TestPinLongLivedFlowKeepsItsLinkAcrossAnAdvertiserJoin(t *testing.T) {
	clock, settings := bridgePinTestSettings(1024)
	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState(bridgePinTestLinks(1, 2), settings)
	pinned := map[netip.Addr]device.BridgeLinkId{}
	for i := range 64 {
		source := bridgePinTestSource(i)
		pinned[source] = table.Pick(entry, bridgePinTestTcp(source, 50000, 443, false))
	}
	entry.Set(bridgePinTestLinks(1, 2, 3))
	for range 72 {
		clock.Advance(100 * time.Second)
		for source, want := range pinned {
			if link := table.Pick(entry, bridgePinTestTcp(source, 50000, 443, false)); link != want {
				t.Fatalf("a long-lived flow moved from %d to %d", want, link)
			}
		}
	}
	// and the joining advertiser takes new pairs
	joined := false
	for i := 1000; i < 1200 && !joined; i += 1 {
		joined = table.Pick(entry, bridgePinTestTcp(bridgePinTestSource(i), 50000, 443, false)) == 3
	}
	if !joined {
		t.Fatal("the joining advertiser took no new pair")
	}
}

// §22.7: a one-advertiser retarget drains its live flows, while a new pair's TCP connection takes the new rule at once,
// and new UDP and ICMP pairs follow the pre-change link for 5 min.
func TestPinOneAdvertiserRetarget(t *testing.T) {
	clock, settings := bridgePinTestSettings(1024)
	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState(bridgePinTestLinks(1), settings)
	live := bridgePinTestSource(1)
	liveUdp := bridgePinTestSource(2)
	if table.Pick(entry, bridgePinTestTcp(live, 50000, 443, false)) != 1 || table.Pick(entry, bridgePinTestUdp(liveUdp, 0, false)) != 1 {
		t.Fatal("the one link was not taken")
	}
	entry.Retarget(1, device.BridgeEntryLink{Link: 2, Weight: 1}, clock.Now().Add(300*time.Second))
	clock.Advance(10 * time.Second)

	if link := table.Pick(entry, bridgePinTestTcp(live, 50000, 443, false)); link != 1 {
		t.Fatalf("a live TCP flow left the draining link for %d", link)
	}
	if link := table.Pick(entry, bridgePinTestUdp(liveUdp, 0, false)); link != 1 {
		t.Fatalf("a live UDP pair left the draining link for %d", link)
	}
	// a new pair's connection takes the new rule at once, and keeps it under its own pin
	fresh := bridgePinTestSource(3)
	if link := table.Pick(entry, bridgePinTestTcp(fresh, 51000, 443, true)); link != 2 {
		t.Fatalf("a new connection took %d", link)
	}
	if link := table.Pick(entry, bridgePinTestTcp(fresh, 51000, 443, false)); link != 2 {
		t.Fatalf("a new connection's next segment took %d", link)
	}
	// so does a new connection of the live pair, pinned to the draining link
	if link := table.Pick(entry, bridgePinTestTcp(live, 52000, 443, true)); link != 2 {
		t.Fatalf("a new connection of a draining pair took %d", link)
	}
	if link := table.Pick(entry, bridgePinTestTcp(live, 50000, 443, false)); link != 1 {
		t.Fatalf("the live flow moved to %d", link)
	}
	// new UDP and ICMP pairs, which cannot be told from live ones, follow the pre-change link
	if link := table.Pick(entry, bridgePinTestUdp(bridgePinTestSource(4), 0, false)); link != 1 {
		t.Fatalf("a new UDP pair took %d in the window", link)
	}
	if link := table.Pick(entry, bridgePinTestIcmp(bridgePinTestSource(5))); link != 1 {
		t.Fatalf("a new ICMP pair took %d in the window", link)
	}
	// past 5 min the window has closed for UDP and ICMP, and the draining link's drain has ended for them
	clock.Advance(5 * time.Minute)
	if link := table.Pick(entry, bridgePinTestUdp(bridgePinTestSource(6), 0, false)); link != 2 {
		t.Fatalf("a new UDP pair took %d after the window", link)
	}
	if link := table.Pick(entry, bridgePinTestUdp(liveUdp, 0, false)); link != 2 {
		t.Fatalf("a UDP pair stayed on %d past its drain", link)
	}
	// TCP drains to 600 s
	if link := table.Pick(entry, bridgePinTestTcp(live, 50000, 443, false)); link != 1 {
		t.Fatalf("the live TCP flow moved to %d inside 600 s", link)
	}
	clock.Advance(300 * time.Second)
	if link := table.Pick(entry, bridgePinTestTcp(live, 50000, 443, false)); link != 2 {
		t.Fatalf("the live TCP flow stayed on %d past 600 s", link)
	}
}

// §22.7: a fragmented UDP datagram stays on one link, pinned or not, since every fragment carries its pair.
func TestPinFragmentedUdpDatagramStaysOnOneLink(t *testing.T) {
	for _, slotCount := range []int{1024, 4} {
		_, settings := bridgePinTestSettings(slotCount)
		table := device.NewBridgePinTable(settings)
		entry := device.NewBridgeEntryState(bridgePinTestLinks(1, 2, 3), settings)
		seen := map[device.BridgeLinkId]bool{}
		for i := range 200 {
			source := bridgePinTestSource(i)
			// the later fragments may arrive first
			last := table.Pick(entry, bridgePinTestUdp(source, 370, false))
			middle := table.Pick(entry, bridgePinTestUdp(source, 185, true))
			first := table.Pick(entry, bridgePinTestUdp(source, 0, true))
			if first == 0 || first != middle || middle != last {
				t.Fatalf("%d slots, pair %d: fragments took %d, %d and %d", slotCount, i, first, middle, last)
			}
			seen[first] = true
		}
		if len(seen) != 3 {
			t.Fatalf("%d slots: pairs spread over %d links", slotCount, len(seen))
		}
	}
}

// §22.9: a 1,024-slot table churned past 1,024 pairs routes the excess unpinned, refuses none and moves no pinned pair.
func TestPinFullTableRefusesNoneAndMovesNoPinnedPair(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := device.MobileBridgeSettings()
	settings.Clock = clock
	table := device.NewBridgePinTable(settings)
	if table.SlotCount() != 1024 {
		t.Fatalf("%d slots", table.SlotCount())
	}
	entry := device.NewBridgeEntryState(bridgePinTestLinks(1, 2, 3), settings)
	pinned := map[netip.Addr]device.BridgeLinkId{}
	for i := range 4096 {
		source := bridgePinTestSource(i)
		packet := bridgePinTestUdp(source, 0, false)
		link := table.Pick(entry, packet)
		if link == 0 {
			t.Fatalf("pair %d was refused", i)
		}
		if pin := table.PairPinForTest(entry, packet); pin != 0 {
			if pin != link {
				t.Fatalf("pair %d pinned to %d and routed to %d", i, pin, link)
			}
			pinned[source] = link
		}
	}
	if table.UnpinnedPickCount() == 0 || len(pinned) < 512 || 1024 < len(pinned) {
		t.Fatalf("%d pinned, %d unpinned picks", len(pinned), table.UnpinnedPickCount())
	}
	// an advertiser joins and weights change, which moves the unpinned and must move no pinned pair
	entry.Set([]device.BridgeEntryLink{{Link: 1, Weight: 5}, {Link: 2, Weight: 1}, {Link: 3, Weight: 1}, {Link: 4, Weight: 9}})
	clock.Advance(time.Minute)
	for source, want := range pinned {
		if link := table.Pick(entry, bridgePinTestUdp(source, 0, false)); link != want {
			t.Fatalf("a pinned pair moved from %d to %d", want, link)
		}
	}
	if pinnedCount := table.PinnedCount(); pinnedCount != len(pinned) {
		t.Fatalf("%d pins counted, %d pinned", pinnedCount, len(pinned))
	}
}

// §17.5's health row: a down link takes no new pairs while another advertiser is up and keeps its pins; with no other
// advertiser up nothing moves; and it comes back after LinkDownTimeout.
func TestPinDownMarks(t *testing.T) {
	clock, settings := bridgePinTestSettings(1024)
	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState(bridgePinTestLinks(1, 2), settings)
	source := bridgePinTestPairOn(t, table, entry, 1, 0)
	entry.MarkDown(1)
	if link := table.Pick(entry, bridgePinTestTcp(source, 50000, 443, false)); link != 1 {
		t.Fatalf("a pinned pair left its down link for %d", link)
	}
	for i := 5000; i < 5100; i += 1 {
		if link := table.Pick(entry, bridgePinTestTcp(bridgePinTestSource(i), 50000, 443, false)); link != 2 {
			t.Fatalf("a new pair took the down link %d", link)
		}
	}
	// both down: new pairs hash over both, refused nowhere
	entry.MarkDown(2)
	seen := map[device.BridgeLinkId]bool{}
	for i := 6000; i < 6100; i += 1 {
		seen[table.Pick(entry, bridgePinTestTcp(bridgePinTestSource(i), 50000, 443, false))] = true
	}
	if len(seen) != 2 || seen[0] {
		t.Fatalf("with no advertiser up, new pairs went to %v", seen)
	}
	// one advertiser, down: nothing moves
	single := device.NewBridgeEntryState(bridgePinTestLinks(9), settings)
	single.MarkDown(9)
	if link := table.Pick(single, bridgePinTestTcp(source, 50000, 443, false)); link != 9 {
		t.Fatalf("a down single link gave %d", link)
	}
	// 30 s on, link 1 takes new pairs again
	clock.Advance(settings.LinkDownTimeout)
	entry.MarkDown(2)
	for i := 7000; i < 7100; i += 1 {
		if link := table.Pick(entry, bridgePinTestTcp(bridgePinTestSource(i), 50000, 443, false)); link != 1 {
			t.Fatalf("link 1 did not come back: %d", link)
		}
	}
}

// §22.5's reset vs drain: a drain keeps a link's pinned pairs on it, and a reset drops them at once.
func TestPinResetDropsPinsAndDrainDoesNot(t *testing.T) {
	clock, settings := bridgePinTestSettings(1024)
	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState(bridgePinTestLinks(1, 2), settings)
	other := device.NewBridgeEntryState(bridgePinTestLinks(1, 2), settings)
	sources := []netip.Addr{}
	for i := 0; len(sources) < 8; {
		source := bridgePinTestPairOn(t, table, entry, 1, i)
		sources = append(sources, source)
		i = int(source.As4()[2])<<8 | int(source.As4()[3]) + 1
	}
	// a pair of the other entry on link 1, which a reset of this entry's link must leave
	otherSource := bridgePinTestPairOn(t, table, other, 1, 0)
	entry.Withdraw(1, clock.Now().Add(300*time.Second))
	clock.Advance(time.Second)
	for _, source := range sources {
		if link := table.Pick(entry, bridgePinTestTcp(source, 50000, 443, false)); link != 1 {
			t.Fatalf("a drain moved a pinned pair to %d", link)
		}
	}
	entry.Reset(1)
	if droppedCount := table.Reset(entry, 1); droppedCount != len(sources) {
		t.Fatalf("a reset dropped %d of %d pins", droppedCount, len(sources))
	}
	for _, source := range sources {
		if link := table.Pick(entry, bridgePinTestTcp(source, 50000, 443, false)); link != 2 {
			t.Fatalf("a reset left a pair on %d", link)
		}
	}
	if link := table.Pick(other, bridgePinTestTcp(otherSource, 50000, 443, false)); link != 1 {
		t.Fatalf("another entry's pin moved to %d", link)
	}
}

// §17.5's idle row: a pin ends 600 s after its pair's last packet for TCP and 5 min after for UDP; a packet before
// then keeps it.
func TestPinIdleEndsAPin(t *testing.T) {
	clock, settings := bridgePinTestSettings(1024)
	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState(bridgePinTestLinks(1, 2), settings)
	tcpPacket := bridgePinTestTcp(bridgePinTestSource(1), 50000, 443, false)
	udpPacket := bridgePinTestUdp(bridgePinTestSource(2), 0, false)
	table.Pick(entry, tcpPacket)
	table.Pick(entry, udpPacket)
	// the UDP pair sends at 299 s and 499 s, the TCP pair not again
	clock.Advance(299 * time.Second)
	table.Pick(entry, udpPacket)
	clock.Advance(200 * time.Second)
	table.Pick(entry, udpPacket)
	if table.PinnedCount() != 2 {
		t.Fatalf("%d pins before either idled", table.PinnedCount())
	}
	clock.Advance(101 * time.Second)
	if table.PairPinForTest(entry, tcpPacket) != 0 {
		t.Fatal("a TCP pin outlived 600 s idle")
	}
	if table.PairPinForTest(entry, udpPacket) == 0 {
		t.Fatal("a UDP pin seen 101 s ago ended")
	}
	clock.Advance(5 * time.Minute)
	if table.PinnedCount() != 0 {
		t.Fatalf("%d pins outlived their idle", table.PinnedCount())
	}
}

// §17.5's record row: a pin's last-seen time is written at most once a second, however many packets its pair sends.
func TestPinRecordsAtMostOncePerSecond(t *testing.T) {
	clock, settings := bridgePinTestSettings(1024)
	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState(bridgePinTestLinks(1, 2), settings)
	packet := bridgePinTestUdp(bridgePinTestSource(1), 0, false)
	table.Pick(entry, packet)
	written := table.WriteCountForTest()
	for range 1000 {
		table.Pick(entry, packet)
	}
	if table.WriteCountForTest() != written {
		t.Fatalf("%d writes within a second", table.WriteCountForTest()-written)
	}
	clock.Advance(time.Second)
	for range 1000 {
		table.Pick(entry, packet)
	}
	if table.WriteCountForTest() != written+1 {
		t.Fatalf("%d writes a second on", table.WriteCountForTest()-written)
	}
}

// A collision compares the whole key: in a table of one run, pairs of two entries and one pair of both keep their own
// links, and a pair finding the run full routes unpinned rather than onto another pair's link.
func TestPinCollisionComparesTheWholeKey(t *testing.T) {
	clock, settings := bridgePinTestSettings(4)
	table := device.NewBridgePinTable(settings)
	if table.SlotCount() != 4 {
		t.Fatalf("%d slots", table.SlotCount())
	}
	// windows send pinless pairs to a known link: 1 for the first entry, 3 for the second
	first := device.NewBridgeEntryState(bridgePinTestLinks(1), settings)
	first.Set(bridgePinTestLinks(1, 2))
	second := device.NewBridgeEntryState(bridgePinTestLinks(3), settings)
	second.Set(bridgePinTestLinks(3, 4))
	shared := bridgePinTestUdp(bridgePinTestSource(1), 0, false)
	if table.Pick(first, shared) != 1 || table.Pick(second, shared) != 3 {
		t.Fatal("the windows did not pin")
	}
	// past the windows, with the pair sending meanwhile, each pin still answers for its own entry alone
	clock.Advance(4 * time.Minute)
	if table.Pick(first, shared) != 1 || table.Pick(second, shared) != 3 {
		t.Fatal("a pin answered for another entry's pair")
	}
	clock.Advance(2 * time.Minute)
	for range 3 {
		if table.Pick(first, shared) != 1 || table.Pick(second, shared) != 3 {
			t.Fatal("a pin answered for another entry's pair")
		}
	}
	// two more pairs fill the run; a fifth routes unpinned, by its own hash
	table.Pick(first, bridgePinTestUdp(bridgePinTestSource(2), 0, false))
	table.Pick(first, bridgePinTestUdp(bridgePinTestSource(3), 0, false))
	unpinned := table.UnpinnedPickCount()
	overflow := bridgePinTestUdp(bridgePinTestSource(4), 0, false)
	link := table.Pick(first, overflow)
	if link == 0 || table.UnpinnedPickCount() != unpinned+1 || table.PairPinForTest(first, overflow) != 0 {
		t.Fatalf("an overflowing pair: link %d, %d unpinned picks", link, table.UnpinnedPickCount()-unpinned)
	}
	if table.Pick(first, shared) != 1 || table.Pick(second, shared) != 3 {
		t.Fatal("an overflowing pair disturbed a pin")
	}
}

// D-BRIDGE-9: rendezvous splits new pairs by weight.
func TestPinRendezvousFollowsWeights(t *testing.T) {
	_, settings := bridgePinTestSettings(16 * 1024)
	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState([]device.BridgeEntryLink{{Link: 1, Weight: 1}, {Link: 2, Weight: 3}}, settings)
	counts := map[device.BridgeLinkId]int{}
	for i := range 4000 {
		counts[table.Pick(entry, bridgePinTestUdp(bridgePinTestSource(i), 0, false))] += 1
	}
	if counts[2] < 2800 || 3200 < counts[2] || counts[1]+counts[2] != 4000 {
		t.Fatalf("weights 1 and 3 split 4,000 pairs as %v", counts)
	}
}

// -race: picks on many goroutines while the entry is swapped, marked and reset under them always name a link the
// entry held.
func TestPinConcurrentPicksDuringEntrySwaps(t *testing.T) {
	_, settings := bridgePinTestSettings(256)
	table := device.NewBridgePinTable(settings)
	entry := device.NewBridgeEntryState(bridgePinTestLinks(1, 2, 3), settings)
	var wait sync.WaitGroup
	done := make(chan struct{})
	failures := make(chan string, 8)
	for worker := range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for i := 0; ; i += 1 {
				select {
				case <-done:
					return
				default:
				}
				source := bridgePinTestSource(worker*1000 + i%500)
				packets := [][]byte{
					bridgePinTestUdp(source, 0, false),
					bridgePinTestTcp(source, uint16(40000+i%7), 443, i%3 == 0),
					bridgePinTestIcmp(source),
				}
				for _, packet := range packets {
					link := table.Pick(entry, packet)
					if link < 1 || 6 < link {
						select {
						case failures <- "a pick named a link the entry never held":
						default:
						}
						return
					}
				}
			}
		}()
	}
	edits := []func(){
		func() { entry.Set(bridgePinTestLinks(1, 2, 3, 4)) },
		func() { entry.MarkDown(2) },
		func() { entry.Withdraw(3, time.Time{}) },
		func() { entry.Retarget(1, device.BridgeEntryLink{Link: 5, Weight: 2}, time.Time{}) },
		func() { entry.Reset(4); table.Reset(entry, 4) },
		func() { entry.Set(bridgePinTestLinks(5, 6)) },
		func() { entry.Set(bridgePinTestLinks(1, 2, 3)) },
	}
	for round := range 200 {
		edits[round%len(edits)]()
	}
	close(done)
	wait.Wait()
	select {
	case failure := <-failures:
		t.Fatal(failure)
	default:
	}
}
