package tlsedgeservice

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// Caps a test can count against: settings with a root, blocks and small bounds where a test says so.
func testCaps(blocks int) (*TlsEdgeCaps, *testManualClock) {
	settings := DefaultTlsEdgeSettings()
	settings.Root = testRoot
	settings.Blocks = blocks
	clock := newTestManualClock()
	return NewTlsEdgeCaps(settings, clock, NewTlsVisitorKeys(clock)), clock
}

// Limits with every cap none but the ones a test sets.
func testUncappedLimits() *TlsEndpointLimits {
	return &TlsEndpointLimits{
		EndpointConcurrent:       -1,
		EndpointNewPerS:          -1,
		EndpointMbitPerS:         -1,
		VisitorConcurrent:        -1,
		VisitorNewPerS:           -1,
		VisitorAggregateMultiple: -1,
	}
}

func testTarget(networkId sidecar.Id, host string) *TlsEdgeTarget {
	return &TlsEdgeTarget{NetworkId: networkId, Label: "m4testlabl", Host: host, Port: 443, Name: "tls/443/" + host}
}

// One admission, process and caps, or the refusal.
func testAdmit(caps *TlsEdgeCaps, visitor string, target *TlsEdgeTarget, limits *TlsEndpointLimits) (*TlsCapHold, TlsCapRefusal) {
	hold, refusal := caps.AdmitProcess()
	if refusal != TlsCapRefusalNone {
		return nil, refusal
	}
	if refusal := caps.Admit(hold, netip.MustParseAddr(visitor), target, limits); refusal != TlsCapRefusalNone {
		caps.Release(hold)
		return nil, refusal
	}
	return hold, TlsCapRefusalNone
}

// max_connections at its limit and one past, and a released slot taken again.
func TestTlsEdgeCapsProcessCap(t *testing.T) {
	caps, _ := testCaps(1)
	caps.settings.MaxConnectionCount = 3
	holds := []*TlsCapHold{}
	for range 3 {
		hold, refusal := caps.AdmitProcess()
		if refusal != TlsCapRefusalNone {
			t.Fatalf("refused %q under the cap", refusal)
		}
		holds = append(holds, hold)
	}
	if _, refusal := caps.AdmitProcess(); refusal != TlsCapRefusalProcess {
		t.Fatalf("one past the cap: %q", refusal)
	}
	caps.Release(holds[0])
	caps.Release(holds[0])
	if caps.ConnectionCount() != 2 {
		t.Fatalf("a second release moved the count to %d", caps.ConnectionCount())
	}
	if _, refusal := caps.AdmitProcess(); refusal != TlsCapRefusalNone {
		t.Fatalf("a released slot was refused: %q", refusal)
	}
}

// Visitor concurrency per /64 at its limit and one past, then the /48 aggregate at 4x, and the same on
// IPv4 per /32 and /24.
func TestTlsEdgeCapsVisitorConcurrent(t *testing.T) {
	for _, family := range []struct {
		name      string
		visitor   func(prefix int, host int) string
		prefixCap int
	}{
		{name: "IPv6", visitor: func(prefix int, host int) string { return fmt.Sprintf("2001:db8:7:%x::%x", prefix, host+1) }},
		{name: "IPv4", visitor: func(prefix int, host int) string { return fmt.Sprintf("203.0.113.%d", prefix) }},
	} {
		caps, _ := testCaps(1)
		limits := testUncappedLimits()
		limits.VisitorConcurrent = 4
		limits.VisitorAggregateMultiple = 4
		target := testTarget(sidecar.NewId(), "blog")
		for index := range 4 {
			if _, refusal := testAdmit(caps, family.visitor(1, index), target, limits); refusal != TlsCapRefusalNone {
				t.Fatalf("%s: refused %q at %d", family.name, refusal, index)
			}
		}
		if _, refusal := testAdmit(caps, family.visitor(1, 4), target, limits); refusal != TlsCapRefusalVisitor {
			t.Fatalf("%s: one past the visitor cap: %q", family.name, refusal)
		}
		// three more prefixes inside the aggregate fill it to 16
		for prefix := 2; prefix <= 4; prefix += 1 {
			for index := range 4 {
				if _, refusal := testAdmit(caps, family.visitor(prefix, index), target, limits); refusal != TlsCapRefusalNone {
					t.Fatalf("%s: refused %q at prefix %d", family.name, refusal, prefix)
				}
			}
		}
		if _, refusal := testAdmit(caps, family.visitor(5, 0), target, limits); refusal != TlsCapRefusalVisitorAggregate {
			t.Fatalf("%s: one past the aggregate: %q", family.name, refusal)
		}
	}
}

// New connections per visitor at 20 a second and the aggregate at 80: at the limit, one past, and one
// token back after 50 ms.
func TestTlsEdgeCapsVisitorRate(t *testing.T) {
	caps, clock := testCaps(1)
	limits := testUncappedLimits()
	limits.VisitorNewPerS = 20
	limits.VisitorAggregateMultiple = 4
	target := testTarget(sidecar.NewId(), "blog")
	admitAndRelease := func(visitor string) TlsCapRefusal {
		hold, refusal := testAdmit(caps, visitor, target, limits)
		caps.Release(hold)
		return refusal
	}
	for index := range 20 {
		if refusal := admitAndRelease("2001:db8:9:1::1"); refusal != TlsCapRefusalNone {
			t.Fatalf("refused %q at %d", refusal, index)
		}
	}
	if refusal := admitAndRelease("2001:db8:9:1::1"); refusal != TlsCapRefusalVisitorRate {
		t.Fatalf("one past the rate: %q", refusal)
	}
	clock.Advance(50 * time.Millisecond)
	if refusal := admitAndRelease("2001:db8:9:1::1"); refusal != TlsCapRefusalNone {
		t.Fatalf("a refilled token was refused: %q", refusal)
	}
	// the aggregate's 80 less 20, plus 4 refilled in the 50 ms, less 1: 63 left for other /64s
	for prefix := 2; prefix <= 4; prefix += 1 {
		for range 20 {
			if refusal := admitAndRelease(fmt.Sprintf("2001:db8:9:%d::1", prefix)); refusal != TlsCapRefusalNone {
				t.Fatalf("refused %q in prefix %d", refusal, prefix)
			}
		}
	}
	for index := range 3 {
		if refusal := admitAndRelease("2001:db8:9:5::1"); refusal != TlsCapRefusalNone {
			t.Fatalf("refused %q at the aggregate's last %d", refusal, index)
		}
	}
	if refusal := admitAndRelease("2001:db8:9:5::1"); refusal != TlsCapRefusalVisitorAggregateRate {
		t.Fatalf("one past the aggregate rate: %q", refusal)
	}
}

// cap ÷ blocks rounds up and never below 1, and none and not-included pass through.
func TestTlsBlockShareRounding(t *testing.T) {
	for _, c := range []struct {
		fleetCap int64
		blocks   int
		share    int64
	}{
		{fleetCap: 256, blocks: 4, share: 64},
		{fleetCap: 2048, blocks: 3, share: 683},
		{fleetCap: 8192, blocks: 1, share: 8192},
		{fleetCap: 1, blocks: 4, share: 1},
		{fleetCap: 5, blocks: 4, share: 2},
		{fleetCap: -1, blocks: 4, share: -1},
		{fleetCap: 0, blocks: 4, share: 0},
	} {
		if share := tlsBlockShare(c.fleetCap, c.blocks); share != c.share {
			t.Errorf("%d ÷ %d: %d", c.fleetCap, c.blocks, share)
		}
	}
}

// Endpoint concurrency at its share in this process and one past; the new-connection bucket at the
// full rate, not divided; another endpoint unaffected.
func TestTlsEdgeCapsEndpoint(t *testing.T) {
	caps, _ := testCaps(3)
	limits := testUncappedLimits()
	limits.EndpointConcurrent = 2048
	networkId := sidecar.NewId()
	target := testTarget(networkId, "blog")
	for index := range 683 {
		if _, refusal := testAdmit(caps, fmt.Sprintf("2001:db8:a:%x::1", index), target, limits); refusal != TlsCapRefusalNone {
			t.Fatalf("refused %q at %d", refusal, index)
		}
	}
	if _, refusal := testAdmit(caps, "2001:db8:b::1", target, limits); refusal != TlsCapRefusalEndpoint {
		t.Fatalf("one past the share: %q", refusal)
	}
	if _, refusal := testAdmit(caps, "2001:db8:b::1", testTarget(networkId, "shop"), limits); refusal != TlsCapRefusalNone {
		t.Fatalf("another host was refused: %q", refusal)
	}
	other := testTarget(networkId, "blog")
	other.Port = 8443
	if _, refusal := testAdmit(caps, "2001:db8:b::1", other, limits); refusal != TlsCapRefusalNone {
		t.Fatalf("another port was refused: %q", refusal)
	}

	rateCaps, _ := testCaps(3)
	rateLimits := testUncappedLimits()
	rateLimits.EndpointNewPerS = 50
	for index := range 50 {
		hold, refusal := testAdmit(rateCaps, fmt.Sprintf("2001:db8:c:%x::1", index), target, rateLimits)
		if refusal != TlsCapRefusalNone {
			t.Fatalf("refused %q at %d of the rate", refusal, index)
		}
		rateCaps.Release(hold)
	}
	if _, refusal := testAdmit(rateCaps, "2001:db8:d::1", target, rateLimits); refusal != TlsCapRefusalEndpointRate {
		t.Fatalf("one past the rate: %q", refusal)
	}
}

// A cap of 0 is not included and refuses, -1 is none and admits past any count, and a refusal counts
// nothing anywhere.
func TestTlsEdgeCapsZeroRefusesAndNoneAdmits(t *testing.T) {
	target := testTarget(sidecar.NewId(), "blog")
	for _, zeroed := range []func(limits *TlsEndpointLimits){
		func(limits *TlsEndpointLimits) { limits.EndpointConcurrent = 0 },
		func(limits *TlsEndpointLimits) { limits.EndpointNewPerS = 0 },
		func(limits *TlsEndpointLimits) { limits.EndpointMbitPerS = 0 },
		func(limits *TlsEndpointLimits) { limits.VisitorConcurrent = 0 },
		func(limits *TlsEndpointLimits) { limits.VisitorNewPerS = 0 },
		func(limits *TlsEndpointLimits) { limits.VisitorAggregateMultiple = 0 },
	} {
		caps, _ := testCaps(1)
		limits := testUncappedLimits()
		zeroed(limits)
		if _, refusal := testAdmit(caps, "192.0.2.10", target, limits); refusal == TlsCapRefusalNone {
			t.Fatalf("a zero cap admitted: %+v", limits)
		}
		if len(caps.visitorCounts) != 0 || len(caps.endpointOpens) != 0 || caps.ConnectionCount() != 0 {
			t.Fatalf("a refusal counted something: %+v", limits)
		}
	}
	caps, _ := testCaps(1)
	for index := range 1000 {
		if _, refusal := testAdmit(caps, "192.0.2.10", target, testUncappedLimits()); refusal != TlsCapRefusalNone {
			t.Fatalf("none refused %q at %d", refusal, index)
		}
	}
}

// A visitor key rotation drops every visitor entry, so a visitor at its cap is admitted again on the new
// day, and the releases of yesterday's connections leave today's counts alone.
func TestTlsEdgeCapsRotationDropsState(t *testing.T) {
	caps, clock := testCaps(1)
	limits := testUncappedLimits()
	limits.VisitorConcurrent = 2
	limits.VisitorAggregateMultiple = 1
	target := testTarget(sidecar.NewId(), "blog")
	yesterday := []*TlsCapHold{}
	for range 2 {
		hold, refusal := testAdmit(caps, "192.0.2.20", target, limits)
		if refusal != TlsCapRefusalNone {
			t.Fatal(refusal)
		}
		yesterday = append(yesterday, hold)
	}
	if _, refusal := testAdmit(caps, "192.0.2.20", target, limits); refusal != TlsCapRefusalVisitor {
		t.Fatalf("one past the cap: %q", refusal)
	}
	clock.Advance(12 * time.Hour)
	today, refusal := testAdmit(caps, "192.0.2.20", target, limits)
	if refusal != TlsCapRefusalNone {
		t.Fatalf("a new day kept yesterday's count: %q", refusal)
	}
	for _, hold := range yesterday {
		caps.Release(hold)
	}
	for key, count := range caps.visitorCounts {
		if count != 1 {
			t.Fatalf("today's count %d under %x after yesterday's releases", count, key)
		}
	}
	caps.Release(today)
	if len(caps.visitorCounts) != 0 || len(caps.aggregateCounts) != 0 || caps.ConnectionCount() != 0 {
		t.Fatalf("counts left: %v, %v, %d", caps.visitorCounts, caps.aggregateCounts, caps.ConnectionCount())
	}
}

// A scan of distinct visitors and hosts holds no more token buckets than the bounds.
func TestTlsEdgeCapsBucketsBounded(t *testing.T) {
	caps, _ := testCaps(1)
	caps.settings.VisitorRateMaxCount = 8
	caps.settings.EndpointRateMaxCount = 8
	caps.visitorRates = newTlsRateBuckets[[tlsVisitorHashByteCount]byte](8)
	caps.aggregateRates = newTlsRateBuckets[[tlsVisitorHashByteCount]byte](8)
	caps.endpointRates = newTlsRateBuckets[tlsEndpointKey](8)
	limits := testUncappedLimits()
	limits.VisitorNewPerS = 20
	limits.VisitorAggregateMultiple = 4
	limits.EndpointNewPerS = 50
	networkId := sidecar.NewId()
	for index := range 1000 {
		hold, refusal := testAdmit(caps, fmt.Sprintf("2001:db8:%x::1", index), testTarget(networkId, fmt.Sprintf("h%d", index)), limits)
		if refusal != TlsCapRefusalNone {
			t.Fatalf("refused %q at %d", refusal, index)
		}
		caps.Release(hold)
	}
	if 8 < len(caps.visitorRates.buckets) || 8 < len(caps.aggregateRates.buckets) || 8 < len(caps.endpointRates.buckets) {
		t.Fatalf("buckets past the bound: %d, %d, %d", len(caps.visitorRates.buckets), len(caps.aggregateRates.buckets), len(caps.endpointRates.buckets))
	}
	if caps.EvictedCount() == 0 {
		t.Fatal("no eviction was counted")
	}
}

// What a test's visitors could leave behind in memory: each address's bytes and its /24 or /48's.
func testRawAddressBytes(visitors []string) [][]byte {
	raws := [][]byte{}
	for _, text := range visitors {
		addr := netip.MustParseAddr(text).Unmap()
		raws = append(raws, addr.AsSlice())
		visitorBits, aggregateBits := 64, 48
		if addr.Is4() {
			visitorBits, aggregateBits = 32, 24
		}
		for _, bits := range []int{visitorBits, aggregateBits} {
			prefix, _ := addr.Prefix(bits)
			raws = append(raws, prefix.Addr().AsSlice()[:bits/8])
		}
	}
	return raws
}

// Walks value and everything it reaches, calling found for each value whose type or bytes look like an
// address.
func testFindAddresses(value reflect.Value, raws [][]byte, seen map[uintptr]bool, found func(what string)) {
	addrType := reflect.TypeOf(netip.Addr{})
	prefixType := reflect.TypeOf(netip.Prefix{})
	ipType := reflect.TypeOf(net.IP{})
	if !value.IsValid() {
		return
	}
	switch value.Type() {
	case addrType, prefixType, ipType:
		found(value.Type().String())
		return
	}
	switch value.Kind() {
	case reflect.Pointer:
		if value.IsNil() || seen[value.Pointer()] {
			return
		}
		seen[value.Pointer()] = true
		testFindAddresses(value.Elem(), raws, seen, found)
	case reflect.Interface:
		testFindAddresses(value.Elem(), raws, seen, found)
	case reflect.Struct:
		for index := range value.NumField() {
			testFindAddresses(value.Field(index), raws, seen, found)
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			testFindAddresses(iterator.Key(), raws, seen, found)
			testFindAddresses(iterator.Value(), raws, seen, found)
		}
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			data := make([]byte, value.Len())
			for index := range value.Len() {
				data[index] = byte(value.Index(index).Uint())
			}
			for _, raw := range raws {
				if 3 <= len(raw) && len(raw) <= len(data) && string(data) == string(raw) {
					found(fmt.Sprintf("raw address bytes %x", raw))
				}
			}
			return
		}
		for index := range value.Len() {
			testFindAddresses(value.Index(index), raws, seen, found)
		}
	}
}

// No map or field of the caps, the visitor keys or a hold holds an address, its prefixes or their bytes:
// only keyed hashes (tls-2, I-13).
func TestTlsEdgeCapsHoldNoRawAddress(t *testing.T) {
	caps, _ := testCaps(1)
	limits := DefaultColdTlsEndpointLimits()
	visitors := []string{"192.0.2.33", "198.51.100.44", "2001:db8:5:6::7", "::ffff:203.0.113.9"}
	holds := []*TlsCapHold{}
	for index, visitor := range visitors {
		hold, refusal := testAdmit(caps, visitor, testTarget(sidecar.NewId(), fmt.Sprintf("h%d", index)), limits)
		if refusal != TlsCapRefusalNone {
			t.Fatal(refusal)
		}
		holds = append(holds, hold)
	}
	raws := testRawAddressBytes(visitors)
	findings := []string{}
	found := func(what string) {
		findings = append(findings, what)
	}
	testFindAddresses(reflect.ValueOf(caps), raws, map[uintptr]bool{}, found)
	testFindAddresses(reflect.ValueOf(holds), raws, map[uintptr]bool{}, found)
	if 0 < len(findings) {
		t.Fatalf("addresses in the caps' state: %v", findings)
	}
}

// The bandwidth bucket: full at the start, a draw past it waits for its debt, and the wait clears as time
// passes; a rate of none never waits.
func TestTlsBandwidthBucket(t *testing.T) {
	start := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	bucket := newTlsBandwidthBucket(1000, time.Second, start)
	if wait := bucket.Draw(1000, start); wait != 0 {
		t.Fatalf("a full bucket waited %v", wait)
	}
	if wait := bucket.Draw(500, start); wait != 500*time.Millisecond {
		t.Fatalf("a draw into debt waits %v", wait)
	}
	if wait := bucket.Draw(0, start.Add(500*time.Millisecond)); wait != 0 {
		t.Fatalf("the debt did not clear: %v", wait)
	}
	if wait := bucket.Draw(2000, start.Add(10*time.Second)); wait != time.Second {
		t.Fatalf("the burst held more than a second: %v", wait)
	}
	none := newTlsBandwidthBucket(0, time.Second, start)
	if wait := none.Draw(1<<30, start); wait != 0 {
		t.Fatalf("none waited %v", wait)
	}
}

// The endpoint's connections share one bucket at the process's share of its rate, and it goes with the
// last of them.
func TestTlsEdgeCapsBandwidthShared(t *testing.T) {
	caps, _ := testCaps(4)
	limits := testUncappedLimits()
	limits.EndpointMbitPerS = 20
	target := testTarget(sidecar.NewId(), "blog")
	first, _ := testAdmit(caps, "192.0.2.1", target, limits)
	second, _ := testAdmit(caps, "192.0.2.2", target, limits)
	if first.Bandwidth() == nil || first.Bandwidth() != second.Bandwidth() {
		t.Fatal("an endpoint's connections drew on two buckets")
	}
	if rate := first.Bandwidth().Rate(); rate != 20*1000*1000/8/4 {
		t.Fatalf("rate %d", rate)
	}
	caps.Release(first)
	caps.Release(second)
	if len(caps.endpointOpens) != 0 {
		t.Fatal("the bucket outlived its endpoint's connections")
	}
	unlimited, _ := testAdmit(caps, "192.0.2.3", target, testUncappedLimits())
	if unlimited.Bandwidth() != nil {
		t.Fatal("bandwidth none drew on a bucket")
	}
}
