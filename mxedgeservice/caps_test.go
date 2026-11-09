package mxedgeservice_test

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
)

// Network ids, by a number that fills their first byte.
func testNetworkId(number byte) sidecar.Id {
	return sidecar.Id{number}
}

// Admits sender, which must pass.
func expectAdmit(t *testing.T, caps *mxedgeservice.Caps, sender string) *mxedgeservice.CapHold {
	t.Helper()
	hold, refusal := caps.Admit(netip.MustParseAddr(sender))
	if refusal != mxedgeservice.CapRefusalNone {
		t.Fatalf("%s refused by %s", sender, refusal)
	}
	return hold
}

// Admits sender, which must be refused by want and count nothing.
func expectRefused(t *testing.T, caps *mxedgeservice.Caps, sender string, want mxedgeservice.CapRefusal) {
	t.Helper()
	sessionCount, entryCount := caps.State()
	hold, refusal := caps.Admit(netip.MustParseAddr(sender))
	if hold != nil || refusal != want {
		t.Fatalf("%s: hold %v, refusal %q, want %q", sender, hold, refusal, want)
	}
	// a refused session counts nothing
	if nextSessionCount, nextEntryCount := caps.State(); nextSessionCount != sessionCount || nextEntryCount != entryCount {
		t.Fatalf("%s: a refusal moved the counters from %d, %d to %d, %d", sender, sessionCount, entryCount, nextSessionCount, nextEntryCount)
	}
}

func TestSenderPrefixesArePer64And48OrPer32And24(t *testing.T) {
	for _, c := range []struct {
		sender        string
		wantSender    string
		wantAggregate string
	}{
		{sender: "203.0.113.9", wantSender: "203.0.113.9/32", wantAggregate: "203.0.113.0/24"},
		{sender: "::ffff:203.0.113.9", wantSender: "203.0.113.9/32", wantAggregate: "203.0.113.0/24"},
		{sender: "2001:db8:1:2:3:4:5:6", wantSender: "2001:db8:1:2::/64", wantAggregate: "2001:db8:1::/48"},
		{sender: "2001:db8:1:2:3:4:5:6%eth0", wantSender: "2001:db8:1:2::/64", wantAggregate: "2001:db8:1::/48"},
	} {
		senderPrefix, aggregatePrefix := mxedgeservice.SenderPrefixes(netip.MustParseAddr(c.sender))
		if senderPrefix.String() != c.wantSender || aggregatePrefix.String() != c.wantAggregate {
			t.Errorf("%s: %s and %s", c.sender, senderPrefix, aggregatePrefix)
		}
	}
}

// One IPv4 host, then one /64: the cap, one past it, and room again after a release.
func TestSenderCapHoldsAtItsLimit(t *testing.T) {
	for _, sender := range []string{"203.0.113.9", "2001:db8:1:2::9"} {
		settings := testSettings()
		caps := mxedgeservice.NewCaps(settings)
		var holds []*mxedgeservice.CapHold
		for range settings.SenderSessionCount {
			holds = append(holds, expectAdmit(t, caps, sender))
		}
		expectRefused(t, caps, sender, mxedgeservice.CapRefusalSender)
		caps.Release(holds[0])
		expectAdmit(t, caps, sender)
		expectRefused(t, caps, sender, mxedgeservice.CapRefusalSender)
	}
}

func TestAddressesInOne64ShareTheCap(t *testing.T) {
	settings := testSettings()
	caps := mxedgeservice.NewCaps(settings)
	for i := range settings.SenderSessionCount {
		expectAdmit(t, caps, fmt.Sprintf("2001:db8:1:2::%x", i+1))
	}
	expectRefused(t, caps, "2001:db8:1:2:ffff::1", mxedgeservice.CapRefusalSender)
	expectAdmit(t, caps, "2001:db8:1:3::1")
}

func TestAggregateCapHoldsAcrossSenders(t *testing.T) {
	for _, c := range []struct {
		name    string
		sender  func(i int) string
		outside string
	}{
		{
			name:    "a /24",
			sender:  func(i int) string { return fmt.Sprintf("203.0.113.%d", i+1) },
			outside: "203.0.114.1",
		},
		{
			name:    "a /48",
			sender:  func(i int) string { return fmt.Sprintf("2001:db8:1:%x::1", i+1) },
			outside: "2001:db8:2::1",
		},
	} {
		settings := testSettings()
		caps := mxedgeservice.NewCaps(settings)
		var holds []*mxedgeservice.CapHold
		for i := range settings.SenderAggregateSessionCount {
			holds = append(holds, expectAdmit(t, caps, c.sender(i)))
		}
		expectRefused(t, caps, c.sender(settings.SenderAggregateSessionCount), mxedgeservice.CapRefusalSenderAggregate)
		expectAdmit(t, caps, c.outside)
		caps.Release(holds[0])
		expectAdmit(t, caps, c.sender(settings.SenderAggregateSessionCount))
	}
}

func TestProcessCapHoldsAcrossAllSenders(t *testing.T) {
	settings := testSettings()
	settings.ProcessSessionCount = 3
	caps := mxedgeservice.NewCaps(settings)
	first := expectAdmit(t, caps, "192.0.2.1")
	expectAdmit(t, caps, "198.51.100.1")
	expectAdmit(t, caps, "2001:db8:1::1")
	expectRefused(t, caps, "203.0.113.1", mxedgeservice.CapRefusalProcess)
	caps.Release(first)
	expectAdmit(t, caps, "203.0.113.1")
}

// An IPv4-mapped peer is the same sender as its IPv4 form, not a second allowance.
func TestMappedAddressCountsAsIpv4(t *testing.T) {
	settings := testSettings()
	caps := mxedgeservice.NewCaps(settings)
	for i := range settings.SenderSessionCount {
		if i%2 == 0 {
			expectAdmit(t, caps, "203.0.113.9")
		} else {
			expectAdmit(t, caps, "::ffff:203.0.113.9")
		}
	}
	expectRefused(t, caps, "203.0.113.9", mxedgeservice.CapRefusalSender)
	expectRefused(t, caps, "::ffff:203.0.113.9", mxedgeservice.CapRefusalSender)
}

// §15.4's 2 sessions per sender /24 per network.
func TestNetworkSenderCapHoldsPerAggregatePerNetwork(t *testing.T) {
	settings := testSettings()
	caps := mxedgeservice.NewCaps(settings)
	network := testNetworkId(1)
	var holds []*mxedgeservice.CapHold
	for i := range settings.NetworkSenderSessionCount {
		hold := expectAdmit(t, caps, fmt.Sprintf("203.0.113.%d", i+1))
		if refusal := caps.AdmitNetwork(hold, network); refusal != mxedgeservice.CapRefusalNone {
			t.Fatalf("refused by %s", refusal)
		}
		holds = append(holds, hold)
	}
	third := expectAdmit(t, caps, "203.0.113.100")
	if refusal := caps.AdmitNetwork(third, network); refusal != mxedgeservice.CapRefusalNetworkSender {
		t.Errorf("third got %q", refusal)
	}
	// the same /24 at another network, and another /24 at this one, are other cells
	if refusal := caps.AdmitNetwork(third, testNetworkId(2)); refusal != mxedgeservice.CapRefusalNone {
		t.Errorf("another network got %q", refusal)
	}
	outside := expectAdmit(t, caps, "203.0.114.1")
	if refusal := caps.AdmitNetwork(outside, network); refusal != mxedgeservice.CapRefusalNone {
		t.Errorf("another /24 got %q", refusal)
	}
	caps.Release(holds[0])
	again := expectAdmit(t, caps, "203.0.113.101")
	if refusal := caps.AdmitNetwork(again, network); refusal != mxedgeservice.CapRefusalNone {
		t.Errorf("after a release got %q", refusal)
	}
}

func TestNetworkSenderCapCountsA48ForIpv6(t *testing.T) {
	settings := testSettings()
	caps := mxedgeservice.NewCaps(settings)
	network := testNetworkId(1)
	for i := range settings.NetworkSenderSessionCount {
		hold := expectAdmit(t, caps, fmt.Sprintf("2001:db8:1:%x::1", i+1))
		if refusal := caps.AdmitNetwork(hold, network); refusal != mxedgeservice.CapRefusalNone {
			t.Fatalf("refused by %s", refusal)
		}
	}
	hold := expectAdmit(t, caps, "2001:db8:1:ffff::1")
	if refusal := caps.AdmitNetwork(hold, network); refusal != mxedgeservice.CapRefusalNetworkSender {
		t.Errorf("got %q", refusal)
	}
}

func TestNetworkCapHoldsAcrossSenders(t *testing.T) {
	settings := testSettings()
	settings.NetworkSessionCount = 3
	caps := mxedgeservice.NewCaps(settings)
	network := testNetworkId(1)
	var holds []*mxedgeservice.CapHold
	for i := range settings.NetworkSessionCount {
		hold := expectAdmit(t, caps, fmt.Sprintf("192.0.2.%d", i+1))
		// each from its own /24, to stay off the cap above
		hold = func() *mxedgeservice.CapHold {
			caps.Release(hold)
			return expectAdmit(t, caps, fmt.Sprintf("198.51.%d.1", 100+i))
		}()
		if refusal := caps.AdmitNetwork(hold, network); refusal != mxedgeservice.CapRefusalNone {
			t.Fatalf("refused by %s", refusal)
		}
		holds = append(holds, hold)
	}
	over := expectAdmit(t, caps, "203.0.113.1")
	if refusal := caps.AdmitNetwork(over, network); refusal != mxedgeservice.CapRefusalNetwork {
		t.Errorf("got %q", refusal)
	}
	caps.Release(holds[0])
	if refusal := caps.AdmitNetwork(over, network); refusal != mxedgeservice.CapRefusalNone {
		t.Errorf("after a release got %q", refusal)
	}
}

// A refusal leaves a session free to name no network and be released whole.
func TestRefusedNetworkLeavesNothingToRelease(t *testing.T) {
	settings := testSettings()
	settings.NetworkSessionCount = 1
	caps := mxedgeservice.NewCaps(settings)
	first := expectAdmit(t, caps, "192.0.2.1")
	if refusal := caps.AdmitNetwork(first, testNetworkId(1)); refusal != mxedgeservice.CapRefusalNone {
		t.Fatalf("refused by %s", refusal)
	}
	second := expectAdmit(t, caps, "198.51.100.1")
	if refusal := caps.AdmitNetwork(second, testNetworkId(1)); refusal != mxedgeservice.CapRefusalNetwork {
		t.Fatalf("got %q", refusal)
	}
	caps.Release(second)
	caps.Release(first)
	if sessionCount, entryCount := caps.State(); sessionCount != 0 || entryCount != 0 {
		t.Errorf("left %d sessions and %d entries", sessionCount, entryCount)
	}
}

func TestSessionNamesOneNetwork(t *testing.T) {
	caps := mxedgeservice.NewCaps(testSettings())
	hold := expectAdmit(t, caps, "203.0.113.9")
	if refusal := caps.AdmitNetwork(hold, testNetworkId(1)); refusal != mxedgeservice.CapRefusalNone {
		t.Fatalf("refused by %s", refusal)
	}
	if refusal := caps.AdmitNetwork(hold, testNetworkId(2)); refusal != mxedgeservice.CapRefusalNetwork {
		t.Errorf("a second network got %q", refusal)
	}
	caps.Release(hold)
	if sessionCount, entryCount := caps.State(); sessionCount != 0 || entryCount != 0 {
		t.Errorf("left %d sessions and %d entries", sessionCount, entryCount)
	}
}

func TestReleasedHoldNamesNoNetwork(t *testing.T) {
	caps := mxedgeservice.NewCaps(testSettings())
	hold := expectAdmit(t, caps, "203.0.113.9")
	caps.Release(hold)
	if refusal := caps.AdmitNetwork(hold, testNetworkId(1)); refusal != mxedgeservice.CapRefusalNetwork {
		t.Errorf("got %q", refusal)
	}
	if sessionCount, entryCount := caps.State(); sessionCount != 0 || entryCount != 0 {
		t.Errorf("left %d sessions and %d entries", sessionCount, entryCount)
	}
}

// A second release would otherwise free a place another session holds.
func TestSecondReleaseDoesNothing(t *testing.T) {
	settings := testSettings()
	settings.SenderSessionCount = 1
	caps := mxedgeservice.NewCaps(settings)
	hold := expectAdmit(t, caps, "203.0.113.9")
	caps.Release(hold)
	expectAdmit(t, caps, "203.0.113.9")
	caps.Release(hold)
	expectRefused(t, caps, "203.0.113.9", mxedgeservice.CapRefusalSender)
}

// A scan of distinct senders leaves nothing behind, and an entry lives only as long as its session.
func TestCapsHoldOnlyWhatIsConnected(t *testing.T) {
	caps := mxedgeservice.NewCaps(testSettings())
	for i := range 4096 {
		hold := expectAdmit(t, caps, fmt.Sprintf("2001:db8:%x:%x::1", i/256+1, i%256+1))
		if refusal := caps.AdmitNetwork(hold, testNetworkId(byte(i%200))); refusal != mxedgeservice.CapRefusalNone {
			t.Fatalf("refused by %s", refusal)
		}
		if sessionCount, entryCount := caps.State(); sessionCount != 1 || 4 < entryCount {
			t.Fatalf("holding %d sessions and %d entries", sessionCount, entryCount)
		}
		caps.Release(hold)
	}
	if sessionCount, entryCount := caps.State(); sessionCount != 0 || entryCount != 0 {
		t.Errorf("left %d sessions and %d entries", sessionCount, entryCount)
	}
}

// However many race for it, a cap admits its number and no more.
func TestCapHoldsUnderRacingSessions(t *testing.T) {
	settings := testSettings()
	caps := mxedgeservice.NewCaps(settings)
	sender := netip.MustParseAddr("203.0.113.9")
	start := make(chan struct{})
	var admittedCount atomic.Int32
	var group sync.WaitGroup
	for range 64 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if _, refusal := caps.Admit(sender); refusal == mxedgeservice.CapRefusalNone {
				admittedCount.Add(1)
			}
		}()
	}
	close(start)
	group.Wait()
	if int(admittedCount.Load()) != settings.SenderSessionCount {
		t.Errorf("admitted %d", admittedCount.Load())
	}
}

// §22.5's hot path: every cap decided with no Redis call and no store call, in the composed engine.
// DenyPostgresForTest is server's, so MAIL-M7-27 repeats this on real stores. Here the fake store,
// which stands where Postgres does, counts every call.
func TestCapsAskNoStoreAndNoRedis(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.host.Redis.ResetOpCounts()
	engine.store.ResetOpCounts()
	for range engine.settings.SenderSessionCount {
		engine.open(testSender)
	}
	over := engine.dial(testSender)
	over.expect("421 4.7.0 " + testBannerHostName + " Too many sessions, try again later")
	over.expectEnd()
	if counts := engine.host.Redis.OpCounts(); len(counts) != 0 {
		t.Errorf("redis calls: %v", counts)
	}
	if counts := engine.store.OpCounts(); len(counts) != 0 {
		t.Errorf("store calls: %v", counts)
	}
}
