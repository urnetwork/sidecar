package mxedgeservice_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Two processes of one fleet, sharing Redis, the secret and the clock.
type testFleet struct {
	ctx    context.Context
	clock  *sidecartest.FakeClock
	host   *sidecartest.FakeHost
	first  *mxedgeservice.ClosedHandshakes
	second *mxedgeservice.ClosedHandshakes
}

// A fleet with an empty memory, whose clock starts at start.
func newTestFleet(t *testing.T, start time.Time) *testFleet {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(start)
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	ttl := mxedgeservice.DefaultMxEdgeSettings().ClosedHandshakeTtl
	return &testFleet{
		ctx:    ctx,
		clock:  clock,
		host:   host,
		first:  mxedgeservice.NewClosedHandshakes(host.Redis, testSecret, ttl, clock),
		second: mxedgeservice.NewClosedHandshakes(host.Redis, testSecret, ttl, clock),
	}
}

// The first process remembers a closed handshake.
func (self *testFleet) record(t *testing.T, sender string) {
	t.Helper()
	if err := self.first.Record(self.ctx, netip.MustParseAddr(sender)); err != nil {
		t.Fatal(err)
	}
}

// The second process reads the memory and gets an answer.
func (self *testFleet) expectRecent(t *testing.T, sender string, want bool) {
	t.Helper()
	recent, answered := self.second.Recent(self.ctx, netip.MustParseAddr(sender))
	if recent != want || !answered {
		t.Fatalf("%s at %s: recent %v, answered %v, want recent %v", sender, self.clock.Now(), recent, answered, want)
	}
}

func TestClosedHandshakeHoldsAt59MinutesAndNotAt61(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	fleet.expectRecent(t, testSender, false)
	fleet.record(t, testSender)
	fleet.expectRecent(t, testSender, true)
	fleet.clock.Advance(59 * time.Minute)
	fleet.expectRecent(t, testSender, true)
	fleet.clock.Advance(2 * time.Minute)
	fleet.expectRecent(t, testSender, false)
}

// A second closed handshake restarts the hour, since §15.4's hour runs from the latest.
func TestLaterClosedHandshakeRestartsTheHour(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	fleet.record(t, testSender)
	fleet.clock.Advance(30 * time.Minute)
	fleet.record(t, testSender)
	fleet.clock.Advance(59 * time.Minute)
	fleet.expectRecent(t, testSender, true)
	fleet.clock.Advance(2 * time.Minute)
	fleet.expectRecent(t, testSender, false)
}

// Written at 23:50 under one day's k and read at 00:10 under the next, as yesterday's key must serve.
func TestClosedHandshakeHoldsAcrossMidnightUtc(t *testing.T) {
	writeTime := time.Date(2026, time.March, 31, 23, 50, 0, 0, time.UTC)
	fleet := newTestFleet(t, writeTime)
	fleet.record(t, testSender)

	fleet.clock.AdvanceTo(writeTime.Add(20 * time.Minute))
	fleet.expectRecent(t, testSender, true)
	sender := netip.MustParseAddr(testSender)
	if today, yesterday := fleet.second.Key(sender, fleet.clock.Now()), fleet.second.Key(sender, writeTime); today == yesterday {
		t.Fatal("midnight changed no key, so this test proves nothing")
	}
	dump := fleet.host.Redis.Dump()
	if _, ok := dump[fleet.second.Key(sender, fleet.clock.Now())]; ok {
		t.Error("the entry moved to today's key, so yesterday's read was never needed")
	}

	fleet.clock.AdvanceTo(writeTime.Add(59 * time.Minute))
	fleet.expectRecent(t, testSender, true)
	fleet.clock.AdvanceTo(writeTime.Add(61 * time.Minute))
	fleet.expectRecent(t, testSender, false)
}

// The other side of midnight is an ordinary read under today's key.
func TestClosedHandshakeJustAfterMidnightUtc(t *testing.T) {
	writeTime := time.Date(2026, time.April, 1, 0, 0, 1, 0, time.UTC)
	fleet := newTestFleet(t, writeTime)
	fleet.record(t, testSender)
	fleet.clock.Advance(59 * time.Minute)
	fleet.expectRecent(t, testSender, true)
}

// Reading 5's k and §15.4's key, computed apart from this code. Blocks of one release and the next run
// side by side in a rollout, so a change here would leave each half blind to what the other remembers.
func TestKeysMatchTheirVectors(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	for sender, want := range map[string]string{
		"203.0.113.9":     "{mxc_9d0833816d6b2899dde907e044a008dd717da8a1dad11f41d6001d7eecce06b9}",
		"2001:db8:1:2::9": "{mxc_e6283c0d20105bf44c11759690b7e1cc1ffbf05bfcd372348abf0b8bbf982008}",
	} {
		if key := fleet.first.Key(netip.MustParseAddr(sender), sidecartest.DefaultClockStart()); key != want {
			t.Errorf("%s: %s", sender, key)
		}
	}
}

// A clock in another zone is the same UTC day, and k follows that.
func TestDayIsUtcWhateverZoneTheClockReads(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	sender := netip.MustParseAddr(testSender)
	instant := time.Date(2026, time.April, 1, 23, 30, 0, 0, time.UTC)
	elsewhere := instant.In(time.FixedZone("UTC+10", 10*60*60))
	if fleet.first.Key(sender, instant) != fleet.first.Key(sender, elsewhere) {
		t.Error("one instant gave two keys")
	}
}

// §15.4: a Postfix retry from a sibling sending address gets 451 too.
func TestMemoryCoversTheSendersAggregate(t *testing.T) {
	for _, c := range []struct {
		sender  string
		sibling string
		outside string
	}{
		{sender: "203.0.113.9", sibling: "203.0.113.200", outside: "203.0.114.9"},
		{sender: "2001:db8:1:2::9", sibling: "2001:db8:1:ffff::1", outside: "2001:db8:2:2::9"},
		{sender: "::ffff:203.0.113.9", sibling: "203.0.113.200", outside: "203.0.114.9"},
	} {
		fleet := newTestFleet(t, sidecartest.DefaultClockStart())
		fleet.record(t, c.sender)
		fleet.expectRecent(t, c.sender, true)
		fleet.expectRecent(t, c.sibling, true)
		fleet.expectRecent(t, c.outside, false)
	}
}

// A Redis error is a retry, never a lasting 530, whichever of the two reads it strikes.
func TestRedisErrorReadsAsRecent(t *testing.T) {
	for _, nth := range []int{1, 2} {
		fleet := newTestFleet(t, sidecartest.DefaultClockStart())
		_, err := fleet.host.Redis.Faults().Add(&sidecartest.FaultPlan{
			Op: sidecartest.FaultOpRedis, KeyPrefix: "{mxc_", Nth: nth, Result: sidecartest.FailBeforeApply,
		})
		if err != nil {
			t.Fatal(err)
		}
		recent, answered := fleet.second.Recent(fleet.ctx, netip.MustParseAddr(testSender))
		if !recent || answered {
			t.Errorf("read %d failing: recent %v, answered %v", nth, recent, answered)
		}
	}
}

func TestRecordReportsARedisError(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	_, err := fleet.host.Redis.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpRedis, KeyPrefix: "{mxc_", Result: sidecartest.FailBeforeApply,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fleet.first.Record(fleet.ctx, netip.MustParseAddr(testSender)); err == nil {
		t.Error("the write failed unseen")
	}
}

func TestShortSecretReadsAsRecentAndWritesNothing(t *testing.T) {
	for _, secret := range [][]byte{nil, testSecret[:mxedgeservice.ClosedHandshakeSecretMinByteCount-1]} {
		fleet := newTestFleet(t, sidecartest.DefaultClockStart())
		ttl := mxedgeservice.DefaultMxEdgeSettings().ClosedHandshakeTtl
		memory := mxedgeservice.NewClosedHandshakes(fleet.host.Redis, secret, ttl, fleet.clock)
		sender := netip.MustParseAddr(testSender)
		if memory.Available() {
			t.Error("a short secret reads as available")
		}
		if err := memory.Record(fleet.ctx, sender); err == nil {
			t.Error("recorded with no secret")
		}
		if recent, answered := memory.Recent(fleet.ctx, sender); !recent || answered {
			t.Errorf("recent %v, answered %v", recent, answered)
		}
		if counts := fleet.host.Redis.OpCounts(); len(counts) != 0 {
			t.Errorf("redis calls: %v", counts)
		}
	}
}

// §2.8 mx-1: a keyed hash, storing no address.
func TestKeyHoldsNoAddressByte(t *testing.T) {
	for _, c := range []struct {
		sender string
		// the sender's text and bytes, whole and as far as its aggregate
		needles [][]byte
	}{
		{
			sender: "203.0.113.9",
			needles: [][]byte{
				[]byte("203.0.113"), {203, 0, 113}, []byte("cb0071"), []byte("CB0071"),
			},
		},
		{
			sender: "2001:db8:1:2::9",
			needles: [][]byte{
				[]byte("2001:db8:1"), []byte("20010db80001"), {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01},
			},
		},
	} {
		fleet := newTestFleet(t, sidecartest.DefaultClockStart())
		fleet.record(t, c.sender)
		dump := fleet.host.Redis.Dump()
		if len(dump) != 1 {
			t.Fatalf("wrote %d keys", len(dump))
		}
		for key, value := range dump {
			if !regexp.MustCompile(`^\{mxc_[0-9a-f]{64}\}$`).MatchString(key) {
				t.Errorf("key %q", key)
			}
			if string(value) != "1" {
				t.Errorf("value %q", value)
			}
			// by hand: PrivacyCapture's encoded forms of so short a needle turn up by chance in any hash
			for _, needle := range c.needles {
				if bytes.Contains([]byte(key), needle) || bytes.Contains(value, needle) {
					t.Errorf("%s: key %q or value %q holds %q", c.sender, key, value, needle)
				}
			}
		}
	}
}

// One sender's key is not linkable from one day to the next, nor one aggregate's to another's, and
// without the secret no key can be computed from an address.
func TestKeysDifferByDayAggregateAndSecret(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	sender := netip.MustParseAddr(testSender)
	day := fleet.clock.Now()
	base := fleet.first.Key(sender, day)
	if base != fleet.second.Key(sender, day) {
		t.Error("two processes disagree on a key")
	}
	if base == fleet.first.Key(sender, day.Add(24*time.Hour)) {
		t.Error("two days share a key")
	}
	if base == fleet.first.Key(netip.MustParseAddr("203.0.114.9"), day) {
		t.Error("two aggregates share a key")
	}
	otherSecret := append([]byte{}, testSecret...)
	otherSecret[0] ^= 0xff
	ttl := mxedgeservice.DefaultMxEdgeSettings().ClosedHandshakeTtl
	other := mxedgeservice.NewClosedHandshakes(fleet.host.Redis, otherSecret, ttl, fleet.clock)
	if base == other.Key(sender, day) {
		t.Error("two secrets share a key")
	}
}

// A family's multi-key call must share a tag, and {mxc_}'s two keys do not, so the memory has to make
// one-key calls. FakeRedis is §22.4's lint at run time: it refuses as production's cluster does, and
// keeps what it refused.
func TestMemoryPassesTheCrossSlotLint(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	fleet.record(t, testSender)
	fleet.expectRecent(t, testSender, true)
	fleet.expectRecent(t, "198.51.100.1", false)
	if violations := fleet.host.Redis.Violations(); len(violations) != 0 {
		t.Errorf("violations: %v", violations)
	}
	counts := fleet.host.Redis.OpCounts()
	if counts["mget"] != 0 || counts["set"] != 1 || counts["get"] != 3 {
		t.Errorf("calls: %v", counts)
	}

	sender := netip.MustParseAddr(testSender)
	now := fleet.clock.Now()
	bothDays := []string{fleet.first.Key(sender, now), fleet.first.Key(sender, now.Add(-24*time.Hour))}
	if _, err := fleet.host.Redis.GetMany(fleet.ctx, bothDays); !errors.Is(err, sidecartest.ErrRedisCrossSlot) {
		t.Errorf("one call for both days answered %v, so this test proves nothing", err)
	}
}

// A hit on today's key spares the second read, and a miss costs both.
func TestReadCostsAtMostTwoGets(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	fleet.record(t, testSender)
	fleet.host.Redis.ResetOpCounts()
	fleet.expectRecent(t, testSender, true)
	if counts := fleet.host.Redis.OpCounts(); counts["get"] != 1 {
		t.Errorf("a hit: %v", counts)
	}
	fleet.host.Redis.ResetOpCounts()
	fleet.expectRecent(t, "198.51.100.1", false)
	if counts := fleet.host.Redis.OpCounts(); counts["get"] != 2 {
		t.Errorf("a miss: %v", counts)
	}
}
