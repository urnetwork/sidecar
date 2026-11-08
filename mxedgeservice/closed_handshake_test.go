// The closed-handshake memory on its own, as two processes of one fleet sharing a FakeRedis and a fake
// clock. A Refresh here stands for the engine's probe, which service_test.go drives for real.

package mxedgeservice_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Two processes of one fleet, sharing Redis and the clock.
type testFleet struct {
	ctx    context.Context
	clock  *sidecartest.FakeClock
	host   *sidecartest.FakeHost
	first  *mxedgeservice.ClosedHandshakes
	second *mxedgeservice.ClosedHandshakes
}

// A fleet with an empty memory, whose clock starts at start, each process holding the day's k: the
// first made it and the second read it.
func newTestFleet(t *testing.T, start time.Time) *testFleet {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(start)
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	self := &testFleet{
		ctx:    ctx,
		clock:  clock,
		host:   host,
		first:  newTestMemory(host, clock),
		second: newTestMemory(host, clock),
	}
	self.refresh(t)
	return self
}

// A process's memory on host's Redis, holding no k yet.
func newTestMemory(host *sidecartest.FakeHost, clock *sidecartest.FakeClock) *mxedgeservice.ClosedHandshakes {
	return mxedgeservice.NewClosedHandshakes(host.Redis, mxedgeservice.DefaultMxEdgeSettings().ClosedHandshakeTtl, clock)
}

// Both processes refresh, as their probes do at each interval and at the date change.
func (self *testFleet) refresh(t *testing.T) {
	t.Helper()
	for _, memory := range []*mxedgeservice.ClosedHandshakes{self.first, self.second} {
		if _, err := memory.Refresh(self.ctx); err != nil {
			t.Fatal(err)
		}
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

// What Redis holds under the k name of the day t falls in, read as an oracle.
func oracleDailyKey(t *testing.T, ctx context.Context, host *sidecartest.FakeHost, at time.Time) ([]byte, bool) {
	t.Helper()
	value, found, err := host.Redis.Get(sidecartest.InspectContext(ctx), mxedgeservice.DailyKeyName(at))
	if err != nil {
		t.Fatal(err)
	}
	return value, found
}

// Puts value under the k name of the day t falls in, as another process would have, before anything
// here reads it.
func seedDailyKey(t *testing.T, ctx context.Context, host *sidecartest.FakeHost, at time.Time, value []byte) {
	t.Helper()
	set, err := host.Redis.SetIfAbsent(sidecartest.InspectContext(ctx), mxedgeservice.DailyKeyName(at), value, mxedgeservice.DailyKeyTtl)
	if err != nil || !set {
		t.Fatalf("seeding: set %v, %v", set, err)
	}
}

// The {mxc_} keys Redis holds.
func memoryKeys(dump map[string][]byte) []string {
	var keys []string
	for key := range dump {
		if regexp.MustCompile(`^\{mxc_`).MatchString(key) {
			keys = append(keys, key)
		}
	}
	return keys
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
	fleet.refresh(t)
	fleet.expectRecent(t, testSender, true)
	sender := netip.MustParseAddr(testSender)
	today, yesterday := fleet.second.Key(sender, fleet.clock.Now()), fleet.second.Key(sender, writeTime)
	if today == "" || yesterday == "" || today == yesterday {
		t.Fatalf("today %q, yesterday %q, so this test proves nothing", today, yesterday)
	}
	if keys := memoryKeys(fleet.host.Redis.Dump()); !slices.Equal(keys, []string{yesterday}) {
		t.Errorf("held %v, so yesterday's read was never needed", keys)
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

// The moment between the date change and the probe that reads the new day's k: nothing can be
// answered for today, so a read tells the sender to retry and a write is refused, not written under
// a k no other process reads today.
func TestNewDayBeforeItsRefreshFailsClosed(t *testing.T) {
	fleet := newTestFleet(t, time.Date(2026, time.March, 31, 23, 59, 0, 0, time.UTC))
	fleet.clock.Advance(2 * time.Minute)
	sender := netip.MustParseAddr(testSender)
	if recent, answered := fleet.second.Recent(fleet.ctx, sender); !recent || answered {
		t.Errorf("recent %v, answered %v", recent, answered)
	}
	if err := fleet.first.Record(fleet.ctx, sender); err == nil {
		t.Error("recorded with no k for today")
	}
	fleet.refresh(t)
	fleet.record(t, testSender)
	fleet.expectRecent(t, testSender, true)
}

// §15.4's key under a k fixed here, computed apart from this code, with Python's hmac. Blocks of one
// release and the next run side by side in a rollout, so a change here would leave each half blind to
// what the other remembers.
func TestKeysMatchTheirVectors(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	seedDailyKey(t, ctx, host, clock.Now(), testDailyKey)
	memory := newTestMemory(host, clock)
	if _, err := memory.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	for sender, want := range map[string]string{
		"203.0.113.9":     "{mxc_bd3c9ad83adbc859559f68e8de743352b72c03ca16d694fed8dd1100670f7906}",
		"2001:db8:1:2::9": "{mxc_6721ddccc082ecce72432b2035fb56485036729b38556ec0c6a855ec54eda424}",
	} {
		address := netip.MustParseAddr(sender)
		if key := mxedgeservice.ClosedHandshakeKey(testDailyKey, address); key != want {
			t.Errorf("%s: %s", sender, key)
		}
		if key := memory.Key(address, clock.Now()); key != want {
			t.Errorf("%s under the k read from Redis: %s", sender, key)
		}
	}
}

// k's name is the UTC date, whatever zone a clock reads in.
func TestDailyKeyNameIsTheUtcDate(t *testing.T) {
	instant := time.Date(2026, time.April, 1, 23, 30, 0, 0, time.UTC)
	elsewhere := instant.In(time.FixedZone("UTC+10", 10*60*60))
	for _, at := range []time.Time{instant, elsewhere} {
		if name := mxedgeservice.DailyKeyName(at); name != "{vhk}mx:20260401" {
			t.Errorf("%s: %s", at, name)
		}
	}
	if name := mxedgeservice.DailyKeyName(time.Date(1969, time.December, 31, 23, 0, 0, 0, time.UTC)); name != "{vhk}mx:19691231" {
		t.Errorf("before the epoch: %s", name)
	}
}

// The resolution's SET NX: the day's first process makes k, 32 random bytes, and every other reads it.
func TestFirstProcessMakesTheDailyKeyAndTheOthersReadIt(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	first, second := newTestMemory(host, clock), newTestMemory(host, clock)
	if result, err := first.Refresh(ctx); result != "created" || err != nil {
		t.Fatalf("first: %s, %v", result, err)
	}
	if result, err := second.Refresh(ctx); result != "read" || err != nil {
		t.Fatalf("second: %s, %v", result, err)
	}
	if counts := host.Redis.OpCounts(); counts["setnx"] != 1 || counts["set"] != 0 {
		t.Errorf("calls: %v", counts)
	}
	dump := host.Redis.Dump()
	dayKey, ok := dump["{vhk}mx:20260102"]
	if !ok || len(dayKey) != mxedgeservice.DailyKeyByteCount {
		t.Fatalf("Redis holds %d bytes of k, found %v", len(dayKey), ok)
	}
	sender := netip.MustParseAddr(testSender)
	if want := mxedgeservice.ClosedHandshakeKey(dayKey, sender); first.Key(sender, clock.Now()) != want || second.Key(sender, clock.Now()) != want {
		t.Error("the two processes do not hold the k Redis holds")
	}
}

// Another process's k is used as it stands, never replaced.
func TestExistingDailyKeyIsKept(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	seedDailyKey(t, ctx, host, clock.Now(), testDailyKey)
	memory := newTestMemory(host, clock)
	if result, err := memory.Refresh(ctx); result != "read" || err != nil {
		t.Fatalf("%s, %v", result, err)
	}
	if counts := host.Redis.OpCounts(); counts["setnx"] != 0 || counts["get"] != 1 {
		t.Errorf("calls: %v", counts)
	}
	if dump := host.Redis.Dump(); !bytes.Equal(dump["{vhk}mx:20260102"], testDailyKey) {
		t.Error("k was replaced")
	}
}

// EX 90000, so no k outlives 25 h in Redis, and so in no backup (D-OPS-16).
func TestDailyKeyLivesTwentyFiveHours(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	created := fleet.clock.Now()
	fleet.clock.AdvanceTo(created.Add(25*time.Hour - time.Second))
	if _, found := oracleDailyKey(t, fleet.ctx, fleet.host, created); !found {
		t.Error("k gone before 25 h")
	}
	fleet.clock.AdvanceTo(created.Add(25 * time.Hour))
	if _, found := oracleDailyKey(t, fleet.ctx, fleet.host, created); found {
		t.Error("k still there at 25 h")
	}
}

// A process holds today's k, and yesterday's for the hour an entry under it may live, and no other.
func TestKeysAreForgottenOnceNothingCanBeUnderThem(t *testing.T) {
	start := time.Date(2026, time.March, 31, 23, 50, 0, 0, time.UTC)
	fleet := newTestFleet(t, start)
	yesterday := mxedgeservice.UtcDay(start)
	today := yesterday + 1
	expectHeld := func(want []int64) {
		t.Helper()
		if held, _ := fleet.first.HeldDays(); !slices.Equal(held, want) {
			t.Errorf("at %s held %v, want %v", fleet.clock.Now(), held, want)
		}
	}
	expectHeld([]int64{yesterday})
	fleet.clock.AdvanceTo(start.Add(20 * time.Minute))
	fleet.refresh(t)
	expectHeld([]int64{yesterday, today})
	fleet.clock.AdvanceTo(start.Add(70 * time.Minute))
	fleet.refresh(t)
	expectHeld([]int64{today})
}

// A process that starts in a day's first hour reads yesterday's k, and never makes it: an entry under
// a k that does not exist cannot exist either, so a missing one is skipped and the read is answered.
func TestYesterdaysKeyIsReadInTheFirstHourAndNeverMade(t *testing.T) {
	// another process remembered a sender before midnight, and this one starts after it
	writeTime := time.Date(2026, time.March, 31, 23, 55, 0, 0, time.UTC)
	fleet := newTestFleet(t, writeTime)
	fleet.record(t, testSender)
	fleet.clock.AdvanceTo(writeTime.Add(25 * time.Minute))
	late := newTestMemory(fleet.host, fleet.clock)
	if _, err := late.Refresh(fleet.ctx); err != nil {
		t.Fatal(err)
	}
	if held, _ := late.HeldDays(); len(held) != 2 {
		t.Errorf("held %v", held)
	}
	if recent, answered := late.Recent(fleet.ctx, netip.MustParseAddr(testSender)); !recent || !answered {
		t.Errorf("recent %v, answered %v", recent, answered)
	}

	// a fleet whose Redis holds no k for yesterday
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(time.Date(2026, time.April, 1, 0, 20, 0, 0, time.UTC))
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	memory := newTestMemory(host, clock)
	if _, err := memory.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if counts := host.Redis.OpCounts(); counts["setnx"] != 1 || counts["get"] != 2 {
		t.Errorf("calls: %v", counts)
	}
	if _, found := oracleDailyKey(t, ctx, host, clock.Now().Add(-24*time.Hour)); found {
		t.Error("yesterday's k was made")
	}
	if _, absent := memory.HeldDays(); len(absent) != 1 {
		t.Errorf("absent %v", absent)
	}
	host.Redis.ResetOpCounts()
	if recent, answered := memory.Recent(ctx, netip.MustParseAddr(testSender)); recent || !answered {
		t.Errorf("recent %v, answered %v", recent, answered)
	}
	if counts := host.Redis.OpCounts(); counts["get"] != 1 {
		t.Errorf("a read with no k for yesterday: %v", counts)
	}

	// and one that starts after the first hour does not ask for yesterday's at all
	clock = sidecartest.NewFakeClock(time.Date(2026, time.April, 1, 1, 20, 0, 0, time.UTC))
	host = sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	memory = newTestMemory(host, clock)
	if _, err := memory.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if counts := host.Redis.OpCounts(); counts["get"] != 1 {
		t.Errorf("past the first hour: %v", counts)
	}
}

// A lost k is made again by the next probe, and every process converges on the new one. What was
// remembered under the old k is lost with it, the cost a lost key has.
func TestLostDailyKeyIsRemadeAndTheFleetConverges(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	fleet.record(t, testSender)
	sender := netip.MustParseAddr(testSender)
	before := fleet.first.Key(sender, fleet.clock.Now())

	fleet.host.Redis.LoseKeys(mxedgeservice.DailyKeyPrefix)
	fleet.refresh(t)
	after := fleet.first.Key(sender, fleet.clock.Now())
	if after == before {
		t.Fatal("the same k came back, so this test proves nothing")
	}
	if fleet.second.Key(sender, fleet.clock.Now()) != after {
		t.Error("the fleet holds two k for one day")
	}
	fleet.expectRecent(t, testSender, false)
	fleet.record(t, testSender)
	fleet.expectRecent(t, testSender, true)
}

// Redis failing on k's name leaves a process holding none: it refuses to write and tells a sender to
// retry, sending nothing under {mxc_}.
func TestDailyKeyRedisErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	_, err := host.Redis.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpRedis, KeyPrefix: mxedgeservice.DailyKeyPrefix, Result: sidecartest.FailBeforeApply, Repeat: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	memory := newTestMemory(host, clock)
	if result, err := memory.Refresh(ctx); result != "failed" || err == nil {
		t.Errorf("%s, %v", result, err)
	}
	expectNothingAnswered(t, ctx, host, memory)
}

// Something under k's name that is not 32 bytes is no k, and nothing here overwrites it.
func TestMalformedDailyKeyFailsClosed(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	seedDailyKey(t, ctx, host, clock.Now(), testDailyKey[:mxedgeservice.DailyKeyByteCount-1])
	memory := newTestMemory(host, clock)
	if result, err := memory.Refresh(ctx); result != "failed" || err == nil {
		t.Errorf("%s, %v", result, err)
	}
	expectNothingAnswered(t, ctx, host, memory)
	if counts := host.Redis.OpCounts(); counts["setnx"] != 0 || counts["set"] != 0 {
		t.Errorf("calls: %v", counts)
	}
}

// Before any Refresh, a memory has no k: it refuses to write, reads as recent, and asks Redis nothing.
func TestNoDailyKeyReadsAsRecentAndWritesNothing(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	expectNothingAnswered(t, ctx, host, newTestMemory(host, clock))
}

// A memory with no k for today: a write refused, a read recent and unanswered, and no {mxc_} call.
func expectNothingAnswered(t *testing.T, ctx context.Context, host *sidecartest.FakeHost, memory *mxedgeservice.ClosedHandshakes) {
	t.Helper()
	host.Redis.ResetOpCounts()
	sender := netip.MustParseAddr(testSender)
	if err := memory.Record(ctx, sender); err == nil {
		t.Error("recorded with no k")
	}
	if recent, answered := memory.Recent(ctx, sender); !recent || answered {
		t.Errorf("recent %v, answered %v", recent, answered)
	}
	if counts := host.Redis.OpCounts(); len(counts) != 0 {
		t.Errorf("redis calls: %v", counts)
	}
	if keys := memoryKeys(host.Redis.Dump()); len(keys) != 0 {
		t.Errorf("wrote %v", keys)
	}
}

// A k already held keeps serving through a failed re-read: it is still the day's k.
func TestHeldKeyServesThroughAFailedRefresh(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	_, err := fleet.host.Redis.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpRedis, KeyPrefix: mxedgeservice.DailyKeyPrefix, Result: sidecartest.FailBeforeApply,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fleet.first.Refresh(fleet.ctx); err == nil {
		t.Fatal("the refresh did not fail, so this test proves nothing")
	}
	fleet.record(t, testSender)
	fleet.expectRecent(t, testSender, true)
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

// A fleet in a day's first hour, holding yesterday's k and today's, so a miss reads both.
func newTestFleetInTheFirstHour(t *testing.T) *testFleet {
	t.Helper()
	start := time.Date(2026, time.March, 31, 23, 50, 0, 0, time.UTC)
	fleet := newTestFleet(t, start)
	fleet.clock.AdvanceTo(start.Add(40 * time.Minute))
	fleet.refresh(t)
	return fleet
}

// A Redis error is a retry, never a lasting 530, whichever of the two reads it strikes.
func TestRedisErrorReadsAsRecent(t *testing.T) {
	for _, nth := range []int{1, 2} {
		fleet := newTestFleetInTheFirstHour(t)
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
		keys := memoryKeys(dump)
		if len(keys) != 1 || len(dump) != 2 {
			t.Fatalf("wrote %v of %d keys", keys, len(dump))
		}
		for _, key := range keys {
			value := dump[key]
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
// without a day's k no key can be computed from an address.
func TestKeysDifferByDayAggregateAndKey(t *testing.T) {
	fleet := newTestFleet(t, sidecartest.DefaultClockStart())
	sender := netip.MustParseAddr(testSender)
	day := fleet.clock.Now()
	base := fleet.first.Key(sender, day)
	if base == "" || base != fleet.second.Key(sender, day) {
		t.Error("two processes disagree on a key")
	}
	if base == fleet.first.Key(netip.MustParseAddr("203.0.114.9"), day) {
		t.Error("two aggregates share a key")
	}
	fleet.clock.Advance(24 * time.Hour)
	fleet.refresh(t)
	if next := fleet.first.Key(sender, fleet.clock.Now()); next == "" || next == base {
		t.Error("two days share a key")
	}
	otherKey := bytes.Clone(testDailyKey)
	otherKey[0] ^= 0xff
	if mxedgeservice.ClosedHandshakeKey(testDailyKey, sender) == mxedgeservice.ClosedHandshakeKey(otherKey, sender) {
		t.Error("two k share a key")
	}
}

// A family's multi-key call must share a tag, and {mxc_}'s keys under two days' k do not, so the
// memory has to make one-key calls. FakeRedis is §22.4's lint at run time: it refuses as production's
// cluster does, and keeps what it refused.
func TestMemoryPassesTheCrossSlotLint(t *testing.T) {
	fleet := newTestFleetInTheFirstHour(t)
	fleet.host.Redis.ResetOpCounts()
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

// In a day's first hour a hit on today's key spares the second read and a miss costs both; past it, a
// miss costs one.
func TestReadCostsAtMostTwoGets(t *testing.T) {
	fleet := newTestFleetInTheFirstHour(t)
	fleet.record(t, testSender)
	fleet.host.Redis.ResetOpCounts()
	fleet.expectRecent(t, testSender, true)
	if counts := fleet.host.Redis.OpCounts(); counts["get"] != 1 {
		t.Errorf("a hit: %v", counts)
	}
	fleet.host.Redis.ResetOpCounts()
	fleet.expectRecent(t, "198.51.100.1", false)
	if counts := fleet.host.Redis.OpCounts(); counts["get"] != 2 {
		t.Errorf("a miss in the first hour: %v", counts)
	}
	fleet.clock.Advance(30 * time.Minute)
	fleet.host.Redis.ResetOpCounts()
	fleet.expectRecent(t, "198.51.100.1", false)
	if counts := fleet.host.Redis.OpCounts(); counts["get"] != 1 {
		t.Errorf("a miss past the first hour: %v", counts)
	}
}
