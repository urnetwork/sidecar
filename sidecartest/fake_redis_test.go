package sidecartest

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

type redisFixture struct {
	clock  *FakeClock
	faults *FaultQueue
	redis  *FakeRedis
}

func newRedisFixture(t *testing.T, settings *FakeRedisSettings) *redisFixture {
	clock := NewFakeClock(DefaultClockStart())
	faults := NewFaultQueue()
	redis := NewFakeRedis(t.Context(), clock, faults, nil, settings)
	t.Cleanup(redis.Close)
	return &redisFixture{clock: clock, faults: faults, redis: redis}
}

func TestRedisClusterSlotMatchesRedis(t *testing.T) {
	// what CLUSTER KEYSLOT answers
	cases := []struct {
		key  string
		slot int
	}{
		{key: "foo", slot: 12182},
		{key: "bar", slot: 5061},
		{key: "hello", slot: 866},
		{key: "{user1000}.following", slot: 3443},
		{key: "{user1000}.followers", slot: 3443},
		{key: "foo{}{bar}", slot: 8363},
		{key: "foo{bar}{zap}", slot: 5061},
	}
	for _, c := range cases {
		if got := RedisClusterSlot(c.key); got != c.slot {
			t.Errorf("%q: slot %d, want %d", c.key, got, c.slot)
		}
	}
}

func TestRedisClusterMastersDivideTheSlots(t *testing.T) {
	cases := []struct {
		slot   int
		master int
	}{
		{slot: 0, master: 0},
		{slot: 5460, master: 0},
		{slot: 5461, master: 1},
		{slot: 10922, master: 1},
		{slot: 10923, master: 2},
		{slot: 16383, master: 2},
	}
	for _, c := range cases {
		if got := RedisClusterMaster(c.slot); got != c.master {
			t.Errorf("slot %d: master %d, want %d", c.slot, got, c.master)
		}
	}
}

// Keys that share a slot by luck, under two different tags: production would pass them, and the lint
// must not, or the two part the day either family's tag changes.
func TestCrossSlotLintRefusesAMatchByLuck(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	luckyKey := ""
	for index := 0; luckyKey == ""; index += 1 {
		if key := fmt.Sprintf("{luck_%d}a", index); RedisClusterSlot(key) == RedisClusterSlot("{home}a") {
			luckyKey = key
		}
	}
	if _, err := fixture.redis.GetMany(t.Context(), []string{"{home}a", luckyKey}); !errors.Is(err, ErrRedisCrossSlot) {
		t.Errorf("err %v", err)
	}
	if len(fixture.redis.Violations()) != 1 {
		t.Errorf("violations %v", fixture.redis.Violations())
	}
}

func TestATagSharedWithABareKeyIsOneTag(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	// bar and foo{bar} hash the same bytes, so no reshard can part them
	if _, err := fixture.redis.GetMany(t.Context(), []string{"bar", "foo{bar}"}); err != nil {
		t.Errorf("err %v", err)
	}
}

func TestCrossSlotRefusalsAreReported(t *testing.T) {
	reported := []string{}
	settings := DefaultFakeRedisSettings()
	settings.Report = func(violation string) { reported = append(reported, violation) }
	fixture := newRedisFixture(t, settings)
	if err := fixture.redis.Delete(t.Context(), []string{"{a}1", "{b}2"}); !errors.Is(err, ErrRedisCrossSlot) {
		t.Errorf("err %v", err)
	}
	if len(reported) != 1 || !strings.Contains(reported[0], "del") {
		t.Errorf("reported %v", reported)
	}
	if len(fixture.redis.Violations()) != 1 {
		t.Errorf("violations %v", fixture.redis.Violations())
	}
}

func TestACrossSlotCallCountsNoOperation(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	if _, err := fixture.redis.GetMany(t.Context(), []string{"{a}1", "{b}2"}); !errors.Is(err, ErrRedisCrossSlot) {
		t.Fatal(err)
	}
	if counts := fixture.redis.OpCounts(); len(counts) != 0 {
		t.Errorf("counts %v", counts)
	}
}

func TestOneKeyCallsNeedNoTag(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	if _, err := fixture.redis.GetMany(t.Context(), []string{"plain-key"}); err != nil {
		t.Error(err)
	}
	if len(fixture.redis.Violations()) != 0 {
		t.Errorf("violations %v", fixture.redis.Violations())
	}
}

func TestOpCountsNameEachCommandAndScript(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	ctx := t.Context()
	script := &sidecar.RedisScript{Name: "find", Source: "return 1"}
	fixture.redis.RegisterScript("find", func(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
		return RedisIntegerReply(1), nil
	})
	fixture.redis.Set(ctx, "{a}1", []byte("v"), 0)
	fixture.redis.Get(ctx, "{a}1")
	fixture.redis.Get(ctx, "{a}1")
	if _, err := fixture.redis.RunScript(ctx, script, []string{"{a}1"}, nil); err != nil {
		t.Fatal(err)
	}
	counts := fixture.redis.OpCounts()
	if counts["set"] != 1 || counts["get"] != 2 || counts["script:find"] != 1 {
		t.Errorf("counts %v", counts)
	}
	fixture.redis.ResetOpCounts()
	if len(fixture.redis.OpCounts()) != 0 {
		t.Error("reset kept counts")
	}
}

func TestInspectingCountsNothingAndTakesNoFault(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	if err := fixture.redis.Set(t.Context(), "{a}1", []byte("v"), 0); err != nil {
		t.Fatal(err)
	}
	fixture.redis.ResetOpCounts()
	if _, err := fixture.faults.Add(&FaultPlan{Op: FaultOpRedis, Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := fixture.redis.Get(InspectContext(t.Context()), "{a}1"); err != nil || !found {
		t.Errorf("found %v, %v", found, err)
	}
	if len(fixture.redis.OpCounts()) != 0 {
		t.Error("an oracle's read counted")
	}
	if len(fixture.faults.Unfired()) != 1 {
		t.Error("an oracle's read took a fault")
	}
}

func TestAScriptWithNoTwinFailsRatherThanDoNothing(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	_, err := fixture.redis.RunScript(t.Context(), &sidecar.RedisScript{Name: "unknown"}, []string{"{a}1"}, nil)
	if !errors.Is(err, ErrRedisNoTwin) {
		t.Errorf("err %v", err)
	}
}

func TestATwinRegisteredTwicePanics(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	twin := func(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) { return RedisNilReply(), nil }
	fixture.redis.RegisterScript("twin", twin)
	defer func() {
		if recover() == nil {
			t.Error("a second twin passed")
		}
	}()
	fixture.redis.RegisterScript("twin", twin)
}

// A script builds no key: anything outside KEYS proves the slot check proved nothing.
func TestAScriptReachesOnlyItsDeclaredKeys(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	fixture.redis.RegisterScript("builder", func(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
		_, _, err := call.Get("{a}undeclared")
		return nil, err
	})
	_, err := fixture.redis.RunScript(t.Context(), &sidecar.RedisScript{Name: "builder"}, []string{"{a}1"}, nil)
	if !errors.Is(err, errRedisKeyNotDeclared) {
		t.Errorf("err %v", err)
	}
	if len(fixture.redis.Violations()) != 1 {
		t.Errorf("violations %v", fixture.redis.Violations())
	}
}

func TestAScriptReadsTheMastersClock(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	var seen time.Time
	fixture.redis.RegisterScript("clock", func(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
		seen = call.Now()
		return RedisNilReply(), nil
	})
	fixture.clock.Advance(1 * time.Hour)
	if _, err := fixture.redis.RunScript(t.Context(), &sidecar.RedisScript{Name: "clock"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !seen.Equal(fixture.clock.Now()) {
		t.Errorf("seen %v", seen)
	}
}

func TestAScriptsWritesNotifyAfterItEnds(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	heard := make(chan sidecar.RedisKeyEvent, 4)
	remove, err := fixture.redis.AddKeyEventCallback("{a}*", func(event sidecar.RedisKeyEvent) { heard <- event })
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	fixture.redis.RegisterScript("hint", func(call *FakeRedisScriptCall) (*sidecar.RedisReply, error) {
		if err := call.HashSet(call.Keys[0], map[string][]byte{"ver": []byte("9")}); err != nil {
			return nil, err
		}
		value, err := call.Increment(call.Keys[1], time.Hour)
		if err != nil {
			return nil, err
		}
		return RedisIntegerReply(value), nil
	})
	reply, err := fixture.redis.RunScript(t.Context(), &sidecar.RedisScript{Name: "hint"}, []string{"{a}ver", "{a}n"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Integer != 1 {
		t.Errorf("reply %+v", reply)
	}
	if err := fixture.redis.AwaitKeyEvents(t.Context()); err != nil {
		t.Fatal(err)
	}
	// the INCR notifies and the HSET does not (D-PROTO-12)
	if len(heard) != 1 {
		t.Fatalf("heard %d", len(heard))
	}
	if event := <-heard; event.Key != "{a}n" {
		t.Errorf("event %+v", event)
	}
}

func TestRedisFaultsDropAnswersAndWrites(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	ctx := t.Context()
	if _, err := fixture.faults.Add(&FaultPlan{Op: FaultOpRedis, KeyPrefix: "{a}", Result: ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.redis.Set(ctx, "{a}1", []byte("v"), 0); err == nil {
		t.Error("the answer came through")
	}
	if _, found, err := fixture.redis.Get(ctx, "{a}1"); err != nil || !found {
		t.Errorf("found %v, %v", found, err)
	}

	if _, err := fixture.faults.Add(&FaultPlan{Op: FaultOpRedis, KeyPrefix: "{b}", Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.redis.Set(ctx, "{b}1", []byte("v"), 0); err == nil {
		t.Error("the plan did not fire")
	}
	if _, found, err := fixture.redis.Get(ctx, "{b}1"); err != nil || found {
		t.Errorf("found %v, %v", found, err)
	}
}

func TestARedisCallDelayedThenDeliveredServesThen(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	if _, err := fixture.faults.Add(&FaultPlan{Op: FaultOpRedis, Result: Delay}); err != nil {
		t.Fatal(err)
	}
	answered := make(chan error, 1)
	go func() {
		answered <- fixture.redis.Set(t.Context(), "{a}1", []byte("v"), 0)
	}()
	if err := fixture.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := fixture.redis.Get(InspectContext(t.Context()), "{a}1"); found {
		t.Fatal("served before delivery")
	}
	if delivered := fixture.redis.DeliverDelayed(); delivered != 1 {
		t.Fatalf("delivered %d", delivered)
	}
	if err := <-answered; err != nil {
		t.Error(err)
	}
	if _, found, _ := fixture.redis.Get(t.Context(), "{a}1"); !found {
		t.Error("not served")
	}
}

func TestARedisCallDelayedPastItsTimeoutFails(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	if _, err := fixture.faults.Add(&FaultPlan{Op: FaultOpRedis, Result: Delay, Delay: DelayNeverLands}); err != nil {
		t.Fatal(err)
	}
	answered := make(chan error, 1)
	go func() {
		answered <- fixture.redis.Set(t.Context(), "{a}1", []byte("v"), 0)
	}()
	if err := fixture.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(DefaultFakeRedisSettings().RequestTimeout)
	if err := <-answered; err == nil {
		t.Error("a call that never landed succeeded")
	}
}

func TestLosingRedisCostsAResync(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	ctx := t.Context()
	events := make(chan sidecar.RedisKeyEvent, 8)
	remove, err := fixture.redis.AddKeyEventCallback("{a}*", func(event sidecar.RedisKeyEvent) { events <- event })
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	if err := fixture.redis.Set(ctx, "{a}1", []byte("v"), 0); err != nil {
		t.Fatal(err)
	}
	if err := fixture.redis.AwaitKeyEvents(ctx); err != nil {
		t.Fatal(err)
	}
	<-events

	fixture.redis.LoseEverything()

	if _, found, err := fixture.redis.Get(ctx, "{a}1"); err != nil || found {
		t.Errorf("found %v, %v", found, err)
	}
	if err := fixture.redis.AwaitKeyEvents(ctx); err != nil {
		t.Fatal(err)
	}
	if event := <-events; !event.Resync || event.Key != "" {
		t.Errorf("event %+v", event)
	}
}

func TestLoseKeysLosesOneFamily(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	ctx := t.Context()
	fixture.redis.Set(ctx, "{evsq_a}1", []byte("v"), 0)
	fixture.redis.Set(ctx, "{gka_a}1", []byte("v"), 0)
	fixture.redis.LoseKeys("{evsq_")
	if _, found, _ := fixture.redis.Get(ctx, "{evsq_a}1"); found {
		t.Error("kept")
	}
	if _, found, _ := fixture.redis.Get(ctx, "{gka_a}1"); !found {
		t.Error("lost too much")
	}
}

func TestDumpHoldsEveryByteAKeyHolds(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	ctx := t.Context()
	canary := []byte("canary-bytes")
	fixture.redis.Set(ctx, "string", canary, 0)
	fixture.redis.HashSet(ctx, "hash", map[string][]byte{"f": canary})
	fixture.redis.StreamAdd(ctx, "stream", 0, map[string][]byte{"f": canary})
	dump := fixture.redis.Dump()
	if len(dump) != 3 {
		t.Fatalf("dump %v", dump)
	}
	for key, value := range dump {
		if !bytes.Contains(value, canary) {
			t.Errorf("%s: %q", key, value)
		}
	}
}

func TestABlockingKeyEventCallbackIsReported(t *testing.T) {
	settings := DefaultFakeRedisSettings()
	settings.CallbackTimeout = 1 * time.Millisecond
	reported := make(chan string, 1)
	settings.Report = func(violation string) { reported <- violation }
	fixture := newRedisFixture(t, settings)
	unblock := make(chan struct{})
	defer close(unblock)
	remove, err := fixture.redis.AddKeyEventCallback("{a}*", func(event sidecar.RedisKeyEvent) {
		<-unblock
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	if err := fixture.redis.Set(t.Context(), "{a}1", []byte("v"), 0); err != nil {
		t.Fatal(err)
	}
	if violation := <-reported; !strings.Contains(violation, "blocked") {
		t.Errorf("violation %q", violation)
	}
}

func TestTtlRunsOnTheInjectedClockOnly(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	ctx := t.Context()
	if err := fixture.redis.Set(ctx, "{a}1", []byte("v"), 1*time.Hour); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(59 * time.Minute)
	if _, found, _ := fixture.redis.Get(ctx, "{a}1"); !found {
		t.Error("gone early")
	}
	fixture.clock.Advance(1 * time.Minute)
	if _, found, _ := fixture.redis.Get(ctx, "{a}1"); found {
		t.Error("kept past its ttl")
	}
}

func TestAReplacedKeysOldTtlDoesNothing(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	ctx := t.Context()
	fixture.redis.Set(ctx, "{a}1", []byte("v"), 1*time.Minute)
	fixture.redis.Set(ctx, "{a}1", []byte("w"), 1*time.Hour)
	fixture.clock.Advance(2 * time.Minute)
	if value, _, _ := fixture.redis.Get(ctx, "{a}1"); string(value) != "w" {
		t.Errorf("value %q", value)
	}
}

func TestStreamPendingShowsWhatIsUnacknowledged(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	ctx := t.Context()
	key := "{wakeq_0}s"
	if err := fixture.redis.StreamGroupCreate(ctx, key, "senders"); err != nil {
		t.Fatal(err)
	}
	entryId, err := fixture.redis.StreamAdd(ctx, key, 0, map[string][]byte{"f": []byte("v")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.redis.StreamGroupRead(ctx, key, "senders", "sender-1", 10, 0); err != nil {
		t.Fatal(err)
	}
	pending := fixture.redis.StreamPending(key, "senders")
	if !slices.Equal(pending["sender-1"], []string{entryId}) {
		t.Errorf("pending %v", pending)
	}
	if err := fixture.redis.StreamGroupAck(ctx, key, "senders", []string{entryId}); err != nil {
		t.Fatal(err)
	}
	if pending := fixture.redis.StreamPending(key, "senders"); len(pending) != 0 {
		t.Errorf("pending %v", pending)
	}
}

func TestAStreamReadBlockedOnTheClockWakesForANewEntry(t *testing.T) {
	fixture := newRedisFixture(t, nil)
	ctx := t.Context()
	key := "{wakeq_0}s"
	if err := fixture.redis.StreamGroupCreate(ctx, key, "senders"); err != nil {
		t.Fatal(err)
	}
	read := make(chan int, 1)
	go func() {
		entries, err := fixture.redis.StreamGroupRead(ctx, key, "senders", "sender-1", 1, 1*time.Hour)
		if err != nil {
			t.Error(err)
		}
		read <- len(entries)
	}()
	if err := fixture.clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.redis.StreamAdd(ctx, key, 0, map[string][]byte{"f": []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if got := <-read; got != 1 {
		t.Errorf("read %d", got)
	}
}

func TestRedisGlobMatchesFamilies(t *testing.T) {
	cases := []struct {
		pattern string
		text    string
		match   bool
	}{
		{pattern: "{tes_*}n", text: "{tes_abc}n", match: true},
		{pattern: "{tes_*}n", text: "{tes_abc}m", match: false},
		{pattern: "{*}c_removed", text: "{c1}c_removed", match: true},
		{pattern: "*", text: "", match: true},
		{pattern: "a?c", text: "abc", match: true},
		{pattern: "a?c", text: "ac", match: false},
	}
	for _, c := range cases {
		if got := redisGlobMatch(c.pattern, c.text); got != c.match {
			t.Errorf("%q on %q: %v", c.pattern, c.text, got)
		}
	}
}
