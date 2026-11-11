package pushservice_test

// §18.7's steps 2 and the live marker (PROTO-M8-01; D-PROTO-5, WK1 to WK4) on T2's FakeRedis: a wake-class
// hint to a token holder queued due now with no live resident, put off 15 s while one is live, due now
// when forced; nothing queued with no token, for a topic of no wake class, or with the switch off; a
// failed XADD retried within the window, then counted and dropped with the hint state untouched; a kill
// between the script and the XADD losing only the wake; every command on one slot; and the publisher's
// {scp_<C>}live written at its start, refreshed on the fake clock and lapsing once it stops.

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A waking writer on a FakeRedis with faults, its clock, and the switch as on says.
type testWakeEnv struct {
	t        *testing.T
	redis    *sidecartest.FakeRedis
	clock    *sidecartest.FakeClock
	faults   *sidecartest.FaultQueue
	metrics  *sidecartest.FakeMetrics
	enqueuer *pushservice.WakeEnqueuer
	writer   *pushservice.HintWriter
	settings *pushservice.WakeQueueSettings
	on       bool
}

func newTestWakeEnv(t *testing.T, settings *pushservice.WakeQueueSettings) *testWakeEnv {
	t.Helper()
	if settings == nil {
		settings = pushservice.DefaultWakeQueueSettings()
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	redis := sidecartest.NewFakeRedis(t.Context(), clock, faults, nil, nil)
	t.Cleanup(redis.Close)
	sidecartest.RegisterPushScripts(redis)
	self := &testWakeEnv{
		t:        t,
		redis:    redis,
		clock:    clock,
		faults:   faults,
		metrics:  sidecartest.NewFakeMetrics(nil),
		settings: settings,
		on:       true,
	}
	enqueuer, err := pushservice.NewWakeEnqueuer(redis, settings, clock, func() bool { return self.on }, self.metrics)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := pushservice.NewWakingHintWriter(redis, nil, nil, nil, enqueuer)
	if err != nil {
		t.Fatal(err)
	}
	self.enqueuer, self.writer = enqueuer, writer
	t.Cleanup(func() {
		if violations := redis.Violations(); len(violations) != 0 {
			t.Errorf("violations %v", violations)
		}
	})
	return self
}

// Gives clientId a wake token, as step 0's apply would.
func (self *testWakeEnv) token(clientId connect.Id) {
	self.t.Helper()
	value := pushservice.WakeTokenValue(sidecar.PushTokenPlatformApns, "synthetic-token-0123456789abcdef")
	if err := self.redis.Set(self.t.Context(), pushservice.HintTokenKey(clientId), value, 0); err != nil {
		self.t.Fatal(err)
	}
}

// Marks clientId's resident live, as its publisher would.
func (self *testWakeEnv) live(clientId connect.Id) {
	self.t.Helper()
	if err := self.redis.Set(self.t.Context(), pushservice.HintLiveKey(clientId), []byte("1"), 90*time.Second); err != nil {
		self.t.Fatal(err)
	}
}

// Every entry of every wake-queue shard.
func (self *testWakeEnv) queued() []*pushservice.WakeEntry {
	self.t.Helper()
	entries := []*pushservice.WakeEntry{}
	for shard := range self.settings.ShardCount {
		streamEntries, err := self.redis.StreamRange(self.t.Context(), pushservice.WakeQueueKey(shard), "", 1000)
		if err != nil {
			self.t.Fatal(err)
		}
		for _, streamEntry := range streamEntries {
			entry, err := pushservice.ParseWakeEntry(streamEntry)
			if err != nil {
				self.t.Fatal(err)
			}
			if pushservice.WakeQueueShard(entry.ClientId, self.settings.ShardCount) != shard {
				self.t.Errorf("an entry of %s in shard %d", entry.ClientId, shard)
			}
			entries = append(entries, entry)
		}
	}
	return entries
}

// The hint, failing the test on an error.
func (self *testWakeEnv) hint(clientId connect.Id, hint *sidecar.ClientHint) *pushservice.PushHintResult {
	self.t.Helper()
	result, err := self.writer.HintClient(self.t.Context(), clientId, hint)
	if err != nil {
		self.t.Fatal(err)
	}
	return result
}

// A token holder with no live resident is woken now; the entry carries the class, the version ver
// holds, the hint's id and its time.
func TestWakeEnqueueDueNowWithoutLiveResident(t *testing.T) {
	env := newTestWakeEnv(t, nil)
	clientId := connect.NewId()
	env.token(clientId)
	result := env.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicCore, Version: 7})
	if result.Wake != pushservice.WakeEnqueueDue {
		t.Fatalf("wake %d", result.Wake)
	}
	entries := env.queued()
	if len(entries) != 1 {
		t.Fatalf("%d entries", len(entries))
	}
	entry := entries[0]
	hintMs, _, err := pushservice.ParseStreamId(result.StreamId)
	if err != nil {
		t.Fatal(err)
	}
	connect.AssertEqual(t, entry.ClientId, clientId)
	connect.AssertEqual(t, entry.TopicClass, sidecar.PushTopicCore)
	connect.AssertEqual(t, entry.Version, result.Version)
	connect.AssertEqual(t, entry.StreamId, result.StreamId)
	connect.AssertEqual(t, entry.HintMs, int64(hintMs))
	connect.AssertEqual(t, entry.DueMs, env.clock.Now().UnixMilli())
	connect.AssertEqual(t, env.enqueuer.Stats().DueCount, uint64(1))
}

// While the resident is live the wake waits 15 s, the deferred check; a forced hint does not wait.
func TestWakeEnqueueDeferredWhileLiveAndForcedNow(t *testing.T) {
	env := newTestWakeEnv(t, nil)
	clientId := connect.NewId()
	env.token(clientId)
	env.live(clientId)
	deferred := env.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicTeam, Version: 3})
	forced := env.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicCore, Version: 4, Forced: true})
	connect.AssertEqual(t, deferred.Wake, pushservice.WakeEnqueueDeferred)
	connect.AssertEqual(t, forced.Wake, pushservice.WakeEnqueueDue)
	entries := env.queued()
	if len(entries) != 2 {
		t.Fatalf("%d entries", len(entries))
	}
	now := env.clock.Now()
	connect.AssertEqual(t, entries[0].DueMs, now.Add(15*time.Second).UnixMilli())
	connect.AssertEqual(t, entries[1].DueMs, now.UnixMilli())
	stats := env.enqueuer.Stats()
	connect.AssertEqual(t, stats.DeferredCount, uint64(1))
	connect.AssertEqual(t, stats.DueCount, uint64(1))
}

// No token, a topic of no wake class, or the switch off queue nothing; the hint lands all the same. Every
// evs topic wakes as the evs class, its repo id left out.
func TestWakeEnqueueOnlyWakeClassToTokenHolders(t *testing.T) {
	env := newTestWakeEnv(t, nil)
	tokenless, holder := connect.NewId(), connect.NewId()
	env.token(holder)
	if result := env.hint(tokenless, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 1}); result.Wake != pushservice.WakeEnqueueNone {
		t.Errorf("no token: %d", result.Wake)
	}
	for _, topic := range []string{sidecar.PushTopicGkm, sidecar.PushTopicSock, sidecar.PushTopicDns, sidecar.PushTopicTls, sidecar.PushTopicGkmGroup(sidecar.NewId())} {
		if result := env.hint(holder, &sidecar.ClientHint{Topic: topic, Version: 2}); result.Wake != pushservice.WakeEnqueueNone {
			t.Errorf("%s: %d", topic, result.Wake)
		}
	}
	if len(env.queued()) != 0 {
		t.Fatal("a wake for no wake-class hint")
	}
	evs := env.hint(holder, &sidecar.ClientHint{Topic: sidecar.PushTopicEvs(sidecar.NewId()), Version: 1800000000000000000})
	connect.AssertEqual(t, evs.Wake, pushservice.WakeEnqueueDue)
	entries := env.queued()
	if len(entries) != 1 || entries[0].TopicClass != "evs" || entries[0].Version != 1800000000000000000 {
		t.Fatalf("entries %+v", entries)
	}

	env.on = false
	if result := env.hint(holder, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 2}); result.Wake != pushservice.WakeEnqueueNone || result.Seq == 0 {
		t.Errorf("switch off: %+v", result)
	}
	connect.AssertEqual(t, len(env.queued()), 1)
	connect.AssertEqual(t, env.enqueuer.Stats().GatedCount, uint64(1))
}

// An XADD that fails every attempt is counted and dropped, and the hint state stays as the script left
// it (WK3).
func TestWakeEnqueueFailureCountedHintIntact(t *testing.T) {
	settings := pushservice.DefaultWakeQueueSettings()
	settings.RetryWindow = 0
	env := newTestWakeEnv(t, settings)
	clientId := connect.NewId()
	env.token(clientId)
	if _, err := env.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpRedis, KeyPrefix: "{wakeq_", Result: sidecartest.FailBeforeApply, Repeat: -1}); err != nil {
		t.Fatal(err)
	}
	result := env.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 5, Body: []byte{1}})
	connect.AssertEqual(t, result.Wake, pushservice.WakeEnqueueDropped)
	stats := env.enqueuer.Stats()
	connect.AssertEqual(t, stats.DroppedCount, uint64(1))
	connect.AssertEqual(t, stats.FailedAttemptCount, uint64(settings.RetryCount+1))
	connect.AssertEqual(t, env.metrics.Value("urnetwork_wake_enqueue_dropped_total", "mail"), float64(1))

	env.faults.Clear()
	versions, err := env.redis.HashGetAll(t.Context(), pushservice.HintVersionsKey(clientId))
	if err != nil {
		t.Fatal(err)
	}
	connect.AssertEqual(t, string(versions[sidecar.PushTopicMail]), "5")
	hints, err := env.redis.StreamRange(t.Context(), pushservice.HintStreamKey(clientId), "", 10)
	if err != nil || len(hints) != 1 || hints[0].Id != result.StreamId {
		t.Fatalf("hint stream %v, %v", hints, err)
	}
	if len(env.queued()) != 0 {
		t.Error("a dropped wake was queued")
	}
}

// Retries are spaced through the window on the clock: two failures, then the third attempt lands, all
// within RetryWindow of the first.
func TestWakeEnqueueRetriesWithinWindow(t *testing.T) {
	env := newTestWakeEnv(t, nil)
	clientId := connect.NewId()
	env.token(clientId)
	if _, err := env.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpRedis, KeyPrefix: "{wakeq_", Result: sidecartest.FailBeforeApply, Repeat: 1}); err != nil {
		t.Fatal(err)
	}
	start := env.clock.Now()
	done := make(chan *pushservice.PushHintResult, 1)
	go func() {
		result, err := env.writer.HintClient(context.Background(), clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicCore, Version: 9})
		if err != nil {
			t.Error(err)
		}
		done <- result
	}()
	spacing := env.settings.RetryWindow / time.Duration(env.settings.RetryCount)
	for range 2 {
		awaitTimerAt(t, env.clock, env.clock.Now().Add(spacing))
		env.clock.Advance(spacing)
	}
	result := <-done
	connect.AssertEqual(t, result.Wake, pushservice.WakeEnqueueDue)
	if elapsed := env.clock.Now().Sub(start); env.settings.RetryWindow < elapsed {
		t.Errorf("landed %v after the first attempt", elapsed)
	}
	connect.AssertEqual(t, env.enqueuer.Stats().FailedAttemptCount, uint64(2))
	connect.AssertEqual(t, len(env.queued()), 1)
}

// A service killed between the script and the XADD loses the wake and nothing else: the hint is in the
// client's slot, and no entry and no drop is counted (WK2's uncounted loss).
func TestWakeEnqueueKillBetweenScriptAndXaddLosesOnlyTheWake(t *testing.T) {
	env := newTestWakeEnv(t, nil)
	clientId := connect.NewId()
	env.token(clientId)
	if _, err := env.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpRedis, KeyPrefix: "{wakeq_", Result: sidecartest.CrashBeforeApply}); err != nil {
		t.Fatal(err)
	}
	returned := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		env.writer.HintClient(context.Background(), clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicTeam, Version: 11})
		close(returned)
	}()
	<-exited
	select {
	case <-returned:
		t.Fatal("the writer returned past its crash point")
	default:
	}
	hints, err := env.redis.StreamRange(t.Context(), pushservice.HintStreamKey(clientId), "", 10)
	if err != nil || len(hints) != 1 {
		t.Fatalf("hint stream %v, %v", hints, err)
	}
	if len(env.queued()) != 0 {
		t.Error("the killed enqueue left an entry")
	}
	connect.AssertEqual(t, env.enqueuer.Stats().DroppedCount, uint64(0))
}

// WK1: the script and the XADD are separate commands, each on one slot, so FakeRedis's slot check sees
// no command span two (its violations fail the test at cleanup); the XADD is the one command on the
// queue's key.
func TestWakeEnqueueNoCommandSpansTwoSlots(t *testing.T) {
	env := newTestWakeEnv(t, nil)
	for range 8 {
		clientId := connect.NewId()
		env.token(clientId)
		env.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicCore, Version: 1})
	}
	connect.AssertEqual(t, len(env.queued()), 8)
	if count := env.redis.OpCounts()["xadd"]; count != 8 {
		t.Errorf("%d xadds", count)
	}
}

// A publisher's Redis that tells the test each SET once it has landed.
type testLiveRedis struct {
	*sidecartest.FakeRedis
	sets chan string
}

func (self *testLiveRedis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	err := self.FakeRedis.Set(ctx, key, value, ttl)
	self.sets <- key
	return err
}

// The publisher writes {scp_<C>}live at its start and every LiveRefreshInterval on the clock, for
// LiveTimeout each time; once it closes the marker lapses LiveTimeout after its last write.
func TestPublisherRefreshesLiveAndItLapsesAfterLoss(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	fakeRedis := sidecartest.NewFakeRedis(t.Context(), clock, nil, nil, nil)
	t.Cleanup(fakeRedis.Close)
	sidecartest.RegisterPushScripts(fakeRedis)
	redis := &testLiveRedis{FakeRedis: fakeRedis, sets: make(chan string, 64)}
	settings := pushservice.DefaultSidecarPublisherSettings()
	publisher, err := pushservice.NewSidecarPublisher(settings, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(publisher.Close)
	clientId := connect.NewId()
	liveKey := pushservice.HintLiveKey(clientId)
	publisher.Start(t.Context(), &pushservice.PublisherEnv{
		ClientId:  clientId,
		NetworkId: connect.NewId(),
		Send: func(frame *connectprotocol.Frame, ack connect.AckFunction) bool {
			connect.MessagePoolReturn(frame.MessageBytes)
			return true
		},
		Redis: redis,
	})
	awaitSet := func() {
		t.Helper()
		select {
		case key := <-redis.sets:
			if key != liveKey {
				t.Fatalf("set %s", key)
			}
		case <-time.After(testPublisherTimeout):
			t.Fatal("no live write")
		}
	}
	live := func() bool {
		t.Helper()
		_, found, err := fakeRedis.Get(t.Context(), liveKey)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	start := clock.Now()
	awaitSet()
	if !live() {
		t.Fatal("no live marker at start")
	}
	// past the reset's coalescing window, so the publisher waits idle on the clock
	awaitTimerAt(t, clock, start.Add(settings.HintCoalesceTimeout))
	clock.Advance(settings.HintCoalesceTimeout)

	// three refreshes, the last at the first write's expiry, keep it past that write's life
	next := start.Add(settings.LiveRefreshInterval)
	for range 3 {
		awaitTimerAt(t, clock, next)
		clock.AdvanceTo(next)
		awaitSet()
		next = next.Add(settings.LiveRefreshInterval)
	}
	clock.Advance(settings.LiveRefreshInterval / 2)
	if !live() {
		t.Fatal("the marker lapsed under a live publisher")
	}
	connect.AssertEqual(t, publisher.Stats().LiveCount, uint64(4))

	// the last write was half an interval ago: it lives LiveTimeout from then, and no one writes it again
	publisher.Close()
	clock.Advance(settings.LiveTimeout - settings.LiveRefreshInterval/2 - time.Second)
	if !live() {
		t.Fatal("the marker went before its life ran out")
	}
	clock.Advance(2 * time.Second)
	if live() {
		t.Fatal("the marker outlived its publisher")
	}
}

// Waits, on real time, until clock holds a timer at at.
func awaitTimerAt(t *testing.T, clock *sidecartest.FakeClock, at time.Time) {
	t.Helper()
	guard := time.After(testPublisherTimeout)
	for {
		pending, added := clock.WatchTimers()
		if slices.ContainsFunc(pending, at.Equal) {
			return
		}
		select {
		case <-added:
		case <-guard:
			t.Fatalf("no timer at %s: %v", at, pending)
		}
	}
}

// An entry ParseWakeEntry refuses: one this package did not write.
func TestParseWakeEntryRefusesForeignEntries(t *testing.T) {
	good := map[string][]byte{
		pushservice.WakeEntryFieldClient:   []byte(connect.NewId().String()),
		pushservice.WakeEntryFieldTopic:    []byte("core"),
		pushservice.WakeEntryFieldVersion:  []byte("12"),
		pushservice.WakeEntryFieldStreamId: []byte("1700000000000-3"),
		pushservice.WakeEntryFieldHintMs:   []byte("1700000000000"),
		pushservice.WakeEntryFieldDueMs:    []byte("1700000015000"),
	}
	if _, err := pushservice.ParseWakeEntry(&sidecar.RedisStreamEntry{Id: "1-1", FieldValues: good}); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		field string
		value string
	}{
		{field: pushservice.WakeEntryFieldClient, value: "not-an-id"},
		{field: pushservice.WakeEntryFieldTopic, value: "evs:" + connect.NewId().String()},
		{field: pushservice.WakeEntryFieldTopic, value: "gkm"},
		{field: pushservice.WakeEntryFieldVersion, value: "012"},
		{field: pushservice.WakeEntryFieldStreamId, value: "1700000000000"},
		{field: pushservice.WakeEntryFieldDueMs, value: "-" + strconv.Itoa(1)},
	} {
		fieldValues := map[string][]byte{}
		for field, value := range good {
			fieldValues[field] = slices.Clone(value)
		}
		fieldValues[change.field] = []byte(change.value)
		if _, err := pushservice.ParseWakeEntry(&sidecar.RedisStreamEntry{Id: "1-1", FieldValues: fieldValues}); err == nil {
			t.Errorf("%s=%q parsed", change.field, change.value)
		}
	}
}
