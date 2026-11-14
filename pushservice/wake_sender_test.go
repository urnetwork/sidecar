package pushservice_test

// §19.4's push sender (SDK-M8-10; §18.7's step 4, WK1 to WK4) on T2's FakeRedis, a fake clock and
// sidecartest.FakeWakeVendor: an entry due now wakes at once and one due 15 s on at its due; an ack at or
// past the hint, no token and an entry over 60 s old each drop it unsent; one wake per client per 10 s across
// a sender killed after its send; a hint inside a window waking once at the window's end; APNs' hourly and
// FCM's per-topic caps; a vendor's 410 tombstoning only at the revision read with the token; retries and
// giving up; a killed sender's entry claimed by another after 30 s idle; WK4's payloads and a scan showing
// no id reaches a vendor; versions past 2^53 exact; and the switch off reading nothing. Every key one call
// names shares one tag, which the fake checks (WK1's lint at run time).

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How long a test waits on the sender before calling itself broken. Every wait is on an event or a timer.
const testWakeSenderTimeout = 30 * time.Second

// A token store that records each tombstone it is asked for, and tombstones only at its row's revision.
type testWakeTokenStore struct {
	stateLock sync.Mutex
	// each client's row revision, and whether it is a tombstone
	revisions  map[connect.Id]int64
	tombstoned map[connect.Id]bool
	asked      []int64
}

func (self *testWakeTokenStore) TombstoneIfRevision(ctx context.Context, clientId connect.Id, revision int64) (bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asked = append(self.asked, revision)
	if self.revisions[clientId] != revision || self.tombstoned[clientId] {
		return false, nil
	}
	self.tombstoned[clientId] = true
	self.revisions[clientId] += 1
	return true, nil
}

// One sender's world: FakeRedis on a fake clock, an APNs and an FCM fake, a token store and the settlements.
type testSenderEnv struct {
	t        *testing.T
	redis    *sidecartest.FakeRedis
	clock    *sidecartest.FakeClock
	metrics  *sidecartest.FakeMetrics
	apns     *sidecartest.FakeWakeVendor
	fcm      *sidecartest.FakeWakeVendor
	tokens   *testWakeTokenStore
	settings *pushservice.WakeSenderSettings
	settled  chan *pushservice.WakeSettled
	on       atomic.Bool
	seq      uint64
}

// Settings a test reads by: reads and claims block long, so the only short timers are the dispatcher's and
// the vendor's backoffs, unless a test asks for claims.
func testWakeSenderSettings() *pushservice.WakeSenderSettings {
	settings := pushservice.DefaultWakeSenderSettings()
	settings.ReadBlock = 100 * time.Hour
	settings.ClaimInterval = 100 * time.Hour
	settings.GateInterval = 100 * time.Hour
	settings.SendConcurrency = 4
	return settings
}

func newTestSenderEnv(t *testing.T, settings *pushservice.WakeSenderSettings) *testSenderEnv {
	t.Helper()
	if settings == nil {
		settings = testWakeSenderSettings()
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	redis := sidecartest.NewFakeRedis(t.Context(), clock, nil, nil, nil)
	t.Cleanup(redis.Close)
	sidecartest.RegisterPushScripts(redis)
	self := &testSenderEnv{
		t:        t,
		redis:    redis,
		clock:    clock,
		metrics:  sidecartest.NewFakeMetrics(nil),
		apns:     sidecartest.NewFakeWakeVendor(pushservice.WakePlatformApns, clock),
		fcm:      sidecartest.NewFakeWakeVendor(pushservice.WakePlatformFcm, clock),
		tokens:   &testWakeTokenStore{revisions: map[connect.Id]int64{}, tombstoned: map[connect.Id]bool{}},
		settings: settings,
		settled:  make(chan *pushservice.WakeSettled, 256),
	}
	self.on.Store(true)
	t.Cleanup(func() {
		if violations := redis.Violations(); len(violations) != 0 {
			t.Errorf("violations %v", violations)
		}
	})
	// the group stands before any entry, as it does in production from the first sender's start: XGROUP
	// CREATE takes entries from now on, so one queued before it would never be read
	for shard := range settings.Queue.ShardCount {
		if err := redis.StreamGroupCreate(t.Context(), pushservice.WakeQueueKey(shard), settings.ConsumerGroup); err != nil {
			t.Fatal(err)
		}
	}
	return self
}

// A sender of the env as consumer, closed at the test's end unless the test closes it.
func (self *testSenderEnv) start(consumer string) *pushservice.WakeSender {
	self.t.Helper()
	return self.startOn(self.t.Context(), consumer)
}

func (self *testSenderEnv) startOn(ctx context.Context, consumer string) *pushservice.WakeSender {
	self.t.Helper()
	sender, err := pushservice.NewWakeSender(ctx, &pushservice.WakeSenderArgs{
		Redis:    self.redis,
		Tokens:   self.tokens,
		Vendors:  []pushservice.WakeVendor{self.apns, self.fcm},
		Consumer: consumer,
		Enabled:  self.on.Load,
		Clock:    self.clock,
		Metrics:  self.metrics,
		Settings: self.settings,
		Settled: func(settled *pushservice.WakeSettled) {
			self.settled <- settled
		},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(sender.Close)
	return sender
}

// Gives clientId a token on platform at revision, as step 0's apply leaves it.
func (self *testSenderEnv) token(clientId connect.Id, platform string, revision int64) string {
	self.t.Helper()
	token := "synthetic-" + platform + "-token-" + clientId.String()[:8]
	ctx := self.t.Context()
	if err := self.redis.Set(ctx, pushservice.HintTokenKey(clientId), pushservice.WakeTokenValue(platform, token), 0); err != nil {
		self.t.Fatal(err)
	}
	if err := self.redis.Set(ctx, pushservice.WakeTokenRevisionKey(clientId), []byte(strconv.FormatInt(revision, 10)), 0); err != nil {
		self.t.Fatal(err)
	}
	self.tokens.stateLock.Lock()
	self.tokens.revisions[clientId] = revision
	self.tokens.stateLock.Unlock()
	return token
}

// Queues a wake for clientId's hint now, due after dueIn, as step 2's enqueue writes it, with the hint
// written hintAgo before now: what the entry's h names.
func (self *testSenderEnv) enqueue(clientId connect.Id, topicClass string, version uint64, hintAgo time.Duration, dueIn time.Duration) *pushservice.WakeEntry {
	self.t.Helper()
	self.seq += 1
	now := self.clock.Now()
	hintMs := now.Add(-hintAgo).UnixMilli()
	entry := &pushservice.WakeEntry{
		ClientId:   clientId,
		TopicClass: topicClass,
		Version:    version,
		StreamId:   fmt.Sprintf("%d-%d", hintMs, self.seq),
		HintMs:     hintMs,
		DueMs:      now.Add(dueIn).UnixMilli(),
	}
	fieldValues := map[string][]byte{
		pushservice.WakeEntryFieldClient:   []byte(clientId.String()),
		pushservice.WakeEntryFieldTopic:    []byte(topicClass),
		pushservice.WakeEntryFieldVersion:  []byte(pushservice.FormatVersion(version)),
		pushservice.WakeEntryFieldStreamId: []byte(entry.StreamId),
		pushservice.WakeEntryFieldHintMs:   []byte(strconv.FormatInt(entry.HintMs, 10)),
		pushservice.WakeEntryFieldDueMs:    []byte(strconv.FormatInt(entry.DueMs, 10)),
	}
	shard := pushservice.WakeQueueShard(clientId, self.settings.Queue.ShardCount)
	if _, err := self.redis.StreamAdd(self.t.Context(), pushservice.WakeQueueKey(shard), self.settings.Queue.MaxLength, fieldValues); err != nil {
		self.t.Fatal(err)
	}
	return entry
}

// The hint id the next enqueue of a hint now names.
func (self *testSenderEnv) nextStreamId() string {
	return fmt.Sprintf("%d-%d", self.clock.Now().UnixMilli(), self.seq+1)
}

// Sets clientId's ack to streamId, as its publisher does on its stack's ack.
func (self *testSenderEnv) ack(clientId connect.Id, streamId string) {
	self.t.Helper()
	if err := self.redis.Set(self.t.Context(), pushservice.HintAckKey(clientId), []byte(streamId), time.Hour); err != nil {
		self.t.Fatal(err)
	}
}

// The next settlement.
func (self *testSenderEnv) next() *pushservice.WakeSettled {
	self.t.Helper()
	select {
	case settled := <-self.settled:
		return settled
	case <-time.After(testWakeSenderTimeout):
		self.t.Fatal("nothing settled")
		return nil
	}
}

// The next settlement, which must be result for clientId.
func (self *testSenderEnv) expect(clientId connect.Id, result pushservice.WakeSettledResult) *pushservice.WakeSettled {
	self.t.Helper()
	settled := self.next()
	if settled.ClientId != clientId || settled.Result != result {
		self.t.Fatalf("settled %+v, not %s for %s", settled, result, clientId)
	}
	return settled
}

// Returns once a timer at at is pending: the dispatcher or a backoff waiting for it.
func (self *testSenderEnv) awaitTimerAt(at time.Time) {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(self.t.Context(), testWakeSenderTimeout)
	defer cancel()
	for {
		pending, added := self.clock.WatchTimers()
		if slices.ContainsFunc(pending, at.Equal) {
			return
		}
		select {
		case <-added:
		case <-ctx.Done():
			self.t.Fatalf("no timer at %v: %v", at, pending)
		}
	}
}

// A synthetic client id.
func testWakeClient(b byte) connect.Id {
	return connect.Id{0xc1, b, 0x5e, 0x1d}
}

// An entry due now wakes at once with its class and version, through the platform its token names, and is
// acknowledged; one due 15 s on wakes only at its due.
func TestWakeSenderSendsAtDue(t *testing.T) {
	env := newTestSenderEnv(t, nil)
	start := env.clock.Now()
	env.start("a")
	now := testWakeClient(1)
	later := testWakeClient(2)
	token := env.token(now, pushservice.WakePlatformApns, 11)
	env.token(later, pushservice.WakePlatformFcm, 12)
	env.enqueue(now, "mail", 42, 0, 0)
	settled := env.expect(now, pushservice.WakeSettledSent)
	if !settled.Acked || settled.Platform != pushservice.WakePlatformApns || settled.TopicClass != "mail" {
		t.Fatalf("%+v", settled)
	}
	submissions := env.apns.Submissions()
	if len(submissions) != 1 || submissions[0].Token != token || submissions[0].Payload.TopicClass != "mail" ||
		submissions[0].Payload.Version != 42 || !submissions[0].At.Equal(start) {
		t.Fatalf("submissions %+v", submissions)
	}
	env.enqueue(later, "team", 7, 0, 15*time.Second)
	env.awaitTimerAt(start.Add(15 * time.Second))
	if len(env.fcm.Submissions()) != 0 {
		t.Fatal("woken before its due")
	}
	env.clock.Advance(15 * time.Second)
	env.expect(later, pushservice.WakeSettledSent)
	if submissions := env.fcm.Submissions(); len(submissions) != 1 || !submissions[0].At.Equal(start.Add(15*time.Second)) || submissions[0].Payload.TopicClass != "team" {
		t.Fatalf("fcm submissions %+v", submissions)
	}
	if pending := env.redis.StreamPending(pushservice.WakeQueueKey(pushservice.WakeQueueShard(now, 16)), env.settings.ConsumerGroup); len(pending) != 0 {
		t.Errorf("pending %v", pending)
	}
}

// An ack at or past the entry's hint, no token, and an entry over 60 s from its hint each settle unsent and
// acknowledged; an ack below the hint wakes.
func TestWakeSenderDropsWhatNeedsNoWake(t *testing.T) {
	env := newTestSenderEnv(t, nil)
	env.start("a")
	acked := testWakeClient(1)
	env.token(acked, pushservice.WakePlatformApns, 1)
	env.ack(acked, env.nextStreamId())
	env.enqueue(acked, "evs", 3, 0, 0)
	env.expect(acked, pushservice.WakeSettledAcked)
	env.ack(acked, fmt.Sprintf("%d-0", env.clock.Now().UnixMilli()+1))
	env.enqueue(acked, "evs", 4, 0, 0)
	env.expect(acked, pushservice.WakeSettledAcked)
	behind := testWakeClient(2)
	env.token(behind, pushservice.WakePlatformApns, 1)
	env.ack(behind, "1-1")
	env.enqueue(behind, "core", 5, 0, 0)
	env.expect(behind, pushservice.WakeSettledSent)

	tokenless := testWakeClient(3)
	env.enqueue(tokenless, "mail", 1, 0, 0)
	if settled := env.expect(tokenless, pushservice.WakeSettledNoToken); !settled.Acked {
		t.Errorf("%+v", settled)
	}
	old := testWakeClient(4)
	env.token(old, pushservice.WakePlatformApns, 1)
	env.enqueue(old, "mail", 1, 61*time.Second, 0)
	env.expect(old, pushservice.WakeSettledExpired)
	if submissions := env.apns.Submissions(); len(submissions) != 1 {
		t.Errorf("submissions %d", len(submissions))
	}
}

// A sender killed after its vendor call and before its ack leaves its window in Redis: a second sender wakes
// the same client no sooner than the window's end, and the killed sender's entry, claimed after 30 s idle,
// drops once the client has acked (FS-36's rate clause).
func TestOneWakePer10sAcrossSenderKill(t *testing.T) {
	settings := testWakeSenderSettings()
	settings.ClaimInterval = 31 * time.Second
	env := newTestSenderEnv(t, settings)
	start := env.clock.Now()
	client := testWakeClient(1)
	env.token(client, pushservice.WakePlatformApns, 3)
	killCtx, kill := context.WithCancel(t.Context())
	env.apns.SetHook(func(ctx context.Context, submission *sidecartest.FakeWakeSubmission) {
		if submission.At.Equal(start) {
			// the process dies once the vendor has the wake, before its ack
			kill()
		}
	})
	killed := env.startOn(killCtx, "killed")
	first := env.enqueue(client, "mail", 1, 0, 0)
	if settled := env.expect(client, pushservice.WakeSettledSent); settled.Acked {
		t.Fatalf("the killed sender acknowledged %+v", settled)
	}
	killed.Close()
	if pending := env.redis.StreamPending(pushservice.WakeQueueKey(pushservice.WakeQueueShard(client, 16)), settings.ConsumerGroup); len(pending["killed"]) != 1 {
		t.Fatalf("pending %v", pending)
	}

	// a new process, and a hint 5 s after the first wake: put off to the killed sender's window's end
	env.start("next")
	env.clock.Advance(5 * time.Second)
	second := env.enqueue(client, "mail", 2, 0, 0)
	env.awaitTimerAt(start.Add(10 * time.Second))
	if submissions := env.apns.Submissions(); len(submissions) != 1 {
		t.Fatalf("a second wake inside the window: %d", len(submissions))
	}
	env.clock.Advance(5 * time.Second)
	env.expect(client, pushservice.WakeSettledSent)
	submissions := env.apns.Submissions()
	if len(submissions) != 2 || submissions[1].At.Sub(submissions[0].At) < 10*time.Second {
		t.Fatalf("submissions at %v and %v", submissions[0].At, submissions[len(submissions)-1].At)
	}
	// the client wakes and acks; the killed sender's entry, claimed after it idled, drops
	env.ack(client, second.StreamId)
	env.clock.Advance(21 * time.Second)
	if settled := env.expect(client, pushservice.WakeSettledAcked); settled.EntryId == "" || !settled.Acked {
		t.Fatalf("%+v", settled)
	}
	_ = first
	if len(env.apns.Submissions()) != 2 {
		t.Errorf("submissions %d", len(env.apns.Submissions()))
	}
}

// Hints inside a client's window earn one wake at its end, and those the window-end wake follows fold into
// it: three hints, two wakes.
func TestWindowEndWake(t *testing.T) {
	env := newTestSenderEnv(t, nil)
	start := env.clock.Now()
	env.start("a")
	client := testWakeClient(1)
	env.token(client, pushservice.WakePlatformApns, 1)
	env.enqueue(client, "mail", 1, 0, 0)
	env.expect(client, pushservice.WakeSettledSent)
	env.clock.Advance(2 * time.Second)
	env.enqueue(client, "mail", 2, 0, 0)
	env.awaitTimerAt(start.Add(10 * time.Second))
	env.clock.Advance(1 * time.Second)
	env.enqueue(client, "team", 3, 0, 0)
	env.awaitTimerAt(start.Add(10 * time.Second))
	env.clock.Advance(7 * time.Second)
	results := []pushservice.WakeSettledResult{env.next().Result, env.next().Result}
	slices.Sort(results)
	if !slices.Equal(results, []pushservice.WakeSettledResult{pushservice.WakeSettledCoalesced, pushservice.WakeSettledSent}) {
		t.Fatalf("results %v", results)
	}
	submissions := env.apns.Submissions()
	if len(submissions) != 2 || !submissions[1].At.Equal(start.Add(10*time.Second)) {
		t.Fatalf("submissions %+v", submissions)
	}
}

// Wakes enough apart that the client window never holds them: the next wake past n windows.
func (self *testSenderEnv) wakeAgain(clientId connect.Id, topicClass string) *pushservice.WakeSettled {
	self.t.Helper()
	self.clock.Advance(self.settings.ClientWindow + time.Second)
	self.enqueue(clientId, topicClass, 1, 0, 0)
	return self.next()
}

// APNs takes three wakes an hour per device: a fourth is capped, and an hour on one wakes again.
func TestApnsHourlyCap(t *testing.T) {
	env := newTestSenderEnv(t, nil)
	env.start("a")
	client := testWakeClient(1)
	env.token(client, pushservice.WakePlatformApns, 1)
	for i := range 3 {
		if settled := env.wakeAgain(client, "mail"); settled.Result != pushservice.WakeSettledSent {
			t.Fatalf("wake %d: %+v", i, settled)
		}
	}
	if settled := env.wakeAgain(client, "team"); settled.Result != pushservice.WakeSettledCapped {
		t.Fatalf("the fourth: %+v", settled)
	}
	env.clock.Advance(time.Hour)
	if settled := env.wakeAgain(client, "mail"); settled.Result != pushservice.WakeSettledSent {
		t.Fatalf("an hour on: %+v", settled)
	}
	if submissions := env.apns.Submissions(); len(submissions) != 4 {
		t.Errorf("submissions %d", len(submissions))
	}
}

// FCM takes one wake a minute per device and topic: a second of one topic is capped, another topic's is not,
// and a minute on the first wakes again.
func TestFcmTopicCap(t *testing.T) {
	env := newTestSenderEnv(t, nil)
	env.start("a")
	client := testWakeClient(1)
	env.token(client, pushservice.WakePlatformFcm, 1)
	if settled := env.wakeAgain(client, "mail"); settled.Result != pushservice.WakeSettledSent {
		t.Fatalf("%+v", settled)
	}
	if settled := env.wakeAgain(client, "mail"); settled.Result != pushservice.WakeSettledCapped {
		t.Fatalf("a second mail inside the minute: %+v", settled)
	}
	if settled := env.wakeAgain(client, "team"); settled.Result != pushservice.WakeSettledSent {
		t.Fatalf("team: %+v", settled)
	}
	env.clock.Advance(time.Minute)
	if settled := env.wakeAgain(client, "mail"); settled.Result != pushservice.WakeSettledSent {
		t.Fatalf("a minute on: %+v", settled)
	}
	if submissions := env.fcm.Submissions(); len(submissions) != 3 {
		t.Errorf("submissions %d", len(submissions))
	}
}

// A vendor's 410 tombstones the row at the revision read with the rejected token, and only there: a token
// registered anew since, at a higher revision, survives the stale rejection.
func Test410TombstonesOnlyAtReadRevision(t *testing.T) {
	env := newTestSenderEnv(t, nil)
	env.start("a")
	client := testWakeClient(1)
	env.token(client, pushservice.WakePlatformApns, 7)
	env.apns.Answer(&pushservice.WakeVendorResult{Outcome: pushservice.WakeVendorUnregistered, Status: 410})
	env.enqueue(client, "mail", 1, 0, 0)
	env.expect(client, pushservice.WakeSettledUnregistered)
	env.tokens.stateLock.Lock()
	asked, tombstoned := slices.Clone(env.tokens.asked), env.tokens.tombstoned[client]
	env.tokens.stateLock.Unlock()
	if !slices.Equal(asked, []int64{7}) || !tombstoned {
		t.Fatalf("asked %v, tombstoned %v", asked, tombstoned)
	}

	// a rejection read with revision 9 while the row has moved on to 10 tombstones nothing
	renewed := testWakeClient(2)
	env.token(renewed, pushservice.WakePlatformApns, 9)
	env.tokens.stateLock.Lock()
	env.tokens.revisions[renewed] = 10
	env.tokens.stateLock.Unlock()
	env.apns.Answer(&pushservice.WakeVendorResult{Outcome: pushservice.WakeVendorUnregistered, Status: 410})
	env.clock.Advance(11 * time.Second)
	env.enqueue(renewed, "mail", 1, 0, 0)
	env.expect(renewed, pushservice.WakeSettledUnregistered)
	env.tokens.stateLock.Lock()
	defer env.tokens.stateLock.Unlock()
	if !slices.Equal(env.tokens.asked, []int64{7, 9}) || env.tokens.tombstoned[renewed] {
		t.Fatalf("asked %v, tombstoned %v", env.tokens.asked, env.tokens.tombstoned)
	}
}

// A 429 or 5xx is retried after 1 s, 2 s and 4 s, then given up; one that clears on a retry is sent.
func TestRetryThenGiveUp(t *testing.T) {
	env := newTestSenderEnv(t, nil)
	start := env.clock.Now()
	env.start("a")
	client := testWakeClient(1)
	env.token(client, pushservice.WakePlatformApns, 1)
	failing := &pushservice.WakeVendorResult{Outcome: pushservice.WakeVendorRetry, Status: 503}
	env.apns.Answer(failing, failing, failing, failing)
	env.enqueue(client, "mail", 1, 0, 0)
	at := start
	for _, backoff := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		at = at.Add(backoff)
		env.awaitTimerAt(at)
		env.clock.Advance(backoff)
	}
	if settled := env.expect(client, pushservice.WakeSettledGivenUp); settled.Status != 503 {
		t.Fatalf("%+v", settled)
	}
	if submissions := env.apns.Submissions(); len(submissions) != 4 || !submissions[3].At.Equal(start.Add(7*time.Second)) {
		t.Fatalf("submissions %d", len(submissions))
	}

	other := testWakeClient(2)
	env.token(other, pushservice.WakePlatformApns, 1)
	env.apns.Answer(&pushservice.WakeVendorResult{Outcome: pushservice.WakeVendorRetry, Status: 429})
	env.enqueue(other, "mail", 1, 0, 0)
	env.awaitTimerAt(env.clock.Now().Add(time.Second))
	env.clock.Advance(time.Second)
	env.expect(other, pushservice.WakeSettledSent)
}

// A sender closed while it holds an entry leaves it pending; another sender claims it once it has idled 30 s
// and wakes it.
func TestAutoclaimRedelivers(t *testing.T) {
	settings := testWakeSenderSettings()
	settings.ClaimInterval = 31 * time.Second
	env := newTestSenderEnv(t, settings)
	client := testWakeClient(1)
	env.token(client, pushservice.WakePlatformApns, 1)
	held := env.start("held")
	env.enqueue(client, "mail", 1, 0, 20*time.Second)
	env.awaitTimerAt(env.clock.Now().Add(20 * time.Second))
	held.Close()
	shardKey := pushservice.WakeQueueKey(pushservice.WakeQueueShard(client, 16))
	if pending := env.redis.StreamPending(shardKey, settings.ConsumerGroup); len(pending["held"]) != 1 {
		t.Fatalf("pending %v", pending)
	}
	claimer := env.start("claimer")
	env.awaitTimerAt(env.clock.Now().Add(31 * time.Second))
	env.clock.Advance(31 * time.Second)
	if settled := env.expect(client, pushservice.WakeSettledSent); !settled.Acked {
		t.Fatalf("%+v", settled)
	}
	if stats := claimer.Stats(); stats.ClaimedCount != 1 {
		t.Errorf("stats %+v", stats)
	}
	if pending := env.redis.StreamPending(shardKey, settings.ConsumerGroup); len(pending) != 0 {
		t.Errorf("pending %v", pending)
	}
}

// While sidecar.yml's wake switch is off nothing is read; switched on, what waited is read, and an entry past
// 60 s drops rather than wake late.
func TestWakeSenderSwitchOffReadsNothing(t *testing.T) {
	settings := testWakeSenderSettings()
	settings.GateInterval = 5 * time.Second
	env := newTestSenderEnv(t, settings)
	env.on.Store(false)
	start := env.clock.Now()
	sender := env.start("a")
	fresh := testWakeClient(1)
	stale := testWakeClient(2)
	env.token(fresh, pushservice.WakePlatformApns, 1)
	env.token(stale, pushservice.WakePlatformApns, 1)
	env.enqueue(stale, "mail", 1, 0, 0)
	// every reader waits on the switch, and the claimer on its interval, before the clock moves
	awaitWaiting := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), testWakeSenderTimeout)
		defer cancel()
		if err := env.clock.AwaitTimers(ctx, settings.Queue.ShardCount+1); err != nil {
			t.Fatalf("the readers never waited: %v", env.clock.PendingTimers())
		}
	}
	awaitWaiting()
	if pending := env.clock.PendingTimers(); !pending[0].Equal(start.Add(5 * time.Second)) {
		t.Fatalf("pending %v", pending)
	}
	env.clock.Advance(61 * time.Second)
	if stats := sender.Stats(); stats.ReadCount != 0 {
		t.Fatalf("read while off: %+v", stats)
	}
	// each reader asked the switch again and waits once more, so switching it on now is read at their next ask
	awaitWaiting()
	env.enqueue(fresh, "mail", 1, 0, 0)
	env.on.Store(true)
	env.clock.Advance(5 * time.Second)
	results := map[connect.Id]pushservice.WakeSettledResult{}
	for range 2 {
		settled := env.next()
		results[settled.ClientId] = settled.Result
	}
	if results[stale] != pushservice.WakeSettledExpired || results[fresh] != pushservice.WakeSettledSent {
		t.Fatalf("results %v", results)
	}
}

// WK4: a wake carries a topic class and a version and nothing else. The bodies match their golden files, and
// a scan of every submission finds neither the client's id nor the repo id an evs topic named.
func TestWakePayloadsCarryNoId(t *testing.T) {
	cases := []struct {
		file string
		body []byte
	}{
		{file: "apns_mail_42.json", body: pushservice.ApnsWakeBody(&pushservice.WakePayload{TopicClass: "mail", Version: 42})},
		{file: "apns_evs_large.json", body: pushservice.ApnsWakeBody(&pushservice.WakePayload{TopicClass: "evs", Version: 18446744073709551615})},
		{file: "fcm_mail_42.json", body: pushservice.FcmWakeMessage("synthetic-fcm-token", &pushservice.WakePayload{TopicClass: "mail", Version: 42})},
		{file: "fcm_evs_large.json", body: pushservice.FcmWakeMessage("synthetic-fcm-token", &pushservice.WakePayload{TopicClass: "evs", Version: 18446744073709551615})},
	}
	for _, c := range cases {
		golden, err := os.ReadFile(filepath.Join("testdata", "wake", c.file))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bytes.TrimSpace(golden), c.body) {
			t.Errorf("%s: %s, not %s", c.file, c.body, bytes.TrimSpace(golden))
		}
	}

	env := newTestSenderEnv(t, nil)
	env.start("a")
	clients := []connect.Id{testWakeClient(1), testWakeClient(2)}
	env.token(clients[0], pushservice.WakePlatformApns, 1)
	env.token(clients[1], pushservice.WakePlatformFcm, 1)
	repoId := connect.Id{0xca, 0x4a, 0x41, 0x7e}
	topicClass, ok := pushservice.WakeTopicClass(sidecar.PushTopicEvsPrefix + repoId.String())
	if !ok || topicClass != "evs" {
		t.Fatalf("the evs topic's class %q", topicClass)
	}
	for _, client := range clients {
		env.enqueue(client, topicClass, 1800000000000000000, 0, 0)
		env.expect(client, pushservice.WakeSettledSent)
	}
	submissions := append(env.apns.Submissions(), env.fcm.Submissions()...)
	if len(submissions) != 2 {
		t.Fatalf("submissions %d", len(submissions))
	}
	for _, submission := range submissions {
		for _, id := range append([]connect.Id{repoId}, clients...) {
			for _, needle := range [][]byte{[]byte(id.String()), id.Bytes()} {
				if bytes.Contains(submission.Body, needle) {
					t.Errorf("a %s body names %s: %s", submission.Platform, id, submission.Body)
				}
			}
		}
	}
}

// A version past 2^53 reaches the vendor exact, as digits, never through a float.
func TestLargeVersionExact(t *testing.T) {
	for _, version := range []uint64{9007199254740993, 18446744073709551615, 1800000000000000001} {
		digits := strconv.FormatUint(version, 10)
		apns := pushservice.ApnsWakeBody(&pushservice.WakePayload{TopicClass: "evs", Version: version})
		if !bytes.HasSuffix(apns, []byte(`"v":`+digits+`}`)) {
			t.Errorf("apns %s", apns)
		}
		fcm := pushservice.FcmWakeMessage("synthetic-fcm-token", &pushservice.WakePayload{TopicClass: "evs", Version: version})
		if !bytes.Contains(fcm, []byte(`"v":"`+digits+`"`)) {
			t.Errorf("fcm %s", fcm)
		}
	}
	env := newTestSenderEnv(t, nil)
	env.start("a")
	client := testWakeClient(1)
	env.token(client, pushservice.WakePlatformApns, 1)
	env.enqueue(client, "evs", 18446744073709551615, 0, 0)
	env.expect(client, pushservice.WakeSettledSent)
	if submissions := env.apns.Submissions(); len(submissions) != 1 || submissions[0].Payload.Version != 18446744073709551615 ||
		!bytes.HasSuffix(submissions[0].Body, []byte(`"v":18446744073709551615}`)) {
		t.Fatalf("%+v", submissions)
	}
}

// A sender refuses what it cannot run on: no Redis, no consumer, settings out of range, two vendors of one
// platform.
func TestNewWakeSenderRefuses(t *testing.T) {
	env := newTestSenderEnv(t, nil)
	bad := testWakeSenderSettings()
	bad.ClientWindow = 0
	for _, args := range []*pushservice.WakeSenderArgs{
		nil,
		{Consumer: "a"},
		{Redis: env.redis},
		{Redis: env.redis, Consumer: "a", Settings: bad},
		{Redis: env.redis, Consumer: "a", Vendors: []pushservice.WakeVendor{env.apns, env.apns}},
	} {
		if sender, err := pushservice.NewWakeSender(t.Context(), args); err == nil {
			sender.Close()
			t.Errorf("%+v opened", args)
		}
	}
}
