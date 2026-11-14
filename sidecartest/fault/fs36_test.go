package fault

// FS-36 (§22.8, WK1 to WK4; §18.7's steps 0 to 4, §19.4's sender; SDK-M8-12) on T2: the hint writer with
// its enqueue, the token apply and the push sender as they ship, over sidecartest's FakeRedis with the
// scripts' twins, one fake clock and a vendor sink, no sleeps. Each client's keys and its wake shard's sit in
// different slots, and the fake refuses a call whose keys span two (WK1), which fails a test at its end. Each
// clause is its own test:
//
//   - live refreshed at 0 s and the client lost: a mail hint at 10 s gives one submission at 25 s +- 1 s, and
//     no second one;
//   - a hint the client's stack acked gives none;
//   - a forced router miss gives one at once, whatever live says;
//   - an XADD failing past its retries is counted in urnetwork_wake_enqueue_dropped_total, and a service
//     killed between the script and the XADD drops the wake uncounted; the hint state is intact in both, and
//     the next hint wakes as ever (WK2, WK3). The kill is at PROTO-M8-01's barrier where the build links the
//     hooks, and at the XADD's leaving the process where it does not. Both faults are the writers' own, at
//     their XADD: a fault plan on the shard's key would as soon take a sender's read;
//   - senders killed after XREADGROUP and after the send give at most one submission per 10 s, across the
//     sender that follows them and its claim of what they left;
//   - after a flush nothing is woken, a token gone with the rest, and wakes resume on a token POST's apply.
//
// The sentinel pass's half of the flush clause and the two restarted masters need the token rows and
// taskworker's pass, which are server's: server/model/fs36_wake_db_test.go runs them over Postgres, with these
// clauses again on a real Redis.

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How long a schedule waits on the sender or a timer before calling itself broken. Every wait is on an
// event.
const fs36Timeout = 30 * time.Second

// One FS-36 world: the fake cluster, its clock, the writers, the vendors and what the senders settled.
type fs36World struct {
	t       *testing.T
	ctx     context.Context
	clock   *sidecartest.FakeClock
	start   time.Time
	redis   *sidecartest.FakeRedis
	queue   *fs36WakeQueue
	metrics *sidecartest.FakeMetrics
	apns    *sidecartest.FakeWakeVendor
	fcm     *sidecartest.FakeWakeVendor

	tokenSettings  *fs36TokenSettings
	hintSettings   *pushservice.HintWriterSettings
	senderSettings *pushservice.WakeSenderSettings
	enqueuer       *pushservice.WakeEnqueuer
	writer         *pushservice.HintWriter
	settled        chan *pushservice.WakeSettled
}

// What the schedule's own steps take from §18.7: a writer's apply window and the publisher's live timeout.
type fs36TokenSettings struct {
	// A token apply older than this from its t0 is EXPIRED: 60 s.
	ApplyWindow time.Duration
	// How long a publisher's refresh keeps live: 90 s.
	LiveTimeout time.Duration
}

func defaultFs36TokenSettings() *fs36TokenSettings {
	return &fs36TokenSettings{
		ApplyWindow: 60 * time.Second,
		LiveTimeout: pushservice.DefaultSidecarPublisherSettings().LiveTimeout,
	}
}

// The sender's settings a schedule reads by: reads, claims and the switch's poll block long, each its own
// length, so the timers a schedule waits on are the dispatcher's, the backoffs', the readers' own and, where
// it asks for them, the claims'.
func fs36SenderSettings() *pushservice.WakeSenderSettings {
	settings := pushservice.DefaultWakeSenderSettings()
	settings.ReadBlock = 100 * time.Hour
	settings.ClaimInterval = 1000 * time.Hour
	settings.GateInterval = 10000 * time.Hour
	return settings
}

// The transport error a schedule's failed XADD answers.
var errFs36Xadd = errors.New("fs36: the wake shard's master did not answer")

// The writers' wake queue: the fake's XADD, which a schedule can fail or kill its caller at.
type fs36WakeQueue struct {
	redis *sidecartest.FakeRedis

	stateLock sync.Mutex
	// what each XADD meets before it leaves: an error fails it, nil or no function sends it on
	meet func() error
}

// Each XADD from here on meets meet first, nil for none.
func (self *fs36WakeQueue) setMeet(meet func() error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.meet = meet
}

// See pushservice.WakeQueueRedis.
func (self *fs36WakeQueue) StreamAdd(ctx context.Context, key string, maxLength int64, fieldValues map[string][]byte) (string, error) {
	meet := func() func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.meet
	}()
	if meet != nil {
		if err := meet(); err != nil {
			return "", err
		}
	}
	return self.redis.StreamAdd(ctx, key, maxLength, fieldValues)
}

func newFs36World(t *testing.T, senderSettings *pushservice.WakeSenderSettings) *fs36World {
	t.Helper()
	if senderSettings == nil {
		senderSettings = fs36SenderSettings()
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	redis := sidecartest.NewFakeRedis(t.Context(), clock, nil, nil, nil)
	t.Cleanup(redis.Close)
	sidecartest.RegisterPushScripts(redis)
	self := &fs36World{
		t:              t,
		ctx:            t.Context(),
		clock:          clock,
		start:          clock.Now(),
		redis:          redis,
		queue:          &fs36WakeQueue{redis: redis},
		metrics:        sidecartest.NewFakeMetrics(nil),
		apns:           sidecartest.NewFakeWakeVendor(pushservice.WakePlatformApns, clock),
		fcm:            sidecartest.NewFakeWakeVendor(pushservice.WakePlatformFcm, clock),
		tokenSettings:  defaultFs36TokenSettings(),
		hintSettings:   pushservice.DefaultHintWriterSettings(),
		senderSettings: senderSettings,
		settled:        make(chan *pushservice.WakeSettled, 256),
	}
	enqueuer, err := pushservice.NewWakeEnqueuer(self.queue, senderSettings.Queue, clock, func() bool { return true }, self.metrics)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := pushservice.NewWakingHintWriter(redis, nil, nil, nil, enqueuer)
	if err != nil {
		t.Fatal(err)
	}
	self.enqueuer, self.writer = enqueuer, writer
	// WK1 at run time: the fake records a call whose keys share no tag
	t.Cleanup(func() {
		if violations := redis.Violations(); len(violations) != 0 {
			t.Errorf("violations %v", violations)
		}
	})
	self.makeGroups()
	return self
}

// The senders' group on every shard, as it stands in production from the first sender's start: XGROUP
// CREATE takes entries from then on, so one queued before it would never be read.
func (self *fs36World) makeGroups() {
	self.t.Helper()
	for shard := range self.shardCount() {
		if err := self.redis.StreamGroupCreate(self.ctx, pushservice.WakeQueueKey(shard), self.senderSettings.ConsumerGroup); err != nil {
			self.t.Fatal(err)
		}
	}
}

func (self *fs36World) shardCount() int {
	if self.senderSettings.Queue != nil {
		return self.senderSettings.Queue.ShardCount
	}
	return pushservice.DefaultWakeQueueSettings().ShardCount
}

// A new client whose keys and whose wake shard's key sit in different slots, as FS-36 asks.
func (self *fs36World) client() connect.Id {
	self.t.Helper()
	for range 64 {
		clientId := connect.NewId()
		if sidecartest.RedisClusterSlot(pushservice.HintTokenKey(clientId)) != sidecartest.RedisClusterSlot(self.shardKey(clientId)) {
			return clientId
		}
	}
	self.t.Fatal("no client whose keys sit apart from its shard's")
	return connect.Id{}
}

// The wake-queue stream clientId's entries go to.
func (self *fs36World) shardKey(clientId connect.Id) string {
	return pushservice.WakeQueueKey(pushservice.WakeQueueShard(clientId, self.shardCount()))
}

// A token POST's apply for clientId at revision, as api runs it after its commit: t0 read from the
// master, then the apply script. Returns the token.
func (self *fs36World) register(clientId connect.Id, platform string, revision int64) string {
	self.t.Helper()
	token := "synthetic-" + platform + "-token-" + clientId.String()[:8]
	t0, err := pushservice.ReadWakeTokenTime(self.ctx, self.redis, clientId)
	if err != nil {
		self.t.Fatal(err)
	}
	row := &pushservice.WakeTokenRow{ClientId: clientId, Revision: revision, Platform: platform, Token: token}
	applied, err := pushservice.ApplyWakeToken(self.ctx, self.redis, row, t0, self.tokenSettings.ApplyWindow)
	if err != nil || applied != pushservice.WakeTokenApplied {
		self.t.Fatalf("the token's apply answered %q: %v", applied, err)
	}
	return token
}

// clientId's publisher refreshes live now. Nothing refreshes it again: the client is lost from here.
func (self *fs36World) live(clientId connect.Id) {
	self.t.Helper()
	if err := self.redis.Set(self.ctx, pushservice.HintLiveKey(clientId), []byte("1"), self.tokenSettings.LiveTimeout); err != nil {
		self.t.Fatal(err)
	}
}

// One hint to clientId through the waking writer, failing the test on an error.
func (self *fs36World) hint(clientId connect.Id, hint *sidecar.ClientHint) *pushservice.PushHintResult {
	self.t.Helper()
	result, err := self.writer.HintClient(self.ctx, clientId, hint)
	if err != nil {
		self.t.Fatal(err)
	}
	return result
}

// A sender as consumer over redis, ended with ctx or at the test's end. Returns once each of its readers is
// in its read, as a sender long up is: one that had not yet made its group would make it after the entries
// a schedule queues, and never read them.
func (self *fs36World) startSender(ctx context.Context, consumer string, redis pushservice.WakeSenderRedis) *pushservice.WakeSender {
	self.t.Helper()
	readsEnd := self.clock.Now().Add(self.senderSettings.ReadBlock)
	readingCount := self.timerCount(readsEnd)
	sender, err := pushservice.NewWakeSender(ctx, &pushservice.WakeSenderArgs{
		Redis:    redis,
		Vendors:  []pushservice.WakeVendor{self.apns, self.fcm},
		Consumer: consumer,
		Enabled:  func() bool { return true },
		Clock:    self.clock,
		Metrics:  self.metrics,
		Settings: self.senderSettings,
		Settled: func(settled *pushservice.WakeSettled) {
			self.settled <- settled
		},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(sender.Close)
	self.awaitTimers(readsEnd, readingCount+self.shardCount())
	return sender
}

// How many timers at at are pending.
func (self *fs36World) timerCount(at time.Time) int {
	pending, _ := self.clock.WatchTimers()
	count := 0
	for _, timer := range pending {
		if timer.Equal(at) {
			count += 1
		}
	}
	return count
}

// The next settlement.
func (self *fs36World) next() *pushservice.WakeSettled {
	self.t.Helper()
	select {
	case settled := <-self.settled:
		return settled
	case <-time.After(fs36Timeout):
		self.t.Fatal("nothing settled")
		return nil
	}
}

// The next settlement, which must be result for clientId.
func (self *fs36World) expect(clientId connect.Id, result pushservice.WakeSettledResult) *pushservice.WakeSettled {
	self.t.Helper()
	settled := self.next()
	if settled.ClientId != clientId || settled.Result != result {
		self.t.Fatalf("settled %+v, not %s for %s", settled, result, clientId)
	}
	return settled
}

// Returns once count timers at at are pending: the dispatcher waiting for a due, or count readers in a
// backoff or a read.
func (self *fs36World) awaitTimers(at time.Time, count int) {
	self.t.Helper()
	guard := time.After(fs36Timeout)
	for {
		pending, added := self.clock.WatchTimers()
		found := 0
		for _, timer := range pending {
			if timer.Equal(at) {
				found += 1
			}
		}
		if count <= found {
			return
		}
		select {
		case <-added:
		case <-guard:
			self.t.Fatalf("%d of %d timers at %s: %v", found, count, at.Sub(self.start), pending)
		}
	}
}

// Moves the clock to offset past the world's start.
func (self *fs36World) advanceTo(offset time.Duration) {
	self.clock.AdvanceTo(self.start.Add(offset))
}

// Every submission of either vendor that carried token, in time order.
func (self *fs36World) submissions(token string) []*sidecartest.FakeWakeSubmission {
	submissions := []*sidecartest.FakeWakeSubmission{}
	for _, submission := range append(self.apns.Submissions(), self.fcm.Submissions()...) {
		if submission.Token == token {
			submissions = append(submissions, submission)
		}
	}
	slices.SortStableFunc(submissions, func(a *sidecartest.FakeWakeSubmission, b *sidecartest.FakeWakeSubmission) int {
		return a.At.Compare(b.At)
	})
	return submissions
}

// Every entry of clientId's wake shard, and the ids still pending in the senders' group.
func (self *fs36World) queued(clientId connect.Id) (entries []*pushservice.WakeEntry, pendingCount int) {
	self.t.Helper()
	streamEntries, err := self.redis.StreamRange(self.ctx, self.shardKey(clientId), "", 1000)
	if err != nil {
		self.t.Fatal(err)
	}
	for _, streamEntry := range streamEntries {
		entry, err := pushservice.ParseWakeEntry(streamEntry)
		if err != nil {
			self.t.Fatal(err)
		}
		if entry.ClientId == clientId {
			entries = append(entries, entry)
		}
	}
	for _, entryIds := range self.redis.StreamPending(self.shardKey(clientId), self.senderSettings.ConsumerGroup) {
		pendingCount += len(entryIds)
	}
	return entries, pendingCount
}

// Fails unless clientId's hint state is as its script left it: ver at version for topic, and the hint
// stream ending at streamId, hintCount entries long.
func (self *fs36World) expectHintState(clientId connect.Id, topic string, version uint64, streamId string, hintCount int) {
	self.t.Helper()
	versions, err := self.redis.HashGetAll(self.ctx, pushservice.HintVersionsKey(clientId))
	if err != nil {
		self.t.Fatal(err)
	}
	if got := string(versions[topic]); got != pushservice.FormatVersion(version) {
		self.t.Fatalf("ver holds %q for %s, not %d", got, topic, version)
	}
	hints, err := self.redis.StreamRange(self.ctx, pushservice.HintStreamKey(clientId), "", 1000)
	if err != nil {
		self.t.Fatal(err)
	}
	if len(hints) != hintCount || (streamId != "" && hints[len(hints)-1].Id != streamId) {
		self.t.Fatalf("the hint stream holds %d entries, not %d ending at %s", len(hints), hintCount, streamId)
	}
}

// Live refreshed at 0 s and the client lost: a mail hint at 10 s is put off 15 s, since a resident
// seemed live, and gives one submission at 25 s +- 1 s, carrying the class and the version and no id. Nothing
// follows it: the entry is acknowledged, and a minute on the vendor has had the one.
func TestFs36LostClientsMailHintWakesOnceAt25s(t *testing.T) {
	world := newFs36World(t, nil)
	clientId := world.client()
	token := world.register(clientId, pushservice.WakePlatformApns, 7)
	world.live(clientId)
	world.startSender(world.ctx, "a", world.redis)

	world.advanceTo(10 * time.Second)
	result := world.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 41, Body: []byte{1}})
	if !result.Live || result.Wake != pushservice.WakeEnqueueDeferred {
		t.Fatalf("the hint at 10 s: live %t, wake %d", result.Live, result.Wake)
	}
	world.awaitTimers(world.start.Add(25*time.Second), 1)
	world.advanceTo(24 * time.Second)
	if submissions := world.submissions(token); len(submissions) != 0 {
		t.Fatalf("woken %s after the start, before the hint's 15 s", submissions[0].At.Sub(world.start))
	}
	world.advanceTo(26 * time.Second)
	if settled := world.expect(clientId, pushservice.WakeSettledSent); !settled.Acked || settled.TopicClass != "mail" {
		t.Fatalf("%+v", settled)
	}
	submissions := world.submissions(token)
	if len(submissions) != 1 {
		t.Fatalf("%d submissions", len(submissions))
	}
	if at := submissions[0].At.Sub(world.start); at < 24*time.Second || 26*time.Second < at {
		t.Fatalf("the submission at %s, not 25 s +- 1 s", at)
	}
	if payload := submissions[0].Payload; payload.TopicClass != "mail" || payload.Version != 41 {
		t.Fatalf("the payload %+v", payload)
	}
	world.advanceTo(90 * time.Second)
	if submissions := world.submissions(token); len(submissions) != 1 {
		t.Fatalf("%d submissions a minute on", len(submissions))
	}
	if entries, pendingCount := world.queued(clientId); len(entries) != 1 || pendingCount != 0 {
		t.Fatalf("%d entries, %d pending", len(entries), pendingCount)
	}
}

// A hint the client's stack acked gives no submission: the same schedule, the client alive, its publisher
// raising ack to the hint at 12 s. At 25 s the sender reads ack at the entry's hint and drops the entry.
func TestFs36AckedHintIsNotWoken(t *testing.T) {
	world := newFs36World(t, nil)
	clientId := world.client()
	token := world.register(clientId, pushservice.WakePlatformApns, 7)
	world.live(clientId)
	world.startSender(world.ctx, "a", world.redis)

	world.advanceTo(10 * time.Second)
	result := world.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 41, Body: []byte{1}})
	if result.Wake != pushservice.WakeEnqueueDeferred {
		t.Fatalf("the hint at 10 s: wake %d", result.Wake)
	}
	world.awaitTimers(world.start.Add(25*time.Second), 1)
	world.advanceTo(12 * time.Second)
	if raised, err := pushservice.RaiseHintAck(world.ctx, world.redis, clientId, result.StreamId, world.hintSettings.AckTimeout); err != nil || !raised {
		t.Fatalf("the ack: %t, %v", raised, err)
	}
	world.advanceTo(25 * time.Second)
	if settled := world.expect(clientId, pushservice.WakeSettledAcked); !settled.Acked {
		t.Fatalf("%+v", settled)
	}
	world.advanceTo(90 * time.Second)
	if submissions := world.submissions(token); len(submissions) != 0 {
		t.Fatalf("an acked hint was woken %d times", len(submissions))
	}
	if _, pendingCount := world.queued(clientId); pendingCount != 0 {
		t.Fatalf("%d pending", pendingCount)
	}
}

// A forced router miss gives one submission at once: live was refreshed 10 s before, so an unforced hint
// would wait its 15 s, and the forced one is due now.
func TestFs36ForcedRouterMissWakesAtOnce(t *testing.T) {
	world := newFs36World(t, nil)
	clientId := world.client()
	token := world.register(clientId, pushservice.WakePlatformFcm, 7)
	world.live(clientId)
	world.startSender(world.ctx, "a", world.redis)

	world.advanceTo(10 * time.Second)
	result := world.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicCore, Version: 9, Forced: true})
	if !result.Live || result.Wake != pushservice.WakeEnqueueDue {
		t.Fatalf("the forced hint: live %t, wake %d", result.Live, result.Wake)
	}
	if settled := world.expect(clientId, pushservice.WakeSettledSent); !settled.Acked || settled.Platform != pushservice.WakePlatformFcm {
		t.Fatalf("%+v", settled)
	}
	submissions := world.submissions(token)
	if len(submissions) != 1 || !submissions[0].At.Equal(world.start.Add(10*time.Second)) || submissions[0].Payload.TopicClass != "core" {
		t.Fatalf("submissions %+v", submissions)
	}
	world.advanceTo(90 * time.Second)
	if submissions := world.submissions(token); len(submissions) != 1 {
		t.Fatalf("%d submissions a minute on", len(submissions))
	}
}

// An XADD that fails past its retries is counted in urnetwork_wake_enqueue_dropped_total and dropped: the
// hint's write stands in the client's slot as the script left it, nothing is queued and nothing is woken
// (WK3). The shard answering again, the next hint wakes as ever.
func TestFs36XaddPastItsRetriesIsCountedHintIntact(t *testing.T) {
	world := newFs36World(t, nil)
	clientId := world.client()
	token := world.register(clientId, pushservice.WakePlatformApns, 7)
	world.startSender(world.ctx, "a", world.redis)
	world.queue.setMeet(func() error { return errFs36Xadd })

	queue := pushservice.DefaultWakeQueueSettings()
	spacing := queue.RetryWindow / time.Duration(queue.RetryCount)
	done := make(chan *pushservice.PushHintResult, 1)
	go func() {
		result, err := world.writer.HintClient(world.ctx, clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 5, Body: []byte{1}})
		if err != nil {
			t.Error(err)
		}
		done <- result
	}()
	for range queue.RetryCount {
		world.awaitTimers(world.clock.Now().Add(spacing), 1)
		world.clock.Advance(spacing)
	}
	var result *pushservice.PushHintResult
	select {
	case result = <-done:
	case <-time.After(fs36Timeout):
		t.Fatal("the hint did not return")
	}
	if result == nil || result.Wake != pushservice.WakeEnqueueDropped {
		t.Fatalf("the hint: %+v", result)
	}
	if elapsed := world.clock.Now().Sub(world.start); queue.RetryWindow < elapsed {
		t.Fatalf("the retries took %s", elapsed)
	}
	if dropped := world.metrics.Value("urnetwork_wake_enqueue_dropped_total", "mail"); dropped != 1 {
		t.Fatalf("urnetwork_wake_enqueue_dropped_total %v", dropped)
	}
	if stats := world.enqueuer.Stats(); stats.DroppedCount != 1 || stats.FailedAttemptCount != uint64(queue.RetryCount+1) {
		t.Fatalf("%+v", stats)
	}
	world.queue.setMeet(nil)
	world.expectHintState(clientId, sidecar.PushTopicMail, 5, result.StreamId, 1)
	if entries, _ := world.queued(clientId); len(entries) != 0 {
		t.Fatalf("a dropped wake left %d entries", len(entries))
	}
	world.advanceTo(30 * time.Second)
	if submissions := world.submissions(token); len(submissions) != 0 {
		t.Fatalf("a dropped wake reached the vendor %d times", len(submissions))
	}

	// the loss is that wake's alone
	next := world.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 6, Body: []byte{2}})
	if next.Wake != pushservice.WakeEnqueueDue {
		t.Fatalf("the next hint: wake %d", next.Wake)
	}
	world.expect(clientId, pushservice.WakeSettledSent)
	world.expectHintState(clientId, sidecar.PushTopicMail, 6, next.StreamId, 2)
	if dropped := world.metrics.Value("urnetwork_wake_enqueue_dropped_total", "mail"); dropped != 1 {
		t.Fatalf("urnetwork_wake_enqueue_dropped_total %v after a wake that landed", dropped)
	}
}

// A service killed between the hint script and the XADD drops the wake and nothing else: the call never
// returns, the hint is in the client's slot as the script left it, no entry is queued, nothing is counted,
// since nothing lived to count it (WK2's uncounted loss), and nothing is woken. The next hint wakes as ever.
func TestFs36KillBetweenScriptAndXaddDropsTheWakeHintIntact(t *testing.T) {
	world := newFs36World(t, nil)
	clientId := world.client()
	token := world.register(clientId, pushservice.WakePlatformApns, 7)
	world.startSender(world.ctx, "a", world.redis)

	// PROTO-M8-01's barrier sits between the two where the build links the hooks; where it does not, the
	// process dies as the XADD leaves it
	removeHooks := func() {}
	if sidecartest.HooksLinked {
		remove, err := sidecartest.InstallTestHooks(nil, func(name string, key string) {
			if name == "pushservice.wake.before" && key == clientId.String() {
				runtime.Goexit()
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		var removeOne sync.Once
		removeHooks = func() { removeOne.Do(remove) }
		t.Cleanup(removeHooks)
	} else {
		world.queue.setMeet(func() error {
			runtime.Goexit()
			return nil
		})
	}
	returned := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		world.writer.HintClient(world.ctx, clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicTeam, Version: 11})
		close(returned)
	}()
	select {
	case <-exited:
	case <-time.After(fs36Timeout):
		t.Fatal("the killed writer is still running")
	}
	select {
	case <-returned:
		t.Fatal("the writer returned past its kill")
	default:
	}
	removeHooks()
	world.queue.setMeet(nil)

	world.expectHintState(clientId, sidecar.PushTopicTeam, 11, "", 1)
	if entries, _ := world.queued(clientId); len(entries) != 0 {
		t.Fatalf("the killed enqueue left %d entries", len(entries))
	}
	if stats := world.enqueuer.Stats(); stats.DroppedCount != 0 || stats.DueCount != 0 {
		t.Fatalf("%+v", stats)
	}
	if dropped := world.metrics.Value("urnetwork_wake_enqueue_dropped_total", "team"); dropped != 0 {
		t.Fatalf("urnetwork_wake_enqueue_dropped_total %v for a wake nothing lived to count", dropped)
	}
	world.advanceTo(30 * time.Second)
	if submissions := world.submissions(token); len(submissions) != 0 {
		t.Fatalf("a wake never queued reached the vendor %d times", len(submissions))
	}

	next := world.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicTeam, Version: 12})
	if next.Wake != pushservice.WakeEnqueueDue {
		t.Fatalf("the next hint: wake %d", next.Wake)
	}
	world.expect(clientId, pushservice.WakeSettledSent)
	world.expectHintState(clientId, sidecar.PushTopicTeam, 12, next.StreamId, 2)
}

// A sender's Redis whose process dies once an XREADGROUP of its has taken entries: they are pending in
// the group under its consumer, and it held none of them.
type fs36KilledAfterRead struct {
	*sidecartest.FakeRedis
	kill    context.CancelFunc
	killed  chan struct{}
	killOne sync.Once
}

func (self *fs36KilledAfterRead) StreamGroupRead(ctx context.Context, key string, group string, consumer string, count int64, block time.Duration) ([]*sidecar.RedisStreamEntry, error) {
	entries, err := self.FakeRedis.StreamGroupRead(ctx, key, group, consumer, count, block)
	if err == nil && 0 < len(entries) {
		self.kill()
		self.killOne.Do(func() { close(self.killed) })
		return nil, context.Canceled
	}
	return entries, err
}

// Sender kills after XREADGROUP and after the send give at most one submission per 10 s. The client is
// lost, so each hint is due at once. The first sender dies holding the first hint's entry unsent; the second
// dies after its vendor call for the second hint, at 1 s, and before its ack, its window left in Redis; the
// third puts a hint at 5 s off to the window's end and wakes at 11 s, then claims what the two left, once
// idle 30 s, and wakes at most once more for both. Every two submissions are at least 10 s apart, and no
// entry stays pending.
func TestFs36SenderKillsGiveAtMostOneSubmissionPer10s(t *testing.T) {
	settings := fs36SenderSettings()
	settings.ClaimInterval = 31 * time.Second
	world := newFs36World(t, settings)
	clientId := world.client()
	token := world.register(clientId, pushservice.WakePlatformApns, 7)

	// killed after XREADGROUP
	readCtx, killRead := context.WithCancel(world.ctx)
	killedAfterRead := &fs36KilledAfterRead{FakeRedis: world.redis, kill: killRead, killed: make(chan struct{})}
	readKilled := world.startSender(readCtx, "killed-after-read", killedAfterRead)
	world.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 1, Body: []byte{1}})
	select {
	case <-killedAfterRead.killed:
	case <-time.After(fs36Timeout):
		t.Fatal("the first sender read nothing")
	}
	readKilled.Close()
	if _, pendingCount := world.queued(clientId); pendingCount != 1 || len(world.submissions(token)) != 0 {
		t.Fatalf("after the kill past the read: %d pending, %d submissions", pendingCount, len(world.submissions(token)))
	}

	// killed after the send
	world.advanceTo(1 * time.Second)
	sendCtx, killSend := context.WithCancel(world.ctx)
	world.apns.SetHook(func(ctx context.Context, submission *sidecartest.FakeWakeSubmission) {
		if submission.At.Equal(world.start.Add(1 * time.Second)) {
			// the process dies once the vendor has the wake, before its ack
			killSend()
		}
	})
	sendKilled := world.startSender(sendCtx, "killed-after-send", world.redis)
	world.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 2, Body: []byte{2}})
	if settled := world.expect(clientId, pushservice.WakeSettledSent); settled.Acked {
		t.Fatalf("the killed sender acknowledged %+v", settled)
	}
	sendKilled.Close()
	if _, pendingCount := world.queued(clientId); pendingCount != 2 {
		t.Fatalf("after the kill past the send: %d pending", pendingCount)
	}

	// a new process: a hint inside the killed sender's window waits for its end
	world.startSender(world.ctx, "next", world.redis)
	world.advanceTo(5 * time.Second)
	world.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 3, Body: []byte{3}})
	world.awaitTimers(world.start.Add(11*time.Second), 1)
	world.advanceTo(10 * time.Second)
	if submissions := world.submissions(token); len(submissions) != 1 {
		t.Fatalf("%d submissions inside the killed sender's window", len(submissions))
	}
	world.advanceTo(11 * time.Second)
	if settled := world.expect(clientId, pushservice.WakeSettledSent); !settled.Acked {
		t.Fatalf("%+v", settled)
	}

	// the killed senders' two entries, idle 30 s at the next sender's first claim, at 32 s
	world.advanceTo(32 * time.Second)
	results := map[pushservice.WakeSettledResult]int{}
	for range 2 {
		settled := world.next()
		if settled.ClientId != clientId || !settled.Acked {
			t.Fatalf("a claimed entry settled %+v", settled)
		}
		results[settled.Result] += 1
	}
	if 1 < results[pushservice.WakeSettledSent] || results[pushservice.WakeSettledSent]+results[pushservice.WakeSettledCoalesced] != 2 {
		t.Fatalf("the claimed entries settled %v", results)
	}
	world.advanceTo(90 * time.Second)
	submissions := world.submissions(token)
	if len(submissions) < 2 || 3 < len(submissions) {
		t.Fatalf("%d submissions", len(submissions))
	}
	for i := 1; i < len(submissions); i += 1 {
		if apart := submissions[i].At.Sub(submissions[i-1].At); apart < settings.ClientWindow {
			t.Fatalf("submissions %s apart, at %s and %s", apart, submissions[i-1].At.Sub(world.start), submissions[i].At.Sub(world.start))
		}
	}
	if entries, pendingCount := world.queued(clientId); len(entries) != 3 || pendingCount != 0 {
		t.Fatalf("%d entries, %d pending", len(entries), pendingCount)
	}
}

// After a flush nothing is woken: the token went with every other key, so a hint finds none and queues
// nothing, its own state made again by its script. The senders make their group again, and wakes resume on a
// token POST's apply, the next hint waking at once with no other step. The fake does not fail a blocked
// XREADGROUP at a flush as a real master does, so the readers meet the missing group at the next stream
// write and make it after their backoff, which the schedule waits out before the POST.
func TestFs36WakesResumeOnATokenPostAfterAFlush(t *testing.T) {
	world := newFs36World(t, nil)
	clientId := world.client()
	token := world.register(clientId, pushservice.WakePlatformApns, 7)
	world.startSender(world.ctx, "a", world.redis)
	if before := world.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 1, Body: []byte{1}}); before.Wake != pushservice.WakeEnqueueDue {
		t.Fatalf("before the flush: wake %d", before.Wake)
	}
	world.expect(clientId, pushservice.WakeSettledSent)

	world.advanceTo(20 * time.Second)
	world.redis.LoseEverything()
	lost := world.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 2, Body: []byte{2}})
	if lost.Token != nil || lost.Wake != pushservice.WakeEnqueueNone {
		t.Fatalf("after the flush: token %q, wake %d", lost.Token, lost.Wake)
	}
	world.expectHintState(clientId, sidecar.PushTopicMail, 2, lost.StreamId, 1)
	// every reader in its backoff, then in its read again, the group made
	world.awaitTimers(world.clock.Now().Add(world.senderSettings.ErrorBackoff), world.shardCount())
	world.clock.Advance(world.senderSettings.ErrorBackoff)
	world.awaitTimers(world.clock.Now().Add(world.senderSettings.ReadBlock), world.shardCount())
	world.advanceTo(40 * time.Second)
	if submissions := world.submissions(token); len(submissions) != 1 {
		t.Fatalf("%d submissions with the token gone", len(submissions))
	}

	// the app's launch posts its token, and the next hint wakes
	reposted := world.register(clientId, pushservice.WakePlatformApns, 8)
	resumed := world.hint(clientId, &sidecar.ClientHint{Topic: sidecar.PushTopicMail, Version: 3, Body: []byte{3}})
	if resumed.Token == nil || resumed.Wake != pushservice.WakeEnqueueDue {
		t.Fatalf("after the POST: token %q, wake %d", resumed.Token, resumed.Wake)
	}
	if settled := world.expect(clientId, pushservice.WakeSettledSent); !settled.Acked {
		t.Fatalf("%+v", settled)
	}
	submissions := world.submissions(reposted)
	if len(submissions) != 2 || !submissions[1].At.Equal(world.start.Add(40*time.Second)) || submissions[1].Payload.Version != 3 {
		t.Fatalf("submissions %+v", submissions)
	}
}
