//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// The later pass of the root's waits that end with their context (clock-sweep-later-pass, after clock-select-ctx-sweep;
// clock_select_ctx_sweep_test.go holds the account). Each loop or wait here stepped past its end, when select took a
// timer, or a wake a clock's AfterFunc gave, as the end landed, into something outward or durable: the agents' inbox
// watch handed messages to agents and took them, the status writer took statuses off their lines and wrote them, a
// creation's wait for the path epoch and gkm's waits let a push or a flow go on, the prefix repair cut its journal,
// the evs subscriber's rounds took the pending deletes off their list and its lease retry dropped the subscription for
// good, the key upkeep dropped and minted ReaderKeys, the usage batcher sent and counted, the record writer tended and
// drained its spool, remote search set the foreground on the dead dispatcher, the search sync began a non-writer's
// receipt round, the config follower anchored and bound the member record, the socket component withdrew key paths and
// rechecked live streams, and the support client logged its token's failure to the support log. Each now answers the
// end whatever else was ready, and an ended context asks the clock for nothing. The Forwarder's wait, which another
// lane held when clock-wait-at-sweep ran, is set for its time itself (QD-1425).
//
// The proof is clockSelectEndingClock (clock_select_ctx_sweep_rest_test.go), sidecartest's EndingClock with its
// AfterFunc's waits fired as FireAfterFuncs has them, which the root's own tests cannot import: it ends the context as
// a wait fires, so the end and the timer or wake are both ready when select runs, over 64 rounds. Where the old loop
// took two coins in a row to step past the end, it passed a round with odds 3/4, and 64 rounds leave it (3/4)^64, under
// one in ten million. The team directory's wait is in clock_select_ctx_sweep_later_external_test.go, on the gkm world.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The Forwarder's loop sets its wait for the time it is next due itself (QD-1425): on a ClockAt, the wait after the
// first follow is set for the follow's time, its start plus FollowInterval, and moving the clock to that time follows
// again. The loop once took the timeout to that time from its reading, so a move of a fake clock by another goroutine
// between the reading and the wait set the wait late, and on this clock it sets no wait for the time at all.
func TestForwarderWaitsForTheFollowsTimeItself(t *testing.T) {
	world := newTestForwarderClockWorld(t)
	clock := newTestClockAt()
	world.sink = &testClockCheckSink{clock: clock}
	followAt := clock.Now().Add(world.settings.FollowInterval)
	networkId := testConfigId("wait at network")
	genesisSha256 := sha256.Sum256([]byte("wait at genesis"))
	forwarder, err := NewForwarder(context.Background(), &ForwarderArgs{
		NetworkId:  networkId,
		SidecarId:  testConfigId("wait at sidecar"),
		Pending:    &bridge.Pending{NetworkId: networkId.Bytes(), GenesisSha256: genesisSha256[:]},
		Projection: world,
		Store:      newTestConfigClientStore(),
		Keys:       &testForwarderKeys{},
		Sink:       world.sink,
		Clock:      clock,
		Log:        NewNoopLogger(),
		Settings:   world.settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(forwarder.Close)
	world.awaitRead()
	guard := time.After(testClockCheckGuardTimeout)
	for {
		// the wait's time is recorded before the clock counts the wait, so a count read first misses no time
		_, changed := clock.clock.waitCount.Get()
		times, _ := clock.asked()
		if slices.ContainsFunc(times, followAt.Equal) {
			break
		}
		select {
		case <-changed:
		case <-guard:
			t.Fatalf("the loop set no wait for the follow's time %v, only for %v", followAt, times)
		}
	}
	world.expectQuiet("before the follow's time")
	clock.clock.Advance(world.settings.FollowInterval)
	world.awaitRead()
}

// An agents client whose feature check refuses every place, so each pass of what reads through it fails at once, with
// no I/O.
func newClockSweepLaterAgentsClient(clock Clock, settings *SkillSettings) *AgentsClient {
	return &AgentsClient{
		args: &AgentsClientArgs{FeatureCheck: func() error {
			return errors.New("agent repos are off in this test")
		}},
		settings:       settings,
		clock:          clock,
		alarmedPushIds: map[Id]bool{},
	}
}

// The agents' inbox watch passes nothing once it has ended: each pass refused, it signals itself and pauses
// WatchRetryWait, and an end landing as the second pause's end fires ends the watch after the two passes before it, in
// each of 64 rounds. A watch that took the pause's end and then its signal passed on the dead watch, which hands the
// messages it reads to the agents they address and records them taken.
func TestAgentInboxWatchPassesNothingAfterItEnds(t *testing.T) {
	settings := DefaultSkillSettings()
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, settings.WatchRetryWait)
		passCount := &atomic.Int64{}
		ctx, cancel := context.WithCancel(context.Background())
		watch := &AgentInboxWatch{
			client: newClockSweepLaterAgentsClient(clock, settings),
			args: &AgentWatchArgs{Passed: func(err error) {
				passCount.Add(1)
			}},
			ctx:           ctx,
			cancel:        cancel,
			wake:          make(chan struct{}, 1),
			done:          make(chan struct{}),
			settings:      settings,
			clock:         clock,
			subscriptions: map[Id]*EvsSubscription{},
		}
		clock.arm(2, cancel)
		clock.open()
		watch.signal()
		go watch.run()
		clock.awaitDone(t, watch.done, "the watch")
		if passes := passCount.Load(); passes != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d passes and %d pauses, want 2 of each", round, passes, clock.waits())
		}
	}
}

// The agents' status writer writes nothing once it has closed: an open line refreshes its status each
// StatusRefreshInterval, its wait an AfterFunc that signals the writer, and a close landing as the second wait's signal
// comes ends the writer after the one refresh between, in each of 64 rounds. A writer that took the signal took the
// line's refresh and wrote it on the closed writer, a registration first where the card is absent.
func TestAgentStatusWriterWritesNothingAfterItCloses(t *testing.T) {
	settings := DefaultSkillSettings()
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), true, settings.StatusRefreshInterval)
		writeCount := &atomic.Int64{}
		ctx, cancel := context.WithCancel(context.Background())
		writer := &AgentStatusWriter{
			client:   newClockSweepLaterAgentsClient(clock, settings),
			settings: settings,
			clock:    clock,
			log:      NewNoopLogger(),
			written: func(name AgentName, err error) {
				writeCount.Add(1)
			},
			ctx:    ctx,
			cancel: cancel,
			wake:   make(chan struct{}, 1),
			done:   make(chan struct{}),
			lines: map[AgentName]*agentStatusLine{
				"builder": {
					name:    "builder",
					last:    &AgentStatus{State: AgentStateWorking, Updated: clock.Now()},
					lastAt:  clock.Now(),
					written: true,
					open:    true,
				},
			},
		}
		clock.arm(2, cancel)
		clock.open()
		go writer.run()
		clock.awaitDone(t, writer.done, "the writer")
		if writes := writeCount.Load(); writes != 1 || clock.waits() != 2 {
			t.Fatalf("round %d: %d writes and %d waits, want 1 write and 2 waits", round, writes, clock.waits())
		}
	}
}

// A creation's wait for the path epoch answers its context's end whatever else was ready: an end landing as the wait's
// timer fires answers the context's error, in each of 64 rounds, and an ended context asks the clock for nothing. A
// wait that took the timer's case answered nil, and its caller planned the push again on the dead context.
func TestEvsWaitPathEpochAnswersTheEndOfItsContext(t *testing.T) {
	settings := DefaultEvsSettings()
	wait := min(settings.PathEpochDueWait, settings.PushRetryMaxWait)
	newRepo := func(clock Clock) *EvsRepo {
		return &EvsRepo{client: &EvsClient{settings: settings, clock: clock, epochs: newEvsClientEpochs()}, repoId: NewId()}
	}
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, wait)
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(1, cancel)
		clock.open()
		if err := newRepo(clock).waitPathEpoch(ctx, NewId(), nil); !errors.Is(err, context.Canceled) || clock.waits() != 1 {
			t.Fatalf("round %d: the wait answered %v after %d waits, want canceled after 1", round, err, clock.waits())
		}
	}
	clock := newClockSelectEndingClock(t, clockSelectTestStart(), false)
	clock.open()
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if err := newRepo(clock).waitPathEpoch(ended, NewId(), nil); !errors.Is(err, context.Canceled) || clock.asks() != 0 {
		t.Fatalf("an ended context: %v after %d waits", err, clock.asks())
	}
}

// gkm's waits answer their context's end whatever else was ready: an end landing as the delay's timer fires, or as the
// time's, answers the context's error, in each of 64 rounds. A wait that took the timer's case answered nil, and its
// flow's next step, a commit's keys or a call, ran on the dead context.
func TestGkmWaitsAnswerTheEndOfTheirContext(t *testing.T) {
	delay := 3 * time.Second
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, delay)
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(1, cancel)
		clock.open()
		if err := (&GkmGroupClient{clock: clock}).wait(ctx, delay); !errors.Is(err, context.Canceled) || clock.waits() != 1 {
			t.Fatalf("round %d: the delay's wait answered %v after %d waits", round, err, clock.waits())
		}

		clock = newClockSelectEndingClock(t, clockSelectTestStart(), false, delay)
		ctx, cancel = context.WithCancel(context.Background())
		clock.arm(1, cancel)
		clock.open()
		if err := (&GkmGroupClient{clock: clock}).waitUntil(ctx, clock.Now().Add(delay)); !errors.Is(err, context.Canceled) || clock.waits() != 1 {
			t.Fatalf("round %d: the time's wait answered %v after %d waits", round, err, clock.waits())
		}
	}
}

// The prefix rules' repair passes nothing once its context has ended: it passes after each RepairPassInterval, and an
// end landing as the second interval's end fires ends the loop after the one pass between, in each of 64 rounds. Each
// pass ends in a wait, so one the end did not stop shows as a third wait asked: a loop that took the timer's case
// passed on the dead context, which removes from the sealed journal what it settles with no read, whatever its reads
// meet.
func TestEvsPrefixRepairPassesNothingAfterItsContextEnds(t *testing.T) {
	settings := testAclPrefixSettingsOn()
	test := newEvsTestClient(t, http.NotFoundHandler(), newEvsTestStore(t))
	test.client.EnablePrefixRules(&EvsPrefixRulesArgs{Repair: true, Settings: settings})
	component := &EvsComponent{client: test.client}
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, settings.RepairPassInterval)
		// no loop runs between rounds, so the client's clock is the round's alone
		test.client.clock = clock
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(2, cancel)
		clock.open()
		clock.awaitRun(t, "the repair loop", func() {
			component.runPrefixRepair(ctx)
		})
		cancel()
		if clock.waits() != 2 {
			t.Fatalf("round %d: %d waits, want the 2 of 1 pass", round, clock.waits())
		}
	}
}

// A store whose listings are refused: the evs subscriber's load fails each round, which then answers its retry's time.
type clockSweepLaterUnlistedStore struct {
	SidecarStore
}

func (self *clockSweepLaterUnlistedStore) List(prefix string) ([]SidecarStoreEntry, error) {
	return nil, errors.New("the listing is refused")
}

// The evs subscriber's rounds run none once their context has ended: with the stored subscriptions refused, each round
// answers SubscribeRetryMaxWait on, and an end landing as the second wait fires ends the rounds after the two before
// it, in each of 64 rounds. Rounds that took the timer's case ran one on the dead context, which takes the pending
// deletes off their list and moves the resync's and the renewals' times whatever its calls meet.
func TestEvsSubscriberRoundsRunNoneAfterTheirContextEnds(t *testing.T) {
	test := newEvsTestClient(t, http.NotFoundHandler(), &clockSweepLaterUnlistedStore{SidecarStore: newEvsTestStore(t)})
	subscriber := test.client.subscriber
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, test.client.settings.SubscribeRetryMaxWait)
		// no round runs between rounds, so the client's clock is the round's alone
		test.client.clock = clock
		roundsBefore := subscriber.roundCount.Value()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		clock.arm(2, cancel)
		clock.open()
		go subscriber.run(ctx, done)
		clock.awaitDone(t, done, "the rounds")
		if rounds := subscriber.roundCount.Value() - roundsBefore; rounds != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d rounds and %d waits, want 2 of each", round, rounds, clock.waits())
		}
	}
}

// A subscription's lease retry answers as its context's end does: with every lease POST answered 503, the first retry
// waits until its due time, and an end landing as that wait fires answers the subscription, kept with its lease owed to
// the rounds, in each of 64 rounds. A retry that took the timer's case leased on the dead context, read the cancel as
// final, and dropped the subscription, from the store too, for good.
func TestEvsSubscribeLeaseRetryKeepsTheSubscriptionAtItsContextsEnd(t *testing.T) {
	world := newEvsTestWorld(t)
	leases := newEvsTestLeases(world)
	test := newEvsSubscribeTest(t, world, leases, newEvsTestStore(t))
	world.push(&evsTestChange{path: "docs/a", content: []byte("a")})
	leases.failPosts = 1 << 20
	retryWait := test.client.settings.SubscribeRetryMinWait
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, retryWait)
		// no subscribe runs between rounds, and the rounds never start, so the client's clock is the round's alone
		test.client.clock = clock
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(1, cancel)
		clock.open()
		subscription, err := test.client.Repo(world.repoId).Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}})
		if err != nil || subscription == nil || clock.waits() != 1 {
			t.Fatalf("round %d: the subscribe answered %v after %d waits, want the subscription after 1", round, err, clock.waits())
		}
		test.client.subscriber.stateLock.Lock()
		held := len(test.client.subscriber.subscriptions)
		test.client.subscriber.stateLock.Unlock()
		if held != round+1 {
			t.Fatalf("round %d: the subscriber holds %d subscriptions", round, held)
		}
	}
}

// gkm's key upkeep passes nothing and retries nothing once it has ended: it passes at once and after each
// UpkeepInterval, and an end landing as the second interval's end fires ends the upkeep after the two passes before it;
// and with every ReaderKey upload refused, its retries wait ReaderKeyRetryWait and then twice that, and an end landing
// as the second retry's wait fires ends it after the one retry between; in each of 64 rounds. An upkeep that took the
// timer's case passed or retried on the dead upkeep, which drops the lapsed ReaderKeys and mints the one due in the
// keychain before its upload meets the dead context.
func TestGkmUpkeepPassesAndRetriesNothingAfterItEnds(t *testing.T) {
	settings := DefaultGkmSettings()
	for round := range 64 {
		fixture := newGkmUpkeepFixture(t, GkmUpkeepRole{})
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, settings.UpkeepInterval)
		fixture.upkeep.clock = clock
		clock.arm(2, fixture.upkeep.cancel)
		clock.open()
		go fixture.upkeep.run()
		clock.awaitDone(t, fixture.upkeep.done, "the upkeep")
		if passes, _ := fixture.upkeep.Passes(); passes != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d passes and %d waits, want 2 of each", round, passes, clock.waits())
		}

		fixture = newGkmUpkeepFixture(t, GkmUpkeepRole{})
		fixture.api.readerKeyErr = &GkmError{Status: http.StatusServiceUnavailable}
		clock = newClockSelectEndingClock(t, clockSelectTestStart(), false, settings.ReaderKeyRetryWait, 2*settings.ReaderKeyRetryWait)
		fixture.upkeep.clock = clock
		clock.arm(2, fixture.upkeep.cancel)
		clock.open()
		go fixture.upkeep.run()
		clock.awaitDone(t, fixture.upkeep.done, "the upkeep")
		if retries, _ := fixture.upkeep.ReaderKeyRetries(); retries != 1 || clock.waits() != 2 {
			t.Fatalf("round %d: %d retries and %d waits, want 1 retry and 2 waits", round, retries, clock.waits())
		}
	}
}

// A Quota whose usage reports go unanswered, counting them.
type clockSweepLaterQuota struct {
	Quota
	reportCount atomic.Int64
}

func (self *clockSweepLaterQuota) ReportUsage(ctx context.Context, batch *UsageBatch) error {
	self.reportCount.Add(1)
	return errors.New("api does not answer")
}

// The usage batcher sends nothing once it has ended: with an unanswered batch due, each round sends it and waits
// RetryTimeout, its wait an AfterFunc that wakes the batcher, and an end landing as the second wait's wake comes ends
// the batcher after the two sends before it, in each of 64 rounds. A batcher that took the wake sent the batch on the
// dead batcher and counted its failure, or past its horizon dropped and counted it, an under-billing alert for bytes
// Close loses by design.
func TestQuotaUsageBatcherSendsNothingAfterItEnds(t *testing.T) {
	settings := DefaultQuotaUsageBatcherSettings()
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), true, settings.RetryTimeout)
		quota := &clockSweepLaterQuota{}
		ctx, cancel := context.WithCancel(context.Background())
		batcher := &QuotaUsageBatcher{
			ctx:         ctx,
			cancel:      cancel,
			quota:       quota,
			clock:       clock,
			producer:    "evs",
			settings:    settings,
			wake:        make(chan struct{}, 1),
			done:        make(chan struct{}),
			windowStart: clock.Now(),
			keyEvents:   map[quotaUsageEventKey]*UsageEvent{},
			sends:       []*quotaUsageSend{{batch: &UsageBatch{}, cutTime: clock.Now(), nextSendTime: clock.Now()}},
			roundDone:   make(chan struct{}),
		}
		clock.arm(2, cancel)
		clock.open()
		go batcher.run()
		clock.awaitDone(t, batcher.done, "the batcher")
		if reports := quota.reportCount.Load(); reports != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d sends and %d waits, want 2 of each", round, reports, clock.waits())
		}
	}
}

// The record writer passes nothing once its context has ended: with its spool's drain due a second on, each pass ends
// in a wait for that time, an AfterFunc that wakes the writer, and an end landing as the second wait's wake comes ends
// the writer after the two passes before it, in each of 64 rounds. A writer that took the wake passed on the dead
// context, which tends, moves its spool's drafts into the journal and plans its pushes.
func TestRecordWriterPassesNothingAfterItsContextEnds(t *testing.T) {
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, time.Second)
		writer := newRecordWriter(&SidecarRecordArgs{
			SidecarId: NewId(),
			Store:     newTestMemoryStore(),
			Clock:     clock,
			Settings:  defaultSidecarRecordSettings(),
		})
		writer.drainRetryMillis = clock.Now().Add(time.Second).UnixMilli()
		tendCount := 0
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(2, cancel)
		clock.open()
		clock.awaitRun(t, "the record writer", func() {
			writer.run(ctx, func(ctx context.Context) {
				tendCount += 1
			})
		})
		cancel()
		if tendCount != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d passes and %d waits, want 2 of each", round, tendCount, clock.waits())
		}
	}
}

// A dispatcher as remote search follows one: the foreground it is told, counted.
type clockSweepLaterSearchTransport struct {
	searchRemoteTransport
	foregroundCount atomic.Int64
}

func (self *clockSweepLaterSearchTransport) SetForeground(foreground bool) {
	self.foregroundCount.Add(1)
}

func (self *clockSweepLaterSearchTransport) SetSearchIndexer(indexerId Id) {
}

// Remote search sets nothing on the dispatcher once its generation has ended: it tells the dispatcher the foreground at
// once and after each ServeRecheckInterval, and an end landing as the second wait fires ends the follow after the two
// before it, in each of 64 rounds. A follow that took the timer's case told the dead generation's dispatcher the
// foreground, and in the foreground the first-choice own indexer.
func TestSearchRemoteFollowSetsNothingAfterItsGenerationEnds(t *testing.T) {
	settings := DefaultSidecarSettings().Search
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, settings.ServeRecheckInterval)
		client := &SearchRemoteClient{
			args:     SearchRemoteClientArgs{State: &SidecarSearchState{changes: NewMonitorValue[uint64](0)}},
			settings: settings,
			clock:    clock,
			log:      NewNoopLogger(),
		}
		transport := &clockSweepLaterSearchTransport{}
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(2, cancel)
		clock.open()
		clock.awaitRun(t, "the follow", func() {
			client.follow(ctx, transport)
		})
		cancel()
		if sets := transport.foregroundCount.Load(); sets != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: the foreground told %d times after %d waits, want 2 of each", round, sets, clock.waits())
		}
	}
}

// The search sync runs no round once its context has ended: a followed ref rounds at once and again at each due time,
// its resync's or its retry's, and an end landing as the second due time's wait fires ends the rounds after the two
// before it, the ref's last round before the end, in each of 64 rounds. Rounds that took the timer's case ran one on
// the dead context, which claims the ref and, for a non-writer's, begins its receipt round, reserving the interval and
// leaving the ref skipped, before its reads meet the dead context.
func TestSearchSyncRunsNoRoundAfterItsContextEnds(t *testing.T) {
	world := newTestSyncWorld(t, false)
	settings := world.cache.settings
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), true, settings.ResyncInterval, settings.SyncRetryInterval)
		engine, err := newSearchSync(&searchSyncArgs{
			cache:         world.cache.cache,
			settings:      settings,
			format:        DefaultIndexFormatSettings(),
			clock:         clock,
			log:           NewNoopLogger(),
			readPathCount: 64,
			readByteCount: 32 * 1024 * 1024,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = engine.Follow(&searchSyncRefArgs{
			repoId: world.repoId, refId: world.refId, repoKind: protocol.RepoKind_REPO_KIND_GENERAL, source: world.source,
			keepAll:  func() bool { return false },
			mayErase: func(signer Id, signedTimeMs int64) bool { return true },
		})
		if err != nil {
			t.Fatal(err)
		}
		engine.Trigger(world.repoId, &world.refId, SearchSyncResync)
		// the trigger's wake, which the first round answers already
		select {
		case <-engine.wake:
		default:
		}
		ctx, cancel := context.WithCancel(context.Background())
		var endAt time.Time
		clock.arm(2, func() {
			endAt = clock.Now()
			cancel()
		})
		clock.open()
		engine.Start(ctx)
		clock.awaitDone(t, engine.done, "the rounds")
		engine.stateLock.Lock()
		roundAt := engine.refs[[2]Id{world.repoId, world.refId}].roundAt
		engine.stateLock.Unlock()
		engine.Close()
		if roundAt.IsZero() || !roundAt.Before(endAt) || clock.waits() != 2 {
			t.Fatalf("round %d: the last round at %v, the end at %v, after %d waits; want a round before the end and 2 waits", round, roundAt, endAt, clock.waits())
		}
	}
}

// A config follower on a bare Sidecar, which holds no identity, so its anchor is asked again until it ends.
func newClockSweepLaterFollower(clock Clock, args *SidecarConfigFollowerArgs) (*SidecarConfigFollower, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return &SidecarConfigFollower{
		sidecar:  newSidecarBase(nil, cheapKeychainSettings()),
		args:     args,
		settings: DefaultSidecarConfigFollowerSettings(),
		clock:    clock,
		log:      NewNoopLogger(),
		ctx:      ctx,
		cancel:   cancel,
		state:    NewMonitorValue(SidecarConfigFollowerWaiting),
	}, cancel
}

// The config follower asks for no anchor and binds no member record once it has ended: with no identity to anchor by,
// it asks again after AnchorRetryInterval, and an end landing as that wait fires answers the follower's error with no
// second ask; and with the binding refused, it binds again each AnchorRetryInterval, and an end landing as the second
// wait fires ends it after the two binds before it; in each of 64 rounds. Each ask and each failed bind ends in a wait,
// so one the end did not stop shows as a wait more. A follower that took the timer's case anchored past the end, which
// records a first use's genesis and starts the client on it, or bound the record and stood, installing its authority.
func TestConfigFollowerAnchorsAndBindsNothingAfterItEnds(t *testing.T) {
	settings := DefaultSidecarConfigFollowerSettings()
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, settings.AnchorRetryInterval, 2*settings.AnchorRetryInterval)
		follower, cancel := newClockSweepLaterFollower(clock, &SidecarConfigFollowerArgs{})
		clock.arm(1, cancel)
		clock.open()
		var anchorErr error
		clock.awaitRun(t, "the anchor", func() {
			_, anchorErr = follower.anchorWithRetry(NewId())
		})
		if !errors.Is(anchorErr, context.Canceled) || clock.waits() != 1 {
			t.Fatalf("round %d: the anchor answered %v after %d waits, want canceled after 1", round, anchorErr, clock.waits())
		}

		clock = newClockSelectEndingClock(t, clockSelectTestStart(), false, settings.AnchorRetryInterval)
		bindCount := &atomic.Int64{}
		follower, cancel = newClockSweepLaterFollower(clock, &SidecarConfigFollowerArgs{RecordEvs: func() (*EvsClient, error) {
			bindCount.Add(1)
			return nil, errors.New("no evs client yet")
		}})
		clock.arm(2, cancel)
		clock.open()
		bound := true
		clock.awaitRun(t, "the binding", func() {
			_, bound = follower.bindRecordWithRetry(nil)
		})
		if binds := bindCount.Load(); bound || binds != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: bound %t after %d binds and %d waits, want unbound after 2 of each", round, bound, binds, clock.waits())
		}
	}
}

// The socket component refreshes nothing once it has ended: with no config follower to read, it reads again each
// RetryInterval, and an end landing as the second wait fires ends the follow after the two reads before it, in each of
// 64 rounds. Each read with no follower ends in a wait, so one the end did not stop shows as a third wait asked: a
// follow that took the timer's case read past the end, where a new base or a refusal withdraws the key paths and
// rechecks the live streams.
func TestSocketConfigFollowRefreshesNothingAfterTheComponentEnds(t *testing.T) {
	settings := DefaultSidecarSocketSettings()
	host := newSidecarBase(nil, cheapKeychainSettings())
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, settings.RetryInterval)
		ctx, cancel := context.WithCancel(context.Background())
		component := &SocketComponent{
			host:       host,
			configDone: make(chan struct{}),
			registrar:  &socketRegistrar{ctx: ctx, cancel: cancel},
			settings:   settings,
			clock:      clock,
		}
		clock.arm(2, cancel)
		clock.open()
		go component.followSocketConfig()
		clock.awaitDone(t, component.configDone, "the config follow")
		if clock.waits() != 2 {
			t.Fatalf("round %d: %d waits, want the 2 of 2 reads", round, clock.waits())
		}
	}
}

// The support client passes nothing once it has closed: it passes at once and after each LoopInterval, and a close
// landing as the second wait fires ends the loop after the two passes before it, in each of 64 rounds. A loop that took
// the timer's case passed on the closed client, which with nothing in its outbox reads the member's events, and on the
// dead context logs its token's failure to the support log.
func TestSupportClientPassesNothingAfterItCloses(t *testing.T) {
	settings := DefaultSupportSettings()
	// each pass answers ErrSupportUnavailable at once, with no I/O
	settings.ServiceEnabled = false
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, settings.LoopInterval)
		ctx, cancel := context.WithCancel(context.Background())
		client := &SupportClient{
			ctx:       ctx,
			cancel:    cancel,
			settings:  settings,
			clock:     clock,
			wake:      make(chan struct{}, 1),
			runDone:   make(chan struct{}),
			passes:    NewMonitorValue(supportPasses{}),
			listeners: map[int]func(update *SupportUpdate){},
		}
		clock.arm(2, cancel)
		clock.open()
		go client.run()
		clock.awaitDone(t, client.runDone, "the support loop")
		if passes := client.passes.Value(); passes.begun != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d passes and %d waits, want 2 of each", round, passes.begun, clock.waits())
		}
	}
}
