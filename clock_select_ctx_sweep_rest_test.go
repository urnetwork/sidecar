//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// The rest of the root's waits that end with their context (clock-select-ctx-sweep, its second sitting;
// clock_select_ctx_sweep_test.go has the first and the sweep's account). Each loop here stepped past its end, when
// select took a timer or a wake its clock gave as the end landed, into something outward or durable: the bridge
// component raised catch_up_waiting, compiled for the device role and saved the binding cache, discovery's host loop
// published and wrote the sealed shares, remote serving registered on the dead generation's dispatcher, the directory
// client synced and told AfterSync, the evs sync engine replayed into the mount and its receive queue took a due push
// off the queue for good, the index schedule ticked, the mail component passed, IMAP IDLE polled, mail ingest passed,
// the head check ran a round and its fetch's second try, the scim_signer component looked and counted, the SMTP outbox
// passed, the share loader listened and the stream keepalive pinged.
//
// The proof is clockSelectEndingClock, tls-wait-ctx-shape's clock with its AfterFunc's waits fired as its After's are,
// which ends the context as a wait fires, so the end and the wake are both ready when select runs, over 64 rounds.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A clock for a loop whose waits must end with its context, the waits AfterFunc sets among them. Its waits are held
// until the test opens it, so the test arms it before the loop asks; then each wait it counts fires at once, After's
// channel ready and AfterFunc's function called on the setting goroutine, until the counted one at which it runs end
// first, so the waiter finds the end and the wake both ready, as a cancel landing with a timer does. A counted wait
// after that one never fires, nor does one it does not count. With moves, each wait that fires moves the clock to its
// time first. It is no ClockAt, so a wait for a time is a wait for the timeout to it from Now. Safe for concurrent use.
type clockSelectEndingClock struct {
	// whether it counts a wait of timeout; nil counts every wait
	counts func(timeout time.Duration) bool
	moves  bool
	// how long a test waits on a loop it drives: a guard against a broken test, never the proof
	guard time.Duration
	// closed when the test lets the waits through
	opened   chan struct{}
	openOnce sync.Once

	stateLock sync.Mutex
	now       time.Time
	// the counted wait, from 1, at which end runs; 0 for none, which fires every counted wait
	endIndex int
	end      func()
	// the counted waits asked so far
	waitCount int
	// every wait asked so far, counted or not
	askCount int
}

var _ Clock = (*clockSelectEndingClock)(nil)

// A held clock reading now, moving to each wait's time as it fires when moves, counting the waits of timeouts, every
// wait when there are none. It opens when the test ends at the latest, so no loop stays held past it.
func newClockSelectEndingClock(t *testing.T, now time.Time, moves bool, timeouts ...time.Duration) *clockSelectEndingClock {
	clock := &clockSelectEndingClock{now: now, moves: moves, guard: 30 * time.Second, opened: make(chan struct{})}
	if 0 < len(timeouts) {
		clock.counts = func(timeout time.Duration) bool {
			for _, counted := range timeouts {
				if timeout == counted {
					return true
				}
			}
			return false
		}
	}
	t.Cleanup(clock.open)
	return clock
}

func (self *clockSelectEndingClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// Takes a wait of timeout once the clock is open: whether it fires, where the clock then stands, and the end to run
// first when it is the end's.
func (self *clockSelectEndingClock) ask(timeout time.Duration) (fires bool, firedAt time.Time, end func()) {
	<-self.opened
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.askCount += 1
	if self.counts != nil && !self.counts(timeout) {
		return false, time.Time{}, nil
	}
	self.waitCount += 1
	if self.waitCount == self.endIndex {
		end = self.end
	}
	fires = self.endIndex == 0 || self.waitCount <= self.endIndex
	if fires && self.moves {
		self.now = self.now.Add(max(0, timeout))
	}
	return fires, self.now, end
}

func (self *clockSelectEndingClock) After(timeout time.Duration) <-chan time.Time {
	fires, firedAt, end := self.ask(timeout)
	// the end lands before the timer's channel is handed back, so the waiter's select finds both ready
	if end != nil {
		end()
	}
	fire := make(chan time.Time, 1)
	if fires {
		fire <- firedAt
	}
	return fire
}

// Calls function on the setting goroutine before it returns when the wait fires, after the end when it is the end's,
// so a wake function pokes is ready beside the end when the waiter's select runs. Only for a function that takes no
// lock its setter holds.
func (self *clockSelectEndingClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	fires, _, end := self.ask(timeout)
	if end != nil {
		end()
	}
	if !fires {
		return func() bool {
			return true
		}
	}
	function()
	return func() bool {
		return false
	}
}

// Runs end as the index-th counted wait, from 1, fires.
func (self *clockSelectEndingClock) arm(index int, end func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.endIndex = index
	self.end = end
}

// Lets the waits through.
func (self *clockSelectEndingClock) open() {
	self.openOnce.Do(func() {
		close(self.opened)
	})
}

// The counted waits asked so far.
func (self *clockSelectEndingClock) waits() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.waitCount
}

// Every wait asked so far.
func (self *clockSelectEndingClock) asks() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.askCount
}

// Waits for done within the clock's guard, failing the test with what otherwise.
func (self *clockSelectEndingClock) awaitDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(self.guard):
		t.Fatalf("%s did not end within %v", what, self.guard)
	}
}

// Runs run on a goroutine of its own and waits for it to return within the clock's guard.
func (self *clockSelectEndingClock) awaitRun(t *testing.T, what string, run func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		run()
	}()
	self.awaitDone(t, done, what)
}

// The index schedule ticks nothing once its context has ended: it ticks at once and after each TickInterval, and an
// end landing as the second wait fires ends Run after the two ticks before it, in each of 64 rounds, asking the clock
// for no third wait. A loop that took the timer's case ticked on the dead context, running merges, roll-ups and
// backfills, and handed observe their outcomes.
func TestIndexScheduleTicksNothingAfterItsContextEnds(t *testing.T) {
	settings := DefaultIndexerSearchSettings()
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, settings.TickInterval)
		schedule := indexNewSchedule(settings, clock)
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(2, cancel)
		clock.open()
		tickCount := 0
		clock.awaitRun(t, "the schedule", func() {
			schedule.Run(ctx, func(ticks []*indexScheduleTick) {
				tickCount += 1
			})
		})
		cancel()
		if tickCount != 2 || clock.asks() != 2 {
			t.Fatalf("round %d: %d ticks and %d waits, want 2 of each", round, tickCount, clock.asks())
		}
	}
}

// Mail ingest's passes stop at their context's end: whether the end lands as the least gap's wait fires, with a pass
// whose timed wait the gap spends, or as the timed wait fires, with no gap, the passes end with the two before the
// second wait, in each of 64 rounds, asking the clock for no third. A loop that took the timer's case passed on the
// dead context, which ingests and writes the mailbox.
func TestMailRunPassesPassNothingAfterItsContextEnds(t *testing.T) {
	gap := 5 * time.Second
	wait := time.Minute
	for round := range 64 {
		for _, gapped := range []bool{true, false} {
			clock := newClockSelectEndingClock(t, clockSelectTestStart(), true)
			ctx, cancel := context.WithCancel(context.Background())
			clock.arm(2, cancel)
			clock.open()
			passCount := 0
			passGap, passWait := time.Duration(0), wait
			if gapped {
				// a timed wait within the gap is spent by it, so each gap's wait brings the next pass
				passGap, passWait = gap, gap
			}
			clock.awaitRun(t, "the passes", func() {
				mailRunPasses(ctx, clock, passGap, nil, func() time.Duration {
					passCount += 1
					return passWait
				})
			})
			cancel()
			if passCount != 2 || clock.asks() != 2 {
				t.Fatalf("round %d, gapped %t: %d passes and %d waits, want 2 of each", round, gapped, passCount, clock.asks())
			}
		}
	}
}

// The SMTP outbox passes nothing once its context has ended: it passes at once and after each OutboxPollInterval, and
// an end landing as the second wait fires ends Run after the two passes before it, in each of 64 rounds. A loop that
// took the timer's case passed on the dead context, which sends what is due and leaves the rest.
func TestSmtpOutboxRunsNoPassAfterItsContextEnds(t *testing.T) {
	settings := DefaultSmtpSenderSettings()
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false)
		passCount := &atomic.Int64{}
		// what Run reads of a runner: each pass asks first whether this host takes the member's mail, and told no,
		// ends there
		runner := &SmtpOutboxRunner{
			args: &SmtpOutboxRunnerArgs{Consented: func() bool {
				passCount.Add(1)
				return false
			}},
			settings: settings,
			clock:    clock,
			log:      NewNoopLogger(),
		}
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(2, cancel)
		clock.open()
		clock.awaitRun(t, "the outbox", func() {
			runner.Run(ctx, nil)
		})
		cancel()
		if passes := passCount.Load(); passes != 2 || clock.asks() != 2 {
			t.Fatalf("round %d: %d passes and %d waits, want 2 of each", round, passes, clock.asks())
		}
	}
}

// A store whose shares' directory is refused, counting the asks: a share load that finds no ledger.
type clockSelectShareStore struct {
	SidecarStore
	directoryCount atomic.Int64
}

func (self *clockSelectShareStore) Directory(name string, class string) (SidecarStore, error) {
	self.directoryCount.Add(1)
	return nil, errors.New("the shares' directory is refused")
}

// What a share load reads of the daemon: the local store alone.
type clockSelectShareBackend struct {
	daemonSocketBackend
	store *clockSelectShareStore
}

func (self *clockSelectShareBackend) localStore() SidecarStore {
	return self.store
}

// The share loader loads nothing once the daemon has ended: it loads at once and after each ResumeInterval, and an
// end landing as the second wait fires ends the loop after the two loads before it, in each of 64 rounds. A loop that
// took the timer's case loaded on the dead daemon, which adopts records and listens each live share.
func TestSocketSharesLoadNothingAfterTheDaemonEnds(t *testing.T) {
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false)
		store := &clockSelectShareStore{}
		ctx, cancel := context.WithCancel(context.Background())
		shares := &socketShares{
			networkId:     NewId(),
			backend:       &clockSelectShareBackend{store: store},
			settings:      DefaultSidecarSocketSettings().Share,
			clock:         clock,
			log:           NewNoopLogger(),
			ctx:           ctx,
			cancel:        cancel,
			tokenShares:   map[string]*socketShare{},
			failedTokens:  map[string]bool{},
			pendingTokens: map[string]bool{},
		}
		clock.arm(2, cancel)
		clock.open()
		clock.awaitRun(t, "the share loader", shares.run)
		cancel()
		// each load reads the ledger first, which asks for the shares' directory
		if loads := store.directoryCount.Load(); loads != 2 || clock.asks() != 2 {
			t.Fatalf("round %d: %d loads and %d waits, want 2 of each", round, loads, clock.asks())
		}
	}
}

// The stream keepalive pings no one once the dispatcher has closed: with a peer's streams silent, the first wake is
// due at its PingTimeout, and a close landing as that wake fires ends the loop with no Ping, in each of 64 rounds,
// asking the clock for no second wake. A loop that took the wake's case pinged the peer, and at the silence bound would
// have reset its streams, on the closed dispatcher.
func TestStreamKeepalivePingsNothingAfterTheDispatcherCloses(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), true)
		ctx, cancel := context.WithCancel(context.Background())
		peerId := connect.NewId()
		// what the keepalive reads of a dispatcher: its context, settings, clock, armed monitor and stream table, one
		// peer with one stream whose last inbound frame is now
		subprotocol := &Subprotocol{
			ctx:                  ctx,
			settings:             settings,
			clock:                clock,
			streamKeepaliveArmed: NewMonitorValue(time.Time{}),
		}
		subprotocol.streams.change = NewMonitorValue[uint64](0)
		subprotocol.streams.outboundWake = make(chan struct{}, 1)
		subprotocol.streams.peers = map[connect.Id]*streamPeer{
			peerId: {
				peerId:          peerId,
				streams:         map[uint64]*SubprotocolStream{1: {}},
				lastInboundTime: clock.Now(),
			},
		}
		subprotocol.handlers.Add(1)
		clock.arm(1, cancel)
		clock.open()
		clock.awaitRun(t, "the keepalive", subprotocol.runStreamKeepalive)
		cancel()
		if pings := subprotocol.streams.stats.pingCount.Load(); pings != 0 || clock.asks() != 1 {
			t.Fatalf("round %d: %d pings and %d wakes, want none and 1", round, pings, clock.asks())
		}
	}
}

// The directory client syncs nothing once its context has ended: it syncs at once and at each due time, its wait an
// AfterFunc that signals the loop, and an end landing as the second due time's signal comes ends Run after the two
// syncs before it, in each of 64 rounds, AfterSync hearing of no third. A loop that took the signal's case moved the
// schedule, synced on the dead context and told AfterSync its error.
func TestDirectoryClientSyncsNothingAfterItsContextEnds(t *testing.T) {
	settings := DefaultSidecarSettings().Directory
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), true)
		syncCount := 0
		client, err := NewDirectoryClient(&DirectoryClientArgs{
			SidecarId: NewId(),
			Store:     newTestMemoryStore(),
			Clock:     clock,
			Settings:  settings,
			Log:       NewNoopLogger(),
			AfterSync: func(err error) {
				syncCount += 1
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(2, cancel)
		clock.open()
		clock.awaitRun(t, "the directory client", func() {
			client.Run(ctx)
		})
		cancel()
		if syncCount != 2 || clock.asks() != 2 {
			t.Fatalf("round %d: %d syncs and %d waits, want 2 of each", round, syncCount, clock.asks())
		}
	}
}

// Remote serving looks at the designation no more once its generation has ended: it looks at once and after each
// ServeRecheckInterval, and an end landing as the second wait fires ends the follow after the two looks before it,
// in each of 64 rounds. A loop that took the timer's case looked on the dead generation, which registers SEARCH and
// sets its bit on that generation's dispatcher where the designation stands.
func TestSearchServeFollowLooksNoMoreAfterItsGenerationEnds(t *testing.T) {
	world := newSearchTestSidecar(t, func(settings *SidecarSettings) {
		settings.Search.RemoteServe = true
	})
	interval := world.sidecar.settings.Search.ServeRecheckInterval
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, interval)
		// no follow runs between rounds, so the sidecar's clock is the round's alone
		world.sidecar.clock = clock
		lookCount := &atomic.Int64{}
		component := newSearchServeComponent(world.sidecar, &DaemonSearchServe{
			// each look asks first whether this device is designated, and told no, registers nothing
			Designated: func() bool {
				lookCount.Add(1)
				return false
			},
			Handler: func(context.Context, *SubprotocolRequest) ([]byte, error) { return nil, nil },
		})
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(2, cancel)
		clock.open()
		clock.awaitRun(t, "the follow", func() {
			component.follow(ctx, newSearchServeTestDispatcher())
		})
		cancel()
		if looks := lookCount.Load(); looks != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d looks and %d waits, want 2 of each", round, looks, clock.waits())
		}
	}
}

// Discovery's host loop passes no more once the component has closed: it passes at once and at each time a lapse
// is due, and a close landing as the second wait fires ends the loop after the two passes before it, in each of 64
// rounds. A loop that took the timer's case passed on the closed component, which publishes the host's view and keeps
// its shares' sightings in the sealed settings.
func TestBridgeDiscoveryHostPassesNoMoreAfterItCloses(t *testing.T) {
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false)
		passCount := &atomic.Int64{}
		component, err := NewBridgeDiscoveryComponent(&BridgeDiscoveryArgs{
			NetworkId: NewId(),
			SidecarId: NewId(),
			// each pass reads the device role's routes first, which publish nothing while there are none
			Routes: func() *BridgeDiscoveryRoutes {
				passCount.Add(1)
				return nil
			},
			Clock: clock,
			Log:   NewNoopLogger(),
		})
		if err != nil {
			t.Fatal(err)
		}
		clock.arm(2, component.cancel)
		clock.open()
		clock.awaitDone(t, component.done, "the host loop")
		component.Close()
		if passes := passCount.Load(); passes != 2 || clock.asks() != 2 {
			t.Fatalf("round %d: %d passes and %d waits, want 2 of each", round, passes, clock.asks())
		}
	}
}

// The scim_signer component looks no more once its generation has ended: it looks at once and after each
// PollInterval, and an end landing as the third poll is set ends the loop after the two looks before it, in each of
// 64 rounds. A loop with no check after its select looked again on the dead generation, counting a look and a pass
// in the status, and would install a signer there where this sidecar is designated.
func TestSidecarScimSignerLooksNoMoreAfterItsGenerationEnds(t *testing.T) {
	settings := DefaultConfigScimSignerSettings()
	sidecar := newSidecarBase(nil, cheapKeychainSettings())
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, settings.PollInterval)
		// no look runs between rounds, so the sidecar's clock is the round's alone
		sidecar.clock = clock
		signer := &SidecarScimSigner{
			sidecar:   sidecar,
			settings:  settings,
			newSource: func(api *SidecarApi) ScimChangeSource { return &clockSelectScimSource{} },
			changes:   NewMonitorValue[uint64](0),
		}
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(3, cancel)
		clock.open()
		clock.awaitRun(t, "the component's loop", func() {
			signer.run(ctx, NewId(), nil)
		})
		cancel()
		if status := signer.Status(); status.LookCount != 2 || status.Installed || clock.waits() != 3 {
			t.Fatalf("round %d: %d looks, installed %t, %d polls; want 2 looks, none installed, 3 polls", round, status.LookCount, status.Installed, clock.waits())
		}
	}
}

// A store that counts the binding cache's writes.
type clockSelectBindingStore struct {
	SidecarStore
	saveCount atomic.Int64
}

func (self *clockSelectBindingStore) Create(name string) (SidecarStoreWriter, error) {
	if name == bridgeBindingCacheName {
		self.saveCount.Add(1)
	}
	return self.SidecarStore.Create(name)
}

// A bridge component over world's client, on clock and settings, its alarms the world's. The caller closes it.
func newClockSelectBridgeComponent(world *testBridgeComponentWorld, clock Clock, settings *BridgeComponentSettings) *BridgeComponent {
	world.t.Helper()
	component, err := NewBridgeComponent(context.Background(), &BridgeComponentArgs{
		NetworkId: world.net.networkId,
		Identity: func() *SidecarIdentity {
			return &SidecarIdentity{NetworkId: world.net.networkId, SidecarId: world.host.sidecarId, IdentityPublicKey: world.host.publicKey()}
		},
		Config: world.client,
		Heads:  world.heads,
		Rows:   world.net.source,
		Emit: func(event SidecarEvent) {
			if event.Kind == SidecarEventBridgeAlarm {
				world.stateLock.Lock()
				world.alarms = append(world.alarms, event.BridgeAlarm)
				world.stateLock.Unlock()
			}
		},
		Clock:    clock,
		Log:      NewNoopLogger(),
		Settings: settings,
		parts: &bridgeProviderParts{
			newNat: func(ctx context.Context, settings *connect.LocalUserNatSettings) *connect.LocalUserNat {
				return nil
			},
			newProvider: func(client *connect.Client, nat *connect.LocalUserNat) (func(), error) {
				return func() {}, nil
			},
		},
	})
	if err != nil {
		world.t.Fatal(err)
	}
	return component
}

// The bridge alarms the world has seen.
func (self *testBridgeComponentWorld) alarmsSoFar() []SidecarBridgeAlarm {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]SidecarBridgeAlarm{}, self.alarms...)
}

// A catch-up whose context ends as its alarm's timer fires raises no catch_up_waiting: with the device role's pin
// past the client's, the catch-up waits on the follow and arms the alarm, and an end landing as it fires answers the
// context's error with no alarm, in each of 64 rounds. A catch-up that took the timer's case raised the alarm for a
// generation already ended.
func TestBridgeComponentCatchUpRaisesNoAlarmAfterItsContextEnds(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	ahead := world.net.n + 2
	pin := &bridge.AuthPin{Version: ahead, Chain: make([]byte, 32)}
	world.sink.decision = BridgeSinkDecision{State: BridgeSinkEnforcing, Pin: pin, StatePin: pin}
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, world.settings.CatchUpAlarmTimeout)
		component := newClockSelectBridgeComponent(world, clock, world.settings)
		// a role of its own each round, the world's lagging decision
		sink := &testBridgeSink{events: world.events, hook: testBridgeHook{}, decision: world.sink.decision}
		clock.open()
		if err := component.SetDeviceRole(sink); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(1, cancel)
		var catchUpErr error
		clock.awaitRun(t, "the catch-up", func() {
			catchUpErr = component.catchUp(ctx)
		})
		cancel()
		component.Close()
		if !errors.Is(catchUpErr, context.Canceled) || len(world.alarmsSoFar()) != 0 || clock.waits() != 1 {
			t.Fatalf("round %d: the catch-up answered %v with alarms %v after %d waits, want canceled with none after 1", round, catchUpErr, world.alarmsSoFar(), clock.waits())
		}
	}
}

// The component compiles nothing once it has closed: a compile wanted waits CompileDelay, and a close landing as that
// wait fires ends the loop with no compile, in each of 64 rounds. A loop that took the timer's case compiled for the
// device role on the closed component, handing it a state.
func TestBridgeComponentCompilesNothingAfterItCloses(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	settings := *world.settings
	settings.CompileDelay = 100 * time.Millisecond
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), true, settings.CompileDelay)
		component := newClockSelectBridgeComponent(world, clock, &settings)
		sink := &testBridgeSink{events: newTestBridgeEvents(), hook: testBridgeHook{}, decision: BridgeSinkDecision{State: BridgeSinkLegacy}}
		// the role's compile is wanted at once, and waits CompileDelay on the clock, which stays held until it is armed
		if err := component.SetDeviceRole(sink); err != nil {
			t.Fatal(err)
		}
		clock.arm(1, component.cancel)
		clock.open()
		clock.awaitDone(t, component.done, "the component's loop")
		component.Close()
		if status := component.Status(); status.CompileCount != 0 || status.CompileErrorCount != 0 || clock.waits() != 1 {
			t.Fatalf("round %d: %d compiles, %d failed, after %d waits; want none after 1", round, status.CompileCount, status.CompileErrorCount, clock.waits())
		}
	}
}

// The binding fetcher keeps nothing once the component has closed: with a kept client id lapsing between the first
// refresh and the second, a close landing as the second refresh's wait fires ends the fetcher with the cache unsaved,
// in each of 64 rounds. A fetcher that took the timer's case expired the id on the closed component and saved the
// cache to the store.
func TestBridgeComponentFetchesNoBindingsAfterItCloses(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	settings := *world.settings
	// a kept id lapses a refresh and a half after it stopped being current
	settings.BindingRetainTimeout = settings.BindingRefreshInterval * 3 / 2
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), true, settings.BindingRefreshInterval)
		component := newClockSelectBridgeComponent(world, clock, &settings)
		store := &clockSelectBindingStore{SidecarStore: newTestMemoryStore()}
		func() {
			component.stateLock.Lock()
			defer component.stateLock.Unlock()
			// what a pass reads: a compile's waits, none, and the generation's store
			component.compiled = &BridgeCompiled{State: &bridge.BridgeState{}}
			component.store = store
		}()
		subject := NewId()
		component.bindings.Record(&BridgeBinding{SidecarId: subject, ClientId: NewId(), Generation: 1, Signed: []byte{1}}, clock.Now())
		component.bindings.Record(&BridgeBinding{SidecarId: subject, ClientId: NewId(), Generation: 2, Signed: []byte{2}}, clock.Now())
		clock.arm(2, component.cancel)
		clock.open()
		clock.awaitDone(t, component.bindingsDone, "the binding fetcher")
		component.Close()
		if saves := store.saveCount.Load(); saves != 0 || clock.waits() != 2 {
			t.Fatalf("round %d: %d saves after %d refreshes, want none after 2", round, saves, clock.waits())
		}
	}
}

// The evs sync engine replays nothing once its context has ended: with a ref's replay asked and the resync's wait
// set, an end landing as that wait fires ends the loop with the replay still asked, in each of 64 rounds. A loop that
// took the wake's case, or the resync's, which wakes every followed ref, replayed into the mount and ran its gc on the
// dead context.
func TestEvsGitSyncEngineReplaysNothingAfterItsContextEnds(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	device := newEvsTestDevice(t, publisher, "reader")
	engine := device.engine
	refId := NewId()
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, engine.settings.SyncResyncInterval)
		// no loop runs between rounds, so the engine's clock is the round's alone
		engine.clock = clock
		engine.Wake(refId)
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(1, cancel)
		clock.open()
		var runErr error
		clock.awaitRun(t, "the sync loop", func() {
			runErr = engine.run(ctx)
		})
		cancel()
		if wakes := engine.takeWakes(); !errors.Is(runErr, context.Canceled) || !slices.Contains(wakes, refId) || clock.waits() != 1 {
			t.Fatalf("round %d: the loop answered %v, the replays asked %v, after %d waits; want canceled with the ref's replay asked after 1", round, runErr, wakes, clock.waits())
		}
	}
}

// The evs receive queue takes nothing off the queue once its context has ended: with an owned ref's push due one
// QueueInterval on, an end landing as that wait fires ends the queue with the push still due, in each of 64 rounds. A
// loop that took the timer's case ran a round on the dead context, which took the push off the queue, failed to
// publish it on that context, and left it queued nowhere.
func TestEvsGitReceiverQueueTakesNothingAfterItsContextEnds(t *testing.T) {
	publisher := newEvsTestPublisher(t)
	device := newEvsTestDevice(t, publisher, "writer")
	receiver := newEvsGitReceiver(device.mounts, device.mount)
	refId := NewId()
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), true, receiver.settings.QueueInterval)
		// no queue runs between rounds, so the receiver's clock is the round's alone
		receiver.clock = clock
		func() {
			receiver.stateLock.Lock()
			defer receiver.stateLock.Unlock()
			receiver.queueDue = map[Id]time.Time{refId: clock.Now().Add(receiver.settings.QueueInterval)}
			receiver.queuedAt = map[Id]time.Time{}
		}()
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(1, cancel)
		clock.open()
		var queueErr error
		clock.awaitRun(t, "the queue", func() {
			queueErr = receiver.runQueue(ctx)
		})
		cancel()
		due := func() bool {
			receiver.stateLock.Lock()
			defer receiver.stateLock.Unlock()
			_, due := receiver.queueDue[refId]
			return due
		}()
		if !errors.Is(queueErr, context.Canceled) || !due || clock.waits() != 1 {
			t.Fatalf("round %d: the queue answered %v, the push due %t, after %d waits; want canceled with it due after 1", round, queueErr, due, clock.waits())
		}
	}
}

// The mail component passes no more once its generation has ended: an unbound client passes at once and after each
// UnboundCheckInterval, and an end landing as the second wait fires ends the generation after the two passes before
// it, in each of 64 rounds. Each pass ends in a wait, so a pass the end did not stop shows as a third wait asked: a
// loop that took the timer's case passed on the dead generation, which binds, starts and publishes what mail runs.
func TestMailClientGenerationPassesNoMoreAfterItEnds(t *testing.T) {
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false)
		client, err := NewMailClient(&MailClientArgs{NetworkId: NewId(), SidecarId: NewId(), Store: newTestMemoryStore(), Clock: clock})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		run := &mailComponentRun{ctx: ctx, cancel: cancel}
		clock.arm(2, cancel)
		clock.open()
		clock.awaitRun(t, "the generation", func() {
			client.runGeneration(run)
		})
		cancel()
		if clock.asks() != 2 {
			t.Fatalf("round %d: %d waits, want the 2 of 2 passes", round, clock.asks())
		}
	}
}

// An auth source that counts its pin's reads: each step of a stop state's reads it.
type clockSelectCountingAuth struct {
	HeadCheckAuthSource
	pinCount atomic.Int64
}

func (self *clockSelectCountingAuth) Pin() *bridge.AuthPin {
	self.pinCount.Add(1)
	return self.HeadCheckAuthSource.Pin()
}

// A head check transport over a device at the api's tip, as AttachHeadCheck makes one, on clock: its dispatcher a
// bare one, its candidates none, each round counted in rounds, and its stop state reading its pin through auth, which
// counts each step it takes. The transport ends with the test.
func newClockSelectHeadCheckTransport(t *testing.T, clock Clock, rounds *atomic.Int64) (*headCheckTransport, *testHeadCheckSourceDevice, *clockSelectCountingAuth) {
	t.Helper()
	settings := DefaultSidecarProtocolSettings()
	networkId := NewId()
	sidecarId := NewId()
	api := newTestHeadCheckApi(networkId, testMainChain, 10)
	source := newTestHeadCheckSourceDevice(sidecarId, networkId, api, testMainChain, 10)
	auth := &clockSelectCountingAuth{HeadCheckAuthSource: source}
	stopSources := source.sources()
	stopSources.Auth = auth
	stop, err := NewHeadStopState(context.Background(), &HeadStopStateEnv{
		SidecarId:         sidecarId,
		NetworkId:         networkId,
		Sources:           stopSources,
		Store:             newTestHeadStopStore(),
		Settings:          settings,
		Clock:             newTestConfigClock(),
		Log:               NewNoopLogger(),
		WitnessBoundHours: func() (uint32, bool) { return WitnessBoundDefaultHours, true },
		SharedGroup:       func(groupId Id) bool { return true },
		Alarm:             func(event SidecarEvent) {},
		RequestRound:      func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	transport := &headCheckTransport{
		ctx:         ctx,
		cancel:      cancel,
		subprotocol: &Subprotocol{log: NewNoopLogger()},
		env: &HeadCheckEnv{
			Stop: stop,
			Candidates: func() []HeadCheckCandidate {
				rounds.Add(1)
				return nil
			},
		},
		stop:                 stop,
		sources:              source.sources(),
		settings:             settings,
		clock:                clock,
		random:               func(n int) int { return 0 },
		roundRequests:        make(chan struct{}, 1),
		exchangeCount:        NewMonitorValue[uint64](0),
		roundCount:           NewMonitorValue[uint64](0),
		wakeCount:            NewMonitorValue[uint64](0),
		peerRotations:        map[Id]*headCheckRotation{},
		peerExchangeTimes:    map[Id]time.Time{},
		peerExchangesRunning: map[Id]bool{},
	}
	return transport, source, auth
}

// The head check runs no round once its transport has ended: it rounds at once and after each HeadCheckInterval, and
// an end landing as the second interval's wait fires ends the loop after the two rounds before it, in each of 64
// rounds. A loop that took the timer's case ran a round on the dead transport, the stop state's round step, its acts
// and an exchange with each pick.
func TestHeadCheckRunsNoRoundAfterTheTransportEnds(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), true, settings.HeadCheckInterval)
		rounds := &atomic.Int64{}
		transport, _, _ := newClockSelectHeadCheckTransport(t, clock, rounds)
		clock.arm(2, transport.cancel)
		clock.open()
		transport.workers.Add(1)
		clock.awaitRun(t, "the rounds", transport.run)
		if count := rounds.Load(); count != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d rounds and %d waits, want 2 of each", round, count, clock.waits())
		}
	}
}

// A fetch's follow-up tries and judges nothing once its transport has ended: with the halfway's timer fired as the
// transport ended, it fetches nothing; and with the second try done, an end landing as the deadline's wait fires
// leaves the stop state unstepped; in each of 64 rounds. A follow-up that took the timer's case fetched on the dead
// transport, or stepped the fetch rows, which ask the claimant for a proof.
func TestHeadCheckFollowFetchTriesNothingAfterTheTransportEnds(t *testing.T) {
	deadlineWait := 7 * time.Second
	// a pin two past the device's, on its chain, so the fetch still waits on it after the second try
	ahead := &bridge.AuthPin{Version: 12, Chain: testMainChain.digest(12)}
	for round := range 64 {
		clock := newClockSelectEndingClock(t, clockSelectTestStart(), false, deadlineWait)
		transport, source, _ := newClockSelectHeadCheckTransport(t, clock, &atomic.Int64{})
		clock.open()
		halfway := make(chan time.Time, 1)
		halfway <- clock.Now()
		transport.cancel()
		clock.awaitRun(t, "the follow-up", func() {
			transport.followFetch(headCheckAct{kind: headCheckActFetch, pin: ahead, deadline: clock.Now().Add(deadlineWait)}, halfway)
		})
		source.actLock.Lock()
		fetchCount := source.fetchCount
		source.actLock.Unlock()
		if fetchCount != 0 {
			t.Fatalf("round %d, the halfway: %d fetches, want none", round, fetchCount)
		}

		clock = newClockSelectEndingClock(t, clockSelectTestStart(), false, deadlineWait)
		transport, _, auth := newClockSelectHeadCheckTransport(t, clock, &atomic.Int64{})
		// the stop state's steps by the end, read as the end lands, once the stop's own loop has seen every change, so
		// no pass of that loop reads the pin after
		var stepsAtEnd int64
		clock.arm(1, func() {
			guard := time.After(clock.guard)
			for {
				mark, marked := transport.stop.loopMark.Get()
				if 0 < mark.passes && mark.seen == transport.stop.changed.Value() {
					break
				}
				select {
				case <-marked:
				case <-guard:
					t.Errorf("round %d: the stop state's loop did not settle within %v", round, clock.guard)
					transport.cancel()
					return
				}
			}
			stepsAtEnd = auth.pinCount.Load()
			transport.cancel()
		})
		clock.open()
		halfway = make(chan time.Time, 1)
		halfway <- clock.Now()
		clock.awaitRun(t, "the follow-up", func() {
			transport.followFetch(headCheckAct{kind: headCheckActFetch, pin: ahead, deadline: clock.Now().Add(deadlineWait)}, halfway)
		})
		if steps := auth.pinCount.Load(); steps != stepsAtEnd || clock.waits() != 1 {
			t.Fatalf("round %d, the deadline: the stop state read its pin %d times past the end, after %d waits; want none after 1", round, steps-stepsAtEnd, clock.waits())
		}
	}
}
