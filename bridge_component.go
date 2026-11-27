//go:build !ios_extension && !sidecar_http

// The bridge component (DESIGN-DETAILS 12.2.5; BRIDGE-M4-17): the root's half of the bridge on a daemon. It follows the
// network's config, compiles it (bridge_compile.go) and feeds the device role's sink, device.Bridge through cli/'s
// adapter, and on each client generation serves bridge flows through a provider whose NAT carries the sink's hook. An
// app builds none (DESIGN-DETAILS 4.7): its VPN component's Forwarder is the sink's producer there.
//
// One goroutine, run, owns every call into the sink, so they are ordered:
//
//	entries   the config client's entry callback only moves a position, since it must not block; run hands the sink
//	          every entry above the newest it holds, read from the client's log, which keeps an entry before its
//	          callbacks run, with ApplyDeltas, then each denial the judge decided at an entry to Revoke at that entry's
//	          own position, never 0 (12.2.5's "a denial is held at its own position")
//	compile   wanted by an entry that is not a pure denial, a base, a binding that arrived; coalesced for
//	          CompileDelay, at most one each CompileMinInterval, retried at CompileRetryInterval doubling to
//	          CompileRetryMaxInterval after an error, which changes nothing but an alarm; a result goes to SetState
//	          with the log run from its base through its pin, and a compile that captured a lower pin than the state
//	          in force is dropped by the posture whole
//	attach    per client generation (12.2.5's gate): the NAT with the hook in its settings, never installed after;
//	          the catch-up, every entry above the sink's state pin replayed with its denials, waiting for the client's
//	          follow where its store lagged the posture's and alarming catch_up_waiting after CatchUpAlarmTimeout; a
//	          compile at the tip where one can run; and only then the provider, so no frame reaches the NAT before it
//	shares    each state the device role takes in force, and each GrantRevoke of a served share's grant, moves the hold
//	          of FriendsAndFamily on every generation's dispatcher, held while a share this host serves stands
//	          (bridge_share.go)
//
// A wanted compile, and a failed one's retry, are dated by a reading of the clock taken before what caused them could
// be seen, never after, as the Forwarder's are (bridge_forward.go): the entries run takes before the sink is handed
// them, since it shows a delta's pin before ApplyDeltas returns and a denial before Revoke does; a device role before
// it is set and anchored; a binding pass before its first fetch; a retry before the failure is counted or its alarms
// raised. Whoever sees the cause may move a test's clock at once, and a reading after that move would date the compile
// past it by the move, which a clock moved once to the time it expects never reaches (wantCompileAt; QD-1425's race
// one step earlier).
//
// The bindings a compile waits for are fetched on a goroutine of their own (GET /sidecar/identity), verified under the
// identity key the config admits (VerifyBridgeBinding), kept in the cache and the component's store, and only change
// the compile's inputs. Logs and alarms name opaque ids, never a prefix, an address or a name (I-13).
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The bridge component is not serving, or was given nothing to feed.
var ErrBridgeComponentClosed = errors.New("bridge component closed")

// Section 4's ForwarderSink (bridge_forward.go) with Revoke and EgressHook (DESIGN-DETAILS 12.2.5): what device.Bridge
// is to its producers. cli/ adapts device.Bridge to it for ur tun. The component calls it from one goroutine.
type BridgeStateSink interface {
	ForwarderSink
	// n is the denial's own position, never 0.
	Revoke(statementType bridge.SignedType, id []byte, n uint64) error
	EgressHook() connect.EgressHook
}

// What the component reads of the network's config: TEAM-M2-10's ConfigClient is one. The log's State and Pin are read
// from any goroutine; its kept entries only on the follower's, in an entry callback, or through BridgeEntries.
type BridgeConfigSource interface {
	// The client's log, nil before its first read or restore.
	Log() *ConfigLog
	// Runs callback on the follower's goroutine after each applied entry, the entry kept first; the returned function
	// removes it.
	AddEntryCallback(callback SidecarAuthorityEntryFunction) func()
	// The state at or past n, once the client's follow reaches it.
	WaitFor(ctx context.Context, n uint64) (*ConfigState, error)
	// The entries the client keeps in [from, through], each with the denials it carried, from the first it keeps to
	// the first gap; read so the follower applies nothing meanwhile.
	BridgeEntries(from uint64, through uint64) []*BridgeConfigEntry
}

// One entry of the log as the component hands it to the sink.
type BridgeConfigEntry struct {
	N uint64
	// The AuthEntry as the log keeps it, verbatim.
	EntryBytes []byte
	// The denials it carried as the judge decided them, each held at N.
	Denials []BridgeDenial
	// Whether it carried denials and nothing else, so it wants no compile.
	Pure bool
}

// One denial an entry carried: what BridgeStateSink.Revoke takes.
type BridgeDenial struct {
	// SIGNED_SIDECAR_REVOKE, SIGNED_MEMBER_REVOKE, SIGNED_SUSPEND, SIGNED_GRANT_REVOKE or a resetting
	// SIGNED_BRIDGE_WITHDRAW.
	Type bridge.SignedType
	// The sidecar_id, member_id, subject, grant_id or rule_id it names.
	Id []byte
}

// Tunables of the bridge component (DESIGN-DETAILS 12.2.2's settings row).
type BridgeComponentSettings struct {
	// How long a wanted compile waits for more wants to coalesce with: 100 ms.
	CompileDelay time.Duration
	// The least time between two compiles' starts: 1 s.
	CompileMinInterval time.Duration
	// The first retry after a compile's error, doubling to CompileRetryMaxInterval: 5 s to 5 min.
	CompileRetryInterval    time.Duration
	CompileRetryMaxInterval time.Duration
	// How long a start's catch-up waits for the client's follow to reach the posture's pin before it alarms
	// catch_up_waiting: 30 s. It waits on after the alarm; the provider is never built before the catch-up.
	CatchUpAlarmTimeout time.Duration
	// The longest a WindowDelegation this sidecar signs lives: 168 h, the longest a window client does (§7.4).
	WindowDelegationMaxLifetime time.Duration
	// How often a current binding is fetched again: 6 h.
	BindingRefreshInterval time.Duration
	// How long a client id stays among a subject's after it stopped being current: 7 days (QD-161).
	BindingRetainTimeout time.Duration
	// The most client ids kept a subject, the current one included: 16.
	BindingMaxCount int
	// The longest one binding fetch runs: 30 s.
	BindingFetchTimeout time.Duration
	// How often the rows of the shares this host serves are fetched again, beside each a compile waits for: 1 h
	// (DESIGN-DETAILS 12.2.2's ShareTableRefreshInterval).
	ShareTableRefreshInterval time.Duration
	// The table view's own settings; nil is its defaults.
	ShareTables *BridgeShareTableViewSettings
	// ur tun ip auto, refused until §22.9's Browsers check (plan-BRIDGE-small-readings #18): false.
	AutoAddressEnabled bool
	// The compile's ledger and own settings. Nil is each one's defaults.
	Ledger  *BridgeLedgerSettings
	Compile *BridgeCompileSettings
	// The provider NAT's settings, whose EgressHook the component sets on a copy, and the provider's. Nil is connect's
	// defaults.
	Nat      *connect.LocalUserNatSettings
	Provider *connect.RemoteUserNatProviderSettings
}

// DESIGN-DETAILS 12.2.2's values.
func DefaultBridgeComponentSettings() *BridgeComponentSettings {
	return &BridgeComponentSettings{
		CompileDelay:                100 * time.Millisecond,
		CompileMinInterval:          1 * time.Second,
		CompileRetryInterval:        5 * time.Second,
		CompileRetryMaxInterval:     5 * time.Minute,
		CatchUpAlarmTimeout:         30 * time.Second,
		WindowDelegationMaxLifetime: 168 * time.Hour,
		BindingRefreshInterval:      6 * time.Hour,
		BindingRetainTimeout:        7 * 24 * time.Hour,
		BindingMaxCount:             16,
		BindingFetchTimeout:         30 * time.Second,
		ShareTableRefreshInterval:   time.Hour,
		AutoAddressEnabled:          false,
	}
}

// What a bridge component is built over.
type BridgeComponentArgs struct {
	NetworkId Id
	// This sidecar's identity: its ids and public keys. Nil is each generation's.
	Identity func() *SidecarIdentity
	// The network's config.
	Config BridgeConfigSource
	// Reads the head a base names. Nil compiles nothing: the sink stays as its posture has it.
	Heads ConfigHeadReader
	// A base's rows, for the log runs the sink verifies.
	Rows ConfigRowsSource
	// The config's generation keys, nil for one not held.
	RepoKeyAt func(generation uint64) *EvsRepoKey
	// AclFollower's local policy, nil with no document or before it compiles.
	AclLocal func() *AclLocalPolicy
	// Takes every advertiser's subnet routes in force at each state the component compiles that the device role then
	// holds in force, for the host's AclEngine (AclEngine.InstallRoutes; owner decision 575), so ur bridge's previews
	// and MCP's acl_check answer a route rule that names no prefix by the routes the device role enforces: a state the
	// role drops or refuses hands none. Nil asks the compile for none. Called on the compile's goroutine with no lock
	// held, so it must not block.
	ServedRoutes func(servedRoutes *AclServedRoutes)
	// Rule 0's input, DaemonLocalListen's binds, host:port. Nil for none.
	DaemonListeners func() []string
	// The zones the names answer under (§12.9), and the labels the zone publishes, which no client name shadows.
	NameZones      []string
	PublishedNames func() []string
	// Called at each Attach, before the generation's gate, with its env: a host's link builder takes the generation's
	// api and client from it. Nil for none.
	OnAttach func(env *SidecarEnv)
	// RecordReach.Note of the network's record, which the device role's reach events are noted to (bridge_reach.go).
	// Nil takes no events: they wait in the device role, bounded.
	Reach func(note *RecordReachNote) error
	// A grant's owner, approver and action by its id, for its receipts. Nil, or a nil answer, leaves them empty.
	ReachGrant func(grantId []byte) *BridgeReachGrant
	// RecordModels.InForce: the model manifest in force for a forward's port on this host. Nil names none.
	ReachManifest func(port uint32) *RecordContentRef
	// Raises bridge_alarm. Nil drops it.
	Emit SidecarEventFunction
	// Where the rows of the shares this host serves are fetched from (BridgeShareTableView); nil is the generation's
	// api, GET /network/bridge/share/<share_id>.
	ShareRows BridgeShareRowSource
	Clock     Clock
	Log       Logger
	Settings  *BridgeComponentSettings

	// tests stand in for connect's NAT and provider; nil is connect's
	parts *bridgeProviderParts
}

// What `ur bridge` and the daemon's status read of the component.
type BridgeComponentStatus struct {
	// Whether a device role is set, and whether the current generation's provider serves.
	DeviceRole bool
	Serving    bool
	// The sink's decision.
	Decision BridgeSinkDecision
	// The newest compile handed to the sink: its pin, its digest, what it waited for and alarmed on.
	CompiledPin *bridge.AuthPin
	Digest      [32]byte
	Waits       []BridgeCompileWait
	Alarms      []BridgeAlarm
	// Compiles run and refused since the component started.
	CompileCount      uint64
	CompileErrorCount uint64
	// Whether a start's catch-up waits for the client's follow.
	CatchUpWaiting bool
	// §16.8's reach receipts (bridge_reach.go): the flows the device role reported that were noted to the record, and
	// those whose event or note was refused.
	ReachNotedCount   uint64
	ReachRefusedCount uint64
}

// The bridge component (the file's comment).
type BridgeComponent struct {
	args     *BridgeComponentArgs
	settings *BridgeComponentSettings
	clock    Clock
	log      Logger

	ctx    context.Context
	cancel context.CancelFunc
	// closed when run returns
	done chan struct{}

	// work run hands its goroutine: a device role, a catch-up's request
	requests chan func()
	// moves when the entry callback adds to pending
	tip          *MonitorValue[uint64]
	removeEntry  func()
	bindings     *BridgeBindingCache
	bindingsWake chan struct{}
	// closed when fetchBindings returns
	bindingsDone chan struct{}
	// the rows of the shares this host serves, which the fetcher keeps and a compile reads (BridgeCompileLocal.ShareTables)
	shareTables *BridgeShareTableView

	stateLock sync.Mutex
	// the entries the callback read on the follower's goroutine, oldest first, which run takes
	pending []*BridgeConfigEntry
	// what run owns, read by Status and SignWindowDelegation under stateLock
	sink          BridgeStateSink
	compiled      *BridgeCompiled
	compileCount  uint64
	compileErrors uint64
	// generations whose provider serves, which overlap while one ends
	servingCount   int
	catchUpWaiting bool
	// the generation's api and store, for the binding fetcher; nil before the first Attach
	api   *SidecarApi
	store SidecarStore
	// the newest generation, and whether its gate started
	generation      *SidecarEnv
	generationGated bool
	parts           *bridgeProviderParts
	// whether the binding cache was read from a generation's store
	bindingsLoaded bool

	// owned by run alone
	compileWanted   bool
	compileWantedAt time.Time
	compileLastAt   time.Time
	compileRetry    time.Duration
	compileRetryAt  time.Time
	// the newest position whose denials the sink was handed
	revokedThrough uint64
	// the block the last compile held, the next one's PreviousBlock, and the record it came from (QD-1205)
	block       *bridge.BridgeBlock
	blockRecord []byte
	// the alarms the last compile raised, so a repeat is not raised again
	raisedAlarms []BridgeAlarm

	// the device role's reach events, noted to the record (bridge_reach.go); its own lock
	reach bridgeComponentReach
	// the share signers the newest compiled head carries, and the generations signed with (bridge_share_signer.go);
	// its own lock
	shares bridgeComponentShares
	// FriendsAndFamily on each generation's dispatcher while a share this host serves stands (bridge_share.go); its own
	// lock and goroutine
	shareMode *bridgeShareMode
}

var _ SidecarComponent = (*BridgeComponent)(nil)
var _ SidecarActiveComponent = (*BridgeComponent)(nil)

// A component over args, its goroutines started, following the config at once. args.Config is required.
func NewBridgeComponent(ctx context.Context, args *BridgeComponentArgs) (*BridgeComponent, error) {
	if args == nil || args.Config == nil {
		return nil, errors.New("bridge component: no config")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultBridgeComponentSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &BridgeComponent{
		args:         args,
		settings:     settings,
		clock:        clock,
		log:          loggerOrDefault(args.Log),
		ctx:          cancelCtx,
		cancel:       cancel,
		done:         make(chan struct{}),
		requests:     make(chan func()),
		tip:          NewMonitorValue[uint64](0),
		bindings:     NewBridgeBindingCache(settings.BindingRetainTimeout, settings.BindingMaxCount),
		bindingsWake: make(chan struct{}, 1),
		bindingsDone: make(chan struct{}),
		compileRetry: settings.CompileRetryInterval,
		parts:        args.parts,
	}
	if self.parts == nil {
		self.parts = defaultBridgeProviderParts(settings)
	}
	self.shareMode = newBridgeShareMode(cancelCtx, args.NetworkId, clock, self.log)
	var shareRows BridgeShareRowSource = &bridgeComponentShareRows{component: self}
	if args.ShareRows != nil {
		shareRows = args.ShareRows
	}
	self.shareTables, _ = NewBridgeShareTableView(shareRows, settings.ShareTables)
	// on the follower's goroutine, which keeps the entry first: it reads the entry there and never blocks
	self.removeEntry = args.Config.AddEntryCallback(func(entry *SidecarAuthorityEntry) {
		log := args.Config.Log()
		if log == nil {
			return
		}
		read := bridgeConfigEntryOf(log, entry.Pin.GetVersion())
		if read == nil {
			return
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.pending = append(self.pending, read)
		}()
		self.tip.Update(func(n uint64) uint64 { return max(n, read.N) })
	})
	if log := args.Config.Log(); log != nil {
		self.tip.Set(log.Pin().GetVersion())
	}
	go self.run()
	go self.fetchBindings()
	return self, nil
}

// "bridge".
func (self *BridgeComponent) Name() string {
	return "bridge"
}

// Whether the bridge serves, which keeps the daemon from idling out (§5.8).
func (self *BridgeComponent) Active() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sink != nil
}

// Sets the device role the component feeds, cli/'s adapter of device.Bridge for ur tun, once. Before its first state the
// role is anchored as pending (§18.6): it denies every private destination and exit until a compile verifies. A role
// set while a generation runs starts that generation's gate.
func (self *BridgeComponent) SetDeviceRole(sink BridgeStateSink) error {
	if sink == nil {
		return errors.New("bridge component: no device role")
	}
	var startErr error
	err := self.onRun(func() {
		// the role's compile is wanted from before Status shows the role set or the role shows its anchor
		setAt := self.clock.Now()
		var generation *SidecarEnv
		set := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.sink != nil {
				return false
			}
			self.sink = sink
			if self.generation != nil && !self.generationGated && self.generation.Ctx.Err() == nil {
				self.generationGated = true
				generation = self.generation
			}
			return true
		}()
		if !set {
			startErr = errors.New("bridge component: a device role is set already")
			return
		}
		self.revokedThrough = sink.Decision().StatePin.GetVersion()
		self.anchor(sink)
		self.followReach(sink)
		self.wantCompileAt(setAt)
		if generation != nil {
			startErr = self.startGate(generation, sink)
		}
	})
	if err != nil {
		return err
	}
	return startErr
}

// Anchors a legacy role as pending at the config's genesis.
func (self *BridgeComponent) anchor(sink BridgeStateSink) {
	if sink.Decision().State != BridgeSinkLegacy {
		return
	}
	log := self.args.Config.Log()
	identity := self.identity()
	if log == nil || identity == nil {
		return
	}
	if err := sink.SetPending(CompileBridgePending(log.State(), identity)); err != nil {
		self.log.Warningf("[bridge]%s the device role refused its anchor: %v", self.args.NetworkId, err)
	}
}

// This sidecar's identity, nil before one.
func (self *BridgeComponent) identity() *SidecarIdentity {
	if self.args.Identity != nil {
		return self.args.Identity()
	}
	return nil
}

// Runs work on run's goroutine and waits for it, or fails once the component is closed.
func (self *BridgeComponent) onRun(work func()) error {
	done := make(chan struct{})
	select {
	case self.requests <- func() {
		defer close(done)
		work()
	}:
	case <-self.ctx.Done():
		return ErrBridgeComponentClosed
	}
	select {
	case <-done:
		return nil
	case <-self.ctx.Done():
		return ErrBridgeComponentClosed
	}
}

// Starts one client generation's part (12.2.5's gate): the NAT with the hook, then on a goroutine of the generation's
// the catch-up and only then the provider. Returns at once; everything it starts ends with env.Ctx. With no device
// role yet nothing is served, the closed direction, until SetDeviceRole.
func (self *BridgeComponent) Attach(env *SidecarEnv) error {
	var sink BridgeStateSink
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		sink = self.sink
		self.generation = env
		self.generationGated = sink != nil
		if env.SidecarApi != nil {
			self.api = env.SidecarApi
		}
		if env.Store != nil {
			self.store = env.Store
		}
	}()
	// the generation's dispatcher provides FriendsAndFamily while a share this host serves stands (bridge_share.go)
	self.shareMode.attach(env.Ctx, env.Subprotocol)
	self.loadBindings(env)
	if self.args.OnAttach != nil {
		self.args.OnAttach(env)
	}
	if sink == nil {
		return nil
	}
	return self.startGate(env, sink)
}

// The gate of one generation: its NAT now, with sink's hook in its settings; on a goroutine the catch-up, then the
// provider, which serves until the generation or the component ends. Returns at once.
func (self *BridgeComponent) startGate(env *SidecarEnv, sink BridgeStateSink) error {
	gate, err := newBridgeProviderGate(env, sink.EgressHook(), self.settings, self.parts)
	if err != nil {
		return err
	}
	go func() {
		defer gate.close()
		if err := self.catchUp(env.Ctx); err != nil {
			return
		}
		testHookBarrier("bridge_component.provide.before", self.args.NetworkId.String())
		if err := gate.serve(); err != nil {
			self.log.Warningf("[bridge]%s no provider on this generation: %v", self.args.NetworkId, err)
			return
		}
		self.addServing(1)
		defer self.addServing(-1)
		select {
		case <-env.Ctx.Done():
		case <-self.ctx.Done():
		}
	}()
	return nil
}

// Counts a generation's provider in or out.
func (self *BridgeComponent) addServing(delta int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.servingCount += delta
}

// 12.2.5's step 3: replays every entry above the sink's state pin with its denials, waiting for the client's follow
// where its store lagged the posture's pin, then compiles at the tip where one can run. Returns once caught up, or
// with ctx's error. No catch_up_waiting is raised once ctx has ended, its timer taken as ctx ended included, and an
// ended ctx asks the clock for nothing.
func (self *BridgeComponent) catchUp(ctx context.Context) error {
	alarmed := false
	waitStart := self.clock.Now()
	for {
		lagging := uint64(0)
		err := self.onRun(func() {
			sink := self.currentSink()
			if sink == nil {
				return
			}
			decision := sink.Decision()
			log := self.args.Config.Log()
			if log == nil || log.Pin().GetVersion() < decision.Pin.GetVersion() {
				lagging = decision.Pin.GetVersion()
				return
			}
			// every entry above the state in force, its denials again: a judged denial held only in memory before a
			// restart is held again before the provider
			self.revokedThrough = min(self.revokedThrough, decision.StatePin.GetVersion())
			tip := log.Pin().GetVersion()
			self.handEntries(self.args.Config.BridgeEntries(self.revokedThrough+1, tip))
			self.compileNow()
		})
		if err != nil {
			return err
		}
		if lagging == 0 {
			self.setCatchUpWaiting(false)
			return nil
		}
		self.setCatchUpWaiting(true)
		waitCtx, cancel := context.WithCancel(ctx)
		reached := make(chan error, 1)
		go func() {
			_, err := self.args.Config.WaitFor(waitCtx, lagging)
			reached <- err
		}()
		var alarmAfter <-chan time.Time
		if !alarmed && ctx.Err() == nil {
			// for the alarm's time itself, so a move of the clock as the wait is set cannot leave it late (QD-1425)
			alarmAfter = ClockAfterAt(self.clock, waitStart.Add(self.settings.CatchUpAlarmTimeout))
		}
		select {
		case err := <-reached:
			cancel()
			if err != nil && ctx.Err() != nil {
				return ctx.Err()
			}
		case <-alarmAfter:
			// select takes any of its ready cases at random: the alarm's timer taken as ctx ended raises nothing
			if err := ctx.Err(); err != nil {
				cancel()
				return err
			}
			alarmed = true
			self.emitAlarm(BridgeAlarm{Reason: SidecarBridgeAlarmCatchUpWaiting, N: lagging,
				Detail: "the config's follow lags the device role's pin; no provider until it catches up"})
			select {
			case err := <-reached:
				cancel()
				if err != nil && ctx.Err() != nil {
					return ctx.Err()
				}
			case <-ctx.Done():
				cancel()
				return ctx.Err()
			}
		case <-ctx.Done():
			cancel()
			return ctx.Err()
		}
	}
}

// Whether a catch-up waits.
func (self *BridgeComponent) setCatchUpWaiting(waiting bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.catchUpWaiting = waiting
}

// The device role, nil before one.
func (self *BridgeComponent) currentSink() BridgeStateSink {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sink
}

// Ends the component: its goroutines, and the entry callback. The device role is the caller's. The binding fetcher is
// joined too, so no pass of its saves the cache once Close has returned: each of its steps ends with the component's
// context, and it takes no lock Close's callers hold.
func (self *BridgeComponent) Close() {
	self.cancel()
	if self.removeEntry != nil {
		self.removeEntry()
	}
	<-self.done
	<-self.shareMode.done
	<-self.bindingsDone
	self.stopReach()
}

// The component's state.
func (self *BridgeComponent) Status() BridgeComponentStatus {
	var sink BridgeStateSink
	status := func() BridgeComponentStatus {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		sink = self.sink
		status := BridgeComponentStatus{
			DeviceRole:        self.sink != nil,
			Serving:           0 < self.servingCount,
			CompileCount:      self.compileCount,
			CompileErrorCount: self.compileErrors,
			CatchUpWaiting:    self.catchUpWaiting,
		}
		if self.compiled != nil && self.compiled.State != nil {
			status.CompiledPin = proto.Clone(self.compiled.State.GetAuth()).(*bridge.AuthPin)
			status.Digest = self.compiled.Digest
			status.Waits = slices.Clone(self.compiled.Waits)
			status.Alarms = slices.Clone(self.compiled.Alarms)
		}
		return status
	}()
	if sink != nil {
		status.Decision = sink.Decision()
	}
	status.ReachNotedCount, status.ReachRefusedCount = self.reachCounts()
	return status
}

// The newest compile handed to the sink, nil before one. The caller must not change it.
func (self *BridgeComponent) Compiled() *BridgeCompiled {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.compiled
}

// The loop that owns every call into the sink (the file's comment). No turn starts once the component has closed, a
// compile's timer or a tip taken as it closed included, so the sink is handed no entry and no compile past the end.
func (self *BridgeComponent) run() {
	defer close(self.done)
	// select takes any of its ready cases at random: a case taken as the component closed reads as the end
	for self.ctx.Err() == nil {
		_, tipChanged := self.tip.Get()
		var reads []*BridgeConfigEntry
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			// with no device role the catch-up at SetDeviceRole reads the log instead
			reads, self.pending = self.pending, nil
			if self.sink == nil {
				reads = nil
			}
		}()
		if 0 < len(reads) {
			self.handEntries(reads)
		}
		if self.ctx.Err() != nil {
			// a component that closed as the entries went asks the clock for nothing
			return
		}
		var compileAt <-chan time.Time
		if self.compileWanted {
			due := self.compileDueAt()
			if !due.After(self.clock.Now()) {
				self.compileNow()
				continue
			}
			compileAt = ClockAfterAt(self.clock, due)
		}
		select {
		case <-self.ctx.Done():
		case work := <-self.requests:
			work()
		case <-tipChanged:
		case <-compileAt:
		}
	}
}

// Marks a compile wanted from at, coalescing with one already wanted. at is a reading of the clock taken before
// anything that caused the want could be seen (the file's comment): whoever saw it may move a test's clock next, and a
// reading taken after that move would put the compile CompileDelay past the move rather than past the want. On run's
// goroutine.
func (self *BridgeComponent) wantCompileAt(at time.Time) {
	if !self.compileWanted {
		self.compileWanted = true
		self.compileWantedAt = at
	}
}

// When the wanted compile may start: CompileDelay after it was wanted, CompileMinInterval after the last one started,
// and no sooner than a retry's wait. On run's goroutine.
func (self *BridgeComponent) compileDueAt() time.Time {
	due := self.compileWantedAt.Add(self.settings.CompileDelay)
	due = laterTime(due, self.compileLastAt.Add(self.settings.CompileMinInterval))
	return laterTime(due, self.compileRetryAt)
}

// Hands the sink entries read from the log, oldest first: those above the newest it holds with ApplyDeltas, then each
// denial of every entry above the newest whose denials it was handed, at the entry's own position, never 0. A gap
// below the first read is filled from the log first. The compile an entry wants is wanted from a reading taken before
// the sink is handed any of them. On run's goroutine.
func (self *BridgeComponent) handEntries(reads []*BridgeConfigEntry) {
	sink := self.currentSink()
	if sink == nil || len(reads) == 0 {
		return
	}
	// the sink shows a delta's pin before ApplyDeltas returns, and a denial before Revoke does (wantCompileAt)
	at := self.clock.Now()
	decision := sink.Decision()
	held := max(decision.Pin.GetVersion(), self.revokedThrough)
	if held+1 < reads[0].N {
		reads = append(self.args.Config.BridgeEntries(held+1, reads[0].N-1), reads...)
	}
	entries := [][]byte{}
	for _, read := range reads {
		if decision.Pin.GetVersion() < read.N && read.N == decision.Pin.GetVersion()+uint64(len(entries))+1 {
			entries = append(entries, read.EntryBytes)
		}
	}
	if decision.State == BridgeSinkEnforcing && 0 < len(entries) {
		run := &BridgeStateLog{Entries: entries, OpenRows: self.openRows()}
		if err := sink.ApplyDeltas(run); err != nil {
			self.log.Warningf("[bridge]%s the device role refused entries from %d: %v", self.args.NetworkId, decision.Pin.GetVersion()+1, err)
		}
	}
	for _, read := range reads {
		if read.N <= self.revokedThrough {
			continue
		}
		for _, denial := range read.Denials {
			testHookBarrier("bridge_component.revoke.before", self.args.NetworkId.String())
			if err := sink.Revoke(denial.Type, denial.Id, read.N); err != nil {
				self.log.Warningf("[bridge]%s the device role refused the denial at %d: %v", self.args.NetworkId, read.N, err)
			}
			if denial.Type == bridge.SignedType_SIGNED_GRANT_REVOKE {
				// a served share whose grant this revokes stands no more, before any compile drops it
				self.shareMode.revoke(denial.Id)
			}
		}
		if !read.Pure {
			self.wantCompileAt(at)
		}
		self.revokedThrough = read.N
	}
}

// The entry at n read from log, with the denials it carried as the judge decided them (its own statement, the one a
// proposal's last cosign completed, or a tick's activations); nil for one the log does not keep. A withdrawal to
// drain is no denial here: the compile drains it (§17.8's disposition). On the log's follower goroutine, or under its
// follow lock.
func bridgeConfigEntryOf(log *ConfigLog, n uint64) *BridgeConfigEntry {
	kept := log.keptEntry(n)
	if kept == nil {
		return nil
	}
	read := &BridgeConfigEntry{N: n, EntryBytes: bytes.Clone(kept.entryBytes)}
	statements := []*configStatement{}
	switch kept.entry.GetKind() {
	case bridge.AuthEntryKindStatement:
		switch statement := kept.statement; {
		case statement == nil || !kept.verdict.Accepted() || statement.proposed != nil:
			// nothing took effect, or a proposal that waits for its cosigns
		case statement.completes != nil:
			statements = append(statements, statement.completes)
		default:
			statements = append(statements, statement)
		}
	case bridge.AuthEntryKindTick:
		for _, activation := range kept.activations {
			statements = append(statements, activation.statement)
		}
	}
	read.Pure = 0 < len(statements)
	for _, statement := range statements {
		denial, ok := bridgeStatementDenial(statement.signedType, statement.bodyBytes)
		if !ok {
			read.Pure = false
			continue
		}
		read.Denials = append(read.Denials, denial)
	}
	return read
}

// The entries a ConfigClient keeps in [from, through], each with its denials, read under its follow lock so its
// follower applies nothing meanwhile (BridgeConfigSource).
func (self *ConfigClient) BridgeEntries(from uint64, through uint64) []*BridgeConfigEntry {
	self.followLock.Lock()
	defer self.followLock.Unlock()
	log := self.configLog.Load()
	reads := []*BridgeConfigEntry{}
	if log == nil {
		return reads
	}
	// from the first entry the log keeps, to the first gap above it
	for n := max(from, log.keptFrom); n <= min(through, log.Pin().GetVersion()); n += 1 {
		read := bridgeConfigEntryOf(log, n)
		if read == nil {
			break
		}
		reads = append(reads, read)
	}
	return reads
}

// The denial a statement is, false for one that is none: a SidecarRevoke, a MemberRevoke, a Suspend, a GrantRevoke, or
// a BridgeWithdraw that resets.
func bridgeStatementDenial(signedType bridge.SignedType, body []byte) (BridgeDenial, bool) {
	var id []byte
	switch signedType {
	case bridge.SignedType_SIGNED_SIDECAR_REVOKE:
		statement := &bridge.SidecarRevoke{}
		if proto.Unmarshal(body, statement) != nil {
			return BridgeDenial{}, false
		}
		id = statement.GetSidecarId()
	case bridge.SignedType_SIGNED_MEMBER_REVOKE:
		statement := &bridge.MemberRevoke{}
		if proto.Unmarshal(body, statement) != nil {
			return BridgeDenial{}, false
		}
		id = statement.GetMemberId()
	case bridge.SignedType_SIGNED_SUSPEND:
		statement := &bridge.Suspend{}
		if proto.Unmarshal(body, statement) != nil {
			return BridgeDenial{}, false
		}
		id = statement.GetSubject()
	case bridge.SignedType_SIGNED_GRANT_REVOKE:
		statement := &bridge.GrantRevoke{}
		if proto.Unmarshal(body, statement) != nil {
			return BridgeDenial{}, false
		}
		id = statement.GetGrantId()
	case bridge.SignedType_SIGNED_BRIDGE_WITHDRAW:
		statement := &bridge.BridgeWithdraw{}
		if proto.Unmarshal(body, statement) != nil || statement.GetMode() != bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET {
			return BridgeDenial{}, false
		}
		id = statement.GetRuleId()
	default:
		return BridgeDenial{}, false
	}
	if len(id) == 0 {
		return BridgeDenial{}, false
	}
	return BridgeDenial{Type: signedType, Id: bytes.Clone(id)}, true
}

// Streams a base's rows for the sink's verification, nil without a rows source.
func (self *BridgeComponent) openRows() func(rowsSha256 []byte) (io.ReadCloser, error) {
	if self.args.Rows == nil {
		return nil
	}
	return func(rowsSha256 []byte) (io.ReadCloser, error) {
		data, err := self.args.Rows.Rows(self.args.NetworkId, rowsSha256)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
}

// Compiles at the client's verified tip and hands the sink the state (12.2.5's Compile). An error changes nothing but
// an alarm, and retries at the next interval, from a reading taken before the error was first shown: its alarms raised
// or its failure counted (wantCompileAt), so a retry waits from the failure. On run's goroutine.
func (self *BridgeComponent) compileNow() {
	self.compileWanted = false
	self.compileLastAt = self.clock.Now()
	// what follows the compile is dated by a reading taken once, just before its outcome is first shown
	var outcomeAt time.Time
	markOutcome := func() {
		if outcomeAt.IsZero() {
			outcomeAt = self.clock.Now()
		}
	}
	sink := self.currentSink()
	log := self.args.Config.Log()
	identity := self.identity()
	if sink == nil || log == nil || identity == nil || self.args.Heads == nil {
		return
	}
	state := log.State()
	base := state.Base()
	if base == nil {
		return
	}
	self.anchor(sink)
	err := func() error {
		ctx, cancel := context.WithTimeout(self.ctx, self.settings.BindingFetchTimeout)
		defer cancel()
		head, err := self.args.Heads.ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
		if err != nil {
			return err
		}
		var aclLocal *AclLocalPolicy
		if self.args.AclLocal != nil {
			aclLocal = self.args.AclLocal()
		}
		view, err := NewBridgeConfigView(state, head, aclLocal, self.args.RepoKeyAt, self.settings.Ledger)
		if err != nil {
			return err
		}
		local := &BridgeCompileLocal{
			SidecarId:           identity.SidecarId,
			Bindings:            self.bindings.Snapshot(),
			PreviousBlock:       self.block,
			PreviousBlockRecord: self.blockRecord,
			NameZones:           self.args.NameZones,
			ShareTables:         self.shareTables.Rows(),
			Settings:            self.settings.Compile,

			AnswerServedRoutes: self.args.ServedRoutes != nil,
		}
		if self.args.DaemonListeners != nil {
			local.DaemonListeners = self.args.DaemonListeners()
		}
		if self.args.PublishedNames != nil {
			local.PublishedNames = self.args.PublishedNames()
		}
		compiled, err := CompileBridgeState(view, local, self.settings.Ledger)
		markOutcome()
		if compiled != nil {
			self.raiseAlarms(compiled.Alarms)
		}
		if err != nil {
			return err
		}
		run := &BridgeStateLog{OpenRows: self.openRows()}
		for _, read := range self.args.Config.BridgeEntries(base.GetVersion(), state.Pin().GetVersion()) {
			run.Entries = append(run.Entries, read.EntryBytes)
		}
		setErr := sink.SetState(compiled.State, run)
		if setErr != nil {
			// the posture drops a state below the one in force whole, and refuses one it cannot verify
			self.log.Warningf("[bridge]%s the device role refused the state at %d: %v", self.args.NetworkId, state.Pin().GetVersion(), setErr)
		} else if self.args.ServedRoutes != nil && proto.Equal(sink.Decision().StatePin, compiled.State.GetAuth()) {
			// the routes of the state the device role holds in force: one it dropped, below the state it keeps, or
			// refused leaves the engine on the routes of the state it keeps
			self.args.ServedRoutes(compiled.ServedRoutes)
		}
		self.block, self.blockRecord = compiled.Block, compiled.BlockRecord
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.compiled = compiled
			self.compileCount += 1
		}()
		if setErr == nil && proto.Equal(sink.Decision().StatePin, compiled.State.GetAuth()) {
			// FriendsAndFamily while a share the state in force serves stands (bridge_share.go): a state the role
			// dropped or refused leaves the hold on the state it keeps
			self.shareMode.serve(compiled.State)
		}
		// a share whose signer changed has its links' window clients signed again (§17.9's resign row)
		if changed := self.shares.setHead(head); 0 < len(changed) {
			self.ResignShares(changed)
		}
		select {
		case self.bindingsWake <- struct{}{}:
		default:
		}
		return nil
	}()
	if err != nil {
		// a head or a view that failed shows first as Status counts it; a compile that failed was read before its alarms
		markOutcome()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.compileErrors += 1
		}()
		self.log.Warningf("[bridge]%s the compile at %d did not run: %v", self.args.NetworkId, state.Pin().GetVersion(), err)
		self.compileWanted = true
		self.compileWantedAt = outcomeAt
		self.compileRetryAt = outcomeAt.Add(self.compileRetry)
		self.compileRetry = min(2*self.compileRetry, self.settings.CompileRetryMaxInterval)
		return
	}
	self.compileRetry = self.settings.CompileRetryInterval
	self.compileRetryAt = time.Time{}
}

// Raises each alarm a compile found that the last one did not.
func (self *BridgeComponent) raiseAlarms(alarms []BridgeAlarm) {
	for _, alarm := range alarms {
		if !slices.Contains(self.raisedAlarms, alarm) {
			self.emitAlarm(alarm)
		}
	}
	self.raisedAlarms = slices.Clone(alarms)
}

// Raises bridge_alarm for a part of the bridge the Sidecar does not run itself: a daemon's component, whose Emit this
// is, and §17.4's shared block, which the daemon judges across its networks (BRIDGE-M6-06). sidecarId names the sidecar
// the alarm concerns, nil for none; an alarm never names a prefix, an address or a name (I-13).
func (self *Sidecar) RaiseBridgeAlarm(alarm SidecarBridgeAlarm, sidecarId *Id) error {
	if alarm == "" {
		return fmt.Errorf("%w: bridge_alarm names no reason", ErrSidecarEventInvalid)
	}
	event := SidecarEvent{Kind: SidecarEventBridgeAlarm, BridgeAlarm: alarm}
	if sidecarId != nil {
		id := *sidecarId
		event.SidecarId = &id
	}
	self.emitEvent(event)
	return nil
}

// Raises one bridge_alarm.
func (self *BridgeComponent) emitAlarm(alarm BridgeAlarm) {
	self.log.Warningf("[bridge]%s %s at %d: %s", self.args.NetworkId, alarm.Reason, alarm.N, alarm.Detail)
	if self.args.Emit == nil {
		return
	}
	event := SidecarEvent{Kind: SidecarEventBridgeAlarm, BridgeAlarm: alarm.Reason}
	if alarm.SidecarId != (Id{}) {
		sidecarId := alarm.SidecarId
		event.SidecarId = &sidecarId
	}
	self.args.Emit(event)
}

// Reads the binding cache from the first generation's store that has one, once.
func (self *BridgeComponent) loadBindings(env *SidecarEnv) {
	if env.Store == nil || self.args.Config.Log() == nil {
		return
	}
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		loaded := self.bindingsLoaded
		self.bindingsLoaded = true
		return !loaded
	}()
	if !first {
		return
	}
	state := self.args.Config.Log().State()
	if err := self.bindings.Load(env.Store, self.args.NetworkId, state.IdentityKey); err != nil {
		self.log.Warningf("[bridge]%s the binding cache did not load: %v", self.args.NetworkId, err)
	}
}

// The binding fetcher: after each compile, and each BindingRefreshInterval, every binding a compile waits for and
// every current one past its refresh, verified and kept, a share link host's under the network and key its alias
// pinned; and the rows of the shares a compile waits for, and each ShareTableRefreshInterval those it compiled. A
// change wants a compile, from the pass's reading of the clock, taken before its first fetch (wantCompileAt). Off the
// compile's path. No pass starts once the component has closed, a wake or a timer taken as it closed included, so no
// binding expires and no cache is saved past the end, and a closed component asks the clock for nothing.
func (self *BridgeComponent) fetchBindings() {
	fetchedAt := map[Id]time.Time{}
	// a share link host's network and pinned key, by its sidecar_id, kept for its refreshes
	shareHosts := map[Id]BridgeCompileWait{}
	sharesRefreshedAt := time.Time{}
	defer close(self.bindingsDone)
	// select takes any of its ready cases at random: a wake or a timer taken as the component closed reads as the end
	for self.ctx.Err() == nil {
		select {
		case <-self.ctx.Done():
		case <-self.bindingsWake:
		case <-self.clock.After(self.settings.BindingRefreshInterval):
		}
		if self.ctx.Err() != nil {
			return
		}
		var api *SidecarApi
		var store SidecarStore
		var compiled *BridgeCompiled
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			api, store, compiled = self.api, self.store, self.compiled
		}()
		log := self.args.Config.Log()
		if log == nil || compiled == nil {
			continue
		}
		state := log.State()
		now := self.clock.Now()
		wanted := []Id{}
		for _, wait := range compiled.Waits {
			// the bindings come from the generation's api; the shares' rows from their own source, which may be none's
			if api == nil {
				break
			}
			switch wait.Kind {
			case BridgeCompileWaitBinding:
				wanted = append(wanted, wait.SidecarId)
			case BridgeCompileWaitShareBinding:
				shareHosts[wait.SidecarId] = wait
				wanted = append(wanted, wait.SidecarId)
			}
		}
		for sidecarId, at := range fetchedAt {
			if api != nil && self.settings.BindingRefreshInterval <= now.Sub(at) && !slices.Contains(wanted, sidecarId) {
				wanted = append(wanted, sidecarId)
			}
		}
		slices.SortFunc(wanted, Id.Cmp)
		changed := false
		for _, sidecarId := range wanted {
			binding, err := func() (*BridgeBinding, error) {
				ctx, cancel := context.WithTimeout(self.ctx, self.settings.BindingFetchTimeout)
				defer cancel()
				record, err := api.GetIdentity(ctx, sidecarId, 0)
				if err != nil {
					return nil, err
				}
				networkId, identityKey := self.args.NetworkId, state.IdentityKey(sidecarId)
				if host, ok := shareHosts[sidecarId]; ok && len(identityKey) == 0 {
					// a share link's host, a sidecar of the sharing network, under the key the alias pinned (QD-077)
					networkId, identityKey = host.NetworkId, host.IdentityPublicKey[:]
				}
				return VerifyBridgeBinding(record.Binding, networkId, sidecarId, identityKey)
			}()
			if err != nil {
				if self.log.V(1).Enabled() {
					self.log.Infof("[bridge]%s no binding for %s: %v", self.args.NetworkId, sidecarId, err)
				}
				continue
			}
			fetchedAt[sidecarId] = now
			changed = self.bindings.Record(binding, now) || changed
		}
		changed = self.bindings.Expire(now) || changed
		changed = self.refreshShareTables(compiled, now, &sharesRefreshedAt) || changed
		if !changed {
			continue
		}
		if store != nil {
			if err := self.bindings.Save(store); err != nil {
				self.log.Warningf("[bridge]%s the binding cache was not kept: %v", self.args.NetworkId, err)
			}
		}
		// from the pass's reading: api saw its fetches, and the store shows the cache saved, before this
		self.onRun(func() { self.wantCompileAt(now) })
	}
}

// The rows of the shares a compile waits for, and each ShareTableRefreshInterval those it compiled, fetched into the
// table view; whether a row changed, which wants a compile. A failed fetch keeps the row held and is logged by count.
func (self *BridgeComponent) refreshShareTables(compiled *BridgeCompiled, now time.Time, refreshedAt *time.Time) bool {
	shareIds := []Id{}
	for _, wait := range compiled.Waits {
		if wait.Kind == BridgeCompileWaitShareTable {
			shareIds = append(shareIds, wait.ShareId)
		}
	}
	if self.settings.ShareTableRefreshInterval <= now.Sub(*refreshedAt) {
		for _, key := range compiled.State.GetShareKeys() {
			if shareId, err := IdFromBytes(key.GetShareId()); err == nil {
				shareIds = append(shareIds, shareId)
			}
		}
		*refreshedAt = now
	}
	if len(shareIds) == 0 {
		return false
	}
	slices.SortFunc(shareIds, Id.Cmp)
	shareIds = slices.Compact(shareIds)
	before := map[Id]*BridgeShareRow{}
	for _, shareId := range shareIds {
		before[shareId] = self.shareTables.Row(shareId)
	}
	if err := self.shareTables.Refresh(self.ctx, shareIds); err != nil && self.ctx.Err() == nil {
		self.log.Warningf("[bridge]%s %d share rows were not fetched: %v", self.args.NetworkId, len(shareIds), err)
	}
	changed := false
	for _, shareId := range shareIds {
		changed = changed || !bridgeShareRowEqual(before[shareId], self.shareTables.Row(shareId))
	}
	return changed
}

// Whether two rows are one: both none, or the same share at the same tables, versions and status.
func bridgeShareRowEqual(a *BridgeShareRow, b *BridgeShareRow) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.ShareId == b.ShareId && a.SharingNetworkId == b.SharingNetworkId && a.AcceptingNetworkId == b.AcceptingNetworkId &&
		bytes.Equal(a.TargetTable, b.TargetTable) && a.TargetTableVersion == b.TargetTableVersion &&
		bytes.Equal(a.AliasTable, b.AliasTable) && a.AliasTableVersion == b.AliasTableVersion && a.AcceptStatus == b.AcceptStatus
}

// The share rows through the generation's api: an error before the first Attach.
type bridgeComponentShareRows struct {
	component *BridgeComponent
}

// BridgeShareRowSource.
func (self *bridgeComponentShareRows) GetBridgeShare(ctx context.Context, shareId Id) (*BridgeShareRow, error) {
	api := func() *SidecarApi {
		self.component.stateLock.Lock()
		defer self.component.stateLock.Unlock()
		return self.component.api
	}()
	if api == nil {
		return nil, errors.New("bridge component: no api yet")
	}
	return api.GetBridgeShare(ctx, shareId)
}

// What the component holds, for a log line: never a prefix, an address or a name.
func (self *BridgeComponent) String() string {
	return fmt.Sprintf("bridge(%s)", self.args.NetworkId)
}
