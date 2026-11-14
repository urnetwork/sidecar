// SocketProjectionGate: SocketGate on the authorization log (§8.9, §9.10, X3, D-SOCK-14, R-SOCK-9), built to
// DESIGN-DETAILS 13.2.3, which governs where it and §9.8 differ. It wraps the process's one AclGateCache (C-09),
// which verifies every entry's chain from its own pin, refuses a lower n, a second A_n or a broken link with an
// alarm and keeps serving the old state (section 5), so nothing here re-reads an entry or judges a chain. What
// this file adds is around the cache: when a network's state may be acted on, and what a load tells the engine.
//
//   - Evidence that network N's log passed what this process holds: the {acl_<N>}v key event (Changed), a store
//     answer naming a position above the state's (Observe), and after a resubscription an {acl_<N>}v that differs
//     from the value recorded with the state (Resync's check). Each asks the cache to load N.
//   - The wrapped source's Entries notes, for the load it begins, the count of evidence that has arrived and
//     {acl_<N>}v, read before the entries. The cache's OnLoad without error then covers every evidence counted up
//     to then, and a loaded position covers every store position at or below it. A load the cache refused, or one
//     that failed, covers nothing.
//   - N is behind while any evidence is uncovered, from the first uncovered evidence's arrival. Past BehindGrace,
//     View answers ErrSocketGateBehind for N alone (QD-655), and a network still behind asks for another load each
//     BehindReloadInterval. With no evidence the last verified state serves without limit: an api outage moves no
//     log, since api is the log's only writer.
//   - A load that raised N's position past an entry socketEntryMayNarrow flags calls the engine's sweep queue. A
//     network's first load here is no rise: every process that held it fresh swept it as the entries landed.
//   - Spent and part of Ready are the over-limit poll's (over_limit.go).
//
// Every answer is from memory: View is a lock-free read of the cache, one short lock and no I/O (I-12). A
// key-event callback does no I/O either: the gate's worker runs the resubscription check, a batch at a time. The
// cache's own 5-minute poll stays and is no evidence: it loads, and if the log did not move nothing changes. The
// host calls no AclGateCache.Watch, since the engine's ProjectionChanged and ProjectionsResync bring the host's
// one subscriber here, and only for networks this process serves: an event for any other is dropped, so no
// process loads a network nobody asked it for.
//
// Evaluation (§8.10's sock row). A view reads its snapshot's AclState for the sidecar a request's token names,
// the only subject a sockets caller has outside urnetwork-edge (QD-040): a listener's listen on its token path or
// tls/ and smtp/ name, a dialer's dial by token path, and a listener's publish on its tls/ name's host, each a
// grant whose rule id and expiry the verdict carries. Three checks wait on ACL-M5-01's AclGateView and refuse
// meanwhile, the closed direction: an urnetwork-edge caller's tls/ dial and publish as autogroup:public (so every
// edge Find of tls/ is denied), the system publish tls/443/mta-sts standing on an smtp/25/mx grant, and the hard
// denies only servers know, abuse halts (§21). urnetwork-edge itself holds no log, so its view refuses every
// check until SOCK-M9-01 judges ur/ names by no state.
//
// Safe for concurrent use.

package socketsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var _ SocketGate = (*SocketProjectionGate)(nil)
var _ SocketGateFollower = (*SocketProjectionGate)(nil)
var _ SocketScopeConsent = (*SocketProjectionGate)(nil)

// Where a gate reads a network's Team scopes in its verified state (§7.9, Q-TLS-3; owner decisions 40, 126;
// SOCK-M6-01): the scope a label names in snapshot, false for a label it holds no scope for. ProjectionRows keeps field 6
// for TeamScopeRow, which no state carries yet (protos-bridge-row-fields #3), so a host sets none, and every scope host
// is refused, the closed direction, until the rows carry scopes and a source reads them.
type SocketScopeSource func(snapshot *sidecar.AclGateSnapshot, label string) (sidecar.AclScope, bool)

// A run of evidence that arrived between two loads' starts: the newest evidence in it by count, and when its first
// came.
type socketEvidenceGroup struct {
	lastSeq   uint64
	firstTime time.Time
}

// What one load's Entries noted as it began, which the load's OnLoad consumes.
type socketLoadBegin struct {
	// The evidence counted before the entries were read: a load without error covers up to it.
	seq uint64
	// {acl_<N>}v as read before the entries, nil for absent; versionKnown false when the read failed.
	version      []byte
	versionKnown bool
	// Whether the entries were read at all.
	read bool
	// The run's entries socketEntryMayNarrow flags, by position.
	narrowPositions []uint64
}

// One network as the gate follows it, beside what the cache holds.
type socketGateNetwork struct {
	// Evidence counted so far, the uncovered runs oldest first, and the count the newest load noted, which closes
	// every run up to it.
	evidenceSeq uint64
	groups      []socketEvidenceGroup
	beginSeq    uint64
	// The highest position a store answer named above the state, and when the first such came. Zero for none.
	positionEvidence uint64
	positionTime     time.Time
	// The running load's note.
	begin *socketLoadBegin
	// {acl_<N>}v as the newest load without error read it, which the resubscription check compares.
	version      []byte
	versionKnown bool
	// The highest position a load reported, and whether one has reported a state.
	position uint64
	loaded   bool
	// When the gate last asked for a load because the network was behind, and when a View served it or a load began,
	// which tells a network the cache still holds without asking the cache, whose every State marks a read.
	reloadTime time.Time
	usedTime   time.Time
	// The newest snapshot's view, so a View allocates once a position.
	view *socketProjectionView
}

// Counts one evidence at now: into the run that opened since the newest load began, or a new run.
func (self *socketGateNetwork) addCountEvidenceWithLock(now time.Time) {
	self.evidenceSeq += 1
	if count := len(self.groups); 0 < count && self.beginSeq < self.groups[count-1].lastSeq {
		self.groups[count-1].lastSeq = self.evidenceSeq
		return
	}
	self.groups = append(self.groups, socketEvidenceGroup{lastSeq: self.evidenceSeq, firstTime: now})
}

// Notes a store position above the state at now.
func (self *socketGateNetwork) addPositionEvidenceWithLock(position uint64, now time.Time) {
	if self.positionEvidence == 0 {
		self.positionTime = now
	}
	self.positionEvidence = max(self.positionEvidence, position)
}

// A load begins at now: every run so far closes into one, which a load without error covers. The count it covers.
func (self *socketGateNetwork) beginLoadWithLock(now time.Time) uint64 {
	self.usedTime = now
	self.beginSeq = self.evidenceSeq
	if 1 < len(self.groups) {
		self.groups = []socketEvidenceGroup{{lastSeq: self.groups[len(self.groups)-1].lastSeq, firstTime: self.groups[0].firstTime}}
	}
	return self.beginSeq
}

// When the first uncovered evidence came, zero while none is.
func (self *socketGateNetwork) behindSinceWithLock() time.Time {
	since := time.Time{}
	if 0 < len(self.groups) {
		since = self.groups[0].firstTime
	}
	if self.positionEvidence != 0 && (since.IsZero() || self.positionTime.Before(since)) {
		since = self.positionTime
	}
	return since
}

// What a load reported: the state at position, and whether it read cleanly, consuming the load's note. Whether
// the position rose past an entry that may narrow.
func (self *socketGateNetwork) loadedWithLock(position uint64, clean bool) bool {
	begin := self.begin
	self.begin = nil
	narrowed := false
	if begin != nil && self.loaded && self.position < position {
		for _, narrowPosition := range begin.narrowPositions {
			if self.position < narrowPosition && narrowPosition <= position {
				narrowed = true
				break
			}
		}
	}
	if clean && begin != nil && begin.read {
		kept := self.groups[:0]
		for _, group := range self.groups {
			if begin.seq < group.lastSeq {
				kept = append(kept, group)
			}
		}
		self.groups = kept
		self.version, self.versionKnown = begin.version, begin.versionKnown
	}
	if 0 < position {
		if self.positionEvidence != 0 && self.positionEvidence <= position {
			self.positionEvidence, self.positionTime = 0, time.Time{}
		}
		self.position = max(self.position, position)
		self.loaded = true
	}
	return narrowed
}

// The production gate. NewSocketProjectionGate makes one.
type SocketProjectionGate struct {
	ctx      context.Context
	cancel   context.CancelFunc
	host     *sidecar.ServiceHost
	settings *SocketGateSettings
	clock    sidecar.Clock
	// The wrapped source, nil for none, which loads nothing and leaves the gate never ready.
	source    *socketGateSource
	cache     *sidecar.AclGateCache
	overLimit *socketOverLimit

	onNarrowed atomic.Pointer[func(networkId connect.Id, position uint64)]
	// Where Team scopes are read, nil refusing every scope host (SetScopeSource).
	scopes atomic.Pointer[SocketScopeSource]
	wake   chan struct{}
	// Loads the cache reported, each counted once the gate has taken it in, so a test sees one land.
	loadCount *sidecar.MonitorValue[uint64]
	// Resubscription checks finished, for the same.
	resyncCount *sidecar.MonitorValue[uint64]
	// Worker passes finished, each counted once its asks for loads are made and the wait for the next is armed, so a
	// test knows no ask of a pass is still to come before it counts loads or moves the clock.
	passCount *sidecar.MonitorValue[uint64]
	group     sync.WaitGroup

	stateLock     sync.Mutex
	networks      map[connect.Id]*socketGateNetwork
	resyncPending bool
}

// The gate on host's Clock, Redis (for {acl_<N>}v), Quota (the over-limit list), Metrics and Gates (for
// urnetwork_edge), reading the log through source, with settings, nil being the defaults. A nil source loads
// nothing, so the gate stays not ready and every network unavailable, as a host with no projection source must
// (C-09). Runs until ctx ends or Close.
func NewSocketProjectionGate(ctx context.Context, host *sidecar.ServiceHost, source sidecar.AclGateSource, settings *SocketGateSettings) (*SocketProjectionGate, error) {
	if host == nil || host.Metrics == nil {
		return nil, errors.New("the socket gate needs a host with Metrics")
	}
	if settings == nil {
		settings = DefaultSocketGateSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	clock := host.ClockOrReal()
	self := &SocketProjectionGate{
		ctx:         cancelCtx,
		cancel:      cancel,
		host:        host,
		settings:    settings,
		clock:       clock,
		wake:        make(chan struct{}, 1),
		loadCount:   sidecar.NewMonitorValue[uint64](0),
		resyncCount: sidecar.NewMonitorValue[uint64](0),
		passCount:   sidecar.NewMonitorValue[uint64](0),
		networks:    map[connect.Id]*socketGateNetwork{},
	}
	var cacheSource sidecar.AclGateSource
	if source != nil {
		self.source = &socketGateSource{gate: self, inner: source}
		cacheSource = self.source
	}
	cacheSettings := *settings.Cache
	next := cacheSettings.OnLoad
	cacheSettings.OnLoad = func(networkId sidecar.Id, pin *bridge.AuthPin, err error) {
		self.onLoad(connect.Id(networkId), pin, err)
		if next != nil {
			next(networkId, pin, err)
		}
	}
	self.cache = sidecar.NewAclGateCache(cancelCtx, cacheSource, clock, &cacheSettings)
	self.overLimit = newSocketOverLimit(host.Quota, clock, host.Metrics, settings)
	self.group.Add(2)
	go func() {
		defer self.group.Done()
		self.overLimit.run(cancelCtx)
	}()
	go self.run()
	return self, nil
}

// Stops the poll, the cache and every load at its next step, and waits for the gate's goroutines.
func (self *SocketProjectionGate) Close() {
	self.cancel()
	self.cache.Close()
	self.group.Wait()
}

// The cache's counts, for the host's metrics: loads, failures, alarms and evictions.
func (self *SocketProjectionGate) Stats() sidecar.AclGateStats {
	return self.cache.Stats()
}

// Over-limit reads finished, and a channel that closes at the next: what a host's test waits on before it asks
// Ready.
func (self *SocketProjectionGate) OverLimitReads() (count int, changed chan struct{}) {
	return self.overLimit.readCount.Get()
}

// Loads the gate has taken in, and a channel that closes at the next: what a test of the composition waits on.
func (self *SocketProjectionGate) Loads() (count uint64, changed chan struct{}) {
	return self.loadCount.Get()
}

// Worker passes finished, each with the wait for the next armed, and a channel that closes at the next. A pass asks
// for a load of every network still behind, the gate's first pass included, which runs on its own goroutine once
// the gate is made: a test waits here before it counts loads, so that no ask of a pass lands among the loads it
// triggers itself.
func (self *SocketProjectionGate) Passes() (count uint64, changed chan struct{}) {
	return self.passCount.Get()
}

// The network's state, made on first use.
func (self *SocketProjectionGate) networkWithLock(networkId connect.Id) *socketGateNetwork {
	network := self.networks[networkId]
	if network == nil {
		network = &socketGateNetwork{}
		self.networks[networkId] = network
	}
	return network
}

// Wakes the worker, never blocking.
func (self *SocketProjectionGate) wakeWorker() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// See SocketGate. A source to load from, and one over-limit answer, which is read on api's internal surface as
// the projection is (QD-055), so it stands for the source being reachable: no network is loaded before a request
// asks for it, so readiness cannot wait on one.
func (self *SocketProjectionGate) Ready() bool {
	return self.source != nil && self.overLimit.ready() && self.ctx.Err() == nil
}

// See SocketGate.
func (self *SocketProjectionGate) Spent(networkId connect.Id) bool {
	return self.overLimit.spent(networkId)
}

// See SocketGate. A network the cache holds nothing of is asked for at once and answers unavailable until its
// first load: every caller outside urnetwork-edge is a bound sidecar, so its network has a log.
func (self *SocketProjectionGate) View(networkId connect.Id) (SocketGateView, error) {
	edgeNetworkId, edgeSet := self.host.GatesOrClosed().UrnetworkEdge()
	if edgeSet && edgeNetworkId == networkId {
		return socketPlatformView{}, nil
	}
	snapshot, status := self.cache.State(sidecar.Id(networkId))
	if status != sidecar.AclGateLoaded || snapshot == nil || snapshot.Acl == nil || snapshot.Config == nil {
		self.cache.Changed(sidecar.Id(networkId))
		return nil, ErrSocketGateUnloaded
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network := self.networkWithLock(networkId)
	if since := network.behindSinceWithLock(); !since.IsZero() && self.settings.BehindGrace <= now.Sub(since) {
		return nil, ErrSocketGateBehind
	}
	network.usedTime = now
	if view := network.view; view != nil && view.snapshot == snapshot && view.edgeSet == edgeSet && view.edgeNetworkId == edgeNetworkId {
		return view, nil
	}
	network.view = &socketProjectionView{
		snapshot:      snapshot,
		position:      snapshot.Pin.GetVersion(),
		edgeNetworkId: edgeNetworkId,
		edgeSet:       edgeSet,
		scopes:        &self.scopes,
	}
	return network.view, nil
}

// Sets where the gate reads Team scopes, nil refusing every scope host, which is what a gate does until it is set. The
// host sets it before serving, once §7.9's rows carry scopes (SOCK-M6-01).
func (self *SocketProjectionGate) SetScopeSource(source SocketScopeSource) {
	if source == nil {
		self.scopes.Store(nil)
		return
	}
	self.scopes.Store(&source)
}

// See SocketScopeConsent: the scope stands in the network's verified state and, in a member scope, sidecarId is one of
// its member's consented devices (§8.5, owner decision 126), on the state View serves. smtp/'s namespace asks this for
// mx.<scope> (SOCK-M7-01); the gate's own listen and publish verdicts apply the same rule to every scope host.
func (self *SocketProjectionGate) ConsentListen(networkId connect.Id, scope string, sidecarId *connect.Id) error {
	view, err := self.View(networkId)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSocketListenUnavailable, err)
	}
	projection, ok := view.(*socketProjectionView)
	if !ok {
		return fmt.Errorf("%w: no state there holds a scope", ErrSocketListenRefused)
	}
	resolved, found := projection.scopeOf(scope)
	if !found {
		return fmt.Errorf("%w: a scope the state does not hold", ErrSocketListenRefused)
	}
	if resolved.MemberId != (sidecar.Id{}) && (sidecarId == nil || !projection.snapshot.Acl.ConsentedFor(sidecar.Id(*sidecarId), resolved.MemberId)) {
		return fmt.Errorf("%w: not a consented device of the scope's member", ErrSocketListenRefused)
	}
	return nil
}

// See SocketGate. A position at or below the state's is no evidence, and neither is
// SocketRemovedClientPosition, which no log reaches; nor is anything said of a network the cache does not hold.
func (self *SocketProjectionGate) Observe(networkId connect.Id, position uint64) {
	if position == 0 || position == SocketRemovedClientPosition {
		return
	}
	snapshot, status := self.cache.State(sidecar.Id(networkId))
	if status == sidecar.AclGateUnknown || (snapshot != nil && position <= snapshot.Pin.GetVersion()) {
		return
	}
	now := self.clock.Now()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.networkWithLock(networkId).addPositionEvidenceWithLock(position, now)
	}()
	self.cache.Changed(sidecar.Id(networkId))
}

// See SocketGateFollower. Dropped for a network the cache holds nothing of: one this process was never asked for. A
// network the gate let go of past MaxNetworkCount while the cache still holds it is taken up again.
func (self *SocketProjectionGate) Changed(networkId connect.Id) {
	now := self.clock.Now()
	add := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		network := self.networks[networkId]
		if network == nil {
			return false
		}
		network.addCountEvidenceWithLock(now)
		return true
	}
	if !add() {
		if _, status := self.cache.State(sidecar.Id(networkId)); status == sidecar.AclGateUnknown {
			return
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.networkWithLock(networkId).addCountEvidenceWithLock(now)
		}()
	}
	self.cache.Changed(sidecar.Id(networkId))
}

// See SocketGateFollower.
func (self *SocketProjectionGate) Resync() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.resyncPending = true
	}()
	self.wakeWorker()
}

// See SocketGateFollower.
func (self *SocketProjectionGate) OnNarrowed(callback func(networkId connect.Id, position uint64)) {
	self.onNarrowed.Store(&callback)
}

// See SocketGate: a View and one call on it.
func (self *SocketProjectionGate) MayListen(ctx context.Context, request *SocketGateRequest) (*SocketGateVerdict, error) {
	view, err := self.View(request.NetworkId)
	if err != nil {
		return nil, err
	}
	return view.MayListen(request, self.clock.Now()), nil
}

// See SocketGate: a View and one call on it.
func (self *SocketProjectionGate) MayDial(ctx context.Context, request *SocketGateRequest) (*SocketGateVerdict, error) {
	view, err := self.View(request.NetworkId)
	if err != nil {
		return nil, err
	}
	return view.MayDial(request, self.clock.Now()), nil
}

// See SocketGate: a View and one call on it.
func (self *SocketProjectionGate) MayPublish(ctx context.Context, request *SocketGateRequest) (*SocketGateVerdict, error) {
	view, err := self.View(request.NetworkId)
	if err != nil {
		return nil, err
	}
	return view.MayPublish(request, self.clock.Now()), nil
}

// See SocketGate: a View and one call on it.
func (self *SocketProjectionGate) IdentityKey(ctx context.Context, networkId connect.Id, sidecarId connect.Id) ([]byte, bool, error) {
	view, err := self.View(networkId)
	if err != nil {
		return nil, false, err
	}
	publicKey, found := view.IdentityKey(sidecarId)
	return publicKey, found, nil
}

// A load begins for networkId: the evidence count it covers if it reads cleanly.
func (self *SocketProjectionGate) beginLoad(networkId connect.Id) uint64 {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkWithLock(networkId).beginLoadWithLock(now)
}

// Records what the running load's Entries read.
func (self *SocketProjectionGate) noteBegin(networkId connect.Id, begin *socketLoadBegin) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).begin = begin
}

// The cache's OnLoad, on the network's loading goroutine: what the load covered, and the sweep queue when the
// position rose past an entry that may narrow. A load with an error covers no counted evidence, but a state it
// installed still covers every store position at or below its own.
func (self *SocketProjectionGate) onLoad(networkId connect.Id, pin *bridge.AuthPin, err error) {
	narrowed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.networkWithLock(networkId).loadedWithLock(pin.GetVersion(), err == nil)
	}()
	if narrowed {
		if callback := self.onNarrowed.Load(); callback != nil && *callback != nil {
			(*callback)(networkId, pin.GetVersion())
		}
	}
	self.loadCount.Update(func(count uint64) uint64 { return count + 1 })
}

// {acl_<networkId>}v now, nil for absent, and false when it cannot be read or the host has no Redis.
func (self *SocketProjectionGate) readVersion(ctx context.Context, networkId connect.Id) ([]byte, bool) {
	if self.host.Redis == nil {
		return nil, false
	}
	readCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(self.settings.VersionReadTimeout, cancel)
	defer func() {
		stop()
		cancel()
	}()
	value, found, err := self.host.Redis.Get(readCtx, sidecar.AclVersionKey(sidecar.Id(networkId)))
	if err != nil {
		return nil, false
	}
	if !found {
		return nil, true
	}
	return value, true
}

// The worker: the resubscription check when one is asked for, and every BehindReloadInterval another load for
// each network still behind, and the networks the cache has forgotten dropped.
func (self *SocketProjectionGate) run() {
	defer self.group.Done()
	for {
		resync := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			resync := self.resyncPending
			self.resyncPending = false
			return resync
		}()
		if resync {
			self.resyncCheck()
			self.resyncCount.Update(func(count uint64) uint64 { return count + 1 })
		}
		self.reloadBehind()
		wait := self.clock.After(self.settings.BehindReloadInterval)
		self.passCount.Update(func(count uint64) uint64 { return count + 1 })
		select {
		case <-self.ctx.Done():
			return
		case <-self.wake:
		case <-wait:
		}
	}
}

// Asks for another load of each network still behind whose last such ask is an interval old; and past
// MaxNetworkCount lets go of the quiet networks served or loaded longest ago, which a later ask, load or event
// takes up again. It asks the cache nothing but loads: a State would mark each network read and undo the cache's
// eviction order.
func (self *SocketProjectionGate) reloadBehind() {
	now := self.clock.Now()
	behindNetworkIds := []connect.Id{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		quietNetworkIds := []connect.Id{}
		for networkId, network := range self.networks {
			if network.behindSinceWithLock().IsZero() {
				if network.begin == nil {
					quietNetworkIds = append(quietNetworkIds, networkId)
				}
				continue
			}
			if !network.reloadTime.IsZero() && now.Sub(network.reloadTime) < self.settings.BehindReloadInterval {
				continue
			}
			network.reloadTime = now
			behindNetworkIds = append(behindNetworkIds, networkId)
		}
		if excess := len(self.networks) - self.settings.MaxNetworkCount; 0 < excess {
			slices.SortFunc(quietNetworkIds, func(a connect.Id, b connect.Id) int {
				return self.networks[a].usedTime.Compare(self.networks[b].usedTime)
			})
			for _, networkId := range quietNetworkIds[:min(excess, len(quietNetworkIds))] {
				delete(self.networks, networkId)
			}
		}
	}()
	for _, networkId := range behindNetworkIds {
		self.cache.Changed(sidecar.Id(networkId))
	}
}

// 13.2.3's resubscription check: {acl_<N>}v for every loaded network the cache still holds, one served or loaded
// within ResyncUsedWithin, ResyncBatchCount at a time with at most ResyncConcurrency reads at once, and only a
// value that differs from the one recorded with the state is evidence. A read that fails is evidence too, since
// nothing can say the log stood still in the gap. A network the cache has evicted is left to its next ask, which
// loads it from the tip, rather than reloaded by every resubscription.
func (self *SocketProjectionGate) resyncCheck() {
	now := self.clock.Now()
	networkIds := func() []connect.Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		networkIds := make([]connect.Id, 0, len(self.networks))
		for networkId, network := range self.networks {
			if network.loaded && now.Sub(network.usedTime) < self.settings.ResyncUsedWithin {
				networkIds = append(networkIds, networkId)
			}
		}
		return networkIds
	}()
	for start := 0; start < len(networkIds); start += self.settings.ResyncBatchCount {
		if self.ctx.Err() != nil {
			return
		}
		batch := networkIds[start:min(start+self.settings.ResyncBatchCount, len(networkIds))]
		versions := make([][]byte, len(batch))
		knowns := make([]bool, len(batch))
		slots := make(chan struct{}, self.settings.ResyncConcurrency)
		var reads sync.WaitGroup
		for index, networkId := range batch {
			slots <- struct{}{}
			reads.Add(1)
			go func() {
				defer reads.Done()
				defer func() { <-slots }()
				versions[index], knowns[index] = self.readVersion(self.ctx, networkId)
			}()
		}
		reads.Wait()
		now := self.clock.Now()
		changedNetworkIds := []connect.Id{}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			for index, networkId := range batch {
				network := self.networks[networkId]
				if network == nil {
					continue
				}
				if knowns[index] && network.versionKnown && bytes.Equal(versions[index], network.version) {
					continue
				}
				network.addCountEvidenceWithLock(now)
				changedNetworkIds = append(changedNetworkIds, networkId)
			}
		}()
		for _, networkId := range changedNetworkIds {
			self.cache.Changed(sidecar.Id(networkId))
		}
	}
}

// The cache's source, wrapped: Entries notes the load it begins (the evidence count, then {acl_<N>}v, each before
// the entries are read) and which of the run's entries may narrow a socket verdict, reading only each entry's kind
// and its statement's type. Everything else passes through.
type socketGateSource struct {
	gate  *SocketProjectionGate
	inner sidecar.AclGateSource
}

// See sidecar.AclGateSource.
func (self *socketGateSource) Genesis(ctx context.Context, networkId sidecar.Id) ([]byte, error) {
	return self.inner.Genesis(ctx, networkId)
}

// See sidecar.AclGateSource.
func (self *socketGateSource) Rows(ctx context.Context, networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
	return self.inner.Rows(ctx, networkId, rowsSha256)
}

// See sidecar.AclGateSource.
func (self *socketGateSource) Entries(ctx context.Context, networkId sidecar.Id, after *bridge.AuthPin) ([][]byte, error) {
	socketNetworkId := connect.Id(networkId)
	seq := self.gate.beginLoad(socketNetworkId)
	version, versionKnown := self.gate.readVersion(ctx, socketNetworkId)
	testHookBarrier("sockets.gate.entries.before", socketNetworkId.String())
	entries, err := self.inner.Entries(ctx, networkId, after)
	testHookBarrier("sockets.gate.entries.after", socketNetworkId.String())
	begin := &socketLoadBegin{seq: seq, version: version, versionKnown: versionKnown, read: err == nil}
	if err == nil {
		begin.narrowPositions = socketNarrowingPositions(entries)
	}
	self.gate.noteBegin(socketNetworkId, begin)
	return entries, err
}

// One network's state at one position, never changed: what a route judges on.
type socketProjectionView struct {
	snapshot      *sidecar.AclGateSnapshot
	position      uint64
	edgeNetworkId connect.Id
	edgeSet       bool
	// The gate's scope source as it stands when a check asks.
	scopes *atomic.Pointer[SocketScopeSource]
}

// The Team scope label names in the snapshot, false for none or with no source.
func (self *socketProjectionView) scopeOf(label string) (sidecar.AclScope, bool) {
	if self.scopes == nil {
		return sidecar.AclScope{}, false
	}
	source := self.scopes.Load()
	if source == nil {
		return sidecar.AclScope{}, false
	}
	return (*source)(self.snapshot, label)
}

// The scope label a tls/ or smtp/ name's host names, <label>.<scope> (§9.4), false for a host of no scope.
func socketNameScope(name string) (string, bool) {
	if !socketGatePublicName(name) {
		return "", false
	}
	return socketHostScope(name[strings.LastIndexByte(name, '/')+1:])
}

// The scope label of host <label>.<scope>, false for a host of no scope.
func socketHostScope(host string) (string, bool) {
	label, scope, found := strings.Cut(host, ".")
	if !found || label == "" || scope == "" || strings.Contains(scope, ".") {
		return "", false
	}
	return scope, true
}

var _ SocketGateView = (*socketProjectionView)(nil)

// See SocketGateView.
func (self *socketProjectionView) Position() uint64 {
	return self.position
}

// A decision as a verdict at the view's position, carrying the grant that allowed it.
func (self *socketProjectionView) verdict(decision sidecar.AclDecision) *SocketGateVerdict {
	if !decision.Allowed {
		return &SocketGateVerdict{}
	}
	verdict := &SocketGateVerdict{Allowed: true, PolicyVersion: self.position}
	if rule := decision.Rule; rule != nil {
		verdict.GrantId = bytes.Clone(rule.GetRuleId())
		if 0 < rule.GetExpires() {
			verdict.GrantExpireMillis = uint64(rule.GetExpires())
		}
	}
	return verdict
}

// Whether the request is an urnetwork-edge platform client's.
func (self *socketProjectionView) edgeCaller(request *SocketGateRequest) bool {
	return self.edgeSet && request.CallerNetworkId == self.edgeNetworkId
}

// See SocketGateView: listen for the request's sidecar on its token path, or on its tls/ or smtp/ name.
func (self *socketProjectionView) MayListen(request *SocketGateRequest, now time.Time) *SocketGateVerdict {
	subject, ok := socketGateSubject(request)
	if !ok {
		return &SocketGateVerdict{}
	}
	socket := sidecar.AclSocketName{NameToken: request.NameToken}
	if len(request.NameToken) == 0 {
		if !socketGatePublicName(request.Name) {
			// ur/ is its service's to authorize (§9.4), and nothing else reaches the service in the clear
			return &SocketGateVerdict{}
		}
		socket = sidecar.AclSocketName{PublicName: request.Name}
		// a scope host stands only for a scope the state holds, a member scope's only on its member's consented devices
		if label, scoped := socketNameScope(request.Name); scoped {
			scope, found := self.scopeOf(label)
			if !found {
				return &SocketGateVerdict{}
			}
			return self.verdict(self.snapshot.Acl.MayListenInScope(subject, socket, scope, now))
		}
	}
	return self.verdict(self.snapshot.Acl.MayListen(subject, socket, now))
}

// See SocketGateView: dial for the request's sidecar on a token path. An edge's tls/ dial as autogroup:public is
// ACL-M5-01's to judge and is refused until it lands; no other name is a sidecar's to dial (§9.4).
func (self *socketProjectionView) MayDial(request *SocketGateRequest, now time.Time) *SocketGateVerdict {
	if self.edgeCaller(request) || len(request.NameToken) == 0 {
		return &SocketGateVerdict{}
	}
	subject, ok := socketGateSubject(request)
	if !ok {
		return &SocketGateVerdict{}
	}
	return self.verdict(self.snapshot.Acl.MayDialSocket(subject, request.NameToken, now))
}

// See SocketGateView: publish for the request's sidecar on its tls/ name's host. A request with no sidecar, an
// edge's before it has a listener, is ACL-M5-01's to judge as autogroup:public and is refused until it lands.
func (self *socketProjectionView) MayPublish(request *SocketGateRequest, now time.Time) *SocketGateVerdict {
	host, found := strings.CutPrefix(request.Name, "tls/")
	if !found {
		return &SocketGateVerdict{}
	}
	host = host[strings.IndexByte(host, '/')+1:]
	subject, ok := socketGateSubject(request)
	if !ok || host == "" {
		return &SocketGateVerdict{}
	}
	if label, scoped := socketHostScope(host); scoped {
		scope, found := self.scopeOf(label)
		if !found {
			return &SocketGateVerdict{}
		}
		return self.verdict(self.snapshot.Acl.MayPublishInScope(subject, host, scope, now))
	}
	return self.verdict(self.snapshot.Acl.MayPublish(subject, host, now))
}

// See SocketGateView: the identity key the log admits for the sidecar, while its admission stands.
func (self *socketProjectionView) IdentityKey(sidecarId connect.Id) ([]byte, bool) {
	publicKey := self.snapshot.Config.IdentityKey(sidecar.Id(sidecarId))
	if len(publicKey) == 0 || !self.snapshot.Acl.Admitted(sidecar.Id(sidecarId)) {
		return nil, false
	}
	return bytes.Clone(publicKey), true
}

// The sidecar a request's token names as a §8 subject, false for none: the only subject a sockets caller has
// outside urnetwork-edge (QD-040), and the one a lease stores for Find's listener check.
func socketGateSubject(request *SocketGateRequest) (sidecar.AclSubject, bool) {
	if request == nil || request.SidecarId == nil || *request.SidecarId == (connect.Id{}) {
		return sidecar.AclSubject{}, false
	}
	return sidecar.AclSidecarSubject(sidecar.Id(*request.SidecarId)), true
}

// Whether name is a tls/ or smtp/ name, which §8 matches in the clear against a grant's public_name.
func socketGatePublicName(name string) bool {
	return strings.HasPrefix(name, "tls/") || strings.HasPrefix(name, "smtp/")
}

// urnetwork-edge's view: it holds no authorization log, so nothing in it is §8's to allow (§9.4) and every check
// refuses until SOCK-M9-01 judges ur/ names by no state.
type socketPlatformView struct{}

var _ SocketGateView = socketPlatformView{}

// See SocketGateView.
func (self socketPlatformView) Position() uint64 {
	return 0
}

// See SocketGateView: refused.
func (self socketPlatformView) MayListen(request *SocketGateRequest, now time.Time) *SocketGateVerdict {
	return &SocketGateVerdict{}
}

// See SocketGateView: refused.
func (self socketPlatformView) MayDial(request *SocketGateRequest, now time.Time) *SocketGateVerdict {
	return &SocketGateVerdict{}
}

// See SocketGateView: refused.
func (self socketPlatformView) MayPublish(request *SocketGateRequest, now time.Time) *SocketGateVerdict {
	return &SocketGateVerdict{}
}

// See SocketGateView: none.
func (self socketPlatformView) IdentityKey(sidecarId connect.Id) ([]byte, bool) {
	return nil, false
}
