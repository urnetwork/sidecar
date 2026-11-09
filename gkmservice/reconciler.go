// §10.6's reconciler (R-KEYS-14; D-KEYS-5, D-KEYS-19, D-KEYS-20, D-KEYS-21; FI-6), which taskworker runs (§19.4;
// KEYS-M2-17 wires it into taskworker): gkm's server-side duties that no request drives.
//
//   - pending hints: when a network's verified state shrinks or grows a repo's key holders, pending goes on the
//     per-client gkm topic to the repo's writers, the entry's signer first, as the revoking device commits the Remove
//     first (§10.6's pending changes, KF4); in the directory group only to that signer and the config writers (§10.9).
//     While a repo's write gate is closed the hint repeats every PendingHintInterval (60 s). An expiry closes a gate
//     with no log entry, so the reconciler keeps each network's next holder expiry and wakes for it. Work is driven by
//     the state's changes ({acl_<networkId>}v, through GkmReconcilerState.Watch) and those expiry times, never by a
//     scan of every repo each minute; what a change costs is its own network's repos, and a gate's check reads its
//     repo's newest form and generation.
//   - sweeps (retention.go): epoch retention by acks, staged-wrap GC and §2.8's TTLs, a page of groups, sidecars and
//     members a run, from a cursor the task framework keeps between runs. A preservation hold pauses them.
//   - ShredGroup (shred.go): §11.12's shred of a repo's gkm objects, which no hold pauses.
//
// The hint loop runs on the reconciler's own goroutine, started by its constructor; hints go out through
// ServiceHost.Push.HintSidecars, lossy, a lost one covered by the next interval or the clients' hourly resync (§6.8).
//
// Safe for concurrent use. No lock is held across I/O.

package gkmservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One network's newest verified state as the reconciler reads it.
type GkmNetworkState struct {
	View sidecar.GkmAuthView
	// Every repo the state holds, sorted.
	RepoIds []sidecar.Id
}

// One move of a network's state, as {acl_<networkId>}v announces it.
type GkmStateChange struct {
	NetworkId sidecar.Id
	// The newest entry's signer, a revocation's revoking device, whose pending hint goes first; nil when not known.
	SignerId *sidecar.Id
}

// What the reconciler reads of the authorization log and of sidecars' standing: §8.9's gate cache over
// {acl_<networkId>}e and proj/, which taskworker supplies (KEYS-M2-17), and a fake in T2. Safe for concurrent use.
type GkmReconcilerState interface {
	// Calls changed for each move of a network's state, and with nil after a lost subscription, so every network is
	// read again. changed never blocks. Returns the call that stops it.
	Watch(changed func(change *GkmStateChange)) (stop func(), err error)
	// The networks whose state the host holds: what a resync reads.
	Networks() []sidecar.Id
	// A network's newest verified state. An error skips the network until its next change or wake.
	State(ctx context.Context, networkId sidecar.Id) (*GkmNetworkState, error)
	// The network that admits a sidecar and whether its newest state revoked it; known false for a sidecar no loaded
	// state admits, whose objects the sweeps then keep.
	SidecarStanding(ctx context.Context, sidecarId sidecar.Id) (networkId sidecar.Id, revoked bool, known bool, err error)
}

// What tunes the reconciler (connect/CODESTYLE.md's settings rule).
type GkmReconcilerSettings struct {
	// The engine's bounds the reconciler reads objects under: list pages, object sizes, the forms' bound and place/'s
	// resolution.
	Service *GkmServiceSettings

	// §10.6's retention (Q-KEYS-11): an epoch goes once it is this old and every ack written within this has passed
	// it, never the newest, and only while the ack family has existed this long, so a lost family delays deletions
	// and never causes one: 30 days.
	EpochRetention time.Duration
	// Staged objects whose c8 is not gen/<g>'s, recovery wraps included, go once this old: 24 h.
	StagedGcAge time.Duration
	// A recipient's delivery of g to an older key goes this long after one to a newer key exists: 30 days.
	OlderKeyDeliveryAge time.Duration
	// gkm-4: KeyPackages until claimed or this old, claims this long: 90 days.
	KeyPackageLifetime time.Duration
	// gkm-5: a Welcome and its pointers at most this long, a pointer earlier once its recipient acked past its
	// epoch: 90 days.
	WelcomeLifetime time.Duration
	// pending repeats this often while a gate is closed (§10.6's pending changes: 60 s).
	PendingHintInterval time.Duration
	// How far ahead a network's next holder expiry is looked for; one past it is found at the wake that horizon
	// sets.
	ExpiryHorizon time.Duration
	// Units, each a group, a sidecar's family or a member's recovery wraps, one sweep run takes.
	SweepUnitCount int
	// How long a finished sweep pass waits before the next one starts.
	SweepInterval time.Duration
	// How long one sweep run may take.
	SweepRunTime time.Duration
	// The most networks whose last state the reconciler keeps; past it one is forgotten, and its next change is
	// judged as a first sight.
	NetworkCount int
	// The most closed gates the reconciler re-hints; past it a new one waits for its network's next change.
	ClosedGateCount int
	// How long one hint send may take.
	HintTimeout time.Duration
	// The most keys one group's, sidecar's or member's family may hold before a sweep of it alarms.
	UnitKeyMaxCount int
}

// The production defaults.
func DefaultGkmReconcilerSettings() *GkmReconcilerSettings {
	return &GkmReconcilerSettings{
		Service:             DefaultGkmServiceSettings(),
		EpochRetention:      30 * 24 * time.Hour,
		StagedGcAge:         24 * time.Hour,
		OlderKeyDeliveryAge: 30 * 24 * time.Hour,
		KeyPackageLifetime:  90 * 24 * time.Hour,
		WelcomeLifetime:     90 * 24 * time.Hour,
		PendingHintInterval: 60 * time.Second,
		ExpiryHorizon:       24 * time.Hour,
		SweepUnitCount:      256,
		SweepInterval:       1 * time.Hour,
		SweepRunTime:        10 * time.Minute,
		NetworkCount:        100 * 1000,
		ClosedGateCount:     100 * 1000,
		HintTimeout:         5 * time.Second,
		UnitKeyMaxCount:     256 * 1024,
	}
}

// Refuses a value the design's argument cannot take.
func (self *GkmReconcilerSettings) Validate() error {
	if self.Service == nil {
		return fmt.Errorf("%w: no service settings", ErrGkmSettings)
	}
	if err := self.Service.Validate(); err != nil {
		return err
	}
	for _, value := range []struct {
		name  string
		value int64
	}{
		{name: "EpochRetention", value: int64(self.EpochRetention)},
		{name: "StagedGcAge", value: int64(self.StagedGcAge)},
		{name: "OlderKeyDeliveryAge", value: int64(self.OlderKeyDeliveryAge)},
		{name: "KeyPackageLifetime", value: int64(self.KeyPackageLifetime)},
		{name: "WelcomeLifetime", value: int64(self.WelcomeLifetime)},
		{name: "PendingHintInterval", value: int64(self.PendingHintInterval)},
		{name: "ExpiryHorizon", value: int64(self.ExpiryHorizon)},
		{name: "SweepUnitCount", value: int64(self.SweepUnitCount)},
		{name: "SweepInterval", value: int64(self.SweepInterval)},
		{name: "HintTimeout", value: int64(self.HintTimeout)},
		{name: "UnitKeyMaxCount", value: int64(self.UnitKeyMaxCount)},
	} {
		if value.value <= 0 {
			return fmt.Errorf("%w: %s must be positive", ErrGkmSettings, value.name)
		}
	}
	return nil
}

// What the reconciler takes beyond its host and settings.
type GkmReconcilerDeps struct {
	// The authorization state. Required: without it no hint goes and no sidecar's objects are swept.
	State GkmReconcilerState
	// The holds every sweep reads. nil reads hold/ through a HoldSet of the reconciler's own.
	Holds *sidecar.HoldSet
	// Alarms and lifecycle. nil discards.
	Log sidecar.Logger
}

// One network as the reconciler last read it.
type gkmReconcilerNetwork struct {
	state *GkmNetworkState
	// When to read it again for an expiry, zero for none within the horizon.
	nextWake time.Time
}

// A repo whose gate was closed at its last check, re-hinted each interval.
type gkmClosedGate struct {
	networkId sidecar.Id
	// when its last pending hint went
	hintedAt time.Time
}

// The reconciler. See the file header.
type GkmReconciler struct {
	ctx      context.Context
	cancel   context.CancelFunc
	host     *sidecar.ServiceHost
	settings *GkmReconcilerSettings
	state    GkmReconcilerState
	clock    sidecar.Clock
	log      sidecar.Logger
	blobs    sidecar.BlobStore
	places   *sidecar.EvsRepoPlaceResolver
	holds    *sidecar.HoldSet

	stateLock      sync.Mutex
	networkEntries map[sidecar.Id]*gkmReconcilerNetwork
	pendingChanges map[sidecar.Id]*GkmStateChange
	resyncPending  bool
	closedGates    map[sidecar.Id]*gkmClosedGate

	wake      chan struct{}
	passCount *sidecar.MonitorValue[int]
	// whether the loop waits, its timer set: a test moves a fake clock only then, so the move reaches the timer
	idle      *sidecar.MonitorValue[bool]
	stopWatch func()
}

// Starts the reconciler's hint loop on host, which needs Blobs; its sweeps run once RegisterSweep has registered
// them. It runs until ctx ends or Close.
func NewGkmReconciler(ctx context.Context, host *sidecar.ServiceHost, settings *GkmReconcilerSettings, deps *GkmReconcilerDeps) (*GkmReconciler, error) {
	if host == nil || host.Blobs == nil {
		return nil, errors.New("gkm's reconciler needs a host with Blobs")
	}
	if settings == nil {
		settings = DefaultGkmReconcilerSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if deps == nil || deps.State == nil {
		return nil, errors.New("gkm's reconciler needs the authorization state")
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	clock := host.ClockOrReal()
	holds := deps.Holds
	if holds == nil {
		holds = sidecar.NewHoldSet(host.Blobs, clock, nil)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &GkmReconciler{
		ctx:            cancelCtx,
		cancel:         cancel,
		host:           host,
		settings:       settings,
		state:          deps.State,
		clock:          clock,
		log:            log,
		blobs:          host.Blobs,
		places:         sidecar.NewEvsRepoPlaceResolver(host.Blobs, clock, settings.Service.Place),
		holds:          holds,
		networkEntries: map[sidecar.Id]*gkmReconcilerNetwork{},
		pendingChanges: map[sidecar.Id]*GkmStateChange{},
		closedGates:    map[sidecar.Id]*gkmClosedGate{},
		wake:           make(chan struct{}, 1),
		passCount:      sidecar.NewMonitorValue(0),
		idle:           sidecar.NewMonitorValue(false),
	}
	stopWatch, err := deps.State.Watch(self.noteChange)
	if err != nil {
		cancel()
		return nil, err
	}
	self.stopWatch = stopWatch
	go self.run()
	return self, nil
}

// Ends the hint loop and the watch. Safe more than once.
func (self *GkmReconciler) Close() {
	self.cancel()
}

// Passes of the hint loop finished, and a channel that closes at the next: what a test waits on.
func (self *GkmReconciler) Passes() (count int, changed chan struct{}) {
	return self.passCount.Get()
}

// Notes a change and wakes the loop, never blocking: the state's watch calls it.
func (self *GkmReconciler) noteChange(change *GkmStateChange) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if change == nil {
			self.resyncPending = true
			return
		}
		if held, ok := self.pendingChanges[change.NetworkId]; ok && change.SignerId == nil {
			// keep the signer an earlier change named
			change = &GkmStateChange{NetworkId: change.NetworkId, SignerId: held.SignerId}
		}
		self.pendingChanges[change.NetworkId] = change
	}()
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// The hint loop: noted changes, due expiry wakes and the closed gates' interval, then a wait for the next of them.
func (self *GkmReconciler) run() {
	defer func() {
		if self.stopWatch != nil {
			self.stopWatch()
		}
	}()
	nextGateHint := self.clock.Now().Add(self.settings.PendingHintInterval)
	for {
		changes := map[sidecar.Id]*GkmStateChange{}
		resync := false
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			changes, self.pendingChanges = self.pendingChanges, changes
			resync, self.resyncPending = self.resyncPending, false
		}()
		if resync {
			for _, networkId := range self.state.Networks() {
				if _, ok := changes[networkId]; !ok {
					changes[networkId] = &GkmStateChange{NetworkId: networkId}
				}
			}
		}
		networkIds := []sidecar.Id{}
		for networkId := range changes {
			networkIds = append(networkIds, networkId)
		}
		slices.SortFunc(networkIds, func(a sidecar.Id, b sidecar.Id) int { return a.Cmp(b) })
		for _, networkId := range networkIds {
			self.reconcileNetwork(changes[networkId], false)
		}
		now := self.clock.Now()
		for _, networkId := range self.dueWakes(now) {
			self.reconcileNetwork(&GkmStateChange{NetworkId: networkId}, true)
		}
		if !now.Before(nextGateHint) {
			self.rehintClosedGates()
			nextGateHint = now.Add(self.settings.PendingHintInterval)
		}
		self.passCount.Update(func(count int) int { return count + 1 })
		wakeAt := nextGateHint
		if earliest, ok := self.earliestWake(); ok && earliest.Before(wakeAt) {
			wakeAt = earliest
		}
		timeout := self.clock.After(max(0, wakeAt.Sub(self.clock.Now())))
		self.idle.Set(true)
		select {
		case <-self.ctx.Done():
			return
		case <-self.wake:
		case <-timeout:
		}
		self.idle.Set(false)
	}
}

// The networks whose expiry wake is due at now.
func (self *GkmReconciler) dueWakes(now time.Time) []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkIds := []sidecar.Id{}
	for networkId, entry := range self.networkEntries {
		if !entry.nextWake.IsZero() && !now.Before(entry.nextWake) {
			networkIds = append(networkIds, networkId)
		}
	}
	slices.SortFunc(networkIds, func(a sidecar.Id, b sidecar.Id) int { return a.Cmp(b) })
	return networkIds
}

// The earliest expiry wake of any network.
func (self *GkmReconciler) earliestWake() (time.Time, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	earliest, found := time.Time{}, false
	for _, entry := range self.networkEntries {
		if !entry.nextWake.IsZero() && (!found || entry.nextWake.Before(earliest)) {
			earliest, found = entry.nextWake, true
		}
	}
	return earliest, found
}

// Reads a network's state and judges each repo against the state last read: holders changed, or a gate closed,
// hints pending; a closed gate is kept for its interval; the next holder expiry sets the network's wake. wake is an
// expiry's wake, which checks every repo's gate though nothing in the log moved.
func (self *GkmReconciler) reconcileNetwork(change *GkmStateChange, wake bool) {
	networkId := change.NetworkId
	state, err := self.state.State(self.ctx, networkId)
	now := self.clock.Now()
	if err != nil || state == nil || state.View == nil {
		if self.log.V(1).Enabled() {
			self.log.Infof("[gkm reconciler] a network's state did not load: %v", err)
		}
		// read it again at the next interval
		self.setNetwork(networkId, nil, now.Add(self.settings.PendingHintInterval))
		return
	}
	var previous *GkmNetworkState
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if entry, ok := self.networkEntries[networkId]; ok {
			previous = entry.state
		}
	}()
	configWriterIds := gkmConfigWriters(state)
	nextWake := time.Time{}
	for _, repoId := range state.RepoIds {
		repo := state.View.Repo(repoId)
		if repo == nil {
			continue
		}
		after, err := sidecar.KeyHolders(state.View, repoId, now)
		if err != nil {
			continue
		}
		holdersChanged := false
		shrinkMoved := false
		if previous != nil && previous.View.Repo(repoId) != nil {
			before, err := sidecar.KeyHolders(previous.View, repoId, now)
			holdersChanged = err != nil || !bytes.Equal(before.Sha256(), after.Sha256())
			shrinkMoved = previous.View.Repo(repoId).GetHoldersShrunkAt() != repo.GetHoldersShrunkAt()
		}
		if previous == nil || holdersChanged || shrinkMoved || wake || self.gateTracked(repoId) {
			closed, groupId, known := self.gateClosed(state.View, repoId, now)
			if known {
				if holdersChanged || closed {
					self.hintPending(state, repoId, groupId, change.SignerId, configWriterIds)
				}
				self.trackGate(networkId, repoId, closed, now)
			}
		}
		expiry, found, err := sidecar.GkmHolderExpiry(state.View, repoId, now, now.Add(self.settings.ExpiryHorizon))
		if err == nil && found && (nextWake.IsZero() || expiry.Before(nextWake)) {
			nextWake = expiry
		}
	}
	if nextWake.IsZero() {
		// no expiry within the horizon: look again at its end
		nextWake = now.Add(self.settings.ExpiryHorizon)
	}
	self.setNetwork(networkId, state, nextWake)
}

// Keeps a network's state and wake, a nil state keeping the one held, forgetting another network first when full.
func (self *GkmReconciler) setNetwork(networkId sidecar.Id, state *GkmNetworkState, nextWake time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry, ok := self.networkEntries[networkId]
	if !ok {
		if self.settings.NetworkCount <= len(self.networkEntries) {
			for evictedNetworkId := range self.networkEntries {
				delete(self.networkEntries, evictedNetworkId)
				break
			}
		}
		entry = &gkmReconcilerNetwork{}
		self.networkEntries[networkId] = entry
	}
	if state != nil {
		entry.state = state
	}
	entry.nextWake = nextWake
}

// Whether a repo's gate is tracked as closed.
func (self *GkmReconciler) gateTracked(repoId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	_, ok := self.closedGates[repoId]
	return ok
}

// Tracks a repo's gate as closed, its hint sent at hintedAt, or forgets it.
func (self *GkmReconciler) trackGate(networkId sidecar.Id, repoId sidecar.Id, closed bool, hintedAt time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !closed {
		delete(self.closedGates, repoId)
		return
	}
	if _, ok := self.closedGates[repoId]; !ok && self.settings.ClosedGateCount <= len(self.closedGates) {
		return
	}
	self.closedGates[repoId] = &gkmClosedGate{networkId: networkId, hintedAt: hintedAt}
}

// Re-checks each tracked gate at its network's last state, hinting pending again while it stays closed.
func (self *GkmReconciler) rehintClosedGates() {
	type trackedGate struct {
		repoId    sidecar.Id
		networkId sidecar.Id
		state     *GkmNetworkState
	}
	gates := []*trackedGate{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		now := self.clock.Now()
		for repoId, gate := range self.closedGates {
			entry, ok := self.networkEntries[gate.networkId]
			if !ok || entry.state == nil {
				delete(self.closedGates, repoId)
				continue
			}
			if now.Sub(gate.hintedAt) < self.settings.PendingHintInterval {
				// hinted within the interval, as a change's pass just did
				continue
			}
			gates = append(gates, &trackedGate{repoId: repoId, networkId: gate.networkId, state: entry.state})
		}
	}()
	now := self.clock.Now()
	for _, gate := range gates {
		closed, groupId, known := self.gateClosed(gate.state.View, gate.repoId, now)
		if !known {
			continue
		}
		if closed {
			self.hintPending(gate.state, gate.repoId, groupId, nil, gkmConfigWriters(gate.state))
		}
		self.trackGate(gate.networkId, gate.repoId, closed, now)
	}
}

// Whether a repo's write gate is closed at now in view: its newest group's newest generation does not cover a shrink
// or an expiry the state shows, or its pin is a fork's (§10.6's gate; sidecar.GkmGateCheck). known is false when
// gkm holds no form or generation of the repo yet, or a read failed, so nothing is hinted on its account.
func (self *GkmReconciler) gateClosed(view sidecar.GkmAuthView, repoId sidecar.Id, now time.Time) (closed bool, groupId sidecar.Id, known bool) {
	ctx := self.ctx
	cluster, _, err := self.places.Cluster(ctx, repoId)
	if err != nil {
		return false, sidecar.Id{}, false
	}
	groupId, found, err := gkmNewestFormGroup(ctx, cluster, repoId, self.settings.Service)
	if err != nil || !found {
		return false, sidecar.Id{}, false
	}
	facts, found, err := gkmNewestGenerationFacts(ctx, cluster, groupId, self.settings.Service)
	if err != nil || !found {
		return false, groupId, false
	}
	err = sidecar.GkmGateCheck(view, repoId, facts.auth, time.UnixMilli(facts.timeMs), now)
	return errors.Is(err, sidecar.ErrGkmGateClosed), groupId, true
}

// The writers of the network's config repo, which a directory group's pending hint goes to (§10.9).
func gkmConfigWriters(state *GkmNetworkState) []sidecar.Id {
	for _, repoId := range state.RepoIds {
		if repo := state.View.Repo(repoId); repo != nil && repo.GetKind() == protocol.RepoKind_REPO_KIND_CONFIG {
			return state.View.RepoWriters(repoId)
		}
	}
	return nil
}

// pending on the per-client gkm topic about a repo's group: to its writers, signerId first when it is one of them, or
// in the directory group to signerId and the config writers (§10.6's pending changes, §10.9's directory row).
func (self *GkmReconciler) hintPending(state *GkmNetworkState, repoId sidecar.Id, groupId sidecar.Id, signerId *sidecar.Id, configWriterIds []sidecar.Id) {
	recipientIds := []sidecar.Id{}
	directory := state.View.Repo(repoId).GetKind() == protocol.RepoKind_REPO_KIND_DIRECTORY
	writerIds := state.View.RepoWriters(repoId)
	if directory {
		writerIds = configWriterIds
	}
	if signerId != nil && (directory || slices.Contains(writerIds, *signerId)) {
		recipientIds = append(recipientIds, *signerId)
	}
	for _, writerId := range writerIds {
		if !slices.Contains(recipientIds, writerId) {
			recipientIds = append(recipientIds, writerId)
		}
	}
	self.sendHint(recipientIds, protocol.GkmHintKind_GKM_HINT_PENDING, &groupId)
}

// Sends one work hint on the per-client gkm topic, versioned by the clock in µs (§6.8), under HintTimeout. A failure
// is logged and passed over: the next interval, or the clients' hourly resync, covers it.
func (self *GkmReconciler) sendHint(sidecarIds []sidecar.Id, kind protocol.GkmHintKind, groupId *sidecar.Id) {
	push := self.host.Push
	if push == nil || len(sidecarIds) == 0 {
		return
	}
	body, err := gkmHintBody(groupId, 0, kind, nil)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(self.ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.HintTimeout, cancel)
	defer stop()
	connectSidecarIds := make([]connect.Id, len(sidecarIds))
	for i, sidecarId := range sidecarIds {
		connectSidecarIds[i] = connect.Id(sidecarId)
	}
	hint := &sidecar.ClientHint{
		Topic:   sidecar.PushTopicGkm,
		Version: uint64(max(1, self.clock.Now().UnixMicro())),
		Kind:    uint32(protocol.MessageType_GKM_HINT),
		Body:    body,
	}
	if err := push.HintSidecars(ctx, connectSidecarIds, hint); err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[gkm reconciler] a %s hint to %d sidecars failed: %v", kind, len(sidecarIds), err)
	}
}

// The group a repo's newest GroupForm names, read fresh: found false for a repo with none yet.
func gkmNewestFormGroup(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, settings *GkmServiceSettings) (sidecar.Id, bool, error) {
	forms, err := gkmReadForms(ctx, cluster, repoId, settings)
	if err != nil || len(forms) == 0 {
		return sidecar.Id{}, false, err
	}
	return forms[len(forms)-1].GroupId, true, nil
}

// A repo's GroupForms, oldest first, with no cache.
func gkmReadForms(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, settings *GkmServiceSettings) ([]*gkmForm, error) {
	prefix := GkmFormPrefix(repoId)
	infos, err := listGkmKeys(ctx, cluster, prefix, settings.ListPageCount, settings.FormMaxCount)
	if err != nil {
		return nil, err
	}
	forms := []*gkmForm{}
	for _, info := range infos {
		seq, ok := parseGkmKeyNumber(strings.TrimPrefix(info.Key, prefix))
		if !ok {
			return nil, errors.Join(errGkmStoreFault, errors.New("a GroupForm key out of form"))
		}
		objectBytes, _, err := readGkmObject(ctx, cluster, info.Key, settings.ObjectMaxByteCount)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		form, err := parseGkmForm(repoId, seq, objectBytes)
		if err != nil {
			return nil, err
		}
		forms = append(forms, form)
	}
	return forms, nil
}

// The facts of a group's newest generation, by one listing of gen/ and one read, through the accessor: found false
// for a group with none.
func gkmNewestGenerationFacts(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, settings *GkmServiceSettings) (*gkmGenerationFacts, bool, error) {
	generations, err := listGkmGenerations(ctx, cluster, groupId, 0, settings.ListPageCount)
	if err != nil || len(generations) == 0 {
		return nil, false, err
	}
	objectBytes, err := readGkmGeneration(ctx, cluster, groupId, generations[len(generations)-1])
	if err != nil {
		return nil, false, err
	}
	facts, err := parseGkmGenerationFacts(objectBytes)
	if err != nil {
		return nil, false, err
	}
	return facts, true, nil
}
