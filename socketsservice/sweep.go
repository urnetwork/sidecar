// The engine's half of DESIGN-DETAILS 13.2.3's removals (§9.8, D-SOCK-9, X8, X10, I-4, I-15): what the host's one
// key-event subscriber calls, each noting its work for a worker of the engine's own and returning at once, since a
// key-event callback does no I/O, and the revocation sweep.
//
//   - ProjectionChanged(N), the {acl_<N>}v event, and ProjectionsResync, after the subscriber resubscribes: the
//     gate's evidence and its version check (SocketGateFollower). A gate that follows nothing is told nothing.
//   - ClientRemoved(C), the {X}c_removed event: C joins the removed-client set at once, so this process refuses its
//     pages with 401 and its leases at every pick, then a worker runs SocketStore.RemoveClient, which works through
//     C's set a batch at a time, leaves a cause-2 tombstone for each lease it ends and a floor at
//     SocketRemovedClientPosition on C's pairs, so processes holding the same event share the work and none
//     repeats another's. No SocketHint: C's transports are closing. A child is removed by its own event, which api
//     sets beside its parent's (§9.3).
//   - KillChanged(N), the {tes_<N>}n event, and KillsResync: the network's {tes_} hash read again and its kills
//     replaced (§13.9). A network whose hash this process never read is read once a tls/ name of it is first
//     judged; until then its tls/ names are judged with no kill, as tlsedge, which reads the same hash, refuses a
//     killed name's visitors on its own (SOCK.md reading 4).
//   - The sweep. The gate queues a network whose load raised its position past an entry socketEntryMayNarrow
//     flags. One pool of SweepConcurrency sweeps queued networks, each at most once per SweepMinInterval and
//     always at the newest position n: ClaimSweep takes the network at n for one process, and the claimer pages
//     the listing SweepPageCount names at a time, renewing its claim at each page, reads each group's listeners
//     and applies Find's listener check (checkListener) to each lease admitted at or below n. It removes the
//     refused for cause at n, in batches of SweepRemoveBatchCount, takes the pairs of a listener left with no edge
//     name, and hints each removed client SOCKET_HINT_REVOKED. A sweep that dies leaves nothing wrong: each lease
//     it missed is judged at its listener's next heartbeat and at any Find that picks it, and its pairs end by
//     EdgePairTtl.
//
// Hints are hints: a lost one costs a listener at most its next heartbeat. Nothing here logs or labels a name, a
// client or a network (I-13). Safe for concurrent use.

package socketsservice

import (
	"context"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// Whether an authorization log entry may take a socket verdict away: DESIGN-DETAILS 13.2.3's kind table, in one
// function. A statement of a kind that only widens (an activation, an unsuspend, an admission or its confirmations,
// a key's registration) or that no socket check reads (an EvsShare and the repo statements from RepoCreate through
// AuditOptOut) cannot; a BASE, a TICK, every other statement and anything this table does not know may, so the
// table errs toward sweeping. It reads the entry's kind and its statement's type alone.
func socketEntryMayNarrow(entry *bridge.AuthEntry) bool {
	if entry.GetKind() != bridge.AuthEntryKindStatement {
		return true
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		return true
	}
	switch signedType := bridge.SignedType(signed.GetType()); signedType {
	case bridge.SignedType_SIGNED_GRANT_ACTIVATE,
		bridge.SignedType_SIGNED_UNSUSPEND,
		bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		bridge.SignedType_SIGNED_MEMBER_ADMIT,
		bridge.SignedType_SIGNED_ADMISSION_CONFIRM,
		bridge.SignedType_SIGNED_OWNER_CONFIRM,
		bridge.SignedType_SIGNED_KEY_REGISTER,
		bridge.SignedType_SIGNED_EVS_SHARE:
		return false
	default:
		return signedType < bridge.SignedType_SIGNED_REPO_CREATE || bridge.SignedType_SIGNED_AUDIT_OPT_OUT < signedType
	}
}

// The positions of a run's entries that may narrow. An entry that does not parse is skipped: the cache refuses
// the whole run for it, so it installs nothing.
func socketNarrowingPositions(entryBytes [][]byte) []uint64 {
	positions := []uint64{}
	for _, oneEntryBytes := range entryBytes {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(oneEntryBytes, entry); err != nil {
			continue
		}
		if socketEntryMayNarrow(entry) {
			positions = append(positions, entry.GetN())
		}
	}
	return positions
}

// The {acl_<networkId>}v key event, from the host's one subscriber: evidence for the network at the gate. Never
// blocks and does no I/O.
func (self *SocketsService) ProjectionChanged(networkId connect.Id) {
	if follower, ok := self.gate.(SocketGateFollower); ok {
		follower.Changed(networkId)
	}
}

// The host's subscriber resubscribed to {acl_*}v: the gate checks each loaded network's version on its own worker.
// Never blocks.
func (self *SocketsService) ProjectionsResync() {
	if follower, ok := self.gate.(SocketGateFollower); ok {
		follower.Resync()
	}
}

// The {X}c_removed key event for clientId, from the host's one subscriber: the client joins the removed-client set
// now, and its store work is queued. Never blocks and does no I/O.
func (self *SocketsService) ClientRemoved(clientId connect.Id) {
	self.removedClients.add(clientId, self.clock.Now())
	self.removals.queue(clientId)
}

// The {tes_<networkId>}n key event: the network's kills are read again. Never blocks and does no I/O.
func (self *SocketsService) KillChanged(networkId connect.Id) {
	self.killSet.request(networkId)
}

// The host's subscriber resubscribed to {tes_*}n: every network whose kills this process holds is read again.
// Never blocks.
func (self *SocketsService) KillsResync() {
	self.killSet.requestAll()
}

// The gate's OnNarrowed: queues a sweep of networkId at position or above. Never blocks.
func (self *SocketsService) queueSweep(networkId connect.Id, position uint64) {
	self.sweeps.queue(networkId, position)
}

// A context bounded by timeout on the engine's clock, and the call that ends it.
func (self *SocketsService) storeContextFor(timeout time.Duration) (context.Context, func()) {
	ctx, cancel := context.WithCancel(self.ctx)
	stop := self.clock.AfterFunc(timeout, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// The removed clients awaiting their store work, in arrival order, each once. Safe for concurrent use.
type socketRemovals struct {
	queueCount int
	wake       chan struct{}

	stateLock         sync.Mutex
	pendingClientIds  []connect.Id
	queuedClientIds   map[connect.Id]bool
	droppedClientIds  int
	finishedClientIds *sidecar.MonitorValue[int]
}

// A queue of at most queueCount, whose wake channel holds one wake per worker.
func newSocketRemovals(queueCount int, workerCount int) *socketRemovals {
	return &socketRemovals{
		queueCount:        queueCount,
		wake:              make(chan struct{}, workerCount),
		queuedClientIds:   map[connect.Id]bool{},
		finishedClientIds: sidecar.NewMonitorValue(0),
	}
}

// Queues clientId once, unless the queue is full.
func (self *socketRemovals) queue(clientId connect.Id) {
	queued := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.queuedClientIds[clientId] {
			return false
		}
		if self.queueCount <= len(self.pendingClientIds) {
			// the removed-client set still refuses it here, and its leases lapse in one lease's time
			self.droppedClientIds += 1
			return false
		}
		self.queuedClientIds[clientId] = true
		self.pendingClientIds = append(self.pendingClientIds, clientId)
		return true
	}()
	if queued {
		select {
		case self.wake <- struct{}{}:
		default:
		}
	}
}

// The oldest queued client, false for none.
func (self *socketRemovals) take() (connect.Id, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.pendingClientIds) == 0 {
		return connect.Id{}, false
	}
	clientId := self.pendingClientIds[0]
	self.pendingClientIds = self.pendingClientIds[1:]
	delete(self.queuedClientIds, clientId)
	return clientId, true
}

// One removal worker, until the engine ends.
func (self *SocketsService) runRemovals() {
	defer self.workers.Done()
	for {
		for {
			clientId, ok := self.removals.take()
			if !ok {
				break
			}
			self.removeClient(clientId)
			self.removals.finishedClientIds.Update(func(count int) int { return count + 1 })
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.removals.wake:
		}
	}
}

// RemoveClient for clientId, tried ClientRemovedAttemptCount times, each resuming where the work stands; then
// LastUnlisten for every edge name it took a group's last lease of, and this process's memos of its pairs
// forgotten.
func (self *SocketsService) removeClient(clientId connect.Id) {
	if self.store == nil {
		return
	}
	for attempt := 0; attempt < self.settings.ClientRemovedAttemptCount; attempt += 1 {
		if 0 < attempt {
			select {
			case <-self.ctx.Done():
				return
			case <-self.clock.After(self.settings.ClientRemovedRetryWait):
			}
		}
		removed, err := func() ([]*SocketStoreRemoved, error) {
			ctx, done := self.storeContextFor(self.settings.ClientRemovedTimeout)
			defer done()
			testHookBarrier("sockets.client_removed.before", clientId.String())
			defer testHookBarrier("sockets.client_removed.after", clientId.String())
			return self.store.RemoveClient(ctx, clientId)
		}()
		if err != nil {
			continue
		}
		for _, one := range removed {
			self.notifyLastUnlisten(one)
		}
		self.pairWrites.forgetListener(clientId)
		self.pairTouches.forget(clientId)
		return
	}
}

// LastUnlisten for a removal that took an edge name's last lease. A token path takes no hook.
func (self *SocketsService) notifyLastUnlisten(removed *SocketStoreRemoved) {
	if removed == nil || !removed.LastListener {
		return
	}
	name := parseSocketNameKey(removed.NameKey)
	if name.name == "" {
		return
	}
	if hooks, registered := self.namespaces.lookup(name.namespace); registered {
		hooks.LastUnlisten(removed.NetworkId, name.name)
	}
}

// The kill set's reader, until the engine ends: every network due a read, then a retry of those that failed after
// KillRetryWait.
func (self *SocketsService) runKills() {
	defer self.workers.Done()
	for {
		failedNetworkIds := []connect.Id{}
		for _, networkId := range self.killSet.takePending() {
			if !self.readKills(networkId) {
				failedNetworkIds = append(failedNetworkIds, networkId)
			}
		}
		var retry <-chan time.Time
		if 0 < len(failedNetworkIds) {
			self.killSet.requeue(failedNetworkIds)
			retry = self.clock.After(self.settings.KillRetryWait)
		}
		self.killSet.readCount.Update(func(count int) int { return count + 1 })
		select {
		case <-self.ctx.Done():
			return
		case <-self.killSet.wake:
		case <-retry:
		}
	}
}

// Reads networkId's {tes_} hash and replaces its kills, with tlsedge's rule for what a hash holds, so a value that
// does not parse kills its host. False when the hash could not be read, which keeps the kills held before.
func (self *SocketsService) readKills(networkId connect.Id) bool {
	if self.host.Redis == nil {
		return false
	}
	fieldValues, err := func() (map[string][]byte, error) {
		ctx, done := self.storeContext()
		defer done()
		return self.host.Redis.HashGetAll(ctx, sidecar.TlsKillKey(sidecar.Id(networkId)))
	}()
	if err != nil {
		return false
	}
	self.killSet.set(networkId, tlsedgeservice.ParseTlsKillHash(fieldValues))
	return true
}

// The revocation sweep's queue: each network's newest queued position, when this process last swept it, and
// whether a sweep of it runs. Safe for concurrent use.
type socketSweeps struct {
	minInterval time.Duration
	wake        chan struct{}

	stateLock          sync.Mutex
	networkIdPositions map[connect.Id]uint64
	networkIdLastTimes map[connect.Id]time.Time
	running            map[connect.Id]bool
	// sweeps finished, each counted once its network is free again, so a test sees one land
	doneCount *sidecar.MonitorValue[int]
}

func newSocketSweeps(minInterval time.Duration) *socketSweeps {
	return &socketSweeps{
		minInterval:        minInterval,
		wake:               make(chan struct{}, 1),
		networkIdPositions: map[connect.Id]uint64{},
		networkIdLastTimes: map[connect.Id]time.Time{},
		running:            map[connect.Id]bool{},
		doneCount:          sidecar.NewMonitorValue(0),
	}
}

// Queues networkId at position, keeping the higher of it and what is queued.
func (self *socketSweeps) queue(networkId connect.Id, position uint64) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.networkIdPositions[networkId] < position {
			self.networkIdPositions[networkId] = position
		}
	}()
	self.wakeDispatcher()
}

func (self *socketSweeps) wakeDispatcher() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// A queued network whose last sweep here is minInterval old and that no sweep runs for, marked running; else how
// long until one is due, 0 for none queued. Drops the last times that can no longer delay anything.
func (self *socketSweeps) take(now time.Time) (connect.Id, bool, time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	wait := time.Duration(0)
	for networkId := range self.networkIdPositions {
		if self.running[networkId] {
			continue
		}
		lastTime, found := self.networkIdLastTimes[networkId]
		if !found || self.minInterval <= now.Sub(lastTime) {
			self.running[networkId] = true
			return networkId, true, 0
		}
		if due := self.minInterval - now.Sub(lastTime); wait == 0 || due < wait {
			wait = due
		}
	}
	for networkId, lastTime := range self.networkIdLastTimes {
		if _, queued := self.networkIdPositions[networkId]; !queued && !self.running[networkId] && self.minInterval <= now.Sub(lastTime) {
			delete(self.networkIdLastTimes, networkId)
		}
	}
	return connect.Id{}, false, wait
}

// A sweep of networkId ended at now. When it swept a position at or above what is queued, the queue entry goes;
// otherwise it waits for its interval and the newest position.
func (self *socketSweeps) done(networkId connect.Id, position uint64, swept bool, now time.Time) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.running, networkId)
		self.networkIdLastTimes[networkId] = now
		if swept && self.networkIdPositions[networkId] <= position {
			delete(self.networkIdPositions, networkId)
		}
	}()
	self.doneCount.Update(func(count int) int { return count + 1 })
	self.wakeDispatcher()
}

// The sweep's dispatcher, until the engine ends: each due network on a slot of SweepConcurrency.
func (self *SocketsService) runSweeps() {
	defer self.workers.Done()
	slots := make(chan struct{}, self.settings.SweepConcurrency)
	for {
		wait := time.Duration(0)
		for {
			networkId, ok, due := self.sweeps.take(self.clock.Now())
			if !ok {
				wait = due
				break
			}
			select {
			case slots <- struct{}{}:
			case <-self.ctx.Done():
				return
			}
			self.workers.Add(1)
			go func() {
				defer self.workers.Done()
				defer func() { <-slots }()
				position, swept := self.sweep(networkId)
				self.sweeps.done(networkId, position, swept, self.clock.Now())
			}()
		}
		var timer <-chan time.Time
		if 0 < wait {
			timer = self.clock.After(wait)
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.sweeps.wake:
		case <-timer:
		}
	}
}

// One refused lease of a sweep's page, with the name it holds.
type socketSweptLease struct {
	listener *SocketStoreListener
	name     *socketParsedName
}

// One sweep of networkId at its newest position: the position swept and true, or false when it could not run, a
// network unloaded or behind, or the store unanswered, which leaves it queued. A claim another process holds at the
// position or above sweeps for this one.
func (self *SocketsService) sweep(networkId connect.Id) (uint64, bool) {
	if self.store == nil || self.gate == nil {
		return 0, false
	}
	view, err := self.gate.View(networkId)
	if err != nil {
		return 0, false
	}
	position := view.Position()
	claim, claimed, err := func() (*SocketSweepClaim, bool, error) {
		ctx, done := self.storeContextFor(self.settings.SweepStoreTimeout)
		defer done()
		return self.store.ClaimSweep(ctx, networkId, position, self.settings.SweepClaimTtl, nil)
	}()
	if err != nil {
		return 0, false
	}
	if !claimed {
		return position, true
	}
	testHookBarrier("sockets.sweep.claimed", networkId.String())
	cursor := ""
	for {
		names, nextCursor, err := func() ([]*sidecar.SocketListName, string, error) {
			ctx, done := self.storeContextFor(self.settings.SweepStoreTimeout)
			defer done()
			return self.store.ListNames(ctx, networkId, cursor, self.settings.SweepPageCount)
		}()
		if err != nil {
			// the claim lapses, and the next sweep or each listener's heartbeat judges what this one did not reach
			return 0, false
		}
		now := self.clock.Now()
		refused := []*socketSweptLease{}
		for _, listName := range names {
			nameKey := []byte(listName.Name)
			if len(nameKey) == 0 {
				nameKey = listName.NameToken
			}
			if len(nameKey) == 0 {
				continue
			}
			name := parseSocketNameKey(nameKey)
			listeners, err := func() ([]*SocketStoreListener, error) {
				ctx, done := self.storeContextFor(self.settings.SweepStoreTimeout)
				defer done()
				return self.store.ListListeners(ctx, networkId, nameKey)
			}()
			if err != nil {
				continue
			}
			for _, listener := range listeners {
				// a lease admitted above the position is the fresher process's to judge, and evidence here
				if check, _ := self.checkListener(view, networkId, name, listener, now); check == socketListenerRefused {
					refused = append(refused, &socketSweptLease{listener: listener, name: name})
				}
				if self.settings.SweepRemoveBatchCount <= len(refused) {
					self.removeSwept(networkId, position, refused, now)
					refused = []*socketSweptLease{}
				}
			}
		}
		self.removeSwept(networkId, position, refused, now)
		if nextCursor == "" {
			return position, true
		}
		cursor = nextCursor
		testHookBarrier("sockets.sweep.page", networkId.String())
		claim, claimed, err = func() (*SocketSweepClaim, bool, error) {
			ctx, done := self.storeContextFor(self.settings.SweepStoreTimeout)
			defer done()
			return self.store.ClaimSweep(ctx, networkId, position, self.settings.SweepClaimTtl, claim)
		}()
		switch {
		case err != nil:
			return 0, false
		case !claimed:
			// a claim at a higher position took the network: its sweep reaches every lease this one would
			return position, true
		case self.ctx.Err() != nil:
			return 0, false
		}
	}
}

// Removes a sweep's refused leases for cause at position (one RemoveEntries), each leaving its tombstone, then for
// each removed: LastUnlisten when it took an edge name's last lease, the listener's pairs at position when it holds
// no other edge name, and SOCKET_HINT_REVOKED for its listen. A removal the store keeps for a newer admission is
// evidence. A failed call removes nothing and the next heartbeat judges them.
func (self *SocketsService) removeSwept(networkId connect.Id, position uint64, refused []*socketSweptLease, now time.Time) {
	if len(refused) == 0 {
		return
	}
	refs := make([]*SocketStoreEntryRef, 0, len(refused))
	for _, lease := range refused {
		refs = append(refs, &SocketStoreEntryRef{ListenerClientId: lease.listener.Candidate.ListenerClientId, NameKey: lease.name.nameKey()})
	}
	removals, err := func() ([]*SocketStoreRemoval, error) {
		ctx, done := self.storeContextFor(self.settings.SweepStoreTimeout)
		defer done()
		testHookBarrier("sockets.sweep.remove.before", networkId.String())
		defer testHookBarrier("sockets.sweep.remove.after", networkId.String())
		return self.store.RemoveEntries(ctx, networkId, SocketRemoveRefused, position, refs)
	}()
	if err != nil || len(removals) != len(refused) {
		return
	}
	pairsRemoved := map[connect.Id]bool{}
	for index, removal := range removals {
		lease := refused[index]
		switch {
		case removal.Removed != nil:
			self.notifyLastUnlisten(removal.Removed)
			listenerClientId := lease.listener.Candidate.ListenerClientId
			if SocketPairNameKey(removal.Removed.NameKey) && !removal.EdgeEntriesRemain && !pairsRemoved[listenerClientId] {
				pairsRemoved[listenerClientId] = true
				self.removePairs(listenerClientId, position)
			}
			self.hintRevoked(lease.listener, now)
		case removal.Kept && position < removal.PolicyVersion:
			self.gate.Observe(networkId, removal.PolicyVersion)
		}
	}
}
