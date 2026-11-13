// T2's SocketStore (SOCK-M5-03): Redis Cluster's groups, sets, listing and pairs in memory, until
// server's model.NewSocketStore (SOCK-M5-04) and after it, held to the same promises by
// RunSocketStoreSuite. A pick is socketsservice.PickSocketListeners itself, on candidates read as the Lua
// script reads them, so the two agree pick for pick on the same clock and draws.
//
// The fences are DESIGN-DETAILS 13.2.3's, as the group, pair and claim scripts keep them (SOCK-M5-18): a
// lease's position and set version, a removal's tombstone, which outlives the group's last listener, a
// pair floor, and the sweep's claim. Positions and set versions here are uint64s, which the scripts
// compare as decimal strings by length and then bytes, and the two agree.
//
// Every lease, share, tombstone, floor and claim lives by the injected clock alone, as the Redis store's
// do by the clock it passes its scripts: a backing ttl there is a backstop, never what a lease means. A
// call goes through hostCall, so a plan under FaultOpHost with the key "sockets.<Method>" reaches it, and
// each is counted, so a test can show a path made one call and no other. Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/socketsservice"
)

var _ socketsservice.SocketStore = (*FakeSocketStore)(nil)

// What a group is keyed by: §9.8's {sg_<network_id>_<h16(name)>}, without the hash.
type fakeSocketGroupKey struct {
	networkId connect.Id
	nameKey   string
}

// One listener of a group, as sock-1 and sock-2 let a store keep it.
type fakeSocketListener struct {
	registration *sidecar.SocketRegistration
	// The listener's sidecar, the highest position the lease was admitted at, and the set_version of the
	// page that last wrote it.
	sidecarId         *connect.Id
	policyVersion     uint64
	setVersion        uint64
	leaseExpireMillis int64
	reportedInflight  int
	reportMillis      int64
	ejection          socketsservice.SocketEjectionState
	// Reports of this listener from any dialer, for the two-network rule.
	reports      []*socketsservice.SocketFailureReport
	dialerShares map[connect.Id]*socketsservice.SocketDialerShare
}

// One group: its listeners and what the listing shows of it.
type fakeSocketGroup struct {
	listeners map[connect.Id]*fakeSocketListener
	// The group version, raised by every change of who listens.
	version uint64
	// The last sealed name written, which the listing shows (§2.8's sock-4).
	listedSealedName []byte
}

// A client's set, {sc_<client_id>}set.
type fakeSocketClientSet struct {
	networkId    connect.Id
	setVersion   uint64
	nameKeys     map[string]bool
	expireMillis int64
}

// One {svc_} field.
type fakeSocketPair struct {
	grantExpireMillis uint64
	expireMillis      int64
}

// A removal's tombstone, x:<L> of a group, or a listener's pair floor, ~f of its {svc_} key: the newest
// position (and, for a tombstone, set version) a removal stood at, until expireMillis.
type fakeSocketFence struct {
	setVersion    uint64
	policyVersion uint64
	cause         socketsservice.SocketRemoveCause
	expireMillis  int64
}

// What one removal did, as the group script's del answers.
type fakeSocketDelResult struct {
	removed      bool
	lastListener bool
	kept         bool
	// The lease's position, when kept.
	policyVersion uint64
}

// The store's state.
type FakeSocketStore struct {
	clock    Clock
	settings *socketsservice.SocketStoreSettings
	faults   *FaultQueue

	stateLock  sync.Mutex
	groups     map[fakeSocketGroupKey]*fakeSocketGroup
	clientSets map[connect.Id]*fakeSocketClientSet
	// by listener, then dialer
	listenerIdPairs map[connect.Id]map[connect.Id]*fakeSocketPair
	// by group, then listener: kept apart from the groups, since a tombstone outlives its group's last
	// listener
	groupTombstones map[fakeSocketGroupKey]map[connect.Id]*fakeSocketFence
	// by listener
	pairFloors map[connect.Id]*fakeSocketFence
	// by network
	sweepClaims map[connect.Id]*socketsservice.SocketSweepClaim
	opCounts    map[string]int
}

// A store on clock, nil being real time, with settings, nil being the defaults. A nil faults takes a
// fresh queue.
func NewFakeSocketStore(clock Clock, settings *socketsservice.SocketStoreSettings, faults *FaultQueue) *FakeSocketStore {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	if settings == nil {
		settings = socketsservice.DefaultSocketStoreSettings()
	}
	if faults == nil {
		faults = NewFaultQueue()
	}
	return &FakeSocketStore{
		clock:           clock,
		settings:        settings,
		faults:          faults,
		groups:          map[fakeSocketGroupKey]*fakeSocketGroup{},
		clientSets:      map[connect.Id]*fakeSocketClientSet{},
		listenerIdPairs: map[connect.Id]map[connect.Id]*fakeSocketPair{},
		groupTombstones: map[fakeSocketGroupKey]map[connect.Id]*fakeSocketFence{},
		pairFloors:      map[connect.Id]*fakeSocketFence{},
		sweepClaims:     map[connect.Id]*socketsservice.SocketSweepClaim{},
		opCounts:        map[string]int{},
	}
}

// The queue plans reach this store through.
func (self *FakeSocketStore) Faults() *FaultQueue {
	return self.faults
}

// How many calls of method, such as "Pick", the store has served.
func (self *FakeSocketStore) OpCount(method string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.opCounts["sockets."+method]
}

// Forgets everything, as a Redis flush or a lost cluster does, so a test can show one round of pages
// rebuilds it (§9.5).
func (self *FakeSocketStore) Wipe() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.groups = map[fakeSocketGroupKey]*fakeSocketGroup{}
	self.clientSets = map[connect.Id]*fakeSocketClientSet{}
	self.listenerIdPairs = map[connect.Id]map[connect.Id]*fakeSocketPair{}
	self.groupTombstones = map[fakeSocketGroupKey]map[connect.Id]*fakeSocketFence{}
	self.pairFloors = map[connect.Id]*fakeSocketFence{}
	self.sweepClaims = map[connect.Id]*socketsservice.SocketSweepClaim{}
}

// See SocketStoreSuiteHooks: the client's set goes, as its ttl ends it, and its leases stay.
func (self *FakeSocketStore) LapseClientSet(ctx context.Context, clientId connect.Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.clientSets, clientId)
	return nil
}

// One call through the fault queue and the count, serve running under the lock at the store's now.
func (self *FakeSocketStore) call(ctx context.Context, method string, serve func(nowMillis int64) error) error {
	return hostCall(ctx, self.faults, "sockets."+method, func() error {
		nowMillis := self.clock.Now().UnixMilli()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.opCounts["sockets."+method] += 1
		return serve(nowMillis)
	})
}

// A deep copy, so neither side's later changes reach the other.
func copySocketRegistration(registration *sidecar.SocketRegistration) *sidecar.SocketRegistration {
	kept := *registration
	kept.NameToken = bytes.Clone(registration.NameToken)
	kept.SealedName = bytes.Clone(registration.SealedName)
	kept.Alpn = slices.Clone(registration.Alpn)
	kept.Claim = bytes.Clone(registration.Claim)
	if registration.ListenId != nil {
		listenId := *registration.ListenId
		kept.ListenId = &listenId
	}
	return &kept
}

// The listen id a registration names, or the zero id.
func fakeSocketListenId(registration *sidecar.SocketRegistration) connect.Id {
	if registration.ListenId == nil {
		return connect.Id{}
	}
	return *registration.ListenId
}

// The group under key with its expired leases dropped, or nil when it has none left.
func (self *FakeSocketStore) liveGroupWithLock(key fakeSocketGroupKey, nowMillis int64) *fakeSocketGroup {
	group := self.groups[key]
	if group == nil {
		return nil
	}
	for listenerClientId, listener := range group.listeners {
		if listener.leaseExpireMillis <= nowMillis {
			delete(group.listeners, listenerClientId)
		}
	}
	if len(group.listeners) == 0 {
		delete(self.groups, key)
		return nil
	}
	return group
}

// The client's set, or nil once it has expired.
func (self *FakeSocketStore) liveClientSetWithLock(clientId connect.Id, nowMillis int64) *fakeSocketClientSet {
	set := self.clientSets[clientId]
	if set != nil && set.expireMillis <= nowMillis {
		delete(self.clientSets, clientId)
		return nil
	}
	return set
}

// Whether nameKey lies in [keyStart, keyEnd), an empty keyEnd being unbounded.
func fakeSocketInRange(nameKey []byte, keyStart []byte, keyEnd []byte) bool {
	return 0 <= bytes.Compare(nameKey, keyStart) && (len(keyEnd) == 0 || bytes.Compare(nameKey, keyEnd) < 0)
}

// Ends listenerClientId's lease in the group under key, and says what that left. found is false when it
// held no live lease there. A taken entry's own removal, which leaves no tombstone.
func (self *FakeSocketStore) removeListenerWithLock(key fakeSocketGroupKey, listenerClientId connect.Id, nowMillis int64) (found bool, lastListener bool) {
	group := self.liveGroupWithLock(key, nowMillis)
	if group == nil || group.listeners[listenerClientId] == nil {
		return false, false
	}
	delete(group.listeners, listenerClientId)
	group.version += 1
	if len(group.listeners) == 0 {
		delete(self.groups, key)
		return true, true
	}
	return true, false
}

// A ttl in whole milliseconds, rounded up, as HPEXPIRE keeps one.
func fakeSocketTtlMillis(ttl time.Duration) int64 {
	return (ttl + time.Millisecond - 1).Milliseconds()
}

// How long a tombstone of cause lives.
func (self *FakeSocketStore) tombstoneTtl(cause socketsservice.SocketRemoveCause) time.Duration {
	if cause == socketsservice.SocketRemoveUnlisten {
		return self.settings.UnlistenFenceTtl
	}
	return self.settings.TombstoneTtl
}

// The live tombstone of listenerClientId in the group under key, or nil.
func (self *FakeSocketStore) liveTombstoneWithLock(key fakeSocketGroupKey, listenerClientId connect.Id, nowMillis int64) *fakeSocketFence {
	tombstones := self.groupTombstones[key]
	tombstone := tombstones[listenerClientId]
	if tombstone == nil {
		return nil
	}
	if tombstone.expireMillis <= nowMillis {
		delete(tombstones, listenerClientId)
		if len(tombstones) == 0 {
			delete(self.groupTombstones, key)
		}
		return nil
	}
	return tombstone
}

// Leaves a tombstone, merged with a live one by the higher of each number and the longer life.
func (self *FakeSocketStore) writeTombstoneWithLock(key fakeSocketGroupKey, listenerClientId connect.Id, written *fakeSocketFence, nowMillis int64) {
	if live := self.liveTombstoneWithLock(key, listenerClientId, nowMillis); live != nil {
		written.setVersion = max(written.setVersion, live.setVersion)
		written.policyVersion = max(written.policyVersion, live.policyVersion)
		written.cause = max(written.cause, live.cause)
		written.expireMillis = max(written.expireMillis, live.expireMillis)
	}
	tombstones := self.groupTombstones[key]
	if tombstones == nil {
		tombstones = map[connect.Id]*fakeSocketFence{}
		self.groupTombstones[key] = tombstones
	}
	tombstones[listenerClientId] = written
}

// The group script's del: ends listenerClientId's lease for cause at (setVersion, policyVersion), unless a
// newer page or position wrote it, and leaves a tombstone. A nil setVersion is the lease's own, as a removal
// no page carries passes.
func (self *FakeSocketStore) delWithLock(key fakeSocketGroupKey, listenerClientId connect.Id, cause socketsservice.SocketRemoveCause, setVersion *uint64, policyVersion uint64, nowMillis int64) *fakeSocketDelResult {
	group := self.liveGroupWithLock(key, nowMillis)
	if group == nil || group.listeners[listenerClientId] == nil {
		return &fakeSocketDelResult{}
	}
	listener := group.listeners[listenerClientId]
	removalSetVersion := listener.setVersion
	if setVersion != nil {
		removalSetVersion = *setVersion
	}
	switch cause {
	case socketsservice.SocketRemoveUnlisten:
		if removalSetVersion < listener.setVersion {
			return &fakeSocketDelResult{kept: true, policyVersion: listener.policyVersion}
		}
	case socketsservice.SocketRemoveRefused:
		if policyVersion < listener.policyVersion || removalSetVersion < listener.setVersion {
			return &fakeSocketDelResult{kept: true, policyVersion: listener.policyVersion}
		}
	}
	_, lastListener := self.removeListenerWithLock(key, listenerClientId, nowMillis)
	self.writeTombstoneWithLock(key, listenerClientId, &fakeSocketFence{
		setVersion:    removalSetVersion,
		policyVersion: policyVersion,
		cause:         cause,
		expireMillis:  nowMillis + fakeSocketTtlMillis(self.tombstoneTtl(cause)),
	}, nowMillis)
	return &fakeSocketDelResult{removed: true, lastListener: lastListener}
}

// The listener's live pair floor, or nil.
func (self *FakeSocketStore) livePairFloorWithLock(listenerClientId connect.Id, nowMillis int64) *fakeSocketFence {
	floor := self.pairFloors[listenerClientId]
	if floor != nil && floor.expireMillis <= nowMillis {
		delete(self.pairFloors, listenerClientId)
		return nil
	}
	return floor
}

// pair_remove: every pair of the listener goes, and the floor stands at the higher of position and a live
// floor, for the longer of TombstoneTtl and what it had left.
func (self *FakeSocketStore) removePairsWithLock(listenerClientId connect.Id, position uint64, nowMillis int64) {
	delete(self.listenerIdPairs, listenerClientId)
	floor := &fakeSocketFence{
		policyVersion: position,
		expireMillis:  nowMillis + fakeSocketTtlMillis(self.settings.TombstoneTtl),
	}
	if live := self.livePairFloorWithLock(listenerClientId, nowMillis); live != nil {
		floor.policyVersion = max(floor.policyVersion, live.policyVersion)
		floor.expireMillis = max(floor.expireMillis, live.expireMillis)
	}
	self.pairFloors[listenerClientId] = floor
}

// Whether the set holds a name key a pair stands for.
func fakeSocketSetHoldsPairName(set *fakeSocketClientSet) bool {
	if set == nil {
		return false
	}
	for nameKey := range set.nameKeys {
		if socketsservice.SocketPairNameKey([]byte(nameKey)) {
			return true
		}
	}
	return false
}

// See socketsservice.SocketStore.
func (self *FakeSocketStore) Ping(ctx context.Context) error {
	return self.call(ctx, "Ping", func(nowMillis int64) error {
		return nil
	})
}

// Whether a page is one the engine could send: entries and refused keys each sorted, inside the range,
// non-empty, and no name key both allowed and refused.
func fakeSocketPageWellFormed(page *socketsservice.SocketStorePage) error {
	if page == nil {
		return fmt.Errorf("%w: no page", socketsservice.ErrSocketStoreRequest)
	}
	var previousNameKey []byte
	allowedNameKeys := map[string]bool{}
	for index, registration := range page.Registrations {
		nameKey := registration.NameKey()
		if len(nameKey) == 0 || !fakeSocketInRange(nameKey, page.KeyStart, page.KeyEnd) ||
			(0 < index && bytes.Compare(nameKey, previousNameKey) <= 0) {
			return fmt.Errorf("%w: entry %d", socketsservice.ErrSocketStoreRequest, index)
		}
		previousNameKey = nameKey
		allowedNameKeys[string(nameKey)] = true
	}
	for index, nameKey := range page.RefusedNameKeys {
		if len(nameKey) == 0 || !fakeSocketInRange(nameKey, page.KeyStart, page.KeyEnd) || allowedNameKeys[string(nameKey)] ||
			(0 < index && bytes.Compare(nameKey, page.RefusedNameKeys[index-1]) <= 0) {
			return fmt.Errorf("%w: refused entry %d", socketsservice.ErrSocketStoreRequest, index)
		}
	}
	return nil
}

// See socketsservice.SocketStore.
func (self *FakeSocketStore) ApplyPage(ctx context.Context, page *socketsservice.SocketStorePage) (*socketsservice.SocketStorePageResult, error) {
	var result *socketsservice.SocketStorePageResult
	err := self.call(ctx, "ApplyPage", func(nowMillis int64) error {
		if err := fakeSocketPageWellFormed(page); err != nil {
			return err
		}

		set := self.liveClientSetWithLock(page.ListenerClientId, nowMillis)
		if set != nil && page.SetVersion < set.setVersion {
			result = &socketsservice.SocketStorePageResult{Stale: true, SetVersion: set.setVersion}
			return nil
		}
		if set == nil {
			set = &fakeSocketClientSet{nameKeys: map[string]bool{}}
			self.clientSets[page.ListenerClientId] = set
		}
		previousNameKeys := []string{}
		for nameKey := range set.nameKeys {
			if fakeSocketInRange([]byte(nameKey), page.KeyStart, page.KeyEnd) {
				previousNameKeys = append(previousNameKeys, nameKey)
			}
		}
		sort.Strings(previousNameKeys)

		result = &socketsservice.SocketStorePageResult{SetVersion: page.SetVersion}
		heldNameKeys := map[string]bool{}
		// keys the page names, and those whose removal a newer page or position stood against
		pageNameKeys := map[string]bool{}
		standingNameKeys := map[string]bool{}
		lastListenerNameKeys := map[string]bool{}
		for _, registration := range page.Registrations {
			key := fakeSocketGroupKey{networkId: page.NetworkId, nameKey: string(registration.NameKey())}
			pageNameKeys[key.nameKey] = true
			outcome := &socketsservice.SocketStoreEntryOutcome{}
			result.Outcomes = append(result.Outcomes, outcome)

			// a removal at a newer position or by a newer set stands
			if tombstone := self.liveTombstoneWithLock(key, page.ListenerClientId, nowMillis); tombstone != nil &&
				(page.PolicyVersion < tombstone.policyVersion || page.SetVersion < tombstone.setVersion) {
				outcome.Fenced = true
				outcome.FencePolicyVersion = tombstone.policyVersion
				outcome.FenceCause = tombstone.cause
				continue
			}
			group := self.liveGroupWithLock(key, nowMillis)
			var existing *fakeSocketListener
			if group != nil {
				existing = group.listeners[page.ListenerClientId]
			}
			if existing != nil {
				outcome.PriorPolicyVersion = existing.policyVersion
				if page.SetVersion < existing.setVersion {
					outcome.Stale = true
					standingNameKeys[key.nameKey] = true
					continue
				}
			}
			if group != nil {
				for listenerClientId, listener := range group.listeners {
					if listenerClientId == page.ListenerClientId {
						continue
					}
					if listener.registration.Exclusive || registration.Exclusive || listener.registration.Protocol != registration.Protocol {
						outcome.Taken = true
					}
				}
			}
			if outcome.Taken {
				if existing != nil {
					self.removeListenerWithLock(key, page.ListenerClientId, nowMillis)
				}
				continue
			}

			if group == nil {
				group = &fakeSocketGroup{listeners: map[connect.Id]*fakeSocketListener{}}
				self.groups[key] = group
				outcome.FirstListener = true
			}
			listener := existing
			if listener == nil {
				listener = &fakeSocketListener{dialerShares: map[connect.Id]*socketsservice.SocketDialerShare{}}
				group.listeners[page.ListenerClientId] = listener
				group.version += 1
			}
			listener.registration = copySocketRegistration(registration)
			listener.sidecarId = copySocketId(page.SidecarId)
			listener.policyVersion = max(page.PolicyVersion, listener.policyVersion)
			listener.setVersion = page.SetVersion
			listener.leaseExpireMillis = nowMillis + self.settings.Lease.Milliseconds()
			listener.reportedInflight = registration.Inflight
			listener.reportMillis = nowMillis
			if len(registration.NameToken) != 0 {
				group.listedSealedName = bytes.Clone(registration.SealedName)
			}
			// the put clears the tombstone it passed
			if tombstones := self.groupTombstones[key]; tombstones != nil {
				delete(tombstones, page.ListenerClientId)
				if len(tombstones) == 0 {
					delete(self.groupTombstones, key)
				}
			}
			heldNameKeys[key.nameKey] = true
		}

		// the refused, for cause at the page's position
		refusedRemovedNameKeys := map[string]bool{}
		for _, nameKey := range page.RefusedNameKeys {
			key := fakeSocketGroupKey{networkId: page.NetworkId, nameKey: string(nameKey)}
			pageNameKeys[key.nameKey] = true
			setVersion := page.SetVersion
			del := self.delWithLock(key, page.ListenerClientId, socketsservice.SocketRemoveRefused, &setVersion, page.PolicyVersion, nowMillis)
			removal := &socketsservice.SocketStoreRemoval{}
			switch {
			case del.removed:
				removal.Removed = &socketsservice.SocketStoreRemoved{
					NetworkId:        page.NetworkId,
					ListenerClientId: page.ListenerClientId,
					NameKey:          bytes.Clone(nameKey),
					LastListener:     del.lastListener,
				}
				refusedRemovedNameKeys[key.nameKey] = true
				lastListenerNameKeys[key.nameKey] = del.lastListener
			case del.kept:
				removal.Kept = true
				removal.PolicyVersion = del.policyVersion
				standingNameKeys[key.nameKey] = true
			}
			result.RefusedOutcomes = append(result.RefusedOutcomes, removal)
		}

		// what the set held in range and the page does not name unlistens; outside it stays
		for _, nameKey := range previousNameKeys {
			if pageNameKeys[nameKey] {
				continue
			}
			key := fakeSocketGroupKey{networkId: page.NetworkId, nameKey: nameKey}
			setVersion := page.SetVersion
			del := self.delWithLock(key, page.ListenerClientId, socketsservice.SocketRemoveUnlisten, &setVersion, 0, nowMillis)
			if del.kept {
				standingNameKeys[nameKey] = true
				continue
			}
			lastListenerNameKeys[nameKey] = del.lastListener
		}

		removedNameKeys := map[string]bool{}
		for _, nameKey := range previousNameKeys {
			if !heldNameKeys[nameKey] && !standingNameKeys[nameKey] {
				removedNameKeys[nameKey] = true
			}
		}
		for nameKey := range refusedRemovedNameKeys {
			removedNameKeys[nameKey] = true
		}
		sortedRemovedNameKeys := make([]string, 0, len(removedNameKeys))
		for nameKey := range removedNameKeys {
			sortedRemovedNameKeys = append(sortedRemovedNameKeys, nameKey)
		}
		sort.Strings(sortedRemovedNameKeys)
		for _, nameKey := range sortedRemovedNameKeys {
			result.Removed = append(result.Removed, &socketsservice.SocketStoreRemoved{
				NetworkId:        page.NetworkId,
				ListenerClientId: page.ListenerClientId,
				NameKey:          []byte(nameKey),
				LastListener:     lastListenerNameKeys[nameKey],
			})
		}

		for _, nameKey := range previousNameKeys {
			delete(set.nameKeys, nameKey)
		}
		for nameKey := range heldNameKeys {
			set.nameKeys[nameKey] = true
		}
		// a lease a newer page wrote stays the set's
		for nameKey := range standingNameKeys {
			set.nameKeys[nameKey] = true
		}
		set.networkId = page.NetworkId
		set.setVersion = page.SetVersion
		set.expireMillis = nowMillis + self.settings.ClientSetTtl.Milliseconds()
		result.EdgeEntriesRemain = fakeSocketSetHoldsPairName(set)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// A copy of an optional id.
func copySocketId(id *connect.Id) *connect.Id {
	if id == nil {
		return nil
	}
	copied := *id
	return &copied
}

// The candidate a pick reads for listener, deep enough that the pick cannot reach the store.
func fakeSocketCandidate(listenerClientId connect.Id, listener *fakeSocketListener) *socketsservice.SocketCandidate {
	dialerShares := map[connect.Id]*socketsservice.SocketDialerShare{}
	for dialerClientId, share := range listener.dialerShares {
		dialerShares[dialerClientId] = &socketsservice.SocketDialerShare{
			PrimaryIssueMillis: slices.Clone(share.PrimaryIssueMillis),
			Exclusion:          share.Exclusion,
		}
	}
	return &socketsservice.SocketCandidate{
		ListenerClientId:     listenerClientId,
		ListenId:             fakeSocketListenId(listener.registration),
		Protocol:             listener.registration.Protocol,
		Version:              listener.registration.Version,
		Alpns:                slices.Clone(listener.registration.Alpn),
		Weight:               listener.registration.Weight,
		MaxStreams:           listener.registration.MaxStreams,
		Serving:              listener.registration.Serving,
		Draining:             listener.registration.Draining,
		LeaseExpireMillis:    listener.leaseExpireMillis,
		ReportedInflight:     listener.reportedInflight,
		ReportMillis:         listener.reportMillis,
		Ejection:             listener.ejection,
		DialerClientIdShares: dialerShares,
	}
}

// What a read gives of one listener.
func fakeSocketStoreListener(listenerClientId connect.Id, listener *fakeSocketListener) *socketsservice.SocketStoreListener {
	registration := copySocketRegistration(listener.registration)
	registration.Inflight = listener.reportedInflight
	return &socketsservice.SocketStoreListener{
		Registration:  registration,
		Candidate:     fakeSocketCandidate(listenerClientId, listener),
		SidecarId:     copySocketId(listener.sidecarId),
		PolicyVersion: listener.policyVersion,
		SetVersion:    listener.setVersion,
	}
}

// The group's listeners in client id order.
func fakeSocketSortedListenerIds(group *fakeSocketGroup) []connect.Id {
	listenerClientIds := make([]connect.Id, 0, len(group.listeners))
	for listenerClientId := range group.listeners {
		listenerClientIds = append(listenerClientIds, listenerClientId)
	}
	slices.SortFunc(listenerClientIds, func(a connect.Id, b connect.Id) int {
		return a.Cmp(b)
	})
	return listenerClientIds
}

// How many of the group's listeners pass active, which a cap on going out reads.
func fakeSocketActiveCount(group *fakeSocketGroup, active func(listener *fakeSocketListener) bool) int {
	count := 0
	for _, listener := range group.listeners {
		if active(listener) {
			count += 1
		}
	}
	return count
}

// See socketsservice.SocketStore.
func (self *FakeSocketStore) Pick(ctx context.Context, request *socketsservice.SocketStorePickRequest) (*socketsservice.SocketStorePickResult, error) {
	var result *socketsservice.SocketStorePickResult
	err := self.call(ctx, "Pick", func(nowMillis int64) error {
		if request == nil || len(request.NameKey) == 0 {
			return fmt.Errorf("%w: no group", socketsservice.ErrSocketStoreRequest)
		}
		scheduler := self.settings.Scheduler
		result = &socketsservice.SocketStorePickResult{}
		key := fakeSocketGroupKey{networkId: request.NetworkId, nameKey: string(request.NameKey)}
		group := self.liveGroupWithLock(key, nowMillis)
		if group == nil {
			result.Outcome = socketsservice.SocketPickNoListener
			return nil
		}

		groupCount := len(group.listeners)
		reporterWindowMillis := scheduler.ReporterWindow.Milliseconds()
		for _, report := range request.Reports {
			listener := group.listeners[report.ListenerClientId]
			if listener == nil || fakeSocketListenId(listener.registration) != report.ListenId {
				continue
			}
			share := listener.dialerShares[request.DialerClientId]
			if share == nil {
				share = &socketsservice.SocketDialerShare{}
				listener.dialerShares[request.DialerClientId] = share
			}
			excludedCount := fakeSocketActiveCount(group, func(other *fakeSocketListener) bool {
				otherShare := other.dialerShares[request.DialerClientId]
				return otherShare != nil && otherShare.Exclusion.Active(nowMillis, scheduler)
			})
			if exclusion, took := share.Exclusion.Eject(nowMillis, excludedCount, groupCount, scheduler); took {
				share.Exclusion = exclusion
				result.ExclusionCount += 1
			}

			reports := []*socketsservice.SocketFailureReport{}
			for _, kept := range listener.reports {
				if kept.ReportMillis <= nowMillis && nowMillis-kept.ReportMillis <= reporterWindowMillis {
					reports = append(reports, kept)
				}
			}
			listener.reports = append(reports, &socketsservice.SocketFailureReport{
				DialerNetworkId: request.DialerNetworkId,
				ReportMillis:    nowMillis,
			})
			if socketsservice.SocketReportersEject(listener.reports, nowMillis, scheduler) {
				ejectedCount := fakeSocketActiveCount(group, func(other *fakeSocketListener) bool {
					return other.ejection.Active(nowMillis, scheduler)
				})
				if ejection, took := listener.ejection.Eject(nowMillis, ejectedCount, groupCount, scheduler); took {
					listener.ejection = ejection
					result.EjectionCount += 1
				}
			}
		}

		listenerClientIds := fakeSocketSortedListenerIds(group)
		if self.settings.SampleCount < len(listenerClientIds) {
			random := rand.New(rand.NewPCG(uint64(request.SampleSeed), 0))
			random.Shuffle(len(listenerClientIds), func(i int, j int) {
				listenerClientIds[i], listenerClientIds[j] = listenerClientIds[j], listenerClientIds[i]
			})
			listenerClientIds = listenerClientIds[:self.settings.SampleCount]
		}
		candidates := make([]*socketsservice.SocketCandidate, 0, len(listenerClientIds))
		for _, listenerClientId := range listenerClientIds {
			candidates = append(candidates, fakeSocketCandidate(listenerClientId, group.listeners[listenerClientId]))
		}
		pick := socketsservice.PickSocketListeners(candidates, &socketsservice.SocketPickRequest{
			DialerClientId: request.DialerClientId,
			Protocol:       request.Protocol,
			MinVersion:     request.MinVersion,
			Alpns:          request.Alpns,
			NowMillis:      nowMillis,
			FirstDraw:      request.FirstDraw,
			SecondDraw:     request.SecondDraw,
		}, scheduler)
		result.Outcome = pick.Outcome
		if pick.Outcome != socketsservice.SocketPickFound {
			return nil
		}

		primary := group.listeners[pick.Primary.ListenerClientId]
		result.Primary = fakeSocketStoreListener(pick.Primary.ListenerClientId, primary)
		if pick.Backup != nil {
			result.Backup = fakeSocketStoreListener(pick.Backup.ListenerClientId, group.listeners[pick.Backup.ListenerClientId])
		}

		// the primary's ticket joins this dialer's share: only issues since the report and inside a
		// ticket's life can count, and of those only the newest c
		share := primary.dialerShares[request.DialerClientId]
		if share == nil {
			share = &socketsservice.SocketDialerShare{}
			primary.dialerShares[request.DialerClientId] = share
		}
		ticketLifetimeMillis := scheduler.TicketLifetime.Milliseconds()
		issueMillis := []int64{}
		for _, issued := range share.PrimaryIssueMillis {
			if primary.reportMillis <= issued && nowMillis < issued+ticketLifetimeMillis {
				issueMillis = append(issueMillis, issued)
			}
		}
		issueMillis = append(issueMillis, nowMillis)
		if clampCount := socketsservice.SocketClampCount(primary.registration.MaxStreams, scheduler); clampCount < len(issueMillis) {
			issueMillis = issueMillis[len(issueMillis)-clampCount:]
		}
		share.PrimaryIssueMillis = issueMillis
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// See socketsservice.SocketStore.
func (self *FakeSocketStore) ListListeners(ctx context.Context, networkId connect.Id, nameKey []byte) ([]*socketsservice.SocketStoreListener, error) {
	listeners := []*socketsservice.SocketStoreListener{}
	err := self.call(ctx, "ListListeners", func(nowMillis int64) error {
		group := self.liveGroupWithLock(fakeSocketGroupKey{networkId: networkId, nameKey: string(nameKey)}, nowMillis)
		if group == nil {
			return nil
		}
		for _, listenerClientId := range fakeSocketSortedListenerIds(group) {
			listeners = append(listeners, fakeSocketStoreListener(listenerClientId, group.listeners[listenerClientId]))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return listeners, nil
}

// See socketsservice.SocketStore. The cursor is the last name key returned, in hex, so pages come in
// name key order and none repeats.
func (self *FakeSocketStore) ListNames(ctx context.Context, networkId connect.Id, cursor string, count int) ([]*sidecar.SocketListName, string, error) {
	names := []*sidecar.SocketListName{}
	nextCursor := ""
	err := self.call(ctx, "ListNames", func(nowMillis int64) error {
		if count <= 0 {
			return fmt.Errorf("%w: a count of %d", socketsservice.ErrSocketStoreRequest, count)
		}
		var after []byte
		if cursor != "" {
			if _, err := fmt.Sscanf(cursor, "%x", &after); err != nil {
				return fmt.Errorf("%w: a cursor no page gave", socketsservice.ErrSocketStoreRequest)
			}
		}
		nameKeys := []string{}
		for key := range self.groups {
			if key.networkId == networkId && (after == nil || bytes.Compare(after, []byte(key.nameKey)) < 0) {
				nameKeys = append(nameKeys, key.nameKey)
			}
		}
		sort.Strings(nameKeys)
		lastNameKey := ""
		for _, nameKey := range nameKeys {
			key := fakeSocketGroupKey{networkId: networkId, nameKey: nameKey}
			group := self.liveGroupWithLock(key, nowMillis)
			if group == nil {
				continue
			}
			if len(names) == count {
				nextCursor = fmt.Sprintf("%x", []byte(lastNameKey))
				break
			}
			lastNameKey = nameKey
			// any listener says which form the name takes
			registration := group.listeners[fakeSocketSortedListenerIds(group)[0]].registration
			if registration.Name != "" {
				names = append(names, &sidecar.SocketListName{Name: registration.Name})
			} else {
				names = append(names, &sidecar.SocketListName{
					NameToken:  bytes.Clone(registration.NameToken),
					SealedName: bytes.Clone(group.listedSealedName),
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return names, nextCursor, nil
}

// See socketsservice.SocketStore.
func (self *FakeSocketStore) SetServicePair(ctx context.Context, listenerClientId connect.Id, dialerClientId connect.Id, grantExpireMillis uint64, ttl time.Duration, position uint64) (bool, uint64, error) {
	wrote := false
	floorPosition := uint64(0)
	err := self.call(ctx, "SetServicePair", func(nowMillis int64) error {
		if ttl <= 0 {
			return fmt.Errorf("%w: a ttl of %v", socketsservice.ErrSocketStoreRequest, ttl)
		}
		if floor := self.livePairFloorWithLock(listenerClientId, nowMillis); floor != nil {
			floorPosition = floor.policyVersion
			if position < floor.policyVersion {
				return nil
			}
		}
		pairs := self.listenerIdPairs[listenerClientId]
		if pairs == nil {
			pairs = map[connect.Id]*fakeSocketPair{}
			self.listenerIdPairs[listenerClientId] = pairs
		}
		pairs[dialerClientId] = &fakeSocketPair{
			grantExpireMillis: grantExpireMillis,
			expireMillis:      nowMillis + fakeSocketTtlMillis(ttl),
		}
		wrote = true
		return nil
	})
	if err != nil {
		return false, 0, err
	}
	return wrote, floorPosition, nil
}

// See socketsservice.SocketStore.
func (self *FakeSocketStore) GetServicePair(ctx context.Context, listenerClientId connect.Id, dialerClientId connect.Id) (uint64, bool, error) {
	grantExpireMillis := uint64(0)
	found := false
	err := self.call(ctx, "GetServicePair", func(nowMillis int64) error {
		pair := self.listenerIdPairs[listenerClientId][dialerClientId]
		if pair == nil {
			return nil
		}
		if pair.expireMillis <= nowMillis {
			delete(self.listenerIdPairs[listenerClientId], dialerClientId)
			return nil
		}
		grantExpireMillis = pair.grantExpireMillis
		found = true
		return nil
	})
	if err != nil {
		return 0, false, err
	}
	return grantExpireMillis, found, nil
}

// See socketsservice.SocketStore.
func (self *FakeSocketStore) RemoveServicePairs(ctx context.Context, listenerClientId connect.Id, position uint64) error {
	return self.call(ctx, "RemoveServicePairs", func(nowMillis int64) error {
		self.removePairsWithLock(listenerClientId, position, nowMillis)
		return nil
	})
}

// See socketsservice.SocketStore.
func (self *FakeSocketStore) TouchServicePairs(ctx context.Context, listenerClientId connect.Id) error {
	return self.call(ctx, "TouchServicePairs", func(nowMillis int64) error {
		ttlMaxMillis := fakeSocketTtlMillis(self.settings.EdgePairTtl)
		pairs := self.listenerIdPairs[listenerClientId]
		for dialerClientId, pair := range pairs {
			if pair.expireMillis <= nowMillis {
				delete(pairs, dialerClientId)
				continue
			}
			ttlMillis := ttlMaxMillis
			if pair.grantExpireMillis != 0 {
				ttlMillis = min(ttlMillis, int64(pair.grantExpireMillis)-nowMillis)
			}
			if ttlMillis <= 0 {
				delete(pairs, dialerClientId)
				continue
			}
			pair.expireMillis = nowMillis + ttlMillis
		}
		return nil
	})
}

// See socketsservice.SocketStore.
func (self *FakeSocketStore) RemoveClient(ctx context.Context, clientId connect.Id) ([]*socketsservice.SocketStoreRemoved, error) {
	removed := []*socketsservice.SocketStoreRemoved{}
	err := self.call(ctx, "RemoveClient", func(nowMillis int64) error {
		if set := self.liveClientSetWithLock(clientId, nowMillis); set != nil {
			// a batch at a time, each leaving the set once its leases are gone
			for 0 < len(set.nameKeys) {
				nameKeys := make([]string, 0, len(set.nameKeys))
				for nameKey := range set.nameKeys {
					nameKeys = append(nameKeys, nameKey)
				}
				sort.Strings(nameKeys)
				if self.settings.RemoveClientBatchCount < len(nameKeys) {
					nameKeys = nameKeys[:self.settings.RemoveClientBatchCount]
				}
				for _, nameKey := range nameKeys {
					key := fakeSocketGroupKey{networkId: set.networkId, nameKey: nameKey}
					del := self.delWithLock(key, clientId, socketsservice.SocketRemoveClientRemoved, nil, socketsservice.SocketRemovedClientPosition, nowMillis)
					if del.removed {
						removed = append(removed, &socketsservice.SocketStoreRemoved{
							NetworkId:        set.networkId,
							ListenerClientId: clientId,
							NameKey:          []byte(nameKey),
							LastListener:     del.lastListener,
						})
					}
				}
				for _, nameKey := range nameKeys {
					delete(set.nameKeys, nameKey)
				}
			}
			delete(self.clientSets, clientId)
		}
		self.removePairsWithLock(clientId, socketsservice.SocketRemovedClientPosition, nowMillis)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// See socketsservice.SocketStore.
func (self *FakeSocketStore) RemoveEntries(ctx context.Context, networkId connect.Id, cause socketsservice.SocketRemoveCause, position uint64, refs []*socketsservice.SocketStoreEntryRef) ([]*socketsservice.SocketStoreRemoval, error) {
	removals := []*socketsservice.SocketStoreRemoval{}
	err := self.call(ctx, "RemoveEntries", func(nowMillis int64) error {
		if !socketsservice.SocketRemovalAllowed(cause, position) {
			return fmt.Errorf("%w: a removal of cause %d at %d", socketsservice.ErrSocketStoreRequest, cause, position)
		}
		for _, ref := range refs {
			if len(ref.NameKey) == 0 {
				return fmt.Errorf("%w: no name key", socketsservice.ErrSocketStoreRequest)
			}
		}
		for _, ref := range refs {
			key := fakeSocketGroupKey{networkId: networkId, nameKey: string(ref.NameKey)}
			del := self.delWithLock(key, ref.ListenerClientId, cause, nil, position, nowMillis)
			removal := &socketsservice.SocketStoreRemoval{}
			if del.kept {
				removal.Kept = true
				removal.PolicyVersion = del.policyVersion
				removals = append(removals, removal)
				continue
			}
			// the set forgets a lease that is gone, whoever ended it
			if set := self.liveClientSetWithLock(ref.ListenerClientId, nowMillis); set != nil && set.networkId == networkId {
				delete(set.nameKeys, string(ref.NameKey))
			}
			if del.removed {
				removal.Removed = &socketsservice.SocketStoreRemoved{
					NetworkId:        networkId,
					ListenerClientId: ref.ListenerClientId,
					NameKey:          bytes.Clone(ref.NameKey),
					LastListener:     del.lastListener,
				}
			}
			removals = append(removals, removal)
		}
		// each answer reads its listener's set once every ref is done, as the set script runs after the dels
		for index, ref := range refs {
			removals[index].EdgeEntriesRemain = fakeSocketSetHoldsPairName(self.liveClientSetWithLock(ref.ListenerClientId, nowMillis))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return removals, nil
}

// See socketsservice.SocketStore.
func (self *FakeSocketStore) ClaimSweep(ctx context.Context, networkId connect.Id, position uint64, ttl time.Duration, held *socketsservice.SocketSweepClaim) (*socketsservice.SocketSweepClaim, bool, error) {
	var claim *socketsservice.SocketSweepClaim
	claimed := false
	err := self.call(ctx, "ClaimSweep", func(nowMillis int64) error {
		if ttl <= 0 {
			return fmt.Errorf("%w: a ttl of %v", socketsservice.ErrSocketStoreRequest, ttl)
		}
		if live := self.sweepClaims[networkId]; live != nil && nowMillis < live.UntilMillis {
			mine := held != nil && *held == *live
			if !mine && position <= live.PolicyVersion {
				kept := *live
				claim = &kept
				return nil
			}
		}
		taken := &socketsservice.SocketSweepClaim{PolicyVersion: position, UntilMillis: nowMillis + fakeSocketTtlMillis(ttl)}
		self.sweepClaims[networkId] = taken
		answer := *taken
		claim = &answer
		claimed = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return claim, claimed, nil
}

// Every value the store holds, raw, as CC3's Redis class: what server's store keeps in {sg_}, {sn_}, {sc_} and
// {svc_} (§2.8's sock-1, sock-3 to sock-5), so the privacy harness scans what a sockets process keeps (SOCK-M5-16):
// a source for PrivacyCapture.AddSource. Each item is one group, client set or listener's pairs, its fields written
// raw, so a value a scan looks for is in it as the store would hold it.
func (self *FakeSocketStore) PrivacyItems() []*PrivacyItem {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	items := []*PrivacyItem{}
	for key, group := range self.groups {
		body := &bytes.Buffer{}
		body.Write(key.networkId.Bytes())
		body.WriteString(key.nameKey)
		body.Write(group.listedSealedName)
		for listenerClientId, listener := range group.listeners {
			body.Write(listenerClientId.Bytes())
			if listener.sidecarId != nil {
				body.Write(listener.sidecarId.Bytes())
			}
			if registration := listener.registration; registration != nil {
				body.WriteString(registration.Name)
				body.Write(registration.NameToken)
				body.Write(registration.SealedName)
				body.Write(registration.Claim)
				body.WriteString(registration.Protocol)
				body.WriteString(registration.AppMode)
				for _, alpn := range registration.Alpn {
					body.WriteString(alpn)
				}
			}
		}
		for listenerClientId := range self.groupTombstones[key] {
			body.Write(listenerClientId.Bytes())
		}
		items = append(items, &PrivacyItem{Class: PrivacyClassRedis, Name: "sockets group of " + key.networkId.String(), Body: body.Bytes()})
	}
	for clientId, set := range self.clientSets {
		body := &bytes.Buffer{}
		body.Write(clientId.Bytes())
		body.Write(set.networkId.Bytes())
		for nameKey := range set.nameKeys {
			body.WriteString(nameKey)
		}
		items = append(items, &PrivacyItem{Class: PrivacyClassRedis, Name: "sockets client set " + clientId.String(), Body: body.Bytes()})
	}
	for listenerClientId, pairs := range self.listenerIdPairs {
		body := &bytes.Buffer{}
		body.Write(listenerClientId.Bytes())
		for dialerClientId := range pairs {
			body.Write(dialerClientId.Bytes())
		}
		items = append(items, &PrivacyItem{Class: PrivacyClassRedis, Name: "sockets pairs of " + listenerClientId.String(), Body: body.Bytes()})
	}
	return items
}
