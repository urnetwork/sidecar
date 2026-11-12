//go:build !sidecar_http && !ios_extension

// What a follower reads of §8.9's gate cache beyond one network's state (QD-718, question
// keys-m2-17-gkm-auth-state-owner): gkm's reconciler in taskworker walks every network the process holds, asks which
// network a sidecar is of, and must read a network's new state once a hint woke it, never the one before.
//
//	Networks            the networks the cache holds a loaded state of, sorted
//	SidecarNetwork      the one loaded network whose state holds a sidecar's row, a revoked tombstone's included
//	AddInstallCallback  a callback run after each new snapshot is installed, the index already moved, so what it wakes
//	                    reads the new snapshot through State
//	AclGateSnapshot.Entry  the time and signer of an entry the gate's log still keeps
//
// Changed is an input: it says a log moved, and returns before any load. The install callback is the output that
// says a load finished with a newer state, which is what a follower waits on.
//
// The index names a sidecar's network only while exactly one loaded state holds its row. A log is each network's
// own, so a second network whose log admits the same id says nothing this cache can weigh against the first: the
// answer is then none, the closed direction for a caller that would act on the sidecar's standing. An evicted
// network's sidecars leave the index with its state, and come back with its next load.
//
// Safe for concurrent use. The index's lock is taken last, after the cache's and a network's, and held across no
// call out. Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"slices"
	"sync"
)

// Called after a network's new snapshot is installed, on that network's loading goroutine, which it must not hold:
// it never blocks and does no I/O. State(networkId) answers snapshot, or a newer one, from the moment it runs.
type AclGateInstallFunction func(networkId Id, snapshot *AclGateSnapshot)

// One registered install callback, a pointer so two registrations of one function are told apart.
type aclGateInstallCallback struct {
	callback AclGateInstallFunction
}

// Runs callback after every install from now on, a cold start's first among them, and never for a load that
// installed nothing newer. Returns what stops it; an install under way may still call it once.
func (self *AclGateCache) AddInstallCallback(callback AclGateInstallFunction) (remove func()) {
	entry := &aclGateInstallCallback{callback: callback}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	next := append(slices.Clone(*self.installCallbacks.Load()), entry)
	self.installCallbacks.Store(&next)
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		next := slices.DeleteFunc(slices.Clone(*self.installCallbacks.Load()), func(other *aclGateInstallCallback) bool {
			return other == entry
		})
		self.installCallbacks.Store(&next)
	}
}

// The networks the cache holds a loaded state of, sorted: not the ones it tracks with nothing loaded, which have
// nothing to read. Counts as no read of any of them, so listing keeps none from eviction.
func (self *AclGateCache) Networks() []Id {
	networkIds := []Id{}
	for networkId, network := range *self.networks.Load() {
		if network.snapshot.Load() != nil {
			networkIds = append(networkIds, networkId)
		}
	}
	slices.SortFunc(networkIds, Id.Cmp)
	return networkIds
}

// The loaded network whose state holds a row of the sidecar, revoked ones included, and false when none does or
// more than one does (the file header). The row itself is read from that network's State.
func (self *AclGateCache) SidecarNetwork(sidecarId Id) (networkId Id, found bool) {
	return self.sidecars.network(sidecarId)
}

// Which loaded networks hold a row of each sidecar.
type aclGateSidecarIndex struct {
	stateLock sync.Mutex
	// each loaded network's sidecars as its last install listed them, sorted
	networkIdSidecarIds map[Id][]Id
	// the loaded networks whose state holds a row of the sidecar: one, but for an id two logs admit
	sidecarIdNetworkIds map[Id][]Id
}

// An index holding no network.
func newAclGateSidecarIndex() *aclGateSidecarIndex {
	return &aclGateSidecarIndex{
		networkIdSidecarIds: map[Id][]Id{},
		sidecarIdNetworkIds: map[Id][]Id{},
	}
}

// Replaces what the index holds of a network with sidecarIds, sorted, which the index keeps: only the ids that came
// or went are touched.
func (self *aclGateSidecarIndex) install(networkId Id, sidecarIds []Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	previous := self.networkIdSidecarIds[networkId]
	i, j := 0, 0
	for i < len(previous) || j < len(sidecarIds) {
		switch {
		case j == len(sidecarIds) || (i < len(previous) && previous[i].Cmp(sidecarIds[j]) < 0):
			self.dropWithLock(previous[i], networkId)
			i += 1
		case i == len(previous) || sidecarIds[j].Cmp(previous[i]) < 0:
			self.sidecarIdNetworkIds[sidecarIds[j]] = append(self.sidecarIdNetworkIds[sidecarIds[j]], networkId)
			j += 1
		default:
			i += 1
			j += 1
		}
	}
	if len(sidecarIds) == 0 {
		delete(self.networkIdSidecarIds, networkId)
		return
	}
	self.networkIdSidecarIds[networkId] = sidecarIds
}

// Takes a network's sidecars out, as its eviction does.
func (self *aclGateSidecarIndex) remove(networkId Id) {
	self.install(networkId, nil)
}

// Forgets that networkId holds the sidecar.
func (self *aclGateSidecarIndex) dropWithLock(sidecarId Id, networkId Id) {
	networkIds := slices.DeleteFunc(self.sidecarIdNetworkIds[sidecarId], func(other Id) bool {
		return other == networkId
	})
	if len(networkIds) == 0 {
		delete(self.sidecarIdNetworkIds, sidecarId)
		return
	}
	self.sidecarIdNetworkIds[sidecarId] = networkIds
}

// The one network holding the sidecar, false for none or several.
func (self *aclGateSidecarIndex) network(sidecarId Id) (Id, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkIds := self.sidecarIdNetworkIds[sidecarId]
	if len(networkIds) != 1 {
		return Id{}, false
	}
	return networkIds[0], true
}

// What a gate's log keeps of one entry.
type AclGateEntry struct {
	// The entry's time_ms, api's clock when it sequenced it.
	TimeMs int64
	// The first sidecar among the signers of the statement the entry carried; nil for a tick, a base, a statement
	// that took no effect, and one no sidecar signed.
	SignerSidecarId *Id
}

// The entry at a position of the snapshot's chain, nil where the gate's log keeps none: past its window, above the
// snapshot, or position 0.
func (self *AclGateSnapshot) Entry(position uint64) *AclGateEntry {
	if self == nil || self.Config == nil {
		return nil
	}
	kept := self.Config.keptEntryAt(position)
	if kept == nil || kept.entry == nil {
		return nil
	}
	entry := &AclGateEntry{TimeMs: kept.entry.GetTimeMs()}
	if kept.statement != nil {
		for _, signer := range kept.statement.signers {
			if signer.Kind == ConfigSignerSidecar {
				signerSidecarId := signer.SidecarId
				entry.SignerSidecarId = &signerSidecarId
				break
			}
		}
	}
	return entry
}
