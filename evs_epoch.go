// Path epochs as evs and its clients both judge them (§11.6's due, map and commit rows; D-EVS-12; DESIGN-DETAILS
// 9.2.2, 9.2.3 and 9.2.6): one function for each rule both sides apply, so the two never differ.
//
//	classify  a push whose generation pin crosses a REMOVE generation records an immediate due unless the newest
//	          verified state shows the repo's holders last shrank at or below the auth pin of the generation it
//	          crosses from: then only expiries passed, and the due is batched. A compromise retirement shrinks though
//	          no holder leaves (§7.9), so every shrink reads as immediate (question evs1-m2-16-due-classification,
//	          option 1). A party that cannot read one of the two, the state's shrink or the generation's pin, reads
//	          the crossing as immediate.
//	blocks    an immediate due blocks creation only on shared and owned refs of general, config and mailcfg repos,
//	          whose names carry meaning; deposit and erasure refs hold random ids under no path key and stay at
//	          epoch 1, and the other kinds name entries by id or sequence (plan-EVS1-epoch-kinds #1 and #2)
//	map hash  path_map_sha256 is SHA-256 over a map's parts' signed bytes in part order (9.2.2's map row), which
//	          the copy checks as it reads the parts (9.2.6) and a mapper computes as it builds them
//
//	status    the ref's path epoch as this device sees it, the overdue alarm, and what a creation the epoch holds
//	          waits on (DESIGN-DETAILS 9.2.8)
//
// On every leg. Package-level functions are safe for concurrent use; an EvsPathMapHasher is not.

package sidecar

import (
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// DESIGN-DETAILS 9.2.2's EvsReadPath: a read names a path in at most 8 epochs, one token path an epoch, which evs
// matches by the epoch field.
const EvsReadPathMaxEpochCount = 8

// Whether a crossing of a REMOVE generation is immediate: a shrink of the repo's holders, at holdersShrunkAt in
// the newest verified state, after fromAuthVersion, the auth pin of the generation the crossing starts from. Batched
// otherwise. See the file header.
func EvsClassifyPathEpochDue(holdersShrunkAt uint64, fromAuthVersion uint64) bool {
	return fromAuthVersion < holdersShrunkAt
}

// Whether an immediate due blocks creation on a ref of refKind in a repo of repoKind: a shared or owned ref of a
// general, config or mailcfg repo. See the file header.
func EvsRefBlocksCreation(repoKind protocol.RepoKind, refKind protocol.EvsRefKind) bool {
	switch repoKind {
	case protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG:
		return refKind == protocol.EvsRefKind_EVS_REF_SHARED || refKind == protocol.EvsRefKind_EVS_REF_OWNED
	}
	return false
}

// path_map_sha256 over a map's parts as they are read or built, one part at a time in part order, so neither the copy
// nor a mapper holds more than one part to hash a map.
type EvsPathMapHasher struct {
	hash      hash.Hash
	partCount int
}

// A hasher before its first part.
func NewEvsPathMapHasher() *EvsPathMapHasher {
	return &EvsPathMapHasher{hash: sha256.New()}
}

// Adds the next part's signed bytes, as stored or sent.
func (self *EvsPathMapHasher) Add(partBytes []byte) {
	self.hash.Write(partBytes)
	self.partCount += 1
}

// How many parts it holds.
func (self *EvsPathMapHasher) PartCount() int {
	return self.partCount
}

// The map's path_map_sha256 over the parts added so far.
func (self *EvsPathMapHasher) Sum() []byte {
	return self.hash.Sum(nil)
}

// path_map_sha256 of a map whose parts' signed bytes are parts, in part order.
func EvsPathMapSha256(parts [][]byte) []byte {
	hasher := NewEvsPathMapHasher()
	for _, partBytes := range parts {
		hasher.Add(partBytes)
	}
	return hasher.Sum()
}

// The ref's path epoch as this device sees it (DESIGN-DETAILS 9.2.8's status): its head's epoch state, the due the
// head records or this device's REMOVE generation implies, and where the epoch's mapping stands.
type EvsPathEpochStatus struct {
	Current       uint64
	Sources       []uint64
	DueGeneration uint64
	// due_by_ms, or when no head records the due, from when this device first held its generation: then, immediate,
	// or 24 h after, batched
	DueBy time.Time
	// "immediate" or "batched", empty with no due
	Class string
	// none, waiting_mapper, waiting_sources, building, uploading, committing or overdue
	State         string
	PartsUploaded int
	PartCount     int
}

// The states EvsPathEpochStatus names.
const (
	EvsPathEpochStateNone           = "none"
	EvsPathEpochStateWaitingMapper  = "waiting_mapper"
	EvsPathEpochStateWaitingSources = "waiting_sources"
	EvsPathEpochStateBuilding       = "building"
	EvsPathEpochStateUploading      = "uploading"
	EvsPathEpochStateCommitting     = "committing"
	EvsPathEpochStateOverdue        = "overdue"
)

// §11.6's commit row: at most 3 sources stand, and a batched epoch waits while 2 do.
const (
	evsPathEpochMaxSourceCount        = 3
	evsPathEpochBatchedMaxSourceCount = 2
)

// §11.6's due row: a batched epoch is due 24 h after the first commit crossing it.
const evsPathEpochBatchedDelay = 24 * time.Hour

// What a mapper on this device says of a ref's job (evs_epoch_map.go), nil while none runs: its state and its parts.
type evsMapperStatusFunction func(repoId Id, refId Id) (state string, partsUploaded int, partCount int, ok bool)

// The ref's path epoch status, from its last verified head, one head read when this client holds none.
func (self *EvsRepo) PathEpochStatus(ctx context.Context, refName []byte) (*EvsPathEpochStatus, error) {
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	return self.pathEpochStatusOf(ctx, refId)
}

// PathEpochStatus of a ref by id.
func (self *EvsRepo) pathEpochStatusOf(ctx context.Context, refId Id) (*EvsPathEpochStatus, error) {
	state := self.client.refEpochState(self.repoId, refId)
	if state == nil {
		if _, err := self.readHeadAlone(ctx, refId, false); err != nil {
			return nil, err
		}
		state = self.client.refEpochState(self.repoId, refId)
	}
	epoch := state.epoch
	status := &EvsPathEpochStatus{Current: evsCurrentEpoch(epoch), Sources: evsSourceEpochs(epoch), State: EvsPathEpochStateNone}
	if evsEpochExempt(state.refKind) {
		return status, nil
	}
	pressure, generation, err := self.pressure(ctx, state)
	if err != nil {
		return nil, err
	}
	if pressure == evsPressureNone {
		return status, nil
	}
	status.DueGeneration = generation
	status.Class = "immediate"
	if pressure == evsPressureBatched {
		status.Class = "batched"
	}
	status.DueBy = self.client.epochs.dueBy(self.repoId, epoch, generation, pressure == evsPressureBatched)
	now := self.client.clock.Now()
	if mapperStatus := self.client.epochs.mapperStatusFunction(); mapperStatus != nil {
		if state, uploaded, count, ok := mapperStatus(self.repoId, refId); ok {
			status.State, status.PartsUploaded, status.PartCount = state, uploaded, count
			return status, nil
		}
	}
	switch {
	case evsPathEpochMaxSourceCount <= len(status.Sources),
		pressure == evsPressureBatched && evsPathEpochBatchedMaxSourceCount <= len(status.Sources):
		status.State = EvsPathEpochStateWaitingSources
	case !status.DueBy.IsZero() && status.DueBy.Add(self.client.settings.EpochOverdueAfter).Before(now):
		status.State = EvsPathEpochStateOverdue
	default:
		status.State = EvsPathEpochStateWaitingMapper
	}
	return status, nil
}

// The line ur status prints for a ref whose State is not none (DESIGN-DETAILS 9.2.8):
// "<repo> <ref>: path epoch <cur> -> <due>, due <time> (<class>): <state>". repoLabel and refLabel are this device's
// own names for them, which never leave it.
func (self *EvsPathEpochStatus) StatusLine(repoLabel string, refLabel string) string {
	return fmt.Sprintf("%s %s: path epoch %d -> %d, due %s (%s): %s", repoLabel, refLabel, self.Current, self.DueGeneration,
		self.DueBy.UTC().Format(time.RFC3339), self.Class, self.State)
}

// When a due falls due: the head's due_by_ms when it records the due, else from when this device first held the
// generation, immediate at once and batched 24 h after; zero when neither is known.
func (self *evsClientEpochs) dueBy(repoId Id, epoch *protocol.EvsPathEpoch, generation uint64, batched bool) time.Time {
	if evsCurrentEpoch(epoch) < epoch.GetDueGeneration() && epoch.GetDueByMs() != 0 {
		return time.UnixMilli(epoch.GetDueByMs())
	}
	held := self.heldRemovalSince(repoId, generation)
	if held.IsZero() || !batched {
		return held
	}
	return held.Add(evsPathEpochBatchedDelay)
}

// One ref's overdue-alarm bookkeeping (DESIGN-DETAILS 9.2.8's alarm).
type evsRefAlarm struct {
	// the head showed two sources, and when it first showed fewer after that
	sawTwoSources bool
	fewerSince    time.Time
	// the last alarm per due generation
	alarmedAt map[uint64]time.Time
}

// The mapper's status function, nil while no mapper is registered.
func (self *evsClientEpochs) mapperStatusFunction() evsMapperStatusFunction {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.mapperStatus
}

// A verified head of a ref: the overdue alarm it calls for, on a device that writes the repo (DESIGN-DETAILS 9.2.8):
// a due whose due_by_ms, or from this device's first holding of a REMOVE generation the head has not recorded, is
// over EpochOverdueAfter past, at most once per ref and due generation in 24 h; not while the due is batched and the
// head lists two sources, nor within EpochOverdueAfter of the first head after that with fewer. Then wakes whatever
// waits on the ref's epoch.
func (self *evsClientEpochs) noteHead(client *EvsClient, repoId Id, refId Id, head *protocol.EvsHeadSummary) {
	defer self.wake(repoId, refId)
	refKind := head.GetRefKind()
	if evsEpochExempt(refKind) {
		return
	}
	config, err := client.verifier.config()
	if err != nil || !slices.Contains(config.RepoWriters(repoId), client.args.Identity().SidecarId) {
		return
	}
	epoch := head.GetPathEpoch()
	current := evsCurrentEpoch(epoch)
	now := client.clock.Now()
	generation, dueBy, batched := uint64(0), time.Time{}, !epoch.GetDueBlocksCreation()
	if current < epoch.GetDueGeneration() {
		generation, dueBy = epoch.GetDueGeneration(), time.UnixMilli(epoch.GetDueByMs())
	} else if held, since := self.newestHeldRemoval(repoId, max(current, head.GetGeneration())); held != 0 {
		// a removal this device holds that no head records yet: immediate, as it reads every unclassed crossing
		generation, dueBy, batched = held, since, false
	}
	key := evsRefKey{repoId: repoId, refId: refId}
	raise := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		alarm := self.refAlarms[key]
		if alarm == nil {
			alarm = &evsRefAlarm{alarmedAt: map[uint64]time.Time{}}
			self.refAlarms[key] = alarm
		}
		sourceCount := len(epoch.GetSources())
		if evsPathEpochBatchedMaxSourceCount <= sourceCount {
			alarm.sawTwoSources, alarm.fewerSince = true, time.Time{}
		} else if alarm.sawTwoSources && alarm.fewerSince.IsZero() {
			alarm.fewerSince = now
		}
		switch {
		case generation == 0 || dueBy.IsZero():
			return false
		case batched && evsPathEpochBatchedMaxSourceCount <= sourceCount:
			return false
		case !alarm.fewerSince.IsZero() && now.Before(alarm.fewerSince.Add(client.settings.EpochOverdueAfter)):
			return false
		case now.Before(dueBy.Add(client.settings.EpochOverdueAfter)):
			return false
		}
		if last, ok := alarm.alarmedAt[generation]; ok && now.Before(last.Add(24*time.Hour)) {
			return false
		}
		alarm.alarmedAt[generation] = now
		return true
	}()
	if raise {
		client.alarm(repoId, refId, SidecarEvsAlarmEpochOverdue, "", nil)
	}
}

// The newest REMOVE generation of a repo this device noted above from, and when it first held it; 0 for none.
func (self *evsClientEpochs) newestHeldRemoval(repoId Id, from uint64) (uint64, time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	newest, since := uint64(0), time.Time{}
	for key, at := range self.heldRemovals {
		if key.repoId == repoId && from < key.generation && newest < key.generation {
			newest, since = key.generation, at
		}
	}
	return newest, since
}

// A channel closed at the next verified head of the ref, which a creation the epoch holds waits on beside its timer
// (DESIGN-DETAILS 9.2.5's 412 PATH_EPOCH_DUE row).
func (self *evsClientEpochs) moved(repoId Id, refId Id) <-chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := evsRefKey{repoId: repoId, refId: refId}
	channel := self.waiters[key]
	if channel == nil {
		channel = make(chan struct{})
		self.waiters[key] = channel
	}
	return channel
}

// Wakes what waits on the ref's next verified head.
func (self *evsClientEpochs) wake(repoId Id, refId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := evsRefKey{repoId: repoId, refId: refId}
	if channel := self.waiters[key]; channel != nil {
		close(channel)
		delete(self.waiters, key)
	}
}
