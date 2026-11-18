// Path epochs as evs and its clients both judge them (§11.6's due, map and commit rows; D-EVS-12; DESIGN-DETAILS
// 9.2.2, 9.2.6 and 9.2.8): one function for each rule both sides apply, so the two never differ.
//
//	batched   every due is batched (QD-1046): a crossing of a REMOVE generation falls due 24 h after the first
//	          commit that crosses it, or 24 h after this device first held the generation while no head records
//	          it, and holds no creation and no new name; a PATH_EPOCH waits while two sources stand. No class is
//	          judged, so neither evs nor a client walks the log for one, and due_blocks_creation stays in the format
//	          unused
//	map hash  path_map_sha256 is SHA-256 over a map's parts' signed bytes in part order (9.2.2's map row), which
//	          the copy checks as it reads the parts (9.2.6) and a mapper computes as it builds them
//
//	status    the ref's path epoch as this device sees it, the overdue alarm, and what a creation a mapper's block
//	          holds waits on (DESIGN-DETAILS 9.2.8)
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
	// due_by_ms, or when no head records the due, 24 h after this device first held its generation
	DueBy time.Time
	// "batched", every due being batched (QD-1046), empty with no due
	Class string
	// none, waiting_mapper, waiting_sources, building, uploading, committing or overdue
	State         string
	PartsUploaded int
	PartCount     int
}

// The class EvsPathEpochStatus names a due by, the one there is (QD-1046).
const EvsPathEpochClassBatched = "batched"

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
	generation, err := self.dueGeneration(ctx, state)
	if err != nil {
		return nil, err
	}
	if generation == 0 {
		return status, nil
	}
	status.DueGeneration = generation
	status.Class = EvsPathEpochClassBatched
	settings := self.client.settings
	status.DueBy = self.client.epochs.dueBy(self.repoId, epoch, generation, settings.PathEpochBatchedDelay)
	now := self.client.clock.Now()
	if mapperStatus := self.client.epochs.mapperStatusFunction(); mapperStatus != nil {
		if state, uploaded, count, ok := mapperStatus(self.repoId, refId); ok {
			status.State, status.PartsUploaded, status.PartCount = state, uploaded, count
			return status, nil
		}
	}
	switch {
	case settings.PathEpochMaxSourceCount <= len(status.Sources), settings.PathEpochBatchedMaxSourceCount <= len(status.Sources):
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

// When a due falls due: the head's due_by_ms when it records the due, else batchedDelay after this device first held
// the generation (EvsSettings.PathEpochBatchedDelay, 24 h); zero when neither is known.
func (self *evsClientEpochs) dueBy(repoId Id, epoch *protocol.EvsPathEpoch, generation uint64, batchedDelay time.Duration) time.Time {
	if evsCurrentEpoch(epoch) < epoch.GetDueGeneration() && epoch.GetDueByMs() != 0 {
		return time.UnixMilli(epoch.GetDueByMs())
	}
	held := self.heldRemovalSince(repoId, generation)
	if held.IsZero() {
		return held
	}
	return held.Add(batchedDelay)
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

// The mapper's waker, nil while no mapper is registered.
func (self *evsClientEpochs) mapperWakeFunction() func(repoId Id, refId Id, headVersion uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.mapperWake
}

// A verified head of a ref: the overdue alarm it calls for, on a device that writes the repo (DESIGN-DETAILS 9.2.8):
// a due whose due_by_ms, or for a REMOVE generation the head has not recorded PathEpochBatchedDelay after the time this
// device first held it, is over EpochOverdueAfter past, at most once per ref and due generation in
// EpochOverdueAlarmInterval; not while the head lists PathEpochBatchedMaxSourceCount sources, every due being batched
// (QD-1046), nor within EpochOverdueAfter of the first head after that with fewer. A head showing such a due asks the
// mapper a tick (DESIGN-DETAILS 9.2.7's verified head), once per version. Then wakes whatever waits on the ref's epoch.
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
	generation, dueBy := uint64(0), time.Time{}
	if current < epoch.GetDueGeneration() {
		generation, dueBy = epoch.GetDueGeneration(), time.UnixMilli(epoch.GetDueByMs())
	} else if held, since := self.newestHeldRemoval(repoId, max(current, head.GetGeneration())); held != 0 {
		// a removal this device holds that no head records yet: due PathEpochBatchedDelay after it was first held, as
		// evs would record it
		generation, dueBy = held, since.Add(client.settings.PathEpochBatchedDelay)
	}
	if generation != 0 {
		if mapperWake := self.mapperWakeFunction(); mapperWake != nil {
			mapperWake(repoId, refId, head.GetVersion())
		}
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
		if client.settings.PathEpochBatchedMaxSourceCount <= sourceCount {
			alarm.sawTwoSources, alarm.fewerSince = true, time.Time{}
		} else if alarm.sawTwoSources && alarm.fewerSince.IsZero() {
			alarm.fewerSince = now
		}
		switch {
		case generation == 0 || dueBy.IsZero():
			return false
		case client.settings.PathEpochBatchedMaxSourceCount <= sourceCount:
			return false
		case !alarm.fewerSince.IsZero() && now.Before(alarm.fewerSince.Add(client.settings.EpochOverdueAfter)):
			return false
		case now.Before(dueBy.Add(client.settings.EpochOverdueAfter)):
			return false
		}
		if last, ok := alarm.alarmedAt[generation]; ok && now.Before(last.Add(client.settings.EpochOverdueAlarmInterval)) {
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
	for key, heldSince := range self.heldRemovals {
		if key.repoId == repoId && from < key.generation && newest < key.generation {
			newest, since = key.generation, heldSince
		}
	}
	return newest, since
}

// A channel closed at the next verified head of the ref, which a creation a mapper's block holds waits on beside its
// timer (DESIGN-DETAILS 9.2.5's 412 PATH_EPOCH_DUE row).
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
