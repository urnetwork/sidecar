// Path epochs as evs and its clients both judge them (§11.6's due, map and commit rows; D-EVS-12; DESIGN-DETAILS
// 9.2.2, 9.2.3 and 9.2.6): one function for each rule both sides apply, so the two never differ.
//
//	classify  a push whose generation pin crosses a REMOVE generation records a due classed from the log between the
//	          auth pins of the generation it crosses from and the one it crosses to (§11.6's due row; question
//	          evs1-m2-16-due-classification, option 3; QD-949): batched when nothing in between shrank the repo's
//	          holders, so only expiries passed (the party's newest state shows no shrink after the earlier pin, or the
//	          walk back from it finds none at or below the later pin); otherwise each entry in between that shrank them
//	          (config_shrink_span.go) is classed by its statement, and one immediate shrink makes the crossing immediate:
//	            batched    an agent's ordinary removal: a tagged sidecar's SidecarRevoke whose reason is not
//	                       compromise or a tick's reap of one, a DelegationRevoke with since_n 0, and a RepoRevoke,
//	                       GrantRevoke or Suspend; each only when every holder it dropped (KeyHolders before and after
//	                       it, at its time and at t_s, the time of the repo's last shrink or making that its row
//	                       carries, as config_coverage.go compares them for a holder whose access had lapsed; QD-883,
//	                       QD-1015) is an agent, a Delegation or a forwarding key
//	            immediate  everything else: a member's removal (a MemberRevoke, or any statement that drops a member's
//	                       recovery), a member device's, an untagged sidecar's, SidecarRevoke, reap or other removal (any
//	                       statement that drops a leaf), and a compromise retirement, a SidecarRevoke whose reason is
//	                       compromise, agents included, or a DelegationRevoke with since_n > 0; a RecoveryRebind too
//	          A party that cannot read what the class needs reads immediate, as for a crossing it cannot judge: either
//	          pin off its chain or above its state, the earlier above the later, a state or kept entry the walk needs
//	          that its window no longer keeps (S(s-1), S(s) and the entry at s for each shrink s in between, §11.6's
//	          "a party that cannot reach the states around a shrink in between", and S(s-1) for a shrink after the
//	          later pin, to step past it), a base whose own change shrank them, a shrink no holder it dropped explains,
//	          a statement type not named above, or holders it cannot compute. A pin before what the party retains is
//	          held to its number alone, as the gate holds a generation's (gkm_gate.go; QD-1018): its chain was checked
//	          when it was new, and the party judges it only where it still holds a chain value there, a kept base's or
//	          one from its retention point on. The walk then needs only the states around each shrink after the earlier
//	          pin, so an agent's ordinary removal reads batched on a repo whose generation was rotated before the
//	          party's window. A view that is no ConfigState reads no entry, so any shrink in between reads immediate
//	          there, as option 1 had every shrink
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
	"errors"
	"fmt"
	"hash"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a view shows of the entries between two pins that shrank a repo's holders, beside GkmAuthView: a ConfigState's
// window (config_shrink_span.go).
type evsShrinkSpanView interface {
	shrinksBetween(repoId Id, from *bridge.AuthPin, through *bridge.AuthPin) ([]*configShrink, error)
}

// Whether a crossing of a REMOVE generation is immediate, false for batched, as view classes it from the log between
// fromAuth, the auth pin of the generation the crossing starts from, and toAuth, that of the generation it crosses to.
// evs passes its gate view and a client its verified state, so the two class one log alike. A pin before what the view
// retains is held to its number, and the class needs only the states around each shrink after fromAuth (QD-1018). See
// the file header.
func EvsClassifyPathEpochDue(view GkmAuthView, repoId Id, fromAuth *bridge.AuthPin, toAuth *bridge.AuthPin) bool {
	if view == nil || fromAuth == nil || toAuth == nil || toAuth.GetVersion() < fromAuth.GetVersion() {
		return true
	}
	// a pin off the chain or above the state reads immediate; one before what the view retains, which it cannot judge,
	// is held to its number, as the gate holds a generation's
	for _, pin := range []*bridge.AuthPin{fromAuth, toAuth} {
		if standing := gkmPinStanding(view, pin); standing != nil && !errors.Is(standing, ErrGkmAuthNotRetained) {
			return true
		}
	}
	newest := view.Repo(repoId)
	if newest == nil {
		return true
	}
	if newest.GetHoldersShrunkAt() <= fromAuth.GetVersion() {
		// nothing has shrunk the holders since the earlier pin: only expiries passed, whether or not the window
		// still reaches either pin
		return false
	}
	spanView, ok := view.(evsShrinkSpanView)
	if !ok {
		// a view that reads no entry: immediate on any shrink in between, as its state at the later pin shows one
		through, err := view.At(toAuth)
		if err != nil {
			return true
		}
		repo := through.Repo(repoId)
		return repo == nil || fromAuth.GetVersion() < repo.GetHoldersShrunkAt()
	}
	// with no shrink in between, only shrinks after the later pin, a later crossing's, only expiries passed
	shrinks, err := spanView.shrinksBetween(repoId, fromAuth, toAuth)
	if err != nil {
		return true
	}
	for _, shrink := range shrinks {
		if evsShrinkImmediate(repoId, shrink) {
			return true
		}
	}
	return false
}

// Whether one entry that shrank the repo's holders makes a crossing covering it immediate, by its statement and the
// holders it dropped. See the file header.
func evsShrinkImmediate(repoId Id, shrink *configShrink) bool {
	kept := shrink.kept
	if kept == nil || kept.entry == nil || !kept.verdict.Accepted() {
		return true
	}
	var effects []*configStatement
	var reapedSidecarIds [][]byte
	switch kept.entry.GetKind() {
	case bridge.AuthEntryKindStatement:
		if kept.statement == nil {
			return true
		}
		effects = configEntryEffects(kept.statement, nil)
	case bridge.AuthEntryKindTick:
		if kept.tick == nil {
			return true
		}
		effects = configEntryEffects(nil, kept.activations)
		reapedSidecarIds = kept.tick.GetReapedSidecarIds()
	default:
		// a base's own change, which no statement says
		return true
	}
	if len(effects) == 0 && len(reapedSidecarIds) == 0 {
		return true
	}
	// whether the id names a tagged sidecar, an agent, in the state before the entry
	agent := func(sidecarIdBytes []byte) bool {
		sidecarId, err := IdFromBytes(sidecarIdBytes)
		if err != nil {
			return false
		}
		row := shrink.before.SidecarRow(sidecarId)
		return row != nil && len(row.GetMemberId()) == 0 && 0 < len(row.GetTagIds())
	}
	for _, statement := range effects {
		switch body := statement.body.(type) {
		case *bridge.SidecarRevoke:
			if body.GetReason() == bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE || 0 < body.GetSinceN() ||
				!agent(body.GetSidecarId()) {
				return true
			}
		case *protocol.DelegationRevoke:
			if 0 < body.GetSinceN() {
				return true
			}
		case *protocol.RepoRevoke, *bridge.GrantRevoke, *bridge.Suspend:
			// whose grant or standing it ended, the holders it dropped say
		default:
			return true
		}
	}
	for _, sidecarIdBytes := range reapedSidecarIds {
		if !agent(sidecarIdBytes) {
			return true
		}
	}
	// the holders it dropped, as config_coverage.go's shrink row compares them: at its own time and at t_s, the time of
	// the repo's last shrink or making that the state before's row carries, for a holder whose access had lapsed by
	// then (QD-883, QD-1015)
	at := time.UnixMilli(shrink.after.TimeMs())
	dropped, err := GkmHoldersDropped(shrink.before, shrink.after, repoId, at)
	if err != nil {
		return true
	}
	if shrinkTime, known := shrink.before.shrinkTime(repoId); known && shrinkTime.UnixMilli() != at.UnixMilli() {
		droppedAtShrink, err := GkmHoldersDropped(shrink.before, shrink.after, repoId, shrinkTime)
		if err != nil {
			return true
		}
		dropped = append(dropped, droppedAtShrink...)
	}
	if len(dropped) == 0 {
		// a shrink that dropped no holder at either time, which no statement named above gives: fail closed
		return true
	}
	for _, holder := range dropped {
		switch holder.Kind {
		case GkmHolderAgent, GkmHolderDelegation, GkmHolderForwarding:
		default:
			return true
		}
	}
	return false
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
	settings := self.client.settings
	status.DueBy = self.client.epochs.dueBy(self.repoId, epoch, generation, pressure == evsPressureBatched, settings.PathEpochBatchedDelay)
	now := self.client.clock.Now()
	if mapperStatus := self.client.epochs.mapperStatusFunction(); mapperStatus != nil {
		if state, uploaded, count, ok := mapperStatus(self.repoId, refId); ok {
			status.State, status.PartsUploaded, status.PartCount = state, uploaded, count
			return status, nil
		}
	}
	switch {
	case settings.PathEpochMaxSourceCount <= len(status.Sources),
		pressure == evsPressureBatched && settings.PathEpochBatchedMaxSourceCount <= len(status.Sources):
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
// generation, immediate at once and batched batchedDelay after (EvsSettings.PathEpochBatchedDelay, 24 h); zero when
// neither is known.
func (self *evsClientEpochs) dueBy(repoId Id, epoch *protocol.EvsPathEpoch, generation uint64, batched bool, batchedDelay time.Duration) time.Time {
	if evsCurrentEpoch(epoch) < epoch.GetDueGeneration() && epoch.GetDueByMs() != 0 {
		return time.UnixMilli(epoch.GetDueByMs())
	}
	held := self.heldRemovalSince(repoId, generation)
	if held.IsZero() || !batched {
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
// a due whose due_by_ms, or for a REMOVE generation the head has not recorded the time this device first held it
// (PathEpochBatchedDelay after that when pressure classed the crossing batched), is over EpochOverdueAfter past, at most
// once per ref and due generation in EpochOverdueAlarmInterval; not while the due is batched and the head lists
// PathEpochBatchedMaxSourceCount sources, nor within EpochOverdueAfter of the first head after that with fewer. A head showing such a due asks the mapper a tick (DESIGN-DETAILS 9.2.7's verified
// head), once per version. Then wakes whatever waits on the ref's epoch.
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
	} else if held, since, heldBatched := self.newestHeldRemoval(repoId, max(current, head.GetGeneration())); held != 0 {
		// a removal this device holds that no head records yet, as pressure last classed the crossing to it: due at
		// once when immediate, PathEpochBatchedDelay after it was first held when batched, as evs would record it
		generation, dueBy, batched = held, since, heldBatched
		if heldBatched {
			dueBy = since.Add(client.settings.PathEpochBatchedDelay)
		}
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
		case batched && client.settings.PathEpochBatchedMaxSourceCount <= sourceCount:
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

// The newest REMOVE generation of a repo this device noted above from, when it first held it, and whether pressure
// last classed the crossing to it batched; 0 for none.
func (self *evsClientEpochs) newestHeldRemoval(repoId Id, from uint64) (uint64, time.Time, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	newest, held := uint64(0), evsHeldRemoval{}
	for key, removal := range self.heldRemovals {
		if key.repoId == repoId && from < key.generation && newest < key.generation {
			newest, held = key.generation, removal
		}
	}
	return newest, held.since, held.batched
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
