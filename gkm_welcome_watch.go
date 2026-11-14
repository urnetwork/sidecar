// The Welcome watches of the pending engine (§10.6's Welcomes row, QD-747; gkm_members.go's header): the Adds this
// device adopted from other leaves' commits, kept in the repo's pending record until gkm has said whether each
// epoch's Welcome stands.
//
//	note   a commit adopted, this device's or another's: a watched joiner that committed it has joined, and one it
//	       removed is no longer that epoch's leaf, so both leave their watches; another leaf's Adds start a watch,
//	       where this device may re-add at its state, due WelcomeTimeout after the epoch's time, which is never past
//	       this device's clock, so a stamp a server chose postpones no ask
//	ask    once per watch, when due and when this device still may re-add: 200 ends the watch; 404 marks its
//	       joiners Unwelcomed for Pending; a refusal ends it, since gkm will not tell this device; no answer leaves
//	       it due
//	valid  the watches hold only while this device's group is the one they name at the epoch they were last noted
//	       at: a join, a resync or a re-form reaches an epoch by no commit this device saw, and it forgets them
//
// Only a writer watches and asks: gkm answers the route under rw, and a leaf that may not commit the Add would leave
// a Remove no member accepts. Forgetting a watch is always safe: the joiner waits on its uploader, as before QD-747.
//
// A timer under AttachHints' ctx runs the engine when the next watch falls due, one per repo; without hints attached
// the engine asks whenever its driver next runs it, and the hint intake's resync covers a timer a restart lost.

package sidecar

import (
	"context"
	"slices"
	"time"
)

// A watch's flag in the pending record: gkm answered that no Welcome stands.
const gkmWelcomeWatchUnwelcomed = 1 << 0

// One epoch's Adds, which another leaf committed, as this device watches for their Welcome.
type gkmWelcomeWatch struct {
	epoch uint64
	// the epoch's time as this device took it, at most its own clock at the adoption: WelcomeTimeout runs from it
	timeMs int64
	// gkm answered 404: the joiners are removed and added again
	unwelcomed bool
	// the joiners still on the leaves the epoch added
	sidecarIds []Id
}

// When the watch's one ask falls due.
func (self *gkmWelcomeWatch) dueTime(settings *GkmSettings) time.Time {
	return time.UnixMilli(self.timeMs).Add(max(settings.WelcomeTimeout, 0))
}

// Whether this sidecar may remove and add a joiner again from its leaf at a state: a standing member device that is
// not read_only and writes the repo, the right gkm answers the ask under and the one that commits both halves.
func (self *gkmGroupManager) mayReadd(state GkmAuthView) bool {
	sidecarId := self.client.args.SidecarId
	row := state.SidecarRow(sidecarId)
	return gkmRowStanding(row) && gkmRowMemberDevice(row) && !gkmRowReadOnly(row) && gkmWrites(state, self.repoId, sidecarId)
}

// The record's watches as they hold for the group at an epoch: none where the record names another group or epoch.
func (self *gkmPendingRecord) watchesAt(groupId Id, epoch uint64) []*gkmWelcomeWatch {
	if self.watchGroupId != groupId || self.watchEpoch != epoch {
		return nil
	}
	return self.welcomeWatches
}

// A commit this device adopted, at the file header's note: committerId made it, epochTime is its epoch object's
// time, or this device's clock for its own, added its Adds and removed its Removes as they stood in the old epoch.
// This device's own Adds start no watch: it owes their Welcome itself (oweWelcome).
func (self *gkmGroupManager) noteWelcomeWatches(state GkmAuthView, groupId Id, epoch uint64, epochTime time.Time, committerId Id, added []MlsMember, removed []MlsMember) error {
	client := self.client
	record, err := self.pendingRecord()
	if err != nil {
		return err
	}
	had := 0 < len(record.welcomeWatches)
	watches := []*gkmWelcomeWatch{}
	if 0 < epoch {
		for _, watch := range record.watchesAt(groupId, epoch-1) {
			watch.sidecarIds = slices.DeleteFunc(watch.sidecarIds, func(sidecarId Id) bool {
				return sidecarId == committerId || slices.ContainsFunc(removed, func(member MlsMember) bool { return member.SidecarId == sidecarId })
			})
			if 0 < len(watch.sidecarIds) {
				watches = append(watches, watch)
			}
		}
	}
	started := false
	if committerId != client.args.SidecarId && 0 < len(added) && self.mayReadd(state) {
		watch := &gkmWelcomeWatch{epoch: epoch}
		now := client.clock.Now()
		if epochTime.After(now) {
			epochTime = now
		}
		watch.timeMs = epochTime.UnixMilli()
		for _, member := range added {
			if member.SidecarId != client.args.SidecarId {
				watch.sidecarIds = append(watch.sidecarIds, member.SidecarId)
			}
		}
		if 0 < len(watch.sidecarIds) {
			watches = append(watches, watch)
			started = true
		}
	}
	// the newest are kept: an old watch dropped unasked leaves its joiners waiting on their uploader
	if maxCount := max(client.settings.WelcomeWatchMaxCount, 0); maxCount < len(watches) {
		watches = watches[len(watches)-maxCount:]
		started = started && 0 < maxCount
	}
	if !had && len(watches) == 0 {
		return nil
	}
	record.watchGroupId, record.watchEpoch, record.welcomeWatches = groupId, epoch, watches
	if err := self.putPendingRecord(record); err != nil {
		return err
	}
	if started {
		client.armWelcomeAsk(self.repoId)
	}
	return nil
}

// Forgets every watch: this device left the group, or holds it at an epoch its watches were not noted at.
func (self *gkmGroupManager) dropWelcomeWatches() error {
	record, err := self.pendingRecord()
	if err != nil {
		return err
	}
	if len(record.welcomeWatches) == 0 {
		return nil
	}
	record.welcomeWatches = nil
	return self.putPendingRecord(record)
}

// The file header's ask, for each watch due at this device's clock, with the group's flow held: the engine's step
// between its catch-up and Pending, so a re-add another leaf already committed has ended its watch before any ask.
// An ask gkm does not answer fails nothing here; the watch stays due.
func (self *gkmGroupManager) askWelcomesInFlow(ctx context.Context, state GkmAuthView, pins *gkmRepoPins) error {
	client := self.client
	record, err := self.pendingRecord()
	if err != nil {
		return err
	}
	if len(record.welcomeWatches) == 0 {
		return nil
	}
	watches := record.watchesAt(pins.groupId, pins.epoch)
	if len(watches) == 0 || !self.mayReadd(state) {
		// another route brought this device to its epoch, or it no longer writes: the joiners wait on their uploader
		record.welcomeWatches = nil
		return self.putPendingRecord(record)
	}
	now := client.clock.Now()
	kept := []*gkmWelcomeWatch{}
	changed := false
	for _, watch := range watches {
		if watch.unwelcomed || now.Before(watch.dueTime(client.settings)) {
			kept = append(kept, watch)
			continue
		}
		stands, err := client.args.Api.WelcomeStands(ctx, self.repoId, pins.groupId, watch.epoch)
		gkmError, refused := GkmErrorOf(err)
		switch {
		case err == nil && stands:
			// its joiners have their Welcome
			changed = true
		case err == nil:
			watch.unwelcomed = true
			kept = append(kept, watch)
			changed = true
		case refused && !gkmError.RefusesNothing():
			// gkm will not tell this device, whose token no longer carries rw there
			changed = true
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			if client.log.V(1).Enabled() {
				client.log.Infof("[gkm]the Welcome of epoch %d was not asked for: %v", watch.epoch, err)
			}
			kept = append(kept, watch)
		}
	}
	if changed {
		// the answer is kept before anything is committed on it: each watch is asked once
		record.welcomeWatches = kept
		if err := self.putPendingRecord(record); err != nil {
			return err
		}
	}
	if slices.ContainsFunc(kept, func(watch *gkmWelcomeWatch) bool { return !watch.unwelcomed }) {
		// a restart lost the timer of a watch not yet due
		client.armWelcomeAsk(self.repoId)
	}
	return nil
}

// The joiners gkm answered have no Welcome, for Pending's Unwelcomed, as the watches hold at the pinned epoch; none
// where this device may not re-add at the state.
func (self *gkmGroupManager) unwelcomedInFlow(state GkmAuthView, pins *gkmRepoPins) ([]Id, error) {
	record, err := self.pendingRecord()
	if err != nil {
		return nil, err
	}
	watches := record.watchesAt(pins.groupId, pins.epoch)
	if len(watches) == 0 || !self.mayReadd(state) {
		return nil, nil
	}
	unwelcomedIds := []Id{}
	for _, watch := range watches {
		if watch.unwelcomed {
			unwelcomedIds = append(unwelcomedIds, watch.sidecarIds...)
		}
	}
	return unwelcomedIds, nil
}

// When the repo's next ask falls due: the earliest watch not yet asked, as the watches hold at the pinned epoch.
// false for none.
func (self *gkmGroupManager) nextWelcomeAsk() (time.Time, bool) {
	self.flowLock.Lock()
	defer self.flowLock.Unlock()
	client := self.client
	pins, err := client.repoPins(self.repoId)
	if err != nil {
		return time.Time{}, false
	}
	record, err := self.pendingRecord()
	if err != nil {
		return time.Time{}, false
	}
	var next time.Time
	found := false
	for _, watch := range record.watchesAt(pins.groupId, pins.epoch) {
		if watch.unwelcomed {
			continue
		}
		if due := watch.dueTime(client.settings); !found || due.Before(next) {
			next, found = due, true
		}
	}
	return next, found
}

// Runs the engine when the repo's next ask falls due, and again for each after it, on one goroutine per repo under
// AttachHints' ctx; nothing without hints attached. Every writer leaf of a group watches the same epoch, so each
// waits its own PendingCommitJitter past the due time, and all but the first find the re-add already committed. A
// pass that leaves its ask still due, gkm unreachable, ends the timer rather than spin: the resync asks again.
func (self *GkmGroupClient) armWelcomeAsk(repoId Id) {
	var ctx context.Context
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ctx = self.hintsCtx
	}()
	if ctx == nil {
		return
	}
	manager := self.manager(repoId)
	self.hintWork(ctx, "welcome-ask", repoId, func() {
		for {
			due, ok := manager.nextWelcomeAsk()
			if !ok {
				return
			}
			if self.wait(ctx, due.Sub(self.clock.Now())+self.jitter(self.settings.PendingCommitJitter)) != nil {
				return
			}
			self.logFlowError("welcome ask", self.RunPending(ctx, repoId))
			if next, ok := manager.nextWelcomeAsk(); ok && !next.After(self.clock.Now()) {
				return
			}
		}
	})
}
