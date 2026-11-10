// Key access (KEYS-M2-22; R-KEYS-3, R-KEYS-4, R-KEYS-9, D-KEYS-6, D-KEYS-8, I-1, I-15; §10.14, DESIGN-DETAILS
// 6.2.5): what the rest of a sidecar reads of a repo's keys, over the generations the keychain holds (gkm_group.go)
// and the ladder (gkm_ladder.go).
//
//	CurrentRepoKey  the newest generation this device holds a key of, from the keychain alone when it holds one, so
//	                a read never waits on a rotation or on gkm (KF7); a stale newest is still answered, and a
//	                poisoned one too, since reading what others sealed to it adds nothing. A device that holds none
//	                yet takes its first wrap. ErrGkmUnavailable with none
//	RepoKey         generation g from the keychain, else the generations gkm holds past this device's, else the
//	                ladder walked down from the newest it opened; ErrGkmKeyMissing for one it cannot reach
//	EnsureWritable  §8.12's primary control, in order:
//	                1  this device writes the repo at its state, else ErrGkmNotWriter
//	                2  it takes what gkm holds past its own generation and epoch, then commits the pending Removes
//	                   and Adds it may (the pending engine), a wrapped writer committing nothing
//	                3  it rotates when the newest generation does not cover its state's holders_shrunk_at or an
//	                   expiry, cause REMOVE, or is past ScheduleInterval, cause SCHEDULE; a leaf with a clean tree
//	                   by leaf_wrap, a wrapped writer or a dirty tree by ReaderWraps (R5)
//	                4  it refuses, ErrGkmWait, while the newest generation still does not cover at its state, with
//	                   evs's gate off too (R7), or is poisoned; ErrGkmKeyMissing while it holds no key of the newest;
//	                   ErrGkmForked while a pin of the repo is forked; and HeadStopState's stop last
//	                5  the newest generation's key
//	                Steps 2 and 3 never wait on a witness stop or a fork: a Remove, a rotation and a revocation only
//	                shrink exposure (owner decision 129). With gkm unreachable they are skipped and steps 4 and 5
//	                answer from the keychain, so writes go on while every shrink is covered and stop at the first
//	                that is not (KF7)
//	ForgetRepo      §11.12's shred: every record of the repo in the keychain, its RK_g, GenRotates, draft, pins,
//	                pending and sync records, and its group's MLS state
//
// §11.7's checkpoint signal is EvsRepoKey.Cause: a REMOVE generation's first write to each file is a full
// checkpoint (R-KEYS-3).
//
// EnsureWritable reaps in batches: a hint rotates nothing eagerly here, and whatever shrank since the newest
// generation is covered by one rotation at the next write (D-KEYS-6).

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The newest generation of the repo this sidecar holds a key of. See the file header.
func (self *GkmGroupClient) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	if !self.holdsState() {
		return nil, fmt.Errorf("%w: this process does not hold the network's state", ErrGkmUnavailable)
	}
	held, err := self.newestOpenedGeneration(repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		// nothing opened yet: a first wrap, or a delivery that came since this device last looked
		state, stateErr := self.currentState()
		if stateErr != nil {
			return nil, stateErr
		}
		if err := manager.takeGenerationsInFlow(ctx, state); err != nil {
			if gkmUnreachable(ctx, err) || errors.Is(err, ErrGkmKeyMissing) {
				return nil, fmt.Errorf("%w: no generation of the repo is held: %w", ErrGkmUnavailable, err)
			}
			return nil, err
		}
		held, err = self.newestOpenedGeneration(repoId)
		if errors.Is(err, ErrGkmKeyMissing) {
			return nil, fmt.Errorf("%w: no generation of the repo is held", ErrGkmUnavailable)
		}
	}
	if err != nil {
		return nil, err
	}
	return self.withFirst(repoId, held.key)
}

// Generation g of the repo. See the file header.
func (self *GkmGroupClient) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	if generation == 0 {
		return nil, fmt.Errorf("%w: generation 0", ErrGkmKeyMissing)
	}
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	if !self.holdsState() {
		return nil, fmt.Errorf("%w: this process does not hold the network's state", ErrGkmUnavailable)
	}
	answer := func() (*EvsRepoKey, error) {
		held, err := self.heldGeneration(repoId, generation)
		if err != nil {
			return nil, err
		}
		if held.key == nil {
			return nil, fmt.Errorf("%w: generation %d is held without its key", ErrGkmKeyMissing, generation)
		}
		return self.withFirst(repoId, held.key)
	}
	if key, err := answer(); !errors.Is(err, ErrGkmKeyMissing) {
		return key, err
	}
	// not in the keychain: past this device's newest, or below one it opened
	state, err := self.currentState()
	if err != nil {
		return nil, err
	}
	newest, err := self.newestOpenedGeneration(repoId)
	if errors.Is(err, ErrGkmKeyMissing) || err == nil && newest.generation.Rotate.GetGeneration() < generation {
		if err := manager.takeGenerationsInFlow(ctx, state); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if pins, err := self.repoPins(repoId); err == nil {
		if err := manager.walkLadderInFlow(ctx, state, pins.groupId, generation); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, ErrGkmKeyMissing) {
		return nil, err
	}
	return answer()
}

// What gkm holds past this device's generations: its first wrap for a repo it holds nothing of, else the refresh.
func (self *gkmGroupManager) takeGenerationsInFlow(ctx context.Context, state GkmAuthView) error {
	_, err := self.client.repoPins(self.repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return self.firstWrapInFlow(ctx, state)
	}
	if err != nil {
		return err
	}
	return self.refreshGenerationsInFlow(ctx, state)
}

// Whether an error of a leaf's work, its catch-up, resync or commit, leaves this device unable to act from its leaf
// for now without refusing its rotation or its write: it waits on another leaf, on a resync or on a key.
func gkmLeafWaits(err error) bool {
	return errors.Is(err, ErrGkmResyncNeeded) || errors.Is(err, ErrGkmWait) || errors.Is(err, ErrGkmCommitRefused) || errors.Is(err, ErrGkmKeyMissing)
}

// The generation new content seals to. See the file header.
func (self *GkmGroupClient) EnsureWritable(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	return manager.ensureWritableInFlow(ctx)
}

// EnsureWritable with the group's flow held.
func (self *gkmGroupManager) ensureWritableInFlow(ctx context.Context) (*EvsRepoKey, error) {
	client := self.client
	state, err := client.currentState()
	if err != nil {
		return nil, err
	}
	// 1
	if state.Repo(self.repoId) == nil {
		return nil, fmt.Errorf("%w: repo %s", ErrGkmNoRepo, self.repoId)
	}
	row := state.SidecarRow(client.args.SidecarId)
	if !gkmRowStanding(row) || gkmRowReadOnly(row) || !gkmWrites(state, self.repoId, client.args.SidecarId) {
		return nil, ErrGkmNotWriter
	}

	// 2 and 3, unless gkm cannot be reached (KF7)
	err = self.takeGenerationsInFlow(ctx, state)
	switch {
	case gkmUnreachable(ctx, err):
		if client.log.V(1).Enabled() {
			client.log.Infof("[gkm]unreachable, writing on what the keychain holds: %v", err)
		}
	case err != nil:
		return nil, err
	default:
		if err := self.commitAndRotateInFlow(ctx, state); err != nil {
			return nil, err
		}
	}

	// 4
	state, err = client.currentState()
	if err != nil {
		return nil, err
	}
	top, err := client.newestHeldGeneration(self.repoId)
	if err != nil {
		return nil, err
	}
	rotate := top.generation.Rotate
	if top.key == nil {
		return nil, fmt.Errorf("%w: no delivery of generation %d reached this device yet", ErrGkmKeyMissing, rotate.GetGeneration())
	}
	if top.poisoned {
		return nil, fmt.Errorf("%w: generation %d is poisoned, and no rotation past it stands yet", ErrGkmWait, rotate.GetGeneration())
	}
	now := client.clock.Now()
	if gate := GkmGateCheck(state, self.repoId, rotate.GetAuth(), time.UnixMilli(rotate.GetTimeMs()), now); gate != nil {
		if errors.Is(gate, ErrGkmAuthAhead) {
			return nil, gate
		}
		// R7, with evs's gate off too: nothing is sealed to a generation a non-reader holds
		return nil, fmt.Errorf("%w: %w", ErrGkmWait, gate)
	}
	if err := client.sealStopped(self.repoId); err != nil {
		return nil, err
	}
	if client.args.SealAllowed != nil {
		if err := client.args.SealAllowed(Id(rotate.GetGroupId())); err != nil {
			return nil, err
		}
	}
	// 5
	return client.withFirst(self.repoId, top.key)
}

// Steps 2 and 3 with gkm reachable: the leaf's catch-up or resync, the pending engine's commits and its rotation;
// and where this device cannot act from its leaf now, the rotation alone, by wraps, so no repo stays gated while a
// leaf waits (R5). A wait of the rotation itself is left to step 4, which refuses if the generation still does not
// cover.
func (self *gkmGroupManager) commitAndRotateInFlow(ctx context.Context, state GkmAuthView) error {
	client := self.client
	err := self.syncEpochsInFlow(ctx, state)
	if err == nil {
		// a leaf_wrap of the newest generation opens once its epoch is adopted
		err = self.openNewestInFlow(ctx, state)
	}
	if err == nil {
		err = self.runPendingInFlow(ctx)
	}
	if err == nil {
		return nil
	}
	if !gkmLeafWaits(err) && !errors.Is(err, ErrGkmNotWriter) {
		return err
	}
	if client.log.V(1).Enabled() {
		client.log.Infof("[gkm]this device's leaf waits, rotating by wraps if a rotation is due: %v", err)
	}
	cause, due, err := self.rotationDueInFlow(state)
	if err != nil || !due {
		return err
	}
	if _, err := self.rotateInFlow(ctx, cause); err != nil && !gkmLeafWaits(err) && !errors.Is(err, ErrGkmNotWriter) && !errors.Is(err, ErrGkmAuthAhead) {
		return err
	}
	return nil
}

// Whether a rotation is due at a state by the pending engine's own rule, and its cause.
func (self *gkmGroupManager) rotationDueInFlow(state GkmAuthView) (GkmCause, bool, error) {
	client := self.client
	top, err := client.newestHeldGeneration(self.repoId)
	if err != nil {
		return 0, false, err
	}
	pending, err := GkmPendingChanges(state, &GkmPendingArgs{
		RepoId: self.repoId, Generation: top.generation, GenerationPoisoned: top.poisoned,
		SeatCount: client.settings.SeatCount, ScheduleInterval: client.settings.ScheduleInterval, Now: client.clock.Now(),
	})
	if err != nil {
		return 0, false, err
	}
	return pending.RotateCause, pending.Rotate, nil
}

// §11.12's shred. See the file header. An engine that cannot drop a group's state leaves the shred undone here,
// with an error, rather than read as done.
func (self *GkmGroupClient) ForgetRepo(ctx context.Context, repoId Id) error {
	if !self.holdsState() {
		return fmt.Errorf("%w: this process does not hold the network's state", ErrGkmUnavailable)
	}
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	pins, err := self.repoPins(repoId)
	if err != nil && !errors.Is(err, ErrGkmKeyMissing) {
		return err
	}
	if err == nil && self.args.Mls != nil {
		forgetter, ok := self.args.Mls.(MlsGroupForgetter)
		if !ok {
			return fmt.Errorf("%w: this engine drops no group's state", ErrGkmUnavailable)
		}
		if err := forgetter.ForgetGroup(pins.groupId); err != nil {
			return err
		}
	}
	names, err := self.args.Secrets.List(gkmRepoRecordName(repoId, ""))
	if err != nil {
		return err
	}
	// the pins last: a shred a kill cut short is found again by them and finished
	pinsName := gkmRepoRecordName(repoId, "pins")
	for _, name := range names {
		if name == pinsName {
			continue
		}
		if err := self.args.Secrets.Delete(name); err != nil {
			return err
		}
	}
	if err := self.args.Secrets.Delete(pinsName); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.repoIdHeads, repoId)
	delete(self.repoIdWantAskedAt, repoId)
	return nil
}
