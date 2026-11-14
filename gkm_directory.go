// The team directory's group (KEYS-M6-01; R-KEYS-11, D-KEYS-2, D-KEYS-23, I-15; §10.9's Directory group rows, owner
// decisions 113, 144, 182): a team's directory repo has its own MLS group, ur_group kind directory with no
// owner_member_id, under §7.9's leaves rule, which gkm_seats.go holds for the config group and this group reuses as
// it stands: the first SeatCount live member devices are leaves, and later ones and agents read by wraps.
//
//	committers  every admitted sidecar reads the directory and all but read_only ones write it. An admission's
//	            signer seats its subject at once by the Add row (GkmGrantingDevice, PendingCommitWait's zero); a
//	            revocation's signer commits a leaf target's Remove, then the rotation (the pending engine's order);
//	            after the reap of an uncovered ephemeral agent the device that signed its admission rotates
//	            (gkm_verify_rotation.go). Any other writer leaf commits only from the pending engine its driver
//	            runs PendingCommitDelay plus jitter after its hint, never from a write
//	hints       gkm hints pending, and a first KeyPackage upload's hint, only to the signer of the statement and to
//	            the config writers, and late-wrap hints to the config writers (gkmservice/directory.go), since
//	            hinting every writer races rotations that each stage about 1.3 KB a wrapped reader
//	unhinted    a writer no hint reached learns of a shrink when the gate refuses its push, and comes here through
//	            EnsureWritable: while the newest generation it holds does not cover its state it waits a random
//	            time of up to DirectoryRotateWait, which a covering generation ends, then takes what gkm holds and
//	            rotates alone, by its leaf_wrap or by wraps, only if no covering generation stands. One rotator
//	            normally stages a rotation's wraps, a writer whose wait a covering generation ended stages nothing,
//	            and the gate reopens within the wait and one rotation of the first refused push
//
// The wait runs outside the group's flow, so the hint work that brings the covering generation is not held behind
// it; it reads only the keychain. A read_only device, a reader and a device with no state wait for nothing: the flow
// answers them as it answers any repo's.
//
// A reading: a SCHEDULE rotation of the directory group waits the same way, since every writer finds it due at the
// same time.
//
// Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// A directory repo's row that names an owner: the team directory is no member's.
var ErrGkmDirectoryOwned = errors.New("gkm: a directory repo with an owner")

// Whether a repo's group is a team directory's.
func GkmDirectoryGroup(repo *protocol.AclRepo) bool {
	return repo != nil && repo.GetKind() == protocol.RepoKind_REPO_KIND_DIRECTORY
}

// What a directory repo's row must hold before this device forms or drives its group: kind directory with no
// owner_member_id, as its ur_group extension carries them (owner decision 182). Nil for any other kind's row.
func GkmDirectoryRepoCheck(repo *protocol.AclRepo) error {
	if !GkmDirectoryGroup(repo) {
		return nil
	}
	if len(repo.GetOwnerMemberId()) != 0 {
		return fmt.Errorf("%w: repo %x", ErrGkmDirectoryOwned, repo.GetRepoId())
	}
	return nil
}

// Who waits for a repo's next held generation. Safe for concurrent use.
type gkmGenerationWaits struct {
	stateLock     sync.Mutex
	repoIdSignals map[Id]chan struct{}
}

// A channel closed when the repo next holds a generation.
func (self *gkmGenerationWaits) signal(repoId Id) <-chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.repoIdSignals == nil {
		self.repoIdSignals = map[Id]chan struct{}{}
	}
	signal, ok := self.repoIdSignals[repoId]
	if !ok {
		signal = make(chan struct{})
		self.repoIdSignals[repoId] = signal
	}
	return signal
}

// The repo holds a generation it did not, or more of one: every waiter looks again.
func (self *gkmGenerationWaits) held(repoId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if signal, ok := self.repoIdSignals[repoId]; ok {
		close(signal)
		delete(self.repoIdSignals, repoId)
	}
}

// Whether this device is a standing writer of a directory repo at its newest state that is not read_only: the
// devices the unhinted row's wait is for. False for a row the flow refuses.
func (self *gkmGroupManager) directoryWriter() bool {
	client := self.client
	state, err := client.currentState()
	if err != nil {
		return false
	}
	repo := state.Repo(self.repoId)
	if !GkmDirectoryGroup(repo) || GkmDirectoryRepoCheck(repo) != nil {
		return false
	}
	row := state.SidecarRow(client.args.SidecarId)
	return gkmRowStanding(row) && !gkmRowReadOnly(row) && gkmWrites(state, self.repoId, client.args.SidecarId)
}

// Whether a rotation of the repo is due by what the keychain holds, with the group's flow taken for the read, and
// whether the keychain holds a generation of it at all. With take, what gkm holds past the keychain is taken first;
// a take that fails leaves the answer to the flow, which meets the same failure.
func (self *gkmGroupManager) directoryRotationDue(ctx context.Context, take bool) (held bool, due bool) {
	self.flowLock.Lock()
	defer self.flowLock.Unlock()
	state, err := self.client.currentState()
	if err != nil {
		return false, false
	}
	if take {
		if err := self.takeGenerationsInFlow(ctx, state); err != nil {
			return true, false
		}
	}
	_, due, err = self.rotationDueInFlow(state)
	if err != nil {
		return !errors.Is(err, ErrGkmKeyMissing), false
	}
	return true, due
}

// The unhinted row's wait, before EnsureWritable's flow and outside it: see the file header. Nil at once for a repo
// that is no directory, for a device that is no writer of it, and while no rotation is due by what this device and
// gkm hold.
func (self *gkmGroupManager) directoryRotateWait(ctx context.Context) error {
	client := self.client
	if !self.directoryWriter() {
		return nil
	}
	signal := client.generationWaits.signal(self.repoId)
	if held, due := self.directoryRotationDue(ctx, false); held && !due {
		return nil
	}
	// the keychain's newest generation does not cover, or it holds none: a covering one gkm holds needs no wait
	if _, due := self.directoryRotationDue(ctx, true); !due {
		return nil
	}
	wait := client.jitter(client.settings.DirectoryRotateWait)
	if wait <= 0 {
		return ctx.Err()
	}
	if client.log.V(1).Enabled() {
		client.log.Infof("[gkm]the directory group's gate is closed, waiting %s before rotating", wait)
	}
	timer := client.clock.After(wait)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer:
			return nil
		case <-signal:
		}
		// a generation was held: a covering one ends the wait
		signal = client.generationWaits.signal(self.repoId)
		if _, due := self.directoryRotationDue(ctx, false); !due {
			return nil
		}
	}
}

// EnsureWritable's steps 2 and 3 in a directory group, with gkm reachable: this device takes the epochs past its
// own and the newest generation, commits nothing, and rotates alone if a rotation is still due. A leaf that waits,
// on a resync or on another leaf's Remove, still rotates, by wraps (R5).
func (self *gkmGroupManager) directoryRotateInFlow(ctx context.Context, state GkmAuthView) error {
	client := self.client
	err := self.syncEpochsInFlow(ctx, state)
	if err == nil {
		err = self.openNewestInFlow(ctx, state)
	}
	if err != nil && !gkmLeafWaits(err) && !errors.Is(err, ErrGkmNotWriter) {
		return err
	}
	cause, due, err := self.rotationDueInFlow(state)
	if err != nil || !due {
		return err
	}
	if client.log.V(1).Enabled() {
		client.log.Infof("[gkm]no covering generation of the directory group stands, rotating for cause %d", cause)
	}
	if _, err := self.rotateInFlow(ctx, cause); err != nil && !gkmLeafWaits(err) && !errors.Is(err, ErrGkmNotWriter) && !errors.Is(err, ErrGkmAuthAhead) {
		return err
	}
	return nil
}
