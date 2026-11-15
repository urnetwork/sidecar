//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// A git-mode ref's pin push (DESIGN-DETAILS 16.2.9, 8.2.10 as amended; QD-802; EVS1-M6-05): the UPDATE of one tip, E,
// with old_tip = new_tip = E and no FORCE, commit, blob, tag, source or change, built on the version b and chain C_b
// replay applied, under the ref's publish lock P_r, on a device that mounts the repo. It is EvsLocalPublish with the
// same oid for the old and the new tip, which carries nothing and states no net change, and it moves no local ref:
// replay applies its version as one that moves no tip.
//
//	refs     a shared branch that has a tip and is not stopped on this device. A tag ref takes no second push and
//	         holds no file; a deleted ref, or one with no tip, takes no UPDATE and is bound from the push that
//	         re-creates it, whose pin evs holds (QD-803); a stopped ref is bound by its recovery, whose DELETE and
//	         re-creating push carry the admin's pin. Each answers its skip, and nothing is sent
//	locks    M shared, then P_r, then L_r for the read of EvsGitRef alone, as an owned ref's queue takes them
//	         (8.2.9); replay runs first, so the push is built on the newest version this mount applied
//	journal  none: no git client waits on the push. A crash after the POST leaves a commitless version that the
//	         next replay applies like any other, and the filer's pin journal sends again if it never committed
//
// Desktop legs only. Safe for concurrent use: the publish lock makes one device's pushes to one ref take turns.

package sidecar

import (
	"bytes"
	"context"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// evsLocalPinPusher's pinPush: the mount of repoId's.
func (self *EvsMounts) pinPush(ctx context.Context, repoId Id, refId Id) (*EvsPinPushResult, error) {
	mount := func() *EvsLocalRepo {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.repoIdMounts[repoId]
	}()
	if mount == nil || mount.Receiver() == nil {
		return nil, ErrEvsPinPushNoMount
	}
	return mount.Receiver().pinPush(ctx, refId)
}

// evsLocalPinPusher's pinStopped: the ref's record on the mount of repoId says a check refused a version of it.
func (self *EvsMounts) pinStopped(repoId Id, refId Id) bool {
	mount := func() *EvsLocalRepo {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.repoIdMounts[repoId]
	}()
	if mount == nil || mount.sync == nil {
		return false
	}
	ref, err := mount.sync.state.gitRef(refId)
	return err == nil && ref.StuckAt != 0
}

// The pin push of one ref of the receiver's mount: see the file header.
func (self *EvsGitReceiver) pinPush(ctx context.Context, refId Id) (*EvsPinPushResult, error) {
	releaseUpkeep, err := self.mount.locks.LockUpkeepShared(ctx)
	if err != nil {
		return nil, err
	}
	defer releaseUpkeep()
	releasePublish, err := self.mount.locks.LockPublish(ctx, refId)
	if err != nil {
		return nil, err
	}
	defer releasePublish()
	if err := self.engine.Replay(ctx, refId); err != nil {
		return nil, err
	}
	var record *EvsGitRef
	var skipped EvsPinPushSkip
	err = self.withApply(ctx, refId, func() error {
		ref, err := self.engine.state.gitRef(refId)
		if err != nil {
			return err
		}
		switch {
		case ref.Version == 0:
			skipped = EvsPinPushSkipNoHead
		case ref.Kind != protocol.EvsRefKind_EVS_REF_SHARED:
			return fmt.Errorf("%w: a pin push goes to a shared ref", ErrEvsWriteInvalid)
		case ref.Mode != protocol.EvsRefMode_EVS_REF_GIT:
			return fmt.Errorf("%w: a file-mode ref's pin push is a statement with no change", ErrEvsWriteInvalid)
		case bytes.HasPrefix(ref.Name, []byte(evsGitTagRefPrefix)):
			skipped = EvsPinPushSkipTag
		case ref.Deleted:
			skipped = EvsPinPushSkipDeleted
		case ref.Tip == nil:
			skipped = EvsPinPushSkipNoHead
		case ref.StuckAt != 0:
			skipped = EvsPinPushSkipStopped
		default:
			record = ref
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if record == nil {
		return &EvsPinPushResult{Skipped: skipped}, nil
	}
	result, err := EvsLocalPublish(ctx, &EvsLocalPublishArgs{
		Mount: self.mount, Repo: self.repo, RefName: record.Name, Old: record.Tip, New: record.Tip,
		BaseVersion: record.Version, BaseChain: record.Chain, Base: record.Base, State: self.engine, OwnClient: self.ownClient(),
	})
	if err != nil {
		return nil, err
	}
	if err := self.engine.Replay(ctx, refId); err != nil {
		return nil, err
	}
	return &EvsPinPushResult{PushId: result.PushId, Version: result.Version}, nil
}
