// repo/'s lifecycle on evs (§11.12's deletion rows, D-EVS-19; EVS1-M2-19): the If-Match transitions that the routes
// (repo.go), the shred (shred.go) and the reconciler (reconcile.go) write, on the root's state machine
// (evs_repo_state.go).
//
// A transition reads repo/ from the cluster, never the cache, decides from what it read, and writes If-Match that
// read's ETag; a 412 reads again and decides again, at most RepoTransitionRetryCount times. An answer lost on the way
// back reads again too: §19.6's settle rule orders that read after the write, which landed or never will, so each
// decision answers the state it reads, and one that finds its own target state there answers done. That makes every
// transition idempotent, which a retried route and a rerun job both need.
//
// Each write's class is its caller's: P0 lifecycle for DELETE and restore, P0 shred for the shred's own steps, and P1
// for activate, which its route pays before it calls (plan-EVSB-write-classes).

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A lifecycle answer that refuses, with the code §11.20 gives it.
type EvsRepoRefusal struct {
	Code   protocol.EvsRefusalCode
	Reason string
}

// The code and why.
func (self *EvsRepoRefusal) Error() string {
	return fmt.Sprintf("evs repo lifecycle refused %s: %s", self.Code, self.Reason)
}

// A refusal with code.
func newEvsRepoRefusal(code protocol.EvsRefusalCode, format string, args ...any) *EvsRepoRefusal {
	return &EvsRepoRefusal{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// A transition that lost RepoTransitionRetryCount races, or as many lost answers: 429 BUSY on a route, a retry for a
// job. It wrote nothing that stands as its own.
var ErrEvsRepoBusy = errors.New("evs repo transition busy")

// The refusal §11.12's refused row gives a route that works only on an active repo, for a repo/ in another state:
// keying 409 REPO_KEYING, deleted 409 REPO_DELETED, shredding and shredded 409 SHREDDING. nil for active.
func repoStateRefusal(object *protocol.EvsRepoObject) *EvsRepoRefusal {
	switch object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_ACTIVE:
		return nil
	case protocol.EvsRepoState_EVS_REPO_KEYING:
		return newEvsRepoRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_REPO_KEYING, "repo/ keying")
	case protocol.EvsRepoState_EVS_REPO_DELETED:
		return newEvsRepoRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED, "repo/ deleted")
	}
	return newEvsRepoRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING, "repo/ %s", object.GetState())
}

// What a transition decides from the repo/ it read: the object to write, or nil and nil for done with nothing to
// write, or an error, an *EvsRepoRefusal for an answer that refuses.
type repoDecide func(read *EvsRepoRead) (*protocol.EvsRepoObject, error)

// The deletion repo/ names, false for none.
func evsRepoDeletionId(object *protocol.EvsRepoObject) (sidecar.Id, bool) {
	deletionId, err := sidecar.IdFromBytes(object.GetDeletionId())
	return deletionId, err == nil
}

// Whether repo/ names deletionId.
func evsRepoNamesDeletion(object *protocol.EvsRepoObject, deletionId sidecar.Id) bool {
	named, ok := evsRepoDeletionId(object)
	return ok && named == deletionId
}

// A copy of a repo/ object to build the next write on.
func cloneEvsRepoObject(object *protocol.EvsRepoObject) *protocol.EvsRepoObject {
	return proto.Clone(object).(*protocol.EvsRepoObject)
}

// One transition's run: see the file header. classify gives the ctx each write is issued under, its class paid. The
// answer is repo/ as written, or as read when the decision wrote nothing.
func transitionRepo(ctx context.Context, cluster sidecar.BlobCluster, repos *RepoCache, repoId sidecar.Id, retryCount int, classify func(ctx context.Context, objectByteCount int) context.Context, decide repoDecide) (*EvsRepoRead, error) {
	barrierKey := barrierRepoKey(repoId)
	for attempt := 0; ; attempt += 1 {
		read, err := repos.ReadFresh(ctx, cluster, repoId)
		if err != nil {
			return nil, err
		}
		next, err := decide(read)
		if err != nil || next == nil {
			return read, err
		}
		if err := sidecar.CheckEvsRepoTransition(read.Object, next); err != nil {
			return nil, err
		}
		nextBytes, err := sidecar.MarshalEvsRepoObject(next)
		if err != nil {
			return nil, err
		}
		testHookBarrier(BarrierRepoCasBefore, barrierKey)
		etag, err := cluster.PutIfMatch(classify(ctx, len(nextBytes)), RepoKey(repoId), read.Etag, nextBytes, nil)
		testHookBarrier(BarrierRepoCasAfter, barrierKey)
		repos.Forget(repoId)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			return &EvsRepoRead{Object: next, Etag: etag, ReadAt: read.ReadAt}, nil
		case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
			// another write came first, or this one's answer was lost: the next read decides again
			if retryCount <= attempt {
				return nil, ErrEvsRepoBusy
			}
		default:
			return nil, err
		}
	}
}

// activate's decision (§11.20's activate row): keying to active at at, active done, any later state its refusal.
// groupReady runs only for a keying repo, since it reads gkm's objects: false refuses 409 GROUP_NOT_READY.
func decideActivate(groupReady func() (bool, error), at time.Time) repoDecide {
	return func(read *EvsRepoRead) (*protocol.EvsRepoObject, error) {
		object := read.Object
		switch object.GetState() {
		case protocol.EvsRepoState_EVS_REPO_ACTIVE:
			return nil, nil
		case protocol.EvsRepoState_EVS_REPO_KEYING:
		default:
			return nil, repoStateRefusal(object)
		}
		ready, err := groupReady()
		if err != nil {
			return nil, err
		}
		if !ready {
			return nil, newEvsRepoRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_GROUP_NOT_READY, "no GroupForm or no gen/1")
		}
		next := cloneEvsRepoObject(object)
		next.State = protocol.EvsRepoState_EVS_REPO_ACTIVE
		next.StateMs = at.UnixMilli()
		return next, nil
	}
}

// DELETE's decision (§11.12's delete and refused rows) on the projection's newest RepoDelete, which the route has held
// to its own now: an active repo goes to deleted{its id, its entry's time and signer}, or with now straight to
// shredding{its id, at}; a deleted one under a newer RepoDelete{now} to shredding; the deletion repo/
// already shows is done, a retry's answer; a keying repo refuses REPO_KEYING, a deleted one under any other RepoDelete
// REPO_DELETED, and a repo shredding or shredded for another deletion SHREDDING. An active repo's deleted state names
// the entry's time and signer, so a projection that no longer tells either refuses STATEMENT_MISSING and writes no
// guessed value: rows date a RepoDelete on any day (QD-743), and its signer only the entry names.
func decideDelete(deletion *EvsRepoDeletionFacts, at time.Time) repoDecide {
	return func(read *EvsRepoRead) (*protocol.EvsRepoObject, error) {
		object := read.Object
		sameDeletion := evsRepoNamesDeletion(object, deletion.DeletionId)
		next := cloneEvsRepoObject(object)
		next.DeletionId = deletion.DeletionId.Bytes()
		// shredding's time is the transition's, which step 1's wait counts from
		next.StateMs = at.UnixMilli()
		next.StateSigner = nil
		switch object.GetState() {
		case protocol.EvsRepoState_EVS_REPO_KEYING:
			return nil, repoStateRefusal(object)
		case protocol.EvsRepoState_EVS_REPO_ACTIVE:
			if deletion.Now {
				next.State = protocol.EvsRepoState_EVS_REPO_SHREDDING
			} else {
				if deletion.Time.IsZero() || deletion.SignerSidecarId == (sidecar.Id{}) {
					return nil, newEvsRepoRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING, "the projection no longer names the RepoDelete's time and signer")
				}
				next.State = protocol.EvsRepoState_EVS_REPO_DELETED
				next.StateMs = deletion.Time.UnixMilli()
				next.StateSigner = deletion.SignerSidecarId.Bytes()
			}
			return next, nil
		case protocol.EvsRepoState_EVS_REPO_DELETED:
			switch {
			case sameDeletion && !deletion.Now:
				return nil, nil
			case deletion.Now:
				next.State = protocol.EvsRepoState_EVS_REPO_SHREDDING
				return next, nil
			}
			return nil, repoStateRefusal(object)
		}
		if sameDeletion {
			return nil, nil
		}
		return nil, repoStateRefusal(object)
	}
}

// restore's decision (§11.12's restore row) on the projection's newest RepoDelete, which the route has held to a
// projected RepoRestore of it: deleted under that deletion to active at at; active done, the restore having landed; a repo
// past deleted 409 SHREDDING; keying REPO_KEYING; deleted under another deletion STATEMENT_MISSING, since no restore
// of the deletion repo/ shows is projected.
func decideRestore(deletion *EvsRepoDeletionFacts, at time.Time) repoDecide {
	return func(read *EvsRepoRead) (*protocol.EvsRepoObject, error) {
		object := read.Object
		switch object.GetState() {
		case protocol.EvsRepoState_EVS_REPO_ACTIVE:
			return nil, nil
		case protocol.EvsRepoState_EVS_REPO_DELETED:
		default:
			return nil, repoStateRefusal(object)
		}
		if !evsRepoNamesDeletion(object, deletion.DeletionId) {
			return nil, newEvsRepoRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING, "no RepoRestore of the deletion repo/ shows")
		}
		next := cloneEvsRepoObject(object)
		next.State = protocol.EvsRepoState_EVS_REPO_ACTIVE
		next.DeletionId = nil
		next.StateSigner = nil
		next.StateMs = at.UnixMilli()
		return next, nil
	}
}

// The shred's start (§11.12's start row): deleted under deletionId to shredding{deletionId, at}, which restore can
// no longer undo; shredding or shredded under it done; any other state or deletion a stale job's, which writes
// nothing and refuses SHREDDING or the state's own refusal, so the caller ends without deleting.
func decideStartShred(deletionId sidecar.Id, at time.Time) repoDecide {
	return func(read *EvsRepoRead) (*protocol.EvsRepoObject, error) {
		object := read.Object
		if !evsRepoNamesDeletion(object, deletionId) {
			return nil, newEvsRepoRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING, "repo/ shows another deletion")
		}
		switch object.GetState() {
		case protocol.EvsRepoState_EVS_REPO_SHREDDING, protocol.EvsRepoState_EVS_REPO_SHREDDED:
			return nil, nil
		case protocol.EvsRepoState_EVS_REPO_DELETED:
		default:
			return nil, repoStateRefusal(object)
		}
		next := cloneEvsRepoObject(object)
		next.State = protocol.EvsRepoState_EVS_REPO_SHREDDING
		next.StateSigner = nil
		next.StateMs = at.UnixMilli()
		return next, nil
	}
}

// The shred's last step (§11.12's phase 7): shredding under deletionId to the shredded tombstone; shredded under it
// done; any other a stale job's refusal.
func decideFinishShred(deletionId sidecar.Id, at time.Time) repoDecide {
	return func(read *EvsRepoRead) (*protocol.EvsRepoObject, error) {
		object := read.Object
		if !evsRepoNamesDeletion(object, deletionId) {
			return nil, newEvsRepoRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING, "repo/ shows another deletion")
		}
		switch object.GetState() {
		case protocol.EvsRepoState_EVS_REPO_SHREDDED:
			return nil, nil
		case protocol.EvsRepoState_EVS_REPO_SHREDDING:
		default:
			return nil, repoStateRefusal(object)
		}
		next := cloneEvsRepoObject(object)
		next.State = protocol.EvsRepoState_EVS_REPO_SHREDDED
		next.StateMs = at.UnixMilli()
		return next, nil
	}
}
