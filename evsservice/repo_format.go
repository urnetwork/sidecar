// repo/'s format and its raise (§11.6's format row, D-EVS-39, FS-72; EVS2-M10-05): a repo is always created at
// format 1 (plan-EVS2-small-readings#11), and its first push carrying a format-2 value, from a network in §19.11's
// format2 gate, raises it by one If-Match on repo/ changing only `format`, after step 6's record and before step 7
// (push_commit.go). Nothing lowers it, and a raise whose push then fails stands: format-1 data is valid format 2.
//
// The raise is a lifecycle transition (repo_state.go): it reads repo/ from the cluster, decides, and writes If-Match
// that read's ETag; on a 412 it reads again and decides again, so two racing raises make one write and the loser
// finds format 2; an answer lost on the way back reads again too. A repo it finds in any state but active refuses by
// 5c's rule, since no push commits on it: keying 409 REPO_KEYING, deleted 409 REPO_DELETED, each recorded, shredding or
// shredded 409 SHREDDING, final. The state machine keeps every field the raise does not change, so a raise never
// revives a deleted repo and a RepoDelete or a shred racing it keeps its own deletion.
//
// It is P1 work priced with its push: the caller issues it under the push's grant. Its barriers are
// evs.migrate.raise.before and .after, around the whole transition, keyed by the repo.

package evsservice

import (
	"context"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The raise: see the file header. The answer is repo/ as written, or as read when it already stood at format 2; an
// *EvsRepoRefusal for a repo not active, ErrEvsRepoBusy past retryCount races. classify gives the ctx the write is
// issued under, its class paid.
func RaiseRepoFormat(ctx context.Context, cluster sidecar.BlobCluster, repos *RepoCache, repoId sidecar.Id, retryCount int, classify func(ctx context.Context, objectByteCount int) context.Context) (*EvsRepoRead, error) {
	barrierKey := barrierRepoKey(repoId)
	testHookBarrier(BarrierMigrateRaiseBefore, barrierKey)
	defer testHookBarrier(BarrierMigrateRaiseAfter, barrierKey)
	return transitionRepo(ctx, cluster, repos, repoId, retryCount, classify, decideRaiseFormat())
}

// The raise's decision: active at format 1 to active at format 2, changing nothing else; active at format 2 or past
// it done; any other state its refusal, since no push commits on it.
func decideRaiseFormat() repoDecide {
	return func(read *EvsRepoRead) (*protocol.EvsRepoObject, error) {
		object := read.Object
		if refusal := repoStateRefusal(object); refusal != nil {
			return nil, refusal
		}
		if sidecar.EvsRepoFormat2 <= object.GetFormat() {
			return nil, nil
		}
		next := cloneEvsRepoObject(object)
		next.Format = sidecar.EvsRepoFormat2
		return next, nil
	}
}
