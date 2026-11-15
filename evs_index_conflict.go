//go:build !ios_extension

// The index's conflicts on the real push path (§11.14's conflict and epoch rows; I-EVS-17; DESIGN-DETAILS 1.2.3's R2
// and 1.7's note for SEARCH-M10-13; SEARCH-M10-13): which refusals of a push the index writer's hook added files to
// plan the whole push again, and what evs's refusals of an index push come to as the index's own typed refusals.
//
//	head 409    a 409 PATH_CONFLICT, evs's or the planner's own, naming only the index's files: another push of this
//	            writer's, or a DROP's rewrite, changed a file of its own since the base. The push is planned again
//	            from a fresh read, which the hook reads too, so its entries are re-applied on the winner's file less
//	            the erasure set's documents: the one versionless path a client rebases, never by putting its bytes
//	            over the winner's (§11.7's writers row holds for every other)
//	content 409 a conflict naming a content path goes back to the caller as any write's does, and the index entries
//	            are rebuilt with the push when the caller writes again
//	INDEX_EPOCH a CUT moved the head's index_epoch: the push is planned again, rereading the head and the erasure set,
//	            and leaves out every document the set lists at or above its version
//
// A refusal's text names its kind and never a path (I-13). On every leg but ios_extension.

package sidecar

import (
	"errors"
	"net/http"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// Whether a push whose plan the index writer's hook added files to is planned again: see the file header. An index
// file the hook planned against that moved before the plan read it (errEvsIndexMoved) is the head 409 found before
// anything is sent.
func evsIndexRebuilds(err error, plan *EvsWritePlan) bool {
	if errors.Is(err, errEvsIndexMoved) {
		return true
	}
	if plan == nil || !plan.indexHooked {
		return false
	}
	if IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH) {
		return true
	}
	if !evsCreationConflict(err) {
		return false
	}
	refusal, _ := EvsErrorOf(err)
	if len(refusal.Paths) == 0 {
		return false
	}
	indexTokens := []EvsTokenPath{}
	for _, planned := range plan.Paths {
		if write := plan.writeOf(planned.Path); write != nil && evsIsIndexWrite(write) {
			indexTokens = append(indexTokens, planned.TokenPath)
		}
	}
	for _, tokenPath := range refusal.Paths {
		if !slices.ContainsFunc(indexTokens, tokenPath.Equal) {
			return false
		}
	}
	return true
}

// What an index push's write through EvsRepo came to, as indexRefStore's typed refusal: a path conflict, evs's or the
// planner's own, names the index paths that moved; 409 INDEX_EPOCH; a 429, retried after its wait; a quota; anything
// else as it is. The sender settles an unknown outcome by push id itself (§11.8's outcomes), so none reaches here.
func indexRefusalOfEvs(err error) error {
	if err == nil {
		return nil
	}
	var conflict *EvsPathConflictError
	if errors.As(err, &conflict) {
		return &indexRefusal{kind: indexRefusalConflict, paths: slices.Clone(conflict.Paths)}
	}
	if errors.Is(err, errEvsIndexMoved) {
		return &indexRefusal{kind: indexRefusalConflict}
	}
	evsError, ok := EvsErrorOf(err)
	if !ok {
		return err
	}
	switch evsError.Code {
	case protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH:
		return &indexRefusal{kind: indexRefusalIndexEpoch}
	case protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT:
		return &indexRefusal{kind: indexRefusalConflict}
	case protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT:
		return &indexRefusal{kind: indexRefusalQuota, retryAfter: evsError.RetryAfter}
	}
	if evsError.Status == http.StatusTooManyRequests {
		return &indexRefusal{kind: indexRefusalRetry, retryAfter: evsError.RetryAfter}
	}
	return err
}
