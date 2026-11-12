// GET /evs/v1/repos/<id>/refs?moved_after=<push sequence> (§11.9's moved row; EVS1-M6-01): only the refs whose last
// commit raised the repo's push sequence (§11.10) past the value, from {evsh_<repo_id>}, which keeps each ref's value
// beside its head (HeadCache.PushSequences). The listing itself is GET .../refs's (refs.go): one LIST of head/<repo>/
// and every head read; the moved form then keeps the refs past the value.
//
//	all      a value from before the sequence's restart, which reads as one above the sequence now (§11.10's
//	         sequence row restarts it above every earlier value, so a value past it predates a restart that went
//	         lower), a ref the hash lacks or holds no value for, and an unreadable sequence or hash each answer every
//	         ref, as GET .../refs does, with all set
//	lost     a commit whose raise a crash lost keeps its ref's older value and shows only at the ref's next commit, so
//	         a reader also lists every ref, with no moved_after, at its first sync each UTC day (the client's rule)
//	bad      a value that does not parse is 400 INVALID
//
// A placeholder head stays absent, as GET .../refs leaves it.

package evsservice

import (
	"strconv"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The query parameter.
const evsMovedAfterParameter = "moved_after"

// The moved form's filter over a full listing: see the file header. ok false is a value that does not parse.
func movedRefs(query string, sequence uint64, sequenceRead bool, refSequences map[sidecar.Id]uint64, refSequencesRead bool, summaries []*protocol.EvsHeadSummary) ([]*protocol.EvsHeadSummary, bool, bool) {
	movedAfter, err := strconv.ParseUint(query, 10, 64)
	if err != nil {
		return nil, false, false
	}
	all := !sequenceRead || !refSequencesRead || sequence < movedAfter
	for _, summary := range summaries {
		refId, err := sidecar.IdFromBytes(summary.GetRefId())
		if err != nil {
			all = true
			break
		}
		if refSequences[refId] == 0 {
			all = true
			break
		}
	}
	if all {
		return summaries, true, true
	}
	moved := []*protocol.EvsHeadSummary{}
	for _, summary := range summaries {
		if movedAfter < summary.GetPushSequence() {
			moved = append(moved, summary)
		}
	}
	return moved, false, true
}
