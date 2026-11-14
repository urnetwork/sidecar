// GET /evs/v1/repos/<id>/refs?moved_after=<push sequence> (§11.9's moved row; EVS1-M6-01): only the refs whose last
// commit raised the repo's push sequence (§11.10) past the value, from {evsh_<repo_id>}, which keeps each ref's value
// beside its head (HeadCache.PushSequences). The listing is GET .../refs's (refs.go): one LIST of head/<repo>/ names
// every ref, and the moved form reads only the heads of the refs the hash holds past the value, so a directory's
// daemon that finds a few streams moved since its last sync pays a few head reads, not one a stream (§16.11's sync
// row).
//
//	all      a value from before the sequence's restart, which reads as one above the sequence now (§11.10's
//	         sequence row restarts it above every earlier value, so a value past it predates a restart that went
//	         lower), and an unreadable sequence or hash, each answer every ref, as GET .../refs does, with all set;
//	         so does a ref the hash lacks or holds no value for once its head is read and stands, since evs cannot
//	         tell whether it moved
//	lost     a commit whose raise a crash lost keeps its ref's older value and shows only at the ref's next commit, so
//	         a reader also lists every ref, with no moved_after, at its first sync each UTC day (the client's rule)
//	bad      a value that does not parse is 400 INVALID
//
// A placeholder head stays absent, as GET .../refs leaves it.

package evsservice

import (
	"strconv"

	"github.com/urnetwork/sidecar"
)

// The query parameter.
const evsMovedAfterParameter = "moved_after"

// The moved form's value. false for one that does not parse.
func parseMovedAfter(query string) (uint64, bool) {
	movedAfter, err := strconv.ParseUint(query, 10, 64)
	return movedAfter, err == nil
}

// Which of the listed refs the moved form reads, and whether it answers every ref already: see the file header. Not
// all, the candidates are the refs past the value and those the hash holds no value for, which serveRefs reads to
// tell whether one stands.
func movedRefCandidates(movedAfter uint64, sequence uint64, sequenceRead bool, refSequences map[sidecar.Id]uint64, hashRead bool, refIds []sidecar.Id) ([]sidecar.Id, bool) {
	if !sequenceRead || !hashRead || sequence < movedAfter {
		return refIds, true
	}
	candidates := []sidecar.Id{}
	for _, refId := range refIds {
		if refSequence := refSequences[refId]; refSequence == 0 || movedAfter < refSequence {
			candidates = append(candidates, refId)
		}
	}
	return candidates, false
}
