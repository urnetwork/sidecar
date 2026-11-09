// Every barrier evsservice calls (§22.4, §22.8): the names a fault schedule holds, listed once here so a schedule
// and the code agree. EVS1-M2-07 opened this file and each later evs task appends its own (CONTRACTS.md C-21).
//
// A name is evs.<part>.<point>, with .before and .after around a linearization point or a step a schedule orders.
// A key says which instance is held: a repo's id for a repo's step, and <repo>:<ref> for a ref's, each id in
// sidecar.EvsKeyId's form. EVS1.md writes the ref key <repo>/<ref>, but sidecartest's driver refuses a slash as a
// path (I-13), so the pair takes a colon, which its pattern allows; a batch's is its minute, instance and seq in
// hex. Keys are opaque ids, never a token path or a name.
//
// Each hook may block for as long as a schedule holds it, so none is called with a state lock held.

package evsservice

import (
	"github.com/urnetwork/sidecar"
)

// EVS1-M2-07: placement and the repo/ creation (§11.8's placement row; FS-63), keyed by the repo.
const (
	// Around place/'s If-None-Match on the first cluster: two creators race here.
	BarrierPlacePutBefore = "evs.place.put.before"
	BarrierPlacePutAfter  = "evs.place.put.after"
	// Around repo/'s If-None-Match on the placed cluster, after place/ landed.
	BarrierRepoPutBefore = "evs.repo.put.before"
	BarrierRepoPutAfter  = "evs.repo.put.after"
)

// A repo's barrier key.
func barrierRepoKey(repoId sidecar.Id) string {
	return sidecar.EvsKeyId(repoId)
}

// A ref's barrier key: <repo>:<ref>.
func barrierRefKey(repoId sidecar.Id, refId sidecar.Id) string {
	return sidecar.EvsKeyId(repoId) + ":" + sidecar.EvsKeyId(refId)
}
