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
	"fmt"

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

// EVS1-M2-08: the head and its cache (§11.8, §11.9), keyed by <repo>:<ref>, and batches, keyed by the batch.
const (
	// Around a cluster GET of a head.
	BarrierHeadReadBefore = "evs.head.read.before"
	BarrierHeadReadAfter  = "evs.head.read.after"
	// Around a head's If-Match or If-None-Match: the commit point of every push and the fence of every write that
	// commits nothing.
	BarrierHeadCasBefore = "evs.head.cas.before"
	BarrierHeadCasAfter  = "evs.head.cas.after"
	// Around {evsh_}'s write after a commit.
	BarrierHeadCacheWriteBefore = "evs.head.cache_write.before"
	BarrierHeadCacheWriteAfter  = "evs.head.cache_write.after"
	// Around a batch's PUT: every record waiting on it is in flight here.
	BarrierBatchPutBefore = "evs.batch.put.before"
	BarrierBatchPutAfter  = "evs.batch.put.after"
)

// A repo's barrier key.
func barrierRepoKey(repoId sidecar.Id) string {
	return sidecar.EvsKeyId(repoId)
}

// A ref's barrier key: <repo>:<ref>.
func barrierRefKey(repoId sidecar.Id, refId sidecar.Id) string {
	return sidecar.EvsKeyId(repoId) + ":" + sidecar.EvsKeyId(refId)
}

// A batch's barrier key: <minute>-<instance>-<seq> in hex, unique as its key is.
func barrierBatchKey(minute uint32, instance uint32, seq uint32) string {
	return fmt.Sprintf("%08x-%08x-%08x", minute, instance, seq)
}
