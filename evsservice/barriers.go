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

// EVS1-M2-09: index entries (§11.7), keyed by <repo>:<ref>.
const (
	// Around an entry's GET, which §11.7's newest rule combines with the head read before it.
	BarrierEntryReadBefore = "evs.entry.read.before"
	BarrierEntryReadAfter  = "evs.entry.read.after"
	// Around the HEADs of a path's prefixes while the head lists sources (§11.6's read row).
	BarrierEntryStateBefore = "evs.entry.state.before"
	BarrierEntryStateAfter  = "evs.entry.state.after"
)

// EVS1-M2-10: folds, markers and log pages (§11.7, §11.8 step 6), keyed by <repo>:<ref>.
const (
	// Around a fold's wait for its P2 budget: FS-58's first fold held in P2's queue while a second folds its range.
	BarrierFoldAcquireBefore = "evs.fold.acquire.before"
	BarrierFoldAcquireAfter  = "evs.fold.acquire.after"
	// Around each entry write of a fold: a folded version's, a delta's or a marker's If-Match or If-None-Match, each
	// carrying the stale rule's deadline.
	BarrierFoldEntryWriteBefore = "evs.fold.entry_write.before"
	BarrierFoldEntryWriteAfter  = "evs.fold.entry_write.after"
	// Around the LIST of the current epoch's entries below a removed path, which follows the path's own marker.
	BarrierFoldListBefore = "evs.fold.list.before"
	BarrierFoldListAfter  = "evs.fold.list.after"
	// Around a page-out's log/<n> create.
	BarrierLogPagePutBefore = "evs.log_page.put.before"
	BarrierLogPagePutAfter  = "evs.log_page.put.after"
)

// EVS1-M2-12: a push's steps (§11.8), keyed by <repo>:<ref>. The head's own CAS and read keep EVS1-M2-08's names.
const (
	// An attempt that has arrived and parsed its body, before step 4: FS-113's attempt held before its handler runs,
	// while the lb's re-send is refused and recorded.
	BarrierPushArrive = "evs.push.arrive"
	// Around step 4's reads: the head, then the one round after it.
	BarrierPushStep4Before = "evs.push.step4.before"
	BarrierPushStep4After  = "evs.push.step4.after"
	// Around step 6: the record's batch write, a page-out and the new slots, before step 7 may issue.
	BarrierPushStep6Before = "evs.push.step6.before"
	BarrierPushStep6After  = "evs.push.step6.after"
	// Around one new slot's If-None-Match at step 6.
	BarrierPushSlotPutBefore = "evs.push.slot_put.before"
	BarrierPushSlotPutAfter  = "evs.push.slot_put.after"
	// Around the refuse row's recording CAS: the push's refusal fence.
	BarrierPushRefuseBefore = "evs.push.refuse.before"
	BarrierPushRefuseAfter  = "evs.push.refuse.after"
	// Around step 8, off the reply path: the sequence, hints, usage, the head cache and the fold trigger.
	BarrierPushStep8Before = "evs.push.step8.before"
	BarrierPushStep8After  = "evs.push.step8.after"
)

// EVS1-M2-19: repo/'s lifecycle (§11.12), keyed by the repo.
const (
	// Around a lifecycle transition's If-Match on repo/: a restore and a --now delete, or a restore and the 7-day
	// start, race here, and the store's order picks one.
	BarrierRepoCasBefore = "evs.repo.cas.before"
	BarrierRepoCasAfter  = "evs.repo.cas.after"
	// Around each step of a shred (shred.go): a schedule kills the worker at each.
	BarrierShredStepBefore = "evs.shred.step.before"
	BarrierShredStepAfter  = "evs.shred.step.after"
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
