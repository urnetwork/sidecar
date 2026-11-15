//go:build !sidecar_http && !ios_extension

// ServiceHost.Budget: §11.13's write budget (D-EVS-21, D-EVS-33, R-EVS-19), one per process and shared
// by the evs, gkm, api and taskworker work it hosts. Every write to a metadata cluster spends that
// cluster's budget before it is issued, in priced bytes: §11.13's cost rows, which the cluster's
// governor calibrates against its busiest drive's measured writes. evsservice implements it, §4.5's
// home for the budget, and the interface sits here so gkmservice and server's api spend it without
// importing a peer engine.
//
// The classes, by §11.13's classes row and plan-EVSB-write-classes:
//
//   - P0, safety work: rev/, proj/, projrows/ and hold/ writes, repo/ lifecycle, shred steps, ERASE,
//     CUT and CLOSURE pushes within their rate and every slot rewrite, gkm Removes and REMOVE
//     rotations. IssueP0 never waits, queues, paces or refuses (owner decision 186). Its bytes drain
//     the bucket as any class's do, past its floor as forgiven excess (owner decision 190).
//   - P1, queued per network by the token's network: pushes, parts, gkm commits, Adds, Welcomes,
//     KeyPackages, ReaderKeys, LATE deliveries, GroupInfo, path maps, place/, a repo's creation writes
//     and activate's CAS. AdmitP1 pays at once for the write and the P2 work it causes, and the
//     deferred part moves into the cluster's wallet, which only that work spends, so it is paid once.
//   - P2, deferred work in §11.13's order (WriteP2Rank). Funded work, which a P1 admission paid for,
//     spends only the wallet. Unfunded work (copies, GC, nightly passes, dry runs, a lapsed credit)
//     takes at most 40% of the allowance.
//
// A write's ctx carries its class once the budget has passed it (WriteClassOf), so a metadata cluster
// that evsservice.BudgetedBlobs wraps refuses a PUT or DELETE that never spent. Segment clusters spend
// nothing here: their uploads queue on §11.13's hdd row.
//
// Safe for concurrent use. No method does I/O on the caller's path: a process's own goroutine reads
// its allowances and writes its reports every 5 s, so the inline path makes no Redis call (I-12).

package sidecar

import (
	"context"

	operator "github.com/urnetwork/operator-core"
)

// §11.13's classes. The zero value is no class: a ctx no budget passed.
type WriteClass int

const (
	WriteClassP0 WriteClass = 1
	WriteClassP1 WriteClass = 2
	WriteClassP2 WriteClass = 3
)

// The class's name in §11.13, as a metric's class label reads it.
func (self WriteClass) String() string {
	switch self {
	case WriteClassP0:
		return "p0"
	case WriteClassP1:
		return "p1"
	case WriteClassP2:
		return "p2"
	}
	return "none"
}

// §11.13's reports row's kinds of P0 work: a closed vocabulary, so a kind may label a metric (I-13).
type WriteP0Kind = operator.WriteP0Kind

const (
	// rev/ writes.
	WriteP0KindRevocation = operator.WriteP0KindRevocation
	// proj/ and projrows/ writes: the authorization log's projection.
	WriteP0KindLog = operator.WriteP0KindLog
	// repo/ lifecycle, deletion and restore, and hold/ writes.
	WriteP0KindLifecycle = operator.WriteP0KindLifecycle
	// Shred steps.
	WriteP0KindShred = operator.WriteP0KindShred
	// ERASE, CUT and CLOSURE pushes within their rate, and every slot rewrite.
	WriteP0KindErasure = operator.WriteP0KindErasure
	// gkm Removes.
	WriteP0KindRemove = operator.WriteP0KindRemove
	// REMOVE rotations, and a staged delivery or claim gkm reads as one (§10.6).
	WriteP0KindRotation = operator.WriteP0KindRotation
)

// Every P0 kind, in §11.13's order.
var WriteP0Kinds = []WriteP0Kind{
	WriteP0KindRevocation,
	WriteP0KindLog,
	WriteP0KindLifecycle,
	WriteP0KindShred,
	WriteP0KindErasure,
	WriteP0KindRemove,
	WriteP0KindRotation,
}

// §11.13's order row: P2 runs by deadline, the lowest rank first.
type WriteP2Rank = operator.WriteP2Rank

const (
	// Evacuation, oldest minute directory first.
	WriteP2RankEvacuation = operator.WriteP2RankEvacuation
	// The folds a page-out needs (§11.7's lag row).
	WriteP2RankPageOutFold = operator.WriteP2RankPageOutFold
	// Other folds.
	WriteP2RankFold = operator.WriteP2RankFold
	// Path-epoch copies (§11.6).
	WriteP2RankCopy = operator.WriteP2RankCopy
	// Packing.
	WriteP2RankPack = operator.WriteP2RankPack
	// Retention.
	WriteP2RankRetention = operator.WriteP2RankRetention
	// GC.
	WriteP2RankGc = operator.WriteP2RankGc
	// Drop jobs and dry runs.
	WriteP2RankDrop = operator.WriteP2RankDrop
)

// How many ranks there are.
const WriteP2RankCount = operator.WriteP2RankCount

// A write's price in priced bytes (evsservice.PricePush builds one).
type WriteCost = operator.WriteCost

// A cost below zero is the caller's bug.
var ErrWriteCost = operator.ErrWriteCost

// One unit of P2 work, as it asks to issue.
type WriteP2Work = operator.WriteP2Work

// What a P1 or P2 admission spent, held until the writes it paid for end.
type WriteGrant = operator.WriteGrant

// A P1 write the process refused past §11.13's shed delay.
type WriteRefusal = operator.WriteRefusal

// See the file header.
type WriteBudget = operator.WriteBudget

// The ctx key a write's class rides under.
type writeClassKey struct{}

// ctx carrying class. Only a WriteBudget calls this, as it passes a write: a write that marks its own
// ctx has spent nothing.
func WithWriteClass(ctx context.Context, class WriteClass) context.Context {
	return context.WithValue(ctx, writeClassKey{}, class)
}

// The class a budget passed ctx under, and false for a ctx no budget passed.
func WriteClassOf(ctx context.Context) (WriteClass, bool) {
	class, ok := ctx.Value(writeClassKey{}).(WriteClass)
	return class, ok && class != 0
}
