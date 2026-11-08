//go:build !sidecar_http

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
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/connect"
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

// §11.13's reports row's kinds of P0 work, which a process reports and §19.8 exports by kind. A closed
// vocabulary, so a kind may label a metric (I-13).
type WriteP0Kind string

const (
	// rev/ writes.
	WriteP0KindRevocation WriteP0Kind = "revocation"
	// proj/ and projrows/ writes: the authorization log's projection.
	WriteP0KindLog WriteP0Kind = "log"
	// repo/ lifecycle, deletion and restore, and hold/ writes.
	WriteP0KindLifecycle WriteP0Kind = "lifecycle"
	// Shred steps.
	WriteP0KindShred WriteP0Kind = "shred"
	// ERASE, CUT and CLOSURE pushes within their rate, and every slot rewrite.
	WriteP0KindErasure WriteP0Kind = "erasure"
	// gkm Removes.
	WriteP0KindRemove WriteP0Kind = "remove"
	// REMOVE rotations, and a staged delivery or claim gkm reads as one (§10.6).
	WriteP0KindRotation WriteP0Kind = "rotation"
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

// Whether the kind is one of WriteP0Kinds.
func (self WriteP0Kind) Valid() bool {
	for _, kind := range WriteP0Kinds {
		if self == kind {
			return true
		}
	}
	return false
}

// §11.13's order row: P2 runs by deadline, the lowest rank first.
type WriteP2Rank int

const (
	// Evacuation, oldest minute directory first.
	WriteP2RankEvacuation WriteP2Rank = 0
	// The folds a page-out needs (§11.7's lag row).
	WriteP2RankPageOutFold WriteP2Rank = 1
	// Other folds.
	WriteP2RankFold WriteP2Rank = 2
	// Path-epoch copies (§11.6).
	WriteP2RankCopy WriteP2Rank = 3
	// Packing.
	WriteP2RankPack WriteP2Rank = 4
	// Retention.
	WriteP2RankRetention WriteP2Rank = 5
	// GC.
	WriteP2RankGc WriteP2Rank = 6
	// Drop jobs and dry runs.
	WriteP2RankDrop WriteP2Rank = 7
)

// How many ranks there are.
const WriteP2RankCount = 8

// Whether the rank is one of §11.13's.
func (self WriteP2Rank) Valid() bool {
	return 0 <= self && self < WriteP2RankCount
}

// The rank's name, a closed vocabulary.
func (self WriteP2Rank) String() string {
	switch self {
	case WriteP2RankEvacuation:
		return "evacuation"
	case WriteP2RankPageOutFold:
		return "page_out_fold"
	case WriteP2RankFold:
		return "fold"
	case WriteP2RankCopy:
		return "copy"
	case WriteP2RankPack:
		return "pack"
	case WriteP2RankRetention:
		return "retention"
	case WriteP2RankGc:
		return "gc"
	case WriteP2RankDrop:
		return "drop"
	}
	return "invalid"
}

// A write's price in priced bytes: §11.13's cost rows for what it does, before the governor's
// calibration (evsservice.PricePush builds one).
type WriteCost struct {
	// What the write itself costs each drive.
	ImmediateByteCount int64
	// The P2 work it causes: its fold share, its batch's delete and evacuation, parcel and pidx/
	// writes, its purge. A P1 admission pays it and moves it into the wallet.
	DeferredByteCount int64
}

// The whole price a P1 admission debits.
func (self WriteCost) ByteCount() int64 {
	return self.ImmediateByteCount + self.DeferredByteCount
}

// A cost below zero is the caller's bug.
var ErrWriteCost = errors.New("write cost invalid")

// ErrWriteCost for a part below zero.
func (self WriteCost) Validate() error {
	if self.ImmediateByteCount < 0 || self.DeferredByteCount < 0 {
		return fmt.Errorf("%w: %d immediate, %d deferred", ErrWriteCost, self.ImmediateByteCount, self.DeferredByteCount)
	}
	return nil
}

// One unit of P2 work, as it asks to issue.
type WriteP2Work struct {
	Rank WriteP2Rank
	// Within its rank, older work goes first: an evacuation's minute directory, else when the work
	// fell due.
	Due time.Time
	// Its priced bytes, the writes it issues and the fences it raises (§11.13's order row).
	ByteCount int64
	// A P1 admission paid for it, so it spends the wallet, and never the allowance unless the wallet
	// lost its credit (a process killed before its report, or {nvb_<set>} lost), when it runs as
	// unfunded P2 and is paid once from there.
	Funded bool
	// Run once the work's turn has come and its bytes are reserved, before the grant returns, since P2
	// rereads repo/ when issued, not when queued (§11.13's skip row). An error releases the bytes and is
	// the acquire's error, nothing spent. Nil checks nothing.
	Recheck func(ctx context.Context) error
}

// What a P1 or P2 admission spent, held until the writes it paid for end.
type WriteGrant interface {
	// The admission's ctx, carrying its class, for the writes it paid for.
	Context() context.Context
	// The writes have ended, landed or not, so their bytes are no longer in flight. Safe to call more
	// than once.
	Close()
}

// A P1 write the process refused past §11.13's shed delay: 429 RESOURCE_EXHAUSTED with retry_after_ms
// (§6.5's codes; evs answers EVS_REFUSAL_RESOURCE_EXHAUSTED). It refuses nothing durable (§11.20):
// nothing was written.
type WriteRefusal struct {
	ClusterId  string
	RetryAfter time.Duration
}

// Says which cluster refused, and when to try again.
func (self *WriteRefusal) Error() string {
	return fmt.Sprintf("write budget of cluster %s exhausted, retry after %s", self.ClusterId, self.RetryAfter)
}

// retry_after_ms's value.
func (self *WriteRefusal) RetryAfterMs() uint32 {
	return uint32(max(0, self.RetryAfter.Milliseconds()))
}

// See the file header. Every method is safe for concurrent use and does no I/O but the waits and the
// rechecks it is given.
type WriteBudget interface {
	// Counts byteCount priced bytes of P0 work of kind on the cluster and returns at once with ctx
	// carrying P0: no queue, no wait, no refusal, whatever the bucket holds (owner decision 186). Any P2
	// work it later causes runs unfunded.
	IssueP0(ctx context.Context, clusterId string, kind WriteP0Kind, byteCount int64) context.Context
	// Waits in the network's fair queue until the process's P1 share covers cost's whole price, then
	// debits it, moves its deferred part into the wallet and returns a grant whose writes are in flight
	// until Close. Refuses with *WriteRefusal past the shed delay, the heaviest network first, and ends
	// with ctx's error if ctx ends first.
	AdmitP1(ctx context.Context, clusterId string, networkId connect.Id, cost WriteCost) (WriteGrant, error)
	// Waits by rank, then Due, until the work's account covers it, runs its Recheck, and returns a grant
	// whose writes are in flight until Close.
	AcquireP2(ctx context.Context, clusterId string, work *WriteP2Work) (WriteGrant, error)
	// AcquireP2 without the wait: ok is false, nothing spent, unless the work's account covers it now and
	// nothing of its rank or before waits in the same account. Serves step 6's page-out fold, which must
	// not stall a push (§11.7's lag row).
	TryAcquireP2(ctx context.Context, clusterId string, work *WriteP2Work) (grant WriteGrant, ok bool, err error)
	// Declares the P2 work owner knows is outstanding at rank, in priced bytes, waiting in AcquireP2 or
	// not yet due, replacing what owner declared there before: evacuation's batches not yet evacuated,
	// the folds refs owe. The wallet is clamped to the funded backlog the processes report, so funded work
	// nobody declares lapses its credit (§11.13's wallet row). owner is a fixed name, never an id.
	DeclareP2Backlog(clusterId string, owner string, rank WriteP2Rank, funded bool, byteCount int64)
	// EVS1-M2-17's path-epoch copy rate for this process on the cluster, operations a second: its part
	// of 250 a cluster, or of up to 1,000 while P1 left a quarter of the allowance unspent over the last
	// minute.
	CopyOpsPerSecond(clusterId string) int
}

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
