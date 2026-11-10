// §11.13's write budget for gkm's writes (R-KEYS-14, D-EVS-33; §10.6's checks row; FI-3, FI-14, FS-117): every write
// gkm sends a metadata cluster spends ServiceHost.Budget first, in priced bytes, under the class §10.6 gives it:
//
//	P0  issued at once, never queued, refused or paced (owner decision 186), its bytes reported by kind:
//	    remove    a commit to epoch/<n> while gkm's newest verified state shows a key holder of the repo dropped since
//	              epoch/<n-1>'s auth pin and time (§10.9's roster row): gkm cannot read the PrivateMessage, so that
//	              state decides, never the commit
//	    rotation  a staged delivery or recovery wrap of generation g, or the claim of gen/<g>, while that state shows a
//	              shrink, an authorization expiry or a compromise retirement since gen/<g-1>'s auth pin and time
//	              (GkmAuthState.HoldersDropped, the causes of §10.9's REMOVE gkm can see); a claim's stated cause
//	              never decides it, so a SCHEDULE or REQUEST rotation that says REMOVE is P1 and may be shed
//	    shred     ShredGroup's deletes, §11.12's shred steps
//	P1  queued per network, the token's, by weighted fair queuing, the heaviest network refused first past the
//	    budget's shed delay, 429 RESOURCE_EXHAUSTED with Retry-After: every other commit, Adds (KeyPackage claims),
//	    Welcomes and their pointers, KeyPackages, ReaderKeys, LATE deliveries, GroupInfo and the pointer's heal, a
//	    group's creation and re-forming, a rebind's recovery wraps and their deletion
//	P2  the reconciler's sweeps, unfunded: epoch retention and the pointer's move at rank retention, staged GC and
//	    §2.8's TTLs at rank GC (retention.go)
//
// A P1 admission debits its immediate writes alone. The P2 work a gkm write later causes, its retention or GC delete
// up to 90 days on, runs as unfunded P2, which §11.13's wallet row allows for work with no payer: a credit moved into
// the wallet would lapse long before that work came due. A retry createGkmObject sends after an unknown outcome is not
// priced again, nor is a claim that loses a KeyPackage race and tries the next: their bytes come out in the
// calibration k.
//
// A P1 admission waits as long as the request's ctx: the budget alone refuses, the heaviest network first, and a
// network waiting alone waits for the next share (FI-14 (d)), as evs's routes do.
//
// A write's ctx carries its class once spent (sidecar.WriteClassOf), and createGkmObject, replaceGkmObject and
// deleteGkmObject refuse one that carries none, so a write that forgot its budget fails in its first test. The engine
// and the reconciler refuse to start without a budget, since no metadata write may go unpriced (§11.13).
//
// Prices are §11.13's cost rows for a 4 KiB XFS block (GkmWritePrices), which the governor's calibration turns into
// drive bytes, so a table off by a constant factor costs nothing but k. gkm cannot import evs's table, so it keeps the
// same rows here, a settings value §22.8's nvme run replaces in config with evs's.

package gkmservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A metadata write whose ctx no write budget passed: nothing was sent (§11.13). Always a handler's bug, which answers
// 503 and alarms.
var errGkmWriteUnbudgeted = errors.New("gkm: a metadata write no write budget passed")

// The P2 backlog's owner name the reconciler's sweep declares under (WriteBudget.DeclareP2Backlog): a fixed name.
const gkmSweepBacklogOwner = "gkm.sweep"

// §11.13's cost rows as gkm prices its writes: what each costs each drive of a metadata cluster before the
// governor's calibration. The defaults are §11.13's inferred figures for a 4 KiB XFS block until §22.8's nvme run
// measures the table (D-TEST-11).
type GkmWritePrices struct {
	// The XFS block the rows are for.
	BlockByteCount int64
	// Objects up to this size cost their row as it stands: ~14 KiB.
	SmallObjectByteCount int64
	// A create's bytes on each drive: ~9 KiB.
	CreateByteCount int64
	// An overwrite's, the old xl.meta written again: ~14 KiB.
	OverwriteByteCount int64
	// A delete's: ~3.5 KiB.
	DeleteByteCount int64
	// What a larger object's bytes past SmallObjectByteCount spread over: EC:4's four data shards.
	ShardCount int64
}

// The 4 KiB block's rows (§11.13).
func DefaultGkmWritePrices() *GkmWritePrices {
	return &GkmWritePrices{
		BlockByteCount:       4 * 1024,
		SmallObjectByteCount: 14 * 1024,
		CreateByteCount:      9 * 1024,
		OverwriteByteCount:   14 * 1024,
		DeleteByteCount:      3584,
		ShardCount:           4,
	}
}

// Refuses rows that price a write at nothing or below.
func (self *GkmWritePrices) validate() error {
	if self.BlockByteCount <= 0 || self.SmallObjectByteCount < 0 || self.CreateByteCount <= 0 ||
		self.OverwriteByteCount <= 0 || self.DeleteByteCount <= 0 || self.ShardCount <= 0 {
		return fmt.Errorf("%w: a write price that is not positive", ErrGkmSettings)
	}
	return nil
}

// What an object's bytes past the small rows add to each drive: its shard, rounded up to the block.
func (self *GkmWritePrices) largeObjectByteCount(objectByteCount int64) int64 {
	if objectByteCount <= self.SmallObjectByteCount {
		return 0
	}
	shardByteCount := (objectByteCount - self.SmallObjectByteCount + self.ShardCount - 1) / self.ShardCount
	return (shardByteCount + self.BlockByteCount - 1) / self.BlockByteCount * self.BlockByteCount
}

// A create's priced bytes: the create row and its large part.
func (self *GkmWritePrices) create(objectByteCount int) int64 {
	return self.CreateByteCount + self.largeObjectByteCount(int64(objectByteCount))
}

// An overwrite's priced bytes.
func (self *GkmWritePrices) overwrite(objectByteCount int) int64 {
	return self.OverwriteByteCount + self.largeObjectByteCount(int64(objectByteCount))
}

// A write to a key gkm changes in place: an overwrite where a read found an etag, else a create.
func (self *GkmWritePrices) replace(etag string, objectByteCount int) int64 {
	if etag == "" {
		return self.create(objectByteCount)
	}
	return self.overwrite(objectByteCount)
}

// A delete's priced bytes.
func (self *GkmWritePrices) delete() int64 {
	return self.DeleteByteCount
}

// errGkmWriteUnbudgeted unless a write budget passed ctx: what every gkm write checks before it is sent.
func checkGkmWriteClass(ctx context.Context) error {
	if _, ok := sidecar.WriteClassOf(ctx); !ok {
		return errGkmWriteUnbudgeted
	}
	return nil
}

// Spends byteCount priced bytes of writes to the cluster: P0 of p0Kind at once when p0Kind is set, never waiting or
// refused, else P1 in networkId's queue for as long as ctx lasts. Returns the ctx those writes issue under, which
// carries their class, and what ends the admission once they have. A *sidecar.WriteRefusal, ctx's error or the
// budget's own wrote nothing.
func spendGkmWrites(ctx context.Context, budget sidecar.WriteBudget, clusterId string, networkId connect.Id, p0Kind sidecar.WriteP0Kind, byteCount int64) (context.Context, func(), error) {
	if budget == nil {
		return nil, nil, errors.New("gkm: no write budget")
	}
	if p0Kind != "" {
		return budget.IssueP0(ctx, clusterId, p0Kind, byteCount), func() {}, nil
	}
	grant, err := budget.AdmitP1(ctx, clusterId, networkId, sidecar.WriteCost{ImmediateByteCount: byteCount})
	if err != nil {
		return nil, nil, err
	}
	return grant.Context(), grant.Close, nil
}

// Spends the writes the request is about to send cluster, under p0Kind or, empty, P1 in the token's network's queue.
// The ctx those writes issue under, or the error that refused them, which writes nothing; the admission ends with the
// request.
func (self *GkmRequest) spendWrites(cluster sidecar.BlobCluster, p0Kind sidecar.WriteP0Kind, byteCount int64) (context.Context, error) {
	ctx, release, err := spendGkmWrites(self.Ctx, self.engine.host.Budget, cluster.ClusterId(), self.Principal.NetworkId, p0Kind, byteCount)
	if err != nil {
		var refusal *sidecar.WriteRefusal
		if errors.As(err, &refusal) {
			self.engine.metrics.budgetShed.Add(1, self.route.Pattern)
		}
		return nil, err
	}
	if p0Kind != "" {
		self.engine.metrics.budgetP0.Add(1, string(p0Kind))
	}
	self.releases = append(self.releases, release)
	return ctx, nil
}

// spendWrites, answering a refusal: 429 RESOURCE_EXHAUSTED with Retry-After for a write the budget shed, 503 for one
// it could not admit. The ctx the writes issue under, or false once it has answered.
func (self *GkmRequest) SpendWrites(cluster sidecar.BlobCluster, p0Kind sidecar.WriteP0Kind, byteCount int64) (context.Context, bool) {
	ctx, err := self.spendWrites(cluster, p0Kind, byteCount)
	if err == nil {
		return ctx, true
	}
	var refusal *sidecar.WriteRefusal
	if errors.As(err, &refusal) {
		// §11.13's shed row: the heaviest network's P1, nothing written, so a retry is safe
		self.retryAfter = max(time.Second, refusal.RetryAfter)
		self.write(429, nil)
		return nil, false
	}
	self.Unavailable()
	return nil, false
}

// Whether gkm's newest verified state shows a key holder of the request's repo dropped since pin and timeMs, through
// now: only an answer of the state counts, so one that cannot tell classes the write P1.
func (self *GkmEngine) holdersDropped(request *GkmRequest, pin *bridge.AuthPin, timeMs int64) bool {
	if pin == nil {
		return false
	}
	answer := self.deps.AuthState.HoldersDropped(request.Principal, request.RepoId, pin, time.UnixMilli(timeMs), request.Now())
	return answer == GkmAuthAllowed
}

// The class a commit making epoch n issues under (§10.6's checks row): P0 remove while gkm's newest verified state
// shows a holder dropped since epoch n-1's auth pin and time, else P1, the empty kind.
func (self *GkmEngine) commitWriteKind(request *GkmRequest, previous *protocol.GkmEpochObject) sidecar.WriteP0Kind {
	if self.holdersDropped(request, previous.GetHeader().GetAuth(), previous.GetTimeMs()) {
		return sidecar.WriteP0KindRemove
	}
	return ""
}

// The class writes toward generation g issue under, a staged delivery or recovery wrap of g or g's claim (§10.6's
// checks row): P0 rotation while gkm's newest verified state shows a shrink, an expiry or a compromise retirement
// since parent's auth pin and time, parent being gen/<g-1>, else P1. nil parent, a creation's generation 1, is P1.
func (self *GkmEngine) rotationWriteKind(request *GkmRequest, parent *gkmGenerationFacts) sidecar.WriteP0Kind {
	if parent != nil && self.holdersDropped(request, parent.auth, parent.timeMs) {
		return sidecar.WriteP0KindRotation
	}
	return ""
}

// The class a staged write of generation in the request's group issues under: rotationWriteKind against gen/<g-1>,
// read through the accessor. A parent gkm cannot read now, or generation 1's, classes it P1.
func (self *GkmEngine) stagedWriteKind(request *GkmRequest, groupId sidecar.Id, generation uint64) sidecar.WriteP0Kind {
	if generation < 2 {
		return ""
	}
	parent, err := self.generationFacts(request.Ctx, request.Cluster, groupId, generation-1)
	if err != nil {
		return ""
	}
	return self.rotationWriteKind(request, parent)
}
