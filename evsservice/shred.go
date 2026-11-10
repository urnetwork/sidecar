// §11.12's shred (D-EVS-19, D-EVS-61, I-1, FI-5; owner decisions 82 and 133; EVS1-M2-19): taskworker's job
// evs.shred, which DELETE queues (repo.go) and the reconciler's walk queues again (reconcile.go), its args a repo, the
// deletion it shreds and its pass. Each run rereads repo/ and acts only on its own deletion:
//
//	start    repo/ deleted under the job's deletion: once 7 d 10 min have passed since its RepoDelete's entry
//	         (state_ms) and the newest projection holds no RepoRestore of it, deleted -> shredding{deletion, now} by
//	         If-Match, so exactly one of restore and start wins at repo/; earlier, the job queues itself for then
//	phases   repo/ shredding under the job's deletion, each step rereading repo/ first and going on only while it still
//	         shows that:
//	         1 wait until 20 s past shredding's state_ms: a push validated before the CAS has landed or never will
//	         2 delete slot/<repo>/*, keys first
//	         3 delete the repo's gkm objects, acks and recovery wraps (ShredGroup, gkm's, passed in since evs cannot
//	           import gkm)
//	         4 under a preservation hold covering the repo, stop, queued again at the hold's end: the ciphertext stays,
//	           and the keys are gone (owner decision 133)
//	         5 delete idx/ head/ log/ pmap/ pidx/ spidx/ hp/ drops/ on the repo's cluster, its Redis families
//	           {evsq_} {evsl_} {evsh_}, and seg/ pack/ dropscan/ on the segment cluster; its records in shared
//	           batches go with their batches, at most 26 h on (§11.13)
//	         6 the first pass queues the final one 10 min after its step 5, which repeats 2, 3 (forms included) and
//	           5 for stragglers
//	         7 the final pass rewrites repo/ as the shredded tombstone, kept with place/ for the network's life
//	stale    repo/ under another deletion, or in a state the pass does not take: the run ends, deleting nothing
//
// Every step is idempotent: a delete of a key already gone is no error, and a rerun after a crash at any step does
// the steps again. The 20 s and 10 min waits are fixed by §11.8's windows and §19.6's request deadline, so they are
// constants, not settings. Metadata deletes and repo/'s writes are P0 of kind shred, issued at once (owner decision
// 186); the segment cluster spends no NVMe budget.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The job's name in taskworker's registry.
const EvsShredTaskName = "evs.shred"

// §11.12's shred timings, fixed by §11.8's validation windows and §19.6's request deadline, not tunable down.
const (
	// 7 d 10 min after the RepoDelete's entry: api takes a RepoRestore only within 7 d, and 10 min more lets its
	// projection reach every evs process.
	evsShredStartAfter = 7*24*time.Hour + 10*time.Minute
	// Step 1: two of §11.8's 5 s validation windows plus §19.6's 10 s request deadline.
	evsShredSettleWait = 20 * time.Second
	// Step 6: past repo/'s 5 s cache, which P2 and gkm writes recheck at issue, plus the request deadline.
	evsShredStragglerWait = 10 * time.Minute
)

// An args body: repo id, deletion id, then the pass.
const evsShredArgsByteCount = 16 + 16 + 1

// The passes.
const (
	evsShredPassFirst = 0
	evsShredPassFinal = 1
)

// A job's args: the repo, the deletion it shreds and whether it is the final pass.
func EvsShredArgs(repoId sidecar.Id, deletionId sidecar.Id, final bool) []byte {
	args := make([]byte, 0, evsShredArgsByteCount)
	args = append(args, repoId[:]...)
	args = append(args, deletionId[:]...)
	if final {
		return append(args, evsShredPassFinal)
	}
	return append(args, evsShredPassFirst)
}

// What args name, or an error for args that name no shred.
func ParseEvsShredArgs(args []byte) (repoId sidecar.Id, deletionId sidecar.Id, final bool, err error) {
	if len(args) != evsShredArgsByteCount || evsShredPassFinal < args[32] {
		return sidecar.Id{}, sidecar.Id{}, false, fmt.Errorf("evs shred args of %d bytes", len(args))
	}
	copy(repoId[:], args[:16])
	copy(deletionId[:], args[16:32])
	return repoId, deletionId, args[32] == evsShredPassFinal, nil
}

// A pass's queue entry: once-keyed by repo, deletion and pass, opaque ids only (I-13), so a retried DELETE or the
// reconciler's walk queues nothing twice.
func evsShredTaskRequest(repoId sidecar.Id, deletionId sidecar.Id, final bool, runAt time.Time) *sidecar.TaskRequest {
	pass := evsShredPassFirst
	if final {
		pass = evsShredPassFinal
	}
	return &sidecar.TaskRequest{
		Name:    EvsShredTaskName,
		OnceKey: fmt.Sprintf("%s.%s.%s.%d", EvsShredTaskName, sidecar.EvsKeyId(repoId), sidecar.EvsKeyId(deletionId), pass),
		Args:    EvsShredArgs(repoId, deletionId, final),
		RunAt:   runAt,
	}
}

// The first pass a repo/ in object's state leaves due at now: a deleted repo's start 7 d 10 min after its RepoDelete's
// entry, a shredding repo's run at once. false for any other state, or one naming no deletion.
func evsShredRequest(repoId sidecar.Id, object *protocol.EvsRepoObject, now time.Time) (*sidecar.TaskRequest, bool) {
	deletionId, err := sidecar.IdFromBytes(object.GetDeletionId())
	if err != nil {
		return nil, false
	}
	switch object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_DELETED:
		return evsShredTaskRequest(repoId, deletionId, false, time.UnixMilli(object.GetStateMs()).Add(evsShredStartAfter)), true
	case protocol.EvsRepoState_EVS_REPO_SHREDDING:
		return evsShredTaskRequest(repoId, deletionId, false, now), true
	}
	return nil, false
}

// The newest projection's RepoDelete of a repo, which the 7-day start and the reconciler read (§11.12's start and log
// first rows). ACL's projection supplies it; safe for concurrent use.
type EvsRepoDeletionSource interface {
	// The repo's newest RepoDelete in networkId's newest projection, nil when it holds none. An error when the
	// projection cannot be read, which leaves the repo as it is.
	RepoDeletion(ctx context.Context, networkId sidecar.Id, repoId sidecar.Id) (*EvsRepoDeletionFacts, error)
}

// What a shred runs on beyond its host.
type EvsShredDeps struct {
	// Step 3: gkm's objects of the repo on its cluster, final at the last pass, its forms included
	// (gkmservice.ShredGroup, which taskworker passes in). nil fails every pass before step 2, so no shred deletes
	// ciphertext while gkm's keys stand.
	ShredGroup func(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, final bool) error
	// The projection the 7-day start reads. nil starts no shred: a deleted repo stays deleted, its start queued again
	// a ShredHoldRecheckInterval on.
	Deletions EvsRepoDeletionSource
	// The holds step 4 reads. nil reads hold/ through a HoldSet of the run's own.
	Holds *sidecar.HoldSet
	// nil: the defaults.
	Settings *EvsSettings
	// nil discards.
	Log sidecar.Logger
}

// What one run did.
type EvsShredOutcome int

const (
	// repo/ is under another deletion or in a state this pass does not take: nothing deleted.
	EvsShredStale EvsShredOutcome = iota + 1
	// Not yet due: the start's 7 d 10 min, step 1's 20 s, or a start the projection could not decide. Queued again.
	EvsShredWaiting
	// The start found the deletion restored in the projection: nothing deleted, nothing queued.
	EvsShredRestored
	// Stopped at step 4 under a hold, keys gone, ciphertext kept. Queued again at the hold's end.
	EvsShredHeld
	// The first pass's steps 2 to 5 done, the final pass queued for 10 min on.
	EvsShredFirstPassDone
	// The tombstone is written.
	EvsShredShredded
)

// One run of evs.shred: see the file header.
func RunShred(ctx context.Context, host *sidecar.ServiceHost, deps *EvsShredDeps, args []byte) (EvsShredOutcome, error) {
	repoId, deletionId, final, err := ParseEvsShredArgs(args)
	if err != nil {
		return 0, err
	}
	if host == nil || host.Blobs == nil || host.Budget == nil || host.Tasks == nil {
		return 0, errors.New("evs's shred needs a host with Blobs, a write budget and a task queue")
	}
	if deps == nil || deps.ShredGroup == nil {
		return 0, errors.New("evs's shred needs gkm's ShredGroup: no ciphertext goes while gkm's keys stand")
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultEvsSettings()
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	priceTable, err := DefaultPriceTable(settings.PriceBlockByteCount)
	if err != nil {
		return 0, err
	}
	clock := host.ClockOrReal()
	blobs := NewBudgetedBlobs(host.Blobs)
	firstCluster, err := blobs.FirstCluster()
	if err != nil {
		return 0, err
	}
	place, err := sidecar.ReadEvsRepoPlace(ctx, firstCluster, repoId)
	if err != nil {
		return 0, err
	}
	cluster, err := blobs.Cluster(place.ClusterId)
	if err != nil {
		return 0, err
	}
	holds := deps.Holds
	if holds == nil {
		holds = sidecar.NewHoldSet(host.Blobs, clock, nil)
	}
	run := &evsShredRun{
		host:       host,
		deps:       deps,
		settings:   settings,
		log:        log,
		clock:      clock,
		blobs:      blobs,
		cluster:    cluster,
		priceTable: priceTable,
		repos:      NewRepoCache(clock, settings),
		holds:      holds,
		repoId:     repoId,
		deletionId: deletionId,
		final:      final,
	}
	return run.run(ctx)
}

// One run's state.
type evsShredRun struct {
	host       *sidecar.ServiceHost
	deps       *EvsShredDeps
	settings   *EvsSettings
	log        sidecar.Logger
	clock      sidecar.Clock
	blobs      sidecar.BlobStore
	cluster    sidecar.BlobCluster
	priceTable *PriceTable
	repos      *RepoCache
	holds      *sidecar.HoldSet
	repoId     sidecar.Id
	deletionId sidecar.Id
	final      bool
}

// The run: the start where repo/ is deleted, then the pass's steps while repo/ shows shredding under the deletion.
func (self *evsShredRun) run(ctx context.Context) (EvsShredOutcome, error) {
	object, err := self.reread(ctx)
	if err != nil || object == nil {
		return EvsShredStale, err
	}
	if object.GetState() == protocol.EvsRepoState_EVS_REPO_DELETED {
		outcome, err := self.start(ctx, object)
		if err != nil || outcome != 0 {
			return outcome, err
		}
		if object, err = self.reread(ctx); err != nil || object == nil {
			return EvsShredStale, err
		}
	}
	switch object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_SHREDDED:
		return EvsShredShredded, nil
	case protocol.EvsRepoState_EVS_REPO_SHREDDING:
	default:
		return EvsShredStale, nil
	}

	// step 1
	settled := time.UnixMilli(object.GetStateMs()).Add(evsShredSettleWait)
	if now := self.clock.Now(); now.Before(settled) {
		return EvsShredWaiting, self.queue(ctx, self.final, settled)
	}
	// steps 2 and 3, keys first, under a hold too
	if ok, err := self.step(ctx, "slots", func() error {
		return self.deletePrefix(ctx, self.cluster, slotKeyPrefix+sidecar.EvsKeyId(self.repoId)+"/")
	}); !ok {
		return EvsShredStale, err
	}
	if ok, err := self.step(ctx, "gkm", func() error { return self.deps.ShredGroup(ctx, self.cluster, self.repoId, self.final) }); !ok {
		return EvsShredStale, err
	}
	// step 4
	held, until, err := self.held(ctx, object)
	if err != nil {
		return 0, err
	}
	if held {
		self.log.Infof("[evs] repo %s: shred stopped under a hold, keys gone, ciphertext kept", sidecar.EvsKeyId(self.repoId))
		return EvsShredHeld, self.queue(ctx, self.final, until)
	}
	// step 5
	if ok, err := self.step(ctx, "families", func() error { return self.deleteFamilies(ctx) }); !ok {
		return EvsShredStale, err
	}
	if !self.final {
		// step 6: the final pass, after the stragglers' bound
		return EvsShredFirstPassDone, self.queue(ctx, true, self.clock.Now().Add(evsShredStragglerWait))
	}
	// step 7
	barrierKey := barrierRepoKey(self.repoId)
	testHookBarrier(BarrierShredStepBefore, barrierKey)
	_, err = transitionRepo(ctx, self.cluster, self.repos, self.repoId, self.settings.RepoTransitionRetryCount,
		evsP0Class(self.host.Budget, self.priceTable, self.cluster, sidecar.WriteP0KindShred), decideFinishShred(self.deletionId, self.clock.Now()))
	testHookBarrier(BarrierShredStepAfter, barrierKey)
	var refusal *EvsRepoRefusal
	if errors.As(err, &refusal) {
		return EvsShredStale, nil
	}
	if err != nil {
		return 0, err
	}
	return EvsShredShredded, nil
}

// repo/ from the cluster, nil when it shows another deletion, which a stale job leaves alone.
func (self *evsShredRun) reread(ctx context.Context) (*protocol.EvsRepoObject, error) {
	read, err := self.repos.ReadFresh(ctx, self.cluster, self.repoId)
	if err != nil {
		return nil, err
	}
	if !evsRepoNamesDeletion(read.Object, self.deletionId) {
		return nil, nil
	}
	return read.Object, nil
}

// One step, rereading repo/ first and running only while it shows shredding under the deletion. false, with nil, when
// it no longer does.
func (self *evsShredRun) step(ctx context.Context, name string, do func() error) (bool, error) {
	object, err := self.reread(ctx)
	if err != nil {
		return false, err
	}
	if object == nil || object.GetState() != protocol.EvsRepoState_EVS_REPO_SHREDDING {
		return false, nil
	}
	barrierKey := barrierRepoKey(self.repoId)
	testHookBarrier(BarrierShredStepBefore, barrierKey)
	err = do()
	testHookBarrier(BarrierShredStepAfter, barrierKey)
	if err != nil {
		return false, fmt.Errorf("evs shred step %s: %w", name, err)
	}
	return true, nil
}

// The start of a deleted repo: 0 and nil once it went to shredding (or already had), else the outcome to answer.
func (self *evsShredRun) start(ctx context.Context, object *protocol.EvsRepoObject) (EvsShredOutcome, error) {
	if self.final {
		// a final pass never starts a shred
		return EvsShredStale, nil
	}
	due := time.UnixMilli(object.GetStateMs()).Add(evsShredStartAfter)
	now := self.clock.Now()
	if now.Before(due) {
		return EvsShredWaiting, self.queue(ctx, false, due)
	}
	if self.deps.Deletions == nil || len(object.GetNetworkId()) != 16 {
		// nothing can show the deletion unrestored: it stays deleted, asked again later
		self.log.Warningf("[evs] repo %s: no projection to start its shred on", sidecar.EvsKeyId(self.repoId))
		return EvsShredWaiting, self.queue(ctx, false, now.Add(self.settings.ShredHoldRecheckInterval))
	}
	deletion, err := self.deps.Deletions.RepoDeletion(ctx, sidecar.Id(object.GetNetworkId()), self.repoId)
	if err != nil {
		return 0, err
	}
	if deletion == nil || deletion.DeletionId != self.deletionId || deletion.Restored {
		// restored, or another deletion is newer: this one never shreds
		return EvsShredRestored, nil
	}
	_, err = transitionRepo(ctx, self.cluster, self.repos, self.repoId, self.settings.RepoTransitionRetryCount,
		evsP0Class(self.host.Budget, self.priceTable, self.cluster, sidecar.WriteP0KindLifecycle), decideStartShred(self.deletionId, now))
	var refusal *EvsRepoRefusal
	if errors.As(err, &refusal) {
		// a restore won at repo/
		return EvsShredStale, nil
	}
	return 0, err
}

// Whether a hold covers the repo, and when to look again: the hold's end, or ShredHoldRecheckInterval on. A repo/
// naming no network reads as held (plan-EVSB-repo-network), and a hold read that fails is the caller's error.
func (self *evsShredRun) held(ctx context.Context, object *protocol.EvsRepoObject) (bool, time.Time, error) {
	recheck := self.clock.Now().Add(self.settings.ShredHoldRecheckInterval)
	networkId, err := sidecar.IdFromBytes(object.GetNetworkId())
	if err != nil {
		return true, recheck, nil
	}
	cover, err := self.holds.Covering(ctx, networkId, self.repoId)
	if err != nil {
		return false, time.Time{}, err
	}
	if !cover.Covered() {
		return false, time.Time{}, nil
	}
	if until, bounded := cover.ExpireTime(); bounded && until.Before(recheck) {
		return true, until, nil
	}
	return true, recheck, nil
}

// Step 5's families: the repo's metadata objects but repo/ and its keys' families, its Redis families, and its
// segment cluster objects.
func (self *evsShredRun) deleteFamilies(ctx context.Context) error {
	repoKey := sidecar.EvsKeyId(self.repoId) + "/"
	for _, prefix := range []string{indexKeyPrefix, headKeyPrefix, logKeyPrefix, pathMapKeyPrefix, pidxKeyPrefix, spidxKeyPrefix, parcelKeyPrefix} {
		if err := self.deletePrefix(ctx, self.cluster, prefix+repoKey); err != nil {
			return err
		}
	}
	if err := self.deleteKey(ctx, self.cluster, DropsKey(self.repoId)); err != nil {
		return err
	}
	if self.host.Redis != nil {
		// one hash tag a call (§11.10's slots row)
		if err := self.host.Redis.Delete(ctx, []string{PushSequenceKey(self.repoId)}); err != nil {
			return err
		}
		if err := self.host.Redis.Delete(ctx, []string{LeaseKey(self.repoId), LeaseVersionKey(self.repoId)}); err != nil {
			return err
		}
		if err := self.host.Redis.Delete(ctx, []string{HeadCacheKey(self.repoId)}); err != nil {
			return err
		}
	}
	segmentCluster, err := self.blobs.SegmentCluster()
	if err != nil {
		return err
	}
	for _, prefix := range []string{segmentKeyPrefix, packKeyPrefix, dropscanKeyPrefix} {
		if err := self.deletePrefix(ctx, segmentCluster, prefix+repoKey); err != nil {
			return err
		}
	}
	return nil
}

// Deletes every key under prefix on cluster, a page at a time.
func (self *evsShredRun) deletePrefix(ctx context.Context, cluster sidecar.BlobCluster, prefix string) error {
	startAfter := ""
	for {
		infos, more, err := cluster.List(ctx, prefix, startAfter, self.settings.ShredListPageCount)
		if err != nil {
			return err
		}
		for _, info := range infos {
			if err := self.deleteKey(ctx, cluster, info.Key); err != nil {
				return err
			}
		}
		if !more || len(infos) == 0 {
			return nil
		}
		startAfter = infos[len(infos)-1].Key
	}
}

// Deletes key, P0 of kind shred on a metadata cluster; a key already gone is no error.
func (self *evsShredRun) deleteKey(ctx context.Context, cluster sidecar.BlobCluster, key string) error {
	price, err := self.priceTable.Price(WriteOperation{Kind: WriteOperationDelete, Count: 1})
	if err != nil {
		return err
	}
	return cluster.Delete(self.host.Budget.IssueP0(ctx, cluster.ClusterId(), sidecar.WriteP0KindShred, price), key)
}

// Queues this repo's shred pass for runAt.
func (self *evsShredRun) queue(ctx context.Context, final bool, runAt time.Time) error {
	return self.host.Tasks.Schedule(ctx, evsShredTaskRequest(self.repoId, self.deletionId, final, runAt))
}
