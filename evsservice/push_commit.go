// Steps 6, 7 and 8 of a push (§11.8), once step 5 passed:
//
//	budget  the push's writes spend its cluster's write budget first: P1, queued in the token network's fair share at
//	        full price, its own writes and the P2 work it causes (§11.13's push row), so one grant pays the record,
//	        the slots, the page-out and the head; a budget past its shed delay answers 429 RESOURCE_EXHAUSTED, which
//	        refuses nothing
//	6       the record joins this process's open batch for the repo's cluster and waits for its write (batch.go);
//	        then, for a push with new slots, one more round PUTs each slot If-None-Match: equal bytes under 23 h old
//	        are success, older ones 409 SLOT_STALE, recorded, and other bytes send the attempt to a cluster read of
//	        the head, where 5a finds the push committed if an ERASE rewrote the slot, else an alarm and SLOT_STALE;
//	        so the record names every slot written. A window about to pass 127 versions pages out first (logpage.go)
//	7       the head If-Match step 4's ETag (If-None-Match for a ref with none): version v+1, C_{v+1}, the push, its
//	        pins, the window with the push's entry and without what was paged, folded_through as this process's
//	        folds raise it, the lease cleared, deleted for a DELETE; issued only within PushStepSevenWindow of step
//	        4's reads, else steps 4 and 5 run again. Its outcomes are outcome.go's
//	8       off the reply path: the push sequence and hints (EvsCommitNotifier, EVS1-M2-15's), usage, the head cache
//	        entry, which records the sequence the commit raised, and the fold trigger
//
// A record is committed only at the place its window entry names, so another attempt's copy of the same push is
// dead weight evacuation drops (§11.8's bind row), and nothing here deletes anything.

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §11.8 step 6: a slot that exists with equal bytes is this push's only while under 23 h old (§11.22's M2 row), as
// a re-uploaded segment is.
const evsSlotExistingMaxAge = 23 * time.Hour

// §11.6's slot: at most 8 KiB.
const evsSlotMaxByteCount = 8 * 1024

// What step 8 learns of a commit.
type EvsCommitted struct {
	RepoId    sidecar.Id
	RefId     sidecar.Id
	ClusterId string
	// The repo's network, whose stored bytes the commit adds to, and the caller's, whose transfer it is.
	RepoNetworkId   sidecar.Id
	CallerNetworkId sidecar.Id
	// The head as this commit wrote it.
	Head *EvsStoredHead
	// The statement and what its payload checked to.
	Statement *sidecar.EvsStatement
	Payload   *sidecar.EvsCheckedPayload
	// The record's bytes, which the batch stores until evacuation moves them, and the request's.
	RecordByteCount  int64
	RequestByteCount int64
}

// Step 8's push sequence and hints (§11.10), which EVS1-M2-15 builds: raises {evsq_<repo_id>} and returns its new
// value, then hints every lease holder the commit matches. An error leaves the commit to the hourly resync, never
// an alarm, since all of it is soft state.
type EvsCommitNotifier interface {
	Notify(ctx context.Context, committed *EvsCommitted) (pushSequence uint64, err error)
}

// Steps 6 and 7 with step 7's outcomes. again asks for steps 4 and 5 again: the 5 s window passed, or a reread sent
// the attempt back.
func (self *pushAttempt) commit() (*pushOutcome, bool) {
	barrierKey := barrierRefKey(self.repoId, self.refId)
	testHookBarrier(BarrierPushStep6Before, barrierKey)
	outcome := self.step6()
	testHookBarrier(BarrierPushStep6After, barrierKey)
	if outcome != nil {
		return outcome, false
	}
	if outcome, again := self.raiseFormat(); outcome != nil || again {
		return outcome, again
	}
	conflicts := 0
	for {
		if !self.withinStepSeven() {
			return nil, true
		}
		next, outcome := self.nextHead()
		if outcome != nil {
			return outcome, false
		}
		prior := self.head
		self.issued = true
		written, err := self.engine.heads.Commit(self.writeCtx, self.cluster, self.repoId, self.refId, prior, next)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			self.head = written
			return self.committed(written), false
		case errors.Is(err, sidecar.ErrBlobPrecondition):
			// another write came first: this PUT can never apply, since an ETag never repeats
			self.issued = false
			conflicts += 1
			if self.settings.PushConflictRetryCount < conflicts {
				return self.busy(), false
			}
			outcome, again := self.afterConflict()
			if outcome != nil || again {
				return outcome, again
			}
		case errors.As(err, &unknown):
			outcome, again := self.afterUnknown(prior)
			if outcome != nil || again {
				return outcome, again
			}
		case errors.Is(err, ErrEvsHeadRule):
			// nothing was sent: a next head that breaks the head's rules is this code's fault
			self.issued = false
			self.engine.log.Errorf("[evs] alarm push_head_rule: repo %s ref %s: %v", sidecar.EvsKeyId(self.repoId), sidecar.EvsKeyId(self.refId), err)
			self.engine.metrics.alarms.Add(1, "push_head_rule")
			return self.unavailable(), false
		default:
			return self.unknown(), false
		}
	}
}

// §11.6's format row, between step 6's record and step 7: a push carrying a format-2 value, which 5c held to the
// format2 gate, raises a format-1 repo/ to format 2 (repo_format.go), under the push's own grant. The raise reads
// repo/ from the cluster, so a sibling's raise, or this push's own on an earlier attempt, is found there and nothing
// is written twice. A repo it finds in any state but active sends the attempt back to steps 4 and 5, where 5c
// refuses by its own rule on a head read from the cluster; lost races past RepoTransitionRetryCount answer 429,
// which refuses nothing. A raise whose push then fails stands, since format-1 data is valid format 2, and step 7's
// window still bounds the whole: a slow raise reruns steps 4 and 5. again asks for them.
func (self *pushAttempt) raiseFormat() (*pushOutcome, bool) {
	if !self.needsFormat2 || !self.engine.format2Instance() || sidecar.EvsRepoFormat2 <= self.reads.repo.Object.GetFormat() {
		return nil, false
	}
	classify := func(ctx context.Context, objectByteCount int) context.Context { return ctx }
	read, err := RaiseRepoFormat(self.writeCtx, self.cluster, self.engine.repos, self.repoId, self.settings.RepoTransitionRetryCount, classify)
	var refusal *EvsRepoRefusal
	switch {
	case err == nil:
		self.reads.repo = read
		return nil, false
	case errors.As(err, &refusal):
		// keying, deleted, shredding or shredded: no push commits on it, and 5c says which
		return nil, true
	case errors.Is(err, ErrEvsRepoBusy):
		return self.busy(), false
	}
	return self.unavailableOn(err), false
}

// Whether step 7 may still issue: within PushStepSevenWindow of step 4's reads.
func (self *pushAttempt) withinStepSeven() bool {
	return self.engine.clock.Now().Before(self.reads.readAt.Add(self.settings.PushStepSevenWindow))
}

// The 200 for this attempt's own commit.
func (self *pushAttempt) committed(written *EvsStoredHead) *pushOutcome {
	outcome := committedOutcome(written.Version(), written)
	if self.ownDepositRef() {
		outcome.depositHead = self.depositHeadOf(written.Head)
	}
	return outcome
}

// Step 6, once per attempt: the budget, the record and the new slots. A rerun of step 7 on a reread head keeps all
// three, since the record and the slots are this statement's whatever head it commits on.
func (self *pushAttempt) step6() *pushOutcome {
	if outcome := self.admit(); outcome != nil {
		return outcome
	}
	if self.place == nil {
		place, err := self.engine.batches.Append(self.writeCtx, self.cluster.ClusterId(), self.batchRecord())
		if err != nil {
			// nothing this attempt carried reached a head
			return self.unavailable()
		}
		self.place = place
	}
	if !self.slotsWritten {
		if outcome := self.writeSlots(); outcome != nil {
			return outcome
		}
		self.slotsWritten = true
	}
	return nil
}

// The batch record this attempt appends at step 6: a push's statement and payload, or a seal's statement and parts
// (push_seal.go); a part's is push_part.go's.
func (self *pushAttempt) batchRecord() *sidecar.EvsBatchRecord {
	record := &sidecar.EvsBatchRecord{
		Type:            protocol.EvsBatchRecordType_EVS_BATCH_PUSH,
		RepoId:          self.repoId,
		RefId:           self.refId,
		PushId:          self.pushId,
		SignerSidecarId: sidecar.Id(self.statement.Push.GetSignerSidecarId()),
		TimeMs:          self.statement.Push.GetTimeMs(),
		Body:            sidecar.EvsPushRecordBody(self.statement.Bytes, self.payloadBytes),
	}
	if self.seal != nil {
		record.Type = protocol.EvsBatchRecordType_EVS_BATCH_SEAL
		record.Body = self.seal.body
	}
	return record
}

// The record's bytes as its batch holds them, for the cost and the usage count.
func (self *pushAttempt) recordByteCount() int64 {
	return int64(sidecar.EvsBatchRecordHeaderByteCount + len(self.batchRecord().Body))
}

// The budget for the push's writes, once per attempt: AdmitP1 at its full price in the token network's queue.
func (self *pushAttempt) admit() *pushOutcome {
	if self.grant != nil {
		return nil
	}
	cost, err := self.cost()
	if err != nil {
		return self.unavailableOn(err)
	}
	if self.erasureP0() {
		// within its network's 60 a minute: P0, never queued or refused (§11.13's classes)
		self.writeCtx = self.engine.budget.IssueP0(self.ctx, self.cluster.ClusterId(), sidecar.WriteP0KindErasure, cost.ByteCount())
		self.grant = p0Grant{ctx: self.writeCtx}
		return nil
	}
	grant, err := self.engine.budget.AdmitP1(self.ctx, self.cluster.ClusterId(), connect.Id(self.tokenNetworkId), cost)
	var refusal *sidecar.WriteRefusal
	switch {
	case errors.As(err, &refusal):
		return refusedOutcome(&protocol.EvsRefusalReply{
			PushId:       self.pushId.Bytes(),
			Code:         protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED,
			RetryAfterMs: max(1, refusal.RetryAfterMs()),
		})
	case err != nil:
		return self.unavailable()
	}
	self.grant = grant
	self.writeCtx = grant.Context()
	return nil
}

// A P0 issue's ctx as a grant: nothing to release.
type p0Grant struct {
	ctx context.Context
}

func (self p0Grant) Context() context.Context {
	return self.ctx
}

func (self p0Grant) Close() {}

// §11.13's push row for this push, at one record a batch: now its head's overwrite, its batch share and its new
// slots; deferred its fold share (~0.3 folded entries a changed path), its batch's delete and evacuation (a parcel
// of its record and a pidx/ entry, as evacuation prices a batch) and its share of a log page.
func (self *pushAttempt) cost() (sidecar.WriteCost, error) {
	recordByteCount := self.recordByteCount()
	headByteCount := int64(len(self.head.Bytes) + sidecar.EvsWindowEntryByteCount)
	slotCount := 0
	changeCount := 0
	if self.payload != nil {
		changeCount = len(self.payload.Changes)
		for _, object := range self.payload.NewObjects {
			if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
				slotCount += 1
			}
		}
	}
	// the raise of a format-1 repo/ is priced with its push (§11.6's format row): one overwrite of repo/
	raiseCount := 0
	if self.needsFormat2 && self.reads.repo.Object.GetFormat() < sidecar.EvsRepoFormat2 {
		raiseCount = 1
	}
	return PricePush(self.engine.priceTable, &PushOperations{
		Immediate: []WriteOperation{
			{Kind: WriteOperationOverwrite, ObjectByteCount: headByteCount, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: recordByteCount, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: evsSlotMaxByteCount, Count: float64(slotCount)},
			{Kind: WriteOperationOverwrite, ObjectByteCount: sidecar.EvsRepoObjectMaxByteCount, Count: float64(raiseCount)},
		},
		Deferred: []WriteOperation{
			{Kind: WriteOperationOverwrite, Count: 0.3 * float64(changeCount)},
			{Kind: WriteOperationDelete, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: recordByteCount, Count: 1},
			{Kind: WriteOperationCreate, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: sidecar.EvsLogPageMaxByteCount, Count: 1.0 / EvsLogPageVersionCount},
		},
	})
}

// Step 6's new slots, one round: each PUT If-None-Match. See the file header.
func (self *pushAttempt) writeSlots() *pushOutcome {
	if self.payload == nil {
		return nil
	}
	slotIds := []sidecar.Id{}
	for _, object := range self.payload.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
			slotIds = append(slotIds, sidecar.Id(object.Id))
		}
	}
	if len(slotIds) == 0 {
		return nil
	}
	if len(slotIds) != len(self.payload.SlotBodies) {
		return refusedOutcome(newEvsCheckRefusal(EvsCheckReasonInvalid, "slot bodies unlike the new slots").Reply(self.pushId))
	}
	results := make([]slotWriteResult, len(slotIds))
	var waitGroup sync.WaitGroup
	for i, slotId := range slotIds {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			results[i] = self.writeSlot(slotId, self.payload.SlotBodies[i])
		}()
	}
	waitGroup.Wait()
	for _, result := range results {
		switch result {
		case slotWritten:
		case slotStale:
			return self.refuse(newEvsCheckRefusal(EvsCheckReasonSlotStale, "a slot that exists past 23 h"))
		case slotOtherBytes:
			// §11.8 step 6: a cluster read of the head, where 5a finds the push committed if an ERASE rewrote its slot
			head, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
			if err != nil {
				return self.unavailableOn(err)
			}
			if outcome := self.settle(head); outcome != nil {
				return outcome
			}
			self.engine.log.Errorf("[evs] alarm slot_mismatch: repo %s: a new slot's id holds another push's bytes", sidecar.EvsKeyId(self.repoId))
			self.engine.metrics.alarms.Add(1, "slot_mismatch")
			self.head = head
			return self.refuse(newEvsCheckRefusal(EvsCheckReasonSlotStale, "a slot that holds other bytes"))
		default:
			return self.unavailable()
		}
	}
	return nil
}

// What one slot's write found.
type slotWriteResult int

const (
	slotUnwritten slotWriteResult = iota
	slotWritten
	slotStale
	slotOtherBytes
)

// One new slot: If-None-Match; on 412 its bytes and age decide; an unknown outcome reads the key back, its bytes
// meaning written and a 404 writing again.
func (self *pushAttempt) writeSlot(slotId sidecar.Id, body []byte) slotWriteResult {
	key := SlotKey(self.repoId, slotId)
	for attempt := 0; attempt < 2; attempt += 1 {
		barrierKey := barrierRefKey(self.repoId, self.refId)
		testHookBarrier(BarrierPushSlotPutBefore, barrierKey)
		_, err := self.cluster.PutIfNoneMatch(self.writeCtx, key, body, nil)
		testHookBarrier(BarrierPushSlotPutAfter, barrierKey)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			return slotWritten
		case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
			object, getErr := self.cluster.Get(self.ctx, key)
			if errors.Is(getErr, sidecar.ErrBlobNotFound) && unknown != nil {
				// the lost write never landed: the same bytes again
				continue
			}
			if getErr != nil {
				return slotUnwritten
			}
			stored, readErr := readAllLimited(object, evsSlotMaxByteCount)
			object.Body.Close()
			switch {
			case readErr != nil:
				return slotUnwritten
			case !bytes.Equal(stored, body):
				return slotOtherBytes
			case evsSlotExistingMaxAge < self.engine.clock.Now().Sub(object.LastModified) && unknown == nil:
				return slotStale
			}
			return slotWritten
		default:
			return slotUnwritten
		}
	}
	return slotUnwritten
}

// Step 7's head over self.head: a page-out first when the window would pass 127 versions, then the commit's fields.
// A page-out that cannot finish pages nothing, and past 255 versions answers 429 FOLD_BEHIND.
func (self *pushAttempt) nextHead() (*protocol.EvsHead, *pushOutcome) {
	engine := self.engine
	if self.statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
		if outcome := self.foldEverything(); outcome != nil {
			return nil, outcome
		}
	}
	pageOut, err := engine.folder.PageOut(self.writeCtx, &EvsPageOutRequest{
		Cluster:    self.cluster,
		RepoId:     self.repoId,
		RefId:      self.refId,
		Head:       self.head,
		Cached:     self.head.Cached,
		HeadReadAt: self.reads.readAt,
		Deadline:   self.reads.readAt.Add(self.settings.PushStepSevenWindow - self.settings.PushPageOutReserve),
	})
	var behind *EvsFoldBehindError
	switch {
	case errors.As(err, &behind):
		return nil, refusedOutcome(&protocol.EvsRefusalReply{
			PushId:       self.pushId.Bytes(),
			Code:         protocol.EvsRefusalCode_EVS_REFUSAL_FOLD_BEHIND,
			RetryAfterMs: max(1, behind.RetryAfterMs()),
		})
	case err != nil:
		return nil, self.unavailableOn(err)
	}
	next, err := self.buildNextHead(pageOut)
	if err != nil {
		return nil, self.unavailableOn(err)
	}
	return next, nil
}

// §11.7's when row (4): a PATH_EPOCH's own process folds every version through the head it commits on, so its step-7
// head sets folded_through = v; a fold that cannot finish within step 7's window answers 503, refusing nothing.
func (self *pushAttempt) foldEverything() *pushOutcome {
	engine := self.engine
	readAt := engine.clock.Now()
	head, err := engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	if err != nil {
		return self.unavailableOn(err)
	}
	deadline := self.reads.readAt.Add(self.settings.PushStepSevenWindow - self.settings.PushPageOutReserve)
	if _, err := engine.folder.FoldAll(self.writeCtx, self.cluster, self.repoId, self.refId, head, readAt, deadline); err != nil {
		return self.unavailable()
	}
	if engine.folder.Horizon(self.repoId, self.refId, self.head.Head) < self.head.Version() {
		return self.unavailable()
	}
	return nil
}

// The commit's head over self.head, with pageOut applied. See the file header.
func (self *pushAttempt) buildNextHead(pageOut *EvsPageOut) (*protocol.EvsHead, error) {
	prior := self.head.Head
	push := self.statement.Push
	next := CloneEvsHead(prior)
	chain := sidecar.EvsChainStart(self.repoId, self.refId)
	if prior.GetVersion() == 0 {
		// the ref's first commit, on no head or on a placeholder holding refusal records, which it keeps
		next.RefKind = push.GetRefKind()
		next.RefMode = push.GetRefMode()
		next.OwnerSidecarId = push.GetOwnerSidecarId()
		next.PathEpoch = &protocol.EvsPathEpoch{Current: max(1, push.GetPathEpoch())}
		next.WindowBaseChain = append([]byte{}, chain[:]...)
		next.Window = nil
	} else {
		var err error
		chain, err = sidecar.EvsChainFromBytes(prior.GetChain())
		if err != nil {
			return nil, fmt.Errorf("%w: a head chain of %d bytes", ErrEvsHeadInvalid, len(prior.GetChain()))
		}
	}
	nextChain := sidecar.EvsChainNext(chain, self.pushId, self.statement.Sha256)
	next.Version = prior.GetVersion() + 1
	next.Chain = nextChain[:]
	next.PushId = self.pushId.Bytes()
	next.Auth = push.GetAuth()
	next.GroupId = push.GetGroupId()
	next.Generation = push.GetGeneration()
	next.GenerationCommitment = push.GetGenerationCommitment()
	var coveringPrefixes []sidecar.EvsTokenPath
	if len(push.GetChangesRoot()) != 0 {
		coveringPrefixes = self.statement.ChangedPrefixes
	}
	entry := sidecar.NewEvsWindowEntry(self.statement.Sha256, push, self.payload.ChangedPaths(), coveringPrefixes, self.payload.CreatesPath, self.place)
	next.Window = append(append([]byte{}, next.GetWindow()...), entry.Encode()...)
	next.Lease = nil
	next.Deleted = push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) != 0
	switch {
	case push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0:
		next.PathEpoch = committedPathEpoch(prior, push.GetPathEpoch(), push.GetPathMapSha256())
	case self.due != nil:
		next.PathEpoch = applyPathEpochDue(next.GetPathEpoch(), self.due, self.engine.clock.Now())
	}
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME) != 0 {
		next.ConsumedThrough = consumedThroughOf(prior, push)
	}
	if err := pageOut.Apply(next); err != nil {
		return nil, err
	}
	return next, nil
}

// What step 8 takes of this attempt's commit.
func (self *pushAttempt) newCommitted(head *EvsStoredHead) *EvsCommitted {
	return &EvsCommitted{
		RepoId:           self.repoId,
		RefId:            self.refId,
		ClusterId:        self.cluster.ClusterId(),
		RepoNetworkId:    self.networkId,
		CallerNetworkId:  self.tokenNetworkId,
		Head:             head,
		Statement:        self.statement,
		Payload:          self.payload,
		RecordByteCount:  self.recordByteCount(),
		RequestByteCount: self.request.requestByteCount,
	}
}

// Step 8, off the reply path, in this order: the push sequence and hints, which the head cache entry records, so
// the sequence is raised first; usage; the head cache; the fold trigger. Each failure is logged and costs only
// latency: everything here is soft state.
func (self *EvsEngine) afterCommit(committed *EvsCommitted) {
	self.stepEightCount.Update(func(count int) int { return count + 1 })
	go func() {
		defer self.stepEightDoneCount.Update(func(count int) int { return count + 1 })
		barrierKey := barrierRefKey(committed.RepoId, committed.RefId)
		testHookBarrier(BarrierPushStep8Before, barrierKey)
		defer testHookBarrier(BarrierPushStep8After, barrierKey)
		ctx := self.ctx
		pushSequence := uint64(0)
		if self.notifier != nil {
			sequence, err := self.notifier.Notify(ctx, committed)
			if err != nil {
				self.log.Infof("[evs] repo %s: push sequence or hints not sent: %v", sidecar.EvsKeyId(committed.RepoId), err)
			} else {
				pushSequence = sequence
			}
		}
		if uploads := self.deps.Uploads; uploads != nil && uploads.Usage != nil {
			if err := uploads.Usage.AddStored(connect.Id(committed.RepoNetworkId), committed.RecordByteCount); err != nil {
				self.log.Infof("[evs] stored bytes of a commit not counted: %v", err)
			}
			if err := uploads.Usage.AddTransfer(connect.Id(committed.CallerNetworkId), committed.RequestByteCount); err != nil {
				self.log.Infof("[evs] transfer of a commit not counted: %v", err)
			}
		}
		self.heads.CacheCommit(ctx, committed.RepoId, committed.RefId, committed.Head, pushSequence)
		self.folder.NoteCommit(committed.ClusterId, committed.RepoId, committed.RefId, committed.Head.Head)
		if push := committed.Statement.Push; push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
			self.queueEpochCopy(ctx, committed.RepoId, committed.RefId, push.GetPathEpoch())
		}
	}()
}

// Queues §11.6's copy of a committed PATH_EPOCH's sources into epoch (epoch_copy.go), once-keyed by repo, ref and
// epoch. A queue that does not answer is logged: the sources stand until a copy runs, which costs reads, never
// correctness.
func (self *EvsEngine) queueEpochCopy(ctx context.Context, repoId sidecar.Id, refId sidecar.Id, epoch uint64) {
	if self.host.Tasks == nil {
		self.log.Warningf("[evs] repo %s: no task queue, so its path-epoch copy waits", sidecar.EvsKeyId(repoId))
		return
	}
	if err := self.host.Tasks.Schedule(ctx, EvsEpochCopyTaskRequest(repoId, refId, epoch, self.clock.Now())); err != nil {
		self.log.Warningf("[evs] repo %s: its path-epoch copy was not queued: %v", sidecar.EvsKeyId(repoId), err)
	}
}

// How many commits have started step 8 and how many have finished it, with a channel that closes at the next
// finish: what a test waits on before it reads what step 8 wrote.
func (self *EvsEngine) StepEights() (started int, finished int, changed chan struct{}) {
	started, _ = self.stepEightCount.Get()
	finished, changed = self.stepEightDoneCount.Get()
	return started, finished, changed
}
