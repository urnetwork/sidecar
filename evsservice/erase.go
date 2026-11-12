// Erasure on evs (§11.12's push, directory and drops rows; owner decisions 61, 133; I-EVS-1, I-EVS-16; EVS1-M2-20):
//
//	route    POST /evs/v1/repos/<id>/slots/delete (admin, the team directory's included) takes an ERASE push on the
//	         repo's erasure ref, as POST .../push takes any push: a token below admin gets 403 SCOPE at arrival,
//	         before any read, commit or slot rewrite (I-EVS-16), and a statement that is no ERASE is refused
//	step 4   reads each slot the ERASE's erased list names
//	5h       a list naming no key those slots still hold gets 409 NOTHING_TO_ERASE, recorded (§11.8's refuse row)
//	after    once the ERASE commits, and again whenever an attempt of it finds it committed, each named slot is
//	         rewritten without those keys, If-Match the slot it read, before the 200, under a preservation hold
//	         too: a slot answering 404 is done, since every key it held is gone (the drops row); a rewrite that
//	         cannot finish answers 503 unknown, which the client's retry finishes, and queues taskworker's
//	         evs.erasure_finish for the repo, which FinishErasures runs
//	class    a network's ERASE, CUT and CLOSURE pushes within 60 a minute are P0, past it P1, counted through
//	         Quota.CountRate's evs_erasure_pushes; every slot rewrite is P0 (§11.13's classes)
//
// FinishErasures, the reconciler's half, reads the erasure ref's head window and finishes every committed ERASE's
// rewrites there; versions paged into log pages are left to the client's own resume (§11.12's reconcile row), which
// re-commits what a crash left missing.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The route's template.
const evsSlotsDeleteTemplate = "POST /evs/v1/repos/{repo_id}/slots/delete"

// taskworker's job that finishes a repo's committed ERASEs' slot rewrites, its args the repo id.
const EvsErasureFinishTaskName = "evs.erasure_finish"

// How long after a rewrite that could not finish taskworker tries it.
const evsErasureFinishDelay = time.Minute

// How many times one slot is read and rewritten again after a 412 or a lost answer.
const evsSlotRewriteRetryCount = 8

// The slots/delete route.
func (self *EvsEngine) erasureRoutes() []*EvsRoute {
	return []*EvsRoute{
		{
			Method:         http.MethodPost,
			Pattern:        evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}/slots/delete",
			Name:           evsSlotsDeleteTemplate,
			Rights:         sidecar.AclEvsAdmin,
			Write:          true,
			NeedsSureClock: true,
			Placed:         true,
			RefuseDeleted:  true,
			Serve:          self.serveSlotsDelete,
		},
	}
}

// See the file header.
func (self *EvsEngine) serveSlotsDelete(request *EvsRequest) {
	body := &protocol.EvsPushRequest{}
	if !request.ReadMessage(body, self.settings.PushBodyMaxByteCount) {
		return
	}
	attempt, ok := self.newPushAttempt(request, body)
	if !ok {
		return
	}
	if attempt.statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) == 0 {
		attempt.cancel()
		request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, "slots/delete takes an ERASE").Reply(attempt.pushId))
		return
	}
	outcome := attempt.run()
	attempt.answer(outcome)
}

// One slot as step 4 read it: its bytes, nil for a 404.
type erasureSlotRead struct {
	objectBytes []byte
}

// Step 4's read of every slot an ERASE names, into self.erasureSlots.
func (self *pushAttempt) readErasureSlots() error {
	slots := map[sidecar.Id]*erasureSlotRead{}
	for _, erased := range self.payload.Erased {
		if _, ok := slots[erased.SlotId]; ok {
			continue
		}
		object, err := self.cluster.Get(self.ctx, SlotKey(self.repoId, erased.SlotId))
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			slots[erased.SlotId] = &erasureSlotRead{}
			continue
		}
		if err != nil {
			return err
		}
		objectBytes, err := readAllLimited(object, DefaultEvsSettings().SlotMaxByteCount)
		object.Body.Close()
		if err != nil {
			return err
		}
		slots[erased.SlotId] = &erasureSlotRead{objectBytes: objectBytes}
	}
	self.erasureSlots = slots
	return nil
}

// 5h's ERASE and CLOSURE rules, the view's ErasureRules.
func (self *pushAttempt) erasureRules(view *PushView) *EvsCheckRefusal {
	switch {
	case view.has(protocol.EvsPushFlag_EVS_PUSH_ERASE):
		return self.eraseRules(view)
	case view.has(protocol.EvsPushFlag_EVS_PUSH_CLOSURE):
		return closureRules(view)
	}
	return nil
}

// An ERASE names at least one key its slots still hold, else 409 NOTHING_TO_ERASE.
func (self *pushAttempt) eraseRules(view *PushView) *EvsCheckRefusal {
	if self.erasureSlots == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no slots read")
	}
	for _, erased := range view.Payload.Erased {
		read := self.erasureSlots[erased.SlotId]
		if read == nil || read.objectBytes == nil {
			continue
		}
		slot, err := sidecar.EvsDecodeSlotObject(read.objectBytes)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a slot that does not parse")
		}
		if _, held := sidecar.EvsSlotKeyAt(slot, uint32(erased.KeyIndex)); held {
			return nil
		}
	}
	return newEvsCheckRefusal(EvsCheckReasonNothingToErase, "no named key is still held")
}

// After an ERASE commits, or an attempt of it finds it committed: every named slot rewritten without its keys. A
// rewrite that cannot finish answers 503 unknown, and queues the reconciler.
func (self *pushAttempt) finishErase() *pushOutcome {
	rewriter := &slotRewriter{budget: self.engine.budget, priceTable: self.engine.priceTable}
	if err := rewriter.rewriteErased(self.ctx, self.cluster, self.repoId, self.payload.Erased); err != nil {
		self.engine.log.Warningf("[evs] repo %s: an ERASE's slot rewrites did not finish: %v", sidecar.EvsKeyId(self.repoId), err)
		self.engine.queueErasureFinish(self.ctx, self.repoId)
		return self.unknown()
	}
	return nil
}

// What rewrites slots: every rewrite P0 (§11.13's classes), priced by the table.
type slotRewriter struct {
	budget     sidecar.WriteBudget
	priceTable *PriceTable
}

// Each named slot without its erased keys: read, rewritten If-Match, again on a 412 or a lost answer; a 404 is done.
func (self *slotRewriter) rewriteErased(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, erased []*sidecar.EvsErasedKey) error {
	slotIndexes := map[sidecar.Id][]uint32{}
	slotIds := []sidecar.Id{}
	for _, key := range erased {
		if _, ok := slotIndexes[key.SlotId]; !ok {
			slotIds = append(slotIds, key.SlotId)
		}
		slotIndexes[key.SlotId] = append(slotIndexes[key.SlotId], uint32(key.KeyIndex))
	}
	for _, slotId := range slotIds {
		if err := self.rewriteSlot(ctx, cluster, repoId, slotId, slotIndexes[slotId]); err != nil {
			return err
		}
	}
	return nil
}

// One slot without the keys at keyIndexes. See rewriteErased.
func (self *slotRewriter) rewriteSlot(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, slotId sidecar.Id, keyIndexes []uint32) error {
	key := SlotKey(repoId, slotId)
	for attempt := 0; attempt <= evsSlotRewriteRetryCount; attempt += 1 {
		object, err := cluster.Get(ctx, key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		objectBytes, err := readAllLimited(object, DefaultEvsSettings().SlotMaxByteCount)
		object.Body.Close()
		if err != nil {
			return err
		}
		rewritten, removedCount, err := sidecar.EvsSlotWithoutKeys(objectBytes, keyIndexes)
		if err != nil {
			return err
		}
		if removedCount == 0 {
			return nil
		}
		price, err := self.priceTable.Price(WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: int64(len(rewritten)), Count: 1})
		if err != nil {
			return err
		}
		writeCtx := self.budget.IssueP0(ctx, cluster.ClusterId(), sidecar.WriteP0KindErasure, price)
		_, err = cluster.PutIfMatch(writeCtx, key, object.Etag, rewritten, nil)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			return nil
		case errors.Is(err, sidecar.ErrBlobNotFound):
			return nil
		case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
			// read again: a landed write leaves nothing to drop
		default:
			return err
		}
	}
	return fmt.Errorf("slot %s: %d rewrites lost their race", sidecar.EvsKeyId(slotId), evsSlotRewriteRetryCount)
}

// Queues taskworker's evs.erasure_finish for the repo, a minute on. A queue that does not answer is logged: the
// client's retry finishes the rewrites too.
func (self *EvsEngine) queueErasureFinish(ctx context.Context, repoId sidecar.Id) {
	if self.host.Tasks == nil {
		return
	}
	err := self.host.Tasks.Schedule(ctx, &sidecar.TaskRequest{
		Name:    EvsErasureFinishTaskName,
		OnceKey: sidecar.EvsKeyId(repoId),
		Args:    repoId.Bytes(),
		RunAt:   self.clock.Now().Add(evsErasureFinishDelay),
	})
	if err != nil {
		self.log.Warningf("[evs] repo %s: the erasure reconciler not queued: %v", sidecar.EvsKeyId(repoId), err)
	}
}

// The reconciler's half (§11.12's push row: "a crash between leaves the client's retry, then taskworker's
// reconciler, to finish the rewrites"): every committed ERASE in the repo's erasure ref's head window has its slots
// rewritten without its keys. How many ERASEs it went over.
func FinishErasures(ctx context.Context, host *sidecar.ServiceHost, repoId sidecar.Id) (int, error) {
	if host == nil || host.Blobs == nil || host.Budget == nil {
		return 0, errors.New("no host to finish erasures on")
	}
	settings := DefaultEvsSettings()
	priceTable, err := DefaultPriceTable(settings.PriceBlockByteCount)
	if err != nil {
		return 0, err
	}
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
	heads := NewHeadStore(host.ClockOrReal(), host.ClockCheck, nil, settings, sidecar.NewNoopLogger())
	refId := sidecar.EvsErasureRefId(repoId)
	head, err := heads.ReadCluster(ctx, cluster, repoId, refId)
	if err != nil || head.Absent() {
		return 0, err
	}
	window, err := EvsHeadWindow(head.Head)
	if err != nil {
		return 0, err
	}
	records := NewRecordCache(settings)
	rewriter := &slotRewriter{budget: host.Budget, priceTable: priceTable}
	finished := 0
	for _, entry := range window {
		if !entry.RewritesHistory() {
			continue
		}
		record, err := ReadRecord(ctx, records, cluster, entry.Place)
		if err != nil {
			return finished, err
		}
		statementBytes, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return finished, err
		}
		statement, err := sidecar.ParseEvsStatement(statementBytes)
		if err != nil || statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) == 0 {
			continue
		}
		payload, err := sidecar.EvsCheckPayload(statement, payloadBytes)
		if err != nil {
			return finished, err
		}
		if err := rewriter.rewriteErased(ctx, cluster, repoId, payload.Erased); err != nil {
			return finished, err
		}
		finished += 1
	}
	return finished, nil
}

// An ERASE's, CUT's or CLOSURE's class: P0 within its network's 60 a minute, counted once a push id, else P1 (§11.13).
// A count that does not answer leaves it P1, which the budget pays.
func (self *pushAttempt) erasureP0() bool {
	flags := self.statement.Push.GetFlags()
	if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE|protocol.EvsPushFlag_EVS_PUSH_CLOSURE) == 0 || self.engine.host.Quota == nil {
		return false
	}
	refusal, err := self.engine.host.Quota.CountRate(self.ctx, connect.Id(self.networkId), map[string]int64{sidecar.QuotaRateKeyErasurePush: 1}, connect.Id(self.pushId))
	return err == nil && refusal == nil
}
