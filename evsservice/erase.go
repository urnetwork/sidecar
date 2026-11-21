// Erasure on evs (§11.12's push, directory and drops rows; owner decisions 61, 133; I-EVS-1, I-EVS-16; EVS1-M2-20):
//
//	route    POST /evs/v1/repos/<id>/slots/delete (admin, the team directory's included) takes an ERASE push on the
//	         repo's erasure ref, as POST .../push takes any push: a token below admin gets 403 SCOPE at arrival,
//	         before any read, commit or slot rewrite (I-EVS-16), and a statement that is no ERASE is refused
//	step 4   reads each slot the ERASE's erased list names
//	5h       a list naming no key those slots still hold gets 409 NOTHING_TO_ERASE, recorded (§11.8's refuse row),
//	         but for a completion ERASE (flag 1024 beside ERASE alone; QD-1132, QD-1137), which evs takes where the
//	         newest earlier ERASE naming each of its keys carries no COMPLETION (eraseRules); it destroys nothing, so
//	         the rewrites after it, and the reconciler's, find nothing to drop
//	after    once the ERASE commits, and again whenever an attempt of it finds it committed, each named slot is
//	         rewritten without those keys, If-Match the slot it read and keeping its origin (DESIGN-DETAILS 14.2.6),
//	         before the 200, under a preservation hold too: a slot answering 404 is done, since every key it held is
//	         gone (the drops row); a rewrite that cannot finish answers 503 unknown, which the client's retry
//	         finishes, and queues taskworker's evs.erasure_finish for the repo, which FinishErasures runs
//	versionless  a slot-keyed repo's versionless path keeps its one key in its own slot, so the rewrite above
//	         destroys every version of the path at once, under a hold too, and waits for no purge (§11.12's
//	         versionless row; EVS2-M10-12); in a general repo the key rides the kind-5 segment and goes with it
//	class    a network's ERASE, CUT and CLOSURE pushes within 60 a minute are P0, past it P1, counted through
//	         Quota.CountRate's evs_erasure_pushes; every slot rewrite is P0 (§11.13's classes)
//
// The nightly inventory discovers each erasure ref independently of the writer. The reconciler walks the committed
// window and earlier log pages, including packed pages and records. Each task finishes one page, newest first.

package evsservice

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
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
		objectBytes, err := readAllLimited(object, self.settings.SlotMaxByteCount)
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
//
// A completion ERASE, flagged COMPLETION beside ERASE alone (§11.12's push row; QD-1132, QD-1137; the root's
// evs_erase_completion.go), ends an erasure that no ERASE with a key is left to complete, and destroys nothing. Its
// erasure id and complete byte ride its sealed metadata, which evs cannot open (I-1), so the flag is what evs reads it
// by. One naming a key a slot still holds is INVALID. Otherwise evs takes it where the newest earlier ERASE naming each
// key, found within CompletionLookbackCount ERASEs of the head (readCompletionNamings), carries no COMPLETION, and
// answers NOTHING_TO_ERASE where one carries it, a racing runner's second completion, or where none names it, a key no
// ERASE destroyed. An unflagged ERASE naming no held key, a duplicate, stays NOTHING_TO_ERASE.
func (self *pushAttempt) eraseRules(view *PushView) *EvsCheckRefusal {
	if self.erasureSlots == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no slots read")
	}
	held := false
	for _, erased := range view.Payload.Erased {
		read := self.erasureSlots[erased.SlotId]
		if read == nil || read.objectBytes == nil {
			continue
		}
		slot, err := sidecar.EvsDecodeSlotObject(read.objectBytes)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a slot that does not parse")
		}
		if _, ok := sidecar.EvsSlotKeyAt(slot, uint32(erased.KeyIndex)); ok {
			held = true
			break
		}
	}
	if !view.has(protocol.EvsPushFlag_EVS_PUSH_COMPLETION) {
		if held {
			return nil
		}
		return newEvsCheckRefusal(EvsCheckReasonNothingToErase, "no named key is still held")
	}
	if held {
		return newEvsCheckRefusal(EvsCheckReasonInvalid, "a completion naming a key a slot still holds")
	}
	if self.completion == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no completion reads")
	}
	for _, erased := range view.Payload.Erased {
		naming := self.completion.newest[*erased]
		switch {
		case naming == nil:
			return newEvsCheckRefusal(EvsCheckReasonNothingToErase, "a completion naming a key no ERASE within the lookback named")
		case naming.completion:
			return newEvsCheckRefusal(EvsCheckReasonNothingToErase, "a completion naming a key a completion named last")
		}
	}
	return nil
}

// QD-1137's reads for a completion ERASE, over the head step 4 read.
type completionReads struct {
	headVersion uint64
	// The newest earlier ERASE naming each key the completion names; a key none within the lookback named is absent.
	newest map[sidecar.EvsErasedKey]*completionNaming
}

// The newest earlier ERASE naming one key: its version on the erasure ref, and whether it is a completion.
type completionNaming struct {
	version    uint64
	completion bool
}

// Step 4's read for a completion ERASE (§11.12's push row; QD-1137): the erasure ref's ERASEs from the head step 4 read
// back, at most CompletionLookbackCount of them, until each key the completion names is found named. Read again for
// each head step 4 reads, since a racing completion moves it.
func (self *pushAttempt) readCompletionNamings() error {
	if self.payload == nil {
		return errors.New("a completion with no payload read")
	}
	head := self.head
	headVersion := uint64(0)
	if head != nil && !head.Absent() {
		headVersion = head.Version()
	}
	if self.completion != nil && self.completion.headVersion == headVersion {
		return nil
	}
	reads := &completionReads{headVersion: headVersion, newest: map[sidecar.EvsErasedKey]*completionNaming{}}
	wanted := map[sidecar.EvsErasedKey]bool{}
	for _, erased := range self.payload.Erased {
		wanted[*erased] = true
	}
	if 0 < headVersion {
		pushes := newReadPushes(self.engine, self.ctx, self.cluster, self.repoId, self.refId, head.Head)
		examined := 0
		for version := headVersion; 0 < version && 0 < len(wanted) && examined < self.settings.CompletionLookbackCount; version -= 1 {
			push, err := pushes.at(version)
			if err != nil {
				return err
			}
			flags := push.statement.Push.GetFlags()
			if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) == 0 {
				continue
			}
			examined += 1
			if err := pushes.readRecord(push); err != nil {
				return err
			}
			if push.payload == nil {
				return fmt.Errorf("%w: an ERASE at version %d whose record holds no payload", ErrEvsStatementMismatch, version)
			}
			completion := flags&uint32(protocol.EvsPushFlag_EVS_PUSH_COMPLETION) != 0
			for _, erased := range push.payload.Erased {
				if wanted[*erased] {
					delete(wanted, *erased)
					reads.newest[*erased] = &completionNaming{version: version, completion: completion}
				}
			}
		}
	}
	self.completion = reads
	return nil
}

// After an ERASE commits, or an attempt of it finds it committed: every named slot rewritten without its keys. A
// rewrite that cannot finish answers 503 unknown, and queues the reconciler.
func (self *pushAttempt) finishErase() *pushOutcome {
	rewriter := &slotRewriter{budget: self.engine.budget, priceTable: self.engine.priceTable, settings: self.engine.settings}
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
	settings   *EvsSettings
}

// Each named slot without its erased keys: read, rewritten If-Match with the object metadata it read, so a slot keeps
// its origin (DESIGN-DETAILS 14.2.6), again on a 412 or a lost answer; a 404 is done.
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
	for attempt := 0; attempt <= self.settings.SlotRewriteRetryCount; attempt += 1 {
		object, err := cluster.Get(ctx, key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		objectBytes, err := readAllLimited(object, self.settings.SlotMaxByteCount)
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
		// the origin rides on, so every slot a push wrote says who made it for as long as it stands
		var options *sidecar.BlobPutOptions
		if 0 < len(object.Metadata) {
			options = &sidecar.BlobPutOptions{Metadata: maps.Clone(object.Metadata)}
		}
		_, err = cluster.PutIfMatch(writeCtx, key, object.Etag, rewritten, options)
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
	return fmt.Errorf("slot %s: %d rewrites lost their race", sidecar.EvsKeyId(slotId), self.settings.SlotRewriteRetryCount)
}

// The initial task accepts the original repo-ID args. A continuation names the
// highest version still to check. Each page gets its own idempotent queue key.
func erasureFinishRequest(repoId sidecar.Id, through uint64, runAt time.Time) *sidecar.TaskRequest {
	args := repoId.Bytes()
	onceKey := sidecar.EvsKeyId(repoId)
	if through != 0 {
		args = binary.BigEndian.AppendUint64(args, through)
		onceKey += fmt.Sprintf("/%d", through)
	}
	return &sidecar.TaskRequest{Name: EvsErasureFinishTaskName, OnceKey: onceKey, Args: args, RunAt: runAt}
}

func ParseErasureFinishArgs(args []byte) (sidecar.Id, uint64, bool) {
	var repoId sidecar.Id
	switch len(args) {
	case len(repoId):
		return sidecar.Id(args), 0, true
	case len(repoId) + 8:
		through := binary.BigEndian.Uint64(args[len(repoId):])
		return sidecar.Id(args[:len(repoId)]), through, through != 0
	default:
		return repoId, 0, false
	}
}

// A live rewrite failure asks for an early pass. The nightly pass will also
// discover the durable head when a writer stops before it can schedule a task.
func (self *EvsEngine) queueErasureFinish(ctx context.Context, repoId sidecar.Id) {
	if self.host.Tasks == nil {
		return
	}
	if err := self.host.Tasks.Schedule(ctx, erasureFinishRequest(repoId, 0, self.clock.Now().Add(self.settings.ErasureFinishDelay))); err != nil {
		self.log.Warningf("[evs] repo %s: the erasure reconciler not queued: %v", sidecar.EvsKeyId(repoId), err)
	}
}

// Reconcile one page. Queue its predecessor before acknowledging this task so
// a worker can restart at either side of the handoff and repeat it safely.
func RunErasureFinish(ctx context.Context, host *sidecar.ServiceHost, repoId sidecar.Id, through uint64) error {
	_, remaining, err := finishErasures(ctx, host, repoId, through, true)
	if err != nil || remaining == 0 {
		return err
	}
	if host.Tasks == nil {
		return errors.New("no task queue to continue erasure reconciliation")
	}
	return host.Tasks.Schedule(ctx, erasureFinishRequest(repoId, remaining, host.ClockOrReal().Now()))
}

// Finishes every committed ERASE on the ref, including archived versions.
func FinishErasures(ctx context.Context, host *sidecar.ServiceHost, repoId sidecar.Id) (int, error) {
	finished, _, err := finishErasures(ctx, host, repoId, 0, false)
	return finished, err
}

func finishErasures(ctx context.Context, host *sidecar.ServiceHost, repoId sidecar.Id, through uint64, pageOnly bool) (int, uint64, error) {
	if host == nil || host.Blobs == nil || host.Budget == nil {
		return 0, 0, errors.New("no host to finish erasures on")
	}
	settings := DefaultEvsSettings()
	priceTable, err := DefaultPriceTable(settings.PriceBlockByteCount)
	if err != nil {
		return 0, 0, err
	}
	blobs := NewBudgetedBlobs(host.Blobs)
	firstCluster, err := blobs.FirstCluster()
	if err != nil {
		return 0, 0, err
	}
	place, err := sidecar.ReadEvsRepoPlace(ctx, firstCluster, repoId)
	if err != nil {
		return 0, 0, err
	}
	cluster, err := blobs.Cluster(place.ClusterId)
	if err != nil {
		return 0, 0, err
	}
	heads := NewHeadStore(host.ClockOrReal(), host.ClockCheck, nil, settings, sidecar.NewNoopLogger())
	refId := sidecar.EvsErasureRefId(repoId)
	head, err := heads.ReadCluster(ctx, cluster, repoId, refId)
	if err != nil || head.Absent() {
		return 0, 0, err
	}
	if through == 0 {
		through = head.Version()
	} else if head.Version() < through {
		return 0, 0, fmt.Errorf("%w: erasure continuation at %d past head %d", ErrEvsStatementMismatch, through, head.Version())
	}
	first := uint64(1)
	if pageOnly && through != 0 {
		first, _ = EvsLogPageVersions(EvsLogPageOf(through))
	}
	reader, err := newDropRefReader(ctx, cluster, repoId, refId, head.Head, NewRecordCache(settings), NewRecordLocator(blobs, nil), NewLogPageCache(settings), nil)
	if err != nil {
		return 0, 0, err
	}
	rewriter := &slotRewriter{budget: host.Budget, priceTable: priceTable, settings: settings}
	finished := 0
	for version := through; first <= version; version -= 1 {
		entry, _, err := reader.entryAt(version)
		if err != nil {
			return finished, 0, err
		}
		if !entry.RewritesHistory() {
			continue
		}
		statement, payload, err := reader.pushAt(version, entry)
		if err != nil {
			return finished, 0, err
		}
		flags := statement.Push.GetFlags()
		if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) == 0 || flags&uint32(protocol.EvsPushFlag_EVS_PUSH_COMPLETION) != 0 {
			continue
		}
		if err := rewriter.rewriteErased(ctx, cluster, repoId, payload.Erased); err != nil {
			return finished, 0, err
		}
		finished += 1
	}
	return finished, first - 1, nil
}

// An ERASE's, CUT's or CLOSURE's class: P0 within its network's 60 a minute, counted once a push id, else P1 (§11.13).
// A count that does not answer leaves it P1, which the budget pays.
func (self *pushAttempt) erasureP0() bool {
	flags := self.statement.Push.GetFlags()
	if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE|protocol.EvsPushFlag_EVS_PUSH_CLOSURE|protocol.EvsPushFlag_EVS_PUSH_CUT) == 0 || self.engine.host.Quota == nil {
		return false
	}
	refusal, err := self.engine.host.Quota.CountRate(self.ctx, connect.Id(self.networkId), map[string]int64{sidecar.QuotaRateKeyErasurePush: 1}, connect.Id(self.pushId))
	return err == nil && refusal == nil
}
