// POST /evs/v1/repos/<id>/push/<push_id>/<k> (§11.8's parts row; EVS1-M2-13): one part of a push over 1 MiB or 1,024
// entry writes, {Signed EvsPush, EvsPushPart k, receipts}, at most 1,024 parts and 4 at once from one client. evs
// runs steps 4 and 5 (a-e, g, h) for the part's own entries over the same reads a one-part push makes (push_step4.go,
// check.go's part stage), then appends the part, its receipts and the head version it checked as a batch record
// (a batch alone above 256 KiB) and answers 200 {place}. Nothing here commits:
//
//   - a part's refusal is answered as is and never recorded, since only its push's seal commits (§11.8's refuse row),
//     and the fence row ends no part, since a part issues no step 7;
//   - a part posted twice is two records, and the seal names one; the rest is dead weight evacuation drops;
//   - 5h takes the part's own receipts as its uploads, and leaves slots to the seal (check_objects.go);
//   - git mode takes the seal lease first (push_lease.go), which 5f holds other pushes to; a part does not run 5f,
//     so a part is taken whatever lease stands, and the seal decides;
//   - at a format-2 instance a part may carry format 2 (EVS2-M10-06): its statement and part are read by format 2's
//     parsers, its staged segments ride its record's tail, and its record lists each versionless version it
//     replaces, whole, with replaced set (DESIGN-DETAILS 10.2.6), which the seal subtracts every part's names from.

package evsservice

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The route's template and path values.
const (
	evsPartRouteTemplate = "POST /evs/v1/repos/{repo_id}/push/{push_id}/{part}"
	evsPushIdPathValue   = "push_id"
	evsPartPathValue     = "part"
)

// The part route.
func (self *EvsEngine) partRoutes() []*EvsRoute {
	return []*EvsRoute{
		{
			Method:         http.MethodPost,
			Pattern:        evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}/push/{" + evsPushIdPathValue + "}/{" + evsPartPathValue + "}",
			Name:           evsPartRouteTemplate,
			Rights:         sidecar.AclEvsWrite | sidecar.AclEvsDeposit | sidecar.AclEvsAdmin,
			Write:          true,
			NeedsSureClock: true,
			Placed:         true,
			Serve:          self.servePart,
		},
	}
}

// The one part this attempt is of.
type partReads struct {
	// k, from 1.
	number uint32
	// The part as sent, which parts_sha256 covers.
	bytes   []byte
	checked *sidecar.EvsCheckedPart
	// Each receipt's bytes, as the record keeps them.
	receiptItems [][]byte
}

// See the file header.
func (self *EvsEngine) servePart(request *EvsRequest) {
	pushId, err := parseEvsHexId(request.Http.PathValue(evsPushIdPathValue))
	if err != nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	number, err := strconv.ParseUint(request.Http.PathValue(evsPartPathValue), 10, 32)
	if err != nil || number == 0 || sidecar.EvsMaxPartCount < number {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	body := &protocol.EvsPartRequest{}
	if !request.ReadMessage(body, self.settings.PushBodyMaxByteCount) {
		return
	}
	attempt, ok := self.newPartAttempt(request, body, pushId, uint32(number))
	if !ok {
		return
	}
	outcome := attempt.run()
	attempt.answer(outcome)
}

// The attempt for one part, or false once the request has been answered: a statement or part that does not parse
// or verify, or of another push than the path's, refuses nothing (400), and a format-2 construct answers
// FORMAT_UNSUPPORTED unrecorded, since only the seal commits.
func (self *EvsEngine) newPartAttempt(request *EvsRequest, body *protocol.EvsPartRequest, pushId sidecar.Id, number uint32) (*pushAttempt, bool) {
	ctx, cancel := self.newAttemptContext(request)
	attempt := &pushAttempt{
		engine:         self,
		request:        request,
		settings:       self.settings,
		ctx:            ctx,
		cancel:         cancel,
		arrival:        request.started,
		repoId:         request.RepoId,
		cluster:        request.Cluster,
		receipts:       body.GetReceipts(),
		tokenNetworkId: networkIdOf(request.Principal),
	}
	ok := false
	defer func() {
		if !ok {
			attempt.cancel()
		}
	}()
	format2 := self.format2Instance()
	statement, err := sidecar.ParseEvsStatement(body.GetStatement())
	if err != nil && format2 && EvsCheckRefusalOfCodec(err).Reason == EvsCheckReasonFormatUnsupported {
		// a format-2 statement at a format-2 instance: the gate's question at 5c
		statement, err = sidecar.ParseEvsStatementFormat2(body.GetStatement())
		attempt.needsFormat2 = err == nil
	}
	if err != nil {
		request.Refuse(EvsCheckRefusalOfCodec(err).Reply(pushId))
		return nil, false
	}
	attempt.statement = statement
	push := statement.Push
	attempt.pushId = sidecar.Id(push.GetPushId())
	attempt.refId = sidecar.Id(push.GetRefId())
	request.NoteRefIds(attempt.refId)
	if attempt.pushId != pushId {
		request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, "a part of another push than the path's").Reply(pushId))
		return nil, false
	}
	if len(body.GetStaged()) != 0 && !format2 {
		// staged segments are format 2's
		refusal := newEvsCheckRefusal(EvsCheckReasonFormatUnsupported, "staged segments")
		refusal.NeedsFormat = 2
		request.Refuse(refusal.Reply(pushId))
		return nil, false
	}
	var checked *sidecar.EvsCheckedPart
	if format2 {
		checked, err = sidecar.EvsCheckPartFormat2(statement, body.GetPart(), body.GetStaged())
	} else {
		checked, err = sidecar.EvsCheckPart(statement, body.GetPart())
	}
	if err != nil {
		request.Refuse(EvsCheckRefusalOfCodec(err).Reply(pushId))
		return nil, false
	}
	if checked.Part != number {
		request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, "a part numbered unlike its path").Reply(pushId))
		return nil, false
	}
	receiptItems := make([][]byte, len(body.GetReceipts()))
	for i, receipt := range body.GetReceipts() {
		item, err := marshalDeterministic(receipt)
		if err != nil {
			request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, "a receipt that does not encode").Reply(pushId))
			return nil, false
		}
		receiptItems[i] = item
	}
	attempt.part = &partReads{number: number, bytes: body.GetPart(), checked: checked, receiptItems: receiptItems}
	attempt.payload = &sidecar.EvsCheckedPayload{Changes: checked.Changes, CreatesPath: checked.CreatesPath, Staged: checked.Staged}
	if format2 {
		attempt.staged = body.GetStaged()
		attempt.needsFormat2 = attempt.needsFormat2 || 0 < len(attempt.staged) || sidecar.EvsChangesNeedFormat2(checked.Changes)
	}
	if !attempt.bind() {
		return nil, false
	}
	ok = true
	return attempt, true
}

// The part's step 6: its record, paid at P1 in the token network's queue, appended to the open batch with the head
// version it was checked at; then 200 {place}. Nothing reaches the head.
func (self *pushAttempt) appendPart() *pushOutcome {
	if outcome := self.admitPart(); outcome != nil {
		return outcome
	}
	record := &sidecar.EvsBatchRecord{
		Type:            protocol.EvsBatchRecordType_EVS_BATCH_PART,
		RepoId:          self.repoId,
		RefId:           self.refId,
		PushId:          self.pushId,
		SignerSidecarId: sidecar.Id(self.statement.Push.GetSignerSidecarId()),
		TimeMs:          self.statement.Push.GetTimeMs(),
		Body:            sidecar.EvsPartRecordBody(self.statement.Bytes, self.part.bytes, self.part.receiptItems, self.head.Version()),
	}
	var tail *sidecar.EvsBatchRecordTail
	if self.engine.format2Instance() {
		// its replaced versions' ids whole, and its staged segments (push_staged.go, push_purge.go)
		base := sidecar.EvsBatchRecordHeaderByteCount + len(record.Body) + 4 + len(self.staged)
		self.purge = evsPartPurge(self.reads.view, evsPurgeListRoom(base))
		var err error
		if tail, err = evsRecordTail(self.staged, self.purge); err != nil {
			return self.unavailableOn(err)
		}
	}
	barrierKey := barrierRefKey(self.repoId, self.refId)
	testHookBarrier(BarrierPartAppendBefore, barrierKey)
	place, err := self.engine.batches.AppendFormat2(self.writeCtx, self.cluster.ClusterId(), record, tail)
	testHookBarrier(BarrierPartAppendAfter, barrierKey)
	if err != nil {
		return self.unavailable()
	}
	return &pushOutcome{committed: true, partPlace: place}
}

// The budget for the part's record: one create at P1, with its evacuation deferred as a push's is.
func (self *pushAttempt) admitPart() *pushOutcome {
	if self.grant != nil {
		return nil
	}
	recordByteCount := int64(sidecar.EvsBatchRecordHeaderByteCount + len(self.statement.Bytes) + len(self.part.bytes) + 8)
	for _, item := range self.part.receiptItems {
		recordByteCount += int64(len(item))
	}
	cost, err := PricePush(self.engine.priceTable, &PushOperations{
		Immediate: []WriteOperation{{Kind: WriteOperationCreate, ObjectByteCount: recordByteCount, Count: 1}},
		Deferred: []WriteOperation{
			{Kind: WriteOperationDelete, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: recordByteCount, Count: 1},
		},
	})
	if err != nil {
		return self.unavailableOn(err)
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
