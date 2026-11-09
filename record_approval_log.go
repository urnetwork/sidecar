// §16.8's Approvals bullet, on every leg: the log an approval request goes to and how a decision comes back.
// RecordApprovals picks the log and files and reads the approval family's entries; MCP-M3-05's ApprovalRouter and
// ApprovalInbox keep the requester's local state on top of it and hold no second route table, and MCP-M3-07's
// ApprovalRender shows what Pending hands it.
//
//	request    to a log its approver reads: the member's vault; for a tagged sidecar its sponsor's, by deposit; for
//	           a tagged sidecar with no sponsor, or an approver who is not the author, the team record, which is
//	           RECORD-M6-01's, so at M3 such a request is refused and stays pending, failing closed
//	decision   back through that vault, by the approver's device; read by the requester by hint, and by Decision,
//	           the poll behind ur://approval/{id}
//	use        approval_use, after §16.6's Outcome, never instead of it
//
// Bodies are stored bytes: an ApprovalRequest as the ledger keeps it, and a decision or a cancel as its Signed bytes,
// never re-marshaled, since request_sha256 and payload_sha256 bind them. ApprovalDecision holds no run or agent id, and
// nothing here adds one. Pending hands an approver's device each request's stored bytes through
// ParseStoredApprovalRequest, which recomputes payload_sha256 and action_id and refuses an action version
// CanonicalActionVersionKnown lacks, so a render shows only daemon-built fields, and summary as untrusted text.
//
// A deposit-only requester reads no vault: its grant decisions reach it as §8.8's GrantActivate deltas (ACL-M4-02), and
// a decision on anything else is to reach it as the sealed ApprovalDelivery delta the owner chose
// (plan-RECORD-deposit-only-decisions), which is not built. Until it is, Decision answers such a requester
// ErrRecordApprovalUndeliverable, and its non-grant actions stay pending: nothing spends.
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// No decision or cancel is in the request's log yet.
	ErrRecordApprovalPending = errors.New("record approval pending")
	// The request was cancelled.
	ErrRecordApprovalCancelled = errors.New("record approval cancelled")
	// The requester reads no vault, so no decision reaches it here: grant decisions arrive as GrantActivate deltas,
	// and the ApprovalDelivery delta for the rest is not built (plan-RECORD-deposit-only-decisions).
	ErrRecordApprovalUndeliverable = errors.New("record approval decision undeliverable to a deposit-only requester")
	// The approval's route is the team record, RECORD-M6-01's: a tagged sidecar with no sponsor, an approver who is not
	// the author, or a log that is not this device's vault.
	ErrRecordApprovalTeamRoute = errors.New("record approval routes to the team record")
	// No request with that approval_id is in the log.
	ErrRecordApprovalUnknown = errors.New("record approval unknown")
)

// The approval family's log, on the record's writer and reader.
type RecordApprovals struct {
	writer *recordWriter
	reader *RecordReader
}

// One request waiting for a decision, as an approver's device reads it.
type RecordPendingApproval struct {
	LogId   Id
	EntryId Id
	// Parsed from its stored bytes, payload_sha256 and action_id recomputed: nil when Refused is set.
	Request *StoredApprovalRequest
	// Why this device will not render the request: an action version it does not know, a payload_sha256 that is not
	// its action's, or a request that does not parse. Shown as refused, never approved unseen (D-MCP-17).
	Refused error
	// The entry's header is tainted.
	Flagged bool
	// The requesting writer.
	WriterSidecarId Id
}

// The route of this device's approval-family entries: its author's vault, and whether it deposits there.
func (self *RecordApprovals) route() (*recordRoute, error) {
	auth := self.writer.auth()
	route, err := recordVaultRoute(auth, self.writer.sidecarId)
	if errors.Is(err, errRecordUnrouted) {
		if _, member := auth.Member(self.writer.sidecarId); !member {
			if _, sponsored := auth.Sponsor(self.writer.sidecarId); !sponsored {
				return nil, fmt.Errorf("%w: a tagged sidecar with no sponsor", ErrRecordApprovalTeamRoute)
			}
		}
	}
	return route, err
}

// Files request, as the ledger stores it, in the log its approver reads, and answers where it went. A request whose
// approvers are not this device's author is the team record's (RECORD-M6-01) and is refused here, staying pending.
func (self *RecordApprovals) FileRequest(request *StoredApprovalRequest) (*RecordEntryRef, error) {
	if request == nil {
		return nil, fmt.Errorf("%w: no request", ErrRecordDraftInvalid)
	}
	auth := self.writer.auth()
	authorId, ok := auth.Member(self.writer.sidecarId)
	if !ok {
		authorId, ok = auth.Sponsor(self.writer.sidecarId)
	}
	if !ok {
		return nil, fmt.Errorf("%w: no author", ErrRecordApprovalTeamRoute)
	}
	for _, approver := range request.Request.GetApprovers() {
		if !bytes.Equal(approver, authorId[:]) {
			return nil, fmt.Errorf("%w: an approver who is not the author", ErrRecordApprovalTeamRoute)
		}
	}
	draft := &RecordDraft{
		Kind:       RecordKindApproval,
		Source:     RecordSourceObserved,
		ActionId:   bytes.Clone(request.Request.GetActionId()),
		StoredBody: request.Bytes,
	}
	if runId := request.Request.GetRunId(); len(runId) != 0 {
		id := recordIdOf(runId)
		draft.RunId = &id
	} else {
		// no run: an app's or a person's command; a request the ledger marked tainted seals tainted
		draft.NoSession = !request.Request.GetTainted()
	}
	if agentId := request.Request.GetAgentId(); len(agentId) != 0 {
		id := recordIdOf(agentId)
		draft.AgentId = &id
	}
	return self.appendOne(draft)
}

// Appends one approval-family draft through the writer, which routes it to this device's author's vault.
func (self *RecordApprovals) appendOne(draft *RecordDraft) (*RecordEntryRef, error) {
	refs, err := self.writer.Append(draft)
	if err != nil {
		return nil, err
	}
	return refs[0], nil
}

// The request entry of approvalId in logId, read by this device's reader.
func (self *RecordApprovals) requestEntry(logId Id, approvalId Id) (*RecordReadEntry, *protocol.ApprovalRequest, bool) {
	for _, entry := range self.reader.Entries(logId) {
		if entry.Kind() != RecordKindApproval || entry.Body == nil {
			continue
		}
		request := &protocol.ApprovalRequest{}
		if proto.Unmarshal(entry.Body, request) != nil || !bytes.Equal(request.GetApprovalId(), approvalId[:]) {
			continue
		}
		return entry, request, true
	}
	return nil, nil, false
}

// Files an approver's decision, its Signed as stored, in logId beside its request. runId is the harness run whose
// prompt decided it, channel harness alone; nil for a decision a person made at a device.
func (self *RecordApprovals) FileDecision(ctx context.Context, logId Id, storedSigned []byte, runId *Id) (*RecordEntryRef, error) {
	decision, err := ParseStoredApprovalDecision(storedSigned)
	if err != nil {
		return nil, err
	}
	approvalId := recordIdOf(decision.Decision.GetApprovalId())
	source := RecordSourceApprover
	if protocol.ApprovalChannel(decision.Decision.GetChannel()) == protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS {
		// FS-28: a harness prompt's decision is only what a same-user process could say
		source = RecordSourceHook
	}
	return self.fileAnswer(ctx, logId, approvalId, RecordKindApprovalDecision, source, storedSigned, runId)
}

// Files an approver's cancel, its Signed as stored, in logId beside its request.
func (self *RecordApprovals) FileCancel(ctx context.Context, logId Id, storedSigned []byte) (*RecordEntryRef, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(storedSigned, signed); err != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_APPROVAL_CANCEL) {
		return nil, fmt.Errorf("%w: no approval cancel", ErrRecordStoredInvalid)
	}
	cancel := &protocol.ApprovalCancel{}
	if err := proto.Unmarshal(signed.GetBody(), cancel); err != nil || len(cancel.GetApprovalId()) != recordIdByteCount {
		return nil, fmt.Errorf("%w: an approval cancel's body", ErrRecordStoredInvalid)
	}
	return self.fileAnswer(ctx, logId, recordIdOf(cancel.GetApprovalId()), RecordKindApprovalCancel, RecordSourceApprover, storedSigned, nil)
}

// A decision or cancel into logId, which must be this device's own route: the log its request is in.
func (self *RecordApprovals) fileAnswer(ctx context.Context, logId Id, approvalId Id, kind RecordKind, source RecordSource, storedSigned []byte, runId *Id) (*RecordEntryRef, error) {
	route, err := self.route()
	if err != nil {
		return nil, err
	}
	if route.logId != logId {
		return nil, fmt.Errorf("%w: a log other than this device's vault", ErrRecordApprovalTeamRoute)
	}
	if err := self.reader.Sync(ctx, logId); err != nil {
		return nil, err
	}
	_, request, ok := self.requestEntry(logId, approvalId)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrRecordApprovalUnknown, approvalId)
	}
	draft := &RecordDraft{
		Kind:       kind,
		Source:     source,
		RunId:      runId,
		NoSession:  runId == nil,
		ActionId:   bytes.Clone(request.GetActionId()),
		StoredBody: storedSigned,
	}
	return self.appendOne(draft)
}

// Files an approval_use for one use of approvalId, after §16.6's Outcome is recorded, in the requester's route.
func (self *RecordApprovals) FileUse(use *protocol.ApprovalUseBody, runId *Id, actionId []byte) (*RecordEntryRef, error) {
	if use == nil {
		return nil, fmt.Errorf("%w: no use", ErrRecordDraftInvalid)
	}
	draft := &RecordDraft{
		Kind:      RecordKindApprovalUse,
		Source:    RecordSourceObserved,
		RunId:     runId,
		NoSession: runId == nil,
		ActionId:  bytes.Clone(actionId),
		Body:      use,
	}
	return self.appendOne(draft)
}

// The requests waiting in the logs this approver's device reads, each with no decision or cancel and not past its
// not_after, in read order. A request this device will not render is listed refused.
func (self *RecordApprovals) Pending(ctx context.Context) ([]*RecordPendingApproval, error) {
	route, err := self.route()
	if err != nil {
		return nil, err
	}
	if err := self.reader.Sync(ctx, route.logId); err != nil {
		return nil, err
	}
	nowMillis := self.writer.clock.Now().UnixMilli()
	entries := self.reader.Entries(route.logId)
	answered := map[Id]bool{}
	for _, entry := range entries {
		if approvalId, ok := recordAnswerApprovalId(entry); ok {
			answered[approvalId] = true
		}
	}
	pending := []*RecordPendingApproval{}
	for _, entry := range entries {
		if entry.Kind() != RecordKindApproval || entry.Body == nil {
			continue
		}
		item := &RecordPendingApproval{
			LogId:           route.logId,
			EntryId:         entry.EntryId,
			Flagged:         entry.Flagged,
			WriterSidecarId: recordIdOf(entry.Header.Header.GetWriterSidecarId()),
		}
		request, err := ParseStoredApprovalRequest(entry.Body)
		if err != nil {
			item.Refused = err
			pending = append(pending, item)
			continue
		}
		if answered[request.ApprovalId()] || request.Request.GetNotAfterMillis() <= nowMillis {
			continue
		}
		if !bytes.Equal(entry.Header.Header.GetActionId(), request.Request.GetActionId()) {
			item.Refused = fmt.Errorf("%w: the entry's action_id is not its request's", ErrRecordStoredInvalid)
		} else {
			item.Request = request
		}
		pending = append(pending, item)
	}
	return pending, nil
}

// The approval_id a decision or cancel entry answers, false for another entry.
func recordAnswerApprovalId(entry *RecordReadEntry) (Id, bool) {
	if entry.Body == nil {
		return Id{}, false
	}
	switch entry.Kind() {
	case RecordKindApprovalDecision:
		decision, err := ParseStoredApprovalDecision(entry.Body)
		if err != nil {
			return Id{}, false
		}
		return recordIdOf(decision.Decision.GetApprovalId()), true
	case RecordKindApprovalCancel:
		signed := &bridge.Signed{}
		cancel := &protocol.ApprovalCancel{}
		if proto.Unmarshal(entry.Body, signed) != nil || proto.Unmarshal(signed.GetBody(), cancel) != nil || len(cancel.GetApprovalId()) != recordIdByteCount {
			return Id{}, false
		}
		return recordIdOf(cancel.GetApprovalId()), true
	}
	return Id{}, false
}

// The requester's poll: the first decision on approvalId in its request's log, which must name the request by its
// stored bytes (StoredApprovalDecision.Binds). ErrRecordApprovalPending while none is there, ErrRecordApprovalCancelled
// once a cancel is, and ErrRecordApprovalUndeliverable to a deposit-only requester. The decision's signature, signer
// and channel are the spender's to check (§16.6's spendable, MCP-M3-05's inbox).
func (self *RecordApprovals) Decision(ctx context.Context, approvalId Id) (*StoredApprovalDecision, error) {
	route, err := self.route()
	if err != nil {
		return nil, err
	}
	if route.deposit {
		return nil, fmt.Errorf("%w: %s", ErrRecordApprovalUndeliverable, approvalId)
	}
	if err := self.reader.Sync(ctx, route.logId); err != nil {
		return nil, err
	}
	requestEntry, _, ok := self.requestEntry(route.logId, approvalId)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrRecordApprovalUnknown, approvalId)
	}
	request, err := ParseStoredApprovalRequest(requestEntry.Body)
	if err != nil {
		return nil, err
	}
	for _, entry := range self.reader.Entries(route.logId) {
		answered, ok := recordAnswerApprovalId(entry)
		if !ok || answered != approvalId {
			continue
		}
		if entry.Kind() == RecordKindApprovalCancel {
			return nil, fmt.Errorf("%w: %s", ErrRecordApprovalCancelled, approvalId)
		}
		decision, err := ParseStoredApprovalDecision(entry.Body)
		if err != nil || !decision.Binds(request) {
			writerId := recordIdOf(entry.Header.Header.GetWriterSidecarId())
			self.writer.raise(SidecarRecordAlarmBadDecision, route.logId, &writerId)
			continue
		}
		return decision, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrRecordApprovalPending, approvalId)
}
