// §16.8's Approvals bullet, on every leg: the log an approval request goes to and how a decision comes back.
// RecordApprovals picks the log and files and reads the approval family's entries; MCP-M3-05's ApprovalRouter and
// ApprovalInbox keep the requester's local state on top of it and hold no second route table, and MCP-M3-07's
// ApprovalRender shows what Pending hands it.
//
//	request    to a log its approver reads: the member's vault, copied to any team record with the same bytes; for
//	           a tagged sidecar its sponsor's, by deposit; for a tagged sidecar with no sponsor, or an approver who is
//	           not the author, an admin's, the team record alone (RECORD-M6-01), its copy in the requester's vault;
//	           in a network with no team record such a request is refused and stays pending, failing closed
//	decision   back through that log, by the approver's device: a member's through the vault, copied to the team
//	           record; an admin's into the team record, where only a requester that reads it finds it, so a member
//	           device's admin-approved non-grant action stays pending until the ApprovalDelivery delta exists; read by
//	           the requester by hint, and by Decision, the poll behind ur://approval/{id}
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
	// The approval's route is the team record, and this network has none, or the log named is neither this device's
	// vault nor the team record: a tagged sidecar with no sponsor, or an approver who is not the author.
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

// Files request, as the ledger stores it, in the log its approver reads, and answers where it went: the author's
// vault, or the team record for a tagged sidecar with no sponsor or an approver who is not the author. With no team
// record those are refused here, staying pending.
func (self *RecordApprovals) FileRequest(request *StoredApprovalRequest) (*RecordEntryRef, error) {
	if request == nil {
		return nil, fmt.Errorf("%w: no request", ErrRecordDraftInvalid)
	}
	auth := self.writer.auth()
	teamRecordId, _ := recordTeamLogs(auth)
	authorId, ok := auth.Member(self.writer.sidecarId)
	if !ok {
		authorId, ok = auth.Sponsor(self.writer.sidecarId)
	}
	if !ok && teamRecordId == nil {
		return nil, fmt.Errorf("%w: no author", ErrRecordApprovalTeamRoute)
	}
	teamOnly := false
	for _, approver := range request.Request.GetApprovers() {
		if ok && !bytes.Equal(approver, authorId[:]) {
			if teamRecordId == nil {
				return nil, fmt.Errorf("%w: an approver who is not the author", ErrRecordApprovalTeamRoute)
			}
			teamOnly = true
		}
	}
	draft := &RecordDraft{
		Kind:       RecordKindApproval,
		Source:     RecordSourceObserved,
		ActionId:   bytes.Clone(request.Request.GetActionId()),
		StoredBody: request.Bytes,
		TeamOnly:   teamOnly,
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

// A decision or cancel into logId, the log its request is in: this device's own vault, or the team record, where it
// goes alone.
func (self *RecordApprovals) fileAnswer(ctx context.Context, logId Id, approvalId Id, kind RecordKind, source RecordSource, storedSigned []byte, runId *Id) (*RecordEntryRef, error) {
	teamRecordId, _ := recordTeamLogs(self.writer.auth())
	inTeam := teamRecordId != nil && *teamRecordId == logId
	if !inTeam {
		route, err := self.route()
		if err != nil {
			return nil, err
		}
		if route.logId != logId {
			return nil, fmt.Errorf("%w: a log other than this device's vault or the team record", ErrRecordApprovalTeamRoute)
		}
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
		TeamOnly:   inTeam,
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

// The logs this device reads approvals in: its author's vault, and the team record where it reads it, an admin's or
// an auditor's device.
func (self *RecordApprovals) approvalLogs() ([]Id, error) {
	auth := self.writer.auth()
	logIds := []Id{}
	route, err := self.route()
	if err == nil && auth.Reads(route.logId, self.writer.sidecarId) {
		logIds = append(logIds, route.logId)
	}
	if teamRecordId, _ := recordTeamLogs(auth); teamRecordId != nil && auth.Reads(*teamRecordId, self.writer.sidecarId) {
		logIds = append(logIds, *teamRecordId)
	}
	if len(logIds) == 0 {
		if err == nil {
			err = fmt.Errorf("%w: this device reads no approval log", ErrRecordNotReader)
		}
		return nil, err
	}
	return logIds, nil
}

// The requests waiting in the logs this approver's device reads, each with no decision or cancel and not past its
// not_after, in read order, the vault's first. A request this device will not render is listed refused.
func (self *RecordApprovals) Pending(ctx context.Context) ([]*RecordPendingApproval, error) {
	logIds, err := self.approvalLogs()
	if err != nil {
		return nil, err
	}
	pending := []*RecordPendingApproval{}
	for _, logId := range logIds {
		logPending, err := self.pendingIn(ctx, logId)
		if err != nil {
			return nil, err
		}
		pending = append(pending, logPending...)
	}
	return pending, nil
}

// Pending's requests in one log.
func (self *RecordApprovals) pendingIn(ctx context.Context, logId Id) ([]*RecordPendingApproval, error) {
	if err := self.reader.Sync(ctx, logId); err != nil {
		return nil, err
	}
	nowMillis := self.writer.clock.Now().UnixMilli()
	entries := self.reader.Entries(logId)
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
			LogId:           logId,
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
	auth := self.writer.auth()
	teamRecordId, _ := recordTeamLogs(auth)
	readsTeam := teamRecordId != nil && auth.Reads(*teamRecordId, self.writer.sidecarId)
	route, err := self.route()
	logIds := []Id{}
	switch {
	case err == nil && !route.deposit:
		logIds = append(logIds, route.logId)
	case err == nil && !readsTeam:
		return nil, fmt.Errorf("%w: %s", ErrRecordApprovalUndeliverable, approvalId)
	case err != nil && (!errors.Is(err, ErrRecordApprovalTeamRoute) || teamRecordId == nil):
		return nil, err
	case err != nil && !readsTeam:
		// a tagged sidecar with no sponsor filed to the team record, which it does not read
		return nil, fmt.Errorf("%w: %s", ErrRecordApprovalUndeliverable, approvalId)
	}
	if readsTeam {
		logIds = append(logIds, *teamRecordId)
	}
	for _, logId := range logIds {
		if err := self.reader.Sync(ctx, logId); err != nil {
			return nil, err
		}
		if requestEntry, _, ok := self.requestEntry(logId, approvalId); ok {
			return self.decisionIn(logId, approvalId, requestEntry)
		}
	}
	if teamRecordId != nil && !readsTeam {
		// filed to the team record, which this device does not read: an admin's decision cannot reach it here
		return nil, fmt.Errorf("%w: %s", ErrRecordApprovalUndeliverable, approvalId)
	}
	return nil, fmt.Errorf("%w: %s", ErrRecordApprovalUnknown, approvalId)
}

// The first decision on approvalId in logId, beside its request's entry.
func (self *RecordApprovals) decisionIn(logId Id, approvalId Id, requestEntry *RecordReadEntry) (*StoredApprovalDecision, error) {
	request, err := ParseStoredApprovalRequest(requestEntry.Body)
	if err != nil {
		return nil, err
	}
	for _, entry := range self.reader.Entries(logId) {
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
			self.writer.raise(SidecarRecordAlarmBadDecision, logId, &writerId)
			continue
		}
		return decision, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrRecordApprovalPending, approvalId)
}
