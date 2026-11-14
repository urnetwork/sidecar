//go:build !ios_extension

// §16.11's decisions (RECORD-M6-19; D-MCP-34, the Requests table's decide, deny, cancel and duplicates rows; FS-100):
// a person approves or denies a request on /dev/tty or in an app, never through MCP, on a device that is not
// read_only, by one resumable protocol:
//
//	1 intent     the decision is journaled in the device's approval ledger before anything is signed
//	             (DirectoryDecideJournal; plan-RECORD-small-readings#9): what was decided, for whom, until when
//	2 statement  an approval signs the target's statement and journals its bytes, then files it: a RepoGrant, or an
//	             owner-bound repo's EvsShare, at once; for reach an ApprovalDecision on channel device or presence,
//	             never harness, which the entry carries and nothing files. A denial signs none
//	3 entry      the decision entry is appended to this device's stream: the request's id and its entry's hash, the
//	             outcome, the statement's hash and position or the ApprovalDecision, the subject and expiry as approved
//	4 notice     last, the notice is rewritten from the version read: an approval adds its DecisionRef, the notice
//	             turning decided, approved, once it holds the rule's count of approvals, and a denial makes it
//	             decided, denied, naming the denial alone
//
// After a crash, at a restart and at each sync, ResumeDecisions takes each unfinished journal up from its last row
// with the same signed bytes and the same push id, filing, appending or rewriting only what is missing, until the
// notice names the decision or is gone; a journal is kept until not_after + 1 d. The decision entry's DecisionRef
// names its header's hash, which this device reads back from its own stream, so the rewrite waits for the entry to
// land and a sync to read it.
//
//	duplicates   a decision on a decided notice signs nothing. Racing deciders meet at the rewrite, each rereading on
//	             a conflict: a denial that finds it decided is void, shown superseded; an approval that finds it
//	             approved is a duplicate; a repo approval that finds it denied rewrites it to approved naming itself,
//	             since its statement is filed and a denial vetoes no eligible approval; a reach approval that finds it
//	             decided is void, its ApprovalDecision never spent; a notice that is gone ends the journal
//	cancel       the requester's decision entry with outcome cancelled, then the notice's removal from the pending
//	             version it read: a cancel that a decided rewrite beat fails and shows that decision
//	workers      an approval for a worker names only services the worker announces (owner decision 179, FI-26): the
//	             request's ports are held to the worker's item, and the action's sealed detail to those ports, before
//	             anything is journaled
//
// Signing and filing are a seam (DirectoryStatements) the daemon binds to its statement filer and its approver;
// unbound, an approval refuses before its intent is journaled and a denial still decides. Barriers:
// directory.decide.<step>.before and .after around each step's effect, keyed by the request's id.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// The journal's row kind in the approval ledger.
const DirectoryDecideLedgerRow ApprovalLedgerRowKind = "decide"

// The protocol's steps, as a journal row names them.
const (
	DirectoryDecideStepIntent    = 1
	DirectoryDecideStepStatement = 2
	DirectoryDecideStepEntry     = 3
	DirectoryDecideStepNotice    = 4
)

// How a journal ended at its notice.
const (
	// The notice names this decision.
	DirectoryDecideWritten = "written"
	// An approval that found the notice approved already.
	DirectoryDecideDuplicate = "duplicate"
	// A denial, or a reach approval, that found the notice decided: void.
	DirectoryDecideSuperseded = "superseded"
	// The notice was gone: cancelled, closed or past its life.
	DirectoryDecideGone = "gone"
)

var (
	// This device does not decide the request: it is not eligible for its target at the state now.
	ErrDirectoryDecideNotEligible = errors.New("this device does not decide the request")
	// The request is decided, cancelled or expired: nothing is signed on it.
	ErrDirectoryRequestDecided = errors.New("directory request is not pending")
	// Nothing here signs or files a target's statement, so no approval is given.
	ErrDirectoryStatementsUnbound = errors.New("nothing signs a directory approval here")
	// No journal is bound, so nothing is decided: a decision is journaled before it is signed.
	ErrDirectoryJournalUnbound = errors.New("no approval ledger journals a directory decision here")
	// An approval for a worker that names a service the worker does not announce, or whose sealed detail does not
	// open to the ports the request names.
	ErrDirectoryDecideServices = errors.New("the request names a service its worker does not announce")
	// A cancel that a decision beat: the request shows that decision.
	ErrDirectoryCancelBeaten = errors.New("the request was decided before its cancel")
)

// What a person decides: `ur directory approve|deny` and an app's decision.
type DirectoryDecideArgs struct {
	RequestId Id
	Approve   bool
	// Narrows a member subject to one of its sidecars; nil keeps the request's subject.
	ForSidecarId *Id
	// The grant's expiry as approved, 0 for the request's ask or the approver's default; never later than asked.
	GrantExpiresMillis int64
	// The request's role, or 0 for it; an approver changes no role.
	Role uint32
	// Prose, at most 512 B.
	Note string
}

// A repo's access as approved, which its statement grants.
type DirectoryRepoAccess struct {
	RepoId  Id
	Subject Id
	// The RepoGrant's role; an EvsShare carries none.
	Role uint32
	// 0 for none.
	ExpiresMillis int64
	// An owner-bound repo: an EvsShare by its owner's consented device, never a RepoGrant.
	OwnerBound bool
}

// The signing and filing of a decision's statements, which a daemon binds to its statement filer (§7.9) and its
// approver (§16.6). Each call is the person's act, confirmed where the daemon confirms such acts.
type DirectoryStatements interface {
	// Signs the RepoGrant or EvsShare of access and answers its Signed as it will be filed, filing nothing.
	SignRepoAccess(ctx context.Context, access *DirectoryRepoAccess) ([]byte, error)
	// Files a statement SignRepoAccess answered, and answers its position in the authorization log once the log
	// holds it. Filing the same bytes again files nothing more and answers the same position.
	FileStatement(ctx context.Context, signed []byte) (uint64, error)
	// Signs an ApprovalDecision approving a reach request for subject until expiresMillis, on channel device or
	// presence, never harness: its Signed, which the decision entry carries.
	SignReachDecision(ctx context.Context, request *StoredApprovalRequest, subject Id, expiresMillis int64) ([]byte, error)
}

// One journal row (plan-RECORD-small-readings#9): Decide{request_id, step, payload, push_id, millis}.
type DirectoryDecideRow struct {
	RequestId Id     `json:"request_id"`
	Step      int    `json:"step"`
	Payload   []byte `json:"payload,omitempty"`
	PushId    Id     `json:"push_id"`
	Millis    int64  `json:"millis"`
}

// Its kind in the ledger.
func (self *DirectoryDecideRow) ApprovalLedgerRowKind() ApprovalLedgerRowKind {
	return DirectoryDecideLedgerRow
}

// Step 1's payload: the decision as the person made it, fixed before anything is signed.
type directoryDecideIntent struct {
	Outcome            uint32 `json:"outcome"`
	RequesterSidecarId Id     `json:"requester_sidecar_id"`
	RequestEntrySha256 []byte `json:"request_entry_sha256"`
	NoticePath         string `json:"notice_path"`
	NotAfterMillis     int64  `json:"not_after_millis"`
	Subject            Id     `json:"subject"`
	Role               uint32 `json:"role"`
	GrantExpiresMillis int64  `json:"grant_expires_millis"`
	Note               string `json:"note"`
	// repo, worker or socket, and a repo's owner-bound bit
	Reach      bool `json:"reach"`
	OwnerBound bool `json:"owner_bound"`
	RepoId     Id   `json:"repo_id"`
}

// Step 2's payload: the statement as signed, and its position once filed.
type directoryDecideStatement struct {
	Signed   []byte `json:"signed"`
	Position uint64 `json:"position,omitempty"`
}

// Step 3's payload: the decision entry as appended.
type directoryDecideEntry struct {
	EntryId Id     `json:"entry_id"`
	Seq     uint64 `json:"seq"`
}

// One request's journal folded.
type directoryDecideState struct {
	requestId Id
	intent    *directoryDecideIntent
	// the notice rewrite's push id, journaled with the intent
	noticePushId Id
	// the newest statement row, nil for none
	statement *directoryDecideStatement
	entry     *directoryDecideEntry
	// how it ended, "" while unfinished
	ended string
}

// The decide rows of the approval ledger (§16.6's file class approval), one file a request, each row fsynced before the
// step it guards.
type DirectoryDecideJournal struct {
	ledger *ApprovalLedger
}

// A journal over ledger, nil for none.
func NewDirectoryDecideJournal(ledger *ApprovalLedger) *DirectoryDecideJournal {
	if ledger == nil {
		return nil
	}
	return &DirectoryDecideJournal{ledger: ledger}
}

// Appends one row.
func (self *DirectoryDecideJournal) append(requestId Id, step int, payload any, pushId Id, millis int64) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return self.ledger.Append(requestId, &DirectoryDecideRow{RequestId: requestId, Step: step, Payload: encoded, PushId: pushId, Millis: millis})
}

// A request's journal folded, nil when the ledger holds no decide row for it.
func (self *DirectoryDecideJournal) state(requestId Id) (*directoryDecideState, error) {
	ledgerState, err := self.ledger.State(requestId)
	if err != nil {
		return nil, err
	}
	var state *directoryDecideState
	for _, ledgerRow := range ledgerState.Rows {
		if ledgerRow.Kind != DirectoryDecideLedgerRow {
			continue
		}
		row := &DirectoryDecideRow{}
		if err := json.Unmarshal(ledgerRow.Body, row); err != nil || row.RequestId != requestId {
			return nil, fmt.Errorf("%w: a decide row that does not read", ErrSidecarStoreFailed)
		}
		if state == nil {
			state = &directoryDecideState{requestId: requestId}
		}
		switch row.Step {
		case DirectoryDecideStepIntent:
			intent := &directoryDecideIntent{}
			if err := json.Unmarshal(row.Payload, intent); err != nil {
				return nil, fmt.Errorf("%w: a decide intent that does not read", ErrSidecarStoreFailed)
			}
			if state.intent == nil {
				state.intent, state.noticePushId = intent, row.PushId
			}
		case DirectoryDecideStepStatement:
			statement := &directoryDecideStatement{}
			if err := json.Unmarshal(row.Payload, statement); err != nil {
				return nil, fmt.Errorf("%w: a decide statement that does not read", ErrSidecarStoreFailed)
			}
			if state.statement != nil && !bytes.Equal(state.statement.Signed, statement.Signed) {
				return nil, fmt.Errorf("%w: a decide journal with two statements", ErrSidecarStoreFailed)
			}
			state.statement = statement
		case DirectoryDecideStepEntry:
			entry := &directoryDecideEntry{}
			if err := json.Unmarshal(row.Payload, entry); err != nil {
				return nil, fmt.Errorf("%w: a decide entry that does not read", ErrSidecarStoreFailed)
			}
			if state.entry == nil {
				state.entry = entry
			}
		case DirectoryDecideStepNotice:
			ended := ""
			if err := json.Unmarshal(row.Payload, &ended); err != nil || ended == "" {
				return nil, fmt.Errorf("%w: a decide notice row that does not read", ErrSidecarStoreFailed)
			}
			state.ended = ended
		}
	}
	if state != nil && state.intent == nil {
		return nil, fmt.Errorf("%w: a decide journal with no intent", ErrSidecarStoreFailed)
	}
	return state, nil
}

// Every request the ledger holds a decide journal for.
func (self *DirectoryDecideJournal) states() ([]*directoryDecideState, error) {
	requestIds, err := self.ledger.approvalIds()
	if err != nil {
		return nil, err
	}
	states := []*directoryDecideState{}
	for _, requestId := range requestIds {
		state, err := self.state(requestId)
		if err != nil {
			return nil, err
		}
		if state != nil {
			states = append(states, state)
		}
	}
	return states, nil
}

// What a decision came to so far.
type DirectoryDecided struct {
	RequestId Id
	Outcome   DirectoryOutcome
	// The protocol's last step done: DirectoryDecideStepNotice once the notice is settled.
	Step int
	// How the notice settled, "" while the rewrite waits for this device's entry to land and be read back.
	Ended string
	// The statement's hash and its position in the authorization log, for a repo approval.
	StatementSha256   []byte
	StatementPosition uint64
}

// Whether the protocol finished.
func (self *DirectoryDecided) Finished() bool {
	return self.Ended != ""
}

// Decides a request: see the file's header. ErrDirectoryReadOnly on a read_only client,
// ErrDirectoryDecideNotEligible for a device that does not decide it, ErrDirectoryRequestDecided for a request that
// is not pending, and an unfinished answer, with no error, while the rewrite waits for the entry to land.
func (self *DirectoryClient) Decide(ctx context.Context, args *DirectoryDecideArgs) (*DirectoryDecided, error) {
	return self.Requests().Decide(ctx, args)
}

// Cancels this sidecar's own pending request: its decision entry with outcome cancelled, then its notice's removal
// from the pending version read. ErrDirectoryCancelBeaten when a decision landed first.
func (self *DirectoryClient) Cancel(ctx context.Context, requestId Id) error {
	return self.Requests().Cancel(ctx, requestId)
}

// Takes up each unfinished decision of this device: at a restart and after each sync. Answers how many finished.
func (self *DirectoryClient) ResumeDecisions(ctx context.Context) (int, error) {
	requests := self.Requests()
	requests.writeLock.Lock()
	defer requests.writeLock.Unlock()
	return requests.resumeDecisionsWithLock(ctx)
}

// The journal bound, nil for none.
func (self *DirectoryAccessRequests) journal() *DirectoryDecideJournal {
	return NewDirectoryDecideJournal(self.bound().Journal)
}

// Holds a worker approval to the services its worker announces: the request's ports each a bridge port of the
// worker's item, and the action's sealed detail open to exactly those ports of that worker.
func (self *DirectoryAccessRequests) checkWorkerServices(view *DirectoryRequestView) error {
	target := view.Request.GetTarget()
	item := self.workerItem(Id(target.GetSidecarId()))
	if item == nil {
		return fmt.Errorf("%w: the worker announces no item", ErrDirectoryDecideServices)
	}
	announced := directoryWorkerPorts(item)
	ports := slices.Clone(target.GetTcpPorts())
	if len(ports) == 0 {
		return fmt.Errorf("%w: the request names no port", ErrDirectoryDecideServices)
	}
	slices.Sort(ports)
	wanted := []string{}
	worker := directoryGrantDst("sidecar", target.GetSidecarId())
	for _, port := range ports {
		if !slices.Contains(announced, port) {
			return ErrDirectoryDecideServices
		}
		wanted = append(wanted, fmt.Sprintf("%s:tcp:%d", worker, port))
	}
	opener := self.bound().Opener
	if opener == nil {
		return fmt.Errorf("%w: nothing opens the action's sealed detail here", ErrDirectoryDecideServices)
	}
	approval, err := view.Stored.Approval()
	if err != nil {
		return err
	}
	action, err := ParseStoredCanonicalAction(approval.Request.GetCanonicalAction())
	if err != nil {
		return err
	}
	if !slices.Equal(action.Action.GetGrantDst(), []string{worker}) || !bytes.Equal(action.Action.GetTargetSidecarId(), target.GetSidecarId()) {
		return fmt.Errorf("%w: the action names another worker", ErrDirectoryDecideServices)
	}
	detail, err := opener.OpenActionDetail(action)
	if err != nil {
		return err
	}
	named := slices.Clone(detail.GetGrantDst())
	slices.Sort(named)
	slices.Sort(wanted)
	if detail == nil || !slices.Equal(named, wanted) || len(detail.GetCidrs()) != 0 {
		return fmt.Errorf("%w: the action's detail names other ports", ErrDirectoryDecideServices)
	}
	return nil
}

// Decides a request: DirectoryClient.Decide.
func (self *DirectoryAccessRequests) Decide(ctx context.Context, args *DirectoryDecideArgs) (*DirectoryDecided, error) {
	client := self.client
	if client.readOnly {
		return nil, ErrDirectoryReadOnly
	}
	if _, ok := client.DirectoryId(); !ok {
		return nil, ErrDirectoryNone
	}
	if client.writer == nil {
		return nil, ErrDirectoryNoWriter
	}
	if args == nil {
		return nil, directoryRefusal("no decision")
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	journal := self.journal()
	if journal == nil {
		return nil, ErrDirectoryJournalUnbound
	}
	// a decision this device already journaled is taken up, never made again
	state, err := journal.state(args.RequestId)
	if err != nil {
		return nil, err
	}
	if state != nil {
		if (DirectoryOutcome(state.intent.Outcome) == DirectoryOutcomeApproved) != args.Approve {
			return nil, fmt.Errorf("%w: this device decided it otherwise", ErrDirectoryRequestDecided)
		}
		return self.advance(ctx, journal, state)
	}

	fold, err := self.fold(ctx)
	if err != nil {
		return nil, err
	}
	view := fold.byId[args.RequestId]
	if view == nil || (!view.Mine && (fold.limits == nil || view.OverLimit)) {
		return nil, ErrDirectoryRequestUnknown
	}
	auth := client.auth()
	sidecarId := client.sidecarId
	decides, err := auth.Decides(view.Request, view.RequesterSidecarId, sidecarId, auth.Pin())
	if err != nil {
		return nil, err
	}
	if !decides {
		return nil, ErrDirectoryDecideNotEligible
	}
	reach := view.TargetKind != DirectoryTargetKindRepo
	switch {
	case view.State == DirectoryRequestPending && view.Notice != nil:
	case view.State == DirectoryRequestDenied && args.Approve && !reach && view.Notice != nil:
		// a repo approval that finds it denied rewrites it to approved: a denial vetoes no eligible approval
	default:
		// a decision on a decided notice signs nothing
		return nil, fmt.Errorf("%w: it reads %s", ErrDirectoryRequestDecided, view.State)
	}
	if view.Notice != nil && directoryNoticeNames(view.Notice, sidecarId) {
		return nil, fmt.Errorf("%w: this device approved it already", ErrDirectoryRequestDecided)
	}
	approvers, err := auth.EligibleApprovers(view.Request, view.RequesterSidecarId, auth.Pin())
	if err != nil {
		return nil, err
	}
	nowMillis := client.clock.Now().UnixMilli()
	settings := self.settings()
	intent := &directoryDecideIntent{
		Outcome:            uint32(DirectoryOutcomeDenied),
		RequesterSidecarId: view.RequesterSidecarId,
		RequestEntrySha256: view.EntrySha256[:],
		NoticePath:         view.NoticePath,
		NotAfterMillis:     view.Request.GetNotAfterMillis(),
		Note:               DirectoryNormalizeProse(args.Note),
		Reach:              reach,
		OwnerBound:         approvers.OwnerBound,
	}
	if !directoryProseValid(intent.Note, DirectoryDecisionNoteByteCount) {
		return nil, directoryRefusal("a note of %d bytes or outside its class", len(intent.Note))
	}
	if args.Approve {
		intent.Outcome = uint32(DirectoryOutcomeApproved)
		if self.bound().Statements == nil {
			return nil, ErrDirectoryStatementsUnbound
		}
		if args.Role != 0 && args.Role != view.Request.GetRole() {
			return nil, directoryRefusal("an approval of another role than the one asked")
		}
		intent.Role = view.Request.GetRole()
		// the subject as approved: the request's, or one sidecar of its member
		intent.Subject = Id(view.Request.GetSubject())
		if args.ForSidecarId != nil && *args.ForSidecarId != intent.Subject {
			memberId, isMember := auth.MemberOf(*args.ForSidecarId)
			if !view.Request.GetSubjectIsMember() || !isMember || memberId != intent.Subject {
				return nil, directoryRefusal("a subject that is no sidecar of the request's member")
			}
			intent.Subject = *args.ForSidecarId
		}
		narrowed := intent.Subject != Id(view.Request.GetSubject()) || !view.Request.GetSubjectIsMember()
		// the expiry as approved: never later than asked; with none asked the approver's, none for a member and
		// SidecarGrantExpiry for a sidecar
		asked := view.Request.GetGrantExpiresMillis()
		intent.GrantExpiresMillis = args.GrantExpiresMillis
		switch {
		case intent.GrantExpiresMillis < 0 || (intent.GrantExpiresMillis != 0 && intent.GrantExpiresMillis <= nowMillis):
			return nil, directoryRefusal("a grant expiry in the past")
		case asked != 0 && (intent.GrantExpiresMillis == 0 || asked < intent.GrantExpiresMillis):
			intent.GrantExpiresMillis = asked
		case asked == 0 && intent.GrantExpiresMillis == 0 && narrowed:
			intent.GrantExpiresMillis = nowMillis + settings.SidecarGrantExpiry.Milliseconds()
		}
		if asked != 0 && asked <= nowMillis {
			return nil, fmt.Errorf("%w: the grant it asks has expired", ErrDirectoryRequestDecided)
		}
		switch view.TargetKind {
		case DirectoryTargetKindRepo:
			intent.RepoId = Id(view.Request.GetTarget().GetRepoId())
		case DirectoryTargetKindWorker:
			if err := self.checkWorkerServices(view); err != nil {
				return nil, err
			}
		}
	}
	noticePushId, err := self.newId()
	if err != nil {
		return nil, err
	}
	hookKey := recordChainIdText(args.RequestId)
	testHookBarrier("directory.decide.intent.before", hookKey)
	err = journal.append(args.RequestId, DirectoryDecideStepIntent, intent, noticePushId, nowMillis)
	testHookBarrier("directory.decide.intent.after", hookKey)
	if err != nil {
		return nil, err
	}
	return self.advance(ctx, journal, &directoryDecideState{requestId: args.RequestId, intent: intent, noticePushId: noticePushId})
}

// Takes one journal up from its last row: the statement signed and filed, the entry appended, the notice rewritten,
// each only when its row is missing.
func (self *DirectoryAccessRequests) advance(ctx context.Context, journal *DirectoryDecideJournal, state *directoryDecideState) (*DirectoryDecided, error) {
	client := self.client
	intent := state.intent
	requestId := state.requestId
	hookKey := recordChainIdText(requestId)
	nowMillis := client.clock.Now().UnixMilli()
	decided := &DirectoryDecided{RequestId: requestId, Outcome: DirectoryOutcome(intent.Outcome), Step: DirectoryDecideStepIntent, Ended: state.ended}
	approve := decided.Outcome == DirectoryOutcomeApproved
	if state.statement != nil {
		statementSha256 := sha256.Sum256(state.statement.Signed)
		decided.Step, decided.StatementSha256, decided.StatementPosition = DirectoryDecideStepStatement, statementSha256[:], state.statement.Position
	}
	if state.entry != nil {
		decided.Step = DirectoryDecideStepEntry
	}
	if state.ended != "" {
		decided.Step = DirectoryDecideStepNotice
		return decided, nil
	}

	// 2: the statement
	if approve && (state.statement == nil || (!intent.Reach && state.statement.Position == 0)) {
		statements := self.bound().Statements
		if statements == nil {
			return decided, ErrDirectoryStatementsUnbound
		}
		if state.statement == nil {
			var signed []byte
			var err error
			testHookBarrier("directory.decide.statement.before", hookKey)
			if intent.Reach {
				var view *DirectoryRequestView
				if view, err = self.viewOf(ctx, requestId); err == nil {
					var approval *StoredApprovalRequest
					if approval, err = view.Stored.Approval(); err == nil {
						signed, err = statements.SignReachDecision(ctx, approval, intent.Subject, intent.GrantExpiresMillis)
					}
				}
			} else {
				signed, err = statements.SignRepoAccess(ctx, &DirectoryRepoAccess{
					RepoId: intent.RepoId, Subject: intent.Subject, Role: intent.Role, ExpiresMillis: intent.GrantExpiresMillis,
					OwnerBound: intent.OwnerBound,
				})
			}
			if err == nil && len(signed) == 0 {
				err = fmt.Errorf("%w: no statement signed", ErrDirectoryStatementsUnbound)
			}
			if err == nil {
				// the bytes are journaled before they are filed, so a resume files these and signs nothing again
				state.statement = &directoryDecideStatement{Signed: signed}
				err = journal.append(requestId, DirectoryDecideStepStatement, state.statement, Id{}, nowMillis)
			}
			testHookBarrier("directory.decide.statement.after", hookKey)
			if err != nil {
				state.statement = nil
				return decided, err
			}
			signedSha256 := sha256.Sum256(state.statement.Signed)
			decided.Step, decided.StatementSha256 = DirectoryDecideStepStatement, signedSha256[:]
		}
		if !intent.Reach {
			testHookBarrier("directory.decide.file.before", hookKey)
			position, err := statements.FileStatement(ctx, state.statement.Signed)
			if err == nil && position == 0 {
				err = fmt.Errorf("%w: a filed statement with no position", ErrDirectoryStatementsUnbound)
			}
			if err == nil {
				state.statement = &directoryDecideStatement{Signed: state.statement.Signed, Position: position}
				err = journal.append(requestId, DirectoryDecideStepStatement, state.statement, Id{}, nowMillis)
			}
			testHookBarrier("directory.decide.file.after", hookKey)
			if err != nil {
				return decided, err
			}
		}
		statementSha256 := sha256.Sum256(state.statement.Signed)
		decided.Step, decided.StatementSha256, decided.StatementPosition = DirectoryDecideStepStatement, statementSha256[:], state.statement.Position
	}

	// 3: the decision entry
	if state.entry == nil {
		decision := &protocol.DirectoryDecision{
			RequestId:          requestId.Bytes(),
			RequestEntrySha256: bytes.Clone(intent.RequestEntrySha256),
			Outcome:            intent.Outcome,
			Note:               intent.Note,
		}
		if approve {
			decision.StatementSha256 = decided.StatementSha256
			decision.Subject = intent.Subject.Bytes()
			decision.GrantExpiresMillis = intent.GrantExpiresMillis
			if intent.Reach {
				decision.ApprovalDecision = state.statement.Signed
			} else {
				decision.StatementPosition = state.statement.Position
			}
		}
		if client.redactor != nil {
			if _, err := DirectoryRedact(client.redactor, decision); err != nil {
				return decided, err
			}
		}
		if err := DirectoryCheckDecision(decision); err != nil {
			return decided, err
		}
		entry, err := self.appendDecision(decision, false, hookKey)
		if err != nil {
			return decided, err
		}
		state.entry = entry
		if err := journal.append(requestId, DirectoryDecideStepEntry, entry, Id{}, nowMillis); err != nil {
			return decided, err
		}
		decided.Step = DirectoryDecideStepEntry
		if land := self.bound().Land; land != nil {
			if err := land(ctx); err != nil {
				client.log.Infof("[directory]a decision's entry waits for its push: %s", err)
			}
		}
	}

	// 4: the notice, from the version read
	ended, err := self.rewriteNotice(ctx, state)
	if err != nil || ended == "" {
		return decided, err
	}
	if err := journal.append(requestId, DirectoryDecideStepNotice, ended, state.noticePushId, nowMillis); err != nil {
		return decided, err
	}
	decided.Step, decided.Ended = DirectoryDecideStepNotice, ended
	return decided, nil
}

// Appends a decision entry to this device's stream and answers where it went; a spooled entry answers seq 0.
func (self *DirectoryAccessRequests) appendDecision(decision *protocol.DirectoryDecision, cancel bool, hookKey string) (*directoryDecideEntry, error) {
	directoryId, ok := self.client.DirectoryId()
	if !ok {
		return nil, ErrDirectoryNone
	}
	if cancel {
		testHookBarrier("directory.cancel.entry.before", hookKey)
	} else {
		testHookBarrier("directory.decide.entry.before", hookKey)
	}
	refs, err := self.client.writer.Append(&RecordDraft{Kind: RecordKindDecision, Source: RecordSourceApprover, NoSession: true, Body: decision})
	if cancel {
		testHookBarrier("directory.cancel.entry.after", hookKey)
	} else {
		testHookBarrier("directory.decide.entry.after", hookKey)
	}
	if err != nil {
		return nil, err
	}
	entry := &directoryDecideEntry{}
	for _, ref := range refs {
		if ref != nil && !ref.Spooled && ref.LogId == directoryId {
			entry.EntryId, entry.Seq = ref.EntryId, ref.Seq
		}
	}
	return entry, nil
}

// One request in this reader's fold, whatever its limits say.
func (self *DirectoryAccessRequests) viewOf(ctx context.Context, requestId Id) (*DirectoryRequestView, error) {
	fold, err := self.fold(ctx)
	if err != nil {
		return nil, err
	}
	view := fold.byId[requestId]
	if view == nil {
		return nil, ErrDirectoryRequestUnknown
	}
	return view, nil
}

// Step 4: rewrites the request's notice from the version this copy read, to name this device's decision. Answers how
// it settled, "" while it cannot settle yet: this device's entry is not read back, or another write landed and the next
// sync rereads.
func (self *DirectoryAccessRequests) rewriteNotice(ctx context.Context, state *directoryDecideState) (string, error) {
	client := self.client
	sidecarId := client.sidecarId
	intent := state.intent
	approve := DirectoryOutcome(intent.Outcome) == DirectoryOutcomeApproved
	view, err := self.viewOf(ctx, state.requestId)
	if errors.Is(err, ErrDirectoryRequestUnknown) {
		// the request's entry is gone from this copy with its notice
		return DirectoryDecideGone, nil
	}
	if err != nil {
		return "", err
	}
	if view.noticeFile == nil {
		return DirectoryDecideGone, nil
	}
	if view.Notice == nil || view.NoticeVersion != view.noticeFile.Version {
		// the path holds a version no rule takes: its requester's repair comes first
		return "", nil
	}
	notice := view.Notice
	if directoryNoticeNames(notice, sidecarId) {
		return DirectoryDecideWritten, nil
	}
	decidedNotice := DirectoryNoticeState(notice.GetState()) == DirectoryNoticeStateDecided
	approvedNotice := decidedNotice && DirectoryOutcome(notice.GetOutcome()) == DirectoryOutcomeApproved
	switch {
	case decidedNotice && !approve:
		return DirectoryDecideSuperseded, nil
	case decidedNotice && intent.Reach:
		// void: its ApprovalDecision is never spent, since the requester takes only the notice's decisions
		return DirectoryDecideSuperseded, nil
	case approvedNotice:
		return DirectoryDecideDuplicate, nil
	}
	// this device's entry, read back from its own stream: its seq and its header's hash
	var own *DirectoryDecisionView
	for _, decision := range view.Decisions {
		if decision.DeciderSidecarId == sidecarId && DirectoryOutcome(decision.Decision.GetOutcome()) == DirectoryOutcome(intent.Outcome) &&
			(state.entry == nil || state.entry.Seq == 0 || decision.Seq == state.entry.Seq) {
			own = decision
		}
	}
	if own == nil {
		return "", nil
	}
	ref := &protocol.DecisionRef{DeciderSidecarId: sidecarId.Bytes(), Seq: own.Seq, HeaderSha256: own.HeaderSha256[:]}
	rewritten := &protocol.DirectoryNotice{
		RequestId:          notice.GetRequestId(),
		RequesterSidecarId: notice.GetRequesterSidecarId(),
		EntrySeq:           notice.GetEntrySeq(),
		NotAfterMillis:     notice.GetNotAfterMillis(),
	}
	if !approve {
		rewritten.State, rewritten.Outcome = uint32(DirectoryNoticeStateDecided), uint32(DirectoryOutcomeDenied)
		rewritten.Decisions = []*protocol.DecisionRef{ref}
	} else {
		auth := client.auth()
		approvers, err := auth.EligibleApprovers(view.Request, view.RequesterSidecarId, auth.Pin())
		if err != nil {
			return "", err
		}
		if !decidedNotice {
			// the approvals so far, then this one
			rewritten.Decisions = append(rewritten.Decisions, notice.GetDecisions()...)
		}
		rewritten.Decisions = append(rewritten.Decisions, ref)
		if max(1, approvers.Count) <= len(rewritten.Decisions) {
			rewritten.State, rewritten.Outcome = uint32(DirectoryNoticeStateDecided), uint32(DirectoryOutcomeApproved)
		} else {
			rewritten.State = uint32(DirectoryNoticeStatePending)
		}
	}
	if _, err := self.putNotice(ctx, view.NoticePath, view.NoticeVersion, rewritten, state.noticePushId); err != nil {
		if directoryPathConflict(err) {
			// another decider's rewrite, or the requester's cancel: reread at the next sync
			return "", nil
		}
		return "", err
	}
	return DirectoryDecideWritten, nil
}

// Takes up every unfinished journal still inside not_after + NoticeGrace. The caller holds writeLock.
func (self *DirectoryAccessRequests) resumeDecisionsWithLock(ctx context.Context) (int, error) {
	journal := self.journal()
	if journal == nil || self.client.readOnly {
		return 0, nil
	}
	states, err := journal.states()
	if err != nil {
		return 0, err
	}
	nowMillis := self.client.clock.Now().UnixMilli()
	grace := self.settings().NoticeGrace.Milliseconds()
	finished := 0
	var firstErr error
	for _, state := range states {
		if state.ended != "" || state.intent.NotAfterMillis+grace < nowMillis {
			continue
		}
		decided, err := self.advance(ctx, journal, state)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("directory decide: resume: %w", err)
			}
			continue
		}
		if decided.Finished() {
			finished += 1
		}
	}
	return finished, firstErr
}

// Cancels this sidecar's own request: DirectoryClient.Cancel.
func (self *DirectoryAccessRequests) Cancel(ctx context.Context, requestId Id) error {
	client := self.client
	if client.readOnly {
		return ErrDirectoryReadOnly
	}
	if client.writer == nil {
		return ErrDirectoryNoWriter
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	view, err := self.viewOf(ctx, requestId)
	if err != nil {
		return err
	}
	if !view.Mine {
		return fmt.Errorf("%w: a cancel is its requester's", ErrDirectoryDecideNotEligible)
	}
	switch view.State {
	case DirectoryRequestPending:
	case DirectoryRequestCancelled:
		return self.finishCancel(ctx, view)
	case DirectoryRequestApproved, DirectoryRequestDenied:
		// after an approval, cancelling is a GrantRevoke or a RepoRevoke
		return ErrDirectoryCancelBeaten
	default:
		return fmt.Errorf("%w: it reads %s", ErrDirectoryRequestDecided, view.State)
	}
	decision := &protocol.DirectoryDecision{
		RequestId:          requestId.Bytes(),
		RequestEntrySha256: view.EntrySha256[:],
		Outcome:            uint32(DirectoryOutcomeCancelled),
	}
	if err := DirectoryCheckDecision(decision); err != nil {
		return err
	}
	if _, err := self.appendDecision(decision, true, recordChainIdText(requestId)); err != nil {
		return err
	}
	if land := self.bound().Land; land != nil {
		if err := land(ctx); err != nil {
			client.log.Infof("[directory]a cancel's entry waits for its push: %s", err)
		}
	}
	return self.finishCancel(ctx, view)
}

// The cancel's second half: removes the notice from the pending version read. A conflict means a write landed since:
// ErrDirectoryCancelBeaten, and the next sync shows whether a decision beat the cancel.
func (self *DirectoryAccessRequests) finishCancel(ctx context.Context, view *DirectoryRequestView) error {
	if view.noticeFile == nil {
		return nil
	}
	if view.Notice == nil || DirectoryNoticeState(view.Notice.GetState()) != DirectoryNoticeStatePending {
		return ErrDirectoryCancelBeaten
	}
	pushId, err := self.newId()
	if err != nil {
		return err
	}
	if err := self.removeNotice(ctx, view.RequestId, view.NoticePath, view.NoticeVersion, pushId); err != nil {
		if directoryPathConflict(err) {
			return ErrDirectoryCancelBeaten
		}
		return err
	}
	return nil
}

// Finishes each of this sidecar's cancels whose notice still stands pending: a crash between the entry and the
// removal. The caller holds writeLock.
func (self *DirectoryAccessRequests) finishCancels(ctx context.Context, fold *directoryRequestFold) {
	for _, view := range fold.views {
		if view.Mine && view.State == DirectoryRequestCancelled && view.noticeFile != nil && view.Notice != nil {
			if err := self.finishCancel(ctx, view); err != nil && !errors.Is(err, ErrDirectoryCancelBeaten) {
				self.client.log.Infof("[directory]a cancelled request's notice was not removed: %s", err)
			}
		}
	}
}
