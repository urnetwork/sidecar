// D-MCP-11's use ledger: one append-only sealed log per approval at approvals/<approval_id> in the network's local
// store, file class approval (§5.9, §16.6's consumption block), each row fsynced before the step it guards. Rows are
// sealed JSON, never proto, so no server-visible field is added (§2.8):
//
//	{"row":"request","body":{"request":<the ApprovalRequest as stored>}}
//	{"row":"decision","body":{"decision":<the Signed ApprovalDecision as received>}}
//	{"row":"reserve","body":{"action_id","use_index","payload_sha256","effect_key","reserved_millis"}}
//	{"row":"outcome","body":{"action_id","state":"done"|"not_done"|"uncertain","effect_ref","millis"}}
//	{"row":"cancel","body":{"millis","signer_sidecar_id"}}
//
// §16.6 names Reserve, Outcome and Cancel. spendable needs the action as stored and request_sha256 the request as
// stored, across restarts, so the file also keeps the request and each decision's bytes (MCP.md's reading 1). The
// row API is open: RECORD's decider appends its Decide rows through Append (plan-RECORD-small-readings#9), and a row
// of a kind this build does not know is kept and read back whole, never refused.
//
// Rows are never edited or removed, and a Reserve is never undone: an uncertain use stays consumed (AU3). The
// approval's mutex (ApprovalHold) is held across the Reserve fsync on purpose, since that fsync is the linearization
// point of a local use, so it is a per-approval lock, never stateLock, and never held across an effect. Its barriers
// sit outside it, record.reserve.before before the mutex and record.reserve.after after its release, because a held
// barrier must hold no lock (testhook.go): FS-25 parks both callers at .before.
//
// A file that reads Failed refuses every spend: State answers the failure, and so does a Reserve.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §5.9's tree and file class for the ledger.
const (
	approvalLedgerDirectoryName = "approvals"
	approvalLedgerClass         = "approval"
)

var (
	// Every use of the approval is reserved: §16.6's spend step 3, spent.
	ErrApprovalSpent = errors.New("approval spent")
	// A Cancel is in the ledger: §16.6's spend step 3, cancelled.
	ErrApprovalCancelled = errors.New("approval cancelled")
	// A row that breaks the ledger's own rules, which only a bug writes: it reads as a failure, never as a row
	// missing, so nothing spends on it.
	errApprovalLedgerRow = fmt.Errorf("%w: an approval ledger row does not hold", ErrSidecarStoreFailed)
)

// What a ledger row records.
type ApprovalLedgerRowKind string

const (
	// The ApprovalRequest as stored.
	ApprovalLedgerRequest ApprovalLedgerRowKind = "request"
	// One ApprovalDecision's Signed as received.
	ApprovalLedgerDecision ApprovalLedgerRowKind = "decision"
	// A use reserved before its effect (spend step 4).
	ApprovalLedgerReserve ApprovalLedgerRowKind = "reserve"
	// What a reserved use's effect came to (spend step 6).
	ApprovalLedgerOutcome ApprovalLedgerRowKind = "outcome"
	// An approver's ApprovalCancel, applied.
	ApprovalLedgerCancel ApprovalLedgerRowKind = "cancel"
)

// A row's body: each row type below, and any a later task adds, such as RECORD's Decide.
type ApprovalLedgerRowBody interface {
	// The row's kind, which its JSON carries beside the body.
	ApprovalLedgerRowKind() ApprovalLedgerRowKind
}

// One row as stored: its kind and its body's JSON, kept whole.
type ApprovalLedgerRow struct {
	Kind ApprovalLedgerRowKind `json:"row"`
	Body json.RawMessage       `json:"body"`
}

// The ApprovalRequest the requester filed, as stored, which request_sha256 and action_id cover.
type ApprovalRequestRow struct {
	Request []byte `json:"request"`
}

// See ApprovalLedgerRowBody.
func (self *ApprovalRequestRow) ApprovalLedgerRowKind() ApprovalLedgerRowKind {
	return ApprovalLedgerRequest
}

// One decision's Signed, as received: verified over these bytes, never a re-marshal.
type ApprovalDecisionRow struct {
	Decision []byte `json:"decision"`
}

// See ApprovalLedgerRowBody.
func (self *ApprovalDecisionRow) ApprovalLedgerRowKind() ApprovalLedgerRowKind {
	return ApprovalLedgerDecision
}

// §16.6's Reserve: a use taken before its effect, never given back.
type ApprovalReserve struct {
	// §16.6's action_id of this use's CanonicalAction, 32 bytes.
	ActionId []byte `json:"action_id"`
	// The count of Reserves before this one.
	UseIndex uint32 `json:"use_index"`
	// SHA-256 of the use's CanonicalAction as stored.
	PayloadSha256 []byte `json:"payload_sha256"`
	// §16.6's effect_key, under which the effect is idempotent and Lookup finds it.
	EffectKey      []byte `json:"effect_key"`
	ReservedMillis int64  `json:"reserved_millis"`
	// The use's CanonicalAction as stored, whose SHA-256 is PayloadSha256, so a restart runs its kind's Lookup with
	// no caller alive: a template's use is not the request's own action. Empty in a row written before it was kept,
	// whose use is the request's action.
	Canonical []byte `json:"canonical,omitempty"`
}

// See ApprovalLedgerRowBody.
func (self *ApprovalReserve) ApprovalLedgerRowKind() ApprovalLedgerRowKind {
	return ApprovalLedgerReserve
}

// How a reserved use's effect ended.
type ApprovalOutcomeState string

const (
	// The effect happened; effect_ref names it.
	ApprovalOutcomeDone ApprovalOutcomeState = "done"
	// The component proved no effect happened. The use stays consumed all the same.
	ApprovalOutcomeNotDone ApprovalOutcomeState = "not_done"
	// Neither is known: a retry of the same action completes it under its effect_key (spend step 5).
	ApprovalOutcomeUncertain ApprovalOutcomeState = "uncertain"
)

// Whether the state is one of the three.
func (self ApprovalOutcomeState) valid() bool {
	switch self {
	case ApprovalOutcomeDone, ApprovalOutcomeNotDone, ApprovalOutcomeUncertain:
		return true
	}
	return false
}

// Whether a later row can change it: done and not_done stand, uncertain waits for a retry.
func (self ApprovalOutcomeState) final() bool {
	return self == ApprovalOutcomeDone || self == ApprovalOutcomeNotDone
}

// §16.6's Outcome of one reserved use.
type ApprovalOutcome struct {
	ActionId []byte               `json:"action_id"`
	State    ApprovalOutcomeState `json:"state"`
	// What the component reports it did, opaque here. Empty unless done.
	EffectRef []byte `json:"effect_ref,omitempty"`
	Millis    int64  `json:"millis"`
}

// See ApprovalLedgerRowBody.
func (self *ApprovalOutcome) ApprovalLedgerRowKind() ApprovalLedgerRowKind {
	return ApprovalLedgerOutcome
}

// §16.6's Cancel: an approver's ApprovalCancel, applied. A use reserved before it still completes.
type ApprovalCancelRow struct {
	Millis          int64 `json:"millis"`
	SignerSidecarId Id    `json:"signer_sidecar_id"`
}

// See ApprovalLedgerRowBody.
func (self *ApprovalCancelRow) ApprovalLedgerRowKind() ApprovalLedgerRowKind {
	return ApprovalLedgerCancel
}

// One row's bytes in the log.
func encodeApprovalLedgerRow(body ApprovalLedgerRowBody) ([]byte, error) {
	encodedBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return json.Marshal(&ApprovalLedgerRow{Kind: body.ApprovalLedgerRowKind(), Body: encodedBody})
}

// An approval's file folded: every row in order, and what §16.6's spend steps read of them.
type ApprovalLedgerState struct {
	ApprovalId Id
	// Every row, in the order appended, kinds this build does not know included.
	Rows []*ApprovalLedgerRow
	// The first request row's ApprovalRequest, nil for none.
	Request []byte
	// Each decision row's Signed, in order.
	Decisions [][]byte
	// In use_index order, each action once.
	Reserves []*ApprovalReserve
	// Every outcome row, in order.
	Outcomes []*ApprovalOutcome
	// The first cancel, nil for none.
	Cancel *ApprovalCancelRow
}

// Checks one Reserve row against those before it: a fixed size for each hash, the next use_index and an action not
// reserved already. The ledger writes nothing else, so anything else is a failure.
func (self *ApprovalLedgerState) checkReserve(reserve *ApprovalReserve) error {
	if len(reserve.ActionId) != sha256.Size || len(reserve.PayloadSha256) != sha256.Size ||
		len(reserve.EffectKey) != sha256.Size || reserve.UseIndex != uint32(len(self.Reserves)) {
		return errApprovalLedgerRow
	}
	if len(reserve.Canonical) != 0 {
		if payloadSha256 := sha256.Sum256(reserve.Canonical); !bytes.Equal(payloadSha256[:], reserve.PayloadSha256) {
			return errApprovalLedgerRow
		}
	}
	if self.FindReserve(reserve.ActionId) != nil {
		return errApprovalLedgerRow
	}
	return nil
}

// Folds rows, as read from approvalId's file.
func foldApprovalLedger(approvalId Id, encodedRows [][]byte) (*ApprovalLedgerState, error) {
	state := &ApprovalLedgerState{ApprovalId: approvalId}
	for _, encodedRow := range encodedRows {
		row := &ApprovalLedgerRow{}
		if err := json.Unmarshal(encodedRow, row); err != nil || row.Kind == "" {
			return nil, errApprovalLedgerRow
		}
		state.Rows = append(state.Rows, row)
		var err error
		switch row.Kind {
		case ApprovalLedgerRequest:
			body := &ApprovalRequestRow{}
			if err = json.Unmarshal(row.Body, body); err == nil && state.Request == nil {
				state.Request = body.Request
			}
		case ApprovalLedgerDecision:
			body := &ApprovalDecisionRow{}
			if err = json.Unmarshal(row.Body, body); err == nil {
				state.Decisions = append(state.Decisions, body.Decision)
			}
		case ApprovalLedgerReserve:
			body := &ApprovalReserve{}
			if err = json.Unmarshal(row.Body, body); err == nil {
				err = state.checkReserve(body)
			}
			if err == nil {
				state.Reserves = append(state.Reserves, body)
			}
		case ApprovalLedgerOutcome:
			body := &ApprovalOutcome{}
			if err = json.Unmarshal(row.Body, body); err == nil &&
				(len(body.ActionId) != sha256.Size || !body.State.valid() || state.FindReserve(body.ActionId) == nil) {
				err = errApprovalLedgerRow
			}
			if err == nil {
				state.Outcomes = append(state.Outcomes, body)
			}
		case ApprovalLedgerCancel:
			body := &ApprovalCancelRow{}
			if err = json.Unmarshal(row.Body, body); err == nil && state.Cancel == nil {
				state.Cancel = body
			}
		}
		if err != nil {
			return nil, errApprovalLedgerRow
		}
	}
	return state, nil
}

// The Reserve of actionId, nil for none.
func (self *ApprovalLedgerState) FindReserve(actionId []byte) *ApprovalReserve {
	for _, reserve := range self.Reserves {
		if bytes.Equal(reserve.ActionId, actionId) {
			return reserve
		}
	}
	return nil
}

// The outcome that stands for actionId: the first done or not_done, which nothing after it changes, else the newest
// uncertain, else nil.
func (self *ApprovalLedgerState) Outcome(actionId []byte) *ApprovalOutcome {
	var standing *ApprovalOutcome
	for _, outcome := range self.Outcomes {
		if !bytes.Equal(outcome.ActionId, actionId) {
			continue
		}
		if outcome.State.final() {
			return outcome
		}
		standing = outcome
	}
	return standing
}

// Each Reserve with no done or not_done outcome: what a restart reconciles by Lookup(effect_key) (spend step 5).
func (self *ApprovalLedgerState) Unresolved() []*ApprovalReserve {
	unresolved := []*ApprovalReserve{}
	for _, reserve := range self.Reserves {
		if outcome := self.Outcome(reserve.ActionId); outcome == nil || !outcome.State.final() {
			unresolved = append(unresolved, reserve)
		}
	}
	return unresolved
}

// The latest not_after any row names, in Unix milliseconds: the request's, each decision's, and that of each row whose
// body has a not_after_millis, as RECORD's Decide rows do, so a file holding no request is dated too. False when none
// does.
func (self *ApprovalLedgerState) NotAfterMillis() (int64, bool) {
	notAfterMillis := int64(0)
	found := false
	take := func(millis int64) {
		if 0 < millis && (!found || notAfterMillis < millis) {
			notAfterMillis = millis
			found = true
		}
	}
	if self.Request != nil {
		request := &protocol.ApprovalRequest{}
		if proto.Unmarshal(self.Request, request) == nil {
			take(request.GetNotAfterMillis())
		}
	}
	for _, encodedSigned := range self.Decisions {
		signed := &bridge.Signed{}
		decision := &protocol.ApprovalDecision{}
		if proto.Unmarshal(encodedSigned, signed) == nil && proto.Unmarshal(signed.GetBody(), decision) == nil {
			take(decision.GetNotAfterMillis())
		}
	}
	for _, row := range self.Rows {
		expiring := struct {
			NotAfterMillis int64 `json:"not_after_millis"`
		}{}
		if json.Unmarshal(row.Body, &expiring) == nil {
			take(expiring.NotAfterMillis)
		}
	}
	return notAfterMillis, found
}

// A Reserve no done or not_done follows, in the file of ApprovalId, or that file's failure.
type ApprovalUnresolved struct {
	ApprovalId Id
	// Nil when Err is set.
	Reserve *ApprovalReserve
	// Whether an uncertain outcome follows it, rather than none.
	Uncertain bool
	// The file did not read: nothing in it may spend, and a person must look (D-CORE-15).
	Err error
}

// The network's approval ledger. One per Sidecar: two would each hold their own mutex for an approval and could
// reserve one use twice, so the Sidecar keeps it (Sidecar.ApprovalLedger). Safe for concurrent use.
type ApprovalLedger struct {
	// approvals/, class approval
	store    SidecarStore
	settings *SidecarMcpSettings
	clock    Clock

	stateLock     sync.Mutex
	approvalHolds map[Id]*approvalHold
}

// One approval's mutex and how many wait on or hold it, so the map forgets an approval nobody holds.
type approvalHold struct {
	lock        sync.Mutex
	holderCount int
}

// A ledger over the network's local store (Sidecar.LocalStore).
func NewApprovalLedger(localStore SidecarStore, settings *SidecarMcpSettings, clock Clock) (*ApprovalLedger, error) {
	store, err := localStore.Directory(approvalLedgerDirectoryName, approvalLedgerClass)
	if err != nil {
		return nil, err
	}
	return &ApprovalLedger{
		store:         store,
		settings:      settings,
		clock:         clockOrReal(clock),
		approvalHolds: map[Id]*approvalHold{},
	}, nil
}

// The file's name: the approval id, as §5.9's tree names ids.
func approvalLedgerName(approvalId Id) string {
	return approvalId.String()
}

// approvalId's log.
func (self *ApprovalLedger) log(approvalId Id) (SidecarStoreLog, error) {
	return OpenSidecarStoreLog(self.store, approvalLedgerName(approvalId))
}

// approvalId's rows, folded. An approval with no file reads as one with no rows.
func (self *ApprovalLedger) State(approvalId Id) (*ApprovalLedgerState, error) {
	log, err := self.log(approvalId)
	if err != nil {
		return nil, err
	}
	encodedRows := [][]byte{}
	err = log.Read(func(index uint64, record []byte) error {
		encodedRows = append(encodedRows, record)
		return nil
	})
	if err != nil && !errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, err
	}
	return foldApprovalLedger(approvalId, encodedRows)
}

// Appends a row a hold does not guard: a request, a decision, an outcome, or a kind another task adds. A Reserve and
// a Cancel go through an ApprovalHold, since each depends on what the file holds when it lands.
func (self *ApprovalLedger) Append(approvalId Id, body ApprovalLedgerRowBody) error {
	switch body.ApprovalLedgerRowKind() {
	case ApprovalLedgerReserve, ApprovalLedgerCancel:
		return fmt.Errorf("a %s row goes through the approval's hold", body.ApprovalLedgerRowKind())
	case ApprovalLedgerOutcome:
		outcome := body.(*ApprovalOutcome)
		if len(outcome.ActionId) != sha256.Size || !outcome.State.valid() {
			return errors.New("an outcome needs an action id and a state")
		}
		state, err := self.State(approvalId)
		if err != nil {
			return err
		}
		if state.FindReserve(outcome.ActionId) == nil {
			return errors.New("an outcome for a use never reserved")
		}
	}
	return self.appendRow(approvalId, body)
}

// Appends body to approvalId's log, fsynced before it returns.
func (self *ApprovalLedger) appendRow(approvalId Id, body ApprovalLedgerRowBody) error {
	encoded, err := encodeApprovalLedgerRow(body)
	if err != nil {
		return err
	}
	log, err := self.log(approvalId)
	if err != nil {
		return err
	}
	return log.Append(encoded)
}

// The approval's mutex, held: spend steps 1 to 4 run between Hold and Release, and the mutex is never held across an
// effect. Not safe for concurrent use; one caller holds it.
type ApprovalHold struct {
	ledger     *ApprovalLedger
	approvalId Id
	hold       *approvalHold
	released   bool
}

// Takes approvalId's mutex, after its record.reserve.before barrier, which holds no lock.
func (self *ApprovalLedger) Hold(approvalId Id) *ApprovalHold {
	testHookBarrier("record.reserve.before", approvalId.String())
	hold := func() *approvalHold {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		hold, ok := self.approvalHolds[approvalId]
		if !ok {
			hold = &approvalHold{}
			self.approvalHolds[approvalId] = hold
		}
		hold.holderCount += 1
		return hold
	}()
	hold.lock.Lock()
	return &ApprovalHold{ledger: self, approvalId: approvalId, hold: hold}
}

// Releases the mutex, then passes record.reserve.after. Safe to call again.
func (self *ApprovalHold) Release() {
	if self.released {
		return
	}
	self.released = true
	self.hold.lock.Unlock()
	func() {
		self.ledger.stateLock.Lock()
		defer self.ledger.stateLock.Unlock()
		self.hold.holderCount -= 1
		if self.hold.holderCount == 0 {
			delete(self.ledger.approvalHolds, self.approvalId)
		}
	}()
	testHookBarrier("record.reserve.after", self.approvalId.String())
}

// The approval's rows as they stand under the mutex.
func (self *ApprovalHold) State() (*ApprovalLedgerState, error) {
	if self.released {
		return nil, errors.New("the approval's hold was released")
	}
	return self.ledger.State(self.approvalId)
}

// Spend step 4, with step 2 and step 3's ledger refusals: a Reserve already made for actionId answers it with false,
// the retry path; a Cancel answers ErrApprovalCancelled and uses Reserves ErrApprovalSpent; otherwise a Reserve at the
// next use_index is appended and fsynced before this returns, true. That fsync is the linearization point of a local
// use. After an error the Reserve may be in the file, as after a kill, so the caller runs no effect and the use stays
// consumed. Expiry and taint are the caller's to check first, from the clock and the run file.
func (self *ApprovalHold) Reserve(actionId []byte, payloadSha256 []byte, effectKey []byte, uses uint32) (*ApprovalReserve, bool, error) {
	return self.ReserveUse(nil, actionId, payloadSha256, effectKey, uses)
}

// Reserve, keeping canonical, the use's CanonicalAction as stored, in the row (ApprovalReserve.Canonical), whose
// SHA-256 must be payloadSha256. nil keeps none.
func (self *ApprovalHold) ReserveUse(canonical []byte, actionId []byte, payloadSha256 []byte, effectKey []byte, uses uint32) (*ApprovalReserve, bool, error) {
	if len(actionId) != sha256.Size || len(payloadSha256) != sha256.Size || len(effectKey) != sha256.Size {
		return nil, false, errors.New("a reserve needs three 32-byte hashes")
	}
	if canonical != nil {
		if canonicalSha256 := sha256.Sum256(canonical); !bytes.Equal(canonicalSha256[:], payloadSha256) {
			return nil, false, errors.New("a reserve's action is not its payload_sha256's")
		}
	}
	state, err := self.State()
	if err != nil {
		return nil, false, err
	}
	if reserve := state.FindReserve(actionId); reserve != nil {
		return reserve, false, nil
	}
	if state.Cancel != nil {
		return nil, false, ErrApprovalCancelled
	}
	if uint32(len(state.Reserves)) >= uses {
		return nil, false, ErrApprovalSpent
	}
	reserve := &ApprovalReserve{
		ActionId:       bytes.Clone(actionId),
		UseIndex:       uint32(len(state.Reserves)),
		PayloadSha256:  bytes.Clone(payloadSha256),
		EffectKey:      bytes.Clone(effectKey),
		ReservedMillis: self.ledger.clock.Now().UnixMilli(),
		Canonical:      bytes.Clone(canonical),
	}
	if err := self.ledger.appendRow(self.approvalId, reserve); err != nil {
		return nil, false, err
	}
	return reserve, true, nil
}

// Appends a Cancel signed by signerSidecarId, the first that lands standing. A use reserved before it still
// completes (§16.6's cancel row).
func (self *ApprovalHold) Cancel(signerSidecarId Id) error {
	if self.released {
		return errors.New("the approval's hold was released")
	}
	return self.ledger.appendRow(self.approvalId, &ApprovalCancelRow{
		Millis:          self.ledger.clock.Now().UnixMilli(),
		SignerSidecarId: signerSidecarId,
	})
}

// The count of uses reserved: Reserves never go away.
func (self *ApprovalLedger) Uses(approvalId Id) (int, error) {
	state, err := self.State(approvalId)
	if err != nil {
		return 0, err
	}
	return len(state.Reserves), nil
}

// The Reserve of actionId under approvalId, nil for none.
func (self *ApprovalLedger) FindReserve(approvalId Id, actionId []byte) (*ApprovalReserve, error) {
	state, err := self.State(approvalId)
	if err != nil {
		return nil, err
	}
	return state.FindReserve(actionId), nil
}

// The approvals with a file, by the names the directory holds. A name that is no id is no approval's.
func (self *ApprovalLedger) approvalIds() ([]Id, error) {
	entries, err := self.store.List("")
	if err != nil {
		return nil, err
	}
	approvalIds := []Id{}
	for _, entry := range entries {
		approvalId, err := ParseId(entry.Name)
		if err != nil || approvalLedgerName(approvalId) != entry.Name {
			continue
		}
		approvalIds = append(approvalIds, approvalId)
	}
	return approvalIds, nil
}

// Every Reserve with no done or not_done outcome, across the network's approvals, for a restart to reconcile by
// Lookup(effect_key); and each file that fails to read, which nothing may spend from.
func (self *ApprovalLedger) Unresolved() ([]*ApprovalUnresolved, error) {
	approvalIds, err := self.approvalIds()
	if err != nil {
		return nil, err
	}
	unresolved := []*ApprovalUnresolved{}
	for _, approvalId := range approvalIds {
		state, err := self.State(approvalId)
		if err != nil {
			unresolved = append(unresolved, &ApprovalUnresolved{ApprovalId: approvalId, Err: err})
			continue
		}
		for _, reserve := range state.Unresolved() {
			outcome := state.Outcome(reserve.ActionId)
			unresolved = append(unresolved, &ApprovalUnresolved{
				ApprovalId: approvalId,
				Reserve:    reserve,
				Uncertain:  outcome != nil,
			})
		}
	}
	return unresolved, nil
}

// Removes each approval's file ApprovalFileRetention past its not_after (§16.6's retention row), under the approval's
// hold so no Reserve races the removal. A file that does not read, or names no expiry, is kept: nothing is deleted
// that cannot be dated. Answers how many went.
func (self *ApprovalLedger) Sweep(ctx context.Context) (int, error) {
	approvalIds, err := self.approvalIds()
	if err != nil {
		return 0, err
	}
	now := self.clock.Now()
	removedCount := 0
	for _, approvalId := range approvalIds {
		if err := ctx.Err(); err != nil {
			return removedCount, err
		}
		removed, err := func() (bool, error) {
			hold := self.Hold(approvalId)
			defer hold.Release()
			state, err := hold.State()
			if err != nil {
				return false, nil
			}
			notAfterMillis, ok := state.NotAfterMillis()
			if !ok || now.Before(time.UnixMilli(notAfterMillis).Add(self.settings.ApprovalFileRetention)) {
				return false, nil
			}
			return true, self.store.Remove(approvalLedgerName(approvalId))
		}()
		if err != nil {
			return removedCount, err
		}
		if removed {
			removedCount += 1
		}
	}
	return removedCount, nil
}

// What a Sidecar keeps of §16's local state, built once its network is known: one ledger, so one mutex per approval,
// one run store, so one memory of taint, and one spool, so one epoch and one cap. Safe for concurrent use.
type sidecarRecords struct {
	stateLock sync.Mutex
	// the network these were built for
	networkId      *Id
	approvalLedger *ApprovalLedger
	runs           *RunStore
	spool          *Spool
	// the record's writer and push loop (RECORD-M3-02), built by Sidecar.Record
	record *SidecarRecord
	// the team directory's client (RECORD-M6-13), built by Sidecar.DirectoryClient
	directory *DirectoryClient
	// each kind's Lookup, which its component registers (Sidecar.RegisterEffectLookup, record_effect.go); kept
	// across forNetworkWithLock, since a component's lookup is not a network's state
	effectLookups map[SidecarActionKind]*sidecarEffectLookupEntry
}

// One registered Lookup, compared by its entry so a stale removal leaves a newer one.
type sidecarEffectLookupEntry struct {
	lookup SidecarEffectLookup
}

// The network's sealed local state, net/<network_id>/ (§5.9): Directory(name, class) reaches §16's approvals/, runs/
// and restore/ and each component's own directory under their classes, and OpenSidecarStoreLog its journals. Before
// enrollment no network is known, and every call on it answers ErrSidecarStoreLocked, as it does while locked.
func (self *Sidecar) LocalStore() SidecarStore {
	networkId := self.knownNetworkId()
	if self.instance == nil || networkId == nil {
		return &sealedStore{}
	}
	return &sealedStore{instance: self.instance, networkId: networkId}
}

// A copy of the network id, nil before enrollment.
func (self *Sidecar) knownNetworkId() *Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.networkId == nil {
		return nil
	}
	networkId := *self.networkId
	return &networkId
}

// The network's ledger. One per Sidecar, so every spend of an approval takes the same mutex. ErrSidecarStoreLocked
// before enrollment.
func (self *Sidecar) ApprovalLedger() (*ApprovalLedger, error) {
	networkId := self.knownNetworkId()
	if self.instance == nil || networkId == nil {
		return nil, ErrSidecarStoreLocked
	}
	self.records.stateLock.Lock()
	defer self.records.stateLock.Unlock()
	self.records.forNetworkWithLock(*networkId)
	if self.records.approvalLedger == nil {
		approvalLedger, err := NewApprovalLedger(self.LocalStore(), self.settings.Mcp, self.settings.ClockOrReal())
		if err != nil {
			return nil, err
		}
		self.records.approvalLedger = approvalLedger
	}
	return self.records.approvalLedger, nil
}

// Drops what was built for another network: a Sidecar learns its network once, at enrollment, so this only ever
// starts from nothing.
func (self *sidecarRecords) forNetworkWithLock(networkId Id) {
	if self.networkId == nil || *self.networkId != networkId {
		self.networkId = &networkId
		self.approvalLedger = nil
		self.runs = nil
		self.spool = nil
		self.record = nil
		self.directory = nil
	}
}
