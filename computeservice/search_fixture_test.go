package computeservice

// Web search's test world (SRCH-M13-07, SRCH-M13-08), on the engine's fixture (engine_fixture_test.go): a ledger that
// holds, settles and releases searches as BAL's search path will (BAL-M13-02 has not landed its script, so the real
// ledger refuses every search), a signer that signs deterministically and holds reports as SRCH-M13-03 and -04's will,
// the sanctions records in memory, the caller's verified state as the test sets it, a policy whose search line names
// a synthetic asset on a test chain, and a catalog version listing the search section. computetest.Broker, CTEST's
// shared broker, has not landed, so these fakes stand in for it. Every fake is safe for concurrent use.

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The sanctions records as a test sets them, standing in for compute_search_flag.
type fakeComputeSearchFlagStore struct {
	stateLock sync.Mutex
	flags     []*model.ComputeSearchFlag
	failing   bool
}

func newFakeComputeSearchFlagStore() *fakeComputeSearchFlagStore {
	return &fakeComputeSearchFlagStore{}
}

func (self *fakeComputeSearchFlagStore) Insert(ctx context.Context, flag *model.ComputeSearchFlag) (bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return false, errors.New("compute_search_flag did not answer")
	}
	for _, stood := range self.flags {
		if stood.Open() && stood.NetworkId == flag.NetworkId && stood.Reason == flag.Reason &&
			bytes.Equal(stood.Payee, flag.Payee) && bytes.Equal(stood.Transaction, flag.Transaction) {
			return false, nil
		}
	}
	copied := *flag
	self.flags = append(self.flags, &copied)
	return true, nil
}

func (self *fakeComputeSearchFlagStore) Suspended(ctx context.Context, networkId sidecar.Id) (bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return false, errors.New("compute_search_flag did not answer")
	}
	for _, flag := range self.flags {
		if flag.NetworkId == networkId && flag.Reason == model.ComputeSearchFlagReasonPayeeRefused && flag.Open() {
			return true, nil
		}
	}
	return false, nil
}

// Every record, a copy.
func (self *fakeComputeSearchFlagStore) all() []*model.ComputeSearchFlag {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	flags := []*model.ComputeSearchFlag{}
	for _, flag := range self.flags {
		copied := *flag
		flags = append(flags, &copied)
	}
	return flags
}

// Reviews networkId's open records, as an operator's resume does.
func (self *fakeComputeSearchFlagStore) review(networkId sidecar.Id, at time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reference := "case-1"
	for _, flag := range self.flags {
		if flag.NetworkId == networkId && flag.Open() {
			reviewedTime := at
			flag.ReviewedTime, flag.ReviewReference = &reviewedTime, &reference
		}
	}
}

// One network's account in the fake ledger.
type fakeSearchAccount struct {
	// settled, less the open holds and the unsettled charges
	availableNanoUsd int64
	// unexpired promotional credit, which pays no search (§9.11)
	promoNanoUsd int64
	state        model.ComputeAccountState
}

// One search operation's row in the fake ledger.
type fakeSearchOp struct {
	opKey     sidecar.Id
	networkId sidecar.Id
	sidecarId sidecar.Id
	agentId   *sidecar.Id
	requestId sidecar.Id
	attempt   int16
	minute    time.Time
	hold      int64
	state     model.ComputeOpState
	outcome   *model.ComputeOpOutcome
}

// A charge the fake ledger booked: what the statements and the day's rows read.
type fakeSearchCharge struct {
	chargeId  sidecar.Id
	networkId sidecar.Id
	agentId   *sidecar.Id
	minute    time.Time
	amount    int64
	cost      int64
}

// BAL's search ledger as BAL-M13-02 will hold, settle and release, in memory (see the file header): the balance less
// promotional credit, grace and worse refused, the agent's and the device's day budgets from §16.5's defaults, the
// clause, the search cap, rows by D-BAL-14's key, a release restoring the hold, a settlement charging the hold.
type fakeComputeSearchLedger struct {
	stateLock sync.Mutex
	settings  *model.ComputeLedgerSettings
	accounts  map[sidecar.Id]*fakeSearchAccount
	clauses   map[sidecar.Id]bool
	caps      map[sidecar.Id]int64
	ops       map[sidecar.Id]*fakeSearchOp
	charges   []*fakeSearchCharge
	// what each subject was charged or holds today, by subject and UTC day
	spentNanoUsds map[string]int64
	// every move in order: "hold <op>", "release <op>", "settle <op>"
	events []string
	// the ledger cannot say
	failing bool
	// the deletion's batch, 0 for any
	deleteLimit int
}

func newFakeComputeSearchLedger() *fakeComputeSearchLedger {
	return &fakeComputeSearchLedger{
		settings:      model.DefaultComputeLedgerSettings(),
		accounts:      map[sidecar.Id]*fakeSearchAccount{},
		clauses:       map[sidecar.Id]bool{},
		caps:          map[sidecar.Id]int64{},
		ops:           map[sidecar.Id]*fakeSearchOp{},
		spentNanoUsds: map[string]int64{},
	}
}

// Funds networkId with amount, active.
func (self *fakeComputeSearchLedger) fund(networkId sidecar.Id, amount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.accounts[networkId] = &fakeSearchAccount{availableNanoUsd: amount, state: model.ComputeAccountStateActive}
}

// Changes networkId's account.
func (self *fakeComputeSearchLedger) account(networkId sidecar.Id, change func(account *fakeSearchAccount)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	change(self.accounts[networkId])
}

func (self *fakeComputeSearchLedger) setClause(networkId sidecar.Id, accepted bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clauses[networkId] = accepted
}

func (self *fakeComputeSearchLedger) setCap(networkId sidecar.Id, searchCap int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.caps[networkId] = searchCap
}

// A subject's budget key for a day.
func fakeSearchSpentKey(subjectId sidecar.Id, budget string, day time.Time) string {
	return sidecar.EvsKeyId(subjectId) + ":" + budget + ":" + day.UTC().Format("20060102")
}

// Spends amount of subjectId's budget for the day of at, as an earlier charge would have.
func (self *fakeComputeSearchLedger) spend(subjectId sidecar.Id, budget string, at time.Time, amount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.spentNanoUsds[fakeSearchSpentKey(subjectId, budget, at)] += amount
}

// The open holds' count and the rows' and charges' snapshots.
func (self *fakeComputeSearchLedger) openCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, op := range self.ops {
		if op.state == model.ComputeOpStateOpen {
			count += 1
		}
	}
	return count
}

func (self *fakeComputeSearchLedger) op(opKey sidecar.Id) *fakeSearchOp {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	op := self.ops[opKey]
	if op == nil {
		return nil
	}
	copied := *op
	return &copied
}

func (self *fakeComputeSearchLedger) chargeList() []*fakeSearchCharge {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	charges := []*fakeSearchCharge{}
	for _, charge := range self.charges {
		copied := *charge
		charges = append(charges, &copied)
	}
	return charges
}

func (self *fakeComputeSearchLedger) eventList() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

func (self *fakeComputeSearchLedger) available(networkId sidecar.Id) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.accounts[networkId].availableNanoUsd
}

func (self *fakeComputeSearchLedger) ClauseAccepted(ctx context.Context, networkId sidecar.Id) (bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return false, errors.New("the ledger did not answer")
	}
	return self.clauses[networkId], nil
}

func (self *fakeComputeSearchLedger) SearchCap(ctx context.Context, networkId sidecar.Id) (int64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return 0, errors.New("the ledger did not answer")
	}
	if searchCap, ok := self.caps[networkId]; ok {
		return searchCap, nil
	}
	return self.settings.SearchCapEstablished, nil
}

func (self *fakeComputeSearchLedger) SearchCount(ctx context.Context, networkId sidecar.Id, since time.Time) (int64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := int64(0)
	for _, op := range self.ops {
		if op.networkId == networkId && op.state != model.ComputeOpStateVoid && !op.minute.Before(since) {
			count += 1
		}
	}
	return count, nil
}

// §16.5's day budgets a search counts to: its agent's, or its device's for none, and its device's ceiling.
func (self *fakeComputeSearchLedger) budgetsWithLock(request *ComputeSearchHoldRequest) map[string]int64 {
	budgets := map[string]int64{}
	if request.AgentId != nil {
		budgets[fakeSearchSpentKey(*request.AgentId, model.ComputeBudgetAgent, request.Minute)] = self.settings.DefaultAgentDayNanoUsd
	} else {
		budgets[fakeSearchSpentKey(request.SidecarId, model.ComputeBudgetDevice, request.Minute)] = self.settings.DefaultDeviceDayNanoUsd
	}
	budgets[fakeSearchSpentKey(request.SidecarId, model.ComputeBudgetCeiling, request.Minute)] = self.settings.DefaultDeviceCeilingDayNanoUsd
	return budgets
}

func (self *fakeComputeSearchLedger) Hold(ctx context.Context, request *ComputeSearchHoldRequest) (*ComputeSearchHoldAnswer, error) {
	opKey, start, err := controller.ComputeOpKeyForSearch(self.settings, request.NetworkId, request.RequestId, request.Attempt, request.Minute)
	if err != nil {
		return nil, err
	}
	if opKey != request.OpKey || !start.Equal(request.Minute) {
		return nil, errors.New("a hold under another key than D-BAL-14's")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return nil, errors.New("the ledger did not answer")
	}
	if op := self.ops[opKey]; op != nil {
		if op.state == model.ComputeOpStateOpen {
			return &ComputeSearchHoldAnswer{Admitted: true, OpKey: opKey}, nil
		}
		return &ComputeSearchHoldAnswer{OpKey: opKey, Finished: true}, nil
	}
	balance := &ComputeRefusal{Code: ComputeRefusalInsufficientQuota, Reason: string(controller.ComputeRefusalBalance)}
	account := self.accounts[request.NetworkId]
	if account == nil || !account.state.CanPay() || account.availableNanoUsd-account.promoNanoUsd < request.HoldNanoUsd {
		return &ComputeSearchHoldAnswer{OpKey: opKey, Refusal: balance}, nil
	}
	budgets := self.budgetsWithLock(request)
	for key, budgetCap := range budgets {
		if budgetCap < self.spentNanoUsds[key]+request.HoldNanoUsd {
			return &ComputeSearchHoldAnswer{OpKey: opKey, Refusal: &ComputeRefusal{Code: ComputeRefusalInsufficientQuota, Reason: string(controller.ComputeRefusalBudget)}}, nil
		}
	}
	for key := range budgets {
		self.spentNanoUsds[key] += request.HoldNanoUsd
	}
	account.availableNanoUsd -= request.HoldNanoUsd
	self.ops[opKey] = &fakeSearchOp{
		opKey: opKey, networkId: request.NetworkId, sidecarId: request.SidecarId, agentId: request.AgentId,
		requestId: request.RequestId, attempt: request.Attempt, minute: request.Minute, hold: request.HoldNanoUsd,
		state: model.ComputeOpStateOpen,
	}
	self.events = append(self.events, "hold "+sidecar.EvsKeyId(opKey))
	return &ComputeSearchHoldAnswer{Admitted: true, OpKey: opKey}, nil
}

// Gives op's hold back to its account and budgets.
func (self *fakeComputeSearchLedger) restoreWithLock(op *fakeSearchOp, amount int64) {
	self.accounts[op.networkId].availableNanoUsd += amount
	request := &ComputeSearchHoldRequest{SidecarId: op.sidecarId, AgentId: op.agentId, Minute: op.minute}
	for key := range self.budgetsWithLock(request) {
		self.spentNanoUsds[key] -= amount
	}
}

func (self *fakeComputeSearchLedger) Settle(ctx context.Context, request *ComputeSearchSettleRequest) (controller.ComputeSettleState, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return "", errors.New("the ledger did not answer")
	}
	op := self.ops[request.OpKey]
	switch {
	case op == nil:
		return controller.ComputeSettleGone, nil
	case op.state == model.ComputeOpStateVoid:
		return controller.ComputeSettleReleased, nil
	case op.state != model.ComputeOpStateOpen:
		return controller.ComputeSettleRepeat, nil
	}
	outcome := *request.Outcome
	// a charge never passes its hold
	outcome.AmountNanoUsd = min(outcome.AmountNanoUsd, op.hold)
	op.state = model.ComputeOpStateSettled
	op.outcome = &outcome
	self.restoreWithLock(op, op.hold-outcome.AmountNanoUsd)
	self.charges = append(self.charges, &fakeSearchCharge{
		chargeId: op.opKey, networkId: op.networkId, agentId: op.agentId, minute: op.minute,
		amount: outcome.AmountNanoUsd, cost: outcome.CostNanoUsd,
	})
	self.events = append(self.events, "settle "+sidecar.EvsKeyId(op.opKey))
	return controller.ComputeSettleSettled, nil
}

func (self *fakeComputeSearchLedger) Release(ctx context.Context, networkId sidecar.Id, opKey sidecar.Id) (controller.ComputeReleaseState, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return "", errors.New("the ledger did not answer")
	}
	op := self.ops[opKey]
	switch {
	case op == nil:
		return controller.ComputeReleaseGone, nil
	case op.state == model.ComputeOpStateVoid:
		return controller.ComputeReleaseReleased, nil
	case op.state != model.ComputeOpStateOpen:
		return controller.ComputeReleaseSettled, nil
	}
	op.state = model.ComputeOpStateVoid
	self.restoreWithLock(op, op.hold)
	self.events = append(self.events, "release "+sidecar.EvsKeyId(opKey))
	return controller.ComputeReleaseReleased, nil
}

func (self *fakeComputeSearchLedger) OpenBefore(ctx context.Context, before time.Time, limit int) ([]*model.ComputeOp, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ops := []*model.ComputeOp{}
	for _, op := range self.ops {
		if op.state == model.ComputeOpStateOpen && op.minute.Before(before) {
			ops = append(ops, &model.ComputeOp{OpKey: op.opKey, NetworkId: op.networkId, Kind: model.ComputeChargeKindWebSearch, State: op.state, StartTime: op.minute})
		}
	}
	sort.Slice(ops, func(i int, j int) bool { return ops[i].StartTime.Before(ops[j].StartTime) })
	if limit < len(ops) {
		ops = ops[:limit]
	}
	return ops, nil
}

// Deletes the searches' rows and charges from before before, oldest first, at most deleteLimit where set, as BAL's
// ComputeDeleteSearchRows will; the day's totals (dayAmount) are left as they are.
func (self *fakeComputeSearchLedger) DeleteBefore(ctx context.Context, before time.Time, limit int) (*ComputeSearchPurged, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < self.deleteLimit {
		limit = min(limit, self.deleteLimit)
	}
	candidates := []*fakeSearchOp{}
	for _, op := range self.ops {
		if op.minute.Before(before) && op.state != model.ComputeOpStateOpen {
			candidates = append(candidates, op)
		}
	}
	sort.Slice(candidates, func(i int, j int) bool { return candidates[i].minute.Before(candidates[j].minute) })
	purged := &ComputeSearchPurged{}
	for _, op := range candidates {
		if limit <= purged.DeletedCount {
			break
		}
		delete(self.ops, op.opKey)
		self.charges = slices.DeleteFunc(self.charges, func(charge *fakeSearchCharge) bool { return charge.chargeId == op.opKey })
		purged.DeletedCount += 1
	}
	for _, op := range self.ops {
		if purged.OldestTime == nil || op.minute.Before(*purged.OldestTime) {
			minute := op.minute
			purged.OldestTime = &minute
		}
	}
	return purged, nil
}

// Plants a settled search row at minute, as one the purge missed would stand.
func (self *fakeComputeSearchLedger) plant(networkId sidecar.Id, minute time.Time) sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	opKey := sidecar.NewId()
	self.ops[opKey] = &fakeSearchOp{opKey: opKey, networkId: networkId, minute: minute, state: model.ComputeOpStateSettled}
	self.charges = append(self.charges, &fakeSearchCharge{chargeId: opKey, networkId: networkId, minute: minute})
	return opKey
}

// searchsigner as SRCH-M13-03 and -04 will answer the broker: deterministic signatures, one nonce a ticket, and the
// reports it holds until the broker answers them.
type fakeSearchSigner struct {
	stateLock sync.Mutex
	// every sign request, in order
	signs []*protocol.SearchSignRequest
	// the sealed payee each ticket was signed for, by the ticket in hex
	signed map[string][]byte
	// a refusal every sign answers with, unspecified for none, and the payee payee_refused returns
	refusal     protocol.SearchSignRefusal
	refusePayee []byte
	// the signer does not answer
	failing bool
	// called with each sign request before it is answered, outside the lock
	onSign func(request *protocol.SearchSignRequest)
	// the reports it holds unanswered, and every answer it got
	reports []*protocol.SearchSignerReport
	answers []*protocol.SearchSignerAnswer
}

func newFakeSearchSigner() *fakeSearchSigner {
	return &fakeSearchSigner{signed: map[string][]byte{}}
}

// What it signs for a request: the same bytes for the same ticket, amount, minute and sealed payee (RFC 6979's
// determinism, as the signer's).
func fakeSearchAuthorization(request *protocol.SearchSignRequest) []byte {
	hash := sha256.New()
	hash.Write([]byte("fake sealed authorization"))
	hash.Write(request.GetTicket())
	hash.Write(binary.BigEndian.AppendUint64(nil, request.GetAmount()))
	hash.Write(binary.BigEndian.AppendUint64(nil, uint64(request.GetMinuteS())))
	hash.Write(request.GetSealedPayee())
	return hash.Sum(nil)
}

func (self *fakeSearchSigner) Sign(ctx context.Context, request *protocol.SearchSignRequest) (*protocol.SearchSignResponse, error) {
	onSign := func() func(request *protocol.SearchSignRequest) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.onSign
	}()
	if onSign != nil {
		onSign(request)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.signs = append(self.signs, proto.Clone(request).(*protocol.SearchSignRequest))
	if self.failing {
		return nil, ErrSearchSignerCall
	}
	if self.refusal != protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_UNSPECIFIED {
		response := &protocol.SearchSignResponse{Refusal: self.refusal}
		if self.refusal == protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_PAYEE_REFUSED {
			response.Payee = self.refusePayee
		}
		return response, nil
	}
	ticketHex := hex.EncodeToString(request.GetTicket())
	if signed, ok := self.signed[ticketHex]; ok && !bytes.Equal(signed, request.GetSealedPayee()) {
		return &protocol.SearchSignResponse{Refusal: protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_NONCE_REUSED}, nil
	}
	self.signed[ticketHex] = bytes.Clone(request.GetSealedPayee())
	return &protocol.SearchSignResponse{SealedAuthorization: fakeSearchAuthorization(request)}, nil
}

func (self *fakeSearchSigner) Reports(ctx context.Context) (*protocol.SearchSignerReports, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return nil, ErrSearchSignerCall
	}
	reports := &protocol.SearchSignerReports{}
	for _, report := range self.reports {
		reports.Reports = append(reports.Reports, proto.Clone(report).(*protocol.SearchSignerReport))
	}
	return reports, nil
}

func (self *fakeSearchSigner) Answer(ctx context.Context, answers *protocol.SearchSignerAnswers) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return ErrSearchSignerCall
	}
	for _, answer := range answers.GetAnswers() {
		self.answers = append(self.answers, proto.Clone(answer).(*protocol.SearchSignerAnswer))
		self.reports = slices.DeleteFunc(self.reports, func(report *protocol.SearchSignerReport) bool {
			return bytes.Equal(report.GetTicket(), answer.GetTicket())
		})
	}
	return nil
}

func (self *fakeSearchSigner) Day(ctx context.Context, request *protocol.SearchSignerDayRequest) (*protocol.SearchSignerDay, error) {
	return nil, errors.New("the fake signer keeps no day")
}

// Holds a report of kind for ticket, as the signer's finality cursor would.
func (self *fakeSearchSigner) report(ticket []byte, kind protocol.SearchSignerReportKind, minuteS int64, payee []byte, transaction []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reports = append(self.reports, &protocol.SearchSignerReport{Ticket: bytes.Clone(ticket), Kind: kind, MinuteS: minuteS, Payee: payee, Transaction: transaction})
}

func (self *fakeSearchSigner) signList() []*protocol.SearchSignRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.signs)
}

func (self *fakeSearchSigner) answerList() []*protocol.SearchSignerAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.answers)
}

func (self *fakeSearchSigner) set(change func(signer *fakeSearchSigner)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	change(self)
}

// The caller's verified state as a test sets it: the compute rows, and whether a compute:search query rule names it.
type fakeComputeSearchAcl struct {
	rows    *protocol.AclComputeRows
	allowed bool
}

func (self *fakeComputeSearchAcl) ComputeRows() *protocol.AclComputeRows {
	return self.rows
}

func (self *fakeComputeSearchAcl) ComputeAllows(subject sidecar.AclSubject, target sidecar.AclComputeTarget, action protocol.AclAction, now time.Time) sidecar.AclDecision {
	allowed := self.allowed && target.Resource == protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_SEARCH && action == protocol.AclAction_ACL_ACTION_QUERY
	return sidecar.AclDecision{Allowed: allowed}
}

// A synthetic search line: a .example host, a test chain, an asset, a payer and a signer key drawn from labels.
func testComputeSearchLine(t testing.TB) (*sidecar.WebSearchPolicyLine, hpke.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("compute search test signer key"))
	key, err := hpke.MLKEM768X25519().DeriveKeyPair(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	asset := sha256.Sum256([]byte("compute search test asset"))
	payer := sha256.Sum256([]byte("compute search test payer"))
	line := &sidecar.WebSearchPolicyLine{
		Host:          "gateway.example",
		Network:       "eip155:84532",
		ChainId:       84532,
		AssetName:     "USD Coin",
		AssetVersion:  "2",
		CeilingAmount: 15_000,
		SignerKey:     key.PublicKey(),
	}
	copy(line.Asset[:], asset[:])
	copy(line.Payer[:], payer[:])
	return line, key
}

// What a search fixture is built with beyond its defaults.
type computeSearchFixtureOptions struct {
	// nil: DefaultComputeEngineSettings, with no report loop of its own
	settings *ComputeEngineSettings
	// a second broker on this one's world: its ledger, signer, records and policy
	sharedWith *computeSearchFixture
	// {cmpa}'s persistence as the host reads it; nil: off
	persistence *ComputeRedisPersistence
	// no persistence reader at all
	noPersistenceReader bool
	// nil: the engine's own log
	log sidecar.Logger
}

// One broker and its search world: the network funded with $10, its clause accepted, its caller allowed to search
// under no compute block, a policy with a search line and catalog version 1 listing the search section.
type computeSearchFixture struct {
	*computeFixture
	ledger    *fakeComputeSearchLedger
	signer    *fakeSearchSigner
	line      *sidecar.WebSearchPolicyLine
	signerKey hpke.PrivateKey
	catalog   *fakeComputeCatalogStore

	stateLock   sync.Mutex
	policy      *sidecar.ComputePolicy
	acls        map[sidecar.Id]*fakeComputeSearchAcl
	persistence *ComputeRedisPersistence
}

func newComputeSearchFixture(t testing.TB, options *computeSearchFixtureOptions) *computeSearchFixture {
	t.Helper()
	if options == nil {
		options = &computeSearchFixtureOptions{}
	}
	settings := options.settings
	if settings == nil {
		settings = DefaultComputeEngineSettings()
		settings.Search.ReportPollInterval = 0
	}
	self := &computeSearchFixture{acls: map[sidecar.Id]*fakeComputeSearchAcl{}}
	if shared := options.sharedWith; shared != nil {
		self.ledger, self.signer, self.line, self.signerKey, self.catalog = shared.ledger, shared.signer, shared.line, shared.signerKey, shared.catalog
		self.policy, self.acls, self.persistence = shared.policy, shared.acls, shared.persistence
	} else {
		self.ledger = newFakeComputeSearchLedger()
		self.signer = newFakeSearchSigner()
		self.line, self.signerKey = testComputeSearchLine(t)
		lineJson, err := sidecar.WebSearchPolicyLineJson(self.line)
		if err != nil {
			t.Fatal(err)
		}
		self.policy = &sidecar.ComputePolicy{Search: lineJson}
		self.persistence = &ComputeRedisPersistence{}
		if options.persistence != nil {
			self.persistence = options.persistence
		}
		self.catalog = &fakeComputeCatalogStore{}
	}
	fixtureOptions := &computeFixtureOptions{
		settings:     settings,
		log:          options.log,
		handlers:     map[string]ComputeHandler{ComputeRouteSearchAuthorize: computeSearchAuthorizeHandler},
		catalogStore: self.catalog,
		editDeps: func(deps *ComputeEngineDeps) {
			deps.Policy = func() *sidecar.ComputePolicy {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				return self.policy
			}
			deps.SearchSigner = self.signer
			deps.SearchLedger = self.ledger
			if !options.noPersistenceReader {
				deps.AdmissionsPersistence = func(ctx context.Context) (*ComputeRedisPersistence, error) {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					copied := *self.persistence
					return &copied, nil
				}
			}
			deps.testSearch.acl = func(caller *ComputeCaller) computeSearchAcl {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				acl := self.acls[caller.NetworkId]
				if acl == nil {
					return &fakeComputeSearchAcl{allowed: true}
				}
				copied := *acl
				return &copied
			}
		},
	}
	if options.sharedWith != nil {
		fixtureOptions.sharedWith = options.sharedWith.computeFixture
	}
	self.computeFixture = newComputeFixture(t, fixtureOptions)
	if options.sharedWith == nil {
		registerComputeSearchTwins(self.redis)
		self.ledger.fund(self.networkId, 10*model.ComputeCreditNanoUsd)
		self.ledger.setClause(self.networkId, true)
		self.publishCatalog(t)
	}
	return self
}

// Publishes the next catalog version, its search section at the default gateway price.
func (self *computeSearchFixture) publishCatalog(t testing.TB) uint64 {
	t.Helper()
	body, err := computeSearchCatalogSection(model.DefaultComputeLedgerSettings(), DefaultComputeSearchSettings())
	if err != nil {
		t.Fatal(err)
	}
	versions, err := self.catalog.Newest(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	next := uint64(1)
	if 0 < len(versions) {
		next = versions[0].Version + 1
	}
	answer := &protocol.InferCatalogAnswer{
		PublishedMs: self.clock.Now().UnixMilli(),
		Models:      []*protocol.InferCatalogModel{},
		Sections:    []*protocol.InferCatalogSection{{Name: ComputeSearchCatalogSectionName, Body: body}},
	}
	if err := self.catalog.Publish(context.Background(), &ComputeCatalogVersion{Version: next, PublishedTime: self.clock.Now(), Answer: answer}); err != nil {
		t.Fatal(err)
	}
	return next
}

// Sets networkId's verified state.
func (self *computeSearchFixture) setAcl(networkId sidecar.Id, acl *fakeComputeSearchAcl) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.acls[networkId] = acl
}

// Sets the policy the broker holds.
func (self *computeSearchFixture) setPolicy(policy *sidecar.ComputePolicy) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.policy = policy
}

// One more admitted member device in a network of its own, loaded, open and in standing, funded and accepting the
// clause: its token.
func (self *computeSearchFixture) addNetwork(label string) (sidecar.Id, string) {
	networkId := testComputeId("network-" + label)
	clientId := testComputeId("client-" + label)
	sidecarId := testComputeId("sidecar-" + label)
	memberId := testComputeId("member-" + label)
	self.authState.load(networkId, 0)
	self.authState.admit(&ComputeCaller{NetworkId: networkId, ClientId: clientId, SidecarId: sidecarId, MemberId: memberId, Consented: true})
	self.gates.AddServiceNetworks(sidecar.ServiceGateCompute, connect.Id(networkId))
	self.abuse.Set(connect.Id(networkId), sidecar.AbuseStandingStandard, true)
	self.ledger.fund(networkId, 10*model.ComputeCreditNanoUsd)
	self.ledger.setClause(networkId, true)
	connectNetworkId, connectClientId := connect.Id(networkId), connect.Id(clientId)
	connectSidecarId, connectMemberId := connect.Id(sidecarId), connect.Id(memberId)
	token := self.authenticator.Issue(&sidecar.Principal{
		NetworkId:   connectNetworkId,
		ClientId:    connectClientId,
		SidecarId:   &connectSidecarId,
		MemberId:    &connectMemberId,
		Audience:    ComputeAudience,
		ProjVersion: 1,
		IssuedAt:    self.clock.Now(),
		ExpiresAt:   self.clock.Now().Add(24 * time.Hour),
	})
	return networkId, token
}

// A request id from a label, the first 16 bytes of its SHA-256, so labels longer than an id stay apart.
func testSearchRequestId(label string) []byte {
	hash := sha256.Sum256([]byte("request " + label))
	return hash[:16]
}

// An authorize request for requestId's attempt at the gateway's price, under catalog version 1.
func (self *computeSearchFixture) request(requestId []byte, attempt uint32) *protocol.ComputeSearchAuthorizeRequest {
	return &protocol.ComputeSearchAuthorizeRequest{
		CatalogVersion: 1,
		RequestId:      requestId,
		Attempt:        attempt,
		SealedPayee:    []byte(fmt.Sprintf("sealed payee of %x attempt %d", requestId, attempt)),
		Amount:         10_000,
		Asset:          self.line.Asset[:],
		Network:        self.line.Network,
	}
}

// Serves request with token (the fixture's sidecar's for ""), answering the recorder and, on 200, the response.
func (self *computeSearchFixture) authorizeAs(token string, request *protocol.ComputeSearchAuthorizeRequest) (*httptest.ResponseRecorder, *protocol.ComputeSearchAuthorizeResponse) {
	self.t.Helper()
	if token == "" {
		token = self.token()
	}
	body, err := proto.Marshal(request)
	if err != nil {
		self.t.Fatal(err)
	}
	recorder := self.serve(http.MethodPost, "/v1/search/authorize", token, string(body), nil)
	if recorder.Code != http.StatusOK {
		return recorder, nil
	}
	response := &protocol.ComputeSearchAuthorizeResponse{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), response); err != nil {
		self.t.Fatalf("the answer does not parse: %v", err)
	}
	return recorder, response
}

// As authorizeAs, as the fixture's sidecar.
func (self *computeSearchFixture) authorize(request *protocol.ComputeSearchAuthorizeRequest) (*httptest.ResponseRecorder, *protocol.ComputeSearchAuthorizeResponse) {
	self.t.Helper()
	return self.authorizeAs("", request)
}

// Fails unless recorder refused with code and reason.
func requireComputeSearchRefusal(t testing.TB, recorder *httptest.ResponseRecorder, code ComputeRefusalCode, reason string) {
	t.Helper()
	body := &computeRefusalBody{}
	if recorder.Header().Get("Content-Type") != computeContentTypeJson {
		t.Fatalf("answered %d %q, want %s %s", recorder.Code, recorder.Body.String(), code, reason)
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), body); err != nil || body.Code != code || body.Reason != reason {
		t.Fatalf("answered %d %q, want %s %s", recorder.Code, recorder.Body.String(), code, reason)
	}
}

// The op key the admission derives for requestId's attempt at the fixture's minute now.
func (self *computeSearchFixture) opKey(networkId sidecar.Id, requestId []byte, attempt int16) sidecar.Id {
	self.t.Helper()
	opKey, _, err := controller.ComputeOpKeyForSearch(model.DefaultComputeLedgerSettings(), networkId, sidecar.Id(requestId), attempt, self.clock.Now())
	if err != nil {
		self.t.Fatal(err)
	}
	return opKey
}

// The search's admission.
func (self *computeSearchFixture) admission() *ComputeSearchAdmission {
	return self.engine.SearchAdmission()
}

// The fixture's whole Redis, both instances, as one dump: key to value.
func (self *computeSearchFixture) dumpRedis() map[string][]byte {
	dump := map[string][]byte{}
	for key, value := range self.redis.Dump() {
		dump["main "+key] = value
	}
	for key, value := range self.admissionsRedis.Dump() {
		dump["admissions "+key] = value
	}
	return dump
}

// The Go twins of the search scripts (search_limits.go, search_outcome_counts.go), each doing what its Lua does; T3
// runs the Lua itself.
func registerComputeSearchTwins(redis *sidecartest.FakeRedis) {
	redis.RegisterScript(computeSearchRateScript.Name, twinComputeSearchRate)
	redis.RegisterScript(computeSearchRateRefundScript.Name, twinComputeSearchRateRefund)
	redis.RegisterScript(computeSearchLimiterScript.Name, twinComputeSearchLimiter)
	redis.RegisterScript(computeSearchOutcomesScript.Name, twinComputeSearchOutcomes)
}
