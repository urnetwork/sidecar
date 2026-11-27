package computeservice

// POST compute/v1/budget/raise's checks before the ledger's transaction (BAL-M12-16): the body, the action and the
// effect key, refused invalid; the subject, the agent or the requesting device and never another sidecar or a member;
// and §16.6's spend check at server time on real signed decisions over a fixed state, which refuses no decision that
// approves, a decision another network's device signed, an expired one and one over another action. The table, the
// claim, a retry, a spent use and the projection's raised cap run on the private stack, in server/computet3's
// compute_budget_raise_t3_test.go. The gate refusing a caller whose verified state is not loaded is the engine's.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One device of the fixture: its sidecar, member and key.
type testBudgetRaiseDevice struct {
	sidecarId sidecar.Id
	memberId  sidecar.Id
	key       ed25519.PrivateKey
}

func newTestBudgetRaiseDevice(label string, memberId sidecar.Id) testBudgetRaiseDevice {
	seed := sha256.Sum256([]byte("budget raise test " + label))
	id := sha256.Sum256([]byte("budget raise test id " + label))
	return testBudgetRaiseDevice{sidecarId: sidecar.Id(id[:16]), memberId: memberId, key: ed25519.NewKeyFromSeed(seed[:])}
}

// A spend state of fixed facts: the devices it admits, each approval-capable for its member, and one rule whose
// approver is the requester's member on channel device.
type testBudgetRaiseState struct {
	pin      *bridge.AuthPin
	devices  []testBudgetRaiseDevice
	approver sidecar.Id
}

func (self *testBudgetRaiseState) Pin() *bridge.AuthPin {
	return self.pin
}

func (self *testBudgetRaiseState) ChainAt(version uint64) ([sha256.Size]byte, bool) {
	if version == self.pin.GetVersion() {
		return [sha256.Size]byte(self.pin.GetChain()), true
	}
	return [sha256.Size]byte{}, false
}

func (self *testBudgetRaiseState) Forked() bool {
	return false
}

func (self *testBudgetRaiseState) IdentityKey(sidecarId sidecar.Id) []byte {
	for _, device := range self.devices {
		if device.sidecarId == sidecarId {
			return device.key.Public().(ed25519.PublicKey)
		}
	}
	return nil
}

func (self *testBudgetRaiseState) ApprovalCapable(sidecarId sidecar.Id, memberId sidecar.Id) bool {
	for _, device := range self.devices {
		if device.sidecarId == sidecarId && device.memberId == memberId {
			return true
		}
	}
	return false
}

func (self *testBudgetRaiseState) PresenceKey(keyId []byte, memberId sidecar.Id) *bridge.KeyRow {
	return nil
}

func (self *testBudgetRaiseState) Govern(action *sidecar.StoredCanonicalAction, spender sidecar.Id, now time.Time) (sidecar.SpendRule, error) {
	return self, nil
}

func (self *testBudgetRaiseState) Evidence() []protocol.ApprovalChannel {
	return []protocol.ApprovalChannel{protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE}
}

func (self *testBudgetRaiseState) ApproverCount() int {
	return 1
}

func (self *testBudgetRaiseState) Names(memberId sidecar.Id) bool {
	return memberId == self.approver
}

func (self *testBudgetRaiseState) ClauseAdmin(memberId sidecar.Id) bool {
	return false
}

func (self *testBudgetRaiseState) AdminClauseMet(memberIds []sidecar.Id) bool {
	return true
}

// The fixture: the requester's laptop, the person's phone that approves, another network's device, and the state of
// the requester's network.
type testBudgetRaiseWorld struct {
	laptop   testBudgetRaiseDevice
	phone    testBudgetRaiseDevice
	stranger testBudgetRaiseDevice
	state    *testBudgetRaiseState
}

func newTestBudgetRaiseWorld() *testBudgetRaiseWorld {
	member := sidecar.NewId()
	chain := sha256.Sum256([]byte("budget raise test chain"))
	world := &testBudgetRaiseWorld{
		laptop:   newTestBudgetRaiseDevice("laptop "+member.String(), member),
		phone:    newTestBudgetRaiseDevice("phone "+member.String(), member),
		stranger: newTestBudgetRaiseDevice("stranger "+member.String(), sidecar.NewId()),
	}
	// the stranger's network's state is its own: this one admits only the person's devices
	world.state = &testBudgetRaiseState{
		pin:      &bridge.AuthPin{Version: 9, Chain: chain[:]},
		devices:  []testBudgetRaiseDevice{world.laptop, world.phone},
		approver: member,
	}
	return world
}

// Bytes laid out as a sealed body, a generation, a nonce, one padded block and the tag, standing in for the config
// key's seal, which no broker opens.
func testBudgetRaiseSealed(label []byte) []byte {
	const byteCount = 8 + 24 + 256 + 16
	sealed := []byte{}
	for counter := byte(0); len(sealed) < byteCount; counter += 1 {
		block := sha256.Sum256(append([]byte{counter}, label...))
		sealed = append(sealed, block[:]...)
	}
	return sealed[:byteCount]
}

// A version-5 compute_budget_raise of agentId's period to amount, its sealed detail a stand-in.
func testBudgetRaiseAction(t testing.TB, agentId []byte, period uint32, amount uint64) *sidecar.StoredCanonicalAction {
	t.Helper()
	stored, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind:         uint32(sidecar.SidecarActionComputeBudgetRaise),
		Version:      computeBudgetRaiseActionVersion,
		Budget:       &protocol.BudgetFields{AgentId: agentId, Period: period, Amount: amount, Current: amount / 2},
		SealedDetail: testBudgetRaiseSealed(append([]byte("budget raise test sealed detail "), agentId...)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// signer's decision for action, approving or not, expiring at notAfter, requested by the laptop, as stored.
func (self *testBudgetRaiseWorld) decision(t testing.TB, action *sidecar.StoredCanonicalAction, approvalId sidecar.Id, verdict protocol.ApprovalVerdict, notAfter time.Time, signer testBudgetRaiseDevice) []byte {
	t.Helper()
	payload := action.PayloadSha256()
	request := sha256.Sum256(append([]byte("budget raise test request "), approvalId[:]...))
	body := &protocol.ApprovalDecision{
		ApprovalId: approvalId.Bytes(), RequestSha256: request[:], PayloadSha256: payload[:], Decision: uint32(verdict), Uses: 1,
		NotAfterMillis: notAfter.UnixMilli(), ApproverMemberId: signer.memberId.Bytes(),
		Channel:            uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
		RequesterSidecarId: self.laptop.sidecarId.Bytes(), AuthPin: self.state.pin, Version: 1,
	}
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := proto.Marshal(&bridge.Signed{
		Body:      bodyBytes,
		SignerId:  signer.sidecarId.Bytes(),
		Signature: ed25519.Sign(signer.key, bridge.SignedBytes(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, bodyBytes)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// A request for the route with key as its Idempotency-Key.
func testBudgetRaiseRequest(key string) *ComputeRequest {
	httpRequest := httptest.NewRequest(http.MethodPost, "/v1/budget/raise", nil)
	if key != "" {
		httpRequest.Header.Set(ComputeIdempotencyKeyHeader, key)
	}
	return &ComputeRequest{Http: httpRequest}
}

// action's effect key under approvalId, as the device sends it.
func testBudgetRaiseKey(action *sidecar.StoredCanonicalAction, approvalId sidecar.Id) string {
	effectKey := sidecar.ApprovalEffectKey(approvalId, action.ActionId(approvalId))
	return base64.RawURLEncoding.EncodeToString(effectKey[:])
}

// The body, the action and the key are refused invalid before anything is read: no decision, more than the bound, a
// decision that does not parse, an action of another kind at version 4, one of kind 21 with a field no server path
// may see, and a key that is not the action's.
func TestBudgetRaiseRefusesABodyTheGateCannotRead(t *testing.T) {
	world := newTestBudgetRaiseWorld()
	ledger := model.DefaultComputeLedgerSettings()
	agentId := sidecar.NewId()
	action := testBudgetRaiseAction(t, agentId.Bytes(), 1, 10_000_000_000)
	approvalId := sidecar.NewId()
	decision := world.decision(t, action, approvalId, protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, time.Now().Add(time.Hour), world.phone)
	key := testBudgetRaiseKey(action, approvalId)
	if parsed, refusal := computeBudgetRaiseParse(testBudgetRaiseRequest(key), &protocol.ComputeBudgetRaiseRequest{Decisions: [][]byte{decision}, Action: action.Bytes}, ledger); refusal != nil || parsed.approvalId != approvalId {
		t.Fatalf("a good request: %+v", refusal)
	}
	dns, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(sidecar.SidecarActionDnsSet), DnsName: "www", DnsType: "A", DnsValue: "192.0.2.1", DnsTtl: 300})
	if err != nil {
		t.Fatal(err)
	}
	tooMany := [][]byte{}
	for range ledger.BudgetRaiseDecisionMaxCount + 1 {
		tooMany = append(tooMany, decision)
	}
	for _, c := range []struct {
		label string
		key   string
		body  *protocol.ComputeBudgetRaiseRequest
	}{
		{label: "no decision", key: key, body: &protocol.ComputeBudgetRaiseRequest{Action: action.Bytes}},
		{label: "past the bound", key: key, body: &protocol.ComputeBudgetRaiseRequest{Decisions: tooMany, Action: action.Bytes}},
		{label: "a decision that does not parse", key: key, body: &protocol.ComputeBudgetRaiseRequest{Decisions: [][]byte{[]byte("not a decision")}, Action: action.Bytes}},
		{label: "a dns_set at version 4", key: testBudgetRaiseKey(dns, approvalId), body: &protocol.ComputeBudgetRaiseRequest{Decisions: [][]byte{decision}, Action: dns.Bytes}},
		{label: "no action", key: key, body: &protocol.ComputeBudgetRaiseRequest{Decisions: [][]byte{decision}}},
		{label: "another action's key", key: testBudgetRaiseKey(testBudgetRaiseAction(t, agentId.Bytes(), 1, 20_000_000_000), approvalId), body: &protocol.ComputeBudgetRaiseRequest{Decisions: [][]byte{decision}, Action: action.Bytes}},
		{label: "a key not base64url", key: "not+a/key", body: &protocol.ComputeBudgetRaiseRequest{Decisions: [][]byte{decision}, Action: action.Bytes}},
	} {
		if _, refusal := computeBudgetRaiseParse(testBudgetRaiseRequest(c.key), c.body, ledger); refusal == nil || refusal.Code != ComputeRefusalInvalid {
			t.Errorf("%s: %+v", c.label, refusal)
		}
	}
}

// A config of fixed rows: which ids are sidecars and members of the network.
type testBudgetRaiseConfig struct {
	sidecarIds []sidecar.Id
	memberIds  []sidecar.Id
}

func (self *testBudgetRaiseConfig) SidecarRow(sidecarId sidecar.Id) *bridge.SidecarRow {
	for _, id := range self.sidecarIds {
		if id == sidecarId {
			return &bridge.SidecarRow{}
		}
	}
	return nil
}

func (self *testBudgetRaiseConfig) Member(memberId sidecar.Id) *bridge.MemberRow {
	for _, id := range self.memberIds {
		if id == memberId {
			return &bridge.MemberRow{}
		}
	}
	return nil
}

// A raise lifts an agent's budgets, or the requesting device's own by its sidecar's id; another sidecar's or a member's
// is refused approval_refused, subject; one naming no agent, a gateway grant's, raises nothing at the broker.
func TestBudgetRaiseSubjectIsTheAgentOrTheRequestingDevice(t *testing.T) {
	caller := &ComputeCaller{SidecarId: sidecar.NewId(), MemberId: sidecar.NewId()}
	other, member, agent := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	config := &testBudgetRaiseConfig{sidecarIds: []sidecar.Id{caller.SidecarId, other}, memberIds: []sidecar.Id{caller.MemberId, member}}
	for _, c := range []struct {
		label   string
		agentId []byte
		subject *sidecar.Id
		refused bool
	}{
		{label: "an agent", agentId: agent.Bytes(), subject: &agent},
		{label: "the device itself", agentId: caller.SidecarId.Bytes(), subject: &caller.SidecarId},
		{label: "a gateway grant's", agentId: nil, subject: nil},
		{label: "another sidecar", agentId: other.Bytes(), refused: true},
		{label: "a member", agentId: member.Bytes(), refused: true},
		{label: "the caller's own member", agentId: caller.MemberId.Bytes(), refused: true},
	} {
		subject, refusal := computeBudgetRaiseSubject(caller, config, &protocol.BudgetFields{AgentId: c.agentId})
		switch {
		case c.refused && (refusal == nil || refusal.Code != ComputeRefusalApprovalRefused || refusal.Reason != computeBudgetRaiseReasonSubject):
			t.Errorf("%s: %+v", c.label, refusal)
		case !c.refused && refusal != nil:
			t.Errorf("%s refused: %+v", c.label, refusal)
		case !c.refused && (subject == nil) != (c.subject == nil):
			t.Errorf("%s: subject %v", c.label, subject)
		case !c.refused && subject != nil && *subject != *c.subject:
			t.Errorf("%s: subject %v, want %v", c.label, *subject, *c.subject)
		}
	}
	if status, ok := ComputeRefusalStatus(ComputeRefusalApprovalRefused); !ok || status != http.StatusForbidden {
		t.Errorf("approval_refused answers %d", status)
	}
	if status, ok := ComputeRefusalStatus(ComputeRefusalSpent); !ok || status != http.StatusConflict {
		t.Errorf("spent answers %d", status)
	}
}

// §16.6's spend check at server time spends an approving decision of the person's phone for the laptop's request, at
// its uses and expiry, and refuses with its code, writing nothing: a decision that denies, one another network's device
// signed, one past its not_after (the gate allows no skew), one over another action, and one the laptop signed for
// itself on channel device.
func TestBudgetRaiseRefusedWithoutAValidDecision(t *testing.T) {
	world := newTestBudgetRaiseWorld()
	ledger := model.DefaultComputeLedgerSettings()
	now := time.Date(2026, time.November, 26, 12, 0, 0, 0, time.UTC)
	agentId := sidecar.NewId()
	action := testBudgetRaiseAction(t, agentId.Bytes(), 1, 10_000_000_000)
	caller := &ComputeCaller{SidecarId: world.laptop.sidecarId, MemberId: world.laptop.memberId}
	stateOf := func(caller *ComputeCaller) (sidecar.SpendState, error) { return world.state, nil }
	spendOf := func(decision []byte, approvalId sidecar.Id, of *sidecar.StoredCanonicalAction) (*controller.ComputeBudgetRaiseSpend, error) {
		parsed, refusal := computeBudgetRaiseParse(testBudgetRaiseRequest(testBudgetRaiseKey(of, approvalId)),
			&protocol.ComputeBudgetRaiseRequest{Decisions: [][]byte{decision}, Action: of.Bytes}, ledger)
		if refusal != nil {
			t.Fatalf("the request does not parse: %+v", refusal)
		}
		// the decision's action, as the gate holds it to the decision
		parsed.action = action
		return computeBudgetRaiseSpend(caller, parsed, stateOf)(now)
	}
	approvalId := sidecar.NewId()
	approved := world.decision(t, action, approvalId, protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, now.Add(time.Hour), world.phone)
	spend, err := spendOf(approved, approvalId, action)
	if err != nil || spend.Uses != 1 || spend.NotAfterMillis != now.Add(time.Hour).UnixMilli() {
		t.Fatalf("the person's approval: %+v %v", spend, err)
	}
	other := testBudgetRaiseAction(t, agentId.Bytes(), 2, 50_000_000_000)
	for _, c := range []struct {
		label    string
		decision []byte
		code     sidecar.SpendRefusalCode
	}{
		{label: "a decision that denies", decision: world.decision(t, action, approvalId, protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY, now.Add(time.Hour), world.phone), code: sidecar.SpendRefusalVerdict},
		{label: "another network's device", decision: world.decision(t, action, approvalId, protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, now.Add(time.Hour), world.stranger), code: sidecar.SpendRefusalSigner},
		{label: "past its not_after", decision: world.decision(t, action, approvalId, protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, now.Add(-time.Second), world.phone), code: sidecar.SpendRefusalExpired},
		{label: "over another action", decision: world.decision(t, other, approvalId, protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, now.Add(time.Hour), world.phone), code: sidecar.SpendRefusalPayload},
		{label: "the requester's own", decision: world.decision(t, action, approvalId, protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, now.Add(time.Hour), world.laptop), code: sidecar.SpendRefusalSigner},
	} {
		_, err := spendOf(c.decision, approvalId, action)
		var refusal *computeBudgetRaiseRefusal
		if !errors.As(err, &refusal) || refusal.code != c.code || !errors.Is(err, controller.ErrComputeBudgetRaiseRefused) {
			t.Errorf("%s: %v", c.label, err)
		}
	}
}

// The stored row's answer: its approval, use, subject, period, amount and expiry, and device_only for a run's raise
// and a gateway grant's.
func TestBudgetRaiseAnswerIsTheStoredRow(t *testing.T) {
	subject := sidecar.NewId()
	expire := time.Date(2026, time.November, 27, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		raise      *model.ComputeBudgetRaise
		deviceOnly bool
	}{
		{raise: &model.ComputeBudgetRaise{ApprovalId: sidecar.NewId(), ApprovalUse: 0, SubjectId: subject, Period: model.ComputeBudgetPeriodDay, AmountNanoUsd: 10, ExpireTime: expire}},
		{raise: &model.ComputeBudgetRaise{ApprovalId: sidecar.NewId(), SubjectId: subject, Period: model.ComputeBudgetPeriodRun, AmountNanoUsd: 10, ExpireTime: expire}, deviceOnly: true},
		{raise: &model.ComputeBudgetRaise{ApprovalId: sidecar.NewId(), Period: model.ComputeBudgetPeriodMonth, AmountNanoUsd: 10, ExpireTime: expire}, deviceOnly: true},
	} {
		answer := computeBudgetRaiseAnswerOf(c.raise)
		if answer.GetDeviceOnly() != c.deviceOnly || answer.GetAmount() != 10 || answer.GetExpireMs() != expire.UnixMilli() ||
			answer.GetPeriod() != uint32(c.raise.Period) || sidecar.Id(answer.GetApprovalId()) != c.raise.ApprovalId {
			t.Errorf("%+v answers %+v", c.raise, answer)
		}
		if (c.raise.SubjectId == sidecar.Id{}) != (len(answer.GetSubjectId()) == 0) {
			t.Errorf("%+v answers subject %x", c.raise, answer.GetSubjectId())
		}
	}
}

// The gate refuses kind 21 503 while the caller's verified state is not loaded, before the handler runs, and every
// approval kind no area registered; the handler is the registered one.
func TestBudgetRaiseGateNeedsTheVerifiedState(t *testing.T) {
	reached := 0
	fixture := newComputeFixture(t, &computeFixtureOptions{handlers: map[string]ComputeHandler{
		ComputeRouteBudgetRaise: func(request *ComputeRequest) {
			reached += 1
			request.Reply(nil)
		},
	}})
	headers := map[string]string{ComputeIdempotencyKeyHeader: "effect-key-1"}
	recorder := fixture.serve(http.MethodPost, "/v1/budget/raise", fixture.token(), "", headers)
	requireComputeRefusal(t, recorder, http.StatusServiceUnavailable, ComputeRefusalUnavailable)
	if reached != 0 {
		t.Fatal("the handler ran past a gate with no verified state")
	}
	if refusal := (&computeApprovalKinds{}).Admit(testBudgetRaiseRequest(""), ComputeApprovalKind(99)); refusal == nil || refusal.Code != ComputeRefusalUnavailable {
		t.Errorf("an unregistered kind: %+v", refusal)
	}
	if computeRouteHandlers[ComputeRouteBudgetRaise] == nil {
		t.Error("the route's handler is not registered")
	}
}
