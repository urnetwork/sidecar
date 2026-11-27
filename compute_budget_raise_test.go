//go:build !ios_extension && !sidecar_http && !js

package sidecar

// Kind 21's effect and lookup on the device (BAL-M12-16) against a broker over TLS that keeps each use's stored result
// by its key: the effect presents the use's decisions and its action under Idempotency-Key, its reference the broker's
// answer; a refusal proves nothing done, an outage leaves the use uncertain; after a restart between the send and the
// answer, the lookup re-presents the same request and reads the stored result; a run's raise comes back device-only;
// and kind 21 is a server gate's kind, its use reserved to its decision's expiry less the skew.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A broker of budget raises over TLS: each key's first request stores its answer, which every repeat answers; it
// drops the connection of the first dropCount requests after it stored, as a lost answer does, and refuses with
// refusal's status and body where set.
type testBudgetRaiseBroker struct {
	server *httptest.Server

	stateLock  sync.Mutex
	keyAnswers map[string]*protocol.ComputeBudgetRaiseAnswer
	requests   []*protocol.ComputeBudgetRaiseRequest
	keys       []string
	dropCount  int
	refusal    *testBudgetRaiseRefusal
}

type testBudgetRaiseRefusal struct {
	status int
	body   string
}

func newTestBudgetRaiseBroker(t *testing.T) *testBudgetRaiseBroker {
	broker := &testBudgetRaiseBroker{keyAnswers: map[string]*protocol.ComputeBudgetRaiseAnswer{}}
	broker.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		raise := &protocol.ComputeBudgetRaiseRequest{}
		if request.Method != http.MethodPost || request.URL.Path != computeBudgetRaisePath || proto.Unmarshal(body, raise) != nil {
			testComputeRefuse(writer, http.StatusBadRequest, `{"code":"invalid"}`)
			return
		}
		key := request.Header.Get(computeBudgetRaiseKeyHeader)
		answer, drop, refusal := func() (*protocol.ComputeBudgetRaiseAnswer, bool, *testBudgetRaiseRefusal) {
			broker.stateLock.Lock()
			defer broker.stateLock.Unlock()
			broker.requests = append(broker.requests, raise)
			broker.keys = append(broker.keys, key)
			if broker.refusal != nil {
				return nil, false, broker.refusal
			}
			stored, ok := broker.keyAnswers[key]
			if !ok {
				action, err := ParseStoredCanonicalAction(raise.GetAction())
				decision, decisionErr := ParseStoredApprovalDecision(raise.GetDecisions()[0])
				if err != nil || decisionErr != nil {
					return nil, false, &testBudgetRaiseRefusal{status: http.StatusBadRequest, body: `{"code":"invalid"}`}
				}
				budget := action.Action.GetBudget()
				stored = &protocol.ComputeBudgetRaiseAnswer{
					ApprovalId: decision.Decision.GetApprovalId(), UseIndex: 0, SubjectId: budget.GetAgentId(), Period: budget.GetPeriod(),
					Amount: budget.GetAmount(), ExpireMs: 1_795_651_200_000, DeviceOnly: budget.GetPeriod() == approvalComputeBudgetPeriodRun,
				}
				broker.keyAnswers[key] = stored
			}
			drop := 0 < broker.dropCount
			if drop {
				broker.dropCount -= 1
			}
			return stored, drop, nil
		}()
		switch {
		case refusal != nil:
			testComputeRefuse(writer, refusal.status, refusal.body)
		case drop:
			// committed, and the answer lost with the connection
			connection, _, err := http.NewResponseController(writer).Hijack()
			if err == nil {
				connection.Close()
			}
		default:
			testComputeAnswer(writer, answer, testDpopNow)
		}
	}))
	t.Cleanup(broker.server.Close)
	return broker
}

// What the broker saw.
func (self *testBudgetRaiseBroker) seen() ([]*protocol.ComputeBudgetRaiseRequest, []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*protocol.ComputeBudgetRaiseRequest{}, self.requests...), append([]string{}, self.keys...)
}

// A host whose compute service client reaches broker, with no retry, so an outage answers at once.
type testBudgetRaiseHost struct {
	client *ComputeServiceClient
}

func (self *testBudgetRaiseHost) ComputeServiceClient() (*ComputeServiceClient, error) {
	return self.client, nil
}

func newTestBudgetRaiseHost(t *testing.T, broker *testBudgetRaiseBroker) *testBudgetRaiseHost {
	t.Helper()
	settings := DefaultInferSettings()
	settings.ComputeServiceRetryCount = 0
	client, err := newComputeServiceClient(&computeServiceClientArgs{
		BaseUrl:     broker.server.URL,
		Credentials: &testComputeCredentials{tokens: []string{"synthetic-compute-token"}},
		Settings:    settings,
		HttpClient:  broker.server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testBudgetRaiseHost{client: client}
}

// Bytes laid out as a sealed body, a generation, a nonce, one padded block and the tag, standing in for the config
// key's seal, which no broker opens.
func testBudgetRaiseSealed(label []byte) []byte {
	const byteCount = configSealGenerationByteCount + 24 + configSealPadByteCount + 16
	sealed := []byte{}
	for counter := byte(0); len(sealed) < byteCount; counter += 1 {
		block := sha256.Sum256(append([]byte{counter}, label...))
		sealed = append(sealed, block[:]...)
	}
	return sealed[:byteCount]
}

// A stored compute_budget_raise of agentId's period to amount, its sealed detail a stand-in.
func testBudgetRaiseStored(t *testing.T, agentId Id, period uint32, amount uint64) *StoredCanonicalAction {
	t.Helper()
	stored, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionComputeBudgetRaise), Version: canonicalActionVersionCompute,
		Budget:       &protocol.BudgetFields{AgentId: agentId.Bytes(), Period: period, Amount: amount, Current: amount / 2},
		SealedDetail: testBudgetRaiseSealed(append([]byte("device budget raise test "), agentId[:]...)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// A decision's Signed over body, under a key of the test's own, which the broker under test never verifies.
func testBudgetRaiseSigned(body []byte) *bridge.Signed {
	seed := sha256.Sum256([]byte("device budget raise test signer"))
	key := ed25519.NewKeyFromSeed(seed[:])
	return &bridge.Signed{
		Body: body, SignerId: NewId().Bytes(), Type: uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
		Signature: ed25519.Sign(key, bridge.SignedBytes(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body)),
	}
}

// ctx carrying a use's spend: decision bytes standing in for the person's Signed, which the broker under test reads
// only for its approval id.
func testBudgetRaiseSpendContext(t *testing.T, action *StoredCanonicalAction, approvalId Id) context.Context {
	t.Helper()
	payload := action.PayloadSha256()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ApprovalDecision{
		ApprovalId: approvalId.Bytes(), RequestSha256: payload[:], PayloadSha256: payload[:], Uses: 1, Version: 1,
		Decision: uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE), RequesterSidecarId: NewId().Bytes(),
		ApproverMemberId: NewId().Bytes(), Channel: uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
		NotAfterMillis: testDpopNow.Add(time.Hour).UnixMilli(), AuthPin: &bridge.AuthPin{Version: 3, Chain: payload[:]},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := proto.Marshal(testBudgetRaiseSigned(body))
	if err != nil {
		t.Fatal(err)
	}
	return withApprovalSpend(context.Background(), &ApprovalSpend{ApprovalId: approvalId, Decisions: [][]byte{signed}, Action: action.Bytes})
}

// The effect presents the use's decisions and its action as stored, under Idempotency-Key: its effect key in
// base64url, and its reference is the broker's answer; presented again under the key, the same.
func TestBudgetRaiseEffectPresentsTheDecisionsUnderItsKey(t *testing.T) {
	broker := newTestBudgetRaiseBroker(t)
	host := newTestBudgetRaiseHost(t, broker)
	agentId, approvalId := NewId(), NewId()
	action := testBudgetRaiseStored(t, agentId, approvalComputeBudgetPeriodDay, 10_000_000_000)
	ctx := testBudgetRaiseSpendContext(t, action, approvalId)
	effectKey := ApprovalEffectKey(approvalId, action.ActionId(approvalId))
	effect := NewComputeBudgetRaiseEffect(host, action.Bytes)
	first, err := effect.Run(ctx, effectKey[:])
	if err != nil {
		t.Fatal(err)
	}
	again, err := effect.Run(ctx, effectKey[:])
	if err != nil || !bytes.Equal(first, again) {
		t.Fatalf("again: %v, the same reference %t", err, bytes.Equal(first, again))
	}
	requests, keys := broker.seen()
	spend, _ := ApprovalSpendFromContext(ctx)
	if len(requests) != 2 || !bytes.Equal(requests[0].GetAction(), action.Bytes) || len(requests[0].GetDecisions()) != 1 ||
		!bytes.Equal(requests[0].GetDecisions()[0], spend.Decisions[0]) {
		t.Fatalf("the broker saw %+v", requests)
	}
	if keys[0] != base64.RawURLEncoding.EncodeToString(effectKey[:]) || keys[1] != keys[0] {
		t.Errorf("the keys %q", keys)
	}
	answer, err := ParseComputeBudgetRaiseReference(first)
	if err != nil || !bytes.Equal(answer.GetApprovalId(), approvalId.Bytes()) || answer.GetAmount() != 10_000_000_000 || answer.GetDeviceOnly() {
		t.Errorf("the reference %+v %v", answer, err)
	}
}

// A refusal proves nothing done (the gate judges a first presentation); an outage, a lost answer and an answer that is
// not this raise's leave it uncertain; a use with no key, no spend or a template sends nothing.
func TestBudgetRaiseEffectRefusalIsNotDoneAndOutageUncertain(t *testing.T) {
	agentId, approvalId := NewId(), NewId()
	action := testBudgetRaiseStored(t, agentId, approvalComputeBudgetPeriodMonth, 90_000_000_000)
	ctx := testBudgetRaiseSpendContext(t, action, approvalId)
	effectKey := ApprovalEffectKey(approvalId, action.ActionId(approvalId))
	for _, c := range []struct {
		label   string
		refusal *testBudgetRaiseRefusal
		notDone bool
	}{
		{label: "approval_refused", refusal: &testBudgetRaiseRefusal{status: http.StatusForbidden, body: `{"code":"approval_refused","reason":"signer"}`}, notDone: true},
		{label: "spent", refusal: &testBudgetRaiseRefusal{status: http.StatusConflict, body: `{"code":"spent"}`}, notDone: true},
		{label: "invalid", refusal: &testBudgetRaiseRefusal{status: http.StatusBadRequest, body: `{"code":"invalid"}`}, notDone: true},
		{label: "unavailable", refusal: &testBudgetRaiseRefusal{status: http.StatusServiceUnavailable, body: `{"code":"unavailable"}`}},
	} {
		broker := newTestBudgetRaiseBroker(t)
		broker.refusal = c.refusal
		_, err := NewComputeBudgetRaiseEffect(newTestBudgetRaiseHost(t, broker), action.Bytes).Run(ctx, effectKey[:])
		if err == nil || errors.Is(err, ErrSidecarEffectNotDone) != c.notDone {
			t.Errorf("%s: %v", c.label, err)
		}
	}
	broker := newTestBudgetRaiseBroker(t)
	broker.dropCount = 1
	if _, err := NewComputeBudgetRaiseEffect(newTestBudgetRaiseHost(t, broker), action.Bytes).Run(ctx, effectKey[:]); err == nil || errors.Is(err, ErrSidecarEffectNotDone) {
		t.Errorf("a lost answer: %v", err)
	}
	// an answer of another approval is the broker's fault, never proof of anything
	other := testBudgetRaiseSpendContext(t, action, NewId())
	broker = newTestBudgetRaiseBroker(t)
	host := newTestBudgetRaiseHost(t, broker)
	if _, err := NewComputeBudgetRaiseEffect(host, action.Bytes).Run(other, effectKey[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := NewComputeBudgetRaiseEffect(host, action.Bytes).Run(ctx, effectKey[:]); !errors.Is(err, ErrComputeBudgetRaiseAnswer) || errors.Is(err, ErrSidecarEffectNotDone) {
		t.Errorf("another approval's answer: %v", err)
	}
	for _, c := range []struct {
		label string
		ctx   context.Context
		key   []byte
	}{
		{label: "no key", ctx: ctx, key: nil},
		{label: "no spend", ctx: context.Background(), key: effectKey[:]},
		{label: "a template's spend", ctx: withApprovalSpend(context.Background(), &ApprovalSpend{ApprovalId: approvalId, Decisions: [][]byte{{1}}, Action: []byte("another")}), key: effectKey[:]},
	} {
		silent := newTestBudgetRaiseBroker(t)
		_, err := NewComputeBudgetRaiseEffect(newTestBudgetRaiseHost(t, silent), action.Bytes).Run(c.ctx, c.key)
		if requests, _ := silent.seen(); !errors.Is(err, ErrSidecarEffectNotDone) || len(requests) != 0 {
			t.Errorf("%s: %v, %d sent", c.label, err, len(requests))
		}
	}
}

// After a restart between the send and the answer, the use's lookup re-presents the same request under its key and
// reads the stored result: done, its reference the one the first presentation would have answered; with the broker
// out it answers uncertain and nothing else.
func TestBudgetRaiseLookupAnswersTheStoredResult(t *testing.T) {
	broker := newTestBudgetRaiseBroker(t)
	broker.dropCount = 1
	agentId, approvalId := NewId(), NewId()
	action := testBudgetRaiseStored(t, agentId, approvalComputeBudgetPeriodDay, 15_000_000_000)
	ctx := testBudgetRaiseSpendContext(t, action, approvalId)
	effectKey := ApprovalEffectKey(approvalId, action.ActionId(approvalId))
	if _, err := NewComputeBudgetRaiseEffect(newTestBudgetRaiseHost(t, broker), action.Bytes).Run(ctx, effectKey[:]); err == nil || errors.Is(err, ErrSidecarEffectNotDone) {
		t.Fatalf("the send whose answer was lost: %v", err)
	}
	// the restarted process: a new client, the lookup alone
	outcome, err := ComputeBudgetRaiseLookup(newTestBudgetRaiseHost(t, broker))(ctx, action.Bytes, effectKey[:])
	if err != nil || outcome.State != ApprovalOutcomeDone {
		t.Fatalf("the lookup: %+v %v", outcome, err)
	}
	stored, _ := proto.MarshalOptions{Deterministic: true}.Marshal(broker.keyAnswers[base64.RawURLEncoding.EncodeToString(effectKey[:])])
	if !bytes.Equal(outcome.EffectRef, stored) {
		t.Error("the lookup's reference is not the stored result")
	}
	requests, keys := broker.seen()
	if len(requests) != 2 || keys[0] != keys[1] || !proto.Equal(requests[0], requests[1]) {
		t.Errorf("the lookup presented another request: %d, %q", len(requests), keys)
	}
	out := newTestBudgetRaiseBroker(t)
	out.refusal = &testBudgetRaiseRefusal{status: http.StatusServiceUnavailable, body: `{"code":"unavailable"}`}
	if outcome, err := ComputeBudgetRaiseLookup(newTestBudgetRaiseHost(t, out))(ctx, action.Bytes, effectKey[:]); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Errorf("with the broker out: %+v %v", outcome, err)
	}
}

// A raise of period run comes back device-only, which the device's run budget takes; kind 21 is a server gate's kind;
// the compute client's effect source gives this effect where its host reaches a broker, none otherwise; and every
// compute Sidecar registers the lookup.
func TestRunRaiseActsOnlyOnTheDevice(t *testing.T) {
	broker := newTestBudgetRaiseBroker(t)
	host := newTestBudgetRaiseHost(t, broker)
	agentId, approvalId := NewId(), NewId()
	action := testBudgetRaiseStored(t, agentId, approvalComputeBudgetPeriodRun, 3_000_000_000)
	effectKey := ApprovalEffectKey(approvalId, action.ActionId(approvalId))
	reference, err := NewComputeBudgetRaiseEffect(host, action.Bytes).Run(testBudgetRaiseSpendContext(t, action, approvalId), effectKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if answer, err := ParseComputeBudgetRaiseReference(reference); err != nil || !answer.GetDeviceOnly() || answer.GetPeriod() != approvalComputeBudgetPeriodRun {
		t.Errorf("a run's raise %+v %v", answer, err)
	}
	if !sidecarActionServerGated(SidecarActionComputeBudgetRaise) {
		t.Error("kind 21 is not a server gate's kind")
	}
	if computeBudgetRaiseEffectSource == nil {
		t.Fatal("no effect source registered")
	}
	if effect := computeBudgetRaiseEffectSource(&ComputeClient{host: &testComputeHost{}}, action); effect != nil {
		t.Errorf("a host with no broker gave an effect %T", effect)
	}
	registered := false
	for _, registration := range sidecarComputeRegistrations {
		registered = registered || registration.name == computeBudgetRaiseComponentName
	}
	if !registered {
		t.Error("the lookup's component is not registered")
	}
}
