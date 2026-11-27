//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension && !windows

package sidecar

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// GW-M12-05's retries and joins (DESIGN-COMPUTE §8.5's retries table; §18's "Gateway run binding and retries" row,
// R2-04): what a caller supplies decides whether a request repeats a call, never across run handles; a join or a kept
// answer makes no provider call; and the marks as they stand when a retry comes decide whether it may take the answer.

// A caller of the world's grant whose token is handle's run handle; nil mints an unbound token.
func (self *testGatewayFrontWorld) callerWithHandle(handle *GatewayRunHandle) *GatewayCaller {
	self.t.Helper()
	token, _, err := self.network.grants.Mint(context.Background(), self.grant.GrantId, handle)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.callerOf(token)
}

// Serves one request for caller under ctx, answering what was written once the answer ended or ctx did.
func (self *testGatewayFrontWorld) serveAs(ctx context.Context, caller *GatewayCaller, front gatewayFront, body string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/responses", strings.NewReader(body)).WithContext(ctx)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	self.fronts.serve(recorder, request, caller, front)
	return recorder
}

// Serves a request whose caller leaves once its first delta was written, the call held at turn's stall meanwhile;
// answers once the caller has left.
func (self *testGatewayFrontWorld) serveAndLeave(caller *GatewayCaller, front gatewayFront, body string, headers map[string]string, turn *testGatewayTurn) {
	self.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		self.serveAs(ctx, caller, front, body, headers)
	}()
	select {
	case <-turn.stalled:
	case <-time.After(testGatewayWait):
		self.t.Fatal("the call never stalled")
	}
	guard := time.After(testGatewayWait)
	for delta := false; !delta; {
		select {
		case written := <-self.written:
			delta = strings.Contains(written, `"delta"`) || strings.Contains(written, `"content":"`)
		case <-guard:
			self.t.Fatal("no delta was written")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(testGatewayWait):
		self.t.Fatal("the caller never left")
	}
}

// A turn that stalls after its first delta until released.
func testGatewayStallingTurn(text ...string) *testGatewayTurn {
	return &testGatewayTurn{text: text, stallAfter: 1, release: make(chan struct{}), stalled: make(chan struct{})}
}

// Two sessions of the same grant, two run handles, send the same bytes, each leaving its call before its end: two
// provider calls and charges, each answer its own, nothing of one in the other; for Codex's Responses and a Chat
// Completions harness alike (Claude Code's Messages front is GW-M13-01's).
func TestTwoSessionsSameBytesTwoCalls(t *testing.T) {
	for _, each := range []struct {
		front gatewayFront
		body  string
	}{
		{front: gatewayResponsesFront{}, body: testGatewayCodexBody(true)},
		{front: gatewayChatFront{}, body: testGatewayChatBody(true)},
	} {
		world := newTestGatewayFrontWorld(t, nil)
		sessionA := world.callerWithHandle(&GatewayRunHandle{Process: ProcessIdentity{Pid: 501, StartMillis: 1}})
		sessionB := world.callerWithHandle(&GatewayRunHandle{Process: ProcessIdentity{Pid: 502, StartMillis: 2}})
		turnA := testGatewayStallingTurn("answer A ", "whole")
		turnB := &testGatewayTurn{text: []string{"answer B"}}
		world.router.script(turnA, turnB)
		world.serveAndLeave(sessionA, each.front, each.body, nil, turnA)
		answerB := world.serveAs(context.Background(), sessionB, each.front, each.body, nil)
		close(turnA.release)
		if len(world.router.inferred()) != 2 {
			t.Fatalf("%d provider calls for two sessions", len(world.router.inferred()))
		}
		if strings.Contains(answerB.Body.String(), "answer A") || !strings.Contains(answerB.Body.String(), "answer B") {
			t.Errorf("session B's answer holds A's: %s", answerB.Body.String())
		}
		begins, _, _ := world.recorder.snapshot()
		if len(begins) != 2 || begins[0].ResponseId == begins[1].ResponseId {
			t.Errorf("two calls recorded as %d", len(begins))
		}
	}
}

// A call whose caller left before its end runs on; the same handle's resend of the same bytes joins it, replaying what
// streamed and following it live, with no second provider call or record; once a caller had the answer whole, the same
// bytes again are a new call.
func TestCutCallResendJoinsOnce(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	turn := testGatewayStallingTurn("first ", "second")
	world.router.script(turn, &testGatewayTurn{text: []string{"a new call"}})
	world.serveAndLeave(world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), nil, turn)
	joined := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		joined <- world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	}()
	close(turn.release)
	var answer *httptest.ResponseRecorder
	select {
	case answer = <-joined:
	case <-time.After(testGatewayWait):
		t.Fatal("the join never ended")
	}
	if len(world.router.inferred()) != 1 || !strings.Contains(answer.Body.String(), `"text":"first second"`) {
		t.Fatalf("%d calls; the join's answer: %s", len(world.router.inferred()), answer.Body.String())
	}
	testGatewayOpenResponsesConformance(t, answer.Body.String())
	if begins, _, _ := world.recorder.snapshot(); len(begins) != 1 {
		t.Errorf("a join recorded: %d begins", len(begins))
	}
	again := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	if len(world.router.inferred()) != 2 || !strings.Contains(again.Body.String(), "a new call") {
		t.Errorf("a resend after the whole answer arrived: %d calls, %s", len(world.router.inferred()), again.Body.String())
	}
}

// With an Idempotency-Key the earlier call's operation is answered from its kept answer, even one that arrived whole,
// byte for byte and with no provider call.
func TestIdempotencyKeyReplaysKept(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.router.script(&testGatewayTurn{text: []string{"kept"}, usage: &InferUsage{InputTokens: 1, OutputTokens: 1}})
	key := map[string]string{"Idempotency-Key": "synthetic-operation-1"}
	first := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	second := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	if len(world.router.inferred()) != 1 || first.Body.String() != second.Body.String() {
		t.Errorf("%d calls; the replay differs:\n%s\n%s", len(world.router.inferred()), first.Body.String(), second.Body.String())
	}
	other := world.callerWithHandle(&GatewayRunHandle{Process: ProcessIdentity{Pid: 777, StartMillis: 3}})
	world.router.script(&testGatewayTurn{text: []string{"another handle's"}})
	third := world.serveAs(context.Background(), other, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	if len(world.router.inferred()) != 2 || !strings.Contains(third.Body.String(), "another handle's") {
		t.Errorf("a key across run handles was joined: %s", third.Body.String())
	}
}

// The key reused with another body is refused 422 idempotency_key_reused before any call.
func TestIdempotencyKeyReusedOtherBody422(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.router.script(&testGatewayTurn{text: []string{"one"}})
	key := map[string]string{"Idempotency-Key": "synthetic-operation-2"}
	world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	reused := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(false), key)
	if reused.Code != http.StatusUnprocessableEntity || !strings.Contains(reused.Body.String(), GatewayErrorCodeIdempotencyKeyReused) {
		t.Errorf("%d %s", reused.Code, reused.Body.String())
	}
	if begins, _, _ := world.recorder.snapshot(); len(begins) != 1 || len(world.router.inferred()) != 1 {
		t.Error("the reused key's request was recorded or sent")
	}
	tooLong := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true),
		map[string]string{"Idempotency-Key": strings.Repeat("k", world.settings.IdempotencyKeyByteCount+1)})
	if tooLong.Code != http.StatusBadRequest {
		t.Errorf("a key past its bound: %d", tooLong.Code)
	}
}

// A token pasted at a terminal binds no process: each request is a new call, even one repeating an abandoned call's
// bytes, which also does not run on once its caller left.
func TestPastedTokenEachRequestACall(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	pasted := world.callerWithHandle(nil)
	turn := testGatewayStallingTurn("pasted ", "call")
	world.router.script(turn, &testGatewayTurn{text: []string{"again"}})
	world.serveAndLeave(pasted, gatewayResponsesFront{}, testGatewayCodexBody(true), nil, turn)
	second := world.serveAs(context.Background(), pasted, gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	if len(world.router.inferred()) != 2 || !strings.Contains(second.Body.String(), "again") {
		t.Errorf("%d calls: %s", len(world.router.inferred()), second.Body.String())
	}
}

// R2-04's acceptance: a run's call whose caller left, then a limited_use mark the run took since (its hooks held back
// until after the call began), and the retry of the same bytes is refused service_model by the router's check as the
// marks stand then: it neither joins the call nor takes its answer, and nothing is sent.
func TestMarkedRunNeverReplaysToRefusedModel(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	turn := testGatewayStallingTurn("before ", "the mark")
	world.router.script(turn)
	world.serveAndLeave(world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), nil, turn)
	// the hook that marks the run lands now
	world.router.stateLock.Lock()
	world.router.checkRefusal = &InferError{Code: InferErrorServiceModel, Model: "chutes-kimi-k3-tee-high", Message: "the run read a connected service under limited use"}
	world.router.stateLock.Unlock()
	refused := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	close(turn.release)
	if refused.Code != http.StatusForbidden || !strings.Contains(refused.Body.String(), `"code":"service_model"`) ||
		strings.Contains(refused.Body.String(), "before") {
		t.Errorf("%d %s", refused.Code, refused.Body.String())
	}
	if len(world.router.inferred()) != 1 {
		t.Errorf("%d provider calls", len(world.router.inferred()))
	}
}

// A kept answer is dropped KeptResponseLife after its call ends: the key's retry is then a new call.
func TestKeptAnswerDroppedAfterLife(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	dropped := make(chan struct{}, 8)
	world.fronts.tables.dropped = func() { dropped <- struct{}{} }
	world.router.script(&testGatewayTurn{text: []string{"one"}}, &testGatewayTurn{text: []string{"two"}})
	key := map[string]string{"Idempotency-Key": "synthetic-operation-3"}
	world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	if world.fronts.keptCount() != 1 {
		t.Fatalf("%d kept", world.fronts.keptCount())
	}
	world.clock.advance(world.settings.KeptResponseLife)
	select {
	case <-dropped:
	case <-time.After(testGatewayWait):
		t.Fatal("the kept answer was never dropped")
	}
	if world.fronts.keptCount() != 0 {
		t.Errorf("%d still kept", world.fronts.keptCount())
	}
	later := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	if len(world.router.inferred()) != 2 || !strings.Contains(later.Body.String(), "two") {
		t.Errorf("a retry past the life: %s", later.Body.String())
	}
}
