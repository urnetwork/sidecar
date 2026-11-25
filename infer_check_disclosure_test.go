//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Fails unless err is disclosure_required for engy's disclosure at version 2 with reason, and returns it.
func testInferDisclosureRequired(t *testing.T, err error, reason string) *InferError {
	t.Helper()
	refused := testInferErrorOf(t, err, InferErrorDisclosureRequired)
	if refused.DisclosureId != "inference:engy" || refused.DisclosureVersion != 2 || refused.Reason != reason {
		t.Errorf("refused as %+v, want reason %s", refused, reason)
	}
	return refused
}

// Where a person is attached to the run, a none model's call asks them, naming the run, the id and the version, and
// runs once their acknowledgment has landed; "Not now" fails the call declined; an answer whose acknowledgment never
// landed is not taken on its word.
func TestCheckNoneModelAsksWhenAttached(t *testing.T) {
	runId := NewId()
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.asker.attached[runId] = true
		world.asker.answer = func(ask *InferDisclosureAsk) (bool, error) {
			world.acks.acknowledge(ask.DisclosureId, ask.DisclosureVersion)
			return true, nil
		}
	})
	if err := world.infer(t, testInferRunRequest("engy-glm-5.2-off", runId)); err != nil {
		t.Fatal(err)
	}
	asks := world.asker.asked()
	if len(asks) != 1 || asks[0].RunId != runId || asks[0].DisclosureId != "inference:engy" || asks[0].DisclosureVersion != 2 {
		t.Errorf("asked %+v", asks)
	}
	if len(world.direct.called()) != 1 {
		t.Error("the acknowledged call did not run")
	}
	// acknowledged now, so the next call asks nothing
	if err := world.infer(t, testInferRunRequest("engy-glm-5.2-high", runId)); err != nil || len(world.asker.asked()) != 1 {
		t.Errorf("a second call: %v, %d asks", err, len(world.asker.asked()))
	}

	declined := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.asker.attached[runId] = true
		world.asker.answer = func(ask *InferDisclosureAsk) (bool, error) {
			return false, nil
		}
	})
	testInferDisclosureRequired(t, declined.infer(t, testInferRunRequest("engy-glm-5.2-off", runId)), InferDisclosureReasonDeclined)

	unlanded := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.asker.attached[runId] = true
		world.asker.answer = func(ask *InferDisclosureAsk) (bool, error) {
			return true, nil
		}
	})
	testInferDisclosureRequired(t, unlanded.infer(t, testInferRunRequest("engy-glm-5.2-off", runId)), InferDisclosureReasonUnacknowledged)
	if declined.dispatched()+unlanded.dispatched() != 0 {
		t.Error("a call whose disclosure was not acknowledged reached its provider")
	}
}

// A context ended while the person is asked answers canceled, and nothing is sent.
func TestCheckNoneModelAskCanceled(t *testing.T) {
	runId := NewId()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.asker.attached[runId] = true
		world.asker.answer = func(ask *InferDisclosureAsk) (bool, error) {
			cancel()
			return false, ctx.Err()
		}
	})
	_, err := world.router.Infer(ctx, testInferRunRequest("engy-glm-5.2-off", runId))
	testInferErrorOf(t, err, InferErrorCanceled)
	if world.dispatched() != 0 {
		t.Error("a canceled ask dispatched")
	}
}

// A caller no person is attached to gets disclosure_required, naming the id, its version and the fix, before any path
// runs, and no one is asked: a run with no one attached, a call with no run, a gateway call even with a person
// attached to its run, and a router with no asker. A TEE model asks nothing.
func TestCheckNoneModelRefusedUnattended(t *testing.T) {
	attachedRun := NewId()
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.asker.attached[attachedRun] = true
		world.asker.answer = func(ask *InferDisclosureAsk) (bool, error) {
			t.Error("an unattended caller was asked")
			return false, nil
		}
	})
	gateway := testInferRunRequest("engy-glm-5.2-off", attachedRun)
	gateway.Binding = &InferBinding{GrantId: NewId(), Handle: "codex-1"}
	for _, request := range []*InferRequest{
		testInferRunRequest("engy-glm-5.2-off", NewId()),
		testInferRequest("engy-glm-5.2-off", ""),
		gateway,
	} {
		refused := testInferDisclosureRequired(t, world.infer(t, request), InferDisclosureReasonUnacknowledged)
		if !strings.Contains(refused.Message, "ur disclosures ack inference:engy") {
			t.Errorf("the fix is not named: %q", refused.Message)
		}
		testInferErrorOf(t, world.router.Check(context.Background(), request), InferErrorDisclosureRequired)
	}
	noAsker := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.sources.Asker = nil
	})
	testInferDisclosureRequired(t, noAsker.infer(t, testInferRunRequest("engy-glm-5.2-off", attachedRun)), InferDisclosureReasonUnacknowledged)
	if world.dispatched()+noAsker.dispatched() != 0 {
		t.Error("an unacknowledged call reached its provider")
	}
	if err := world.infer(t, testInferRequest("chutes-qwen3.8-27b-tee-high", "")); err != nil {
		t.Errorf("a TEE model with no acknowledgment: %v", err)
	}

	missing := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.policy.policy.Disclosures = world.policy.policy.Disclosures[:2]
	})
	testInferCheckRefusedBy(t, missing, "engy-glm-5.2-off", InferRefusedRuleDisclosure)
}

// The previous version's acknowledgment covers through the current version's grace, measured on the gate's clock from
// the instant the version took effect, and not at its end; a grace of 0 refuses at once; the current version covers
// always; no acknowledgment covers nothing.
func TestCheckPreviousVersionWithinGrace(t *testing.T) {
	cases := []struct {
		acknowledged uint32
		graceDays    uint32
		after        time.Duration
		covered      bool
	}{
		{acknowledged: 1, graceDays: 14, after: 13 * 24 * time.Hour, covered: true},
		{acknowledged: 1, graceDays: 14, after: 14*24*time.Hour - time.Millisecond, covered: true},
		{acknowledged: 1, graceDays: 14, after: 14 * 24 * time.Hour, covered: false},
		{acknowledged: 1, graceDays: 0, after: time.Minute, covered: false},
		{acknowledged: 2, graceDays: 0, after: 400 * 24 * time.Hour, covered: true},
		{acknowledged: 3, graceDays: 14, after: time.Hour, covered: true},
		{acknowledged: 0, graceDays: 14, after: time.Hour, covered: false},
	}
	for _, c := range cases {
		world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
			world.acks.versions["inference:engy"] = c.acknowledged
			world.policy.policy.Disclosures[2].GraceDays = c.graceDays
			world.policy.setNow(testInferDisclosureSince.Add(c.after))
		})
		err := world.infer(t, testInferRequest("engy-glm-5.2-off", ""))
		if c.covered && err != nil {
			t.Errorf("version %d, grace %d, %s after: %v", c.acknowledged, c.graceDays, c.after, err)
		}
		if !c.covered {
			testInferDisclosureRequired(t, err, InferDisclosureReasonUnacknowledged)
		}
	}
}

// The acknowledgments read are the ones the source says cover the caller: on a tagged or cloud sidecar the network's,
// whose fix names --network for an Owner or Admin; in an enclave the sponsor's; and an acknowledgment in that set
// covers the call.
func TestCheckTaggedSidecarUsesNetworkAcknowledgment(t *testing.T) {
	tagged := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.acks.scope = InferAcknowledgmentNetwork
	})
	refused := testInferDisclosureRequired(t, tagged.infer(t, testInferRequest("engy-glm-5.2-off", "")), InferDisclosureReasonUnacknowledged)
	if !strings.Contains(refused.Message, "--network") || !strings.Contains(refused.Message, "Owner or Admin") {
		t.Errorf("a tagged sidecar's fix: %q", refused.Message)
	}
	tagged.acks.acknowledge("inference:engy", 2)
	if err := tagged.infer(t, testInferRequest("engy-glm-5.2-off", "")); err != nil {
		t.Errorf("with the network's acknowledgment: %v", err)
	}

	enclave := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.acks.scope = InferAcknowledgmentSponsor
	})
	refused = testInferDisclosureRequired(t, enclave.infer(t, testInferRequest("engy-glm-5.2-off", "")), InferDisclosureReasonUnacknowledged)
	if !strings.Contains(refused.Message, "sponsor") {
		t.Errorf("an enclave's fix: %q", refused.Message)
	}
	enclave.acks.acknowledge("inference:engy", 2)
	if err := enclave.infer(t, testInferRequest("engy-glm-5.2-off", "")); err != nil {
		t.Errorf("with the sponsor's acknowledgment: %v", err)
	}

	unreadable := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.acks.err = errors.New("the vault is locked")
	})
	testInferCheckRefusedBy(t, unreadable, "engy-glm-5.2-off", InferRefusedRuleSource)
}

// One check covers every way a run reaches a model (§6.4, §18's mail and calendar row): a first pick, a model change,
// a continuation, a fork, an enclave's continuation and a child's launch each reach the router as a call or a Check,
// and each is refused before the acknowledgment and passes after it.
func TestCheckEveryWayARunReachesAModel(t *testing.T) {
	world := newTestInferCheckWorld(t, nil)
	parentRun := NewId()
	childAgent := NewId()
	ways := []struct {
		way     string
		request *InferRequest
		check   bool
	}{
		{way: "a first pick", request: testInferRunRequest("engy-glm-5.2-off", parentRun)},
		{way: "SetModel", request: testInferRunRequest("engy-glm-5.2-high", parentRun), check: true},
		{way: "a continuation", request: testInferRunRequest("engy-glm-5.2-off", NewId())},
		{way: "a fork", request: testInferRunRequest("engy-glm-5.2", NewId())},
		{way: "an enclave's continuation", request: testInferRunRequest("engy-deepseek-v4.1-flash-off", NewId())},
		{way: "a child's launch", request: func() *InferRequest {
			request := testInferRunRequest("engy-glm-5.2-off", NewId())
			request.AgentId = &childAgent
			return request
		}(), check: true},
	}
	reach := func(request *InferRequest, check bool) error {
		if check {
			return world.router.Check(context.Background(), request)
		}
		return world.infer(t, request)
	}
	for _, w := range ways {
		testInferDisclosureRequired(t, reach(w.request, w.check), InferDisclosureReasonUnacknowledged)
	}
	if world.dispatched() != 0 {
		t.Fatal("a call reached its provider before the acknowledgment")
	}
	world.acks.acknowledge("inference:engy", 2)
	for _, w := range ways {
		if err := reach(w.request, w.check); err != nil {
			t.Errorf("%s after the acknowledgment: %v", w.way, err)
		}
	}
}
