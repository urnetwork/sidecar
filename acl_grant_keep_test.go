//go:build !sidecar_http && !ios_extension && !js

// A grant's action asked again (acl_grant_keep.go): GrantActionKeeper hands back the action a request was filed with
// while its expiry is ahead and a fresh build differs from it in that expiry alone, gives way once it expires, once
// the fresh one names another rule or asks a shorter grant, once its grant ended, and once its caller forgets it, and
// calls ended with no lock held; the standing effect does nothing under an empty key and proves nothing happened
// under a use's. installTestGrantGate is §16.6's real gate on a bridge file world's sidecar, which the listen, publish
// and share tests of this track run their actions through (socket_listen_grant_test.go, tls_publish_gate_test.go,
// bridge_share_activate_test.go). Synthetic values only.

package sidecar

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// §16.6's real gate on a bridge file world's sidecar, in place of its seam gate: an approval ledger, a run store with
// the world's run in it, untainted, and presence counts on an enrolled instance's store, the approval family's log in
// memory, its P the world's verified state and its standing grants the world's engine.
type testGrantGate struct {
	world     *testBridgeFileWorld
	approvals *testApprovalLog
	ledger    *ApprovalLedger
	inbox     *ApprovalInbox
}

func installTestGrantGate(t *testing.T, world *testBridgeFileWorld) *testGrantGate {
	t.Helper()
	instance, _, _ := enrolledInstance(t)
	localStore := instance.Store(&testNetworkId)
	mcpSettings := defaultSidecarMcpSettings()
	ledger, err := NewApprovalLedger(localStore, mcpSettings, world.clock)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := NewRunStore(localStore, mcpSettings, world.clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := runs.Create(t.Context(), &RunFile{RunId: world.runId, Harness: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	counter, err := NewApprovalPresenceCounts(localStore)
	if err != nil {
		t.Fatal(err)
	}
	gate := &testGrantGate{world: world, approvals: newTestApprovalLog(), ledger: ledger}
	args := &ApprovalArgs{
		SidecarId: world.hostId,
		Ledger:    ledger,
		Approvals: gate.approvals,
		Runs:      &testApprovalRunView{runs: runs},
		States: func() (ApprovalStates, error) {
			return NewConfigApprovalStates(world.net.log.State(), false, nil)
		},
		Counter:  counter,
		Clock:    world.clock,
		Settings: mcpSettings,
		Spend:    DefaultSpendSettings(),
		Log:      NewNoopLogger(),
	}
	if gate.inbox, err = NewApprovalInbox(args); err != nil {
		t.Fatal(err)
	}
	router, err := NewApprovalRouter(args, gate.inbox)
	if err != nil {
		t.Fatal(err)
	}
	approvalGate, err := NewApprovalGate(args, gate.inbox, router, &ApprovalGateArgs{Grants: world.engine, Lookups: world.sidecar.effectLookup})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.sidecar.InstallGate(approvalGate))
	return gate
}

// The request a pending answer names, from the ledger.
func (self *testGrantGate) pendingRequest(t *testing.T, err error) *StoredApprovalRequest {
	t.Helper()
	pending := &ApprovalPendingError{}
	if !errors.As(err, &pending) {
		t.Fatalf("not pending: %v", err)
	}
	state, err := self.ledger.State(pending.ApprovalId)
	if err != nil || state.Request == nil {
		t.Fatalf("no request for %s: %v", pending.ApprovalId, err)
	}
	request, err := ParseStoredApprovalRequest(state.Request)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// approver's approval of request from signer, one of its approval-capable devices, one use: put in the request's log
// and read by the requester's inbox, and answered as it would be handed in.
func (self *testGrantGate) approve(t *testing.T, request *StoredApprovalRequest, signer testConfigDevice, approver Id) []byte {
	t.Helper()
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	body := &protocol.ApprovalDecision{
		ApprovalId:         request.Request.GetApprovalId(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     request.Request.GetNotAfterMillis(),
		ApproverMemberId:   approver.Bytes(),
		Channel:            uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
		RequesterSidecarId: request.Request.GetRequesterSidecarId(),
		AuthPin:            self.world.net.log.State().Pin(),
		Version:            1,
	}
	stored, err := proto.Marshal(testSpendSignedBy(t, signer.sidecarId, signer.key, body))
	if err != nil {
		t.Fatal(err)
	}
	self.approvals.putDecision(request.ApprovalId(), stored)
	if err := self.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	return stored
}

// Moves the world's clock on by d, and the log's time with it, so a statement the sidecar signs then is within the
// log's window at its entry.
func (self *testBridgeFileWorld) advance(d time.Duration) {
	self.clock.advance(d)
	self.net.timeMs = max(self.net.timeMs, self.clock.Now().UnixMilli())
}

// A listen grant's action as a filer fills it: under ruleLabel's rule, expiring at expiresMs.
func testGrantKeepAction(t *testing.T, ruleLabel string, expiresMs int64) *StoredCanonicalAction {
	return buildTestAction(t, &protocol.CanonicalAction{
		Kind: uint32(SidecarActionListen), RuleId: testSocketId(ruleLabel).Bytes()[:aclAtomByteCount],
		Subject: testSocketId("a keeping sidecar").Bytes(), ExpiresMillis: expiresMs,
		GrantDst: []string{"sock:tls/443/blog"}, GrantAllow: []string{"listen"},
	})
}

// The keeper hands back the kept action while its expiry is ahead and a fresh build differs from it in that expiry
// alone, under its own key; a fresh one replaces it once it names another rule, asks a shorter grant, once the kept
// one expired, once ended says its grant ended, and once its caller forgets it; and ended runs with no lock held, so
// it may call back into the keeper.
func TestGrantActionKeeperKeepsTheActionItsRequestWasFiledWith(t *testing.T) {
	keeper := NewGrantActionKeeper[string]()
	now := time.UnixMilli(1762387200000)
	nowMs := now.UnixMilli()
	first := testGrantKeepAction(t, "rule", nowMs+60_000)
	if kept := keeper.Keep("blog", first, now, nil); kept != first {
		t.Fatal("the first action was not kept")
	}
	later := testGrantKeepAction(t, "rule", nowMs+120_000)
	if kept := keeper.Keep("blog", later, now.Add(time.Minute-time.Millisecond), nil); kept != first {
		t.Error("a later build replaced the action its request was filed with")
	}
	if kept := keeper.Keep("shop", later, now, nil); kept != later {
		t.Error("another key took the first key's action")
	}
	if kept := keeper.Keep("blog", testGrantKeepAction(t, "another rule", nowMs+120_000), now, nil); kept == first {
		t.Error("an action naming another rule kept the first")
	}
	keeper.Keep("blog", first, now, nil)
	if kept := keeper.Keep("blog", testGrantKeepAction(t, "rule", nowMs+30_000), now, nil); kept == first {
		t.Error("a grant shorter than the kept one asks kept the longer")
	}
	keeper.Keep("blog", first, now, nil)
	if kept := keeper.Keep("blog", later, now.Add(time.Minute), nil); kept != later {
		t.Error("an expired action was kept")
	}

	// ended, with no lock held: the keeper is free to the callback, and the fresh action takes the kept one's place
	keeper.Keep("blog", first, now, nil)
	endedAsked := 0
	ended := func(kept *StoredCanonicalAction) bool {
		endedAsked += 1
		keeper.Keep("shop", later, now, nil)
		return kept == first
	}
	if kept := keeper.Keep("blog", later, now, ended); kept != later || endedAsked != 1 {
		t.Errorf("a kept action whose grant ended was presented, ended asked %d times", endedAsked)
	}
	if kept := keeper.Keep("blog", later, now, ended); kept != later {
		t.Error("the fresh action did not take the ended one's place")
	}
	keeper.Forget("blog")
	if kept := keeper.Keep("blog", first, now, nil); kept != first {
		t.Error("a forgotten key handed back what it kept")
	}
}

// The standing effect does nothing under a standing grant's empty key and proves nothing happened under a use's; and
// a grant's action no requests rule takes names no rule and no expiry, its grant's fields filled.
func TestAclStandingGrantEffectAndAction(t *testing.T) {
	effect := aclStandingGrantEffect{}
	if ref, err := effect.Run(t.Context(), nil); err != nil || ref != nil {
		t.Errorf("under a standing grant: %v, %v", ref, err)
	}
	if _, err := effect.Run(t.Context(), []byte("an effect key")); !errors.Is(err, ErrSidecarEffectNotDone) {
		t.Errorf("under a use: %v", err)
	}
	subject := testSocketId("a standing subject")
	base := &protocol.CanonicalAction{
		Kind: uint32(SidecarActionPublish), Version: 1, Host: "blog", Port: 443,
		Audience: uint32(protocol.AclAudience_ACL_AUDIENCE_MEMBERS), AppMode: uint32(protocol.AclAppMode_ACL_APP_MODE_HTTP),
	}
	stored, err := aclStandingGrantAction(base, &AclGrantRequest{
		Subject: subject, GrantDst: []string{"dns:blog", "sock:tls/443/blog"}, GrantAllow: []string{"publish", "listen"}, ExpiresMs: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Action.GetRuleId()) != 0 || stored.Action.GetExpiresMillis() != 0 || Id(stored.Action.GetSubject()) != subject ||
		stored.Action.GetHost() != "blog" || len(stored.Action.GetGrantDst()) != 2 || len(stored.Action.GetGrantAllow()) != 2 {
		t.Errorf("the standing action: %+v", stored.Action)
	}
	if len(base.GetSubject()) != 0 {
		t.Error("the standing action's build changed its base")
	}
	if _, err := aclStandingGrantAction(nil, nil); !errors.Is(err, ErrAclGrantFile) {
		t.Errorf("no action: %v", err)
	}
}
