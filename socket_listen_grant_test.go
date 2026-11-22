//go:build !sidecar_http && !ios_extension && !js

// A listen's grant-backed action beside the socket component, as MCP's socket_listen asks it on an application name's
// token path (socket_listen_grant.go; §16.6's grant row, QD-772), at §16.6's real gate on the bridge file world's
// sidecar, config log and ACL engine, under the world's run and agent:
//
//   - a standing grant, a document's rule on the token path, passes the listen with nothing filed and nothing posted,
//     its action naming no rule and no expiry;
//   - under a requests rule the listen waits for a person, and asked again later presents the action its request was
//     filed with, though the rule's expiry moved on with the clock; the member's decision then spends into the
//     GrantActivate the approval fixes, done with its grant_id, which the log holds; asked again once the engine holds
//     the grant, the listen passes on it with nothing filed or posted, and priorGrant names that grant;
//   - once that grant is revoked, the listen asked again asks afresh, filing a new request, where the kept action's
//     spent decision would answer done for a grant that no longer stands;
//   - with neither a requests rule nor a standing grant on the name, the listen is refused before the gate, filing
//     nothing.
//
// Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The world's network's K_sock ring from a synthetic key, as a daemon's MCP tool blinds an application name with it.
func testListenGrantRing(t *testing.T, networkId Id) *SocketKeyRing {
	t.Helper()
	ring, err := NewSocketKeyRing(networkId, &protocol.SocketKeyFile{CurrentKey: bytes.Repeat([]byte{0x5a}, socketKeyByteCount)}, DefaultSocketKeyRingSettings())
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// A listen of the world's host on an application name, as MCP's socket_listen asks it: the name's token path under
// the network's current K_sock, the name and the local port beside it, the world's run and agent bound.
type testListenGrantWorld struct {
	*testBridgeFileWorld
	gate      *testGrantGate
	ring      *SocketKeyRing
	grants    *AclGrantFiler
	keeper    *GrantActionKeeper[string]
	name      string
	tokenPath []byte
	grantDst  string
	detail    *SidecarActionDetail
}

func newTestListenGrantWorld(t *testing.T) *testListenGrantWorld {
	t.Helper()
	fileWorld := newTestBridgeFileWorld(t, false)
	world := &testListenGrantWorld{
		testBridgeFileWorld: fileWorld,
		gate:                installTestGrantGate(t, fileWorld),
		ring:                testListenGrantRing(t, fileWorld.net.networkId),
		grants:              NewAclGrantFiler(fileWorld.sidecar, fileWorld.engine),
		keeper:              NewGrantActionKeeper[string](),
		name:                "db/primary",
	}
	world.detail = &SidecarActionDetail{SocketName: world.name, LocalPort: 15432}
	var err error
	if world.tokenPath, err = world.ring.Current().TokenPath(world.name); err != nil {
		t.Fatal(err)
	}
	if world.grantDst, err = SocketListenGrantDst(world.name, world.ring.Current()); err != nil {
		t.Fatal(err)
	}
	// the stock socket component's Lookup answers a listen's use through the grant component's
	t.Cleanup(fileWorld.sidecar.RegisterEffectLookup(SidecarActionListen, world.grants.Lookup))
	return world
}

// A rule on the token path of name: a standing listen rule for the network's members, or a requests rule by which a
// member asks listen and its own member approves; the rule's id.
func (self *testListenGrantWorld) rule(name string, requests bool) []byte {
	self.t.Helper()
	tokenPath, err := self.ring.Current().TokenPath(name)
	if err != nil {
		self.t.Fatal(err)
	}
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()
	targets := []*protocol.AclTarget{{SocketTokens: [][]byte{tokenPath}}}
	listen := []uint32{uint32(protocol.AclAction_ACL_ACTION_LISTEN)}
	ruleId := testConfigId("listen grant " + name).Bytes()
	self.net.withAclRows(func(rows *protocol.AclRows) {
		if requests {
			rows.Requests = append(rows.Requests, &protocol.AclRequestRule{
				RuleId: ruleId, SrcAtoms: [][]byte{member}, Targets: targets, Actions: listen,
				ApproverAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()},
			})
			return
		}
		rows.Rules = append(rows.Rules, &protocol.AclRule{RuleId: ruleId, SrcAtoms: [][]byte{member}, Targets: targets, Actions: listen})
	})
	self.install()
	return ruleId
}

// The listen's action as MCP's tool builds it now, and the answer of §5.4's gate on it.
func (self *testListenGrantWorld) listen() (*SidecarAction, *StoredCanonicalAction, error) {
	self.t.Helper()
	runId, agentId := self.runId, self.agentId
	stored, effect, err := SocketListenGrantAction(self.t.Context(), &SocketListenGrantArgs{
		Grants: self.grants, Subject: self.hostId, GrantDst: self.grantDst, Detail: self.detail, RunId: &runId, AgentId: &agentId,
	}, self.keeper, self.name, self.clock.Now())
	if err != nil {
		return nil, nil, err
	}
	action, err := NewSidecarAction(stored, SidecarRiskNormal, SidecarRiskNormal, &runId, &agentId)
	if err != nil {
		self.t.Fatal(err)
	}
	action.Detail, action.Effect = self.detail, effect
	return action, stored, self.sidecar.Authorize(self.t.Context(), action, nil)
}

// Under a standing grant on the token path the listen passes the gate with nothing filed and nothing posted: its
// action names no rule and no expiry, only the grant's subject, socket and action, and its standing effect runs under
// an empty key to done.
func TestSocketListenGrantActionPassesTheGateOnAStandingGrant(t *testing.T) {
	world := newTestListenGrantWorld(t)
	world.rule(world.name, false)
	action, stored, err := world.listen()
	if err != nil {
		t.Fatalf("a listen under a standing grant: %v", err)
	}
	if action.Outcome == nil || action.Outcome.State != ApprovalOutcomeDone || len(action.Outcome.EffectRef) != 0 {
		t.Errorf("the outcome: %+v", action.Outcome)
	}
	if len(stored.Action.GetRuleId()) != 0 || stored.Action.GetExpiresMillis() != 0 || !slices.Equal(stored.Action.GetGrantDst(), []string{world.grantDst}) ||
		!bytes.Equal(stored.Action.GetSubject(), world.hostId.Bytes()) {
		t.Errorf("the standing listen's action: %+v", stored.Action)
	}
	if world.gate.approvals.filedCount() != 0 || world.api.postCount() != 0 {
		t.Errorf("a standing grant filed %d requests and posted %d statements", world.gate.approvals.filedCount(), world.api.postCount())
	}
}

// Under a requests rule the listen waits, asked again presents its request's action, spends the member's decision into
// its grant, passes on that grant once the engine holds it, and asks afresh once the grant is revoked.
func TestSocketListenGrantActionSpendsAnApprovalAskedAgain(t *testing.T) {
	world := newTestListenGrantWorld(t)
	ruleId := world.rule(world.name, true)
	_, filed, err := world.listen()
	request := world.gate.pendingRequest(t, err)
	if !bytes.Equal(request.Action.Bytes, filed.Bytes) || !bytes.Equal(filed.Action.GetRuleId(), ruleId) ||
		filed.Action.GetExpiresMillis() != world.clock.Now().Add(time.Duration(aclRequestDefaultExpiryMs)*time.Millisecond).UnixMilli() {
		t.Fatalf("the filed action: %+v", filed.Action)
	}
	if request.Request.GetSocketName() != world.name || request.Request.GetLocalPort() != 15432 ||
		!bytes.Equal(request.Request.GetRunId(), world.runId.Bytes()) || !bytes.Equal(request.Request.GetAgentId(), world.agentId.Bytes()) {
		t.Errorf("the request: %+v", request.Request)
	}

	// asked again a minute on, the rule's expiry moved with the clock, and the listen presents its request's action
	world.advance(time.Minute)
	_, again, err := world.listen()
	if pending := world.gate.pendingRequest(t, err); pending.ApprovalId() != request.ApprovalId() || !bytes.Equal(again.Bytes, filed.Bytes) {
		t.Fatalf("the listen asked again filed %s beside %s", pending.ApprovalId(), request.ApprovalId())
	}
	if world.gate.approvals.filedCount() != 1 || world.api.postCount() != 0 {
		t.Fatalf("%d requests filed, %d statements posted", world.gate.approvals.filedCount(), world.api.postCount())
	}

	// the member's decision spends into the grant its approval fixes
	world.gate.approve(t, request, world.laptop, world.member)
	spent, spentStored, err := world.listen()
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())
	if err != nil || spent.Outcome == nil || spent.Outcome.State != ApprovalOutcomeDone || !bytes.Equal(spent.Outcome.EffectRef, grantId[:]) ||
		!bytes.Equal(spentStored.Bytes, filed.Bytes) {
		t.Fatalf("the approved listen: %v, outcome %+v", err, spent.Outcome)
	}
	if types := world.api.postedTypes(t); !slices.Equal(types, []bridge.SignedType{bridge.SignedType_SIGNED_GRANT_ACTIVATE}) {
		t.Fatalf("the spend posted %v", types)
	}
	acl, err := world.net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if decision := acl.MayListen(AclSidecarSubject(world.hostId), AclSocketName{NameToken: world.tokenPath}, world.clock.Now()); !decision.Allowed ||
		!bytes.Equal(decision.Rule.GetRuleId(), grantId[:]) {
		t.Errorf("the log's grant: %+v", decision)
	}

	// the engine holds the grant: the listen passes on it, filing and posting nothing, and priorGrant names it
	world.install()
	standing, _, err := world.listen()
	if err != nil || standing.Outcome == nil || standing.Outcome.State != ApprovalOutcomeDone || world.api.postCount() != 1 || world.gate.approvals.filedCount() != 1 {
		t.Fatalf("the listen on its own grant: %v, outcome %+v", err, standing.Outcome)
	}
	runId, agentId := world.runId, world.agentId
	if prior, stands := world.grants.priorGrant(filed, world.detail, &runId, &agentId, world.clock.Now()); !stands || !bytes.Equal(prior, grantId[:]) {
		t.Errorf("priorGrant: %s, %t", hex.EncodeToString(prior), stands)
	}

	// revoked, the grant no longer stands: the listen asked again asks afresh, where the kept action's spent decision
	// would answer done for it
	if err := world.grants.Revoke(t.Context(), grantId[:], SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	world.install()
	if prior, stands := world.grants.priorGrant(filed, world.detail, &runId, &agentId, world.clock.Now()); stands || !bytes.Equal(prior, grantId[:]) {
		t.Errorf("priorGrant after the revocation: %s, %t", hex.EncodeToString(prior), stands)
	}
	world.advance(time.Minute)
	_, afresh, err := world.listen()
	if pending := world.gate.pendingRequest(t, err); pending.ApprovalId() == request.ApprovalId() || bytes.Equal(afresh.Bytes, filed.Bytes) {
		t.Fatalf("the listen after its grant's revocation presented its spent action: approval %s", pending.ApprovalId())
	}
}

// With no requests rule on the name and no standing grant on it, a standing grant on another name only, the listen is
// refused before the gate, filing nothing and posting nothing; and a filer with no state refuses it too.
func TestSocketListenGrantActionRefusedWhereNoGrantCoversIt(t *testing.T) {
	world := newTestListenGrantWorld(t)
	world.rule("db/replica", false)
	if _, _, err := world.listen(); !errors.Is(err, ErrAclGrantFile) || !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a listen no grant covers: %v", err)
	}
	if world.gate.approvals.filedCount() != 0 || world.api.postCount() != 0 {
		t.Errorf("a refused listen filed %d requests and posted %d statements", world.gate.approvals.filedCount(), world.api.postCount())
	}
	empty := NewAclGrantFiler(world.sidecar, NewAclEngine(world.hostId, nil, nil, nil))
	if _, _, err := SocketListenGrantAction(context.Background(), &SocketListenGrantArgs{Grants: empty, Subject: world.hostId, GrantDst: world.grantDst},
		(*GrantActionKeeper[string])(nil), "", world.clock.Now()); !errors.Is(err, ErrAclGrantFile) {
		t.Errorf("a filer with no state: %v", err)
	}
}
