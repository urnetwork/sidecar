//go:build !sidecar_http && !ios_extension && !js

// A tls/ or smtp/ listen at §16.6's real gate (§9.10, §16.6's grant row, I-8; QD-772): Sidecar.Listen's action carries
// the grant's fields and the grant component's effect, so ApprovalGate.Authorize takes it, where it once refused every
// listen as an action with no effect. On the bridge file world's sidecar, config log and ACL engine, with the gate
// installed over them and a socket component whose generation authorizes through Sidecar.Authorize:
//
//   - a standing grant, a document's rule, passes a listen no requests rule takes, and one a requests rule takes, with
//     nothing filed and nothing posted, and the listen registers;
//   - with neither a standing grant nor a requests rule, or a standing grant on another name only, the listen is refused,
//     filing nothing and registering nothing;
//   - under a requests rule alone the listen waits for a person, its request naming the rule, the subject, the socket and
//     the expiry the rule gives, with its name and weight beside it, and the same listen asked again later finds that
//     request; the member's decision then spends into the GrantActivate the approval fixes, done with its grant_id, which
//     the log holds and the listen kind's Lookup finds, and the listen registers;
//   - a listen's kept action stands while its expiry is ahead and a fresh build differs from it in that alone, and
//     gives way once it expires, its rule changes or the rule gives a shorter grant;
//   - a use that came to not_done refuses the listen and an uncertain one answers unavailable, nothing registered;
//   - the standing effect does nothing under an empty key and proves nothing happened under a use's;
//   - ActiveGrant judges a listen that names no requests rule on its subject, socket and action alone, and still covers
//     no other kind that names none;
//   - the stock component registers the listen kind's Lookup on its host for its life, and builds a listen's grant on its
//     host's standing follower's engine alone.
//
// Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The bridge file world's sidecar as a tls/ and smtp/ listener behind §16.6's real gate: the world's ACL engine is the
// gate's standing grants and the listen's grant filer, and the approval ledger, run store and log are the gate's.
type testListenGateWorld struct {
	*testBridgeFileWorld
	approvals  *testApprovalLog
	ledgerRows *ApprovalLedger
	inbox      *ApprovalInbox
	service    *testListenService
	component  *SocketComponent
	generation *socketGeneration

	stateLock sync.Mutex
	// each action the generation took to the gate, in order
	asked []*SidecarAction
}

func newTestListenGateWorld(t *testing.T) *testListenGateWorld {
	t.Helper()
	fileWorld := newTestBridgeFileWorld(t, false)
	instance, _, _ := enrolledInstance(t)
	localStore := instance.Store(&testNetworkId)
	mcpSettings := defaultSidecarMcpSettings()
	ledgerRows, err := NewApprovalLedger(localStore, mcpSettings, fileWorld.clock)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := NewRunStore(localStore, mcpSettings, fileWorld.clock)
	if err != nil {
		t.Fatal(err)
	}
	counter, err := NewApprovalPresenceCounts(localStore)
	if err != nil {
		t.Fatal(err)
	}
	world := &testListenGateWorld{testBridgeFileWorld: fileWorld, approvals: newTestApprovalLog(), ledgerRows: ledgerRows}
	args := &ApprovalArgs{
		SidecarId: fileWorld.hostId,
		Ledger:    ledgerRows,
		Approvals: world.approvals,
		Runs:      &testApprovalRunView{runs: runs},
		States: func() (ApprovalStates, error) {
			return NewConfigApprovalStates(fileWorld.net.log.State(), false, nil)
		},
		Counter:  counter,
		Clock:    fileWorld.clock,
		Settings: mcpSettings,
		Spend:    DefaultSpendSettings(),
		Log:      NewNoopLogger(),
	}
	if world.inbox, err = NewApprovalInbox(args); err != nil {
		t.Fatal(err)
	}
	router, err := NewApprovalRouter(args, world.inbox)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := NewApprovalGate(args, world.inbox, router, &ApprovalGateArgs{Grants: fileWorld.engine, Lookups: fileWorld.sidecar.effectLookup})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fileWorld.sidecar.InstallGate(gate))

	signer := newTestSocketSigner("listen gate")
	component, err := NewSocketComponent(t.Context(), &SocketComponentArgs{
		NetworkId: fileWorld.net.networkId,
		Settings:  DefaultSidecarSocketSettings(),
		Sign:      signer.sign,
		Clock:     fileWorld.clock,
		Log:       NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(component.Close)
	world.component = component
	func() {
		component.stateLock.Lock()
		defer component.stateLock.Unlock()
		component.grants = NewAclGrantFiler(fileWorld.sidecar, fileWorld.engine)
	}()
	t.Cleanup(fileWorld.sidecar.RegisterEffectLookup(SidecarActionListen, component.listenLookup))
	if err := component.SetNetworkLabels(&SocketNetworkLabels{Label: "abcdefghij"}); err != nil {
		t.Fatal(err)
	}
	component.SetPolicy(newTestSocketPolicy(5))
	world.generation = &socketGeneration{
		ctx: t.Context(),
		seq: 1,
		identity: &SidecarIdentity{
			NetworkId:         fileWorld.net.networkId,
			SidecarId:         fileWorld.hostId,
			ClientId:          testSocketId("listen gate client"),
			IdentityPublicKey: signer.publicKey(),
		},
		authorize: func(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
			func() {
				world.stateLock.Lock()
				defer world.stateLock.Unlock()
				world.asked = append(world.asked, action)
			}()
			return fileWorld.sidecar.Authorize(ctx, action, decision)
		},
	}
	world.service = &testListenService{
		urnetworkEdge: testSocketId("urnetwork-edge"),
		pages:         make(chan *SocketRegistrationsArgs, 64),
		status:        SocketRegistrationStatusOk,
		serverTime:    fileWorld.clock.Now,
	}
	component.registrar.attach(t.Context(), world.service.registrations, signer.publicKey())
	func() {
		component.stateLock.Lock()
		defer component.stateLock.Unlock()
		component.generation = world.generation
	}()
	return world
}

// A document rule letting the network's members listen on name, a standing grant, installed in the world's engine.
func (self *testListenGateWorld) standing(name string) {
	self.t.Helper()
	self.net.withAclRows(func(rows *protocol.AclRows) {
		rows.Rules = append(rows.Rules, &protocol.AclRule{
			RuleId:   testConfigId("listen gate standing " + name).Bytes(),
			SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:  []*protocol.AclTarget{{PublicName: name}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_LISTEN)},
		})
	})
	self.install()
}

// A requests rule by which members ask listen on name, which the requester's own member approves, installed; its id.
func (self *testListenGateWorld) requests(name string) []byte {
	self.t.Helper()
	ruleId := testConfigId("listen gate requests " + name).Bytes()
	self.net.withAclRows(func(rows *protocol.AclRows) {
		rows.Requests = append(rows.Requests, &protocol.AclRequestRule{
			RuleId:        ruleId,
			SrcAtoms:      [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:       []*protocol.AclTarget{{PublicName: name}},
			Actions:       []uint32{uint32(protocol.AclAction_ACL_ACTION_LISTEN)},
			ApproverAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()},
		})
	})
	self.install()
	return ruleId
}

// Moves the world's clock on by d, and the log's time with it, so a statement the sidecar signs then is within the
// log's window at its entry.
func (self *testListenGateWorld) advance(d time.Duration) {
	self.clock.advance(d)
	self.net.timeMs = max(self.net.timeMs, self.clock.Now().UnixMilli())
}

// A listen on name through the world's component, as Sidecar.Listen runs it.
func (self *testListenGateWorld) listen(name string, settings *SocketListenSettings) (*SocketListener, error) {
	parsed, err := ParseSocketAddress(name)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.component.listen(self.t.Context(), parsed, settings, false)
}

// The last action the gate was asked, its stored action parsed.
func (self *testListenGateWorld) lastAsked() (*SidecarAction, *StoredCanonicalAction) {
	self.t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.asked) == 0 {
		self.t.Fatal("the gate was asked nothing")
	}
	action := self.asked[len(self.asked)-1]
	stored, err := ParseStoredCanonicalAction(action.Canonical)
	if err != nil {
		self.t.Fatal(err)
	}
	return action, stored
}

// How many actions the gate was asked.
func (self *testListenGateWorld) askedCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.asked)
}

// Fails if the component sent the service a page.
func (self *testListenGateWorld) expectNoPage(what string) {
	self.t.Helper()
	select {
	case page := <-self.service.pages:
		self.t.Errorf("%s registered %d entries", what, len(page.Registrations))
	default:
	}
}

// The request a pending answer names, from the ledger.
func (self *testListenGateWorld) pendingRequest(err error) *StoredApprovalRequest {
	self.t.Helper()
	pending := &ApprovalPendingError{}
	if !errors.As(err, &pending) {
		self.t.Fatalf("not pending: %v", err)
	}
	state, err := self.ledgerRows.State(pending.ApprovalId)
	if err != nil || state.Request == nil {
		self.t.Fatalf("no request for %s: %v", pending.ApprovalId, err)
	}
	request, err := ParseStoredApprovalRequest(state.Request)
	if err != nil {
		self.t.Fatal(err)
	}
	return request
}

// The member's approval of request from its consented laptop, one use, put in the request's log and read by the
// requester's inbox.
func (self *testListenGateWorld) approve(request *StoredApprovalRequest) {
	self.t.Helper()
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	body := &protocol.ApprovalDecision{
		ApprovalId:         request.Request.GetApprovalId(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     request.Request.GetNotAfterMillis(),
		ApproverMemberId:   self.member.Bytes(),
		Channel:            uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
		RequesterSidecarId: request.Request.GetRequesterSidecarId(),
		AuthPin:            self.net.log.State().Pin(),
		Version:            1,
	}
	stored, err := proto.Marshal(testSpendSignedBy(self.t, self.laptop.sidecarId, self.laptop.key, body))
	if err != nil {
		self.t.Fatal(err)
	}
	self.approvals.putDecision(request.ApprovalId(), stored)
	if err := self.inbox.Poll(self.t.Context()); err != nil {
		self.t.Fatal(err)
	}
}

// fixture's component given a grant filer over engine, which its tls/ and smtp/ listens build their grants on.
func (self *testListenFixture) useListenGrants(engine *AclEngine) {
	self.component.stateLock.Lock()
	defer self.component.stateLock.Unlock()
	self.component.grants = NewAclGrantFiler(nil, engine)
}

// fixture's component given a grant filer over an ACL state that admits the fixture's own listener as a member's
// device, with what edit adds to its rows; the engine.
func (self *testListenFixture) listenGrantsWith(t testing.TB, edit func(acl *aclTestFixture, listener Id)) *AclEngine {
	t.Helper()
	acl := newAclTestFixture()
	member, _ := acl.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	listener := self.generation.identity.SidecarId
	acl.view.sidecars[listener] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: listener.Bytes(), AdmittedAt: acl.next()}, MemberId: member}
	edit(acl, listener)
	engine := NewAclEngine(listener, nil, nil, nil)
	if err := engine.Install(acl.state(t), nil); err != nil {
		t.Fatal(err)
	}
	self.useListenGrants(engine)
	return engine
}

// Public names' socket targets, as rows carry a tls/ or smtp/ name.
func testListenTargets(names []string) []*protocol.AclTarget {
	targets := []*protocol.AclTarget{}
	for _, name := range names {
		targets = append(targets, &protocol.AclTarget{PublicName: name})
	}
	return targets
}

// fixture's listener asks listen on each of names under a requests rule by which members ask it, which the
// requester's own member approves, and holds no standing grant. The rule's id.
func (self *testListenFixture) grantListensByRequest(t testing.TB, names ...string) []byte {
	t.Helper()
	var ruleId []byte
	self.listenGrantsWith(t, func(acl *aclTestFixture, listener Id) {
		ruleId = acl.requestRule([]Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)}, testListenTargets(names),
			[]protocol.AclAction{protocol.AclAction_ACL_ACTION_LISTEN}, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0)
	})
	return ruleId
}

// fixture's listener holds a standing grant, a document's rule naming it, to listen on each of names, and no requests
// rule takes a listen.
func (self *testListenFixture) grantStandingListens(t testing.TB, names ...string) {
	t.Helper()
	self.listenGrantsWith(t, func(acl *aclTestFixture, listener Id) {
		acl.rule([]Id{acl.sidecarAtom(listener)}, testListenTargets(names), protocol.AclAction_ACL_ACTION_LISTEN)
	})
}

// A listen no requests rule takes passes the gate on a standing grant, a document's rule: its action names the
// subject, the socket and the action and no rule, it carries an effect, the gate files nothing and posts nothing, and
// the listen registers. A requests rule beside the standing grant names its id in the action, and the standing grant
// still passes it with nothing filed.
func TestSocketListenPassesTheGateOnAStandingGrant(t *testing.T) {
	world := newTestListenGateWorld(t)
	world.standing("tls/443/blog")
	listener, err := world.listen("tls/443/blog", nil)
	if err != nil {
		t.Fatalf("a listen under a standing grant: %v", err)
	}
	defer listener.Close()
	action, stored := world.lastAsked()
	if action.Effect == nil || action.Outcome == nil || action.Outcome.State != ApprovalOutcomeDone {
		t.Fatalf("the gate's action: effect %v, outcome %+v", action.Effect, action.Outcome)
	}
	if !slices.Equal(stored.Action.GetGrantDst(), []string{"sock:tls/443/blog"}) || !slices.Equal(stored.Action.GetGrantAllow(), []string{"listen"}) ||
		!bytes.Equal(stored.Action.GetSubject(), world.hostId.Bytes()) || len(stored.Action.GetRuleId()) != 0 || stored.Action.GetExpiresMillis() != 0 {
		t.Errorf("the standing listen's action: %+v", stored.Action)
	}
	if err := CheckCanonicalActionForServer(stored); err != nil {
		t.Errorf("the listen's action on a server path: %v", err)
	}
	if !action.Detail.Equal(&SidecarActionDetail{SocketName: "tls/443/blog", Weight: int32(DefaultSocketFormatSettings().DefaultWeight)}) {
		t.Errorf("the detail: %+v", action.Detail)
	}
	page := testSocketAwait(t, world.service.pages, "the page")
	if registration := page.Registrations[0]; registration.Name != "tls/443/blog" || registration.Protocol != "tls" {
		t.Errorf("the registration %+v", registration)
	}
	if world.approvals.filedCount() != 0 || world.api.postCount() != 0 {
		t.Errorf("a standing grant filed %d requests and posted %d statements", world.approvals.filedCount(), world.api.postCount())
	}

	// a requests rule beside a standing grant: the action names the rule, and the standing grant passes it
	ruleId := world.requests("smtp/25/mx")
	world.standing("smtp/25/mx")
	receiver, err := world.listen("smtp/25/mx", nil)
	if err != nil {
		t.Fatalf("a receiver's listen under a standing grant: %v", err)
	}
	defer receiver.Close()
	action, stored = world.lastAsked()
	if !bytes.Equal(stored.Action.GetRuleId(), ruleId) || stored.Action.GetExpiresMillis() <= world.clock.Now().UnixMilli() ||
		action.Outcome == nil || action.Outcome.State != ApprovalOutcomeDone || len(action.Outcome.EffectRef) != 0 {
		t.Errorf("the receiver's action: %+v, outcome %+v", stored.Action, action.Outcome)
	}
	if world.approvals.filedCount() != 0 || world.api.postCount() != 0 {
		t.Errorf("a standing grant under a requests rule filed %d requests and posted %d statements", world.approvals.filedCount(), world.api.postCount())
	}
}

// With no standing grant and no requests rule a listen is refused before the gate, filing nothing and registering
// nothing, and a standing grant on another name covers none of this one.
func TestSocketListenRefusedWhereNoGrantCoversIt(t *testing.T) {
	world := newTestListenGateWorld(t)
	for _, name := range []string{"tls/443/blog", "smtp/25/mx"} {
		if _, err := world.listen(name, nil); !errors.Is(err, ErrSocketDenied) {
			t.Errorf("%s with no grant: %v", name, err)
		}
	}
	world.standing("tls/443/shop")
	if _, err := world.listen("tls/443/blog", nil); !errors.Is(err, ErrSocketDenied) {
		t.Errorf("a listen under another name's grant: %v", err)
	}
	if world.askedCount() != 0 || world.approvals.filedCount() != 0 || world.api.postCount() != 0 {
		t.Errorf("a refused listen asked the gate %d times, filed %d requests and posted %d statements", world.askedCount(), world.approvals.filedCount(), world.api.postCount())
	}
	world.expectNoPage("a refused listen")
}

// Under a requests rule alone a listen waits for a person: its request names the rule, the subject, the socket and the
// rule's expiry, the name and the weight beside them, and the same listen asked again later finds it. The member's
// decision then spends into the GrantActivate the approval fixes, which the log holds, the use done with its grant_id,
// which the listen kind's Lookup finds; the listen registers, and asked again after it closes it registers again with
// nothing filed.
func TestSocketListenWaitsForADecisionThenActivatesItsGrant(t *testing.T) {
	world := newTestListenGateWorld(t)
	ruleId := world.requests("tls/443/blog")
	settings := &SocketListenSettings{Weight: 250}
	_, err := world.listen("tls/443/blog", settings)
	request := world.pendingRequest(err)
	action := request.Action.Action
	if !bytes.Equal(action.GetRuleId(), ruleId) || !bytes.Equal(action.GetSubject(), world.hostId.Bytes()) ||
		!slices.Equal(action.GetGrantDst(), []string{"sock:tls/443/blog"}) || !slices.Equal(action.GetGrantAllow(), []string{"listen"}) ||
		action.GetExpiresMillis() != world.clock.Now().Add(time.Duration(aclRequestDefaultExpiryMs)*time.Millisecond).UnixMilli() {
		t.Errorf("the request's action: %+v", action)
	}
	if request.Request.GetSocketName() != "tls/443/blog" || request.Request.GetWeight() != 250 ||
		!bytes.Equal(request.Request.GetRequesterSidecarId(), world.hostId.Bytes()) {
		t.Errorf("the request: %+v", request.Request)
	}
	world.expectNoPage("a pending listen")

	// asked again later, the listen presents the action its request was filed with, whose expiry has not moved
	world.advance(time.Minute)
	_, err = world.listen("tls/443/blog", settings)
	if again := world.pendingRequest(err); again.ApprovalId() != request.ApprovalId() {
		t.Fatalf("the listen asked again filed %s beside %s", again.ApprovalId(), request.ApprovalId())
	}
	if filed := world.approvals.filedCount(); filed != 1 {
		t.Errorf("%d requests filed", filed)
	}
	if world.api.postCount() != 0 {
		t.Error("a pending listen posted a statement")
	}

	world.approve(request)
	listener, err := world.listen("tls/443/blog", settings)
	if err != nil {
		asked, _ := world.lastAsked()
		t.Fatalf("the approved listen: %v, outcome %+v, the log's last verdict %+v", err, asked.Outcome, world.net.verdicts[world.net.n])
	}
	spent, stored := world.lastAsked()
	grantId := AclGrantId(request.ApprovalId(), sha256.Sum256(request.Action.Bytes))
	if !bytes.Equal(stored.Bytes, request.Action.Bytes) || spent.Outcome == nil || spent.Outcome.State != ApprovalOutcomeDone ||
		!bytes.Equal(spent.Outcome.EffectRef, grantId[:]) {
		t.Fatalf("the spent listen: outcome %+v", spent.Outcome)
	}
	if types := world.api.postedTypes(t); !slices.Equal(types, []bridge.SignedType{bridge.SignedType_SIGNED_GRANT_ACTIVATE}) {
		t.Errorf("the spend posted %v", types)
	}
	acl, err := world.net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	decision := acl.MayListen(AclSidecarSubject(world.hostId), AclSocketName{PublicName: "tls/443/blog"}, world.clock.Now())
	if !decision.Allowed || !bytes.Equal(decision.Rule.GetRuleId(), grantId[:]) || !bytes.Equal(decision.Rule.GetSourceRuleId(), ruleId) {
		t.Errorf("the log's grant: %+v", decision)
	}
	page := testSocketAwait(t, world.service.pages, "the page")
	if registration := page.Registrations[0]; registration.Name != "tls/443/blog" || registration.Weight != 250 {
		t.Errorf("the registration %+v", registration)
	}

	// the use's Lookup finds the grant once the engine holds it
	world.install()
	ledgerState, err := world.ledgerRows.State(request.ApprovalId())
	if err != nil || len(ledgerState.Reserves) != 1 {
		t.Fatalf("the ledger: %+v, %v", ledgerState, err)
	}
	spendCtx := withApprovalSpend(t.Context(), &ApprovalSpend{ApprovalId: request.ApprovalId(), Action: request.Action.Bytes})
	if outcome, err := world.component.listenLookup(spendCtx, request.Action.Bytes, ledgerState.Reserves[0].EffectKey); err != nil ||
		outcome.State != ApprovalOutcomeDone || !bytes.Equal(outcome.EffectRef, grantId[:]) {
		t.Errorf("the Lookup: %+v, %v", outcome, err)
	}

	// closed and asked again, the listen registers once more and files nothing
	listener.Close()
	again, err := world.listen("tls/443/blog", settings)
	if err != nil {
		t.Fatalf("the listen asked again: %v", err)
	}
	defer again.Close()
	testSocketAwait(t, world.service.pages, "the page again")
	if world.approvals.filedCount() != 1 || world.api.postCount() != 1 {
		t.Errorf("the listen asked again filed %d requests and posted %d statements", world.approvals.filedCount(), world.api.postCount())
	}
}

// A gate whose use of the listen's grant came to not_done refuses the listen, and one that came to uncertain answers
// unavailable, which the same listen asked again completes; neither registers.
func TestSocketListenRefusedWhereItsGrantDidNotActivate(t *testing.T) {
	fixture := newTestListenFixture(t)
	fixture.grantListensByRequest(t, "tls/443/blog")
	for _, c := range []struct {
		state ApprovalOutcomeState
		want  error
	}{
		{state: ApprovalOutcomeNotDone, want: ErrSocketDenied},
		{state: ApprovalOutcomeUncertain, want: ErrSocketUnavailable},
	} {
		fixture.generation.authorize = func(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
			action.Outcome = &SidecarOutcome{State: c.state}
			return nil
		}
		parsed, err := ParseSocketAddress("tls/443/blog")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.component.listen(t.Context(), parsed, nil, false); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.state, err)
		}
	}
	select {
	case page := <-fixture.service.pages:
		t.Errorf("a listen whose grant did not activate registered %+v", page.Registrations)
	default:
	}
}

// The standing effect does nothing under a standing grant's empty key and proves nothing happened under a use's; the
// listen kind's Lookup answers not_done for a listen no requests rule names, uncertain with no grant filer, and the
// filer's answer otherwise.
func TestSocketListenStandingEffectAndLookup(t *testing.T) {
	effect := socketListenStandingEffect{}
	if ref, err := effect.Run(t.Context(), nil); err != nil || ref != nil {
		t.Errorf("under a standing grant: %v, %v", ref, err)
	}
	if _, err := effect.Run(t.Context(), []byte("an effect key")); !errors.Is(err, ErrSidecarEffectNotDone) {
		t.Errorf("under a use: %v", err)
	}

	fixture := newTestListenFixture(t)
	standing := buildTestAction(t, &protocol.CanonicalAction{
		Kind: uint32(SidecarActionListen), Subject: fixture.generation.identity.SidecarId.Bytes(),
		GrantDst: []string{"sock:tls/443/blog"}, GrantAllow: []string{"listen"},
	})
	if outcome, err := fixture.component.listenLookup(t.Context(), standing.Bytes, []byte("an effect key")); err != nil || outcome.State != ApprovalOutcomeNotDone {
		t.Errorf("a listen no requests rule names: %+v, %v", outcome, err)
	}
	requested := buildTestAction(t, &protocol.CanonicalAction{
		Kind: uint32(SidecarActionListen), RuleId: testSocketId("a rule").Bytes()[:aclAtomByteCount], Subject: fixture.generation.identity.SidecarId.Bytes(),
		GrantDst: []string{"sock:tls/443/blog"}, GrantAllow: []string{"listen"},
	})
	if outcome, err := fixture.component.listenLookup(t.Context(), requested.Bytes, []byte("an effect key")); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Errorf("with no grant filer: %+v, %v", outcome, err)
	}
	fixture.grantListensByRequest(t, "tls/443/blog")
	// the filer's own Lookup, which with no spend in ctx cannot name a grant
	if outcome, err := fixture.component.listenLookup(t.Context(), requested.Bytes, []byte("an effect key")); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Errorf("the filer's Lookup with no spend: %+v, %v", outcome, err)
	}
	if _, err := fixture.component.listenLookup(t.Context(), []byte("not an action"), []byte("an effect key")); err == nil {
		t.Error("a canonical that does not parse answered")
	}
}

// A listen's kept action stands while its expiry is ahead and a fresh build differs from it in that expiry alone; a
// fresh one replaces it once it expires, once the fresh one names another rule, and once the rule gives a shorter
// grant than the kept one asks; another weight is another key.
func TestSocketListenKeepsTheActionItsRequestWasFiledWith(t *testing.T) {
	fixture := newTestListenFixture(t)
	component := fixture.component
	nowMs := testSocketNow.UnixMilli()
	action := func(ruleLabel string, expiresMs int64) *StoredCanonicalAction {
		return buildTestAction(t, &protocol.CanonicalAction{
			Kind: uint32(SidecarActionListen), RuleId: testSocketId(ruleLabel).Bytes()[:aclAtomByteCount],
			Subject: fixture.generation.identity.SidecarId.Bytes(), ExpiresMillis: expiresMs,
			GrantDst: []string{"sock:tls/443/blog"}, GrantAllow: []string{"listen"},
		})
	}
	key := socketListenActionKey{name: "tls/443/blog", weight: 100}
	first := action("rule", nowMs+60_000)
	if kept := component.keptListenAction(key, first, testSocketNow); kept != first {
		t.Fatal("the first action was not kept")
	}
	later := action("rule", nowMs+120_000)
	if kept := component.keptListenAction(key, later, testSocketNow.Add(time.Minute-time.Millisecond)); kept != first {
		t.Error("a later build replaced the action its request was filed with")
	}
	if kept := component.keptListenAction(socketListenActionKey{name: "tls/443/blog", weight: 250}, later, testSocketNow); kept != later {
		t.Error("another weight took the first weight's action")
	}
	if kept := component.keptListenAction(key, action("another rule", nowMs+120_000), testSocketNow); kept == first {
		t.Error("an action naming another rule kept the first")
	}
	component.keptListenAction(key, first, testSocketNow)
	shorter := action("rule", nowMs+30_000)
	if kept := component.keptListenAction(key, shorter, testSocketNow); kept != shorter {
		t.Error("a grant shorter than the kept one asks kept the longer")
	}
	// the kept one, shorter, has expired a minute on, and the fresh one takes its place
	if kept := component.keptListenAction(key, later, testSocketNow.Add(time.Minute)); kept != later {
		t.Error("an expired action was kept")
	}
	func() {
		component.stateLock.Lock()
		defer component.stateLock.Unlock()
		for keptKey, kept := range component.listenActions {
			if kept.Action.GetExpiresMillis() <= nowMs+60_000 {
				t.Errorf("an expired action under %+v outlived its expiry", keptKey)
			}
		}
	}()
}

// ActiveGrant judges a listen that names no requests rule on its subject, socket and action alone: a standing rule
// covers its own subject's, and no other spender's, no other socket's and no other action's; and it still covers no
// publish that names none, nor a listen naming a rule_id of the wrong size.
func TestAclActiveGrantReadsAListenWithNoRequestsRule(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	fixture.rule([]Id{fixture.sidecarAtom(cast.laptop)}, []*protocol.AclTarget{{PublicName: "tls/443/blog"}, {PublicName: "blog"}},
		protocol.AclAction_ACL_ACTION_LISTEN, protocol.AclAction_ACL_ACTION_PUBLISH)
	engine := NewAclEngine(cast.laptop, nil, nil, nil)
	if err := engine.Install(fixture.state(t), nil); err != nil {
		t.Fatal(err)
	}
	listen := func(subject Id, grantDst string, allow string, ruleId []byte) *StoredCanonicalAction {
		return buildTestAction(t, &protocol.CanonicalAction{
			Kind: uint32(SidecarActionListen), RuleId: ruleId, Subject: subject.Bytes(), GrantDst: []string{grantDst}, GrantAllow: []string{allow},
		})
	}
	for _, c := range []struct {
		name    string
		action  *StoredCanonicalAction
		spender Id
		active  bool
	}{
		{name: "its subject's listen", action: listen(cast.laptop, "sock:tls/443/blog", "listen", nil), spender: cast.laptop, active: true},
		{name: "another spender presenting it", action: listen(cast.laptop, "sock:tls/443/blog", "listen", nil), spender: cast.phone},
		{name: "a stranger's listen", action: listen(cast.stranger, "sock:tls/443/blog", "listen", nil), spender: cast.stranger},
		{name: "another socket", action: listen(cast.laptop, "sock:tls/443/shop", "listen", nil), spender: cast.laptop},
		{name: "a dial on the socket", action: listen(cast.laptop, "sock:tls/443/blog", "dial", nil), spender: cast.laptop},
	} {
		if active := engine.ActiveGrant(c.action, c.spender, aclTestNow); active != c.active {
			t.Errorf("%s: active %t", c.name, active)
		}
	}
	// a rule_id of the wrong size is no listen's rule, so the parse refuses it
	wrongSize := &StoredCanonicalAction{Action: &protocol.CanonicalAction{
		Kind: uint32(SidecarActionListen), RuleId: []byte{1, 2, 3}, Subject: cast.laptop.Bytes(),
		GrantDst: []string{"sock:tls/443/blog"}, GrantAllow: []string{"listen"},
	}}
	if engine.ActiveGrant(wrongSize, cast.laptop, aclTestNow) {
		t.Error("a listen with a rule_id of the wrong size was covered")
	}
	// a publish that names no requests rule is still covered by nothing
	publish := buildTestAction(t, &protocol.CanonicalAction{
		Kind: uint32(SidecarActionPublish), Host: "blog", Port: 443,
		Audience: uint32(protocol.AclAudience_ACL_AUDIENCE_MEMBERS), AppMode: uint32(protocol.AclAppMode_ACL_APP_MODE_HTTP),
		Subject: cast.laptop.Bytes(), GrantDst: []string{"dns:blog", "sock:tls/443/blog"}, GrantAllow: []string{"publish", "listen"},
	})
	if engine.ActiveGrant(publish, cast.laptop, aclTestNow) {
		t.Error("a publish that names no requests rule was covered")
	}
}

// The stock component registers the listen kind's Lookup on its host for its life, and Close takes it off; it builds a
// listen's grant on its host's standing follower's engine, and on none while the follower does not stand.
func TestSocketComponentRegistersTheListenLookup(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	running := world.sidecar
	networkId := world.net.networkId
	running.networkId = &networkId
	client := &ConfigClient{args: &ConfigClientArgs{NetworkId: networkId}}
	client.configLog.Store(world.net.log)
	follower := &SidecarConfigFollower{client: client, state: NewMonitorValue(SidecarConfigFollowerStanding), aclEngine: world.engine}
	running.configFollower.Store(follower)
	if running.effectLookup(SidecarActionListen) != nil {
		t.Fatal("a listen Lookup before any socket component")
	}
	component, err := running.NewSocketComponent(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if running.effectLookup(SidecarActionListen) == nil {
		component.Close()
		t.Fatal("the stock component registered no listen Lookup")
	}
	if grants := component.listenGrantFiler(); grants == nil || grants.engine != world.engine || grants.sidecar != running {
		t.Errorf("the stock grant filer: %+v", grants)
	}
	// a follower that no longer stands lends no engine
	follower.state.Set(SidecarConfigFollowerAnchoring)
	if grants := component.listenGrantFiler(); grants != nil {
		t.Errorf("a grant filer from a follower that does not stand: %+v", grants)
	}
	component.Close()
	if running.effectLookup(SidecarActionListen) != nil {
		t.Error("the listen Lookup outlived its component")
	}
}
