//go:build !ios_extension

// QD-772, a socket_listen's name in the sealed ApprovalRequest: a listen's action names its socket by one grant_dst
// entry alone, in the form a server may see, and passes every server path, its grant activating at a GrantActivate and
// taking effect, for a tls/ name and for an application name's token path; an action that still sets field 23 is
// refused by every parser, the builder and a GrantActivate; a listen's request carries the name, which the parse holds
// to the action's grant_dst as far as no key is needed and an approver's device under its K_sock ring before it
// approves, a request whose name disagrees, or that the device could not read, listing deny alone and signing no
// approval; and the spend binds the name the approver saw. On the approver world of record_approval_decide_test.go,
// the approval world of record_approval_state_test.go and ACL's statement cast. Synthetic values only.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The network a test's socket names are blinded in.
func testListenNetworkId() Id {
	return testConfigId("listen network")
}

// A network's K_sock ring from a synthetic key of keyByte, and a previous key of previousByte while a rotation's
// overlap holds one, 0 for none.
func testListenSocketRing(t *testing.T, keyByte byte, previousByte byte) *SocketKeyRing {
	t.Helper()
	file := &protocol.SocketKeyFile{CurrentKey: bytes.Repeat([]byte{keyByte}, socketKeyByteCount)}
	if previousByte != 0 {
		file.PreviousKey = bytes.Repeat([]byte{previousByte}, socketKeyByteCount)
		file.RotatedAtMs = 1762387200000
	}
	ring, err := NewSocketKeyRing(testListenNetworkId(), file, DefaultSocketKeyRingSettings())
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// The grant_dst a listen on name carries under keys (SocketListenGrantDst), which must answer.
func testListenGrantDst(t *testing.T, name string, keys *SocketKeys) string {
	t.Helper()
	grantDst, err := SocketListenGrantDst(name, keys)
	if err != nil {
		t.Fatal(err)
	}
	return grantDst
}

// A listen's action as a daemon builds it outside a grant: its socket named by grantDst alone.
func testListenAction(t *testing.T, grantDst string) *StoredCanonicalAction {
	t.Helper()
	return buildTestAction(t, &protocol.CanonicalAction{Kind: uint32(SidecarActionListen), GrantDst: []string{grantDst}})
}

// An approver's K_sock ring as a test hands it, nil holding none.
type testListenSocketKeys struct {
	ring *SocketKeyRing
}

func (self testListenSocketKeys) SocketKeyRing() *SocketKeyRing {
	return self.ring
}

// A listen's action names its socket as a server may see it and nothing more: a tls/ or smtp/ name in full, an
// application name by its token path under the network's current K_sock, never its text, and no name the action's
// form cannot hold. The builder takes no listen that names no socket, a template's included, and a server path takes
// every listen it builds.
func TestListenActionNamesItsSocketByGrantDstAlone(t *testing.T) {
	ring := testListenSocketRing(t, 0x61, 0)
	for name, want := range map[string]string{"tls/443/blog": "sock:tls/443/blog", "smtp/25/mx": "sock:smtp/25/mx"} {
		if grantDst, err := SocketListenGrantDst(name, nil); err != nil || grantDst != want {
			t.Errorf("%s: %q, %v", name, grantDst, err)
		}
	}
	tokenPath, err := ring.Current().TokenPath("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	grantDst := testListenGrantDst(t, "db/primary", ring.Current())
	if grantDst != "sock:"+hex.EncodeToString(tokenPath) || strings.Contains(grantDst, "primary") {
		t.Errorf("an application name's grant_dst: %q", grantDst)
	}
	if _, err := SocketListenGrantDst("db/primary", nil); !errors.Is(err, ErrSocketListenName) {
		t.Errorf("an application name with no K_sock: %v", err)
	}
	for _, name := range []string{"DB/Primary", "Tls/443/blog", "ur/smtpedge", "share/abcdefghijklmnopqrstuvwxyz", "c/x", "", "db//x"} {
		if _, err := SocketListenGrantDst(name, ring.Current()); !errors.Is(err, ErrSocketListenName) {
			t.Errorf("%q answered %v", name, err)
		}
	}

	if _, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionListen), ExpiresMillis: 1762387200000}); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a listen naming no socket: %v", err)
	}
	if _, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionListen), Scope: true}); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a template of every listen: %v", err)
	}
	for _, grantDst := range []string{"sock:tls/443/blog", grantDst} {
		stored := testListenAction(t, grantDst)
		if err := CheckCanonicalActionForServer(stored); err != nil {
			t.Errorf("%s on a server path: %v", grantDst, err)
		}
		template := buildTestAction(t, &protocol.CanonicalAction{Kind: uint32(SidecarActionListen), Scope: true, GrantDst: []string{grantDst}})
		if !ActionMatchesTemplate(template, stored) {
			t.Errorf("%s: a listen does not match its socket's template", grantDst)
		}
		if ActionMatchesTemplate(template, testListenAction(t, "sock:tls/443/other")) {
			t.Errorf("%s: another socket's listen matches its template", grantDst)
		}
	}
}

// A socket_listen action that still sets field 23, the name's old place, as another build's bytes would: every parser
// refuses a field this build cannot name, the builder takes none, a server path's column refuses it unparsed too, and
// a request carrying such an action is refused with it. (A GrantActivate carrying one:
// TestListenGrantActivatesOnTheServerPath.)
func TestListenActionWithItsOldNameFieldRefused(t *testing.T) {
	old := &protocol.CanonicalAction{Kind: uint32(SidecarActionListen), Version: 1, GrantDst: []string{"sock:tls/443/blog"}}
	testRecordSetUnknownString(old, 23, "tls/443/blog")
	oldBytes := testRecordStored(t, old)
	if _, err := ParseStoredCanonicalAction(oldBytes); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a listen's action with field 23: %v", err)
	}
	if _, err := NewCanonicalAction(old); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a listen built with field 23: %v", err)
	}
	// a server path holds the action to its column even where no parse came first
	if err := CheckCanonicalActionForServer(&StoredCanonicalAction{Action: old, Bytes: oldBytes}); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("an unparsed listen with field 23 on a server path: %v", err)
	}
	// a request carrying it, its hashes over those bytes, is refused for its action
	world := newTestApproverWorld(t)
	request := &protocol.ApprovalRequest{}
	if err := proto.Unmarshal(world.storedRequest(world.requesterId, testListenAction(t, "sock:tls/443/blog"), &SidecarActionDetail{SocketName: "tls/443/blog"}), request); err != nil {
		t.Fatal(err)
	}
	payloadSha256 := ApprovalPayloadSha256(oldBytes)
	actionId := ApprovalActionId(recordIdOf(request.GetApprovalId()), oldBytes)
	request.CanonicalAction, request.PayloadSha256, request.ActionId = oldBytes, payloadSha256[:], actionId[:]
	if _, err := ParseStoredApprovalRequest(testRecordStored(t, request)); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a request whose action sets field 23: %v", err)
	}
}

// A listen's grant activates on the server path (QD-772): its action, built as a daemon builds it with the grant's
// fields alone, passes CheckCanonicalActionForServer and every reader's GrantActivate check, folds to a rule that lets
// its subject listen on that socket, a tls/ name by the name and an application name by its token path, and the same
// action with its name still at field 23 is refused there.
func TestListenGrantActivatesOnTheServerPath(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	self := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)
	listen := []protocol.AclAction{protocol.AclAction_ACL_ACTION_LISTEN}
	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	ring := testListenSocketRing(t, 0x61, 0)
	tokenPath, err := ring.Current().TokenPath("db/primary")
	if err != nil {
		t.Fatal(err)
	}
	tlsRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{{PublicName: "tls/443/blog"}}, listen, []Id{self}, 0)
	appRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{{SocketTokens: [][]byte{tokenPath}}}, listen, []Id{self}, 0)
	spend := &aclTestSpendCheck{}
	for _, c := range []struct {
		name     string
		ruleId   []byte
		grantDst string
		socket   AclSocketName
	}{
		{name: "a tls/ name", ruleId: tlsRule, grantDst: "sock:tls/443/blog", socket: AclSocketName{PublicName: "tls/443/blog"}},
		{name: "an application name", ruleId: appRule, grantDst: testListenGrantDst(t, "db/primary", ring.Current()), socket: AclSocketName{NameToken: tokenPath}},
	} {
		state := fixture.state(t)
		stored := buildTestAction(t, &protocol.CanonicalAction{
			Kind: uint32(SidecarActionListen), RuleId: c.ruleId, Subject: cast.laptop.Bytes(),
			GrantDst: []string{c.grantDst}, GrantAllow: []string{"listen"},
		})
		if err := CheckCanonicalActionForServer(stored); err != nil {
			t.Fatalf("%s: the listen's action on a server path: %v", c.name, err)
		}
		if state.MayListen(AclSidecarSubject(cast.laptop), c.socket, aclTestNow).Allowed {
			t.Fatalf("%s: listens before its grant", c.name)
		}

		// the old shape, its name still at field 23, is refused by every reader's check
		old := proto.Clone(stored.Action).(*protocol.CanonicalAction)
		testRecordSetUnknownString(old, 23, "tls/443/blog")
		oldGrant := newAclTestGrantOf(testRecordStored(t, old), cast.laptop).approve(t, cast.member, device, aclTestDecisionNotAfter)
		_, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, oldGrant.activate(), cast.laptop), spend)
		if !errors.Is(err, ErrConfigRule) || !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("%s: a GrantActivate whose listen sets field 23: %v", c.name, err)
		}

		grant := newAclTestGrantOf(stored.Bytes, cast.laptop).approve(t, cast.member, device, aclTestDecisionNotAfter)
		activate := grant.activate()
		statement := fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate, cast.laptop)
		verdict, err := state.CheckStatement(statement, spend)
		if err != nil {
			t.Fatalf("%s: the listen's GrantActivate: %v", c.name, err)
		}
		rows, _, err := state.ApplyStatement(statement, verdict)
		if err != nil {
			t.Fatal(err)
		}
		fixture.rows = rows
		decision := fixture.state(t).MayListen(AclSidecarSubject(cast.laptop), c.socket, aclTestNow)
		if !decision.Allowed || !bytes.Equal(decision.Rule.GetRuleId(), activate.GetGrantId()) || !bytes.Equal(decision.Rule.GetSourceRuleId(), c.ruleId) {
			t.Errorf("%s: the activated grant: %+v", c.name, decision)
		}
		if c.socket.NameToken != nil && bytes.Contains(activate.GetCanonicalAction(), []byte("primary")) {
			t.Errorf("%s: the GrantActivate shows the application name", c.name)
		}
	}
}

// The parse holds a listen's request to what needs no key (QD-772): it names its socket, in its one form, in a
// namespace a listen's action names, and that name agrees with the action's one grant_dst entry, a tls/ or smtp/ name
// in full and an application name by a token path of its segments' length; no other kind's request names a socket. An
// application name whose token path is another name's of that length parses: only K_sock tells them apart, which is
// the approver's to hold.
func TestListenRequestBindsItsName(t *testing.T) {
	world := newTestApproverWorld(t)
	ring := testListenSocketRing(t, 0x61, 0)
	appDst := testListenGrantDst(t, "db/primary", ring.Current())
	oneSegmentDst := testListenGrantDst(t, "db", ring.Current())
	tlsAction := testListenAction(t, "sock:tls/443/blog")
	appAction := testListenAction(t, appDst)
	parses := []struct {
		name   string
		action *StoredCanonicalAction
		detail *SidecarActionDetail
	}{
		{name: "a tls/ name", action: tlsAction, detail: &SidecarActionDetail{SocketName: "tls/443/blog", Weight: 100}},
		{name: "an smtp/ name", action: testListenAction(t, "sock:smtp/25/mx"), detail: &SidecarActionDetail{SocketName: "smtp/25/mx"}},
		{name: "an application name", action: appAction, detail: &SidecarActionDetail{SocketName: "db/primary", LocalPort: 15432}},
		{name: "another name's token path of its length", action: testListenAction(t, testListenGrantDst(t, "db/replica", ring.Current())), detail: &SidecarActionDetail{SocketName: "db/primary"}},
	}
	for _, c := range parses {
		request, err := ParseStoredApprovalRequest(world.storedRequest(world.requesterId, c.action, c.detail))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		} else if !request.Detail().Equal(c.detail) {
			t.Errorf("%s: the request's detail %+v", c.name, request.Detail())
		}
	}
	refusals := []struct {
		name    string
		action  *StoredCanonicalAction
		detail  *SidecarActionDetail
		pointed bool
	}{
		{name: "a listen naming no socket", action: tlsAction, detail: &SidecarActionDetail{Weight: 100}},
		{name: "a publish naming a socket", action: buildTestAction(t, testBuildableActions()["tls_publish"]), detail: &SidecarActionDetail{SocketName: "tls/443/blog"}},
		{name: "a name in capitals", action: tlsAction, detail: &SidecarActionDetail{SocketName: "TLS/443/blog"}, pointed: true},
		{name: "a platform name", action: testListenAction(t, "sock:ur/smtpedge"), detail: &SidecarActionDetail{SocketName: "ur/smtpedge"}, pointed: true},
		{name: "a share name", action: appAction, detail: &SidecarActionDetail{SocketName: "share/abcdefghijklmnopqrstuvwxyz"}, pointed: true},
		{name: "a reserved name", action: appAction, detail: &SidecarActionDetail{SocketName: "c/x"}, pointed: true},
		{name: "another tls/ name", action: tlsAction, detail: &SidecarActionDetail{SocketName: "tls/443/shop"}, pointed: true},
		{name: "a tls/ name beside a token path", action: appAction, detail: &SidecarActionDetail{SocketName: "tls/443/blog"}, pointed: true},
		{name: "an application name beside a public name", action: tlsAction, detail: &SidecarActionDetail{SocketName: "db/primary"}, pointed: true},
		{name: "an application name beside a shorter token path", action: testListenAction(t, oneSegmentDst), detail: &SidecarActionDetail{SocketName: "db/primary"}, pointed: true},
		{name: "a token path in capitals", action: testListenAction(t, "sock:"+strings.ToUpper(strings.TrimPrefix(appDst, "sock:"))), detail: &SidecarActionDetail{SocketName: "db/primary"}, pointed: true},
		{name: "a grant_dst naming no socket", action: testListenAction(t, "dns:blog.example"), detail: &SidecarActionDetail{SocketName: "tls/443/blog"}, pointed: true},
		{name: "two destinations", action: buildTestAction(t, &protocol.CanonicalAction{
			Kind: uint32(SidecarActionListen), GrantDst: []string{"sock:tls/443/blog", "sock:tls/443/shop"},
		}), detail: &SidecarActionDetail{SocketName: "tls/443/blog"}, pointed: true},
	}
	for _, c := range refusals {
		_, err := ParseStoredApprovalRequest(world.storedRequest(world.requesterId, c.action, c.detail))
		if !errors.Is(err, ErrRecordStoredInvalid) || c.pointed != errors.Is(err, ErrSocketListenName) {
			t.Errorf("%s answered %v", c.name, err)
		}
		// the refusal names no socket, since a log may carry it (I-13)
		if err != nil && (strings.Contains(err.Error(), "blog") || strings.Contains(err.Error(), "primary")) {
			t.Errorf("%s: the refusal names the socket: %v", c.name, err)
		}
	}
}

// An approver's device reads a listen's name against its action's grant_dst before it approves (QD-772): the render
// shows the name from the opened request; an application name whose token path under the device's K_sock ring is the
// grant_dst's, the current key's or, through a rotation's overlap, the previous one's, takes an approval; one whose
// grant_dst is another name's token path, or that the device holds no ring to derive, renders so, lists deny alone,
// and signs no approval, a denial still signed; and a tls/ name needs no key.
func TestListenNameIsReadByTheApprover(t *testing.T) {
	ring := testListenSocketRing(t, 0x61, 0)
	rotated := testListenSocketRing(t, 0x62, 0x61)
	otherNetwork, err := NewSocketKeyRing(testConfigId("another network"), &protocol.SocketKeyFile{CurrentKey: bytes.Repeat([]byte{0x61}, socketKeyByteCount)}, DefaultSocketKeyRingSettings())
	if err != nil {
		t.Fatal(err)
	}
	appAction := testListenAction(t, testListenGrantDst(t, "db/primary", ring.Current()))
	replicaAction := testListenAction(t, testListenGrantDst(t, "db/replica", ring.Current()))
	appDetail := &SidecarActionDetail{SocketName: "db/primary", LocalPort: 15432}
	for _, c := range []struct {
		name    string
		keys    ApprovalSocketKeys
		action  *StoredCanonicalAction
		detail  *SidecarActionDetail
		agrees  bool
		setKeys bool
	}{
		{name: "an application name under the device's key", keys: testListenSocketKeys{ring: ring}, setKeys: true, action: appAction, detail: appDetail, agrees: true},
		{name: "built under the previous key through a rotation's overlap", keys: testListenSocketKeys{ring: rotated}, setKeys: true, action: appAction, detail: appDetail, agrees: true},
		{name: "a tls/ name on a device with no ring", setKeys: true, action: testListenAction(t, "sock:tls/443/blog"), detail: &SidecarActionDetail{SocketName: "tls/443/blog", Weight: 100}, agrees: true},
		{name: "another name's token path", keys: testListenSocketKeys{ring: ring}, setKeys: true, action: replicaAction, detail: appDetail},
		{name: "a ring of another network", keys: testListenSocketKeys{ring: otherNetwork}, setKeys: true, action: appAction, detail: appDetail},
		{name: "a ring past the key it was built under", keys: testListenSocketKeys{ring: testListenSocketRing(t, 0x62, 0)}, setKeys: true, action: appAction, detail: appDetail},
		{name: "a device that holds no ring", keys: testListenSocketKeys{}, setKeys: true, action: appAction, detail: appDetail},
		{name: "a device with no reader", setKeys: true, action: appAction, detail: appDetail},
		// the world's own sidecar, whose sockets hold no ring, or which runs none
		{name: "the device's own sidecar", action: appAction, detail: appDetail},
	} {
		world := newTestApproverWorld(t)
		if c.setKeys {
			world.approver = world.approver.WithSocketKeys(c.keys)
		}
		request := world.putDetail(world.requesterId, c.action, c.detail)
		item := world.item(request.ApprovalId())
		if value, ok := testRenderField(item.Render, "socket_name"); !ok || value != c.detail.SocketName {
			t.Errorf("%s: socket_name renders %q (%t)", c.name, value, ok)
		}
		if c.agrees {
			if item.Render.NameUnread || len(item.Decisions) != 2 || strings.Contains(item.Render.Text(), "does not read") {
				t.Errorf("%s: the item %+v:\n%s", c.name, item, item.Render.Text())
			}
			if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); err != nil {
				t.Errorf("%s: an approval: %v", c.name, err)
			} else if decision := world.lastDecision(); !decision.Binds(request) ||
				decision.Decision.GetDecision() != uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE) {
				t.Errorf("%s: the decision %+v", c.name, decision.Decision)
			}
			continue
		}
		if !item.Render.NameUnread || !slices.Equal(item.Decisions, []string{SidecarDecisionDeny}) ||
			!strings.Contains(item.Render.Text(), "socket_name: it does not read as the action's grant_dst") {
			t.Errorf("%s: the item %+v:\n%s", c.name, item, item.Render.Text())
		}
		err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil)
		if !errors.Is(err, ErrApprovalListenName) || world.decisionCount() != 0 {
			t.Errorf("%s: an approval answered %v, %d filed", c.name, err, world.decisionCount())
		}
		if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionDeny}, SidecarActConfirmed, nil); err != nil {
			t.Errorf("%s: a denial: %v", c.name, err)
		} else if denial := world.lastDecision(); denial.Decision.GetDecision() != uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY) {
			t.Errorf("%s: the denial %+v", c.name, denial.Decision)
		}
	}
	// the reader carries through the detail opener's copy, and the opener through the reader's
	world := newTestApproverWorld(t)
	world.approver = world.approver.WithSocketKeys(testListenSocketKeys{ring: ring}).WithDetailOpener(newTestActionDetailOpener(testActionDetailGeneration))
	request := world.putDetail(world.requesterId, appAction, appDetail)
	if item := world.item(request.ApprovalId()); item.Render.NameUnread || len(item.Decisions) != 2 {
		t.Errorf("the reader after WithDetailOpener: %+v", item)
	}
}

// The spend binds the name the approver saw (QD-772): a listen's request is filed with its socket_name, the same ask
// finds it again and another name's ask files its own, a request whose name disagrees with its action's grant_dst is
// never filed, a decision on it spends nothing on another name or weight, and the effect sees the name it approved.
func TestListenSpendBindsItsName(t *testing.T) {
	world := newTestApprovalWorld(t)
	world.lookups[SidecarActionListen] = world.effect.lookup
	blog := testListenAction(t, "sock:tls/443/blog")
	asked := func(action *StoredCanonicalAction, name string, weight int32) *SidecarAction {
		sidecarAction := world.action(action)
		sidecarAction.Detail = &SidecarActionDetail{SocketName: name, Weight: weight}
		return sidecarAction
	}
	request := world.pendingRequest(world.gate.Authorize(t.Context(), asked(blog, "tls/443/blog", 100), nil))
	if request.Request.GetSocketName() != "tls/443/blog" || request.Request.GetWeight() != 100 || !bytes.Equal(request.Action.Bytes, blog.Bytes) {
		t.Fatalf("the request: %+v", request.Request)
	}
	if again := world.pendingRequest(world.gate.Authorize(t.Context(), asked(blog, "tls/443/blog", 100), nil)); again.ApprovalId() != request.ApprovalId() {
		t.Error("the same listen filed a second request")
	}
	shop := world.pendingRequest(world.gate.Authorize(t.Context(), asked(testListenAction(t, "sock:tls/443/shop"), "tls/443/shop", 100), nil))
	if shop.ApprovalId() == request.ApprovalId() || shop.Request.GetSocketName() != "tls/443/shop" {
		t.Error("another socket's listen found the first request")
	}
	// a request whose name disagrees with its action, or names none, is never filed
	filed := world.log.filedCount()
	for name, action := range map[string]*SidecarAction{
		"another name": asked(blog, "tls/443/shop", 100), "no name": asked(blog, "", 100),
	} {
		err := world.gate.Authorize(t.Context(), action, nil)
		pending := &ApprovalPendingError{}
		if err == nil || errors.As(err, &pending) || !errors.Is(err, ErrRecordStoredInvalid) {
			t.Errorf("a listen with %s answered %v", name, err)
		}
	}
	if world.log.filedCount() != filed {
		t.Error("a listen whose name disagrees with its action was filed")
	}

	decision := world.approve(request)
	world.log.putDecision(request.ApprovalId(), decision)
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := world.gate.Authorize(t.Context(), asked(blog, "tls/443/blog", 200), testGateSigned(t, decision)); !errors.Is(err, ErrApprovalRefused) {
		t.Errorf("the decision on another weight: %v", err)
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Fatalf("an effect ran %d times before its spend", runCount)
	}
	spent := asked(blog, "tls/443/blog", 100)
	testGateExpectOutcome(t, "the approved listen", world.gate.Authorize(t.Context(), spent, nil), spent, ApprovalOutcomeDone)
	spend, ok := world.effect.spendSeen()
	if !ok || spend.ApprovalId != request.ApprovalId() || !spend.Detail.Equal(&SidecarActionDetail{SocketName: "tls/443/blog", Weight: 100}) {
		t.Errorf("the spend the effect saw: %+v", spend)
	}
	if got := world.status(shop.ApprovalId()); got != ApprovalStatusPending {
		t.Errorf("the other socket's request: %s", got)
	}
	// the request's hash covers the name: the same request naming another socket is one no decision on it saw
	renamed := proto.Clone(request.Request).(*protocol.ApprovalRequest)
	renamed.SocketName = "tls/443/shop"
	renamedSha256 := ApprovalRequestSha256(testRecordStored(t, renamed))
	if requestSha256 := request.Sha256(); bytes.Equal(renamedSha256[:], requestSha256[:]) {
		t.Error("request_sha256 does not cover socket_name")
	}
}
