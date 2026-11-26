//go:build !sidecar_http && !ios_extension && !js

// The listen expiry's other surfaces (owner decision 687; QD-1172): the grant a listen beside the socket component asks,
// MCP's socket_listen's (SocketListenGrantArgs.ExpiresAt), an app's tls/ listen through the tls component
// (TlsListenSettings.Expires), and the end of its grant a listener keeps for the daemon's reply. At §16.6's real gate,
// over the bridge file world's config log and ACL engine, under a requests rule that gives at most 7 days:
//
//   - a listen beside the component asking an end 3 days on files its request for that end, which it presents again a
//     minute later, and the member's decision activates a grant the log holds for those 3 days and no longer; asked
//     again once the engine holds that grant, it passes on it, naming it;
//   - one asking an end 30 days on is refused before the gate, filing and posting nothing, its error a grant filing's
//     refusal beside an AclGrantMaxExpiryError naming the 7 days, while an end 7 days on is filed, a standing grant
//     passes the 30 days' listen, a listen no requests rule takes names no maximum, and an end not ahead is refused;
//   - Sidecar.Listen's listener keeps its grant's end: the approved 3-day listen's, the same listen's asked again once
//     its grant stands, which the gate passes as standing, the rule's default end where it asks none, and none under a
//     document's standing rule; its refusal past the maximum carries the AclGrantMaxExpiryError beside ErrSocketDenied;
//   - ListenTls's Expires reaches the registration, its listener answers the registration's grant end, and a negative
//     one is refused before anything is ordered.
//
// Synthetic values only.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A requests rule on the world's token path by which a member asks listen, the requester's own member approving,
// giving a grant of at most maxExpiry; installed, and its id.
func (self *testListenGrantWorld) requestsWithin(maxExpiry time.Duration) []byte {
	self.t.Helper()
	ruleId := testConfigId("listen grant expires " + self.name).Bytes()
	self.net.withAclRows(func(rows *protocol.AclRows) {
		rows.Requests = append(rows.Requests, &protocol.AclRequestRule{
			RuleId:           ruleId,
			SrcAtoms:         [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:          []*protocol.AclTarget{{SocketTokens: [][]byte{self.tokenPath}}},
			Actions:          []uint32{uint32(protocol.AclAction_ACL_ACTION_LISTEN)},
			ApproverAtoms:    [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()},
			MaxExpirySeconds: int64(maxExpiry / time.Second),
		})
	})
	self.install()
	return ruleId
}

// The listen as MCP's tool builds it now asking its grant to end at expires, zero for the rule's default, kept by the
// name and that end as the tool keeps it, and the answer of §5.4's gate on it.
func (self *testListenGrantWorld) listenAsking(expires time.Time) (*SidecarAction, *StoredCanonicalAction, error) {
	self.t.Helper()
	runId, agentId := self.runId, self.agentId
	var config AclGrantConfig
	if self.config != nil {
		config = self.config
	}
	key := self.name
	if !expires.IsZero() {
		key = fmt.Sprintf("%s until %d", self.name, expires.UnixMilli())
	}
	stored, effect, err := SocketListenGrantAction(self.t.Context(), &SocketListenGrantArgs{
		Grants: self.grants, Subject: self.hostId, GrantDst: self.grantDst, Detail: self.detail, RunId: &runId, AgentId: &agentId,
		Config: config, ExpiresAt: expires,
	}, self.keeper, key, self.clock.Now())
	if err != nil {
		return nil, nil, err
	}
	action, err := NewSidecarAction(stored, SidecarRiskNormal, SidecarRiskNormal, &runId, &agentId)
	if err != nil {
		self.t.Fatalf("the listen's action: %v", err)
	}
	action.Detail, action.Effect = self.detail, effect
	return action, stored, self.sidecar.Authorize(self.t.Context(), action, nil)
}

// An end 3 days on under a rule giving at most 7: the request asks that end, the listen asked again a minute on
// presents the same action, and the member's decision activates a grant the log holds until that end and not at it;
// once the engine holds the grant, the listen asked again passes on it, naming it, with nothing more filed.
func TestSocketListenGrantActionAsksItsExpiresAt(t *testing.T) {
	world := newTestListenGrantWorld(t)
	ruleId := world.requestsWithin(testListenExpiresRuleMax)
	end := world.clock.Now().Add(3 * 24 * time.Hour)
	_, filed, err := world.listenAsking(end)
	request := world.gate.pendingRequest(t, err)
	if !bytes.Equal(request.Action.Bytes, filed.Bytes) || !bytes.Equal(filed.Action.GetRuleId(), ruleId) ||
		filed.Action.GetExpiresMillis() != end.UnixMilli() {
		t.Fatalf("the filed action: %+v", filed.Action)
	}

	world.advance(time.Minute)
	_, again, err := world.listenAsking(end)
	if pending := world.gate.pendingRequest(t, err); pending.ApprovalId() != request.ApprovalId() || !bytes.Equal(again.Bytes, filed.Bytes) {
		t.Fatalf("the listen asked again filed %s beside %s", pending.ApprovalId(), request.ApprovalId())
	}

	world.gate.approve(t, request, world.laptop, world.member)
	spent, _, err := world.listenAsking(end)
	grantId := AclGrantId(request.ApprovalId(), request.Action.PayloadSha256())
	if err != nil || spent.Outcome == nil || spent.Outcome.State != ApprovalOutcomeDone || !bytes.Equal(spent.Outcome.EffectRef, grantId[:]) {
		t.Fatalf("the approved listen: %v, outcome %+v", err, spent.Outcome)
	}
	acl, err := world.net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	subject := AclSidecarSubject(world.hostId)
	socket := AclSocketName{NameToken: world.tokenPath}
	if decision := acl.MayListen(subject, socket, end.Add(-time.Millisecond)); !decision.Allowed ||
		!bytes.Equal(decision.Rule.GetRuleId(), grantId[:]) || decision.Rule.GetExpires() != end.UnixMilli() {
		t.Errorf("the log's grant a millisecond before its end: %+v", decision)
	}
	if acl.MayListen(subject, socket, end).Allowed {
		t.Error("the grant outlasts its 3 days")
	}

	world.install()
	standing, _, err := world.listenAsking(end)
	if err != nil || standing.Outcome == nil || standing.Outcome.State != ApprovalOutcomeDone || !bytes.Equal(standing.Outcome.EffectRef, grantId[:]) {
		t.Errorf("the listen on its own grant: %v, outcome %+v", err, standing.Outcome)
	}
	if world.gate.approvals.filedCount() != 1 || world.api.postCount() != 1 {
		t.Errorf("%d requests filed, %d statements posted", world.gate.approvals.filedCount(), world.api.postCount())
	}
}

// An end 30 days on under a rule giving at most 7 is refused before the gate, filing and posting nothing, a grant
// filing's refusal beside an AclGrantMaxExpiryError naming the 7 days; a listen no requests rule takes is refused with no
// maximum named; an end now or before it is refused; an end 7 days on is filed; and a standing grant passes the 30
// days' listen with nothing more filed.
func TestSocketListenGrantActionPastTheMaxExpiryIsRefused(t *testing.T) {
	world := newTestListenGrantWorld(t)
	month := world.clock.Now().Add(30 * 24 * time.Hour)
	world.rule("db/replica", false)
	if _, _, err := world.listenAsking(month); !errors.Is(err, ErrAclGrantFile) || errors.As(err, new(*AclGrantMaxExpiryError)) {
		t.Errorf("a listen no requests rule takes: %v", err)
	}

	world.requestsWithin(testListenExpiresRuleMax)
	_, _, err := world.listenAsking(month)
	var maxExpiry *AclGrantMaxExpiryError
	if !errors.Is(err, ErrAclGrantFile) || !errors.As(err, &maxExpiry) || maxExpiry.MaxExpiry != testListenExpiresRuleMax ||
		!strings.Contains(err.Error(), "maxExpiry") || !strings.Contains(err.Error(), testListenExpiresRuleMax.String()) {
		t.Fatalf("a listen asking past the rule's maxExpiry: %v", err)
	}
	if world.gate.approvals.filedCount() != 0 || world.api.postCount() != 0 {
		t.Errorf("a refused listen filed %d requests and posted %d statements", world.gate.approvals.filedCount(), world.api.postCount())
	}
	for _, end := range []time.Time{world.clock.Now(), world.clock.Now().Add(-time.Hour)} {
		if _, _, err := world.listenAsking(end); !errors.Is(err, ErrAclGrantFile) || errors.As(err, new(*AclGrantMaxExpiryError)) {
			t.Errorf("an end at %v: %v", end, err)
		}
	}
	if world.gate.approvals.filedCount() != 0 {
		t.Errorf("%d requests filed for ends not ahead", world.gate.approvals.filedCount())
	}

	week := world.clock.Now().Add(testListenExpiresRuleMax)
	_, filed, err := world.listenAsking(week)
	if request := world.gate.pendingRequest(t, err); request.Action.Action.GetExpiresMillis() != week.UnixMilli() || !bytes.Equal(request.Action.Bytes, filed.Bytes) {
		t.Errorf("the maximum's request: %+v", request.Action.Action)
	}

	world.rule(world.name, false)
	standing, stored, err := world.listenAsking(month)
	if err != nil || standing.Outcome == nil || standing.Outcome.State != ApprovalOutcomeDone || len(stored.Action.GetRuleId()) != 0 ||
		stored.Action.GetExpiresMillis() != 0 {
		t.Errorf("a standing grant's listen asking 30 days: %v, outcome %+v, action %+v", err, standing.Outcome, stored.Action)
	}
	if world.gate.approvals.filedCount() != 1 || world.api.postCount() != 0 {
		t.Errorf("%d requests filed, %d statements posted", world.gate.approvals.filedCount(), world.api.postCount())
	}
}

// Sidecar.Listen's listener keeps when its grant ends: the approved listen asking 3 days its action's end; the same
// listen asked again once the engine holds that grant, which the gate passes as standing on it, the same end; under a
// document's standing rule, none; and a listen asking nothing the end the rule's default gives from its filing.
func TestSocketListenerKeepsItsGrantsEnd(t *testing.T) {
	world := newTestListenGateWorld(t)
	world.requestsWithin("tls/443/blog", testListenExpiresRuleMax, 0)
	settings := &SocketListenSettings{Expires: 3 * 24 * time.Hour}
	end := world.clock.Now().Add(3 * 24 * time.Hour)
	_, err := world.listen("tls/443/blog", settings)
	world.approve(world.pendingRequest(err))
	listener, err := world.listen("tls/443/blog", settings)
	if err != nil {
		t.Fatalf("the approved listen: %v", err)
	}
	if got := listener.GrantExpires(); !got.Equal(end) {
		t.Errorf("the approved listen's grant ends %v, not %v", got, end)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	world.install()
	world.advance(time.Minute)
	again, err := world.listen("tls/443/blog", settings)
	if err != nil {
		t.Fatalf("the listen asked again: %v", err)
	}
	defer again.Close()
	if action, _ := world.lastAsked(); action.Outcome == nil || action.Outcome.State != ApprovalOutcomeDone || len(action.Outcome.EffectRef) != 0 {
		t.Errorf("the listen asked again was not passed as standing: %+v", action.Outcome)
	}
	if got := again.GrantExpires(); !got.Equal(end) {
		t.Errorf("the listen asked again on its grant: it ends %v, not %v", got, end)
	}
	if world.approvals.filedCount() != 1 || world.api.postCount() != 1 {
		t.Errorf("%d requests filed, %d statements posted", world.approvals.filedCount(), world.api.postCount())
	}

	world.standing("smtp/25/mx")
	standing, err := world.listen("smtp/25/mx", nil)
	if err != nil {
		t.Fatalf("a standing rule's listen: %v", err)
	}
	defer standing.Close()
	if got := standing.GrantExpires(); !got.IsZero() {
		t.Errorf("a standing rule's listen names an end, %v", got)
	}

	world.requestsWithin("tls/443/app", testListenExpiresRuleMax, 2*time.Hour)
	filedAt := world.clock.Now()
	_, err = world.listen("tls/443/app", nil)
	world.approve(world.pendingRequest(err))
	world.advance(time.Minute)
	byDefault, err := world.listen("tls/443/app", nil)
	if err != nil {
		t.Fatalf("the approved listen asking nothing: %v", err)
	}
	defer byDefault.Close()
	if got := byDefault.GrantExpires(); !got.Equal(filedAt.Add(2 * time.Hour)) {
		t.Errorf("a listen asking nothing: its grant ends %v, not the rule's 2 h from its filing", got)
	}
}

// Sidecar.Listen's refusal past the maximum carries the AclGrantMaxExpiryError beside ErrSocketDenied, naming the 7
// days, so a caller can read the maximum as well as show it.
func TestSocketListenPastTheMaxExpiryCarriesTheMaximum(t *testing.T) {
	world := newTestListenGateWorld(t)
	world.requestsWithin("tls/443/blog", testListenExpiresRuleMax, 0)
	_, err := world.listen("tls/443/blog", &SocketListenSettings{Expires: 30 * 24 * time.Hour})
	var maxExpiry *AclGrantMaxExpiryError
	if !errors.Is(err, ErrSocketDenied) || !errors.As(err, &maxExpiry) || maxExpiry.MaxExpiry != testListenExpiresRuleMax {
		t.Fatalf("a listen asking past the rule's maxExpiry: %v", err)
	}
	var codeErr *SocketCodeError
	if !errors.As(err, &codeErr) || codeErr.Err != ErrSocketDenied {
		t.Errorf("the refusal carries no denied code: %v", err)
	}
	if world.askedCount() != 0 || world.approvals.filedCount() != 0 {
		t.Errorf("a refused listen asked the gate %d times and filed %d requests", world.askedCount(), world.approvals.filedCount())
	}
}

// ListenTls's Expires reaches the registration as its SocketListenSettings.Expires, and none as none, and the app
// listener answers its registration's grant end; a negative one is refused before anything is ordered or registered.
func TestTlsComponentListenAsksItsExpires(t *testing.T) {
	// no api attached: an order would answer offline, so a refusal that names the listen came before any
	unattached := newTlsCertFixture(t)
	refusals := &testTlsListenRegistrations{edgeNetworkId: NewId()}
	component, parts := newTlsListenTestComponent(t, unattached, refusals)
	if _, err := component.listen(t.Context(), "tls/443/app", &TlsListenSettings{Expires: -time.Hour}, parts); !errors.Is(err, ErrTlsListenInvalid) {
		t.Errorf("a negative expiry: %v", err)
	}
	if refusals.count() != 0 || unattached.api.orderCount() != 0 {
		t.Errorf("a negative expiry registered %d times and ordered %d certificates", refusals.count(), unattached.api.orderCount())
	}

	fixture := newAttachedTlsCertFixture(t)
	fixture.ensureIssued()
	end := fixture.clock.Now().Add(3 * 24 * time.Hour)
	registrations := &testTlsListenRegistrations{edgeNetworkId: NewId(), grantExpireTime: end}
	component, parts = newTlsListenTestComponent(t, fixture, registrations)
	for _, expires := range []time.Duration{3 * 24 * time.Hour, 0} {
		listener, err := component.listen(t.Context(), "tls/443/app", &TlsListenSettings{Weight: 250, Expires: expires}, parts)
		if err != nil {
			t.Fatalf("a listen asking %v: %v", expires, err)
		}
		// the app listener's grant end is its registration's
		if got := listener.GrantExpires(); !got.Equal(end) {
			t.Errorf("a listen asking %v: its grant ends %v, not its registration's %v", expires, got, end)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if registrations.count() != 2 || registrations.settings[0].Expires != 3*24*time.Hour || registrations.settings[1].Expires != 0 ||
		registrations.settings[0].Weight != 250 {
		t.Errorf("the registrations asked %+v", registrations.settings)
	}
}
