// The real EvsAuthState through evs's guard (ACL-M2-14), on T2's fake host and clock: the newest verified state alone
// decides each scope, so a group edit and a Suspend close a live token's scope at the next state (FS-14's closing
// case, 403 with no clock moving), a grant's expiry closes it at its time and a projection that drops it at the next
// state (FS-3's inputs to step 7's recheck); cold state answers 503 and starts a load; a token's sidecar is served
// while its network's state admits it, whichever client the exchange bound it to (QD-717), and refused once revoked,
// when another network admitted it and when none did; rev/ and repo facts answer as the state and their seam do. The
// gate cache's own event and poll timing is acl_gate_scope_test.go's, on TEAM's real log.

package evsservice

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// rev/ as a test says it reads.
type testRevocations struct {
	err   error
	count int
}

func (self *testRevocations) Check(ctx context.Context, principal *sidecar.Principal) error {
	self.count += 1
	return self.err
}

// One network for the real state: a member's device, its states installed by hand as the cache would load them.
type aclAuthFixture struct {
	*evsFixture
	states      *sidecartest.FakeAclContractStates
	revocations *testRevocations
	view        *sidecartest.FakeAclView
	member      sidecar.Id
	device      sidecar.Id
	repoId      sidecar.Id
}

// The engine of newEvsFixture, its auth state the real one over hand-installed states.
func newAclAuthFixture(t *testing.T, routes ...*EvsRoute) *aclAuthFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1", "meta-2"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	sidecartest.RegisterEvsTwins(host.Redis)
	networkId := connect.Id(testId("network-a"))
	host.Gates.OpenService(sidecar.ServiceGateEvs, networkId)
	states := sidecartest.NewFakeAclContractStates()
	revocations := &testRevocations{}
	serviceLog := &recordingServiceLog{}
	engine, err := NewEvsEngine(ctx, host.ServiceHost(), DefaultEvsSettings(), &EvsEngineDeps{
		AuthState:  NewAclEvsAuthState(states, revocations),
		ServiceLog: serviceLog,
		testRoutes: routes,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	fixture := &aclAuthFixture{
		evsFixture:  &evsFixture{t: t, ctx: ctx, clock: clock, host: host, serviceLog: serviceLog, engine: engine, networkId: networkId},
		states:      states,
		revocations: revocations,
		view:        sidecartest.NewFakeAclView(),
		repoId:      testId("acl-repo"),
	}
	fixture.member = fixture.view.AddMember(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	fixture.device = fixture.view.AddDevice(fixture.member)
	return fixture
}

// The client a fixture token names for a sidecar.
func (self *aclAuthFixture) clientOf(sidecarId sidecar.Id) sidecar.Id {
	return testId("client-" + string(sidecarId[:4]))
}

// Installs the network's state: the member device's rule on the repo, with the rights and expiry given, and the
// suspensions given. No rule is installed for zero actions.
func (self *aclAuthFixture) install(expiresMs int64, actions []protocol.AclAction, suspensions ...*protocol.AclSuspension) {
	self.t.Helper()
	rows := &protocol.AclRows{
		HasDocument: true,
		Repos:       []*protocol.AclRepo{{RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}},
		Suspensions: suspensions,
	}
	if 0 < len(actions) {
		rule := &protocol.AclRule{
			RuleId:   testId("member rule").Bytes(),
			SrcAtoms: [][]byte{sidecar.AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:  []*protocol.AclTarget{{RepoId: self.repoId.Bytes()}},
			Expires:  expiresMs,
		}
		for _, action := range actions {
			rule.Actions = append(rule.Actions, uint32(action))
		}
		rows.Rules = []*protocol.AclRule{rule}
	}
	if err := self.states.Install(sidecar.Id(self.networkId), rows, self.view); err != nil {
		self.t.Fatal(err)
	}
}

// A GET of the probe route with a read token of the device.
func (self *aclAuthFixture) read() int {
	token := self.token(self.device, repoScope(self.repoId, "r"))
	return self.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(self.repoId)+"/probe", token, nil).Code
}

// FS-14's closing case at evs: a state that drops the member's read, as a group edit's does, answers the same live
// token 403 at once, and one with the device suspended does too.
func TestAclEvsAuthStateClosesALiveTokensScopeAtTheNextState(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newAclAuthFixture(t, probe.route)
	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ})
	if code := fixture.read(); code != http.StatusOK {
		t.Fatalf("with the read: %d", code)
	}
	fixture.install(0, nil)
	recorder := fixture.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(fixture.repoId)+"/probe",
		fixture.token(fixture.device, repoScope(fixture.repoId, "r")), nil)
	requireRefusal(t, recorder, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)

	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ}, &protocol.AclSuspension{
		Subject: fixture.device.Bytes(), SuspendId: testId("suspend").Bytes(), SignerClass: 2, Signer: testId("admin").Bytes(), At: 3,
	})
	if code := fixture.read(); code != http.StatusForbidden {
		t.Errorf("after the Suspend: %d", code)
	}
	if probe.calls != 1 {
		t.Errorf("the route ran %d times", probe.calls)
	}
}

// FS-3's inputs to step 7's recheck: a grant honored before its expiry is refused once evs's clock passes it, and one a
// later projection drops is refused at that state, each with the token unchanged.
func TestAclEvsAuthStateHonorsAGrantUntilItsExpiry(t *testing.T) {
	probe := newProbeRoute(http.MethodPost, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsWrite, false, false, false)
	fixture := newAclAuthFixture(t, probe.route)
	expiry := fixture.clock.Now().Add(time.Minute)
	fixture.install(expiry.UnixMilli(), []protocol.AclAction{protocol.AclAction_ACL_ACTION_WRITE})
	token := fixture.token(fixture.device, repoScope(fixture.repoId, "rw"))
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(fixture.repoId) + "/probe"
	if recorder := fixture.serve(http.MethodPost, path, token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("before the expiry: %d", recorder.Code)
	}
	fixture.clock.AdvanceTo(expiry)
	requireRefusal(t, fixture.serve(http.MethodPost, path, token, nil), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)

	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_WRITE})
	if recorder := fixture.serve(http.MethodPost, path, token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("a standing grant: %d", recorder.Code)
	}
	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ})
	requireRefusal(t, fixture.serve(http.MethodPost, path, token, nil), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
}

// Cold state is no pass: a network with no state answers 503 and asks the cache for it.
func TestAclEvsAuthStateIsUnavailableWhileTheStateIsCold(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newAclAuthFixture(t, probe.route)
	recorder := fixture.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(fixture.repoId)+"/probe",
		fixture.token(fixture.device, repoScope(fixture.repoId, "r")), nil)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if changed := fixture.states.ChangedNetworks(); !slices.Contains(changed, sidecar.Id(fixture.networkId)) {
		t.Errorf("no load asked for: %v", changed)
	}
	if probe.calls != 0 {
		t.Errorf("the route ran %d times", probe.calls)
	}
}

// A read token of sidecarId in networkId, its client clientId, as the exchange would mint it.
func (self *aclAuthFixture) tokenOf(networkId sidecar.Id, sidecarId sidecar.Id, clientId sidecar.Id) string {
	connectSidecarId := connect.Id(sidecarId)
	return self.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(networkId),
		ClientId:  connect.Id(clientId),
		SidecarId: &connectSidecarId,
		Audience:  EvsAudience,
		Scopes:    []string{repoScope(self.repoId, "r")},
		IssuedAt:  self.clock.Now(),
		ExpiresAt: self.clock.Now().Add(15 * time.Minute),
	})
}

// A GET of the probe route with token.
func (self *aclAuthFixture) readWith(token string) *httptest.ResponseRecorder {
	return self.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(self.repoId)+"/probe", token, nil)
}

// The read rule every member's device holds on the fixture's repo, as rows for one network's state.
func (self *aclAuthFixture) readRows() *protocol.AclRows {
	return &protocol.AclRows{
		HasDocument: true,
		Repos:       []*protocol.AclRepo{{RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}},
		Rules: []*protocol.AclRule{{
			RuleId:   testId("member rule").Bytes(),
			SrcAtoms: [][]byte{sidecar.AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:  []*protocol.AclTarget{{RepoId: self.repoId.Bytes()}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_READ)},
		}},
	}
}

// QD-717's binding, the mint is the match: a real state with no binding source serves a sidecar its network's state
// admits, under whichever client the exchange wrote into the token, and looks no binding up.
func TestAclEvsAuthStateServesAnAdmittedSidecar(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newAclAuthFixture(t, probe.route)
	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ})
	if code := fixture.read(); code != http.StatusOK {
		t.Fatalf("an admitted sidecar: %d", code)
	}
	// a rebind's new client: the pair in the token is the binding as api made it
	rebound := fixture.tokenOf(sidecar.Id(fixture.networkId), fixture.device, testId("a rebind's client"))
	if recorder := fixture.readWith(rebound); recorder.Code != http.StatusOK {
		t.Errorf("the sidecar under another client: %d", recorder.Code)
	}
	if probe.calls != 2 {
		t.Errorf("the route ran %d times", probe.calls)
	}

	connectDevice := connect.Id(fixture.device)
	state := NewAclEvsAuthState(fixture.states, fixture.revocations)
	principal := &sidecar.Principal{NetworkId: fixture.networkId, ClientId: connect.Id(fixture.clientOf(fixture.device)), SidecarId: &connectDevice}
	if answer := state.MatchBinding(principal); answer != EvsAuthAllowed {
		t.Errorf("the state's answer for an admitted sidecar: %d", answer)
	}
	if answer := state.MatchBinding(&sidecar.Principal{NetworkId: fixture.networkId, ClientId: principal.ClientId}); answer != EvsAuthDenied {
		t.Errorf("a token naming no sidecar: %d", answer)
	}
	if answer := NewAclEvsAuthState(nil, fixture.revocations).MatchBinding(principal); answer != EvsAuthUnknown {
		t.Errorf("no gate cache: %d", answer)
	}
}

// A revoked sidecar is refused at the state that revokes it, its token and its client unchanged, and the route
// never runs for it.
func TestAclEvsAuthStateRefusesARevokedSidecar(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newAclAuthFixture(t, probe.route)
	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ})
	token := fixture.token(fixture.device, repoScope(fixture.repoId, "r"))
	if recorder := fixture.readWith(token); recorder.Code != http.StatusOK {
		t.Fatalf("before the revocation: %d", recorder.Code)
	}
	fixture.view.Revoke(fixture.device)
	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ})
	requireRefusal(t, fixture.readWith(token), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	if probe.calls != 1 {
		t.Errorf("the route ran %d times", probe.calls)
	}
	connectDevice := connect.Id(fixture.device)
	principal := &sidecar.Principal{NetworkId: fixture.networkId, ClientId: connect.Id(fixture.clientOf(fixture.device)), SidecarId: &connectDevice}
	if answer := NewAclEvsAuthState(fixture.states, fixture.revocations).MatchBinding(principal); answer != EvsAuthDenied {
		t.Errorf("the state's answer for a revoked sidecar: %d", answer)
	}
}

// A sidecar of another network is refused: a token naming network b for a sidecar only network a admits answers 403
// from b's state, and one naming network a for a sidecar only b admits answers 403 from a's, each network's own
// sidecar served beside it. A network whose state is not loaded answers 503, never an allow.
func TestAclEvsAuthStateRefusesASidecarOfAnotherNetwork(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newAclAuthFixture(t, probe.route)
	networkA, networkB, networkC := sidecar.Id(fixture.networkId), testId("network-b"), testId("network-c")
	fixture.host.Gates.OpenService(sidecar.ServiceGateEvs, fixture.networkId, connect.Id(networkB), connect.Id(networkC))
	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ})
	otherView := sidecartest.NewFakeAclView()
	otherDevice := otherView.AddDevice(otherView.AddMember(bridge.MemberRole_MEMBER_ROLE_MEMBER))
	if err := fixture.states.Install(networkB, fixture.readRows(), otherView); err != nil {
		t.Fatal(err)
	}

	if recorder := fixture.readWith(fixture.tokenOf(networkA, fixture.device, fixture.clientOf(fixture.device))); recorder.Code != http.StatusOK {
		t.Fatalf("network a's sidecar in a: %d", recorder.Code)
	}
	if recorder := fixture.readWith(fixture.tokenOf(networkB, otherDevice, fixture.clientOf(otherDevice))); recorder.Code != http.StatusOK {
		t.Fatalf("network b's sidecar in b: %d", recorder.Code)
	}
	requireRefusal(t, fixture.readWith(fixture.tokenOf(networkB, fixture.device, fixture.clientOf(fixture.device))),
		http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	requireRefusal(t, fixture.readWith(fixture.tokenOf(networkA, otherDevice, fixture.clientOf(otherDevice))),
		http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	requireRefusal(t, fixture.readWith(fixture.tokenOf(networkC, fixture.device, fixture.clientOf(fixture.device))),
		http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if probe.calls != 2 {
		t.Errorf("the route ran %d times", probe.calls)
	}
}

// A token whose sidecar no state ever admitted is refused, though the token authenticates and names a client and a
// scope the network's members hold: the exchange's word alone admits no sidecar.
func TestAclEvsAuthStateRefusesASidecarNeverAdmitted(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newAclAuthFixture(t, probe.route)
	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ})
	stranger := testId("a sidecar never admitted")
	requireRefusal(t, fixture.readWith(fixture.tokenOf(sidecar.Id(fixture.networkId), stranger, fixture.clientOf(fixture.device))),
		http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	if probe.calls != 0 {
		t.Errorf("the route ran %d times", probe.calls)
	}
	connectStranger := connect.Id(stranger)
	principal := &sidecar.Principal{NetworkId: fixture.networkId, ClientId: connect.Id(fixture.clientOf(fixture.device)), SidecarId: &connectStranger}
	if answer := NewAclEvsAuthState(fixture.states, fixture.revocations).MatchBinding(principal); answer != EvsAuthDenied {
		t.Errorf("the state's answer for a sidecar never admitted: %d", answer)
	}
	if code := fixture.read(); code != http.StatusOK {
		t.Errorf("the admitted sidecar beside it: %d", code)
	}
}

// rev/ through the real state: a voiding object answers a write 401, a read that cannot tell 503, and no reader 503.
func TestAclEvsAuthStateReadsRevocations(t *testing.T) {
	probe := newProbeRoute(http.MethodPost, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsWrite, true, false, false)
	fixture := newAclAuthFixture(t, probe.route)
	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_WRITE})
	token := fixture.token(fixture.device, repoScope(fixture.repoId, "rw"))
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(fixture.repoId) + "/probe"
	if recorder := fixture.serve(http.MethodPost, path, token, nil); recorder.Code != http.StatusOK || fixture.revocations.count != 1 {
		t.Fatalf("no object: %d, %d reads", recorder.Code, fixture.revocations.count)
	}
	fixture.revocations.err = sidecar.ErrRevocationVoidsToken
	if recorder := fixture.serve(http.MethodPost, path, token, nil); recorder.Code != http.StatusUnauthorized {
		t.Errorf("a voiding object: %d", recorder.Code)
	}
	fixture.revocations.err = errors.New("the cluster did not answer")
	if recorder := fixture.serve(http.MethodPost, path, token, nil); recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("a read that cannot tell: %d", recorder.Code)
	}
	if err := NewAclEvsAuthState(fixture.states, nil).CheckRevocation(t.Context(), &sidecar.Principal{}); err == nil || errors.Is(err, ErrEvsTokenRevoked) {
		t.Errorf("no reader: %v", err)
	}
}

// What the projection holds of a repo: its kind and owner, a RepoDelete{now} without a date, and no facts for one the
// gate cannot date or a repo it does not hold.
func TestAclEvsAuthStateRepoFacts(t *testing.T) {
	fixture := newAclAuthFixture(t)
	vaultId, deletedId, undatedId := testId("acl-vault"), testId("acl-deleted"), testId("acl-undated")
	rows := &protocol.AclRows{HasDocument: true, Repos: []*protocol.AclRepo{
		{RepoId: vaultId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: fixture.member.Bytes()},
		{RepoId: deletedId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Deletion: &protocol.AclRepoDeletionRow{DeletionId: testId("deletion now").Bytes(), Now: true, DeletedAt: 4}},
		{RepoId: undatedId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Deletion: &protocol.AclRepoDeletionRow{DeletionId: testId("deletion").Bytes(), DeletedAt: 5}},
	}}
	if err := fixture.states.Install(sidecar.Id(fixture.networkId), rows, fixture.view); err != nil {
		t.Fatal(err)
	}
	connectDevice := connect.Id(fixture.device)
	principal := &sidecar.Principal{NetworkId: fixture.networkId, ClientId: connect.Id(fixture.clientOf(fixture.device)), SidecarId: &connectDevice}
	state := NewAclEvsAuthState(fixture.states, fixture.revocations)
	facts, answer := state.Repo(principal, vaultId)
	if answer != EvsAuthAllowed || facts.Kind != protocol.RepoKind_REPO_KIND_VAULT || facts.OwnerMemberId != fixture.member ||
		facts.NetworkId != sidecar.Id(fixture.networkId) || facts.Deletion != nil {
		t.Errorf("the vault: %+v, %d", facts, answer)
	}
	facts, answer = state.Repo(principal, deletedId)
	if answer != EvsAuthAllowed || facts.Deletion == nil || !facts.Deletion.Now || facts.Deletion.DeletionId != testId("deletion now") {
		t.Errorf("a RepoDelete{now}: %+v, %d", facts, answer)
	}
	if facts, answer := state.Repo(principal, undatedId); answer != EvsAuthAllowed || facts.Deletion != nil {
		t.Errorf("an undated RepoDelete: %+v, %d", facts, answer)
	}
	if _, answer := state.Repo(principal, testId("no such repo")); answer != EvsAuthDenied {
		t.Errorf("an unknown repo: %d", answer)
	}
	otherNetwork := &sidecar.Principal{NetworkId: connect.Id(testId("network-b")), ClientId: principal.ClientId, SidecarId: &connectDevice}
	if _, answer := state.Repo(otherNetwork, vaultId); answer != EvsAuthUnknown {
		t.Errorf("a network the cache does not hold: %d", answer)
	}
}
