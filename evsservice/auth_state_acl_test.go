// The real EvsAuthState through evs's guard (ACL-M2-14), on T2's fake host and clock: the newest verified state alone
// decides each scope, so a group edit and a Suspend close a live token's scope at the next state (FS-14's closing
// case, 403 with no clock moving), a grant's expiry closes it at its time and a projection that drops it at the next
// state (FS-3's inputs to step 7's recheck); cold state answers 503 and starts a load; the binding, rev/ and repo facts
// answer as the state and their seams do. The gate cache's own event and poll timing is acl_gate_scope_test.go's, on
// TEAM's real log.

package evsservice

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The binding a test says api made: each sidecar's current client.
type testBindings struct {
	stateLock sync.Mutex
	clientIds map[sidecar.Id]sidecar.Id
	unknown   bool
}

func (self *testBindings) MatchBinding(networkId sidecar.Id, clientId sidecar.Id, sidecarId sidecar.Id) EvsAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unknown {
		return EvsAuthUnknown
	}
	if bound, ok := self.clientIds[sidecarId]; ok && bound == clientId {
		return EvsAuthAllowed
	}
	return EvsAuthDenied
}

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
	bindings    *testBindings
	revocations *testRevocations
	view        *sidecartest.FakeAclView
	member      sidecar.Id
	device      sidecar.Id
	repoId      sidecar.Id
}

// The engine of newEvsFixture, its auth state the real one over hand-installed states.
func newAclAuthFixture(t *testing.T, bindings *testBindings, routes ...*EvsRoute) *aclAuthFixture {
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
	var bindingSource EvsBindingSource
	if bindings != nil {
		bindingSource = bindings
	}
	serviceLog := &recordingServiceLog{}
	engine, err := NewEvsEngine(ctx, host.ServiceHost(), DefaultEvsSettings(), &EvsEngineDeps{
		AuthState:  NewAclEvsAuthState(states, revocations, bindingSource),
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
		bindings:    bindings,
		revocations: revocations,
		view:        sidecartest.NewFakeAclView(),
		repoId:      testId("acl-repo"),
	}
	fixture.member = fixture.view.AddMember(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	fixture.device = fixture.view.AddDevice(fixture.member)
	if bindings != nil {
		bindings.clientIds[fixture.device] = fixture.clientOf(fixture.device)
	}
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
	fixture := newAclAuthFixture(t, &testBindings{clientIds: map[sidecar.Id]sidecar.Id{}}, probe.route)
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
	fixture := newAclAuthFixture(t, &testBindings{clientIds: map[sidecar.Id]sidecar.Id{}}, probe.route)
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
	fixture := newAclAuthFixture(t, &testBindings{clientIds: map[sidecar.Id]sidecar.Id{}}, probe.route)
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

// The binding: an unrevoked admission and a binding source that names the token's client; another client is 403, a
// revoked sidecar 403, and no source or a source that cannot tell 503.
func TestAclEvsAuthStateMatchesTheBinding(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	bindings := &testBindings{clientIds: map[sidecar.Id]sidecar.Id{}}
	fixture := newAclAuthFixture(t, bindings, probe.route)
	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ})
	if code := fixture.read(); code != http.StatusOK {
		t.Fatalf("bound: %d", code)
	}
	bindings.stateLock.Lock()
	bindings.clientIds[fixture.device] = testId("another client")
	bindings.stateLock.Unlock()
	if code := fixture.read(); code != http.StatusForbidden {
		t.Errorf("another client: %d", code)
	}
	bindings.stateLock.Lock()
	bindings.clientIds[fixture.device] = fixture.clientOf(fixture.device)
	bindings.unknown = true
	bindings.stateLock.Unlock()
	if code := fixture.read(); code != http.StatusServiceUnavailable {
		t.Errorf("a source that cannot tell: %d", code)
	}
	bindings.stateLock.Lock()
	bindings.unknown = false
	bindings.stateLock.Unlock()
	fixture.view.Revoke(fixture.device)
	fixture.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ})
	if code := fixture.read(); code != http.StatusForbidden {
		t.Errorf("a revoked sidecar: %d", code)
	}

	unbound := newAclAuthFixture(t, nil, newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false).route)
	unbound.install(0, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ})
	if code := unbound.read(); code != http.StatusServiceUnavailable {
		t.Errorf("no binding source: %d", code)
	}
}

// rev/ through the real state: a voiding object answers a write 401, a read that cannot tell 503, and no reader 503.
func TestAclEvsAuthStateReadsRevocations(t *testing.T) {
	probe := newProbeRoute(http.MethodPost, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsWrite, true, false, false)
	fixture := newAclAuthFixture(t, &testBindings{clientIds: map[sidecar.Id]sidecar.Id{}}, probe.route)
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
	if err := NewAclEvsAuthState(fixture.states, nil, nil).CheckRevocation(t.Context(), &sidecar.Principal{}); err == nil || errors.Is(err, ErrEvsTokenRevoked) {
		t.Errorf("no reader: %v", err)
	}
}

// What the projection holds of a repo: its kind and owner, a RepoDelete{now} without a date, and no facts for one the
// gate cannot date or a repo it does not hold.
func TestAclEvsAuthStateRepoFacts(t *testing.T) {
	fixture := newAclAuthFixture(t, &testBindings{clientIds: map[sidecar.Id]sidecar.Id{}})
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
	state := NewAclEvsAuthState(fixture.states, fixture.revocations, fixture.bindings)
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
