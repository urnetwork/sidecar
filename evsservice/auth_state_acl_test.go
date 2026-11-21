// The real EvsAuthState through evs's guard (ACL-M2-14), on T2's fake host and clock: the newest verified state alone
// decides each scope, so a group edit and a Suspend close a live token's scope at the next state (FS-14's closing
// case, 403 with no clock moving), a grant's expiry closes it at its time and a projection that drops it at the next
// state (FS-3's inputs to step 7's recheck); cold state answers 503 and starts a load; a token's sidecar is served
// while its network's state admits it, whichever client the exchange bound it to (QD-717), and refused once revoked,
// when another network admitted it and when none did; rev/ and repo facts answer as the state and their seam do; a
// repo whose rows hold an unrestored RepoDelete is open to its standing admin's DELETE and restore alone (QD-880); and
// in a recovery that admin's segment uploads reach §11.12's re-seed exception, and nothing else of the repo opens
// (QD-977). The gate cache's own event and poll timing is acl_gate_scope_test.go's, on TEAM's real log.

package evsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

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
	return newAclAuthFixtureWith(t, false, routes...)
}

// newAclAuthFixture's engine, with the upload route's deps when uploads is set, so a segment upload runs under the
// real state as the upload fixture's runs under the fake.
func newAclAuthFixtureWith(t *testing.T, uploads bool, routes ...*EvsRoute) *aclAuthFixture {
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
	deps := &EvsEngineDeps{
		AuthState:  NewAclEvsAuthState(states, revocations),
		ServiceLog: serviceLog,
		testRoutes: routes,
	}
	if uploads {
		quota, err := newQuotaGate(ctx, host.ServiceHost(), nil)
		if err != nil {
			t.Fatal(err)
		}
		quota.refresh(ctx)
		hdd, err := newHddAdmission(ctx, host.ServiceHost(), "seg-1", nil)
		if err != nil {
			t.Fatal(err)
		}
		usage, err := NewUsageBatcher(ctx, host.ServiceHost(), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(usage.Close)
		deps.Uploads = &EvsUploadDeps{
			Keys:  testReceiptKeys(t, testReceiptKey(1, clock.Now().Add(-time.Hour))),
			Quota: quota,
			Hdd:   hdd,
			Usage: usage,
		}
	}
	engine, err := NewEvsEngine(ctx, host.ServiceHost(), DefaultEvsSettings(), deps)
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

// A second network displaces the first. Each normal EVS guard can request its previous snapshot again.
func TestAclEvsGuardsReloadEvictedNetworks(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, sidecartest.NewFaultQueue(), nil, nil)
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	owner := func() *sidecar.Principal {
		networkId, ownerId := connect.NewId(), connect.NewId()
		world := sidecartest.NewConfigLogSuiteWorldFor(t.Context(), cluster, sidecar.Id(networkId), sidecar.NewId(), sidecar.Id(ownerId))
		api := sidecartest.NewFakeApi(t.Context(), world.Clock(), blobs.Faults(), nil, cluster, nil)
		if err := world.Start(api); err != nil {
			t.Fatal(err)
		}
		return &sidecar.Principal{NetworkId: networkId, ClientId: connect.NewId(), SidecarId: &ownerId}
	}
	first, second := owner(), owner()
	loads := make(chan error, 1)
	settings := sidecar.DefaultAclGateSettings()
	settings.PollInterval = 0
	settings.ByteBudget = 1
	settings.OnLoad = func(_ sidecar.Id, _ *bridge.AuthPin, err error) { loads <- err }
	cache := sidecar.NewAclGateCache(t.Context(), sidecar.NewAclGateDirectSource(nil, blobs, settings), clock, settings)
	t.Cleanup(cache.Close)
	waitLoad := func() {
		t.Helper()
		select {
		case err := <-loads:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the guard did not request its network")
		}
	}
	auth := NewAclEvsAuthState(cache, nil)
	for _, principal := range []*sidecar.Principal{first, second, first} {
		if got := auth.MatchBinding(principal); got != EvsAuthUnknown {
			t.Fatalf("binding before loading: %v", got)
		}
		waitLoad()
		if got := auth.MatchBinding(principal); got != EvsAuthAllowed {
			t.Fatalf("verified owner's binding: %v", got)
		}
	}
	views := NewAclGateViews(cache)
	if _, answer := views.View(sidecar.Id(second.NetworkId)); answer != EvsAuthUnknown {
		t.Fatalf("evicted push view: %v", answer)
	}
	waitLoad()
	if view, answer := views.View(sidecar.Id(second.NetworkId)); view == nil || answer != EvsAuthAllowed {
		t.Fatalf("reloaded push view: %v", answer)
	}
	locks := NewAclDropLocks(cache)
	repoId := sidecar.NewId()
	if _, answer := locks.LockStanding(sidecar.Id(first.NetworkId), repoId); answer != EvsAuthUnknown {
		t.Fatalf("evicted DROP lock view: %v", answer)
	}
	waitLoad()
	if _, answer := locks.LockStanding(sidecar.Id(first.NetworkId), repoId); answer != EvsAuthAllowed {
		t.Fatalf("reloaded DROP lock view: %v", answer)
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

// What the projection holds of a repo: its kind and owner, a RepoDelete{now} without a date, a RepoDelete dated and
// signed by its row (QD-743, QD-798) with no log behind the gate, one whose row carries no signer, as no fold leaves
// it, dated and unsigned, and no facts for one its row does not date or a repo the gate does not hold.
func TestAclEvsAuthStateRepoFacts(t *testing.T) {
	fixture := newAclAuthFixture(t)
	vaultId, deletedId, datedId, undatedId := testId("acl-vault"), testId("acl-deleted"), testId("acl-dated"), testId("acl-undated")
	signedId, signer := testId("acl-signed"), testId("acl-deleting admin")
	deletedTime := fixture.clock.Now().Add(-48 * time.Hour)
	rows := &protocol.AclRows{HasDocument: true, Repos: []*protocol.AclRepo{
		{RepoId: vaultId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: fixture.member.Bytes()},
		{RepoId: deletedId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Deletion: &protocol.AclRepoDeletionRow{DeletionId: testId("deletion now").Bytes(), Now: true, DeletedAt: 4}},
		{RepoId: datedId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Deletion: &protocol.AclRepoDeletionRow{DeletionId: testId("dated deletion").Bytes(), DeletedAt: 5, DeletedTimeMs: deletedTime.UnixMilli(), RestoredAt: 6}},
		{RepoId: undatedId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Deletion: &protocol.AclRepoDeletionRow{DeletionId: testId("deletion").Bytes(), DeletedAt: 5}},
		{RepoId: signedId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Deletion: &protocol.AclRepoDeletionRow{
				DeletionId: testId("signed deletion").Bytes(), DeletedAt: 7, DeletedTimeMs: deletedTime.UnixMilli(), Signer: signer.Bytes(),
			}},
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
	facts, answer = state.Repo(principal, datedId)
	if answer != EvsAuthAllowed || facts.Deletion == nil || facts.Deletion.Now || !facts.Deletion.Restored ||
		!facts.Deletion.Time.Equal(time.UnixMilli(deletedTime.UnixMilli())) || facts.Deletion.SignerSidecarId != (sidecar.Id{}) {
		t.Errorf("a RepoDelete its row dates and does not sign: %+v, %d", facts.Deletion, answer)
	}
	facts, answer = state.Repo(principal, signedId)
	if answer != EvsAuthAllowed || facts.Deletion == nil || facts.Deletion.Now || facts.Deletion.Restored ||
		!facts.Deletion.Time.Equal(time.UnixMilli(deletedTime.UnixMilli())) || facts.Deletion.SignerSidecarId != signer {
		t.Errorf("a RepoDelete its row dates and signs: %+v, %d", facts.Deletion, answer)
	}
	if deletion, err := state.RepoDeletion(t.Context(), sidecar.Id(fixture.networkId), signedId); err != nil || deletion == nil ||
		deletion.SignerSidecarId != signer || !deletion.Time.Equal(time.UnixMilli(deletedTime.UnixMilli())) {
		t.Errorf("by network, a RepoDelete its row signs: %+v, %v", deletion, err)
	}
	if facts, answer := state.Repo(principal, undatedId); answer != EvsAuthAllowed || facts.Deletion != nil {
		t.Errorf("an undated RepoDelete: %+v, %d", facts, answer)
	}
	// the same facts by network, as taskworker's shred start and reconciler read them; an undated RepoDelete is no
	// answer at all, so neither takes it for no deletion
	if deletion, err := state.RepoDeletion(t.Context(), sidecar.Id(fixture.networkId), datedId); err != nil || deletion == nil || !deletion.Restored ||
		!deletion.Time.Equal(time.UnixMilli(deletedTime.UnixMilli())) {
		t.Errorf("by network, a RepoDelete its row dates: %+v, %v", deletion, err)
	}
	if deletion, err := state.RepoDeletion(t.Context(), sidecar.Id(fixture.networkId), undatedId); err == nil {
		t.Errorf("by network, an undated RepoDelete: %+v", deletion)
	}
	if deletion, err := state.RepoDeletion(t.Context(), sidecar.Id(fixture.networkId), vaultId); err != nil || deletion != nil {
		t.Errorf("by network, a repo with no RepoDelete: %+v, %v", deletion, err)
	}
	unloaded := testId("network-c")
	if _, err := state.RepoDeletion(t.Context(), unloaded, datedId); err == nil || !slices.Contains(fixture.states.ChangedNetworks(), unloaded) {
		t.Errorf("by network, a network the gate has not loaded: %v, told %v", err, fixture.states.ChangedNetworks())
	}
	if _, answer := state.Repo(principal, testId("no such repo")); answer != EvsAuthDenied {
		t.Errorf("an unknown repo: %d", answer)
	}
	otherNetwork := &sidecar.Principal{NetworkId: connect.Id(testId("network-b")), ClientId: principal.ClientId, SidecarId: &connectDevice}
	if _, answer := state.Repo(otherNetwork, vaultId); answer != EvsAuthUnknown {
		t.Errorf("a network the cache does not hold: %d", answer)
	}
}

// §11.12's shred start judged from rows alone (QD-743), with the real state as taskworker's EvsRepoDeletionSource over
// a gate that keeps no log: a deleted repo waits until 7 d 10 min past its row's deleted_time_ms and then goes to
// shredding; a RepoRestore in the rows stops it for good; and a row with no time stops nothing and starts nothing, the
// run failing to be retried while repo/ stays deleted.
func TestAclEvsAuthStateStartsAShredFromRows(t *testing.T) {
	for _, c := range []string{"started", "restored", "undated"} {
		fixture := newEvsFixture(t)
		repoId, admin := testId("repo"), testId("sidecar-a")
		fixture.activeRepo(repoId, admin)
		entryTime := fixture.clock.Now().Add(-time.Minute)
		deletionId := testId("deletion")
		fixture.projectDeletion(repoId, &EvsRepoDeletionFacts{DeletionId: deletionId, Time: entryTime, SignerSidecarId: admin})
		if status := fixture.lifecycle(http.MethodDelete, repoId, "", admin); status != http.StatusOK {
			t.Fatalf("%s: delete: %d", c, status)
		}

		row := &protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), DeletedAt: 9, DeletedTimeMs: entryTime.UnixMilli()}
		switch c {
		case "restored":
			row.RestoredAt = 10
		case "undated":
			row.DeletedTimeMs = 0
		}
		states := sidecartest.NewFakeAclContractStates()
		rows := &protocol.AclRows{HasDocument: true, Repos: []*protocol.AclRepo{{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Deletion: row}}}
		if err := states.Install(sidecar.Id(fixture.networkId), rows, sidecartest.NewFakeAclView()); err != nil {
			t.Fatal(err)
		}
		deletions := NewAclEvsAuthState(states, nil)
		probe := &shredProbe{}
		host := fixture.host.ServiceHost()
		args := EvsShredArgs(repoId, deletionId, false)

		fixture.clock.AdvanceTo(entryTime.Add(evsShredStartAfter - time.Second))
		if outcome, err := RunShred(fixture.ctx, host, probe.deps(deletions), args); err != nil || outcome != EvsShredWaiting {
			t.Fatalf("%s: a second early: %v %v", c, outcome, err)
		}
		fixture.clock.AdvanceTo(entryTime.Add(evsShredStartAfter))
		outcome, err := RunShred(fixture.ctx, host, probe.deps(deletions), args)
		state := fixture.repoObject(repoId).GetState()
		switch c {
		case "started":
			if err != nil || outcome != EvsShredWaiting || state != protocol.EvsRepoState_EVS_REPO_SHREDDING {
				t.Errorf("%s: %v %v %s", c, outcome, err, state)
			}
		case "restored":
			if err != nil || outcome != EvsShredRestored || state != protocol.EvsRepoState_EVS_REPO_DELETED {
				t.Errorf("%s: %v %v %s", c, outcome, err, state)
			}
		case "undated":
			if err == nil || state != protocol.EvsRepoState_EVS_REPO_DELETED {
				t.Errorf("%s: %v %v %s", c, outcome, err, state)
			}
		}
		if len(probe.groupCalls) != 0 {
			t.Errorf("%s: gkm shredded at the start: %v", c, probe.groupCalls)
		}
	}
}

// DELETE without now writes deleted{deletion, time, signer} only from a projection that names both: one that dates
// the RepoDelete but names no signer, neither its log nor its row (a row no fold writes), or one that does not date it,
// refuses STATEMENT_MISSING and leaves repo/ active; a RepoDelete{now} needs neither.
func TestRepoDeleteRefusesADeletionWithNoSigner(t *testing.T) {
	for _, c := range []struct {
		name     string
		deletion EvsRepoDeletionFacts
		ok       bool
	}{
		{name: "no signer", deletion: EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: time.UnixMilli(1)}},
		{name: "no time", deletion: EvsRepoDeletionFacts{DeletionId: testId("deletion"), SignerSidecarId: testId("signer")}},
		{name: "both", deletion: EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: time.UnixMilli(1), SignerSidecarId: testId("signer")}, ok: true},
		{name: "now with neither", deletion: EvsRepoDeletionFacts{DeletionId: testId("deletion"), Now: true}, ok: true},
	} {
		object := &protocol.EvsRepoObject{RepoId: testId("repo").Bytes(), State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Kind: protocol.RepoKind_REPO_KIND_GENERAL}
		next, err := decideDelete(&c.deletion, time.UnixMilli(2))(&EvsRepoRead{Object: object})
		var refusal *EvsRepoRefusal
		switch {
		case c.ok && (err != nil || next == nil):
			t.Errorf("%s: %v", c.name, err)
		case !c.ok && (!errors.As(err, &refusal) || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING || next != nil):
			t.Errorf("%s: %v %v", c.name, next, err)
		}
	}
}

// QD-798's reconciler from rows alone, the real state over a gate that keeps no log, as one whose log no longer keeps
// the RepoDelete's entry, or never held it: a device filed a RepoDelete three days ago and was killed before calling
// DELETE, so repo/ is still active when taskworker's walk comes. With the row's signer, the walk applies it as DELETE
// would, deleted{deletion_id, the row's time, the row's signer}, and queues the start, which at 7 d 10 min past the
// row's time moves repo/ to shredding with gkm untouched. A row without a signer, which no fold writes, is refused
// STATEMENT_MISSING as before the field: repo/ stays active, nothing is applied or queued, and the walk does not fail.
func TestAclEvsAuthStateReconcilesARepoDeleteFromItsRow(t *testing.T) {
	for _, signed := range []bool{true, false} {
		fixture := newEvsFixture(t)
		repoId, admin := testId("repo"), testId("sidecar-a")
		fixture.activeRepo(repoId, admin)
		entryTime := fixture.clock.Now().Add(-3 * 24 * time.Hour)
		deletionId := testId("deletion")
		row := &protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), DeletedAt: 9, DeletedTimeMs: entryTime.UnixMilli()}
		if signed {
			row.Signer = admin.Bytes()
		}
		states := sidecartest.NewFakeAclContractStates()
		rows := &protocol.AclRows{HasDocument: true, Repos: []*protocol.AclRepo{{
			RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Admins:   []*protocol.AclRepoAdminRow{{SidecarId: admin.Bytes(), Signer: admin.Bytes(), At: 2}},
			Deletion: row,
		}}}
		if err := states.Install(sidecar.Id(fixture.networkId), rows, sidecartest.NewFakeAclView()); err != nil {
			t.Fatal(err)
		}
		deletions := NewAclEvsAuthState(states, nil)
		host := fixture.host.ServiceHost()

		counts, err := RunReconcile(fixture.ctx, host, &EvsReconcileDeps{Deletions: deletions})
		object := fixture.repoObject(repoId)
		if !signed {
			if err != nil || counts.Applied != 0 || counts.Queued != 0 || counts.Failed != 0 || object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE ||
				len(fixture.shredRequests(repoId)) != 0 {
				t.Errorf("a row with no signer: %+v %v, repo/ %v", counts, err, object)
			}
			continue
		}
		if err != nil || counts.Applied != 1 || counts.Queued != 1 {
			t.Fatalf("the walk: %+v %v", counts, err)
		}
		if object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || !bytes.Equal(object.GetDeletionId(), deletionId.Bytes()) ||
			object.GetStateMs() != entryTime.UnixMilli() || !bytes.Equal(object.GetStateSigner(), admin.Bytes()) {
			t.Fatalf("repo/ %v", object)
		}
		if requests := fixture.shredRequests(repoId); len(requests) != 1 || !requests[0].RunAt.Equal(entryTime.Add(evsShredStartAfter)) {
			t.Fatalf("the start %v", requests)
		}

		// the start, when the queue runs it, from the same rows
		probe := &shredProbe{}
		fixture.clock.AdvanceTo(entryTime.Add(evsShredStartAfter))
		outcome, err := RunShred(fixture.ctx, host, probe.deps(deletions), EvsShredArgs(repoId, deletionId, false))
		if state := fixture.repoObject(repoId).GetState(); err != nil || outcome != EvsShredWaiting || state != protocol.EvsRepoState_EVS_REPO_SHREDDING ||
			len(probe.groupCalls) != 0 {
			t.Errorf("the start: %v %v %s, gkm %v", outcome, err, state, probe.groupCalls)
		}
	}
}

// The network's state for QD-880's cases: a general repo admin administers, writer writes and depositor deposits into
// by RepoGrant, with the deletion row given, nil for none.
func (self *aclAuthFixture) installGrantedRepo(admin sidecar.Id, writer sidecar.Id, depositor sidecar.Id, deletion *protocol.AclRepoDeletionRow) {
	self.t.Helper()
	rows := &protocol.AclRows{HasDocument: true, Repos: []*protocol.AclRepo{{
		RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
		Admins: []*protocol.AclRepoAdminRow{{SidecarId: admin.Bytes(), Signer: admin.Bytes(), At: 2}},
		Grants: []*protocol.AclRepoGrantRow{
			{Subject: writer.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER, Signer: admin.Bytes(), At: 3},
			{Subject: depositor.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT, Signer: admin.Bytes(), At: 4},
		},
		Deletion: deletion,
	}}}
	if err := self.states.Install(sidecar.Id(self.networkId), rows, self.view); err != nil {
		self.t.Fatal(err)
	}
}

// The repo scopes the exchange's table gives the sidecar in the installed state, each of §7.8's roles judged alone
// against EvsAccess as AclExchangeScopes judges it (acl_exchange_test.go runs the table itself on TEAM's log).
func (self *aclAuthFixture) mintedScopes(sidecarId sidecar.Id) []string {
	self.t.Helper()
	snapshot, status := self.states.State(sidecar.Id(self.networkId))
	if status != sidecar.AclGateLoaded {
		self.t.Fatalf("no state: %d", status)
	}
	rights := snapshot.Acl.EvsAccess(sidecar.AclSidecarSubject(sidecarId), self.repoId, sidecar.AclTokenAudienceEvs, self.clock.Now()).Rights
	scopes := []string{}
	for _, role := range []struct {
		name  string
		right sidecar.AclEvsRights
	}{{"deposit", sidecar.AclEvsDeposit}, {"r", sidecar.AclEvsRead}, {"rw", sidecar.AclEvsWrite}, {"admin", sidecar.AclEvsAdmin}} {
		if rights.Has(role.right) {
			scopes = append(scopes, repoScope(self.repoId, role.name))
		}
	}
	return scopes
}

// QD-880 through evs's guard under the real state, the rows holding the RepoDelete while repo/ is still active, as
// between a device's RepoDelete and its DELETE: the repo's standing admin is minted admin alone, and that token
// passes DELETE, with now and without, and no route that takes r, rw or deposit, each refused 403 SCOPE before it
// runs, as are the tokens it held before for r, rw and deposit; a writer and a depositor by RepoGrant are minted
// nothing, their live tokens are refused, and a token naming admin for one of them does not pass DELETE. Once the
// rows hold the RepoRestore the same admin's restore answers 200 and every right is back.
func TestAclEvsAuthStateHoldsADeletedReposAdminToDeleteAndRestore(t *testing.T) {
	for _, now := range []bool{false, true} {
		// the right sets of the read routes, the lease and the push
		readProbe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe-read", evsReadRights, false, false, false)
		readProbe.route.Name = "probe read"
		writeProbe := newProbeRoute(http.MethodPost, "/evs/v1/repos/{repo_id}/probe-write", sidecar.AclEvsWrite|sidecar.AclEvsAdmin, true, false, false)
		writeProbe.route.Name = "probe write"
		pushProbe := newProbeRoute(http.MethodPost, "/evs/v1/repos/{repo_id}/probe-push", sidecar.AclEvsWrite|sidecar.AclEvsDeposit|sidecar.AclEvsAdmin, true, false, false)
		pushProbe.route.Name = "probe push"
		fixture := newAclAuthFixture(t, readProbe.route, writeProbe.route, pushProbe.route)
		repoId, admin := fixture.repoId, fixture.device
		writer := fixture.view.AddDevice(fixture.view.AddMember(bridge.MemberRole_MEMBER_ROLE_MEMBER))
		depositor := fixture.view.AddDevice(fixture.view.AddMember(bridge.MemberRole_MEMBER_ROLE_MEMBER))
		repoPath := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId)
		role := func(name string) string { return repoScope(repoId, name) }
		probes := []struct {
			name   string
			method string
			path   string
			probe  *probeRoute
		}{
			{name: "read", method: http.MethodGet, path: repoPath + "/probe-read", probe: readProbe},
			{name: "lease", method: http.MethodPost, path: repoPath + "/probe-write", probe: writeProbe},
			{name: "push", method: http.MethodPost, path: repoPath + "/probe-push", probe: pushProbe},
		}

		fixture.installGrantedRepo(admin, writer, depositor, nil)
		if status := fixture.putRepo(repoId, admin); status != http.StatusOK {
			t.Fatalf("now %t: create: %d", now, status)
		}
		fixture.formGroup(repoId, testId("deleted repo group"), true)
		if status := fixture.lifecycle(http.MethodPost, repoId, "/activate", admin); status != http.StatusOK {
			t.Fatalf("now %t: activate: %d", now, status)
		}
		live := func(name string) {
			t.Helper()
			if scopes := fixture.mintedScopes(admin); !slices.Equal(scopes, []string{role("r"), role("rw"), role("admin")}) {
				t.Errorf("now %t, %s: the admin is minted %v", now, name, scopes)
			}
			if scopes := fixture.mintedScopes(writer); !slices.Equal(scopes, []string{role("r"), role("rw")}) {
				t.Errorf("now %t, %s: the writer is minted %v", now, name, scopes)
			}
			if scopes := fixture.mintedScopes(depositor); !slices.Equal(scopes, []string{role("deposit")}) {
				t.Errorf("now %t, %s: the depositor is minted %v", now, name, scopes)
			}
			for _, c := range probes {
				if code := fixture.serve(c.method, c.path, fixture.token(admin, role("admin")), nil).Code; code != http.StatusOK {
					t.Errorf("now %t, %s: the admin's %s: %d", now, name, c.name, code)
				}
			}
			if code := fixture.serve(http.MethodGet, repoPath+"/refs", fixture.token(admin, role("admin")), nil).Code; code != http.StatusOK {
				t.Errorf("now %t, %s: the admin's refs: %d", now, name, code)
			}
			if code := fixture.serve(http.MethodGet, repoPath, fixture.token(admin, role("r")), nil).Code; code != http.StatusOK {
				t.Errorf("now %t, %s: the admin's repo/: %d", now, name, code)
			}
			if code := fixture.serve(http.MethodPost, repoPath+"/probe-write", fixture.token(writer, role("rw")), nil).Code; code != http.StatusOK {
				t.Errorf("now %t, %s: the writer's lease: %d", now, name, code)
			}
			if code := fixture.serve(http.MethodPost, repoPath+"/probe-push", fixture.token(depositor, role("deposit")), nil).Code; code != http.StatusOK {
				t.Errorf("now %t, %s: the depositor's push: %d", now, name, code)
			}
		}
		live("live")

		deletionId := testId("acl deletion")
		deletion := &protocol.AclRepoDeletionRow{
			DeletionId: deletionId.Bytes(), Now: now, DeletedAt: 9, DeletedTimeMs: fixture.clock.Now().Add(-time.Minute).UnixMilli(), Signer: admin.Bytes(),
		}
		fixture.installGrantedRepo(admin, writer, depositor, deletion)
		if scopes := fixture.mintedScopes(admin); !slices.Equal(scopes, []string{role("admin")}) {
			t.Fatalf("now %t: the deleted repo's admin is minted %v", now, scopes)
		}
		if scopes := append(fixture.mintedScopes(writer), fixture.mintedScopes(depositor)...); len(scopes) != 0 {
			t.Fatalf("now %t: a deleted repo's writer and depositor are minted %v", now, scopes)
		}
		refused := func(name string) {
			t.Helper()
			calls := readProbe.calls + writeProbe.calls + pushProbe.calls
			for _, c := range probes {
				// the minted token, and the same sidecar's tokens from before the RepoDelete
				for _, scopes := range [][]string{{role("admin")}, {role("r"), role("rw"), role("admin")}, {role("rw")}, {role("r")}, {role("deposit")}} {
					recorder := fixture.serve(c.method, c.path, fixture.token(admin, scopes...), nil)
					if recorder.Code != http.StatusForbidden || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
						t.Errorf("now %t, %s: the admin's %s with %v: %d", now, name, c.name, scopes, recorder.Code)
					}
				}
			}
			for _, c := range []struct {
				name   string
				method string
				path   string
				token  string
			}{
				{name: "the admin's refs", method: http.MethodGet, path: repoPath + "/refs", token: fixture.token(admin, role("admin"))},
				{name: "the admin's log", method: http.MethodGet, path: repoPath + "/log", token: fixture.token(admin, role("admin"))},
				{name: "the admin's repo/", method: http.MethodGet, path: repoPath, token: fixture.token(admin, role("admin"))},
				{name: "the writer's read", method: http.MethodGet, path: repoPath + "/probe-read", token: fixture.token(writer, role("rw"))},
				{name: "the writer's lease", method: http.MethodPost, path: repoPath + "/probe-write", token: fixture.token(writer, role("rw"))},
				{name: "the depositor's push", method: http.MethodPost, path: repoPath + "/probe-push", token: fixture.token(depositor, role("deposit"))},
				{name: "the writer's DELETE", method: http.MethodDelete, path: repoPath, token: fixture.token(writer, role("admin"))},
				{name: "the writer's DELETE with now", method: http.MethodDelete, path: repoPath + "?now=1", token: fixture.token(writer, role("admin"))},
				{name: "the depositor's restore", method: http.MethodPost, path: repoPath + "/restore", token: fixture.token(depositor, role("admin"))},
			} {
				recorder := fixture.serve(c.method, c.path, c.token, nil)
				if recorder.Code != http.StatusForbidden || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
					t.Errorf("now %t, %s: %s: %d", now, name, c.name, recorder.Code)
				}
			}
			if after := readProbe.calls + writeProbe.calls + pushProbe.calls; after != calls {
				t.Errorf("now %t, %s: %d refused requests ran their routes", now, name, after-calls)
			}
		}
		refused("before DELETE")
		if state := fixture.repoObject(repoId).GetState(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
			t.Fatalf("now %t: repo/ %s before DELETE", now, state)
		}

		suffix, deletedState := "", protocol.EvsRepoState_EVS_REPO_DELETED
		if now {
			suffix, deletedState = "?now=1", protocol.EvsRepoState_EVS_REPO_SHREDDING
		}
		if code := fixture.serve(http.MethodDelete, repoPath+suffix, fixture.token(admin, fixture.mintedScopes(admin)...), nil).Code; code != http.StatusOK {
			t.Fatalf("now %t: the admin's DELETE: %d", now, code)
		}
		if object := fixture.repoObject(repoId); object.GetState() != deletedState || !bytes.Equal(object.GetDeletionId(), deletionId.Bytes()) {
			t.Fatalf("now %t: repo/ after DELETE: %v", now, object)
		}
		refused("after DELETE")
		if now {
			continue
		}

		// the admin's restore before the rows hold a RepoRestore passes the guard and finds no statement
		requireRefusal(t, fixture.serve(http.MethodPost, repoPath+"/restore", fixture.token(admin, role("admin")), nil),
			http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING)
		restored := proto.Clone(deletion).(*protocol.AclRepoDeletionRow)
		restored.RestoredAt = 10
		fixture.installGrantedRepo(admin, writer, depositor, restored)
		if code := fixture.serve(http.MethodPost, repoPath+"/restore", fixture.token(admin, role("admin")), nil).Code; code != http.StatusOK {
			t.Fatalf("the admin's restore: %d", code)
		}
		if state := fixture.repoObject(repoId).GetState(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
			t.Fatalf("repo/ %s after the restore", state)
		}
		live("restored")
	}
}

// One segment upload into the fixture's repo by sidecarId under a token of scopes, closure or not.
func (self *aclAuthFixture) upload(sidecarId sidecar.Id, segment []byte, closure bool, scopes ...string) *httptest.ResponseRecorder {
	segmentId := sha256.Sum256(segment)
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(self.repoId) + "/segments/" + hex.EncodeToString(segmentId[:]) + "?push=" + sidecar.EvsKeyId(testId("push"))
	if closure {
		path += "&closure=1"
	}
	return self.serve(http.MethodPut, path, self.token(sidecarId, scopes...), segment)
}

// Whether seg/ holds segment under the fixture's repo.
func (self *aclAuthFixture) stored(segment []byte) bool {
	segmentId := sha256.Sum256(segment)
	return self.object("seg-1", SegmentKey(self.repoId, segmentId)) != nil
}

// The fixture's repo created, its group formed and activated under installGrantedRepo's live rows: the repo's admin
// is the fixture's device, the writer and depositor new devices of other members.
func (self *aclAuthFixture) activeGrantedRepo() (admin sidecar.Id, writer sidecar.Id, depositor sidecar.Id) {
	self.t.Helper()
	admin = self.device
	writer = self.view.AddDevice(self.view.AddMember(bridge.MemberRole_MEMBER_ROLE_MEMBER))
	depositor = self.view.AddDevice(self.view.AddMember(bridge.MemberRole_MEMBER_ROLE_MEMBER))
	self.installGrantedRepo(admin, writer, depositor, nil)
	if status := self.putRepo(self.repoId, admin); status != http.StatusOK {
		self.t.Fatalf("create: %d", status)
	}
	self.formGroup(self.repoId, testId("reseeded group"), true)
	if status := self.lifecycle(http.MethodPost, self.repoId, "/activate", admin); status != http.StatusOK {
		self.t.Fatalf("activate: %d", status)
	}
	return admin, writer, depositor
}

// A recovery's first re-seed call by admin, which places repo/ deleted under the projection's restorable RepoDelete
// before it takes anything (§11.13's repos rule; reseed.go's reseedRepo), whatever it carries: here no statement, so
// it takes nothing and is refused 400 INVALID.
func (self *aclAuthFixture) reseedPlacesDeleted(admin sidecar.Id, deletionId sidecar.Id) {
	self.t.Helper()
	requireRefusal(self.t, self.serve(http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(self.repoId)+"/reseed", self.token(admin, repoScope(self.repoId, "admin")), nil),
		http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	if object := self.repoObject(self.repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || !bytes.Equal(object.GetDeletionId(), deletionId.Bytes()) {
		self.t.Fatalf("repo/ after the re-seed's call: %v", object)
	}
}

// QD-977 under the real state: §11.12's re-seed exception reaches PUT .../segments. A live repo's uploads are as they
// were, the reseed gate off or on. Once the rows hold an unrestored RepoDelete the repo's standing admin holds admin
// alone (QD-880), which passes the segment route only marked, by the exception, while the gate is on, and the route
// takes a marked upload only through the exception: refused 403 SCOPE while repo/ is still active, then, once a
// re-seed's call has placed repo/ deleted under the RepoDelete, taken, under its minted token and the one it held
// before the RepoDelete; refused 403 SCOPE with the gate off, from a token without admin, as a closure upload, past
// the restore window, for a RepoDelete with now, one its row does not date and another RepoDelete than repo/ names,
// each writing nothing. The writer and the depositor upload nothing while the repo is deleted. Once the rows hold the
// RepoRestore the admin is honored whole again and refused REPO_DELETED until restore, after which every upload is back.
func TestAclEvsAuthStateTakesADeletedReposSegmentsFromItsAdminInARecovery(t *testing.T) {
	fixture := newAclAuthFixtureWith(t, true)
	repoId := fixture.repoId
	admin, writer, depositor := fixture.activeGrantedRepo()
	role := func(name string) string { return repoScope(repoId, name) }
	fill := byte(0)
	type upload struct {
		name      string
		sidecarId sidecar.Id
		scopes    []string
		closure   bool
	}
	send := func(c upload) ([]byte, *httptest.ResponseRecorder) {
		fill += 1
		segment := testSegment(repoId, 4096, fill)
		return segment, fixture.upload(c.sidecarId, segment, c.closure, c.scopes...)
	}
	taken := func(name string, c upload) {
		t.Helper()
		segment, recorder := send(c)
		if recorder.Code != http.StatusOK || !fixture.stored(segment) {
			t.Errorf("%s: %s: %d", name, c.name, recorder.Code)
		}
	}
	refused := func(name string, c upload, status int, code protocol.EvsRefusalCode) {
		t.Helper()
		segment, recorder := send(c)
		if recorder.Code != status || refusalOf(t, recorder).GetCode() != code {
			t.Errorf("%s: %s: %d %s", name, c.name, recorder.Code, refusalOf(t, recorder).GetCode())
		}
		if fixture.stored(segment) {
			t.Errorf("%s: %s: a refused upload wrote", name, c.name)
		}
	}
	scope := protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE
	adminUpload := upload{name: "the admin's", sidecarId: admin, scopes: []string{role("admin")}}
	everyRole := []upload{
		adminUpload,
		{name: "the admin's closure", sidecarId: admin, scopes: []string{role("admin")}, closure: true},
		{name: "the writer's", sidecarId: writer, scopes: []string{role("rw")}},
		{name: "the depositor's", sidecarId: depositor, scopes: []string{role("deposit")}},
	}
	withoutAdmin := []upload{
		{name: "the admin's rw", sidecarId: admin, scopes: []string{role("rw")}},
		{name: "the admin's r and rw", sidecarId: admin, scopes: []string{role("r"), role("rw")}},
		{name: "the admin's deposit", sidecarId: admin, scopes: []string{role("deposit")}},
		{name: "the writer's", sidecarId: writer, scopes: []string{role("rw")}},
		{name: "the writer's naming admin", sidecarId: writer, scopes: []string{role("admin")}},
		{name: "the depositor's", sidecarId: depositor, scopes: []string{role("deposit")}},
	}

	for _, reseed := range []bool{false, true} {
		fixture.setReseed(reseed)
		for _, c := range everyRole {
			taken(fmt.Sprintf("live, reseed %t", reseed), c)
		}
	}

	// the RepoDelete reaches the gate's state while repo/ is still active
	deletionId := testId("reseed deletion")
	entryTime := fixture.clock.Now().Add(-3 * 24 * time.Hour)
	install := func(edit func(row *protocol.AclRepoDeletionRow)) {
		t.Helper()
		row := &protocol.AclRepoDeletionRow{DeletionId: deletionId.Bytes(), DeletedAt: 9, DeletedTimeMs: entryTime.UnixMilli(), Signer: admin.Bytes()}
		if edit != nil {
			edit(row)
		}
		fixture.installGrantedRepo(admin, writer, depositor, row)
	}
	install(nil)
	if scopes := fixture.mintedScopes(admin); !slices.Equal(scopes, []string{role("admin")}) {
		t.Fatalf("the deleted repo's admin is minted %v", scopes)
	}
	fixture.setReseed(false)
	refused("active, the gate off", adminUpload, http.StatusForbidden, scope)
	fixture.setReseed(true)
	refused("active", adminUpload, http.StatusForbidden, scope)
	for _, c := range withoutAdmin {
		refused("active", c, http.StatusForbidden, scope)
	}
	if state := fixture.repoObject(repoId).GetState(); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Fatalf("repo/ %s before the re-seed", state)
	}

	fixture.reseedPlacesDeleted(admin, deletionId)
	taken("deleted", adminUpload)
	taken("deleted", upload{name: "the admin's token from before", sidecarId: admin, scopes: []string{role("r"), role("rw"), role("admin")}})
	refused("deleted", upload{name: "the admin's closure", sidecarId: admin, scopes: []string{role("admin")}, closure: true}, http.StatusForbidden, scope)
	for _, c := range withoutAdmin {
		refused("deleted", c, http.StatusForbidden, scope)
	}
	fixture.setReseed(false)
	refused("deleted, the gate off", adminUpload, http.StatusForbidden, scope)
	fixture.setReseed(true)
	for _, c := range []struct {
		name string
		edit func(row *protocol.AclRepoDeletionRow)
	}{
		{name: "past the restore window", edit: func(row *protocol.AclRepoDeletionRow) {
			row.DeletedTimeMs = fixture.clock.Now().Add(-fixture.engine.settings.ReseedRestoreWindow).UnixMilli()
		}},
		{name: "a RepoDelete with now", edit: func(row *protocol.AclRepoDeletionRow) { row.Now = true }},
		{name: "a RepoDelete its row does not date", edit: func(row *protocol.AclRepoDeletionRow) { row.DeletedTimeMs = 0 }},
		{name: "another RepoDelete than repo/ names", edit: func(row *protocol.AclRepoDeletionRow) { row.DeletionId = testId("another deletion").Bytes() }},
	} {
		install(c.edit)
		refused(c.name, adminUpload, http.StatusForbidden, scope)
	}
	install(nil)
	taken("deleted again", adminUpload)

	// the RepoRestore in the rows: the admin is honored whole again, and repo/ refuses until restore
	install(func(row *protocol.AclRepoDeletionRow) { row.RestoredAt = 10 })
	refused("restored in the rows", adminUpload, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	if code := fixture.lifecycle(http.MethodPost, repoId, "/restore", admin); code != http.StatusOK {
		t.Fatalf("the admin's restore: %d", code)
	}
	for _, reseed := range []bool{true, false} {
		fixture.setReseed(reseed)
		for _, c := range everyRole {
			taken(fmt.Sprintf("restored, reseed %t", reseed), c)
		}
	}
}

// QD-977 keeps QD-880's closed reads and writes in a recovery: with the reseed gate on, a deleted repo's standing
// admin passes none of the table's routes that take a weaker right than admin, the segment route aside, each refused
// 403 SCOPE at the guard (its evs-7 line naming no repo) under the token it is minted and those it held before, while
// repo/ is still active and once a re-seed's call has placed it deleted; and every route that takes admin alone passes
// the guard for it (its line naming the repo), the gate on or off, moving repo/ nowhere.
func TestAclEvsAuthStateHoldsADeletedReposAdminToTheAdminRoutesInARecovery(t *testing.T) {
	fixture := newAclAuthFixtureWith(t, true)
	repoId := fixture.repoId
	admin, writer, depositor := fixture.activeGrantedRepo()
	role := func(name string) string { return repoScope(repoId, name) }
	deletionId := testId("sweep deletion")
	fixture.installGrantedRepo(admin, writer, depositor, &protocol.AclRepoDeletionRow{
		DeletionId: deletionId.Bytes(), DeletedAt: 9, DeletedTimeMs: fixture.clock.Now().Add(-time.Hour).UnixMilli(), Signer: admin.Bytes(),
	})
	fixture.setReseed(true)

	// a route's path for the repo, with well-formed values for its other path values
	pathOf := func(route *EvsRoute) string {
		t.Helper()
		path := strings.ReplaceAll(route.Pattern, "{"+evsRepoIdPathValue+"}", sidecar.EvsKeyId(repoId))
		path = strings.ReplaceAll(path, "{"+evsSegmentPathValue+"}", strings.Repeat("ab", 32))
		path = strings.ReplaceAll(path, "{push_id}", sidecar.EvsKeyId(testId("push")))
		path = strings.ReplaceAll(path, "{part}", "1")
		path = strings.ReplaceAll(path, "{"+evsDropPreviewIdPathValue+"}", sidecar.EvsKeyId(testId("preview")))
		if strings.Contains(path, "{") {
			t.Fatalf("a path value this test does not fill: %s", route.Pattern)
		}
		return path
	}
	weakerRoutes, adminRoutes := []*EvsRoute{}, []*EvsRoute{}
	for _, route := range fixture.engine.Routes() {
		switch {
		case route.Rights == 0 || route.ReseedException:
		case route.Rights == sidecar.AclEvsAdmin:
			adminRoutes = append(adminRoutes, route)
		default:
			weakerRoutes = append(weakerRoutes, route)
		}
	}
	if len(weakerRoutes) == 0 || len(adminRoutes) == 0 {
		t.Fatalf("%d routes take a weaker right and %d admin alone", len(weakerRoutes), len(adminRoutes))
	}
	refused := func(name string) {
		t.Helper()
		for _, route := range weakerRoutes {
			for _, scopes := range [][]string{{role("admin")}, {role("r"), role("rw"), role("admin")}, {role("rw")}, {role("r")}, {role("deposit")}} {
				recorder := fixture.serve(route.Method, pathOf(route), fixture.token(admin, scopes...), nil)
				if recorder.Code != http.StatusForbidden || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE ||
					fixture.serviceLog.last().RepoId != (sidecar.Id{}) {
					t.Errorf("%s: the admin's %s %s with %v: %d", name, route.Method, route.Pattern, scopes, recorder.Code)
				}
			}
		}
	}
	refused("active")
	fixture.reseedPlacesDeleted(admin, deletionId)
	refused("deleted")
	for _, reseed := range []bool{true, false} {
		fixture.setReseed(reseed)
		for _, route := range adminRoutes {
			recorder := fixture.serve(route.Method, pathOf(route), fixture.token(admin, role("admin")), nil)
			if fixture.serviceLog.last().RepoId != repoId {
				t.Errorf("reseed %t: the admin's %s %s stopped at the guard: %d", reseed, route.Method, route.Pattern, recorder.Code)
			}
		}
	}
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || !bytes.Equal(object.GetDeletionId(), deletionId.Bytes()) {
		t.Errorf("repo/ after the admin routes: %v", object)
	}
}
