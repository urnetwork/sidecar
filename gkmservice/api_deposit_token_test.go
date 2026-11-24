// QD-1229: api's own deposit token at gkm, the one §14.8's report intake reads a network mail repo's drop key under
// (§7.8's self-issued token, §10.14's drop-key row): aud gkm, one repo:<repo_id>:deposit scope, the asked network, a
// client of its own, and no ur_sidecar_id or member. The guard passes it at GET /gkm/repos/<id>/drop-key alone and
// asks no standing of it; AclGkmAuthState.HonorScope honors its deposit on a repo the network's newest verified state
// holds, standing, that takes deposits (D-KEYS-17), answers Unknown while that state is not loaded, and Denied
// otherwise.
//
// The guard's rows run over the matrix's world (auth_test.go) and a group KF1 created (groups_test.go), with the fake
// state answering every sidecar's token and the real AclGkmAuthState answering api's, over a gate holding hand-made
// loaded states of the rows alone.

package gkmservice

import (
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The drop-key route's pattern, the one route api's token reaches.
const gkmDropKeyPattern = "GET /gkm/repos/{repo_id}/drop-key"

// A gate holding hand-made loaded states by network, and the cache's unknown for a network it holds none of: what
// AclGkmAuthState reads, recording each load it is asked for and how many scope questions it was asked.
type loadedGkmAclGate struct {
	stateLock  sync.Mutex
	snapshots  map[sidecar.Id]*sidecar.AclGateSnapshot
	changedIds []sidecar.Id
	honorCount int
}

func newLoadedGkmAclGate() *loadedGkmAclGate {
	return &loadedGkmAclGate{snapshots: map[sidecar.Id]*sidecar.AclGateSnapshot{}}
}

// Builds a network's state from repos, with no admission, atom or rule, and installs it in place of any before. Its
// config part is a zero ConfigState: nothing api's token reaches reads it.
func (self *loadedGkmAclGate) install(t *testing.T, networkId sidecar.Id, repos ...*protocol.AclRepo) {
	t.Helper()
	view := sidecartest.NewFakeAclView()
	acl, err := sidecar.NewAclState(&protocol.AclRows{Repos: repos}, view)
	if err != nil {
		t.Fatal(err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.snapshots[networkId] = &sidecar.AclGateSnapshot{Pin: view.Pin(), Config: &sidecar.ConfigState{}, Acl: acl}
}

func (self *loadedGkmAclGate) State(networkId sidecar.Id) (*sidecar.AclGateSnapshot, sidecar.AclGateStatus) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	snapshot := self.snapshots[networkId]
	if snapshot == nil {
		return nil, sidecar.AclGateUnknown
	}
	return snapshot, sidecar.AclGateLoaded
}

func (self *loadedGkmAclGate) Changed(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.changedIds = append(self.changedIds, networkId)
}

// The cache's own check over the installed state, which asks for a network it holds none of.
func (self *loadedGkmAclGate) HonorScope(networkId sidecar.Id, subjectId sidecar.Id, repoId sidecar.Id, scope sidecar.AclEvsRights, audience sidecar.AclTokenAudience, now time.Time) sidecar.AclScopeAnswer {
	snapshot := func() *sidecar.AclGateSnapshot {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.honorCount += 1
		return self.snapshots[networkId]
	}()
	if snapshot == nil {
		self.Changed(networkId)
		return sidecar.AclScopeUnknown
	}
	return sidecar.AclHonorScope(snapshot.Acl, subjectId, repoId, scope, audience, now)
}

// The networks a load was asked for so far, in order, and how many scope questions the gate was asked.
func (self *loadedGkmAclGate) asked() ([]sidecar.Id, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.changedIds), self.honorCount
}

// A repo's folded row as a RepoCreate of kind, marked inbox, leaves it: an owner-bound kind's naming its owner.
func apiDepositRepo(repoId sidecar.Id, kind protocol.RepoKind, inbox protocol.RepoInbox) *protocol.AclRepo {
	repo := &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: kind, Inbox: inbox}
	switch kind {
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET:
		repo.OwnerMemberId = testId("member-owner").Bytes()
	}
	return repo
}

// The row with a RepoDelete at position 7, and when restoredAt is not 0 its RepoRestore there.
func apiDepositDeleted(repo *protocol.AclRepo, restoredAt uint64) *protocol.AclRepo {
	deleted := proto.Clone(repo).(*protocol.AclRepo)
	deleted.Deletion = &protocol.AclRepoDeletionRow{
		DeletionId:    testId("deletion-1").Bytes(),
		DeletedAt:     7,
		RestoredAt:    restoredAt,
		DeletedTimeMs: 1790000000000,
		Signer:        testId("sc-repo-admin").Bytes(),
	}
	return deleted
}

// api's own principal for gkm as oauth.MintServiceToken mints it for the report intake: aud gkm, scopes, networkId, a
// client of its own, and no ur_sidecar_id; memberId names a member, which api's never does, for the shapes refused.
func apiDepositPrincipal(networkId sidecar.Id, memberId *sidecar.Id, issuedAt time.Time, scopes ...string) *sidecar.Principal {
	principal := &sidecar.Principal{
		NetworkId: connect.Id(networkId),
		ClientId:  connect.Id(testId("client-api")),
		Audience:  GkmAudience,
		Scopes:    scopes,
		IssuedAt:  issuedAt,
		ExpiresAt: issuedAt.Add(15 * time.Minute),
	}
	if memberId != nil {
		connectMemberId := connect.Id(*memberId)
		principal.MemberId = &connectMemberId
	}
	return principal
}

// apiDepositPrincipal's token, issued by the fixture's authenticator.
func apiDepositToken(fixture *gkmFixture, networkId sidecar.Id, memberId *sidecar.Id, scopes ...string) string {
	return fixture.host.Authenticator.Issue(apiDepositPrincipal(networkId, memberId, fixture.clock.Now(), scopes...))
}

// The fake state, with a token naming no sidecar judged by the real AclGkmAuthState over a gate, counting the scope
// questions asked of such a token and each standing, which the guard must never ask of one.
type apiDepositGkmAuthState struct {
	*fakeGkmAuthState
	acl *AclGkmAuthState

	stateLock     sync.Mutex
	honorCount    int
	standingCount int
}

// Has the fixture's engine judge a token naming no sidecar by the real state over gate, from its next request on: the
// engine reads its deps' AuthState per request, on the request's own goroutine.
func useApiDepositState(fixture *gkmFixture, gate *loadedGkmAclGate) *apiDepositGkmAuthState {
	state := &apiDepositGkmAuthState{fakeGkmAuthState: fixture.auth, acl: NewAclGkmAuthState(gate, nil, fixture.clock)}
	fixture.deps.AuthState = state
	return state
}

func (self *apiDepositGkmAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) GkmAuthAnswer {
	if principal.SidecarId == nil {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.honorCount += 1
		}()
		return self.acl.HonorScope(principal, repoId, rights, now)
	}
	return self.fakeGkmAuthState.HonorScope(principal, repoId, rights, now)
}

// The scope questions asked of a token naming no sidecar so far.
func (self *apiDepositGkmAuthState) unboundHonorCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.honorCount
}

func (self *apiDepositGkmAuthState) Sidecar(principal *sidecar.Principal, sidecarId sidecar.Id) (*GkmSidecarFacts, GkmAuthAnswer) {
	if principal.SidecarId == nil {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.standingCount += 1
		}()
	}
	return self.fakeGkmAuthState.Sidecar(principal, sidecarId)
}

// The standings asked of a token naming no sidecar so far.
func (self *apiDepositGkmAuthState) unboundStandingCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.standingCount
}

// The scope matrix's row for api's deposit token (§22.5's matrix; QD-1229): over the matrix's world, its repo a
// general repo marked the network's admin inbox, a Team's network mail key repo, api's token reaches the drop-key
// route's handler holding deposit alone, and every other route of the table refuses it 403 before its handler. Neither
// a standing nor the gate's scope check is asked of it: it names no sidecar.
func TestGkmApiDepositTokenReachesTheDropKeyRouteAlone(t *testing.T) {
	matrix := newGkmMatrix(t)
	fixture := matrix.fixture
	networkId := sidecar.Id(fixture.networkId)
	gate := newLoadedGkmAclGate()
	gate.install(t, networkId, apiDepositRepo(matrix.repoId, protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoInbox_REPO_INBOX_ADMIN))
	state := useApiDepositState(fixture, gate)
	token := apiDepositToken(fixture, networkId, nil, repoScope(matrix.repoId, "deposit"))
	for _, route := range gkmRoutes {
		servedBefore := matrix.served[route.Pattern]
		method, path := matrix.path(route.Pattern)
		recorder := fixture.serve(method, path, token, nil)
		servedCount := matrix.served[route.Pattern] - servedBefore
		if route.Pattern == gkmDropKeyPattern {
			if recorder.Code != http.StatusOK || servedCount != 1 || matrix.servedRights[route.Pattern] != sidecar.AclEvsDeposit {
				t.Errorf("%s by api's deposit token: %d, served %d times holding %04b, want 200 once holding deposit",
					route.Pattern, recorder.Code, servedCount, matrix.servedRights[route.Pattern])
			}
			continue
		}
		if recorder.Code != http.StatusForbidden || servedCount != 0 {
			t.Errorf("%s by api's deposit token: %d, served %d times, want 403 unserved", route.Pattern, recorder.Code, servedCount)
		}
	}
	if count := state.unboundStandingCount(); count != 0 {
		t.Errorf("a standing asked %d times of a token naming no sidecar", count)
	}
	// the state was asked at the drop key alone, and answered it without the gate's scope check
	if count := state.unboundHonorCount(); count != 1 {
		t.Errorf("the state asked %d times of api's token, want once", count)
	}
	if _, honorCount := gate.asked(); honorCount != 0 {
		t.Errorf("the gate's scope check asked %d times of a token naming no sidecar", honorCount)
	}
}

// Only the token api mints passes as one (QD-1229): at the drop-key route a token naming no sidecar is refused 403
// before its handler, and before the state is asked, when it holds r, rw or admin beside its deposit, or a recovery
// scope, or names a member as an unadmitted client's token does, or holds no scope that parses, or a deposit scope on
// another repo alone, which reaches only the repo it names; another network's token is asked of that network's state,
// which refuses a repo it does not hold.
func TestGkmApiDepositTokenOfAnotherShapeIsRefused(t *testing.T) {
	matrix := newGkmMatrix(t)
	fixture := matrix.fixture
	networkId := sidecar.Id(fixture.networkId)
	otherRepoId := testId("repo-other")
	fixture.placeRepo(otherRepoId, "meta-1", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	gate := newLoadedGkmAclGate()
	gate.install(t, networkId,
		apiDepositRepo(matrix.repoId, protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoInbox_REPO_INBOX_ADMIN),
		apiDepositRepo(otherRepoId, protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoInbox_REPO_INBOX_GROUP))
	state := useApiDepositState(fixture, gate)
	deposit := repoScope(matrix.repoId, "deposit")
	memberId := matrix.memberId
	_, path := matrix.path(gkmDropKeyPattern)
	refusals := []struct {
		name  string
		token string
	}{
		{name: "deposit beside r", token: apiDepositToken(fixture, networkId, nil, deposit, repoScope(matrix.repoId, "r"))},
		{name: "deposit beside another repo's rw", token: apiDepositToken(fixture, networkId, nil, deposit, repoScope(otherRepoId, "rw"))},
		{name: "deposit beside admin", token: apiDepositToken(fixture, networkId, nil, deposit, repoScope(matrix.repoId, "admin"))},
		{name: "deposit beside a recovery scope", token: apiDepositToken(fixture, networkId, nil, deposit, "recovery:"+memberId.String())},
		{name: "deposit naming a member", token: apiDepositToken(fixture, networkId, &memberId, deposit)},
		{name: "no scope", token: apiDepositToken(fixture, networkId, nil)},
		{name: "a scope that does not parse", token: apiDepositToken(fixture, networkId, nil, "repo:"+matrix.repoId.String()+":drop")},
		{name: "deposit on another repo alone", token: apiDepositToken(fixture, networkId, nil, repoScope(otherRepoId, "deposit"))},
	}
	for _, refusal := range refusals {
		servedBefore := matrix.served[gkmDropKeyPattern]
		honorBefore := state.unboundHonorCount()
		recorder := fixture.serve(http.MethodGet, path, refusal.token, nil)
		switch {
		case recorder.Code != http.StatusForbidden || matrix.served[gkmDropKeyPattern] != servedBefore:
			t.Errorf("%s: %d, want 403 unserved", refusal.name, recorder.Code)
		case state.unboundHonorCount() != honorBefore:
			t.Errorf("%s: refused only once the state was asked", refusal.name)
		}
	}
	// the other repo's deposit token reaches the other repo's drop key
	otherPath := "/gkm/repos/" + sidecar.EvsKeyId(otherRepoId) + "/drop-key"
	otherToken := apiDepositToken(fixture, networkId, nil, repoScope(otherRepoId, "deposit"))
	if recorder := fixture.serve(http.MethodGet, otherPath, otherToken, nil); recorder.Code != http.StatusOK {
		t.Errorf("the other repo's drop key under its own deposit token: %d", recorder.Code)
	}
	// a token of another network gkm admits, whose state holds no such repo
	otherNetworkId := testId("network-b")
	fixture.host.Gates.OpenService(sidecar.ServiceGateGkm, fixture.networkId, connect.Id(otherNetworkId))
	gate.install(t, otherNetworkId, apiDepositRepo(testId("repo-b"), protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoInbox_REPO_INBOX_NONE))
	servedBefore := matrix.served[gkmDropKeyPattern]
	honorBefore := state.unboundHonorCount()
	recorder := fixture.serve(http.MethodGet, path, apiDepositToken(fixture, otherNetworkId, nil, deposit), nil)
	if recorder.Code != http.StatusForbidden || matrix.served[gkmDropKeyPattern] != servedBefore || state.unboundHonorCount() != honorBefore+1 {
		t.Errorf("another network's token for a repo its state does not hold: %d, the state asked %d times",
			recorder.Code, state.unboundHonorCount()-honorBefore)
	}
}

// Through the guard, the token's network's newest verified state decides api's token (QD-1229): while the state is
// not loaded the read answers 503 with Retry-After and the gate is asked to load it; a repo the state holds that takes
// no deposits, a general repo not marked an inbox, is refused 403 unserved, as are a repo the state does not hold and
// the inbox once its RepoDelete stands; the inbox standing, the read is served.
func TestGkmApiDepositTokenIsJudgedByTheNetworksState(t *testing.T) {
	matrix := newGkmMatrix(t)
	fixture := matrix.fixture
	networkId := sidecar.Id(fixture.networkId)
	gate := newLoadedGkmAclGate()
	useApiDepositState(fixture, gate)
	token := apiDepositToken(fixture, networkId, nil, repoScope(matrix.repoId, "deposit"))
	_, path := matrix.path(gkmDropKeyPattern)
	inbox := apiDepositRepo(matrix.repoId, protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoInbox_REPO_INBOX_ADMIN)

	servedBefore := matrix.served[gkmDropKeyPattern]
	recorder := fixture.serve(http.MethodGet, path, token, nil)
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" || matrix.served[gkmDropKeyPattern] != servedBefore {
		t.Errorf("a network whose state is not loaded: %d, Retry-After %q", recorder.Code, recorder.Header().Get("Retry-After"))
	}
	if changedIds, _ := gate.asked(); !slices.Contains(changedIds, networkId) {
		t.Errorf("the gate was not asked to load the network: %v", changedIds)
	}

	states := []struct {
		name  string
		repos []*protocol.AclRepo
		want  int
	}{
		{name: "a general repo not marked an inbox", repos: []*protocol.AclRepo{apiDepositRepo(matrix.repoId, protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoInbox_REPO_INBOX_NONE)}, want: http.StatusForbidden},
		{name: "a state that does not hold the repo", repos: []*protocol.AclRepo{apiDepositRepo(testId("repo-unrelated"), protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoInbox_REPO_INBOX_NONE)}, want: http.StatusForbidden},
		{name: "the admin inbox", repos: []*protocol.AclRepo{inbox}, want: http.StatusOK},
		{name: "the admin inbox under a RepoDelete", repos: []*protocol.AclRepo{apiDepositDeleted(inbox, 0)}, want: http.StatusForbidden},
		{name: "the admin inbox restored", repos: []*protocol.AclRepo{apiDepositDeleted(inbox, 9)}, want: http.StatusOK},
	}
	for _, state := range states {
		gate.install(t, networkId, state.repos...)
		servedBefore := matrix.served[gkmDropKeyPattern]
		recorder := fixture.serve(http.MethodGet, path, token, nil)
		servedCount := matrix.served[gkmDropKeyPattern] - servedBefore
		switch {
		case recorder.Code != state.want:
			t.Errorf("%s: %d, want %d", state.name, recorder.Code, state.want)
		case state.want == http.StatusOK && servedCount != 1:
			t.Errorf("%s: served %d times", state.name, servedCount)
		case state.want != http.StatusOK && servedCount != 0:
			t.Errorf("%s: a refused read reached the handler", state.name)
		}
	}
}

// AclGkmAuthState.HonorScope for a token naming no sidecar (QD-1229): deposit alone is Allowed on every repo the state
// holds, standing, of a kind that takes deposits, the vault, the mailbox, the secret store and the team record, and on
// a general repo marked a group or admin inbox (D-KEYS-17); Denied on a repo of any other kind, a general repo not so
// marked, one whose RepoDelete stands unrestored, and one the state does not hold. Every right set but deposit alone,
// and a token naming a member, are Denied on every repo, and the gate's scope check, which needs a subject, is never
// asked of such a token. A network whose state is not loaded answers Unknown and is asked for, and with no gate the
// answer is Unknown; a sidecar's token is still the gate's to answer.
func TestAclGkmAuthStateHonorsApiDepositOnReposThatTakeDeposits(t *testing.T) {
	networkId := testId("network-a")
	now := time.UnixMilli(1790000000000)
	mailbox := apiDepositRepo(testId("repo-mailbox"), protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoInbox_REPO_INBOX_NONE)
	cases := []struct {
		name string
		repo *protocol.AclRepo
		want GkmAuthAnswer
	}{
		{name: "a vault", repo: apiDepositRepo(testId("repo-vault"), protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoInbox_REPO_INBOX_NONE), want: GkmAuthAllowed},
		{name: "a mailbox", repo: mailbox, want: GkmAuthAllowed},
		{name: "a secret store", repo: apiDepositRepo(testId("repo-secret"), protocol.RepoKind_REPO_KIND_SECRET, protocol.RepoInbox_REPO_INBOX_NONE), want: GkmAuthAllowed},
		{name: "the team record", repo: apiDepositRepo(testId("repo-team-rec"), protocol.RepoKind_REPO_KIND_TEAM_RECORD, protocol.RepoInbox_REPO_INBOX_NONE), want: GkmAuthAllowed},
		{name: "a group inbox", repo: apiDepositRepo(testId("repo-group-inbox"), protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoInbox_REPO_INBOX_GROUP), want: GkmAuthAllowed},
		{name: "the admin inbox", repo: apiDepositRepo(testId("repo-admin-inbox"), protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoInbox_REPO_INBOX_ADMIN), want: GkmAuthAllowed},
		{name: "a restored mailbox", repo: apiDepositDeleted(apiDepositRepo(testId("repo-restored"), protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoInbox_REPO_INBOX_NONE), 9), want: GkmAuthAllowed},
		{name: "a general repo", repo: apiDepositRepo(testId("repo-general"), protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoInbox_REPO_INBOX_NONE), want: GkmAuthDenied},
		{name: "a record repo", repo: apiDepositRepo(testId("repo-record"), protocol.RepoKind_REPO_KIND_RECORD, protocol.RepoInbox_REPO_INBOX_NONE), want: GkmAuthDenied},
		{name: "a config repo", repo: apiDepositRepo(testId("repo-config"), protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoInbox_REPO_INBOX_NONE), want: GkmAuthDenied},
		{name: "the directory", repo: apiDepositRepo(testId("repo-directory"), protocol.RepoKind_REPO_KIND_DIRECTORY, protocol.RepoInbox_REPO_INBOX_NONE), want: GkmAuthDenied},
		{name: "the network's mailcfg", repo: apiDepositRepo(testId("repo-mailcfg"), protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoInbox_REPO_INBOX_NONE), want: GkmAuthDenied},
		{name: "a deleted mailbox", repo: apiDepositDeleted(apiDepositRepo(testId("repo-deleted"), protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoInbox_REPO_INBOX_NONE), 0), want: GkmAuthDenied},
	}
	repos := []*protocol.AclRepo{}
	for _, c := range cases {
		repos = append(repos, c.repo)
	}
	gate := newLoadedGkmAclGate()
	gate.install(t, networkId, repos...)
	state := NewAclGkmAuthState(gate, nil, nil)
	principal := apiDepositPrincipal(networkId, nil, now)
	memberId := testId("member-m")
	memberPrincipal := apiDepositPrincipal(networkId, &memberId, now)
	others := []sidecar.AclEvsRights{
		sidecar.AclEvsRead,
		sidecar.AclEvsWrite | sidecar.AclEvsRead,
		sidecar.AclEvsAdmin | sidecar.AclEvsWrite | sidecar.AclEvsRead,
		sidecar.AclEvsAdmin,
		sidecar.AclEvsDeposit | sidecar.AclEvsRead,
		0,
	}
	for _, c := range cases {
		repoId, err := sidecar.IdFromBytes(c.repo.GetRepoId())
		if err != nil {
			t.Fatal(err)
		}
		if answer := state.HonorScope(principal, repoId, sidecar.AclEvsDeposit, now); answer != c.want {
			t.Errorf("%s: deposit answered %d, want %d", c.name, answer, c.want)
		}
		for _, rights := range others {
			if answer := state.HonorScope(principal, repoId, rights, now); answer != GkmAuthDenied {
				t.Errorf("%s: %04b answered %d, want denied", c.name, rights, answer)
			}
		}
		if answer := state.HonorScope(memberPrincipal, repoId, sidecar.AclEvsDeposit, now); answer != GkmAuthDenied {
			t.Errorf("%s: a token naming a member answered %d, want denied", c.name, answer)
		}
	}
	if answer := state.HonorScope(principal, testId("repo-absent"), sidecar.AclEvsDeposit, now); answer != GkmAuthDenied {
		t.Errorf("a repo the state does not hold: %d", answer)
	}
	if changedIds, honorCount := gate.asked(); len(changedIds) != 0 || honorCount != 0 {
		t.Errorf("a loaded network asked for %v, the scope check asked %d times", changedIds, honorCount)
	}

	// a network whose state is not loaded is asked for, and tells nothing
	otherNetworkId := testId("network-b")
	if answer := state.HonorScope(apiDepositPrincipal(otherNetworkId, nil, now), testId("repo-mailbox"), sidecar.AclEvsDeposit, now); answer != GkmAuthUnknown {
		t.Errorf("a network whose state is not loaded: %d", answer)
	}
	if changedIds, _ := gate.asked(); !slices.Equal(changedIds, []sidecar.Id{otherNetworkId}) {
		t.Errorf("loads asked for %v", changedIds)
	}
	if answer := NewAclGkmAuthState(nil, nil, nil).HonorScope(principal, testId("repo-mailbox"), sidecar.AclEvsDeposit, now); answer != GkmAuthUnknown {
		t.Errorf("no gate: %d", answer)
	}

	// a sidecar's deposit token is the gate's to answer, which gives one it never admitted nothing
	sidecarId := connect.Id(testId("sc-depositor"))
	sidecarPrincipal := apiDepositPrincipal(networkId, nil, now, repoScope(testId("repo-mailbox"), "deposit"))
	sidecarPrincipal.SidecarId = &sidecarId
	if answer := state.HonorScope(sidecarPrincipal, testId("repo-mailbox"), sidecar.AclEvsDeposit, now); answer != GkmAuthDenied {
		t.Errorf("an unadmitted sidecar's deposit: %d", answer)
	}
	if _, honorCount := gate.asked(); honorCount != 1 {
		t.Errorf("the gate's scope check asked %d times of a sidecar's token, want once", honorCount)
	}
}

// api's token through gkm's real drop-key route (QD-1229; §14.8's report intake): over a group KF1 created, its repo
// the network's admin inbox in the network's state, the token reads the newest GenRotates after since, each the stored
// Signed bytes, and its gkm-9 line names its own client and the group; once the state holds the inbox deleted, the
// same read is refused.
func TestGkmApiDepositTokenReadsTheNewestGenRotates(t *testing.T) {
	world := newGkmGroupWorld(t)
	world.createAndActivate()
	fixture := world.fixture
	networkId := sidecar.Id(fixture.networkId)
	gate := newLoadedGkmAclGate()
	inbox := apiDepositRepo(world.repoId, protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoInbox_REPO_INBOX_ADMIN)
	gate.install(t, networkId, inbox)
	useApiDepositState(fixture, gate)
	_, rotate2 := world.putGeneration(world.admin, world.key1)
	token := apiDepositToken(fixture, networkId, nil, repoScope(world.repoId, "deposit"))
	read := func(since string) (int, []*bridge.Signed) {
		path := "/gkm/repos/" + sidecar.EvsKeyId(world.repoId) + "/drop-key?since=" + since
		recorder := fixture.serve(http.MethodGet, path, token, nil)
		reply := &protocol.GkmGenerationsReply{}
		if recorder.Code == http.StatusOK && proto.Unmarshal(recorder.Body.Bytes(), reply) != nil {
			t.Fatal("a drop-key answer that does not parse")
		}
		return recorder.Code, reply.GetGenerations()
	}
	code, generations := read("0")
	if code != http.StatusOK || len(generations) != 2 || !proto.Equal(generations[0], world.rotate1) || !proto.Equal(generations[1], rotate2) {
		t.Errorf("the drop key from generation 0: %d, %d generations", code, len(generations))
	}
	code, generations = read("1")
	if code != http.StatusOK || len(generations) != 1 || !proto.Equal(generations[0], rotate2) {
		t.Errorf("the drop key after generation 1: %d, %d generations", code, len(generations))
	}
	entry := fixture.serviceLog.last()
	if entry.Route != gkmDropKeyPattern || entry.GroupId == nil || *entry.GroupId != world.groupId || entry.ClientId != testId("client-api") {
		t.Errorf("gkm-9's line for api's read: %+v", entry)
	}
	gate.install(t, networkId, apiDepositDeleted(inbox, 0))
	if code, _ := read("0"); code != http.StatusForbidden {
		t.Errorf("the inbox under a RepoDelete: %d", code)
	}
}
