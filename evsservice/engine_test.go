package evsservice

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A synthetic id from a label, so tests read the same every run.
func testId(label string) sidecar.Id {
	var id sidecar.Id
	copy(id[:], fmt.Sprintf("%-16s", label))
	return id
}

// One sidecar's rights on one repo in the fake state.
type fakeAuthKey struct {
	sidecarId sidecar.Id
	repoId    sidecar.Id
}

// T2's EvsAuthState: what a test says the newest verified state holds. Safe for concurrent use.
type fakeAuthState struct {
	stateLock sync.Mutex
	// every answer unknown, as a network whose state is not loaded
	unloaded bool
	// sidecars whose binding the state denies
	unboundSidecarIds map[sidecar.Id]bool
	// sidecars a rev/ object voids
	revokedSidecarIds map[sidecar.Id]bool
	// what CheckRevocation answers when it cannot tell
	revocationErr   error
	revocationCount int
	rights          map[fakeAuthKey]sidecar.AclEvsRights
	repoFacts       map[sidecar.Id]*EvsRepoFacts
	honorCount      int
}

func newFakeAuthState() *fakeAuthState {
	return &fakeAuthState{
		unboundSidecarIds: map[sidecar.Id]bool{},
		revokedSidecarIds: map[sidecar.Id]bool{},
		rights:            map[fakeAuthKey]sidecar.AclEvsRights{},
		repoFacts:         map[sidecar.Id]*EvsRepoFacts{},
	}
}

// Gives the sidecar rights on the repo, with what they imply, replacing what it held.
func (self *fakeAuthState) grant(sidecarId sidecar.Id, repoId sidecar.Id, rights sidecar.AclEvsRights) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rights[fakeAuthKey{sidecarId: sidecarId, repoId: repoId}] = impliedRights(strongestRight(rights)) | rights
}

func (self *fakeAuthState) setRepo(repoId sidecar.Id, facts *EvsRepoFacts) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.repoFacts[repoId] = facts
}

func (self *fakeAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.revocationCount += 1
	if self.revocationErr != nil {
		return self.revocationErr
	}
	if principal.SidecarId != nil && self.revokedSidecarIds[sidecar.Id(*principal.SidecarId)] {
		return ErrEvsTokenRevoked
	}
	return nil
}

func (self *fakeAuthState) MatchBinding(principal *sidecar.Principal) EvsAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unloaded {
		return EvsAuthUnknown
	}
	if self.unboundSidecarIds[sidecar.Id(*principal.SidecarId)] {
		return EvsAuthDenied
	}
	return EvsAuthAllowed
}

func (self *fakeAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) EvsAuthAnswer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.honorCount += 1
	if self.unloaded {
		return EvsAuthUnknown
	}
	held := self.rights[fakeAuthKey{sidecarId: sidecar.Id(*principal.SidecarId), repoId: repoId}]
	if held.Has(rights) {
		return EvsAuthAllowed
	}
	return EvsAuthDenied
}

func (self *fakeAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*EvsRepoFacts, EvsAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unloaded {
		return nil, EvsAuthUnknown
	}
	facts, ok := self.repoFacts[repoId]
	if !ok {
		return nil, EvsAuthDenied
	}
	return facts, EvsAuthAllowed
}

// evs-7's lines as a test reads them.
type recordingServiceLog struct {
	stateLock sync.Mutex
	entries   []*EvsServiceLogEntry
}

func (self *recordingServiceLog) Write(entry *EvsServiceLogEntry) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.entries = append(self.entries, entry)
}

func (self *recordingServiceLog) last() *EvsServiceLogEntry {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.entries[len(self.entries)-1]
}

// One engine on one fake host, its network admitted by the evs gate, with two metadata clusters.
type evsFixture struct {
	t          *testing.T
	ctx        context.Context
	clock      *sidecartest.FakeClock
	host       *sidecartest.FakeHost
	auth       *fakeAuthState
	serviceLog *recordingServiceLog
	engine     *EvsEngine
	networkId  connect.Id
}

func newEvsFixture(t *testing.T, routes ...*EvsRoute) *evsFixture {
	return newEvsFixtureWith(t, nil, routes...)
}

func newEvsFixtureWith(t *testing.T, adjust func(hostSettings *sidecartest.FakeHostSettings, settings *EvsSettings), routes ...*EvsRoute) *evsFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1", "meta-2"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	settings := DefaultEvsSettings()
	if adjust != nil {
		adjust(hostSettings, settings)
	}
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	sidecartest.RegisterEvsTwins(host.Redis)
	networkId := connect.Id(testId("network-a"))
	host.Gates.OpenService(sidecar.ServiceGateEvs, networkId)
	auth := newFakeAuthState()
	serviceLog := &recordingServiceLog{}
	engine, err := NewEvsEngine(ctx, host.ServiceHost(), settings, &EvsEngineDeps{
		AuthState:  auth,
		ServiceLog: serviceLog,
		testRoutes: routes,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return &evsFixture{
		t: t, ctx: ctx, clock: clock, host: host, auth: auth, serviceLog: serviceLog, engine: engine, networkId: networkId,
	}
}

// A sidecar's evs token for scopes, each repo:<id>:<role>.
func (self *evsFixture) token(sidecarId sidecar.Id, scopes ...string) string {
	connectSidecarId := connect.Id(sidecarId)
	return self.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: self.networkId,
		ClientId:  connect.Id(testId("client-" + string(sidecarId[:4]))),
		SidecarId: &connectSidecarId,
		Audience:  EvsAudience,
		Scopes:    scopes,
		IssuedAt:  self.clock.Now(),
		ExpiresAt: self.clock.Now().Add(15 * time.Minute),
	})
}

// The scope string for a repo and role.
func repoScope(repoId sidecar.Id, role string) string {
	return "repo:" + repoId.String() + ":" + role
}

// One request through the engine's handler.
func (self *evsFixture) serve(method string, path string, token string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(self.ctx, method, path, strings.NewReader(string(body)))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// The refusal a non-200 answer carries.
func refusalOf(t *testing.T, recorder *httptest.ResponseRecorder) *protocol.EvsRefusalReply {
	t.Helper()
	reply := &protocol.EvsRefusalReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		t.Fatalf("a refusal that does not parse: %v", err)
	}
	return reply
}

// Asserts status and refusal code.
func requireRefusal(t *testing.T, recorder *httptest.ResponseRecorder, status int, code protocol.EvsRefusalCode) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status %d, want %d (%s)", recorder.Code, status, refusalOf(t, recorder).GetCode())
	}
	if got := refusalOf(t, recorder).GetCode(); got != code {
		t.Fatalf("code %s, want %s", got, code)
	}
}

// A repo route under test: takes rights, counts its calls.
type probeRoute struct {
	route *EvsRoute
	calls int
	last  *EvsRequest
}

func newProbeRoute(method string, pattern string, rights sidecar.AclEvsRights, write bool, needsSureClock bool, placed bool) *probeRoute {
	probe := &probeRoute{}
	probe.route = &EvsRoute{
		Method: method, Pattern: pattern, Name: "probe", Rights: rights, Write: write,
		NeedsSureClock: needsSureClock, Placed: placed,
		Serve: func(request *EvsRequest) {
			probe.calls += 1
			probe.last = request
			request.Reply(nil)
		},
	}
	return probe
}

func TestEvsEngineRefusesToStartWithoutABudget(t *testing.T) {
	ctx := t.Context()
	host := sidecartest.NewFakeHost(ctx, nil, nil, nil, nil).ServiceHost()
	host.Budget = nil
	if _, err := NewEvsEngine(ctx, host, nil, &EvsEngineDeps{AuthState: newFakeAuthState()}); err == nil {
		t.Fatal("an engine started with no write budget")
	}
}

func TestEvsEngineRefusesSettingsPastTheDesignsBounds(t *testing.T) {
	settings := DefaultEvsSettings()
	settings.RepoCacheTtl = 6 * time.Second
	if err := settings.Validate(); !errors.Is(err, ErrEvsSettings) {
		t.Errorf("repo/ cached 6 s: %v", err)
	}
	settings = DefaultEvsSettings()
	settings.HeadCacheServeAge = 11 * time.Minute
	if err := settings.Validate(); !errors.Is(err, ErrEvsSettings) {
		t.Errorf("a head served 11 min: %v", err)
	}
	if err := DefaultEvsSettings().Validate(); err != nil {
		t.Errorf("the defaults: %v", err)
	}
}

func TestEvsEngineAnswersAMissingOrUnknownToken401(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newEvsFixture(t, probe.route)
	repoId := testId("repo")
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId) + "/probe"
	if recorder := fixture.serve(http.MethodGet, path, "", nil); recorder.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", recorder.Code)
	}
	if recorder := fixture.serve(http.MethodGet, path, "not-a-token", nil); recorder.Code != http.StatusUnauthorized {
		t.Errorf("a guessed token: %d", recorder.Code)
	}
	// a token for another audience verifies under the shared keys but is not evs's
	sidecarId := testId("sidecar-a")
	connectSidecarId := connect.Id(sidecarId)
	gkmToken := fixture.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: fixture.networkId, ClientId: connect.Id(testId("client")), SidecarId: &connectSidecarId,
		Audience: "gkm", Scopes: []string{repoScope(repoId, "r")}, IssuedAt: fixture.clock.Now(),
		ExpiresAt: fixture.clock.Now().Add(time.Minute),
	})
	if recorder := fixture.serve(http.MethodGet, path, gkmToken, nil); recorder.Code != http.StatusUnauthorized {
		t.Errorf("a gkm token: %d", recorder.Code)
	}
	if probe.calls != 0 {
		t.Errorf("the route ran %d times", probe.calls)
	}
}

func TestEvsEngineAnswersAnAuthenticatorThatCannotTell503(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newEvsFixture(t, probe.route)
	repoId := testId("repo")
	token := fixture.token(testId("sidecar-a"), repoScope(repoId, "r"))
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpHost, KeyPrefix: "authenticator.Authenticate", Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	recorder := fixture.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/probe", token, nil)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if recorder.Header().Get("Retry-After") == "" {
		t.Error("a 503 with no Retry-After")
	}
}

func TestEvsEngineRefusesATokenOfNoSidecar(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newEvsFixture(t, probe.route)
	repoId := testId("repo")
	token := fixture.host.Authenticator.Issue(&sidecar.Principal{
		NetworkId: fixture.networkId, ClientId: connect.Id(testId("client")), Audience: EvsAudience,
		Scopes: []string{repoScope(repoId, "r")}, IssuedAt: fixture.clock.Now(), ExpiresAt: fixture.clock.Now().Add(time.Minute),
	})
	recorder := fixture.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/probe", token, nil)
	requireRefusal(t, recorder, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
}

func TestEvsEngineGateClosedAnswers503WithTheGatesRetryAfter(t *testing.T) {
	read := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/read-probe", sidecar.AclEvsRead, false, false, false)
	write := newProbeRoute(http.MethodPost, "/evs/v1/repos/{repo_id}/write-probe", sidecar.AclEvsWrite, true, false, false)
	fixture := newEvsFixture(t, read.route, write.route)
	repoId := testId("repo")
	sidecarId := testId("sidecar-a")
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsWrite)
	token := fixture.token(sidecarId, repoScope(repoId, "rw"))
	readPath := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId) + "/read-probe"
	writePath := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId) + "/write-probe"

	// writes: false, the incident switch, closes writes and leaves reads
	if err := fixture.host.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, writes: false, networks: [%s]}\n", fixture.networkId)); err != nil {
		t.Fatal(err)
	}
	if recorder := fixture.serve(http.MethodGet, readPath, token, nil); recorder.Code != http.StatusOK {
		t.Errorf("a read while writes are off: %d", recorder.Code)
	}
	recorder := fixture.serve(http.MethodPost, writePath, token, nil)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if recorder.Header().Get("Retry-After") != "60" {
		t.Errorf("Retry-After %q, want the gates' 60", recorder.Header().Get("Retry-After"))
	}
	if write.calls != 0 {
		t.Error("a write ran while writes are off")
	}

	// a network the gate does not admit: every route
	if err := fixture.host.Gates.Set("sidecar:\n  evs: {enabled: true, networks: []}\n"); err != nil {
		t.Fatal(err)
	}
	recorder = fixture.serve(http.MethodGet, readPath, token, nil)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
}

func TestEvsEngineRefusesASidecarTheBindingDoesNotMatch(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newEvsFixture(t, probe.route)
	repoId := testId("repo")
	sidecarId := testId("sidecar-a")
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsRead)
	token := fixture.token(sidecarId, repoScope(repoId, "r"))
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId) + "/probe"
	fixture.auth.unboundSidecarIds[sidecarId] = true
	requireRefusal(t, fixture.serve(http.MethodGet, path, token, nil), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	delete(fixture.auth.unboundSidecarIds, sidecarId)
	fixture.auth.unloaded = true
	requireRefusal(t, fixture.serve(http.MethodGet, path, token, nil), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	fixture.auth.unloaded = false
	if recorder := fixture.serve(http.MethodGet, path, token, nil); recorder.Code != http.StatusOK {
		t.Errorf("a bound sidecar: %d", recorder.Code)
	}
	if probe.calls != 1 {
		t.Errorf("the route ran %d times", probe.calls)
	}
}

func TestEvsEngineRefusesAScopeTheTokenLacks(t *testing.T) {
	admin := newProbeRoute(http.MethodPost, "/evs/v1/repos/{repo_id}/admin-probe", sidecar.AclEvsAdmin, true, false, false)
	fixture := newEvsFixture(t, admin.route)
	repoId := testId("repo")
	otherRepoId := testId("other-repo")
	sidecarId := testId("sidecar-a")
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsAdmin)
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId) + "/admin-probe"
	for _, scopes := range [][]string{
		{repoScope(repoId, "rw")},
		{repoScope(repoId, "deposit")},
		{repoScope(otherRepoId, "admin")},
		{"repo:not-an-id:admin"},
		{repoScope(repoId, "owner")},
	} {
		recorder := fixture.serve(http.MethodPost, path, fixture.token(sidecarId, scopes...), nil)
		requireRefusal(t, recorder, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	}
	if admin.calls != 0 {
		t.Errorf("the route ran %d times", admin.calls)
	}
	if recorder := fixture.serve(http.MethodPost, path, fixture.token(sidecarId, repoScope(repoId, "admin")), nil); recorder.Code != http.StatusOK {
		t.Errorf("admin: %d", recorder.Code)
	}
}

func TestEvsEngineHonorsAScopeOnlyWhileTheStateAgrees(t *testing.T) {
	// D-ACL-21: a token minted with rw keeps it for 15 min, and evs honors it only while the newest state agrees
	write := newProbeRoute(http.MethodPost, "/evs/v1/repos/{repo_id}/write-probe", sidecar.AclEvsWrite|sidecar.AclEvsDeposit, true, false, false)
	fixture := newEvsFixture(t, write.route)
	repoId := testId("repo")
	sidecarId := testId("sidecar-a")
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId) + "/write-probe"
	token := fixture.token(sidecarId, repoScope(repoId, "rw"))
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsWrite)
	if recorder := fixture.serve(http.MethodPost, path, token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("while held: %d", recorder.Code)
	}
	if write.last.Rights != sidecar.AclEvsWrite|sidecar.AclEvsRead {
		t.Errorf("rights %b", write.last.Rights)
	}
	// a group edit drops the sidecar's write: the same token is refused at once
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsRead)
	requireRefusal(t, fixture.serve(http.MethodPost, path, token, nil), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	// a state not loaded allows nothing
	fixture.auth.unloaded = true
	requireRefusal(t, fixture.serve(http.MethodPost, path, token, nil), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if write.calls != 1 {
		t.Errorf("the route ran %d times", write.calls)
	}
}

func TestEvsEngineChecksADepositScopeAgainstTheState(t *testing.T) {
	// g0-recheck-0-deposit-scope#1: a deposit grant revoked, the sidecar still admitted, is refused at evs
	write := newProbeRoute(http.MethodPost, "/evs/v1/repos/{repo_id}/deposit-probe", sidecar.AclEvsWrite|sidecar.AclEvsDeposit, true, false, false)
	fixture := newEvsFixture(t, write.route)
	repoId := testId("repo")
	sidecarId := testId("sidecar-a")
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId) + "/deposit-probe"
	token := fixture.token(sidecarId, repoScope(repoId, "deposit"))
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsDeposit)
	if recorder := fixture.serve(http.MethodPost, path, token, nil); recorder.Code != http.StatusOK {
		t.Fatalf("while held: %d", recorder.Code)
	}
	if write.last.Rights != sidecar.AclEvsDeposit {
		t.Errorf("a deposit token honored as %b", write.last.Rights)
	}
	fixture.auth.grant(sidecarId, repoId, 0)
	requireRefusal(t, fixture.serve(http.MethodPost, path, token, nil), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	// deposit implies no read
	read := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/read-probe", sidecar.AclEvsRead, false, false, false)
	readFixture := newEvsFixture(t, read.route)
	readFixture.auth.grant(sidecarId, repoId, sidecar.AclEvsDeposit)
	recorder := readFixture.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/read-probe", readFixture.token(sidecarId, repoScope(repoId, "deposit")), nil)
	requireRefusal(t, recorder, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
}

func TestEvsEngineReadsRevocationOnWritesOnly(t *testing.T) {
	read := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/read-probe", sidecar.AclEvsRead, false, false, false)
	write := newProbeRoute(http.MethodPost, "/evs/v1/repos/{repo_id}/write-probe", sidecar.AclEvsWrite, true, false, false)
	fixture := newEvsFixture(t, read.route, write.route)
	repoId := testId("repo")
	sidecarId := testId("sidecar-a")
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsWrite)
	token := fixture.token(sidecarId, repoScope(repoId, "rw"))
	readPath := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId) + "/read-probe"
	writePath := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId) + "/write-probe"
	if recorder := fixture.serve(http.MethodGet, readPath, token, nil); recorder.Code != http.StatusOK || fixture.auth.revocationCount != 0 {
		t.Errorf("a read: %d, %d rev/ reads", recorder.Code, fixture.auth.revocationCount)
	}
	if recorder := fixture.serve(http.MethodPost, writePath, token, nil); recorder.Code != http.StatusOK || fixture.auth.revocationCount != 1 {
		t.Errorf("a write: %d, %d rev/ reads", recorder.Code, fixture.auth.revocationCount)
	}
	// a removed sidecar's unexpired token: void at evs through rev/
	fixture.auth.revokedSidecarIds[sidecarId] = true
	if recorder := fixture.serve(http.MethodPost, writePath, token, nil); recorder.Code != http.StatusUnauthorized {
		t.Errorf("a revoked subject's write: %d", recorder.Code)
	}
	delete(fixture.auth.revokedSidecarIds, sidecarId)
	fixture.auth.revocationErr = errors.New("rev/ unreadable")
	requireRefusal(t, fixture.serve(http.MethodPost, writePath, token, nil), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if write.calls != 1 {
		t.Errorf("the write ran %d times", write.calls)
	}
}

func TestEvsEngineRecheckRevocationOnLongStreams(t *testing.T) {
	var streamRequest *EvsRequest
	stream := &EvsRoute{
		Method: http.MethodPost, Pattern: "/evs/v1/repos/{repo_id}/stream", Name: "stream",
		Rights: sidecar.AclEvsRead, Write: true,
		Serve: func(request *EvsRequest) {
			streamRequest = request
			request.Reply(nil)
		},
	}
	fixture := newEvsFixture(t, stream)
	repoId := testId("repo")
	sidecarId := testId("sidecar-a")
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsRead)
	fixture.serve(http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/stream", fixture.token(sidecarId, repoScope(repoId, "r")), nil)
	if fixture.auth.revocationCount != 1 {
		t.Fatalf("%d rev/ reads", fixture.auth.revocationCount)
	}
	fixture.clock.Advance(59 * time.Second)
	if !streamRequest.RecheckRevocation() || fixture.auth.revocationCount != 1 {
		t.Errorf("a stream at 59 s read rev/ again: %d", fixture.auth.revocationCount)
	}
	fixture.clock.Advance(time.Second)
	if !streamRequest.RecheckRevocation() || fixture.auth.revocationCount != 2 {
		t.Errorf("a stream at 60 s: %d rev/ reads", fixture.auth.revocationCount)
	}
}

func TestEvsEngineAnswersPushes503BeforeStep4WhileTheClockIsUnsure(t *testing.T) {
	push := newProbeRoute(http.MethodPost, "/evs/v1/repos/{repo_id}/push-probe", sidecar.AclEvsWrite, true, true, true)
	fixture := newEvsFixture(t, push.route)
	repoId := testId("repo")
	sidecarId := testId("sidecar-a")
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsWrite)
	token := fixture.token(sidecarId, repoScope(repoId, "rw"))
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId) + "/push-probe"
	fixture.host.ClockCheck.SetUnknown()
	getsBefore := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	recorder := fixture.serve(http.MethodPost, path, token, nil)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if push.calls != 0 {
		t.Error("a push ran on an unsure clock")
	}
	if got := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet); got != getsBefore {
		t.Errorf("an unsure clock read %d objects before refusing", got-getsBefore)
	}
	fixture.host.ClockCheck.SetOffset(60 * time.Millisecond)
	requireRefusal(t, fixture.serve(http.MethodPost, path, token, nil), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	fixture.host.ClockCheck.SetOffset(10 * time.Millisecond)
	// sure again: the guard goes on, and a repo never placed is 404
	requireRefusal(t, fixture.serve(http.MethodPost, path, token, nil), http.StatusNotFound, protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
}

func TestEvsEngineRefusesARepoIdNotInKeyForm(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newEvsFixture(t, probe.route)
	repoId := testId("repo")
	sidecarId := testId("sidecar-a")
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsRead)
	token := fixture.token(sidecarId, repoScope(repoId, "r"))
	for _, text := range []string{repoId.String(), strings.ToUpper(sidecar.EvsKeyId(repoId)), "abc"} {
		requireRefusal(t, fixture.serve(http.MethodGet, "/evs/v1/repos/"+text+"/probe", token, nil), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	}
}

func TestEvsEngineWritesItsServiceLogWithOpaqueIdsOnly(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newEvsFixture(t, probe.route)
	repoId := testId("repo")
	sidecarId := testId("sidecar-a")
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsRead)
	fixture.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/probe", fixture.token(sidecarId, repoScope(repoId, "r")), nil)
	entry := fixture.serviceLog.last()
	if entry.Route != "probe" || entry.Status != http.StatusOK || entry.RepoId != repoId || entry.SidecarId != sidecarId ||
		entry.NetworkId != sidecar.Id(fixture.networkId) {
		t.Errorf("entry %+v", entry)
	}
	// the Logger form holds hex ids and numbers, never a path
	var lines []string
	logger := &capturingLogger{lines: &lines}
	NewLoggerServiceLog(logger).Write(entry)
	if len(lines) != 1 || !strings.Contains(lines[0], sidecar.EvsKeyId(repoId)) || strings.Contains(lines[0], "/evs/v1") {
		t.Errorf("line %q", lines)
	}
	if fixture.host.Metrics.Value("urnetwork_evs_requests_total", "probe", "200") != 1 {
		t.Error("the request was not counted")
	}
}

// A Logger keeping each formatted line.
type capturingLogger struct {
	lines *[]string
}

func (self *capturingLogger) Info(args ...any) {
	*self.lines = append(*self.lines, fmt.Sprint(args...))
}

func (self *capturingLogger) Infof(format string, args ...any) {
	*self.lines = append(*self.lines, fmt.Sprintf(format, args...))
}

func (self *capturingLogger) Warningf(format string, args ...any) {
	*self.lines = append(*self.lines, fmt.Sprintf(format, args...))
}

func (self *capturingLogger) Errorf(format string, args ...any) {
	*self.lines = append(*self.lines, fmt.Sprintf(format, args...))
}

func (self *capturingLogger) V(level int32) sidecar.Verbose {
	return sidecar.NewNoopLogger().V(level)
}

func TestEvsEngineDrainAnswersNewRequests503(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newEvsFixture(t, probe.route)
	repoId := testId("repo")
	sidecarId := testId("sidecar-a")
	fixture.auth.grant(sidecarId, repoId, sidecar.AclEvsRead)
	fixture.engine.Drain()
	requireRefusal(t, fixture.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/probe", fixture.token(sidecarId, repoScope(repoId, "r")), nil),
		http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
}

func TestEvsEngineIsReadyOnceItsFirstClusterAnswers(t *testing.T) {
	fixture := newEvsFixture(t)
	for {
		count, changed := fixture.engine.Probes()
		if 0 < count {
			break
		}
		<-changed
	}
	if !fixture.engine.Ready() {
		t.Error("not ready with its first cluster answering")
	}
	fixture.engine.Close()
	if fixture.engine.Ready() {
		t.Error("ready once closed")
	}
}

// §22.5's "no key prefixes another": every family's keys for a few ids and paths, entries beside their children,
// and no key a prefix of any other.
func TestEvsObjectKeysNoKeyPrefixesAnother(t *testing.T) {
	repoId := testId("repo")
	otherRepoId := testId("repo-2")
	refId := testId("ref")
	tokenA := sidecar.EvsToken(testId("token-a"))
	tokenB := sidecar.EvsToken(testId("token-b"))
	segmentId := [32]byte{1, 2, 3}
	mapSha256 := make([]byte, 32)
	keys := []string{
		RepoKey(repoId), RepoKey(otherRepoId),
		HeadKey(repoId, refId), HeadKey(otherRepoId, refId),
		LogPageKey(repoId, refId, 0), LogPageKey(repoId, refId, 1), LogPageKey(repoId, refId, 10),
		BatchKey(BatchMinute(sidecartest.DefaultClockStart()), 7, 0), BatchKey(BatchMinute(sidecartest.DefaultClockStart()), 7, 1),
		IndexEntryKey(repoId, refId, 1, sidecar.EvsTokenPath{tokenA}),
		IndexEntryKey(repoId, refId, 1, sidecar.EvsTokenPath{tokenA, tokenB}),
		IndexEntryKey(repoId, refId, 1, sidecar.EvsTokenPath{tokenB}),
		IndexEntryKey(repoId, refId, 2, sidecar.EvsTokenPath{tokenA}),
		SlotKey(repoId, testId("slot")), ParcelKey(repoId, testId("parcel")),
		PathMapKey(repoId, refId, 2, mapSha256, 1), PathMapKey(repoId, refId, 2, mapSha256, 2),
		PidxKey(repoId, refId, 1, testId("container")), PidxKey(repoId, refId, 65, testId("container")),
		SpidxKey(repoId, 0), SpidxKey(repoId, 1), DropsKey(repoId),
		SegmentKey(repoId, segmentId), PackKey(repoId, testId("pack")),
		DropscanKey(repoId, testId("job"), "snap"), DropscanKey(repoId, testId("job"), "cand"),
		DropscanKey(repoId, testId("job"), "mark"), DropscanKey(repoId, testId("job"), "del"), DropscanKey(repoId, testId("job"), "held"),
		sidecar.EvsPlaceKey(repoId), sidecar.EvsPlaceKey(otherRepoId),
	}
	for i, key := range keys {
		for j, other := range keys {
			if i != j && strings.HasPrefix(other, key) {
				t.Errorf("%s prefixes %s", key, other)
			}
		}
		if 1024 < len(key) {
			t.Errorf("%s past MinIO's 1,024 B", key)
		}
	}
	// a LIST of a directory's children lists its subtree and not the directory's own entry
	children := IndexChildrenPrefix(repoId, refId, 1, sidecar.EvsTokenPath{tokenA})
	if !strings.HasPrefix(IndexEntryKey(repoId, refId, 1, sidecar.EvsTokenPath{tokenA, tokenB}), children) ||
		strings.HasPrefix(IndexEntryKey(repoId, refId, 1, sidecar.EvsTokenPath{tokenA}), children) {
		t.Errorf("children prefix %s", children)
	}
	// the deepest entry, 32 components, within 1,024 B (plan-EVS1-format-bytes#9: 956 B)
	deep := make(sidecar.EvsTokenPath, sidecar.EvsTokenPathMaxLength)
	for i := range deep {
		deep[i] = tokenA
	}
	if key := IndexEntryKey(repoId, refId, 1, deep); 956 < len(key) {
		t.Errorf("the deepest entry key is %d bytes", len(key))
	}
	// pidx/ keys under a ref have one length
	if len(PidxKey(repoId, refId, 1, testId("c"))) != len(PidxKey(repoId, refId, 1<<40, testId("d"))) {
		t.Error("pidx/ keys of two lengths")
	}
	tokenPath, err := IndexEntryTokenPath(IndexEpochPrefix(repoId, refId, 1), IndexEntryKey(repoId, refId, 1, sidecar.EvsTokenPath{tokenA, tokenB}))
	if err != nil || !tokenPath.Equal(sidecar.EvsTokenPath{tokenA, tokenB}) {
		t.Errorf("token path back from a key: %v %v", tokenPath, err)
	}
	if slices.Contains(keys, "") {
		t.Error("an empty key")
	}
}

func TestEvsBatchKeysNameTheirUtcHourAndMinute(t *testing.T) {
	at := time.Date(2026, time.November, 6, 16, 30, 59, 0, time.UTC)
	if key := BatchKey(BatchMinute(at), 0xa, 0xb); key != "pb/2026110616/30/0000000a-0000000b" {
		t.Errorf("key %s", key)
	}
}

// The route table a host reads is the router's, in its order, with every handler withheld: a copy changed by its
// reader changes nothing the engine serves.
func TestEvsEngineRoutesAreTheRoutersTableWithNoHandler(t *testing.T) {
	probe := newProbeRoute(http.MethodGet, "/evs/v1/repos/{repo_id}/probe", sidecar.AclEvsRead, false, false, false)
	fixture := newEvsFixture(t, probe.route)
	routes := fixture.engine.Routes()
	names := []string{}
	for _, route := range routes {
		if route.Serve != nil {
			t.Errorf("%s %s: a handler past the guard", route.Method, route.Pattern)
		}
		names = append(names, route.Method+" "+route.Pattern)
	}
	want := []string{
		"PUT /evs/v1/repos/{repo_id}",
		"PUT /evs/v1/repos/{repo_id}/segments/{segment_id}",
		"POST /evs/v1/repos/{repo_id}/push",
		"GET /evs/v1/repos/{repo_id}/probe",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("routes %v, want %v", names, want)
	}
	for _, route := range routes {
		if route.Name == "" || route.Name == "probe" {
			continue
		}
		if route.Name != route.Method+" "+route.Pattern {
			t.Errorf("route %s named %s: not its method and pattern", route.Method+" "+route.Pattern, route.Name)
		}
	}
	routes[0].Pattern = "/evs/v1/elsewhere"
	if again := fixture.engine.Routes(); again[0].Pattern != "/evs/v1/repos/{repo_id}" {
		t.Errorf("a reader's change reached the engine's table: %s", again[0].Pattern)
	}
	// the probe still answers through the guard, and only there
	repoId := testId("repo-1")
	if recorder := fixture.serve(http.MethodGet, "/evs/v1/repos/"+sidecar.EvsKeyId(repoId)+"/probe", "", nil); recorder.Code != http.StatusUnauthorized || probe.calls != 0 {
		t.Errorf("an unauthenticated probe answered %d after %d calls", recorder.Code, probe.calls)
	}
}
