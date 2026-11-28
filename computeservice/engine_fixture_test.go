package computeservice

// The engine every computeservice test runs on (CSRV-M12-01): sidecartest's FakeRedis twice, the host's and the
// admissions instance's, FakeAuthenticator, FakeServiceGates, FakeMetrics and FakeAbuseGate on one fake clock, a fake
// auth state the test sets, a region lookup and an abuse hold store the test sets (CARCH-M12-01), web search's
// sanctions records in memory, none standing (SRCH-M13-07), a recording service log, and the groups the test links. Each area's internal tests build on it: they plant their handlers through
// computeFixtureOptions.handlers, by route name, so the guard runs in front of them as it does in a block, and set the
// state rather than bypass a step. A fixture sharedWith another is a second broker instance on the first one's world:
// its clock, its stores, its gates and its state.

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An id from a label, the same each run.
func testComputeId(label string) sidecar.Id {
	id := sidecar.Id{}
	copy(id[:], fmt.Sprintf("%-16s", label))
	return id
}

// The auth state as a test sets it. Safe for concurrent use.
type fakeComputeAuthState struct {
	stateLock sync.Mutex
	// the networks whose state is loaded, with the features their newest base turns on
	networks map[sidecar.Id]ComputeAuthFeatures
	// admitted callers by sidecar, each in its network
	callers map[sidecar.Id]*ComputeCaller
	// sidecars a rev/ object voids
	revoked map[sidecar.Id]bool
	// rev/ cannot be read
	revocationUnknown bool
	// how many times each question was asked
	callerCount int
}

func newFakeComputeAuthState() *fakeComputeAuthState {
	return &fakeComputeAuthState{
		networks: map[sidecar.Id]ComputeAuthFeatures{},
		callers:  map[sidecar.Id]*ComputeCaller{},
		revoked:  map[sidecar.Id]bool{},
	}
}

// Loads a network's state with the features given.
func (self *fakeComputeAuthState) load(networkId sidecar.Id, features ComputeAuthFeatures) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networks[networkId] = features
}

// Forgets a network's state, as a cold cache holds none.
func (self *fakeComputeAuthState) unload(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.networks, networkId)
}

// Admits a caller in its network.
func (self *fakeComputeAuthState) admit(caller *ComputeCaller) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *caller
	self.callers[caller.SidecarId] = &copied
}

// Voids a sidecar's tokens.
func (self *fakeComputeAuthState) revoke(sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.revoked[sidecarId] = true
}

func (self *fakeComputeAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.revocationUnknown {
		return fmt.Errorf("rev/ did not answer")
	}
	if principal.SidecarId != nil && self.revoked[sidecar.Id(*principal.SidecarId)] {
		return ErrComputeTokenRevoked
	}
	return nil
}

func (self *fakeComputeAuthState) Caller(principal *sidecar.Principal) (*ComputeCaller, ComputeAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.callerCount += 1
	networkId := sidecar.Id(principal.NetworkId)
	if _, loaded := self.networks[networkId]; !loaded {
		return nil, ComputeAuthUnknown
	}
	if principal.SidecarId == nil {
		return nil, ComputeAuthDenied
	}
	caller := self.callers[sidecar.Id(*principal.SidecarId)]
	if caller == nil || caller.NetworkId != networkId {
		return nil, ComputeAuthDenied
	}
	copied := *caller
	copied.Principal = principal
	return &copied, ComputeAuthAllowed
}

func (self *fakeComputeAuthState) Features(networkId sidecar.Id) (ComputeAuthFeatures, ComputeAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	features, loaded := self.networks[networkId]
	if !loaded {
		return 0, ComputeAuthUnknown
	}
	return features, ComputeAuthAllowed
}

// The service log's lines, in order. Safe for concurrent use.
type recordingComputeServiceLog struct {
	stateLock sync.Mutex
	entries   []*ComputeServiceLogEntry
}

func (self *recordingComputeServiceLog) Write(entry *ComputeServiceLogEntry) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *entry
	copied.RowIds = slices.Clone(entry.RowIds)
	self.entries = append(self.entries, &copied)
}

func (self *recordingComputeServiceLog) lines() []*ComputeServiceLogEntry {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.entries)
}

// An approval gate a test sets: it records each kind it was asked and answers refusal.
type fakeComputeApprovalGate struct {
	stateLock sync.Mutex
	refusal   *ComputeRefusal
	kinds     []ComputeApprovalKind
}

func (self *fakeComputeApprovalGate) Admit(request *ComputeRequest, kind ComputeApprovalKind) *ComputeRefusal {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.kinds = append(self.kinds, kind)
	return self.refusal
}

// Regions by address, as a test sets them: every other address is placed nowhere. Safe for concurrent use.
type fakeComputeRegionLookup struct {
	stateLock   sync.Mutex
	addrRegions map[netip.Addr]*ComputeRegion
	// the lookup cannot answer
	failing bool
	// every address asked, in order
	asked []netip.Addr
}

func newFakeComputeRegionLookup() *fakeComputeRegionLookup {
	return &fakeComputeRegionLookup{addrRegions: map[netip.Addr]*ComputeRegion{}}
}

// Places addr in region.
func (self *fakeComputeRegionLookup) place(addr netip.Addr, region *ComputeRegion) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *region
	self.addrRegions[addr] = &copied
}

func (self *fakeComputeRegionLookup) Region(addr netip.Addr) (*ComputeRegion, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asked = append(self.asked, addr)
	if self.failing {
		return nil, fmt.Errorf("the geo database did not answer")
	}
	if region, ok := self.addrRegions[addr]; ok {
		copied := *region
		return &copied, nil
	}
	return &ComputeRegion{}, nil
}

// The abuse holds as a test sets them, standing in for compute_abuse_hold. Safe for concurrent use.
type fakeComputeAbuseHoldStore struct {
	stateLock    sync.Mutex
	networkHolds map[sidecar.Id]*model.ComputeAbuseHold
	// the store cannot answer
	failing bool
	// how many rows were read
	readCount int
}

func newFakeComputeAbuseHoldStore() *fakeComputeAbuseHoldStore {
	return &fakeComputeAbuseHoldStore{networkHolds: map[sidecar.Id]*model.ComputeAbuseHold{}}
}

// Sets networkId's row, its version raised as each change raises it, and answers its state.
func (self *fakeComputeAbuseHoldStore) set(networkId sidecar.Id, reason model.ComputeAbuseHoldReason, held bool, at time.Time) *model.ComputeAbuseHoldState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hold := self.networkHolds[networkId]
	if hold == nil {
		hold = &model.ComputeAbuseHold{NetworkId: networkId, HoldStaffId: testComputeId("staff-1"), HoldTime: at}
	} else {
		copied := *hold
		hold = &copied
	}
	hold.Version += 1
	hold.Reason = reason
	hold.ResumeStaffId, hold.ResumeTime = nil, nil
	if !held {
		staffId := testComputeId("staff-2")
		resumeTime := at
		hold.ResumeStaffId, hold.ResumeTime = &staffId, &resumeTime
	}
	self.networkHolds[networkId] = hold
	return model.ComputeAbuseHoldStateOf(hold)
}

func (self *fakeComputeAbuseHoldStore) Hold(ctx context.Context, networkId sidecar.Id) (*model.ComputeAbuseHold, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.failing {
		return nil, fmt.Errorf("compute_abuse_hold did not answer")
	}
	self.readCount += 1
	hold := self.networkHolds[networkId]
	if hold == nil {
		return nil, nil
	}
	copied := *hold
	return &copied, nil
}

// How many rows were read.
func (self *fakeComputeAbuseHoldStore) reads() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.readCount
}

// What a fixture is built with beyond its defaults.
type computeFixtureOptions struct {
	// handlers by route name in place of the registered ones; nil serves the registered ones
	handlers map[string]ComputeHandler
	// admission checks after the registered ones
	admissionChecks []ComputeAdmissionCheck
	// the approval gate; nil installs none
	approvalGate ComputeApprovalGate
	// nil: DefaultComputeEngineSettings
	settings *ComputeEngineSettings
	// nil discards
	log sidecar.Logger
	// nil: the recording service log
	serviceLog ComputeServiceLog
	// the catalog's versions; nil reads compute_catalog_version, which a test engine has no database for
	catalogStore computeCatalogVersionStore
	// a second broker instance on this fixture's world: its clock, stores, gates, auth state, region lookup and
	// abuse holds, and its network and sidecar
	sharedWith *computeFixture
	// an area's own deps beyond the fixture's, its seams set on deps before the engine is built
	editDeps func(deps *ComputeEngineDeps)
}

// One engine and the world it reads, with one admitted member device in one loaded network whose gate is open and
// whose groups are all linked: each test takes away what it refuses.
type computeFixture struct {
	t               testing.TB
	ctx             context.Context
	clock           *sidecartest.FakeClock
	faults          *sidecartest.FaultQueue
	redis           *sidecartest.FakeRedis
	admissionsRedis *sidecartest.FakeRedis
	authenticator   *sidecartest.FakeAuthenticator
	gates           *sidecartest.FakeServiceGates
	metrics         *sidecartest.FakeMetrics
	authState       *fakeComputeAuthState
	abuse           *sidecartest.FakeAbuseGate
	regions         *fakeComputeRegionLookup
	abuseHolds      *fakeComputeAbuseHoldStore
	searchFlags     *fakeComputeSearchFlagStore
	serviceLog      *recordingComputeServiceLog
	host            *sidecar.ServiceHost
	engine          *ComputeEngine

	groupsLock sync.Mutex
	groups     map[ComputeMigrationGroup]bool

	networkId sidecar.Id
	clientId  sidecar.Id
	sidecarId sidecar.Id
	memberId  sidecar.Id
}

func newComputeFixture(t testing.TB, options *computeFixtureOptions) *computeFixture {
	if options == nil {
		options = &computeFixtureOptions{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var self *computeFixture
	if shared := options.sharedWith; shared != nil {
		self = &computeFixture{
			t:               t,
			ctx:             ctx,
			clock:           shared.clock,
			faults:          shared.faults,
			redis:           shared.redis,
			admissionsRedis: shared.admissionsRedis,
			authenticator:   shared.authenticator,
			gates:           shared.gates,
			metrics:         sidecartest.NewFakeMetrics(nil),
			authState:       shared.authState,
			abuse:           shared.abuse,
			regions:         shared.regions,
			abuseHolds:      shared.abuseHolds,
			searchFlags:     shared.searchFlags,
			serviceLog:      &recordingComputeServiceLog{},
			groups:          maps.Clone(shared.groups),
			networkId:       shared.networkId,
			clientId:        shared.clientId,
			sidecarId:       shared.sidecarId,
			memberId:        shared.memberId,
		}
	} else {
		clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
		faults := sidecartest.NewFaultQueue()
		redisSettings := sidecartest.DefaultFakeRedisSettings()
		self = &computeFixture{
			t:               t,
			ctx:             ctx,
			clock:           clock,
			faults:          faults,
			redis:           sidecartest.NewFakeRedis(ctx, clock, faults, nil, redisSettings),
			admissionsRedis: sidecartest.NewFakeRedis(ctx, clock, faults, nil, redisSettings),
			authenticator:   sidecartest.NewFakeAuthenticator(clock, faults),
			gates:           sidecartest.NewFakeServiceGates(nil),
			metrics:         sidecartest.NewFakeMetrics(nil),
			authState:       newFakeComputeAuthState(),
			abuse:           sidecartest.NewFakeAbuseGate(),
			regions:         newFakeComputeRegionLookup(),
			abuseHolds:      newFakeComputeAbuseHoldStore(),
			searchFlags:     newFakeComputeSearchFlagStore(),
			serviceLog:      &recordingComputeServiceLog{},
			groups: map[ComputeMigrationGroup]bool{
				ComputeMigrationGroupC1: true,
				ComputeMigrationGroupC2: true,
				ComputeMigrationGroupC3: true,
			},
			networkId: testComputeId("network-a"),
			clientId:  testComputeId("client-a"),
			sidecarId: testComputeId("sidecar-a"),
			memberId:  testComputeId("member-a"),
		}
		self.authState.load(self.networkId, 0)
		self.authState.admit(&ComputeCaller{
			NetworkId: self.networkId,
			ClientId:  self.clientId,
			SidecarId: self.sidecarId,
			MemberId:  self.memberId,
			Consented: true,
		})
		self.gates.OpenService(sidecar.ServiceGateCompute, connect.Id(self.networkId))
		// in standing with §21, from an address placed nowhere, with no hold: each test takes away what it refuses
		self.abuse.Set(connect.Id(self.networkId), sidecar.AbuseStandingStandard, true)
	}
	self.host = &sidecar.ServiceHost{
		Authenticator: self.authenticator,
		Metrics:       self.metrics,
		Redis:         self.redis,
		Clock:         self.clock,
		Gates:         self.gates,
		Abuse:         self.abuse,
	}
	var serviceLog ComputeServiceLog = self.serviceLog
	if options.serviceLog != nil {
		serviceLog = options.serviceLog
	}
	deps := &ComputeEngineDeps{
		AuthState:       self.authState,
		ApprovalGate:    options.approvalGate,
		AdmissionsRedis: self.admissionsRedis,
		GroupLinked: func(group ComputeMigrationGroup) bool {
			self.groupsLock.Lock()
			defer self.groupsLock.Unlock()
			return self.groups[group]
		},
		SecretFile: func(name string) ([]byte, error) {
			return nil, fmt.Errorf("a test block holds no %s", name)
		},
		RegionLookup:        self.regions,
		ServiceLog:          serviceLog,
		Log:                 options.log,
		testHandlers:        options.handlers,
		testAdmissionChecks: options.admissionChecks,
		testCatalogStore:    options.catalogStore,
		testAbuseHoldStore:  self.abuseHolds,
		testSearch:          &computeSearchTestDeps{flags: self.searchFlags},
	}
	if options.editDeps != nil {
		options.editDeps(deps)
	}
	if deps.testHandlers == nil {
		// no test hands the registry over by accident: an empty map serves every route unbuilt
		deps.testHandlers = map[string]ComputeHandler{}
	}
	engine, err := NewComputeEngine(ctx, self.host, options.settings, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	self.engine = engine
	return self
}

// Unlinks a group, as a release build that does not link it reads.
func (self *computeFixture) unlink(group ComputeMigrationGroup) {
	self.groupsLock.Lock()
	defer self.groupsLock.Unlock()
	self.groups[group] = false
}

// The principal of the fixture's sidecar for audience, good for 15 minutes.
func (self *computeFixture) principal(audience string) *sidecar.Principal {
	networkId := connect.Id(self.networkId)
	clientId := connect.Id(self.clientId)
	sidecarId := connect.Id(self.sidecarId)
	memberId := connect.Id(self.memberId)
	return &sidecar.Principal{
		NetworkId:   networkId,
		ClientId:    clientId,
		SidecarId:   &sidecarId,
		MemberId:    &memberId,
		Audience:    audience,
		ProjVersion: 1,
		IssuedAt:    self.clock.Now(),
		ExpiresAt:   self.clock.Now().Add(15 * time.Minute),
	}
}

// A compute token of the fixture's sidecar.
func (self *computeFixture) token() string {
	return self.authenticator.Issue(self.principal(ComputeAudience))
}

// A request through the engine's handler, with the bearer given (none for ""), and the headers given.
func (self *computeFixture) serve(method string, path string, bearer string, body string, headers map[string]string) *httptest.ResponseRecorder {
	self.t.Helper()
	request := httptest.NewRequestWithContext(self.ctx, method, "http://compute.example"+path, strings.NewReader(body))
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// A served request's refusal code, "" for an answer that is no refusal.
func computeRefusalCodeOf(recorder *httptest.ResponseRecorder) ComputeRefusalCode {
	if recorder.Header().Get("Content-Type") != computeContentTypeJson {
		return ""
	}
	body := &computeRefusalBody{}
	if err := json.Unmarshal(recorder.Body.Bytes(), body); err != nil {
		return ""
	}
	return body.Code
}

// Fails unless recorder answered status with code.
func requireComputeRefusal(t testing.TB, recorder *httptest.ResponseRecorder, status int, code ComputeRefusalCode) {
	t.Helper()
	if recorder.Code != status || computeRefusalCodeOf(recorder) != code {
		t.Fatalf("answered %d %q, want %d %q", recorder.Code, recorder.Body.String(), status, code)
	}
}

// A handler that counts its calls and answers 200 with no body.
type countingComputeHandler struct {
	stateLock sync.Mutex
	calls     int
	requests  []*ComputeRequest
}

func (self *countingComputeHandler) serve(request *ComputeRequest) {
	self.stateLock.Lock()
	self.calls += 1
	self.requests = append(self.requests, request)
	self.stateLock.Unlock()
	request.Reply(nil)
}

func (self *countingComputeHandler) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.calls
}

// Every design route served by one counting handler.
func countingComputeHandlers(counting *countingComputeHandler) map[string]ComputeHandler {
	handlers := map[string]ComputeHandler{}
	for _, route := range computeRouteDesign() {
		handlers[route.Name] = counting.serve
	}
	return handlers
}
