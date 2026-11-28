// computetest.Broker (CTEST-M12-01; DESIGN-COMPUTE §18, with §14.2's engine, §14.3's routes and §19.11's gate): the
// broker in process, for INFER, BAL, SRCH, ENC and GW. It is CSRV-M12-01's real engine, computeservice.ComputeEngine,
// on an httptest server, so every request a test sends passes the engine's whole guard, in its order, before any
// handler: the route, the compute token and the newest verified state, the gate, the migration group, Idempotency-Key,
// the admission checks and the approval gate. It serves every handler the linked areas registered, and a design route
// no area has built answers 503 not_built, as in production.
//
//	stores     on T2: sidecartest's FakeRedis twice, the main instance and {cmpa}'s (§14.4), and FakeAuthenticator,
//	           FakeServiceGates, FakeMetrics and FakeAbuseGate on one clock, a FakeClock unless the test gives one; the
//	           broker's own Env grants those and refuses PostgreSQL, which no sidecar test reaches (pgx stays out of this
//	           module, DESIGN §4.5), so a handler that needs a table answers 503 there. On the local test stack the
//	           caller gives real stores instead: the stack's Redis Cluster (sidecartest/localstack), and from server's
//	           tests core's Env with PostgreSQL and the test Redis (T3)
//	state      FakeComputeAuthState (broker_auth.go): networks, members, roles, tags, consent, the admission flags,
//	           revocations, the compute block and its budgets, which a test sets; AddNetwork loads a network, opens the
//	           compute gate to it and puts it in standing (§21.7), and a test takes away what it refuses
//	tokens     each test sidecar (AddSidecar) mints audience-compute service tokens through FakeAuthenticator, good for
//	           BrokerSettings.TokenLife, as the exchange mints them after a ClientKey's DPoP proof (§7.8)
//	tables     compute_abuse_hold and compute_catalog_version stand in fakes on T2 (broker_stores.go), with the host's
//	           region lookup, so an admission reads a real step's store rather than skipping it; those and a test's
//	           planted handlers and admission checks reach the engine through computeservice's sidecar_testhooks seam
//	           (broker_testhooks.go), and an untagged build refuses to plant (ErrBrokerPlantUnlinked), its admissions
//	           reading the Env's tables, so they answer 503 on T2
//	asserts    the ledger's own reads through the broker's Env: a network's projection (holds, unsettled charges,
//	           the balance, §9.7) and an operation's row (compute_op), each answering what the stores can: the
//	           projection's scripts run on real Redis and have no FakeRedis twins, and the rows need PostgreSQL
//
// It never skips a guard step: a test that needs a refusal sets the state, the gate, the group, a store or a fault,
// never a bypass. On fakes it is T2, and says so (Tier); the same broker on real stores is the local stack's.
//
// Safe for concurrent use. Stop ends the engine, the server and every request in flight.

package computetest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/computeservice"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	// The untagged build has no seam into the engine's handlers, admission checks or table stores
	// (broker_testhooks.go).
	ErrBrokerPlantUnlinked = errors.New("computetest: planting into the broker needs the sidecar_testhooks build")
	// A test sidecar or network the broker cannot add: an empty label, one taken, a member of another network.
	ErrBrokerInvalid = errors.New("computetest: the broker cannot add that")
	// The broker has stopped.
	ErrBrokerStopped = errors.New("computetest: the broker has stopped")
)

// The tiers a broker runs at (DESIGN §22.4): identifiers.
const (
	// sidecartest's fakes.
	BrokerTierT2 = "T2"
	// Real stores a caller gave: the local stack's Redis, or server's core Env.
	BrokerTierT3 = "T3"
)

// The broker's settings (QD-702).
type BrokerSettings struct {
	// The engine's. Nil takes computeservice.DefaultComputeEngineSettings.
	Engine *computeservice.ComputeEngineSettings
	// Each fake Redis instance's. Nil takes sidecartest.DefaultFakeRedisSettings.
	Redis *sidecartest.FakeRedisSettings
	// The fake gates'. Nil takes sidecartest.DefaultFakeServiceGatesSettings.
	Gates *sidecartest.FakeServiceGatesSettings
	// The fake metrics'. Nil takes sidecartest.DefaultFakeMetricsSettings.
	Metrics *sidecartest.FakeMetricsSettings
	// The auth state's. Nil takes DefaultFakeComputeAuthStateSettings.
	AuthState *FakeComputeAuthStateSettings
	// How long a token a test sidecar mints is good for: 15 minutes, a service token's life (DESIGN §7.8).
	TokenLife time.Duration
	// The most service log lines the broker keeps for a test to read, the oldest dropped past it: 65536, far past any
	// test's requests. Non-positive keeps none.
	ServiceLogLineMaxCount int
	// The most bytes of an answer Do reads: 32 MiB, a gateway request's bound (§8.7), past any compute answer.
	ResponseByteCount int64
}

// The defaults, the only place one is set.
func DefaultBrokerSettings() *BrokerSettings {
	return &BrokerSettings{
		Engine:                 computeservice.DefaultComputeEngineSettings(),
		Redis:                  sidecartest.DefaultFakeRedisSettings(),
		Gates:                  sidecartest.DefaultFakeServiceGatesSettings(),
		Metrics:                sidecartest.DefaultFakeMetricsSettings(),
		AuthState:              DefaultFakeComputeAuthStateSettings(),
		TokenLife:              15 * time.Minute,
		ServiceLogLineMaxCount: 65536,
		ResponseByteCount:      32 * 1024 * 1024,
	}
}

// What NewBroker builds on. Every field may be left empty.
type BrokerArgs struct {
	// Nil takes DefaultBrokerSettings; a nil field of it, that field's default.
	Settings *BrokerSettings
	// Where the broker's ids for networks, members and sidecars are drawn from, by label; empty takes "broker".
	Seed string
	// The engine's, the authenticator's and the state's clock. Nil takes a FakeClock at sidecartest.DefaultClockStart,
	// which FakeClock answers.
	Clock sidecar.Clock
	// The main instance. Nil takes the Env's Redis where an Env is given, else a FakeRedis.
	Redis sidecar.Redis
	// {cmpa}'s instance (§14.4). Nil takes a second FakeRedis.
	AdmissionsRedis sidecar.Redis
	// The process's Env, through which handlers reach PostgreSQL: server's T3 passes core's. Nil takes the broker's
	// own, which grants its Redis, clock, metrics, gates, authenticator and abuse gate and refuses the rest, PostgreSQL
	// among them.
	Env operator.Env
	// §16.6's broker gate for kinds 19 and 21. Nil takes the one an area registered; with none, every approval route
	// answers 503.
	ApprovalGate computeservice.ComputeApprovalGate
	// Handlers planted by design route name, each served behind the whole guard in place of the registered one of that
	// name: a test's handler, registered as an area registers one (sidecar_testhooks).
	Handlers map[string]computeservice.ComputeHandler
	// Checks run on every admission route after the registered ones (sidecar_testhooks).
	AdmissionChecks []computeservice.ComputeAdmissionCheck
	// The tables' stand-ins where no Env is given (sidecar_testhooks): compute_abuse_hold's and
	// compute_catalog_version's. Nil takes an empty one of each; with an Env given, its tables unless set here.
	AbuseHolds      *FakeComputeAbuseHolds
	CatalogVersions *FakeComputeCatalogVersions
	// The host's region lookup. Nil takes FakeComputeRegions, every address placed nowhere.
	Regions computeservice.ComputeRegionLookup
	// Lifecycle and alarm lines. Nil discards.
	Log sidecar.Logger
}

// See the file header.
type Broker struct {
	settings *BrokerSettings
	seed     string
	tier     string
	ctx      context.Context
	cancel   context.CancelFunc

	clock           sidecar.Clock
	fakeClock       *sidecartest.FakeClock
	faults          *sidecartest.FaultQueue
	redis           sidecar.Redis
	admissionsRedis sidecar.Redis
	authenticator   *sidecartest.FakeAuthenticator
	gates           *sidecartest.FakeServiceGates
	metrics         *sidecartest.FakeMetrics
	abuse           *sidecartest.FakeAbuseGate
	authState       *FakeComputeAuthState
	abuseHolds      *FakeComputeAbuseHolds
	catalogVersions *FakeComputeCatalogVersions
	regions         computeservice.ComputeRegionLookup
	serviceLog      *BrokerServiceLog
	env             operator.Env
	host            *sidecar.ServiceHost
	engine          *computeservice.ComputeEngine
	server          *httptest.Server
	client          *http.Client

	groupsLock sync.Mutex
	groups     map[computeservice.ComputeMigrationGroup]bool

	stateLock      sync.Mutex
	labelNetworks  map[string]*BrokerNetwork
	labelSidecars  map[string]*BrokerSidecar
	memberNetworks map[sidecar.Id]sidecar.Id
	stopped        bool
}

// Starts a broker over args (see the file header), serving at once; Stop ends it.
func NewBroker(args *BrokerArgs) (*Broker, error) {
	if args == nil {
		args = &BrokerArgs{}
	}
	settings := brokerSettingsOf(args.Settings)
	if err := settings.Engine.Validate(); err != nil {
		return nil, err
	}
	seed := args.Seed
	if seed == "" {
		seed = "broker"
	}
	ctx, cancel := context.WithCancel(context.Background())
	self := &Broker{
		settings:       settings,
		seed:           seed,
		tier:           BrokerTierT2,
		ctx:            ctx,
		cancel:         cancel,
		faults:         sidecartest.NewFaultQueue(),
		gates:          sidecartest.NewFakeServiceGates(settings.Gates),
		metrics:        sidecartest.NewFakeMetrics(settings.Metrics),
		abuse:          sidecartest.NewFakeAbuseGate(),
		serviceLog:     newBrokerServiceLog(settings.ServiceLogLineMaxCount),
		groups:         map[computeservice.ComputeMigrationGroup]bool{},
		labelNetworks:  map[string]*BrokerNetwork{},
		labelSidecars:  map[string]*BrokerSidecar{},
		memberNetworks: map[sidecar.Id]sidecar.Id{},
	}
	for _, group := range []computeservice.ComputeMigrationGroup{computeservice.ComputeMigrationGroupC1, computeservice.ComputeMigrationGroupC2, computeservice.ComputeMigrationGroupC3} {
		self.groups[group] = true
	}
	self.clock = args.Clock
	if self.clock == nil {
		self.fakeClock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
		self.clock = self.fakeClock
	} else if fakeClock, ok := args.Clock.(*sidecartest.FakeClock); ok {
		self.fakeClock = fakeClock
	}
	self.authenticator = sidecartest.NewFakeAuthenticator(self.clock, self.faults)
	self.authState = NewFakeComputeAuthState(settings.AuthState, self.clock)

	self.redis = args.Redis
	if self.redis == nil && args.Env != nil {
		if redis, err := args.Env.Redis(); err == nil {
			self.redis = redis
		}
	}
	if self.redis == nil {
		self.redis = sidecartest.NewFakeRedis(ctx, self.clock, self.faults, nil, settings.Redis)
	} else {
		self.tier = BrokerTierT3
	}
	self.admissionsRedis = args.AdmissionsRedis
	if self.admissionsRedis == nil {
		self.admissionsRedis = sidecartest.NewFakeRedis(ctx, self.clock, self.faults, nil, settings.Redis)
	}
	if args.Env != nil {
		self.tier = BrokerTierT3
	}

	self.regions = args.Regions
	if self.regions == nil {
		self.regions = NewFakeComputeRegions()
	}
	self.abuseHolds = args.AbuseHolds
	self.catalogVersions = args.CatalogVersions
	if args.Env == nil {
		if self.abuseHolds == nil {
			self.abuseHolds = NewFakeComputeAbuseHolds()
		}
		if self.catalogVersions == nil {
			self.catalogVersions = NewFakeComputeCatalogVersions()
		}
	}

	self.host = &sidecar.ServiceHost{
		Authenticator: self.authenticator,
		Metrics:       self.metrics,
		Redis:         self.redis,
		Clock:         self.clock,
		Gates:         self.gates,
		Abuse:         self.abuse,
	}
	self.env = args.Env
	if self.env == nil {
		self.env = &brokerEnv{broker: self}
	}
	logger := args.Log
	if logger == nil {
		logger = sidecar.NewNoopLogger()
	}
	deps := &computeservice.ComputeEngineDeps{
		AuthState:       self.authState,
		ApprovalGate:    args.ApprovalGate,
		Env:             self.env,
		AdmissionsRedis: self.admissionsRedis,
		GroupLinked:     self.groupLinked,
		SecretFile: func(name string) ([]byte, error) {
			// the error names the file alone: a test broker holds no vault
			return nil, fmt.Errorf("computetest: a test broker holds no %s", name)
		},
		RegionLookup: self.regions,
		ServiceLog:   self.serviceLog,
		Log:          logger,
	}
	storesPlanted, err := brokerPlant(deps, &brokerPlanted{
		handlers:        args.Handlers,
		admissionChecks: args.AdmissionChecks,
		abuseHolds:      self.abuseHolds,
		catalogVersions: self.catalogVersions,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	if !storesPlanted {
		// the untagged build reads the Env's tables: no stand-in a test could set is answered
		self.abuseHolds, self.catalogVersions = nil, nil
	}
	engine, err := computeservice.NewComputeEngine(ctx, self.host, settings.Engine, deps)
	if err != nil {
		cancel()
		return nil, err
	}
	self.engine = engine
	server := httptest.NewUnstartedServer(engine.Handler())
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	self.server = server
	self.client = server.Client()
	return self, nil
}

// settings with every nil field its default, a copy.
func brokerSettingsOf(settings *BrokerSettings) *BrokerSettings {
	defaults := DefaultBrokerSettings()
	if settings == nil {
		return defaults
	}
	copied := *settings
	if copied.Engine == nil {
		copied.Engine = defaults.Engine
	}
	if copied.Redis == nil {
		copied.Redis = defaults.Redis
	}
	if copied.Gates == nil {
		copied.Gates = defaults.Gates
	}
	if copied.Metrics == nil {
		copied.Metrics = defaults.Metrics
	}
	if copied.AuthState == nil {
		copied.AuthState = defaults.AuthState
	}
	return &copied
}

// Ends the engine, every request in flight with it, the server and the broker's fakes. Safe more than once.
func (self *Broker) Stop() {
	stop := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.stopped {
			return false
		}
		self.stopped = true
		return true
	}()
	if !stop {
		return
	}
	self.engine.Close()
	self.server.Close()
	self.cancel()
}

// The tier it runs at: BrokerTierT2 on sidecartest's fakes, BrokerTierT3 on stores a caller gave.
func (self *Broker) Tier() string {
	return self.tier
}

// The base URL, the root of compute.<root>: every route is under its /v1/.
func (self *Broker) Url() string {
	return self.server.URL
}

// A client of the server, which a test's own requests go through.
func (self *Broker) Client() *http.Client {
	return self.client
}

// The engine, its routes and settings among what it answers.
func (self *Broker) Engine() *computeservice.ComputeEngine {
	return self.engine
}

// The design routes no linked area has built, each answering 503 not_built.
func (self *Broker) UnbuiltRoutes() []string {
	return self.engine.UnbuiltRoutes()
}

// The clock.
func (self *Broker) Clock() sidecar.Clock {
	return self.clock
}

// The FakeClock a test steps, nil where the test gave a clock of another kind.
func (self *Broker) FakeClock() *sidecartest.FakeClock {
	return self.fakeClock
}

// The fault queue the fake stores read, so a test drops or delays a store's call.
func (self *Broker) Faults() *sidecartest.FaultQueue {
	return self.faults
}

// The state a test sets.
func (self *Broker) AuthState() *FakeComputeAuthState {
	return self.authState
}

// §19.11's gates as a test sets them.
func (self *Broker) Gates() *sidecartest.FakeServiceGates {
	return self.gates
}

// The authenticator every token is minted through.
func (self *Broker) Authenticator() *sidecartest.FakeAuthenticator {
	return self.authenticator
}

// §21.7's standing and verification, per network.
func (self *Broker) Abuse() *sidecartest.FakeAbuseGate {
	return self.abuse
}

// The engine's metrics.
func (self *Broker) Metrics() *sidecartest.FakeMetrics {
	return self.metrics
}

// The main instance.
func (self *Broker) Redis() sidecar.Redis {
	return self.redis
}

// {cmpa}'s instance.
func (self *Broker) AdmissionsRedis() sidecar.Redis {
	return self.admissionsRedis
}

// The Env the handlers reach their stores through.
func (self *Broker) Env() operator.Env {
	return self.env
}

// compute_abuse_hold's stand-in, nil where the broker reads the Env's table.
func (self *Broker) AbuseHolds() *FakeComputeAbuseHolds {
	return self.abuseHolds
}

// compute_catalog_version's stand-in, nil where the broker reads the Env's table.
func (self *Broker) CatalogVersions() *FakeComputeCatalogVersions {
	return self.catalogVersions
}

// The host's region lookup.
func (self *Broker) Regions() computeservice.ComputeRegionLookup {
	return self.regions
}

// The service log's lines.
func (self *Broker) ServiceLog() *BrokerServiceLog {
	return self.serviceLog
}

// Whether group's tables are linked, as the binary's SidecarMgC*Linked answers: every group until Unlink.
func (self *Broker) groupLinked(group computeservice.ComputeMigrationGroup) bool {
	self.groupsLock.Lock()
	defer self.groupsLock.Unlock()
	return self.groups[group]
}

// Unlinks group, as a release build that does not link it reads: every route that names it answers 503.
func (self *Broker) Unlink(group computeservice.ComputeMigrationGroup) {
	self.groupsLock.Lock()
	defer self.groupsLock.Unlock()
	self.groups[group] = false
}

// Links group again.
func (self *Broker) Link(group computeservice.ComputeMigrationGroup) {
	self.groupsLock.Lock()
	defer self.groupsLock.Unlock()
	self.groups[group] = true
}

// An id drawn from the broker's seed for kind and label, the same each run.
func (self *Broker) id(kind string, label string) sidecar.Id {
	id := sidecar.Id{}
	copy(id[:], fakeBytes(self.seed, "broker id "+kind+" "+label, len(id)))
	return id
}

// A network's state loaded with features, its compute gate opened to it beside every network opened before, and in
// standard standing, verified (§21.7). A label used before answers the network it named.
func (self *Broker) AddNetwork(label string, features computeservice.ComputeAuthFeatures) (*BrokerNetwork, error) {
	if label == "" {
		return nil, fmt.Errorf("%w: a network needs a label", ErrBrokerInvalid)
	}
	network, made, err := func() (*BrokerNetwork, bool, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.stopped {
			return nil, false, ErrBrokerStopped
		}
		if network, ok := self.labelNetworks[label]; ok {
			return network, false, nil
		}
		network := &BrokerNetwork{broker: self, Label: label, NetworkId: self.id("network", label)}
		self.labelNetworks[label] = network
		return network, true, nil
	}()
	if err != nil || !made {
		return network, err
	}
	self.authState.LoadNetwork(network.NetworkId, features)
	self.gates.AddServiceNetworks(sidecar.ServiceGateCompute, connect.Id(network.NetworkId))
	self.abuse.Set(connect.Id(network.NetworkId), sidecar.AbuseStandingStandard, true)
	return network, nil
}

// One test network of a broker.
type BrokerNetwork struct {
	broker    *Broker
	Label     string
	NetworkId sidecar.Id
}

// A member of the network with role, its id drawn from the label; a label used before sets that member's role.
func (self *BrokerNetwork) AddMember(label string, role bridge.MemberRole) (sidecar.Id, error) {
	if label == "" {
		return sidecar.Id{}, fmt.Errorf("%w: a member needs a label", ErrBrokerInvalid)
	}
	memberId := self.broker.id("member", label)
	err := func() error {
		self.broker.stateLock.Lock()
		defer self.broker.stateLock.Unlock()
		if networkId, ok := self.broker.memberNetworks[memberId]; ok && networkId != self.NetworkId {
			return fmt.Errorf("%w: member %q is another network's", ErrBrokerInvalid, label)
		}
		self.broker.memberNetworks[memberId] = self.NetworkId
		return nil
	}()
	if err != nil {
		return sidecar.Id{}, err
	}
	self.broker.authState.SetMember(self.NetworkId, memberId, role)
	return memberId, nil
}

// What a test sidecar is admitted as.
type BrokerSidecarArgs struct {
	// Names the sidecar and its client among the broker's, each id drawn from it. Required and not taken.
	Label string
	// An untagged sidecar's member, from AddMember; the zero id for a tagged one.
	MemberId sidecar.Id
	// A tagged sidecar's tags, by label, each id drawn from it; none for an untagged one.
	TagLabels []string
	// Its row's flags and standing, as FakeComputeSidecar holds them.
	Consented          bool
	ReadOnly           bool
	Ephemeral          bool
	DelegationAdmitted bool
	EnclaveIncarnation bool
}

// A sidecar admitted in the network as args says, with a minter of its tokens.
func (self *BrokerNetwork) AddSidecar(args *BrokerSidecarArgs) (*BrokerSidecar, error) {
	if args == nil || args.Label == "" {
		return nil, fmt.Errorf("%w: a sidecar needs a label", ErrBrokerInvalid)
	}
	added := &BrokerSidecar{
		broker:    self.broker,
		Label:     args.Label,
		NetworkId: self.NetworkId,
		ClientId:  self.broker.id("client", args.Label),
		SidecarId: self.broker.id("sidecar", args.Label),
		MemberId:  args.MemberId,
	}
	tagIds := []sidecar.Id{}
	for _, tagLabel := range args.TagLabels {
		tagIds = append(tagIds, self.broker.id("tag", tagLabel))
	}
	err := func() error {
		self.broker.stateLock.Lock()
		defer self.broker.stateLock.Unlock()
		if self.broker.stopped {
			return ErrBrokerStopped
		}
		if _, ok := self.broker.labelSidecars[args.Label]; ok {
			return fmt.Errorf("%w: sidecar %q is added already", ErrBrokerInvalid, args.Label)
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}
	if err := self.broker.authState.Admit(self.NetworkId, &FakeComputeSidecar{
		SidecarId:          added.SidecarId,
		ClientId:           added.ClientId,
		MemberId:           args.MemberId,
		TagIds:             tagIds,
		Consented:          args.Consented,
		ReadOnly:           args.ReadOnly,
		Ephemeral:          args.Ephemeral,
		DelegationAdmitted: args.DelegationAdmitted,
		EnclaveIncarnation: args.EnclaveIncarnation,
	}); err != nil {
		return nil, err
	}
	self.broker.stateLock.Lock()
	defer self.broker.stateLock.Unlock()
	self.broker.labelSidecars[args.Label] = added
	return added, nil
}

// A sidecar the broker's state never admitted, with a minter of its tokens: what a refusal of an unadmitted caller is
// tested with. Its label must be new.
func (self *BrokerNetwork) Unadmitted(label string, memberId sidecar.Id) (*BrokerSidecar, error) {
	if label == "" {
		return nil, fmt.Errorf("%w: a sidecar needs a label", ErrBrokerInvalid)
	}
	self.broker.stateLock.Lock()
	defer self.broker.stateLock.Unlock()
	if _, ok := self.broker.labelSidecars[label]; ok {
		return nil, fmt.Errorf("%w: sidecar %q is added already", ErrBrokerInvalid, label)
	}
	unadmitted := &BrokerSidecar{
		broker:    self.broker,
		Label:     label,
		NetworkId: self.NetworkId,
		ClientId:  self.broker.id("client", label),
		SidecarId: self.broker.id("sidecar", label),
		MemberId:  memberId,
	}
	self.broker.labelSidecars[label] = unadmitted
	return unadmitted, nil
}

// One test sidecar: its ids, and a minter of its service tokens.
type BrokerSidecar struct {
	broker    *Broker
	Label     string
	NetworkId sidecar.Id
	ClientId  sidecar.Id
	SidecarId sidecar.Id
	// The zero id for a tagged sidecar.
	MemberId sidecar.Id
}

// The claims a token of audience names for the sidecar, issued now and good for the broker's TokenLife.
func (self *BrokerSidecar) Principal(audience string) *sidecar.Principal {
	now := self.broker.clock.Now()
	sidecarId := connect.Id(self.SidecarId)
	principal := &sidecar.Principal{
		NetworkId:   connect.Id(self.NetworkId),
		ClientId:    connect.Id(self.ClientId),
		SidecarId:   &sidecarId,
		Audience:    audience,
		ProjVersion: 1,
		IssuedAt:    now,
		ExpiresAt:   now.Add(self.broker.settings.TokenLife),
	}
	if self.MemberId != (sidecar.Id{}) {
		memberId := connect.Id(self.MemberId)
		principal.MemberId = &memberId
	}
	return principal
}

// A compute token of the sidecar's (computeservice.ComputeAudience).
func (self *BrokerSidecar) Token() string {
	return self.broker.authenticator.Issue(self.Principal(computeservice.ComputeAudience))
}

// A token of the sidecar's for another audience, which the broker refuses.
func (self *BrokerSidecar) TokenFor(audience string) string {
	return self.broker.authenticator.Issue(self.Principal(audience))
}

// Sends method path with body under a fresh compute token of the sidecar's and headers, and answers the response with
// its body read whole, at most the broker's ResponseByteCount.
func (self *BrokerSidecar) Do(ctx context.Context, method string, path string, body []byte, headers map[string]string) (*BrokerResponse, error) {
	merged := map[string]string{"Authorization": "Bearer " + self.Token()}
	for name, value := range headers {
		merged[name] = value
	}
	return self.broker.Do(ctx, method, path, body, merged)
}

// One answer, read whole.
type BrokerResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// A refusal's body, as the engine writes it (engine_refusal.go).
type BrokerRefusal struct {
	Code         computeservice.ComputeRefusalCode `json:"code"`
	Reason       string                            `json:"reason,omitempty"`
	RetryAfterMs int64                             `json:"retry_after_ms,omitempty"`
}

// The answer's refusal, nil for an answer that is none: a JSON body naming a code.
func (self *BrokerResponse) Refusal() *BrokerRefusal {
	if !strings.HasPrefix(self.Header.Get("Content-Type"), "application/json") {
		return nil
	}
	refusal := &BrokerRefusal{}
	if err := json.Unmarshal(self.Body, refusal); err != nil || refusal.Code == "" {
		return nil
	}
	return refusal
}

// Sends method path with body and headers as given, no token added, and answers the response read whole.
func (self *Broker) Do(ctx context.Context, method string, path string, body []byte, headers map[string]string) (*BrokerResponse, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("computetest: a path from the root, not %q", path)
	}
	request, err := http.NewRequestWithContext(ctx, method, self.Url()+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := self.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, self.settings.ResponseByteCount))
	if err != nil {
		return nil, err
	}
	return &BrokerResponse{Status: response.StatusCode, Header: response.Header.Clone(), Body: responseBody}, nil
}

// networkId's projection as the ledger reads it (§9.7: settled, unsettled, holds, the state), through the broker's
// Env: its scripts run on real Redis, and a FakeRedis, which holds no twin of them, answers its no-twin error.
func (self *Broker) Projection(ctx context.Context, networkId sidecar.Id) (*model.ComputeProjection, error) {
	return model.ComputeProjectionRead(self.env, ctx, networkId)
}

// An operation's row (compute_op), nil for none, through the broker's Env: its own Env grants no PostgreSQL, so this
// answers not granted on T2; server's T3 gives core's Env.
func (self *Broker) Op(ctx context.Context, networkId sidecar.Id, opKey sidecar.Id) (*model.ComputeOp, error) {
	return model.ComputeOpGet(self.env, ctx, networkId, opKey)
}

// The service log's lines as the engine wrote them, the newest kept (see BrokerSettings.ServiceLogLineMaxCount). Safe
// for concurrent use.
type BrokerServiceLog struct {
	maxCount int

	stateLock sync.Mutex
	entries   []*computeservice.ComputeServiceLogEntry
}

var _ computeservice.ComputeServiceLog = (*BrokerServiceLog)(nil)

func newBrokerServiceLog(maxCount int) *BrokerServiceLog {
	return &BrokerServiceLog{maxCount: maxCount}
}

// Keeps a copy of entry, dropping the oldest past the bound.
func (self *BrokerServiceLog) Write(entry *computeservice.ComputeServiceLogEntry) {
	if self.maxCount <= 0 {
		return
	}
	copied := *entry
	copied.RowIds = slices.Clone(entry.RowIds)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.entries = append(self.entries, &copied)
	if self.maxCount < len(self.entries) {
		self.entries = slices.Clone(self.entries[len(self.entries)-self.maxCount:])
	}
}

// The lines kept, oldest first.
func (self *BrokerServiceLog) Lines() []*computeservice.ComputeServiceLogEntry {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.entries)
}

// The broker's own Env: its stores, and a refusal for each service a test broker does not hold, PostgreSQL among them.
type brokerEnv struct {
	broker *Broker
}

var _ operator.Env = (*brokerEnv)(nil)

// The refusal of a service the broker does not hold.
func (self *brokerEnv) refusal(service string) error {
	return &operator.NotGrantedError{Service: service, Reason: "a test broker on sidecartest's fakes holds none; server's T3 passes core's Env"}
}

func (self *brokerEnv) Db() (operator.Db, error) {
	return nil, self.refusal("Db")
}

func (self *brokerEnv) Redis() (operator.Redis, error) {
	return self.broker.redis, nil
}

func (self *brokerEnv) Blobs() (operator.BlobStore, error) {
	return nil, self.refusal("Blobs")
}

func (self *brokerEnv) Authenticator() (operator.Authenticator, error) {
	return self.broker.authenticator, nil
}

func (self *brokerEnv) Quota() (operator.Quota, error) {
	return nil, self.refusal("Quota")
}

func (self *brokerEnv) Metrics() (operator.Metrics, error) {
	return self.broker.metrics, nil
}

func (self *brokerEnv) Tasks() (operator.Tasks, error) {
	return nil, self.refusal("Tasks")
}

func (self *brokerEnv) Push() (operator.Push, error) {
	return nil, self.refusal("Push")
}

func (self *brokerEnv) ServiceClient() (operator.ServiceClientSource, error) {
	return nil, self.refusal("ServiceClient")
}

func (self *brokerEnv) Clock() (operator.Clock, error) {
	return self.broker.clock, nil
}

func (self *brokerEnv) ClockCheck() (operator.ClockCheck, error) {
	return nil, self.refusal("ClockCheck")
}

func (self *brokerEnv) Gates() (operator.ServiceGates, error) {
	return self.broker.gates, nil
}

func (self *brokerEnv) Budget() (operator.WriteBudget, error) {
	return nil, self.refusal("Budget")
}

func (self *brokerEnv) Abuse() (operator.AbuseGate, error) {
	return self.broker.abuse, nil
}

// What a broker plants into its engine (broker_testhooks.go).
type brokerPlanted struct {
	handlers        map[string]computeservice.ComputeHandler
	admissionChecks []computeservice.ComputeAdmissionCheck
	abuseHolds      *FakeComputeAbuseHolds
	catalogVersions *FakeComputeCatalogVersions
}
