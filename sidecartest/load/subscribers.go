// §22.8's evs row's "1,000 subscribers per repo" (TEST-M2-14; §11.15's commit-to-hint target, p99 ≤ 2 s, which
// testdata/targets.yml names evs-hint-1000-subscribers), and the evs load the soak drives (server's
// local/sidecar-soak).
//
// SubscriberWorkload's arrivals are commits to one ref that every subscriber holds a lease on, paced open loop by a
// Driver. Each arrival commits, takes the time evs answered, and waits until every subscriber has been hinted that
// version or a newer one, since §11.10's hints coalesce: a subscriber's latency is from the commit's answer to the
// first hint that covers it, and one not hinted within HintTimeout is a missed hint and fails its arrival. A hint
// that lands before the answer reads as zero.
//
// EvsSubscriberWorld is the T2 target: evsservice's engine on a host's stores, a writer device committing through
// sidecar.EvsClient as built, the fake gkm on the host's blobs, an authorization state listing every subscriber as
// a reader, and Subscribers leases taken through the engine's own POST /evs/v1/subscriptions route, each under its
// own client's token. A hint is read where step 8 hands it to ServiceHost.Push, as a subscriber's resident would
// take it, and goes no further. On a fake clock a run's latencies are all zero, so a T2 run proves that every
// subscriber is hinted every commit and nothing about time: its report is a smoke. The target's latency, on real
// stores and real time, is T3's, whose target over server's engine on the private stack is not built yet.
//
// A workload runs once. Its methods are safe for concurrent use.

package load

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// targets.yml's row for §11.15's hint target at §22.8's 1,000 subscribers.
const SubscriberTargetId = "evs-hint-1000-subscribers"

// The subscribers a repo holds at most (§20.4's evs_subscribers_per_repo, plan-EVS1-subscription-caps#1), which a run
// at the target's scale reaches.
const SubscribersPerRepo = 1000

// What a subscriber workload drives.
type SubscriberTarget interface {
	// How many subscribers hold a lease on the committed ref.
	Subscribers() int
	// Sets where each subscriber's hints go: hinted(subscriber, version) for each hint naming the ref at a version,
	// subscriber counting from 0. Called once, before the first commit.
	Watch(hinted func(subscriber int, version uint64))
	// One commit to the subscribed ref, returning once evs answered: the ref version it committed at.
	Commit(ctx context.Context, arrival int64) (uint64, error)
}

type SubscriberSettings struct {
	// The pace and phases, the driver's.
	Driver *DriverSettings
	// How long an arrival waits, on the driver's clock, for every subscriber's hint before the rest count as
	// missed: §11.15's p99 bound, 2 s.
	HintTimeout time.Duration
}

// One commit a second for a minute after ten seconds of warm-up, each waiting up to §11.15's 2 s for its hints.
func DefaultSubscriberSettings() *SubscriberSettings {
	driver := DefaultDriverSettings()
	driver.Name = "evs-subscribers"
	return &SubscriberSettings{Driver: driver, HintTimeout: 2 * time.Second}
}

// What a subscriber run reports: the driver's report of its commits, and every subscriber's hint latency.
type SubscriberReport struct {
	Report      *Report `json:"report"`
	Subscribers int     `json:"subscribers"`
	// From each steady commit's answer to each subscriber's first hint covering it.
	HintLatencyMillis Percentiles `json:"hint_latency_ms"`
	// Steady commits' subscribers not hinted within HintTimeout.
	MissedHints int64 `json:"missed_hints"`
}

// See the file header.
type SubscriberWorkload struct {
	settings *SubscriberSettings
	target   SubscriberTarget
	clock    sidecartest.Clock
	driver   *Driver

	stateLock sync.Mutex
	// per subscriber: each hint it took, in arrival order
	hints [][]subscriberHint
	// closed and replaced at each hint
	hintChanged chan struct{}
	latencies   []time.Duration
	missed      int64
	started     bool
	watchOnce   sync.Once
	// arrivals waiting on their hints with their timeout armed, closed and replaced at each change
	waiting     int64
	waitChanged chan struct{}
}

type subscriberHint struct {
	version uint64
	at      time.Time
}

// A workload of target under settings, nil for the defaults.
func NewSubscriberWorkload(settings *SubscriberSettings, target SubscriberTarget) *SubscriberWorkload {
	if settings == nil {
		settings = DefaultSubscriberSettings()
	}
	clock := settings.Driver.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	workload := &SubscriberWorkload{
		settings:    settings,
		target:      target,
		clock:       clock,
		hints:       make([][]subscriberHint, target.Subscribers()),
		hintChanged: make(chan struct{}),
		waitChanged: make(chan struct{}),
	}
	workload.driver = NewDriver(settings.Driver, workload.arrival)
	return workload
}

// The driver's progress, and a channel that closes at its next change.
func (self *SubscriberWorkload) Progress() (Progress, <-chan struct{}) {
	return self.driver.Progress()
}

// How many arrivals wait on their hints with their timeout armed, and a channel that closes at the next change: with
// Progress, how a run on a fake clock knows every launched commit has ended or waits on the clock before it moves
// time.
func (self *SubscriberWorkload) Waiting() (int64, <-chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.waiting, self.waitChanged
}

func (self *SubscriberWorkload) addWaiting(delta int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.waiting += delta
	close(self.waitChanged)
	self.waitChanged = make(chan struct{})
}

// Where the target hands each subscriber's hint.
func (self *SubscriberWorkload) hinted(subscriber int, version uint64) {
	at := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if subscriber < 0 || len(self.hints) <= subscriber {
		return
	}
	self.hints[subscriber] = append(self.hints[subscriber], subscriberHint{version: version, at: at})
	close(self.hintChanged)
	self.hintChanged = make(chan struct{})
}

// Whether arrival n is the steady phase's, by the driver's own reckoning of its due time.
func (self *SubscriberWorkload) steady(n int64) bool {
	driver := self.settings.Driver
	return driver.Warmup <= time.Duration(float64(n)*float64(time.Second)/driver.Rate)
}

// One arrival: a commit, then every subscriber's hint of it or a newer version.
func (self *SubscriberWorkload) arrival(ctx context.Context, n int64) error {
	version, err := self.target.Commit(ctx, n)
	if err != nil {
		return err
	}
	answered := self.clock.Now()
	timeout := self.clock.After(self.settings.HintTimeout)
	self.addWaiting(1)
	defer self.addWaiting(-1)
	for {
		self.stateLock.Lock()
		missing := 0
		for _, hints := range self.hints {
			if len(hints) == 0 || hints[len(hints)-1].version < version {
				missing += 1
			}
		}
		changed := self.hintChanged
		self.stateLock.Unlock()
		if missing == 0 {
			break
		}
		select {
		case <-changed:
			continue
		case <-timeout:
		case <-ctx.Done():
		}
		if self.steady(n) {
			self.stateLock.Lock()
			self.missed += int64(missing)
			self.stateLock.Unlock()
		}
		return fmt.Errorf("%d of %d subscribers not hinted version %d within %s", missing, len(self.hints), version, self.settings.HintTimeout)
	}
	if !self.steady(n) {
		return nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, hints := range self.hints {
		for _, hint := range hints {
			if version <= hint.version {
				self.latencies = append(self.latencies, max(0, hint.at.Sub(answered)))
				break
			}
		}
	}
	return nil
}

// One arrival as a Workload, for a caller that paces arrivals itself across phases, as the soak does, numbering them
// so no two share a number: the target is watched before the first. A caller does this or Run, never both.
func (self *SubscriberWorkload) Attempt(ctx context.Context, arrival int64) error {
	self.watchOnce.Do(func() { self.target.Watch(self.hinted) })
	return self.arrival(ctx, arrival)
}

// Runs the workload once and reports.
func (self *SubscriberWorkload) Run(ctx context.Context) *SubscriberReport {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.started {
			panic("load: a SubscriberWorkload runs once")
		}
		self.started = true
	}()
	self.watchOnce.Do(func() { self.target.Watch(self.hinted) })
	report := self.driver.Run(ctx)
	subscribers := self.target.Subscribers()
	if SubscribersPerRepo <= subscribers {
		report.Targets = append(report.Targets, SubscriberTargetId)
	} else {
		report.Notes = append(report.Notes, fmt.Sprintf("%d subscribers, short of §22.8's %d: no target's evidence", subscribers, SubscribersPerRepo))
	}
	report.Settings["subscribers"] = fmt.Sprint(subscribers)
	report.Settings["hint_timeout"] = self.settings.HintTimeout.String()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &SubscriberReport{
		Report:            report,
		Subscribers:       subscribers,
		HintLatencyMillis: PercentilesOf(self.latencies),
		MissedHints:       self.missed,
	}
}

// Why the run is no evidence for its target, or nil: the report's own reasons, and a missed hint, which fails the
// target outright.
func (self *SubscriberReport) GateEvidence() error {
	if err := self.Report.GateEvidence(); err != nil {
		return err
	}
	if 0 < self.MissedHints {
		return fmt.Errorf("%s missed %d hints", self.Report.Name, self.MissedHints)
	}
	return nil
}

type EvsSubscriberWorldSettings struct {
	// Leases on the committed ref, each its own client and sidecar. At most SubscribersPerRepo, the route's cap.
	Subscribers int
	// The bytes each commit writes, one small file, inline.
	CommitByteCount int
	// The engine's tunables; nil takes evsservice's defaults with batches flushed at once, since a fake clock's
	// flush timer moves only when the run moves it.
	Engine *evsservice.EvsSettings
}

// §22.8's 1,000 subscribers, each commit 64 B.
func DefaultEvsSubscriberWorldSettings() *EvsSubscriberWorldSettings {
	return &EvsSubscriberWorldSettings{Subscribers: SubscribersPerRepo, CommitByteCount: 64}
}

// See the file header.
type EvsSubscriberWorld struct {
	ctx       context.Context
	fakes     *sidecartest.FakeHost
	clock     sidecartest.Clock
	settings  *EvsSubscriberWorldSettings
	networkId sidecar.Id
	repoId    sidecar.Id
	refId     sidecar.Id
	writer    *sidecartest.FakeGkmSigner
	clientId  sidecar.Id
	engine    *evsservice.EvsEngine
	device    *sidecar.EvsClient
	closers   []func()
	// each subscriber's client, whose hints are its
	subscriberClients map[connect.Id]int

	stateLock sync.Mutex
	watch     func(subscriber int, version uint64)
}

// A world on fakes' stores, its engine on host, which is fakes' or a Net's recorder over them, every lease taken
// before it returns. Close ends it.
func NewEvsSubscriberWorld(ctx context.Context, fakes *sidecartest.FakeHost, host *sidecar.ServiceHost, clock sidecartest.Clock, settings *EvsSubscriberWorldSettings) (world *EvsSubscriberWorld, returnErr error) {
	if settings == nil {
		settings = DefaultEvsSubscriberWorldSettings()
	}
	if settings.Subscribers <= 0 || SubscribersPerRepo < settings.Subscribers {
		return nil, fmt.Errorf("load: %d subscribers, where a repo takes 1 to %d", settings.Subscribers, SubscribersPerRepo)
	}
	world = &EvsSubscriberWorld{
		ctx: ctx, fakes: fakes, clock: clock, settings: settings,
		networkId: sidecar.NewId(), repoId: sidecar.NewId(), writer: sidecartest.NewFakeGkmSigner(), clientId: sidecar.NewId(),
		subscriberClients: map[connect.Id]int{},
	}
	defer func() {
		if returnErr != nil {
			world.Close()
		}
	}()
	sidecartest.RegisterEvsTwins(fakes.Redis)
	network := connect.Id(world.networkId).String()
	if err := fakes.Gates.Set(fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n", network)); err != nil {
		return nil, err
	}
	fakes.Quota.SetBalance(connect.Id(world.networkId), 1<<40)
	fakes.Quota.SetLimits(connect.Id(world.networkId), &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{"evs_subscribers_per_repo": SubscribersPerRepo}})

	readers := []sidecar.Id{world.writer.SidecarId}
	subscriberSidecars := make([]sidecar.Id, settings.Subscribers)
	subscriberClients := make([]sidecar.Id, settings.Subscribers)
	for i := range settings.Subscribers {
		subscriberSidecars[i] = sidecar.NewId()
		subscriberClients[i] = sidecar.NewId()
		readers = append(readers, subscriberSidecars[i])
		world.subscriberClients[connect.Id(subscriberClients[i])] = i
	}
	rows := sidecartest.FakeGkmAuthRows(&protocol.AclRepo{RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(sidecar.NewId(), readers...)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	view := sidecartest.NewFakeGkmAuthLog().Append(&sidecartest.FakeGkmAuthFixture{
		Rows:         rows,
		IdentityKeys: map[sidecar.Id][]byte{world.writer.SidecarId: world.writer.PublicKey()},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{world.repoId: readers},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{world.repoId: {world.writer.SidecarId}},
	})
	gkm := sidecartest.NewFakeGkm(clock, host.Blobs, nil)

	usage, err := evsservice.NewUsageBatcher(ctx, host, nil)
	if err != nil {
		return nil, err
	}
	world.closers = append(world.closers, usage.Close)
	quota, err := evsservice.NewQuotaGate(ctx, host, nil)
	if err != nil {
		return nil, err
	}
	world.closers = append(world.closers, quota.Close)
	receiptKey := sha256.Sum256([]byte("evs subscriber world receipt key"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{
		{KeyId: 1, Key: receiptKey[:], IssueFrom: clock.Now().Add(-48 * time.Hour)},
	}, nil)
	if err != nil {
		return nil, err
	}
	engineSettings := settings.Engine
	if engineSettings == nil {
		engineSettings = evsservice.DefaultEvsSettings()
		engineSettings.InstanceFormat = sidecar.EvsRepoFormat1
		engineSettings.BatchFlushDelay = 0
	}
	engineHost := *host
	engineHost.Push = &subscriberPush{world: world}
	world.engine, err = evsservice.NewEvsEngine(ctx, &engineHost, engineSettings, &evsservice.EvsEngineDeps{
		AuthState: &subscriberAuthState{networkId: world.networkId},
		Uploads:   &evsservice.EvsUploadDeps{Keys: receiptKeys, Quota: quota, Usage: usage},
		GateViews: &subscriberGateViews{networkId: world.networkId, view: view},
	})
	if err != nil {
		return nil, err
	}
	world.closers = append(world.closers, world.engine.Close)

	first, err := host.Blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: first.ClusterId(), CreatorSidecarId: world.writer.SidecarId}).Marshal()
	if err != nil {
		return nil, err
	}
	if _, err := first.PutIfNoneMatch(ctx, sidecar.EvsPlaceKey(world.repoId), placeBytes, nil); err != nil {
		return nil, err
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: world.networkId.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	if _, err := first.PutIfNoneMatch(ctx, sidecar.EvsRepoObjectKey(world.repoId), repoBytes, nil); err != nil {
		return nil, err
	}

	groupClient := gkm.Client(world.writer.SidecarId, world.writer.Sign)
	groupClient.AuthAdvanced(view)
	repoKey, err := groupClient.CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		return nil, err
	}
	refKey, err := sidecar.NewEvsRefKey(repoKey)
	if err != nil {
		return nil, err
	}
	if world.refId, err = sidecar.EvsRefId(refKey, []byte("main")); err != nil {
		return nil, err
	}
	deviceGkm := gkm.Client(world.writer.SidecarId, world.writer.Sign)
	deviceGkm.AuthAdvanced(view)
	identity := &sidecar.SidecarIdentity{
		NetworkId: world.networkId, SidecarId: world.writer.SidecarId, ClientId: world.clientId, Generation: 1,
		IdentityPublicKey: world.writer.PublicKey(),
	}
	world.device, err = sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: world.networkId,
		EvsUrl:    "https://evs.example",
		Transport: world,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return world.token(world.clientId, world.writer.SidecarId, scopes), nil
		},
		Sign:     sidecar.EvsSignFunction(world.writer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      deviceGkm,
		Store:    sidecartest.NewFakeStore().Root(),
		Config:   func() sidecar.GkmAuthView { return view },
		Clock:    clock,
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		return nil, err
	}
	world.closers = append(world.closers, world.device.Close)

	for i := range settings.Subscribers {
		if err := world.subscribe(subscriberClients[i], subscriberSidecars[i]); err != nil {
			return nil, fmt.Errorf("subscriber %d: %w", i, err)
		}
	}
	return world, nil
}

// Ends the engine, the device and what they run on.
func (self *EvsSubscriberWorld) Close() {
	for i := len(self.closers) - 1; 0 <= i; i -= 1 {
		self.closers[i]()
	}
	self.closers = nil
}

// A token for a client and sidecar of the world's network, as the exchange mints one.
func (self *EvsSubscriberWorld) token(clientId sidecar.Id, sidecarId sidecar.Id, scopes []string) string {
	connectSidecarId := connect.Id(sidecarId)
	return self.fakes.Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(self.networkId),
		ClientId:  connect.Id(clientId),
		SidecarId: &connectSidecarId,
		Audience:  evsservice.EvsAudience,
		Scopes:    scopes,
		IssuedAt:  self.clock.Now(),
		ExpiresAt: self.clock.Now().Add(15 * time.Minute),
	})
}

// One subscriber's lease on main, the whole ref, through POST /evs/v1/subscriptions.
func (self *EvsSubscriberWorld) subscribe(clientId sidecar.Id, sidecarId sidecar.Id) error {
	body, err := proto.Marshal(&protocol.EvsSubscriptionRequest{RepoId: self.repoId.Bytes(), RefId: self.refId.Bytes(), PathEpoch: 1})
	if err != nil {
		return err
	}
	request := httptest.NewRequestWithContext(self.ctx, http.MethodPost, "/evs/v1/subscriptions", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+self.token(clientId, sidecarId, []string{"repo:" + self.repoId.String() + ":r"}))
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		reply := &protocol.EvsRefusalReply{}
		proto.Unmarshal(recorder.Body.Bytes(), reply)
		return fmt.Errorf("the lease route answered %d %s", recorder.Code, reply.GetCode())
	}
	return nil
}

// The device's transport: the engine's handler.
func (self *EvsSubscriberWorld) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	response := recorder.Result()
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		// the client would wait out the answer on a clock this world may hold still: the arrival fails instead
		reply := &protocol.EvsRefusalReply{}
		proto.Unmarshal(recorder.Body.Bytes(), reply)
		return nil, fmt.Errorf("evs answered %d %s", response.StatusCode, reply.GetCode())
	}
	return response, nil
}

func (self *EvsSubscriberWorld) Subscribers() int {
	return self.settings.Subscribers
}

func (self *EvsSubscriberWorld) Watch(hinted func(subscriber int, version uint64)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.watch = hinted
}

// One small file written to main.
func (self *EvsSubscriberWorld) Commit(ctx context.Context, arrival int64) (uint64, error) {
	content := bytes.Repeat([]byte(fmt.Sprintf("commit %d;", arrival)), self.settings.CommitByteCount/8+1)[:self.settings.CommitByteCount]
	result, err := self.device.Repo(self.repoId).Write(ctx, &sidecar.EvsWriteArgs{
		Path: fmt.Sprintf("load/%d.txt", arrival), Content: bytes.NewReader(content), Size: int64(len(content)),
	})
	if err != nil {
		return 0, err
	}
	return result.Version, nil
}

// The engine whose step 8 hints the subscribers, for a caller that waits out its work.
func (self *EvsSubscriberWorld) Engine() *evsservice.EvsEngine {
	return self.engine
}

// ServiceHost.Push as the subscribers' residents: each evs hint is its client's subscriber's, and goes no further.
type subscriberPush struct {
	world *EvsSubscriberWorld
}

func (self *subscriberPush) Hint(ctx context.Context, clientIds []connect.Id, hint *sidecar.ClientHint) error {
	if hint == nil || hint.Kind != uint32(protocol.MessageType_EVS_HEAD_CHANGED) {
		return nil
	}
	changed := &protocol.EvsHeadChanged{}
	if err := proto.Unmarshal(hint.Body, changed); err != nil {
		return err
	}
	if !bytes.Equal(changed.GetRefId(), self.world.refId.Bytes()) {
		return nil
	}
	self.world.stateLock.Lock()
	watch := self.world.watch
	self.world.stateLock.Unlock()
	if watch == nil {
		return nil
	}
	for _, clientId := range clientIds {
		if subscriber, ok := self.world.subscriberClients[clientId]; ok {
			watch(subscriber, changed.GetVersion())
		}
	}
	return nil
}

func (self *subscriberPush) HintSidecars(ctx context.Context, sidecarIds []connect.Id, hint *sidecar.ClientHint) error {
	return errors.New("load: evs hints clients, never sidecars")
}

type subscriberAuthState struct {
	networkId sidecar.Id
}

func (self *subscriberAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *subscriberAuthState) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *subscriberAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *subscriberAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	return &evsservice.EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: self.networkId}, evsservice.EvsAuthAllowed
}

type subscriberGateViews struct {
	networkId sidecar.Id
	view      sidecar.GkmAuthView
}

func (self *subscriberGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	if networkId != self.networkId {
		return nil, evsservice.EvsAuthUnknown
	}
	return self.view, evsservice.EvsAuthAllowed
}
