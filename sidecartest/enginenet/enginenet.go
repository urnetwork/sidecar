// evs and gkm on a sidecartest Net as a hosted network's Sidecar reaches them (QD-804's tests, the daemon's
// composition in cli/daemon_clients.go): the engines run on the Net's host behind their real authorization seams, so a
// Sidecar's own GkmApi, EvsClient and config head reader talk to real engines judging by the network's real log.
//
//	gate      §8.9's one gate cache, sidecar.AclGateCache, over AclGateDirectSource on the Net's Redis and stores,
//	          which reads each network's proj/ as api's sequencer (the Net's FakeApi) writes it; gkm's and evs's
//	          AuthState are their real AclGkmAuthState and AclEvsAuthState over it, evs's push views
//	          evsservice.NewAclGateViews over it, and rev/ is sidecar.RevocationChecker on the Net's stores
//	origins  the Net's FakeApi serves https://evs.<domain> and https://gkm.<domain> through the engines' handlers
//	          (FakeApi.ServeService), the origins a Net's Sidecar settings name, on the transport its api uses
//	scopes    the exchange's scope source is api's (TEAM-M2-15's ProjectionExchangeScopeSource) copied over the gate:
//	          §8's table (sidecar.AclExchangeScopes) at the gate's state of the token's network, with its refusals,
//	          so the exchange answers temporarily_unavailable while the gate holds no state of the network,
//	          invalid_grant to a client the state does not admit, not yet or no longer, and invalid_scope to a
//	          request it grants none of, as api's does (exchangeScopes)
//
// Every request is the real gate's, a bootstrapping network's included: its first device reaches evs and gkm only once
// base 1 has landed (bootstrap.go; QD-824), and before that the gate holds no log of it and answers nothing.
//
// The gate learns of a log's new entries when told (Sync): api writes no {acl_} hint here, and the cache polls
// nothing. An ask of a network the gate holds no state of tells it too, as at api, and the load it starts installs by
// itself, so a test that asks again before the gate holds the network holds the gate's loads first (holdGateLoads).
// The engines are the Net's (AddEngine), closed with it; the cache closes at the test's end and waits for its loaders,
// so none reads the Net's stores, reaches its hooks or counts a load once the test's cleanups move on. Safe for
// concurrent use.

package enginenet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Tunables of an Engines world.
type EnginesSettings struct {
	// Catch the service gate up before pricing an exchange. Used when the fixture drives the unmodified CLI.
	FollowBeforeExchange bool
	// The evs storage balance each opened network starts with: 1 TiB, so no test write meets quota.
	NetworkBalanceByteCount int64
	// The EVS binary the service runs. An unspecified format exercises the format-1 rollout.
	EvsInstanceFormat uint32
	// How long a wait on the gate's load of a log may take in real time: 60 s, only a failure's bound.
	SyncTimeout time.Duration
	// How far before the Net's clock evs's receipt key may issue from: 48 h, so a receipt is issued at once.
	ReceiptKeyAge time.Duration
	// How long a statement PostStatement files lives, its header's not_after past the Net's clock: 1 h.
	StatementLife time.Duration
	// How many head/ objects one list of a repo's heads reads (RefHeads): 1,000, past any test's refs.
	HeadListPageCount int
}

// 1 TiB a network, 60 s a load, a receipt key 48 h old, statements for an hour and 1,000 heads a list.
func DefaultEnginesSettings() *EnginesSettings {
	return &EnginesSettings{
		NetworkBalanceByteCount: 1024 * 1024 * 1024 * 1024,
		EvsInstanceFormat:       sidecar.EvsRepoFormat1,
		SyncTimeout:             60 * time.Second,
		ReceiptKeyAge:           48 * time.Hour,
		StatementLife:           time.Hour,
		HeadListPageCount:       1000,
	}
}

// The world: see the file header.
type Engines struct {
	t        testing.TB
	net      *sidecartest.Net
	api      *sidecartest.FakeApi
	settings *EnginesSettings

	cache *sidecar.AclGateCache
	// what the cache reads, which a test holds (holdGateLoads)
	gateSource *enginesGateSource
	// how many loads the cache has finished, which Sync waits on
	loads *sidecar.MonitorValue[uint64]
	gkm   *gkmservice.GkmEngine
	evs   *enginesEvsHost

	stateLock sync.Mutex
	// every request the exchange asked the scope source, in order
	scopeRequests []*sidecartest.FakeApiScopeRequest
}

// evs and gkm on net's host behind the real gate, the Net's api serving their origins and minting their scopes.
// settings may be nil for the defaults.
func NewEngines(t testing.TB, net *sidecartest.Net, settings *EnginesSettings) *Engines {
	t.Helper()
	if settings == nil {
		settings = DefaultEnginesSettings()
	}
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	self := &Engines{
		t:        t,
		net:      net,
		api:      api,
		settings: settings,
		loads:    sidecar.NewMonitorValue(uint64(0)),
	}
	sidecartest.RegisterEvsTwins(net.Fakes().Redis)

	gateSettings := sidecar.DefaultAclGateSettings()
	gateSettings.Log = sidecar.NewNoopLogger()
	gateSettings.PollInterval = 0
	gateSettings.FailureBackoff = 0
	gateSettings.OnLoad = func(networkId sidecar.Id, pin *bridge.AuthPin, err error) {
		self.loads.Update(func(count uint64) uint64 { return count + 1 })
	}
	self.gateSource = &enginesGateSource{source: sidecar.NewAclGateDirectSource(net.Host().Redis, net.Host().Blobs, gateSettings)}
	self.cache = sidecar.NewAclGateCache(net.Context(), self.gateSource, net.Clock(), gateSettings)
	// its close cancels a load still running, whose store read the fakes then answer, so the wait ends
	t.Cleanup(self.cache.CloseAndWait)
	revocationSettings := sidecar.DefaultRevocationSettings()
	revocationSettings.Clock = net.Clock()
	revocations := sidecar.NewRevocationChecker(net.Host().Blobs, func(object []byte) ([]byte, error) {
		return nil, errors.New("this world signs no revocation object")
	}, revocationSettings)

	gkmSettings := gkmservice.DefaultGkmServiceSettings()
	// every read of place/, repo/, the forms and group-info goes to the store, so a write is seen at once
	gkmSettings.RepoCacheTtl = 0
	gkmSettings.FormCacheTtl = 0
	gkmSettings.GroupInfoCacheTtl = 0
	place := *gkmSettings.Place
	place.NotFoundTtl = 0
	gkmSettings.Place = &place
	gkmState := gkmservice.NewAclGkmAuthState(self.cache, revocations, net.Clock())
	gkmEngine, err := net.AddEngine("gkm", func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return gkmservice.NewGkmEngine(ctx, host, gkmSettings, &gkmservice.GkmEngineDeps{AuthState: gkmState})
	})
	if err != nil {
		t.Fatalf("gkm: %v", err)
	}
	self.gkm = gkmEngine.(*gkmservice.GkmEngine)
	evsState := evsservice.NewAclEvsAuthState(self.cache, revocations)
	evsViews := evsservice.NewAclGateViews(self.cache)
	evsEngine, err := net.AddEngine("evs", func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return newEnginesEvsHost(ctx, host, net.Clock(), settings, evsState, evsViews)
	})
	if err != nil {
		t.Fatalf("evs: %v", err)
	}
	self.evs = evsEngine.(*enginesEvsHost)

	api.ServeService(evsservice.EvsAudience, self.evs.Handler())
	api.ServeService(gkmservice.GkmAudience, self.gkm.Handler())
	t.Cleanup(func() {
		api.ServeService(evsservice.EvsAudience, nil)
		api.ServeService(gkmservice.GkmAudience, nil)
	})
	api.SetExchangeScopeSource(self.exchangeScopes)
	t.Cleanup(func() { api.SetExchangeScopeSource(nil) })
	return self
}

// The Net's api, whose log the gate reads and whose origins serve the engines.
func (self *Engines) Api() *sidecartest.FakeApi {
	return self.api
}

// The gate cache evs and gkm judge by.
func (self *Engines) Gate() *sidecar.AclGateCache {
	return self.cache
}

// Opens evs and gkm to networkId beside every network their gates list already, as sidecar.yml's dark gates list each
// network a test runs, and funds its storage. So a world that opens a second network, as a second Bootstrap does, keeps
// evs and gkm open to the first, and to any network a test opened through the gates itself.
func (self *Engines) OpenNetwork(networkId sidecar.Id) {
	fakes := self.net.Fakes()
	fakes.Gates.AddServiceNetworks(sidecar.ServiceGateEvs, connect.Id(networkId))
	fakes.Gates.AddServiceNetworks(sidecar.ServiceGateGkm, connect.Id(networkId))
	fakes.Quota.SetBalance(connect.Id(networkId), self.settings.NetworkBalanceByteCount)
}

// Tells the gate the network's log moved and waits until it holds api's tip, so evs, gkm and the exchange judge by
// every entry landed so far.
func (self *Engines) Sync(ctx context.Context, networkId sidecar.Id) error {
	tip, err := self.api.Tip(ctx, networkId)
	if err != nil {
		return err
	}
	if tip == nil {
		return fmt.Errorf("network %s has no log for the gate to load", networkId)
	}
	ctx, cancel := context.WithTimeout(ctx, self.settings.SyncTimeout)
	defer cancel()
	for {
		_, changed := self.loads.Get()
		snapshot, status := self.cache.State(networkId)
		if status == sidecar.AclGateLoaded && snapshot != nil && tip.GetVersion() <= snapshot.Pin.GetVersion() {
			return nil
		}
		self.cache.Changed(networkId)
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("the gate did not load network %s's position %d: %w", networkId, tip.GetVersion(), ctx.Err())
		}
	}
}

// Holds each read the gate makes of any network's log from now until release, so no load that reads meanwhile installs
// before it: a test asks with a load running and the gate holding no newer state, as the exchange's ask of a network
// the gate holds no state of starts a load (sidecar.RequestAclGateSnapshot) that would otherwise install whenever it got
// there. arrived closes at the first read held. release, which the test's end calls too, lets every held and later read
// go; a held read also gives up with its load, at the cache's close or the load's timeout (AclGateSettings.LoadTimeout).
// A Sync meanwhile waits for the release.
func (self *Engines) holdGateLoads() (arrived <-chan struct{}, release func()) {
	arrived, release = self.gateSource.hold()
	self.t.Cleanup(release)
	return arrived, release
}

// The gate's source: the Net's stores through AclGateDirectSource, each read waiting out a test's hold
// (holdGateLoads).
type enginesGateSource struct {
	source sidecar.AclGateSource

	stateLock sync.Mutex
	// the hold set, nil for none
	held *enginesGateHold
}

var _ sidecar.AclGateSource = (*enginesGateSource)(nil)

// One holdGateLoads.
type enginesGateHold struct {
	// closed at the first read held
	arrived     chan struct{}
	arrivedOnce sync.Once
	// closed by the release
	released    chan struct{}
	releaseOnce sync.Once
}

// Sets a hold, replacing any set before, whose release then lets go only what it held.
func (self *enginesGateSource) hold() (arrived <-chan struct{}, release func()) {
	held := &enginesGateHold{arrived: make(chan struct{}), released: make(chan struct{})}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.held = held
	}()
	return held.arrived, func() {
		held.releaseOnce.Do(func() {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				if self.held == held {
					self.held = nil
				}
			}()
			close(held.released)
		})
	}
}

// Waits out the hold set, if any, until its release or the end of ctx, the load's.
func (self *enginesGateSource) wait(ctx context.Context) error {
	held := func() *enginesGateHold {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.held
	}()
	if held == nil {
		return nil
	}
	held.arrivedOnce.Do(func() { close(held.arrived) })
	select {
	case <-held.released:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (self *enginesGateSource) Genesis(ctx context.Context, networkId sidecar.Id) ([]byte, error) {
	if err := self.wait(ctx); err != nil {
		return nil, err
	}
	return self.source.Genesis(ctx, networkId)
}

func (self *enginesGateSource) Entries(ctx context.Context, networkId sidecar.Id, after *bridge.AuthPin) ([][]byte, error) {
	if err := self.wait(ctx); err != nil {
		return nil, err
	}
	return self.source.Entries(ctx, networkId, after)
}

func (self *enginesGateSource) Rows(ctx context.Context, networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
	if err := self.wait(ctx); err != nil {
		return nil, err
	}
	return self.source.Rows(ctx, networkId, rowsSha256)
}

// The heads evs committed for repoId's refs, as head/<repo>/ holds them on whichever metadata cluster placed it: what
// the repo's pushes committed, read from the store, never through evs.
func (self *Engines) RefHeads(ctx context.Context, repoId sidecar.Id) ([]*protocol.EvsHead, error) {
	blobs := self.net.Host().Blobs
	heads := []*protocol.EvsHead{}
	for _, clusterId := range blobs.MetadataClusterIds() {
		cluster, err := blobs.Cluster(clusterId)
		if err != nil {
			return nil, err
		}
		infos, _, err := cluster.List(ctx, evsservice.HeadRepoPrefix(repoId), "", self.settings.HeadListPageCount)
		if err != nil {
			return nil, err
		}
		for _, info := range infos {
			object, err := cluster.Get(ctx, info.Key)
			if err != nil {
				return nil, err
			}
			headBytes, err := io.ReadAll(object.Body)
			object.Body.Close()
			if err != nil {
				return nil, err
			}
			head, err := evsservice.ParseEvsHead(headBytes)
			if err != nil {
				return nil, err
			}
			heads = append(heads, head)
		}
	}
	return heads, nil
}

// Every request the exchange has asked the scope source, in order: who asked, for which service, and which scopes.
func (self *Engines) ScopeRequests() []*sidecartest.FakeApiScopeRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*sidecartest.FakeApiScopeRequest{}, self.scopeRequests...)
}

// The exchange's scope source (the file header): server/oauth's ProjectionExchangeScopeSource.Grant step for step,
// over the world's gate, so a client meets the answer api's exchange gives in each case a test reaches here, and
// rides out, or ends at, what it would at api:
//
//	not loaded   a network the gate holds no verified state of, a bootstrapping one before its base 1 among them, is
//	             told to the gate and answers temporarily_unavailable, 503, which refuses nothing; with
//	             FollowBeforeExchange, so does a gate that could not catch up to api's tip
//	unadmitted   a client bound to no sidecar, or to one the state holds no row of, an admission not at the gate yet
//	             among them, is refused invalid_grant, whatever it asks
//	standing     a sidecar the state holds a row of whose admission no longer stands, revoked, its member gone,
//	             parked, suspended or past its not_after, is refused invalid_grant, whatever it asks: a revoked
//	             device's exchange ends there, as at api, and rides out nothing
//	scopes       each repo scope alone by §8's table at the gate's state (sidecar.AclExchangeScopes), the config's
//	             admin only to a config writer from base 1 (QD-894), and no repo scope at an audience that takes none:
//	             a request none of whose scopes is granted, a grant not at the gate yet among them, is refused
//	             invalid_scope, which a client rides out for §8.9's 5 s (QD-1226, QD-1230); one some of whose scopes
//	             are granted gets those alone; one that asks none gets a token naming its sidecar and member
//
// proj_v is the position of the state read, and the member the admitted sidecar's row names, none for a tagged one.
// Server's exchange also grants an unadmitted client of member M its recovery:<M> scope at gkm, and a forwarding
// client the config's r while its sidecar's forwarding Delegation lives (grantUnadmitted, grantForwardOnly). The
// fake's exchange names neither the member a client's credential names nor the sidecar a forwarding client speaks
// for, so neither is modeled here: each is refused invalid_grant, as an unadmitted client's every other ask is.
func (self *Engines) exchangeScopes(ctx context.Context, request *sidecartest.FakeApiScopeRequest) (*sidecartest.FakeApiScopeGrant, error) {
	if self.settings.FollowBeforeExchange {
		if err := self.Sync(ctx, request.NetworkId); err != nil {
			return nil, fmt.Errorf("%w: the gate did not catch up: %w", sidecartest.ErrFakeApiExchangeUnavailable, err)
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.scopeRequests = append(self.scopeRequests, request)
	}()
	// 0 for a service audience that takes no repo scope: dns, certs, mail and sockets
	aclAudience := enginesAudiences[request.Audience]
	snapshot := sidecar.RequestAclGateSnapshot(self.cache, request.NetworkId)
	if snapshot == nil || snapshot.Config == nil || snapshot.Acl == nil {
		return nil, fmt.Errorf("%w: network %s's state is not loaded", sidecartest.ErrFakeApiExchangeUnavailable, request.NetworkId)
	}
	state := snapshot.Config
	now := self.net.Clock().Now()

	// §8.6's hard denies, as server's exchangeSidecarStanding: a row, not revoked or its member gone, not parked or
	// suspended, its not_after unpassed
	standing := func(sidecarId sidecar.Id) bool {
		row := state.SidecarRow(sidecarId)
		if row == nil || !snapshot.Acl.Admitted(sidecarId) || state.Parked(sidecarId) || state.Suspended(sidecarId) {
			return false
		}
		return row.GetNotAfter() == 0 || now.UnixMilli() < row.GetNotAfter()
	}
	if request.SidecarId == nil || state.SidecarRow(*request.SidecarId) == nil {
		return nil, fmt.Errorf("%w: a client the state does not admit gets no token here", sidecartest.ErrFakeApiInvalidGrant)
	}
	sidecarId := *request.SidecarId
	if !standing(sidecarId) {
		return nil, fmt.Errorf("%w: the client's sidecar is not admitted", sidecartest.ErrFakeApiInvalidGrant)
	}

	configRepoId, err := sidecar.IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		return nil, fmt.Errorf("the state's genesis names no config repo: %w", err)
	}
	// the config's admin goes to each config writer from base 1, as at api, which the table judges too
	configAdmin := aclAudience != 0 && state.Base() != nil && state.IsConfigWriter(sidecarId)
	// repo:<id>:<role> whatever its role, as server's exchange parses a scope before the table; false for another
	parseRepoScope := func(scope string) (sidecar.Id, string, bool) {
		rest, ok := strings.CutPrefix(scope, enginesRepoScopePrefix)
		if !ok {
			return sidecar.Id{}, "", false
		}
		idText, role, ok := strings.Cut(rest, ":")
		if !ok {
			return sidecar.Id{}, "", false
		}
		repoId, err := sidecar.ParseId(idText)
		if err != nil || repoId == (sidecar.Id{}) {
			return sidecar.Id{}, "", false
		}
		return repoId, role, true
	}
	tableScopes := []string{}
	for _, scope := range request.Scopes {
		repoId, role, ok := parseRepoScope(scope)
		if ok && repoId == configRepoId && role == enginesAdminRole && !configAdmin {
			continue
		}
		if ok {
			tableScopes = append(tableScopes, scope)
		}
	}
	tableGranted := map[string]bool{}
	if 0 < len(tableScopes) && aclAudience != 0 {
		tableGrant, err := sidecar.AclExchangeScopes(state, &sidecar.AclExchangeRequest{
			SidecarId: sidecarId,
			Audience:  aclAudience,
			Scopes:    tableScopes,
			Now:       now,
		})
		if err != nil {
			if errors.Is(err, sidecar.ErrAclExchangeScope) {
				return nil, fmt.Errorf("%w: %w", sidecartest.ErrFakeApiInvalidScope, err)
			}
			return nil, err
		}
		for _, scope := range tableGrant.Scopes {
			tableGranted[scope] = true
		}
	}

	grant := &sidecartest.FakeApiScopeGrant{Scopes: []string{}, ProjVersion: snapshot.Pin.GetVersion()}
	// the member the admitted sidecar's row names, none for a tagged one, as server's exchangeSidecarMember
	if admitted := state.Sidecar(sidecarId); admitted != nil && admitted.MemberId != (sidecar.Id{}) && len(admitted.TagIds) == 0 {
		memberId := admitted.MemberId
		grant.MemberId = &memberId
	}
	for _, scope := range request.Scopes {
		if tableGranted[scope] {
			grant.Scopes = append(grant.Scopes, scope)
		}
	}
	if 0 < len(request.Scopes) && len(grant.Scopes) == 0 {
		return nil, fmt.Errorf("%w: the gate's state grants none of the scopes", sidecartest.ErrFakeApiInvalidScope)
	}
	return grant, nil
}

// The audiences that take repo scopes, by the exchange's names.
var enginesAudiences = map[string]sidecar.AclTokenAudience{
	evsservice.EvsAudience: sidecar.AclTokenAudienceEvs,
	gkmservice.GkmAudience: sidecar.AclTokenAudienceGkm,
}

// §7.8's repo capability scope, repo:<id>:<role>, and the role the config's admin is.
const (
	enginesRepoScopePrefix = "repo:"
	enginesAdminRole       = "admin"
)

// evs's block as server/cli/evs builds it (evshost.NewHost), on the world's state: the engine with the segment route's
// receipt keys, storage gate, HDD share, usage producer and cohort limit, every batch flushed at once and every repo/
// read from the store.
type enginesEvsHost struct {
	engine  *evsservice.EvsEngine
	closers []func()
}

func newEnginesEvsHost(ctx context.Context, host *sidecar.ServiceHost, clock sidecar.Clock, world *EnginesSettings, state evsservice.EvsAuthState, views evsservice.EvsGateViews) (evsHost *enginesEvsHost, returnErr error) {
	evsHost = &enginesEvsHost{}
	defer func() {
		if returnErr != nil {
			evsHost.Close()
		}
	}()
	receiptKey := sha256.Sum256([]byte("enginenet receipt key"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{{KeyId: 1, Key: receiptKey[:], IssueFrom: clock.Now().Add(-world.ReceiptKeyAge)}}, nil)
	if err != nil {
		return nil, err
	}
	clusterLimit, err := evsservice.NewClusterLimitOfHost(host, nil)
	if err != nil {
		return nil, err
	}
	uploads := &evsservice.EvsUploadDeps{Keys: receiptKeys, ClusterLimit: clusterLimit}
	quota, err := evsservice.NewQuotaGate(ctx, host, nil)
	if err != nil {
		return nil, err
	}
	evsHost.closers = append(evsHost.closers, quota.Close)
	uploads.Quota = quota
	usage, err := evsservice.NewUsageBatcher(ctx, host, nil)
	if err != nil {
		return nil, err
	}
	evsHost.closers = append(evsHost.closers, usage.Close)
	uploads.Usage = usage
	segmentCluster, err := host.Blobs.SegmentCluster()
	if err != nil {
		return nil, err
	}
	hdd, err := evsservice.NewHddAdmission(ctx, host, segmentCluster.ClusterId(), nil)
	if err != nil {
		return nil, err
	}
	evsHost.closers = append(evsHost.closers, hdd.Close)
	uploads.Hdd = hdd
	settings := evsservice.DefaultEvsSettings()
	settings.InstanceFormat = max(sidecar.EvsRepoFormat1, world.EvsInstanceFormat)
	settings.BatchFlushDelay = 0
	settings.RepoCacheTtl = 0
	settings.PushUnknownRereadInterval = 0
	evsHost.engine, err = evsservice.NewEvsEngine(ctx, host, settings, &evsservice.EvsEngineDeps{
		AuthState: state,
		Uploads:   uploads,
		GateViews: views,
	})
	if err != nil {
		return nil, err
	}
	return evsHost, nil
}

func (self *enginesEvsHost) Handler() http.Handler {
	return self.engine.Handler()
}

func (self *enginesEvsHost) Ready() bool {
	return self.engine != nil && self.engine.Ready()
}

func (self *enginesEvsHost) Drain() {
	if self.engine != nil {
		self.engine.Drain()
	}
}

func (self *enginesEvsHost) Close() {
	if self.engine != nil {
		self.engine.Close()
	}
	for i := len(self.closers) - 1; 0 <= i; i -= 1 {
		self.closers[i]()
	}
	self.closers = nil
}

// Deterministic bytes, as a signer writes them.
func enginesMarshal(message proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}
