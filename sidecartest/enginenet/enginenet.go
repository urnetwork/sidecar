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
//	scopes    the exchange's scope source is §8's table (sidecar.AclExchangeScopes) at the gate's state of the
//	          token's network, as TEAM-M2-15's projection source is api's
//	window    from a network's Bootstrap until its base 1 lands (bootstrap.go), a bootstrap window answers in the gate's
//	          place for that network: it honors the bootstrapping device alone, on the config repo alone, as base 1
//	          will, its identity key the Genesis's and its pins the genesis state's. The config writer's side that signs
//	          the first head's push before base 1 and sends it after (QD-081 #4) is not built, nor KF1's draft before
//	          base 1, so the bootstrap sends both before base 1 lands, while no log exists for the gate to read. Every
//	          request after base 1 is the real gate's
//
// The gate learns of a log's new entries when told (Sync): api writes no {acl_} hint here, and the cache polls
// nothing. The engines are the Net's (AddEngine), closed with it; the cache closes at the test's end. Safe for
// concurrent use.

package enginenet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	// The evs storage balance each opened network starts with: 1 TiB, so no test write meets quota.
	NetworkBalanceByteCount int64
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
	// how many loads the cache has finished, which Sync waits on
	loads *sidecar.MonitorValue[uint64]
	gkm   *gkmservice.GkmEngine
	evs   *enginesEvsHost
	// the engines' seams: each answers a bootstrap window's network by its window and every other by the gate
	gkmState *enginesGkmAuthState
	evsState *enginesEvsAuthState
	evsViews *enginesEvsGateViews

	stateLock sync.Mutex
	// the networks in their bootstrap window, by id
	windows map[sidecar.Id]*bootstrapWindow
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
		windows:  map[sidecar.Id]*bootstrapWindow{},
	}
	sidecartest.RegisterEvsTwins(net.Fakes().Redis)

	gateSettings := sidecar.DefaultAclGateSettings()
	gateSettings.Log = sidecar.NewNoopLogger()
	gateSettings.PollInterval = 0
	gateSettings.FailureBackoff = 0
	gateSettings.OnLoad = func(networkId sidecar.Id, pin *bridge.AuthPin, err error) {
		self.loads.Update(func(count uint64) uint64 { return count + 1 })
	}
	self.cache = sidecar.NewAclGateCache(net.Context(), sidecar.NewAclGateDirectSource(net.Host().Redis, net.Host().Blobs, gateSettings), net.Clock(), gateSettings)
	t.Cleanup(self.cache.Close)
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
	self.gkmState = &enginesGkmAuthState{engines: self, real: gkmservice.NewAclGkmAuthState(self.cache, revocations, net.Clock())}
	gkmEngine, err := net.AddEngine("gkm", func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return gkmservice.NewGkmEngine(ctx, host, gkmSettings, &gkmservice.GkmEngineDeps{AuthState: self.gkmState})
	})
	if err != nil {
		t.Fatalf("gkm: %v", err)
	}
	self.gkm = gkmEngine.(*gkmservice.GkmEngine)
	self.evsState = &enginesEvsAuthState{engines: self, real: evsservice.NewAclEvsAuthState(self.cache, revocations)}
	self.evsViews = &enginesEvsGateViews{engines: self, real: evsservice.NewAclGateViews(self.cache)}
	evsEngine, err := net.AddEngine("evs", func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		return newEnginesEvsHost(ctx, host, net.Clock(), settings.ReceiptKeyAge, self.evsState, self.evsViews)
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

// Opens evs and gkm to networkId (sidecar.yml's dark gates) and funds its storage.
func (self *Engines) OpenNetwork(networkId sidecar.Id) {
	fakes := self.net.Fakes()
	fakes.Gates.OpenService(sidecar.ServiceGateEvs, connect.Id(networkId))
	fakes.Gates.OpenService(sidecar.ServiceGateGkm, connect.Id(networkId))
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

// The window of networkId while it bootstraps, nil once base 1 landed or for a network that never bootstrapped here.
func (self *Engines) window(networkId sidecar.Id) *bootstrapWindow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.windows[networkId]
}

// The window of a principal's network, nil for none.
func (self *Engines) windowOf(principal *sidecar.Principal) *bootstrapWindow {
	if principal == nil {
		return nil
	}
	return self.window(sidecar.Id(principal.NetworkId))
}

// The exchange's scope source (the file header): §8's table at the gate's state of the token's network, or in a
// bootstrap window the bootstrapping device's scopes on the config repo. A network the gate has not loaded is told to
// it and answers a server error, which the sidecar asks again past.
func (self *Engines) exchangeScopes(ctx context.Context, request *sidecartest.FakeApiScopeRequest) (*sidecartest.FakeApiScopeGrant, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.scopeRequests = append(self.scopeRequests, request)
	}()
	if window := self.window(request.NetworkId); window != nil {
		return window.scopes(request)
	}
	snapshot, status := self.cache.State(request.NetworkId)
	if status != sidecar.AclGateLoaded || snapshot == nil || snapshot.Config == nil {
		self.cache.Changed(request.NetworkId)
		return nil, fmt.Errorf("network %s's projection is not loaded yet", request.NetworkId)
	}
	audience, ok := enginesAudiences[request.Audience]
	if !ok || request.SidecarId == nil {
		if 0 < len(request.Scopes) {
			return nil, fmt.Errorf("%w: no repo scope for this subject or audience", sidecartest.ErrFakeApiInvalidScope)
		}
		return &sidecartest.FakeApiScopeGrant{ProjVersion: snapshot.Pin.GetVersion()}, nil
	}
	grant, err := sidecar.AclExchangeScopes(snapshot.Config, &sidecar.AclExchangeRequest{
		SidecarId: *request.SidecarId,
		Audience:  audience,
		Scopes:    request.Scopes,
		Now:       self.net.Clock().Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", sidecartest.ErrFakeApiInvalidScope, err)
	}
	answer := &sidecartest.FakeApiScopeGrant{Scopes: grant.Scopes, ProjVersion: grant.ProjVersion}
	if row := snapshot.Config.SidecarRow(*request.SidecarId); row != nil {
		if memberId, err := sidecar.IdFromBytes(row.GetMemberId()); err == nil {
			answer.MemberId = &memberId
		}
	}
	return answer, nil
}

// The audiences that take repo scopes, by the exchange's names.
var enginesAudiences = map[string]sidecar.AclTokenAudience{
	evsservice.EvsAudience: sidecar.AclTokenAudienceEvs,
	gkmservice.GkmAudience: sidecar.AclTokenAudienceGkm,
}

// A network's bootstrap window (the file header): the bootstrapping device, the config repo the Genesis names, and
// the genesis state, S(0).
type bootstrapWindow struct {
	networkId    sidecar.Id
	sidecarId    sidecar.Id
	memberId     sidecar.Id
	configRepoId sidecar.Id
	identityKey  []byte
	genesisState *sidecar.ConfigState
}

// Whether principal is the bootstrapping device.
func (self *bootstrapWindow) device(principal *sidecar.Principal) bool {
	return principal != nil && principal.SidecarId != nil && sidecar.Id(*principal.SidecarId) == self.sidecarId
}

// The bootstrapping device's scopes on the config repo, every role it asks; any other scope, or another subject's, is
// refused.
func (self *bootstrapWindow) scopes(request *sidecartest.FakeApiScopeRequest) (*sidecartest.FakeApiScopeGrant, error) {
	if request.SidecarId == nil || *request.SidecarId != self.sidecarId {
		if 0 < len(request.Scopes) {
			return nil, fmt.Errorf("%w: only the bootstrapping device takes scopes before base 1", sidecartest.ErrFakeApiInvalidScope)
		}
		return &sidecartest.FakeApiScopeGrant{}, nil
	}
	prefix := "repo:" + self.configRepoId.String() + ":"
	for _, scope := range request.Scopes {
		if len(scope) <= len(prefix) || scope[:len(prefix)] != prefix {
			return nil, fmt.Errorf("%w: %s before base 1", sidecartest.ErrFakeApiInvalidScope, scope)
		}
	}
	memberId := self.memberId
	return &sidecartest.FakeApiScopeGrant{Scopes: request.Scopes, MemberId: &memberId}, nil
}

// A pin the window holds: the genesis state's own, or one off its chain.
func (self *bootstrapWindow) onChain(pin *bridge.AuthPin) bool {
	return self.genesisState.OnChain(pin)
}

// gkm's AuthState: the window's answers for a bootstrapping network, the real state's for every other.
type enginesGkmAuthState struct {
	engines *Engines
	real    *gkmservice.AclGkmAuthState
}

var _ gkmservice.GkmAuthState = (*enginesGkmAuthState)(nil)

// Allowed or Denied.
func enginesGkmAnswer(allowed bool) gkmservice.GkmAuthAnswer {
	if allowed {
		return gkmservice.GkmAuthAllowed
	}
	return gkmservice.GkmAuthDenied
}

func (self *enginesGkmAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	if self.engines.windowOf(principal) != nil {
		return nil
	}
	return self.real.CheckRevocation(ctx, principal)
}

func (self *enginesGkmAuthState) Sidecar(principal *sidecar.Principal, sidecarId sidecar.Id) (*gkmservice.GkmSidecarFacts, gkmservice.GkmAuthAnswer) {
	window := self.engines.windowOf(principal)
	if window == nil {
		return self.real.Sidecar(principal, sidecarId)
	}
	if sidecarId != window.sidecarId {
		return nil, gkmservice.GkmAuthDenied
	}
	memberId := window.memberId
	return &gkmservice.GkmSidecarFacts{IdentityPublicKey: window.identityKey, MemberDevice: true, MemberId: &memberId}, gkmservice.GkmAuthAllowed
}

func (self *enginesGkmAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, right sidecar.AclEvsRights, now time.Time) gkmservice.GkmAuthAnswer {
	window := self.engines.windowOf(principal)
	if window == nil {
		return self.real.HonorScope(principal, repoId, right, now)
	}
	return enginesGkmAnswer(window.device(principal) && repoId == window.configRepoId)
}

func (self *enginesGkmAuthState) Reads(principal *sidecar.Principal, repoId sidecar.Id, sidecarId sidecar.Id, now time.Time) gkmservice.GkmAuthAnswer {
	window := self.engines.windowOf(principal)
	if window == nil {
		return self.real.Reads(principal, repoId, sidecarId, now)
	}
	return enginesGkmAnswer(repoId == window.configRepoId && sidecarId == window.sidecarId)
}

func (self *enginesGkmAuthState) PendingTargets(principal *sidecar.Principal, sidecarId sidecar.Id, now time.Time) ([]*gkmservice.GkmPendingTarget, gkmservice.GkmAuthAnswer) {
	if self.engines.windowOf(principal) == nil {
		return self.real.PendingTargets(principal, sidecarId, now)
	}
	return nil, gkmservice.GkmAuthAllowed
}

func (self *enginesGkmAuthState) RepoReaders(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	window := self.engines.windowOf(principal)
	if window == nil {
		return self.real.RepoReaders(principal, repoId, now)
	}
	if repoId != window.configRepoId {
		return nil, gkmservice.GkmAuthDenied
	}
	return []sidecar.Id{window.sidecarId}, gkmservice.GkmAuthAllowed
}

func (self *enginesGkmAuthState) RepoWriters(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	window := self.engines.windowOf(principal)
	if window == nil {
		return self.real.RepoWriters(principal, repoId, now)
	}
	if repoId != window.configRepoId {
		return nil, gkmservice.GkmAuthDenied
	}
	return []sidecar.Id{window.sidecarId}, gkmservice.GkmAuthAllowed
}

func (self *enginesGkmAuthState) CheckPin(principal *sidecar.Principal, pin *bridge.AuthPin) gkmservice.GkmAuthAnswer {
	window := self.engines.windowOf(principal)
	if window == nil {
		return self.real.CheckPin(principal, pin)
	}
	if 0 < pin.GetVersion() {
		return gkmservice.GkmAuthUnknown
	}
	return enginesGkmAnswer(window.onChain(pin))
}

func (self *enginesGkmAuthState) DelegationReads(principal *sidecar.Principal, repoId sidecar.Id, delegationId []byte, now time.Time) gkmservice.GkmAuthAnswer {
	if self.engines.windowOf(principal) == nil {
		return self.real.DelegationReads(principal, repoId, delegationId, now)
	}
	return gkmservice.GkmAuthDenied
}

func (self *enginesGkmAuthState) DelegationKey(principal *sidecar.Principal, delegationId []byte) (*gkmservice.GkmDelegationKeyFacts, gkmservice.GkmAuthAnswer) {
	if self.engines.windowOf(principal) == nil {
		return self.real.DelegationKey(principal, delegationId)
	}
	return nil, gkmservice.GkmAuthDenied
}

func (self *enginesGkmAuthState) LateHolders(principal *sidecar.Principal, repoId sidecar.Id, recipient string, now time.Time) ([]sidecar.Id, gkmservice.GkmAuthAnswer) {
	window := self.engines.windowOf(principal)
	if window == nil {
		return self.real.LateHolders(principal, repoId, recipient, now)
	}
	if repoId != window.configRepoId {
		return nil, gkmservice.GkmAuthDenied
	}
	return []sidecar.Id{window.sidecarId}, gkmservice.GkmAuthAllowed
}

func (self *enginesGkmAuthState) HoldersDropped(principal *sidecar.Principal, repoId sidecar.Id, pin *bridge.AuthPin, since time.Time, now time.Time) gkmservice.GkmAuthAnswer {
	if self.engines.windowOf(principal) == nil {
		return self.real.HoldersDropped(principal, repoId, pin, since, now)
	}
	return gkmservice.GkmAuthDenied
}

// evs's AuthState: the window's answers for a bootstrapping network, the real state's for every other.
type enginesEvsAuthState struct {
	engines *Engines
	real    *evsservice.AclEvsAuthState
}

var _ evsservice.EvsAuthState = (*enginesEvsAuthState)(nil)

// Allowed or Denied.
func enginesEvsAnswer(allowed bool) evsservice.EvsAuthAnswer {
	if allowed {
		return evsservice.EvsAuthAllowed
	}
	return evsservice.EvsAuthDenied
}

func (self *enginesEvsAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	if self.engines.windowOf(principal) != nil {
		return nil
	}
	return self.real.CheckRevocation(ctx, principal)
}

func (self *enginesEvsAuthState) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	window := self.engines.windowOf(principal)
	if window == nil {
		return self.real.MatchBinding(principal)
	}
	return enginesEvsAnswer(window.device(principal))
}

func (self *enginesEvsAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	window := self.engines.windowOf(principal)
	if window == nil {
		return self.real.HonorScope(principal, repoId, rights, now)
	}
	return enginesEvsAnswer(window.device(principal) && repoId == window.configRepoId)
}

func (self *enginesEvsAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	window := self.engines.windowOf(principal)
	if window == nil {
		return self.real.Repo(principal, repoId)
	}
	if repoId != window.configRepoId {
		return nil, evsservice.EvsAuthDenied
	}
	return &evsservice.EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_CONFIG, NetworkId: window.networkId}, evsservice.EvsAuthAllowed
}

// evs's push views: a bootstrapping network's genesis state, the gate's for every other.
type enginesEvsGateViews struct {
	engines *Engines
	real    evsservice.EvsGateViews
}

func (self *enginesEvsGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	if window := self.engines.window(networkId); window != nil {
		return window.genesisState, evsservice.EvsAuthAllowed
	}
	return self.real.View(networkId)
}

// evs's block as server/cli/evs builds it (evshost.NewHost), on the world's state: the engine with the segment route's
// receipt keys, storage gate, HDD share, usage producer and cohort limit, every batch flushed at once and every repo/
// read from the store.
type enginesEvsHost struct {
	engine  *evsservice.EvsEngine
	closers []func()
}

func newEnginesEvsHost(ctx context.Context, host *sidecar.ServiceHost, clock sidecar.Clock, receiptKeyAge time.Duration, state evsservice.EvsAuthState, views evsservice.EvsGateViews) (evsHost *enginesEvsHost, returnErr error) {
	evsHost = &enginesEvsHost{}
	defer func() {
		if returnErr != nil {
			evsHost.Close()
		}
	}()
	receiptKey := sha256.Sum256([]byte("enginenet receipt key"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{{KeyId: 1, Key: receiptKey[:], IssueFrom: clock.Now().Add(-receiptKeyAge)}}, nil)
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
	settings.InstanceFormat = sidecar.EvsRepoFormat1
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
