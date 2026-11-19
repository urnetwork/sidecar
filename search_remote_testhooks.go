//go:build sidecar_testhooks && !ios_extension && !js && !sidecar_http

// Remote search on search worlds, for SEARCH-M10-39's schedules (FS-80, FS-83, S11, S12, §22.7's search rows) and
// SEARCH-M10-40's benchmarks (§22.8's search, remote and phone rows): a device of one network that follows several
// search worlds' refs at once, one repo each, so one engine answers a search, local or remote, over every repo it reads;
// and the requester's transport, which a test routes to indexers' SearchRemoteServer.Handle in place of a client
// generation's dispatcher (searchRemoteSubprotocolTransport), so a relay's view is what the test records.
//
//	device     its own instance, cache, sync engine, policy, search state and engine, following each world's ref with
//	           that world's source (search_schedule_testhooks.go), sealed as evs seals a record and taking its bytes at
//	           the device's rate; gkm answers each world's RK_1 as a reader's key store holds it
//	scope      every world's repo, readable, its ref the default, of the world's kind: what the device reads. A world
//	           read as a non-writer (an EvsShare's subject, an audit reader) deposits its round's receipt first
//	transport  SetSearchTestRemoteTransport puts the test's in place: what a Call sends, which indexers stand and which
//	           show bit 0, and what the client tells the dispatcher of the foreground, the first-choice own indexer and
//	           bit 1, all through the test
//
// Only the sidecar_testhooks build has it, which no release leg is (§22.4). Safe for concurrent use as the worlds are.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"time"
)

// One world a network device follows, and how.
type SearchTestNetworkRef struct {
	World *SearchTestWorld
	// The device reads the repo as a non-writer: each round deposits Receipt, naming its wanted files, before its first
	// fetch, and fetches nothing when that fails (§16.10's read receipt). Nil with NonWriter fetches nothing.
	NonWriter bool
	Receipt   func(ctx context.Context, wantedPaths []string) error
	// Whether the device keeps the ref's latest set synced; nil keeps it.
	KeepLatest func() bool
}

// What a network device is made of.
type SearchTestNetworkDeviceArgs struct {
	// The host class's search settings, §18.4's rows as the host sets them.
	Settings *SidecarSearchSettings
	// The host's reports, read at each decision.
	Conditions func() SearchConditions
	// Bytes a second a read takes on the worlds' clock; 0 takes none.
	ReadByteRate int64
	// The most one read asks for (§11.9's 32 MiB). Required.
	ReadByteCount int64
	// The refs it follows, one a repo; the first world's clock is the device's.
	Refs []*SearchTestNetworkRef
	// At every record a search opens, gkm being asked for its RK_g. Nil for none.
	OnRecord func()
	// The host's own plaintext of a ref, as a desktop's mirror or an indexer's text view holds it: what a search
	// verifies its candidates against (SearchEngineArgs.Text). Nil holds none, so hits are confirmed from their fields
	// or possible.
	Text func(repoId Id, refId Id) SearchTextSource
	// Where the device's state lives; "" keeps it in memory.
	StateDirectory string
}

// One device of a network following several worlds' refs for search, with its network's search state.
type SearchTestNetworkDevice struct {
	args      SearchTestNetworkDeviceArgs
	clock     SearchTestClock
	instance  *SidecarInstance
	networkId Id
	cache     *SearchCache
	sync      *SearchSync
	policy    *SearchPolicy
	engine    *SearchEngine
	state     *SidecarSearchState
	// each ref's source, by repo
	sources map[Id]*searchWorldSource
	worlds  []*SearchTestWorld
}

// A fresh device following every ref of args.
func NewSearchTestNetworkDevice(ctx context.Context, args *SearchTestNetworkDeviceArgs) (*SearchTestNetworkDevice, error) {
	if args == nil || args.Settings == nil || args.Conditions == nil || args.ReadByteCount <= 0 || len(args.Refs) == 0 {
		return nil, errors.New("search test network device: settings, conditions, a read limit and a ref")
	}
	worlds := []*SearchTestWorld{}
	for _, ref := range args.Refs {
		if ref == nil || ref.World == nil {
			return nil, errors.New("search test network device: a ref without its world")
		}
		if slices.ContainsFunc(worlds, func(world *SearchTestWorld) bool { return world.repoId == ref.World.repoId }) {
			return nil, errors.New("search test network device: two refs of one repo")
		}
		worlds = append(worlds, ref.World)
	}
	clock := worlds[0].clock
	backend := NewSidecarMemoryBackend()
	if args.StateDirectory != "" {
		var err error
		if backend, err = NewSidecarOsBackend(args.StateDirectory); err != nil {
			return nil, err
		}
	}
	settings := DefaultSidecarSettings()
	settings.Log = NewNoopLogger()
	settings.KeychainSettings.PassMemoryByteCount = 64 * 1024
	settings.KeychainSettings.PassIterationCount = 1
	settings.KeychainSettings.PassThreadCount = 1
	settings.KeychainSettings.AutoLockTimeout = 0
	instance, err := NewSidecarInstance(ctx, &SidecarInstanceArgs{Backend: backend, KeyStore: NewSidecarMemoryKeyStore(), Settings: settings})
	if err != nil {
		return nil, err
	}
	device := &SearchTestNetworkDevice{
		args: *args, clock: clock, instance: instance, networkId: NewId(), sources: map[Id]*searchWorldSource{}, worlds: worlds,
	}
	fail := func(err error) (*SearchTestNetworkDevice, error) {
		device.Close()
		return nil, err
	}
	if err := instance.Unlock(nil); err != nil {
		return fail(err)
	}
	if _, err := instance.createKeychain(device.networkId); err != nil {
		return fail(err)
	}
	store := instance.Store(&device.networkId)
	if device.cache, err = NewSearchCache(ctx, store, args.Settings, clock, NewNoopLogger()); err != nil {
		return fail(err)
	}
	if device.state, err = newSidecarSearchState(store, args.Settings, clock, NewNoopLogger(), nil); err != nil {
		return fail(err)
	}
	if device.policy, err = NewSearchPolicy(&SearchPolicyArgs{Settings: args.Settings, Conditions: args.Conditions, Clock: clock}); err != nil {
		return fail(err)
	}
	if device.sync, err = newSearchSync(&searchSyncArgs{
		cache: device.cache, settings: args.Settings, format: DefaultIndexFormatSettings(), clock: clock, log: NewNoopLogger(),
		readPathCount: DefaultEvsFormatSettings().ReadMaxPathCount, readByteCount: args.ReadByteCount, budget: device.policy,
	}); err != nil {
		return fail(err)
	}
	keys := map[Id]*EvsRepoKey{}
	scope := &searchTestNetworkScope{}
	for _, ref := range args.Refs {
		world := ref.World
		source := &searchWorldSource{world: world, rate: args.ReadByteRate}
		device.sources[world.repoId] = source
		keys[world.repoId] = world.repoKey
		refArgs := &searchSyncRefArgs{
			repoId: world.repoId, refId: world.refId, repoKind: world.kind, source: source,
			keepAll:    func() bool { return device.policy.KeepsAll(world.repoId, world.AllByteCount()) },
			keepLatest: ref.KeepLatest,
			mayErase:   world.mayErase,
			nonWriter:  ref.NonWriter,
		}
		if ref.NonWriter {
			receipt := ref.Receipt
			refArgs.depositReceipt = func(ctx context.Context, wanted []*SearchSyncWanted) error {
				if receipt == nil {
					return errors.New("search test network device: a non-writer with no receipt")
				}
				paths := []string{}
				for _, file := range wanted {
					paths = append(paths, file.Path)
				}
				return receipt(ctx, paths)
			}
		}
		// a config, mailcfg or secret repo's index is never followed (FI-17): the device keeps none of it
		if err := device.sync.Follow(refArgs); err != nil && !errors.Is(err, ErrSearchSyncUnfollowed) {
			return fail(err)
		}
		scope.repos = append(scope.repos, &SearchScopeRepo{
			RepoId: world.repoId, Kind: world.kind, Readable: true, Refs: []*SearchScopeRef{{RefId: world.refId, Default: true}},
		})
	}
	gkm := &searchTestNetworkGkm{repoKeys: keys, onRecord: args.OnRecord}
	if device.engine, err = NewSearchEngine(&SearchEngineArgs{
		Settings: args.Settings, Cache: device.cache, Sync: device.sync, Policy: device.policy, Gkm: gkm, Clock: clock,
		Log: NewNoopLogger(), Scope: scope, Text: args.Text,
	}); err != nil {
		return fail(err)
	}
	return device, nil
}

// Ends the device and its state.
func (self *SearchTestNetworkDevice) Close() {
	if self.engine != nil {
		self.engine.Close()
	}
	if self.sync != nil {
		self.sync.Close()
	}
	if self.cache != nil {
		self.cache.Close()
	}
	if self.instance != nil {
		self.instance.Close()
	}
}

// The device's engine: its local searches, a remote client's local engine, and what an indexer serves from
// (NewSearchRemoteServer's Engine).
func (self *SearchTestNetworkDevice) Engine() *SearchEngine {
	return self.engine
}

// The network's search state: the mode, the notice answers, the served memory and the served record.
func (self *SearchTestNetworkDevice) State() *SidecarSearchState {
	return self.state
}

// One round of every ref now, in the order the device follows them.
func (self *SearchTestNetworkDevice) Sync(ctx context.Context) error {
	for _, world := range self.worlds {
		if err := self.sync.RunRound(ctx, world.repoId, world.refId, false); err != nil && !errors.Is(err, ErrSearchSyncUnfollowed) {
			return err
		}
	}
	return nil
}

// What the device fetched of repoId's ref so far, in order.
func (self *SearchTestNetworkDevice) Fetches(repoId Id) []SearchTestFetch {
	source := self.sources[repoId]
	if source == nil {
		return nil
	}
	return source.fetched()
}

// The cache's bytes in all.
func (self *SearchTestNetworkDevice) CacheByteCount() int64 {
	return self.cache.ByteCount()
}

// The device's own index of repoId's ref refId as its sync engine holds it: the pin its latest set is whole at, whether
// the index is a companion's, and the ring of versions it replayed; false before its first swap. What a requester's
// remote client reads as its own index (SearchRemoteClientArgs.OwnIndex), and what an indexer holding the ref's text at
// that version gives as its text pin (SearchRemoteServerArgs.TextPin).
func (self *SearchTestNetworkDevice) OwnIndex(repoId Id, refId Id) (SearchSyncPin, bool, []SearchSyncPinPair, bool) {
	self.sync.stateLock.Lock()
	defer self.sync.stateLock.Unlock()
	ref := self.sync.refs[[2]Id{repoId, refId}]
	if ref == nil || ref.manifest == nil {
		return SearchSyncPin{}, false, nil, false
	}
	return ref.manifest.Pin, searchRootCompanion(ref.manifest.Root), slices.Clone(ref.manifest.Pins), true
}

// gkm as a reader of each world's repo holds it: RK_1 of each, at each record it opens.
type searchTestNetworkGkm struct {
	gkmRefusingClient
	repoKeys map[Id]*EvsRepoKey
	onRecord func()
}

// See GkmClient: RK_1, each world's one generation.
func (self *searchTestNetworkGkm) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return self.RepoKey(ctx, repoId, 1)
}

// See GkmClient: RK_1 of a world's repo, the record hook told first; any other repo or generation is missing.
func (self *searchTestNetworkGkm) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	repoKey := self.repoKeys[repoId]
	if repoKey == nil || generation != 1 {
		return nil, ErrGkmKeyMissing
	}
	if self.onRecord != nil {
		self.onRecord()
	}
	return repoKey, nil
}

// Every world's repo, readable, its ref the default.
type searchTestNetworkScope struct {
	repos []*SearchScopeRepo
}

// See SearchScopeSource.
func (self *searchTestNetworkScope) Repos(ctx context.Context) ([]*SearchScopeRepo, error) {
	repos := []*SearchScopeRepo{}
	for _, repo := range self.repos {
		copied := *repo
		copied.Refs = slices.Clone(repo.Refs)
		repos = append(repos, &copied)
	}
	return repos, nil
}

// What a requester sends and asks over in a test: searchRemoteTransport, exported. A relay's view is the test's to
// record.
type SearchTestRemoteTransport interface {
	// One SEARCH body to the indexer, its Hello first where none stands; the reply's body, or the error: a
	// *SubprotocolError for an envelope Error, ErrSearchTestRemoteTimeout for no reply by the deadline, and
	// ErrSearchTestRemoteAuth for an indexer whose identity binding or bit 0 did not hold.
	Call(ctx context.Context, indexerId Id, body []byte) ([]byte, error)
	// Whether a Hello with the indexer stands, and whether it showed bit 0.
	Peer(indexerId Id) (servesSearch bool, standing bool)
	// Whether a Hello with the indexer verified after at and stands.
	SeenSince(indexerId Id, at time.Time) bool
	// The first-choice own indexer the dispatcher's foreground round counts; the zero Id none.
	SetSearchIndexer(indexerId Id)
	// The host's foreground, as the dispatcher is told it.
	SetForeground(foreground bool)
	// Bit 1 toward each indexer asksSearch names.
	SetAsksSearch(asksSearch func(indexerId Id) bool) error
}

var (
	// What a test transport answers for no reply by a leg's deadline.
	ErrSearchTestRemoteTimeout = errSearchRemoteTimeout
	// What a test transport answers for an indexer whose identity binding or Hello bit 0 did not hold.
	ErrSearchTestRemoteAuth = errSearchRemoteAuth
)

// Puts transport in place of a client generation's dispatcher on client, and follows it as Attach follows one, until
// ctx ends: bit 1, the foreground and the first-choice own indexer go to it. nil takes the transport away.
func SetSearchTestRemoteTransport(ctx context.Context, client *SearchRemoteClient, transport SearchTestRemoteTransport) {
	if transport == nil {
		client.setTransport(nil)
		return
	}
	wrapped := &searchTestRemoteTransport{inner: transport}
	client.setTransport(wrapped)
	go func() {
		client.follow(ctx, wrapped)
		client.stateLock.Lock()
		defer client.stateLock.Unlock()
		if client.transport == wrapped {
			client.transport = nil
		}
	}()
}

// A test's transport as searchRemoteTransport.
type searchTestRemoteTransport struct {
	inner SearchTestRemoteTransport
}

// See searchRemoteTransport: the test transport's.
func (self *searchTestRemoteTransport) Call(ctx context.Context, indexerId Id, body []byte) ([]byte, error) {
	return self.inner.Call(ctx, indexerId, body)
}

// See searchRemoteTransport: the test transport's.
func (self *searchTestRemoteTransport) Peer(indexerId Id) (bool, bool) {
	return self.inner.Peer(indexerId)
}

// See searchRemoteTransport: the test transport's.
func (self *searchTestRemoteTransport) SeenSince(indexerId Id, at time.Time) bool {
	return self.inner.SeenSince(indexerId, at)
}

// See searchRemoteTransport: the test transport's.
func (self *searchTestRemoteTransport) SetSearchIndexer(indexerId Id) {
	self.inner.SetSearchIndexer(indexerId)
}

// See searchRemoteTransport: the test transport's.
func (self *searchTestRemoteTransport) SetForeground(foreground bool) {
	self.inner.SetForeground(foreground)
}

// See searchRemoteTransport: the test transport's.
func (self *searchTestRemoteTransport) SetAsksSearch(asksSearch func(indexerId Id) bool) error {
	return self.inner.SetAsksSearch(asksSearch)
}
