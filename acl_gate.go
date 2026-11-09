//go:build !sidecar_http

// §8.9's gate cache: one per process, which every gate service shares (C-09), holding each network's verified state
// at its newest position so a check reads it with no lock and no I/O (D-ACL-16, R-ACL-8, I-12).
//
// Per network the cache keeps a rows-only ConfigLog (TEAM-M2-11) and an atomic.Pointer to its snapshot (n, A_n, the
// ConfigState and its AclState), so a state's bitsets are built once per position, never per check. State is one map
// read: a network the cache holds nothing of costs one miss and no I/O, which a gate whose networks all have logs (evs,
// gkm) answers as not loaded after asking for a load, and a network the cache tracks with nothing loaded reports not
// loaded, which every gate refuses or answers unavailable, never allows.
//
// Loads run on goroutines of their own, outside every packet lock: on Changed, which api's INCR of {acl_<networkId>}v
// reaches through ServiceHost.Redis's shared subscriber (Watch) or server's keyEventSubscriber, on a resubscription,
// and on a poll every PollInterval plus jitter, so a revocation whose event was lost still lands. Triggers coalesce:
// one load per network at a time, and a trigger during it causes exactly one more. LoadConcurrency bounds loads across
// networks (§8.18's fan-out risk).
//
// A load checks every entry's chain from this process's own pin, wherever the source read it (ConfigLog.ApplyRun): a
// run that breaks a link, a lower n, or a second A_n at a position the cache holds is refused with an alarm, and the
// old state keeps serving; a cold start is held to the pin the cache last held for the network. The cache writes
// nothing anywhere, {acl_}e included.
//
// Memory is bounded by ByteBudget over each network's retained entries and rows: past it, the networks read longest
// ago lose their loaded state and keep their pins, up to UnloadedCount of them.
//
// Safe for concurrent use. The install of a new snapshot is this cache's linearization point, between the
// acl_gate.install barriers. Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What State says of a network.
type AclGateStatus int

const (
	// The cache holds nothing of the network: no log it was told of, or one it has forgotten. A gate whose networks
	// all have logs asks for a load and refuses meanwhile.
	AclGateUnknown AclGateStatus = iota
	// The network has a log the cache tracks and no verified state is loaded: refuse, or answer unavailable.
	AclGateNotLoaded
	// A verified state is loaded.
	AclGateLoaded
)

// One network's verified state at one position, immutable.
type AclGateSnapshot struct {
	// (n, A_n).
	Pin *bridge.AuthPin
	// The rows-only state S(n), which the cache's log built.
	Config *ConfigState
	// Its acl part.
	Acl *AclState
}

// What the cache has done since it started, for the host's metrics.
type AclGateStats struct {
	// Loads that ran, cold starts included.
	LoadCount uint64
	// Loads that failed to read, the old state kept.
	LoadFailureCount uint64
	// Runs refused for a broken link, a lower n or a second A_n at a held position, and forks: each an alarm.
	AlarmCount uint64
	// Networks whose loaded state the byte budget evicted.
	EvictionCount uint64
}

// One network the cache tracks.
type aclGateNetwork struct {
	networkId Id
	snapshot  atomic.Pointer[AclGateSnapshot]
	// the cache's epoch when a gate last read it, for the least-recently-read eviction
	lastRead atomic.Uint64

	stateLock sync.Mutex
	// a load is running, and the network's loader owns log and byteCount until it stops
	loading bool
	// a trigger came while loading, or before the loader took it
	dirty bool
	// the rows-only log, nil before a cold start and after an eviction
	log *ConfigLog
	// the pin the network last held, which a cold start may not land below
	floor *bridge.AuthPin
	// what the log keeps, ConfigLog.RetainedByteCount
	byteCount int64
}

// §8.9's per-process gate cache.
type AclGateCache struct {
	ctx      context.Context
	cancel   context.CancelFunc
	source   AclGateSource
	clock    Clock
	settings *AclGateSettings
	log      Logger

	// read with no lock; replaced whole under stateLock
	networks  atomic.Pointer[map[Id]*aclGateNetwork]
	stateLock sync.Mutex
	// bumped every poll, a coarse clock for the least-recently-read order that a check can stamp cheaply
	epoch atomic.Uint64
	// bounds loads across networks
	loadSlots chan struct{}

	// every network's byteCount, and how many tracked networks hold no log
	byteTotal     atomic.Int64
	unloadedCount atomic.Int64

	loadCount        atomic.Uint64
	loadFailureCount atomic.Uint64
	alarmCount       atomic.Uint64
	evictionCount    atomic.Uint64
}

// A cache reading source, its poll running on clock until ctx ends or Close. A nil source loads nothing, so every
// network it is told of stays not loaded; a nil clock is real time.
func NewAclGateCache(ctx context.Context, source AclGateSource, clock Clock, settings *AclGateSettings) *AclGateCache {
	if settings == nil {
		settings = DefaultAclGateSettings()
	}
	if clock == nil {
		clock = RealClock{}
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &AclGateCache{
		ctx:       cancelCtx,
		cancel:    cancel,
		source:    source,
		clock:     clock,
		settings:  settings,
		log:       loggerOrDefault(settings.Log),
		loadSlots: make(chan struct{}, max(1, settings.LoadConcurrency)),
	}
	networks := map[Id]*aclGateNetwork{}
	self.networks.Store(&networks)
	self.epoch.Store(1)
	go self.run()
	return self
}

// Stops the poll and every load at its next step. Snapshots already installed stay readable.
func (self *AclGateCache) Close() {
	self.cancel()
}

// The network's verified state and what the cache says of it: one map read, no lock, no I/O and no allocation.
// Snapshot is nil unless the status is AclGateLoaded.
func (self *AclGateCache) State(networkId Id) (*AclGateSnapshot, AclGateStatus) {
	network := (*self.networks.Load())[networkId]
	if network == nil {
		return nil, AclGateUnknown
	}
	network.lastRead.Store(self.epoch.Load())
	snapshot := network.snapshot.Load()
	if snapshot == nil {
		return nil, AclGateNotLoaded
	}
	return snapshot, AclGateLoaded
}

// Tells the cache the network's log moved, or that a gate needs it: tracks the network, and starts a load, or marks
// one due after the load running. Never blocks or reads, so the shared subscriber's callback may call it.
func (self *AclGateCache) Changed(networkId Id) {
	self.trigger(self.track(networkId))
}

// Loads every network that holds a log again, as a resubscription asks: whatever was published in the gap is gone.
func (self *AclGateCache) Resync() {
	for _, network := range *self.networks.Load() {
		if network.snapshot.Load() != nil {
			self.trigger(network)
		}
	}
}

// Watches every network's {acl_}v on the process's shared key-event subscriber, which calls Changed for each INCR and
// Resync for a resubscription. Returns what stops it.
func (self *AclGateCache) Watch(redis Redis) (remove func(), err error) {
	return redis.AddKeyEventCallback(AclVersionKeyPattern, func(event RedisKeyEvent) {
		if event.Resync {
			self.Resync()
			return
		}
		if networkId, ok := ParseAclVersionKey(event.Key); ok {
			self.Changed(networkId)
		}
	})
}

// What the cache has counted.
func (self *AclGateCache) Stats() AclGateStats {
	return AclGateStats{
		LoadCount:        self.loadCount.Load(),
		LoadFailureCount: self.loadFailureCount.Load(),
		AlarmCount:       self.alarmCount.Load(),
		EvictionCount:    self.evictionCount.Load(),
	}
}

// The network's entry, made when the cache holds none.
func (self *AclGateCache) track(networkId Id) *aclGateNetwork {
	if network := (*self.networks.Load())[networkId]; network != nil {
		return network
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networks := *self.networks.Load()
	if network := networks[networkId]; network != nil {
		return network
	}
	network := &aclGateNetwork{networkId: networkId}
	network.lastRead.Store(self.epoch.Load())
	next := configCloneMap(networks)
	next[networkId] = network
	self.networks.Store(&next)
	self.unloadedCount.Add(1)
	return network
}

// Marks a load due and starts the network's loader when none runs.
func (self *AclGateCache) trigger(network *aclGateNetwork) {
	start := func() bool {
		network.stateLock.Lock()
		defer network.stateLock.Unlock()
		network.dirty = true
		if network.loading {
			return false
		}
		network.loading = true
		return true
	}()
	if start {
		go self.loader(network)
	}
}

// Loads the network while triggers keep coming, one load at a time, each holding one of the process's load slots.
func (self *AclGateCache) loader(network *aclGateNetwork) {
	for {
		due := func() bool {
			network.stateLock.Lock()
			defer network.stateLock.Unlock()
			if !network.dirty || self.ctx.Err() != nil {
				network.loading = false
				return false
			}
			network.dirty = false
			return true
		}()
		if !due {
			return
		}
		select {
		case self.loadSlots <- struct{}{}:
		case <-self.ctx.Done():
			func() {
				network.stateLock.Lock()
				defer network.stateLock.Unlock()
				network.loading = false
			}()
			return
		}
		err := self.load(network)
		<-self.loadSlots
		self.evict(network)
		if onLoad := self.settings.OnLoad; onLoad != nil {
			var pin *bridge.AuthPin
			if snapshot := network.snapshot.Load(); snapshot != nil {
				pin = snapshot.Pin
			}
			onLoad(network.networkId, pin, err)
		}
	}
}

// One load: a cold start from the source's retained run, held to the network's floor, or the run after the log's
// pin; then the new snapshot's install. Any failure keeps the old snapshot, and comes back.
func (self *AclGateCache) load(network *aclGateNetwork) error {
	if self.source == nil {
		return errAclGateNoSource
	}
	self.loadCount.Add(1)
	ctx := self.ctx
	if 0 < self.settings.LoadTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(self.ctx, self.settings.LoadTimeout)
		defer cancel()
	}
	networkId := network.networkId
	var loadErr error
	rowsSource := ConfigRowsOnlySource(func(rowsNetworkId Id, rowsSha256 []byte) ([]byte, error) {
		return self.source.Rows(ctx, rowsNetworkId, rowsSha256)
	})
	logSettings := self.settings.ConfigLog
	if logSettings == nil {
		logSettings = DefaultConfigLogSettings()
		logSettings.Log = self.settings.Log
	}

	log := network.log
	if log == nil {
		genesis, err := self.source.Genesis(ctx, networkId)
		if err != nil {
			return self.loadFailed(networkId, "genesis", err)
		}
		entries, err := self.source.Entries(ctx, networkId, nil)
		if err != nil {
			return self.loadFailed(networkId, "entries", err)
		}
		floor := func() *bridge.AuthPin {
			network.stateLock.Lock()
			defer network.stateLock.Unlock()
			return network.floor
		}()
		log, err = RestoreConfigLogRowsOnly(logSettings, &ConfigRetained{SignedGenesis: genesis, Entries: entries}, rowsSource, floor)
		if err != nil {
			if errors.Is(err, ErrConfigRunRefused) || errors.Is(err, ErrConfigBelowPin) || errors.Is(err, ErrConfigFork) {
				return self.alarm(networkId, err)
			}
			return self.loadFailed(networkId, "cold start", err)
		}
		func() {
			network.stateLock.Lock()
			defer network.stateLock.Unlock()
			network.log = log
		}()
		self.unloadedCount.Add(-1)
	} else {
		entries, err := self.source.Entries(ctx, networkId, log.Pin())
		if err != nil {
			return self.loadFailed(networkId, "entries", err)
		}
		if _, err := log.ApplyRun(entries, rowsSource); err != nil {
			if errors.Is(err, ErrConfigRunRefused) || errors.Is(err, ErrConfigFork) {
				loadErr = self.alarm(networkId, err)
			} else {
				loadErr = self.loadFailed(networkId, "run", err)
			}
			// entries before a failure that is no refusal applied: their state still installs below
		}
	}
	byteCount := log.RetainedByteCount()
	func() {
		network.stateLock.Lock()
		defer network.stateLock.Unlock()
		self.byteTotal.Add(byteCount - network.byteCount)
		network.byteCount = byteCount
	}()
	if err := self.install(network, log.State()); err != nil {
		return err
	}
	return loadErr
}

// Installs a state's snapshot, never one at or below what the network holds.
func (self *AclGateCache) install(network *aclGateNetwork, state *ConfigState) error {
	acl, err := state.Acl()
	if err != nil {
		return self.alarm(network.networkId, err)
	}
	pin := state.Pin()
	if current := network.snapshot.Load(); current != nil && pin.GetVersion() <= current.Pin.GetVersion() {
		return nil
	}
	barrierKey := network.networkId.String()
	testHookBarrier("acl_gate.install.before", barrierKey)
	network.snapshot.Store(&AclGateSnapshot{Pin: pin, Config: state, Acl: acl})
	testHookBarrier("acl_gate.install", barrierKey)
	func() {
		network.stateLock.Lock()
		defer network.stateLock.Unlock()
		network.floor = pin
	}()
	testHookBarrier("acl_gate.install.after", barrierKey)
	return nil
}

// A load that read nothing usable, the old state kept: err, logged and counted.
func (self *AclGateCache) loadFailed(networkId Id, step string, err error) error {
	self.loadFailureCount.Add(1)
	self.log.Warningf("[acl_gate]%s load failed at its %s: %v", networkId, step, err)
	return err
}

// A run the chain check refused, a lower n or a fork, while the old state keeps serving: err, alarmed.
func (self *AclGateCache) alarm(networkId Id, err error) error {
	self.alarmCount.Add(1)
	self.log.Errorf("[acl_gate]%s alarm, the old state keeps serving: %v", networkId, err)
	return err
}

// A cache with no source loads nothing.
var errAclGateNoSource = errors.New("no gate source")

// Past ByteBudget, drops the loaded state of the networks read longest ago, never a loading one or the one just
// loaded, keeping each one's pin; past UnloadedCount, forgets the longest unread unloaded networks. A load within both
// bounds costs two atomic reads here.
func (self *AclGateCache) evict(loaded *aclGateNetwork) {
	overBytes := 0 < self.settings.ByteBudget && self.settings.ByteBudget < self.byteTotal.Load()
	overUnloaded := int64(max(0, self.settings.UnloadedCount)) < self.unloadedCount.Load()
	if !overBytes && !overUnloaded {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networks := *self.networks.Load()
	byLastRead := make([]*aclGateNetwork, 0, len(networks))
	for _, network := range networks {
		byLastRead = append(byLastRead, network)
	}
	slices.SortFunc(byLastRead, func(a *aclGateNetwork, b *aclGateNetwork) int {
		return cmp.Compare(a.lastRead.Load(), b.lastRead.Load())
	})
	for _, network := range byLastRead {
		if self.byteTotal.Load() <= self.settings.ByteBudget || self.settings.ByteBudget <= 0 {
			break
		}
		if network == loaded {
			continue
		}
		func() {
			network.stateLock.Lock()
			defer network.stateLock.Unlock()
			if network.loading || network.log == nil {
				return
			}
			if snapshot := network.snapshot.Load(); snapshot != nil {
				network.floor = snapshot.Pin
			}
			self.byteTotal.Add(-network.byteCount)
			network.log = nil
			network.byteCount = 0
			network.snapshot.Store(nil)
			self.unloadedCount.Add(1)
			self.evictionCount.Add(1)
		}()
	}
	if self.unloadedCount.Load() <= int64(max(0, self.settings.UnloadedCount)) {
		return
	}
	next := configCloneMap(networks)
	for _, network := range byLastRead {
		if self.unloadedCount.Load() <= int64(max(0, self.settings.UnloadedCount)) {
			break
		}
		forget := func() bool {
			network.stateLock.Lock()
			defer network.stateLock.Unlock()
			return !network.loading && network.log == nil && network != loaded
		}()
		if forget {
			delete(next, network.networkId)
			self.unloadedCount.Add(-1)
		}
	}
	self.networks.Store(&next)
}

// The poll: every PollInterval plus up to PollJitter, every network holding a log loads again, and the epoch moves.
func (self *AclGateCache) run() {
	if self.settings.PollInterval <= 0 {
		return
	}
	for {
		wait := self.settings.PollInterval
		if 0 < self.settings.PollJitter {
			wait += time.Duration(rand.Int64N(int64(self.settings.PollJitter) + 1))
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(wait):
		}
		self.epoch.Add(1)
		self.Resync()
	}
}
