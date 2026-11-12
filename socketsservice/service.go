// The engine's lifecycle: construction, readiness, drain and close, and the parts every route shares.
// Its routes are each in their own file: POST /socket/registrations (registrations.go), GET /socket/list
// (list.go) and GET /socket/keys (keys.go), SOCK-M5-05's, and POST /socket/find (find.go, tickets.go),
// SOCK-M5-06's. request.go holds the steps they share, and refusals.go what they refuse from memory.
//
// The engine turns ready only when everything a route needs is present: a store that answers its probe,
// a gate that is ready, and a ticket key that signs (§19.4's column for sockets: Redis, ticket key,
// projection loaded). A host that has none of these, or only ClosedSocketGate, serves nothing.
//
// Beside its probe the engine runs the workers sweep.go describes: the revocation sweep, a removed client's
// store work and the kill set's reader, each fed by what the host's key-event subscriber calls, and each
// joined by Close.
//
// Every wait is on the host's sidecar.Clock, so a schedule moves them. Safe for concurrent use.

package socketsservice

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

var _ sidecar.HttpEngine = (*SocketsService)(nil)

// The service's ticket keys (§9.8): the newest settled key signs, and every listed key verifies.
// SOCK-M5-08's SocketTicketKeySet reads them from vault's secret_files and rotates them on 30 days with
// overlap. Safe for concurrent use.
type SocketTicketKeys interface {
	// The key that signs now, and false when none is loaded, which leaves the engine not ready and
	// signing nothing.
	SigningKey() (keyId string, privateKey ed25519.PrivateKey, ok bool)
	// Every key a ticket may verify under, as registration answers and GET /socket/keys publish them.
	VerifyKeys() []*sidecar.SocketTicketKey
}

// The engine. Everything here is safe for concurrent use.
type SocketsService struct {
	ctx      context.Context
	cancel   context.CancelFunc
	host     *sidecar.ServiceHost
	store    SocketStore
	gate     SocketGate
	settings *SocketsSettings
	clock    sidecar.Clock
	metrics  *socketMetrics

	bound      *SocketControlBound
	fairQueue  *SocketFairQueue
	namespaces *socketNamespaceRegistry

	// What the routes refuse from memory (refusals.go), which ClientRemoved and the kills reader fill (sweep.go).
	removedClients *socketRemovedClients
	killSet        *socketKillSet
	// The revocation sweep's queue and the removed clients awaiting their store work (sweep.go), and what joins
	// every worker the engine starts beside its probe.
	sweeps   *socketSweeps
	removals *socketRemovals
	workers  sync.WaitGroup
	// Claims seen to pass (registrations.go), pair renewals and pair writes this process made (find.go), and
	// the registrations gauge's count.
	claimMemo    *socketClaimMemo
	pairTouches  *socketPairTouches
	pairWrites   *socketPairWrites
	leaseCounter *socketLeaseCounter
	// One uniform draw for a pick (§9.7): the system's randomness, which a test may fix.
	draw func() uint32
	// Tickets signed, so a test can show that a refusal signed none, and claim signatures checked, so a test
	// can show that a heartbeat checks none.
	signedCount      atomic.Int64
	claimVerifyCount atomic.Int64

	// What the last probe found.
	storeReachable *sidecar.MonitorValue[bool]
	// Probes finished, each counted once the wait for the next is armed, so a test can see one land
	// and move a fake clock past the next.
	probeCount *sidecar.MonitorValue[int]
	// Closed once the run loop has ended.
	released chan struct{}

	handlerOnce sync.Once
	handler     http.Handler

	stateLock  sync.Mutex
	ticketKeys SocketTicketKeys
	draining   bool
}

// Starts the engine, which stays not ready until its store answers, its gate has loaded and a ticket
// key is set, and runs until ctx ends or Close. host needs Metrics. A nil store or gate is allowed and
// leaves the engine not ready for good, as ClosedSocketGate does.
func NewSocketsService(
	ctx context.Context,
	host *sidecar.ServiceHost,
	store SocketStore,
	gate SocketGate,
	settings *SocketsSettings,
) (*SocketsService, error) {
	if host == nil || host.Metrics == nil {
		return nil, errors.New("sockets needs a host with Metrics")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	clock := host.ClockOrReal()
	metrics := newSocketMetrics(host.Metrics)
	self := &SocketsService{
		ctx:            cancelCtx,
		cancel:         cancel,
		host:           host,
		store:          store,
		gate:           gate,
		settings:       settings,
		clock:          clock,
		metrics:        metrics,
		bound:          NewSocketControlBound(settings.Bound, clock),
		fairQueue:      NewSocketFairQueue(settings.FairQueue, clock),
		namespaces:     newSocketNamespaceRegistry(),
		removedClients: newSocketRemovedClients(settings.RemovedClientTtl),
		killSet:        newSocketKillSet(),
		sweeps:         newSocketSweeps(settings.SweepMinInterval),
		removals:       newSocketRemovals(settings.ClientRemovedQueueCount, settings.ClientRemovedConcurrency),
		claimMemo:      newSocketClaimMemo(settings.ClaimMemoCount),
		pairTouches:    newSocketPairTouches(settings.EdgePairTouchInterval),
		pairWrites:     newSocketPairWrites(settings.PairWriteInterval),
		leaseCounter:   newSocketLeaseCounter(settings.Store.Lease, metrics.registrations),
		draw:           socketCryptoDraw,
		storeReachable: sidecar.NewMonitorValue(false),
		probeCount:     sidecar.NewMonitorValue(0),
		released:       make(chan struct{}),
	}
	if follower, ok := gate.(SocketGateFollower); ok {
		follower.OnNarrowed(self.queueSweep)
	}
	self.workers.Add(2 + settings.ClientRemovedConcurrency)
	go self.runSweeps()
	go self.runKills()
	for range settings.ClientRemovedConcurrency {
		go self.runRemovals()
	}
	go self.run()
	return self, nil
}

// Probes the store each ProbeInterval until the engine ends.
func (self *SocketsService) run() {
	defer close(self.released)
	for {
		reachable := false
		if self.store != nil {
			testHookBarrier("sockets.probe.before", "")
			reachable = func() bool {
				ctx, done := self.storeContext()
				defer done()
				return self.store.Ping(ctx) == nil
			}()
			testHookBarrier("sockets.probe.after", "")
		}
		self.storeReachable.Set(reachable)
		probeTimer := self.clock.After(self.settings.ProbeInterval)
		self.probeCount.Update(func(count int) int { return count + 1 })
		select {
		case <-self.ctx.Done():
			return
		case <-probeTimer:
		}
	}
}

// A context bounded by StoreTimeout on the engine's clock, and the call that ends it. Every store call
// takes one, so a stalled store reads as unavailable and never holds a caller.
func (self *SocketsService) storeContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(self.ctx)
	stop := self.clock.AfterFunc(self.settings.StoreTimeout, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// Probes finished, and a channel that closes at the next: what a host's test waits on before it asks Ready.
func (self *SocketsService) Probes() (count int, changed chan struct{}) {
	return self.probeCount.Get()
}

// Lays config/<env>/sidecar.yml's sockets_control_qps over the control bound's sidecar rate and burst
// (§19.11): the host calls it each time it rereads the file. A rate or burst that is not positive changes
// nothing.
func (self *SocketsService) SetControlRate(callsPerSecond int, burst int) {
	self.bound.SetRate(callsPerSecond, burst)
}

// Sets the keys tickets are signed and verified with: SOCK-M5-08's host calls this once its key file
// loads, and again on each rotation. nil takes them away, and the engine turns not ready.
func (self *SocketsService) SetTicketKeys(ticketKeys SocketTicketKeys) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.ticketKeys = ticketKeys
}

// The keys set, and whether one of them signs.
func (self *SocketsService) currentTicketKeys() (SocketTicketKeys, bool) {
	self.stateLock.Lock()
	ticketKeys := self.ticketKeys
	self.stateLock.Unlock()
	if ticketKeys == nil {
		return nil, false
	}
	_, _, signs := ticketKeys.SigningKey()
	return ticketKeys, signs
}

// Registers the owner of an edge namespace, tls/, smtp/ or ur/ (§9.4): TLS-M5-22's, MAIL-M7-22's and
// SOCK-M9-01's hosts call this before serving. An edge namespace nobody registered refuses every
// entry, and a second registration of one namespace is an error.
func (self *SocketsService) RegisterNamespace(namespace sidecar.SocketNamespace, hooks SocketNamespaceHooks) error {
	return self.namespaces.register(namespace, hooks)
}

// Whether network is the urnetwork-edge platform network, whose callers take the edge bound and Find as
// autogroup:public (§9.10), from §19.11's sidecar.yml. Unset reads as no network, so an engine whose
// host did not set it treats every caller as a sidecar, the closed direction.
func (self *SocketsService) isUrnetworkEdge(networkId connect.Id) bool {
	edgeNetworkId, set := self.host.GatesOrClosed().UrnetworkEdge()
	return set && edgeNetworkId == networkId
}

// See sidecar.Engine. Ready once the store answered its last probe, the gate has loaded and a ticket
// key signs, and until Drain or Close.
func (self *SocketsService) Ready() bool {
	if self.store == nil || self.gate == nil || !self.gate.Ready() {
		return false
	}
	if _, signs := self.currentTicketKeys(); !signs {
		return false
	}
	if !self.storeReachable.Value() || self.ctx.Err() != nil {
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return !self.draining
}

// See sidecar.Engine. Every call is one request, bounded by StoreTimeout, so there is nothing to wait
// for here: the host has stopped new connections, and calls in flight finish on their own bound.
func (self *SocketsService) Drain() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.draining = true
}

// See sidecar.Engine. Joins the probe and every worker: sweeps, removals and the kills reader. The gate is the
// host's to close.
func (self *SocketsService) Close() {
	self.cancel()
	<-self.released
	self.workers.Wait()
}

// See sidecar.HttpEngine. Built once: §9.15's four routes, each served from its own file, and any other
// path or method answers as the mux does, 404 or 405.
func (self *SocketsService) Handler() http.Handler {
	self.handlerOnce.Do(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /socket/registrations", self.serveRegistrations)
		mux.HandleFunc("GET /socket/list", self.serveList)
		mux.HandleFunc("GET /socket/keys", self.serveKeys)
		mux.HandleFunc("POST /socket/find", self.serveFind)
		self.handler = mux
	})
	return self.handler
}
