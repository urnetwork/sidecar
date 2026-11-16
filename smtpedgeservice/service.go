// The engine's lifecycle: construction, readiness, drain and close. It builds the outbound path's parts
// from what its host gives: the send gate (SMTP-M9-10), quotas (SMTP-M9-11), MX and pre-TLS with the
// sending set (SMTP-M9-12), and the preamble handler that runs them in order (preamble.go); the streams,
// connections, proof RPCs, leases, send log and outcomes (SMTP-M9-13: splice.go, connection.go,
// proof_rpc.go, lease.go, send_log.go, outcome.go); and §14.8's ladder for cuts and bounces (SMTP-M9-16).
// It turns ready only when everything those need is present, so no host can route mail to it early: in
// production server injects no verifier until SMTP-M9-27's KeySet is pinned, and a nil verifier never
// turns ready (R-SMTP-13); with no X-UR-Ref key, no gate or world, no Redis, or no sending address whose
// FCrDNS holds, it is not ready either.
//
// Each probe reloads the halts (halt_reload.go): it makes the quota's halts exactly ActiveHalts, in memory
// and in Redis, so a halt survives Redis's loss, a lifted one leaves, and the memory holds what the store
// does (§14.9).
//
// Every wait is on the host's sidecar.Clock, so a schedule moves them.

package smtpedgeservice

import (
	"context"
	"errors"
	"sync"

	"github.com/urnetwork/sidecar"
)

var _ sidecar.Engine = (*SmtpEdgeService)(nil)

// What the outbound path reads beyond §14.9's signature, which SMTP-M9-20's host supplies: the send gate
// and the world. A nil member leaves the engine not ready.
type SmtpEdgeDeps struct {
	Gate SmtpGate
	// The DNSSEC-validating resolver and the TCP 25 dialer (SmtpMxNetDialer on a sending host).
	Resolver sidecar.SmtpMxResolver
	Dialer   sidecar.SmtpMxDialer
	// The sending addresses' reverse names, for FCrDNS.
	Ptr SmtpPtrResolver
	// The dialing client's sidecar, for mail_send. nil answers every stream's preamble TRY_LATER.
	Dialers SmtpDialerSource
	// How the LAN splice reaches mxedge's LAN listener (lan_splice.go). nil dials TCP.
	LanDial SmtpLanDial
	// What §14.8's ladder reads for cuts and hard bounces, and §21's sink. Any nil leaves both unjudged.
	Lookups SmtpReportLookups
	Halts   SmtpHaltLookups
	Sink    SmtpAbuseSink
}

// The engine. Everything here is safe for concurrent use.
type SmtpEdgeService struct {
	ctx      context.Context
	cancel   context.CancelFunc
	host     *sidecar.ServiceHost
	store    SmtpEdgeStore
	verifier sidecar.SmtpProofVerifier
	settings *SmtpEdgeSettings
	clock    sidecar.Clock
	metrics  *smtpMetrics
	deps     SmtpEdgeDeps
	// nil when the host gave no Redis.
	quota *SmtpQuota
	// nil when the deps hold no resolver or PTR resolver.
	sendingSet *SmtpSendingSet
	// nil when settings hold no X-UR-Ref key.
	issuer *smtpIssuer
	// nil unless every part above and the gate and dialer are present.
	preamble *smtpPreambleHandler
	// nil with no store.
	sendLog *smtpSendLog
	// nil with no Quota on the host; leases then refuse every connection.
	usage    *sidecar.QuotaUsageBatcher
	leases   *smtpEdgeLeases
	outcomes *smtpOutcomes
	// nil unless the host has Quota and deps hold the ladder's reads and sink.
	ladder   *SmtpHaltLadder
	haltWork chan *smtpHaltWork
	// the engine's own goroutines past run: the ladder's
	workers sync.WaitGroup
	// one per stream being served
	streams sync.WaitGroup
	// halt work the ladder finished, and waits a connection began for room, each counted once done, so a
	// test can see one land
	haltWorkCount *sidecar.MonitorValue[int]
	heldWaitCount *sidecar.MonitorValue[int]

	// What the last probe found.
	storeReachable *sidecar.MonitorValue[bool]
	// Probes finished, each counted once the wait for the next is armed, so a test can see one land and
	// move a fake clock past the next.
	probeCount *sidecar.MonitorValue[int]
	// Closed once the run loop has ended.
	released chan struct{}

	stateLock sync.Mutex
	draining  bool
	closed    bool
	// live connections by send_id, and what closes at each change
	sendIdConnections  map[string]*smtpEdgeConnection
	connectionsChanged chan struct{}
	listener           *sidecar.SocketPlatformListener
	handlerRemoves     []func()
}

// Starts the engine with no deps, so it is never ready: §14.9's signature, which a host that serves mail
// replaces with NewSmtpEdgeServiceWithDeps.
func NewSmtpEdgeService(
	ctx context.Context,
	host *sidecar.ServiceHost,
	store SmtpEdgeStore,
	verifier sidecar.SmtpProofVerifier,
	settings *SmtpEdgeSettings,
) (*SmtpEdgeService, error) {
	return NewSmtpEdgeServiceWithDeps(ctx, host, store, verifier, nil, settings)
}

// Starts the engine, which stays not ready until store, verifier, deps, Redis, an X-UR-Ref key and a
// sending address whose FCrDNS holds are all present and a probe has reached the store, and runs until
// ctx ends or Close. host needs Metrics. A nil store, verifier or deps is allowed and leaves the engine
// not ready for good.
func NewSmtpEdgeServiceWithDeps(
	ctx context.Context,
	host *sidecar.ServiceHost,
	store SmtpEdgeStore,
	verifier sidecar.SmtpProofVerifier,
	deps *SmtpEdgeDeps,
	settings *SmtpEdgeSettings,
) (*SmtpEdgeService, error) {
	if host == nil || host.Metrics == nil {
		return nil, errors.New("smtpedge needs a host with Metrics")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &SmtpEdgeService{
		ctx:            cancelCtx,
		cancel:         cancel,
		host:           host,
		store:          store,
		verifier:       verifier,
		settings:       settings,
		clock:          host.ClockOrReal(),
		metrics:        newSmtpMetrics(host.Metrics),
		storeReachable: sidecar.NewMonitorValue(false),
		probeCount:     sidecar.NewMonitorValue(0),
		released:       make(chan struct{}),

		sendIdConnections:  map[string]*smtpEdgeConnection{},
		connectionsChanged: make(chan struct{}),
		haltWork:           make(chan *smtpHaltWork, settings.HaltEventMaxCount),
		haltWorkCount:      sidecar.NewMonitorValue(0),
		heldWaitCount:      sidecar.NewMonitorValue(0),
	}
	if deps != nil {
		self.deps = *deps
	}
	if host.Redis != nil {
		quota, err := NewSmtpQuota(cancelCtx, host, settings)
		if err != nil {
			cancel()
			return nil, err
		}
		self.quota = quota
	}
	if self.deps.Resolver != nil && self.deps.Ptr != nil {
		var breaker func() (*SmtpBreakerState, bool)
		if self.deps.Gate != nil {
			breaker = self.deps.Gate.Breaker
		}
		self.sendingSet = NewSmtpSendingSet(cancelCtx, settings, self.clock, host.Metrics, self.deps.Ptr, self.deps.Resolver, breaker)
	}
	self.issuer = newSmtpIssuer(settings)
	if self.quota != nil && self.sendingSet != nil && self.issuer != nil && self.deps.Gate != nil && self.deps.Dialer != nil {
		self.preamble = &smtpPreambleHandler{
			settings: settings,
			frame:    sidecar.DefaultSmtpFrameSettings(),
			clock:    self.clock,
			abuse:    host.AbuseOrUnloaded(),
			gate:     self.deps.Gate,
			quota:    self.quota,
			mx:       newSmtpMxConnector(settings, self.clock, self.deps.Resolver, self.deps.Dialer, self.sendingSet, self.quota.DestinationCaps(), newSmtpLanDialer(settings, self.deps.LanDial)),
			verifier: verifier,
			issuer:   self.issuer,
			metrics:  self.metrics,
		}
	}
	if store != nil {
		self.sendLog = newSmtpSendLog(cancelCtx, store, settings, self.clock, host.Metrics)
	}
	if host.Quota != nil {
		usage, err := sidecar.NewQuotaUsageBatcher(cancelCtx, host, smtpUsageProducer, nil)
		if err != nil {
			self.closeParts()
			cancel()
			return nil, err
		}
		self.usage = usage
	}
	self.leases = newSmtpEdgeLeases(cancelCtx, host.Quota, self.usage, settings, self.clock)
	if host.Quota != nil && store != nil && self.deps.Lookups != nil && self.deps.Halts != nil && self.deps.Sink != nil {
		ladder, err := NewSmtpHaltLadder(host, &SmtpHaltLadderDeps{
			Store:   store,
			Lookups: self.deps.Lookups,
			Halts:   self.deps.Halts,
			Quota:   self.quota,
			Sink:    self.deps.Sink,
		}, settings)
		if err != nil {
			self.closeParts()
			cancel()
			return nil, err
		}
		self.ladder = ladder
		self.workers.Add(1)
		go self.runHalts()
	}
	self.outcomes = newSmtpOutcomes(settings, self.clock, host.Metrics, func(event *SmtpHaltEvent) {
		self.haltEvent(event, nil)
	})
	go self.run()
	return self, nil
}

// Closes what construction made before run started, on a construction that fails.
func (self *SmtpEdgeService) closeParts() {
	if self.sendLog != nil {
		self.sendLog.close()
	}
	if self.usage != nil {
		self.usage.Close()
	}
	if self.quota != nil {
		self.quota.Breaker().Close()
	}
	if self.sendingSet != nil {
		self.sendingSet.Close()
	}
}

// Probes the store each HaltReloadInterval until the engine ends. A probe reads ActiveHalts, the
// state an edge loads first, so reaching the store and loading halts are one call, and holds each row
// in the quota (§14.8: edges reload every 60 s).
func (self *SmtpEdgeService) run() {
	defer close(self.released)
	for {
		reachable := false
		if self.store != nil {
			testHookBarrier("smtpedge.probe.before", "")
			reachable = func() bool {
				ctx, done := self.storeContext()
				defer done()
				reloader := &smtpHaltReloader{store: self.store, quota: self.quota}
				return reloader.reload(ctx) == nil
			}()
			testHookBarrier("smtpedge.probe.after", "")
			if reachable {
				self.metrics.storeProbes.Add(1, smtpProbeResultOk)
			} else {
				self.metrics.storeProbes.Add(1, smtpProbeResultFailed)
			}
		}
		self.storeReachable.Set(reachable)
		probeTimer := self.clock.After(self.settings.HaltReloadInterval)
		self.probeCount.Update(func(count int) int { return count + 1 })
		select {
		case <-self.ctx.Done():
			return
		case <-probeTimer:
		}
	}
}

// A context bounded by StoreTimeout on the engine's clock, and the call that ends it.
func (self *SmtpEdgeService) storeContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(self.ctx)
	stop := self.clock.AfterFunc(self.settings.StoreTimeout, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// See sidecar.Engine. Ready once the store, the verifier, the preamble path's parts and at least one
// usable sending address are present and the last probe reached the store, and until Drain or Close.
func (self *SmtpEdgeService) Ready() bool {
	if self.store == nil || self.verifier == nil || len(self.settings.SendingAddresses) == 0 || self.preamble == nil {
		return false
	}
	if len(self.sendingSet.Usable()) == 0 {
		return false
	}
	if !self.storeReachable.Value() || self.ctx.Err() != nil {
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return !self.draining
}

// See sidecar.Engine: no new ticket or stream, then the connections finish, up to DrainTimeout on the
// engine's clock, and what is left resets; its mail retries from its sender (§14.9). The open usage window
// leaves at once.
func (self *SmtpEdgeService) Drain() {
	listener := func() *sidecar.SocketPlatformListener {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.draining = true
		return self.listener
	}()
	if listener != nil {
		listener.SetServing(false)
	}
	self.drainConnections()
	if self.usage != nil {
		self.usage.Drain(context.WithoutCancel(self.ctx))
	}
}

// See sidecar.Engine: the listener and every connection end, and every goroutine is joined.
func (self *SmtpEdgeService) Close() {
	listener, removes := func() (*sidecar.SocketPlatformListener, []func()) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		removes := self.handlerRemoves
		self.handlerRemoves = nil
		return self.listener, removes
	}()
	for _, remove := range removes {
		remove()
	}
	if listener != nil {
		listener.Close()
	}
	self.closeConnections()
	self.cancel()
	<-self.released
	self.workers.Wait()
	self.closeParts()
}
