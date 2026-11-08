// The engine's lifecycle: construction, readiness, drain and close. What it serves arrives with M9's
// tasks: the preamble gate (SMTP-M9-10), quotas (SMTP-M9-11), MX and pre-TLS (SMTP-M9-12), the splice
// and proof checks (SMTP-M9-13), and the halt reloader (SMTP-M9-16). Until then it serves nothing,
// and it turns ready only when everything those need is present, so no host can route mail to it
// early: in production server injects no verifier until SMTP-M9-27's KeySet is pinned, and a nil
// verifier never turns ready (R-SMTP-13).
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

	// What the last probe found.
	storeReachable *sidecar.MonitorValue[bool]
	// Probes finished, each counted once the wait for the next is armed, so a test can see one land and
	// move a fake clock past the next.
	probeCount *sidecar.MonitorValue[int]
	// Closed once the run loop has ended.
	released chan struct{}

	stateLock sync.Mutex
	draining  bool
}

// Starts the engine, which stays not ready until store, verifier and a sending address are all present
// and a probe has reached the store, and runs until ctx ends or Close. host needs Metrics. A nil
// store or verifier is allowed and leaves the engine not ready for good.
func NewSmtpEdgeService(
	ctx context.Context,
	host *sidecar.ServiceHost,
	store SmtpEdgeStore,
	verifier sidecar.SmtpProofVerifier,
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
	}
	go self.run()
	return self, nil
}

// Probes the store each HaltReloadInterval until the engine ends. A probe reads ActiveHalts, the
// state an edge loads first, so reaching the store and loading halts are one call; SMTP-M9-16's
// reloader keeps the halts it reads, and this probe keeps only whether the read answered.
func (self *SmtpEdgeService) run() {
	defer close(self.released)
	for {
		reachable := false
		if self.store != nil {
			testHookBarrier("smtpedge.probe.before", "")
			reachable = func() bool {
				ctx, done := self.storeContext()
				defer done()
				_, err := self.store.ActiveHalts(ctx)
				return err == nil
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

// See sidecar.Engine. Ready once the store, the verifier and at least one sending address are present
// and the last probe reached the store, and until Drain or Close.
func (self *SmtpEdgeService) Ready() bool {
	if self.store == nil || self.verifier == nil || len(self.settings.SendingAddresses) == 0 {
		return false
	}
	if !self.storeReachable.Value() || self.ctx.Err() != nil {
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return !self.draining
}

// See sidecar.Engine. With no connection path yet there is nothing in flight, so this returns at once;
// SMTP-M9-13 waits here for connections up to DrainTimeout.
func (self *SmtpEdgeService) Drain() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.draining = true
}

// See sidecar.Engine.
func (self *SmtpEdgeService) Close() {
	self.cancel()
	<-self.released
}
