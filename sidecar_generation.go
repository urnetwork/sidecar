// One client generation (§5.5): what every leg runs for it, and the seam to what only the leg runs. On every leg a
// generation installs its token and the ClientKey's DPoP signer in SidecarApi and runs D-CORE-8's refresher
// (api_token_manager.go); on connect legs the leg adds the client, its subprotocol and each component's Attach
// (sidecar_new_connect.go), and installs each refreshed token in connect's holders too.
//
// Only the run loop starts and ends a generation, so a generation's teardown never runs on a goroutine it would
// join: the refresher's refusal, connect's notifications and a component's call each ask the run loop, through
// wake, rather than tear anything down themselves. Events and moves carry the generation, so an older generation's
// are dropped (D-SDK-14).

package sidecar

import (
	"context"
	"crypto/rand"
	"sync/atomic"
)

// What only a leg runs beside the core. Every method is called from the run loop or a host's call, never under
// stateLock.
type sidecarLeg interface {
	// Starts the leg's half of generation, which must end with generation's ctx. An error leaves nothing running.
	startGeneration(generation *sidecarGeneration) (sidecarLegGeneration, error)
	// The components that re-register after a restore (§19.10).
	restorers() []SidecarRestorer
	// The running generation's dispatcher's counters, zero with none.
	subprotocolStats() SidecarSubprotocolStats
	// Closes each component, once the last generation has ended.
	close()
}

// The leg's half of one generation.
type sidecarLegGeneration interface {
	// Begins what reports on or uses the generation, once the run loop has published it: the watch on the
	// connection and each component's Attach, so a report or a removal always finds the generation it names.
	start()
	// Installs a refreshed token in the leg's holders: connect's api, transport and out-of-band control.
	install(byJwt string)
	// Brings the attached components in line with the leg's list.
	reconcileComponents()
	// The generation's dispatcher's counters.
	subprotocolStats() SidecarSubprotocolStats
	// Ends the client and everything on it and joins them. The generation's ctx has already ended.
	closeAndWait()
}

// What the run loop starts a generation from: an identity the keychain holds, with its token and ClientKey seed.
type sidecarGenerationArgs struct {
	identity          *SidecarIdentity
	networkId         Id
	connectInstanceId Id
	byJwt             string
	// a copy, which the generation erases once the leg has read it
	clientKeySeed []byte
	// the generation's marshalled SignedSidecarIdentityBinding, which §6's Hello carries
	binding []byte
	// the core's namespace of the network's keychain
	secrets SidecarSecrets
	// the client is a child of a device client (sidecar.json's record)
	child bool
}

// One running client generation.
type sidecarGeneration struct {
	sidecar           *Sidecar
	generation        int64
	identity          *SidecarIdentity
	networkId         Id
	connectInstanceId Id
	byJwt             string
	// read by the leg while it starts, then erased
	clientKeySeed []byte
	// the generation's marshalled SignedSidecarIdentityBinding, which §6's Hello carries
	binding []byte
	ctx     context.Context
	cancel  context.CancelFunc
	// set once the refresher runs; connect's notifications before then are dropped, since the refresher's own
	// schedule covers a token that close was about
	tokenManager atomic.Pointer[sidecarTokenManager]
	leg          sidecarLegGeneration
	// closed once the start's post of pending statements has returned (identity_pending.go)
	pendingDone chan struct{}
}

// connect's AuthorizationClosed for this generation's client: a close for unavailability is ignored, and anything
// else asks the refresher for a refresh and nothing more (connect/transport.go:528).
func (self *sidecarGeneration) authorizationClosed(unavailable bool) {
	if manager := self.tokenManager.Load(); manager != nil {
		manager.authorizationClosed(unavailable)
	}
}

// The client connected or lost its connection: Online or Offline at this generation, which the machine drops once a
// newer generation runs.
func (self *sidecarGeneration) connectionChanged(connected bool) {
	if self.ctx.Err() != nil {
		return
	}
	to := SidecarStateOffline
	if connected {
		to = SidecarStateOnline
	}
	self.sidecar.applyTransition(sidecarTransition{to: to, generation: self.generation})
}

// The generation the run loop is running, or nil.
func (self *Sidecar) runningGeneration() *sidecarGeneration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.generation
}

// Starts args' generation: Offline at its number, then the leg's client and the refresher. The run loop calls this
// with no generation running. A leg that cannot start leaves the sidecar Offline with no client, which the next wake
// tries again; nothing here wakes the loop, so a failure cannot spin it.
func (self *Sidecar) startGeneration(args *sidecarGenerationArgs) {
	defer clear(args.clientKeySeed)
	generationNumber := args.identity.Generation
	// The generation's proof signer and token are installed before the status names the generation, so a host
	// or component that acts on that status finds them. A refused move takes them back out.
	signer, signerErr := newDpopSigner(args.clientKeySeed, self.clock.Now, self.apiClockOffset, rand.Reader)
	if signerErr == nil {
		self.sidecarApi.setDpopSigner(signer)
		self.sidecarApi.SetByJwt(args.byJwt)
	}
	moved := self.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: generationNumber})
	if !moved && self.lifecycleState() != SidecarStateOffline {
		if signerErr == nil {
			self.sidecarApi.SetByJwt("")
			self.sidecarApi.setDpopSigner(nil)
		}
		self.log.Warningf("[sidecar]generation %d did not start from %s", generationNumber, self.lifecycleState())
		return
	}
	if signerErr != nil {
		self.log.Errorf("[sidecar]generation %d has no proof signer: %s", generationNumber, signerErr)
		return
	}

	generationCtx, cancel := context.WithCancel(self.ctx)
	generation := &sidecarGeneration{
		sidecar:           self,
		generation:        generationNumber,
		identity:          args.identity,
		networkId:         args.networkId,
		connectInstanceId: args.connectInstanceId,
		byJwt:             args.byJwt,
		clientKeySeed:     args.clientKeySeed,
		binding:           args.binding,
		ctx:               generationCtx,
		cancel:            cancel,
	}
	if self.leg != nil {
		testHookBarrier("sidecar.generation.start.before", args.identity.SidecarId.String())
		legGeneration, err := self.leg.startGeneration(generation)
		testHookBarrier("sidecar.generation.start.after", args.identity.SidecarId.String())
		if err != nil {
			cancel()
			self.sidecarApi.SetByJwt("")
			self.sidecarApi.setDpopSigner(nil)
			self.log.Errorf("[sidecar]generation %d did not start: %s", generationNumber, err)
			return
		}
		generation.leg = legGeneration
	}
	var install func(byJwt string)
	if generation.leg != nil {
		install = generation.leg.install
	}
	secrets := args.secrets
	persist := func(byJwt string) error {
		return persistSidecarByJwt(secrets, byJwt)
	}
	// an sdk host's token source refreshes once it holds this generation's signer, and only then does the core's
	// refresher stand down (CORE-M8-01)
	source := self.hostTokenSource()
	hostRefreshes := self.handOffDpopSigner(source, signer)
	manager := newSidecarTokenManager(generationCtx, &sidecarTokenManagerArgs{
		Api:           self.sidecarApi,
		Settings:      self.settings.TokenRefreshSettings,
		Clock:         self.clock,
		Log:           self.log,
		Generation:    generationNumber,
		Child:         args.child,
		HostRefreshes: hostRefreshes,
		Persist:       persist,
		Install:       install,
		Refused: func(refusedGeneration int64, reason SidecarStateReason) {
			self.tokenRefused(refusedGeneration, reason)
			self.generationRefused(refusedGeneration)
		},
		Restore: func(ctx context.Context, install func(presentedByJwt string, byJwt string) error) error {
			var restorers []SidecarRestorer
			if self.leg != nil {
				restorers = self.leg.restorers()
			}
			return self.restoreRegistrations(ctx, restorers, install)
		},
	})
	generation.tokenManager.Store(manager)
	if hostRefreshes {
		self.followTokenSource(generationCtx, source, generationNumber, args.identity, persist, install, manager.end)
	}
	// made before the generation is published, so whoever reads the generation can wait on its repost below
	generation.pendingDone = make(chan struct{})
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.generation = generation
	}()
	self.runningGenerationNumber.Set(generationNumber)
	self.stats.generationCount.Add(1)
	if generation.leg != nil {
		// published first, so a component removed meanwhile is detached from this generation or never attached,
		// and Online names a generation Status and the components already see
		generation.leg.start()
	}
	// what a kill or a lost answer left pending goes again, the same bytes, on the new generation's token (§5.6's
	// sign row); one still pending waits for the next start or a caller's PostPendingStatements
	go func() {
		defer close(generation.pendingDone)
		if err := self.PostPendingStatements(generationCtx); err != nil && generationCtx.Err() == nil {
			self.log.Infof("[identity]pending statements stay pending: %s", err)
		}
	}()
	if self.log.V(1).Enabled() {
		self.log.Infof("[sidecar]generation %d started", generationNumber)
	}
}

// A confirmed rejection ended generation: it is not started again, and the run loop tears it down.
func (self *Sidecar) generationRefused(generation int64) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.endedGeneration = max(self.endedGeneration, generation)
	}()
	self.wake()
}

// Ends the running generation, if any, and joins everything it started: the leg's client and components' calls,
// then the refresher. The token and signer leave SidecarApi with it, and so does every cached service token. Runs on
// the run loop only.
func (self *Sidecar) stopGeneration() {
	var generation *sidecarGeneration
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		generation = self.generation
		self.generation = nil
	}()
	if generation == nil {
		return
	}
	testHookBarrier("sidecar.generation.stop.before", generation.identity.SidecarId.String())
	generation.cancel()
	if generation.pendingDone != nil {
		<-generation.pendingDone
	}
	if generation.leg != nil {
		generation.leg.closeAndWait()
	}
	if manager := generation.tokenManager.Load(); manager != nil {
		manager.closeAndWait()
	}
	self.sidecarApi.SetByJwt("")
	self.sidecarApi.setDpopSigner(nil)
	self.serviceTokens.clear()
	self.runningGenerationNumber.Set(0)
	testHookBarrier("sidecar.generation.stop.after", generation.identity.SidecarId.String())
	if self.log.V(1).Enabled() {
		self.log.Infof("[sidecar]generation %d ended", generation.generation)
	}
}
