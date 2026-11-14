// The Sidecar's lifecycle on every leg (§5.4, D-CORE-2): the run loop that NewSidecar starts, which alone starts and
// ends client generations, and the calls a host makes on a running Sidecar: Unlock, Status, AddEventCallback, Stats,
// Close and CloseAndWait. Nothing here names a connect type; each leg's NewSidecar brings its own sidecarLeg, the
// connect legs' client generations and components (sidecar_new_connect.go), and the sidecar_http leg its long-poll
// (CORE-M4-01).
//
// The run loop reads the instance's state and the network's keychain, and moves the machine of sidecar_state.go to
// match: a locked or failed store is Locked with the client torn down and the identity kept (§5.9), a lost one is
// Unenrolled(keystore_lost), and an open one with an enrolled identity and its token runs that identity's generation.
// A generation a confirmed rejection ended is not started again, since only a re-enrollment binds the next (D-CORE-8).
// It wakes on the instance's changes and on wake(), which an enrollment, a generation's end and a close raise, and
// never polls.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"sync"
)

// A Sidecar closed, or closing: nothing more starts.
var ErrSidecarClosed = errors.New("sidecar closed")

// Starts the run loop on what the leg's NewSidecar built, until ctx ends or cancel. networkId is the host store's, nil
// before enrollment.
func (self *Sidecar) start(ctx context.Context, cancel context.CancelFunc, instance *SidecarInstance, networkId *Id, leg sidecarLeg) {
	self.instance = instance
	self.leg = leg
	self.ctx = ctx
	self.cancel = cancel
	self.done = make(chan struct{})
	if networkId != nil {
		id := *networkId
		self.networkId = &id
	}
	go self.run()
}

// Asks the run loop to look again. Never blocks.
func (self *Sidecar) wake() {
	self.wakes.Update(func(count uint64) uint64 {
		return count + 1
	})
}

// The loop: subscribe to both sources of change, then act on what they show, until the Sidecar closes. On the way out
// it ends the generation and closes every component, then closes done.
func (self *Sidecar) run() {
	defer close(self.done)
	defer func() {
		self.stopGeneration()
		if self.leg != nil {
			self.leg.close()
		}
	}()
	// D-TRUST-3's alarm runs at the start and each SyncRefetchInterval after
	hostStoreScan := self.clock.After(0)
	for {
		_, wakeChanged := self.wakes.Get()
		instanceState, instanceChanged := self.instance.State()
		if self.ctx.Err() != nil {
			return
		}
		self.reconcile(instanceState)
		select {
		case <-self.ctx.Done():
			return
		case <-wakeChanged:
		case <-instanceChanged:
		case <-hostStoreScan:
			self.alarmHostCredentialStores()
			hostStoreScan = self.clock.After(self.settings.ProtocolSettings.SyncRefetchInterval)
		}
	}
}

// The stores on this host holding a readable network credential (D-TRUST-3).
func (self *Sidecar) hostCredentialStores() []SidecarHostCredentialStore {
	if self.hostStores == nil {
		return nil
	}
	return self.hostStores()
}

// An enrolled sidecar's alarm while a store on this host holds a readable network credential: one credential_store
// event, naming no path or value (plan-CORE-host-store-refusal). By state, with no signal to wait for, so a host the
// releases cleaned stops alarming by itself.
func (self *Sidecar) alarmHostCredentialStores() {
	if self.currentIdentity() == nil {
		return
	}
	if stores := self.hostCredentialStores(); 0 < len(stores) {
		self.log.Warningf("[sidecar]a URnetwork app or extension on this host holds a network credential")
		self.emitEvent(SidecarEvent{Kind: SidecarEventCredentialStore})
	}
}

// Moves the lifecycle to match the instance's state and the network's keychain. Runs on the run loop only.
func (self *Sidecar) reconcile(instanceState SidecarInstanceState) {
	previousState := func() SidecarInstanceState {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		previous := self.instanceState
		self.instanceState = instanceState
		return previous
	}()
	switch instanceState {
	case SidecarInstanceOpen:
		self.reconcileOpen()
	case SidecarInstanceLost:
		// D-CORE-15: only the pass, a recovery code or the person's confirmation goes on from here
		self.stopGeneration()
		self.leaveForUnenrolled(SidecarReasonKeystoreLost)
	case SidecarInstanceFailed:
		self.stopGeneration()
		self.enterLocked()
		if previousState != SidecarInstanceFailed {
			// §5.9's Failed: as Locked, and alarms
			self.emitEvent(SidecarEvent{Kind: SidecarEventRefused})
		}
	default:
		self.stopGeneration()
		self.enterLocked()
	}
}

// The open instance's half: read this network's identity and token, and run its generation.
func (self *Sidecar) reconcileOpen() {
	var networkId *Id
	var revoked bool
	var endedGeneration int64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.networkId != nil {
			id := *self.networkId
			networkId = &id
		}
		revoked = self.lifecycle.state == SidecarStateRevoked
		endedGeneration = self.endedGeneration
	}()
	if revoked {
		self.stopGeneration()
		return
	}
	if networkId == nil {
		// not enrolled in any network yet
		self.stopGeneration()
		self.leaveForUnenrolled("")
		return
	}
	secrets := self.instance.secrets(*networkId, sidecarCoreSecretsNamespace)
	record, err := loadSidecarIdentity(secrets)
	switch {
	case err == nil:
	case errors.Is(err, ErrSidecarNoIdentity):
		self.setIdentity(secrets, nil)
		self.stopGeneration()
		self.leaveForUnenrolled("")
		return
	case errors.Is(err, ErrSidecarKeystoreLost):
		self.stopGeneration()
		self.leaveForUnenrolled(SidecarReasonKeystoreLost)
		return
	case errors.Is(err, ErrSidecarStoreLocked):
		// the instance locked under us, which wakes the loop again
		self.stopGeneration()
		self.enterLocked()
		return
	default:
		// a keychain that fails decoding or AEAD: as Locked, and alarms, creating nothing (D-CORE-15)
		self.log.Warningf("[sidecar]the network's keychain failed: %s", err)
		self.stopGeneration()
		self.enterLocked()
		self.emitEvent(SidecarEvent{Kind: SidecarEventRefused})
		return
	}
	defer record.keys.erase()
	self.setIdentity(secrets, record.identity)
	if self.lifecycleState() == SidecarStateLocked {
		self.leaveForUnenrolled("")
	}

	identity := record.identity
	if identity.Generation <= endedGeneration {
		// refused: only a re-enrollment, which binds the next generation, goes on (D-CORE-8)
		self.stopGeneration()
		return
	}
	if running := self.runningGeneration(); running != nil && running.generation == identity.Generation {
		if running.leg != nil {
			running.leg.reconcileComponents()
		}
		return
	}
	byJwt, err := loadSidecarByJwt(secrets)
	if err != nil {
		if !errors.Is(err, ErrSidecarStoreAbsent) {
			self.log.Warningf("[sidecar]the client token did not load: %s", err)
		}
		self.stopGeneration()
		self.leaveForUnenrolled("")
		return
	}
	if _, tokenClientId, ok := sidecarJwtClient(byJwt); !ok || tokenClientId != identity.ClientId {
		// the identity and its token are written one after the other, so an enrollment a kill cut short can leave
		// one generation's token beside another's binding: that runs no client
		self.log.Warningf("[sidecar]the client token is not generation %d's", identity.Generation)
		self.stopGeneration()
		self.leaveForUnenrolled("")
		return
	}
	connectInstanceId, child, ok := self.networkRecordOf(*networkId)
	if !ok {
		// enrollment records the network last, so an identity with no record is an enrollment a kill cut short
		self.log.Warningf("[sidecar]an identity with no network record does not start")
		self.stopGeneration()
		self.leaveForUnenrolled("")
		return
	}
	self.stopGeneration()
	self.startGeneration(&sidecarGenerationArgs{
		identity:          identity.clone(),
		networkId:         *networkId,
		connectInstanceId: connectInstanceId,
		byJwt:             byJwt,
		clientKeySeed:     record.keys.clientKeySeedCopy(),
		binding:           bytes.Clone(record.binding),
		secrets:           secrets,
		child:             child,
	})
}

// The connect InstanceId and child flag sidecar.json keeps for the network.
func (self *Sidecar) networkRecordOf(networkId Id) (Id, bool, bool) {
	for _, record := range self.instance.Networks() {
		if record.NetworkId == networkId {
			return record.ConnectInstanceId, record.Child, true
		}
	}
	return Id{}, false, false
}

// The connect InstanceId sidecar.json keeps for the network, so a restart keeps the resident (§5.9).
func (self *Sidecar) connectInstanceIdOf(networkId Id) (Id, bool) {
	for _, record := range self.instance.Networks() {
		if record.NetworkId == networkId {
			return record.ConnectInstanceId, true
		}
	}
	return Id{}, false
}

// Points the sidecar at secrets and the identity they hold, nil for none.
func (self *Sidecar) setIdentity(secrets SidecarSecrets, identity *SidecarIdentity) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.coreSecrets = secrets
	if identity == nil {
		self.identity = nil
		return
	}
	self.identity = identity.clone()
}

// The state the machine is in.
func (self *Sidecar) lifecycleState() SidecarState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.lifecycle.state
}

// The machine's generation.
func (self *Sidecar) lifecycleGeneration() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.lifecycle.generation
}

// Locked, at the current generation: a lock or a store's failure, never a client's. Revoked stays.
func (self *Sidecar) enterLocked() {
	if state := self.lifecycleState(); state == SidecarStateLocked || state == SidecarStateRevoked {
		return
	}
	self.applyTransition(sidecarTransition{to: SidecarStateLocked, generation: self.lifecycleGeneration()})
}

// Unenrolled for reason at the current generation, Online dropping to Offline first, as its connection does.
// Revoked stays, and a reason already recorded stays unless a new one replaces it.
func (self *Sidecar) leaveForUnenrolled(reason SidecarStateReason) {
	var current sidecarLifecycle
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		current = self.lifecycle
	}()
	switch current.state {
	case SidecarStateRevoked:
		return
	case SidecarStateUnenrolled:
		if reason == "" || reason == current.reason {
			return
		}
	case SidecarStateOnline:
		self.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: current.generation})
	}
	self.applyTransition(sidecarTransition{to: SidecarStateUnenrolled, reason: reason, generation: current.generation})
}

// Opens U, which opens every network's keychain (§5.9): by the key store's wrap of U when passphrase is nil, else by
// the pass, which approves nothing. The Sidecar leaves Locked once its keychain reads; Status shows when. Answers
// the instance's own errors: ErrSidecarStoreLocked while the store is locked or a pass is needed,
// ErrSidecarStoreFailed, ErrSidecarKeystoreLost, ErrSidecarPassRefused and ErrSidecarPassLimited.
func (self *Sidecar) Unlock(passphrase []byte) error {
	if self.instance == nil {
		return ErrSidecarClosed
	}
	err := self.instance.Unlock(passphrase)
	self.wake()
	return err
}

// The state, its reason, the bound client generation, and §6.4's witnessed_at and open UNVERIFIED pins, for `ur
// status` and §18.5's GetState.
//
// Offline and Online are a client generation's own states, so beside them the generation is the one in that state:
// a pairing or a re-enrollment binds generation n+1 while n's client is up, and Status names n+1 only once the run
// loop has ended n, installed n+1's token and proof signer, and moved to it, Offline (§18.5's State block;
// startGeneration). So whoever acts on a status at a generation finds that generation's token in the api client,
// bind's re-mint included (QD-797). Short of a client, in Locked, Unenrolled and Revoked, the generation is the
// keychain's, which a binding may have moved past the last client's. BoundGeneration answers the keychain's at
// any time.
func (self *Sidecar) Status() SidecarStatus {
	status := func() SidecarStatus {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		status := SidecarStatus{
			State:      self.lifecycle.state,
			Reason:     self.lifecycle.reason,
			Generation: self.lifecycle.generation,
		}
		switch status.State {
		case SidecarStateOffline, SidecarStateOnline:
			// the generation whose client is in that state
		default:
			if self.identity != nil && status.Generation < self.identity.Generation {
				status.Generation = self.identity.Generation
			}
		}
		return status
	}()
	self.fillHeadCheckStatus(&status)
	status.ZoneWatchDegraded = self.dns.zoneWatchDegraded()
	return status
}

// Calls callback with each event from here on, until the answer is called (§5.4). See SidecarEventFunction for what
// a callback may do.
func (self *Sidecar) AddEventCallback(callback SidecarEventFunction) func() {
	callbackId := self.eventCallbacks.Add(callback)
	var once sync.Once
	return func() {
		once.Do(func() {
			self.eventCallbacks.Remove(callbackId)
		})
	}
}

// Stops the Sidecar without waiting: the run loop ends its generation and closes each component on its own
// goroutine. Safe to call from a callback and to call again. The instance is the host's, and stays open.
func (self *Sidecar) Close() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
	}()
	if self.cancel != nil {
		self.cancel()
	}
}

// Close, then waits until the generation has ended and every component has closed, or ctx ends. Never call it from
// an event callback or a component's call, which it would wait for (connect/CODESTYLE.md:171).
func (self *Sidecar) CloseAndWait(ctx context.Context) error {
	self.Close()
	if self.done == nil {
		return nil
	}
	select {
	case <-self.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Whether Close has been called.
func (self *Sidecar) isClosed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}
