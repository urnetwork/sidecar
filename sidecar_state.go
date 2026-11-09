// §5.4's state machine and §18.5's State block, as a pure function: which moves are legal, and what
// each does to the state, its reason and the client generation. Nothing else writes a Sidecar's
// state, and emitEvent is the one way a root file raises an event. Neither names a connect type, so
// both build on every leg.
//
// Locked → Unenrolled ⇄ Offline ⇄ Online, a locked store → Locked (§5.9), and only a verified
// SidecarRevoke → Revoked (D-CORE-8). A move is between neighbors, so a client refused while Online
// reports Offline, as its connection drops, and then Unenrolled, as its refresh is refused.

package sidecar

// §18.5's GetState, as its strings.
type SidecarState string

const (
	// No key is open, so this sidecar reads and signs nothing (§5.9).
	SidecarStateLocked SidecarState = "locked"
	// The keychain is open and no client holds a working credential. Identity and admission stand
	// (D-CORE-8).
	SidecarStateUnenrolled SidecarState = "unenrolled"
	// A client generation exists and is not connected.
	SidecarStateOffline SidecarState = "offline"
	// That client is connected.
	SidecarStateOnline SidecarState = "online"
	// A SidecarRevoke verified against the config. Nothing leaves this state: a device enrolls
	// anew as a new sidecar_id (§5.5).
	SidecarStateRevoked SidecarState = "revoked"
)

// §18.5's GetStateReason, as its strings. Empty on every state but these.
type SidecarStateReason string

const (
	// Unenrolled: strict_exp passed unrefreshed.
	SidecarReasonExpired SidecarStateReason = "expired"
	// Unenrolled: a confirmed 401, or a revocation claim that did not verify (D-SDK-14).
	SidecarReasonRefused SidecarStateReason = "refused"
	// Unenrolled: the parent client was removed or reaped (§5.8).
	SidecarReasonParentLost SidecarStateReason = "parent_lost"
	// Unenrolled: a confirmed 401 whose cause is session_revoked (D-SDK-14).
	SidecarReasonSessionEnded SidecarStateReason = "session_ended"
	// Unenrolled: the key store's item or keychain.wrap is lost, and only the pass, a recovery code
	// or the person's confirmation goes on from here (D-CORE-15).
	SidecarReasonKeystoreLost SidecarStateReason = "keystore_lost"
	// Revoked: a SidecarRevoke verified.
	SidecarReasonSigned SidecarStateReason = "signed"
)

// Where a Sidecar stands in the machine. Comparable, and what Status reads.
type sidecarLifecycle struct {
	state      SidecarState
	reason     SidecarStateReason
	generation int64
}

// One input to the machine.
type sidecarTransition struct {
	to     SidecarState
	reason SidecarStateReason
	// The client generation this comes from. A lock or an unlock, which no client raised, names the
	// current one.
	generation int64
	// Set only by the code that verified a SidecarRevoke against the config (CORE-M2-07), and read
	// only for a move to Revoked, which it alone allows.
	verifiedRevocation bool
}

// What the machine did with an input.
type sidecarTransitionResult int

const (
	// The move is not in the machine: the lifecycle stands, and nothing may act as if it happened.
	sidecarTransitionRefused sidecarTransitionResult = iota
	// A stale input from an older client generation, ignored as D-SDK-14 says. Not an error: it
	// reports on a client that is gone.
	sidecarTransitionDropped
	// Already there.
	sidecarTransitionUnchanged
	// The lifecycle moved.
	sidecarTransitionApplied
)

// The machine. An older generation's input is dropped before anything else is read, so a stale
// callback cannot end a new pairing, whatever it claims. Revoked is left only by staying.
//
// A newer generation only ever begins at Offline: a re-enrollment or a pairing binds generation n+1
// and goes offline (§18.5), from wherever the old client was short of Locked. Anything else naming a
// generation this sidecar has not bound is refused.
func nextSidecarLifecycle(current sidecarLifecycle, transition sidecarTransition) (sidecarLifecycle, sidecarTransitionResult) {
	if transition.generation < current.generation {
		return current, sidecarTransitionDropped
	}
	reasonFits := func() bool {
		switch transition.to {
		case SidecarStateUnenrolled:
			switch transition.reason {
			case "", SidecarReasonExpired, SidecarReasonRefused, SidecarReasonParentLost,
				SidecarReasonSessionEnded, SidecarReasonKeystoreLost:
				return true
			}
			return false
		case SidecarStateRevoked:
			return transition.reason == SidecarReasonSigned
		case SidecarStateLocked, SidecarStateOffline, SidecarStateOnline:
			return transition.reason == ""
		}
		return false
	}
	if !reasonFits() {
		return current, sidecarTransitionRefused
	}
	next := sidecarLifecycle{
		state:      transition.to,
		reason:     transition.reason,
		generation: transition.generation,
	}
	if next == current {
		return current, sidecarTransitionUnchanged
	}
	if transition.generation != current.generation && transition.to != SidecarStateOffline {
		return current, sidecarTransitionRefused
	}
	edgeFits := func() bool {
		switch current.state {
		case SidecarStateLocked:
			return transition.to == SidecarStateUnenrolled
		case SidecarStateUnenrolled:
			switch transition.to {
			case SidecarStateLocked, SidecarStateOffline, SidecarStateRevoked:
				return true
			case SidecarStateUnenrolled:
				// a later cause replaces the reason
				return true
			}
		case SidecarStateOffline:
			switch transition.to {
			case SidecarStateLocked, SidecarStateUnenrolled, SidecarStateOnline, SidecarStateRevoked:
				return true
			case SidecarStateOffline:
				// a new client while the old one was offline: next != current, so its generation rose
				return true
			}
		case SidecarStateOnline:
			switch transition.to {
			case SidecarStateLocked, SidecarStateOffline, SidecarStateRevoked:
				return true
			}
		}
		return false
	}
	if !edgeFits() {
		return current, sidecarTransitionRefused
	}
	if transition.to == SidecarStateRevoked && !transition.verifiedRevocation {
		return current, sidecarTransitionRefused
	}
	return next, sidecarTransitionApplied
}

// A Sidecar with its machine at Locked and nothing bound, which NewSidecar builds on. settings must
// have passed validate.
func newSidecarBase(host SidecarHost, settings *SidecarSettings) *Sidecar {
	return &Sidecar{
		host:           host,
		settings:       settings,
		log:            loggerOrDefault(settings.Log),
		state:          NewMonitorValue(SidecarStateLocked),
		eventCallbacks: NewCallbackList[SidecarEventFunction](),
		wakes:          NewMonitorValue[uint64](0),
		clock:          settings.ClockOrReal(),
		lifecycle:      sidecarLifecycle{state: SidecarStateLocked},
	}
}

// Runs one input through the machine and, if it moved, raises the state event, outside stateLock.
// Reports whether it moved. A refused move is logged and changes nothing.
func (self *Sidecar) applyTransition(transition sidecarTransition) bool {
	var current sidecarLifecycle
	var next sidecarLifecycle
	var result sidecarTransitionResult
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		current = self.lifecycle
		next, result = nextSidecarLifecycle(current, transition)
		self.lifecycle = next
		self.state.Set(next.state)
	}()
	switch result {
	case sidecarTransitionRefused:
		self.log.Infof("[sidecar]refused a move from %s to %s", current.state, transition.to)
		return false
	case sidecarTransitionApplied:
		self.emitEvent(SidecarEvent{
			Kind:       SidecarEventState,
			Generation: next.generation,
			State:      next.state,
			Reason:     next.reason,
		})
		return true
	}
	return false
}

// The one entry other root files use to raise §5.4's kinds. An event of an older client generation
// is dropped (D-SDK-14), and one naming no generation, which no client raised, is stamped with the
// current one.
//
// Events reach the callbacks in the order they were raised, so no subscriber sees an older generation's
// event after a newer one's. One raised while another is being delivered, on any goroutine or from
// inside a callback, joins a queue that the delivering goroutine runs next, and this returns at once;
// otherwise this goroutine delivers it, and anything raised meanwhile. A callback runs with no lock
// held, and an event that a newer generation overtook while it waited is dropped at each subscriber it
// had not reached.
func (self *Sidecar) emitEvent(event SidecarEvent) {
	queued := false
	deliver := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if event.Generation == 0 {
			event.Generation = self.lifecycle.generation
		}
		if event.Generation < self.lifecycle.generation {
			return
		}
		queued = true
		self.eventQueue = append(self.eventQueue, event)
		if !self.eventDelivering {
			self.eventDelivering = true
			deliver = true
		}
	}()
	if !queued {
		self.logDroppedEvent(event)
		return
	}
	if deliver {
		self.deliverEvents()
	}
}

// Delivers the queue until it is empty. A callback that panics leaves the rest to the next event raised.
func (self *Sidecar) deliverEvents() {
	delivering := true
	defer func() {
		if delivering {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.eventDelivering = false
		}
	}()
	for {
		var event SidecarEvent
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if len(self.eventQueue) == 0 {
				self.eventQueue = nil
				self.eventDelivering = false
				delivering = false
				return
			}
			event = self.eventQueue[0]
			self.eventQueue = self.eventQueue[1:]
		}()
		if !delivering {
			return
		}
		if self.log.V(2).Enabled() {
			self.log.Infof("[sidecar]event %s generation %d", event.Kind, event.Generation)
		}
		for _, callback := range self.eventCallbacks.Get() {
			overtaken := func() bool {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				return event.Generation < self.lifecycle.generation
			}()
			if overtaken {
				self.logDroppedEvent(event)
				break
			}
			callback(event)
		}
	}
}

// Notes an event of an older generation, which goes nowhere.
func (self *Sidecar) logDroppedEvent(event SidecarEvent) {
	if self.log.V(2).Enabled() {
		self.log.Infof("[sidecar]dropped a %s event of generation %d", event.Kind, event.Generation)
	}
}
