//go:build !ios_extension && !sidecar_http && !js

// compute_low (DESIGN-COMPUTE §9.9, CF-12; BAL-M12-17): the SidecarEvent each member device raises with the network's
// new compute state at each change of it the device sees, declared here rather than in sidecar_types.go, which BAL
// edits no line of. The state is §9.9's, as the balance route answers it, and the device learns it three ways:
//
//	push      a hint on the compute topic, the clock topic compute-plan-compute-low-delivery settles (QD-1238), which
//	          the server's compute_suspend raises at each change through Push.HintSidecars; a hint carries no state,
//	          so the device reads the balance route on it, as on the topic's resync
//	poll      a read of the balance route every ComputeClientSettings.BalancePollInterval while no client generation
//	          holds the topic
//	refusal   a read after every hold the broker refused (ComputeClient.HoldRefused), and every read a surface makes
//
// Each read that shows a state other than the one last raised raises compute_low once, with the new state in
// SidecarEvent.Outcome, which every surface already carries (the daemon's event ring, the sdk's listeners); the
// enclaves a suspension would stop and the days the network's indexer enclave has left travel in the client's notice
// (ComputeLowNotice, ComputeClient.AddLowListener and LowNotice), from §9.9's low on, since SidecarEvent holds no field
// for them and sidecar_types.go is not BAL's to edit. Reads are ordered by the account's version, so an older answer
// that lands after a newer one changes nothing, and two reads racing raise at most once for one change; their
// notices may reach listeners in the opposite of their order, as any two SidecarEvents may, and LowNotice is always
// the newest.
//
// The first state a client sees raises only when it is not active: a device that starts while its network is low
// says so, and one that starts while all is well says nothing. A device restarted mid-state raises that state again,
// once, since nothing of it is kept on disk.
//
// Safe for concurrent use.

package sidecar

import (
	"slices"
	"sync"
	"time"
)

// §9.9's notice to every member device: the network's compute state changed.
const SidecarEventComputeLow SidecarEventKind = "compute_low"

// §9.9's states of a network's compute account, as the balance route answers them and compute_low carries them.
type ComputeAccountState string

const (
	// The balance holds at least 24 hours of the network's burn.
	ComputeAccountStateActive ComputeAccountState = "active"
	// Under 24 hours of burn, or under the threshold T: a warning, and the threshold top-up's trigger (§9.8).
	ComputeAccountStateLow ComputeAccountState = "low"
	// The balance at or under zero: new remote inference and searches are refused, running enclaves run down to the
	// floor.
	ComputeAccountStateGrace ComputeAccountState = "grace"
	// At or under minus the floor, or grace past its hour: remote inference refused and enclaves stopped (§11.6).
	ComputeAccountStateSuspended ComputeAccountState = "suspended"
	// The network was deleted.
	ComputeAccountStateClosed ComputeAccountState = "closed"
)

// Every state, in §9.9's order.
var computeAccountStates = []ComputeAccountState{
	ComputeAccountStateActive,
	ComputeAccountStateLow,
	ComputeAccountStateGrace,
	ComputeAccountStateSuspended,
	ComputeAccountStateClosed,
}

// Whether the state is one of §9.9's.
func (self ComputeAccountState) Valid() bool {
	return slices.Contains(computeAccountStates, self)
}

// Whether the network can pay for a new remote call or search in this state: active or low (§9.9). What §7.5's
// compute_balance says of the network, never its balance.
func (self ComputeAccountState) CanPay() bool {
	return self == ComputeAccountStateActive || self == ComputeAccountStateLow
}

// What one compute_low says, in full: the state the network moved to, the one the device had seen before it, and
// from §9.9's low on the enclaves a suspension would stop and the days the network's indexer enclave's reserve and
// grace leave before its mail waits on senders' retries.
type ComputeLowNotice struct {
	State ComputeAccountState `json:"state"`
	// Empty where this device saw no state before.
	Previous ComputeAccountState `json:"previous,omitempty"`
	// The account's version the notice was read at, which orders notices.
	Version uint64 `json:"version"`
	// The enclaves a suspension would stop, by id; the device names them by their admissions (§11.4).
	EnclaveIds []Id `json:"enclave_ids,omitempty"`
	// Whole days the network's indexer enclave has left on its reserve and grace; nil where it has none.
	IndexerDaysLeft *int64 `json:"indexer_days_left,omitempty"`
	// When the device saw it.
	Time time.Time `json:"time"`
}

// A copy sharing nothing.
func (self *ComputeLowNotice) clone() *ComputeLowNotice {
	clone := *self
	clone.EnclaveIds = slices.Clone(self.EnclaveIds)
	if self.IndexerDaysLeft != nil {
		days := *self.IndexerDaysLeft
		clone.IndexerDaysLeft = &days
	}
	return &clone
}

// Called with each notice, on the goroutine that read the balance. It must not block. Two reads racing may deliver
// their notices in the opposite of their order, as SidecarEvent's callbacks may see events (sidecar_types.go): a
// listener that needs the newest reads ComputeClient.LowNotice, which version order keeps.
type ComputeLowListener func(notice *ComputeLowNotice)

// The newest state a client applied, and what raises compute_low from a read. Safe for concurrent use.
type computeLowTracker struct {
	stateLock sync.Mutex
	// Whether any read applied yet.
	known   bool
	state   ComputeAccountState
	version uint64
	notice  *ComputeLowNotice
}

// The notice a read of balance at now raises, or nil: a read older than the newest applied, one at the same state, or
// a first read that shows active raises nothing. A read at a version not below the newest always becomes the newest, so
// a later read compares with it, and one at the state already raised refreshes what that notice names, keeping when it
// was raised. The caller raises what this answers, outside every lock.
func (self *computeLowTracker) apply(balance *ComputeBalance, now time.Time) *ComputeLowNotice {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.known && balance.Version < self.version {
		return nil
	}
	previous := self.state
	known := self.known
	self.known = true
	self.state = balance.State
	self.version = balance.Version
	if known && previous == balance.State {
		if self.notice != nil && self.notice.State == balance.State {
			self.notice = computeLowNoticeOf(balance, self.notice.Previous, self.notice.Time)
		}
		return nil
	}
	if !known && balance.State == ComputeAccountStateActive {
		return nil
	}
	self.notice = computeLowNoticeOf(balance, previous, now)
	return self.notice.clone()
}

// The newest notice raised, refreshed by every later read at its state, or nil before any.
func (self *computeLowTracker) latest() *ComputeLowNotice {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.notice == nil {
		return nil
	}
	return self.notice.clone()
}

// A notice of balance's state after previous, seen at seen; the enclaves and the indexer's days only from low on, as
// §9.9 names them.
func computeLowNoticeOf(balance *ComputeBalance, previous ComputeAccountState, seen time.Time) *ComputeLowNotice {
	notice := &ComputeLowNotice{
		State:    balance.State,
		Previous: previous,
		Version:  balance.Version,
		Time:     seen,
	}
	if balance.State != ComputeAccountStateActive {
		notice.EnclaveIds = slices.Clone(balance.AtRiskEnclaveIds)
		if balance.IndexerDaysLeft != nil {
			days := *balance.IndexerDaysLeft
			notice.IndexerDaysLeft = &days
		}
	}
	return notice
}

// The SidecarEvent a notice raises: compute_low, the new state in Outcome.
func computeLowEvent(notice *ComputeLowNotice) SidecarEvent {
	return SidecarEvent{Kind: SidecarEventComputeLow, Outcome: string(notice.State)}
}
