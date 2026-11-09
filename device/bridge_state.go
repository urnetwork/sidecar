// From posture to enforcement (§17.8's engine, D-BRIDGE-18, D-BRIDGE-21): SetPending, SetState and ApplyDeltas go
// through the posture, which owns the machine, the store and offline verification (SDK-M4-01), and each decision it
// returns becomes the provider hook's next state, built off the packet path and published, then the flows the new state
// no longer keeps end. Revoke is that same path for the sidecar role's own revocations (AclSuspendEffects), so its
// immediate reset and a later state agree, and run's timer is that path for expiries and drains.
//
// D-BRIDGE-21's order on every path: compute the next state, publish it (generation g+1), then CloseFlows on each tag
// that state no longer keeps (bridge_disposition.go), on every NAT the hook is installed on, outside every lock, with
// testHookBarrier between the swap and the closes. A flow that resolved at g and dials across the swap is caught by
// connect's recheck, which reads g+1 before its first byte.
//
// Pending, with no rules, publishes a state that denies every Network flow; enforcing{nodoc} comes only from a state the
// posture verified, never from an unsigned value; and what the posture refuses leaves what is published as it was.
// Between states a delta names only ids, so the overlay's SidecarRevoke, MemberRevoke, Suspend, GrantRevoke and
// BridgeWithdraw narrow the rows by the sidecar, member, grant and rule ids they hold, a covered one included, until
// the next state confirms or reverses it.
//
// The state path's argument: the posture takes a state's log beside it (question sdk-m4-01-state-proof), so SetState
// and ApplyDeltas carry a PostureLog where §18.6's deviceBridge writes the state and the deltas alone.

package device

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A revocation Revoke does not take.
var ErrBridgeRevocationRefused = errors.New("bridge revocation refused")

// The overlay kind a revocation's statement type narrows by.
var bridgeRevocationKinds = map[bridge.SignedType]PostureOverlayKind{
	bridge.SignedType_SIGNED_SIDECAR_REVOKE:  PostureOverlaySidecarRevoke,
	bridge.SignedType_SIGNED_MEMBER_REVOKE:   PostureOverlayMemberRevoke,
	bridge.SignedType_SIGNED_SUSPEND:         PostureOverlaySuspend,
	bridge.SignedType_SIGNED_GRANT_REVOKE:    PostureOverlayGrantRevoke,
	bridge.SignedType_SIGNED_BRIDGE_WITHDRAW: PostureOverlayBridgeWithdraw,
}

// The longest id a revocation names: a grant's or a rule's 32 bytes, with room for an atom's.
const bridgeRevocationIdMaxByteCount = 64

// The hook a host or an sdk provider installs on its provider NATs: the bridge's policy, with a binder that keeps each
// NAT's closer, so a revocation ends flows on every NAT the hook is on, overlapping client generations included.
type bridgeEgressHook struct {
	*BridgeEgressPolicy
	bridge *Bridge
}

var (
	_ connect.EgressHook       = (*bridgeEgressHook)(nil)
	_ connect.EgressHookBinder = (*bridgeEgressHook)(nil)
)

// connect.EgressHookBinder: keeps the NAT's closer until the hook leaves it.
func (self *bridgeEgressHook) BindFlowCloser(closer connect.EgressFlowCloser) (unbind func()) {
	closerId := self.bridge.closers.Add(closer)
	return func() {
		self.bridge.closers.Remove(closerId)
	}
}

// §18.6's EgressHook (C5, §17.6): the provider hook to install with LocalUserNat.SetEgressHook, the same value on every
// call, so installing it again keeps the flows it decided.
func (self *Bridge) EgressHook() connect.EgressHook {
	return self.hook
}

// Calls callback, on the goroutine that published, after each publish of what the bridge enforces, once its flows
// have ended; the returned function removes it. A callback must not block, and runs under no lock of the bridge's.
func (self *Bridge) AddChangeCallback(callback func()) func() {
	callbackId := self.changeCallbacks.Add(callback)
	return func() {
		self.changeCallbacks.Remove(callbackId)
	}
}

// legacy -> pending, once the sidecar role has a sidecar_id (§18.6). See Posture.SetPending.
func (self *Bridge) SetPending(pending *bridge.Pending) error {
	return self.apply(func() (PostureDecision, bool, error) {
		decision, err := self.posture.SetPending(pending)
		return decision, false, err
	})
}

// The sidecar role's compiled view, with the log that vouches for it (§17.8). See Posture.SetState. A state the
// posture refuses, a forged has_document among them, publishes nothing.
func (self *Bridge) SetState(state *bridge.BridgeState, log *PostureLog) error {
	return self.apply(func() (PostureDecision, bool, error) {
		decision, err := self.posture.SetState(state, log)
		return decision, false, err
	})
}

// Verified projection deltas between states (§8.9). See Posture.ApplyDeltas.
func (self *Bridge) ApplyDeltas(log *PostureLog) error {
	return self.apply(func() (PostureDecision, bool, error) {
		decision, err := self.posture.ApplyDeltas(log)
		return decision, false, err
	})
}

// AclSuspendEffects' path (§8.6): narrows what is in force at once, by a revocation the sidecar role verified and is
// applying, then publishes and ends the flows it closes, as a verified entry between states does. statementType names
// what id is: a sidecar_id for SIGNED_SIDECAR_REVOKE, a member_id for SIGNED_MEMBER_REVOKE, a subject for
// SIGNED_SUSPEND, a grant_id for SIGNED_GRANT_REVOKE and a rule_id, reset, for SIGNED_BRIDGE_WITHDRAW. n is the
// revocation's log position: it holds until a state at or past n confirms or reverses it, and 0 holds it until the next
// state past the one in force. It only narrows, so it needs no signature here, and it never widens what a state allows.
func (self *Bridge) Revoke(statementType bridge.SignedType, id []byte, n uint64) error {
	kind, ok := bridgeRevocationKinds[statementType]
	if !ok {
		return fmt.Errorf("%w: type %#x revokes nothing here", ErrBridgeRevocationRefused, int32(statementType))
	}
	if len(id) == 0 || bridgeRevocationIdMaxByteCount < len(id) {
		return fmt.Errorf("%w: an id of %d bytes", ErrBridgeRevocationRefused, len(id))
	}
	return self.apply(func() (PostureDecision, bool, error) {
		decision := self.posture.Decision()
		if n == 0 {
			n = bridgeDecisionPinN(decision) + 1
		}
		entry := PostureOverlayEntry{Kind: kind, N: n, Id: bytes.Clone(id)}
		if kind == PostureOverlayBridgeWithdraw {
			entry.WithdrawMode = bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET
		}
		if slices.ContainsFunc(self.revocations, func(held PostureOverlayEntry) bool {
			return postureOverlayEntryEqual(held, entry)
		}) {
			return decision, false, nil
		}
		if self.settings.RevocationMaxCount <= len(self.revocations) {
			return decision, false, fmt.Errorf("%w: past the %d held between states", ErrBridgeRevocationRefused, self.settings.RevocationMaxCount)
		}
		self.revocations = append(self.revocations, entry)
		return decision, true, nil
	})
}

// Publishes again at the clock's now, so what lapsed since ends: run's timer.
func (self *Bridge) refresh() {
	self.apply(func() (PostureDecision, bool, error) {
		return self.posture.Decision(), true, nil
	})
}

// The state's pin, 0 before one.
func bridgeDecisionPinN(decision PostureDecision) uint64 {
	if decision.BridgeState == nil {
		return 0
	}
	return decision.BridgeState.GetAuth().GetVersion()
}

// Runs call, which returns the posture's decision, whether to publish even if it is unchanged, and call's error, then
// adopts the decision, and outside every lock ends the flows the new state no longer keeps and tells the change
// callbacks. Returns call's error.
func (self *Bridge) apply(call func() (PostureDecision, bool, error)) error {
	var callErr error
	var closeTags []uint64
	published := false
	func() {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		decision, force, err := call()
		callErr = err
		closeTags, published = self.adoptWithLock(decision, force)
	}()
	if 0 < len(closeTags) {
		testHookBarrier("bridge_state.close.before", "")
		closers := self.closers.Get()
		for _, closer := range closers {
			for _, tag := range closeTags {
				closer.CloseFlows(tag)
			}
		}
		testHookBarrier("bridge_state.close.after", "")
	}
	if published {
		for _, callback := range self.changeCallbacks.Get() {
			connect.HandleError(callback)
		}
	}
	return callErr
}

// Takes what the posture decided: its state's rules parsed once, Revoke's narrowing that the state has not passed,
// and, when anything the hook reads changed or force says the clock moved, the hook's next state published and the
// tags it no longer keeps returned. Sets the counts and the next deadline either way. Returns the tags and whether it
// published.
func (self *Bridge) adoptWithLock(decision PostureDecision, force bool) ([]uint64, bool) {
	previous, previousRules, previousAlarms := func() (PostureDecision, *bridge.BridgeRules, []BridgeAlarm) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.decision, self.rules, self.alarms
	}()
	var rules *bridge.BridgeRules
	alarms := []BridgeAlarm{}
	if decision.State.Enforcing() && decision.BridgeState != nil {
		if decision.BridgeState == previous.BridgeState && previous.State.Enforcing() {
			rules, alarms = previousRules, previousAlarms
		} else {
			parsed, err := ParseBridgeRules(decision.BridgeState.GetRules(), self.settings)
			if err != nil {
				alarms = append(alarms, BridgeAlarm{Kind: BridgeAlarmRulesRefused, Reason: err.Error()})
			} else {
				rules = parsed
			}
		}
	}
	// a state at or past a revocation confirms or reverses it, and a wipe to legacy ends them all
	statePinN := bridgeDecisionPinN(decision)
	revocationCount := len(self.revocations)
	self.revocations = slices.DeleteFunc(self.revocations, func(entry PostureOverlayEntry) bool {
		return decision.State == PostureLegacy || entry.N <= statePinN
	})
	changed := force || revocationCount != len(self.revocations) || decision.State != previous.State ||
		decision.BridgeState != previous.BridgeState ||
		!slices.EqualFunc(decision.Overlay, previous.Overlay, postureOverlayEntryEqual) ||
		!bytes.Equal(decision.NetworkId, previous.NetworkId) || !bytes.Equal(decision.SidecarId, previous.SidecarId)

	now := self.clock.Now()
	closeTags := []uint64{}
	if changed {
		previousState := self.policy.state.Load()
		self.policy.Publish(&BridgePolicyInput{
			State:       decision.State,
			BridgeState: decision.BridgeState,
			Rules:       rules,
			Overlay:     slices.Concat(decision.Overlay, self.revocations),
			NetworkId:   decision.NetworkId,
			SidecarId:   decision.SidecarId,
			// this device's addresses come with BRIDGE-M4-13's SetLocalAddresses; until then rule 0 reads every address
			LocalAddresses: nil,
		})
		closeTags = bridgeDispositionTags(previousState, self.publishedAt, self.policy.state.Load(), now, self.settings.PolicyProfile)
		self.publishedAt = now
	}
	times := scanBridgeRulesTimes(rules, now, self.settings)
	testHookBarrier("bridge.adopt.before", "")
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.decision = decision
		self.rules = rules
		self.alarms = alarms
		self.drainingCount = times.drainingCount
		self.expiredCount = times.expiredCount
	}()
	testHookBarrier("bridge.adopt.after", "")
	self.deadline.Set(times.next)
	return closeTags, changed
}
