// §6.4's witness, stops and alarms rows as they read witnessed_at (D-TRUST-10): the refresh at the end of
// an exchange that counts, the bound the stop reads, and the 24 h alarm. A device never witnessed runs
// its clock from this state's first start, so a new device gets the bound's grace before its first
// HeadCheck, and not a stop at once.
//
// HeadStopState's methods, with its rules (rpc_headcheck_stop.go). No connect type appears here.

package sidecar

import (
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The stop's bound: ServiceSettings.witness_bound_hours as this device's newest state holds it, 72 h
// when the config leaves it unset. A value outside 24 to 168 h is refused, and so is a config head this
// device could not read: either way the stop reads the least the config may set, 24 h, the side that
// bounds exposure.
func (self *HeadStopState) witnessBound() time.Duration {
	hours, known := self.env.WitnessBoundHours()
	switch {
	case !known:
		return WitnessBoundMinHours * time.Hour
	case hours == 0:
		return WitnessBoundDefaultHours * time.Hour
	case hours < WitnessBoundMinHours || WitnessBoundMaxHours < hours:
		if self.env.Log.V(1).Enabled() {
			self.env.Log.Infof("[headcheck] witness_bound_hours %d refused, outside %d to %d", hours, WitnessBoundMinHours, WitnessBoundMaxHours)
		}
		return WitnessBoundMinHours * time.Hour
	}
	return time.Duration(hours) * time.Hour
}

// The newest consistent witness (§6.4), what Status shows as witnessed_at. Zero: none yet.
func (self *HeadStopState) WitnessedAt() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.witnessedAt
}

// The auth pin the newest consistent witness compared, the state witnessed_at names; nil while none has
// been. A copy.
func (self *HeadStopState) WitnessedPin() *bridge.AuthPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return headCheckPinCopy(self.witnessPin)
}

// The withheld tip this device holds proof of withholding for, which its HeadCheck sends as proven and
// which stops sealing in shared groups until api serves it (§6.4's proven row); nil while it holds none.
// A copy.
func (self *HeadStopState) Withheld() *bridge.AuthPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state.withheld == nil {
		return nil
	}
	return headCheckPinCopy(self.state.withheld.pin)
}

// The UNVERIFIED auth pins held, as AuthPin bytes, highest first, what Status shows (§6.4's alarms row).
// Empty: none.
func (self *HeadStopState) Unverified() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state.unverifiedPins()
}

// Where the unwitnessed clock runs from: the last consistent witness, or on a device never witnessed,
// this state's first start.
func (self *HeadStopState) lastWitnessWithLock() time.Time {
	if !self.witnessedAt.IsZero() {
		return self.witnessedAt
	}
	return self.unwitnessedSince
}

// Ends one exchange with peerId, once its acts have run: refreshes witnessed_at when witnessDecision
// counts it, but only for this device's pin as it stands now, since a witness never refreshes a pin it
// did not reconcile; and lets the revoker see the pin the peer holds. message is what the peer sent and
// forked whether any of the exchange's steps found a fork. Answers the witness, nil for none.
func (self *HeadStopState) witness(peerId Id, message headCheckMessage, forked bool) *headCheckWitness {
	self.stepLock.Lock()
	defer self.stepLock.Unlock()
	mine := self.mine()
	state := func() headCheckState {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.state
	}()
	witness := headCheckWitnessFor(state, mine, peerId, message, forked)
	auth := mine.sources.Auth
	myPin := auth.Pin()
	peerPin := message.GetAuth()
	// the revoker counts a peer that holds a pin on this device's chain, standing as a witness would
	var heldPin *bridge.AuthPin
	peer := mine.sources.Peers.HeadCheckPeer(peerId)
	if headCheckPinValid(myPin) && headCheckPinValid(peerPin) && headCheckStanding(peer) && !peer.Suspended {
		switch headCheckRelate(auth, myPin, peerPin) {
		case headCheckRelationSame, headCheckRelationOnChain:
			heldPin = peerPin
		}
	}

	testHookBarrier("rpc.witness_refresh", peerId.String())
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		changed := false
		if witness != nil && headCheckPinEqual(witness.pin, myPin) {
			self.witnessedAt = witness.at
			self.witnessPin = headCheckPinCopy(witness.pin)
			self.unwitnessedAlarmed = false
			changed = true
		}
		if heldPin != nil && self.clearRevocationsWithLock(heldPin) {
			changed = true
		}
		if changed {
			self.version += 1
		}
		return changed
	}()
	if changed {
		self.afterChange(nil)
	}
	if witness != nil && !headCheckPinEqual(witness.pin, myPin) {
		return nil
	}
	return witness
}

// The run loop's part for witnessed_at: the 24 h alarm, once per lapse, re-armed by the next witness.
// Answers its alarm, if due, and its next deadline, zero for none.
func (self *HeadStopState) witnessTickWithLock(now time.Time, myPinBytes []byte) ([]SidecarEvent, time.Time) {
	if self.unwitnessedAlarmed {
		return nil, time.Time{}
	}
	alarmAt := self.lastWitnessWithLock().Add(HeadCheckUnwitnessedAlarmTimeout)
	if now.Before(alarmAt) {
		return nil, alarmAt
	}
	self.unwitnessedAlarmed = true
	var witnessPinBytes []byte
	if self.witnessPin != nil {
		witnessPinBytes = headCheckEvidence(self.witnessPin)
	}
	return []SidecarEvent{headStopAlarm(SidecarHeadAlarmUnwitnessed, nil, myPinBytes, witnessPinBytes)}, time.Time{}
}
