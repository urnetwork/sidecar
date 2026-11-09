// §6.4's revoker row and §7.10's confirm row: a revocation this device signed shows unwitnessed until a
// HeadCheck peer holds an auth pin at or past its position. Until then the revoker asks the transport
// for a round at once, each HeadCheckUnwitnessedInterval and at each start, and alarms once after
// HeadCheckRevocationAlarmTimeout, so a server that hides the revocation from every other device is
// seen. CORE-M2-05's RevokeDevice calls TrackRevocation once its revocation lands.
//
// HeadStopState's methods, with its rules (rpc_headcheck_stop.go). No connect type appears here.

package sidecar

import (
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One revocation this device signed that no peer has been seen to hold.
type headStopRevocation struct {
	// The position of the entry that carries it.
	position uint64
	since    time.Time
	// When the revoker next asks for a round.
	nextRound time.Time
	alarmed   bool
}

// Shows the revocation at position unwitnessed until a HeadCheck peer holds an auth pin at or past it,
// asking for a round now and on the revoker's schedule. Tracking a position already tracked changes
// nothing.
func (self *HeadStopState) TrackRevocation(position uint64) {
	now := self.env.Clock.Now()
	added := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, revocation := range self.revocations {
			if revocation.position == position {
				return false
			}
		}
		self.revocations = append(self.revocations, &headStopRevocation{
			position:  position,
			since:     now,
			nextRound: now.Add(self.env.Settings.HeadCheckUnwitnessedInterval),
		})
		self.version += 1
		return true
	}()
	if added {
		self.afterChange(nil)
		self.env.RequestRound()
	}
}

// The positions of the revocations this device signed that no peer has been seen to hold, lowest
// first, what Status shows. Empty: none.
func (self *HeadStopState) UnwitnessedRevocations() []uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	positions := []uint64{}
	for _, revocation := range self.revocations {
		positions = append(positions, revocation.position)
	}
	slices.Sort(positions)
	return positions
}

// Drops every revocation a peer holding pin holds: those at or before pin's position.
func (self *HeadStopState) clearRevocationsWithLock(pin *bridge.AuthPin) bool {
	count := len(self.revocations)
	self.revocations = slices.DeleteFunc(self.revocations, func(revocation *headStopRevocation) bool {
		return revocation.position <= pin.GetVersion()
	})
	return len(self.revocations) != count
}

// The run loop's part for the revoker: whether a round is due, which moves each due revocation's next
// round on by HeadCheckUnwitnessedInterval, and each revocation's alarm once
// HeadCheckRevocationAlarmTimeout has passed, with the revocation's position and this device's pin as
// evidence. A non-positive interval asks for no further rounds. Answers the alarms, the next deadline,
// zero for none, and whether to ask for a round.
func (self *HeadStopState) revokerTickWithLock(now time.Time, myPinBytes []byte) ([]SidecarEvent, time.Time, bool) {
	interval := self.env.Settings.HeadCheckUnwitnessedInterval
	alarms := []SidecarEvent{}
	next := time.Time{}
	requestRound := false
	for _, revocation := range self.revocations {
		if 0 < interval {
			if !now.Before(revocation.nextRound) {
				requestRound = true
				revocation.nextRound = now.Add(interval)
			}
			next = headStopEarliest(next, revocation.nextRound)
		}
		if revocation.alarmed {
			continue
		}
		alarmAt := revocation.since.Add(HeadCheckRevocationAlarmTimeout)
		if now.Before(alarmAt) {
			next = headStopEarliest(next, alarmAt)
			continue
		}
		revocation.alarmed = true
		position := headCheckEvidence(&bridge.AuthPin{Version: revocation.position})
		alarms = append(alarms, headStopAlarm(SidecarHeadAlarmUnwitnessed, nil, position, myPinBytes))
	}
	return alarms, next, requestRound
}
