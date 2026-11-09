// Status's HeadCheck half (CORE-M2-03, §5.4's SidecarStatus, §6.4): witnessed_at, the newest consistent witness, and
// the open UNVERIFIED auth pins, as AuthPin bytes, which `ur status` and §18.5's GetState show. They come from the
// network's §6.4 state, HeadStopState, which the transport builds (PROTO-M2-03) and installs here; with none
// installed, Status shows no witness and no pin.
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"sync"
	"time"
)

// What Status reads of §6.4's state. HeadStopState implements it. Safe for concurrent use.
type SidecarHeadCheckStatus interface {
	// The newest consistent witness. Zero: none yet.
	WitnessedAt() time.Time
	// The open UNVERIFIED auth pins, as AuthPin bytes. Empty: none.
	Unverified() [][]byte
}

// The installed §6.4 state, under its own lock.
type sidecarHeadCheckStatuses struct {
	stateLock sync.Mutex
	status    SidecarHeadCheckStatus
}

// Installs status as the network's §6.4 state that Status reads; the answer removes it, if it is still installed.
func (self *Sidecar) InstallHeadCheckStatus(status SidecarHeadCheckStatus) func() {
	self.headCheckStatuses.stateLock.Lock()
	self.headCheckStatuses.status = status
	self.headCheckStatuses.stateLock.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			self.headCheckStatuses.stateLock.Lock()
			defer self.headCheckStatuses.stateLock.Unlock()
			if self.headCheckStatuses.status == status {
				self.headCheckStatuses.status = nil
			}
		})
	}
}

// Fills status's witnessed_at and UNVERIFIED pins from the installed §6.4 state, copies sharing nothing.
func (self *Sidecar) fillHeadCheckStatus(status *SidecarStatus) {
	self.headCheckStatuses.stateLock.Lock()
	headCheck := self.headCheckStatuses.status
	self.headCheckStatuses.stateLock.Unlock()
	if headCheck == nil {
		return
	}
	status.WitnessedAt = headCheck.WitnessedAt()
	for _, pin := range headCheck.Unverified() {
		status.Unverified = append(status.Unverified, bytes.Clone(pin))
	}
}
