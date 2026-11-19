//go:build !sidecar_http && !ios_extension

// SmtpStatusHold: the queue's hold on SmtpStatus hints (§14.8's mechanics, §14.14, plan-SMTP-wire-gaps#2;
// SMTP-M9-09). smtpedge's halt job hints each client that sent in the last 24 h on topic mail, PushHint.hint a
// SmtpStatus: HALTED or QUOTA holds the outbox until retry_after_ms, CLEAR releases it, and 0 is §6.11's protocol
// error, whose hint is dropped. A client that misses a hint gets HALTED at its next preamble, which holds that
// send alone.
//
// A hint names no label, since a client reads a halt's scope from GET /smtp/status, which is not read here: the
// hold covers the network's whole queue, so a label's halt holds more than it must, the closed direction, until the
// status read lands (a reading).
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10). Safe for concurrent use; Notice never blocks.

package sidecar

import (
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One network's hold.
type SmtpStatusHold struct {
	settings *SmtpSenderSettings
	clock    Clock

	stateLock sync.Mutex
	// the queue waits until this time; zero holds nothing
	holdUntil time.Time
	// hints dropped as §6.11's protocol errors
	droppedCount int
}

// A hold under settings, which must have passed validate, on clock (nil is real time).
func NewSmtpStatusHold(settings *SmtpSenderSettings, clock Clock) *SmtpStatusHold {
	return &SmtpStatusHold{settings: settings, clock: clockOrReal(clock)}
}

// Subscribes the hold to subprotocol's topic mail; the answer removes it.
func (self *SmtpStatusHold) Attach(subprotocol *Subprotocol) (remove func(), err error) {
	return subprotocol.Subscribe(PushTopicMail, self.Notice)
}

// One notice of topic mail: a SmtpStatus hint applies, any other kind of hint and a resync leave the hold as it is.
func (self *SmtpStatusHold) Notice(notice PushNotice) {
	if notice.Topic != PushTopicMail || notice.Kind != uint32(protocol.MessageType_SMTP_STATUS) {
		return
	}
	status := &protocol.SmtpStatus{}
	if err := proto.Unmarshal(notice.Hint, status); err != nil {
		self.drop()
		return
	}
	self.Apply(status)
}

// Applies one status: HALTED and QUOTA hold until now plus retry_after_ms, or StatusHoldTimeout when it names
// none, never shortening a longer hold; CLEAR releases at once; 0 or an unknown kind is dropped.
func (self *SmtpStatusHold) Apply(status *protocol.SmtpStatus) {
	now := self.clock.Now()
	switch protocol.SmtpStatusKind(status.GetKind()) {
	case protocol.SmtpStatusKind_SMTP_STATUS_HALTED, protocol.SmtpStatusKind_SMTP_STATUS_QUOTA:
		wait := time.Duration(status.GetRetryAfterMs()) * time.Millisecond
		if wait <= 0 {
			wait = self.settings.StatusHoldTimeout
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if until := now.Add(wait); until.After(self.holdUntil) {
			self.holdUntil = until
		}
	case protocol.SmtpStatusKind_SMTP_STATUS_CLEAR:
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.holdUntil = time.Time{}
	default:
		self.drop()
	}
}

func (self *SmtpStatusHold) drop() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.droppedCount += 1
}

// Whether the queue is held now, and until when.
func (self *SmtpStatusHold) Held() (bool, time.Time) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.holdUntil.IsZero() || !now.Before(self.holdUntil) {
		return false, time.Time{}
	}
	return true, self.holdUntil
}

// How many hints were dropped as protocol errors.
func (self *SmtpStatusHold) DroppedCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.droppedCount
}
