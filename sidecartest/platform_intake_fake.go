// T2's PlatformIntake: SMTP-M5-05's SmtpReportIntake as the platform listener reaches it, until
// SMTP-M5-06 adapts the real one in the platform host. It keeps a copy of each message it is given and
// answers what a test scripted for its recipient, PlatformOutcomeTaken by default. A test may also hold
// every call at a gate, so messages stay in the listener's memory while others arrive. Safe for
// concurrent use.

package sidecartest

import (
	"context"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/mxedgeservice"
)

var _ mxedgeservice.PlatformIntake = (*FakePlatformIntake)(nil)

// Calls kept and answers scripted, in memory.
type FakePlatformIntake struct {
	stateLock sync.Mutex
	messages  []*mxedgeservice.PlatformMessage
	// By recipient.
	recipientOutcomes map[string]mxedgeservice.PlatformOutcome
	recipientErrs     map[string]error
	// Closed to let held calls answer; nil holds nothing.
	gate chan struct{}
	held chan struct{}
}

// Takes everything, holding nothing.
func NewFakePlatformIntake() *FakePlatformIntake {
	return &FakePlatformIntake{
		recipientOutcomes: map[string]mxedgeservice.PlatformOutcome{},
		recipientErrs:     map[string]error{},
		held:              make(chan struct{}, 1024),
	}
}

// What Accept answers for recipient, lowercased as the listener passes it.
func (self *FakePlatformIntake) SetOutcome(recipient string, outcome mxedgeservice.PlatformOutcome) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.recipientOutcomes[recipient] = outcome
}

// The error Accept answers for recipient, as an intake whose store or DNS did not answer.
func (self *FakePlatformIntake) SetError(recipient string, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.recipientErrs[recipient] = err
}

// Holds each call from now on until Release. A call signals Held once it waits.
func (self *FakePlatformIntake) Hold() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.gate = make(chan struct{})
}

// Lets every held call answer, and holds no later one.
func (self *FakePlatformIntake) Release() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.gate != nil {
		close(self.gate)
		self.gate = nil
	}
}

// Receives once for each call that has come to wait at the gate.
func (self *FakePlatformIntake) Held() <-chan struct{} {
	return self.held
}

// Keeps a copy of message, then answers as scripted, after the gate if one is up.
func (self *FakePlatformIntake) Accept(ctx context.Context, message *mxedgeservice.PlatformMessage) (mxedgeservice.PlatformOutcome, error) {
	gate := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		kept := *message
		kept.Raw = slices.Clone(message.Raw)
		self.messages = append(self.messages, &kept)
		return self.gate
	}()
	if gate != nil {
		self.held <- struct{}{}
		select {
		case <-gate:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.recipientErrs[message.Recipient]; err != nil {
		return 0, err
	}
	if outcome, ok := self.recipientOutcomes[message.Recipient]; ok {
		return outcome, nil
	}
	return mxedgeservice.PlatformOutcomeTaken, nil
}

// Every message given so far, oldest first, as copies.
func (self *FakePlatformIntake) Messages() []*mxedgeservice.PlatformMessage {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	messages := make([]*mxedgeservice.PlatformMessage, 0, len(self.messages))
	for _, message := range self.messages {
		kept := *message
		kept.Raw = slices.Clone(message.Raw)
		messages = append(messages, &kept)
	}
	return messages
}
