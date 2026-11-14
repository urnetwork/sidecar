// A fake of pushservice.WakeVendor (SDK-M8-10): one platform's submissions recorded with the time on a
// clock and the body the real vendor would have sent, answered from a script a test queues, sent
// otherwise. What the push sender's tests and FS-36's schedules (SDK-M8-12) wake through before T3 has a
// vendor to reach.
//
// Safe for concurrent use.

package sidecartest

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
)

// One submission a FakeWakeVendor took.
type FakeWakeSubmission struct {
	Platform string
	// The token it went to: a test's synthetic one.
	Token   string
	Payload pushservice.WakePayload
	// The vendor's body: ApnsWakeBody's, or FcmWakeMessage's with the token.
	Body []byte
	// On the vendor's clock.
	At time.Time
	// What it was answered.
	Result pushservice.WakeVendorResult
}

// A scripted vendor. NewFakeWakeVendor makes one.
type FakeWakeVendor struct {
	platform string
	clock    sidecar.Clock

	stateLock   sync.Mutex
	submissions []*FakeWakeSubmission
	// answers for the next submissions, in order; sent once they run out
	answers []*pushservice.WakeVendorResult
	// called with each submission before it is answered, on the sender's goroutine, nil for none
	hook func(ctx context.Context, submission *FakeWakeSubmission)
	// each submission, for a test to wait on
	submitted chan *FakeWakeSubmission
}

var _ pushservice.WakeVendor = (*FakeWakeVendor)(nil)

// A vendor for platform, apns or fcm, timing submissions on clock, nil being real time.
func NewFakeWakeVendor(platform string, clock sidecar.Clock) *FakeWakeVendor {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &FakeWakeVendor{
		platform:  platform,
		clock:     clock,
		submitted: make(chan *FakeWakeSubmission, 1024),
	}
}

// See pushservice.WakeVendor.
func (self *FakeWakeVendor) Platform() string {
	return self.platform
}

// Queues answers for the next submissions, in order.
func (self *FakeWakeVendor) Answer(results ...*pushservice.WakeVendorResult) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, result := range results {
		copied := *result
		self.answers = append(self.answers, &copied)
	}
}

// Calls hook with each submission before it is answered: a kill after the send, say.
func (self *FakeWakeVendor) SetHook(hook func(ctx context.Context, submission *FakeWakeSubmission)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.hook = hook
}

// See pushservice.WakeVendor: recorded, then answered by the script's next answer, or sent.
func (self *FakeWakeVendor) Send(ctx context.Context, token string, payload *pushservice.WakePayload) *pushservice.WakeVendorResult {
	submission := &FakeWakeSubmission{
		Platform: self.platform,
		Token:    token,
		Payload:  *payload,
		At:       self.clock.Now(),
		Result:   pushservice.WakeVendorResult{Outcome: pushservice.WakeVendorSent, Status: 200},
	}
	if self.platform == pushservice.WakePlatformFcm {
		submission.Body = pushservice.FcmWakeMessage(token, payload)
	} else {
		submission.Body = pushservice.ApnsWakeBody(payload)
	}
	hook := func() func(context.Context, *FakeWakeSubmission) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if 0 < len(self.answers) {
			submission.Result = *self.answers[0]
			self.answers = self.answers[1:]
		}
		self.submissions = append(self.submissions, submission)
		return self.hook
	}()
	if hook != nil {
		hook(ctx, submission)
	}
	select {
	case self.submitted <- submission:
	default:
	}
	result := submission.Result
	return &result
}

// Every submission so far, in order.
func (self *FakeWakeVendor) Submissions() []*FakeWakeSubmission {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.submissions)
}

// Each submission as it is made, for a test to wait on.
func (self *FakeWakeVendor) Submitted() <-chan *FakeWakeSubmission {
	return self.submitted
}
