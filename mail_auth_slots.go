//go:build !sidecar_http && !js && !ios_extension

// §15.5's receiver row (D-MAIL-14, FS-121; MAIL-M7-09): a receiver's check slots. At most CheckSlotMaxCount messages,
// 4, check at once, and the rest wait in arrival order. A message's 30 s start only when a slot takes it, after its
// last byte, since MailAuthChecker.Check starts its budget when called, so waiting for a slot costs it no checking.
// With max_streams' 16 sessions a message waits behind at most 3 rounds of 4 checks of at most 30 s each, so its own
// check ends within 2 min of its last byte, inside the sender's 10 min (RFC 5321 §4.5.3.2.6).
//
// A freed slot passes straight to the longest waiter, so no later arrival takes it first, and a waiter whose context
// ends leaves the line, passing on a slot handed to it as it left. Safe for concurrent use.

package sidecar

import (
	"context"
	"slices"
	"sync"
)

// A receiver's check slots. See the file header.
type MailAuthSlots struct {
	settings *MailAuthSettings

	stateLock  sync.Mutex
	takenCount int
	// Each closed when handed a slot, the longest waiting first.
	waiters []chan struct{}
}

// Slots as many as settings' CheckSlotMaxCount.
func NewMailAuthSlots(settings *MailAuthSettings) *MailAuthSlots {
	return &MailAuthSlots{settings: settings}
}

// Waits in arrival order for a slot, and returns its release, which frees it once. ctx ending first leaves the line
// with ctx's error.
func (self *MailAuthSlots) Take(ctx context.Context) (release func(), err error) {
	testHookBarrier("mail.auth.slots.take.before", "")
	waiter := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.takenCount < self.settings.CheckSlotMaxCount && len(self.waiters) == 0 {
			self.takenCount += 1
			return nil
		}
		waiter := make(chan struct{})
		self.waiters = append(self.waiters, waiter)
		return waiter
	}()
	if waiter != nil {
		select {
		case <-waiter:
		case <-ctx.Done():
			handed := func() bool {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				if index := slices.Index(self.waiters, waiter); 0 <= index {
					self.waiters = slices.Delete(self.waiters, index, index+1)
					return false
				}
				return true
			}()
			if handed {
				self.release()
			}
			return nil, ctx.Err()
		}
	}
	testHookBarrier("mail.auth.slots.take.after", "")
	return sync.OnceFunc(self.release), nil
}

// Frees a slot: to the longest waiter, else back to the free count.
func (self *MailAuthSlots) release() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < len(self.waiters) {
		waiter := self.waiters[0]
		self.waiters = slices.Delete(self.waiters, 0, 1)
		close(waiter)
		return
	}
	self.takenCount -= 1
}

// One message's checks once a slot takes it, its 30 s starting then. ctx ending while it waits returns ctx's error;
// otherwise as checker.Check.
func (self *MailAuthSlots) Check(ctx context.Context, checker *MailAuthChecker, input *MailAuthInput) (*MailAuthOutcome, error) {
	release, err := self.Take(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return checker.Check(ctx, input)
}
