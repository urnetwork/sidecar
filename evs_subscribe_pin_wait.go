// The subscriber's pin waits (QD-1202 on evs_subscribe.go's rounds): a read or a delivery of a followed ref that meets
// a statement pinned above this device's config state waits for the log to reach that pin within
// EvsSettings.AuthPinWaitTimeout, as every reader's does (EvsVerifier.awaitPin), but never on the round, whose one
// goroutine serves every subscription. A pin the log does not reach, which only a server lying about pins or a
// follower that cannot follow leaves, would otherwise hold every other subscription's rounds for the bound, again at
// each retry.
//
//	defer    a round's reads and walks carry an evsPinWaitDeferral (withEvsPinWaitDeferral): the verifier withholds
//	         such a statement at once, ErrConfigPinAhead as past the bound, and notes its pin in place of waiting
//	hold     a read or delivery withheld so holds its ref: the rounds skip the ref, its reads and deliveries owed to
//	         the hold, while every other ref's go on in the same round. The hold's bound, AuthPinWaitTimeout from
//	         when it was taken, is a timer of the client's clock
//	waiter   one goroutine of the subscriber's while any hold stands (waitForPins) waits for the log to reach the
//	         lowest pin a hold waits for, through EvsClientArgs.ConfigWait, as a reader's wait asks it: a bound
//	         passing or a hold of a lower pin ends its wait sooner, so its goroutine and its wakes do not grow with
//	         the refs held
//	release  a hold goes once the log reaches its pin, its owed read queued and its owed delivery due at once, which
//	         the next round judges the statement in; or once its bound passes, the waiter's wait fails on its own or
//	         the subscriber closes, its owed work due after ReadRetryWait, as a read that failed is retried. Retried
//	         with its pin still above the state, the ref is withheld again, alarming nothing, and held anew
//	close    EvsClient.Close ends the waiter, which releases every hold, and joins it once its last pass has counted
//	         and woken what it released
//
// Without a wait wired (EvsClientArgs.ConfigWait nil, or AuthPinWaitTimeout not positive) such a statement is withheld
// at once as before and nothing is held: the read is queued again after ReadRetryWait. The fault program's devices wire
// none, so their rounds start no goroutine.
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"sync"
)

// What a subscriber's round asks of one read or walk it makes: see the file header's defer row.
type evsPinWaitDeferral struct {
	stateLock sync.Mutex
	// the highest pin noted, 0 for none
	position uint64
}

// The context key of an evsPinWaitDeferral.
type evsPinWaitDeferralKey struct{}

// ctx carrying deferral, which the verifier's waits under it note in place of waiting.
func withEvsPinWaitDeferral(ctx context.Context, deferral *evsPinWaitDeferral) context.Context {
	return context.WithValue(ctx, evsPinWaitDeferralKey{}, deferral)
}

// The deferral ctx carries, nil for none: any other caller's read, which waits.
func evsPinWaitDeferralOf(ctx context.Context) *evsPinWaitDeferral {
	deferral, _ := ctx.Value(evsPinWaitDeferralKey{}).(*evsPinWaitDeferral)
	return deferral
}

// Notes a statement's pin n above the reader's state, which the verifier withheld the statement at.
func (self *evsPinWaitDeferral) note(n uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.position = max(self.position, n)
}

// The pin err withheld its statement at, once noted, 0 where nothing was noted or err is another failure, which the
// caller retries as before.
func (self *evsPinWaitDeferral) heldPosition(err error) uint64 {
	if err == nil || !errors.Is(err, ErrGkmAuthAhead) {
		return 0
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.position
}

// A followed ref held for a pin (see the file header's hold row).
type evsPinHold struct {
	// the pin it waits for
	position uint64
	// its bound passed, and the stop of the bound's timer, nil until armed
	expired   bool
	stopBound func() bool
	// a read of the ref came due while held, fresh if one asked fresh; and its delivery is what the pin held
	readOwed     bool
	fresh        bool
	deliveryOwed bool
}

// Whether key is held for a pin, the read a round came to owed to the hold, fresh with fresh.
func (self *evsSubscriber) readHeldForPin(key evsRefKey, fresh bool) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hold := self.pinHolds[key]
	if hold == nil {
		return false
	}
	hold.readOwed = true
	hold.fresh = hold.fresh || fresh
	return true
}

// Holds key for its pin at position, a read of it owed, fresh with fresh: what a round's read withheld for the pin
// does (see the file header's hold row). ctx is the round's, which the waiter it starts runs within.
func (self *evsSubscriber) holdReadForPin(ctx context.Context, key evsRefKey, position uint64, fresh bool) {
	var start func()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		start = self.holdForPinWithLock(ctx, key, position, true, fresh)
	}()
	start()
}

// Holds key for its pin at position, owing it a read, fresh with fresh, or with read false its delivery; a hold that
// stands takes what is owed, and a lower pin. Answers what the caller runs once it has let go of stateLock: a new
// hold's bound armed, and the waiter started where none runs, or its wait ended where it waits for a pin above this
// hold's. ctx is the round's, which a waiter started here runs within.
func (self *evsSubscriber) holdForPinWithLock(ctx context.Context, key evsRefKey, position uint64, read bool, fresh bool) func() {
	hold := self.pinHolds[key]
	created := hold == nil
	if created {
		hold = &evsPinHold{position: position}
		self.pinHolds[key] = hold
	} else if position < hold.position {
		hold.position = position
	}
	if read {
		hold.readOwed = true
		hold.fresh = hold.fresh || fresh
	} else {
		hold.deliveryOwed = true
	}
	var startWaiter func()
	var retarget context.CancelFunc
	switch {
	case self.pinWaiterCancel == nil:
		waiterCtx, cancel := context.WithCancel(ctx)
		self.pinWaiterCancel = cancel
		self.pinWaits.Add(1)
		startWaiter = func() { go self.waitForPins(waiterCtx, cancel) }
	case self.pinWaitCancel != nil && hold.position < self.pinWaitPosition:
		retarget = self.pinWaitCancel
	}
	barrierKey := key.repoId.String() + ":" + key.refId.String()
	return func() {
		if created {
			// the ref's rounds are deferred from here until its release
			testHookBarrier("evs.subscribe.pin_held", barrierKey)
			self.armPinBound(key, hold)
		}
		if startWaiter != nil {
			startWaiter()
		}
		if retarget != nil {
			retarget()
		}
	}
}

// Arms hold's bound, AuthPinWaitTimeout on the client's clock, whose passing releases it (see the file header's
// release row). A hold released before its bound is armed stops it at once.
func (self *evsSubscriber) armPinBound(key evsRefKey, hold *evsPinHold) {
	stop := self.client.clock.AfterFunc(self.client.settings.AuthPinWaitTimeout, func() { self.expirePinHold(key, hold) })
	released := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.pinHolds[key] != hold {
			return true
		}
		hold.stopBound = stop
		return false
	}()
	if released {
		stop()
	}
}

// hold's bound passed: it expires, and the waiter's wait ends so the waiter releases it.
func (self *evsSubscriber) expirePinHold(key evsRefKey, hold *evsPinHold) {
	cancel := func() context.CancelFunc {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.pinHolds[key] != hold {
			return nil
		}
		hold.expired = true
		return self.pinWaitCancel
	}()
	if cancel != nil {
		cancel()
	}
}

// The waiter (see the file header's waiter row), until no hold stands or ctx ends, when it releases every hold; then
// it cancels ctx and leaves pinWaits, which Close joins, once what its last pass released is counted and woken. Each
// pass releases what it can, then waits for the lowest pin held, a wait that ends on its own short of that pin, failing
// or answering below it, releasing every hold the next pass, so a wait that cannot run never spins.
func (self *evsSubscriber) waitForPins(ctx context.Context, cancel context.CancelFunc) {
	defer self.pinWaits.Done()
	defer cancel()
	failed := false
	for {
		position := self.configPosition()
		var released []evsRefKey
		var stops []func() bool
		waitCtx, waitCancel, target, more := func() (context.Context, context.CancelFunc, uint64, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			released, stops = self.releasePinHoldsWithLock(position, failed || ctx.Err() != nil)
			if len(self.pinHolds) == 0 {
				// a hold taken from here starts another waiter
				self.pinWaiterCancel, self.pinWaitCancel, self.pinWaitPosition = nil, nil, 0
				return nil, nil, 0, false
			}
			target := uint64(0)
			for _, hold := range self.pinHolds {
				if target == 0 || hold.position < target {
					target = hold.position
				}
			}
			waitCtx, waitCancel := context.WithCancel(ctx)
			self.pinWaitCancel, self.pinWaitPosition = waitCancel, target
			return waitCtx, waitCancel, target, true
		}()
		for _, stop := range stops {
			stop()
		}
		if 0 < len(released) {
			for _, key := range released {
				// the ref's owed work is due from here
				testHookBarrier("evs.subscribe.pin_released", key.repoId.String()+":"+key.refId.String())
			}
			self.pinReleaseCount.Update(func(count int) int { return count + len(released) })
			self.wakeRounds()
		}
		if !more {
			return
		}
		err := ErrEvsNoConfig
		if wait := self.client.args.ConfigWait; wait != nil {
			err = wait(waitCtx, target)
		}
		// ended on its own, neither by a bound, a lower pin nor ctx, and short of the pin
		failed = waitCtx.Err() == nil && self.configPosition() < target
		waitCancel()
		if failed && self.client.log.V(1).Enabled() {
			self.client.log.Infof("[evs]the subscriber's wait for the config log to reach pin %d: %v", target, err)
		}
	}
}

// Releases each hold the log reached at position, its owed work due now, and each whose bound passed, or every hold
// with all, its owed work due after ReadRetryWait (see the file header's release row). Answers the keys released and
// the bounds to stop.
func (self *evsSubscriber) releasePinHoldsWithLock(position uint64, all bool) ([]evsRefKey, []func() bool) {
	now := self.client.clock.Now()
	released := []evsRefKey{}
	stops := []func() bool{}
	for key, hold := range self.pinHolds {
		reached := hold.position <= position
		if !reached && !hold.expired && !all {
			continue
		}
		delete(self.pinHolds, key)
		released = append(released, key)
		if hold.stopBound != nil {
			stops = append(stops, hold.stopBound)
		}
		dueAt := now
		if !reached {
			dueAt = now.Add(self.client.settings.ReadRetryWait)
		}
		if hold.readOwed {
			self.queueSyncWithLock(key.repoId, &key.refId, hold.fresh, dueAt)
		}
		if mark := self.refMarks[key]; hold.deliveryOwed && mark != nil && mark.owed {
			mark.deliverAt = dueAt
		}
	}
	return released, stops
}

// The position of the newest config state this client judges at, 0 with none.
func (self *evsSubscriber) configPosition() uint64 {
	state, err := self.client.verifier.config()
	if err != nil {
		return 0
	}
	return state.Pin().GetVersion()
}

// Ends the waiter and joins it, every hold released, a waiter already on its last pass among them: what
// EvsClient.Close does once the rounds have stopped, so no round takes a hold meanwhile.
func (self *evsSubscriber) endPinWaits() {
	cancel := func() context.CancelFunc {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.pinWaiterCancel
	}()
	if cancel != nil {
		cancel()
	}
	self.pinWaits.Wait()
}

// Whether key is held for a pin, its delivery skipped by the rounds until its release.
func (self *evsSubscriber) heldForPinWithLock(key evsRefKey) bool {
	return self.pinHolds[key] != nil
}
