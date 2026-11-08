// FakeRedis's shared key-event subscriber (host_redis.go): one per process, one goroutine, every
// callback on it in order, as server/connect/key_event_subscriber.go runs them. A callback must note
// the key and return, so one that holds the goroutine past settings.CallbackTimeout is reported.
//
// FakeRedis publishes with its own stateLock held, so an event fires as the write applies. That makes
// this lock the inner of the two: nothing here calls into FakeRedis while holding it.

package sidecartest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

type fakeKeyEventCallback struct {
	pattern  string
	callback sidecar.RedisKeyEventFunction
}

// One event on its way, with who was listening when it fired: a subscription hears nothing older than
// itself, however far behind the queue is.
type fakeKeyEventDelivery struct {
	event     sidecar.RedisKeyEvent
	callbacks []*fakeKeyEventCallback
}

type fakeKeyEventSubscriber struct {
	ctx      context.Context
	settings *FakeRedisSettings
	violate  func(violation string)

	stateLock sync.Mutex
	callbacks []*fakeKeyEventCallback
	queue     []*fakeKeyEventDelivery
	// events taken from the queue and not yet delivered
	delivering int
	// closed and replaced when the queue or delivering changes
	changed chan struct{}
}

func newFakeKeyEventSubscriber(ctx context.Context, settings *FakeRedisSettings, violate func(violation string)) *fakeKeyEventSubscriber {
	self := &fakeKeyEventSubscriber{
		ctx:      ctx,
		settings: settings,
		violate:  violate,
		changed:  make(chan struct{}),
	}
	go self.run()
	return self
}

func (self *fakeKeyEventSubscriber) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

func (self *fakeKeyEventSubscriber) publish(key string) {
	self.enqueue(sidecar.RedisKeyEvent{Key: key})
}

// Tells every callback the subscription came back: whatever was published in the gap is gone.
func (self *fakeKeyEventSubscriber) resync() {
	self.enqueue(sidecar.RedisKeyEvent{Resync: true})
}

func (self *fakeKeyEventSubscriber) enqueue(event sidecar.RedisKeyEvent) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	callbacks := []*fakeKeyEventCallback{}
	for _, callback := range self.callbacks {
		if event.Resync || redisGlobMatch(callback.pattern, event.Key) {
			callbacks = append(callbacks, callback)
		}
	}
	self.queue = append(self.queue, &fakeKeyEventDelivery{event: event, callbacks: callbacks})
	self.notifyWithLock()
}

// Whether a callback that was listening still is: one removed since hears nothing more.
func (self *fakeKeyEventSubscriber) stillListening(callback *fakeKeyEventCallback) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Contains(self.callbacks, callback)
}

func (self *fakeKeyEventSubscriber) run() {
	for {
		var delivery *fakeKeyEventDelivery
		var changed chan struct{}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			changed = self.changed
			if len(self.queue) == 0 {
				return
			}
			delivery = self.queue[0]
			self.queue = self.queue[1:]
			self.delivering = 1
			changed = nil
		}()
		if changed != nil {
			select {
			case <-changed:
				continue
			case <-self.ctx.Done():
				return
			}
		}
		for _, callback := range delivery.callbacks {
			if self.stillListening(callback) {
				self.deliver(callback, delivery.event)
			}
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.delivering = 0
			self.notifyWithLock()
		}()
	}
}

func (self *fakeKeyEventSubscriber) deliver(callback *fakeKeyEventCallback, event sidecar.RedisKeyEvent) {
	if self.settings.CallbackTimeout <= 0 {
		callback.callback(event)
		return
	}
	returned := make(chan struct{})
	go func() {
		select {
		case <-returned:
		case <-self.ctx.Done():
		case <-time.After(self.settings.CallbackTimeout):
			self.violate(fmt.Sprintf("a key event callback for %s blocked the shared subscriber", callback.pattern))
		}
	}()
	callback.callback(event)
	close(returned)
}

// Waits until every event published so far has reached its callbacks, how a test gets past the
// subscriber's goroutine with no sleep.
func (self *fakeKeyEventSubscriber) awaitDrained(ctx context.Context) error {
	for {
		var changed chan struct{}
		drained := false
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			changed = self.changed
			drained = len(self.queue) == 0 && self.delivering == 0
		}()
		if drained {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Redis's glob, the part a family pattern uses: * and ?, with braces literal.
func redisGlobMatch(pattern string, text string) bool {
	if pattern == "" {
		return text == ""
	}
	switch pattern[0] {
	case '*':
		for start := 0; start <= len(text); start += 1 {
			if redisGlobMatch(pattern[1:], text[start:]) {
				return true
			}
		}
		return false
	case '?':
		return text != "" && redisGlobMatch(pattern[1:], text[1:])
	}
	return text != "" && pattern[0] == text[0] && redisGlobMatch(pattern[1:], text[1:])
}

func (self *FakeRedis) AddKeyEventCallback(keyPattern string, callback sidecar.RedisKeyEventFunction) (func(), error) {
	if !strings.Contains(keyPattern, "*") {
		return nil, fmt.Errorf("pattern %q names one key: watch a family, never one client", keyPattern)
	}
	entry := &fakeKeyEventCallback{pattern: keyPattern, callback: callback}
	subscriber := self.subscriber
	func() {
		subscriber.stateLock.Lock()
		defer subscriber.stateLock.Unlock()
		subscriber.callbacks = append(subscriber.callbacks, entry)
	}()
	return func() {
		subscriber.stateLock.Lock()
		defer subscriber.stateLock.Unlock()
		subscriber.callbacks = slices.DeleteFunc(subscriber.callbacks, func(other *fakeKeyEventCallback) bool {
			return other == entry
		})
	}, nil
}

// Returns once every key event published so far has reached its callbacks.
func (self *FakeRedis) AwaitKeyEvents(ctx context.Context) error {
	return self.subscriber.awaitDrained(ctx)
}

// Sends every callback a Resync, as a subscription coming back does.
func (self *FakeRedis) ResyncKeyEvents() {
	self.subscriber.resync()
}
