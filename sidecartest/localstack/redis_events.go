// The process's one shared key-event subscriber (host_redis.go), as server/connect/key_event_subscriber.go
// runs it: a keyspace event stays on the node that fired it, so one socket PSUBSCRIBEs on each master,
// and one goroutine runs every callback in order.
//
// A pattern stays subscribed until Close, even after its last callback goes: nothing here frees it,
// since a test process watches few families, and so a later add cannot race an unsubscribe. A socket
// that dies comes back with every pattern, and only then does each callback hear Resync, so a reread
// misses nothing. The masters are read once, at the first callback: a cluster that gains a master
// later goes unheard, and the local stack's 3 stay 3.

package localstack

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// Where a keyspace event is published, db 0 being all a cluster has.
const redisKeyspaceChannelPrefix = "__keyspace@0__:"

type redisKeyEventCallback struct {
	pattern  string
	callback sidecar.RedisKeyEventFunction
}

// One event for the subscriber's goroutine. pattern is empty on Resync, which goes to every callback.
type redisKeyEventDelivery struct {
	pattern string
	event   sidecar.RedisKeyEvent
}

type redisKeyEventSubscriber struct {
	ctx        context.Context
	redis      *Redis
	deliveries chan *redisKeyEventDelivery

	stateLock sync.Mutex
	callbacks []*redisKeyEventCallback
	patterns  map[string]bool
	links     []*redisEventLink
}

func newRedisKeyEventSubscriber(ctx context.Context, redis *Redis) *redisKeyEventSubscriber {
	self := &redisKeyEventSubscriber{
		ctx:        ctx,
		redis:      redis,
		deliveries: make(chan *redisKeyEventDelivery, redis.settings.KeyEventQueueCount),
		patterns:   map[string]bool{},
	}
	go self.run()
	return self
}

func (self *redisKeyEventSubscriber) run() {
	for {
		select {
		case delivery := <-self.deliveries:
			var callbacks []*redisKeyEventCallback
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				callbacks = slices.Clone(self.callbacks)
			}()
			for _, callback := range callbacks {
				if delivery.event.Resync || callback.pattern == delivery.pattern {
					callback.callback(delivery.event)
				}
			}
		case <-self.ctx.Done():
			return
		}
	}
}

func (self *redisKeyEventSubscriber) deliver(delivery *redisKeyEventDelivery) {
	select {
	case self.deliveries <- delivery:
	case <-self.ctx.Done():
	}
}

// A link per master, started at the first call.
func (self *redisKeyEventSubscriber) startLinks() []*redisEventLink {
	masters := self.redis.Masters()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.links == nil {
		for _, address := range masters {
			link := &redisEventLink{
				subscriber: self,
				address:    address,
				session:    sidecar.NewMonitorValue[*redisEventSession](nil),
			}
			self.links = append(self.links, link)
			go link.run()
		}
	}
	return self.links
}

func (self *redisKeyEventSubscriber) currentPatterns() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Sorted(maps.Keys(self.patterns))
}

func (self *Redis) AddKeyEventCallback(keyPattern string, callback sidecar.RedisKeyEventFunction) (func(), error) {
	if !strings.Contains(keyPattern, "*") {
		return nil, fmt.Errorf("pattern %q names one key: watch a family, never one client", keyPattern)
	}
	subscriber := self.subscriber
	entry := &redisKeyEventCallback{pattern: keyPattern, callback: callback}
	remove := func() {
		subscriber.stateLock.Lock()
		defer subscriber.stateLock.Unlock()
		subscriber.callbacks = slices.DeleteFunc(subscriber.callbacks, func(other *redisKeyEventCallback) bool {
			return other == entry
		})
	}
	func() {
		subscriber.stateLock.Lock()
		defer subscriber.stateLock.Unlock()
		subscriber.callbacks = append(subscriber.callbacks, entry)
		subscriber.patterns[keyPattern] = true
	}()
	ctx, cancel := context.WithTimeout(subscriber.ctx, self.settings.DialTimeout+self.settings.CallTimeout)
	defer cancel()
	for _, link := range subscriber.startLinks() {
		if err := link.subscribe(ctx, keyPattern); err != nil {
			remove()
			return nil, fmt.Errorf("subscribing on %s: %w", link.address, err)
		}
	}
	return remove, nil
}

// One master's subscription, won back by its goroutine whenever it dies.
type redisEventLink struct {
	subscriber *redisKeyEventSubscriber
	address    string
	// The live socket, nil while it is down.
	session *sidecar.MonitorValue[*redisEventSession]
}

// One socket's subscription. Only run reads it. A caller writes with the write lock held, which orders
// its PSUBSCRIBE and so names which acknowledgement is its own.
type redisEventSession struct {
	connection *redisConnection
	// Closes when run stops reading.
	lost chan struct{}
	// Acknowledgements read so far.
	acknowledgedCount *sidecar.MonitorValue[int]

	writeLock sync.Mutex
	sentCount int
}

// Sends one PSUBSCRIBE per pattern, returning how many acknowledgements cover them.
func (self *redisEventSession) send(timeout time.Duration, patterns ...string) (int, error) {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	var buffer []byte
	for _, pattern := range patterns {
		buffer = appendRedisCommand(buffer, redisArgs("PSUBSCRIBE", redisKeyspaceChannelPrefix+pattern))
	}
	if err := self.connection.conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}
	if _, err := self.connection.conn.Write(buffer); err != nil {
		return 0, err
	}
	self.sentCount += len(patterns)
	return self.sentCount, nil
}

// Returns once pattern is live on this master. A socket lost meanwhile comes back with pattern on it,
// so this asks the next one, and fails only when ctx ends with no socket having answered.
func (self *redisEventLink) subscribe(ctx context.Context, pattern string) error {
	for {
		session, changed := self.session.Get()
		if session != nil {
			done, err := func() (bool, error) {
				want, err := session.send(self.subscriber.redis.settings.CallTimeout, pattern)
				if err != nil {
					return false, nil
				}
				for {
					count, acknowledged := session.acknowledgedCount.Get()
					if want <= count {
						return true, nil
					}
					select {
					case <-acknowledged:
					case <-session.lost:
						return false, nil
					case <-ctx.Done():
						return false, ctx.Err()
					}
				}
			}()
			if done || err != nil {
				return err
			}
			continue
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (self *redisEventLink) run() {
	settings := self.subscriber.redis.settings
	resync := false
	for {
		reconnect := connect.NewPacedReconnect(settings.ResubscribeTimeout)
		if self.serve(resync) {
			// what comes next is a win back, after a gap
			resync = true
		}
		select {
		case <-reconnect.After():
		case <-self.subscriber.ctx.Done():
			return
		}
	}
}

// One socket's life. True when it got as far as subscribing, so its loss leaves a gap.
func (self *redisEventLink) serve(resync bool) bool {
	ctx := self.subscriber.ctx
	settings := self.subscriber.redis.settings
	connection, err := dialRedis(ctx, self.address, settings.DialTimeout)
	if err != nil {
		return false
	}
	defer connection.conn.Close()
	stopWatching := context.AfterFunc(ctx, func() {
		connection.conn.Close()
	})
	defer stopWatching()

	session := &redisEventSession{
		connection:        connection,
		lost:              make(chan struct{}),
		acknowledgedCount: sidecar.NewMonitorValue(0),
	}
	defer close(session.lost)
	patterns := self.subscriber.currentPatterns()
	if len(patterns) == 0 && resync {
		self.subscriber.deliver(&redisKeyEventDelivery{event: sidecar.RedisKeyEvent{Resync: true}})
		resync = false
	}
	if 0 < len(patterns) {
		if _, err := session.send(settings.CallTimeout, patterns...); err != nil {
			return false
		}
	}
	self.session.Set(session)
	defer self.session.Set(nil)

	for {
		value, err := readRedisValue(connection.reader)
		if err != nil {
			return true
		}
		if value.kind != redisArray || len(value.values) == 0 {
			continue
		}
		switch string(value.values[0].text) {
		case "psubscribe":
			session.acknowledgedCount.Update(func(count int) int {
				return count + 1
			})
			if resync && len(patterns) <= session.acknowledgedCount.Value() {
				self.subscriber.deliver(&redisKeyEventDelivery{event: sidecar.RedisKeyEvent{Resync: true}})
				resync = false
			}
		case "pmessage":
			if len(value.values) != 4 {
				// nothing after it can be trusted, so this socket goes and a Resync says so
				return true
			}
			self.subscriber.deliver(&redisKeyEventDelivery{
				pattern: strings.TrimPrefix(string(value.values[1].text), redisKeyspaceChannelPrefix),
				event:   sidecar.RedisKeyEvent{Key: strings.TrimPrefix(string(value.values[2].text), redisKeyspaceChannelPrefix)},
			})
		}
	}
}
