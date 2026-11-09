// §9.10's control-plane bound (D-SOCK-15): a token bucket per calling client in this process, charged
// one token for each Find and each registration page of at most 1,024 entries, before any sampling or
// signing. It bounds the work a byte-free client can make Redis and the signing key do, and nothing
// else: a stream, its bytes and its lifetime are never charged, and no count of names, listeners or
// streams is bounded anywhere (owner decision 66). An urnetwork-edge caller's bucket takes W2's edge
// rate instead (§19.5).
//
// Buckets are in memory and per process, so the bound is the configured rate times the process count,
// and a restart forgets it. Time is the host's clock, so a test moves it. A charge refused takes no
// token, so a refused client is never charged for being refused. No client, network or address enters
// a metric label (I-13).
//
// Safe for concurrent use.

package socketsservice

import (
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// One client's bucket. Its level counts in units of a billionth of a token, and each nanosecond refills
// as many units as the rate's calls a second, so a refill is an exact integer and no rounding builds up
// across charges.
type socketControlBucket struct {
	// In billionths of a token.
	level int64
	// When level was last brought up to date.
	refillTime time.Time
	edge       bool
}

// The bound's state. NewSocketControlBound makes one.
type SocketControlBound struct {
	settings *SocketControlBoundSettings
	clock    sidecar.Clock

	stateLock       sync.Mutex
	clientIdBuckets map[connect.Id]*socketControlBucket
	lastSweepTime   time.Time
}

// A bound on clock with settings, which the caller has validated.
func NewSocketControlBound(settings *SocketControlBoundSettings, clock sidecar.Clock) *SocketControlBound {
	return &SocketControlBound{
		settings:        settings,
		clock:           clock,
		clientIdBuckets: map[connect.Id]*socketControlBucket{},
		lastSweepTime:   clock.Now(),
	}
}

// One token, in level units.
const socketControlTokenUnits = int64(time.Second)

// The rate and burst a bucket of this kind keeps, in level units: units refilled per nanosecond, and
// the most it holds.
func (self *SocketControlBound) rateAndCapacity(edge bool) (int64, int64) {
	if edge {
		return int64(self.settings.EdgeCallsPerSecond), int64(self.settings.EdgeBurst) * socketControlTokenUnits
	}
	return int64(self.settings.CallsPerSecond), int64(self.settings.Burst) * socketControlTokenUnits
}

// Brings bucket up to now.
func (self *SocketControlBound) refillWithLock(bucket *socketControlBucket, now time.Time) {
	rate, capacity := self.rateAndCapacity(bucket.edge)
	if elapsed := now.Sub(bucket.refillTime); 0 < elapsed {
		// a level saturates at capacity, so a long idle never overflows the product
		elapsedNanos := min(int64(elapsed), capacity/rate+1)
		bucket.level = min(capacity, bucket.level+elapsedNanos*rate)
	}
	bucket.refillTime = now
}

// Charges one call to clientId, an urnetwork-edge client when edge is set. allowed false took no token,
// and retryAfter says when the next one is there. A client's first call finds a full bucket.
func (self *SocketControlBound) Charge(clientId connect.Id, edge bool) (allowed bool, retryAfter time.Duration) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	self.sweepWithLock(now)
	rate, capacity := self.rateAndCapacity(edge)
	bucket, found := self.clientIdBuckets[clientId]
	if !found || bucket.edge != edge {
		bucket = &socketControlBucket{level: capacity, refillTime: now, edge: edge}
		self.clientIdBuckets[clientId] = bucket
	}
	self.refillWithLock(bucket, now)
	if bucket.level < socketControlTokenUnits {
		missing := socketControlTokenUnits - bucket.level
		// rounded up to the nanosecond, so waiting this long always finds the token
		return false, time.Duration((missing + rate - 1) / rate)
	}
	bucket.level -= socketControlTokenUnits
	return true, 0
}

// Drops the buckets that have refilled to full since their last charge, at most once a SweepInterval,
// so the map holds only the clients of about the last interval.
func (self *SocketControlBound) sweepWithLock(now time.Time) {
	if now.Sub(self.lastSweepTime) < self.settings.SweepInterval {
		return
	}
	self.lastSweepTime = now
	for clientId, bucket := range self.clientIdBuckets {
		self.refillWithLock(bucket, now)
		if _, capacity := self.rateAndCapacity(bucket.edge); capacity <= bucket.level {
			delete(self.clientIdBuckets, clientId)
		}
	}
}

// How many clients hold a bucket that is not full, or was charged since the last sweep: a test's view.
func (self *SocketControlBound) bucketCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.clientIdBuckets)
}
