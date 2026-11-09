// §10.6's rates, counted per process and in memory, as plan-KEYS-rate-counters (decided) has it: each limit is its
// stated rate times the process count, and a restart forgets it, as §9.10 counts sockets'. They are behind one
// interface, so a Redis form would be one implementation more. The 24 h ReaderKey rule is not here: it is exact, read
// from the stored object.
//
// Each key is a token bucket holding up to the rate's count, refilled evenly over its interval, so a quiet key may
// spend its whole count at once and a busy one gets the rate. Keys are a route's limit name and opaque ids (I-13).
// Memory is bounded: past RateEntryCount entries, a full bucket, which has forgotten its key, goes first, and any
// entry when none is full, which costs only that key a fresh bucket.
//
// Safe for concurrent use. No method does I/O.

package gkmservice

import (
	"sync"
	"time"
)

// What every rate limit takes an event through. Safe for concurrent use.
type GkmRateCounter interface {
	// Whether key may take one more event under rate at now, counting it if so.
	Allow(rate GkmRate, key string, now time.Time) bool
}

// One key's bucket, and the rate it was last spent under, so a sweep can tell a full one.
type gkmRateBucket struct {
	tokens float64
	at     time.Time
	rate   GkmRate
}

// The process's counters. See the file header.
type gkmRateCounters struct {
	maxEntryCount int

	stateLock  sync.Mutex
	keyBuckets map[string]*gkmRateBucket
}

// Counters keeping at most maxEntryCount keys.
func newGkmRateCounters(maxEntryCount int) *gkmRateCounters {
	return &gkmRateCounters{maxEntryCount: maxEntryCount, keyBuckets: map[string]*gkmRateBucket{}}
}

// See GkmRateCounter.
func (self *gkmRateCounters) Allow(rate GkmRate, key string, now time.Time) bool {
	if !rate.valid() {
		// a rate that cannot be met admits nothing
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	bucket, ok := self.keyBuckets[key]
	if !ok {
		if self.maxEntryCount <= len(self.keyBuckets) {
			self.evictWithLock(now)
		}
		bucket = &gkmRateBucket{tokens: float64(rate.Count), at: now, rate: rate}
		self.keyBuckets[key] = bucket
	}
	bucket.rate = rate
	bucket.refill(now)
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens -= 1
	return true
}

// Adds what the time since the bucket's last event refills, up to its rate's count. A clock that went back
// refills nothing.
func (self *gkmRateBucket) refill(now time.Time) {
	if elapsed := now.Sub(self.at); 0 < elapsed {
		refilled := self.tokens + float64(self.rate.Count)*float64(elapsed)/float64(self.rate.Interval)
		self.tokens = min(float64(self.rate.Count), refilled)
		self.at = now
	}
}

// Makes room for new keys: every bucket that has refilled to its count goes, since it remembers nothing, and if that
// frees too little, a sixteenth of the entries go as well, so a sweep, which reads every entry, runs at most once
// per sixteenth of the bound's new keys.
func (self *gkmRateCounters) evictWithLock(now time.Time) {
	for key, bucket := range self.keyBuckets {
		bucket.refill(now)
		if float64(bucket.rate.Count) <= bucket.tokens {
			delete(self.keyBuckets, key)
		}
	}
	evictCount := len(self.keyBuckets) - (self.maxEntryCount - max(1, self.maxEntryCount/16))
	for key := range self.keyBuckets {
		if evictCount <= 0 {
			return
		}
		delete(self.keyBuckets, key)
		evictCount -= 1
	}
}

// How many keys the counters hold, for tests and gauges.
func (self *gkmRateCounters) entryCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.keyBuckets)
}
