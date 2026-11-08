// The fleet's closed-handshake memory (§15.4; §2.8 mx-1): when a handshake closes, Redis remembers the
// sender's /24 or /48 for an hour, so that sender's plaintext retry gets 451, a retry, and not 530,
// which a Postfix falling back from TLS would take as final. It reaches a sibling sending address and
// another lb host's retry alike, since every block shares the keys.
//
// A key is {mxc_<HMAC_k(prefix)>} under a daily k, and holds no address. k is the fleet's daily key at
// {vhk}mx:<yyyymmdd>, the UTC date: 32 random bytes that the day's first process creates with SET NX
// and a 25 h ttl, and that every process reads again at each probe and at the date change (reading 5,
// as mx-foundation-closed-handshake-key settled it on plan-TLS-visitor-hash-key's key). No vault file
// holds it, and once it expires no one can compute that day's keys again. A process holds today's k,
// and yesterday's for the hour an entry under it may live, and no other.
//
// An entry written at 23:50 is under yesterday's k by 00:10, so a read in a day's first hour tries
// today's key and then yesterday's, and the 1 h holds across 00:00 UTC. The two keys hash to different
// slots, so they are two calls, never one GetMany, which production's cluster would refuse. Each
// carries its own hash in the tag, spreading the family over the cluster.
//
// Keys are soft state. A lost entry or a lost k costs a sender a 530 it should not have had. What
// cannot be answered, a Redis error or a k not held, reads as recent, so a sender is told to retry and
// never told no for good. Unlike tlsedge, a process has no k of its own to fall back to: one would find
// nothing another process wrote, a lasting 530.
//
// Safe for concurrent use.

package mxedgeservice

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"net/netip"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

const (
	// What a key holds: its existence is the whole of the memory.
	mxClosedHandshakeValue = "1"
	// k's name before its date: the {vhk} family's tag, then mxedge's own name in it, so tlsedge's
	// {vhk}tls: keys and these never meet.
	mxDailyKeyPrefix = "{vhk}mx:"
	// Go's layout for the date in k's name, yyyymmdd.
	mxDailyKeyDateLayout = "20060102"
	// k's length.
	mxDailyKeyByteCount = 32
	// How long k lives in Redis from its creation, the resolution's EX 90000: a UTC day and the hour
	// an entry under it may outlive the day. Not a setting, since it is the bound §19.7's tag and
	// D-OPS-16's filter promise no key outlives, and ClosedHandshakeTtl's ceiling follows from it.
	mxDailyKeyTtl = 25 * time.Hour
	// A UTC day, which has no leap second in Unix time.
	mxSecondsPerDay = 24 * 60 * 60
)

var (
	// Today's k is not held: Redis has not answered for it since the day began.
	errMxNoDailyKey = errors.New("no closed-handshake key for today")
	// Redis holds something under k's name that is not 32 bytes, which nothing here writes.
	errMxDailyKeyMalformed = errors.New("closed-handshake key is not 32 bytes")
)

// How a Refresh went, a metric's result.
const (
	// This process made today's k.
	mxDailyKeyResultCreated = "created"
	// Today's k was in Redis.
	mxDailyKeyResultRead = "read"
	// Redis did not answer, or held no k this process could use.
	mxDailyKeyResultFailed = "failed"
)

// The UTC day t falls in, as days since the epoch.
func mxUtcDay(t time.Time) int64 {
	seconds := t.Unix()
	day := seconds / mxSecondsPerDay
	// division rounds toward zero, and a day before the epoch must round down
	if seconds%mxSecondsPerDay < 0 {
		day -= 1
	}
	return day
}

// The first instant of day.
func mxUtcDayStart(day int64) time.Time {
	return time.Unix(day*mxSecondsPerDay, 0).UTC()
}

// Where day's k lives in Redis.
func mxDailyKeyName(day int64) string {
	return mxDailyKeyPrefix + mxUtcDayStart(day).Format(mxDailyKeyDateLayout)
}

// The memory's key for aggregate under dayKey, a day's k.
func mxClosedHandshakeKey(dayKey []byte, aggregate netip.Prefix) string {
	// a prefix never fails to marshal, and its bytes tell the two families apart by length
	prefixBytes, _ := aggregate.MarshalBinary()
	mac := hmac.New(sha256.New, dayKey)
	mac.Write(prefixBytes)
	return "{mxc_" + hex.EncodeToString(mac.Sum(nil)) + "}"
}

// The memory, as this process reaches it.
type mxClosedHandshakes struct {
	redis sidecar.Redis
	ttl   time.Duration
	clock MxEdgeClock
	// The UTC day of the newest k a Refresh has held, 0 before the first, so a wait can see one land.
	keyDay *sidecar.MonitorValue[int64]

	stateLock sync.Mutex
	// k by UTC day. A value is never changed in place, so one read under the lock may be used after.
	dayKeys map[int64][]byte
	// Days whose k Redis does not hold, so no entry under one can be found, and a read skips them.
	absentDays map[int64]bool
}

// A memory holding no k: it answers recent and writes nothing until a Refresh succeeds.
func newMxClosedHandshakes(redis sidecar.Redis, ttl time.Duration, clock MxEdgeClock) *mxClosedHandshakes {
	return &mxClosedHandshakes{
		redis:      redis,
		ttl:        ttl,
		clock:      clock,
		keyDay:     sidecar.NewMonitorValue(int64(0)),
		dayKeys:    map[int64][]byte{},
		absentDays: map[int64]bool{},
	}
}

// Whether an entry written under yesterday's k may still live at now.
func (self *mxClosedHandshakes) yesterdayNeeded(now time.Time) bool {
	return now.Before(mxUtcDayStart(mxUtcDay(now)).Add(self.ttl))
}

// Reads today's k, creating it if no process has yet, and yesterday's while an entry under it may live,
// and forgets every other, so no k outlives what it serves. The engine's probe calls this, at each
// probe and at the date change. An error keeps what is held, so a k already held still serves, and a
// day whose k is not held fails closed.
func (self *mxClosedHandshakes) Refresh(ctx context.Context) (result string, err error) {
	now := self.clock.Now()
	today := mxUtcDay(now)
	yesterdayNeeded := self.yesterdayNeeded(now)
	yesterdayKnown := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		keep := func(day int64) bool {
			return day == today || day == today-1 && yesterdayNeeded
		}
		maps.DeleteFunc(self.dayKeys, func(day int64, dayKey []byte) bool { return !keep(day) })
		maps.DeleteFunc(self.absentDays, func(day int64, absent bool) bool { return !keep(day) })
		return self.dayKeys[today-1] != nil || self.absentDays[today-1]
	}()

	todayKey, created, _, err := self.fetch(ctx, today, true)
	if err != nil {
		return mxDailyKeyResultFailed, err
	}
	self.hold(today, todayKey, created)
	// yesterday's k is read and never made: no entry can be under one that does not exist
	if yesterdayNeeded && !yesterdayKnown {
		yesterdayKey, _, found, err := self.fetch(ctx, today-1, false)
		if err != nil {
			return mxDailyKeyResultFailed, err
		}
		if found {
			self.hold(today-1, yesterdayKey, false)
		} else {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.absentDays[today-1] = true
			}()
		}
	}
	self.keyDay.Set(today)
	if created {
		return mxDailyKeyResultCreated, nil
	}
	return mxDailyKeyResultRead, nil
}

// Day's k from Redis. With create, a k no process has made yet is made here, and if another process
// makes it first, its k is the one read: the SET NX is where the fleet agrees. found is false only
// without create, when Redis holds no k for day.
func (self *mxClosedHandshakes) fetch(ctx context.Context, day int64, create bool) (dayKey []byte, created bool, found bool, err error) {
	name := mxDailyKeyName(day)
	value, found, err := self.redis.Get(ctx, name)
	if err != nil {
		return nil, false, false, err
	}
	if !found && create {
		candidate := make([]byte, mxDailyKeyByteCount)
		if _, err := rand.Read(candidate); err != nil {
			return nil, false, false, err
		}
		testHookSecret("K_mxc_day", candidate)
		testHookBarrier("mxedge.daily_key_create.before", "")
		set, err := self.redis.SetIfAbsent(ctx, name, candidate, mxDailyKeyTtl)
		testHookBarrier("mxedge.daily_key_create.after", "")
		if err != nil {
			return nil, false, false, err
		}
		if set {
			return candidate, true, true, nil
		}
		value, found, err = self.redis.Get(ctx, name)
		if err != nil {
			return nil, false, false, err
		}
		if !found {
			// made and gone between two calls, which only a lost key does: the next probe makes another
			return nil, false, false, errMxNoDailyKey
		}
	}
	if !found {
		return nil, false, false, nil
	}
	if len(value) != mxDailyKeyByteCount {
		return nil, false, false, errMxDailyKeyMalformed
	}
	return value, false, true, nil
}

// Holds dayKey as day's k, replacing what was held, since after a lost k the fleet converges on the one
// Redis holds now. A k this process did not create reaches the hooks the first time it is held.
func (self *mxClosedHandshakes) hold(day int64, dayKey []byte, created bool) {
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.absentDays, day)
		if bytes.Equal(self.dayKeys[day], dayKey) {
			return false
		}
		self.dayKeys[day] = dayKey
		return true
	}()
	if changed && !created {
		testHookSecret("K_mxc_day", dayKey)
	}
}

// Day's k, or nil when it is not held.
func (self *mxClosedHandshakes) heldKey(day int64) []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.dayKeys[day]
}

// Remembers a closed handshake from sender's /24 or /48, under today's k. A failure leaves nothing to do
// but count it: the sender's retry then finds no memory, the outcome a lost key has.
func (self *mxClosedHandshakes) Record(ctx context.Context, sender netip.Addr) error {
	dayKey := self.heldKey(mxUtcDay(self.clock.Now()))
	if dayKey == nil {
		return errMxNoDailyKey
	}
	_, aggregate := mxSenderPrefixes(sender)
	key := mxClosedHandshakeKey(dayKey, aggregate)
	testHookBarrier("mxedge.closed_handshake_write.before", "")
	err := self.redis.Set(ctx, key, []byte(mxClosedHandshakeValue), self.ttl)
	testHookBarrier("mxedge.closed_handshake_write.after", "")
	return err
}

// Whether sender's /24 or /48 closed a handshake within the ttl, as far as an answer says, and whether
// one could be had at all. Anything but a clean miss under every k an entry may be under reads as
// recent: a k not held as much as a Redis error.
func (self *mxClosedHandshakes) Recent(ctx context.Context, sender netip.Addr) (recent bool, answered bool) {
	now := self.clock.Now()
	today := mxUtcDay(now)
	var dayKeys [][]byte
	known := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		todayKey := self.dayKeys[today]
		if todayKey == nil {
			return false
		}
		dayKeys = append(dayKeys, todayKey)
		if self.yesterdayNeeded(now) && !self.absentDays[today-1] {
			yesterdayKey := self.dayKeys[today-1]
			if yesterdayKey == nil {
				return false
			}
			dayKeys = append(dayKeys, yesterdayKey)
		}
		return true
	}()
	if !known {
		return true, false
	}
	_, aggregate := mxSenderPrefixes(sender)
	testHookBarrier("mxedge.closed_handshake_read.before", "")
	defer testHookBarrier("mxedge.closed_handshake_read.after", "")
	for _, dayKey := range dayKeys {
		_, found, err := self.redis.Get(ctx, mxClosedHandshakeKey(dayKey, aggregate))
		if err != nil {
			return true, false
		}
		if found {
			return true, true
		}
	}
	return false, true
}
