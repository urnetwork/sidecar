// The keys tlsedge holds a visitor by, so no map, record or metric holds an address (§13.9, §2.8 tls-2
// and tls-3, I-13). Each is an HMAC-SHA256 of the visitor's prefix under a key of one UTC day, never
// written anywhere but Redis's daily key below: a map built on yesterday's key holds nothing that
// today's can find, so a rotation drops every cap entry, and once a day's key is gone no one can compute
// that day's hashes again.
//
//   - Cap keys (tls-2): per process, as §13.9's table has them, over the visitor's /64 or /32 and the
//     /48 or /24 above it, under a key this process draws at random each UTC day.
//   - The record hash (tls-3) and Find's affinity key (§9.7, sock-2): the visitor's /24 or /48,
//     HMAC-SHA256(k, family byte || prefix) cut to 16 bytes, k being k_record or k_affinity, derived by
//     HKDF-SHA256 with infos urnetwork-sidecar-v1/tls-visitor-record and
//     urnetwork-sidecar-v1/tls-visitor-affinity from the fleet's daily key, as plan-TLS-visitor-hash-key
//     settles it: 32 random bytes in Redis at {vhk}tls:<yyyymmdd> (UTC), which the day's first process
//     creates with SET NX and a 25 h ttl and every process reads again each VisitorKeyRefreshInterval and
//     at the date change (Refresh). So one visitor's records link, and its Finds keep their affinity,
//     across every tlsedge process for a day. A process that has not read today's key from Redis uses a
//     random key of its own for that day, the closed direction: its records link only within itself and
//     its affinity is its own, and nothing is refused for it.
//
// An IPv4-mapped IPv6 address is its IPv4 address, or one visitor would count against two sets of caps.
// The family byte is 4 or 6. Safe for concurrent use.

package tlsedgeservice

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// Formats, not tunables: the daily key's length, a key's and a record hash's length (tls-3: 16 bytes),
// the HKDF infos, the fleet key's name, and the prefixes §13.9 and tls-3 count by.
const (
	tlsVisitorDailyKeyByteCount = 32
	tlsVisitorHashByteCount     = 16
	tlsVisitorCapKeyInfo        = "urnetwork-sidecar-v1/tls-visitor-cap"
	tlsVisitorRecordKeyInfo     = "urnetwork-sidecar-v1/tls-visitor-record"
	tlsVisitorAffinityKeyInfo   = "urnetwork-sidecar-v1/tls-visitor-affinity"
	// The fleet's daily key's name before its date: the {vhk} family's tag, then tlsedge's own name in
	// it, so mxedge's {vhk}mx: keys and these never meet.
	tlsVisitorFleetKeyPrefix = "{vhk}tls:"
	// Go's layout for the date in the name, yyyymmdd.
	tlsVisitorFleetKeyDateLayout = "20060102"
	tlsVisitorFamilyIpv4         = 4
	tlsVisitorFamilyIpv6         = 6
	tlsVisitorIpv4Bits           = 32
	tlsVisitorIpv4AggregateBits  = 24
	tlsVisitorIpv6Bits           = 64
	tlsVisitorIpv6AggregateBits  = 48
	// A UTC day, which has no leap second in Unix time.
	tlsSecondsPerDay = 24 * 60 * 60
)

// Redis holds something under the fleet key's name that is not 32 bytes, which nothing here writes.
var errTlsVisitorFleetKeyMalformed = errors.New("the visitor-hash daily key is not 32 bytes")

// Redis lost the fleet key between this process's create and its read, which only a lost key does.
var errTlsVisitorFleetKeyLost = errors.New("the visitor-hash daily key was lost")

// How a Refresh went, a metric's result.
const (
	// This process made today's key.
	tlsVisitorKeyResultCreated = "created"
	// Today's key was in Redis.
	tlsVisitorKeyResultRead = "read"
	// Redis did not answer, or held no key this process could use: the process's own key serves today.
	tlsVisitorKeyResultFailed = "failed"
)

// A visitor as the caps count it: keyed hashes of its /64 or /32 and of the /48 or /24 above it, under
// the day's key of Generation.
type TlsVisitorCapKeys struct {
	// Rises at each rotation, so a hold from before one leaves today's maps alone.
	Generation uint64
	Visitor    [tlsVisitorHashByteCount]byte
	Aggregate  [tlsVisitorHashByteCount]byte
}

// The day's keys. See the file header.
type TlsVisitorKeys struct {
	clock sidecar.Clock
	// The UTC day of the newest fleet key a Refresh has held, 0 before the first, so a wait can see one land.
	fleetDayHeld *sidecar.MonitorValue[int64]

	stateLock sync.Mutex
	// the UTC day the process's own keys are for, as days since the epoch
	day        int64
	generation uint64
	capKey     []byte
	// the process's own k_record and k_affinity, which serve while the fleet's are not held for today
	recordKey   []byte
	affinityKey []byte
	// the fleet's, derived from {vhk}tls:<yyyymmdd>, for fleetDay alone
	fleetDay         int64
	fleetRecordKey   []byte
	fleetAffinityKey []byte
}

// Keys drawn at the first use, for the clock's day. nil is real time.
func NewTlsVisitorKeys(clock sidecar.Clock) *TlsVisitorKeys {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &TlsVisitorKeys{clock: clock, fleetDayHeld: sidecar.NewMonitorValue(int64(0))}
}

// The UTC day t falls in, as days since the epoch.
func tlsUtcDay(t time.Time) int64 {
	seconds := t.Unix()
	day := seconds / tlsSecondsPerDay
	// division rounds toward zero, and a day before the epoch must round down
	if seconds%tlsSecondsPerDay < 0 {
		day -= 1
	}
	return day
}

// The first instant of day.
func tlsUtcDayStart(day int64) time.Time {
	return time.Unix(day*tlsSecondsPerDay, 0).UTC()
}

// Where day's fleet key lives in Redis.
func TlsVisitorFleetKeyName(day time.Time) string {
	return tlsVisitorFleetKeyPrefix + day.UTC().Format(tlsVisitorFleetKeyDateLayout)
}

// The keys HKDF-SHA256 derives from a daily key under info, which never fails for these lengths:
// HKDF-SHA256 gives up to 8,160 bytes.
func tlsVisitorDerive(dailyKey []byte, info string) []byte {
	key, _ := hkdf.Key(sha256.New, dailyKey, nil, info, tlsVisitorDailyKeyByteCount)
	return key
}

// Today's keys and the cap keys' generation, the process's own drawn anew at the first use of each UTC
// day, and the record and affinity keys the fleet's when a Refresh holds them for today.
func (self *TlsVisitorKeys) keys() (generation uint64, capKey []byte, recordKey []byte, affinityKey []byte) {
	day := tlsUtcDay(self.clock.Now())
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.capKey == nil || self.day != day {
		dailyKey := make([]byte, tlsVisitorDailyKeyByteCount)
		// crypto/rand's Read never fails (crypto/rand docs)
		rand.Read(dailyKey)
		testHookSecret("tls_visitor_daily", dailyKey)
		capKey := tlsVisitorDerive(dailyKey, tlsVisitorCapKeyInfo)
		testHookSecret("tls_visitor_cap", capKey)
		recordKey := tlsVisitorDerive(dailyKey, tlsVisitorRecordKeyInfo)
		testHookSecret("tls_visitor_record", recordKey)
		affinityKey := tlsVisitorDerive(dailyKey, tlsVisitorAffinityKeyInfo)
		testHookSecret("tls_visitor_affinity", affinityKey)
		clear(dailyKey)
		self.day = day
		self.generation += 1
		self.capKey = capKey
		self.recordKey = recordKey
		self.affinityKey = affinityKey
	}
	if self.fleetRecordKey != nil && self.fleetDay == day {
		return self.generation, self.capKey, self.fleetRecordKey, self.fleetAffinityKey
	}
	return self.generation, self.capKey, self.recordKey, self.affinityKey
}

// The visitor's address as the caps count it: IPv4 when it is IPv4-mapped, with no zone, and false for
// an address that is none.
func tlsVisitorAddr(visitor netip.Addr) (netip.Addr, bool) {
	if !visitor.IsValid() {
		return netip.Addr{}, false
	}
	return visitor.Unmap().WithZone(""), true
}

// HMAC-SHA256(key, family byte || prefix length byte || the prefix's bytes) cut to 16 bytes, the length
// byte telling a /64 from a /48 of the same family.
func tlsVisitorHash(key []byte, prefix netip.Prefix, withLength bool) [tlsVisitorHashByteCount]byte {
	family := byte(tlsVisitorFamilyIpv6)
	if prefix.Addr().Is4() {
		family = tlsVisitorFamilyIpv4
	}
	addressBytes := prefix.Addr().AsSlice()
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte{family})
	if withLength {
		mac.Write([]byte{byte(prefix.Bits())})
	}
	mac.Write(addressBytes[:prefix.Bits()/8])
	var hash [tlsVisitorHashByteCount]byte
	copy(hash[:], mac.Sum(nil))
	return hash
}

// The /64 or /32 a visitor counts by, and the /48 or /24 above it.
func tlsVisitorPrefixes(visitor netip.Addr) (netip.Prefix, netip.Prefix) {
	visitorBits, aggregateBits := tlsVisitorIpv6Bits, tlsVisitorIpv6AggregateBits
	if visitor.Is4() {
		visitorBits, aggregateBits = tlsVisitorIpv4Bits, tlsVisitorIpv4AggregateBits
	}
	// neither fails: each bit count fits the family chosen above
	visitorPrefix, _ := visitor.Prefix(visitorBits)
	aggregatePrefix, _ := visitor.Prefix(aggregateBits)
	return visitorPrefix, aggregatePrefix
}

// The visitor's cap keys under today's cap key, and false for an address that is none.
func (self *TlsVisitorKeys) CapKeys(visitor netip.Addr) (*TlsVisitorCapKeys, bool) {
	visitor, ok := tlsVisitorAddr(visitor)
	if !ok {
		return nil, false
	}
	generation, capKey, _, _ := self.keys()
	visitorPrefix, aggregatePrefix := tlsVisitorPrefixes(visitor)
	return &TlsVisitorCapKeys{
		Generation: generation,
		Visitor:    tlsVisitorHash(capKey, visitorPrefix, true),
		Aggregate:  tlsVisitorHash(capKey, aggregatePrefix, true),
	}, true
}

// tls-3's visitor hash: the visitor's /24 or /48 under today's k_record, 16 bytes, and nil for an
// address that is none.
func (self *TlsVisitorKeys) RecordHash(visitor netip.Addr) []byte {
	visitor, ok := tlsVisitorAddr(visitor)
	if !ok {
		return nil
	}
	_, _, recordKey, _ := self.keys()
	_, aggregatePrefix := tlsVisitorPrefixes(visitor)
	hash := tlsVisitorHash(recordKey, aggregatePrefix, false)
	return hash[:]
}

// §9.7's affinity key Find takes: the visitor's /24 or /48 under today's k_affinity, 16 bytes, and nil
// for an address that is none. Stable within its key's day, in every process once the fleet's key is
// held, and never stored.
func (self *TlsVisitorKeys) AffinityKey(visitor netip.Addr) []byte {
	visitor, ok := tlsVisitorAddr(visitor)
	if !ok {
		return nil
	}
	_, _, _, affinityKey := self.keys()
	_, aggregatePrefix := tlsVisitorPrefixes(visitor)
	hash := tlsVisitorHash(affinityKey, aggregatePrefix, false)
	return hash[:]
}

// The generation of today's keys, drawing them if the day has turned.
func (self *TlsVisitorKeys) Generation() uint64 {
	generation, _, _, _ := self.keys()
	return generation
}

// The UTC day of the newest fleet key held, 0 before the first, and a channel that closes at the next.
func (self *TlsVisitorKeys) FleetDay() (day int64, changed chan struct{}) {
	return self.fleetDayHeld.Get()
}

// Whether the record and affinity keys are the fleet's for the clock's day.
func (self *TlsVisitorKeys) FleetHeld() bool {
	day := tlsUtcDay(self.clock.Now())
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.fleetRecordKey != nil && self.fleetDay == day
}

// Reads today's fleet key from redis, creating it with SET NX and ttl when no process has yet, and holds
// what derives from it for today. The SET NX is where the fleet agrees: when another process made the
// key first, its key is the one read. An error keeps what is held, so a key already held for today still
// serves, and a day whose key is not held uses the process's own (see the file header). Called by the
// engine's loop, never on a connection's path.
func (self *TlsVisitorKeys) Refresh(ctx context.Context, redis sidecar.Redis, ttl time.Duration) (result string, err error) {
	day := tlsUtcDay(self.clock.Now())
	name := TlsVisitorFleetKeyName(tlsUtcDayStart(day))
	testHookBarrier("tlsedge.visitor_key_read.before", "")
	value, found, err := redis.Get(ctx, name)
	testHookBarrier("tlsedge.visitor_key_read.after", "")
	if err != nil {
		return tlsVisitorKeyResultFailed, err
	}
	created := false
	if !found {
		candidate := make([]byte, tlsVisitorDailyKeyByteCount)
		// crypto/rand's Read never fails (crypto/rand docs)
		rand.Read(candidate)
		testHookSecret("tls_visitor_fleet_daily", candidate)
		testHookBarrier("tlsedge.visitor_key_create.before", "")
		set, err := redis.SetIfAbsent(ctx, name, candidate, ttl)
		testHookBarrier("tlsedge.visitor_key_create.after", "")
		if err != nil {
			return tlsVisitorKeyResultFailed, err
		}
		if set {
			value, created = candidate, true
		} else {
			value, found, err = redis.Get(ctx, name)
			if err != nil {
				return tlsVisitorKeyResultFailed, err
			}
			if !found {
				return tlsVisitorKeyResultFailed, errTlsVisitorFleetKeyLost
			}
		}
	}
	if len(value) != tlsVisitorDailyKeyByteCount {
		return tlsVisitorKeyResultFailed, errTlsVisitorFleetKeyMalformed
	}
	if !created {
		testHookSecret("tls_visitor_fleet_daily", value)
	}
	recordKey := tlsVisitorDerive(value, tlsVisitorRecordKeyInfo)
	testHookSecret("tls_visitor_fleet_record", recordKey)
	affinityKey := tlsVisitorDerive(value, tlsVisitorAffinityKeyInfo)
	testHookSecret("tls_visitor_fleet_affinity", affinityKey)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.fleetDay = day
		self.fleetRecordKey = recordKey
		self.fleetAffinityKey = affinityKey
	}()
	self.fleetDayHeld.Set(day)
	if created {
		return tlsVisitorKeyResultCreated, nil
	}
	return tlsVisitorKeyResultRead, nil
}

// How long from now until the next UTC date begins, when the fleet's key must be read again.
func (self *TlsVisitorKeys) untilNextDay() time.Duration {
	now := self.clock.Now()
	return tlsUtcDayStart(tlsUtcDay(now) + 1).Sub(now)
}
