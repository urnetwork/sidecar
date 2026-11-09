// The keys tlsedge holds a visitor by, so no map, record or metric holds an address (§13.9, §2.8 tls-2
// and tls-3, I-13). Each is an HMAC-SHA256 of the visitor's prefix under a key this process draws at
// random for each UTC day and never writes anywhere: a map built on yesterday's key holds nothing that
// today's can find, so a rotation drops every cap entry, and once a day's key is gone no one can
// compute that day's hashes again.
//
//   - Cap keys (tls-2): per process, as §13.9's table has them, over the visitor's /64 or /32 and the
//     /48 or /24 above it.
//   - The record hash (tls-3): the visitor's /24 or /48, HMAC-SHA256(k_record, family byte || prefix)
//     cut to 16 bytes, k_record derived by HKDF-SHA256 with info urnetwork-sidecar-v1/tls-visitor-record,
//     as plan-TLS-visitor-hash-key words it. That answer moves k_record's daily key to the fleet's
//     {vhk}tls:<yyyymmdd>, so one visitor links across processes; its interim keeps it per process until
//     the {vhk} family has its §2.8 row, so for now records link a visitor only within one process.
//
// An IPv4-mapped IPv6 address is its IPv4 address, or one visitor would count against two sets of caps.
// The family byte is 4 or 6. Safe for concurrent use.

package tlsedgeservice

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"net/netip"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// Formats, not tunables: the daily key's length, a key's and a record hash's length (tls-3: 16 bytes),
// the HKDF infos, and the prefixes §13.9 counts by.
const (
	tlsVisitorDailyKeyByteCount = 32
	tlsVisitorHashByteCount     = 16
	tlsVisitorCapKeyInfo        = "urnetwork-sidecar-v1/tls-visitor-cap"
	tlsVisitorRecordKeyInfo     = "urnetwork-sidecar-v1/tls-visitor-record"
	tlsVisitorFamilyIpv4        = 4
	tlsVisitorFamilyIpv6        = 6
	tlsVisitorIpv4Bits          = 32
	tlsVisitorIpv4AggregateBits = 24
	tlsVisitorIpv6Bits          = 64
	tlsVisitorIpv6AggregateBits = 48
	// A UTC day, which has no leap second in Unix time.
	tlsSecondsPerDay = 24 * 60 * 60
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

	stateLock sync.Mutex
	// the UTC day the keys are for, as days since the epoch
	day        int64
	generation uint64
	capKey     []byte
	recordKey  []byte
}

// Keys drawn at the first use, for the clock's day. nil is real time.
func NewTlsVisitorKeys(clock sidecar.Clock) *TlsVisitorKeys {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &TlsVisitorKeys{clock: clock}
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

// Today's two keys and their generation, drawn anew at the first use of each UTC day.
func (self *TlsVisitorKeys) keys() (generation uint64, capKey []byte, recordKey []byte) {
	day := tlsUtcDay(self.clock.Now())
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.capKey == nil || self.day != day {
		dailyKey := make([]byte, tlsVisitorDailyKeyByteCount)
		// crypto/rand's Read never fails (crypto/rand docs)
		rand.Read(dailyKey)
		testHookSecret("tls_visitor_daily", dailyKey)
		// neither derivation fails: HKDF-SHA256 gives up to 8,160 bytes
		capKey, _ := hkdf.Key(sha256.New, dailyKey, nil, tlsVisitorCapKeyInfo, tlsVisitorDailyKeyByteCount)
		testHookSecret("tls_visitor_cap", capKey)
		recordKey, _ := hkdf.Key(sha256.New, dailyKey, nil, tlsVisitorRecordKeyInfo, tlsVisitorDailyKeyByteCount)
		testHookSecret("tls_visitor_record", recordKey)
		clear(dailyKey)
		self.day = day
		self.generation += 1
		self.capKey = capKey
		self.recordKey = recordKey
	}
	return self.generation, self.capKey, self.recordKey
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
	generation, capKey, _ := self.keys()
	visitorPrefix, aggregatePrefix := tlsVisitorPrefixes(visitor)
	return &TlsVisitorCapKeys{
		Generation: generation,
		Visitor:    tlsVisitorHash(capKey, visitorPrefix, true),
		Aggregate:  tlsVisitorHash(capKey, aggregatePrefix, true),
	}, true
}

// tls-3's visitor hash: the visitor's /24 or /48 under today's record key, 16 bytes, and nil for an
// address that is none.
func (self *TlsVisitorKeys) RecordHash(visitor netip.Addr) []byte {
	visitor, ok := tlsVisitorAddr(visitor)
	if !ok {
		return nil
	}
	_, _, recordKey := self.keys()
	_, aggregatePrefix := tlsVisitorPrefixes(visitor)
	hash := tlsVisitorHash(recordKey, aggregatePrefix, false)
	return hash[:]
}

// The generation of today's keys, drawing them if the day has turned.
func (self *TlsVisitorKeys) Generation() uint64 {
	generation, _, _ := self.keys()
	return generation
}
