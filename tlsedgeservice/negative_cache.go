// §13.5's 30 s negative cache, which absorbs scans: a Find that answered no_listener or denied refuses
// the same key again, in memory, without a Find, until its time passes. Nothing else is cached here, so
// a busy listener, a spent network or a closed gate is asked again on the next connection.
//
// The key is the mapped name, the port and the set of ALPN ids the visitor offered (reading 18), so a
// scanner offering a bogus id caches only its own set, and a visitor offering a served one still
// reaches Find. The set is order-free and stored as a keyed 64-bit hash, so a 16 KiB ALPN list costs an
// entry no more than a short one; the hash's seed is drawn per cache, so no visitor can aim a
// collision at another's set.
//
// Bounded: past NegativeCacheMaxCount the oldest entry goes. Every entry lives the same ttl, so oldest
// is also first to expire, and eviction only ever sends a key back to Find sooner. Time is the cache's
// injected clock. Safe for concurrent use.

package tlsedgeservice

import (
	"hash/maphash"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// Why a key is refused, the two answers §13.5 caches.
type TlsNegativeReason string

const (
	// Find found no listener for the name and the offered ALPN: internal_error.
	TlsNegativeNoListener TlsNegativeReason = "no_listener"
	// The projection does not let autogroup:public dial the name: unrecognized_name.
	TlsNegativeDenied TlsNegativeReason = "denied"
)

type tlsNegativeKey struct {
	name     string
	port     int
	alpnHash uint64
}

type tlsNegativeEntry struct {
	reason     TlsNegativeReason
	expireTime time.Time
}

// The order entries were added in, so the oldest can go first.
type tlsNegativeQueued struct {
	key        tlsNegativeKey
	expireTime time.Time
}

// The cache. See the file header.
type tlsNegativeCache struct {
	ttl      time.Duration
	maxCount int
	clock    sidecar.Clock
	seed     maphash.Seed

	stateLock sync.Mutex
	entries   map[tlsNegativeKey]*tlsNegativeEntry
	// oldest first; an item whose entry has since been replaced or removed is skipped when reached
	queue []tlsNegativeQueued
}

func newTlsNegativeCache(ttl time.Duration, maxCount int, clock sidecar.Clock) *tlsNegativeCache {
	return &tlsNegativeCache{
		ttl:      ttl,
		maxCount: maxCount,
		clock:    clock,
		seed:     maphash.MakeSeed(),
		entries:  map[tlsNegativeKey]*tlsNegativeEntry{},
	}
}

// The order-free hash of an offered ALPN list: the ids sorted, each written with its length first so
// that no two sets write the same bytes.
func (self *tlsNegativeCache) alpnHash(alpnIds []string) uint64 {
	sorted := alpnIds
	if !slices.IsSorted(alpnIds) {
		sorted = slices.Sorted(slices.Values(alpnIds))
	}
	var hash maphash.Hash
	hash.SetSeed(self.seed)
	var length [2]byte
	for _, id := range sorted {
		length[0] = byte(len(id) >> 8)
		length[1] = byte(len(id))
		hash.Write(length[:])
		hash.WriteString(id)
	}
	return hash.Sum64()
}

func (self *tlsNegativeCache) key(name string, port int, alpnIds []string) tlsNegativeKey {
	return tlsNegativeKey{name: name, port: port, alpnHash: self.alpnHash(alpnIds)}
}

// The reason a key is refused, or false when the cache holds nothing live for it.
func (self *tlsNegativeCache) Lookup(name string, port int, alpnIds []string) (TlsNegativeReason, bool) {
	key := self.key(name, port, alpnIds)
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry, ok := self.entries[key]
	if !ok {
		return "", false
	}
	if !now.Before(entry.expireTime) {
		delete(self.entries, key)
		return "", false
	}
	return entry.reason, true
}

// Refuses a key for the ttl from now. Any reason but the two cached ones is ignored. Returns how many
// live entries the bound evicted to make room.
func (self *tlsNegativeCache) Add(name string, port int, alpnIds []string, reason TlsNegativeReason) int {
	if reason != TlsNegativeNoListener && reason != TlsNegativeDenied {
		return 0
	}
	key := self.key(name, port, alpnIds)
	now := self.clock.Now()
	expireTime := now.Add(self.ttl)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	evictedCount := 0
	// drop what has expired from the front, then the oldest while the cache is full
	for 0 < len(self.queue) {
		front := self.queue[0]
		entry, ok := self.entries[front.key]
		current := ok && entry.expireTime.Equal(front.expireTime)
		if current && now.Before(front.expireTime) && (len(self.entries) < self.maxCount || front.key == key) {
			break
		}
		if current {
			delete(self.entries, front.key)
			if now.Before(front.expireTime) && front.key != key {
				evictedCount += 1
			}
		}
		self.queue = self.queue[1:]
	}
	self.entries[key] = &tlsNegativeEntry{reason: reason, expireTime: expireTime}
	self.queue = append(self.queue, tlsNegativeQueued{key: key, expireTime: expireTime})
	// a queue that drained its front keeps its old array; copy when the slack outgrows what is held
	if self.maxCount < cap(self.queue)-len(self.queue) {
		self.queue = slices.Clone(self.queue)
	}
	return evictedCount
}

// Entries held, live or not yet dropped.
func (self *tlsNegativeCache) Count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.entries)
}
