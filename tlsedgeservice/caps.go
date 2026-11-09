// §13.9's caps, which protect the devices that do the handshakes, all in memory on the engine's clock:
// nothing here reads a store, Redis or Quota, so a connection over a cap costs one lock (I-12).
//
//   - Process: max_connections at once, taken before a hello is read.
//   - Endpoint, keyed (network, host, port): connections at once at ceil(cap ÷ blocks) with no shared
//     counter, new connections on this process's token bucket at the full rate, and bandwidth on a
//     bucket the splice draws at ceil(cap ÷ blocks) (reading 12).
//   - Visitor, per process: per /64 or /32 a count at once and a token bucket of new connections, and
//     the aggregate multiple of both per /48 or /24, keyed by TlsVisitorKeys' hashes, never by address.
//
// A connection takes every cap it meets in one step or none of them, so a refusal counts nothing. A
// cap never touches a connection already admitted, except the bandwidth bucket its splice draws.
//
// Every map is bounded. Counts at once hold only what is open, an entry going at zero, so the process cap
// bounds them. Token buckets outlive their connections, since a rate is about connections gone, so each
// map of them holds at most its settings' count, the oldest going first: an evicted bucket is a full one
// again, which can only admit sooner. A visitor key rotation drops every visitor entry, and a connection
// admitted under the old keys gives back only what it took from maps that still hold it, so no count can
// go below what is open.
//
// Safe for concurrent use.

package tlsedgeservice

import (
	"net/netip"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// Which cap refused a connection, a metric's result. Empty admits.
type TlsCapRefusal string

const (
	TlsCapRefusalNone                 TlsCapRefusal = ""
	TlsCapRefusalProcess              TlsCapRefusal = "process"
	TlsCapRefusalNoVisitor            TlsCapRefusal = "no_visitor"
	TlsCapRefusalVisitor              TlsCapRefusal = "visitor"
	TlsCapRefusalVisitorAggregate     TlsCapRefusal = "visitor_aggregate"
	TlsCapRefusalVisitorRate          TlsCapRefusal = "visitor_rate"
	TlsCapRefusalVisitorAggregateRate TlsCapRefusal = "visitor_aggregate_rate"
	TlsCapRefusalEndpoint             TlsCapRefusal = "endpoint"
	TlsCapRefusalEndpointRate         TlsCapRefusal = "endpoint_rate"
	TlsCapRefusalEndpointBandwidth    TlsCapRefusal = "endpoint_bandwidth"
)

// An endpoint, the unit §13.9's endpoint caps count by.
type tlsEndpointKey struct {
	networkId sidecar.Id
	host      string
	port      int
}

// An endpoint's connections open in this process, and the bandwidth bucket they share.
type tlsEndpointOpen struct {
	count  int64
	bucket *TlsBandwidthBucket
}

// A token bucket of new connections, refilled at a rate a second up to one second's worth.
type tlsRateBucket struct {
	tokens float64
	last   time.Time
}

// The tokens a bucket holds at now under rate, a new bucket full.
func (self *tlsRateBucket) available(now time.Time, rate int64) float64 {
	tokens := self.tokens
	if elapsed := now.Sub(self.last).Seconds(); 0 < elapsed {
		tokens += elapsed * float64(rate)
	}
	return min(float64(rate), tokens)
}

// Token buckets by key, at most maxCount of them, the oldest going first.
type tlsRateBuckets[K comparable] struct {
	maxCount int
	buckets  map[K]*tlsRateBucket
	queue    []K
}

func newTlsRateBuckets[K comparable](maxCount int) *tlsRateBuckets[K] {
	return &tlsRateBuckets[K]{maxCount: maxCount, buckets: map[K]*tlsRateBucket{}}
}

// Whether key's bucket holds a token at now under rate. -1 is none and always holds one; 0 never does.
func (self *tlsRateBuckets[K]) hasToken(key K, now time.Time, rate int64) bool {
	if rate == tlsLimitNone {
		return true
	}
	if rate <= 0 {
		return false
	}
	bucket, ok := self.buckets[key]
	if !ok {
		return true
	}
	return 1 <= bucket.available(now, rate)
}

// Takes one of key's tokens at now, after hasToken said there is one, and returns how many buckets the
// bound evicted.
func (self *tlsRateBuckets[K]) take(key K, now time.Time, rate int64) int {
	if rate == tlsLimitNone {
		return 0
	}
	evictedCount := 0
	bucket, ok := self.buckets[key]
	if !ok {
		for self.maxCount <= len(self.buckets) && 0 < len(self.queue) {
			if _, held := self.buckets[self.queue[0]]; held {
				delete(self.buckets, self.queue[0])
				evictedCount += 1
			}
			self.queue = self.queue[1:]
		}
		bucket = &tlsRateBucket{tokens: float64(rate), last: now}
		self.buckets[key] = bucket
		self.queue = append(self.queue, key)
	}
	bucket.tokens = bucket.available(now, rate) - 1
	bucket.last = now
	return evictedCount
}

// What one connection holds of the caps. Give it back with Release.
type TlsCapHold struct {
	// in the visitor maps of this generation
	visitorGeneration uint64
	visitor           [tlsVisitorHashByteCount]byte
	aggregate         [tlsVisitorHashByteCount]byte
	inVisitor         bool
	endpoint          tlsEndpointKey
	inEndpoint        bool
	// the endpoint's bandwidth bucket, nil until admitted to one or when its bandwidth is none
	bucket   *TlsBandwidthBucket
	released bool
}

// The bandwidth bucket the connection's splice draws on, nil when its endpoint's bandwidth is none.
func (self *TlsCapHold) Bandwidth() *TlsBandwidthBucket {
	return self.bucket
}

// The caps of one process. See the file header.
type TlsEdgeCaps struct {
	settings    *TlsEdgeSettings
	clock       sidecar.Clock
	visitorKeys *TlsVisitorKeys

	stateLock       sync.Mutex
	connectionCount int64
	// the visitor key generation the visitor maps are under
	visitorGeneration uint64
	visitorCounts     map[[tlsVisitorHashByteCount]byte]int64
	aggregateCounts   map[[tlsVisitorHashByteCount]byte]int64
	visitorRates      *tlsRateBuckets[[tlsVisitorHashByteCount]byte]
	aggregateRates    *tlsRateBuckets[[tlsVisitorHashByteCount]byte]
	endpointOpens     map[tlsEndpointKey]*tlsEndpointOpen
	endpointRates     *tlsRateBuckets[tlsEndpointKey]
	evictedCount      int
}

// Caps with nothing counted, keying visitors by visitorKeys.
func NewTlsEdgeCaps(settings *TlsEdgeSettings, clock sidecar.Clock, visitorKeys *TlsVisitorKeys) *TlsEdgeCaps {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &TlsEdgeCaps{
		settings:        settings,
		clock:           clock,
		visitorKeys:     visitorKeys,
		visitorCounts:   map[[tlsVisitorHashByteCount]byte]int64{},
		aggregateCounts: map[[tlsVisitorHashByteCount]byte]int64{},
		visitorRates:    newTlsRateBuckets[[tlsVisitorHashByteCount]byte](settings.VisitorRateMaxCount),
		aggregateRates:  newTlsRateBuckets[[tlsVisitorHashByteCount]byte](settings.VisitorRateMaxCount),
		endpointOpens:   map[tlsEndpointKey]*tlsEndpointOpen{},
		endpointRates:   newTlsRateBuckets[tlsEndpointKey](settings.EndpointRateMaxCount),
	}
}

// Takes a process slot, §13.5's step 1, before the hello is read. A refused connection holds nothing.
func (self *TlsEdgeCaps) AdmitProcess() (*TlsCapHold, TlsCapRefusal) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if int64(self.settings.MaxConnectionCount) <= self.connectionCount {
		return nil, TlsCapRefusalProcess
	}
	self.connectionCount += 1
	return &TlsCapHold{}, TlsCapRefusalNone
}

// Whether a count at once has room under a cap: -1 is none, and 0 has none.
func tlsCountFits(count int64, cap int64) bool {
	return cap == tlsLimitNone || count < cap
}

// Counts a connection the process admitted against its visitor's and its endpoint's caps under limits,
// §13.5's step 3, all of them or none, or says which refused it. A hold admits once.
func (self *TlsEdgeCaps) Admit(hold *TlsCapHold, visitor netip.Addr, target *TlsEdgeTarget, limits *TlsEndpointLimits) TlsCapRefusal {
	now := self.clock.Now()
	endpoint := tlsEndpointKey{networkId: target.NetworkId, host: target.Host, port: target.Port}
	visitorAggregateConcurrent := tlsAggregateCap(limits.VisitorConcurrent, limits.VisitorAggregateMultiple)
	visitorAggregateNewPerS := tlsAggregateCap(limits.VisitorNewPerS, limits.VisitorAggregateMultiple)
	endpointConcurrent := tlsBlockShare(limits.EndpointConcurrent, self.settings.Blocks)
	// Mbit/s to bytes a second, then this process's share
	endpointBytesPerS := limits.EndpointMbitPerS
	if 0 < endpointBytesPerS {
		endpointBytesPerS = tlsBlockShare(endpointBytesPerS*1000*1000/8, self.settings.Blocks)
	}

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if hold.released || hold.inVisitor || hold.inEndpoint {
		return TlsCapRefusalProcess
	}
	// read under the lock, so two admits across a rotation cannot move the generation back
	capKeys, ok := self.visitorKeys.CapKeys(visitor)
	if !ok {
		return TlsCapRefusalNoVisitor
	}
	if capKeys.Generation != self.visitorGeneration {
		// a rotation: yesterday's keys find nothing, so nothing under them is kept
		clear(self.visitorCounts)
		clear(self.aggregateCounts)
		self.visitorRates = newTlsRateBuckets[[tlsVisitorHashByteCount]byte](self.settings.VisitorRateMaxCount)
		self.aggregateRates = newTlsRateBuckets[[tlsVisitorHashByteCount]byte](self.settings.VisitorRateMaxCount)
		self.visitorGeneration = capKeys.Generation
	}
	switch {
	case !tlsCountFits(self.visitorCounts[capKeys.Visitor], limits.VisitorConcurrent):
		return TlsCapRefusalVisitor
	case !tlsCountFits(self.aggregateCounts[capKeys.Aggregate], visitorAggregateConcurrent):
		return TlsCapRefusalVisitorAggregate
	case !self.visitorRates.hasToken(capKeys.Visitor, now, limits.VisitorNewPerS):
		return TlsCapRefusalVisitorRate
	case !self.aggregateRates.hasToken(capKeys.Aggregate, now, visitorAggregateNewPerS):
		return TlsCapRefusalVisitorAggregateRate
	case endpointBytesPerS == 0:
		// not included (§20.5)
		return TlsCapRefusalEndpointBandwidth
	}
	open := self.endpointOpens[endpoint]
	openCount := int64(0)
	if open != nil {
		openCount = open.count
	}
	switch {
	case !tlsCountFits(openCount, endpointConcurrent):
		return TlsCapRefusalEndpoint
	case !self.endpointRates.hasToken(endpoint, now, limits.EndpointNewPerS):
		return TlsCapRefusalEndpointRate
	}

	self.visitorCounts[capKeys.Visitor] += 1
	self.aggregateCounts[capKeys.Aggregate] += 1
	self.evictedCount += self.visitorRates.take(capKeys.Visitor, now, limits.VisitorNewPerS)
	self.evictedCount += self.aggregateRates.take(capKeys.Aggregate, now, visitorAggregateNewPerS)
	self.evictedCount += self.endpointRates.take(endpoint, now, limits.EndpointNewPerS)
	if open == nil {
		open = &tlsEndpointOpen{}
		if 0 < endpointBytesPerS {
			open.bucket = newTlsBandwidthBucket(endpointBytesPerS, self.settings.BandwidthBurst, now)
		}
		self.endpointOpens[endpoint] = open
	} else if open.bucket != nil && open.bucket.Rate() != endpointBytesPerS {
		// the network's limits moved: the shared bucket takes the new rate
		func() {
			open.bucket.stateLock.Lock()
			defer open.bucket.stateLock.Unlock()
			open.bucket.setRateWithLock(endpointBytesPerS, self.settings.BandwidthBurst)
		}()
	}
	open.count += 1
	hold.visitorGeneration = capKeys.Generation
	hold.visitor = capKeys.Visitor
	hold.aggregate = capKeys.Aggregate
	hold.inVisitor = true
	hold.endpoint = endpoint
	hold.inEndpoint = true
	hold.bucket = open.bucket
	return TlsCapRefusalNone
}

// Takes one from a count, dropping the entry at zero so a map holds only what is open.
func tlsCapDecrement[K comparable](counts map[K]int64, key K) {
	if counts[key] <= 1 {
		delete(counts, key)
		return
	}
	counts[key] -= 1
}

// Gives back everything a hold took, at the connection's end. A second call does nothing, and a hold
// from before a visitor key rotation gives nothing to the new maps, so no count goes below what is open.
func (self *TlsEdgeCaps) Release(hold *TlsCapHold) {
	if hold == nil {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if hold.released {
		return
	}
	hold.released = true
	self.connectionCount -= 1
	if hold.inVisitor && hold.visitorGeneration == self.visitorGeneration {
		tlsCapDecrement(self.visitorCounts, hold.visitor)
		tlsCapDecrement(self.aggregateCounts, hold.aggregate)
	}
	if hold.inEndpoint {
		if open, ok := self.endpointOpens[hold.endpoint]; ok {
			open.count -= 1
			if open.count <= 0 {
				delete(self.endpointOpens, hold.endpoint)
			}
		}
	}
}

// Connections the process holds now.
func (self *TlsEdgeCaps) ConnectionCount() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.connectionCount
}

// Token buckets the bounds evicted before their time, since the caps were made.
func (self *TlsEdgeCaps) EvictedCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.evictedCount
}
