// §13.9's caps per network, as ServiceHost.Quota.Limits gives them, loaded off every connection's path
// and cached per network (reading 11): a connection reads the cache and never waits on Quota (I-12). A
// network the cache has not loaded yet gets ColdLimits, Community's caps, never a refusal for being
// cold. §21's tightening (network_sidecar_limit) arrives the same way, in the network's next load.
//
// Endpoint caps are tier quotas and visitor caps are sidecar_abuse: limits, equal on every tier but
// tightened per network by §21 (D-QUOTA-7). A value of -1 is none, §20.4's none, and 0 is not included,
// which refuses (§20.5): a limit this build reads as 0 fails closed.
//
// TlsBandwidthBucket is the token bucket an endpoint's splices draw on in this process, at cap ÷ blocks.
//
// Safe for concurrent use.

package tlsedgeservice

import (
	"context"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// The QuotaLimits keys of §13.9's caps (§20.4; reading 10).
const (
	tlsLimitKeyEndpointConcurrent       = "tls_endpoint_concurrent"
	tlsLimitKeyEndpointNewPerS          = "tls_endpoint_new_per_s"
	tlsLimitKeyEndpointMbitPerS         = "tls_endpoint_mbit_per_s"
	tlsLimitKeyVisitorConcurrent        = "tls_visitor_concurrent"
	tlsLimitKeyVisitorNewPerS           = "tls_visitor_new_per_s"
	tlsLimitKeyVisitorAggregateMultiple = "tls_visitor_aggregate_multiple"
	// QuotaLimits' none (§20.4).
	tlsLimitNone = int64(-1)
)

// One network's §13.9 caps, as the fleet states them: the per-process shares (cap ÷ blocks) are the
// caps' to take. -1 is none and 0 refuses.
type TlsEndpointLimits struct {
	// Connections open at once to one (host, port) across the fleet: 256 / 2,048 / 8,192.
	EndpointConcurrent int64
	// New connections a second to one (host, port), per process: 50 / 200 / 1,000.
	EndpointNewPerS int64
	// Bytes both ways through one (host, port) across the fleet, in Mbit/s: 20 / 200 / 1,000.
	EndpointMbitPerS int64
	// Connections open at once from one visitor /64 or /32, per process: 64.
	VisitorConcurrent int64
	// New connections a second from one visitor /64 or /32, per process: 20.
	VisitorNewPerS int64
	// Both visitor caps times this for the /48 or /24 above: 4.
	VisitorAggregateMultiple int64
}

// Community's caps (§13.9, §20.4's pro.yml): what a cold network gets.
func DefaultColdTlsEndpointLimits() *TlsEndpointLimits {
	return &TlsEndpointLimits{
		EndpointConcurrent:       256,
		EndpointNewPerS:          50,
		EndpointMbitPerS:         20,
		VisitorConcurrent:        64,
		VisitorNewPerS:           20,
		VisitorAggregateMultiple: 4,
	}
}

// The caps a QuotaLimits states. A key it lacks reads 0, so its cap refuses (§20.5).
func tlsEndpointLimitsFrom(quotaLimits *sidecar.QuotaLimits) *TlsEndpointLimits {
	value := func(key string) int64 {
		if quotaLimits == nil {
			return 0
		}
		return quotaLimits.Limits[key]
	}
	return &TlsEndpointLimits{
		EndpointConcurrent:       value(tlsLimitKeyEndpointConcurrent),
		EndpointNewPerS:          value(tlsLimitKeyEndpointNewPerS),
		EndpointMbitPerS:         value(tlsLimitKeyEndpointMbitPerS),
		VisitorConcurrent:        value(tlsLimitKeyVisitorConcurrent),
		VisitorNewPerS:           value(tlsLimitKeyVisitorNewPerS),
		VisitorAggregateMultiple: value(tlsLimitKeyVisitorAggregateMultiple),
	}
}

// A fleet-wide count's share in one process: ceil(cap ÷ blocks), at least 1 (reading 12). None and 0
// pass through as themselves.
func tlsBlockShare(fleetCap int64, blocks int) int64 {
	if fleetCap <= 0 {
		return fleetCap
	}
	return max(1, (fleetCap+int64(blocks)-1)/int64(blocks))
}

// A visitor cap times the aggregate multiple: 0 when either is not included, else none when either is
// none.
func tlsAggregateCap(visitorCap int64, multiple int64) int64 {
	switch {
	case visitorCap == 0 || multiple == 0:
		return 0
	case visitorCap == tlsLimitNone || multiple == tlsLimitNone:
		return tlsLimitNone
	}
	return visitorCap * multiple
}

// One network's cached caps.
type tlsCachedLimits struct {
	limits *TlsEndpointLimits
	// zero until a load answered
	loadTime time.Time
	usedTime time.Time
}

// The cache, filled by run.
type tlsEndpointLimitsCache struct {
	settings *TlsEdgeSettings
	quota    sidecar.Quota
	clock    sidecar.Clock
	// wakes run for a network asked for and not yet loaded
	wake chan struct{}
	// rises at each finished refresh pass, so a wait can see one land
	passCount *sidecar.MonitorValue[uint64]

	stateLock       sync.Mutex
	networkIdLimits map[sidecar.Id]*tlsCachedLimits
	networkIdQueue  []sidecar.Id
}

// An empty cache. quota may be nil, and then every network keeps ColdLimits.
func newTlsEndpointLimitsCache(settings *TlsEdgeSettings, quota sidecar.Quota, clock sidecar.Clock) *tlsEndpointLimitsCache {
	return &tlsEndpointLimitsCache{
		settings:        settings,
		quota:           quota,
		clock:           clock,
		wake:            make(chan struct{}, 1),
		passCount:       sidecar.NewMonitorValue(uint64(0)),
		networkIdLimits: map[sidecar.Id]*tlsCachedLimits{},
	}
}

// The network's caps as last loaded, or ColdLimits until one load answers. Marks the network in use, so
// the next pass loads or refreshes it. No I/O and no wait.
func (self *tlsEndpointLimitsCache) Limits(networkId sidecar.Id) *TlsEndpointLimits {
	now := self.clock.Now()
	limits, wake := func() (*TlsEndpointLimits, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cached, ok := self.networkIdLimits[networkId]
		if !ok {
			// bounded: past the bound the oldest network goes, which only makes it cold again
			for self.settings.LimitsMaxNetworkCount <= len(self.networkIdLimits) && 0 < len(self.networkIdQueue) {
				delete(self.networkIdLimits, self.networkIdQueue[0])
				self.networkIdQueue = self.networkIdQueue[1:]
			}
			cached = &tlsCachedLimits{}
			self.networkIdLimits[networkId] = cached
			self.networkIdQueue = append(self.networkIdQueue, networkId)
		}
		cached.usedTime = now
		if cached.limits == nil {
			return self.settings.ColdLimits, !ok
		}
		return cached.limits, false
	}()
	if wake {
		select {
		case self.wake <- struct{}{}:
		default:
		}
	}
	return limits
}

// Loads every network in use that is cold or older than LimitsRefreshInterval, and forgets those unused
// for LimitsActiveWindow, until ctx ends. A load that fails keeps what the network had, cold included.
// No lock is held across a Quota call.
func (self *tlsEndpointLimitsCache) run(ctx context.Context) {
	for {
		if self.quota != nil {
			self.refresh(ctx)
		}
		// armed before the pass is counted, so a wait that sees the count can move the clock past it
		next := self.clock.After(self.settings.LimitsRefreshInterval)
		self.passCount.Update(func(count uint64) uint64 { return count + 1 })
		select {
		case <-ctx.Done():
			return
		case <-self.wake:
		case <-next:
		}
	}
}

// One pass.
func (self *tlsEndpointLimitsCache) refresh(ctx context.Context) {
	now := self.clock.Now()
	networkIds := func() []sidecar.Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		networkIds := []sidecar.Id{}
		keptQueue := []sidecar.Id{}
		for _, networkId := range self.networkIdQueue {
			cached, ok := self.networkIdLimits[networkId]
			if !ok {
				continue
			}
			if self.settings.LimitsActiveWindow < now.Sub(cached.usedTime) {
				delete(self.networkIdLimits, networkId)
				continue
			}
			keptQueue = append(keptQueue, networkId)
			if cached.limits == nil || self.settings.LimitsRefreshInterval <= now.Sub(cached.loadTime) {
				networkIds = append(networkIds, networkId)
			}
		}
		self.networkIdQueue = keptQueue
		return networkIds
	}()
	for _, networkId := range networkIds {
		quotaLimits, err := func() (*sidecar.QuotaLimits, error) {
			callCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			stop := self.clock.AfterFunc(self.settings.StoreTimeout, cancel)
			defer stop()
			return self.quota.Limits(callCtx, connect.Id(networkId))
		}()
		if err != nil || quotaLimits == nil {
			continue
		}
		limits := tlsEndpointLimitsFrom(quotaLimits)
		loadTime := self.clock.Now()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if cached, ok := self.networkIdLimits[networkId]; ok {
				cached.limits = limits
				cached.loadTime = loadTime
			}
		}()
	}
}

// A token bucket an endpoint's splices draw bytes from, refilled at rate bytes a second up to burst. A
// draw takes what it needs at once, into debt if it must, and says how long its caller waits for the
// debt to clear, so a splice moves whole chunks and still holds the rate. Safe for concurrent use.
type TlsBandwidthBucket struct {
	stateLock sync.Mutex
	// bytes a second; 0 or less passes everything, which is none
	rate  float64
	burst float64
	// may go below zero: the debt draws have run up
	tokens float64
	last   time.Time
}

// A full bucket of rate bytes a second holding burstDuration of them, as of now.
func newTlsBandwidthBucket(rate int64, burstDuration time.Duration, now time.Time) *TlsBandwidthBucket {
	bucket := &TlsBandwidthBucket{last: now}
	bucket.setRateWithLock(rate, burstDuration)
	bucket.tokens = bucket.burst
	return bucket
}

func (self *TlsBandwidthBucket) setRateWithLock(rate int64, burstDuration time.Duration) {
	self.rate = float64(rate)
	self.burst = float64(rate) * burstDuration.Seconds()
}

// Takes byteCount bytes at now and returns how long the caller waits before sending them: zero while
// the bucket holds them.
func (self *TlsBandwidthBucket) Draw(byteCount int, now time.Time) time.Duration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.rate <= 0 {
		return 0
	}
	if elapsed := now.Sub(self.last).Seconds(); 0 < elapsed {
		self.tokens = min(self.burst, self.tokens+elapsed*self.rate)
		self.last = now
	}
	self.tokens -= float64(byteCount)
	if 0 <= self.tokens {
		return 0
	}
	return time.Duration(-self.tokens / self.rate * float64(time.Second))
}

// Bytes a second this bucket refills at, 0 for none.
func (self *TlsBandwidthBucket) Rate() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return int64(self.rate)
}
