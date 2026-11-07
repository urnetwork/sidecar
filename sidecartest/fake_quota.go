// ServiceHost.Quota in memory (§20.6, §20.7): limits, rate windows, edge leases and usage. Money moves
// here as the design says it does: a debit counts once per debit id, a batch once per batch id, and a
// lease spends without I/O and gives back what it did not use. What a real Quota computes from
// Postgres and Stripe a test sets by hand.

package sidecartest

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

type FakeQuotaSettings struct {
	// Bytes a lease draws at a time: §20.6's 64 MiB, 16 MiB on Community.
	LeaseDrawByteCount int64
	// The fraction of a draw used before a lease renews itself: §20.6's 75%.
	LeaseRenewFraction float64
}

func DefaultFakeQuotaSettings() *FakeQuotaSettings {
	return &FakeQuotaSettings{
		LeaseDrawByteCount: 64 * 1024 * 1024,
		LeaseRenewFraction: 0.75,
	}
}

type fakeQuotaNetwork struct {
	limits         *sidecar.QuotaLimits
	rateLimits     map[string]int64
	rateUsed       map[string]int64
	debitIds       map[connect.Id]bool
	balance        int64
	transferUsed   map[string]int64
	storedDelta    int64
	storageRefusal *sidecar.QuotaRefusal
	spentRefusal   *sidecar.QuotaRefusal
}

type FakeQuota struct {
	faults   *FaultQueue
	settings *FakeQuotaSettings

	stateLock sync.Mutex
	networks  map[connect.Id]*fakeQuotaNetwork
	batchIds  map[connect.Id]bool
	batches   []*sidecar.UsageBatch
}

func NewFakeQuota(faults *FaultQueue, settings *FakeQuotaSettings) *FakeQuota {
	if settings == nil {
		settings = DefaultFakeQuotaSettings()
	}
	return &FakeQuota{
		faults:   faults,
		settings: settings,
		networks: map[connect.Id]*fakeQuotaNetwork{},
		batchIds: map[connect.Id]bool{},
	}
}

func (self *FakeQuota) networkWithLock(networkId connect.Id) *fakeQuotaNetwork {
	network, ok := self.networks[networkId]
	if !ok {
		network = &fakeQuotaNetwork{
			limits:       &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{}},
			rateLimits:   map[string]int64{},
			rateUsed:     map[string]int64{},
			debitIds:     map[connect.Id]bool{},
			transferUsed: map[string]int64{},
		}
		self.networks[networkId] = network
	}
	return network
}

// What Limits answers. A key not set here reads 0, not included, as §20.5 defines it.
func (self *FakeQuota) SetLimits(networkId connect.Id, limits *sidecar.QuotaLimits) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).limits = limits
}

// Caps a rate key for CountRate. A key with no cap is refused, since what a network was not given
// reads 0.
func (self *FakeQuota) SetRateLimit(networkId connect.Id, key string, limit int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).rateLimits[key] = limit
}

// Starts a new rate window: what a rate's time does at a real Quota.
func (self *FakeQuota) ResetRates(networkId connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clear(self.networkWithLock(networkId).rateUsed)
}

// The bytes leases may draw on: escrow's reservations for this network.
func (self *FakeQuota) SetBalance(networkId connect.Id, byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).balance = byteCount
}

func (self *FakeQuota) Balance(networkId connect.Id) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkWithLock(networkId).balance
}

// Marks a network over its storage limit: OverLimit carries the refusal until it is cleared by nil.
func (self *FakeQuota) SetStorageRefusal(networkId connect.Id, refusal *sidecar.QuotaRefusal) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).storageRefusal = refusal
}

// Marks a network spent: OverLimit carries the refusal until it is cleared by nil.
func (self *FakeQuota) SetSpentRefusal(networkId connect.Id, refusal *sidecar.QuotaRefusal) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).spentRefusal = refusal
}

// Bytes debited on a meter, counted once per batch.
func (self *FakeQuota) TransferUsed(networkId connect.Id, meter string) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkWithLock(networkId).transferUsed[meter]
}

// The sum of stored-byte deltas reported.
func (self *FakeQuota) StoredDelta(networkId connect.Id) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkWithLock(networkId).storedDelta
}

// Every batch accepted, once each.
func (self *FakeQuota) Batches() []*sidecar.UsageBatch {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*sidecar.UsageBatch{}, self.batches...)
}

// host_quota.go's rule: a zero id names no one's limits or balance, and two calls sharing one would read
// as one retried, the second counting nothing.
func checkQuotaId(what string, id connect.Id) error {
	if id == (connect.Id{}) {
		return fmt.Errorf("a zero %s id", what)
	}
	return nil
}

func (self *FakeQuota) Limits(ctx context.Context, networkId connect.Id) (*sidecar.QuotaLimits, error) {
	if err := checkQuotaId("network", networkId); err != nil {
		return nil, err
	}
	var limits *sidecar.QuotaLimits
	err := hostCall(ctx, self.faults, "quota.Limits", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		network := self.networkWithLock(networkId)
		limits = &sidecar.QuotaLimits{Tier: network.limits.Tier, Limits: maps.Clone(network.limits.Limits)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return limits, nil
}

func (self *FakeQuota) CountRate(ctx context.Context, networkId connect.Id, keyAmounts map[string]int64, debitId connect.Id) (*sidecar.QuotaRefusal, error) {
	if err := checkQuotaId("network", networkId); err != nil {
		return nil, err
	}
	if err := checkQuotaId("debit", debitId); err != nil {
		return nil, err
	}
	var refusal *sidecar.QuotaRefusal
	err := hostCall(ctx, self.faults, "quota.CountRate", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		network := self.networkWithLock(networkId)
		if network.debitIds[debitId] {
			return nil
		}
		// all or none: check every key before counting any
		for key, amount := range keyAmounts {
			limit := network.rateLimits[key]
			if used := network.rateUsed[key]; limit < used+amount {
				refusal = &sidecar.QuotaRefusal{LimitKey: key, Limit: limit, Used: used}
				return nil
			}
		}
		for key, amount := range keyAmounts {
			network.rateUsed[key] += amount
		}
		network.debitIds[debitId] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return refusal, nil
}

func (self *FakeQuota) Lease(ctx context.Context, networkId connect.Id, meter string) (sidecar.QuotaLease, *sidecar.QuotaRefusal, error) {
	if err := checkQuotaId("network", networkId); err != nil {
		return nil, nil, err
	}
	var lease *fakeQuotaLease
	var refusal *sidecar.QuotaRefusal
	err := hostCall(ctx, self.faults, "quota.Lease", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		network := self.networkWithLock(networkId)
		draw := min(self.settings.LeaseDrawByteCount, network.balance)
		if draw <= 0 {
			refusal = &sidecar.QuotaRefusal{LimitKey: meter, Upgrade: true}
			// a refused lease marks the network spent (host_quota.go)
			network.spentRefusal = refusal
			return nil
		}
		network.spentRefusal = nil
		network.balance -= draw
		lease = &fakeQuotaLease{quota: self, networkId: networkId, meter: meter}
		lease.available.Store(draw)
		lease.drawn = draw
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if refusal != nil {
		return nil, refusal, nil
	}
	return lease, nil, nil
}

func (self *FakeQuota) ReportUsage(ctx context.Context, batch *sidecar.UsageBatch) error {
	if err := checkQuotaId("batch", batch.BatchId); err != nil {
		return err
	}
	for _, event := range batch.Events {
		if err := checkQuotaId("network", event.NetworkId); err != nil {
			return err
		}
	}
	return hostCall(ctx, self.faults, "quota.ReportUsage", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.batchIds[batch.BatchId] {
			return nil
		}
		self.batchIds[batch.BatchId] = true
		self.batches = append(self.batches, batch)
		for _, event := range batch.Events {
			network := self.networkWithLock(event.NetworkId)
			network.transferUsed[event.Meter] += event.TransferByteCount
			network.storedDelta += event.StoredByteDelta
		}
		return nil
	})
}

func (self *FakeQuota) OverLimit(ctx context.Context) (*sidecar.QuotaOverLimit, error) {
	overLimit := &sidecar.QuotaOverLimit{
		StorageNetworkIdRefusals: map[connect.Id]*sidecar.QuotaRefusal{},
		SpentNetworkIdRefusals:   map[connect.Id]*sidecar.QuotaRefusal{},
	}
	err := hostCall(ctx, self.faults, "quota.OverLimit", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for networkId, network := range self.networks {
			if network.storageRefusal != nil {
				overLimit.StorageNetworkIdRefusals[networkId] = network.storageRefusal
			}
			if network.spentRefusal != nil {
				overLimit.SpentNetworkIdRefusals[networkId] = network.spentRefusal
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return overLimit, nil
}

type fakeQuotaLease struct {
	quota     *FakeQuota
	networkId connect.Id
	meter     string
	// bytes spendable now
	available atomic.Int64
	stateLock sync.Mutex
	drawn     int64
	closed    bool
}

// Atomic, with no I/O. Renewing at §20.6's fraction is a move between two counters here, so it costs
// no I/O either, and it happens on the spender's goroutine.
func (self *fakeQuotaLease) Spend(byteCount int64) bool {
	for {
		available := self.available.Load()
		if available < byteCount {
			self.renew()
			if available = self.available.Load(); available < byteCount {
				self.markSpent()
				return false
			}
		}
		if self.available.CompareAndSwap(available, available-byteCount) {
			break
		}
	}
	settings := self.quota.settings
	self.stateLock.Lock()
	drawn := self.drawn
	self.stateLock.Unlock()
	if float64(drawn-self.available.Load()) >= settings.LeaseRenewFraction*float64(drawn) {
		self.renew()
	}
	return true
}

// A lease run out means the network is spent, until a new Lease says otherwise (host_quota.go).
func (self *fakeQuotaLease) markSpent() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return
	}
	self.quota.stateLock.Lock()
	defer self.quota.stateLock.Unlock()
	self.quota.networkWithLock(self.networkId).spentRefusal = &sidecar.QuotaRefusal{LimitKey: self.meter, Upgrade: true}
}

func (self *fakeQuotaLease) renew() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return
	}
	self.quota.stateLock.Lock()
	defer self.quota.stateLock.Unlock()
	network := self.quota.networkWithLock(self.networkId)
	draw := min(self.quota.settings.LeaseDrawByteCount, network.balance)
	if 0 < draw {
		network.balance -= draw
		self.available.Add(draw)
		self.drawn += draw
	}
}

// Gives back the unused rest. Spend then refuses.
func (self *fakeQuotaLease) Close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return
	}
	self.closed = true
	rest := self.available.Swap(0)
	self.quota.stateLock.Lock()
	defer self.quota.stateLock.Unlock()
	self.quota.networkWithLock(self.networkId).balance += rest
}

func (self *fakeQuotaLease) String() string {
	return fmt.Sprintf("lease on %s", self.meter)
}
