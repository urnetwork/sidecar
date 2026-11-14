// FI-13's oracle (§22.8; QUOTA-M2-13): the accounting invariant, checked after every step of a schedule
// against what the store holds, never against what a call answered.
//
//	(a) every metered byte debits at most once and, barring an unclean producer exit or a batch dropped
//	    past its retry horizon, exactly once. A schedule tells the oracle what each producer metered
//	    (Meter) and which of those bytes a kill or a drop may have lost (Lose). Check holds the upper
//	    bound at any instant: the balances are never debited more than was metered, and never less than
//	    they were. CheckSettled holds the lower bound once nothing is in flight: everything metered and
//	    not lost has debited, so with nothing lost the debit is exact.
//	(c) after a nightly pass, stored bytes equal §20.7's formula over the store's own listing, which a
//	    schedule reads with LISTs and heads and gives as a QuotaStoredListing (CheckStored).
//	(d) §20.9's E-a, as far as a balance listing shows it: the credit line holds a reservation only once
//	    no other balance has room (CheckCreditLast). E-b to E-e are FS-46's own steps to read.
//
// The store is read through a QuotaOracleSource: FakeQuota's at T2 (NewFakeQuotaOracleSource), Postgres
// and Redis at T3 (server's quotahost tests). Safe for concurrent use.

package sidecartest

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// What a store holds of one network at one instant.
type QuotaOracleReading struct {
	// Every balance of the network in draw order, each with what is left of it once every debit the
	// store holds is taken off, applied to the balance or still journaled, and what reservations hold.
	Balances []*QuotaBalance
	// Bytes the store counts used on each meter, where it keeps such a count. nil where it keeps only the
	// debits, as server does until the daily roll-up.
	MeterUsedByteCounts map[string]int64
	// Bytes the store took and billed to no balance (urnetwork_quota_unbilled_bytes_total), when
	// UnbilledKnown. A source that cannot read it per network leaves UnbilledKnown false, and the lower
	// bound of (a) is then not checked at the balance.
	UnbilledByteCount int64
	UnbilledKnown     bool
	// The network's stored-byte count.
	StoredByteCount int64
}

// Reads a store for the oracle.
type QuotaOracleSource interface {
	ReadQuota(ctx context.Context, networkId connect.Id) (*QuotaOracleReading, error)
}

// What LISTs and heads show of a network's stored bytes: §20.7's count row, FI-13 (c).
type QuotaStoredListing struct {
	// The seg/, pack/ and hp/ objects' sizes.
	SegmentByteCount int64
	PackByteCount    int64
	ParcelByteCount  int64
	// The lengths heads and log pages give for records still in batches.
	BatchRecordByteCount int64
	// Objects only a hold keeps, objects held for a drop included: listed above, and not counted.
	HeldOnlyByteCount int64
	// Containers whose every record a newer container's pidx/ entry names: listed above, and not counted.
	SupersededByteCount int64
}

// The count the formula gives.
func (self *QuotaStoredListing) StoredByteCount() int64 {
	return self.SegmentByteCount + self.PackByteCount + self.ParcelByteCount + self.BatchRecordByteCount - self.HeldOnlyByteCount - self.SupersededByteCount
}

type quotaOracleNetwork struct {
	grantedByteCount int64
	// what producers metered, and how much of it a kill or a drop may have lost
	meterMeteredByteCounts map[string]int64
	meterLostByteCounts    map[string]int64
	// the previous check's figures: a debit never runs back
	debitedByteCount    int64
	meterUsedByteCounts map[string]int64
}

// See the file header.
type QuotaOracle struct {
	source QuotaOracleSource

	stateLock sync.Mutex
	networks  map[connect.Id]*quotaOracleNetwork
}

func NewQuotaOracle(source QuotaOracleSource) *QuotaOracle {
	return &QuotaOracle{
		source:   source,
		networks: map[connect.Id]*quotaOracleNetwork{},
	}
}

func (self *QuotaOracle) networkWithLock(networkId connect.Id) *quotaOracleNetwork {
	network, ok := self.networks[networkId]
	if !ok {
		network = &quotaOracleNetwork{
			meterMeteredByteCounts: map[string]int64{},
			meterLostByteCounts:    map[string]int64{},
			meterUsedByteCounts:    map[string]int64{},
		}
		self.networks[networkId] = network
	}
	return network
}

// The network's balances were given byteCount in all. A schedule calls it wherever it sets balances, with
// the sum of what it set; what was debited before is forgotten with the old balances.
func (self *QuotaOracle) Grant(networkId connect.Id, byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network := self.networkWithLock(networkId)
	network.grantedByteCount = byteCount
	network.debitedByteCount = 0
	network.meterMeteredByteCounts = map[string]int64{}
	network.meterLostByteCounts = map[string]int64{}
	network.meterUsedByteCounts = map[string]int64{}
}

// A producer metered byteCount for the network on meter: bytes that moved, each to debit once.
func (self *QuotaOracle) Meter(networkId connect.Id, meter string, byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).meterMeteredByteCounts[meter] += byteCount
}

// Of the bytes metered, byteCount may never debit: an unclean exit's open window and unanswered
// batches, or a batch dropped past its retry horizon. They may still have debited, where the store
// took a batch whose answer the producer never saw.
func (self *QuotaOracle) Lose(networkId connect.Id, meter string, byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).meterLostByteCounts[meter] += byteCount
}

// FI-13 (a)'s upper bound over every network the oracle was told of: no byte debited twice, at the
// meter or at the balance, and no debit taken back. Holds after any step, with calls in flight.
func (self *QuotaOracle) Check(ctx context.Context) error {
	return self.check(ctx, false)
}

// Check, and (a)'s lower bound: with nothing in flight, every metered byte not lost has debited.
func (self *QuotaOracle) CheckSettled(ctx context.Context) error {
	return self.check(ctx, true)
}

func (self *QuotaOracle) check(ctx context.Context, settled bool) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkIds := []connect.Id{}
	for networkId := range self.networks {
		networkIds = append(networkIds, networkId)
	}
	// a fixed order, so a failing schedule names the same network each run
	slices.SortFunc(networkIds, func(a connect.Id, b connect.Id) int {
		return slices.Compare(a[:], b[:])
	})
	for _, networkId := range networkIds {
		reading, err := self.source.ReadQuota(InspectContext(ctx), networkId)
		if err != nil {
			return fmt.Errorf("FI-13: reading network %s: %w", networkId, err)
		}
		if err := self.checkNetworkWithLock(networkId, self.networks[networkId], reading, settled); err != nil {
			return err
		}
	}
	return nil
}

func (self *QuotaOracle) checkNetworkWithLock(networkId connect.Id, network *quotaOracleNetwork, reading *QuotaOracleReading, settled bool) error {
	meteredByteCount := int64(0)
	lostByteCount := int64(0)
	for meter, byteCount := range network.meterMeteredByteCounts {
		meteredByteCount += byteCount
		lostByteCount += min(byteCount, network.meterLostByteCounts[meter])
	}
	leftByteCount := int64(0)
	for _, balance := range reading.Balances {
		leftByteCount += balance.ByteCount
	}
	debitedByteCount := network.grantedByteCount - leftByteCount
	if debitedByteCount < network.debitedByteCount {
		return fmt.Errorf("FI-13 (a): network %s: a debit ran back, %d after %d", networkId, debitedByteCount, network.debitedByteCount)
	}
	if meteredByteCount < debitedByteCount {
		return fmt.Errorf("FI-13 (a): network %s: %d debited for %d metered: a byte debited twice", networkId, debitedByteCount, meteredByteCount)
	}
	if reading.MeterUsedByteCounts != nil {
		usedByteCount := int64(0)
		for _, meter := range slices.Sorted(maps.Keys(reading.MeterUsedByteCounts)) {
			used := reading.MeterUsedByteCounts[meter]
			usedByteCount += used
			if metered := network.meterMeteredByteCounts[meter]; metered < used {
				return fmt.Errorf("FI-13 (a): network %s: %d counted on %s for %d metered: a byte counted twice", networkId, used, meter, metered)
			}
			if previous := network.meterUsedByteCounts[meter]; used < previous {
				return fmt.Errorf("FI-13 (a): network %s: %s's count ran back, %d after %d", networkId, meter, used, previous)
			}
		}
		if usedByteCount < debitedByteCount {
			return fmt.Errorf("FI-13 (a): network %s: %d debited for %d counted", networkId, debitedByteCount, usedByteCount)
		}
		if settled {
			for meter, metered := range network.meterMeteredByteCounts {
				lost := min(metered, network.meterLostByteCounts[meter])
				if used := reading.MeterUsedByteCounts[meter]; used < metered-lost {
					return fmt.Errorf("FI-13 (a): network %s: %d counted on %s for %d metered with %d lost: a byte never counted", networkId, used, meter, metered, lost)
				}
			}
			if reading.UnbilledKnown && debitedByteCount+reading.UnbilledByteCount != usedByteCount {
				return fmt.Errorf("FI-13 (a): network %s: %d debited and %d unbilled for %d counted", networkId, debitedByteCount, reading.UnbilledByteCount, usedByteCount)
			}
		}
	}
	if settled && reading.UnbilledKnown && debitedByteCount+reading.UnbilledByteCount < meteredByteCount-lostByteCount {
		return fmt.Errorf("FI-13 (a): network %s: %d debited and %d unbilled for %d metered with %d lost: a byte never debited",
			networkId, debitedByteCount, reading.UnbilledByteCount, meteredByteCount, lostByteCount)
	}
	network.debitedByteCount = debitedByteCount
	if reading.MeterUsedByteCounts != nil {
		for meter, used := range reading.MeterUsedByteCounts {
			network.meterUsedByteCounts[meter] = used
		}
	}
	return nil
}

// FI-13 (c): the store's count for the network is what the formula gives over listing.
func (self *QuotaOracle) CheckStored(ctx context.Context, networkId connect.Id, listing *QuotaStoredListing) error {
	reading, err := self.source.ReadQuota(InspectContext(ctx), networkId)
	if err != nil {
		return fmt.Errorf("FI-13: reading network %s: %w", networkId, err)
	}
	if want := listing.StoredByteCount(); reading.StoredByteCount != want {
		return fmt.Errorf("FI-13 (c): network %s: %d stored, and the listing gives %d (%+v)", networkId, reading.StoredByteCount, want, *listing)
	}
	return nil
}

// FI-13 (d), §20.9's E-a as a listing shows it: at now, a credit line holds a reservation only while no
// other in-window balance has unreserved room. It holds where reservations are made and returned in
// draw order, as FS-46's steps do; a schedule that closes leases out of order does not call it.
func (self *QuotaOracle) CheckCreditLast(ctx context.Context, networkId connect.Id, now time.Time) error {
	reading, err := self.source.ReadQuota(InspectContext(ctx), networkId)
	if err != nil {
		return fmt.Errorf("FI-13: reading network %s: %w", networkId, err)
	}
	roomByteCount := int64(0)
	creditReservedByteCount := int64(0)
	for _, balance := range reading.Balances {
		if !balance.inWindow(now) {
			continue
		}
		if balance.Credit {
			creditReservedByteCount += balance.ReservedByteCount
		} else {
			roomByteCount += max(0, balance.ByteCount-balance.ReservedByteCount)
		}
	}
	if 0 < creditReservedByteCount && 0 < roomByteCount {
		return fmt.Errorf("FI-13 (d) E-a: network %s: %d reserved on the credit line while %d is free on the balances before it", networkId, creditReservedByteCount, roomByteCount)
	}
	return nil
}

// FakeQuota as the oracle's store, for T2.
type fakeQuotaOracleSource struct {
	quota *FakeQuota
}

func NewFakeQuotaOracleSource(quota *FakeQuota) QuotaOracleSource {
	return &fakeQuotaOracleSource{quota: quota}
}

func (self *fakeQuotaOracleSource) ReadQuota(ctx context.Context, networkId connect.Id) (*QuotaOracleReading, error) {
	reading := &QuotaOracleReading{
		Balances:            self.quota.Balances(networkId),
		MeterUsedByteCounts: map[string]int64{},
		UnbilledByteCount:   self.quota.UnbilledByteCount(networkId),
		UnbilledKnown:       true,
		// the fake keeps no nightly count: its stored bytes are the deltas reported
		StoredByteCount: self.quota.StoredDelta(networkId),
	}
	for _, meter := range []string{sidecar.QuotaMeterTls, sidecar.QuotaMeterMx, sidecar.QuotaMeterSmtp, sidecar.QuotaMeterEvs, sidecar.QuotaMeterRelay} {
		if used := self.quota.TransferUsed(networkId, meter); used != 0 {
			reading.MeterUsedByteCounts[meter] = used
		}
	}
	return reading, nil
}
