package sidecartest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

type quotaOracleFixture struct {
	clock     *sidecartest.FakeClock
	faults    *sidecartest.FaultQueue
	quota     *sidecartest.FakeQuota
	oracle    *sidecartest.QuotaOracle
	networkId connect.Id
}

// One network with a balance of 1000 the oracle knows of.
func newQuotaOracleFixture() *quotaOracleFixture {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	quota := sidecartest.NewFakeQuota(clock, faults, nil)
	fixture := &quotaOracleFixture{
		clock:     clock,
		faults:    faults,
		quota:     quota,
		oracle:    sidecartest.NewQuotaOracle(sidecartest.NewFakeQuotaOracleSource(quota)),
		networkId: connect.NewId(),
	}
	quota.SetBalance(fixture.networkId, 1000)
	fixture.oracle.Grant(fixture.networkId, 1000)
	return fixture
}

func (self *quotaOracleFixture) evsBatch(byteCount int64, storedByteDelta int64) *sidecar.UsageBatch {
	return &sidecar.UsageBatch{
		BatchId:  connect.NewId(),
		Producer: sidecar.QuotaProducerEvs,
		Events: []*sidecar.UsageEvent{{
			NetworkId:         self.networkId,
			Meter:             sidecar.QuotaMeterEvs,
			TransferByteCount: byteCount,
			StoredByteDelta:   storedByteDelta,
		}},
	}
}

func expectOracleError(t *testing.T, err error, clause string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), clause) {
		t.Fatalf("%v, want a %s violation", err, clause)
	}
}

// A batch applied once, retried or not, holds FI-13 (a) at every step and exactly once settled.
func TestQuotaOracleHoldsOnABatchAppliedOnce(t *testing.T) {
	ctx := context.Background()
	fixture := newQuotaOracleFixture()
	batch := fixture.evsBatch(100, 0)
	fixture.oracle.Meter(fixture.networkId, sidecar.QuotaMeterEvs, 100)
	if err := fixture.oracle.Check(ctx); err != nil {
		t.Fatal(err)
	}
	// metered and not yet sent: the lower bound does not hold yet
	expectOracleError(t, fixture.oracle.CheckSettled(ctx), "never counted")
	for range 2 {
		if err := fixture.quota.ReportUsage(ctx, batch); err != nil {
			t.Fatal(err)
		}
		if err := fixture.oracle.CheckSettled(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// A store that applies a retried batch again is caught at the step that did it.
func TestQuotaOracleCatchesADoubleDebit(t *testing.T) {
	ctx := context.Background()
	fixture := newQuotaOracleFixture()
	fixture.oracle.Meter(fixture.networkId, sidecar.QuotaMeterEvs, 100)
	batch := fixture.evsBatch(100, 0)
	if err := fixture.quota.ReportUsage(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := fixture.oracle.Check(ctx); err != nil {
		t.Fatal(err)
	}
	// the retry under a new id, as a store that forgot the first would count it
	again := *batch
	again.BatchId = connect.NewId()
	if err := fixture.quota.ReportUsage(ctx, &again); err != nil {
		t.Fatal(err)
	}
	expectOracleError(t, fixture.oracle.Check(ctx), "twice")
}

// Bytes a kill or a drop lost may be missing or present, and nothing else may.
func TestQuotaOracleAllowsOnlyTheLossItIsTold(t *testing.T) {
	ctx := context.Background()
	fixture := newQuotaOracleFixture()
	fixture.oracle.Meter(fixture.networkId, sidecar.QuotaMeterEvs, 100)
	fixture.oracle.Meter(fixture.networkId, sidecar.QuotaMeterEvs, 40)
	if err := fixture.quota.ReportUsage(ctx, fixture.evsBatch(100, 0)); err != nil {
		t.Fatal(err)
	}
	expectOracleError(t, fixture.oracle.CheckSettled(ctx), "never counted")
	fixture.oracle.Lose(fixture.networkId, sidecar.QuotaMeterEvs, 40)
	if err := fixture.oracle.CheckSettled(ctx); err != nil {
		t.Fatal(err)
	}
	// the lost window's batch had reached the store after all
	if err := fixture.quota.ReportUsage(ctx, fixture.evsBatch(40, 0)); err != nil {
		t.Fatal(err)
	}
	if err := fixture.oracle.CheckSettled(ctx); err != nil {
		t.Fatal(err)
	}
}

// A balance that grows back fails: a debit is never returned.
func TestQuotaOracleCatchesADebitTakenBack(t *testing.T) {
	ctx := context.Background()
	fixture := newQuotaOracleFixture()
	fixture.oracle.Meter(fixture.networkId, sidecar.QuotaMeterEvs, 100)
	if err := fixture.quota.ReportUsage(ctx, fixture.evsBatch(100, 0)); err != nil {
		t.Fatal(err)
	}
	if err := fixture.oracle.Check(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.quota.SetBalance(fixture.networkId, 1000)
	expectOracleError(t, fixture.oracle.Check(ctx), "ran back")
}

// FI-13 (c): the count against the listing's formula, holds and superseded containers taken off.
func TestQuotaOracleStoredFormula(t *testing.T) {
	ctx := context.Background()
	fixture := newQuotaOracleFixture()
	if err := fixture.quota.ReportUsage(ctx, fixture.evsBatch(0, 700)); err != nil {
		t.Fatal(err)
	}
	listing := &sidecartest.QuotaStoredListing{
		SegmentByteCount:     400,
		PackByteCount:        250,
		ParcelByteCount:      80,
		BatchRecordByteCount: 20,
		HeldOnlyByteCount:    30,
		SupersededByteCount:  20,
	}
	if err := fixture.oracle.CheckStored(ctx, fixture.networkId, listing); err != nil {
		t.Fatal(err)
	}
	listing.BatchRecordByteCount += 1
	expectOracleError(t, fixture.oracle.CheckStored(ctx, fixture.networkId, listing), "FI-13 (c)")
}

// FI-13 (d) E-a: a reservation on the credit line while a pack has room fails; the fake's own draws,
// which take the pack first, pass.
func TestQuotaOracleCreditLast(t *testing.T) {
	ctx := context.Background()
	fixture := newQuotaOracleFixture()
	draw := sidecartest.DefaultFakeQuotaSettings().CommunityLeaseDrawByteCount
	now := fixture.clock.Now()
	fixture.quota.SetLimits(fixture.networkId, &sidecar.QuotaLimits{Tier: "free"})
	fixture.quota.SetBalances(fixture.networkId, []*sidecartest.QuotaBalance{
		{ByteCount: 10 * draw, Credit: true, EndTime: now.Add(30 * 24 * time.Hour)},
		{ByteCount: draw / 2, EndTime: now.Add(365 * 24 * time.Hour)},
	})
	lease, refusal, err := fixture.quota.Lease(ctx, fixture.networkId, sidecar.QuotaMeterTls)
	if err != nil || refusal != nil {
		t.Fatalf("lease: %v, %+v", err, refusal)
	}
	defer lease.Close()
	if err := fixture.oracle.CheckCreditLast(ctx, fixture.networkId, now); err != nil {
		t.Fatal(err)
	}
	// a store that drew the line first
	source := &creditFirstSource{now: now, draw: draw}
	oracle := sidecartest.NewQuotaOracle(source)
	expectOracleError(t, oracle.CheckCreditLast(ctx, fixture.networkId, now), "E-a")
}

type creditFirstSource struct {
	now  time.Time
	draw int64
}

func (self *creditFirstSource) ReadQuota(ctx context.Context, networkId connect.Id) (*sidecartest.QuotaOracleReading, error) {
	return &sidecartest.QuotaOracleReading{
		Balances: []*sidecartest.QuotaBalance{
			{BalanceId: connect.NewId(), ByteCount: self.draw, EndTime: self.now.Add(365 * 24 * time.Hour)},
			{BalanceId: connect.NewId(), ByteCount: 10 * self.draw, Credit: true, EndTime: self.now.Add(30 * 24 * time.Hour), ReservedByteCount: self.draw / 2},
		},
	}, nil
}
