package fault

// FS-46 (§20.9, FI-13 (d); QUOTA-M4-03) on T2: a data pack ending in a year and a team_credit line ending in
// 30 days on the fake Quota's balances, with FI-13's oracle after every step. A lease takes the pack first and
// the line only past it (E-a); a lease closed with part of its draw spent returns the line's reservation
// first and keeps what it spent on the pack (E-b); an edge killed with a lease on the line leaves no
// reservation once its token's lifetime has passed, and no debit 24 h later (E-d). E-e, the provider paid at
// the line's rate, has no provider on sidecar.Quota: it runs at T3 in server's model, on escrow's own rows.

import (
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

type fs46World struct {
	clock     *sidecartest.FakeClock
	quota     *sidecartest.FakeQuota
	oracle    *sidecartest.QuotaOracle
	table     *sidecartest.ActorTable
	networkId connect.Id
	packId    connect.Id
	lineId    connect.Id
	draw      int64
}

// A Team network whose pack holds half a draw and whose line holds ten.
func newFs46World(t *testing.T) *fs46World {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecartest.DefaultFakeQuotaSettings()
	quota := sidecartest.NewFakeQuota(clock, sidecartest.NewFaultQueue(), settings)
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	world := &fs46World{
		clock:     clock,
		quota:     quota,
		oracle:    sidecartest.NewQuotaOracle(sidecartest.NewFakeQuotaOracleSource(quota)),
		table:     sidecartest.NewActorTable(clock, driver),
		networkId: connect.NewId(),
		packId:    connect.NewId(),
		lineId:    connect.NewId(),
		draw:      settings.LeaseDrawByteCount,
	}
	now := clock.Now()
	quota.SetLimits(world.networkId, &sidecar.QuotaLimits{Tier: "team"})
	quota.SetBalances(world.networkId, []*sidecartest.QuotaBalance{
		{BalanceId: world.lineId, ByteCount: 10 * world.draw, Credit: true, StartTime: now.Add(-time.Hour), EndTime: now.Add(30 * 24 * time.Hour)},
		{BalanceId: world.packId, ByteCount: world.draw / 2, StartTime: now.Add(-time.Hour), EndTime: now.Add(365 * 24 * time.Hour)},
	})
	world.oracle.Grant(world.networkId, 10*world.draw+world.draw/2)
	return world
}

// The pack's and the line's balances as the store holds them, FI-13 (a) and E-a checked first.
func (self *fs46World) balances(t *testing.T, what string) (pack *sidecartest.QuotaBalance, line *sidecartest.QuotaBalance) {
	t.Helper()
	if err := self.oracle.Check(t.Context()); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if err := self.oracle.CheckCreditLast(t.Context(), self.networkId, self.clock.Now()); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	for _, balance := range self.quota.Balances(self.networkId) {
		switch balance.BalanceId {
		case self.packId:
			pack = balance
		case self.lineId:
			line = balance
		}
	}
	if pack == nil || line == nil {
		t.Fatalf("%s: the balances are gone", what)
	}
	return
}

// E-a and E-b for a lease: the pack is reserved whole before the line is touched, the bytes spent debit the
// pack first, and the close returns the line's reservation.
func TestFs46LeaseTakesThePackFirstAndReturnsToTheLineFirst(t *testing.T) {
	world := newFs46World(t)
	edge := world.table.Actor(t.Context(), "tlsedge1")
	lease, refusal, err := world.quota.Lease(edge.Context(), world.networkId, sidecar.QuotaMeterTls)
	if err != nil || refusal != nil {
		t.Fatalf("lease: %v, %+v", err, refusal)
	}
	pack, line := world.balances(t, "E-a, the draw")
	if pack.ReservedByteCount != world.draw/2 || line.ReservedByteCount != world.draw/2 {
		t.Fatalf("E-a: the draw reserved %d of the pack and %d of the line", pack.ReservedByteCount, line.ReservedByteCount)
	}
	// part of the pack's half, short of the renewal point
	spent := world.draw / 4
	if !lease.Spend(spent) {
		t.Fatal("a spend within the draw refused")
	}
	world.oracle.Meter(world.networkId, sidecar.QuotaMeterTls, spent)
	lease.Close()
	pack, line = world.balances(t, "E-b, the close")
	if line.ReservedByteCount != 0 || pack.ReservedByteCount != spent {
		t.Fatalf("E-b: the close left %d on the line and %d on the pack, want the line returned whole and the pack keeping the %d spent", line.ReservedByteCount, pack.ReservedByteCount, spent)
	}
	batch := &sidecar.UsageBatch{
		BatchId:  connect.NewId(),
		Producer: sidecar.QuotaProducerTlsEdge,
		Events:   []*sidecar.UsageEvent{{NetworkId: world.networkId, Meter: sidecar.QuotaMeterTls, TransferByteCount: spent}},
	}
	for range 2 {
		if err := world.quota.ReportUsage(edge.Context(), batch); err != nil {
			t.Fatal(err)
		}
		pack, line = world.balances(t, "the batch")
	}
	if err := world.oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
	if pack.ByteCount != world.draw/2-spent || line.ByteCount != 10*world.draw || pack.ReservedByteCount != 0 {
		t.Fatalf("after the debit: the pack %+v, the line %+v", pack, line)
	}
}

// E-d: an edge with a lease on the line, bytes spent and never reported, is killed. The reservation stays
// for its token's lifetime, then is gone, and 24 h later nothing has been debited.
func TestFs46KilledEdgeLeavesNoReservationAndNoDebit(t *testing.T) {
	world := newFs46World(t)
	edge := world.table.Actor(t.Context(), "tlsedge1")
	lease, refusal, err := world.quota.Lease(edge.Context(), world.networkId, sidecar.QuotaMeterTls)
	if err != nil || refusal != nil {
		t.Fatalf("lease: %v, %+v", err, refusal)
	}
	// past the pack's half, onto the line
	spent := world.draw/2 + world.draw/8
	if !lease.Spend(spent) {
		t.Fatal("a spend within the draw refused")
	}
	world.oracle.Meter(world.networkId, sidecar.QuotaMeterTls, spent)
	_, line := world.balances(t, "the lease on the line")
	if line.ReservedByteCount == 0 {
		t.Fatal("the lease holds nothing of the line")
	}
	edge.Kill()
	world.oracle.Lose(world.networkId, sidecar.QuotaMeterTls, spent)
	lifetime := sidecartest.DefaultFakeQuotaSettings().LeaseTokenLifetime
	world.clock.Advance(lifetime - time.Millisecond)
	if _, line = world.balances(t, "inside the token's lifetime"); line.ReservedByteCount == 0 {
		t.Fatal("the reservation was gone before its token's lifetime")
	}
	world.clock.Advance(time.Millisecond)
	pack, line := world.balances(t, "at the token's lifetime")
	if pack.ReservedByteCount != 0 || line.ReservedByteCount != 0 {
		t.Fatalf("E-d: %d still reserved on the pack and %d on the line", pack.ReservedByteCount, line.ReservedByteCount)
	}
	world.clock.Advance(24 * time.Hour)
	pack, line = world.balances(t, "24 h later")
	if pack.ByteCount != world.draw/2 || line.ByteCount != 10*world.draw || pack.ReservedByteCount != 0 || line.ReservedByteCount != 0 {
		t.Fatalf("E-d: 24 h later the pack %+v, the line %+v", pack, line)
	}
	if err := world.oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
}
