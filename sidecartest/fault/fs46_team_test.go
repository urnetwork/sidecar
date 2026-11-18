package fault

// FS-46 on a Team's flows (§20.9, FI-13; QUOTA-M6-06) on T2: where fs46_test.go holds a pack and a line, this
// network holds what a Team's paid period leaves, the period's team grant and its team_credit line, both ending
// with the period, and a data code's pack ending in a year, on the fake Quota's balances with FI-13's oracle
// after every step. A lease takes the grant, then the pack, and the line only past both (E-a), and its close
// returns the line first (E-b). evs's bytes, which no lease spends, debit in the same order at apply, each once,
// so the line pays exactly the bytes past the others (E-c's sum; Stripe is server's, and a relayed contract's
// bytes settle by contract and never by batch, both at T3 in quotahost's team_billing_t3_test.go). Two edges lease at once and the one killed on the line leaves
// no reservation and no debit (E-d). And through a renewal, with the last period's line in its grace beside the
// new one, and a downgrade with a line still in window, the lines stay last, the one ending first before the
// other. E-e has no provider on sidecar.Quota and runs at T3.

import (
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

type fs46TeamWorld struct {
	clock     *sidecartest.FakeClock
	quota     *sidecartest.FakeQuota
	oracle    *sidecartest.QuotaOracle
	table     *sidecartest.ActorTable
	networkId connect.Id
	grantId   connect.Id
	packId    connect.Id
	lineId    connect.Id
	draw      int64
}

// A Team network in a paid period: a quarter of a draw on its grant and on its pack, ten draws on its line.
func newFs46TeamWorld(t *testing.T) *fs46TeamWorld {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecartest.DefaultFakeQuotaSettings()
	quota := sidecartest.NewFakeQuota(clock, sidecartest.NewFaultQueue(), settings)
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	world := &fs46TeamWorld{
		clock:     clock,
		quota:     quota,
		oracle:    sidecartest.NewQuotaOracle(sidecartest.NewFakeQuotaOracleSource(quota)),
		table:     sidecartest.NewActorTable(clock, driver),
		networkId: connect.NewId(),
		grantId:   connect.NewId(),
		packId:    connect.NewId(),
		lineId:    connect.NewId(),
		draw:      settings.LeaseDrawByteCount,
	}
	now := clock.Now()
	periodEnd := now.Add(31 * 24 * time.Hour)
	quota.SetLimits(world.networkId, &sidecar.QuotaLimits{Tier: "team"})
	world.setBalances([]*sidecartest.QuotaBalance{
		{BalanceId: world.lineId, ByteCount: 10 * world.draw, Credit: true, StartTime: now.Add(-time.Hour), EndTime: periodEnd},
		{BalanceId: world.packId, ByteCount: world.draw / 4, StartTime: now.Add(-time.Hour), EndTime: now.Add(365 * 24 * time.Hour)},
		{BalanceId: world.grantId, ByteCount: world.draw / 4, StartTime: now.Add(-time.Hour), EndTime: periodEnd},
	})
	return world
}

// The network's balances are these, as a payment or a purchase leaves them.
func (self *fs46TeamWorld) setBalances(balances []*sidecartest.QuotaBalance) {
	total := int64(0)
	for _, balance := range balances {
		total += balance.ByteCount
	}
	self.quota.SetBalances(self.networkId, balances)
	self.oracle.Grant(self.networkId, total)
}

// The network's balances by id as the store holds them, FI-13 (a) and (d)'s E-a checked first.
func (self *fs46TeamWorld) balances(t *testing.T, what string) map[connect.Id]*sidecartest.QuotaBalance {
	t.Helper()
	if err := self.oracle.Check(t.Context()); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if err := self.oracle.CheckCreditLast(t.Context(), self.networkId, self.clock.Now()); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	idBalances := map[connect.Id]*sidecartest.QuotaBalance{}
	for _, balance := range self.quota.Balances(self.networkId) {
		idBalances[balance.BalanceId] = balance
	}
	return idBalances
}

func (self *fs46TeamWorld) lease(t *testing.T, actor *sidecartest.Actor, meter string) sidecar.QuotaLease {
	t.Helper()
	lease, refusal, err := self.quota.Lease(actor.Context(), self.networkId, meter)
	if err != nil || refusal != nil {
		t.Fatalf("lease: %v, %+v", err, refusal)
	}
	return lease
}

// The actor's batch of byteCount on meter, with storedDelta, sent twice as a lost answer is repeated.
func (self *fs46TeamWorld) reportTwice(t *testing.T, actor *sidecartest.Actor, producer string, meter string, byteCount int64, storedDelta int64) {
	t.Helper()
	batch := &sidecar.UsageBatch{
		BatchId:  connect.NewId(),
		Producer: producer,
		Events:   []*sidecar.UsageEvent{{NetworkId: self.networkId, Meter: meter, TransferByteCount: byteCount, StoredByteDelta: storedDelta}},
	}
	for range 2 {
		if err := self.quota.ReportUsage(actor.Context(), batch); err != nil {
			t.Fatal(err)
		}
		self.balances(t, "the batch")
	}
}

// E-a and E-b for a lease on a Team: the grant and the pack are reserved whole before the line is touched, the
// bytes spent debit the grant and then the pack, and the close returns the line's reservation whole.
func TestFs46TeamLeaseTakesTheGrantThePackAndThenTheLine(t *testing.T) {
	world := newFs46TeamWorld(t)
	edge := world.table.Actor(t.Context(), "tlsedge1")
	lease := world.lease(t, edge, sidecar.QuotaMeterTls)
	balances := world.balances(t, "E-a, the draw")
	if balances[world.grantId].ReservedByteCount != world.draw/4 || balances[world.packId].ReservedByteCount != world.draw/4 || balances[world.lineId].ReservedByteCount != world.draw/2 {
		t.Fatalf("E-a: the draw reserved %d of the grant, %d of the pack and %d of the line", balances[world.grantId].ReservedByteCount, balances[world.packId].ReservedByteCount, balances[world.lineId].ReservedByteCount)
	}
	// the grant and half the pack, short of the renewal point
	spent := world.draw/4 + world.draw/8
	if !lease.Spend(spent) {
		t.Fatal("a spend within the draw refused")
	}
	world.oracle.Meter(world.networkId, sidecar.QuotaMeterTls, spent)
	lease.Close()
	balances = world.balances(t, "E-b, the close")
	if balances[world.lineId].ReservedByteCount != 0 || balances[world.packId].ReservedByteCount != world.draw/8 || balances[world.grantId].ReservedByteCount != world.draw/4 {
		t.Fatalf("E-b: the close left %d on the line, %d on the pack and %d on the grant", balances[world.lineId].ReservedByteCount, balances[world.packId].ReservedByteCount, balances[world.grantId].ReservedByteCount)
	}
	world.reportTwice(t, edge, sidecar.QuotaProducerTlsEdge, sidecar.QuotaMeterTls, spent, 0)
	if err := world.oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
	balances = world.balances(t, "after the debit")
	if balances[world.grantId].ByteCount != 0 || balances[world.packId].ByteCount != world.draw/8 || balances[world.lineId].ByteCount != 10*world.draw {
		t.Fatalf("after the debit: the grant %+v, the pack %+v, the line %+v", balances[world.grantId], balances[world.packId], balances[world.lineId])
	}
	for _, balance := range balances {
		if balance.ReservedByteCount != 0 {
			t.Fatalf("after the debit: %d still reserved on %s", balance.ReservedByteCount, balance.BalanceId)
		}
	}
}

// E-a for the bytes no lease spends, and E-c's sum: evs's bytes debit the grant, the pack and then the line at
// apply, each once, so what the line paid is exactly the bytes past the others; and the Team's stored bytes are
// counted beside them (FI-13 (c)).
func TestFs46TeamBytesAtApplyDrawTheLineLast(t *testing.T) {
	world := newFs46TeamWorld(t)
	evs := world.table.Actor(t.Context(), "evs1")
	const stored = int64(4096)

	// the grant and half the pack
	first := world.draw/4 + world.draw/8
	world.oracle.Meter(world.networkId, sidecar.QuotaMeterEvs, first)
	world.reportTwice(t, evs, sidecar.QuotaProducerEvs, sidecar.QuotaMeterEvs, first, stored)
	balances := world.balances(t, "evs's bytes")
	if balances[world.grantId].ByteCount != 0 || balances[world.packId].ByteCount != world.draw/8 || balances[world.lineId].ByteCount != 10*world.draw {
		t.Fatalf("E-a: the grant %+v, the pack %+v, the line %+v", balances[world.grantId], balances[world.packId], balances[world.lineId])
	}
	if err := world.oracle.CheckStored(t.Context(), world.networkId, &sidecartest.QuotaStoredListing{SegmentByteCount: stored}); err != nil {
		t.Fatal(err)
	}

	// the pack's rest, and the line for what is past it
	second := world.draw / 4
	world.oracle.Meter(world.networkId, sidecar.QuotaMeterEvs, second)
	world.reportTwice(t, evs, sidecar.QuotaProducerEvs, sidecar.QuotaMeterEvs, second, 0)
	if err := world.oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
	balances = world.balances(t, "evs's bytes past the pack")
	if balances[world.packId].ByteCount != 0 {
		t.Fatalf("E-a: the pack holds %d", balances[world.packId].ByteCount)
	}
	// E-c's sum: everything metered, less what the grant and the pack held
	linePaid := 10*world.draw - balances[world.lineId].ByteCount
	if want := first + second - world.draw/2; linePaid != want {
		t.Fatalf("E-c: the line paid %d, want the %d bytes past the grant and the pack", linePaid, want)
	}
	if err := world.oracle.CheckStored(t.Context(), world.networkId, &sidecartest.QuotaStoredListing{SegmentByteCount: stored}); err != nil {
		t.Fatal(err)
	}
}

// E-d with two edges on a Team: the first holds the grant, the pack and part of the line, the second the line
// alone. The second is killed with bytes spent and never reported: its reservation is gone at its token's
// lifetime and nothing debits, while the first's lease lives through it and settles in order.
func TestFs46TeamKilledEdgeOnTheLineLeavesTheLivingLease(t *testing.T) {
	world := newFs46TeamWorld(t)
	tlsEdge := world.table.Actor(t.Context(), "tlsedge1")
	mxEdge := world.table.Actor(t.Context(), "mxedge1")
	tlsLease := world.lease(t, tlsEdge, sidecar.QuotaMeterTls)
	mxLease := world.lease(t, mxEdge, sidecar.QuotaMeterMx)
	balances := world.balances(t, "two leases")
	if balances[world.lineId].ReservedByteCount != world.draw/2+world.draw {
		t.Fatalf("the two leases hold %d of the line", balances[world.lineId].ReservedByteCount)
	}
	lost := world.draw / 8
	if !mxLease.Spend(lost) {
		t.Fatal("a spend within the draw refused")
	}
	world.oracle.Meter(world.networkId, sidecar.QuotaMeterMx, lost)
	mxEdge.Kill()
	world.oracle.Lose(world.networkId, sidecar.QuotaMeterMx, lost)
	lifetime := sidecartest.DefaultFakeQuotaSettings().LeaseTokenLifetime
	world.clock.Advance(lifetime - time.Millisecond)
	if balances = world.balances(t, "inside the token's lifetime"); balances[world.lineId].ReservedByteCount != world.draw/2+world.draw {
		t.Fatalf("inside the token's lifetime the line holds %d", balances[world.lineId].ReservedByteCount)
	}
	world.clock.Advance(time.Millisecond)
	balances = world.balances(t, "at the token's lifetime")
	if balances[world.lineId].ReservedByteCount != world.draw/2 || balances[world.grantId].ReservedByteCount != world.draw/4 || balances[world.packId].ReservedByteCount != world.draw/4 {
		t.Fatalf("E-d: at the lifetime the line holds %d, the grant %d and the pack %d", balances[world.lineId].ReservedByteCount, balances[world.grantId].ReservedByteCount, balances[world.packId].ReservedByteCount)
	}

	// the living lease spends the grant and half the pack, and settles
	spent := world.draw/4 + world.draw/8
	if !tlsLease.Spend(spent) {
		t.Fatal("a spend within the draw refused")
	}
	world.oracle.Meter(world.networkId, sidecar.QuotaMeterTls, spent)
	tlsLease.Close()
	world.reportTwice(t, tlsEdge, sidecar.QuotaProducerTlsEdge, sidecar.QuotaMeterTls, spent, 0)
	world.clock.Advance(24 * time.Hour)
	balances = world.balances(t, "24 h later")
	if balances[world.grantId].ByteCount != 0 || balances[world.packId].ByteCount != world.draw/8 || balances[world.lineId].ByteCount != 10*world.draw {
		t.Fatalf("E-d: 24 h later the grant %+v, the pack %+v, the line %+v", balances[world.grantId], balances[world.packId], balances[world.lineId])
	}
	for _, balance := range balances {
		if balance.ReservedByteCount != 0 {
			t.Fatalf("E-d: 24 h later %d still reserved on %s", balance.ReservedByteCount, balance.BalanceId)
		}
	}
	if err := world.oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// A renewal and a downgrade: with the last period's line in its grace beside the new period's, the lines stay
// last and the one ending first pays first; and once the Team has left its tier with a line still in window, a
// pack bought then still pays before it.
func TestFs46TeamRenewalAndDowngradeKeepTheLinesLast(t *testing.T) {
	world := newFs46TeamWorld(t)
	edge := world.table.Actor(t.Context(), "tlsedge1")
	now := world.clock.Now()
	oldLineId, newGrantId, newLineId, boughtId := world.lineId, connect.NewId(), connect.NewId(), connect.NewId()
	// The renewal: the old grant is used up, the old line has two draws left for its day of grace. The pack
	// that is bought after the downgrade is here from the start, its window opening then, since the oracle
	// follows one set of balances.
	world.setBalances([]*sidecartest.QuotaBalance{
		{BalanceId: boughtId, ByteCount: world.draw / 8, StartTime: now.Add(47 * time.Hour), EndTime: now.Add(365 * 24 * time.Hour)},
		{BalanceId: newLineId, ByteCount: 10 * world.draw, Credit: true, StartTime: now.Add(-time.Hour), EndTime: now.Add(31 * 24 * time.Hour)},
		{BalanceId: oldLineId, ByteCount: 2 * world.draw, Credit: true, StartTime: now.Add(-31 * 24 * time.Hour), EndTime: now.Add(24 * time.Hour)},
		{BalanceId: world.packId, ByteCount: world.draw / 4, StartTime: now.Add(-time.Hour), EndTime: now.Add(365 * 24 * time.Hour)},
		{BalanceId: newGrantId, ByteCount: world.draw / 4, StartTime: now.Add(-time.Hour), EndTime: now.Add(31 * 24 * time.Hour)},
	})
	lease := world.lease(t, edge, sidecar.QuotaMeterTls)
	balances := world.balances(t, "E-a, the draw after the renewal")
	if balances[newGrantId].ReservedByteCount != world.draw/4 || balances[world.packId].ReservedByteCount != world.draw/4 || balances[oldLineId].ReservedByteCount != world.draw/2 || balances[newLineId].ReservedByteCount != 0 {
		t.Fatalf("E-a: the draw reserved %d of the grant, %d of the pack, %d of the old line and %d of the new", balances[newGrantId].ReservedByteCount, balances[world.packId].ReservedByteCount, balances[oldLineId].ReservedByteCount, balances[newLineId].ReservedByteCount)
	}
	// the grant, the pack and an eighth of a draw of the old line
	spent := world.draw/2 + world.draw/8
	if !lease.Spend(spent) {
		t.Fatal("a spend within the draw refused")
	}
	world.oracle.Meter(world.networkId, sidecar.QuotaMeterTls, spent)
	lease.Close()
	world.reportTwice(t, edge, sidecar.QuotaProducerTlsEdge, sidecar.QuotaMeterTls, spent, 0)
	if err := world.oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
	balances = world.balances(t, "after the renewal's debit")
	if balances[newGrantId].ByteCount != 0 || balances[world.packId].ByteCount != 0 || balances[oldLineId].ByteCount != 2*world.draw-world.draw/8 || balances[newLineId].ByteCount != 10*world.draw {
		t.Fatalf("after the renewal's debit: the grant %+v, the pack %+v, the old line %+v, the new line %+v", balances[newGrantId], balances[world.packId], balances[oldLineId], balances[newLineId])
	}

	// Two days on the old line's window has ended and the Team has left its tier, the paid period's line
	// still in window; a pack was bought an hour ago.
	world.clock.Advance(48 * time.Hour)
	world.quota.SetLimits(world.networkId, &sidecar.QuotaLimits{Tier: "free"})
	communityDraw := sidecartest.DefaultFakeQuotaSettings().CommunityLeaseDrawByteCount
	lease = world.lease(t, edge, sidecar.QuotaMeterTls)
	balances = world.balances(t, "E-a, the draw after the downgrade")
	if balances[boughtId].ReservedByteCount != world.draw/8 || balances[newLineId].ReservedByteCount != communityDraw-world.draw/8 || balances[oldLineId].ReservedByteCount != 0 {
		t.Fatalf("E-a after the downgrade: the draw reserved %d of the pack, %d of the line in window and %d of the one ended", balances[boughtId].ReservedByteCount, balances[newLineId].ReservedByteCount, balances[oldLineId].ReservedByteCount)
	}
	lease.Close()
	balances = world.balances(t, "E-b, the close after the downgrade")
	for _, balance := range balances {
		if balance.ReservedByteCount != 0 {
			t.Fatalf("E-b after the downgrade: %d still reserved on %s", balance.ReservedByteCount, balance.BalanceId)
		}
	}
}
