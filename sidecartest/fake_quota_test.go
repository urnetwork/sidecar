// FakeQuota's own rules, beside what quotasuite holds it to: what ages out by a ttl a real store keeps on
// real time, leases that belong to a process, and what a lost or failing Redis does to them.

package sidecartest

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

func newQuotaFixture(t *testing.T) (*FakeQuota, *FakeClock, *FaultQueue) {
	clock := NewFakeClock(DefaultClockStart())
	faults := NewFaultQueue()
	return NewFakeQuota(clock, faults, nil), clock, faults
}

// §20.7's 48 h keys: within them a debit id that passed answers pass and counts nothing, past them it counts
// anew.
func TestFakeQuotaDebitIdsLapseAfterTheirLifetime(t *testing.T) {
	quota, clock, _ := newQuotaFixture(t)
	networkId := connect.NewId()
	quota.SetLimits(networkId, &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{"evs_drops_per_day": 1}})
	debitId := connect.NewId()
	keyAmounts := map[string]int64{sidecar.QuotaRateKeyDrop: 1}
	if refusal, err := quota.CountRate(t.Context(), networkId, keyAmounts, debitId); err != nil || refusal != nil {
		t.Fatalf("refusal %+v, %v", refusal, err)
	}
	clock.Advance(47 * time.Hour)
	if refusal, err := quota.CountRate(t.Context(), networkId, keyAmounts, debitId); err != nil || refusal != nil {
		t.Errorf("a replay within 48 h: %+v, %v", refusal, err)
	}
	clock.Advance(time.Hour)
	// two days on the drop is the day's first again, so the old id counts and the next is refused
	if refusal, err := quota.CountRate(t.Context(), networkId, keyAmounts, debitId); err != nil || refusal != nil {
		t.Errorf("the id past 48 h: %+v, %v", refusal, err)
	}
	if refusal, err := quota.CountRate(t.Context(), networkId, keyAmounts, connect.NewId()); err != nil || refusal == nil {
		t.Errorf("past the day's one drop: %+v, %v", refusal, err)
	}
}

// service_usage_batch's 24 h: a batch id replayed past it applies again, the hazard QUOTA-M10-01 asks a
// stalled drop job to stay inside.
func TestFakeQuotaBatchIdsLapseAfterTheirLifetime(t *testing.T) {
	quota, clock, _ := newQuotaFixture(t)
	networkId := connect.NewId()
	quota.SetBalance(networkId, 1000)
	batch := &sidecar.UsageBatch{
		BatchId:  connect.NewId(),
		Producer: sidecar.QuotaProducerTaskworker,
		Events:   []*sidecar.UsageEvent{{NetworkId: networkId, Meter: sidecar.QuotaMeterEvs, TransferByteCount: 10, StoredByteDelta: -5}},
	}
	for range 2 {
		if err := quota.ReportUsage(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
	}
	if got := quota.StoredDelta(networkId); got != -5 {
		t.Errorf("within 24 h: stored %d", got)
	}
	clock.Advance(24 * time.Hour)
	if err := quota.ReportUsage(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	if got := quota.StoredDelta(networkId); got != -10 {
		t.Errorf("past 24 h: stored %d", got)
	}
}

// FS-46's clause: an edge killed with a lease out debits nothing, and its reservation comes back after
// escrow's 24 h.
func TestFakeQuotaAKilledProcessReservationLapsesWithNoDebit(t *testing.T) {
	quota, clock, _ := newQuotaFixture(t)
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	table := NewActorTable(clock, driver)
	networkId := connect.NewId()
	balanceId := connect.NewId()
	quota.SetBalances(networkId, []*QuotaBalance{{BalanceId: balanceId, ByteCount: 1000, Credit: true}})
	edge := table.Actor(t.Context(), "tlsedge1")
	lease, refusal, err := quota.Lease(edge.Context(), networkId, sidecar.QuotaMeterTls)
	if err != nil || refusal != nil {
		t.Fatalf("refusal %+v, %v", refusal, err)
	}
	if !lease.Spend(300) {
		t.Fatal("spend refused")
	}
	edge.Kill()
	balances := quota.Balances(networkId)
	if balances[0].ByteCount != 1000 || balances[0].ReservedByteCount != 1000 {
		t.Fatalf("after the kill: %+v", balances[0])
	}
	clock.Advance(24*time.Hour - time.Millisecond)
	if got := quota.Balances(networkId)[0].ReservedByteCount; got != 1000 {
		t.Errorf("before 24 h: reserved %d", got)
	}
	clock.Advance(time.Millisecond)
	balances = quota.Balances(networkId)
	if balances[0].ByteCount != 1000 || balances[0].ReservedByteCount != 0 {
		t.Errorf("after 24 h: %+v", balances[0])
	}
}

// One process, one lease per network and meter; a restarted process is another, and its batches carve
// only its own lease.
func TestFakeQuotaLeasesBelongToTheirProcess(t *testing.T) {
	settings := DefaultFakeQuotaSettings()
	settings.CommunityLeaseDrawByteCount = 100
	clock := NewFakeClock(DefaultClockStart())
	quota := NewFakeQuota(clock, nil, settings)
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	table := NewActorTable(clock, driver)
	networkId := connect.NewId()
	balanceId := connect.NewId()
	quota.SetBalances(networkId, []*QuotaBalance{{BalanceId: balanceId, ByteCount: 1000}})
	first := table.Actor(t.Context(), "tlsedge1")
	firstLease, _, err := quota.Lease(first.Context(), networkId, sidecar.QuotaMeterTls)
	if err != nil {
		t.Fatal(err)
	}
	firstLease.Spend(10)
	first.Kill()
	// the restarted process asks again: a lease of its own, beside the dead one's reservation
	second := table.Actor(t.Context(), "tlsedge1")
	secondLease, _, err := quota.Lease(second.Context(), networkId, sidecar.QuotaMeterTls)
	if err != nil {
		t.Fatal(err)
	}
	if got := quota.Balances(networkId)[0].ReservedByteCount; got != 200 {
		t.Errorf("reserved %d, want two draws", got)
	}
	secondLease.Spend(40)
	batch := &sidecar.UsageBatch{
		BatchId:  connect.NewId(),
		Producer: sidecar.QuotaProducerTlsEdge,
		Events:   []*sidecar.UsageEvent{{NetworkId: networkId, Meter: sidecar.QuotaMeterTls, TransferByteCount: 40}},
	}
	if err := quota.ReportUsage(second.Context(), batch); err != nil {
		t.Fatal(err)
	}
	balances := quota.Balances(networkId)
	// the second process's 40 carved; the dead one's 100 still reserved, and nothing debited for it
	if balances[0].ByteCount != 960 || balances[0].ReservedByteCount != 160 {
		t.Errorf("%+v", balances[0])
	}
	secondLease.Close()
}

// §20.15: Redis lost over-admits at most what live leases hold, and the debits still land.
func TestFakeQuotaLosingRedisOverAdmitsAtMostTheLease(t *testing.T) {
	settings := DefaultFakeQuotaSettings()
	settings.CommunityLeaseDrawByteCount = 100
	clock := NewFakeClock(DefaultClockStart())
	quota := NewFakeQuota(clock, nil, settings)
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	table := NewActorTable(clock, driver)
	networkId := connect.NewId()
	quota.SetBalance(networkId, 100)
	edge1 := table.Actor(t.Context(), "tlsedge1")
	edge2 := table.Actor(t.Context(), "tlsedge2")
	lease1, _, err := quota.Lease(edge1.Context(), networkId, sidecar.QuotaMeterTls)
	if err != nil {
		t.Fatal(err)
	}
	if _, refusal, _ := quota.Lease(edge2.Context(), networkId, sidecar.QuotaMeterTls); refusal == nil {
		t.Fatal("a second lease drew a balance the first holds")
	}
	quota.LoseRedis()
	lease2, refusal, err := quota.Lease(edge2.Context(), networkId, sidecar.QuotaMeterTls)
	if err != nil || refusal != nil {
		t.Fatalf("after the loss: %+v, %v", refusal, err)
	}
	// both spend all they hold: the balance's 100 twice, over-admitted by one lease's draw
	if !lease1.Spend(100) || !lease2.Spend(100) {
		t.Fatal("a lease refused what it held")
	}
	if lease1.Spend(1) || lease2.Spend(1) {
		t.Error("spent past what the leases held")
	}
	for index, edge := range []*Actor{edge1, edge2} {
		batch := &sidecar.UsageBatch{
			BatchId:  connect.NewId(),
			Producer: sidecar.QuotaProducerTlsEdge,
			Events:   []*sidecar.UsageEvent{{NetworkId: networkId, Meter: sidecar.QuotaMeterTls, TransferByteCount: 100}},
		}
		if err := quota.ReportUsage(edge.Context(), batch); err != nil {
			t.Fatalf("edge %d: %v", index, err)
		}
	}
	if got := quota.Balances(networkId)[0].ByteCount; got != -100 {
		t.Errorf("debits after the loss: %d left", got)
	}
}

// While Redis fails a lease neither starts nor renews, and one that runs out does not mark the network
// spent, since its balance is not what failed.
func TestFakeQuotaAFailingRedisStopsLeasesWithoutMarkingSpent(t *testing.T) {
	settings := DefaultFakeQuotaSettings()
	settings.CommunityLeaseDrawByteCount = 100
	quota := NewFakeQuota(nil, nil, settings)
	networkId := connect.NewId()
	quota.SetBalance(networkId, 1000)
	lease, _, err := quota.Lease(t.Context(), networkId, sidecar.QuotaMeterTls)
	if err != nil {
		t.Fatal(err)
	}
	quota.SetRedisFailing(true)
	if _, _, err := quota.Lease(t.Context(), connect.NewId(), sidecar.QuotaMeterTls); err == nil {
		t.Error("a lease started while Redis failed")
	}
	if !lease.Spend(100) {
		t.Fatal("the lease refused what it held")
	}
	if lease.Spend(1) {
		t.Error("the lease renewed while Redis failed")
	}
	overLimit, err := quota.OverLimit(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if overLimit.SpentNetworkIdRefusals[networkId] != nil {
		t.Error("a failing Redis marked a funded network spent")
	}
	quota.SetRedisFailing(false)
	if !lease.Spend(1) {
		t.Error("the lease did not renew once Redis came back")
	}
	if refusal, err := quota.CountRate(t.Context(), networkId, map[string]int64{sidecar.QuotaRateKeyDrop: 1}, connect.NewId()); err != nil || refusal == nil {
		t.Errorf("an unset drop limit after Redis came back: %+v, %v", refusal, err)
	}
	quota.SetRedisFailing(true)
	if refusal, err := quota.CountRate(t.Context(), networkId, map[string]int64{sidecar.QuotaRateKeyDrop: 1}, connect.NewId()); err != nil || refusal != nil {
		t.Errorf("while Redis fails: %+v, %v", refusal, err)
	}
	if got := quota.RateFailOpenCount(); got != 1 {
		t.Errorf("fail-opens %d", got)
	}
}

// A refused batch reached the store, so the privacy capture sees it, though nothing applied.
func TestFakeQuotaKeepsRefusedBatchesAsSent(t *testing.T) {
	quota, _, _ := newQuotaFixture(t)
	networkId := connect.NewId()
	refused := &sidecar.UsageBatch{BatchId: connect.NewId(), Producer: sidecar.QuotaProducerEvs, Events: []*sidecar.UsageEvent{{NetworkId: networkId, Meter: "no-such-meter"}}}
	if err := quota.ReportUsage(t.Context(), refused); err == nil {
		t.Fatal("took an unknown meter")
	}
	if len(quota.Batches()) != 0 || len(quota.SentBatches()) != 1 {
		t.Errorf("applied %d, sent %d", len(quota.Batches()), len(quota.SentBatches()))
	}
}

// Leases draw 16 MiB on Community and 64 MiB above it (§20.6).
func TestFakeQuotaDrawsByTier(t *testing.T) {
	quota, _, _ := newQuotaFixture(t)
	for _, c := range []struct {
		tier string
		want int64
	}{
		{tier: "free", want: 16 * 1024 * 1024},
		{tier: "pro", want: 64 * 1024 * 1024},
		{tier: "team", want: 64 * 1024 * 1024},
	} {
		networkId := connect.NewId()
		quota.SetLimits(networkId, &sidecar.QuotaLimits{Tier: c.tier})
		quota.SetBalance(networkId, 1024*1024*1024)
		lease, _, err := quota.Lease(t.Context(), networkId, sidecar.QuotaMeterMx)
		if err != nil {
			t.Fatal(err)
		}
		if got := quota.Balances(networkId)[0].ReservedByteCount; got != c.want {
			t.Errorf("%s: drew %d, want %d", c.tier, got, c.want)
		}
		lease.Close()
	}
}

// NewFaultQuota gives a wrapped Quota the host plans FakeQuota takes itself: here a lost response, which
// applies and then fails, so a retry under the same batch id applies nothing more.
func TestFaultQuotaDropsAWrappedQuotasAnswer(t *testing.T) {
	inner, _, _ := newQuotaFixture(t)
	faults := NewFaultQueue()
	quota := NewFaultQuota(inner, faults)
	networkId := connect.NewId()
	inner.SetBalance(networkId, 1000)
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	batch := &sidecar.UsageBatch{
		BatchId:  connect.NewId(),
		Producer: sidecar.QuotaProducerEvs,
		Events:   []*sidecar.UsageEvent{{NetworkId: networkId, Meter: sidecar.QuotaMeterEvs, TransferByteCount: 100}},
	}
	if err := quota.ReportUsage(t.Context(), batch); err == nil {
		t.Fatal("the plan did not fire")
	}
	if err := quota.ReportUsage(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	if got := inner.Balance(networkId); got != 900 {
		t.Errorf("balance %d", got)
	}
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "quota.Lease", Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := quota.Lease(t.Context(), networkId, sidecar.QuotaMeterTls); err == nil {
		t.Error("the lease plan did not fire")
	}
	if got := inner.Balances(networkId)[0].ReservedByteCount; got != 0 {
		t.Errorf("a lease failed before it applied reserved %d", got)
	}
}

// The fake's pacing is sidecar.QuotaClosurePacing behind the call's own counters: on a fixed-seed run of
// paced uploads, each eraser's 60 a minute judged first, every answer is the reference's, which server's
// {sq_} script is held to in turn (quota_rate_pacing_test.go).
func TestFakeQuotaPacingFollowsTheReference(t *testing.T) {
	for _, perS := range []int64{4, 7} {
		quota, clock, _ := newQuotaFixture(t)
		networkId := connect.NewId()
		quota.SetLimits(networkId, &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{"evs_closure_uploads_per_s": perS}})
		reference := sidecar.NewQuotaClosurePacing()
		eraserMinuteTakes := map[connect.Id]map[int64]int64{}
		random := rand.New(rand.NewPCG(uint64(perS), 652))
		eraserIds := []connect.Id{}
		for range 6 {
			eraserIds = append(eraserIds, connect.NewId())
			eraserMinuteTakes[eraserIds[len(eraserIds)-1]] = map[int64]int64{}
		}
		for step := range 3000 {
			clock.Advance(time.Duration(random.IntN(120*1000)) * time.Microsecond)
			now := clock.Now()
			eraserId := eraserIds[random.IntN(len(eraserIds))]
			refusal, err := quota.CountRate(t.Context(), networkId, map[string]int64{sidecar.QuotaRateKeyClosureUpload(eraserId): 1}, connect.NewId())
			if err != nil {
				t.Fatal(err)
			}
			minute := sidecar.QuotaRateWindowMinute.Index(now)
			var want *sidecar.QuotaRefusal
			if 60 <= eraserMinuteTakes[eraserId][minute] {
				want = &sidecar.QuotaRefusal{LimitKey: "evs_closure_uploads_per_min", Limit: 60, Used: 60, RetryAfterMs: sidecar.QuotaRetryAfterMs(now, sidecar.QuotaRateWindowMinute.End(minute))}
			} else if ok, seatTime, taken := reference.Ask(eraserId, now, perS); !ok {
				want = sidecar.QuotaClosurePacingRefusal(&sidecar.QuotaLimits{Limits: map[string]int64{"evs_closure_uploads_per_s": perS}}, taken, reference.Clock(), seatTime)
			} else {
				reference.Take(eraserId, now, perS)
				eraserMinuteTakes[eraserId][minute] += 1
			}
			if (refusal == nil) != (want == nil) || (refusal != nil && *refusal != *want) {
				t.Fatalf("R = %d, step %d: %+v, want %+v", perS, step, refusal, want)
			}
		}
	}
}

// An upload refused for its turn records nothing under its debit id, so asked again at its seat under the
// same id it is judged afresh and takes; a replay of that pass counts nothing and takes no second seat.
func TestFakeQuotaJudgesARefusedDebitAfresh(t *testing.T) {
	quota, clock, _ := newQuotaFixture(t)
	networkId := connect.NewId()
	firstId := connect.NewId()
	secondId := connect.NewId()
	upload := func(eraserId connect.Id, debitId connect.Id) *sidecar.QuotaRefusal {
		refusal, err := quota.CountRate(t.Context(), networkId, map[string]int64{
			sidecar.QuotaRateKeyClosureUpload(eraserId): 1,
			sidecar.QuotaRateKeyClosureBytes(eraserId):  1024,
		}, debitId)
		if err != nil {
			t.Fatal(err)
		}
		return refusal
	}
	if refusal := upload(firstId, connect.NewId()); refusal != nil {
		t.Fatalf("the first upload: %+v", refusal)
	}
	debitId := connect.NewId()
	refused := upload(secondId, debitId)
	if refused == nil || refused.LimitKey != "evs_closure_uploads_per_s" {
		t.Fatalf("the second eraser's upload: %+v", refused)
	}
	clock.Advance(time.Duration(refused.RetryAfterMs) * time.Millisecond)
	if refusal := upload(secondId, debitId); refusal != nil {
		t.Fatalf("asked again at its seat under its id: %+v", refusal)
	}
	// the replay passes, counts no bytes and leaves the seat its take gave it
	if refusal := upload(secondId, debitId); refusal != nil {
		t.Fatalf("the replay of the pass: %+v", refusal)
	}
	// one cell behind its take, not two: the replay took no seat
	next := upload(secondId, connect.NewId())
	if next == nil || next.LimitKey != "evs_closure_uploads_per_s" || next.RetryAfterMs != 250 {
		t.Fatalf("a new upload past the replayed one: %+v", next)
	}
	rule, err := sidecar.ParseQuotaRateKey(sidecar.QuotaRateKeyClosureBytes(secondId))
	if err != nil {
		t.Fatal(err)
	}
	allowance := rule.Limit(&sidecar.QuotaLimits{Tier: "free"})
	if refusal, err := quota.CountRate(t.Context(), networkId, map[string]int64{sidecar.QuotaRateKeyClosureBytes(secondId): allowance - 1024}, connect.NewId()); err != nil || refusal != nil {
		t.Errorf("the allowance less one upload's bytes: %+v, %v", refusal, err)
	}
}

// An eraser its own allowance refuses is given no seat: an eraser asking after it at the same instant takes
// the cell it would have held.
func TestFakeQuotaGivesNoSeatToAnAskItsAllowanceRefuses(t *testing.T) {
	quota, _, _ := newQuotaFixture(t)
	networkId := connect.NewId()
	spentId := connect.NewId()
	rule, err := sidecar.ParseQuotaRateKey(sidecar.QuotaRateKeyClosureBytes(spentId))
	if err != nil {
		t.Fatal(err)
	}
	allowance := rule.Limit(&sidecar.QuotaLimits{Tier: "free"})
	if refusal, err := quota.CountRate(t.Context(), networkId, map[string]int64{sidecar.QuotaRateKeyClosureBytes(spentId): allowance}, connect.NewId()); err != nil || refusal != nil {
		t.Fatalf("the allowance: %+v, %v", refusal, err)
	}
	refusal, err := quota.CountRate(t.Context(), networkId, map[string]int64{
		sidecar.QuotaRateKeyClosureUpload(spentId): 1,
		sidecar.QuotaRateKeyClosureBytes(spentId):  1,
	}, connect.NewId())
	if err != nil || refusal == nil || refusal.LimitKey != "evs_closure_bytes_per_day" {
		t.Fatalf("past the allowance: %+v, %v", refusal, err)
	}
	otherId := connect.NewId()
	if refusal, err := quota.CountRate(t.Context(), networkId, map[string]int64{sidecar.QuotaRateKeyClosureUpload(otherId): 1}, connect.NewId()); err != nil || refusal != nil {
		t.Errorf("the next eraser at the same instant: %+v, %v", refusal, err)
	}
}
