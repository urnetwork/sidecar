package controller

// compute_settle's draws and a rebuild's snapshot as far as the sidecar repo sees them (BAL-M12-04): §9.4's draw order,
// a search passing over promotions, an overrun left in settled, a refund's reverse draws (a reversed lot passed over,
// an expired promotion forfeiting its part), a support credit drawing nothing, the rollups a refund adds, and a
// snapshot's holds, unsettled charges and this UTC day's and month's counters. The booking on real PostgreSQL and
// Redis runs in server/computet3/compute_book_t3_test.go.

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

const testBookUsd = int64(1_000_000_000)

// A lot of kind with amount left, made at created, expiring at expire where it is a promotion.
func testBookLot(first byte, kind model.ComputeLotKind, remaining int64, created time.Time, expire *time.Time) *model.ComputeLot {
	return &model.ComputeLot{
		LotId: testOpKeyId(first), NetworkId: testOpKeyId(0x10), Kind: kind, Market: model.ComputeMarketStripe,
		AmountNanoUsd: remaining, RemainingNanoUsd: remaining, CreateTime: created, ExpireTime: expire,
	}
}

// A charge of kind and amount, its key from first.
func testBookCharge(first byte, kind model.ComputeChargeKind, amount int64, start time.Time) *model.ComputeCharge {
	return &model.ComputeCharge{
		ChargeId: testOpKeyId(first), NetworkId: testOpKeyId(0x10), Kind: kind, SubjectRef: testOpKeyId(first + 1),
		SidecarId: testOpKeyId(0x20), Provider: 1, AmountNanoUsd: amount, StartTime: start, EndTime: start, SettleTime: start,
	}
}

// The draws a charge made, as lot first bytes and amounts.
func testBookDrawsOf(plan *computeDraws, chargeId operator.Id) [][2]int64 {
	draws := [][2]int64{}
	for _, draw := range plan.draws {
		if draw.ChargeId == chargeId {
			draws = append(draws, [2]int64{int64(draw.LotId[0]), draw.AmountNanoUsd})
		}
	}
	return draws
}

// A charge draws promotions first, nearest expiry first, then subscription grants, then purchases, oldest first, in
// the order the lots arrive, which is ComputeLotsForDrawInTx's; a search passes over promotions; an overrun no lot
// covers is left in settled, which falls by every charge in full.
func TestComputeDrawPlanFollowsTheDrawOrder(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	soon, later := now.Add(24*time.Hour), now.Add(10*24*time.Hour)
	lots := []*model.ComputeLot{
		testBookLot(0xa0, model.ComputeLotKindPromotion, 1*testBookUsd, now.Add(-time.Hour), &soon),
		testBookLot(0xa1, model.ComputeLotKindPromotion, 2*testBookUsd, now.Add(-2*time.Hour), &later),
		testBookLot(0xa2, model.ComputeLotKindSubscription, 3*testBookUsd, now.Add(-3*time.Hour), nil),
		testBookLot(0xa3, model.ComputeLotKindPurchase, 4*testBookUsd, now.Add(-4*time.Hour), nil),
	}
	call := testBookCharge(0x01, model.ComputeChargeKindInference, 2*testBookUsd+testBookUsd/2, now)
	search := testBookCharge(0x03, model.ComputeChargeKindWebSearch, testBookUsd, now.Add(time.Second))
	big := testBookCharge(0x05, model.ComputeChargeKindInference, 7*testBookUsd, now.Add(2*time.Second))
	plan := computeDrawPlan(lots, nil, nil, []*model.ComputeCharge{call, search, big}, now)
	// $2.50: the $1 promotion expiring first, then $1.50 of the other
	if got := testBookDrawsOf(plan, call.ChargeId); !slices.Equal(got, [][2]int64{{0xa0, testBookUsd}, {0xa1, testBookUsd + testBookUsd/2}}) {
		t.Errorf("the call drew %v", got)
	}
	// $1 of search: past the $0.50 of promotion left, from the subscription
	if got := testBookDrawsOf(plan, search.ChargeId); !slices.Equal(got, [][2]int64{{0xa2, testBookUsd}}) {
		t.Errorf("the search drew %v", got)
	}
	// $7: the promotion's $0.50, the subscription's $2, the purchase's $4, and $0.50 over
	if got := testBookDrawsOf(plan, big.ChargeId); !slices.Equal(got, [][2]int64{{0xa1, testBookUsd / 2}, {0xa2, 2 * testBookUsd}, {0xa3, 4 * testBookUsd}}) {
		t.Errorf("the large call drew %v", got)
	}
	if plan.settledDelta != 2*testBookUsd+testBookUsd/2+testBookUsd+7*testBookUsd {
		t.Errorf("settled falls by %d", plan.settledDelta)
	}
	// each lot's change is what it lost, and every lot is empty
	changes := map[byte]int64{}
	for _, change := range plan.lotChanges() {
		changes[change.LotId[0]] = change.RemainingDelta
	}
	if changes[0xa0] != -testBookUsd || changes[0xa1] != -2*testBookUsd || changes[0xa2] != -3*testBookUsd || changes[0xa3] != -4*testBookUsd {
		t.Errorf("the lots change by %v", changes)
	}
	// each charge's draws are indexed from 0
	for _, draw := range plan.draws {
		if draw.ChargeId == big.ChargeId && draw.LotId[0] == 0xa3 && draw.DrawIndex != 2 {
			t.Errorf("the purchase's draw is at %d", draw.DrawIndex)
		}
	}
}

// A refund gives back to the lots its charge drew in reverse draw order, as negative draws, never past a draw; a
// reversed lot gets nothing; an expired promotion's part lapses rather than returning; settled rises by the refund
// less what it forfeited. A support credit draws nothing and raises settled.
func TestComputeDrawPlanReturnsARefundInReverse(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Hour)
	reversedAt := now.Add(-2 * time.Hour)
	promotion := testBookLot(0xb0, model.ComputeLotKindPromotion, 0, now.Add(-40*24*time.Hour), &expired)
	reversed := testBookLot(0xb1, model.ComputeLotKindPurchase, 0, now.Add(-20*24*time.Hour), nil)
	reversed.ReversedTime = &reversedAt
	purchase := testBookLot(0xb2, model.ComputeLotKindPurchase, testBookUsd, now.Add(-10*24*time.Hour), nil)
	refundedId := testOpKeyId(0x40)
	prior := map[operator.Id][]*model.ComputeChargeDraw{
		refundedId: {
			{ChargeId: refundedId, LotId: promotion.LotId, AmountNanoUsd: testBookUsd, DrawIndex: 0},
			{ChargeId: refundedId, LotId: reversed.LotId, AmountNanoUsd: testBookUsd, DrawIndex: 1},
			{ChargeId: refundedId, LotId: purchase.LotId, AmountNanoUsd: testBookUsd, DrawIndex: 2},
		},
	}
	refund := testBookCharge(0x50, model.ComputeChargeKindInference, -(2*testBookUsd + testBookUsd/2), now)
	refund.SubjectRef = refundedId
	credit := testBookCharge(0x60, model.ComputeChargeKindAdjustment, -testBookUsd, now)
	others := map[operator.Id]*model.ComputeLot{promotion.LotId: promotion, reversed.LotId: reversed}
	plan := computeDrawPlan([]*model.ComputeLot{purchase}, others, prior, []*model.ComputeCharge{refund, credit}, now)
	// $2.50 back: $1 to the purchase, the reversed lot's $1 passed over, $0.50 of the expired promotion
	if got := testBookDrawsOf(plan, refund.ChargeId); !slices.Equal(got, [][2]int64{{0xb2, -testBookUsd}, {0xb0, -testBookUsd / 2}}) {
		t.Errorf("the refund drew %v", got)
	}
	if len(testBookDrawsOf(plan, credit.ChargeId)) != 0 {
		t.Error("a support credit drew a lot")
	}
	changes := map[byte]*model.ComputeLotChange{}
	for _, change := range plan.lotChanges() {
		changes[change.LotId[0]] = change
	}
	if changes[0xb2].RemainingDelta != testBookUsd || changes[0xb0].RemainingDelta != 0 || changes[0xb0].LapsedAddNanoUsd != testBookUsd/2 || changes[0xb1] != nil {
		t.Errorf("the lots change by %+v, %+v, %+v", changes[0xb2], changes[0xb0], changes[0xb1])
	}
	// settled rises by the refund's $2.50 less the $0.50 forfeited, and by the credit's $1
	if plan.settledDelta != -(2*testBookUsd)-testBookUsd {
		t.Errorf("settled falls by %d", plan.settledDelta)
	}
}

// A refund's rollup adds its negative amount and its size to refunded, with no count and no units; a charge adds its
// units, amount and a count of one; a support credit is a charge of the network's own line, counted.
func TestComputeRollupOfARefundAddsNoCount(t *testing.T) {
	now := time.Date(2026, 11, 25, 23, 59, 30, 0, time.UTC)
	charge := testBookCharge(0x01, model.ComputeChargeKindInference, testBookUsd, now)
	charge.Units = model.ComputeUnits{InputTokens: 10, OutputTokens: 20}
	refund := testBookCharge(0x03, model.ComputeChargeKindInference, -testBookUsd/4, now.Add(time.Minute))
	refund.Units = model.ComputeUnits{InputTokens: 99}
	credit := testBookCharge(0x05, model.ComputeChargeKindAdjustment, -testBookUsd, now)
	add := model.ComputeRollupAddOf(charge)
	if add.Count != 1 || add.AmountNanoUsd != testBookUsd || add.RefundedNanoUsd != 0 || add.Units.OutputTokens != 20 || !add.Day.Equal(time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("a charge adds %+v", add)
	}
	add = model.ComputeRollupAddOf(refund)
	// the refund, written a minute later, counts to its own UTC day, the next
	if add.Count != 0 || add.AmountNanoUsd != -testBookUsd/4 || add.RefundedNanoUsd != testBookUsd/4 || add.Units != (model.ComputeUnits{}) || !add.Day.Equal(time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("a refund adds %+v", add)
	}
	add = model.ComputeRollupAddOf(credit)
	if add.Count != 1 || add.AmountNanoUsd != -testBookUsd || add.RefundedNanoUsd != 0 {
		t.Errorf("a credit adds %+v", add)
	}
}

// §16.5's default lines for an op's subjects, as a broker without CACL's resolver gives them.
func testBookBudgets(settings *model.ComputeLedgerSettings) ComputeBudgetLines {
	return func(ctx context.Context, subjects *ComputeBudgetSubjects) ([]*model.ComputeBudgetLine, error) {
		return model.ComputeDefaultBudgetLines(settings, &model.ComputeBudgetCaller{SidecarId: subjects.SidecarId, AgentId: subjects.AgentId})
	}
}

// A snapshot holds each open row as a hold with its lines, each settled row's charge as an unsettled charge and in its
// counters, and this UTC day's and month's booked charges by their lines; refunds, enclave kinds' budgets, other days
// and other months stay out.
func TestComputeRebuildSnapshotCountsTodayAndThisMonth(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	networkId, sidecarId, agentId := testOpKeyId(0x10), testOpKeyId(0x20), testOpKeyId(0x30)
	open := &model.ComputeOp{
		OpKey: testOpKeyId(0x40), NetworkId: networkId, State: model.ComputeOpStateOpen, Kind: model.ComputeChargeKindInference,
		SidecarId: sidecarId, AgentId: &agentId, HoldNanoUsd: 2 * testBookUsd, ReserveNanoUsd: 2 * testBookUsd, StartTime: now,
	}
	settled := &model.ComputeOp{
		OpKey: testOpKeyId(0x50), NetworkId: networkId, State: model.ComputeOpStateSettled, Kind: model.ComputeChargeKindInference,
		SidecarId: sidecarId, AgentId: &agentId, HoldNanoUsd: testBookUsd, ReserveNanoUsd: testBookUsd, StartTime: now,
		Outcome: &model.ComputeOpOutcome{AmountNanoUsd: testBookUsd / 4},
	}
	refund := &model.ComputeOp{
		OpKey: testOpKeyId(0x60), NetworkId: networkId, State: model.ComputeOpStateSettled, Kind: model.ComputeChargeKindInference,
		SidecarId: sidecarId, AgentId: &agentId, StartTime: now, Outcome: &model.ComputeOpOutcome{AmountNanoUsd: -testBookUsd},
	}
	enclaveId := testOpKeyId(0x70)
	egress := &model.ComputeOp{
		OpKey: testOpKeyId(0x80), NetworkId: networkId, State: model.ComputeOpStateSettled, Kind: model.ComputeChargeKindEnclaveHostEgress,
		SidecarId: sidecarId, EnclaveId: &enclaveId, StartTime: now, Outcome: &model.ComputeOpOutcome{AmountNanoUsd: testBookUsd / 10},
	}
	days := []*model.ComputeBookedDay{
		// today: the agent's $1, the device's own $2 (no agent)
		{Day: model.ComputeUtcDay(now), Kind: model.ComputeChargeKindInference, SidecarId: sidecarId, AgentId: &agentId, ChargedNanoUsd: testBookUsd},
		{Day: model.ComputeUtcDay(now), Kind: model.ComputeChargeKindWebSearch, SidecarId: sidecarId, ChargedNanoUsd: 2 * testBookUsd},
		// earlier this month: the agent's $3
		{Day: model.ComputeUtcDay(now.Add(-5 * 24 * time.Hour)), Kind: model.ComputeChargeKindInference, SidecarId: sidecarId, AgentId: &agentId, ChargedNanoUsd: 3 * testBookUsd},
	}
	account := &model.ComputeProjectionAccount{Version: 9, SettledNanoUsd: 10 * testBookUsd, State: model.ComputeAccountStateActive}
	snapshot, err := computeRebuildSnapshot(context.Background(), networkId, account, []*model.ComputeOp{open, settled, refund, egress}, days, testBookBudgets(settings), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Holds) != 1 || snapshot.Holds[0].OpKey != open.OpKey || len(snapshot.Holds[0].Lines) != 3 {
		t.Errorf("holds %+v", snapshot.Holds)
	}
	charges := map[byte]int64{}
	for _, charge := range snapshot.Charges {
		charges[charge.OpKey[0]] = charge.AmountNanoUsd
	}
	if len(charges) != 2 || charges[0x50] != testBookUsd/4 || charges[0x80] != testBookUsd/10 {
		t.Errorf("unsettled charges %v", charges)
	}
	counters := map[string]int64{}
	for _, counter := range snapshot.Counters {
		counters[string(counter.SubjectId[0:1])+counter.Budget+counter.Period.String()] = counter.ChargedNanoUsd
	}
	agent, sidecar := string(agentId[0:1]), string(sidecarId[0:1])
	want := map[string]int64{
		// the agent: today's $1 booked and $0.25 unbooked; this month's also the $3
		agent + "agentday":   testBookUsd + testBookUsd/4,
		agent + "agentmonth": 3*testBookUsd + testBookUsd + testBookUsd/4,
		// the device's own budget: the search with no agent, today and this month
		sidecar + "deviceday":   2 * testBookUsd,
		sidecar + "devicemonth": 2 * testBookUsd,
		// the device's ceiling, a day's only: every call of the device today
		sidecar + "ceilingday": testBookUsd + testBookUsd/4 + 2*testBookUsd,
	}
	if len(counters) != len(want) {
		t.Errorf("counters %v, want %v", counters, want)
	}
	for key, amount := range want {
		if counters[key] != amount {
			t.Errorf("counter %q is %d, want %d", key, counters[key], amount)
		}
	}
}

// A resolver that fails fails the snapshot, so a rebuild writes nothing it cannot count; and with no resolver a
// rebuild is refused before any store is asked.
func TestComputeRebuildNeedsItsBudgets(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	failing := func(ctx context.Context, subjects *ComputeBudgetSubjects) ([]*model.ComputeBudgetLine, error) {
		return nil, model.ErrComputeBudgetsUnread
	}
	open := &model.ComputeOp{OpKey: testOpKeyId(0x40), State: model.ComputeOpStateOpen, Kind: model.ComputeChargeKindInference, SidecarId: testOpKeyId(0x20), StartTime: now}
	account := &model.ComputeProjectionAccount{State: model.ComputeAccountStateActive}
	if _, err := computeRebuildSnapshot(context.Background(), testOpKeyId(0x10), account, []*model.ComputeOp{open}, nil, failing, now); !errors.Is(err, model.ErrComputeBudgetsUnread) {
		t.Errorf("a failing resolver: %v", err)
	}
	env := newTestLedgerEnv()
	if _, err := ComputeRebuild(env, context.Background(), model.DefaultComputeLedgerSettings(), testOpKeyId(0x10), nil); !errors.Is(err, ErrComputeRebuildNoBudgets) {
		t.Errorf("no resolver: %v", err)
	}
	if len(env.redis.calls) != 0 || env.db.callCount != 0 {
		t.Error("a rebuild with no resolver reached the stores")
	}
}

// A source registered for a kind no hold path takes, or twice for one kind, panics.
func TestComputeRecoverSourceRegistrationRefusesWhatHoldsNothing(t *testing.T) {
	panics := func(register func()) (panicked bool) {
		defer func() { panicked = recover() != nil }()
		register()
		return false
	}
	if !panics(func() { RegisterComputeRecoverSource(model.ComputeChargeKindAdjustment, nil) }) {
		t.Error("an adjustment source registered")
	}
	if !panics(func() { RegisterComputeRecoverSource(model.ComputeChargeKindEnclaveHostEgress, nil) }) {
		t.Error("a host egress source registered")
	}
}
