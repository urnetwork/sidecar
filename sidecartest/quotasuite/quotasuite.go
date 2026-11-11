// The conformance suite for sidecar.Quota (§22.4): what host_quota.go and host_quota_keys.go promise,
// run on sidecartest.FakeQuota at T2 and on server's Quota at T3 (QUOTA-M2-11), so what an engine built
// on the fake keeps holding on the real thing, and a divergence fails here first.
//
// A case is a plain function returning its first failure, and Run loops over them, since they are
// variations of one Quota's behavior (connect/CODESTYLE.md:216). Each case gets a fresh target from
// NewTarget and makes new networks, so no case sees another's counts. RunLimits, RunRates, RunUsage and
// RunLeases run one group each, for a target whose other parts have not landed yet.
//
// Time is the target's FakeClock: windows turn when a case moves it, as the real Quota counts windows on
// the clock its host gives the script (QUOTA-M2-03). What a real store ages out by its own ttl, debit
// ids and reservations, runs on real time there, so those rules are each target's own tests' to hold.

package quotasuite

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One Quota under test, with the levers a case needs that the interface does not give.
type Target struct {
	Quota sidecar.Quota
	// The clock Quota counts its windows on, which cases move.
	Clock *sidecartest.FakeClock
	// The queue Quota's calls take host plans from, by FaultOpHost and "quota.<Method>", as FakeQuota's
	// do. A real Quota reaches it through sidecartest.NewFaultQuota.
	Faults *sidecartest.FaultQueue
	// Makes a network's tier and these keys read as given, as pro.yml and network_sidecar_limit rows
	// would. Keys not given read as the store reads them.
	SetLimits func(networkId connect.Id, limits *sidecar.QuotaLimits) error
	// Replaces a network's transfer balances.
	SetBalances func(networkId connect.Id, balances []*sidecartest.QuotaBalance) error
	// A network's balances in draw order as the store holds them, each with what reservations hold of it.
	ReadBalances func(networkId connect.Id) ([]*sidecartest.QuotaBalance, error)
	// Applies what the store leaves for later, as T3's debit flush. nil where debits apply at once.
	Settle func() error
	// Forgets every rate counter, debit id, pacing seat and reservation, as a Redis failover does.
	LoseRedis func() error
	// Makes the Quota's Redis fail, or work again.
	SetRedisFailing func(failing bool) error
	// What one lease draw reserves above Community and on it, and the fraction of a draw spent before a
	// lease reserves the next: the target's settings.
	LeaseDrawByteCount          int64
	CommunityLeaseDrawByteCount int64
	LeaseRenewFraction          float64
}

// A fresh target for one case.
type NewTarget func(t *testing.T) *Target

type suiteCase struct {
	name string
	run  func(ctx context.Context, target *Target) error
}

// Every case.
func Run(t *testing.T, newTarget NewTarget) {
	t.Helper()
	runCases(t, newTarget, limitCases(), rateCases(), usageCases(), leaseCases())
}

// Limits and ids.
func RunLimits(t *testing.T, newTarget NewTarget) {
	t.Helper()
	runCases(t, newTarget, limitCases())
}

// CountRate: windows, debit ids, allowances, the floor and the pacing by seat.
func RunRates(t *testing.T, newTarget NewTarget) {
	t.Helper()
	runCases(t, newTarget, rateCases())
}

// ReportUsage and the debits it makes.
func RunUsage(t *testing.T, newTarget NewTarget) {
	t.Helper()
	runCases(t, newTarget, usageCases())
}

// Leases over balances.
func RunLeases(t *testing.T, newTarget NewTarget) {
	t.Helper()
	runCases(t, newTarget, leaseCases())
}

func runCases(t *testing.T, newTarget NewTarget, groups ...[]*suiteCase) {
	t.Helper()
	for _, cases := range groups {
		for _, c := range cases {
			if err := c.run(t.Context(), newTarget(t)); err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
		}
	}
}

func limitCases() []*suiteCase {
	return []*suiteCase{
		{name: "limits-read-back-as-set", run: caseLimitsReadBackAsSet},
		{name: "zero-ids-are-errors", run: caseZeroIdsAreErrors},
	}
}

func rateCases() []*suiteCase {
	return []*suiteCase{
		{name: "caller-bugs-are-errors", run: caseRateCallerBugsAreErrors},
		{name: "count-rate-is-all-or-none", run: caseCountRateIsAllOrNone},
		{name: "a-debit-counts-once-across-a-lost-response", run: caseADebitCountsOnce},
		{name: "a-passed-debit-replays-and-a-refused-one-is-judged-afresh", run: caseAReplayIsJudgedByItsPass},
		{name: "minute-windows-turn-on-the-clock", run: caseMinuteWindowsTurn},
		{name: "day-windows-turn-at-utc-midnight", run: caseDayWindowsTurn},
		{name: "an-erasers-allowance-is-its-own", run: caseAnErasersAllowanceIsItsOwn},
		{name: "the-allowance-never-reads-below-the-floor", run: caseTheAllowanceReadsTheFloor},
		{name: "an-eraser-past-its-minute-leaves-another-passing", run: caseAnEraserPastItsMinute},
		{name: "the-pacing-gives-equal-turns", run: casePacingGivesEqualTurns},
		{name: "a-waiting-eraser-keeps-its-place", run: caseAWaitingEraserKeepsItsPlace},
		{name: "erasers-returning-together-take-their-seats", run: caseErasersReturningTogether},
		{name: "an-upload-refused-for-its-turn-asks-again-under-its-id", run: caseARefusedUploadAsksAgain},
		{name: "an-eraser-its-allowance-refuses-holds-no-seat", run: caseAnAllowanceRefusalHoldsNoSeat},
		{name: "redis-lost-or-failing-opens-the-rates", run: caseRedisLostOrFailing},
	}
}

func usageCases() []*suiteCase {
	return []*suiteCase{
		{name: "a-batch-applies-once-across-a-lost-response", run: caseABatchAppliesOnce},
		{name: "a-refused-batch-applies-nothing", run: caseARefusedBatchAppliesNothing},
		{name: "evs-bytes-debit-in-draw-order", run: caseEvsBytesDebitInDrawOrder},
		{name: "evs-bytes-past-every-balance-mark-spent", run: caseEvsBytesPastEveryBalance},
		{name: "a-network-with-no-balance-is-spent", run: caseNoBalanceIsSpent},
	}
}

func leaseCases() []*suiteCase {
	return []*suiteCase{
		{name: "a-lease-draws-in-order-and-gives-back-in-reverse", run: caseALeaseDrawsInOrder},
		{name: "a-refused-lease-marks-spent-until-one-draws", run: caseARefusedLeaseMarksSpent},
		{name: "a-lease-renews-past-its-fraction", run: caseALeaseRenews},
		{name: "spend-stops-at-the-balance", run: caseSpendStopsAtTheBalance},
		{name: "handles-share-their-processs-lease", run: caseHandlesShareTheirLease},
		{name: "a-lease-names-a-meter", run: caseALeaseNamesAMeter},
	}
}

// The limit keys the grammar's refusals name.
const (
	limitKeyClosureUploadsPerS   = "evs_closure_uploads_per_s"
	limitKeyClosureUploadsPerMin = "evs_closure_uploads_per_min"
	limitKeyClosureBytesPerDay   = "evs_closure_bytes_per_day"
	limitKeyClosureBytesFloor    = "evs_closure_bytes_floor"
	limitKeyErasurePushesPerMin  = "evs_erasure_pushes_per_min"
	limitKeyDropsPerDay          = "evs_drops_per_day"
	limitKeyReadReceipts         = "evs_read_receipts_per_repo_day"
)

func retryAfter(refusal *sidecar.QuotaRefusal) time.Duration {
	return time.Duration(refusal.RetryAfterMs) * time.Millisecond
}

// One CountRate or Lease answer, so a check takes a call's two results whole.
type rateAnswer struct {
	refusal *sidecar.QuotaRefusal
	err     error
}

func answered(refusal *sidecar.QuotaRefusal, err error) rateAnswer {
	return rateAnswer{refusal: refusal, err: err}
}

func expectNoRefusal(what string, answer rateAnswer) error {
	if answer.err != nil {
		return fmt.Errorf("%s: %w", what, answer.err)
	}
	if answer.refusal != nil {
		return fmt.Errorf("%s: refused %+v", what, answer.refusal)
	}
	return nil
}

func expectRefusal(what string, answer rateAnswer, limitKey string) error {
	if answer.err != nil {
		return fmt.Errorf("%s: %w", what, answer.err)
	}
	if answer.refusal == nil {
		return fmt.Errorf("%s: passed", what)
	}
	if answer.refusal.LimitKey != limitKey {
		return fmt.Errorf("%s: refused for %q, want %q", what, answer.refusal.LimitKey, limitKey)
	}
	return nil
}

// A network with limits set, for a case.
func newNetwork(target *Target, tier string, limits map[string]int64) (connect.Id, error) {
	networkId := connect.NewId()
	if err := target.SetLimits(networkId, &sidecar.QuotaLimits{Tier: tier, Limits: limits}); err != nil {
		return networkId, err
	}
	return networkId, nil
}

func countOnce(ctx context.Context, target *Target, networkId connect.Id, key string, amount int64) (*sidecar.QuotaRefusal, error) {
	return target.Quota.CountRate(ctx, networkId, map[string]int64{key: amount}, connect.NewId())
}

// Counts one closure upload, waiting out its turn of the pacing as an obedient eraser does: any other
// refusal comes back.
func countPacedUpload(ctx context.Context, target *Target, networkId connect.Id, eraserId connect.Id) (*sidecar.QuotaRefusal, error) {
	key := sidecar.QuotaRateKeyClosureUpload(eraserId)
	for range 1000 {
		refusal, err := countOnce(ctx, target, networkId, key, 1)
		if err != nil || refusal == nil || refusal.LimitKey != limitKeyClosureUploadsPerS {
			return refusal, err
		}
		target.Clock.Advance(retryAfter(refusal))
	}
	return nil, errors.New("a thousand turns never came")
}

// The settled balances by id.
func settledBalances(target *Target, networkId connect.Id) (map[connect.Id]*sidecartest.QuotaBalance, error) {
	if target.Settle != nil {
		if err := target.Settle(); err != nil {
			return nil, err
		}
	}
	balances, err := target.ReadBalances(networkId)
	if err != nil {
		return nil, err
	}
	idBalances := map[connect.Id]*sidecartest.QuotaBalance{}
	for _, balance := range balances {
		idBalances[balance.BalanceId] = balance
	}
	return idBalances, nil
}

func expectBalance(idBalances map[connect.Id]*sidecartest.QuotaBalance, what string, balanceId connect.Id, byteCount int64, reservedByteCount int64) error {
	balance, ok := idBalances[balanceId]
	if !ok {
		return fmt.Errorf("%s: no balance %s", what, balanceId)
	}
	if balance.ByteCount != byteCount || balance.ReservedByteCount != reservedByteCount {
		return fmt.Errorf("%s: %d left and %d reserved, want %d and %d", what, balance.ByteCount, balance.ReservedByteCount, byteCount, reservedByteCount)
	}
	return nil
}

func isSpent(ctx context.Context, target *Target, networkId connect.Id) (bool, error) {
	overLimit, err := target.Quota.OverLimit(ctx)
	if err != nil {
		return false, err
	}
	return overLimit.SpentNetworkIdRefusals[networkId] != nil, nil
}

func caseLimitsReadBackAsSet(ctx context.Context, target *Target) error {
	set := map[string]int64{limitKeyDropsPerDay: 7, "storage": 100 * 1024 * 1024, "mail_burners_active": -1}
	networkId, err := newNetwork(target, "pro", set)
	if err != nil {
		return err
	}
	limits, err := target.Quota.Limits(ctx, networkId)
	if err != nil {
		return err
	}
	if limits.Tier != "pro" {
		return fmt.Errorf("tier %q", limits.Tier)
	}
	for key, value := range set {
		if limits.Limits[key] != value {
			return fmt.Errorf("%s reads %d, want %d", key, limits.Limits[key], value)
		}
	}
	return nil
}

// host_quota.go: a zero id is the caller's bug and an error, never a lookup, so nothing counts.
func caseZeroIdsAreErrors(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", map[string]int64{limitKeyDropsPerDay: 1})
	if err != nil {
		return err
	}
	zero := connect.Id{}
	if _, err := target.Quota.Limits(ctx, zero); err == nil {
		return errors.New("Limits took a zero network")
	}
	if _, err := target.Quota.CountRate(ctx, zero, map[string]int64{sidecar.QuotaRateKeyDrop: 1}, connect.NewId()); err == nil {
		return errors.New("CountRate took a zero network")
	}
	// two debits sharing a zero id would read as one retried, the second counting nothing
	for range 2 {
		if _, err := target.Quota.CountRate(ctx, networkId, map[string]int64{sidecar.QuotaRateKeyDrop: 1}, zero); err == nil {
			return errors.New("CountRate took a zero debit")
		}
	}
	if _, _, err := target.Quota.Lease(ctx, zero, sidecar.QuotaMeterTls); err == nil {
		return errors.New("Lease took a zero network")
	}
	event := &sidecar.UsageEvent{NetworkId: networkId, Meter: sidecar.QuotaMeterEvs, TransferByteCount: 1}
	if err := target.Quota.ReportUsage(ctx, &sidecar.UsageBatch{Producer: sidecar.QuotaProducerEvs, Events: []*sidecar.UsageEvent{event}}); err == nil {
		return errors.New("ReportUsage took a zero batch")
	}
	// the zero-debit calls counted nothing, so the one drop is still there
	return expectNoRefusal("the day's drop", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1)))
}

// A key no family names, a negative count, or a paced key counted other than once alone, counts nothing.
func caseRateCallerBugsAreErrors(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", map[string]int64{limitKeyDropsPerDay: 1})
	if err != nil {
		return err
	}
	eraserId := connect.NewId()
	for _, keyAmounts := range []map[string]int64{
		{sidecar.QuotaRateKeyDrop: 1, "a": 1},
		{sidecar.QuotaRateKeyDrop: 1, "evs_closure_uploads:" + eraserId.String() + ":x": 1},
		{sidecar.QuotaRateKeyDrop: -1},
		{sidecar.QuotaRateKeyDrop: 1, sidecar.QuotaRateKeyClosureUpload(eraserId): 2},
		{sidecar.QuotaRateKeyClosureUpload(eraserId): 1, sidecar.QuotaRateKeyClosureUpload(connect.NewId()): 1},
	} {
		if refusal, err := target.Quota.CountRate(ctx, networkId, keyAmounts, connect.NewId()); err == nil {
			return fmt.Errorf("%v: answered %+v and no error", keyAmounts, refusal)
		}
	}
	return expectNoRefusal("the day's drop", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1)))
}

func caseCountRateIsAllOrNone(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", map[string]int64{limitKeyDropsPerDay: 2, limitKeyReadReceipts: 5})
	if err != nil {
		return err
	}
	repoId := connect.NewId()
	refusal, err := target.Quota.CountRate(ctx, networkId, map[string]int64{
		sidecar.QuotaRateKeyDrop:                1,
		sidecar.QuotaRateKeyReadReceipt(repoId): 6,
	}, connect.NewId())
	if err := expectRefusal("six receipts", answered(refusal, err), limitKeyReadReceipts); err != nil {
		return err
	}
	if refusal.Limit != 5 || refusal.Used != 0 {
		return fmt.Errorf("refusal %+v", refusal)
	}
	// nothing of that debit counted, so both drops are still there
	if err := expectNoRefusal("two drops", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 2))); err != nil {
		return err
	}
	return expectRefusal("a third drop", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1)), limitKeyDropsPerDay)
}

func caseADebitCountsOnce(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", map[string]int64{limitKeyDropsPerDay: 1})
	if err != nil {
		return err
	}
	if _, err := target.Faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.CountRate", Result: sidecartest.ApplyThenDrop}); err != nil {
		return err
	}
	debitId := connect.NewId()
	keyAmounts := map[string]int64{sidecar.QuotaRateKeyDrop: 1}
	if _, err := target.Quota.CountRate(ctx, networkId, keyAmounts, debitId); err == nil {
		return errors.New("the lost response came back")
	}
	if err := expectNoRefusal("the retry", answered(target.Quota.CountRate(ctx, networkId, keyAmounts, debitId))); err != nil {
		return err
	}
	return expectRefusal("a new debit past the limit", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1)), limitKeyDropsPerDay)
}

// DESIGN-DETAILS 13.2.1: a debit id that passed answers pass again and counts nothing; one that was refused
// recorded nothing, so asked again it is judged afresh, and once it passes it too replays as passed.
func caseAReplayIsJudgedByItsPass(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", map[string]int64{limitKeyDropsPerDay: 1})
	if err != nil {
		return err
	}
	keyAmounts := map[string]int64{sidecar.QuotaRateKeyDrop: 1}
	passedId := connect.NewId()
	if err := expectNoRefusal("the day's drop", answered(target.Quota.CountRate(ctx, networkId, keyAmounts, passedId))); err != nil {
		return err
	}
	if err := expectNoRefusal("the passed debit replayed", answered(target.Quota.CountRate(ctx, networkId, keyAmounts, passedId))); err != nil {
		return err
	}
	refusedId := connect.NewId()
	first, err := target.Quota.CountRate(ctx, networkId, keyAmounts, refusedId)
	if err := expectRefusal("a second drop", answered(first, err), limitKeyDropsPerDay); err != nil {
		return err
	}
	if err := expectRefusal("the refused debit asked again the same day", answered(target.Quota.CountRate(ctx, networkId, keyAmounts, refusedId)), limitKeyDropsPerDay); err != nil {
		return err
	}
	target.Clock.Advance(retryAfter(first))
	if err := expectNoRefusal("the refused debit on the next day", answered(target.Quota.CountRate(ctx, networkId, keyAmounts, refusedId))); err != nil {
		return err
	}
	if err := expectNoRefusal("its pass replayed", answered(target.Quota.CountRate(ctx, networkId, keyAmounts, refusedId))); err != nil {
		return err
	}
	if err := expectNoRefusal("yesterday's pass replayed", answered(target.Quota.CountRate(ctx, networkId, keyAmounts, passedId))); err != nil {
		return err
	}
	// the day's one drop is the refused debit's, counted once
	return expectRefusal("a new drop", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1)), limitKeyDropsPerDay)
}

// The network's 60 ERASE, CUT and CLOSURE pushes a minute, whose refusal only classes: it lifts at the
// minute's end.
func caseMinuteWindowsTurn(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	for i := range 60 {
		if err := expectNoRefusal(fmt.Sprintf("push %d", i), answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyErasurePush, 1))); err != nil {
			return err
		}
	}
	now := target.Clock.Now()
	refusal, err := countOnce(ctx, target, networkId, sidecar.QuotaRateKeyErasurePush, 1)
	if err := expectRefusal("push 61", answered(refusal, err), limitKeyErasurePushesPerMin); err != nil {
		return err
	}
	minuteEnd := sidecar.QuotaRateWindowMinute.End(sidecar.QuotaRateWindowMinute.Index(now))
	if refusal.Limit != 60 || refusal.Used != 60 || refusal.RetryAfterMs != sidecar.QuotaRetryAfterMs(now, minuteEnd) || refusal.Upgrade {
		return fmt.Errorf("refusal %+v", refusal)
	}
	target.Clock.AdvanceTo(minuteEnd)
	return expectNoRefusal("the next minute's push", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyErasurePush, 1)))
}

// evs_drops_per_day turns at 00:00:00 UTC, and a higher tier lifts it below Team.
func caseDayWindowsTurn(ctx context.Context, target *Target) error {
	for _, tier := range []string{"free", "pro", "team"} {
		networkId, err := newNetwork(target, tier, map[string]int64{limitKeyDropsPerDay: 2})
		if err != nil {
			return err
		}
		if err := expectNoRefusal(tier+" drops", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 2))); err != nil {
			return err
		}
		now := target.Clock.Now()
		refusal, err := countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1)
		if err := expectRefusal(tier+" third drop", answered(refusal, err), limitKeyDropsPerDay); err != nil {
			return err
		}
		dayEnd := sidecar.QuotaRateWindowUtcDay.End(sidecar.QuotaRateWindowUtcDay.Index(now))
		want := sidecar.QuotaRefusal{LimitKey: limitKeyDropsPerDay, Limit: 2, Used: 2, RetryAfterMs: sidecar.QuotaRetryAfterMs(now, dayEnd), Upgrade: tier != "team"}
		if *refusal != want {
			return fmt.Errorf("%s: refusal %+v, want %+v", tier, refusal, want)
		}
		target.Clock.AdvanceTo(dayEnd)
		if err := expectNoRefusal(tier+" next day's drop", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1))); err != nil {
			return err
		}
	}
	return nil
}

// One eraser past its closure bytes leaves another's whole (owner decision 146), and its refusal lifts
// at the next 00:00 UTC.
func caseAnErasersAllowanceIsItsOwn(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", map[string]int64{limitKeyClosureBytesPerDay: 6 * 1024 * 1024})
	if err != nil {
		return err
	}
	limits, err := target.Quota.Limits(ctx, networkId)
	if err != nil {
		return err
	}
	eraserA := connect.NewId()
	eraserB := connect.NewId()
	rule, err := sidecar.ParseQuotaRateKey(sidecar.QuotaRateKeyClosureBytes(eraserA))
	if err != nil {
		return err
	}
	allowance := rule.Limit(limits)
	if err := expectNoRefusal("A's allowance", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureBytes(eraserA), allowance))); err != nil {
		return err
	}
	now := target.Clock.Now()
	refusal, err := countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureBytes(eraserA), 1)
	if err := expectRefusal("A's next byte", answered(refusal, err), limitKeyClosureBytesPerDay); err != nil {
		return err
	}
	dayEnd := sidecar.QuotaRateWindowUtcDay.End(sidecar.QuotaRateWindowUtcDay.Index(now))
	if refusal.Limit != allowance || refusal.Used != allowance || refusal.RetryAfterMs != sidecar.QuotaRetryAfterMs(now, dayEnd) || refusal.Upgrade {
		return fmt.Errorf("refusal %+v", refusal)
	}
	return expectNoRefusal("B's allowance", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureBytes(eraserB), allowance)))
}

// No limit takes an allowance below evs_closure_bytes_floor, nor the floor below one full re-key.
func caseTheAllowanceReadsTheFloor(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", map[string]int64{limitKeyClosureBytesPerDay: 1})
	if err != nil {
		return err
	}
	limits, err := target.Quota.Limits(ctx, networkId)
	if err != nil {
		return err
	}
	floor := max(limits.Limits[limitKeyClosureBytesFloor], sidecar.QuotaClosureUploadMaxByteCount)
	eraserId := connect.NewId()
	if err := expectNoRefusal("the floor's bytes", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureBytes(eraserId), floor))); err != nil {
		return err
	}
	refusal, err := countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureBytes(eraserId), 1)
	if err := expectRefusal("past the floor", answered(refusal, err), limitKeyClosureBytesPerDay); err != nil {
		return err
	}
	if refusal.Limit != floor {
		return fmt.Errorf("the allowance read %d, want the floor %d", refusal.Limit, floor)
	}
	return nil
}

// An eraser past its own 60 uploads a minute leaves another's uploads passing.
func caseAnEraserPastItsMinute(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	// start at a minute's top, so 60 paced uploads fit in one minute
	now := target.Clock.Now()
	target.Clock.AdvanceTo(sidecar.QuotaRateWindowMinute.End(sidecar.QuotaRateWindowMinute.Index(now)))
	eraserA := connect.NewId()
	for i := range 60 {
		if err := expectNoRefusal(fmt.Sprintf("A's upload %d", i), answered(countPacedUpload(ctx, target, networkId, eraserA))); err != nil {
			return err
		}
	}
	refusal, err := countPacedUpload(ctx, target, networkId, eraserA)
	if err := expectRefusal("A's upload 61", answered(refusal, err), limitKeyClosureUploadsPerMin); err != nil {
		return err
	}
	if refusal.Limit != 60 || refusal.Used != 60 {
		return fmt.Errorf("refusal %+v", refusal)
	}
	return expectNoRefusal("B's upload", answered(countPacedUpload(ctx, target, networkId, connect.NewId())))
}

// k erasers asking all the while each take one upload every k/R s, none starved, and the network at
// most R a second (FS-47's pacing clause).
func casePacingGivesEqualTurns(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	limits, err := target.Quota.Limits(ctx, networkId)
	if err != nil {
		return err
	}
	perS := sidecar.QuotaClosurePacingPerS(limits)
	spacing := time.Second / time.Duration(perS)
	step := spacing / 5
	eraserIds := []connect.Id{}
	for range 5 {
		eraserIds = append(eraserIds, connect.NewId())
	}
	eraserTakeTimes := map[connect.Id][]time.Time{}
	secondTakeCounts := map[int64]int64{}
	steps := int(20 * time.Second / step)
	for i := range steps {
		if 0 < i {
			target.Clock.Advance(step)
		}
		now := target.Clock.Now()
		for _, eraserId := range eraserIds {
			refusal, err := countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureUpload(eraserId), 1)
			if err != nil {
				return err
			}
			if refusal == nil {
				eraserTakeTimes[eraserId] = append(eraserTakeTimes[eraserId], now)
				secondTakeCounts[now.Unix()] += 1
			} else if refusal.LimitKey != limitKeyClosureUploadsPerS {
				return fmt.Errorf("refused %+v", refusal)
			}
		}
	}
	for second, count := range secondTakeCounts {
		if perS < count {
			return fmt.Errorf("second %d took %d", second, count)
		}
	}
	turnTimeout := time.Duration(len(eraserIds)) * spacing
	for index, eraserId := range eraserIds {
		takeTimes := eraserTakeTimes[eraserId]
		if len(takeTimes) < int(20*time.Second/turnTimeout)-1 {
			return fmt.Errorf("eraser %d took %d turns in 20 s", index, len(takeTimes))
		}
		// the first eraser took twice before the others asked
		first := 0
		if index == 0 {
			first = 1
		}
		for i := first + 1; i < len(takeTimes); i += 1 {
			if gap := takeTimes[i].Sub(takeTimes[i-1]); gap != turnTimeout {
				return fmt.Errorf("eraser %d: turn %d came %s after the last, want %s", index, i, gap, turnTimeout)
			}
		}
	}
	return nil
}

// An eraser that waits out its retry_after_ms keeps its place against erasers asking all the while.
func caseAWaitingEraserKeepsItsPlace(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	limits, err := target.Quota.Limits(ctx, networkId)
	if err != nil {
		return err
	}
	spacing := time.Second / time.Duration(sidecar.QuotaClosurePacingPerS(limits))
	askerIds := []connect.Id{}
	for range 20 {
		askerId := connect.NewId()
		askerIds = append(askerIds, askerId)
		if _, err := countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureUpload(askerId), 1); err != nil {
			return err
		}
	}
	waiterId := connect.NewId()
	refusal, err := countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureUpload(waiterId), 1)
	if err := expectRefusal("the waiter", answered(refusal, err), limitKeyClosureUploadsPerS); err != nil {
		return err
	}
	turnTime := target.Clock.Now().Add(retryAfter(refusal))
	// the others ask every slot until the waiter's turn
	for target.Clock.Now().Add(spacing).Before(turnTime) {
		target.Clock.Advance(spacing)
		for _, askerId := range askerIds {
			if _, err := countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureUpload(askerId), 1); err != nil {
				return err
			}
		}
	}
	target.Clock.AdvanceTo(turnTime)
	return expectNoRefusal("the waiter at its turn", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureUpload(waiterId), 1)))
}

// Twelve erasers whose seats lapsed while they were away ask at one instant, the top of a second, in a fixed
// order that puts the last seated first, then each obeys every answer (DESIGN-DETAILS 13.6). The second takes
// R uploads, two by the first asker, whose next seat is the cell behind its own; each asker past the first R - 1
// is told an instant in a later second; and all twelve have taken three times within 10 s.
func caseErasersReturningTogether(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	limits, err := target.Quota.Limits(ctx, networkId)
	if err != nil {
		return err
	}
	perS := sidecar.QuotaClosurePacingPerS(limits)
	cell := time.Second / time.Duration(perS)
	eraserIds := []connect.Id{}
	for range 3 * perS {
		eraserId := connect.NewId()
		eraserIds = append(eraserIds, eraserId)
		if _, err := countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureUpload(eraserId), 1); err != nil {
			return err
		}
	}
	slices.Reverse(eraserIds)
	now := target.Clock.Now()
	target.Clock.AdvanceTo(time.Unix(now.Unix()+10, 0))
	back := target.Clock.Now()
	backSecond := back.Unix()
	eraserAskTimes := map[connect.Id]time.Time{}
	for index, eraserId := range eraserIds {
		refusal, err := countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureUpload(eraserId), 1)
		if err != nil {
			return err
		}
		switch {
		case index == 0 && refusal != nil:
			return fmt.Errorf("the first asker was refused %+v", refusal)
		case index == 0:
			eraserAskTimes[eraserId] = back.Add(cell)
		case refusal == nil || refusal.LimitKey != limitKeyClosureUploadsPerS:
			return fmt.Errorf("asker %d answered %+v", index, refusal)
		default:
			askTime := back.Add(retryAfter(refusal))
			if want := back.Add(time.Duration(index+1) * cell); !askTime.Equal(want) {
				return fmt.Errorf("asker %d told %s, want %s", index, askTime.Sub(back), want.Sub(back))
			}
			if int64(index) >= perS-1 && askTime.Unix() == backSecond {
				return fmt.Errorf("asker %d told %s, in the second they came back in", index, askTime.Sub(back))
			}
			eraserAskTimes[eraserId] = askTime
		}
	}
	eraserTakeCounts := map[connect.Id]int{eraserIds[0]: 1}
	secondTakeCounts := map[int64]int64{backSecond: 1}
	firstAskerTakes := 1
	for range 1000 {
		var next time.Time
		for _, eraserId := range eraserIds {
			if askTime, ok := eraserAskTimes[eraserId]; ok && (next.IsZero() || askTime.Before(next)) {
				next = askTime
			}
		}
		if next.IsZero() {
			break
		}
		target.Clock.AdvanceTo(next)
		for _, eraserId := range eraserIds {
			if askTime, ok := eraserAskTimes[eraserId]; !ok || !askTime.Equal(next) {
				continue
			}
			refusal, err := countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureUpload(eraserId), 1)
			if err != nil {
				return err
			}
			if refusal != nil {
				return fmt.Errorf("an eraser asking at its seat %s was refused %+v", next.Sub(back), refusal)
			}
			secondTakeCounts[next.Unix()] += 1
			eraserTakeCounts[eraserId] += 1
			if eraserId == eraserIds[0] && next.Unix() == backSecond {
				firstAskerTakes += 1
			}
			delete(eraserAskTimes, eraserId)
			if eraserTakeCounts[eraserId] == 3 {
				continue
			}
			// its next upload asks at once and is told its seat
			refusal, err = countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureUpload(eraserId), 1)
			if err := expectRefusal("the next upload", answered(refusal, err), limitKeyClosureUploadsPerS); err != nil {
				return err
			}
			eraserAskTimes[eraserId] = next.Add(retryAfter(refusal))
		}
	}
	for second, count := range secondTakeCounts {
		if perS < count {
			return fmt.Errorf("second %d took %d", second, count)
		}
	}
	if secondTakeCounts[backSecond] != perS || firstAskerTakes != 2 {
		return fmt.Errorf("the second they came back in took %d, %d by the first asker", secondTakeCounts[backSecond], firstAskerTakes)
	}
	for index, eraserId := range eraserIds {
		if eraserTakeCounts[eraserId] != 3 {
			return fmt.Errorf("eraser %d took %d times", index, eraserTakeCounts[eraserId])
		}
	}
	if done := target.Clock.Now(); back.Add(10 * time.Second).Before(done) {
		return fmt.Errorf("the last took %s after they came back", done.Sub(back))
	}
	return nil
}

// An upload refused for its turn keeps its debit id: asked again at its retry_after_ms under the same id it
// takes, and the replay of that pass counts nothing (the upload route's one debit id an upload).
func caseARefusedUploadAsksAgain(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	if err := expectNoRefusal("the first eraser", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureUpload(connect.NewId()), 1))); err != nil {
		return err
	}
	eraserId := connect.NewId()
	keyAmounts := map[string]int64{
		sidecar.QuotaRateKeyClosureUpload(eraserId): 1,
		sidecar.QuotaRateKeyClosureBytes(eraserId):  1024,
	}
	debitId := connect.NewId()
	refusal, err := target.Quota.CountRate(ctx, networkId, keyAmounts, debitId)
	if err := expectRefusal("the second eraser", answered(refusal, err), limitKeyClosureUploadsPerS); err != nil {
		return err
	}
	target.Clock.Advance(retryAfter(refusal))
	if err := expectNoRefusal("asked again under its id", answered(target.Quota.CountRate(ctx, networkId, keyAmounts, debitId))); err != nil {
		return err
	}
	if err := expectNoRefusal("its pass replayed", answered(target.Quota.CountRate(ctx, networkId, keyAmounts, debitId))); err != nil {
		return err
	}
	// the bytes counted once: the rest of the allowance still fits
	limits, err := target.Quota.Limits(ctx, networkId)
	if err != nil {
		return err
	}
	rule, err := sidecar.ParseQuotaRateKey(sidecar.QuotaRateKeyClosureBytes(eraserId))
	if err != nil {
		return err
	}
	return expectNoRefusal("the allowance's rest", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureBytes(eraserId), rule.Limit(limits)-1024)))
}

// An eraser its own allowance refuses is given no seat, so the next eraser at the same instant takes the cell
// it would have held.
func caseAnAllowanceRefusalHoldsNoSeat(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	limits, err := target.Quota.Limits(ctx, networkId)
	if err != nil {
		return err
	}
	spentId := connect.NewId()
	rule, err := sidecar.ParseQuotaRateKey(sidecar.QuotaRateKeyClosureBytes(spentId))
	if err != nil {
		return err
	}
	if err := expectNoRefusal("the allowance", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureBytes(spentId), rule.Limit(limits)))); err != nil {
		return err
	}
	refusal, err := target.Quota.CountRate(ctx, networkId, map[string]int64{
		sidecar.QuotaRateKeyClosureUpload(spentId): 1,
		sidecar.QuotaRateKeyClosureBytes(spentId):  1,
	}, connect.NewId())
	if err := expectRefusal("past the allowance", answered(refusal, err), limitKeyClosureBytesPerDay); err != nil {
		return err
	}
	return expectNoRefusal("the next eraser at the same instant", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyClosureUpload(connect.NewId()), 1)))
}

// A lost Redis forgets its counts, and a failing one answers nil: open, never shut (§20.7).
func caseRedisLostOrFailing(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", map[string]int64{limitKeyDropsPerDay: 1})
	if err != nil {
		return err
	}
	if err := expectNoRefusal("the day's drop", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1))); err != nil {
		return err
	}
	if err := expectRefusal("a second", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1)), limitKeyDropsPerDay); err != nil {
		return err
	}
	if err := target.SetRedisFailing(true); err != nil {
		return err
	}
	for i := range 3 {
		if err := expectNoRefusal(fmt.Sprintf("drop %d while Redis fails", i), answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1))); err != nil {
			return err
		}
	}
	if err := target.SetRedisFailing(false); err != nil {
		return err
	}
	if err := target.LoseRedis(); err != nil {
		return err
	}
	if err := expectNoRefusal("the drop after the loss", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1))); err != nil {
		return err
	}
	return expectRefusal("the next", answered(countOnce(ctx, target, networkId, sidecar.QuotaRateKeyDrop, 1)), limitKeyDropsPerDay)
}

func evsBatch(batchId connect.Id, networkId connect.Id, byteCount int64) *sidecar.UsageBatch {
	return &sidecar.UsageBatch{
		BatchId:  batchId,
		Producer: sidecar.QuotaProducerEvs,
		Events:   []*sidecar.UsageEvent{{NetworkId: networkId, Meter: sidecar.QuotaMeterEvs, TransferByteCount: byteCount}},
	}
}

// FS-44: a batch retried after a lost response debits once.
func caseABatchAppliesOnce(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	balanceId := connect.NewId()
	if err := target.SetBalances(networkId, []*sidecartest.QuotaBalance{{BalanceId: balanceId, ByteCount: 1000}}); err != nil {
		return err
	}
	if _, err := target.Faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: sidecartest.ApplyThenDrop}); err != nil {
		return err
	}
	batch := evsBatch(connect.NewId(), networkId, 100)
	if err := target.Quota.ReportUsage(ctx, batch); err == nil {
		return errors.New("the lost response came back")
	}
	if err := target.Quota.ReportUsage(ctx, batch); err != nil {
		return err
	}
	idBalances, err := settledBalances(target, networkId)
	if err != nil {
		return err
	}
	return expectBalance(idBalances, "after the retry", balanceId, 900, 0)
}

// A zero id, an unknown producer or meter, a negative transfer or too many events refuses the whole
// batch, which leaves its id unused.
func caseARefusedBatchAppliesNothing(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	balanceId := connect.NewId()
	if err := target.SetBalances(networkId, []*sidecartest.QuotaBalance{{BalanceId: balanceId, ByteCount: 1000}}); err != nil {
		return err
	}
	batchId := connect.NewId()
	good := &sidecar.UsageEvent{NetworkId: networkId, Meter: sidecar.QuotaMeterEvs, TransferByteCount: 10}
	tooMany := []*sidecar.UsageEvent{}
	for range sidecar.QuotaUsageBatchMaxEventCount + 1 {
		tooMany = append(tooMany, good)
	}
	for _, batch := range []*sidecar.UsageBatch{
		{BatchId: batchId, Producer: "api", Events: []*sidecar.UsageEvent{good}},
		{BatchId: batchId, Producer: sidecar.QuotaProducerEvs, Events: []*sidecar.UsageEvent{good, {NetworkId: networkId, Meter: "storage", TransferByteCount: 10}}},
		{BatchId: batchId, Producer: sidecar.QuotaProducerEvs, Events: []*sidecar.UsageEvent{good, {NetworkId: networkId, Meter: sidecar.QuotaMeterEvs, TransferByteCount: -10}}},
		{BatchId: batchId, Producer: sidecar.QuotaProducerEvs, Events: []*sidecar.UsageEvent{good, {Meter: sidecar.QuotaMeterEvs, TransferByteCount: 10}}},
		{BatchId: batchId, Producer: sidecar.QuotaProducerEvs, Events: tooMany},
	} {
		if err := target.Quota.ReportUsage(ctx, batch); err == nil {
			return fmt.Errorf("took a batch from %q of %d events", batch.Producer, len(batch.Events))
		}
	}
	if err := target.Quota.ReportUsage(ctx, &sidecar.UsageBatch{BatchId: batchId, Producer: sidecar.QuotaProducerEvs, Events: []*sidecar.UsageEvent{good}}); err != nil {
		return fmt.Errorf("the good batch under the refused one's id: %w", err)
	}
	idBalances, err := settledBalances(target, networkId)
	if err != nil {
		return err
	}
	return expectBalance(idBalances, "after one good batch", balanceId, 990, 0)
}

// D-QUOTA-9: the credit line pays last, though it ends first; then by end time.
func caseEvsBytesDebitInDrawOrder(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "team", nil)
	if err != nil {
		return err
	}
	now := target.Clock.Now()
	lineId := connect.NewId()
	yearPackId := connect.NewId()
	monthPackId := connect.NewId()
	if err := target.SetBalances(networkId, []*sidecartest.QuotaBalance{
		{BalanceId: lineId, ByteCount: 1000, Credit: true, StartTime: now.Add(-time.Hour), EndTime: now.Add(24 * time.Hour)},
		{BalanceId: yearPackId, ByteCount: 100, StartTime: now.Add(-time.Hour), EndTime: now.Add(365 * 24 * time.Hour)},
		{BalanceId: monthPackId, ByteCount: 100, StartTime: now.Add(-time.Hour), EndTime: now.Add(30 * 24 * time.Hour)},
	}); err != nil {
		return err
	}
	if err := target.Quota.ReportUsage(ctx, evsBatch(connect.NewId(), networkId, 250)); err != nil {
		return err
	}
	idBalances, err := settledBalances(target, networkId)
	if err != nil {
		return err
	}
	if err := expectBalance(idBalances, "the month's pack", monthPackId, 0, 0); err != nil {
		return err
	}
	if err := expectBalance(idBalances, "the year's pack", yearPackId, 0, 0); err != nil {
		return err
	}
	return expectBalance(idBalances, "the credit line", lineId, 950, 0)
}

// Bytes past every balance's room overdraw the last in draw order and mark the network spent
// (plan-QUOTA-small-readings reading 5).
func caseEvsBytesPastEveryBalance(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	balanceId := connect.NewId()
	if err := target.SetBalances(networkId, []*sidecartest.QuotaBalance{{BalanceId: balanceId, ByteCount: 100}}); err != nil {
		return err
	}
	if err := target.Quota.ReportUsage(ctx, evsBatch(connect.NewId(), networkId, 150)); err != nil {
		return err
	}
	idBalances, err := settledBalances(target, networkId)
	if err != nil {
		return err
	}
	if err := expectBalance(idBalances, "the overdrawn balance", balanceId, -50, 0); err != nil {
		return err
	}
	if spent, err := isSpent(ctx, target, networkId); err != nil || !spent {
		return fmt.Errorf("spent %v: %v", spent, err)
	}
	return nil
}

func caseNoBalanceIsSpent(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	if err := target.Quota.ReportUsage(ctx, evsBatch(connect.NewId(), networkId, 10)); err != nil {
		return err
	}
	if target.Settle != nil {
		if err := target.Settle(); err != nil {
			return err
		}
	}
	if spent, err := isSpent(ctx, target, networkId); err != nil || !spent {
		return fmt.Errorf("spent %v: %v", spent, err)
	}
	return nil
}

// §20.6: a lease reserves in draw order, the credit line last; its Close gives the rest back in reverse,
// and a batch from its process carves what it spent into debits.
func caseALeaseDrawsInOrder(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	draw := target.CommunityLeaseDrawByteCount
	now := target.Clock.Now()
	packId := connect.NewId()
	lineId := connect.NewId()
	if err := target.SetBalances(networkId, []*sidecartest.QuotaBalance{
		{BalanceId: lineId, ByteCount: 10 * draw, Credit: true, StartTime: now.Add(-time.Hour), EndTime: now.Add(24 * time.Hour)},
		{BalanceId: packId, ByteCount: draw / 2, StartTime: now.Add(-time.Hour), EndTime: now.Add(365 * 24 * time.Hour)},
	}); err != nil {
		return err
	}
	lease, refusal, err := target.Quota.Lease(ctx, networkId, sidecar.QuotaMeterTls)
	if err := expectNoRefusal("the lease", answered(refusal, err)); err != nil {
		return err
	}
	idBalances, err := settledBalances(target, networkId)
	if err != nil {
		return err
	}
	if err := expectBalance(idBalances, "the pack, drawn", packId, draw/2, draw/2); err != nil {
		return err
	}
	if err := expectBalance(idBalances, "the line, drawn", lineId, 10*draw, draw/2); err != nil {
		return err
	}
	// past the pack, short of the renewal point
	spent := draw/2 + draw/8
	if !lease.Spend(spent) {
		return errors.New("a spend within the draw refused")
	}
	lease.Close()
	idBalances, err = settledBalances(target, networkId)
	if err != nil {
		return err
	}
	if err := expectBalance(idBalances, "the pack, closed", packId, draw/2, draw/2); err != nil {
		return err
	}
	if err := expectBalance(idBalances, "the line, closed", lineId, 10*draw, draw/8); err != nil {
		return err
	}
	batch := &sidecar.UsageBatch{
		BatchId:  connect.NewId(),
		Producer: sidecar.QuotaProducerTlsEdge,
		Events:   []*sidecar.UsageEvent{{NetworkId: networkId, Meter: sidecar.QuotaMeterTls, TransferByteCount: spent}},
	}
	if err := target.Quota.ReportUsage(ctx, batch); err != nil {
		return err
	}
	idBalances, err = settledBalances(target, networkId)
	if err != nil {
		return err
	}
	if err := expectBalance(idBalances, "the pack, carved", packId, 0, 0); err != nil {
		return err
	}
	return expectBalance(idBalances, "the line, carved", lineId, 10*draw-draw/8, 0)
}

func caseARefusedLeaseMarksSpent(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	lease, refusal, err := target.Quota.Lease(ctx, networkId, sidecar.QuotaMeterTls)
	if err != nil {
		return err
	}
	if lease != nil || refusal == nil || !refusal.Upgrade {
		return fmt.Errorf("lease %v, refusal %+v", lease, refusal)
	}
	if spent, err := isSpent(ctx, target, networkId); err != nil || !spent {
		return fmt.Errorf("spent %v: %v", spent, err)
	}
	if err := target.SetBalances(networkId, []*sidecartest.QuotaBalance{{BalanceId: connect.NewId(), ByteCount: 10}}); err != nil {
		return err
	}
	lease, refusal, err = target.Quota.Lease(ctx, networkId, sidecar.QuotaMeterTls)
	if err := expectNoRefusal("the lease on the new balance", answered(refusal, err)); err != nil {
		return err
	}
	defer lease.Close()
	if spent, err := isSpent(ctx, target, networkId); err != nil || spent {
		return fmt.Errorf("a drawing lease left the network spent: %v", err)
	}
	return nil
}

// At §20.6's 75% used a lease reserves its next draw.
func caseALeaseRenews(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	draw := target.CommunityLeaseDrawByteCount
	balanceId := connect.NewId()
	if err := target.SetBalances(networkId, []*sidecartest.QuotaBalance{{BalanceId: balanceId, ByteCount: 3 * draw}}); err != nil {
		return err
	}
	lease, refusal, err := target.Quota.Lease(ctx, networkId, sidecar.QuotaMeterTls)
	if err := expectNoRefusal("the lease", answered(refusal, err)); err != nil {
		return err
	}
	defer lease.Close()
	if !lease.Spend(int64(target.LeaseRenewFraction * float64(draw))) {
		return errors.New("a spend within the draw refused")
	}
	idBalances, err := settledBalances(target, networkId)
	if err != nil {
		return err
	}
	return expectBalance(idBalances, "renewed", balanceId, 3*draw, 2*draw)
}

func caseSpendStopsAtTheBalance(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	draw := target.CommunityLeaseDrawByteCount
	if err := target.SetBalances(networkId, []*sidecartest.QuotaBalance{{BalanceId: connect.NewId(), ByteCount: draw + draw/2}}); err != nil {
		return err
	}
	lease, refusal, err := target.Quota.Lease(ctx, networkId, sidecar.QuotaMeterTls)
	if err := expectNoRefusal("the lease", answered(refusal, err)); err != nil {
		return err
	}
	defer lease.Close()
	if !lease.Spend(draw) || !lease.Spend(draw/2) {
		return errors.New("a spend within the balance refused")
	}
	if lease.Spend(1) {
		return errors.New("spent past the balance")
	}
	if spent, err := isSpent(ctx, target, networkId); err != nil || !spent {
		return fmt.Errorf("a lease run dry left the network unspent: %v", err)
	}
	return nil
}

// One process holds one lease per network and meter: a second handle reserves nothing more, and only
// the last Close gives the rest back (plan-QUOTA-small-readings reading 16).
func caseHandlesShareTheirLease(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	draw := target.CommunityLeaseDrawByteCount
	balanceId := connect.NewId()
	if err := target.SetBalances(networkId, []*sidecartest.QuotaBalance{{BalanceId: balanceId, ByteCount: 10 * draw}}); err != nil {
		return err
	}
	first, refusal, err := target.Quota.Lease(ctx, networkId, sidecar.QuotaMeterTls)
	if err := expectNoRefusal("the first handle", answered(refusal, err)); err != nil {
		return err
	}
	second, refusal, err := target.Quota.Lease(ctx, networkId, sidecar.QuotaMeterTls)
	if err := expectNoRefusal("the second handle", answered(refusal, err)); err != nil {
		return err
	}
	if !first.Spend(10) || !second.Spend(20) {
		return errors.New("a handle refused to spend")
	}
	idBalances, err := settledBalances(target, networkId)
	if err != nil {
		return err
	}
	if err := expectBalance(idBalances, "two handles", balanceId, 10*draw, draw); err != nil {
		return err
	}
	first.Close()
	if first.Spend(1) {
		return errors.New("a closed handle spent")
	}
	if !second.Spend(5) {
		return errors.New("the open handle refused after the other closed")
	}
	idBalances, err = settledBalances(target, networkId)
	if err != nil {
		return err
	}
	if err := expectBalance(idBalances, "one handle closed", balanceId, 10*draw, draw); err != nil {
		return err
	}
	second.Close()
	idBalances, err = settledBalances(target, networkId)
	if err != nil {
		return err
	}
	// the spent 35 bytes stay reserved until a batch carves them
	return expectBalance(idBalances, "both closed", balanceId, 10*draw, 35)
}

func caseALeaseNamesAMeter(ctx context.Context, target *Target) error {
	networkId, err := newNetwork(target, "free", nil)
	if err != nil {
		return err
	}
	if err := target.SetBalances(networkId, []*sidecartest.QuotaBalance{{BalanceId: connect.NewId(), ByteCount: 1000}}); err != nil {
		return err
	}
	if lease, refusal, err := target.Quota.Lease(ctx, networkId, "storage"); err == nil {
		if lease != nil {
			lease.Close()
		}
		return fmt.Errorf("leased on no meter: %+v", refusal)
	}
	return nil
}
