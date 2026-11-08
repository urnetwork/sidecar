package evsservice

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A process's budget on one metadata cluster beside the loop that steps its governor, both on one fake
// clock and one fake Redis. The process's goroutines are not started: interval drives both sides in
// turn, so every test knows what each side has seen.
type budgetFixture struct {
	t   *testing.T
	ctx context.Context
	// one signal each time an admission starts to wait
	waits    chan struct{}
	waitSeen int
	settings *WriteBudgetSettings
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	client   *WriteBudgetClient
	account  *writeBudgetAccount
	governor *Governor
}

func newBudgetFixture(t *testing.T) *budgetFixture {
	ctx := t.Context()
	settings := governorTestSettings()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	client, err := newWriteBudgetClient(ctx, host.ServiceHost(), []string{"meta-1"}, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	waits := make(chan struct{}, 1024)
	client.waitHook = func() {
		waits <- struct{}{}
	}
	return &budgetFixture{
		t:        t,
		ctx:      ctx,
		waits:    waits,
		settings: settings,
		clock:    clock,
		host:     host,
		client:   client,
		account:  client.clusterIdAccounts["meta-1"],
		governor: NewGovernor("meta-1", settings, &GovernorState{
			Seq:             1,
			TimeMs:          clock.Now().UnixMilli(),
			BucketByteCount: 720000,
			Calibration:     1,
		}),
	}
}

// The loop's half of an interval: the governor steps on what the reports say and what the drives
// measured, and publishes.
func (self *budgetFixture) publish(measuredByteCount int64) *WriteBudgetAllowance {
	self.t.Helper()
	reports, err := ReadWriteBudgetReports(self.ctx, self.host.Redis, "meta-1")
	if err != nil {
		self.t.Fatal(err)
	}
	allowance := self.governor.Step(self.clock.Now(), measuredByteCount, reports)
	if err := PublishWriteBudgetAllowance(self.ctx, self.host.Redis, self.settings, allowance); err != nil {
		self.t.Fatal(err)
	}
	if err := SaveGovernorState(self.ctx, self.host.Redis, self.settings, "meta-1", self.governor.State()); err != nil {
		self.t.Fatal(err)
	}
	return allowance
}

// One interval: the clock moves, the loop publishes, and the process takes its shares and reports.
func (self *budgetFixture) interval(measuredByteCount int64) *WriteBudgetAllowance {
	self.clock.Advance(self.settings.Interval)
	allowance := self.publish(measuredByteCount)
	self.account.tick(self.ctx)
	return allowance
}

// Runs intervals until the process holds a P1 share of at least byteCount.
func (self *budgetFixture) warm(byteCount int64) {
	self.t.Helper()
	// the first tick reports, so the next allowance carries this process's share
	self.account.tick(self.ctx)
	for range 10 {
		self.interval(0)
		if byteCount <= self.left().P1ByteCount {
			return
		}
	}
	self.t.Fatalf("no P1 share of %d", byteCount)
}

// What the account holds for the rest of this interval.
func (self *budgetFixture) left() *WriteBudgetShare {
	self.account.stateLock.Lock()
	defer self.account.stateLock.Unlock()
	return &WriteBudgetShare{
		P1ByteCount:        self.account.p1Left,
		UnfundedByteCount:  self.account.unfundedLeft + self.account.uncoveredLeft,
		UncoveredByteCount: self.account.uncoveredLeft,
		FundedByteCount:    self.account.fundedLeft,
	}
}

// Sets the pools as a share would, for tests of what spends them.
func (self *budgetFixture) setPools(share *WriteBudgetShare) {
	self.account.stateLock.Lock()
	defer self.account.stateLock.Unlock()
	self.account.epoch += 1
	self.account.p1Left = share.P1ByteCount
	self.account.uncoveredLeft = share.UncoveredByteCount
	self.account.unfundedLeft = share.UnfundedByteCount - share.UncoveredByteCount
	self.account.fundedLeft = share.FundedByteCount
	self.account.dispatchP1WithLock()
	self.account.dispatchP2WithLock()
}

// The process's report as the next tick would write it.
func (self *budgetFixture) report() *WriteBudgetReport {
	self.account.stateLock.Lock()
	defer self.account.stateLock.Unlock()
	return self.account.reportWithLock(self.clock.Now())
}

// An AdmitP1 running on its own goroutine.
type pendingAdmission struct {
	done  chan struct{}
	grant sidecar.WriteGrant
	err   error
}

func (self *budgetFixture) admitAsync(ctx context.Context, networkId connect.Id, cost sidecar.WriteCost) *pendingAdmission {
	pending := &pendingAdmission{done: make(chan struct{})}
	go func() {
		defer close(pending.done)
		pending.grant, pending.err = self.client.AdmitP1(ctx, "meta-1", networkId, cost)
	}()
	return pending
}

// Returns once total admissions, counted from the fixture's start, have started to wait.
func (self *budgetFixture) awaitWaits(total int) {
	self.t.Helper()
	for self.waitSeen < total {
		select {
		case <-self.waits:
			self.waitSeen += 1
		case <-self.ctx.Done():
			self.t.Fatal(self.ctx.Err())
		}
	}
}

func (self *pendingAdmission) wait(t *testing.T) {
	t.Helper()
	select {
	case <-self.done:
	case <-t.Context().Done():
		t.Fatal("an admission never decided")
	}
}

func (self *pendingAdmission) decided() bool {
	select {
	case <-self.done:
		return true
	default:
		return false
	}
}

// FI-14 (c): P0 issues at once whatever the budget holds, a bucket at zero, no allowance ever and a
// queue full included, counted by kind and carried by its ctx.
func TestWriteBudgetIssueP0NeverWaitsOrRefuses(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{})
	blocked := fixture.admitAsync(t.Context(), connect.NewId(), sidecar.WriteCost{ImmediateByteCount: 100})
	fixture.awaitWaits(1)
	for range 100 {
		ctx := fixture.client.IssueP0(t.Context(), "meta-1", sidecar.WriteP0KindRemove, 1000)
		if class, ok := sidecar.WriteClassOf(ctx); !ok || class != sidecar.WriteClassP0 {
			t.Fatalf("class %v %v", class, ok)
		}
	}
	// a kind outside the vocabulary still drains the bucket, and a cluster with no account still issues
	fixture.client.IssueP0(t.Context(), "meta-1", "not-a-kind", 7)
	if _, ok := sidecar.WriteClassOf(fixture.client.IssueP0(t.Context(), "meta-9", sidecar.WriteP0KindLog, 5)); !ok {
		t.Error("P0 on another cluster carried no class")
	}
	report := fixture.report()
	if report.P0ByteCounts[sidecar.WriteP0KindRemove] != 100000 || report.P0ByteCounts[sidecar.WriteP0KindLifecycle] != 7 {
		t.Errorf("P0 %v", report.P0ByteCounts)
	}
	if blocked.decided() {
		t.Error("the P1 waiter moved")
	}
}

// §22.5's hot-path gate: admission, P0, P2 and a grant's close make no Redis op; only the interval's
// tick reads and writes.
func TestWriteBudgetInlinePathMakesNoRedisOp(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.warm(1000)
	fixture.setPools(&WriteBudgetShare{P1ByteCount: 1000000, UnfundedByteCount: 1000000, FundedByteCount: 1000000})
	fixture.host.Redis.ResetOpCounts()
	networkId := connect.NewId()
	for range 100 {
		fixture.client.IssueP0(t.Context(), "meta-1", sidecar.WriteP0KindLog, 100)
		grant, err := fixture.client.AdmitP1(t.Context(), "meta-1", networkId, sidecar.WriteCost{ImmediateByteCount: 63, DeferredByteCount: 37})
		if err != nil {
			t.Fatal(err)
		}
		grant.Close()
		grant, err = fixture.client.AcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{Rank: sidecar.WriteP2RankFold, ByteCount: 50, Funded: true})
		if err != nil {
			t.Fatal(err)
		}
		grant.Close()
		grant, ok, err := fixture.client.TryAcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{Rank: sidecar.WriteP2RankGc, ByteCount: 50})
		if err != nil || !ok {
			t.Fatal(ok, err)
		}
		grant.Close()
		fixture.client.DeclareP2Backlog("meta-1", "folds", sidecar.WriteP2RankFold, true, 500)
		fixture.client.CopyOpsPerSecond("meta-1")
	}
	if counts := fixture.host.Redis.OpCounts(); len(counts) != 0 {
		t.Errorf("Redis ops on the inline path: %v", counts)
	}
	fixture.account.tick(t.Context())
	if counts := fixture.host.Redis.OpCounts(); len(counts) == 0 {
		t.Error("the tick made no Redis op")
	}
}

// P1 is admitted within its share, and what does not fit waits for the next.
func TestWriteBudgetAdmitsP1WithinItsShare(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.warm(1000)
	fixture.setPools(&WriteBudgetShare{P1ByteCount: 1000})
	networkId := connect.NewId()
	for range 10 {
		if _, err := fixture.client.AdmitP1(t.Context(), "meta-1", networkId, sidecar.WriteCost{ImmediateByteCount: 63, DeferredByteCount: 37}); err != nil {
			t.Fatal(err)
		}
	}
	eleventh := fixture.admitAsync(t.Context(), networkId, sidecar.WriteCost{ImmediateByteCount: 63, DeferredByteCount: 37})
	fixture.awaitWaits(1)
	if eleventh.decided() {
		t.Fatal("the eleventh push passed its share")
	}
	fixture.setPools(&WriteBudgetShare{P1ByteCount: 1000})
	eleventh.wait(t)
	if eleventh.err != nil {
		t.Error(eleventh.err)
	}
}

// Admission pays the deferred part into the credit the report carries, the immediate part is in flight
// until its grant closes, and a grant's ctx carries P1.
func TestWriteBudgetMovesTheDeferredPartToCredit(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{P1ByteCount: 1000})
	grant, err := fixture.client.AdmitP1(t.Context(), "meta-1", connect.NewId(), sidecar.WriteCost{ImmediateByteCount: 63, DeferredByteCount: 37})
	if err != nil {
		t.Fatal(err)
	}
	if class, _ := sidecar.WriteClassOf(grant.Context()); class != sidecar.WriteClassP1 {
		t.Errorf("class %v", class)
	}
	report := fixture.report()
	if report.P1ByteCount != 63 || report.CreditByteCount != 37 || report.InFlightByteCount != 63 {
		t.Errorf("report %+v", report)
	}
	grant.Close()
	grant.Close()
	if report := fixture.report(); report.InFlightByteCount != 0 {
		t.Errorf("in flight %d after close", report.InFlightByteCount)
	}
	if left := fixture.left(); left.P1ByteCount != 900 {
		t.Errorf("P1 left %d", left.P1ByteCount)
	}
}

// FI-14 (d) and §11.13's shed row: past 100 ms of queueing delay the heaviest network by queued priced
// bytes per weight is refused, 429 with retry_after_ms, while a lighter one waits on to be served; a
// network alone is never refused for waiting.
func TestWriteBudgetShedsTheHeaviestNetworkFirst(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{})
	heavy := connect.NewId()
	light := connect.NewId()
	cost := sidecar.WriteCost{ImmediateByteCount: 100}
	heavies := []*pendingAdmission{}
	for range 3 {
		heavies = append(heavies, fixture.admitAsync(t.Context(), heavy, cost))
	}
	fixture.awaitWaits(3)
	// alone past the delay: nothing lighter to make room for, so it waits
	fixture.clock.Advance(fixture.settings.ShedDelay)
	for _, pending := range heavies {
		if pending.decided() {
			t.Fatal("a network alone was refused")
		}
	}
	lighter := fixture.admitAsync(t.Context(), light, cost)
	for _, pending := range heavies {
		pending.wait(t)
		refusal := &sidecar.WriteRefusal{}
		if !errors.As(pending.err, &refusal) || refusal.RetryAfterMs() != 5000 || refusal.ClusterId != "meta-1" {
			t.Errorf("heavy: %v", pending.err)
		}
	}
	if lighter.decided() {
		t.Fatal("the lighter network was refused or admitted without a share")
	}
	fixture.setPools(&WriteBudgetShare{P1ByteCount: 100})
	lighter.wait(t)
	if lighter.err != nil {
		t.Errorf("light: %v", lighter.err)
	}
}

// The shed rule weighs by store_weight: a Team network queueing four times a Community network's bytes
// is the lighter, so the Community network is refused.
func TestWriteBudgetShedsByQueuedBytesPerWeight(t *testing.T) {
	fixture := newBudgetFixture(t)
	team := connect.NewId()
	community := connect.NewId()
	fixture.host.Quota.SetLimits(team, &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{"store_weight": 16}})
	fixture.host.Quota.SetLimits(community, &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{"store_weight": 1}})
	fixture.client.weights.weight(team, fixture.clock.Now())
	fixture.client.weights.weight(community, fixture.clock.Now())
	fixture.client.weights.refresh(t.Context(), fixture.clock)
	fixture.setPools(&WriteBudgetShare{})
	teams := []*pendingAdmission{}
	for range 4 {
		teams = append(teams, fixture.admitAsync(t.Context(), team, sidecar.WriteCost{ImmediateByteCount: 100}))
	}
	fixture.awaitWaits(4)
	communityAdmission := fixture.admitAsync(t.Context(), community, sidecar.WriteCost{ImmediateByteCount: 100})
	fixture.awaitWaits(5)
	fixture.clock.Advance(fixture.settings.ShedDelay)
	communityAdmission.wait(t)
	if refusal := (&sidecar.WriteRefusal{}); !errors.As(communityAdmission.err, &refusal) {
		t.Errorf("community: %v", communityAdmission.err)
	}
	for _, pending := range teams {
		if pending.decided() {
			t.Error("a team push was decided")
		}
	}
	fixture.setPools(&WriteBudgetShare{P1ByteCount: 400})
	for _, pending := range teams {
		pending.wait(t)
		if pending.err != nil {
			t.Error(pending.err)
		}
	}
}

// A waiter whose ctx ends leaves the queue, nothing spent.
func TestWriteBudgetAdmissionLeavesWithItsContext(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{})
	ctx, cancel := context.WithCancel(t.Context())
	pending := fixture.admitAsync(ctx, connect.NewId(), sidecar.WriteCost{ImmediateByteCount: 100})
	fixture.awaitWaits(1)
	cancel()
	pending.wait(t)
	if !errors.Is(pending.err, context.Canceled) {
		t.Errorf("err %v", pending.err)
	}
	if report := fixture.report(); report.P1QueuedByteCount != 0 || report.P1ByteCount != 0 {
		t.Errorf("report %+v", report)
	}
}

// P2 rereads repo/ when issued, not when queued: Recheck runs once the work's turn and bytes come, and a
// refusing recheck gives its bytes back to the next.
func TestWriteBudgetRechecksP2AtIssue(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{})
	rechecked := make(chan string, 4)
	errSkipped := errors.New("the repo was deleted")
	type result struct {
		grant sidecar.WriteGrant
		err   error
	}
	acquire := func(name string, err error) chan result {
		results := make(chan result, 1)
		go func() {
			grant, acquireErr := fixture.client.AcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{
				Rank:      sidecar.WriteP2RankFold,
				Due:       fixture.clock.Now(),
				ByteCount: 100,
				Funded:    true,
				Recheck: func(ctx context.Context) error {
					rechecked <- name
					return err
				},
			})
			results <- result{grant: grant, err: acquireErr}
		}()
		return results
	}
	skipped := acquire("skipped", errSkipped)
	fixture.awaitWaits(1)
	kept := acquire("kept", nil)
	fixture.awaitWaits(2)
	select {
	case name := <-rechecked:
		t.Fatalf("%s rechecked while queued", name)
	default:
	}
	// one work's bytes: the first rechecks and refuses, and its bytes go to the second
	fixture.setPools(&WriteBudgetShare{FundedByteCount: 100})
	if skippedResult := <-skipped; !errors.Is(skippedResult.err, errSkipped) {
		t.Errorf("skipped: %v", skippedResult.err)
	}
	keptResult := <-kept
	if keptResult.err != nil {
		t.Fatal(keptResult.err)
	}
	if first, second := <-rechecked, <-rechecked; first != "skipped" || second != "kept" {
		t.Errorf("rechecked %s then %s", first, second)
	}
	if class, _ := sidecar.WriteClassOf(keptResult.grant.Context()); class != sidecar.WriteClassP2 {
		t.Errorf("class %v", class)
	}
	if report := fixture.report(); report.FundedByteCount != 100 || report.InFlightByteCount != 100 {
		t.Errorf("report %+v", report)
	}
}

// §11.13's order row: evacuation before folds whatever came first, and within a rank the older first.
func TestWriteBudgetServesP2ByRank(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{})
	order := make(chan string, 3)
	acquire := func(name string, rank sidecar.WriteP2Rank, due time.Time) {
		go func() {
			grant, err := fixture.client.AcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{Rank: rank, Due: due, ByteCount: 100, Funded: true})
			if err == nil {
				grant.Close()
			}
			order <- name
		}()
	}
	now := fixture.clock.Now()
	acquire("fold", sidecar.WriteP2RankFold, now.Add(-time.Hour))
	fixture.awaitWaits(1)
	acquire("newer evacuation", sidecar.WriteP2RankEvacuation, now)
	fixture.awaitWaits(2)
	acquire("older evacuation", sidecar.WriteP2RankEvacuation, now.Add(-time.Minute))
	fixture.awaitWaits(3)
	for _, want := range []string{"older evacuation", "newer evacuation", "fold"} {
		fixture.setPools(&WriteBudgetShare{FundedByteCount: 100})
		if got := <-order; got != want {
			t.Errorf("served %s, want %s", got, want)
		}
	}
}

// TryAcquireP2 never waits: no share, or work of its rank or before waiting, and it says no at once.
func TestWriteBudgetTryAcquireP2NeverWaits(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{})
	pageOut := &sidecar.WriteP2Work{Rank: sidecar.WriteP2RankPageOutFold, ByteCount: 100, Funded: true}
	if _, ok, err := fixture.client.TryAcquireP2(t.Context(), "meta-1", pageOut); ok || err != nil {
		t.Fatalf("no share: %v %v", ok, err)
	}
	fixture.setPools(&WriteBudgetShare{FundedByteCount: 1000})
	go fixture.client.AcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{Rank: sidecar.WriteP2RankEvacuation, ByteCount: 5000, Funded: true})
	fixture.awaitWaits(1)
	if _, ok, _ := fixture.client.TryAcquireP2(t.Context(), "meta-1", pageOut); ok {
		t.Error("passed an evacuation waiting ahead")
	}
	// unfunded work waits in its own account, and holds back no funded work
	fixture.setPools(&WriteBudgetShare{FundedByteCount: 6000})
	rechecked := false
	pageOut.Recheck = func(ctx context.Context) error {
		rechecked = true
		return nil
	}
	grant, ok, err := fixture.client.TryAcquireP2(t.Context(), "meta-1", pageOut)
	if !ok || err != nil || !rechecked {
		t.Fatalf("with a share: %v %v, rechecked %v", ok, err, rechecked)
	}
	grant.Close()
}

// Funded work spends A2, then the uncovered part of A_U, never the rest of A_U, and the report says
// which: what came from A_U is unfunded issue, not credit spent.
func TestWriteBudgetPaysUncoveredFundedWorkFromAU(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{FundedByteCount: 100, UnfundedByteCount: 500, UncoveredByteCount: 200})
	for range 3 {
		grant, err := fixture.client.AcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{Rank: sidecar.WriteP2RankEvacuation, ByteCount: 100, Funded: true})
		if err != nil {
			t.Fatal(err)
		}
		grant.Close()
	}
	if _, ok, _ := fixture.client.TryAcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{Rank: sidecar.WriteP2RankEvacuation, ByteCount: 100, Funded: true}); ok {
		t.Error("funded work spent past A2 and the uncovered part")
	}
	report := fixture.report()
	if report.FundedByteCount != 100 || report.UnfundedByteCount != 200 {
		t.Errorf("report %+v", report)
	}
	if left := fixture.left(); left.UnfundedByteCount != 300 || left.UncoveredByteCount != 0 {
		t.Errorf("left %+v", left)
	}
}

// §11.13's fallback row on the fake clock: the last shares for up to 60 s without a fresh allowance,
// then P1 and unfunded P2 at half, and funded P2 at most at the last minute's rate.
func TestWriteBudgetFallsBackWithoutAFreshAllowance(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.warm(1000)
	if left := fixture.left(); left.P1ByteCount != 1000 {
		t.Fatalf("share %+v", left)
	}
	// the loop stops publishing: its last allowance expires in 15 s, and each interval goes on with
	// the last shares
	for range 11 {
		fixture.clock.Advance(fixture.settings.Interval)
		fixture.account.tick(t.Context())
		if left := fixture.left(); left.P1ByteCount != 1000 {
			t.Fatalf("within 60 s: %+v", left)
		}
	}
	fixture.clock.Advance(fixture.settings.Interval)
	fixture.account.tick(t.Context())
	if left := fixture.left(); left.P1ByteCount != 500 || left.FundedByteCount != 0 {
		t.Errorf("past 60 s: %+v", left)
	}
	// a fresh allowance ends it
	fixture.interval(0)
	if left := fixture.left(); left.P1ByteCount != 1000 {
		t.Errorf("fresh again: %+v", left)
	}
}

// A process that never had an allowance runs within the refill over twice the process count, unless
// the loop's saved state shows B at zero, when it runs no P1 or unfunded P2. P0 runs throughout.
func TestWriteBudgetWithNoAllowanceEverRunsWithinTheRefill(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.account.tick(t.Context())
	// no state and no other report: one process, 1,000 over 2, A_U's part at most 40%
	if left := fixture.left(); left.P1ByteCount != 300 || left.UnfundedByteCount != 200 || left.FundedByteCount != 0 {
		t.Errorf("no state: %+v", left)
	}
	if err := SaveGovernorState(t.Context(), fixture.host.Redis, fixture.settings, "meta-1", &GovernorState{Seq: 9, BucketByteCount: 0, Calibration: 1}); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(fixture.settings.Interval)
	fixture.account.tick(t.Context())
	if left := fixture.left(); left.P1ByteCount != 0 || left.UnfundedByteCount != 0 {
		t.Errorf("B at zero: %+v", left)
	}
	if _, ok := sidecar.WriteClassOf(fixture.client.IssueP0(t.Context(), "meta-1", sidecar.WriteP0KindShred, 10)); !ok {
		t.Error("P0 waited")
	}
}

// The report names no network or repo, and lives in {nvb_<set>} for 15 s.
func TestWriteBudgetReportNamesNoNetwork(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{P1ByteCount: 1000})
	networkId := connect.NewId()
	if _, err := fixture.client.AdmitP1(t.Context(), "meta-1", networkId, sidecar.WriteCost{ImmediateByteCount: 100}); err != nil {
		t.Fatal(err)
	}
	fixture.account.tick(t.Context())
	fieldValues, err := fixture.host.Redis.HashGetAll(t.Context(), writeBudgetKey("meta-1"))
	if err != nil || len(fieldValues) != 1 {
		t.Fatalf("reports %v, %v", fieldValues, err)
	}
	for field, value := range fieldValues {
		if field != writeBudgetReportFieldPrefix+fixture.client.ProcessId() {
			t.Errorf("field %q", field)
		}
		if bytes.Contains(value, []byte(networkId.String())) || strings.Contains(field, networkId.String()) {
			t.Error("the report names the network")
		}
	}
	fixture.clock.Advance(fixture.settings.ReportTtl + time.Second)
	if fieldValues, _ := fixture.host.Redis.HashGetAll(t.Context(), writeBudgetKey("meta-1")); len(fieldValues) != 0 {
		t.Errorf("a report outlived its ttl: %v", fieldValues)
	}
}

// The issued metric carries each class's bytes, P0's by kind, with no network label.
func TestWriteBudgetExportsIssuedBytes(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{P1ByteCount: 1000, UnfundedByteCount: 1000, FundedByteCount: 1000})
	fixture.client.IssueP0(t.Context(), "meta-1", sidecar.WriteP0KindRotation, 300)
	if grant, err := fixture.client.AdmitP1(t.Context(), "meta-1", connect.NewId(), sidecar.WriteCost{ImmediateByteCount: 63, DeferredByteCount: 37}); err == nil {
		grant.Close()
	}
	if grant, err := fixture.client.AcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{Rank: sidecar.WriteP2RankGc, ByteCount: 20}); err == nil {
		grant.Close()
	}
	if grant, err := fixture.client.AcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{Rank: sidecar.WriteP2RankFold, ByteCount: 30, Funded: true}); err == nil {
		grant.Close()
	}
	fixture.account.tick(t.Context())
	metrics := fixture.host.Metrics
	for _, c := range []struct {
		class string
		kind  string
		want  float64
	}{
		{class: "p0", kind: "rotation", want: 300},
		{class: "p1", kind: "", want: 63},
		{class: "p2_unfunded", kind: "", want: 20},
		{class: "p2_funded", kind: "", want: 30},
	} {
		if got := metrics.Value(writeBudgetIssuedMetricName, "meta-1", c.class, c.kind); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.class, c.kind, got, c.want)
		}
	}
	// a second tick adds only what is new
	fixture.account.tick(t.Context())
	if got := metrics.Value(writeBudgetIssuedMetricName, "meta-1", "p0", "rotation"); got != 300 {
		t.Errorf("p0 after a second tick: %v", got)
	}
	if violations := metrics.Violations(); len(violations) != 0 {
		t.Errorf("metric violations %v", violations)
	}
}

// The copy rate is the cluster's over the processes copying, this one counted.
func TestWriteBudgetCopyRateIsShared(t *testing.T) {
	fixture := newBudgetFixture(t)
	if rate := fixture.client.CopyOpsPerSecond("meta-1"); rate != 250 {
		t.Errorf("no allowance: %d", rate)
	}
	fixture.warm(1)
	fixture.account.stateLock.Lock()
	fixture.account.allowance = &WriteBudgetAllowance{ClusterId: "meta-1", CopyOpsPerSecond: 1000, CopyProcessCount: 3}
	fixture.account.stateLock.Unlock()
	if rate := fixture.client.CopyOpsPerSecond("meta-1"); rate != 250 {
		t.Errorf("one of four: %d", rate)
	}
	fixture.client.DeclareP2Backlog("meta-1", "copies", sidecar.WriteP2RankCopy, false, 1000)
	if rate := fixture.client.CopyOpsPerSecond("meta-1"); rate != 333 {
		t.Errorf("one of three: %d", rate)
	}
}

// A declared backlog reaches the report, the larger of it and what waits, and so the wallet's clamp.
func TestWriteBudgetReportsDeclaredBacklog(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{})
	fixture.client.DeclareP2Backlog("meta-1", "evacuation", sidecar.WriteP2RankEvacuation, true, 5000)
	fixture.client.DeclareP2Backlog("meta-1", "gc", sidecar.WriteP2RankGc, false, 700)
	go fixture.client.AcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{Rank: sidecar.WriteP2RankEvacuation, ByteCount: 300, Funded: true})
	fixture.awaitWaits(1)
	report := fixture.report()
	if report.FundedDemandByteCounts[sidecar.WriteP2RankEvacuation] != 300 || report.FundedBacklogByteCounts[sidecar.WriteP2RankEvacuation] != 5000 {
		t.Errorf("funded %v %v", report.FundedDemandByteCounts, report.FundedBacklogByteCounts)
	}
	if report.UnfundedBacklogByteCounts[sidecar.WriteP2RankGc] != 700 {
		t.Errorf("unfunded %v", report.UnfundedBacklogByteCounts)
	}
}

// Close refuses what waits, and nothing is admitted after.
func TestWriteBudgetCloseEndsTheWaits(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{})
	pending := fixture.admitAsync(t.Context(), connect.NewId(), sidecar.WriteCost{ImmediateByteCount: 100})
	fixture.awaitWaits(1)
	p2 := make(chan error, 1)
	go func() {
		_, err := fixture.client.AcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{Rank: sidecar.WriteP2RankGc, ByteCount: 100})
		p2 <- err
	}()
	fixture.awaitWaits(2)
	fixture.client.Close()
	pending.wait(t)
	if !errors.Is(pending.err, ErrWriteBudgetClosed) {
		t.Errorf("P1: %v", pending.err)
	}
	if err := <-p2; !errors.Is(err, ErrWriteBudgetClosed) {
		t.Errorf("P2: %v", err)
	}
	if _, err := fixture.client.AdmitP1(t.Context(), "meta-1", connect.NewId(), sidecar.WriteCost{ImmediateByteCount: 1}); !errors.Is(err, ErrWriteBudgetClosed) {
		t.Errorf("after close: %v", err)
	}
}

// What the interface refuses: a cost below zero, no network, a cluster with no account, an invalid
// rank.
func TestWriteBudgetRefusesBadCalls(t *testing.T) {
	fixture := newBudgetFixture(t)
	fixture.setPools(&WriteBudgetShare{P1ByteCount: 1000})
	if _, err := fixture.client.AdmitP1(t.Context(), "meta-1", connect.NewId(), sidecar.WriteCost{ImmediateByteCount: -1}); !errors.Is(err, sidecar.ErrWriteCost) {
		t.Errorf("negative: %v", err)
	}
	if _, err := fixture.client.AdmitP1(t.Context(), "meta-1", connect.Id{}, sidecar.WriteCost{}); !errors.Is(err, ErrWriteBudgetNetwork) {
		t.Errorf("no network: %v", err)
	}
	if _, err := fixture.client.AdmitP1(t.Context(), "seg-1", connect.NewId(), sidecar.WriteCost{}); !errors.Is(err, ErrWriteBudgetCluster) {
		t.Errorf("segment cluster: %v", err)
	}
	if _, err := fixture.client.AcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{Rank: 99}); !errors.Is(err, sidecar.ErrWriteCost) {
		t.Errorf("rank: %v", err)
	}
}

// The process's own goroutine ticks at once and then every interval on the host's clock.
func TestWriteBudgetRunsOnTheHostsClock(t *testing.T) {
	ctx := t.Context()
	settings := governorTestSettings()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	client, err := NewWriteBudget(ctx, host.ServiceHost(), nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	// both goroutines parked on the clock: the first tick is done
	if err := clock.AwaitTimers(ctx, 2); err != nil {
		t.Fatal(err)
	}
	reports, err := ReadWriteBudgetReports(ctx, host.Redis, "meta-1")
	if err != nil || len(reports) != 1 || reports[0].ProcessId != client.ProcessId() {
		t.Fatalf("reports %v, %v", reports, err)
	}
	if violations := host.Redis.Violations(); len(violations) != 0 {
		t.Errorf("Redis violations %v", violations)
	}
}

// Every write on a metadata cluster needs a class a budget gave its ctx; the segment cluster and reads
// do not.
func TestBudgetedBlobsRefusesAnUnbudgetedWrite(t *testing.T) {
	fixture := newBudgetFixture(t)
	blobs := NewBudgetedBlobs(fixture.host.Blobs)
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if _, err := cluster.PutIfNoneMatch(ctx, "place/r/_", []byte("x"), nil); !errors.Is(err, ErrWriteUnbudgeted) || !errors.Is(err, sidecar.ErrBlobPutOptions) {
		t.Errorf("unclassed put: %v", err)
	}
	if err := cluster.Delete(ctx, "place/r/_"); !errors.Is(err, ErrWriteUnbudgeted) {
		t.Errorf("unclassed delete: %v", err)
	}
	if _, err := cluster.Head(ctx, "place/r/_"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Errorf("the refused put wrote: %v", err)
	}
	p0 := fixture.client.IssueP0(ctx, "meta-1", sidecar.WriteP0KindLifecycle, 9216)
	if _, err := cluster.PutIfNoneMatch(p0, "place/r/_", []byte("x"), nil); err != nil {
		t.Errorf("P0 put: %v", err)
	}
	segment, err := blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	sum := [32]byte{}
	if _, err := segment.PutStream(ctx, "seg/r/x", bytes.NewReader(nil), 0, sum[:]); errors.Is(err, ErrWriteUnbudgeted) {
		t.Error("the segment cluster asked for a budget")
	}
	if ids := blobs.MetadataClusterIds(); len(ids) != 1 || ids[0] != "meta-1" {
		t.Errorf("ids %v", ids)
	}
}
