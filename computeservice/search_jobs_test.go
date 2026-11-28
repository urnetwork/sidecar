package computeservice

// SRCH-M13-08: compute_search_tickets, compute_search_purge and compute_op_recover's web search source (search_jobs.go)
// on the search fixture's fake ledger and clock. The purge's deletion itself is BAL-M13-02's ComputeDeleteSearchRows,
// which has not landed: the fake ledger deletes as it will, and the real one answers ErrComputeSearchLedgerUnbuilt.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An Env whose services a test does not give: the jobs here read their stores from the test, and its metrics refuse.
type refusingSearchEnv struct {
	operator.Env
}

func (self *refusingSearchEnv) Metrics() (operator.Metrics, error) {
	return nil, errors.New("a test env holds no metrics")
}

// The retention as a test sets it: each prune's cutoff, and what it answers.
type fakeComputeSearchRetention struct {
	stateLock        sync.Mutex
	flagBefores      []time.Time
	outcomeBefores   []time.Time
	flagCount        int64
	outcomeHourCount int64
}

func (self *fakeComputeSearchRetention) PruneFlags(ctx context.Context, before time.Time, limit int) (int64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.flagBefores = append(self.flagBefores, before)
	return self.flagCount, nil
}

func (self *fakeComputeSearchRetention) PruneOutcomeHours(ctx context.Context, before time.Time, limit int) (int64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.outcomeBefores = append(self.outcomeBefores, before)
	return self.outcomeHourCount, nil
}

// The jobs' args over the fixture's ledger, clock and metrics.
func (self *computeSearchFixture) jobArgs(retention computeSearchRetention) *ComputeSearchJobArgs {
	if retention == nil {
		retention = &fakeComputeSearchRetention{}
	}
	return &ComputeSearchJobArgs{
		Env:           &refusingSearchEnv{},
		Ledger:        self.ledger,
		Clock:         self.clock,
		Metrics:       self.metrics,
		testRetention: retention,
	}
}

// compute_search_tickets over the fixture.
func (self *computeSearchFixture) ticketsJob(t testing.TB) *ComputeSearchTicketsJob {
	t.Helper()
	job, err := NewComputeSearchTicketsJob(self.jobArgs(nil))
	if err != nil {
		t.Fatal(err)
	}
	return job
}

// compute_search_purge over the fixture.
func (self *computeSearchFixture) purgeJob(t testing.TB, retention computeSearchRetention) *ComputeSearchPurgeJob {
	t.Helper()
	job, err := NewComputeSearchPurgeJob(self.jobArgs(retention))
	if err != nil {
		t.Fatal(err)
	}
	return job
}

// An admission no report reached is released an hour past its window, not a moment before.
func TestSearchTicketsReleaseAfterHour(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	requestId := testSearchRequestId("tickets")
	fixture.admitTicket(t, requestId, 1)
	opKey := fixture.opKey(fixture.networkId, requestId, 1)
	minute := fixture.clock.Now().UTC().Truncate(time.Minute)
	job := fixture.ticketsJob(t)
	settings := DefaultComputeSearchSettings()
	due := minute.Add(settings.webSearch().WindowAfter + settings.TicketReportGrace)
	fixture.clock.AdvanceTo(due)
	result, err := job.Run(context.Background())
	if err != nil || result.ReleasedCount != 0 {
		t.Fatalf("released %+v at the hour's end, %v", result, err)
	}
	if op := fixture.ledger.op(opKey); op == nil || op.state != model.ComputeOpStateOpen {
		t.Fatal("the admission was released within its hour")
	}
	fixture.clock.Advance(time.Millisecond)
	result, err = job.Run(context.Background())
	if err != nil || result.ReleasedCount != 1 {
		t.Fatalf("released %+v past the hour, %v", result, err)
	}
	if op := fixture.ledger.op(opKey); op == nil || op.state != model.ComputeOpStateVoid {
		t.Fatal("the admission was not released past its hour")
	}
}

// compute_op_recover's web search source: an open search row waits for its report until an hour past its window, then
// is released at no charge, never settled; a row of another kind waits, as no search's.
func TestSearchRecoverSourceReleasesAfterHour(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	source, err := NewComputeSearchRecoverSource(fixture.jobArgs(nil))
	if err != nil {
		t.Fatal(err)
	}
	minute := fixture.clock.Now().UTC().Truncate(time.Minute)
	search := &model.ComputeOp{Kind: model.ComputeChargeKindWebSearch, StartTime: minute, State: model.ComputeOpStateOpen}
	inference := &model.ComputeOp{Kind: model.ComputeChargeKindInference, StartTime: minute, State: model.ComputeOpStateOpen}
	stateOf := func(op *model.ComputeOp) controller.ComputeRecoverState {
		t.Helper()
		answer, err := source.Recover(nil, context.Background(), op)
		if err != nil || answer == nil {
			t.Fatalf("the source answered %+v, %v", answer, err)
		}
		if answer.Outcome != nil {
			t.Fatal("the source settled a search, whose outcome only its report gives")
		}
		return answer.State
	}
	settings := DefaultComputeSearchSettings()
	fixture.clock.AdvanceTo(minute.Add(settings.webSearch().WindowAfter + settings.TicketReportGrace))
	if state := stateOf(search); state != controller.ComputeRecoverWait {
		t.Fatalf("a search at its hour's end answered %d", state)
	}
	fixture.clock.Advance(time.Millisecond)
	if state := stateOf(search); state != controller.ComputeRecoverUnknown {
		t.Fatalf("a search past its hour answered %d", state)
	}
	if state := stateOf(inference); state != controller.ComputeRecoverWait {
		t.Fatalf("another kind's row answered %d", state)
	}
	invalid := DefaultComputeSearchSettings()
	invalid.TicketReportGrace = 0
	args := fixture.jobArgs(nil)
	args.Settings = invalid
	if _, err := NewComputeSearchRecoverSource(args); err == nil {
		t.Fatal("a source was built on settings that do not validate")
	}
}

// A report that comes after the tickets job released its admission is answered unknown and charges nothing: the
// settlement is URnetwork's unattributed expense.
func TestSearchTicketsLateReportUnknown(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	ticket := fixture.admitTicket(t, testSearchRequestId("late report"), 1)
	minuteS := fixture.minuteS()
	settings := DefaultComputeSearchSettings()
	fixture.clock.Advance(settings.webSearch().WindowAfter + settings.TicketReportGrace + time.Minute)
	if result, err := fixture.ticketsJob(t).Run(context.Background()); err != nil || result.ReleasedCount != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	fixture.signer.report(ticket, 1, minuteS, nil, nil)
	fixture.pull(t)
	if len(fixture.ledger.chargeList()) != 0 {
		t.Fatal("a late report charged a released search")
	}
}

// The purge deletes a search's rows from 71 h 55 min, not at 71 h 54 min, leaves the day's totals as they are, and a
// row it finds past 72 hours pages.
func TestSearchPurgeBoundary(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	ticket := fixture.admitTicket(t, testSearchRequestId("purge"), 1)
	fixture.signer.report(ticket, 1, fixture.minuteS(), nil, nil)
	fixture.pull(t)
	minute := fixture.clock.Now().UTC().Truncate(time.Minute)
	ledgerSettings := model.DefaultComputeLedgerSettings()
	job := fixture.purgeJob(t, nil)
	fixture.clock.AdvanceTo(minute.Add(71*time.Hour + 54*time.Minute))
	result, err := job.Run(context.Background())
	if err != nil || result.SearchCount != 0 || len(fixture.ledger.chargeList()) != 1 {
		t.Fatalf("the purge at 71 h 54 min: %+v %v", result, err)
	}
	fixture.clock.AdvanceTo(minute.Add(ledgerSettings.SearchChargePurgeAge).Add(time.Second))
	result, err = job.Run(context.Background())
	if err != nil || result.SearchCount != 1 || len(fixture.ledger.chargeList()) != 0 || result.Retained {
		t.Fatalf("the purge from 71 h 55 min: %+v %v", result, err)
	}
	// one planted past 72 hours, which a purge whose batch is spent leaves: it pages
	fixture.ledger.plant(fixture.networkId, fixture.clock.Now().Add(-73*time.Hour))
	fixture.ledger.plant(fixture.networkId, fixture.clock.Now().Add(-74*time.Hour))
	func() {
		fixture.ledger.stateLock.Lock()
		defer fixture.ledger.stateLock.Unlock()
		fixture.ledger.deleteLimit = 1
	}()
	result, err = job.Run(context.Background())
	if err != nil || !result.Retained {
		t.Fatalf("a row past 72 hours did not page: %+v %v", result, err)
	}
	if fixture.metrics.Value("urnetwork_compute_alarms_total", ComputeAlarmSearchRowRetained) != 1 {
		t.Fatal("the page is not counted")
	}
}

// The purge keeps the search's own records to their ttls: reviewed sanctions records past the recordkeeping period,
// hourly outcome rows past 400 days, each cut from the run's clock.
func TestSearchPurgeRecordsRetention(t *testing.T) {
	fixture := newComputeSearchFixture(t, nil)
	retention := &fakeComputeSearchRetention{flagCount: 2, outcomeHourCount: 4}
	result, err := fixture.purgeJob(t, retention).Run(context.Background())
	if err != nil || result.FlagCount != 2 || result.OutcomeHourCount != 4 {
		t.Fatalf("%+v %v", result, err)
	}
	settings := DefaultComputeSearchSettings()
	now := fixture.clock.Now()
	if len(retention.flagBefores) != 1 || !retention.flagBefores[0].Equal(now.Add(-settings.FlagRetention)) ||
		len(retention.outcomeBefores) != 1 || !retention.outcomeBefores[0].Equal(now.Add(-settings.OutcomeHourRetention)) {
		t.Fatalf("the cutoffs: %v %v", retention.flagBefores, retention.outcomeBefores)
	}
}

// Over BAL's real ledger, whose deletion has not landed, the purge's run fails with ErrComputeSearchLedgerUnbuilt after
// keeping the records to their ttls, so taskworker retries it on its backoff.
func TestSearchPurgeUnbuiltLedger(t *testing.T) {
	retention := &fakeComputeSearchRetention{}
	job, err := NewComputeSearchPurgeJob(&ComputeSearchJobArgs{
		Env:           &refusingSearchEnv{},
		Ledger:        NewComputeSearchLedger(nil, nil),
		Clock:         sidecartest.NewFakeClock(sidecartest.DefaultClockStart()),
		testRetention: retention,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := job.Run(context.Background()); !errors.Is(err, ErrComputeSearchLedgerUnbuilt) {
		t.Fatalf("the purge answered %v", err)
	}
	if len(retention.flagBefores) != 1 || len(retention.outcomeBefores) != 1 {
		t.Fatal("the records' retention did not run first")
	}
}
