// Web search's two taskworker jobs (DESIGN-COMPUTE §14.5, §21.5, D-SRCH-13, compute-10, compute-11; SRCH-M13-08),
// ComputeSearchTicketsJob and ComputeSearchPurgeJob, whose logic is here and whose names sidecar/work registers
// (compute_search_jobs.go there), installed by the process that runs taskworker, as compute_provider_prices' is, since
// sidecar/work may not import an engine (§4.4):
//
//	compute_search_tickets  each minute: every search admission no report reached an hour past its window, as after
//	                        the signer's failover (§21.5), has its hold released and its operation row voided, oldest
//	                        first, at most TicketsBatchMaxCount a run. A report that comes later finds the row void and
//	                        is answered unknown, its settlement URnetwork's unattributed expense (search_settle.go)
//	compute_search_purge    every 5 minutes: every web search's charge, its lot draws and its operation row, a search
//	                        refund's with them, deleted once their minute is the ledger's SearchChargePurgeAge (71 h
//	                        55 min) old, so none outlives SearchChargeRetention (72 hours), the day rows still counting
//	                        them (BAL-M13-02's ComputeDeleteSearchRows, through ComputeSearchLedger); a search row found
//	                        past 72 hours pages (urnetwork_compute_alarms_total{kind="search_row_retained"}). Beside it,
//	                        the purge keeps the search's own records to their ttls: a reviewed sanctions record past
//	                        FlagRetention, and an hourly outcome row past OutcomeHourRetention, are deleted
//
// Each run reads its clock once, is bounded by its batches, and is idempotent: a run that stops partway is the next
// run's work. Both read Postgres alone, never {cmpa}, which only the compute block reaches. The purge deletes by kind
// and age alone, returning nothing to lots, and never a row of another kind. Safe for concurrent use, though each
// schedule runs one at a time.

package computeservice

import (
	"context"
	"errors"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
)

// The alarm a search row past 72 hours raises: the monitor's compute-search-row-retained page (§14.7).
const ComputeAlarmSearchRowRetained = "search_row_retained"

// The search's own records' retention, over the Env or a test's.
type computeSearchRetention interface {
	// Deletes at most limit reviewed sanctions records from before before.
	PruneFlags(ctx context.Context, before time.Time, limit int) (int64, error)
	// Deletes at most limit hourly outcome rows from before before.
	PruneOutcomeHours(ctx context.Context, before time.Time, limit int) (int64, error)
}

// The real retention.
type envComputeSearchRetention struct {
	env operator.Env
}

// See computeSearchRetention.
func (self *envComputeSearchRetention) PruneFlags(ctx context.Context, before time.Time, limit int) (int64, error) {
	return model.ComputeSearchFlagPrune(self.env, ctx, before, limit)
}

// See computeSearchRetention.
func (self *envComputeSearchRetention) PruneOutcomeHours(ctx context.Context, before time.Time, limit int) (int64, error) {
	return model.ComputeSearchOutcomeHourPrune(self.env, ctx, before, limit)
}

// What the jobs run on.
type ComputeSearchJobArgs struct {
	// The process's Env, whose Postgres links MG-C1 and MG-C2. nil: operator's global one.
	Env operator.Env
	// The ledger's search calls. nil: BAL's over Env, under LedgerSettings.
	Ledger ComputeSearchLedger
	// nil: DefaultComputeSearchSettings.
	Settings *ComputeSearchSettings
	// The ledger's, whose search rows' purge age and retention the purge reads. nil: model.DefaultComputeLedgerSettings.
	LedgerSettings *model.ComputeLedgerSettings
	// nil: the wall clock.
	Clock sidecar.Clock
	// Where the purge's page counts. nil: the Env's metrics, and none where it gives none.
	Metrics sidecar.Metrics
	// nil discards.
	Log sidecar.Logger

	// A test's retention, in place of the Env's.
	testRetention computeSearchRetention
}

// What both jobs read, from their args.
type computeSearchJob struct {
	env            operator.Env
	ledger         ComputeSearchLedger
	settings       *ComputeSearchSettings
	ledgerSettings *model.ComputeLedgerSettings
	clock          sidecar.Clock
	log            sidecar.Logger
	retention      computeSearchRetention
	alarms         sidecar.MetricsCounter
}

// compute_search_tickets' run. See the file header.
type ComputeSearchTicketsJob struct {
	computeSearchJob
}

// compute_search_purge's run. See the file header.
type ComputeSearchPurgeJob struct {
	computeSearchJob
}

// compute_search_tickets over args: settings that do not validate refuse it.
func NewComputeSearchTicketsJob(args *ComputeSearchJobArgs) (*ComputeSearchTicketsJob, error) {
	job, err := newComputeSearchJob(args)
	if err != nil {
		return nil, err
	}
	return &ComputeSearchTicketsJob{computeSearchJob: *job}, nil
}

// compute_search_purge over args: settings that do not validate refuse it.
func NewComputeSearchPurgeJob(args *ComputeSearchJobArgs) (*ComputeSearchPurgeJob, error) {
	job, err := newComputeSearchJob(args)
	if err != nil {
		return nil, err
	}
	return &ComputeSearchPurgeJob{computeSearchJob: *job}, nil
}

// What a job reads, from args.
func newComputeSearchJob(args *ComputeSearchJobArgs) (*computeSearchJob, error) {
	if args == nil {
		args = &ComputeSearchJobArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultComputeSearchSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	ledgerSettings := args.LedgerSettings
	if ledgerSettings == nil {
		ledgerSettings = model.DefaultComputeLedgerSettings()
	}
	if ledgerSettings.SearchChargePurgeAge <= 0 || ledgerSettings.SearchChargeRetention <= ledgerSettings.SearchChargePurgeAge {
		return nil, errors.New("compute search: the purge deletes a search's rows before their retention ends")
	}
	env := args.Env
	if env == nil {
		env = operator.GlobalEnv()
	}
	ledger := args.Ledger
	if ledger == nil {
		ledger = NewComputeSearchLedger(env, ledgerSettings)
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	log := args.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	var retention computeSearchRetention = &envComputeSearchRetention{env: env}
	if args.testRetention != nil {
		retention = args.testRetention
	}
	metrics := args.Metrics
	if metrics == nil {
		if envMetrics, err := env.Metrics(); err == nil {
			metrics = envMetrics
		}
	}
	self := &computeSearchJob{
		env:            env,
		ledger:         ledger,
		settings:       settings,
		ledgerSettings: ledgerSettings,
		clock:          clock,
		log:            log,
		retention:      retention,
	}
	if metrics != nil {
		self.alarms = metrics.Counter("urnetwork_compute_alarms_total", "compute faults that alarm, by kind", "kind")
	}
	return self, nil
}

// Raises kind's alarm, with its line, which names no network.
func (self *computeSearchJob) alarm(kind string, format string, args ...any) {
	if self.alarms != nil {
		self.alarms.Add(1, kind)
	}
	self.log.Errorf("[compute-search] "+format, args...)
}

// What one compute_search_tickets run did.
type ComputeSearchTicketsResult struct {
	ReleasedCount int
	// Rows the ledger had charged by the time it was asked: their reports came in time.
	SettledCount int
	// Rows the ledger could not release this run, left for the next.
	FailedCount int
}

// One compute_search_tickets run (see the file header).
func (self *ComputeSearchTicketsJob) Run(ctx context.Context) (*ComputeSearchTicketsResult, error) {
	now := self.clock.Now()
	before := now.Add(-(self.settings.webSearch().WindowAfter + self.settings.TicketReportGrace))
	ops, err := self.ledger.OpenBefore(ctx, before, self.settings.TicketsBatchMaxCount)
	if err != nil {
		return nil, err
	}
	result := &ComputeSearchTicketsResult{}
	for _, op := range ops {
		if op.Kind != model.ComputeChargeKindWebSearch {
			continue
		}
		state, err := self.ledger.Release(ctx, op.NetworkId, op.OpKey)
		switch {
		case err != nil:
			result.FailedCount += 1
		case state == controller.ComputeReleaseReleased:
			result.ReleasedCount += 1
		case state == controller.ComputeReleaseSettled:
			result.SettledCount += 1
		}
	}
	return result, nil
}

// What one compute_search_purge run did.
type ComputeSearchPurgeResult struct {
	// Searches whose charge, draws and row went.
	SearchCount int
	// Reviewed sanctions records and hourly outcome rows past their ttls.
	FlagCount        int64
	OutcomeHourCount int64
	// Whether a search row past SearchChargeRetention was found, which pages.
	Retained bool
}

// One compute_search_purge run (see the file header). The records' retention runs first, so a purge whose deletion
// BAL has not landed (ErrComputeSearchLedgerUnbuilt) still keeps them to their ttls.
func (self *ComputeSearchPurgeJob) Run(ctx context.Context) (*ComputeSearchPurgeResult, error) {
	now := self.clock.Now()
	result := &ComputeSearchPurgeResult{}
	flagCount, err := self.retention.PruneFlags(ctx, now.Add(-self.settings.FlagRetention), self.settings.PurgeBatchMaxCount)
	if err != nil {
		return nil, err
	}
	result.FlagCount = flagCount
	hourCount, err := self.retention.PruneOutcomeHours(ctx, now.Add(-self.settings.OutcomeHourRetention), self.settings.PurgeBatchMaxCount)
	if err != nil {
		return nil, err
	}
	result.OutcomeHourCount = hourCount
	purged, err := self.ledger.DeleteBefore(ctx, now.Add(-self.ledgerSettings.SearchChargePurgeAge), self.settings.PurgeBatchMaxCount)
	if err != nil {
		return result, err
	}
	result.SearchCount = purged.DeletedCount
	if purged.OldestTime != nil && !now.Before(purged.OldestTime.Add(self.ledgerSettings.SearchChargeRetention)) {
		result.Retained = true
		self.alarm(ComputeAlarmSearchRowRetained, "a web search's rows are past %s", self.ledgerSettings.SearchChargeRetention)
	}
	return result, nil
}
