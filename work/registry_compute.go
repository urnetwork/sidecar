// §14.5's compute jobs (DESIGN-COMPUTE §14.5, §14.8; CSRV-M12-05): the design table taskworker schedules from, each
// job's area, the migration group whose tables it reads, and its cadence, every figure a field of ComputeJobSettings
// (QD-702), the ledger's own in BAL's model.ComputeLedgerSettings. searchsigner's four jobs run in its own block and
// are CSRV-M13-01's.
//
//	job                       area   group  cadence
//	compute_settle            BAL    MG-C1  a loop a shard, every 2 s (§9.7)
//	compute_op_recover        BAL    MG-C1  every minute
//	compute_rollup_day        BAL    MG-C1  daily at 02:00 UTC
//	compute_auto_renew        BAL    MG-C1  every minute
//	compute_enclave_meter     ENC    MG-C3  every 10 minutes
//	compute_provider_prices   INFER  MG-C2  hourly
//	compute_model_mirror      CSRV          when a manifest adds a file, once-keyed by its SHA-256 (CO-49)
//	compute_canary            PROV   MG-C2  hourly
//	compute_gamma_mint        GAMMA  MG-C2  every 5 minutes
//	compute_gamma_spend       GAMMA  MG-C2  every 5 minutes
//	compute_gamma_watch       GAMMA  MG-C2  each finalized block, read by a loop polling the finalized head
//	compute_reconcile         GAMMA  MG-C2  daily at 04:00 UTC, web search's part with §10.7's
//	compute_search_tickets    SRCH   MG-C1  every minute
//	compute_search_purge      SRCH   MG-C1  every 5 minutes
//	compute_direct_settle     INFER  MG-C1  every minute
//	compute_search_outcomes   SRCH   MG-C2  hourly
//	compute_suspend           BAL    MG-C1  every minute
//	compute_promo_lapse       BAL    MG-C1  hourly
//
// Each area registers its jobs' logic from its own file through RegisterJob, by the name above; a design job no area
// has registered stays listed in computeJobUnbuilt, and taskworker runs it as a run that fails and waits on
// server/task's backoff, so the job's chain stands from the start and begins working the moment its logic lands.
// TestComputeJobDesignIsRegisteredOrUnbuilt fails a job that is neither registered nor listed, or both, and an area
// removes its job's line in the change that registers it.
//
// The jobs whose logic landed before this registry are registered here: BAL's compute_settle (one run a shard, its
// args the shard's number), compute_op_recover, compute_rollup_day (its args the cursor a run stopped at, so a
// continuation resumes there) and compute_promo_lapse, and CSRV-M11-02's compute_model_mirror (its args the manifest's
// file, its copy ComputeModelMirror.Copy over the store taskworker installs).

package work

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
)

// §14.5's job names, each its key in every request for it.
const (
	ComputeJobSettle          = "compute_settle"
	ComputeJobOpRecover       = "compute_op_recover"
	ComputeJobRollupDay       = "compute_rollup_day"
	ComputeJobAutoRenew       = "compute_auto_renew"
	ComputeJobEnclaveMeter    = "compute_enclave_meter"
	ComputeJobProviderPrices  = "compute_provider_prices"
	ComputeJobModelMirror     = "compute_model_mirror"
	ComputeJobCanary          = "compute_canary"
	ComputeJobGammaMint       = "compute_gamma_mint"
	ComputeJobGammaSpend      = "compute_gamma_spend"
	ComputeJobGammaWatch      = "compute_gamma_watch"
	ComputeJobReconcile       = "compute_reconcile"
	ComputeJobSearchTickets   = "compute_search_tickets"
	ComputeJobSearchPurge     = "compute_search_purge"
	ComputeJobDirectSettle    = "compute_direct_settle"
	ComputeJobSearchOutcomes  = "compute_search_outcomes"
	ComputeJobSuspend         = "compute_suspend"
	ComputeJobPromoLapse      = "compute_promo_lapse"
	computeJobTaskNamePrefix  = "compute."
	computeJobNamePrefix      = "compute_"
	computeJobOwnerBal        = "BAL"
	computeJobOwnerEnc        = "ENC"
	computeJobOwnerInfer      = "INFER"
	computeJobOwnerProv       = "PROV"
	computeJobOwnerGamma      = "GAMMA"
	computeJobOwnerSrch       = "SRCH"
	computeJobOwnerCsrv       = "CSRV"
	ComputeJobGroupLedger     = "MG-C1"
	ComputeJobGroupProviders  = "MG-C2"
	ComputeJobGroupEnclaves   = "MG-C3"
	computeJobShardArgsFormat = "shard:%d"
)

// How a compute job is scheduled.
type ComputeJobCadence int

const (
	// A once-keyed chain: each run queues the next an interval on before it works.
	ComputeJobCadenceEvery ComputeJobCadence = 1
	// A once-keyed chain at a UTC time of day: each run queues the next day's.
	ComputeJobCadenceDaily ComputeJobCadence = 2
	// A loop a shard on goroutines of its own, every interval, never a chain through pending_task, which at 2 s would
	// write Postgres tens of thousands of times a day a shard for nothing.
	ComputeJobCadenceShardLoop ComputeJobCadence = 3
	// One loop on a goroutine of its own, every interval: compute_gamma_watch's poll of the finalized head.
	ComputeJobCadenceLoop ComputeJobCadence = 4
	// No schedule: queued when its trigger comes, once-keyed by its subject.
	ComputeJobCadenceQueued ComputeJobCadence = 5
)

// One job of §14.5's table.
type ComputeJob struct {
	Name string
	// The area that builds its logic.
	Owner string
	// The pending migration group whose tables it reads, which the binary must link for it to be scheduled; "" for
	// none.
	Group   string
	Cadence ComputeJobCadence
	// Every and the loops: the wait between runs.
	Interval time.Duration
	// Daily: the time past 00:00 UTC it runs at.
	TimeOfDay time.Duration
	// The shard loop: how many shards, one loop each.
	ShardCount int
	// How long one run may take; zero for taskworker's default.
	MaxTime time.Duration
}

// The compute jobs' settings (QD-702). BAL's jobs' figures are the ledger's own (model.ComputeLedgerSettings), so each
// default stays in one place.
type ComputeJobSettings struct {
	// compute_settle's interval, shards and batch, compute_op_recover's, compute_auto_renew's, compute_suspend's and
	// compute_promo_lapse's intervals, and compute_rollup_day's time of day.
	Ledger *model.ComputeLedgerSettings
	// compute_model_mirror's copy, whose CopyTimeout bounds a run.
	ModelMirror *model.ComputeModelMirrorSettings
	// compute_enclave_meter: every 10 minutes (§9.6, §14.5).
	EnclaveMeterInterval time.Duration
	// compute_provider_prices and compute_canary: hourly.
	ProviderPricesInterval time.Duration
	CanaryInterval         time.Duration
	// compute_gamma_mint and compute_gamma_spend: every 5 minutes (§10.4).
	GammaMintInterval  time.Duration
	GammaSpendInterval time.Duration
	// compute_gamma_watch reads each finalized block by polling the chain's finalized head this often: 12 s, the
	// chain's block time, so no finalized block waits more than one poll. A reading: §14.5 says "each finalized
	// block" and the chain pushes nothing to taskworker.
	GammaWatchPollInterval time.Duration
	// compute_reconcile: daily, at 04:00 UTC, the time §14.5 gives web search's part, the day before's whole
	// reconciliation running then too (a reading).
	ReconcileTimeOfDay time.Duration
	// compute_search_tickets and compute_direct_settle: every minute; compute_search_purge every 5 minutes;
	// compute_search_outcomes hourly.
	SearchTicketsInterval  time.Duration
	DirectSettleInterval   time.Duration
	SearchPurgeInterval    time.Duration
	SearchOutcomesInterval time.Duration
	// The wait before a run that failed partway is continued from where it stopped: 1 minute, so a failure that
	// stands does not loop.
	ContinueRetryAfter time.Duration
}

// The defaults, the only place one is set.
func DefaultComputeJobSettings() *ComputeJobSettings {
	return &ComputeJobSettings{
		Ledger:                 model.DefaultComputeLedgerSettings(),
		ModelMirror:            model.DefaultComputeModelMirrorSettings(),
		EnclaveMeterInterval:   10 * time.Minute,
		ProviderPricesInterval: 1 * time.Hour,
		CanaryInterval:         1 * time.Hour,
		GammaMintInterval:      5 * time.Minute,
		GammaSpendInterval:     5 * time.Minute,
		GammaWatchPollInterval: 12 * time.Second,
		ReconcileTimeOfDay:     4 * time.Hour,
		SearchTicketsInterval:  1 * time.Minute,
		DirectSettleInterval:   1 * time.Minute,
		SearchPurgeInterval:    5 * time.Minute,
		SearchOutcomesInterval: 1 * time.Hour,
		ContinueRetryAfter:     1 * time.Minute,
	}
}

// §14.5's table under settings, nil taking the defaults, a fresh copy each call.
func ComputeJobDesign(settings *ComputeJobSettings) []*ComputeJob {
	if settings == nil {
		settings = DefaultComputeJobSettings()
	}
	ledger := settings.Ledger
	if ledger == nil {
		ledger = model.DefaultComputeLedgerSettings()
	}
	mirror := settings.ModelMirror
	if mirror == nil {
		mirror = model.DefaultComputeModelMirrorSettings()
	}
	every := func(name string, owner string, group string, interval time.Duration) *ComputeJob {
		return &ComputeJob{Name: name, Owner: owner, Group: group, Cadence: ComputeJobCadenceEvery, Interval: interval}
	}
	daily := func(name string, owner string, group string, timeOfDay time.Duration) *ComputeJob {
		return &ComputeJob{Name: name, Owner: owner, Group: group, Cadence: ComputeJobCadenceDaily, TimeOfDay: timeOfDay}
	}
	return []*ComputeJob{
		{Name: ComputeJobSettle, Owner: computeJobOwnerBal, Group: ComputeJobGroupLedger, Cadence: ComputeJobCadenceShardLoop, Interval: ledger.SettleInterval, ShardCount: ledger.SettleShardCount},
		every(ComputeJobOpRecover, computeJobOwnerBal, ComputeJobGroupLedger, ledger.RecoverInterval),
		daily(ComputeJobRollupDay, computeJobOwnerBal, ComputeJobGroupLedger, ledger.RollupDayOffset),
		every(ComputeJobAutoRenew, computeJobOwnerBal, ComputeJobGroupLedger, ledger.AutoRenewInterval),
		every(ComputeJobEnclaveMeter, computeJobOwnerEnc, ComputeJobGroupEnclaves, settings.EnclaveMeterInterval),
		every(ComputeJobProviderPrices, computeJobOwnerInfer, ComputeJobGroupProviders, settings.ProviderPricesInterval),
		{Name: ComputeJobModelMirror, Owner: computeJobOwnerCsrv, Cadence: ComputeJobCadenceQueued, MaxTime: mirror.CopyTimeout},
		every(ComputeJobCanary, computeJobOwnerProv, ComputeJobGroupProviders, settings.CanaryInterval),
		every(ComputeJobGammaMint, computeJobOwnerGamma, ComputeJobGroupProviders, settings.GammaMintInterval),
		every(ComputeJobGammaSpend, computeJobOwnerGamma, ComputeJobGroupProviders, settings.GammaSpendInterval),
		{Name: ComputeJobGammaWatch, Owner: computeJobOwnerGamma, Group: ComputeJobGroupProviders, Cadence: ComputeJobCadenceLoop, Interval: settings.GammaWatchPollInterval},
		daily(ComputeJobReconcile, computeJobOwnerGamma, ComputeJobGroupProviders, settings.ReconcileTimeOfDay),
		every(ComputeJobSearchTickets, computeJobOwnerSrch, ComputeJobGroupLedger, settings.SearchTicketsInterval),
		every(ComputeJobSearchPurge, computeJobOwnerSrch, ComputeJobGroupLedger, settings.SearchPurgeInterval),
		every(ComputeJobDirectSettle, computeJobOwnerInfer, ComputeJobGroupLedger, settings.DirectSettleInterval),
		every(ComputeJobSearchOutcomes, computeJobOwnerSrch, ComputeJobGroupProviders, settings.SearchOutcomesInterval),
		every(ComputeJobSuspend, computeJobOwnerBal, ComputeJobGroupLedger, ledger.SuspendInterval),
		every(ComputeJobPromoLapse, computeJobOwnerBal, ComputeJobGroupLedger, ledger.PromoLapseInterval),
	}
}

// The design jobs whose areas have not registered their logic. An area removes its job in the change that registers
// it.
var computeJobUnbuilt = []string{
	ComputeJobEnclaveMeter,
	ComputeJobCanary,
	ComputeJobGammaMint,
	ComputeJobGammaSpend,
	ComputeJobGammaWatch,
	ComputeJobReconcile,
	ComputeJobDirectSettle,
	ComputeJobSearchOutcomes,
}

// The design jobs listed unbuilt, a copy.
func ComputeJobUnbuilt() []string {
	return append([]string{}, computeJobUnbuilt...)
}

// A compute job's name in taskworker's sidecar task registry: compute.<job>, compute_settle's compute.settle.
func ComputeJobTaskName(name string) string {
	return computeJobTaskNamePrefix + strings.TrimPrefix(name, computeJobNamePrefix)
}

// A shard's run's args for compute_settle.
func ComputeSettleJobArgs(shard int16) []byte {
	return fmt.Appendf(nil, computeJobShardArgsFormat, shard)
}

// The shard of compute_settle's args.
func computeSettleJobShard(args []byte) (int16, error) {
	text, found := strings.CutPrefix(string(args), strings.TrimSuffix(computeJobShardArgsFormat, "%d"))
	if !found {
		return 0, fmt.Errorf("%w: compute_settle takes a shard", ErrComputeJobArgs)
	}
	shard, err := strconv.ParseInt(text, 10, 16)
	if err != nil || shard < 0 {
		return 0, fmt.Errorf("%w: compute_settle's shard %q", ErrComputeJobArgs, text)
	}
	return int16(shard), nil
}

// A compute_model_mirror run's args, the manifest's file, and the key its requests coalesce under, its SHA-256, so
// the job runs once a file however often a manifest names it.
func ComputeModelMirrorJobArgs(file *sidecar.InferManifestModelFile) (args []byte, onceKey string, err error) {
	if file == nil || file.Sha256 == "" {
		return nil, "", fmt.Errorf("%w: compute_model_mirror takes a file with its SHA-256", ErrComputeJobArgs)
	}
	args, err = json.Marshal(file)
	if err != nil {
		return nil, "", err
	}
	return args, ComputeJobModelMirror + "." + file.Sha256, nil
}

// A run's args its job does not take.
var ErrComputeJobArgs = errors.New("work: a compute job's args")

// A run needing what the process installs (InstallComputeJobDeps), in a process that installed none: it fails and
// waits on server/task's backoff.
var ErrComputeJobDepsNotInstalled = errors.New("work: this process installed nothing the compute job runs on")

// What a process gives the compute jobs that sidecar/work cannot reach itself.
type ComputeJobDeps struct {
	// The settings the runs read; nil for the defaults.
	Settings *ComputeJobSettings
	// The api's model mirror's objects, server's ComputeModelBlobStore over its blob store; nil where the process holds
	// none, and compute_model_mirror's runs fail and wait.
	ModelMirrorStore model.ComputeModelMirrorStore
	// The hub compute_model_mirror copies from; nil for Hugging Face's, through model.NewComputeModelHubFetcher.
	ModelMirrorFetcher model.ComputeModelFetcher
	// Where a job logs what it found, never content; nil logs nothing.
	Log sidecar.Logger
}

// What the newest install gave.
var computeJobDeps atomic.Pointer[ComputeJobDeps]

// Installs what the compute jobs run on in this process. Answers what removes it, which leaves a later install in
// place.
func InstallComputeJobDeps(deps *ComputeJobDeps) func() {
	if deps == nil {
		deps = &ComputeJobDeps{}
	}
	computeJobDeps.Store(deps)
	return func() {
		computeJobDeps.CompareAndSwap(deps, nil)
	}
}

// The installed settings, the defaults where none are.
func computeJobSettings() *ComputeJobSettings {
	if deps := computeJobDeps.Load(); deps != nil && deps.Settings != nil {
		return deps.Settings
	}
	return DefaultComputeJobSettings()
}

// The installed log, a no-op where none is.
func computeJobLog() sidecar.Logger {
	if deps := computeJobDeps.Load(); deps != nil && deps.Log != nil {
		return deps.Log
	}
	return sidecar.NewNoopLogger()
}

func init() {
	RegisterJob(&Job{Name: ComputeJobSettle, Run: func(ctx context.Context, args []byte) ([]byte, error) {
		shard, err := computeSettleJobShard(args)
		if err != nil {
			return nil, err
		}
		return nil, ComputeSettleTask(ctx, computeJobSettings().Ledger, shard)
	}})
	RegisterJob(&Job{Name: ComputeJobOpRecover, Run: func(ctx context.Context, args []byte) ([]byte, error) {
		return nil, ComputeOpRecoverTask(ctx, computeJobSettings().Ledger)
	}})
	RegisterJob(&Job{Name: ComputeJobRollupDay, Run: func(ctx context.Context, args []byte) ([]byte, error) {
		cursor, err := controller.ParseComputeRollupCursor(args)
		if err != nil {
			return nil, err
		}
		reached, err := ComputeRollupDayTask(ctx, computeJobSettings().Ledger, computeJobLog(), cursor)
		if reached == nil || reached.Phase == controller.ComputeRollupPhaseDone {
			return nil, err
		}
		// stopped short of the day's end: its continuation resumes at the cursor it reached
		continueArgs, argsErr := reached.Args()
		if argsErr != nil {
			return nil, errors.Join(err, argsErr)
		}
		return continueArgs, err
	}})
	RegisterJob(&Job{Name: ComputeJobPromoLapse, Run: func(ctx context.Context, args []byte) ([]byte, error) {
		return nil, ComputePromoLapseTask(ctx, computeJobSettings().Ledger)
	}})
	RegisterJob(&Job{Name: ComputeJobModelMirror, Run: func(ctx context.Context, args []byte) ([]byte, error) {
		return nil, computeModelMirrorRun(ctx, args)
	}})
}

// One compute_model_mirror run: the file of args copied into the mirror unless the mirror holds it already, through
// the store the process installed and the hub.
func computeModelMirrorRun(ctx context.Context, args []byte) error {
	file := &sidecar.InferManifestModelFile{}
	if err := json.Unmarshal(args, file); err != nil || file.Sha256 == "" {
		return fmt.Errorf("%w: compute_model_mirror's file", ErrComputeJobArgs)
	}
	deps := computeJobDeps.Load()
	if deps == nil || deps.ModelMirrorStore == nil {
		return fmt.Errorf("%w: no model mirror store", ErrComputeJobDepsNotInstalled)
	}
	settings := computeJobSettings()
	var fetcher model.ComputeModelFetcher = deps.ModelMirrorFetcher
	if fetcher == nil {
		fetcher = model.NewComputeModelHubFetcher(settings.ModelMirror, nil, nil)
	}
	mirror := model.NewComputeModelMirror(
		deps.ModelMirrorStore,
		fetcher,
		settings.ModelMirror,
		nil,
		nil,
		deps.Log,
	)
	_, _, err := mirror.Copy(ctx, file)
	return err
}
