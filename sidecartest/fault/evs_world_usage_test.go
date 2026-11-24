// The evs world's usage producer under a schedule's clock move (EvsWorldSettings.UsageReportTimeout). A world's
// instance reports usage from a goroutine of its own once an Advance closes its window, so a report can be on its way
// to the fake Quota while the same Advance moves the clock on. These tests hold one report there, between the
// producer's taking the window and the Quota's counting the call, with a Quota that keeps the call until the test lets
// it go, move the clock as FS-1's 26 h move does, and let it go. On the world's settings the report reaches the Quota,
// one host write, as §22.8's unknown rule needs every run to repeat; on the producer's own 30 s bound, which the world's
// blocks took before, the move cancels the report before the Quota counts it and the retry, due past RetryHorizon,
// drops the batch, so the write is never made: how FS-1's rerun losing its third host write found none to lose
// ("never fired: [host  nth=3 ApplyThenDrop]").

package fault

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A Quota that keeps the first ReportUsage on its way to the fake until Release, telling arrived when it has it and
// answered what the fake said, and passes every other call straight through.
type evsWorldKeptQuota struct {
	sidecar.Quota
	keepOnce    sync.Once
	releaseOnce sync.Once
	arrived     chan struct{}
	release     chan struct{}
	answered    chan error
}

func newEvsWorldKeptQuota(quota sidecar.Quota) *evsWorldKeptQuota {
	return &evsWorldKeptQuota{
		Quota:    quota,
		arrived:  make(chan struct{}),
		release:  make(chan struct{}),
		answered: make(chan error, 1),
	}
}

func (self *evsWorldKeptQuota) ReportUsage(ctx context.Context, batch *sidecar.UsageBatch) error {
	kept := false
	self.keepOnce.Do(func() {
		kept = true
	})
	if !kept {
		return self.Quota.ReportUsage(ctx, batch)
	}
	close(self.arrived)
	<-self.release
	err := self.Quota.ReportUsage(ctx, batch)
	self.answered <- err
	return err
}

// Lets the kept call go on to the fake. Safe more than once, so a test that fails first still frees the producer
// its Close joins.
func (self *evsWorldKeptQuota) Release() {
	self.releaseOnce.Do(func() {
		close(self.release)
	})
}

// What a report kept through the move came to.
type evsWorldUsageMove struct {
	// the clock's timers while the report was kept: its bound's, where the producer arms one
	keptTimers []time.Time
	// what the kept report answered
	err error
	// once the retry a failed report waits for was due: the host writes the fault queue counted, the batches that
	// reached the fake Quota and those it applied, and the producer's counted failures and drops
	hostWrites   []FaultResult
	sentBatches  []*sidecar.UsageBatch
	appliedCount int
	failedCount  float64
	droppedCount float64
	// where the window ended, and where the move left the clock
	windowEnd time.Time
	movedTo   time.Time
}

// An evs producer on usageSettings, built as the world's T2 block builds it, its window holding 100 bytes; the clock
// moved to the window's end, the report kept on its way to the Quota, the clock moved 26 h, the report let go, then the
// clock moved on to where a failed report's retry falls due. Only the producer arms timers on this clock, so the
// clock's holding one says the producer has finished its round and waits (owner decision 549).
func evsWorldUsageReportInMove(t *testing.T, usageSettings *sidecar.QuotaUsageBatcherSettings) *evsWorldUsageMove {
	t.Helper()
	// a guard, never a wait the test orders (§22.8's 60 s)
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	metrics := sidecartest.NewFakeMetrics(nil)
	fakeQuota := sidecartest.NewFakeQuota(clock, faults, nil)
	quota := newEvsWorldKeptQuota(fakeQuota)
	host := &sidecar.ServiceHost{Quota: quota, Metrics: metrics, Clock: clock}
	usage, err := evsservice.NewUsageBatcher(t.Context(), host, usageSettings)
	if err != nil {
		t.Fatal(err)
	}
	// deferred calls run last first: the kept call goes on before Close joins the producer
	defer usage.Close()
	defer quota.Release()
	awaitIdle := func(what string) {
		if err := clock.AwaitTimers(ctx, 1); err != nil {
			t.Fatalf("the producer never waited %s: %v", what, err)
		}
	}
	awaitIdle("for its first window's end")
	if err := usage.AddTransfer(connect.NewId(), 100); err != nil {
		t.Fatal(err)
	}

	move := &evsWorldUsageMove{}
	move.windowEnd = clock.Now().Add(usageSettings.WindowTimeout)
	clock.Advance(usageSettings.WindowTimeout)
	select {
	case <-quota.arrived:
	case <-ctx.Done():
		t.Fatalf("the window's report never reached the Quota: %v", ctx.Err())
	}
	move.keptTimers = clock.PendingTimers()

	clock.Advance(26 * time.Hour)
	move.movedTo = clock.Now()
	quota.Release()
	select {
	case move.err = <-quota.answered:
	case <-ctx.Done():
		t.Fatalf("the kept report never answered: %v", ctx.Err())
	}
	awaitIdle("after the kept report")

	clock.Advance(usageSettings.RetryTimeout)
	awaitIdle("after its retry fell due")
	move.hostWrites = faults.WriteResults(sidecartest.FaultOpHost)
	move.sentBatches = fakeQuota.SentBatches()
	move.appliedCount = len(fakeQuota.Batches())
	move.failedCount = metrics.Value("urnetwork_quota_usage_send_failures_total", sidecar.QuotaProducerEvs)
	move.droppedCount = metrics.Value("urnetwork_quota_usage_batches_dropped_total", sidecar.QuotaProducerEvs)
	return move
}

// On the world's settings a report in flight through FS-1's move reaches the Quota: one host write, the batch applied
// once, nothing failed or dropped.
func TestEvsWorldUsageReportOutlivesTheMove(t *testing.T) {
	settings := evsWorldUsageSettings(DefaultEvsWorldSettings())
	if 0 < settings.ReportTimeout {
		t.Fatalf("the world bounds a report by %s, which a schedule's Advance passes", settings.ReportTimeout)
	}
	move := evsWorldUsageReportInMove(t, settings)
	if len(move.keptTimers) != 0 {
		t.Fatalf("the kept report armed %v", move.keptTimers)
	}
	if move.err != nil {
		t.Fatalf("the report answered %v", move.err)
	}
	if !slices.Equal(move.hostWrites, []FaultResult{0}) {
		t.Fatalf("host writes %v, want the report's one", move.hostWrites)
	}
	if len(move.sentBatches) != 1 || move.appliedCount != 1 {
		t.Fatalf("%d batches reached the Quota and %d applied, want 1 and 1", len(move.sentBatches), move.appliedCount)
	}
	if move.failedCount != 0 || move.droppedCount != 0 {
		t.Fatalf("%v sends failed and %v batches dropped", move.failedCount, move.droppedCount)
	}
}

// On the producer's own bound, which the world's blocks took before, the same move cancels the report before the Quota
// counts it, and the retry, due past RetryHorizon, drops the batch: no host write at all.
func TestEvsWorldUsageReportBoundCancelledByTheMove(t *testing.T) {
	settings := sidecar.DefaultQuotaUsageBatcherSettings()
	move := evsWorldUsageReportInMove(t, settings)
	bound := move.windowEnd.Add(settings.ReportTimeout)
	if !slices.EqualFunc(move.keptTimers, []time.Time{bound}, time.Time.Equal) {
		t.Fatalf("the kept report armed %v, want its bound at %s", move.keptTimers, bound)
	}
	if !move.movedTo.After(bound) {
		t.Fatalf("the move ended at %s, short of the bound at %s", move.movedTo, bound)
	}
	if !errors.Is(move.err, context.Canceled) {
		t.Fatalf("the report answered %v, want its bound's cancel", move.err)
	}
	if len(move.hostWrites) != 0 || len(move.sentBatches) != 0 || move.appliedCount != 0 {
		t.Fatalf("host writes %v, %d batches reached the Quota, %d applied: the cancel reached it", move.hostWrites, len(move.sentBatches), move.appliedCount)
	}
	if move.failedCount != 1 || move.droppedCount != 1 {
		t.Fatalf("%v sends failed and %v batches dropped, want the cancel and the retry past the horizon", move.failedCount, move.droppedCount)
	}
}
