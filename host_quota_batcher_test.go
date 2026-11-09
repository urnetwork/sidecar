//go:build !sidecar_http

// QuotaUsageBatcher on FakeQuota and a fake clock: FS-44's producer half. The batcher arms its next wait
// only once a round has ended, so a test knows a round ended by the timer it waits on, never by a sleep.

package sidecar_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Returns once clock has a timer pending at at. The real-time bound only fails a test that would hang;
// it orders nothing.
func awaitQuotaTimerAt(t *testing.T, clock *sidecartest.FakeClock, at time.Time) {
	t.Helper()
	for {
		pending, added := clock.WatchTimers()
		if slices.ContainsFunc(pending, func(pendingTime time.Time) bool { return pendingTime.Equal(at) }) {
			return
		}
		select {
		case <-added:
		case <-time.After(10 * time.Second):
			t.Fatalf("no timer at %s, pending %v", at, pending)
		}
	}
}

type quotaBatcherFixture struct {
	clock   *sidecartest.FakeClock
	faults  *sidecartest.FaultQueue
	quota   *sidecartest.FakeQuota
	metrics *sidecartest.FakeMetrics
	batcher *sidecar.QuotaUsageBatcher
	start   time.Time
}

// An evs batcher on the defaults, waiting at its first window's end.
func newQuotaBatcherFixture(t *testing.T) *quotaBatcherFixture {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	quota := sidecartest.NewFakeQuota(clock, faults, nil)
	metrics := sidecartest.NewFakeMetrics(nil)
	host := &sidecar.ServiceHost{Quota: quota, Metrics: metrics, Clock: clock}
	batcher, err := sidecar.NewQuotaUsageBatcher(t.Context(), host, sidecar.QuotaProducerEvs, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(batcher.Close)
	fixture := &quotaBatcherFixture{clock: clock, faults: faults, quota: quota, metrics: metrics, batcher: batcher, start: clock.Now()}
	awaitQuotaTimerAt(t, clock, fixture.at(60*time.Second))
	if violations := metrics.Violations(); len(violations) != 0 {
		t.Fatalf("metrics %v", violations)
	}
	return fixture
}

func (self *quotaBatcherFixture) at(timeout time.Duration) time.Time {
	return self.start.Add(timeout)
}

// Moves the clock to the batcher's timer at at, and returns once the round it starts has ended in the
// batcher's next wait, at next.
func (self *quotaBatcherFixture) step(t *testing.T, at time.Time, next time.Time) {
	t.Helper()
	awaitQuotaTimerAt(t, self.clock, at)
	self.clock.AdvanceTo(at)
	awaitQuotaTimerAt(t, self.clock, next)
}

func mustAdd(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// One batch a window, its events summed by network and meter, each window under its own id.
func TestQuotaUsageBatcherSendsEachWindow(t *testing.T) {
	fixture := newQuotaBatcherFixture(t)
	networkA := connect.NewId()
	networkB := connect.NewId()
	mustAdd(t, fixture.batcher.AddTransfer(networkA, sidecar.QuotaMeterEvs, 100))
	mustAdd(t, fixture.batcher.AddTransfer(networkA, sidecar.QuotaMeterEvs, 50))
	mustAdd(t, fixture.batcher.AddStoredDelta(networkA, 7))
	mustAdd(t, fixture.batcher.AddTransfer(networkB, sidecar.QuotaMeterEvs, 5))
	fixture.step(t, fixture.at(60*time.Second), fixture.at(120*time.Second))
	batches := fixture.quota.Batches()
	if len(batches) != 1 {
		t.Fatalf("%d batches", len(batches))
	}
	batch := batches[0]
	if batch.Producer != sidecar.QuotaProducerEvs || !batch.WindowStart.Equal(fixture.start) || len(batch.Events) != 2 {
		t.Fatalf("batch %+v", batch)
	}
	for _, event := range batch.Events {
		switch event.NetworkId {
		case networkA:
			if event.Meter != sidecar.QuotaMeterEvs || event.TransferByteCount != 150 || event.StoredByteDelta != 7 {
				t.Errorf("A's event %+v", event)
			}
		case networkB:
			if event.TransferByteCount != 5 || event.StoredByteDelta != 0 {
				t.Errorf("B's event %+v", event)
			}
		default:
			t.Errorf("an event for %s", event.NetworkId)
		}
	}
	mustAdd(t, fixture.batcher.AddTransfer(networkA, sidecar.QuotaMeterEvs, 1))
	fixture.step(t, fixture.at(120*time.Second), fixture.at(180*time.Second))
	batches = fixture.quota.Batches()
	if len(batches) != 2 || batches[1].BatchId == batches[0].BatchId || !batches[1].WindowStart.Equal(fixture.at(60*time.Second)) {
		t.Fatalf("batches %+v", batches)
	}
	if got := fixture.quota.TransferUsed(networkA, sidecar.QuotaMeterEvs); got != 151 {
		t.Errorf("A's transfer %d", got)
	}
	if got := fixture.quota.StoredDelta(networkA); got != 7 {
		t.Errorf("A's stored delta %d", got)
	}
}

// A window with nothing in it, or with deltas that net to nothing, sends no batch.
func TestQuotaUsageBatcherSendsNoEmptyWindow(t *testing.T) {
	fixture := newQuotaBatcherFixture(t)
	fixture.step(t, fixture.at(60*time.Second), fixture.at(120*time.Second))
	networkId := connect.NewId()
	mustAdd(t, fixture.batcher.AddStoredDelta(networkId, 10))
	mustAdd(t, fixture.batcher.AddStoredDelta(networkId, -10))
	fixture.step(t, fixture.at(120*time.Second), fixture.at(180*time.Second))
	if sent := fixture.quota.SentBatches(); len(sent) != 0 {
		t.Errorf("sent %+v", sent)
	}
}

// FS-44: a lost response is retried under the same id, and api applies the batch once.
func TestQuotaUsageBatcherRetriesALostResponseUnderOneId(t *testing.T) {
	fixture := newQuotaBatcherFixture(t)
	if _, err := fixture.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	networkId := connect.NewId()
	mustAdd(t, fixture.batcher.AddTransfer(networkId, sidecar.QuotaMeterEvs, 100))
	// the send at 60 s loses its answer, so the retry is due 5 s later
	fixture.step(t, fixture.at(60*time.Second), fixture.at(65*time.Second))
	fixture.step(t, fixture.at(65*time.Second), fixture.at(120*time.Second))
	sent := fixture.quota.SentBatches()
	if len(sent) != 2 || sent[0].BatchId != sent[1].BatchId {
		t.Fatalf("sent %+v", sent)
	}
	if len(fixture.quota.Batches()) != 1 {
		t.Errorf("applied %d", len(fixture.quota.Batches()))
	}
	if got := fixture.quota.TransferUsed(networkId, sidecar.QuotaMeterEvs); got != 100 {
		t.Errorf("transfer %d", got)
	}
	if got := fixture.metrics.Value("urnetwork_quota_usage_send_failures_total", "evs"); got != 1 {
		t.Errorf("failures %v", got)
	}
	if got := fixture.metrics.Value("urnetwork_quota_usage_batches_dropped_total", "evs"); got != 0 {
		t.Errorf("dropped %v", got)
	}
}

// FS-44: api away for 11 min. The batch is retried for 10, then dropped and counted, and never applied:
// under-billing, never double-billing.
func TestQuotaUsageBatcherDropsABatchUnansweredForTenMinutes(t *testing.T) {
	fixture := newQuotaBatcherFixture(t)
	if _, err := fixture.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: sidecartest.FailBeforeApply, Repeat: -1}); err != nil {
		t.Fatal(err)
	}
	networkId := connect.NewId()
	mustAdd(t, fixture.batcher.AddTransfer(networkId, sidecar.QuotaMeterEvs, 100))
	cutTime := fixture.at(60 * time.Second)
	for at := cutTime; at.Before(cutTime.Add(10 * time.Minute)); at = at.Add(5 * time.Second) {
		fixture.step(t, at, at.Add(5*time.Second))
	}
	if got := fixture.metrics.Value("urnetwork_quota_usage_batches_dropped_total", "evs"); got != 0 {
		t.Fatalf("dropped %v inside the horizon", got)
	}
	// the attempt due at 10 min finds the horizon passed
	dropTime := cutTime.Add(10 * time.Minute)
	fixture.step(t, dropTime, dropTime.Add(60*time.Second))
	if got := fixture.metrics.Value("urnetwork_quota_usage_batches_dropped_total", "evs"); got != 1 {
		t.Errorf("dropped %v", got)
	}
	if got := fixture.metrics.Value("urnetwork_quota_usage_dropped_bytes_total", "evs"); got != 100 {
		t.Errorf("dropped bytes %v", got)
	}
	if got := fixture.metrics.Value("urnetwork_quota_usage_send_failures_total", "evs"); got != 120 {
		t.Errorf("failures %v", got)
	}
	// api back at 11 min: nothing is sent again, and nothing was ever applied
	fixture.faults.Clear()
	fixture.step(t, dropTime.Add(60*time.Second), dropTime.Add(120*time.Second))
	if len(fixture.quota.SentBatches()) != 0 || fixture.quota.TransferUsed(networkId, sidecar.QuotaMeterEvs) != 0 {
		t.Errorf("sent %d, transfer %d", len(fixture.quota.SentBatches()), fixture.quota.TransferUsed(networkId, sidecar.QuotaMeterEvs))
	}
}

// FS-44: a SIGTERM drain sends the open window at once and loses nothing.
func TestQuotaUsageBatcherDrainSendsTheOpenWindow(t *testing.T) {
	fixture := newQuotaBatcherFixture(t)
	networkId := connect.NewId()
	mustAdd(t, fixture.batcher.AddTransfer(networkId, sidecar.QuotaMeterEvs, 100))
	if err := fixture.batcher.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	batches := fixture.quota.Batches()
	if len(batches) != 1 || !batches[0].WindowStart.Equal(fixture.start) {
		t.Fatalf("batches %+v", batches)
	}
	if got := fixture.quota.TransferUsed(networkId, sidecar.QuotaMeterEvs); got != 100 {
		t.Errorf("transfer %d", got)
	}
}

// A drain waits out a lost response's retry, and returns once api has the batch.
func TestQuotaUsageBatcherDrainWaitsOutALostResponse(t *testing.T) {
	fixture := newQuotaBatcherFixture(t)
	if _, err := fixture.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	networkId := connect.NewId()
	mustAdd(t, fixture.batcher.AddTransfer(networkId, sidecar.QuotaMeterEvs, 100))
	drained := make(chan error, 1)
	go func() {
		drained <- fixture.batcher.Drain(t.Context())
	}()
	awaitQuotaTimerAt(t, fixture.clock, fixture.at(5*time.Second))
	fixture.clock.AdvanceTo(fixture.at(5 * time.Second))
	select {
	case err := <-drained:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the drain never returned")
	}
	if len(fixture.quota.SentBatches()) != 2 || len(fixture.quota.Batches()) != 1 {
		t.Errorf("sent %d, applied %d", len(fixture.quota.SentBatches()), len(fixture.quota.Batches()))
	}
}

// FS-44: a kill loses the open window and nothing a window before it sent.
func TestQuotaUsageBatcherKillLosesAtMostTheOpenWindow(t *testing.T) {
	fixture := newQuotaBatcherFixture(t)
	networkId := connect.NewId()
	mustAdd(t, fixture.batcher.AddTransfer(networkId, sidecar.QuotaMeterEvs, 100))
	fixture.step(t, fixture.at(60*time.Second), fixture.at(120*time.Second))
	mustAdd(t, fixture.batcher.AddTransfer(networkId, sidecar.QuotaMeterEvs, 7))
	fixture.batcher.Close()
	if got := fixture.quota.TransferUsed(networkId, sidecar.QuotaMeterEvs); got != 100 {
		t.Errorf("transfer %d", got)
	}
	if err := fixture.batcher.AddTransfer(networkId, sidecar.QuotaMeterEvs, 1); !errors.Is(err, sidecar.ErrQuotaUsageBatcherClosed) {
		t.Errorf("an add after the kill: %v", err)
	}
	if err := fixture.batcher.Drain(t.Context()); !errors.Is(err, sidecar.ErrQuotaUsageBatcherClosed) {
		t.Errorf("a drain after the kill: %v", err)
	}
}

// A zero network, an unknown meter or a negative count is the caller's bug and counts nothing, and a
// batcher needs a Quota, a producer and positive timeouts.
func TestQuotaUsageBatcherRefusesCallerBugs(t *testing.T) {
	fixture := newQuotaBatcherFixture(t)
	networkId := connect.NewId()
	if err := fixture.batcher.AddTransfer(connect.Id{}, sidecar.QuotaMeterEvs, 1); err == nil {
		t.Error("took a zero network")
	}
	if err := fixture.batcher.AddTransfer(networkId, "storage", 1); err == nil {
		t.Error("took no meter")
	}
	if err := fixture.batcher.AddTransfer(networkId, sidecar.QuotaMeterEvs, -1); err == nil {
		t.Error("took a negative transfer")
	}
	if err := fixture.batcher.AddStoredDelta(connect.Id{}, 1); err == nil {
		t.Error("took a zero network's delta")
	}
	mustAdd(t, fixture.batcher.AddTransfer(networkId, sidecar.QuotaMeterEvs, 0))
	fixture.step(t, fixture.at(60*time.Second), fixture.at(120*time.Second))
	if sent := fixture.quota.SentBatches(); len(sent) != 0 {
		t.Errorf("sent %+v", sent)
	}

	host := &sidecar.ServiceHost{Quota: fixture.quota, Clock: fixture.clock}
	if _, err := sidecar.NewQuotaUsageBatcher(t.Context(), host, "api", nil); err == nil {
		t.Error("made a batcher for no producer")
	}
	if _, err := sidecar.NewQuotaUsageBatcher(t.Context(), &sidecar.ServiceHost{Clock: fixture.clock}, sidecar.QuotaProducerEvs, nil); err == nil {
		t.Error("made a batcher with no Quota")
	}
	settings := sidecar.DefaultQuotaUsageBatcherSettings()
	settings.WindowTimeout = 0
	if _, err := sidecar.NewQuotaUsageBatcher(t.Context(), host, sidecar.QuotaProducerEvs, settings); err == nil {
		t.Error("made a batcher with no window")
	}
}

// A window past QuotaUsageBatchMaxEventCount goes as several batches, each under its own id, so api
// refuses none as oversize.
func TestQuotaUsageBatcherSplitsAWindowPastTheBatchLimit(t *testing.T) {
	fixture := newQuotaBatcherFixture(t)
	networkIds := []connect.Id{}
	for range sidecar.QuotaUsageBatchMaxEventCount + 5 {
		networkId := connect.NewId()
		networkIds = append(networkIds, networkId)
		mustAdd(t, fixture.batcher.AddTransfer(networkId, sidecar.QuotaMeterEvs, 1))
	}
	fixture.step(t, fixture.at(60*time.Second), fixture.at(120*time.Second))
	batches := fixture.quota.Batches()
	if len(batches) != 2 || len(batches[0].Events) != sidecar.QuotaUsageBatchMaxEventCount || len(batches[1].Events) != 5 || batches[0].BatchId == batches[1].BatchId {
		t.Fatalf("%d batches", len(batches))
	}
	for _, networkId := range networkIds {
		if got := fixture.quota.TransferUsed(networkId, sidecar.QuotaMeterEvs); got != 1 {
			t.Fatalf("transfer %d", got)
		}
	}
}
