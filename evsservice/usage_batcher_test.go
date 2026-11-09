package evsservice

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// evs's producer on a fake Quota, waiting at its first window's end.
type usageBatcherFixture struct {
	t       *testing.T
	clock   *sidecartest.FakeClock
	faults  *sidecartest.FaultQueue
	quota   *sidecartest.FakeQuota
	batcher *UsageBatcher
	start   time.Time
}

func newUsageBatcherFixture(t *testing.T) *usageBatcherFixture {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	quota := sidecartest.NewFakeQuota(clock, faults, nil)
	host := &sidecar.ServiceHost{Quota: quota, Metrics: sidecartest.NewFakeMetrics(nil), Clock: clock}
	batcher, err := NewUsageBatcher(t.Context(), host, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(batcher.Close)
	fixture := &usageBatcherFixture{t: t, clock: clock, faults: faults, quota: quota, batcher: batcher, start: clock.Now()}
	fixture.awaitTimerAt(fixture.start.Add(60 * time.Second))
	return fixture
}

// Returns once a timer is pending at at: the batcher arms its next wait only once a round has ended.
func (self *usageBatcherFixture) awaitTimerAt(at time.Time) {
	self.t.Helper()
	for {
		pending, added := self.clock.WatchTimers()
		if slices.ContainsFunc(pending, func(pendingAt time.Time) bool { return pendingAt.Equal(at) }) {
			return
		}
		select {
		case <-added:
		case <-self.t.Context().Done():
			self.t.Fatal(self.t.Context().Err())
		}
	}
}

// Moves to the round at at, and returns once it has ended in the wait at next.
func (self *usageBatcherFixture) step(at time.Duration, next time.Duration) {
	self.t.Helper()
	self.clock.AdvanceTo(self.start.Add(at))
	self.awaitTimerAt(self.start.Add(next))
}

// FS-44's evs producer: an upload's size moves the repo network's stored count, a read's bytes debit the
// caller's network, on meter evs, under producer evs.
func TestUsageBatcherSendsStoredToTheRepoAndTransferToTheCaller(t *testing.T) {
	fixture := newUsageBatcherFixture(t)
	repoNetworkId := connect.NewId()
	callerNetworkId := connect.NewId()
	if err := fixture.batcher.AddStored(repoNetworkId, 4096); err != nil {
		t.Fatal(err)
	}
	if err := fixture.batcher.AddTransfer(callerNetworkId, 1000); err != nil {
		t.Fatal(err)
	}
	fixture.step(60*time.Second, 120*time.Second)
	batches := fixture.quota.Batches()
	if len(batches) != 1 || batches[0].Producer != sidecar.QuotaProducerEvs {
		t.Fatalf("batches %+v", batches)
	}
	if got := fixture.quota.StoredDelta(repoNetworkId); got != 4096 {
		t.Errorf("repo network's stored delta %d", got)
	}
	if got := fixture.quota.TransferUsed(callerNetworkId, sidecar.QuotaMeterEvs); got != 1000 {
		t.Errorf("caller's transfer %d", got)
	}
	if got := fixture.quota.StoredDelta(callerNetworkId); got != 0 {
		t.Errorf("caller's stored delta %d", got)
	}
}

// FI-13 (a): a batch whose answer is lost is retried under its id and debits once.
func TestUsageBatcherRetriedAfterALostResponseDebitsOnce(t *testing.T) {
	fixture := newUsageBatcherFixture(t)
	if _, err := fixture.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	callerNetworkId := connect.NewId()
	if err := fixture.batcher.AddTransfer(callerNetworkId, 700); err != nil {
		t.Fatal(err)
	}
	fixture.step(60*time.Second, 65*time.Second)
	fixture.step(65*time.Second, 120*time.Second)
	sent := fixture.quota.SentBatches()
	if len(sent) != 2 || sent[0].BatchId != sent[1].BatchId {
		t.Fatalf("sent %+v", sent)
	}
	if got := fixture.quota.TransferUsed(callerNetworkId, sidecar.QuotaMeterEvs); got != 700 {
		t.Fatalf("debited %d, want 700 once", got)
	}
}

// Drain sends the open window at once, losing nothing.
func TestUsageBatcherDrainLosesNothing(t *testing.T) {
	fixture := newUsageBatcherFixture(t)
	repoNetworkId := connect.NewId()
	for range 10 {
		if err := fixture.batcher.AddStored(repoNetworkId, 100); err != nil {
			t.Fatal(err)
		}
	}
	if err := fixture.batcher.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := fixture.quota.StoredDelta(repoNetworkId); got != 1000 {
		t.Fatalf("stored delta %d after a drain", got)
	}
}
