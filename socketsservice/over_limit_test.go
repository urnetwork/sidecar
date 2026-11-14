// The over-limit poll (SOCK-M5-07; DESIGN-DETAILS 13.2.3, SOCK.md reading 9) on the fake host's Quota and fake
// clock: only a spent network stops new streams, a failed read keeps the last answer and counts itself stale, and
// before the first answer every network reads as spent and the gate is not ready.

package socketsservice_test

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A gate on a fake host of its own over source, the poll at its defaults, and the host's faults.
func testOverLimitGate(t *testing.T, source sidecar.AclGateSource) (*socketsservice.SocketProjectionGate, *sidecartest.FakeHost, context.Context, *sidecartest.FaultQueue) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	faults := sidecartest.NewFaultQueue()
	host := sidecartest.NewFakeHost(ctx, nil, faults, nil, nil)
	gate, err := socketsservice.NewSocketProjectionGate(ctx, host.ServiceHost(), source, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	return gate, host, ctx, faults
}

// Spent is the spent set alone: a network over its storage limit with balance left is never spent, and a network
// that recovers reads unspent at the next read.
func TestOverLimitMarksSpentAndIgnoresStorageOnly(t *testing.T) {
	spentNetworkId, storageNetworkId, otherNetworkId := testSocketId(), testSocketId(), testSocketId()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	host := sidecartest.NewFakeHost(ctx, nil, nil, nil, nil)
	host.Quota.SetSpentRefusal(spentNetworkId, &sidecar.QuotaRefusal{LimitKey: "transfer_balance"})
	host.Quota.SetStorageRefusal(storageNetworkId, &sidecar.QuotaRefusal{LimitKey: "storage"})
	gate, err := socketsservice.NewSocketProjectionGate(ctx, host.ServiceHost(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err := gate.AwaitOverLimitReads(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if !gate.Spent(spentNetworkId) || gate.Spent(storageNetworkId) || gate.Spent(otherNetworkId) {
		t.Fatalf("spent %v, storage-only %v, other %v", gate.Spent(spentNetworkId), gate.Spent(storageNetworkId), gate.Spent(otherNetworkId))
	}
	host.Quota.SetSpentRefusal(spentNetworkId, nil)
	host.Clock.(*sidecartest.FakeClock).Advance(socketsservice.DefaultSocketGateSettings().OverLimitInterval)
	if err := gate.AwaitOverLimitReads(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if gate.Spent(spentNetworkId) {
		t.Fatal("a network that recovered stays spent")
	}
}

// A read that fails keeps the last answer, counts urnetwork_sockets_over_limit_stale_total and shows the answer's
// age; the next answer clears the age.
func TestOverLimitKeepsTheLastAnswerWhenAReadFails(t *testing.T) {
	gate, host, ctx, faults := testOverLimitGate(t, nil)
	clock := host.Clock.(*sidecartest.FakeClock)
	if err := gate.AwaitOverLimitReads(ctx, 1); err != nil {
		t.Fatal(err)
	}
	spentNetworkId := testSocketId()
	host.Quota.SetSpentRefusal(spentNetworkId, &sidecar.QuotaRefusal{LimitKey: "transfer_balance"})
	interval := socketsservice.DefaultSocketGateSettings().OverLimitInterval
	clock.Advance(interval)
	if err := gate.AwaitOverLimitReads(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if !gate.Spent(spentNetworkId) {
		t.Fatal("the spent mark was not read")
	}
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.OverLimit", Result: sidecartest.FailBeforeApply, Repeat: 1}); err != nil {
		t.Fatal(err)
	}
	host.Quota.SetSpentRefusal(spentNetworkId, nil)
	clock.Advance(interval)
	if err := gate.AwaitOverLimitReads(ctx, 3); err != nil {
		t.Fatal(err)
	}
	clock.Advance(interval)
	if err := gate.AwaitOverLimitReads(ctx, 4); err != nil {
		t.Fatal(err)
	}
	if !gate.Spent(spentNetworkId) {
		t.Fatal("a failed read dropped the last answer")
	}
	if stale := host.Metrics.Value("urnetwork_sockets_over_limit_stale_total"); stale != 2 {
		t.Fatalf("%v stale reads counted", stale)
	}
	if age := host.Metrics.Value("urnetwork_sockets_over_limit_age_seconds"); age != (2 * interval).Seconds() {
		t.Fatalf("the answer's age reads %v", age)
	}
	clock.Advance(interval)
	if err := gate.AwaitOverLimitReads(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if gate.Spent(spentNetworkId) || host.Metrics.Value("urnetwork_sockets_over_limit_age_seconds") != 0 {
		t.Fatal("the answer after the failures did not land")
	}
}

// Before its first answer the gate is not ready and every network is spent, so nothing is signed for anyone; a gate
// with a source and an answer is ready, and one with no source never is.
func TestOverLimitGateIsNotReadyBeforeItsFirstAnswer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	faults := sidecartest.NewFaultQueue()
	host := sidecartest.NewFakeHost(ctx, nil, faults, nil, nil)
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.OverLimit", Result: sidecartest.FailBeforeApply, Repeat: -1}); err != nil {
		t.Fatal(err)
	}
	source := sidecar.NewAclGateDirectSource(nil, host.Blobs, nil)
	gate, err := socketsservice.NewSocketProjectionGate(ctx, host.ServiceHost(), source, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err := gate.AwaitOverLimitReads(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if gate.Ready() || !gate.Spent(testSocketId()) {
		t.Fatal("a gate with no answer is ready or spares a network")
	}

	answered, _, answeredCtx, _ := testOverLimitGate(t, source)
	if err := answered.AwaitOverLimitReads(answeredCtx, 1); err != nil {
		t.Fatal(err)
	}
	if !answered.Ready() || answered.Spent(testSocketId()) {
		t.Fatal("a gate with a source and an answer is not ready")
	}
	sourceless, _, sourcelessCtx, _ := testOverLimitGate(t, nil)
	if err := sourceless.AwaitOverLimitReads(sourcelessCtx, 1); err != nil {
		t.Fatal(err)
	}
	if sourceless.Ready() {
		t.Fatal("a gate with no projection source is ready")
	}
}
