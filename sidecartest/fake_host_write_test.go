// QD-1155: each host fake declares the calls that write (fake_host.go's hostWrite), and the fault queue counts those
// alone among the host's writes, which a WritesOnly plan names by place and §22.8's unknown rule loses one at a time.

package sidecartest

import (
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// Every call of the Quota, Tasks and Push fakes reaches the queue as a write or a read, as its fake declares: what
// fault.EveryWrite's dry run counts.
func TestHostFakesDeclareWhichCallsWrite(t *testing.T) {
	host, _, faults := newHostFixture(t)
	ctx := t.Context()
	networkId := connect.NewId()
	host.Quota.SetBalance(networkId, 1024*1024*1024)
	clientId := connect.NewId()
	sidecarId := connect.NewId()
	host.Push.BindSidecar(sidecarId, clientId)
	var first sidecar.QuotaLease
	var shared sidecar.QuotaLease
	for _, c := range []struct {
		name string
		// whether the queue sees the call at all, and whether as a write
		reaches bool
		write   bool
		call    func() error
	}{
		{name: "quota.Limits", reaches: true, call: func() error {
			_, err := host.Quota.Limits(ctx, networkId)
			return err
		}},
		{name: "quota.OverLimit", reaches: true, call: func() error {
			_, err := host.Quota.OverLimit(ctx)
			return err
		}},
		{name: "quota.CountRate", reaches: true, write: true, call: func() error {
			_, err := host.Quota.CountRate(ctx, networkId, map[string]int64{sidecar.QuotaRateKeyDrop: 1}, connect.NewId())
			return err
		}},
		{name: "quota.ReportUsage", reaches: true, write: true, call: func() error {
			return host.Quota.ReportUsage(ctx, &sidecar.UsageBatch{
				BatchId:  connect.NewId(),
				Producer: sidecar.QuotaProducerEvs,
				Events:   []*sidecar.UsageEvent{{NetworkId: networkId, Meter: sidecar.QuotaMeterEvs, TransferByteCount: 1}},
			})
		}},
		// the first Lease draws
		{name: "quota.Lease drawing", reaches: true, write: true, call: func() error {
			var err error
			first, _, err = host.Quota.Lease(ctx, networkId, sidecar.QuotaMeterTls)
			return err
		}},
		// one on the process's lease while it holds bytes gives a handle with no I/O
		{name: "quota.Lease sharing", reaches: true, call: func() error {
			var err error
			shared, _, err = host.Quota.Lease(ctx, networkId, sidecar.QuotaMeterTls)
			return err
		}},
		// a handle that is not the lease's last closes with no I/O; the last settles the lease
		{name: "quotalease.Close not the last", call: func() error {
			shared.Close()
			return nil
		}},
		{name: "quotalease.Close settling", reaches: true, write: true, call: func() error {
			first.Close()
			return nil
		}},
		{name: "tasks.Schedule", reaches: true, write: true, call: func() error {
			return host.Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "job", OnceKey: "once"})
		}},
		{name: "push.Hint", reaches: true, write: true, call: func() error {
			return host.Push.Hint(ctx, []connect.Id{clientId}, &sidecar.ClientHint{Topic: "core"})
		}},
		{name: "push.HintSidecars", reaches: true, write: true, call: func() error {
			return host.Push.HintSidecars(ctx, []connect.Id{sidecarId}, &sidecar.ClientHint{Topic: "core"})
		}},
	} {
		opCount, writeCount := len(faults.OpResults(FaultOpHost)), len(faults.WriteResults(FaultOpHost))
		if err := c.call(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		wantOps, wantWrites := opCount, writeCount
		if c.reaches {
			wantOps += 1
		}
		if c.write {
			wantWrites += 1
		}
		if got := len(faults.OpResults(FaultOpHost)); got != wantOps {
			t.Errorf("%s: %d host calls counted, want %d", c.name, got, wantOps)
		}
		if got := len(faults.WriteResults(FaultOpHost)); got != wantWrites {
			t.Errorf("%s: %d host writes counted, want %d", c.name, got, wantWrites)
		}
	}
	if got := host.Quota.Balances(networkId)[0].ReservedByteCount; got != 0 {
		t.Errorf("both handles closed with %d still reserved", got)
	}
}

// A WritesOnly host plan counts the host's writes alone toward its Nth, whatever reads come between.
func TestAWritesOnlyHostPlanCountsWritesAlone(t *testing.T) {
	host, _, faults := newHostFixture(t)
	ctx := t.Context()
	clientId := connect.NewId()
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, Nth: 2, Result: FailBeforeApply, WritesOnly: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Quota.Limits(ctx, connect.NewId()); err != nil {
		t.Fatalf("a read took the plan: %v", err)
	}
	if err := host.Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "job", OnceKey: "once"}); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	if _, err := host.Quota.OverLimit(ctx); err != nil {
		t.Fatalf("a read took the plan: %v", err)
	}
	if err := host.Push.Hint(ctx, []connect.Id{clientId}, &sidecar.ClientHint{Topic: "core"}); err == nil {
		t.Error("the second write did not take the plan")
	}
	if len(host.Push.Hints(clientId)) != 0 {
		t.Error("a hint failed before it applied reached the client")
	}
	if unfired := faults.Unfired(); len(unfired) != 0 {
		t.Errorf("unfired %v", unfired)
	}
}

// The hint limit is FakePushSettings' format's, the protocol's 256 B by default: a body past it is refused before any
// plan, and a test may set another.
func TestFakePushRefusesAHintPastItsFormat(t *testing.T) {
	faults := NewFaultQueue()
	push := NewFakePush(faults)
	clientId := connect.NewId()
	limit := DefaultFakePushSettings().Format.MaxHintByteCount
	if err := push.Hint(t.Context(), []connect.Id{clientId}, &sidecar.ClientHint{Topic: "core", Body: make([]byte, limit)}); err != nil {
		t.Errorf("a body at the limit: %v", err)
	}
	if err := push.Hint(t.Context(), []connect.Id{clientId}, &sidecar.ClientHint{Topic: "core", Body: make([]byte, limit+1)}); err == nil {
		t.Error("a body past the limit was sent")
	}
	if got := len(faults.OpResults(FaultOpHost)); got != 1 {
		t.Errorf("%d host calls counted: a refused body reached the queue", got)
	}
	settings := DefaultFakePushSettings()
	settings.Format.MaxHintByteCount = 8
	small := NewFakePushWithSettings(NewFaultQueue(), settings)
	if err := small.Hint(t.Context(), []connect.Id{clientId}, &sidecar.ClientHint{Topic: "core", Body: make([]byte, 9)}); err == nil {
		t.Error("a body past a set limit was sent")
	}
}
