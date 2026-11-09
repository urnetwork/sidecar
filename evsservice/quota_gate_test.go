package evsservice

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A gate on a fake Quota whose reads the test drives.
type quotaGateFixture struct {
	t     *testing.T
	ctx   context.Context
	clock *sidecartest.FakeClock
	host  *sidecartest.FakeHost
	gate  *QuotaGate
}

func newQuotaGateFixture(t *testing.T) *quotaGateFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(governorTestStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	gate, err := newQuotaGate(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	return &quotaGateFixture{t: t, ctx: ctx, clock: clock, host: host, gate: gate}
}

// The network over its storage limit, exactly at it, as api's list says, read by the gate.
func (self *quotaGateFixture) atLimit(networkId connect.Id) *sidecar.QuotaRefusal {
	refusal := &sidecar.QuotaRefusal{LimitKey: "storage", Limit: 1000, Used: 1000, Upgrade: true}
	self.host.Quota.SetStorageRefusal(networkId, refusal)
	self.gate.refresh(self.ctx)
	return refusal
}

// The network spent, read by the gate.
func (self *quotaGateFixture) spent(networkId connect.Id) *sidecar.QuotaRefusal {
	refusal := &sidecar.QuotaRefusal{LimitKey: "transfer", Limit: 0, Used: 0, Upgrade: true}
	self.host.Quota.SetSpentRefusal(networkId, refusal)
	self.gate.refresh(self.ctx)
	return refusal
}

// Every push kind of FS-47's gate clauses, with whether it passes at the limit and while spent.
func quotaGateKinds(networkId connect.Id) []struct {
	name   string
	push   *QuotaPush
	passes bool
} {
	flag := func(flags ...protocol.EvsPushFlag) uint32 {
		var all uint32
		for _, f := range flags {
			all |= uint32(f)
		}
		return all
	}
	return []struct {
		name   string
		push   *QuotaPush
		passes bool
	}{
		{name: "a 1-byte ordinary push", push: &QuotaPush{NetworkId: networkId, InlineRecordCount: 1}, passes: false},
		{name: "an ordinary push with a segment", push: &QuotaPush{NetworkId: networkId, NewSegmentCount: 1}, passes: false},
		{name: "a push adding no payload", push: &QuotaPush{NetworkId: networkId}, passes: true},
		{name: "DELETE", push: &QuotaPush{NetworkId: networkId, Flags: flag(protocol.EvsPushFlag_EVS_PUSH_DELETE)}, passes: true},
		{name: "CONSUME", push: &QuotaPush{NetworkId: networkId, Flags: flag(protocol.EvsPushFlag_EVS_PUSH_CONSUME)}, passes: true},
		{name: "ERASE", push: &QuotaPush{NetworkId: networkId, Flags: flag(protocol.EvsPushFlag_EVS_PUSH_ERASE)}, passes: true},
		{name: "BASE", push: &QuotaPush{NetworkId: networkId, Flags: flag(protocol.EvsPushFlag_EVS_PUSH_BASE)}, passes: true},
		{name: "PATH_EPOCH", push: &QuotaPush{NetworkId: networkId, Flags: flag(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH)}, passes: true},
		{name: "a maintenance push naming a new segment", push: &QuotaPush{NetworkId: networkId, Flags: flag(protocol.EvsPushFlag_EVS_PUSH_BASE), NewSegmentCount: 1}, passes: false},
		{name: "a CUT and its staged record", push: &QuotaPush{NetworkId: networkId, Flags: flag(protocol.EvsPushFlag_EVS_PUSH_CUT), InlineRecordCount: 1}, passes: true},
		{name: "a CLOSURE with its payload", push: &QuotaPush{NetworkId: networkId, Flags: flag(protocol.EvsPushFlag_EVS_PUSH_CLOSURE), NewSegmentCount: 2, InlineRecordCount: 1}, passes: true},
		{name: "a DROP uploading nothing", push: &QuotaPush{NetworkId: networkId, Flags: flag(protocol.EvsPushFlag_EVS_PUSH_DROP), InlineRecordCount: 1}, passes: true},
		{name: "a DROP needing an upload", push: &QuotaPush{NetworkId: networkId, Flags: flag(protocol.EvsPushFlag_EVS_PUSH_DROP), NewSegmentCount: 1}, passes: false},
		{name: "a repo's deletion or restore", push: &QuotaPush{NetworkId: networkId, Lifecycle: true}, passes: true},
		{name: "a config push", push: &QuotaPush{NetworkId: networkId, Authorization: true, InlineRecordCount: 3}, passes: true},
	}
}

// Under the limit and not spent, every kind passes; another network's state is not this one's.
func TestQuotaGateAcceptsEverythingUnderTheLimit(t *testing.T) {
	fixture := newQuotaGateFixture(t)
	networkId := connect.NewId()
	fixture.atLimit(connect.NewId())
	for _, kind := range quotaGateKinds(networkId) {
		if refusal := fixture.gate.CheckPush(kind.push); refusal != nil {
			t.Errorf("%s refused under the limit: %+v", kind.name, refusal)
		}
	}
	if refusal := fixture.gate.CheckUpload(networkId, false); refusal != nil {
		t.Errorf("an upload refused under the limit: %+v", refusal)
	}
}

// FS-47's gate clauses at the exact storage limit and while spent: maintenance, config and re-seed pass, and
// new payload is refused with the list's own refusal.
func TestQuotaGateRefusesNewPayloadAtTheLimitAndSpent(t *testing.T) {
	for _, state := range []string{"at the limit", "spent"} {
		fixture := newQuotaGateFixture(t)
		networkId := connect.NewId()
		var want *sidecar.QuotaRefusal
		if state == "spent" {
			want = fixture.spent(networkId)
		} else {
			want = fixture.atLimit(networkId)
		}
		for _, kind := range quotaGateKinds(networkId) {
			refusal := fixture.gate.CheckPush(kind.push)
			switch {
			case kind.passes && refusal != nil:
				t.Errorf("%s: %s refused", state, kind.name)
			case !kind.passes && refusal == nil:
				t.Errorf("%s: %s passed", state, kind.name)
			case !kind.passes && *refusal != *want:
				t.Errorf("%s: %s refused with %+v, want %+v", state, kind.name, refusal, want)
			}
		}
		if refusal := fixture.gate.CheckUpload(networkId, false); refusal == nil || *refusal != *want {
			t.Errorf("%s: a plain segment upload got %+v", state, refusal)
		}
		if refusal := fixture.gate.CheckUpload(networkId, true); refusal != nil {
			t.Errorf("%s: a re-seed upload refused", state)
		}
	}
}

// The list is reread every interval: a network over its limit is refused at the next read, and one back under
// passes at the next; a read that fails keeps the last list.
func TestQuotaGateFollowsTheListOnItsInterval(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(governorTestStart())
	faults := sidecartest.NewFaultQueue()
	host := sidecartest.NewFakeHost(ctx, clock, faults, nil, nil)
	gate, err := NewQuotaGate(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	networkId := connect.NewId()
	interval := DefaultQuotaGateSettings().OverLimitInterval
	// each read ends by arming the next interval's timer, which says the read is done
	awaitRead := func() {
		t.Helper()
		next := clock.Now().Add(interval)
		for {
			pending, added := clock.WatchTimers()
			if slices.ContainsFunc(pending, func(at time.Time) bool { return at.Equal(next) }) {
				return
			}
			select {
			case <-added:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	awaitRead()
	upload := &QuotaPush{NetworkId: networkId, NewSegmentCount: 1}
	if gate.CheckPush(upload) != nil {
		t.Fatal("refused before the list said so")
	}
	host.Quota.SetStorageRefusal(networkId, &sidecar.QuotaRefusal{LimitKey: "storage", Limit: 1, Used: 1})
	if gate.CheckPush(upload) != nil {
		t.Fatal("refused before the gate read the list")
	}
	clock.Advance(interval)
	awaitRead()
	if gate.CheckPush(upload) == nil {
		t.Fatal("admitted an interval after the list named the network")
	}
	// api unreachable: the last list stands
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.OverLimit", Result: sidecartest.FailBeforeApply, Repeat: -1}); err != nil {
		t.Fatal(err)
	}
	host.Quota.SetStorageRefusal(networkId, nil)
	clock.Advance(interval)
	awaitRead()
	if gate.CheckPush(upload) == nil {
		t.Fatal("a failed read dropped the last list")
	}
}

// FS-47's closure clauses: at the limit a closure upload over 1,088 KiB is refused as any upload is; within it,
// an eraser's own 60 a minute and its daily allowance answer 429 with retry_after_ms, the allowance's at the next
// 00:00 UTC; no eraser spends another's; below the limit nothing is counted.
func TestQuotaGateChargesClosureUploadsAtTheLimit(t *testing.T) {
	fixture := newQuotaGateFixture(t)
	networkId := connect.NewId()
	eraser := connect.NewId()
	other := connect.NewId()
	fixture.host.Quota.SetLimits(networkId, &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{
		"evs_closure_uploads_per_s":   4,
		"evs_closure_uploads_per_min": 60,
		// a day's allowance set below the floor reads the floor
		"evs_closure_bytes_per_day": 1,
		"evs_closure_bytes_floor":   4 * 1024 * 1024,
	}})
	charge := func(sidecarId connect.Id, byteCount int64) *sidecar.QuotaRefusal {
		t.Helper()
		refusal, err := fixture.gate.ChargeClosure(fixture.ctx, networkId, sidecarId, byteCount, connect.NewId())
		if err != nil {
			t.Fatal(err)
		}
		return refusal
	}
	// below the limit: ordinary payload, nothing counted
	for range 10 {
		if refusal := charge(eraser, 1088*1024); refusal != nil {
			t.Fatalf("below the limit: %+v", refusal)
		}
	}
	limit := fixture.atLimit(networkId)
	if refusal := charge(eraser, 1088*1024+1); refusal == nil || *refusal != *limit {
		t.Fatalf("an oversized closure upload got %+v", refusal)
	}
	// the floor of 4 MiB holds 3 full re-keys and change; the 4th full one passes the day's allowance
	for i := range 3 {
		if refusal := charge(eraser, 1088*1024); refusal != nil {
			t.Fatalf("closure upload %d refused: %+v", i, refusal)
		}
		fixture.clock.Advance(time.Second)
	}
	refusal := charge(eraser, 1088*1024)
	if refusal == nil || refusal.LimitKey != "evs_closure_bytes_per_day" {
		t.Fatalf("past the allowance: %+v", refusal)
	}
	now := fixture.clock.Now().UTC()
	midnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	if wait := time.Duration(refusal.RetryAfterMs) * time.Millisecond; wait < midnight.Sub(now)-time.Second || midnight.Sub(now) < wait {
		t.Fatalf("retry after %s, want the next 00:00 UTC, %s away", wait, midnight.Sub(now))
	}
	// another eraser's allowance is its own
	if refusal := charge(other, 1088*1024); refusal != nil {
		t.Fatalf("the other eraser was refused: %+v", refusal)
	}
	// a CLOSURE push's inline records spend the same allowance
	inline, err := fixture.gate.ChargeClosureRecords(fixture.ctx, networkId, eraser, 1024*1024, connect.NewId())
	if err != nil || inline == nil {
		t.Fatalf("records past the allowance: %+v %v", inline, err)
	}
}

// An eraser's own 60 uploads a minute, at the limit: the 61st within the minute is refused 429.
func TestQuotaGateHoldsAnErasersSixtyAMinute(t *testing.T) {
	fixture := newQuotaGateFixture(t)
	networkId := connect.NewId()
	eraser := connect.NewId()
	fixture.host.Quota.SetLimits(networkId, &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{
		"evs_closure_uploads_per_s":   100,
		"evs_closure_uploads_per_min": 60,
		"evs_closure_bytes_per_day":   1024 * 1024 * 1024,
		"evs_closure_bytes_floor":     4 * 1024 * 1024,
	}})
	fixture.atLimit(networkId)
	start := fixture.clock.Now()
	refusedAt := -1
	for i := range 61 {
		refusal, err := fixture.gate.ChargeClosure(fixture.ctx, networkId, eraser, 1024, connect.NewId())
		if err != nil {
			t.Fatal(err)
		}
		if refusal != nil {
			refusedAt = i
			if refusal.RetryAfterMs == 0 {
				t.Fatalf("a rate refusal with no retry_after_ms: %+v", refusal)
			}
			break
		}
		fixture.clock.Advance(500 * time.Millisecond)
	}
	if refusedAt != 60 || time.Minute <= fixture.clock.Now().Sub(start) {
		t.Fatalf("refused at upload %d", refusedAt)
	}
}
