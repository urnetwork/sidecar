//go:build !ios_extension && !sidecar_http && !js

package sidecar

// CACL-M12-05: the budgets that cap a call (DESIGN-COMPUTE §16.4, §16.5; D-CACL-6, IC-11): BudgetSettings' defaults as
// §16.5 and CO-35 and CO-41 set them, the budgets a call naming an agent, an untagged device's own call and a tagged
// sidecar's spend, a policy budget replacing the default for its subject and period, a kind-21 raise lifting one budget
// until its expiry, a local model's call touching none, and a grant clamped to its agent's default. Synthetic values.

import (
	"context"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A dollar amount to the cent in nano-USD.
func testBudgetUsd(dollars float64) uint64 {
	return uint64(math.Round(dollars*100)) * 10_000_000
}

// The budgets as name:period:cap, for comparing.
func testBudgetsShown(budgets []*ComputeBudget) []string {
	shown := []string{}
	for _, budget := range budgets {
		counted := ""
		if !budget.DeviceCounts {
			counted = " (broker)"
		}
		shown = append(shown, budget.Name+":"+budget.Period.String()+":"+approvalComputeUsd(budget.CapNanoUsd)+counted)
	}
	slices.Sort(shown)
	return shown
}

// §16.5's defaults, as CO-35 and CO-41 set them.
func TestBudgetDefaultsMatchDesign(t *testing.T) {
	settings := DefaultBudgetSettings()
	if settings.AgentDayNanoUsd != testBudgetUsd(5) || settings.AgentMonthNanoUsd != testBudgetUsd(50) ||
		settings.DeviceDayNanoUsd != testBudgetUsd(20) || settings.DeviceMonthNanoUsd != testBudgetUsd(200) ||
		settings.DeviceCeilingDayNanoUsd != testBudgetUsd(50) {
		t.Errorf("the defaults: %+v", settings)
	}
	if DefaultSidecarSettings().Budget.DeviceCeilingDayNanoUsd != settings.DeviceCeilingDayNanoUsd {
		t.Error("the Sidecar's settings do not carry the defaults")
	}
}

// A call naming an agent spends the agent's day and month and the device's ceiling; an untagged device's own call its
// device budget and its ceiling; a tagged sidecar's its own as a tagged subject, and no ceiling.
func TestBudgetsForAgentCall(t *testing.T) {
	now := time.Date(2026, time.November, 27, 12, 0, 0, 0, time.UTC)
	device, agent := NewId(), NewId()
	for name, item := range map[string]struct {
		call *ComputeBudgetCall
		want []string
	}{
		"an agent's call": {call: &ComputeBudgetCall{SidecarId: device, MemberId: NewId(), AgentId: &agent},
			want: []string{"agent:day:$5.00", "agent:month:$50.00", "ceiling:day:$50.00"}},
		"the device's own call": {call: &ComputeBudgetCall{SidecarId: device, MemberId: NewId()},
			want: []string{"ceiling:day:$50.00", "device:day:$20.00", "device:month:$200.00"}},
		"a tagged sidecar's call": {call: &ComputeBudgetCall{SidecarId: device, Tagged: true},
			want: []string{"tagged:day:$5.00", "tagged:month:$50.00"}},
		"a tagged sidecar's agent's call": {call: &ComputeBudgetCall{SidecarId: device, Tagged: true, AgentId: &agent},
			want: []string{"agent:day:$5.00", "agent:month:$50.00", "tagged:day:$5.00", "tagged:month:$50.00"}},
	} {
		budgets := ComputeBudgetsFor(item.call, nil, now)
		if shown := testBudgetsShown(budgets); !slices.Equal(shown, item.want) {
			t.Errorf("%s: %v", name, shown)
		}
		for _, budget := range budgets {
			switch budget.Name {
			case ComputeBudgetNameAgent:
				if budget.SubjectId != agent {
					t.Errorf("%s: the agent's budget counts under %s", name, budget.SubjectId)
				}
			default:
				// the ceiling and the device's own count by the calls' sidecar, never the agent id (D-CACL-6)
				if budget.SubjectId != device {
					t.Errorf("%s: %s counts under %s", name, budget.Name, budget.SubjectId)
				}
			}
		}
	}
}

// A policy budget for the same subject and period replaces the default, narrowing or raising it; one per member or per
// network adds a budget the broker alone counts; a run's budget rides beside them.
func TestBudgetPolicyReplacesDefault(t *testing.T) {
	now := time.Date(2026, time.November, 27, 12, 0, 0, 0, time.UTC)
	device, agent, run := NewId(), NewId(), NewId()
	call := &ComputeBudgetCall{
		SidecarId: device, MemberId: NewId(), AgentId: &agent,
		Policy: []*protocol.AclComputeBudgetRow{
			{Per: uint32(AclComputeBudgetPerAgent), DayNanoUsd: testBudgetUsd(2)},
			{Per: uint32(AclComputeBudgetPerSubject), DayNanoUsd: testBudgetUsd(80), MonthNanoUsd: testBudgetUsd(400)},
			{Per: uint32(AclComputeBudgetPerMember), MonthNanoUsd: testBudgetUsd(100)},
			{Per: uint32(AclComputeBudgetPerNetwork), DayNanoUsd: testBudgetUsd(500)},
		},
		Run: &ComputeBudgetRun{Id: run, CapNanoUsd: testBudgetUsd(1.5)},
	}
	want := []string{
		"agent:day:$2.00", "agent:month:$50.00", "member:month:$100.00 (broker)", "network:day:$500.00 (broker)",
		"run:run:$1.50", "subject:day:$80.00", "subject:month:$400.00",
	}
	if shown := testBudgetsShown(ComputeBudgetsFor(call, nil, now)); !slices.Equal(shown, want) {
		t.Errorf("the budgets: %v", shown)
	}
	// an untagged device's own call: the policy per subject stands in for its device budget and its ceiling
	own := &ComputeBudgetCall{SidecarId: device, MemberId: NewId(), Policy: call.Policy[1:2]}
	if shown := testBudgetsShown(ComputeBudgetsFor(own, nil, now)); !slices.Equal(shown, []string{"subject:day:$80.00", "subject:month:$400.00"}) {
		t.Errorf("the device's own call: %v", shown)
	}
	// a tagged sidecar's per subject replaces its tagged budget
	tagged := &ComputeBudgetCall{SidecarId: device, Tagged: true, Policy: []*protocol.AclComputeBudgetRow{{Per: uint32(AclComputeBudgetPerSubject), MonthNanoUsd: testBudgetUsd(10)}}}
	if shown := testBudgetsShown(ComputeBudgetsFor(tagged, nil, now)); !slices.Equal(shown, []string{"tagged:day:$5.00", "tagged:month:$10.00"}) {
		t.Errorf("a tagged sidecar's call: %v", shown)
	}
}

// An approved kind-21 raise lifts the one budget it names for its period until its expiry, and no other.
func TestBudgetRaiseLiftsUntilExpiry(t *testing.T) {
	now := time.Date(2026, time.November, 27, 12, 0, 0, 0, time.UTC)
	device, agent := NewId(), NewId()
	call := &ComputeBudgetCall{SidecarId: device, MemberId: NewId(), AgentId: &agent, Raises: []*ComputeBudgetRaise{
		{Name: ComputeBudgetNameAgent, SubjectId: agent, Period: ComputeBudgetPeriodDay, CapNanoUsd: testBudgetUsd(20), NotAfter: now.Add(time.Hour)},
	}}
	budgets := ComputeBudgetsFor(call, nil, now)
	if shown := testBudgetsShown(budgets); !slices.Equal(shown, []string{"agent:day:$20.00", "agent:month:$50.00", "ceiling:day:$50.00"}) {
		t.Errorf("under the raise: %v", shown)
	}
	if index := slices.IndexFunc(budgets, func(budget *ComputeBudget) bool { return budget.RaisedUntil.Equal(now.Add(time.Hour)) }); index < 0 {
		t.Error("the raised budget does not say until when")
	}
	if shown := testBudgetsShown(ComputeBudgetsFor(call, nil, now.Add(time.Hour))); !slices.Equal(shown, []string{"agent:day:$5.00", "agent:month:$50.00", "ceiling:day:$50.00"}) {
		t.Errorf("at its expiry: %v", shown)
	}
	// a raise naming another agent lifts nothing here
	call.Raises[0].SubjectId = NewId()
	if shown := testBudgetsShown(ComputeBudgetsFor(call, nil, now)); shown[0] != "agent:day:$5.00" {
		t.Errorf("another agent's raise: %v", shown)
	}
}

// A local model's call touches no budget (CO-9): none applies, and the router's gate admits it reading nothing.
func TestLocalCallTouchesNoBudget(t *testing.T) {
	agent := NewId()
	if budgets := ComputeBudgetsFor(&ComputeBudgetCall{SidecarId: NewId(), AgentId: &agent, Local: true}, nil, time.Now()); len(budgets) != 0 {
		t.Errorf("a local call's budgets: %v", testBudgetsShown(budgets))
	}
	gate := &sidecarBudgetGate{sidecar: nil}
	call := &InferCall{Request: &InferRequest{Model: "local-gemma-4-e4b-off"}, Entry: &InferCatalogEntry{Provider: "local", Kind: InferCatalogKindLocal}}
	if err := gate.Admit(context.Background(), call); err != nil {
		t.Errorf("a local call at the gate: %v", err)
	}
	for _, name := range []string{"cacl-budgets", "cacl-compute-block"} {
		if !slices.ContainsFunc(inferCheckSourcesRegistrations, func(registration *inferCheckSourcesRegistration) bool { return registration.name == name }) {
			t.Errorf("%s is not among the router's sources", name)
		}
	}
	if computeRegisteredBudgetLeftSource() == nil {
		t.Error("compute_balance's budget view is not registered")
	}
}

// A grant's or a Harness agent's budget is held to its agent's default unless a raise in force lifts it (§8.6, IC-11).
func TestBudgetClampGrant(t *testing.T) {
	now := time.Date(2026, time.November, 27, 12, 0, 0, 0, time.UTC)
	raise := &ComputeBudgetRaise{Period: ComputeBudgetPeriodDay, CapNanoUsd: testBudgetUsd(30), NotAfter: now.Add(time.Hour)}
	for _, item := range []struct {
		requested uint64
		period    ComputeBudgetPeriod
		raise     *ComputeBudgetRaise
		at        time.Time
		want      uint64
	}{
		{requested: testBudgetUsd(100), period: ComputeBudgetPeriodDay, at: now, want: testBudgetUsd(5)},
		{requested: testBudgetUsd(3), period: ComputeBudgetPeriodDay, at: now, want: testBudgetUsd(3)},
		{requested: testBudgetUsd(100), period: ComputeBudgetPeriodMonth, at: now, want: testBudgetUsd(50)},
		{requested: testBudgetUsd(100), period: ComputeBudgetPeriodRun, at: now, want: testBudgetUsd(5)},
		{requested: testBudgetUsd(100), period: ComputeBudgetPeriodDay, raise: raise, at: now, want: testBudgetUsd(30)},
		{requested: testBudgetUsd(100), period: ComputeBudgetPeriodDay, raise: raise, at: now.Add(time.Hour), want: testBudgetUsd(5)},
		{requested: testBudgetUsd(100), period: ComputeBudgetPeriodMonth, raise: raise, at: now, want: testBudgetUsd(50)},
	} {
		if got := ComputeBudgetClampGrant(nil, item.requested, item.period, item.raise, item.at); got != item.want {
			t.Errorf("%d for a %s: %d, want %d", item.requested, item.period, got, item.want)
		}
	}
}

// A model's worst case is its window at the input price and its most output at the output price, rounded up.
func TestBudgetWorstCase(t *testing.T) {
	entry := &InferCatalogEntry{ContextWindow: 128_000, MaxOutput: 8_000, Remote: &InferRemoteModel{
		InputNanoUsdPerMillion: 600_000_000, OutputNanoUsdPerMillion: 2_400_000_001}}
	worstCase, ok := computeBudgetWorstCase(entry)
	// 128,000 × $0.60 + 8,000 × $2.400000001 per million: $0.0768 + $0.019200000008, up to the nano-USD
	if !ok || worstCase != 96_000_001 {
		t.Errorf("the worst case %d, %v", worstCase, ok)
	}
	if _, ok := computeBudgetWorstCase(&InferCatalogEntry{ContextWindow: 1 << 62, Remote: &InferRemoteModel{InputNanoUsdPerMillion: 1 << 40}}); ok {
		t.Error("a worst case past 64 bits read")
	}
	if _, ok := computeBudgetWorstCase(&InferCatalogEntry{ContextWindow: 10}); ok {
		t.Error("an unpriced model read a worst case")
	}
}
