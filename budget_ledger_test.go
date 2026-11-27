//go:build !ios_extension && !sidecar_http && !js

package sidecar

// CACL-M12-05: the device's budget ledger (DESIGN-COMPUTE §16.4; D-CACL-6, IC-6): a hold checked against each budget's
// room and held durably, a settlement and a release, eleven agents refused past the device's $50 ceiling in a UTC day,
// tallies that survive a restart, UTC day and month rollovers under a fake clock, and a ledger that does not read
// refusing rather than starting from nothing. Synthetic values only.

import (
	"errors"
	"testing"
	"time"
)

// A ledger over a fresh network store, with its clock, at 2026-11-27 23:00 UTC.
func newTestBudgetLedger(t *testing.T) (*BudgetLedger, SidecarStore, *recordTestClock) {
	t.Helper()
	instance, _, _ := enrolledInstance(t)
	store, err := instance.Store(&testNetworkId).Directory(budgetComponentName, budgetComponentName)
	if err != nil {
		t.Fatal(err)
	}
	clock := &recordTestClock{at: time.Date(2026, time.November, 27, 23, 0, 0, 0, time.UTC)}
	ledger, err := NewBudgetLedger(&BudgetLedgerArgs{Store: store, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return ledger, store, clock
}

// An untagged device's call naming agent: the agent's budgets and the device's ceiling.
func testBudgetAgentCall(device Id, agent Id, now time.Time) []*ComputeBudget {
	return ComputeBudgetsFor(&ComputeBudgetCall{SidecarId: device, MemberId: device, AgentId: &agent}, nil, now)
}

// A hold takes room in every budget the device counts, a settlement keeps what was charged, a release gives the rest
// back; a budget whose room is below the worst case refuses, naming the budget and period.
func TestBudgetLedgerHoldsAndSettles(t *testing.T) {
	ledger, _, clock := newTestBudgetLedger(t)
	device, agent := NewId(), NewId()
	budgets := testBudgetAgentCall(device, agent, clock.Now())
	call := NewId()
	if err := ledger.Hold(call, budgets, testBudgetUsd(3)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Hold(call, budgets, testBudgetUsd(1)); !errors.Is(err, ErrBudgetHoldExists) {
		t.Errorf("a second hold of one call: %v", err)
	}
	agentDay := budgets[0]
	if agentDay.Name != ComputeBudgetNameAgent || agentDay.Period != ComputeBudgetPeriodDay || ledger.Room(agentDay) != testBudgetUsd(2) {
		t.Fatalf("the agent's day after the hold: %d", ledger.Room(agentDay))
	}
	var exceeded *ComputeBudgetExceededError
	if err := ledger.Check(budgets, testBudgetUsd(2.01)); !errors.As(err, &exceeded) || exceeded.Budget != ComputeBudgetNameAgent ||
		exceeded.Period != ComputeBudgetPeriodDay || exceeded.RoomNanoUsd != testBudgetUsd(2) || !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("a check past the room: %v", err)
	}
	if err := ledger.Settle(call, testBudgetUsd(1.25)); err != nil {
		t.Fatal(err)
	}
	if ledger.Room(agentDay) != testBudgetUsd(3.75) {
		t.Errorf("the agent's day after the settlement: %d", ledger.Room(agentDay))
	}
	// a settlement repeated settles nothing more
	if err := ledger.Settle(call, testBudgetUsd(1.25)); err != nil || ledger.Room(agentDay) != testBudgetUsd(3.75) {
		t.Errorf("a repeated settlement: %v, %d", err, ledger.Room(agentDay))
	}
	failed := NewId()
	if err := ledger.Hold(failed, budgets, testBudgetUsd(3)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Release(failed); err != nil || ledger.Room(agentDay) != testBudgetUsd(3.75) {
		t.Errorf("a release: %v, %d", err, ledger.Room(agentDay))
	}
	// a member's budget across devices and the network's are the broker's: never checked or held here
	broker := &ComputeBudget{Name: ComputeBudgetNameNetwork, Period: ComputeBudgetPeriodDay, CapNanoUsd: 1}
	if err := ledger.Check([]*ComputeBudget{broker}, testBudgetUsd(100)); err != nil || ledger.Room(broker) != 1 {
		t.Errorf("the broker's budget at the device: %v", err)
	}
}

// Eleven agents at $4.90 each fit their own $5 a day, and the device's ceiling refuses the eleventh past $50 in a UTC
// day, counted by the calls' sidecar whatever agent id each names (D-CACL-6, Q-CACL-4).
func TestBudgetDeviceCeilingAcrossAgents(t *testing.T) {
	ledger, _, clock := newTestBudgetLedger(t)
	device := NewId()
	for i := range 11 {
		budgets := testBudgetAgentCall(device, NewId(), clock.Now())
		err := ledger.Hold(NewId(), budgets, testBudgetUsd(4.90))
		if i < 10 && err != nil {
			t.Fatalf("agent %d: %v", i, err)
		}
		if i == 10 {
			var exceeded *ComputeBudgetExceededError
			if !errors.As(err, &exceeded) || exceeded.Budget != ComputeBudgetNameCeiling || exceeded.Period != ComputeBudgetPeriodDay ||
				exceeded.RoomNanoUsd != testBudgetUsd(1) {
				t.Errorf("the eleventh agent: %v", err)
			}
		}
	}
	// another device's ceiling is its own
	if err := ledger.Hold(NewId(), testBudgetAgentCall(NewId(), NewId(), clock.Now()), testBudgetUsd(4.90)); err != nil {
		t.Errorf("another device: %v", err)
	}
}

// Holds and settlements outlive the ledger: a new one over the same store reads the same room, and settles a hold the
// old one took.
func TestBudgetLedgerSurvivesRestart(t *testing.T) {
	ledger, store, clock := newTestBudgetLedger(t)
	device, agent := NewId(), NewId()
	budgets := testBudgetAgentCall(device, agent, clock.Now())
	settled, open := NewId(), NewId()
	if err := ledger.Hold(settled, budgets, testBudgetUsd(2)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Settle(settled, testBudgetUsd(1)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Hold(open, budgets, testBudgetUsd(2)); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewBudgetLedger(&BudgetLedgerArgs{Store: store, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Room(budgets[0]) != testBudgetUsd(2) {
		t.Fatalf("after a restart: %d", restarted.Room(budgets[0]))
	}
	if err := restarted.Settle(open, testBudgetUsd(0.5)); err != nil || restarted.Room(budgets[0]) != testBudgetUsd(3.5) {
		t.Errorf("settling the old hold: %v, %d", err, restarted.Room(budgets[0]))
	}
}

// A UTC day's tally ends at midnight UTC and a month's at the month's end; tallies past the retention go.
func TestBudgetLedgerUtcRollover(t *testing.T) {
	ledger, _, clock := newTestBudgetLedger(t)
	clock.at = time.Date(2026, time.November, 30, 23, 59, 0, 0, time.UTC)
	device, agent := NewId(), NewId()
	call := NewId()
	if err := ledger.Hold(call, testBudgetAgentCall(device, agent, clock.Now()), testBudgetUsd(4)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Settle(call, testBudgetUsd(4)); err != nil {
		t.Fatal(err)
	}
	day := func() *ComputeBudget { return testBudgetAgentCall(device, agent, clock.Now())[0] }
	month := func() *ComputeBudget { return testBudgetAgentCall(device, agent, clock.Now())[1] }
	if ledger.Room(day()) != testBudgetUsd(1) || ledger.Room(month()) != testBudgetUsd(46) {
		t.Fatalf("before midnight: %d, %d", ledger.Room(day()), ledger.Room(month()))
	}
	// one minute on: a new UTC day and a new UTC month
	clock.advance(time.Minute)
	if ledger.Room(day()) != testBudgetUsd(5) || ledger.Room(month()) != testBudgetUsd(50) {
		t.Errorf("after midnight on the 1st: %d, %d", ledger.Room(day()), ledger.Room(month()))
	}
	// within a month, a new day keeps the month's tally
	clock.at = time.Date(2026, time.December, 1, 10, 0, 0, 0, time.UTC)
	second := NewId()
	if err := ledger.Hold(second, testBudgetAgentCall(device, agent, clock.Now()), testBudgetUsd(2)); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Settle(second, testBudgetUsd(2)); err != nil {
		t.Fatal(err)
	}
	clock.advance(24 * time.Hour)
	if ledger.Room(day()) != testBudgetUsd(5) || ledger.Room(month()) != testBudgetUsd(48) {
		t.Errorf("the next day: %d, %d", ledger.Room(day()), ledger.Room(month()))
	}
	// past the retention, an ended window's tally is pruned at the next change
	clock.advance(DefaultBudgetSettings().LedgerRetention + 32*24*time.Hour)
	if err := ledger.Hold(NewId(), testBudgetAgentCall(device, agent, clock.Now()), 1); err != nil {
		t.Fatal(err)
	}
	ledger.stateLock.Lock()
	tallies := len(ledger.state.Tallies)
	ledger.stateLock.Unlock()
	if tallies != 3 {
		t.Errorf("%d tallies kept past the retention", tallies)
	}
}

// A ledger whose file does not read refuses, so no restart resets a tally to nothing.
func TestBudgetLedgerUnreadableRefuses(t *testing.T) {
	_, store, clock := newTestBudgetLedger(t)
	writer, err := store.Create(budgetLedgerFileName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(`{"version": 9}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if _, err := NewBudgetLedger(&BudgetLedgerArgs{Store: store, Clock: clock}); !errors.Is(err, ErrBudgetLedgerUnreadable) {
		t.Errorf("an unreadable ledger: %v", err)
	}
}
