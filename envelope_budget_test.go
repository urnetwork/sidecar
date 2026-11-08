// The budget's counters: each stops at its cap, all stop at the memory budget, and two budgets share
// nothing (connect/CODESTYLE.md, budgets).

package sidecar

import (
	"sync"
	"testing"
)

// Caps small enough to read, inside a budget that holds them all.
func testBudgetSettings() *SidecarProtocolSettings {
	settings := DefaultSidecarProtocolSettings()
	settings.ReassemblyProcessByteCount = 100
	settings.IdempotencyProcessByteCount = 200
	settings.StreamProcessCreditByteCount = 300
	return settings
}

func TestEachCounterStopsAtItsCap(t *testing.T) {
	cases := []struct {
		name    string
		reserve func(budget *SubprotocolBudget, byteCount int64) bool
		release func(budget *SubprotocolBudget, byteCount int64)
		held    func(usage subprotocolBudgetUsage) int64
		cap     int64
	}{
		{
			name:    "reassembly",
			reserve: (*SubprotocolBudget).reserveReassembly,
			release: (*SubprotocolBudget).releaseReassembly,
			held:    func(usage subprotocolBudgetUsage) int64 { return usage.reassemblyByteCount },
			cap:     100,
		},
		{
			name:    "idempotency",
			reserve: (*SubprotocolBudget).reserveIdempotency,
			release: (*SubprotocolBudget).releaseIdempotency,
			held:    func(usage subprotocolBudgetUsage) int64 { return usage.idempotencyByteCount },
			cap:     200,
		},
		{
			name:    "credit",
			reserve: (*SubprotocolBudget).reserveCredit,
			release: (*SubprotocolBudget).releaseCredit,
			held:    func(usage subprotocolBudgetUsage) int64 { return usage.creditByteCount },
			cap:     300,
		},
	}
	for _, c := range cases {
		budget := NewSubprotocolBudget(testBudgetSettings(), 1000)
		if !c.reserve(budget, c.cap) {
			t.Errorf("%s: refused its whole cap", c.name)
		}
		if c.reserve(budget, 1) {
			t.Errorf("%s: took a byte past its cap", c.name)
		}
		if held := c.held(budget.currentUsage()); held != c.cap {
			t.Errorf("%s: holds %d after a refusal", c.name, held)
		}
		c.release(budget, 1)
		if !c.reserve(budget, 1) {
			t.Errorf("%s: refused what was just given back", c.name)
		}
		c.release(budget, c.cap)
		if held := c.held(budget.currentUsage()); held != 0 {
			t.Errorf("%s: holds %d after releasing it all", c.name, held)
		}
	}
}

// Three caps of 600 B together do not fit 350 B, so what one counter holds comes out of the others.
func TestAllCountersStopAtTheMemoryBudget(t *testing.T) {
	budget := NewSubprotocolBudget(testBudgetSettings(), 350)
	if !budget.reserveCredit(300) {
		t.Fatal("credit refused")
	}
	if !budget.reserveIdempotency(50) {
		t.Fatal("idempotency refused at the budget's last byte")
	}
	if budget.reserveReassembly(1) {
		t.Fatal("reassembly took a byte past the budget, under its own cap")
	}
	budget.releaseCredit(1)
	if !budget.reserveReassembly(1) {
		t.Fatal("reassembly refused a byte the budget has")
	}
}

func TestNoBudgetRefusesEverything(t *testing.T) {
	budget := NewSubprotocolBudget(testBudgetSettings(), 0)
	if budget.reserveReassembly(1) || budget.reserveIdempotency(1) || budget.reserveCredit(1) {
		t.Fatal("a budget of nothing gave a byte")
	}
}

// A second owner in one process is another instance, so filling one leaves the other whole.
func TestBudgetsShareNothing(t *testing.T) {
	settings := testBudgetSettings()
	first := NewSubprotocolBudget(settings, 1000)
	second := NewSubprotocolBudget(settings, 1000)
	if !first.reserveReassembly(100) {
		t.Fatal("the first refused")
	}
	if !second.reserveReassembly(100) {
		t.Fatal("the first's reservation reached the second")
	}
}

// A release no reservation matches must not leave room nobody paid for.
func TestReleaseStopsAtZero(t *testing.T) {
	budget := NewSubprotocolBudget(testBudgetSettings(), 1000)
	budget.releaseReassembly(50)
	if !budget.reserveReassembly(100) {
		t.Fatal("refused the whole cap")
	}
	if budget.reserveReassembly(1) {
		t.Fatal("an unmatched release widened the cap")
	}
}

// However goroutines interleave, reservations never pass the cap and every one comes back.
func TestConcurrentReservationsHoldTheCap(t *testing.T) {
	budget := NewSubprotocolBudget(testBudgetSettings(), 1000)
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 1000 {
				if budget.reserveReassembly(30) {
					if held := budget.currentUsage().reassemblyByteCount; 100 < held {
						t.Errorf("holds %d", held)
					}
					budget.releaseReassembly(30)
				}
			}
		}()
	}
	workers.Wait()
	if held := budget.currentUsage().reassemblyByteCount; held != 0 {
		t.Errorf("holds %d at the end", held)
	}
}
