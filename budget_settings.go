//go:build !ios_extension && !sidecar_http

// Compute budgets' settings, DESIGN-COMPUTE §16.4's and §16.5's (CACL-M12-05). Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultBudgetSettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created by the compute
// skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultBudgetSettings.
//
// The default budgets are in the root package so the broker (BAL, CSRV) and the device share one default: the broker's
// ledger settings carry the same values (model.ComputeLedgerSettings' Default*NanoUsd), which a test holds to these.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

import (
	"time"
)

// DESIGN-COMPUTE §16.4, budgets: an agent's, a tagged subject's, a device's and its ceiling, which the broker applies
// whatever a document says (§16.5) and the device checks before it asks; and the device's ledger of what it holds and
// settled against them. Amounts in nano-USD (D-BAL-2).
type BudgetSettings struct {
	// Per agent id, and per tagged subject: $5 a UTC day and $50 a UTC month (Q-CACL-2, CO-35).
	AgentDayNanoUsd   uint64
	AgentMonthNanoUsd uint64
	// Per untagged device, for calls naming no agent: $20 a UTC day and $200 a UTC month (Q-CACL-2, CO-35).
	DeviceDayNanoUsd   uint64
	DeviceMonthNanoUsd uint64
	// Per untagged device across all its agents and calls, counted by the calls' sidecar: $50 a UTC day (Q-CACL-4,
	// CO-41).
	DeviceCeilingDayNanoUsd uint64
	// How long the ledger keeps a period's tallies once it has ended: 63 days, past the month that follows it, as the
	// broker keeps its counters (model.ComputeLedgerSettings.BudgetCounterTtl).
	LedgerRetention time.Duration
	// The most holds the ledger keeps open at once: 4,096. A hold past it is refused, so a call that never settles
	// cannot grow the ledger without bound.
	LedgerHoldMaxCount int
	// The most tallies the ledger keeps: 16,384, each a budget in one period.
	LedgerTallyMaxCount int
	// The ledger's file in the sidecar's network store: at most 4 MiB.
	LedgerMaxByteCount int
}

// The component's defaults, the only place one is set.
func DefaultBudgetSettings() *BudgetSettings {
	usd := func(dollars uint64) uint64 {
		return dollars * 1_000_000_000
	}
	return &BudgetSettings{
		AgentDayNanoUsd:         usd(5),
		AgentMonthNanoUsd:       usd(50),
		DeviceDayNanoUsd:        usd(20),
		DeviceMonthNanoUsd:      usd(200),
		DeviceCeilingDayNanoUsd: usd(50),
		LedgerRetention:         63 * 24 * time.Hour,
		LedgerHoldMaxCount:      4096,
		LedgerTallyMaxCount:     16384,
		LedgerMaxByteCount:      4 * 1024 * 1024,
	}
}
