//go:build sidecar_testhooks

// FS-25 on T2 (MCP-M3-24): the registered case under every rule §22.8 gives the row, and each of the row's other
// clauses (fs25.go) under the same rules: the schedule, its twin where it refuses, the explorer's seeds over the
// schedule, and, FS-25 being on the unknown list, every write of the daemon's local state with its response lost. The
// schedules hold callers at the gate's barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs25(t *testing.T) {
	RunRow(t, "FS-25", "", nil)
}

// One clause under the rules CheckRow runs for a registered case, for a builder no catalog case names, its traces
// written nowhere.
func fs25CheckClause(t *testing.T, builder Builder) {
	t.Helper()
	ctx := t.Context()
	settings := DefaultRuleSettings()
	settings.WriteTraces = false
	var fixed *Schedule
	result := runBuilt(ctx, func(net *Net) *Schedule {
		fixed = builder(net)
		return fixed
	}, settings.Net, nil)
	if result.Err != nil {
		t.Errorf("%s", result)
		return
	}
	if fixed.Refuses != "" {
		if fixed.Twin == nil {
			t.Errorf("%s refuses %s and names no twin", fixed.Id, fixed.Refuses)
		} else if twin := RunTwin(ctx, fixed, settings.Net); twin.Err != nil {
			t.Errorf("%s", twin)
		}
	}
	explore := Explore(ctx, builder, settings)
	for _, failure := range explore.Failures {
		t.Errorf("%s", failure)
	}
	for _, err := range explore.TraceErrors {
		t.Errorf("%v", err)
	}
	failures, lostWrites := EveryWrite(ctx, builder, settings.Net)
	for _, failure := range failures {
		t.Errorf("%s", failure)
	}
	t.Logf("%s: %s; %d writes run with their responses lost", fixed.Id, explore, len(lostWrites))
}

// FS-25's other clauses, each under the rules.
func TestFs25Clauses(t *testing.T) {
	for _, builder := range []Builder{
		Fs25RetrySameAction,
		Fs25KillAfterReserve,
		Fs25KillAfterEffect,
		Fs25KillBeforeOutcome,
		Fs25KillThenLateRetry,
		Fs25TwoUsesThreeActions,
		Fs25Cancel,
		Fs25Expiry,
		Fs25ServerGatedExpiry,
		Fs25TaintedAfterFirstUse,
	} {
		fs25CheckClause(t, builder)
	}
}
