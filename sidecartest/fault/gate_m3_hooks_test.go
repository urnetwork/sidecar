//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FI-7's and FI-8's item at M3's exit (TEST-M3-02): the build in which FS-26's, FS-27's, FS-28's and FS-115's T2
// builders register, as fs26_test.go and fs115_test.go do under the hooks.

import (
	"slices"
	"testing"
)

// FI-7 and FI-8 answer through their oracles, bound by MCP-M3-24 and MCP-M3-27, and every M3 row whose checks name
// one names it in its registered schedule's Check, its twin's too, so Run checks it after every step and at the end
// (TestChecksRunAfterEveryStepAndAtTheEnd).
func TestGateM3EffectsAndAttributionRunAfterEveryStep(t *testing.T) {
	for _, n := range []int{7, 8} {
		if !invariantBound(n) {
			t.Errorf("FI-%d has no oracle bound", n)
		}
	}
	catalog := DefaultCatalog()
	rows := gateEffectsAndAttributionRows(catalog)
	if len(rows) == 0 {
		t.Fatal("no M3 row checks FI-7 or FI-8")
	}
	checked := []string{}
	for _, testCase := range catalog.GateCases(gateM3OutGate) {
		checks, ok := rows[testCase.String()]
		if !ok || !slices.Contains(testCase.Tiers(), TierT2) {
			continue
		}
		registration := Lookup(testCase.Row.Id, testCase.Name, TierT2)
		if registration == nil {
			t.Errorf("%s checks %v and has no T2 builder registered", testCase, checks)
			continue
		}
		schedule, err := gateBuildSchedule(t.Context(), registration.Build, DefaultGateWrittenSettings())
		if err != nil {
			t.Errorf("%s's builder: %v", testCase, err)
			continue
		}
		schedules := []*Schedule{schedule}
		if schedule.Twin != nil {
			twin, err := gateBuildSchedule(t.Context(), twinBuilder(schedule), DefaultGateWrittenSettings())
			if err != nil {
				t.Errorf("%s's twin: %v", testCase, err)
				continue
			}
			schedules = append(schedules, twin)
		}
		for _, built := range schedules {
			named := []string{}
			for _, invariant := range built.Check {
				named = append(named, invariant.Id())
			}
			for _, check := range checks {
				if !slices.Contains(named, check) {
					t.Errorf("%s's schedule %q checks %v, not %s", testCase, built.Id, named, check)
				}
			}
			checked = append(checked, built.Id)
		}
	}
	t.Logf("FI-7 and FI-8 named in %d schedules: %v", len(checked), checked)
	if len(checked) < len(rows) {
		t.Errorf("%d schedules checked for %d rows", len(checked), len(rows))
	}
}
