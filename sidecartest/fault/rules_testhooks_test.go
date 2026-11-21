//go:build sidecar_testhooks

package fault

// The explorer's short form (QD-1151) on the build the gate runs, with the hooks linked, where a barrier in sidecar's
// own code reaches the driver: the cases the gate's rules item names are the ones a registered schedule of which
// leaves a seed nothing to order.

import (
	"slices"
	"testing"
)

// The gate's rules item names each case some registered T2 schedule of which, the case's own, its twin or a clause of
// it, leaves a seed nothing to order, and no other case. Each schedule runs fixed once here, built as CheckRow and
// CheckClause build it, and exploreOrderChoice reads its run as the explorer does. A schedule that fails here leaves
// its seeds something to order, as it does for the explorer, so it names no case: FS-77's and FS-109's, which pass only
// in a search heap process of their own, pass barriers before their heap checks refuse.
func TestTheRulesItemNamesEveryCaseWithABarrierFreeScheduleAndNoOther(t *testing.T) {
	catalog := DefaultCatalog()
	settings := DefaultRuleSettings()
	foundNames := []string{}
	found := func(testCase *Case, builder Builder) {
		var schedule *Schedule
		result := runBuilt(t.Context(), builder, settings.Net, func(built *Schedule) { schedule = built })
		if exploreOrderChoice(schedule, result) == "" {
			t.Logf("%s: %s", result.Id, ExploreOneOrderText)
			if !slices.Contains(foundNames, testCase.String()) {
				foundNames = append(foundNames, testCase.String())
			}
		}
		if schedule == nil || schedule.Twin == nil {
			return
		}
		var twin *Schedule
		twinResult := runBuilt(t.Context(), twinBuilder(schedule), settings.Net, func(built *Schedule) { twin = built })
		if exploreOrderChoice(twin, twinResult) == "" {
			t.Logf("%s: %s", twinResult.Id, ExploreOneOrderText)
			if !slices.Contains(foundNames, testCase.String()) {
				foundNames = append(foundNames, testCase.String())
			}
		}
	}
	scheduleCount := 0
	for _, registration := range Registered() {
		testCase := catalog.Case(registration.Row, registration.Case)
		if testCase == nil || !slices.Contains(registration.Tiers, TierT2) {
			continue
		}
		scheduleCount += 1
		found(testCase, func(net *Net) *Schedule {
			schedule := registration.Build(net)
			schedule.Id = testCase.String()
			schedule.Forged = testCase.Forged()
			return schedule
		})
	}
	for _, registration := range RegisteredClauses() {
		testCase := catalog.Case(registration.Row, registration.Case)
		if testCase == nil || !slices.Contains(registration.Tiers, TierT2) {
			continue
		}
		scheduleCount += 1
		found(testCase, func(net *Net) *Schedule {
			schedule := registration.Build(net)
			schedule.Id = registration.Row + " " + registration.Name
			schedule.Forged = schedule.Forged || testCase.Row.Forged
			return schedule
		})
	}
	t.Logf("%d registered T2 schedules run fixed; the cases with one taking the short form: %v", scheduleCount, foundNames)

	for _, name := range foundNames {
		if !slices.Contains(exploreOneOrderCases(), name) {
			t.Errorf("a registered schedule of %s leaves a seed nothing to order, and the gate's rules item leaves %s out (exploreOneOrderCases)", name, name)
		}
	}
	for _, name := range exploreOneOrderCases() {
		if !slices.Contains(foundNames, name) {
			t.Errorf("the gate's rules item names %s, and every registered schedule of it leaves a seed something to order (exploreOneOrderCases)", name)
		}
	}
}
