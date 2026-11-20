//go:build sidecar_testhooks

package fault

import (
	"strings"
	"testing"
)

// The rules a run of one seed takes, its traces written nowhere.
func clauseOneSeedSettingsForTest(tier Tier) *RuleSettings {
	settings := DefaultRuleSettings()
	settings.Tier = tier
	settings.Seeds = MergeSeeds()[:1]
	settings.WriteTraces = false
	return settings
}

// A forged case's clause runs its twin on T3, which must succeed, under "<row> <clause> twin", as server's evshost
// runs FS-10's rollback clause, and its forged schedule beside the twin on T2. The tier the rules name picks the twin,
// so the run here is on T2's fakes with the rules naming T3. A clause asked for on a tier it is not registered on reads
// missing and runs nothing.
func TestARegisteredClauseOfAForgedCaseRunsItsTwinOnT3(t *testing.T) {
	registration := LookupClause("FS-10", "rollback refused")
	if registration == nil {
		t.Fatal("FS-10's rollback clause is not registered")
	}
	onT3 := CheckRegisteredClause(t.Context(), registration, clauseOneSeedSettingsForTest(TierT3))
	if onT3.Failed() || onT3.Fixed == nil || onT3.Fixed.Id != "FS-10 rollback refused twin" || onT3.Twin != nil {
		t.Fatalf("%s on T3 ran %s", registration, onT3)
	}
	onT2 := CheckRegisteredClause(t.Context(), registration, clauseOneSeedSettingsForTest(TierT2))
	if onT2.Failed() || onT2.Fixed == nil || onT2.Fixed.Id != "FS-10 rollback refused" || onT2.Twin == nil || onT2.Twin.Id != "FS-10 rollback refused twin" {
		t.Fatalf("%s on T2 ran %s", registration, onT2)
	}

	t2Alone := LookupClause("FS-9", "unfolded listing")
	missing := CheckRegisteredClause(t.Context(), t2Alone, clauseOneSeedSettingsForTest(TierT3))
	if missing.Fixed != nil || len(missing.Errors) != 1 || !strings.Contains(missing.Errors[0].Error(), "is not registered on T3: missing") {
		t.Fatalf("%s on T3: %s", t2Alone, missing)
	}
}
