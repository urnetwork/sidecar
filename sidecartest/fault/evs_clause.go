// A row's clause beyond its registered case, under every rule §22.8 gives the row (EVS1-M2-40, EVS1-M2-41): the
// catalog names one case for most evs rows, so the main clause registers and each other clause is an exported
// Builder of its own, which a T2 test runs here and server's T3 test through sidecart3's rule settings. A clause is
// named "<row> <clause>", so its explorer's traces are its own and a replay never takes another clause's order.
//
// The rules are CheckRow's: the fixed schedule, its twin when it refuses something, the explorer's seeds over both,
// in the short form where the fixed run passed no barrier, the schedule has no Background step and nothing else left a
// seed anything to order (QD-1151; explore.go), every write's lost response when the row is on the unknown list, and a
// replay of every committed trace. A registered clause that takes the short form on the gate's build fails unless the
// gate's rules item names its case, as a registered case does (rules.go).

package fault

import (
	"context"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Runs builder as clause of rowId under every rule the row takes. settings nil takes the defaults.
func CheckClause(ctx context.Context, rowId string, clause string, builder Builder, settings *RuleSettings) *RowReport {
	return checkClause(ctx, rowId, clause, builder, settings, nil)
}

// CheckClause, child naming how a child process rebuilds builder, for a registered clause on T2, or nil.
func checkClause(ctx context.Context, rowId string, clause string, builder Builder, settings *RuleSettings, child *ruleChildName) *RowReport {
	if settings == nil {
		settings = DefaultRuleSettings()
	}
	row := DefaultCatalog().Row(rowId)
	id := rowId + " " + clause
	report := &RowReport{Case: &Case{Name: clause, Row: &Row{Id: rowId}}, Tier: settings.Tier}
	if row == nil {
		report.Errors = append(report.Errors, fmt.Errorf("%s: no such row in §22.8", id))
		return report
	}
	report.Case = &Case{Name: clause, Row: row}
	if err := checkRuleSettings(settings); err != nil {
		report.Errors = append(report.Errors, err)
		return report
	}
	subject := &ruleSubject{id: id, builder: clauseBuilder(row, id, builder), unknown: row.Unknown, child: child}
	// a clause registered under this name, which the gate shows with its case, on the build the gate runs
	if registration := LookupClause(rowId, clause); sidecartest.HooksLinked && registration != nil {
		subject.oneOrderCase = DefaultCatalog().Case(rowId, registration.Case)
	}
	report.checkRules(ctx, subject, settings)
	return report
}

// builder's schedule as the clause of row that id names, forged where the row is.
func clauseBuilder(row *Row, id string, builder Builder) Builder {
	return func(net *Net) *Schedule {
		schedule := builder(net)
		schedule.Id = id
		schedule.Forged = schedule.Forged || row.Forged
		return schedule
	}
}

// CheckClause on T2, failing t with each failure and logging what ran. settings nil takes the defaults.
func RunClause(t testing.TB, rowId string, clause string, builder Builder, settings *RuleSettings) *RowReport {
	t.Helper()
	report := CheckClause(t.Context(), rowId, clause, builder, settings)
	t.Log(report.String())
	for _, failure := range report.Failures {
		t.Errorf("%s", failure)
	}
	for _, err := range report.Errors {
		t.Errorf("%v", err)
	}
	return report
}
