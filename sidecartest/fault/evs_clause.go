// A row's clause beyond its registered case, under every rule §22.8 gives the row (EVS1-M2-40, EVS1-M2-41): the
// catalog names one case for most evs rows, so the main clause registers and each other clause is an exported
// Builder of its own, which a T2 test runs here and server's T3 test through sidecart3's rule settings. A clause is
// named "<row> <clause>", so its explorer's traces are its own and a replay never takes another clause's order.
//
// The rules are CheckRow's: the fixed schedule, its twin when it refuses something, the explorer's seeds over both,
// every write's lost response when the row is on the unknown list, and a replay of every committed trace.

package fault

import (
	"context"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Runs builder as clause of rowId under every rule the row takes. settings nil takes the defaults.
func CheckClause(ctx context.Context, rowId string, clause string, builder Builder, settings *RuleSettings) *RowReport {
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
	named := func(net *Net) *Schedule {
		schedule := builder(net)
		schedule.Id = id
		schedule.Forged = schedule.Forged || row.Forged
		return schedule
	}
	traces, err := Traces(settings.SeedsDirectory, id)
	if err != nil {
		report.Errors = append(report.Errors, err)
	}
	twinTraces, err := Traces(settings.SeedsDirectory, id+" twin")
	if err != nil {
		report.Errors = append(report.Errors, err)
	}

	var fixed *Schedule
	func() {
		net := sidecartest.NewNet(ctx, settings.Net)
		defer net.Close()
		fixed = named(net)
		report.Fixed = Run(ctx, fixed, net)
	}()
	report.fail(report.Fixed)
	var twin Builder
	if fixed.Twin != nil {
		twin = twinBuilder(fixed)
		report.Twin = RunTwin(ctx, fixed, settings.Net)
		report.fail(report.Twin)
	}
	report.Explore = Explore(ctx, named, settings)
	report.Failures = append(report.Failures, report.Explore.Failures...)
	report.Errors = append(report.Errors, report.Explore.TraceErrors...)
	if twin != nil {
		report.ExploreTwin = Explore(ctx, twin, settings)
		report.Failures = append(report.Failures, report.ExploreTwin.Failures...)
		report.Errors = append(report.Errors, report.ExploreTwin.TraceErrors...)
	}
	if row.Unknown {
		failures, lostWrites := EveryWrite(ctx, named, settings.Net)
		report.Failures = append(report.Failures, failures...)
		report.LostWrites = lostWrites
	}
	for _, trace := range traces {
		result := runBuilt(ctx, Replay(named, trace), settings.Net, nil)
		report.Replays = append(report.Replays, result)
		report.fail(result)
	}
	if twin != nil {
		for _, trace := range twinTraces {
			result := runBuilt(ctx, Replay(twin, trace), settings.Net, nil)
			report.Replays = append(report.Replays, result)
			report.fail(result)
		}
	}
	return report
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
