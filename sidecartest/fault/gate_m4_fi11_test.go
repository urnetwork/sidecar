//go:build !js && !sidecar_http

package fault

// FI-11's fixture schedule (gate_m4.go) on T2's Net: each case reads as its name says, at the step it names, which
// server's sidecart3 then holds T3's Net to (TEST-M4-04).

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFi11FixtureReadsEachCaseOnT2(t *testing.T) {
	run := func(fixtureCase Fi11FixtureCase) *Result {
		net := sidecartest.NewNet(t.Context(), nil)
		defer net.Close()
		return Run(t.Context(), Fi11BackendSchedule(fixtureCase, nil)(net), net)
	}
	if result := run(Fi11FixtureTwin); result.Err != nil {
		t.Fatalf("the twin: %s", result)
	}
	for fixtureCase, text := range map[Fi11FixtureCase]string{
		Fi11FixtureBeforeCheck:     "bytes before its audience check",
		Fi11FixtureAfterRevocation: "after its flow's revocation",
		Fi11FixtureDeadPath:        "dead path",
	} {
		result := run(fixtureCase)
		if result.Err == nil || result.FailedStep != Fi11FixtureFailedStep(fixtureCase) || !strings.Contains(result.Err.Error(), text) {
			t.Errorf("%s: %s", fixtureCase, result)
		}
		if len(result.Violations) == 0 || result.Violations[0].Invariant != "FI-11" {
			t.Errorf("%s: violations %v", fixtureCase, result.Violations)
		}
	}
	// the fixture names FI-11 and both tiers, so T3 runs this schedule and no copy of it
	schedule := Fi11BackendSchedule(Fi11FixtureTwin, nil)(nil)
	if len(schedule.Check) != 1 || len(schedule.Tiers) != 2 {
		t.Errorf("the fixture checks %v on %v", schedule.Check, schedule.Tiers)
	}
}
