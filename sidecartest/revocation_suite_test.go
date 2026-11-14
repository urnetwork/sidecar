package sidecartest_test

// §22.7's revocation suite on T2 (TEST-M2-12): the device form with every check this binary registers, the composed
// keys and evs checks of sidecartest/scenarios among them, and the suite's own rules: a way no check names fails, a
// check runs in every way it names, a gate-off check runs with evs's gate off or reads open, and a writer sealing to
// an old generation fails. Under sidecar_testhooks every way judges X's held keys; without them the held-key clauses
// read open, never passed.

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/scenarios"
)

// The device form, whole: every way of it named by some check and none failing; under the hooks the composed checks
// judge, and the clauses not composed yet read open in every way, never passed.
func TestRevocationSuiteDeviceForm(t *testing.T) {
	report := sidecartest.RunRevocationSuite(t, sidecartest.RevocationFormDevice, nil)
	if 0 < len(report.Missing) {
		t.Fatalf("ways no check names: %v", report.Missing)
	}
	composed := []string{scenarios.RevocationKeysNextGeneration.Id, scenarios.RevocationEvsNewContent.Id}
	for _, way := range sidecartest.RevocationFormDevice.Ways() {
		results := report.Of(way)
		if !slices.ContainsFunc(results, func(result *sidecartest.RevocationResult) bool {
			return result.CheckId == scenarios.RevocationKeysNextGeneration.Id
		}) {
			t.Errorf("%s: the keys check did not run", way)
		}
		for _, result := range results {
			switch {
			case !slices.Contains(composed, result.CheckId):
				if result.Open == "" || result.Err != nil {
					t.Errorf("%s: a clause not composed did not read open: %s", way, result)
				}
			case sidecartest.HooksLinked && result.Open != "":
				t.Errorf("%s: open under the hooks: %s", way, result)
			case !sidecartest.HooksLinked && result.Err == nil && result.Open == "":
				t.Errorf("%s: passed without the hooks, which hold none of X's keys to judge: %s", way, result)
			}
		}
	}
}

// A writer sealing to the generation it held before X's loss: the suite fails it in every way.
func TestRevocationSuiteFailsAWriterSealingToAnOldGeneration(t *testing.T) {
	settings := &sidecartest.RevocationSuiteSettings{Checks: []*sidecartest.RevocationCheck{scenarios.RevocationKeysCheck(true)}}
	report := (&sidecartest.RevocationSuite{Form: sidecartest.RevocationFormDevice}).Run(t, settings)
	if !report.Failed() {
		t.Fatalf("the mutant passed: %s", report)
	}
	for _, result := range report.Results {
		if result.Err == nil || !strings.Contains(result.Err.Error(), "which X holds") {
			t.Errorf("%s: not failed for sealing to a generation X holds: %s", result.Way, result)
		}
	}
}

// A form whose ways a check leaves unnamed: each such way is missing, and the run fails.
func TestRevocationSuiteFailsAWayWithNoCheck(t *testing.T) {
	check := &sidecartest.RevocationCheck{
		Id: "test/only-read-loss", Area: "TEST", Ways: []sidecartest.RevocationWay{sidecartest.RevocationReadLoss},
		Run: func(run *sidecartest.RevocationRun) (string, error) { return "", nil },
	}
	report := (&sidecartest.RevocationSuite{Form: sidecartest.RevocationFormDevice}).Run(t, &sidecartest.RevocationSuiteSettings{Checks: []*sidecartest.RevocationCheck{check}})
	want := []sidecartest.RevocationWay{sidecartest.RevocationDeviceRevoke, sidecartest.RevocationGrantExpiry, sidecartest.RevocationSuspension, sidecartest.RevocationEphemeralReap}
	if !slices.Equal(report.Missing, want) || !report.Failed() {
		t.Fatalf("missing %v, failed %t: %s", report.Missing, report.Failed(), report)
	}
}

// A check naming two ways runs once in each, on a Net of its own, told the way.
func TestRevocationSuiteRunsACheckInEveryWayItNames(t *testing.T) {
	stateLock := sync.Mutex{}
	ran := []sidecartest.RevocationWay{}
	nets := map[*sidecartest.Net]bool{}
	check := &sidecartest.RevocationCheck{
		Id: "test/two-ways", Area: "TEST",
		Ways: []sidecartest.RevocationWay{sidecartest.RevocationSuspension, sidecartest.RevocationDeviceRevoke, sidecartest.RevocationMemberRemove},
		Run: func(run *sidecartest.RevocationRun) (string, error) {
			stateLock.Lock()
			defer stateLock.Unlock()
			ran = append(ran, run.Way)
			nets[run.Net] = true
			return "", nil
		},
	}
	report := (&sidecartest.RevocationSuite{Form: sidecartest.RevocationFormDevice}).Run(t, &sidecartest.RevocationSuiteSettings{Checks: []*sidecartest.RevocationCheck{check}})
	// the member form's way is not the device form's, so it does not run
	if !slices.Equal(ran, []sidecartest.RevocationWay{sidecartest.RevocationDeviceRevoke, sidecartest.RevocationSuspension}) || len(nets) != 2 {
		t.Fatalf("ran %v on %d Nets: %s", ran, len(nets), report)
	}
}

// A gate-off check runs with evs's gate off under the hooks, its run saying so, and reads open on a leg that cannot
// switch it.
func TestRevocationSuiteRunsAGateOffCheckWithTheGateOff(t *testing.T) {
	gateOff := false
	check := &sidecartest.RevocationCheck{
		Id: "test/gate-off", Area: "TEST", Ways: []sidecartest.RevocationWay{sidecartest.RevocationReadLoss}, GateOff: true,
		Run: func(run *sidecartest.RevocationRun) (string, error) {
			gateOff = run.GateOff
			return "", nil
		},
	}
	report := (&sidecartest.RevocationSuite{Form: sidecartest.RevocationFormDevice}).Run(t, &sidecartest.RevocationSuiteSettings{Checks: []*sidecartest.RevocationCheck{check}})
	results := report.Of(sidecartest.RevocationReadLoss)
	if len(results) != 1 {
		t.Fatalf("%d results for the read loss", len(results))
	}
	if sidecartest.HooksLinked {
		if results[0].Open != "" || !gateOff {
			t.Fatalf("under the hooks the gate-off check did not run with the gate off: %s", results[0])
		}
		return
	}
	if results[0].Open == "" || gateOff {
		t.Fatalf("without the hooks the gate-off check ran: %s", results[0])
	}
}

// A check naming a way the suite does not know panics at registration; so does a second check of one id.
func TestRegisterRevocationCheckRefusesWhatCannotRun(t *testing.T) {
	panics := func(check *sidecartest.RevocationCheck) (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = errors.New("panicked")
			}
		}()
		sidecartest.RegisterRevocationCheck(check)
		return nil
	}
	run := func(run *sidecartest.RevocationRun) (string, error) { return "", nil }
	if panics(&sidecartest.RevocationCheck{Id: "test/unknown-way", Ways: []sidecartest.RevocationWay{"a way of no one's"}, Run: run}) == nil {
		t.Errorf("a check of an unknown way registered")
	}
	if panics(&sidecartest.RevocationCheck{Id: "test/no-way", Run: run}) == nil {
		t.Errorf("a check of no way registered")
	}
	if panics(&sidecartest.RevocationCheck{Id: scenarios.RevocationKeysNextGeneration.Id, Ways: []sidecartest.RevocationWay{sidecartest.RevocationReadLoss}, Run: run}) == nil {
		t.Errorf("a second check of one id registered")
	}
}
