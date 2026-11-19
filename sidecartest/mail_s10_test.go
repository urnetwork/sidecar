//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// S10's receive-only half on T2 (§22.7; MAIL-M8-10): mailworld's builder (s10.go), which server's sidecart3 runs on T3
// (TestScenarioS10ReceiveOnlyOnT3), under RunScenario's T2 defaults, and what the registry reads for S10 at its gate.

package sidecartest_test

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// S10's receive-only half under the harness and guard (RunScenario's T2 defaults).
func TestScenarioS10ReceiveOnlyBurner(t *testing.T) {
	sidecartest.RunScenario(t, mailworld.S10ReceiveOnly(t, nil), nil)
}

// What the default registry reads for S10 at its gate: on T2 and on T3 the receive-only half is registered, to this
// file's test and to server's, and only the replying half reads missing, MAIL-M9-06's.
func TestS10ReceiveOnlyHalfIsRegisteredOnT2AndT3(t *testing.T) {
	registry := sidecartest.DefaultScenarioRegistry()
	missingOf := func(tier string) []string {
		missing := []string{}
		for _, part := range registry.Missing("M9-out", tier) {
			if part.Row.Id == "S10" {
				missing = append(missing, part.Clause)
			}
		}
		return missing
	}
	replying := []string{"first-selector-keeps-blabel-mx-and-a", "last-selector-restores-wildcard-only"}
	for _, tier := range []string{sidecartest.ScenarioTierT2, sidecartest.ScenarioTierT3} {
		if missing := missingOf(tier); !slices.Equal(missing, replying) {
			t.Errorf("S10's missing parts on %s: %q", tier, missing)
		}
	}
	tests := registry.Tests("S10", "burned-label-550-no-dns-change", sidecartest.ScenarioTierT2)
	if len(tests) != 1 || tests[0].Name != "TestScenarioS10ReceiveOnlyBurner" || tests[0].Tags != "sidecar_testhooks" {
		t.Errorf("S10's burned-label clause is registered on T2 to %v", tests)
	}
	tests = registry.Tests("S10", "receive-only-burner-creates-no-child", sidecartest.ScenarioTierT3)
	if len(tests) != 1 || tests[0].Repo != "server" || tests[0].Name != "TestScenarioS10ReceiveOnlyOnT3" {
		t.Errorf("S10's no-child clause is registered on T3 to %v", tests)
	}
}
