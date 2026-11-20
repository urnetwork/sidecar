//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// S10's receive-only half on T2 (§22.7; MAIL-M8-10): mailworld's builder (s10.go), which server's sidecart3 runs on T3
// (TestScenarioS10ReceiveOnlyOnT3), under RunScenario's T2 defaults, and what the registry reads for S10 at its gate,
// its replying half (MAIL-M9-06, mail_m9_test.go) included.

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

// What the default registry reads for S10 at its gate: on T2 and on T3 no part reads missing, the receive-only half
// registered to MAIL-M8-10's tests and the replying half to MAIL-M9-06's, each half's test on T2 here and on T3 in
// server's sidecart3, and a burned label's clause to both halves.
func TestS10IsRegisteredWholeOnT2AndT3(t *testing.T) {
	registry := sidecartest.DefaultScenarioRegistry()
	for _, tier := range []string{sidecartest.ScenarioTierT2, sidecartest.ScenarioTierT3} {
		for _, part := range registry.Missing("M9-out", tier) {
			if part.Row.Id == "S10" {
				t.Errorf("S10's %q reads missing on %s", part.Clause, tier)
			}
		}
	}
	names := func(clause string, tier string) []string {
		names := []string{}
		for _, test := range registry.Tests("S10", clause, tier) {
			names = append(names, test.Repo+" "+test.Name)
		}
		slices.Sort(names)
		return names
	}
	cases := []struct {
		clause string
		tier   string
		want   []string
	}{
		{clause: "burned-label-550-no-dns-change", tier: sidecartest.ScenarioTierT2, want: []string{"sidecar TestScenarioS10ReceiveOnlyBurner", "sidecar TestScenarioS10ReplyingBurner"}},
		{clause: "burned-label-550-no-dns-change", tier: sidecartest.ScenarioTierT3, want: []string{"server TestScenarioS10ReceiveOnlyOnT3", "server TestScenarioS10ReplyingOnT3"}},
		{clause: "receive-only-burner-creates-no-child", tier: sidecartest.ScenarioTierT3, want: []string{"server TestScenarioS10ReceiveOnlyOnT3"}},
		{clause: "first-selector-keeps-blabel-mx-and-a", tier: sidecartest.ScenarioTierT2, want: []string{"sidecar TestScenarioS10ReplyingBurner"}},
		{clause: "last-selector-restores-wildcard-only", tier: sidecartest.ScenarioTierT3, want: []string{"server TestScenarioS10ReplyingOnT3"}},
	}
	for _, c := range cases {
		if have := names(c.clause, c.tier); !slices.Equal(have, c.want) {
			t.Errorf("S10's %s is registered on %s to %q, not %q", c.clause, c.tier, have, c.want)
		}
	}
}
