//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"testing"
)

// Kind 24's rule (D-HARN-7): a tainted run's send is outward into an enclave that reaches out, an egress-none one a
// rule lets dial another device's services among them, and to another member's agent or enclave; never into an
// egress-none enclave no rule lets dial, never to the member's own local agents, and never from an untainted run. A
// target the rule cannot read is outward.
func TestHarnessSendIsOutwardTable(t *testing.T) {
	cases := []struct {
		name    string
		tainted bool
		target  *HarnessSendTarget
		want    bool
	}{
		{name: "egress auto", tainted: true, target: &HarnessSendTarget{Kind: HarnessSendEnclave, EnclaveEgress: "auto"}, want: true},
		{name: "egress exits", tainted: true, target: &HarnessSendTarget{Kind: HarnessSendEnclave, EnclaveEgress: "exits"}, want: true},
		{name: "egress none", tainted: true, target: &HarnessSendTarget{Kind: HarnessSendEnclave, EnclaveEgress: HarnessEnclaveEgressNone}, want: false},
		{name: "egress none with a listener grant", tainted: true, target: &HarnessSendTarget{Kind: HarnessSendEnclave, EnclaveEgress: HarnessEnclaveEgressNone, DialsServices: true}, want: true},
		{name: "egress unknown", tainted: true, target: &HarnessSendTarget{Kind: HarnessSendEnclave}, want: true},
		{name: "another member's agent", tainted: true, target: &HarnessSendTarget{Kind: HarnessSendMemberAgent}, want: true},
		{name: "another member's egress-none enclave", tainted: true, target: &HarnessSendTarget{Kind: HarnessSendMemberEnclave, EnclaveEgress: HarnessEnclaveEgressNone}, want: true},
		{name: "the member's local agent", tainted: true, target: &HarnessSendTarget{Kind: HarnessSendLocalAgent}, want: false},
		{name: "an unknown kind", tainted: true, target: &HarnessSendTarget{Kind: "somewhere"}, want: true},
		{name: "no target", tainted: true, target: nil, want: true},
		{name: "an untainted run into egress auto", tainted: false, target: &HarnessSendTarget{Kind: HarnessSendEnclave, EnclaveEgress: "auto"}, want: false},
		{name: "an untainted run to another member's agent", tainted: false, target: &HarnessSendTarget{Kind: HarnessSendMemberAgent}, want: false},
	}
	for _, c := range cases {
		if got := HarnessSendIsOutward(c.tainted, c.target); got != c.want {
			t.Errorf("%s: outward %v, want %v", c.name, got, c.want)
		}
	}

	// the run reads its own taint now
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	run := newHarnessTestRun(t, runs, nil)
	auto := &HarnessSendTarget{Kind: HarnessSendEnclave, EnclaveEgress: "auto"}
	if run.SendIsOutward(auto) {
		t.Fatal("an untainted run's send is outward")
	}
	if err := run.Taint(context.Background(), RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	if !run.SendIsOutward(auto) {
		t.Fatal("a tainted run's send into egress auto is not outward")
	}
}
