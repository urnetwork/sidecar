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
		{"egress auto", true, &HarnessSendTarget{Kind: HarnessSendEnclave, EnclaveEgress: "auto"}, true},
		{"egress exits", true, &HarnessSendTarget{Kind: HarnessSendEnclave, EnclaveEgress: "exits"}, true},
		{"egress none", true, &HarnessSendTarget{Kind: HarnessSendEnclave, EnclaveEgress: HarnessEnclaveEgressNone}, false},
		{"egress none with a listener grant", true, &HarnessSendTarget{Kind: HarnessSendEnclave, EnclaveEgress: HarnessEnclaveEgressNone, DialsServices: true}, true},
		{"egress unknown", true, &HarnessSendTarget{Kind: HarnessSendEnclave}, true},
		{"another member's agent", true, &HarnessSendTarget{Kind: HarnessSendMemberAgent}, true},
		{"another member's egress-none enclave", true, &HarnessSendTarget{Kind: HarnessSendMemberEnclave, EnclaveEgress: HarnessEnclaveEgressNone}, true},
		{"the member's local agent", true, &HarnessSendTarget{Kind: HarnessSendLocalAgent}, false},
		{"an unknown kind", true, &HarnessSendTarget{Kind: "somewhere"}, true},
		{"no target", true, nil, true},
		{"an untainted run into egress auto", false, &HarnessSendTarget{Kind: HarnessSendEnclave, EnclaveEgress: "auto"}, false},
		{"an untainted run to another member's agent", false, &HarnessSendTarget{Kind: HarnessSendMemberAgent}, false},
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
