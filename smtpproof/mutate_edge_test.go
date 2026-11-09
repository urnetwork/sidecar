// The mutated witnesses of E1 to E3 (mutate_test.go): each break is refused by edgeSession itself, the
// gate and smtpproof/checker naming the one check alike, whatever the gate's verifier.

package smtpproof_test

import (
	"testing"
)

func TestMutatedWitnessE1(t *testing.T) {
	testRunMutations(t, "E1")
}

func TestMutatedWitnessE2(t *testing.T) {
	testRunMutations(t, "E2")
}

func TestMutatedWitnessE3(t *testing.T) {
	testRunMutations(t, "E3")
}
