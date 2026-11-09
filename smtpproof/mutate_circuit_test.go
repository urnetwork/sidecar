// The mutated witnesses of Z1 to Z9 (mutate_test.go): relationCheckPart, through the gate, and
// smtpproof/checker name the one check alike, and the circuit refuses the part.

package smtpproof_test

import (
	"testing"
)

func TestMutatedWitnessZ1(t *testing.T) {
	testRunMutations(t, "Z1")
}

func TestMutatedWitnessZ2(t *testing.T) {
	testRunMutations(t, "Z2")
}

func TestMutatedWitnessZ3(t *testing.T) {
	testRunMutations(t, "Z3")
}

func TestMutatedWitnessZ4(t *testing.T) {
	testRunMutations(t, "Z4")
}

func TestMutatedWitnessZ5(t *testing.T) {
	testRunMutations(t, "Z5")
}

func TestMutatedWitnessZ6(t *testing.T) {
	testRunMutations(t, "Z6")
}

func TestMutatedWitnessZ7(t *testing.T) {
	testRunMutations(t, "Z7")
}

func TestMutatedWitnessZ8(t *testing.T) {
	testRunMutations(t, "Z8")
}

func TestMutatedWitnessZ9(t *testing.T) {
	testRunMutations(t, "Z9")
}
