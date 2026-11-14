// The commitment gadget against gnark-crypto's own arithmetic (DESIGN-DETAILS 3.6's SMTP-M9-36 row).

package smtpproof

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
)

// A commitment of private message and blind bits, asserted equal to a public point. The harness asserts
// every private bit boolean, which a part does where its bits enter.
type testCommitCircuit struct {
	generators *commitGenerators
	Bits       []frontend.Variable
	BlindBits  []frontend.Variable
	Commitment []frontend.Variable `gnark:",public"`
}

func (self *testCommitCircuit) Define(api frontend.API) error {
	for _, bit := range append(append([]frontend.Variable{}, self.Bits...), self.BlindBits...) {
		api.AssertIsBoolean(bit)
	}
	assertCommitment(api, self.generators, self.Bits, self.BlindBits, self.Commitment)
	return nil
}

func newTestCommitCircuit(generators *commitGenerators, bitCount int) *testCommitCircuit {
	return &testCommitCircuit{
		generators: generators,
		Bits:       make([]frontend.Variable, bitCount),
		BlindBits:  make([]frontend.Variable, commitBlindBits),
		Commitment: make([]frontend.Variable, 2),
	}
}

// The assignment of bits and a blind to a commitment.
func testCommitAssignment(t *testing.T, generators *commitGenerators, bits []uint8, blind *big.Int, commitment []byte) *testCommitCircuit {
	t.Helper()
	assignment := newTestCommitCircuit(generators, len(bits))
	for i, bit := range bits {
		assignment.Bits[i] = bit
	}
	for i, bit := range commitBlindBitsOf(blind) {
		assignment.BlindBits[i] = bit
	}
	public, err := assignCommitment(commitment)
	if err != nil {
		t.Fatal(err)
	}
	copy(assignment.Commitment, public)
	return assignment
}

func TestCommitGadgetMatchesGnarkCrypto(t *testing.T) {
	keyGenerators, scanGenerators := commitGeneratorSets()
	for _, c := range []struct {
		name       string
		generators *commitGenerators
		bitCount   int
	}{
		{name: "aes keys", generators: keyGenerators, bitCount: 8 * (2*tlsAes128KeyBytes + 2*tlsIv13Bytes)},
		{name: "chacha20 keys", generators: keyGenerators, bitCount: 8 * (2*tlsChachaKeyBytes + 2*tlsIv13Bytes)},
		{name: "a carry", generators: scanGenerators, bitCount: carryStateBits},
	} {
		compiled := testCompile(t, newTestCommitCircuit(c.generators, c.bitCount))
		for round := range 3 {
			bits := make([]uint8, c.bitCount)
			random := make([]byte, (c.bitCount+7)/8)
			rand.Read(random)
			for i := range bits {
				bits[i] = (random[i/8] >> (i % 8)) & 1
			}
			blind, err := newCommitBlind("test_commit_blind")
			if err != nil {
				t.Fatal(err)
			}
			point, err := commitBits(c.generators, bits, blind)
			if err != nil {
				t.Fatal(err)
			}
			commitment := encodeCommitment(point)
			if err := testSolved(t, compiled, testCommitAssignment(t, c.generators, bits, blind, commitment)); err != nil {
				t.Errorf("%s round %d: an honest opening is refused: %v", c.name, round, err)
			}
			// one message bit off, at the round's position, and one blind bit off
			flipped := append([]uint8{}, bits...)
			flipped[(round*97)%c.bitCount] ^= 1
			if err := testSolved(t, compiled, testCommitAssignment(t, c.generators, flipped, blind, commitment)); err == nil {
				t.Errorf("%s round %d: a message one bit off opens the commitment", c.name, round)
			}
			otherBlind := new(big.Int).Xor(blind, big.NewInt(1<<(round*5)))
			if err := testSolved(t, compiled, testCommitAssignment(t, c.generators, bits, otherBlind, commitment)); err == nil {
				t.Errorf("%s round %d: a blind one bit off opens the commitment", c.name, round)
			}
		}
	}
}

// DESIGN-DETAILS 3.6: the key part derives both directions always, under Z1's own derivation, so a C
// over another server key leaves it unsatisfiable while the honest C solves; the relation names Z1 alike.
func TestKeyPartBindsBothDirections(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 1)
		shape, err := partShapeFor(statement)
		if err != nil {
			t.Fatal(err)
		}
		if !shape.derivesKeys() {
			t.Fatalf("%s: the key part proves under %s, which derives nothing", leg.name, partShapeName(shape))
		}
		compiled := testCompileShape(t, shape)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
			t.Fatalf("%s: the honest key part: %v", leg.name, err)
		}
		otherServerKey := bytes.Clone(witness.serverKey)
		otherServerKey[0] ^= 1
		forged, err := commitKeys(witness.clientKey, witness.clientIv, otherServerKey, witness.serverIv, witness.keyBlind)
		if err != nil {
			t.Fatal(err)
		}
		statement.keyCommitment = encodeCommitment(forged)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: a key part solves under a C that holds another server key", leg.name)
		}
		// nor does a witness that claims that key alongside it: the derivation refuses it
		witness.serverKey = otherServerKey
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: a key part solves with a server key its secret does not give", leg.name)
		}
		testExpectOnly(t, leg.name+" another server key", statement, witness, checkZ1)
	}
}

// DESIGN-DETAILS 3.6: every later part opens the key part's C. One key bit off in either direction, an IV
// bit off, or another blind leaves the part unsatisfiable, on a shape of each later kind, and the relation
// names Z1 for each.
func TestLaterPartOpensTheKeyPartsCommitment(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		for _, data := range []bool{false, true} {
			settings := DefaultProverSettings()
			job := testJob("one line\r\nanother line\r\nand a third\r\n", "bob", "carol")
			if data {
				settings.ForceData = true
				settings.DataPartBytes = 12
			}
			capture := testCapture(t, leg, testMxDefaults(), settings, job)
			for index := uint32(2); int(index) <= len(capture.statements); index += 1 {
				statement, witness := capture.part(t, index)
				shape, err := testShapeFitting(statement, 0, 8)
				if err != nil {
					t.Fatal(err)
				}
				compiled := testCompileShape(t, shape)
				name := fmt.Sprintf("%s data %t part %d", leg.name, data, index)
				if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
					t.Fatalf("%s: the honest part: %v", name, err)
				}
				for _, c := range []struct {
					what   string
					mutate func(witness *partWitness)
				}{
					{what: "a client key bit", mutate: func(witness *partWitness) {
						witness.clientKey = bytes.Clone(witness.clientKey)
						witness.clientKey[len(witness.clientKey)-1] ^= 0x80
					}},
					{what: "a server key bit", mutate: func(witness *partWitness) {
						witness.serverKey = bytes.Clone(witness.serverKey)
						witness.serverKey[0] ^= 1
					}},
					{what: "a client IV bit", mutate: func(witness *partWitness) {
						witness.clientIv = bytes.Clone(witness.clientIv)
						witness.clientIv[0] ^= 2
					}},
					{what: "another blind", mutate: func(witness *partWitness) {
						witness.keyBlind = new(big.Int).Add(witness.keyBlind, big.NewInt(1))
					}},
				} {
					mutated := testCloneWitness(witness)
					c.mutate(mutated)
					if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, mutated)); err == nil {
						t.Errorf("%s: %s off opens C", name, c.what)
					}
					if failures := relationCheckPart(statement, mutated); len(failures) == 0 || failures[0].check != checkZ1 {
						t.Errorf("%s: %s off: the relation says %v", name, c.what, failures)
					}
				}
			}
		}
	}
}
