// A real proof, end to end: the prover proves pi1 under Groth16, and the edge's own statement checks
// it. Keys here come from a single-party test setup, which SPEC.md 10.3's verified setup replaces.

package smtpproof

import (
	"context"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

// A small shape with Z1 left out: everything but the key schedule, in milliseconds.
func testQuickShape(suite uint16, localOctets bool) *partShape {
	shape := &partShape{kind: partKindEhlo, version: tlsVersion13, suite: suite, clientBlocks: 4, localOctets: localOctets, withoutKeySchedule: true}
	if suite == tlsSuiteChacha20Poly1305Sha256 {
		shape.clientBlocks = 1
	}
	return shape
}

func testPartAssignment(t *testing.T, shape *partShape, statement *partStatement, witness *partWitness) *partCircuit {
	t.Helper()
	circuit, err := partAssignment(shape, statement)
	if err != nil {
		t.Fatal(err)
	}
	assignWitness(circuit, witness)
	return circuit
}

func testPartSolved(t *testing.T, compiled constraint.ConstraintSystem, circuit *partCircuit) error {
	t.Helper()
	return testSolved(t, compiled, circuit)
}

func TestPartCircuitAcceptsARealEhlo(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		shape := testQuickShape(leg.suites[0], false)
		compiled := testCompile(t, newPartCircuit(shape))
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 1)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
			t.Errorf("%s: %v", leg.name, err)
		}
	}
}

func TestPartCircuitRefusesWhatTheRelationRefuses(t *testing.T) {
	// the same mutated witnesses as relation_test.go, through the circuit
	for _, leg := range testTlsLegs()[:2] {
		shape := testQuickShape(leg.suites[0], false)
		compiled := testCompile(t, newPartCircuit(shape))
		capture := testBdatCapture(t, leg)

		// Z2: a ciphertext that does not hold the claimed record
		statement, witness := capture.part(t, 1)
		record := statement.clientRecords[0]
		record.raw[len(record.raw)-tlsAeadTagBytes-2] ^= 1
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: Z2: accepted", leg.name)
		}

		// Z2 and Z1's substituted key: another key does not open the record to the literal
		statement, witness = capture.part(t, 1)
		witness.clientKey[0] ^= 1
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: a substituted key: accepted", leg.name)
		}

		// Z2: a record at another sequence number
		statement, witness = capture.part(t, 1)
		statement.clientRecords[0].seq += 1
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: another sequence number: accepted", leg.name)
		}

		// Z3: another inner type, authored under the true key
		statement, witness = capture.part(t, 1)
		plaintext := witness.clientPlaintexts[0]
		plaintext[len(plaintext)-1] = tlsRecordHandshake
		testSeal(t, statement, statement.clientRecords[0], witness.clientKey, witness.clientIv, plaintext)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: Z3: accepted", leg.name)
		}

		// Z4: another HELO name of the same length, so the record still fits its template
		statement, witness = capture.part(t, 1)
		other := []byte("EHLO " + "x" + testHeloName[1:] + "\r\n")
		testAuthorClientRecord(t, statement, witness, 0, other)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: Z4: accepted", leg.name)
		}
	}
}

func TestPartCircuitChecksALocalPartsOctets(t *testing.T) {
	// MAIL's template, on a shape that carries local octets
	for _, leg := range testTlsLegs()[:2] {
		shape := testQuickShape(leg.suites[0], true)
		compiled := testCompile(t, newPartCircuit(shape))
		capture := testBdatCapture(t, leg)
		solve := func(content string) error {
			t.Helper()
			statement, witness := capture.part(t, 2)
			statement.index = 1
			statement.clientRecords = statement.clientRecords[:1]
			witness.clientPlaintexts = witness.clientPlaintexts[:1]
			testAuthorClientRecord(t, statement, witness, 0, []byte(content))
			circuit := newZeroAssignment(shape)
			circuit.ShtsHash = assignBits(statement.session.shtsHash)
			circuit.HelloHash = assignBits(statement.session.helloHash)
			circuit.FinishedHash = assignBits(statement.session.finishedHash)
			template, err := clientRecordTemplate(statement.session, recordRoleMail, statement.clientRecords[0])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := assignRecordBlocks(shape, statement, statement.clientRecords[0], template, circuit.Client); err != nil {
				t.Fatal(err)
			}
			assignWitness(circuit, witness)
			return testPartSolved(t, compiled, circuit)
		}
		suffix := "@" + testEnvelopeDomain + ">\r\n"
		if err := solve("MAIL FROM:<bounce-1" + suffix); err != nil {
			t.Errorf("%s: an honest MAIL: %v", leg.name, err)
		}
		for _, local := range []string{"a,b", "a b", "a>b", "a@b", "a%b", "a!b", "a\rb", "a\x00b", "a\xc3b"} {
			if err := solve("MAIL FROM:<" + local + suffix); err == nil {
				t.Errorf("%s: local part %q: accepted", leg.name, local)
			}
		}
	}
}

func TestProductionShapesProveZ1(t *testing.T) {
	for _, shape := range partShapes() {
		if shape.withoutKeySchedule {
			t.Errorf("a production shape leaves Z1 out: %+v", shape)
		}
	}
}

func TestCircuitsUseNoCommitments(t *testing.T) {
	// SPEC.md 10.2's zero knowledge argument is vanilla Groth16's: a commitment would need its own
	for _, shape := range partShapes() {
		compiled, err := compilePartShape(shape)
		if err != nil {
			t.Fatal(err)
		}
		commitments := compiled.GetCommitments()
		if commitments != nil && len(commitments.CommitmentIndexes()) != 0 {
			t.Errorf("%+v carries %d commitments", shape, len(commitments.CommitmentIndexes()))
		}
		t.Logf("%+v: %d constraints, %d public inputs", *shape, compiled.GetNbConstraints(), compiled.GetNbPublicVariables())
	}
}

func TestUnknownPartsFailClosed(t *testing.T) {
	backend := newGroth16Backend()
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		// pi2 has no circuit yet, and pi1 has no keys loaded here
		for _, index := range []uint32{1, 2, 3} {
			statement, witness := capture.part(t, index)
			if _, err := backend.provePart(context.Background(), statement, witness); err == nil {
				t.Errorf("%s: proved part %d", leg.name, index)
			}
			if err := backend.verifyPart(context.Background(), statement, []byte("not a proof")); err == nil {
				t.Errorf("%s: verified part %d", leg.name, index)
			}
		}
	}
}

// Runs a test-only setup for a shape, which is the slow step here.
func testSetup(t *testing.T, shape *partShape) *shapeKeys {
	t.Helper()
	compiled, err := compilePartShape(shape)
	if err != nil {
		t.Fatal(err)
	}
	provingKey, verifyingKey, err := groth16.Setup(compiled)
	if err != nil {
		t.Fatal(err)
	}
	return &shapeKeys{shape: shape, compiled: compiled, provingKey: provingKey, verifyingKey: verifyingKey}
}

func TestGroth16ProofOfARealEhlo(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real setup")
	}
	leg := testTlsLegs()[1]
	shape := partShapes()[1]
	keys := testSetup(t, shape)
	backend := newGroth16Backend()
	backend.addKeys(keys)

	capture := testBdatCapture(t, leg)
	statement, witness := capture.part(t, 1)
	proof, err := backend.provePart(context.Background(), statement, witness)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.verifyPart(context.Background(), statement, proof); err != nil {
		t.Fatalf("an honest proof did not verify: %v", err)
	}
	t.Logf("%d octet proof over %d constraints", len(proof), keys.compiled.GetNbConstraints())

	// the same proof against any other statement: this is where a key or plaintext swap would land
	other, _ := capture.part(t, 1)
	other.clientRecords[0].raw[len(other.clientRecords[0].raw)-tlsAeadTagBytes-2] ^= 1
	if err := backend.verifyPart(context.Background(), other, proof); err == nil {
		t.Error("a proof verified against another ciphertext")
	}
	other, _ = capture.part(t, 1)
	other.session.finishedHash = append([]byte{}, other.session.finishedHash...)
	other.session.finishedHash[0] ^= 1
	if err := backend.verifyPart(context.Background(), other, proof); err == nil {
		t.Error("a proof verified against another handshake")
	}

	// a mutated witness cannot even be proven: the solver finds no satisfying assignment
	statement, witness = capture.part(t, 1)
	witness.handshakeSecret[0] ^= 1
	if _, err := backend.provePart(context.Background(), statement, witness); err == nil {
		t.Error("proved a witness with another HS")
	}
}
