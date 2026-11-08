// A real proof, end to end: the prover proves pi1 under Groth16, and the edge's own statement checks
// it. Keys here come from a single-party test setup, which SPEC.md 10.3's verified setup replaces.

package smtpproof

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	gnarkwitness "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/urnetwork/sidecar"
)

// A suite's version.
func testVersionOf(suite uint16) uint16 {
	if tlsSuiteCovered(tlsVersion13, suite) {
		return tlsVersion13
	}
	return tlsVersion12
}

// A small shape with Z1 left out: everything but the key schedule, in milliseconds.
func testQuickShape(suite uint16, localOctets bool) *partShape {
	shape := &partShape{kind: partKindEhlo, version: testVersionOf(suite), suite: suite, clientBlocks: 4, localOctets: localOctets, withoutKeySchedule: true}
	if suite == tlsSuiteChacha20Poly1305Sha256 {
		shape.clientBlocks = 1
	}
	return shape
}

// Compiled shapes, shared by every test: compiling dwarfs solving.
var (
	testCompiledLock   sync.Mutex
	testCompiledShapes = map[partShape]constraint.ConstraintSystem{}
)

func testCompileShape(t *testing.T, shape *partShape) constraint.ConstraintSystem {
	t.Helper()
	testCompiledLock.Lock()
	defer testCompiledLock.Unlock()
	if compiled, ok := testCompiledShapes[*shape]; ok {
		return compiled
	}
	compiled := testCompile(t, newPartCircuit(shape))
	testCompiledShapes[*shape] = compiled
	return compiled
}

func testPartAssignment(t *testing.T, shape *partShape, statement *partStatement, witness *partWitness) *partCircuit {
	t.Helper()
	circuit, err := partAssignment(shape, statement)
	if err != nil {
		t.Fatal(err)
	}
	assignWitness(circuit, statement, witness)
	return circuit
}

func testPartSolved(t *testing.T, compiled constraint.ConstraintSystem, circuit *partCircuit) error {
	t.Helper()
	return testSolved(t, compiled, circuit)
}

func TestPartCircuitAcceptsARealEhlo(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		shape := testQuickShape(leg.suites[0], false)
		compiled := testCompileShape(t, shape)
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 1)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
			t.Errorf("%s: %v", leg.name, err)
		}
	}
}

func TestPartCircuitRefusesWhatTheRelationRefuses(t *testing.T) {
	t.Parallel()
	// the same mutated witnesses as relation_test.go, through the circuit
	for _, leg := range testTlsLegs() {
		shape := testQuickShape(leg.suites[0], false)
		compiled := testCompileShape(t, shape)
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

		if statement.session.version == tlsVersion13 {
			// Z2: a record at another sequence number. 1.2 carries its nonce in the record
			statement, witness = capture.part(t, 1)
			statement.clientRecords[0].seq += 1
			if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
				t.Errorf("%s: another sequence number: accepted", leg.name)
			}

			// Z3: another inner type, authored under the true key. 1.2 has none
			statement, witness = capture.part(t, 1)
			plaintext := witness.clientPlaintexts[0]
			plaintext[len(plaintext)-1] = tlsRecordHandshake
			testSeal(t, statement, statement.clientRecords[0], witness.clientKey, witness.clientIv, plaintext)
			if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
				t.Errorf("%s: Z3: accepted", leg.name)
			}
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
	t.Parallel()
	// MAIL's template, on a shape that carries local octets
	for _, leg := range testTlsLegs() {
		shape := testQuickShape(leg.suites[0], true)
		compiled := testCompileShape(t, shape)
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
			assignWitness(circuit, statement, witness)
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

// An envelope shape with Z1 left out, sized to the test connection.
func testQuickEnvelopeShape(suite uint16) *partShape {
	shape := &partShape{kind: partKindEnvelope, version: testVersionOf(suite), suite: suite, clientBlocks: 12, serverBlocks: 8, localOctets: true, withoutKeySchedule: true}
	if suite == tlsSuiteChacha20Poly1305Sha256 {
		shape.clientBlocks = 4
		shape.serverBlocks = 3
	}
	return shape
}

// Compiled once per suite: every case below shares it.
func testEnvelopeCircuit(t *testing.T, leg *testTlsLeg) (*partShape, constraint.ConstraintSystem) {
	t.Helper()
	shape := testQuickEnvelopeShape(leg.suites[0])
	return shape, testCompileShape(t, shape)
}

func TestEnvelopeCircuitAcceptsARealEhloReply(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		shape, compiled := testEnvelopeCircuit(t, leg)
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 2)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
			t.Errorf("%s: %v", leg.name, err)
		}
	}
}

func TestEnvelopeCircuitAgreesWithTheRelationOnReplies(t *testing.T) {
	t.Parallel()
	// Z7-Z9 differentially: each stream goes through the reference relation and the circuit, and both
	// must give the same answer. The stream is the EHLO reply, as the MX might have sent it.
	cases := []struct {
		name    string
		content string
		accept  bool
	}{
		{name: "chunking offered", content: "250-mx\r\n250-PIPELINING\r\n250-CHUNKING\r\n250 OK\r\n", accept: true},
		{name: "chunking last", content: "250-mx\r\n250 CHUNKING\r\n", accept: true},
		{name: "chunking in lower case", content: "250-mx\r\n250 chunking\r\n", accept: true},
		{name: "chunking in mixed case", content: "250-mx\r\n250-ChUnKiNg\r\n250 OK\r\n", accept: true},
		{name: "chunking absent", content: "250-mx\r\n250-PIPELINING\r\n250 OK\r\n"},
		{name: "chunking in the MX's name line", content: "250-CHUNKING\r\n250 OK\r\n"},
		{name: "chunking inside a longer keyword", content: "250-mx\r\n250-XCHUNKING\r\n250 OK\r\n"},
		{name: "a keyword starting with chunking", content: "250-mx\r\n250-CHUNKINGX\r\n250 OK\r\n"},
		{name: "a keyword only Unicode folds to chunking", content: "250-mx\r\n250-CHUN\u212aING\r\n250 OK\r\n"},
		{name: "a one-line reply", content: "250 mx\r\n"},
		{name: "another code", content: "251-mx\r\n250-CHUNKING\r\n250 OK\r\n"},
		{name: "another code on the last line", content: "250-mx\r\n250-CHUNKING\r\n251 OK\r\n"},
		{name: "a refusal", content: "550 no\r\n"},
		{name: "two replies", content: "250-mx\r\n250 CHUNKING\r\n250 OK\r\n"},
		{name: "a truncated reply", content: "250-mx\r\n250 CHUNKING"},
		{name: "a reply ending inside a multiline", content: "250-mx\r\n250-CHUNKING\r\n"},
		{name: "a bare LF", content: "250-mx\n250 CHUNKING\r\n"},
		{name: "a bare CR", content: "250-mx\r250 CHUNKING\r\n"},
		{name: "a malformed code", content: "25x-mx\r\n250 CHUNKING\r\n"},
		{name: "a malformed separator", content: "250+mx\r\n250 CHUNKING\r\n"},
	}
	for _, leg := range testTlsLegs() {
		shape, compiled := testEnvelopeCircuit(t, leg)
		capture := testBdatCapture(t, leg)
		for _, c := range cases {
			statement, witness := capture.part(t, 2)
			statement.serverRecords = statement.serverRecords[:1]
			witness.serverPlaintexts = witness.serverPlaintexts[:1]
			testAuthorServerRecord(t, statement, witness, 0, testServerContent(statement, c.content))
			reference := len(relationCheckPart(statement, witness)) == 0
			if reference != c.accept {
				t.Errorf("%s: %s: the relation says %v", leg.name, c.name, reference)
			}
			circuit, err := partAssignment(shape, statement)
			if err != nil {
				t.Fatal(err)
			}
			assignWitness(circuit, statement, witness)
			if err := testPartSolved(t, compiled, circuit); (err == nil) != c.accept {
				t.Errorf("%s: %s: the circuit says %v", leg.name, c.name, err)
			}
		}
	}
}

func TestEnvelopeCircuitAcceptsDataWithoutChunking(t *testing.T) {
	t.Parallel()
	// Z9 binds BDAT alone
	for _, leg := range testTlsLegs() {
		shape, compiled := testEnvelopeCircuit(t, leg)
		capture := testDataCapture(t, leg)
		statement, witness := capture.part(t, 2)
		statement.serverRecords = statement.serverRecords[:1]
		witness.serverPlaintexts = witness.serverPlaintexts[:1]
		testAuthorServerRecord(t, statement, witness, 0, testServerContent(statement, "250 mx\r\n"))
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
			t.Errorf("%s: %v", leg.name, err)
		}
	}
}

func TestEnvelopeCircuitChecksRecordKinds(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs()[:2] {
		shape, compiled := testEnvelopeCircuit(t, leg)
		capture := testBdatCapture(t, leg)
		ticket := []byte{tlsHandshakeNewSessionTicket, 0, 0, 0, tlsRecordHandshake}

		// Z7: a ticket before the reply is skipped, and which record it was stays private
		statement, witness := capture.part(t, 2)
		record := &partRecord{seq: statement.serverRecords[0].seq + 1, raw: bytes.Clone(statement.serverRecords[0].raw)}
		reply := witness.serverPlaintexts[0]
		statement.serverRecords = append(statement.serverRecords, record)
		witness.serverPlaintexts = append(witness.serverPlaintexts, nil)
		testAuthorServerRecord(t, statement, witness, 0, ticket)
		testAuthorServerRecord(t, statement, witness, 1, reply)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
			t.Errorf("%s: a ticket before the reply: %v", leg.name, err)
		}

		// Z7: a KeyUpdate cannot pass as one
		statement, witness = capture.part(t, 2)
		record = &partRecord{seq: statement.serverRecords[0].seq + 1, raw: bytes.Clone(statement.serverRecords[0].raw)}
		reply = witness.serverPlaintexts[0]
		statement.serverRecords = append(statement.serverRecords, record)
		witness.serverPlaintexts = append(witness.serverPlaintexts, nil)
		testAuthorServerRecord(t, statement, witness, 0, []byte{tlsHandshakeKeyUpdate, 0, 0, 1, 0, tlsRecordHandshake})
		testAuthorServerRecord(t, statement, witness, 1, reply)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: a KeyUpdate: accepted", leg.name)
		}

		// Z7: an alert fits neither kind
		statement, witness = capture.part(t, 2)
		testAuthorServerRecord(t, statement, witness, 0, []byte{1, 0, tlsRecordAlert})
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: an alert: accepted", leg.name)
		}

		// Z7: a server record claimed as a ticket by the prover, when it is a reply, fails its type octet
		statement, witness = capture.part(t, 2)
		circuit := testPartAssignment(t, shape, statement, witness)
		for _, block := range circuit.Server {
			block.Ticket = 1
		}
		if err := testPartSolved(t, compiled, circuit); err == nil {
			t.Errorf("%s: a reply claimed as a ticket: accepted", leg.name)
		}

		// Z1 and Z7: the MX's replies open only under its key
		statement, witness = capture.part(t, 2)
		witness.serverKey = bytes.Clone(witness.serverKey)
		witness.serverKey[0] ^= 1
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: a substituted server key: accepted", leg.name)
		}
	}
}

func TestEnvelopeCircuitAgreesWithTheRelationOnSplitReplies(t *testing.T) {
	t.Parallel()
	// a reply may split anywhere for Z8, and only inside the keyword's window for Z9
	cases := []struct {
		name     string
		contents []string
		accept   bool
	}{
		{name: "split before the keyword's line", contents: []string{"250-mx\r\n250-PIPE", "LINING\r\n250-CHUNKING\r\n250 OK\r\n"}, accept: true},
		{name: "split inside the keyword", contents: []string{"250-mx\r\n250-CHUN", "KING\r\n250 OK\r\n"}},
		{name: "split at the keyword's line", contents: []string{"250-mx\r\n", "250-CHUNKING\r\n250 OK\r\n"}},
		{name: "split after the keyword", contents: []string{"250-mx\r\n250-CHUNKING", "\r\n250 OK\r\n"}},
	}
	for _, leg := range testTlsLegs() {
		shape, compiled := testEnvelopeCircuit(t, leg)
		capture := testBdatCapture(t, leg)
		for _, c := range cases {
			statement, witness := testEhloRecords(t, capture, c.contents...)
			if reference := len(relationCheckPart(statement, witness)) == 0; reference != c.accept {
				t.Errorf("%s: %s: the relation says %v", leg.name, c.name, reference)
			}
			if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); (err == nil) != c.accept {
				t.Errorf("%s: %s: the circuit says %v", leg.name, c.name, err)
			}
		}
	}
}

func TestEnvelopeCircuitRefusesAReplayAndAPaddedRecord(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		shape, compiled := testEnvelopeCircuit(t, leg)
		capture := testBdatCapture(t, leg)

		// the honest twin of both
		statement, witness := capture.part(t, 2)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
			t.Fatalf("%s: %v", leg.name, err)
		}

		if statement.session.version == tlsVersion13 {
			// a record the MX really sent, at a sequence number it did not send it: 1.2 carries its nonce
			// in the record, and the MX's own tag refuses a replay there
			statement, witness = capture.part(t, 2)
			statement.serverRecords[0].seq += 1
			if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
				t.Errorf("%s: a replayed record: accepted", leg.name)
			}

			// Z7: padding moves the type octet off the record's last position
			statement, witness = capture.part(t, 2)
			padded := append(bytes.Clone(witness.serverPlaintexts[0]), 0, 0)
			testAuthorServerRecord(t, statement, witness, 0, padded)
			testExpectOnly(t, leg.name, statement, witness, checkZ7)
			if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
				t.Errorf("%s: a padded record: accepted", leg.name)
			}
		}
	}
}

func TestEnvelopeCircuitFindsNoKeywordInsideATicket(t *testing.T) {
	t.Parallel()
	// a ticket's octets are skipped, so they are no part of the reply Z9 reads, and whatever a ticket
	// holds cannot stand in for the keyword the EHLO reply lacks
	for _, leg := range testTlsLegs()[:2] {
		shape, compiled := testEnvelopeCircuit(t, leg)
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 2)
		statement.serverRecords = append(statement.serverRecords[:1], &partRecord{seq: statement.serverRecords[0].seq + 1, raw: bytes.Clone(statement.serverRecords[0].raw)})
		witness.serverPlaintexts = append(witness.serverPlaintexts[:1], nil)
		ticket := append([]byte{tlsHandshakeNewSessionTicket, 0, 0, 16}, []byte("\r\n250-CHUNKING\r\n")...)
		testAuthorServerRecord(t, statement, witness, 0, append(ticket, tlsRecordHandshake))
		testAuthorServerRecord(t, statement, witness, 1, testServerContent(statement, "250-mx\r\n250 OK\r\n"))
		testExpectOnly(t, leg.name, statement, witness, checkZ9)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: the circuit took a ticket's octets for the keyword", leg.name)
		}

		// the same reply with the keyword in it is what the check is for
		testAuthorServerRecord(t, statement, witness, 1, testServerContent(statement, "250-mx\r\n250 CHUNKING\r\n"))
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
			t.Errorf("%s: a ticket beside a reply that offers it: %v", leg.name, err)
		}
	}
}

func TestEnvelopeCircuitChecksTheEnvelope(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		shape, compiled := testEnvelopeCircuit(t, leg)
		capture := testBdatCapture(t, leg)
		cases := []struct {
			name    string
			record  int
			content string
		}{
			{name: "a local part with a comma", record: 1, content: "RCPT TO:<a,b@" + testRecipientDomain + ">\r\n"},
			{name: "a percent route", record: 1, content: "RCPT TO:<a%b@" + testRecipientDomain + ">\r\n"},
			{name: "a same-length domain", record: 1, content: "RCPT TO:<bob@" + "x" + testRecipientDomain[1:] + ">\r\n"},
			{name: "a same-length sender domain", record: 0, content: "MAIL FROM:<bounce-1@x" + testEnvelopeDomain[1:] + ">\r\n"},
		}
		for _, c := range cases {
			statement, witness := capture.part(t, 2)
			testAuthorClientRecord(t, statement, witness, c.record, []byte(c.content))
			if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
				t.Errorf("%s: %s: accepted", leg.name, c.name)
			}
		}
	}
}

// A message shape with Z1 left out, sized to the test connection's header block.
func testQuickMessageShape(suite uint16, bodyBlocks int) *partShape {
	shape := &partShape{kind: partKindMessage, version: testVersionOf(suite), suite: suite, clientBlocks: 4, serverBlocks: 12, headerBlocks: 40, bodyBlocks: bodyBlocks, withoutKeySchedule: true}
	if suite == tlsSuiteChacha20Poly1305Sha256 {
		shape.clientBlocks = 2
		shape.serverBlocks = 5
		shape.headerBlocks = 10
	}
	return shape
}

func TestMessageCircuitAcceptsARealMessage(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		shape := testQuickMessageShape(leg.suites[0], 0)
		compiled := testCompileShape(t, shape)
		t.Logf("%s: %d constraints", leg.name, compiled.GetNbConstraints())
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 3)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
			t.Errorf("%s: %v", leg.name, err)
		}
	}
}

func TestMessageCircuitAgreesWithTheRelationOnHeaders(t *testing.T) {
	t.Parallel()
	// Z5 differentially: every smuggled header is refused by the relation and by the circuit alike
	for _, leg := range testTlsLegs() {
		shape := testQuickMessageShape(leg.suites[0], 0)
		compiled := testCompileShape(t, shape)
		capture := testBdatCapture(t, leg)
		for _, c := range testSmuggledHeaders(t) {
			statement, witness := capture.part(t, 3)
			testAuthorHeaderBlock(t, statement, witness, c.block)
			if failures := relationCheckPart(statement, witness); len(failures) != 1 || failures[0].check != checkZ5 {
				t.Errorf("%s: %s: the relation says %v", leg.name, c.name, failures)
			}
			// must reach the circuit: a case the shape cannot hold would prove nothing by being skipped
			if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
				t.Errorf("%s: %s: the circuit accepted", leg.name, c.name)
			}
		}
	}
}

func TestMessageCircuitRefusesAnyPositionsForAHostileFrom(t *testing.T) {
	t.Parallel()
	// the positions of < and @ are the prover's to choose, so a refusal must not rest on the honest
	// helper's choice: every candidate pair is tried here, as a malicious prover could
	header := testHeaderBlock()
	fromLine := "From: Alice Example <alice@" + testNetworkDomain + ">\r\n"
	blocks := []string{
		strings.Replace(header, fromLine, "From: <x@victim.example>, <alice@"+testNetworkDomain+">\r\n", 1),
		strings.Replace(header, fromLine, "From: x@victim.example <alice@"+testNetworkDomain+">\r\n", 1),
		strings.Replace(header, fromLine, "From: <x@victim.example> <alice@"+testNetworkDomain+">\r\n", 1),
		strings.Replace(header, fromLine, "From: <alice@"+testNetworkDomain+"> <x@victim.example>\r\n", 1),
	}
	for _, leg := range testTlsLegs() {
		shape := testQuickMessageShape(leg.suites[0], 0)
		compiled := testCompileShape(t, shape)
		capture := testBdatCapture(t, leg)
		for _, block := range blocks {
			var angles, ats []int
			for i := range block {
				if block[i] == '<' {
					angles = append(angles, i)
				}
				if block[i] == '@' {
					ats = append(ats, i)
				}
			}
			statement, witness := capture.part(t, 3)
			testAuthorHeaderBlock(t, statement, witness, block)
			for _, angle := range angles {
				for _, at := range ats {
					circuit := testPartAssignment(t, shape, statement, witness)
					for i := range circuit.Header.FromAngle {
						circuit.Header.FromAngle[i] = 0
						circuit.Header.FromAt[i] = 0
					}
					circuit.Header.FromAngle[angle] = 1
					circuit.Header.FromAt[at] = 1
					if err := testPartSolved(t, compiled, circuit); err == nil {
						t.Errorf("%s: %q: accepted with < at %d and @ at %d", leg.name, block[:40], angle, at)
					}
				}
			}
		}
	}
}

func TestMessageCircuitAcceptsFormsAnHonestMessageUses(t *testing.T) {
	t.Parallel()
	header := testHeaderBlock()
	fromLine := "From: Alice Example <alice@" + testNetworkDomain + ">\r\n"
	blocks := []string{
		strings.Replace(header, fromLine, "From: <alice@"+testNetworkDomain+">\r\n", 1),
		strings.Replace(header, fromLine, "From: =?utf-8?q?Al=C3=ADce?= <alice@"+testNetworkDomain+">\r\n", 1),
		strings.Replace(header, "Subject: A synthetic", "Subject: A\r\n synthetic", 1),
		"Received: by example\r\n" + header,
	}
	for _, leg := range testTlsLegs() {
		shape := testQuickMessageShape(leg.suites[0], 0)
		compiled := testCompileShape(t, shape)
		capture := testBdatCapture(t, leg)
		for i, block := range blocks {
			statement, witness := capture.part(t, 3)
			testAuthorHeaderBlock(t, statement, witness, block)
			if failures := relationCheckPart(statement, witness); len(failures) != 0 {
				t.Fatalf("%s: block %d: %v", leg.name, i, failures)
			}
			if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
				t.Errorf("%s: block %d: %v", leg.name, i, err)
			}
		}
	}
}

func TestMessageCircuitChecksTheReplies(t *testing.T) {
	t.Parallel()
	// Z8 for pi3: the same streams the relation's tests use
	cases := []struct {
		name    string
		content string
		accept  bool
	}{
		{name: "all accepted", content: "250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n250 2.1.5 Ok\r\n", accept: true},
		{name: "a multiline reply", content: "250-2.1.0 Ok\r\n250 go on\r\n250 2.1.5 Ok\r\n250 2.1.5 Ok\r\n", accept: true},
		{name: "a refused MAIL", content: "550 5.7.1 Refused\r\n250 2.1.5 Ok\r\n250 2.1.5 Ok\r\n"},
		{name: "a refused RCPT", content: "250 2.1.0 Ok\r\n550 5.1.1 Unknown\r\n250 2.1.5 Ok\r\n"},
		{name: "a deferred RCPT", content: "250 2.1.0 Ok\r\n451 4.3.0 Later\r\n250 2.1.5 Ok\r\n"},
		{name: "a missing reply", content: "250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n"},
		{name: "an extra reply", content: "250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n250 2.1.5 Ok\r\n250 Ok\r\n"},
		{name: "a truncated reply", content: "250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n250 2.1"},
	}
	for _, leg := range testTlsLegs() {
		shape := testQuickMessageShape(leg.suites[0], 0)
		compiled := testCompileShape(t, shape)
		capture := testBdatCapture(t, leg)
		for _, c := range cases {
			statement, witness := capture.part(t, 3)
			statement.serverRecords = statement.serverRecords[:1]
			witness.serverPlaintexts = witness.serverPlaintexts[:1]
			testAuthorServerRecord(t, statement, witness, 0, testServerContent(statement, c.content))
			if reference := len(relationCheckPart(statement, witness)) == 0; reference != c.accept {
				t.Errorf("%s: %s: the relation says %v", leg.name, c.name, reference)
			}
			if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); (err == nil) != c.accept {
				t.Errorf("%s: %s: the circuit says %v", leg.name, c.name, err)
			}
		}
	}
}

func TestMessageCircuitChecksTheBdatEnd(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		shape := testQuickMessageShape(leg.suites[0], 0)
		compiled := testCompileShape(t, shape)
		capture := testBdatCapture(t, leg)
		// same-length records, so only their octets differ from what the public template wants
		for _, c := range []struct {
			record  int
			content string
		}{
			{record: 2, content: "RSET\r\n"},
			{record: 0, content: strings.Replace(string(clientContent(capture.statements[2].session.version, capture.witnesses[2].clientPlaintexts[0])), "LAST", "XXXX", 1)},
		} {
			statement, witness := capture.part(t, 3)
			testAuthorClientRecord(t, statement, witness, c.record, []byte(c.content))
			if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
				t.Errorf("%s: %q: accepted", leg.name, c.content)
			}
		}
	}
}

func TestMessageCircuitChecksDataFraming(t *testing.T) {
	t.Parallel()
	// Z6 differentially: the same smuggled DATA ends as relation_test.go
	cases := []struct {
		name    string
		content string
		accept  bool
	}{
		{name: "whole lines", content: "first\r\nsecond\r\n", accept: true},
		{name: "a dot-stuffed line", content: "first\r\n..\r\n.leading dot\r\n", accept: true},
		{name: "the end mark inside the record", content: "first\r\n.\r\nMAIL FROM:<x@b.example>\r\n"},
		{name: "an end mark at the record's start", content: ".\r\nMAIL FROM:<x@b.example>\r\n"},
		{name: "a bare-LF end", content: "first\n.\nMAIL FROM:<x@b.example>\r\n"},
		{name: "a bare-LF dot before CRLF", content: "first\n.\r\n"},
		{name: "a bare-CR end", content: "first\r.\r\n"},
		{name: "a record ending inside a line", content: "first\r\nunfinished"},
	}
	for _, leg := range testTlsLegs() {
		bodyBlocks := 6
		if leg.suites[0] == tlsSuiteChacha20Poly1305Sha256 {
			bodyBlocks = 2
		}
		shape := testQuickMessageShape(leg.suites[0], bodyBlocks)
		compiled := testCompileShape(t, shape)
		capture := testDataCapture(t, leg)
		for _, c := range cases {
			statement, witness := capture.part(t, 3)
			testAuthorClientRecord(t, statement, witness, 1, []byte(c.content))
			// the declared count follows the body, so Z6's framing alone decides this
			if reference := relationZ6(statement, witness) == nil; reference != c.accept {
				t.Errorf("%s: %s: the relation says %v", leg.name, c.name, reference)
			}
			if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); (err == nil) != c.accept {
				t.Errorf("%s: %s: the circuit says %v", leg.name, c.name, err)
			}
		}
	}
}

func TestMessageCircuitRequiresThe354(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		bodyBlocks := 6
		if leg.suites[0] == tlsSuiteChacha20Poly1305Sha256 {
			bodyBlocks = 2
		}
		shape := testQuickMessageShape(leg.suites[0], bodyBlocks)
		compiled := testCompileShape(t, shape)
		capture := testDataCapture(t, leg)
		solve := func(content string) error {
			statement, witness := capture.part(t, 3)
			statement.serverRecords = statement.serverRecords[:1]
			witness.serverPlaintexts = witness.serverPlaintexts[:1]
			testAuthorServerRecord(t, statement, witness, 0, testServerContent(statement, content))
			return testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness))
		}
		if err := solve("250 Ok\r\n250 Ok\r\n250 Ok\r\n354 Go\r\n"); err != nil {
			t.Errorf("%s: an honest 354: %v", leg.name, err)
		}
		for _, content := range []string{"250 Ok\r\n250 Ok\r\n250 Ok\r\n250 Go\r\n", "250 Ok\r\n250 Ok\r\n250 Ok\r\n355 Go\r\n", "250 Ok\r\n250 Ok\r\n354 Go\r\n354 Go\r\n"} {
			if err := solve(content); err == nil {
				t.Errorf("%s: %q: accepted", leg.name, content)
			}
		}
	}
}

// A real TLS 1.2 connection's shape, with Z1 in it: the key schedule is what is under test.
func test12Shape() *partShape {
	return &partShape{kind: partKindEhlo, version: tlsVersion12, suite: tlsSuiteEcdheEcdsaAes128GcmSha256, clientBlocks: 4}
}

func TestZ1CircuitIn12DerivesARealConnectionsKeys(t *testing.T) {
	t.Parallel()
	leg := testTlsLegs()[2]
	shape := test12Shape()
	compiled := testCompileShape(t, shape)
	t.Logf("pi1 in TLS 1.2: %d constraints", compiled.GetNbConstraints())
	capture := testBdatCapture(t, leg)
	statement, witness := capture.part(t, 1)
	if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err != nil {
		t.Fatal(err)
	}

	// mutated witnesses and handshake inputs, each refused here as relation_test.go refuses it
	mutations := []struct {
		name   string
		mutate func(statement *partStatement, witness *partWitness)
	}{
		{name: "another master secret", mutate: func(statement *partStatement, witness *partWitness) { witness.masterSecret[0] ^= 1 }},
		{name: "another server random", mutate: func(statement *partStatement, witness *partWitness) {
			statement.session.serverRandom = bytes.Clone(statement.session.serverRandom)
			statement.session.serverRandom[0] ^= 1
		}},
		{name: "another SF", mutate: func(statement *partStatement, witness *partWitness) {
			statement.session.serverFinishedRecord = bytes.Clone(statement.session.serverFinishedRecord)
			statement.session.serverFinishedRecord[tlsRecordHeaderBytes+tlsExplicitNonceBytes] ^= 1
		}},
		{name: "another SF nonce", mutate: func(statement *partStatement, witness *partWitness) {
			statement.session.serverFinishedRecord = bytes.Clone(statement.session.serverFinishedRecord)
			statement.session.serverFinishedRecord[tlsRecordHeaderBytes] ^= 1
		}},
		{name: "another transcript", mutate: func(statement *partStatement, witness *partWitness) {
			state := *statement.session.preFinishedState
			state.chaining[0] ^= 1
			statement.session.preFinishedState = &state
		}},
	}
	for _, mutation := range mutations {
		statement, witness := capture.part(t, 1)
		mutation.mutate(statement, witness)
		if err := testPartSolved(t, compiled, testPartAssignment(t, shape, statement, witness)); err == nil {
			t.Errorf("%s: accepted", mutation.name)
		}
	}
}

// S_ckx resumed over a client Finished, on its own: all that depends on the tail's length.
type testResumeCircuit struct {
	ClientFinished  []frontend.Variable
	Chaining        []frontend.Variable `gnark:",public"`
	ResumeBase      []frontend.Variable `gnark:",public"`
	ResumeShift     []frontend.Variable `gnark:",public"`
	ResumeTwoBlocks frontend.Variable   `gnark:",public"`
	Digest          []frontend.Variable `gnark:",public"`
}

func (self *testResumeCircuit) Define(api frontend.API) error {
	inputs := &circuitInputs12{resumeBase: publicBytes(self.ResumeBase), resumeShift: self.ResumeShift, resumeTwoBlocks: self.ResumeTwoBlocks}
	for i := range inputs.chaining {
		copy(inputs.chaining[i][:], self.Chaining[32*i:32*i+32])
	}
	testAssertBytesEqual(api, inputs.resumedHash(api, testByteWires(api, self.ClientFinished)), testByteWires(api, self.Digest))
	return nil
}

func TestZ1CircuitIn12CoversEveryTailLength(t *testing.T) {
	t.Parallel()
	// the client Finished's offset depends on the transcript's length, and so on which blocks it
	// falls in: a real handshake lands on one tail length, so this walks all 64 over a synthetic one.
	// Each runs on the resume alone, which is what varies. The lengths around the one-block limit and
	// at the ends also run through a whole shape, where the rest of Z1 meets them
	shape := test12Shape()
	compiled := testCompileShape(t, shape)
	resume := testCompile(t, &testResumeCircuit{
		ClientFinished: make([]frontend.Variable, 8*(4+tlsVerifyData12Bytes)),
		Chaining:       make([]frontend.Variable, 8*tlsSecretBytes),
		ResumeBase:     make([]frontend.Variable, 8*2*sha256BlockBytes),
		ResumeShift:    make([]frontend.Variable, 6),
		Digest:         make([]frontend.Variable, 8*tlsSecretBytes),
	})
	leg := testTlsLegs()[2]
	capture := testBdatCapture(t, leg)
	for tail := range 64 {
		statement, witness := capture.part(t, 1)
		session := statement.session
		messages := make([]byte, 3*sha256BlockBytes+tail)
		for i := range messages {
			messages[i] = byte(11*i + tail)
		}
		state, err := newSha256State(messages)
		if err != nil {
			t.Fatal(err)
		}
		session.preFinishedState = state
		// the record the MX would have sent for this transcript
		clientHash, err := state.finish(nil)
		if err != nil {
			t.Fatal(err)
		}
		clientFinished := tls12FinishedMessage(witness.masterSecret, tlsLabelClientFinished, clientHash)
		serverHash, err := state.finish(clientFinished)
		if err != nil {
			t.Fatal(err)
		}
		record := &partRecord{raw: bytes.Clone(session.serverFinishedRecord)}
		testSeal(t, statement, record, witness.serverKey, witness.serverIv, tls12FinishedMessage(witness.masterSecret, tlsLabelServerFinished, serverHash))
		session.serverFinishedRecord = record.raw
		if failures := relationCheckPart(statement, witness); len(failures) != 0 {
			t.Fatalf("tail %d: %v", tail, failures)
		}

		public := testPartAssignment(t, shape, statement, witness)
		assignment := func(digest []byte) *testResumeCircuit {
			return &testResumeCircuit{
				ClientFinished:  testAssignBits(clientFinished),
				Chaining:        public.Chaining,
				ResumeBase:      public.ResumeBase,
				ResumeShift:     public.ResumeShift,
				ResumeTwoBlocks: public.ResumeTwoBlocks,
				Digest:          testAssignBits(digest),
			}
		}
		if err := testSolved(t, resume, assignment(serverHash)); err != nil {
			t.Errorf("tail %d: %v", tail, err)
		}
		serverHash[0] ^= 1
		if err := testSolved(t, resume, assignment(serverHash)); err == nil {
			t.Errorf("tail %d: accepted another digest", tail)
		}
		if slices.Contains([]int{0, 39, 40, 63}, tail) {
			if err := testPartSolved(t, compiled, public); err != nil {
				t.Errorf("tail %d through the whole shape: %v", tail, err)
			}
		}
	}
}

func TestAShapeWithoutTheLocalTableRefusesATemplateThatNeedsIt(t *testing.T) {
	// its IsLocal wires go unread on such a shape, so a local position there must not assign at all
	leg := testTlsLegs()[0]
	shape := testQuickShape(leg.suites[0], false)
	capture := testBdatCapture(t, leg)
	statement, _ := capture.part(t, 2)
	template, err := clientRecordTemplate(statement.session, recordRoleMail, statement.clientRecords[0])
	if err != nil {
		t.Fatal(err)
	}
	circuit := newZeroAssignment(shape)
	if _, err := assignRecordBlocks(shape, statement, statement.clientRecords[0], template, circuit.Client); err == nil {
		t.Error("a local position assigned on a shape that ignores it")
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
	t.Parallel()
	// SPEC.md 10.2's zero knowledge argument is vanilla Groth16's: a commitment would need its own.
	// Compiling every production shape takes minutes, so this covers each gadget through the quick
	// shapes, and TestMeasureShapes covers the production ones.
	for _, shape := range []*partShape{
		testQuickEnvelopeShape(tlsSuiteAes128GcmSha256),
		testQuickMessageShape(tlsSuiteChacha20Poly1305Sha256, 2),
		test12Shape(),
	} {
		commitments := testCompileShape(t, shape).GetCommitments()
		if commitments != nil && len(commitments.CommitmentIndexes()) != 0 {
			t.Errorf("%+v carries %d commitments", shape, len(commitments.CommitmentIndexes()))
		}
	}
}

func TestUnknownPartsFailClosed(t *testing.T) {
	backend := newGroth16Backend()
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		// these parts have circuits, and no keys are loaded here
		for _, index := range []uint32{1, 2, 3} {
			statement, witness := capture.part(t, index)
			if _, err := backend.provePart(context.Background(), statement, witness); err == nil {
				t.Errorf("%s: proved part %d", leg.name, index)
			}
			if err := backend.verifyPart(context.Background(), statement, []byte("not a proof")); err == nil {
				t.Errorf("%s: verified part %d", leg.name, index)
			}
		}

		// keys that hold neither half refuse too, rather than reach gnark with a nil key
		statement, witness := capture.part(t, 1)
		shape, err := partShapeFor(statement)
		if err != nil {
			t.Fatal(err)
		}
		halfLoaded := newGroth16Backend()
		halfLoaded.addKeys(&shapeKeys{shape: shape})
		if _, err := halfLoaded.provePart(context.Background(), statement, witness); !errors.Is(err, errNoKeys) {
			t.Errorf("%s: proving with no key: %v", leg.name, err)
		}
		if err := halfLoaded.verifyPart(context.Background(), statement, []byte("not a proof")); !errors.Is(err, errNoKeys) {
			t.Errorf("%s: verifying with no key: %v", leg.name, err)
		}
	}
}

func TestVerifierRefusesAPreambleATemplateCouldCarryMoreThan(t *testing.T) {
	// a template is a literal, so a declared value that can end a path or a line would put a command
	// of the sidecar's own into what the circuit then proves
	cases := []struct {
		name     string
		mutation func(preamble *sidecar.SmtpProofPreamble)
	}{
		{name: "no recipient", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.RecipientCount = 0 }},
		{name: "a recipient domain ending the path", mutation: func(preamble *sidecar.SmtpProofPreamble) {
			preamble.RecipientDomain = "a.example>\r\nRCPT TO:<victim@other.example"
		}},
		{name: "a recipient domain with a parameter", mutation: func(preamble *sidecar.SmtpProofPreamble) {
			preamble.RecipientDomain = "a.example> NOTIFY=NEVER"
		}},
		{name: "an empty recipient domain", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.RecipientDomain = "" }},
		{name: "a label starting with a hyphen", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.RecipientDomain = "-a.example" }},
		{name: "a label ending with a hyphen", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.RecipientDomain = "a-.example" }},
		{name: "an empty label", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.RecipientDomain = "a..example" }},
		{name: "a trailing dot", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.RecipientDomain = "a.example." }},
		{name: "a label past 63 octets", mutation: func(preamble *sidecar.SmtpProofPreamble) {
			preamble.RecipientDomain = strings.Repeat("a", 64) + ".example"
		}},
		{name: "a domain past 255 octets", mutation: func(preamble *sidecar.SmtpProofPreamble) {
			preamble.RecipientDomain = strings.Repeat("a.", 128) + "example"
		}},
		{name: "a From domain ending the line", mutation: func(preamble *sidecar.SmtpProofPreamble) {
			preamble.HeaderFromDomain = "a.example>\r\nX: <b"
		}},
		{name: "a selector with a tag in it", mutation: func(preamble *sidecar.SmtpProofPreamble) {
			preamble.DkimSelector = "s1; d=victim.example"
		}},
		{name: "a Message-ID ending the field", mutation: func(preamble *sidecar.SmtpProofPreamble) {
			preamble.MessageId = "a@b>\r\nX: <c@d"
		}},
		{name: "a Message-ID with no @", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.MessageId = "ab" }},
		{name: "a Message-ID with two", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.MessageId = "a@b@c" }},
		{name: "an issued reference with a space", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.XUrRef = "1.A B" }},
		{name: "an issued Feedback-ID with a CRLF", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.FeedbackId = "a\r\nb" }},
		{name: "an empty HELO name", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.HeloName = "" }},
		{name: "no envelope domain", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.EnvelopeDomain = "" }},
		{name: "no MX host", mutation: func(preamble *sidecar.SmtpProofPreamble) { preamble.MxHost = "" }},
	}
	verifier := NewVerifier(DefaultVerifierSettings())
	if _, err := verifier.NewSmtpProofSession(testJob("x\r\n", "bob").Preamble); err != nil {
		t.Fatalf("an honest preamble: %v", err)
	}
	for _, c := range cases {
		preamble := testJob("x\r\n", "bob").Preamble
		c.mutation(preamble)
		if _, err := verifier.NewSmtpProofSession(preamble); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestNewProverAndVerifierRefuseEveryPartUntilKeysLoad(t *testing.T) {
	// what cli/ and server get today: an injected module that sends and passes no mail
	for _, leg := range testTlsLegs() {
		job := testJob("one line\r\n", "bob")
		backend := newGroth16Backend()
		send := testRunSendWith(t, leg, testMxDefaults(), DefaultProverSettings(), job, backend, backend)
		if send.err == nil || !strings.Contains(send.err.Error(), errNoKeys.Error()) {
			t.Errorf("%s: %v", leg.name, send.err)
		}
		if len(send.mx.transactions()) != 0 {
			t.Errorf("%s: a transaction was accepted", leg.name)
		}
		// nothing past the handshake reached the MX: its first command needed a proof
		if commands := send.mx.seen(); len(commands) != 0 {
			t.Errorf("%s: %v reached the MX", leg.name, commands)
		}
	}
	verifier := NewVerifier(DefaultVerifierSettings())
	if _, err := verifier.NewSmtpProofSession(&sidecar.SmtpProofPreamble{}); err == nil {
		t.Error("a session opened without the edge's own values")
	}
	session, err := verifier.NewSmtpProofSession(testJob("x\r\n", "bob").Preamble)
	if err != nil || session == nil {
		t.Errorf("%v", err)
	}
}

// Runs a test-only setup for a shape, which is the slow step here.
func testSetup(t *testing.T, shape *partShape) *shapeKeys {
	t.Helper()
	compiled := testCompileShape(t, shape)
	provingKey, verifyingKey, err := groth16.Setup(compiled)
	if err != nil {
		t.Fatal(err)
	}
	return &shapeKeys{shape: shape, compiled: compiled, provingKey: provingKey, verifyingKey: verifyingKey}
}

func TestGroth16ProofOfARealEhlo(t *testing.T) {
	t.Parallel()
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
	_, err = backend.provePart(context.Background(), statement, witness)
	if err == nil {
		t.Fatal("proved a witness with another HS")
	}
	// gnark's solver writes wire values into its errors, and those wires are keys and plaintext
	if errors.Unwrap(err) != nil || strings.Contains(err.Error(), "constraint") {
		t.Errorf("a failed proof carried the solver's error: %v", err)
	}
}

// A shape small enough for a real ceremony in a test.
type testSetupCircuit struct {
	Secret frontend.Variable
	Public frontend.Variable `gnark:",public"`
}

func (self *testSetupCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(self.Secret, self.Secret), self.Public)
	return nil
}

func TestDecodeProofRefusesWhatGnarkWouldAllocateFor(t *testing.T) {
	// gnark's ReadFrom allocates the commitment count a proof declares before reading one, so a few
	// hostile octets could ask an edge for 256 GiB. decodeProof reads the fixed form and nothing else
	var g1 bn254.G1Affine
	var g2 bn254.G2Affine
	g1.ScalarMultiplicationBase(big.NewInt(3))
	g2.ScalarMultiplicationBase(big.NewInt(5))
	first := g1.Bytes()
	second := g2.Bytes()
	uncompressed := g1.RawBytes()
	var pok bn254.G1Affine
	pokBytes := pok.Bytes()
	valid := slices.Concat(first[:], second[:], first[:], make([]byte, 4), pokBytes[:])
	if _, err := decodeProof(valid); err != nil {
		t.Fatal(err)
	}
	count := bytes.Clone(valid)
	count[len(first)+len(second)+len(first)] = 0xff
	shifted := slices.Concat(uncompressed[:], second[:], first[:], []byte{0xff, 0xff, 0xff, 0xff})
	badPoint := bytes.Clone(valid)
	badPoint[1] ^= 1
	for name, encoded := range map[string][]byte{
		"empty":                       nil,
		"short":                       valid[:len(valid)-1],
		"long":                        append(bytes.Clone(valid), 0),
		"a declared commitment":       count,
		"an uncompressed Ar":          shifted,
		"a point off the curve":       badPoint,
		"a proof of knowledge of one": slices.Concat(first[:], second[:], first[:], make([]byte, 4), first[:]),
	} {
		if _, err := decodeProof(encoded); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifiedSetupGivesKeysThatProve(t *testing.T) {
	compiled := testCompile(t, &testSetupCircuit{})
	transcript, err := runSetup(compiled, []byte("a synthetic beacon"))
	if err != nil {
		t.Fatal(err)
	}
	provingKey, verifyingKey, err := verifySetup(compiled, transcript)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(&testSetupCircuit{Secret: 3, Public: 9}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(compiled, provingKey, witness)
	if err != nil {
		t.Fatal(err)
	}
	public, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, verifyingKey, public); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySetupRefusesWhatIsNotTheCeremony(t *testing.T) {
	compiled := testCompile(t, &testSetupCircuit{})
	transcript, err := runSetup(compiled, []byte("a synthetic beacon"))
	if err != nil {
		t.Fatal(err)
	}
	// no contribution at all: an edge that offers keys with nothing behind them
	if _, _, err := verifySetup(compiled, &setupTranscript{beacon: transcript.beacon}); err == nil {
		t.Error("verified an empty transcript")
	}
	// the same transcript verifies twice, so a refusal below is the mutation's and nothing else's
	if _, _, err := verifySetup(compiled, transcript); err != nil {
		t.Fatalf("the honest transcript: %v", err)
	}
	if _, _, err := verifySetup(compiled, transcript); err != nil {
		t.Fatalf("the honest transcript, again: %v", err)
	}
	// a contribution changed by one octet at any depth
	for _, offset := range []int{40, 100, 200, 500} {
		for _, phase := range []int{1, 2} {
			tampered := &setupTranscript{beacon: transcript.beacon, phase1: transcript.phase1, phase2: transcript.phase2}
			target := &tampered.phase2
			if phase == 1 {
				target = &tampered.phase1
			}
			changed := bytes.Clone((*target)[0])
			if offset < len(changed) {
				changed[offset] ^= 1
				*target = [][]byte{changed}
				if _, _, err := verifySetup(compiled, tampered); err == nil {
					t.Errorf("phase %d: verified with octet %d changed", phase, offset)
				}
			}
		}
	}
	// a phase 2 contributed for another circuit: keys that are not this relation's
	other := testCompile(t, &testSetupOtherCircuit{})
	otherTranscript, err := runSetup(other, transcript.beacon)
	if err != nil {
		t.Fatal(err)
	}
	mixed := &setupTranscript{beacon: transcript.beacon, phase1: transcript.phase1, phase2: otherTranscript.phase2}
	if _, _, err := verifySetup(compiled, mixed); err == nil {
		t.Error("verified another circuit's phase 2")
	}
	// another phase 1 under a phase 2 it never fed
	mixed = &setupTranscript{beacon: transcript.beacon, phase1: otherTranscript.phase1, phase2: transcript.phase2}
	if _, _, err := verifySetup(compiled, mixed); err == nil {
		t.Error("verified a phase 2 against another phase 1")
	}
}

// As testSetupCircuit, with one more constraint, so its keys differ.
type testSetupOtherCircuit struct {
	Secret frontend.Variable
	Public frontend.Variable `gnark:",public"`
}

func (self *testSetupOtherCircuit) Define(api frontend.API) error {
	square := api.Mul(self.Secret, self.Secret)
	api.AssertIsEqual(api.Mul(square, self.Secret), self.Public)
	return nil
}

func TestSetupRefusesACircuitWithACommitment(t *testing.T) {
	compiled := testCompile(t, &testCommittingCircuit{})
	if _, err := runSetup(compiled, []byte("a synthetic beacon")); err == nil || !strings.Contains(err.Error(), "commitment") {
		t.Errorf("err %v", err)
	}
}

// A circuit with a commitment, which SPEC.md 10.2 has no argument for.
type testCommittingCircuit struct {
	Secret frontend.Variable
	Public frontend.Variable `gnark:",public"`
}

func (self *testCommittingCircuit) Define(api frontend.API) error {
	committer, ok := api.(frontend.Committer)
	if !ok {
		return nil
	}
	commitment, err := committer.Commit(self.Secret)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(commitment, 0)
	api.AssertIsEqual(self.Secret, self.Public)
	return nil
}

// Compiles every production shape, which takes minutes, so it stays out of the ordinary run: set
// SMTPPROOF_MEASURE_SHAPES. It holds each to SPEC.md 10.2's rule, and its output is SPEC.md 11.2's.
func TestMeasureShapes(t *testing.T) {
	if os.Getenv("SMTPPROOF_MEASURE_SHAPES") == "" {
		t.Skip("set SMTPPROOF_MEASURE_SHAPES to run")
	}
	for _, shape := range partShapes() {
		compiled, err := compilePartShape(shape)
		if err != nil {
			t.Fatal(err)
		}
		if commitments := compiled.GetCommitments(); commitments != nil && len(commitments.CommitmentIndexes()) != 0 {
			t.Errorf("%+v carries %d commitments", *shape, len(commitments.CommitmentIndexes()))
		}
		t.Logf("kind %d version %#x suite %#x client %d server %d header %d body %d: %d constraints, %d public inputs",
			shape.kind, shape.version, shape.suite, shape.clientBlocks, shape.serverBlocks, shape.headerBlocks, shape.bodyBlocks,
			compiled.GetNbConstraints(), compiled.GetNbPublicVariables())
	}
}

// Measures every part of whole sends under real Groth16, through the real gate, with a real test-only
// setup. SMTPPROOF_MEASURE names the legs to run, as tls13-aes, tls13-chacha, tls12-aes; this takes
// minutes, so it stays out of the ordinary run. Each leg sends D-SMTP-16's BDAT case, then unless
// SMTPPROOF_MEASURE_BDAT_ONLY is set a DATA send of the same header block and three body parts, which
// is enough to price a part: D-SMTP-16's 100 KiB is that part's cost times the parts it takes. Its
// output is SPEC.md 11.3's source.
func TestMeasureWholeSend(t *testing.T) {
	legs := os.Getenv("SMTPPROOF_MEASURE")
	if legs == "" {
		t.Skip("set SMTPPROOF_MEASURE to run")
	}
	for _, leg := range testTlsLegs() {
		if !strings.Contains(legs, strings.ReplaceAll(leg.name, " ", "-")) {
			continue
		}
		// D-SMTP-16's BDAT case: a 4 KiB header block and 10 recipients
		recipients := []string{"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"}
		padding := strings.Repeat("X-Padding: a line of filler to reach the gate's header size\r\n", 58)
		measuring := &testMeasuringBackend{t: t, backend: newGroth16Backend(), kinds: map[partShape]bool{}}
		send := func(body string, settings *ProverSettings, mode string) {
			message := padding + testHeaderBlock() + body
			job := testJob("", recipients...)
			job.Message = []byte(message)
			job.Preamble.MessageByteCount = uint64(len(message))
			t.Logf("%s %s: header block %d octets, body %d octets", leg.name, mode, strings.Index(message, "\r\n\r\n")+4, len(body))
			measuring.provingTotal = 0
			measuring.cpuTotal = 0
			result := testRunSendWith(t, leg, testMxDefaults(), settings, job, measuring, measuring)
			testExpectOneTransaction(t, leg, result, job)
			t.Logf("%s %s: whole send proved and accepted; proving took %v wall, %v cpu", leg.name, mode, measuring.provingTotal.Round(10*time.Millisecond), measuring.cpuTotal.Round(10*time.Millisecond))
		}
		send("a body line\r\n", DefaultProverSettings(), "bdat")
		if os.Getenv("SMTPPROOF_MEASURE_BDAT_ONLY") == "" {
			settings := DefaultProverSettings()
			settings.ForceData = true
			send(strings.Repeat("a line of body text, whole and ending as a DATA record must\r\n", 100), settings, "data")
		}
	}
}

// Sets a shape up the first time it is needed, and measures each part. Wall time depends on what
// else the machine is running, so CPU time is the figure to read, and memory comes from a separate
// process that only loads the key and proves, as a prover host would.
type testMeasuringBackend struct {
	t            *testing.T
	backend      *groth16Backend
	kinds        map[partShape]bool
	provingTotal time.Duration
	cpuTotal     time.Duration
}

// CPU time this process has used so far.
func testCpuTime(t *testing.T) time.Duration {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

// Counts what passes through it.
type testByteCounter struct {
	count int64
}

func (self *testByteCounter) Write(data []byte) (int, error) {
	self.count += int64(len(data))
	return len(data), nil
}

func (self *testMeasuringBackend) provePart(ctx context.Context, statement *partStatement, witness *partWitness) ([]byte, error) {
	shape, err := partShapeFor(statement)
	if err != nil {
		return nil, err
	}
	if !self.kinds[*shape] {
		self.kinds[*shape] = true
		start := time.Now()
		keys := testSetup(self.t, shape)
		self.backend.addKeys(keys)
		provingBytes := &testByteCounter{}
		if _, err := keys.provingKey.WriteTo(provingBytes); err != nil {
			return nil, err
		}
		verifyingBytes := &testByteCounter{}
		if _, err := keys.verifyingKey.WriteTo(verifyingBytes); err != nil {
			return nil, err
		}
		self.t.Logf("part %d: %d constraints, %d public inputs, proving key %d MiB, verifying key %d KiB, setup %v",
			statement.index, keys.compiled.GetNbConstraints(), keys.compiled.GetNbPublicVariables(),
			provingBytes.count/1024/1024, verifyingBytes.count/1024, time.Since(start).Round(time.Second))
		self.measureProveOnly(shape, keys, statement, witness)
	}
	cpuStart := testCpuTime(self.t)
	start := time.Now()
	proof, err := self.backend.provePart(ctx, statement, witness)
	elapsed := time.Since(start)
	cpu := testCpuTime(self.t) - cpuStart
	if err != nil {
		return nil, err
	}
	self.t.Logf("part %d: proved in %v wall, %v cpu, %d octets", statement.index, elapsed.Round(10*time.Millisecond), cpu.Round(10*time.Millisecond), len(proof))
	self.provingTotal += elapsed
	self.cpuTotal += cpu
	return proof, nil
}

// Writes what a prover host holds to files, and proves from them in a fresh process.
func (self *testMeasuringBackend) measureProveOnly(shape *partShape, keys *shapeKeys, statement *partStatement, witness *partWitness) {
	t := self.t
	directory := t.TempDir()
	write := func(name string, value io.WriterTo) {
		file, err := os.Create(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := value.WriteTo(file); err != nil {
			t.Fatal(err)
		}
	}
	circuit, err := partAssignment(shape, statement)
	if err != nil {
		t.Fatal(err)
	}
	assignWitness(circuit, statement, witness)
	full, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	write("compiled", keys.compiled)
	write("key", keys.provingKey)
	write("witness", full)
	command := exec.Command(os.Args[0], "-test.run=^TestMeasureProveOnly$", "-test.v")
	command.Env = append(os.Environ(), "SMTPPROOF_PROVE_DIR="+directory)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("prove-only process: %v: %s", err, output)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "prove-only:") {
			t.Logf("part %d: %s", statement.index, strings.TrimSpace(line[strings.Index(line, "prove-only:"):]))
		}
	}
}

// The child of measureProveOnly: reads a compiled circuit, key and witness, and proves once.
func TestMeasureProveOnly(t *testing.T) {
	directory := os.Getenv("SMTPPROOF_PROVE_DIR")
	if directory == "" {
		t.Skip("run by TestMeasureWholeSend")
	}
	read := func(name string, value io.ReaderFrom) {
		file, err := os.Open(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if _, err := value.ReadFrom(bufio.NewReaderSize(file, 1024*1024)); err != nil {
			t.Fatal(err)
		}
	}
	compiled := groth16.NewCS(ecc.BN254)
	read("compiled", compiled)
	provingKey := groth16.NewProvingKey(ecc.BN254)
	read("key", provingKey)
	full, err := gnarkwitness.New(ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	read("witness", full)
	cpuStart := testCpuTime(t)
	start := time.Now()
	if _, err := groth16.Prove(compiled, provingKey, full); err != nil {
		t.Fatal(err)
	}
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	// ru_maxrss is in octets on darwin
	t.Logf("prove-only: %v wall, %v cpu, peak %d MiB", time.Since(start).Round(10*time.Millisecond), (testCpuTime(t) - cpuStart).Round(10*time.Millisecond), usage.Maxrss/1024/1024)
}

func (self *testMeasuringBackend) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	start := time.Now()
	err := self.backend.verifyPart(ctx, statement, proof)
	self.t.Logf("part %d: verified in %v: %v", statement.index, time.Since(start).Round(time.Millisecond), err)
	if err != nil {
		return fmt.Errorf("measuring: %w", err)
	}
	return nil
}
