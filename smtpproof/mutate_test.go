// The mutated witnesses of §22.10: for each of E1 to E3 and Z1 to Z9, in each TLS version and mode the
// check applies to, a break of one honest connection that only that check refuses. "Only that check"
// is the point, since a break that trips two checks shows neither doing work the other does not. Each
// break must be pinned on one check, the same one, by two readers written apart: the gate, whose
// verifier is relationCheckPart over the edge's own statement, so that a part it refuses names every
// check of the relation failing there; and smtpproof/checker, which reads SPEC.md and nothing of this
// module. Then a Z break must be refused by the circuit at its part, and an E break by edgeSession on
// its own, before any circuit is asked.
//
// mutate_edge_test.go runs the E rows and mutate_circuit_test.go the Z rows, one test a check.
// TestMutatedWitnessTable holds this registry to every cell, and to testdata/mutations/table.md, the
// evidence table M9's review reads.

package smtpproof_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/smtpproof"
)

// Every check §22.10 asks a mutation for, in SPEC.md's order.
var testMutationChecks = []string{"E1", "E2", "E3", "Z1", "Z2", "Z3", "Z4", "Z5", "Z6", "Z7", "Z8", "Z9"}

// A break of an honest capture that one check alone must refuse.
type testMutation struct {
	check string
	name  string
	// Whether the break applies to a leg and mode. Nil is every one.
	applies func(c *testLegCase) bool
	// The part a Z break's circuit refuses. Unused for an E break, which the gate refuses itself.
	part   func(c *testLegCase) uint32
	mutate func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture)
}

// A cell of the table: a check, a TLS version and a mode.
type testMutationCell struct {
	check string
	tls12 bool
	data  bool
}

func (self testMutationCell) String() string {
	version, mode := "1.3", "BDAT"
	if self.tls12 {
		version = "1.2"
	}
	if self.data {
		mode = "DATA"
	}
	return fmt.Sprintf("%s %s %s", self.check, version, mode)
}

// Cells no witness can break alone, each with why. A cell here may hold no mutation, and a cell not
// here must hold one.
func testInapplicableCells() map[testMutationCell]string {
	cells := map[testMutationCell]string{}
	for _, data := range []bool{false, true} {
		cells[testMutationCell{check: "Z3", tls12: true, data: data}] = "1.2's Z3 holds nothing private: the outer type is public, which E1 checks on the stream and E3 on a part's records before any verification (see E3's rows), and the plaintext's length is the record's, which Z2 fixes"
		cells[testMutationCell{check: "Z7", tls12: true, data: data}] = "1.2's server record types are public: E1 refuses any but application_data after the handshake and an alert closes the connection (see E1's rows), and a record opens at its own sequence number by Z2"
	}
	for _, tls12 := range []bool{false, true} {
		cells[testMutationCell{check: "Z9", tls12: tls12, data: true}] = "DATA has no Z9 condition: DATA to an MX offering CHUNKING is allowed (SPEC.md Z9)"
	}
	return cells
}

func testTls13Only(c *testLegCase) bool {
	return !c.tls12
}

func testBdatOnly(c *testLegCase) bool {
	return !c.data
}

func testDataOnly(c *testLegCase) bool {
	return c.data
}

func testPartAt(index uint32) func(c *testLegCase) uint32 {
	return func(c *testLegCase) uint32 { return index }
}

func testPartByMode(bdat uint32, data uint32) func(c *testLegCase) uint32 {
	return func(c *testLegCase) uint32 {
		if c.data {
			return data
		}
		return bdat
	}
}

// Replaces, in the stream, every copy of a client record with what edit makes of a clone of it.
func testEditStreamRecord(capture *smtpproof.ExportedCapture, record []byte, edit func(record []byte)) {
	for _, event := range capture.Events {
		if bytes.Equal(event.ClientRecord, record) {
			edited := bytes.Clone(record)
			edit(edited)
			event.ClientRecord = edited
		}
	}
}

// As testRewriteClientRecord, with the whole plaintext given, 1.3's type octet included.
func testRewriteClientPlaintext(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture, partEvent int, i int, plaintext []byte) {
	t.Helper()
	part := capture.Events[partEvent].Part
	witness := capture.Witnesses[partEvent]
	seq := part.FirstRecord + uint64(i)
	if part.Mode == 1 && part.Index == 3 && i == len(part.Records)-1 {
		seq = part.LastRecord
	}
	original := part.Records[i]
	sealed := testSealRecord(t, c.tls12, witness.ClientKey, witness.ClientIv, seq, plaintext)
	clone := *part
	clone.Records = slices.Clone(part.Records)
	clone.Records[i] = sealed
	capture.Events[partEvent].Part = &clone
	witness.ClientPlaintexts = slices.Clone(witness.ClientPlaintexts)
	witness.ClientPlaintexts[i] = plaintext
	for _, event := range capture.Events {
		if bytes.Equal(event.ClientRecord, original) {
			event.ClientRecord = sealed
		}
	}
}

// A record's content: its plaintext less 1.3's type octet.
func testRecordContent(c *testLegCase, plaintext []byte) []byte {
	if c.tls12 {
		return plaintext
	}
	return plaintext[:len(plaintext)-1]
}

// Replaces the plaintext of the i-th server record a part adds, sealed again under the server key at
// its sequence number as the MX would have sent it, in the stream and in the part's witness.
func testRewriteServerRecord(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture, partEvent int, i int, plaintext []byte) {
	t.Helper()
	part := capture.Events[partEvent].Part
	previous := uint64(0)
	if 1 < part.Index {
		previous = capture.Events[testPartEvents(capture)[part.Index-1]].Part.ServerRecordCount
	}
	position := previous + uint64(i)
	seq := position
	if c.tls12 {
		// the client's and the server's Finished took sequence number 0
		seq += 1
	}
	witness := capture.Witnesses[partEvent]
	capture.Events[testServerApplicationEvents(capture)[position]].ServerRecord = testSealRecord(t, c.tls12, witness.ServerKey, witness.ServerIv, seq, plaintext)
	witness.ServerPlaintexts = slices.Clone(witness.ServerPlaintexts)
	witness.ServerPlaintexts[i] = plaintext
}

// A server record's plaintext from its content: application data, with 1.3's type octet.
func testServerPlaintext(c *testLegCase, content string) []byte {
	if c.tls12 {
		return []byte(content)
	}
	return append([]byte(content), 23)
}

// Flips the last octet of the ServerKeyExchange's signature in 1.2's clear flight, wherever the
// records split the flight's messages.
func testFlipServerKeyExchangeSignature(t *testing.T, capture *smtpproof.ExportedCapture) {
	t.Helper()
	type place struct {
		event  int
		offset int
	}
	var flight []byte
	var places []place
	for i, event := range capture.Events {
		if event.Part != nil {
			break
		}
		if event.ServerRecord == nil || event.ServerRecord[0] != 22 {
			continue
		}
		for offset := 5; offset < len(event.ServerRecord); offset += 1 {
			flight = append(flight, event.ServerRecord[offset])
			places = append(places, place{event: i, offset: offset})
		}
	}
	for at := 0; at+4 <= len(flight); {
		length := int(flight[at+1])<<16 | int(flight[at+2])<<8 | int(flight[at+3])
		end := at + 4 + length
		if len(flight) < end {
			break
		}
		if flight[at] == 12 {
			last := places[end-1]
			record := bytes.Clone(capture.Events[last.event].ServerRecord)
			record[last.offset] ^= 1
			capture.Events[last.event].ServerRecord = record
			return
		}
		at = end
	}
	t.Fatal("no ServerKeyExchange in the flight")
}

// Every break, by check. Each keeps every record's length, so that a break's part fits the shape its
// honest twin's does and nothing but the break differs.
func testMutations() []*testMutation {
	return []*testMutation{
		// E1
		{check: "E1", name: "a client record of another type after the handshake", mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			testEditStreamRecord(capture, capture.Events[testPartEvents(capture)[1]].Part.Records[0], func(record []byte) { record[0] = 22 })
		}},
		{check: "E1", name: "a server record of type handshake after the handshake, renegotiation in 1.2", mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			event := capture.Events[testServerApplicationEvents(capture)[0]]
			event.ServerRecord = bytes.Clone(event.ServerRecord)
			event.ServerRecord[0] = 22
		}},

		// E2
		{check: "E2", name: "a disclosed SHTS one bit off", applies: testTls13Only, mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			for _, event := range capture.Events {
				if event.Shts != nil {
					event.Shts = bytes.Clone(event.Shts)
					event.Shts[0] ^= 1
				}
			}
		}},
		{check: "E2", name: "a ServerKeyExchange whose signature is one bit off", applies: func(c *testLegCase) bool { return c.tls12 }, mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			testFlipServerKeyExchangeSignature(t, capture)
		}},

		// E3
		{check: "E3", name: "a record one bit off the ciphertext its part proved", mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			record := capture.Events[testPartEvents(capture)[2]].Part.Records[0]
			testEditStreamRecord(capture, record, func(record []byte) { record[len(record)-1] ^= 1 })
		}},
		{check: "E3", name: "a part's record of another outer type, which the circuit cannot see", mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			event := capture.Events[testPartEvents(capture)[2]]
			part := *event.Part
			part.Records = slices.Clone(part.Records)
			part.Records[0] = bytes.Clone(part.Records[0])
			part.Records[0][0] = 22
			event.Part = &part
		}},
		{check: "E3", name: "a part opening one record more than its index has roles for", mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			event := capture.Events[testPartEvents(capture)[2]]
			part := *event.Part
			part.Records = append(slices.Clone(part.Records), part.Records[len(part.Records)-1])
			part.LastRecord += 1
			event.Part = &part
		}},

		// Z1
		{check: "Z1", name: "another HS or master secret, the keys it gave kept", part: testPartAt(1), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			witness := capture.Witnesses[testPartEvents(capture)[1]]
			if c.tls12 {
				witness.MasterSecret = bytes.Clone(witness.MasterSecret)
				witness.MasterSecret[0] ^= 1
			} else {
				witness.HandshakeSecret = bytes.Clone(witness.HandshakeSecret)
				witness.HandshakeSecret[0] ^= 1
			}
		}},

		// Z2
		{check: "Z2", name: "a MAIL record whose first ciphertext octet no longer opens to the claimed M", part: testPartAt(2), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			event := capture.Events[testPartEvents(capture)[2]]
			original := event.Part.Records[0]
			offset := 5
			if c.tls12 {
				// past the explicit nonce
				offset += 8
			}
			flip := func(record []byte) { record[offset] ^= 1 }
			part := *event.Part
			part.Records = slices.Clone(part.Records)
			part.Records[0] = bytes.Clone(original)
			flip(part.Records[0])
			event.Part = &part
			testEditStreamRecord(capture, original, flip)
		}},

		// Z3
		{check: "Z3", name: "pi3's first record sealed with inner type 22 under the true key", applies: testTls13Only, part: testPartAt(3), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			message := testPartEvents(capture)[3]
			plaintext := bytes.Clone(capture.Witnesses[message].ClientPlaintexts[0])
			plaintext[len(plaintext)-1] = 22
			testRewriteClientPlaintext(t, c, capture, message, 0, plaintext)
		}},

		// Z4
		{check: "Z4", name: "a command of its template's length that says another: BDAT's count, or DATB", part: testPartByMode(3, 2), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			if c.data {
				envelope := testPartEvents(capture)[2]
				last := len(capture.Events[envelope].Part.Records) - 1
				testRewriteClientRecord(t, c, capture, envelope, last, []byte("DATB\r\n"))
				return
			}
			message := testPartEvents(capture)[3]
			command := string(testRecordContent(c, capture.Witnesses[message].ClientPlaintexts[0]))
			digit := strings.Index(command, " LAST") - 1
			changed := command[:digit] + string('0'+('9'-command[digit])) + command[digit+1:]
			testRewriteClientRecord(t, c, capture, message, 0, []byte(changed))
		}},

		// Z5
		{check: "Z5", name: "a header block whose Feedback-ID field is renamed, so it has none", part: testPartAt(3), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			message := testPartEvents(capture)[3]
			header := 1
			if c.data {
				header = 0
			}
			block := string(testRecordContent(c, capture.Witnesses[message].ClientPlaintexts[header]))
			if !strings.Contains(block, "\r\nFeedback-ID: ") {
				t.Fatal("no Feedback-ID line")
			}
			testRewriteClientRecord(t, c, capture, message, header, []byte(strings.Replace(block, "\r\nFeedback-ID: ", "\r\nFeedback-IX: ", 1)))
		}},

		// Z6
		{check: "Z6", name: "QUIX in QUIT's place at last_record", applies: testBdatOnly, part: testPartAt(3), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			message := testPartEvents(capture)[3]
			testRewriteClientRecord(t, c, capture, message, len(capture.Events[message].Part.Records)-1, []byte("QUIX\r\n"))
		}},
		{check: "Z6", name: "a body record ending the message early, as long as its honest twin", applies: testDataOnly, part: testPartAt(4), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			body := testPartEvents(capture)[4]
			length := len(testRecordContent(c, capture.Witnesses[body].ClientPlaintexts[0]))
			testRewriteClientRecord(t, c, capture, body, 0, []byte(strings.Repeat("x", length-5)+"\r\n.\r\n"))
		}},

		// Z7
		{check: "Z7", name: "an RCPT reply's record replaced by a server KeyUpdate", applies: testTls13Only, part: testPartAt(3), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			testRewriteServerRecord(t, c, capture, testPartEvents(capture)[3], 1, []byte{24, 0, 0, 1, 0, 22})
		}},

		// Z8
		{check: "Z8", name: "an RCPT reply refused, 550 in 250's place", part: testPartAt(3), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			message := testPartEvents(capture)[3]
			reply := string(testRecordContent(c, capture.Witnesses[message].ServerPlaintexts[1]))
			if !strings.HasPrefix(reply, "250 ") {
				t.Fatalf("an RCPT reply of %q", reply)
			}
			testRewriteServerRecord(t, c, capture, message, 1, testServerPlaintext(c, "5"+reply[1:]))
		}},

		// Z9
		{check: "Z9", name: "an EHLO reply whose CHUNKING line is misspelled CHUNKINX", applies: testBdatOnly, part: testPartAt(2), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			envelope := testPartEvents(capture)[2]
			reply := string(testRecordContent(c, capture.Witnesses[envelope].ServerPlaintexts[0]))
			if !strings.Contains(reply, "CHUNKING\r\n") {
				t.Fatalf("an EHLO reply of %q", reply)
			}
			testRewriteServerRecord(t, c, capture, envelope, 0, testServerPlaintext(c, strings.Replace(reply, "CHUNKING\r\n", "CHUNKINX\r\n", 1)))
		}},
	}
}

// Runs every break of one check on every leg and mode it applies to.
func testRunMutations(t *testing.T, check string) {
	t.Helper()
	// the checks' tests share only the compiled shapes, which compile once under their lock
	t.Parallel()
	ran := 0
	for _, m := range testMutations() {
		if m.check != check {
			continue
		}
		for _, c := range testLegCases() {
			if m.applies == nil || m.applies(c) {
				testRunMutation(t, m, c)
				ran += 1
			}
		}
	}
	if ran == 0 {
		t.Fatalf("no mutation of %s ran", check)
	}
}

// Holds one break to its check: the gate's relation and the checker each name it alone, then the
// circuit refuses its part, or edgeSession refuses on its own with the solver as its verifier too.
func testRunMutation(t *testing.T, m *testMutation, c *testLegCase) {
	t.Helper()
	name := fmt.Sprintf("%s, %s: %s", m.check, c.name, m.name)
	capture := smtpproof.ExportCapture(t, c.leg, c.data)
	m.mutate(t, c, capture)
	want := []string{m.check}
	if gate := testGateVerdict(capture); !slices.Equal(gate, want) {
		t.Errorf("%s: the gate names %v", name, gate)
	}
	if ours := testCheckerVerdict(capture); !slices.Equal(ours, want) {
		t.Errorf("%s: the checker names %v", name, ours)
	}
	if !smtpproof.ExportCircuitsRun() {
		return
	}
	verdict := smtpproof.ExportCircuitVerdict
	if m.check == "Z1" {
		verdict = smtpproof.ExportKeyedCircuitVerdict
	}
	part, err := verdict(t, capture)
	switch {
	case strings.HasPrefix(m.check, "E") && (part != 0 || err == nil):
		t.Errorf("%s: with the solver as its verifier the gate refuses part %d (%v), want its own refusal", name, part, err)
	case strings.HasPrefix(m.check, "Z") && (part != m.part(c) || err != nil):
		t.Errorf("%s: the circuits refuse part %d (%v), want part %d", name, part, err, m.part(c))
	}
}

// Every honest capture the breaks start from passes the gate, the checker and every part's circuit,
// pi1's with Z1 in it.
func TestMutatedWitnessHonestTwins(t *testing.T) {
	t.Parallel()
	for _, c := range testLegCases() {
		capture := smtpproof.ExportCapture(t, c.leg, c.data)
		if verdict := testGateVerdict(capture); len(verdict) != 0 {
			t.Errorf("%s: the gate refuses an honest send: %v", c.name, verdict)
		}
		if verdict := testCheckerVerdict(capture); len(verdict) != 0 {
			t.Errorf("%s: the checker refuses an honest send: %v", c.name, verdict)
		}
		if !smtpproof.ExportCircuitsRun() {
			continue
		}
		if part, err := smtpproof.ExportKeyedCircuitVerdict(t, capture); part != 0 || err != nil {
			t.Errorf("%s: the circuits refuse an honest send at part %d: %v", c.name, part, err)
		}
	}
}

// The TLS a leg runs, as the table names it.
func testLegTls(c *testLegCase) string {
	return []string{"1.3 AES-128-GCM", "1.3 ChaCha20-Poly1305", "1.2 ECDHE-ECDSA AES-128-GCM"}[c.leg]
}

func testLegMode(c *testLegCase) string {
	if c.data {
		return "DATA"
	}
	return "BDAT"
}

// The evidence table, one row a break and leg, then the cells no break fills.
func testMutationTable() string {
	var table strings.Builder
	table.WriteString("# Mutated witnesses (SMTP-M9-29)\n\n")
	table.WriteString("Written by `TestMutatedWitnessTable` from `mutate_test.go`'s registry, which fails when this file differs; set `SMTPPROOF_WRITE_MUTATIONS` to rewrite it. ")
	table.WriteString("Each row is a break of one honest connection that the named check alone refuses. The gate, whose verifier is `relationCheckPart` over the edge's own statement, and `smtpproof/checker`, which reads SPEC.md apart from this module, each name exactly that check; ")
	table.WriteString("then the circuit refuses the part named, through gnark's solver over the edge's own statement, or `edgeSession` refuses on its own (\"gate\"), with the solver as its verifier as well. ")
	table.WriteString("Every record keeps its length, so a break's part fits the shape its honest twin's does. The test named runs the row on every run of the package; its circuit half runs in the leg without `sidecar_testhooks`.\n\n")
	table.WriteString("| Check | TLS | Mode | Refused at | Mutation | Test |\n")
	table.WriteString("|---|---|---|---|---|---|\n")
	for _, check := range testMutationChecks {
		for _, m := range testMutations() {
			if m.check != check {
				continue
			}
			for _, c := range testLegCases() {
				if m.applies != nil && !m.applies(c) {
					continue
				}
				at := "gate"
				if m.part != nil {
					at = fmt.Sprintf("pi%d", m.part(c))
					if check == "Z1" {
						at += ", Z1 in its circuit"
					}
				}
				fmt.Fprintf(&table, "| %s | %s | %s | %s | %s | TestMutatedWitness%s |\n", check, testLegTls(c), testLegMode(c), at, m.name, check)
			}
		}
	}
	table.WriteString("\nCells no witness can break alone:\n\n")
	table.WriteString("| Check | TLS | Mode | Why |\n")
	table.WriteString("|---|---|---|---|\n")
	inapplicable := testInapplicableCells()
	for _, check := range testMutationChecks {
		for _, tls12 := range []bool{false, true} {
			for _, data := range []bool{false, true} {
				cell := testMutationCell{check: check, tls12: tls12, data: data}
				if reason, ok := inapplicable[cell]; ok {
					version, mode := "1.3", "BDAT"
					if tls12 {
						version = "1.2"
					}
					if data {
						mode = "DATA"
					}
					fmt.Fprintf(&table, "| %s | %s | %s | %s |\n", check, version, mode, reason)
				}
			}
		}
	}
	return table.String()
}

// Fails if any check lacks a break in a cell it applies to, if a cell no break can fill holds one, if
// a check's test is missing, or if the evidence table differs from the registry.
func TestMutatedWitnessTable(t *testing.T) {
	inapplicable := testInapplicableCells()
	covered := map[testMutationCell][]string{}
	for _, m := range testMutations() {
		if !slices.Contains(testMutationChecks, m.check) {
			t.Errorf("%s: no such check", m.name)
		}
		if strings.HasPrefix(m.check, "Z") != (m.part != nil) {
			t.Errorf("%s %s: a Z break names its part, and only a Z break", m.check, m.name)
		}
		for _, c := range testLegCases() {
			if m.applies == nil || m.applies(c) {
				cell := testMutationCell{check: m.check, tls12: c.tls12, data: c.data}
				covered[cell] = append(covered[cell], m.name)
			}
		}
	}
	for _, check := range testMutationChecks {
		for _, tls12 := range []bool{false, true} {
			for _, data := range []bool{false, true} {
				cell := testMutationCell{check: check, tls12: tls12, data: data}
				_, excused := inapplicable[cell]
				switch {
				case excused && 0 < len(covered[cell]):
					t.Errorf("%v: listed as no witness's to break, yet %q breaks it", cell, covered[cell])
				case !excused && len(covered[cell]) == 0:
					t.Errorf("%v: no mutation", cell)
				}
			}
		}
	}

	// each check's test exists, so that every row the table names runs
	var sources []byte
	for _, name := range []string{"mutate_edge_test.go", "mutate_circuit_test.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, source...)
	}
	for _, check := range testMutationChecks {
		if !bytes.Contains(sources, []byte("func TestMutatedWitness"+check+"(t *testing.T) {\n\ttestRunMutations(t, \""+check+"\")\n")) {
			t.Errorf("no TestMutatedWitness%s running %s's breaks", check, check)
		}
	}

	path := filepath.Join("testdata", "mutations", "table.md")
	table := testMutationTable()
	if os.Getenv("SMTPPROOF_WRITE_MUTATIONS") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(table), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != table {
		t.Errorf("%s differs from the registry; set SMTPPROOF_WRITE_MUTATIONS to rewrite it", path)
	}
	t.Log("\n" + table)
}
