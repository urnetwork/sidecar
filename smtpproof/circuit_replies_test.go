// Z7 to Z9 in the circuit beside the relation: the MX's replies, opened under its own key inside the
// circuit and parsed there, which is D-SMTP-22's reason for existing: a malicious sidecar's control
// flow is no evidence of the MX's state (SPEC.md 9.4). Each break of SMTP-M9-24's list sits beside an
// honest twin, both through relationCheckPart and the constraint solver, and what a server octet
// costs is held to SPEC.md 11.2.

package smtpproof

import (
	"bytes"
	"crypto/tls"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// A part's server records replaced by one record per content, each authored as the MX would have
// sealed it at the sequence number that follows the last.
func testServerRecords(t *testing.T, statement *partStatement, witness *partWitness, plaintexts ...[]byte) {
	t.Helper()
	first := statement.serverRecords[0]
	statement.serverRecords = nil
	witness.serverPlaintexts = nil
	for i, plaintext := range plaintexts {
		raw := bytes.Clone(first.raw)
		if statement.session.version == tlsVersion12 {
			// 1.2's record carries its own explicit nonce, which the MX counts like seq
			nonce := raw[tlsRecordHeaderBytes : tlsRecordHeaderBytes+tlsExplicitNonceBytes]
			nonce[len(nonce)-1] += byte(i)
		}
		statement.serverRecords = append(statement.serverRecords, &partRecord{seq: first.seq + uint64(i), raw: raw})
		witness.serverPlaintexts = append(witness.serverPlaintexts, nil)
		testAuthorServerRecord(t, statement, witness, i, plaintext)
	}
	statement.serverRecordCount = statement.previousServerRecordCount + uint64(len(plaintexts))
}

// One malicious or honest reply flow for a part, and whether both sides must take it.
type testReplyCase struct {
	name string
	// Which part, in which mode, and its server records' contents in order, 1.3's type octet appended
	// for each. A nil content is a ticket.
	index    uint32
	data     bool
	contents []string
	accept   bool
	// What the relation must name, when set.
	checks []relationCheck
}

// Replies to MAIL and three RCPTs, the honest stream and its breaks, with DATA's 354 where it goes.
func testReplyCases() []*testReplyCase {
	ehlo := "250-" + testMxHost + "\r\n250-PIPELINING\r\n250-CHUNKING\r\n250 SMTPUTF8\r\n"
	ok := "250 2.1.0 Ok\r\n"
	rcpt := "250 2.1.5 Ok\r\n"
	refused := "550 5.1.1 No such user\r\n"
	deferred := "451 4.3.0 Try later\r\n"
	go354 := "354 End data with <CR><LF>.<CR><LF>\r\n"
	return []*testReplyCase{
		{name: "an EHLO reply offering CHUNKING", index: 2, contents: []string{ehlo}, accept: true},
		{name: "an EHLO reply without CHUNKING, under BDAT", index: 2, contents: []string{"250-" + testMxHost + "\r\n250-PIPELINING\r\n250 SMTPUTF8\r\n"}, checks: []relationCheck{checkZ9}},
		{name: "the same reply under DATA", index: 2, data: true, contents: []string{"250-" + testMxHost + "\r\n250-PIPELINING\r\n250 SMTPUTF8\r\n"}, accept: true},
		{name: "an EHLO reply split across two records", index: 2, contents: []string{"250-" + testMxHost + "\r\n250-PIPE", "LINING\r\n250-CHUNKING\r\n250 SMTPUTF8\r\n"}, accept: true},
		{name: "an EHLO reply refusing", index: 2, contents: []string{"554 5.7.1 Go away\r\n"}, checks: []relationCheck{checkZ8, checkZ9}},
		{name: "a late ticket after the EHLO reply", index: 2, contents: []string{ehlo, ""}, accept: true},
		{name: "a ticket before the EHLO reply", index: 2, contents: []string{"", ehlo}, accept: true},

		{name: "every reply accepting", index: 3, contents: []string{ok + rcpt + rcpt + rcpt}, accept: true},
		{name: "every reply in a record of its own", index: 3, contents: []string{ok, rcpt, rcpt, rcpt}, accept: true},
		{name: "a reply split across two records", index: 3, contents: []string{ok + "250 2.1", ".5 Ok\r\n" + rcpt + rcpt}, accept: true},
		{name: "a late ticket after the last RCPT's reply", index: 3, contents: []string{ok + rcpt + rcpt + rcpt, ""}, accept: true},
		{name: "a ticket between replies", index: 3, contents: []string{ok + rcpt, "", rcpt + rcpt}, accept: true},
		{name: "a refused MAIL", index: 3, contents: []string{refused + rcpt + rcpt + rcpt}, checks: []relationCheck{checkZ8}},
		{name: "a refused RCPT among accepted ones", index: 3, contents: []string{ok + rcpt + refused + rcpt}, checks: []relationCheck{checkZ8}},
		{name: "a deferred last RCPT", index: 3, contents: []string{ok + rcpt + rcpt + deferred}, checks: []relationCheck{checkZ8}},
		{name: "every RCPT refused", index: 3, contents: []string{ok + refused + refused + refused}, checks: []relationCheck{checkZ8}},
		{name: "one reply too few", index: 3, contents: []string{ok + rcpt + rcpt}, checks: []relationCheck{checkZ8}},

		{name: "DATA's 354 after the envelope's replies", index: 3, data: true, contents: []string{ok + rcpt + rcpt + rcpt + go354}, accept: true},
		{name: "no 354", index: 3, data: true, contents: []string{ok + rcpt + rcpt + rcpt + "250 2.0.0 Ok\r\n"}, checks: []relationCheck{checkZ8}},
		{name: "DATA refused", index: 3, data: true, contents: []string{ok + rcpt + rcpt + rcpt + "554 5.5.1 No valid recipients\r\n"}, checks: []relationCheck{checkZ8}},
		{name: "the 354 reordered ahead of an RCPT's reply", index: 3, data: true, contents: []string{ok + rcpt + go354 + rcpt + rcpt}, checks: []relationCheck{checkZ8}},
		{name: "the 354 ahead of every reply", index: 3, data: true, contents: []string{go354 + ok + rcpt + rcpt + rcpt}, checks: []relationCheck{checkZ8}},
	}
}

// Three recipients, so that mixed outcomes have room, in either mode.
func testThreeRecipientCapture(t *testing.T, leg *testTlsLeg, data bool) *testCapturedParts {
	t.Helper()
	settings := DefaultProverSettings()
	settings.ForceData = data
	return testCapture(t, leg, testMxDefaults(), settings, testJob("one line\r\n", "bob", "carol", "dave"))
}

func TestReplyCircuitAgreesWithTheRelation(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs() {
		tls12 := leg.suites[0] == tlsSuiteEcdheEcdsaAes128GcmSha256
		bodyBlocks := 6
		if leg.suites[0] == tlsSuiteChacha20Poly1305Sha256 {
			bodyBlocks = 2
		}
		envelope, envelopeCompiled := testEnvelopeCircuit(t, leg)
		messages := map[bool]*partShape{false: testQuickMessageShape(leg.suites[0], 0), true: testQuickMessageShape(leg.suites[0], bodyBlocks)}
		// the EHLO reply's cases need no third recipient, and the envelope's quick shape holds two
		envelopeCaptures := map[bool]*testCapturedParts{false: testBdatCapture(t, leg), true: testDataCapture(t, leg)}
		messageCaptures := map[bool]*testCapturedParts{false: testThreeRecipientCapture(t, leg, false), true: testThreeRecipientCapture(t, leg, true)}
		for _, c := range testReplyCases() {
			var plaintexts [][]byte
			ticketed := false
			for _, content := range c.contents {
				if content == "" {
					ticketed = true
					plaintexts = append(plaintexts, testTicket(16))
					continue
				}
				plaintexts = append(plaintexts, nil)
			}
			// 1.2 offers no ticket here
			if ticketed && tls12 {
				continue
			}
			captures, shape, compiled := envelopeCaptures, envelope, envelopeCompiled
			if c.index == 3 {
				captures, shape = messageCaptures, messages[c.data]
				compiled = testCompileShape(t, shape)
			}
			statement, witness := captures[c.data].part(t, c.index)
			for i, content := range c.contents {
				if content != "" {
					plaintexts[i] = testServerContent(statement, content)
				}
			}
			testServerRecords(t, statement, witness, plaintexts...)
			testCircuitAgrees(t, leg.name+": "+c.name, shape, compiled, statement, witness, c.accept, c.checks...)
		}
	}
}

func TestReplyCircuitRefusesWhatOnlyTheRecordsBreak(t *testing.T) {
	t.Parallel()
	// Z7 over the records themselves, each beside its honest twin: a record opens only at its own
	// sequence number, and a 1.3 record is unpadded application data or a ticket
	for _, leg := range testTlsLegs() {
		tls12 := leg.suites[0] == tlsSuiteEcdheEcdsaAes128GcmSha256
		shape, compiled := testEnvelopeCircuit(t, leg)
		capture := testBdatCapture(t, leg)
		ehlo := "250-" + testMxHost + "\r\n250-PIPELINING\r\n250-CHUNKING\r\n250 SMTPUTF8\r\n"
		// whole lines in each record, so that the first two read in either order still parse as one
		// reply offering CHUNKING, and only the records' own keystreams tell the orders apart
		honest := func() (*partStatement, *partWitness) {
			statement, witness := capture.part(t, 2)
			testServerRecords(t, statement, witness,
				testServerContent(statement, "250-"+testMxHost+"\r\n250-PIPELINING\r\n"),
				testServerContent(statement, "250-SIZE 1000\r\n250-8BITMIME\r\n"),
				testServerContent(statement, "250-SMTPUTF8\r\n250-CHUNKING\r\n250 OK\r\n"))
			return statement, witness
		}
		statement, witness := honest()
		testCircuitAgrees(t, leg.name+": the honest twin", shape, compiled, statement, witness, true)

		// No case here changes only the witness's server plaintexts: the circuit opens server records
		// under the key and reads what they hold, so its witness has no plaintext to misstate, and only
		// the relation's representation of one could disagree. What moves the circuit is the records.
		if tls12 {
			// a 1.2 record carries its own nonce, so order there rests on the edge relaying each server
			// record once, as the MX sent it (SPEC.md 9.4), and 1.2 has no inner type to pad or to make a
			// ticket of
			continue
		}
		// records the MX really sent, relayed at sequence numbers it did not send them at
		statement, witness = honest()
		statement.serverRecords[0].seq, statement.serverRecords[1].seq = statement.serverRecords[1].seq, statement.serverRecords[0].seq
		statement.serverRecords[0], statement.serverRecords[1] = statement.serverRecords[1], statement.serverRecords[0]
		witness.serverPlaintexts[0], witness.serverPlaintexts[1] = witness.serverPlaintexts[1], witness.serverPlaintexts[0]
		testCircuitAgrees(t, leg.name+": records replayed at each other's sequence numbers", shape, compiled, statement, witness, false, checkZ2)

		statement, witness = capture.part(t, 2)
		testServerRecords(t, statement, witness, []byte{tlsHandshakeKeyUpdate, 0, 0, 1, 0, tlsRecordHandshake}, testServerContent(statement, ehlo))
		testCircuitAgrees(t, leg.name+": a KeyUpdate", shape, compiled, statement, witness, false, checkZ7)
		statement, witness = capture.part(t, 2)
		testServerRecords(t, statement, witness, testTicket(16), testServerContent(statement, ehlo))
		testCircuitAgrees(t, leg.name+": its twin, a ticket", shape, compiled, statement, witness, true)

		statement, witness = capture.part(t, 2)
		testServerRecords(t, statement, witness, append(testServerContent(statement, ehlo), 0, 0))
		testCircuitAgrees(t, leg.name+": a padded record", shape, compiled, statement, witness, false, checkZ7)
		statement, witness = capture.part(t, 2)
		testServerRecords(t, statement, witness, testServerContent(statement, ehlo))
		testCircuitAgrees(t, leg.name+": its twin, unpadded", shape, compiled, statement, witness, true)

		statement, witness = capture.part(t, 2)
		testServerRecords(t, statement, witness, append(testTicket(16), 0), testServerContent(statement, ehlo))
		testCircuitAgrees(t, leg.name+": a padded ticket", shape, compiled, statement, witness, false, checkZ7)
	}
}

// One of sidecartest's MX legs for a leg of testTlsLegs, by its suite.
func testMxLegFor(t *testing.T, leg *testTlsLeg) *testMxLeg {
	t.Helper()
	for _, candidate := range testMxLegs() {
		if candidate.suites[0] == leg.suites[0] {
			return candidate
		}
	}
	t.Fatalf("no MX leg for %s", leg.name)
	return nil
}

func TestReplyCircuitFindsNoChunkingOfferedOnlyBeforeTls(t *testing.T) {
	t.Parallel()
	// RFC 3207 §4.2: STARTTLS voids what the MX said before it, so a CHUNKING it offered only then is
	// no input here. An honest sidecar sends such an MX DATA, which both sides take; the same envelope
	// claimed as BDAT both refuse (Z9), though the edge saw CHUNKING in the clear
	testNeedCircuits(t)
	for _, leg := range testTlsLegs() {
		mxLeg := testMxLegFor(t, leg)
		script := sidecartest.DefaultMxScript()
		script.PreTlsKeywords = []string{"PIPELINING", "CHUNKING"}
		script.Keywords = []string{"PIPELINING", "SMTPUTF8"}
		mx, err := sidecartest.NewScriptedMx(testMxHost, script, &sidecartest.ScriptedMxSettings{
			MinVersion:   mxLeg.version,
			MaxVersion:   mxLeg.version,
			CipherSuites: []uint16{mxLeg.suite},
			RsaKey:       mxLeg.suite == tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		})
		if err != nil {
			t.Fatal(err)
		}
		job := testJob("one line\r\n", "bob", "carol")
		job.Preamble.MessageByteCount = uint64(len(dotStuffed(job.Message)))
		send := testRunSendToMx(t, mxLeg.suites, mx, DefaultProverSettings(), job)
		testExpectMxTransaction(t, leg.name, send, mx.Transactions(), job)
		if send.result.Mode != partModeData {
			t.Fatalf("%s: mode %d, want DATA", leg.name, send.result.Mode)
		}
		capture := &testCapturedParts{leg: leg, statements: send.backend.statements, witnesses: send.backend.proved}
		shape, compiled := testEnvelopeCircuit(t, leg)

		statement, witness := capture.part(t, 2)
		testCircuitAgrees(t, leg.name+": DATA to it", shape, compiled, statement, witness, true)

		statement, witness = capture.part(t, 2)
		statement.mode = partModeBdat
		statement.clientRecords = statement.clientRecords[:len(statement.clientRecords)-1]
		witness.clientPlaintexts = witness.clientPlaintexts[:len(witness.clientPlaintexts)-1]
		testCircuitAgrees(t, leg.name+": BDAT to it", shape, compiled, statement, witness, false, checkZ9)
	}
}

// What a server block costs, SPEC.md 11.2's measured rows, held here: two shapes 64 server octets
// apart, Z1 left out, so the difference is Z7's opening, Z8's parse and, in pi2, Z9's window over 64
// octets, with Z2's keystream.
var testSpecServerOctetCosts = map[string]int{
	"aes, envelope":      51046,
	"aes, message":       51302,
	"chacha20, envelope": 26202,
	"chacha20, message":  26458,
}

func TestReplyScanCostIsSpecMds(t *testing.T) {
	t.Parallel()
	for _, suite := range []uint16{tlsSuiteAes128GcmSha256, tlsSuiteChacha20Poly1305Sha256} {
		for _, kind := range []partKind{partKindEnvelope, partKindMessage} {
			shape := &partShape{kind: kind, version: tlsVersion13, suite: suite, clientBlocks: 1, serverBlocks: 4, withoutKeySchedule: true}
			name := "aes"
			keystream := 4 * testSpecGadgetSizes["aes keystream block"]
			if suite == tlsSuiteChacha20Poly1305Sha256 {
				shape.serverBlocks = 1
				name = "chacha20"
				keystream = testSpecGadgetSizes["chacha20 keystream block"]
			}
			if kind == partKindEnvelope {
				shape.localOctets = true
				name += ", envelope"
			} else {
				// room for Z5's literals, which a block too short to hold them leaves constant
				shape.headerBlocks = 256 / shape.blockBytes()
				name += ", message"
			}
			wider := *shape
			wider.serverBlocks += 64 / shape.blockBytes()
			cost := testCompileShape(t, &wider).GetNbConstraints() - testCompileShape(t, shape).GetNbConstraints()
			t.Logf("%s: 64 server octets cost %d constraints, %d beyond the keystream, %.1f an octet", name, cost, cost-keystream, float64(cost-keystream)/64)
			if want := testSpecServerOctetCosts[name]; cost != want {
				t.Errorf("%s: 64 server octets cost %d constraints, SPEC.md 11.2 says %d", name, cost, want)
			}
		}
	}
}
