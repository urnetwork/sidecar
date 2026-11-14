// A late NewSessionTicket during DATA's body: the message's parts cover no server record, so a part that
// opens no client record, of the env kind, covers it, since a ticket is no reply, while any reply there
// stays unprovable (Z7, Z8; DESIGN-DETAILS 3.2.3's last row). The circuit runs on a quick env shape, and
// the production shapes are checked to hold such a part.

package smtpproof

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A DATA send cut into several body parts, so part 4 is a body part that is not the last.
func testLaterPartCapture(t *testing.T, leg *testTlsLeg) *testCapturedParts {
	t.Helper()
	settings := DefaultProverSettings()
	settings.ForceData = true
	settings.DataPartBytes = 12
	return testCapture(t, leg, testMxDefaults(), settings, testJob("one line\r\nanother line\r\nand a third\r\n", "bob", "carol"))
}

// A part that opens no client record after part 4, covering one more server record that holds
// plaintext as the MX would have sealed it.
func testLateRecordPart(t *testing.T, capture *testCapturedParts, plaintext []byte) (*partStatement, *partWitness) {
	t.Helper()
	statement, witness := capture.part(t, 4)
	if statement.last || 0 < len(statement.serverRecords) {
		t.Fatalf("part 4 is the last or covers %d server records", len(statement.serverRecords))
	}
	statement.index = 5
	statement.firstRecord = statement.lastRecord + 1
	statement.clientRecords = nil
	statement.carryIn = nil
	statement.carryOut = nil
	statement.serverRecords = []*partRecord{{seq: statement.previousServerRecordCount, raw: tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 1))}}
	statement.serverRecordCount = statement.previousServerRecordCount + 1
	witness.clientPlaintexts = nil
	witness.serverPlaintexts = [][]byte{nil}
	testAuthorServerRecord(t, statement, witness, 0, plaintext)
	return statement, witness
}

// A 1.3 NewSessionTicket's plaintext: its handshake header, a body and the inner type.
func testTicket(bodyBytes int) []byte {
	ticket := []byte{tlsHandshakeNewSessionTicket, 0, byte(bodyBytes >> 8), byte(bodyBytes)}
	ticket = append(ticket, bytes.Repeat([]byte{7}, bodyBytes)...)
	return append(ticket, tlsRecordHandshake)
}

func TestAPartThatOpensNoRecordCoversALateTicketAndNoReply(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs()[:2] {
		shape := testPartShape(partKindEnvelope, suiteFamily(leg.suites[0]), 0)
		shape.clientBlocks = 1
		shape.serverBlocks = 7
		if leg.suites[0] == tlsSuiteChacha20Poly1305Sha256 {
			shape.serverBlocks = 2
		}
		compiled := testCompileShape(t, shape)
		capture := testLaterPartCapture(t, leg)
		cases := []struct {
			name      string
			plaintext []byte
			check     relationCheck
		}{
			{name: "a late ticket", plaintext: testTicket(96)},
			{name: "a reply during the body", plaintext: append([]byte("250 2.0.0 Ok\r\n"), tlsRecordApplicationData), check: checkZ8},
			{name: "a KeyUpdate", plaintext: []byte{tlsHandshakeKeyUpdate, 0, 0, 1, 0, tlsRecordHandshake}, check: checkZ7},
			{name: "a padded ticket", plaintext: append(testTicket(96), 0, 0), check: checkZ7},
		}
		for _, c := range cases {
			statement, witness := testLateRecordPart(t, capture, c.plaintext)
			failures := relationCheckPart(statement, witness)
			if c.check == "" && len(failures) != 0 || c.check != "" && (len(failures) != 1 || failures[0].check != c.check) {
				t.Errorf("%s: %s: the relation says %v", leg.name, c.name, failures)
			}
			assignment, err := partAssignment(shape, statement)
			if err != nil {
				// a record the shape cannot even hold is refused before any proof, as unprovable
				if c.check == "" {
					t.Errorf("%s: %s: %v", leg.name, c.name, err)
				}
				continue
			}
			assignWitness(assignment, statement, witness)
			if err := testPartSolved(t, compiled, assignment); (err == nil) != (c.check == "") {
				t.Errorf("%s: %s: the circuit says %v", leg.name, c.name, err)
			}
		}
	}
}

func TestProductionShapesHoldALateTicketInAPartOfItsOwn(t *testing.T) {
	// finding a shape builds an assignment and compiles nothing, so this runs in both legs
	for _, leg := range testTlsLegs()[:2] {
		capture := testLaterPartCapture(t, leg)
		plain, _ := capture.part(t, 4)
		withTicket, _ := testLateRecordPart(t, capture, testTicket(250))
		plainShape, err := partShapeFor(DefaultProofSettings(), plain)
		if err != nil || plainShape.kind != partKindBody || plainShape.serverBlocks != 0 {
			t.Errorf("%s: a body part takes %+v, %v", leg.name, plainShape, err)
		}
		ticketShape, err := partShapeFor(DefaultProofSettings(), withTicket)
		if err != nil || ticketShape.kind != partKindEnvelope {
			t.Errorf("%s: a part over a ticket takes %+v, %v", leg.name, ticketShape, err)
		}
		// past the env shape's server blocks there is no shape, and the send fails closed
		tooLong, _ := testLateRecordPart(t, capture, testTicket(2000))
		if shape, err := partShapeFor(DefaultProofSettings(), tooLong); err == nil {
			t.Errorf("%s: a 2000-octet ticket took %+v", leg.name, shape)
		}
	}
}

// The prover as it stands after part 4 of a DATA send, with a reader that already holds record.
func testProverAfterPart4(t *testing.T, capture *testCapturedParts, plaintext []byte) (*proverRun, *testWitnessBackend, *testChannelLog) {
	t.Helper()
	statement, witness := capture.part(t, 4)
	session := statement.session
	backend := newTestWitnessBackend()
	channel := &testChannelLog{}
	run := &proverRun{
		settings: DefaultProverSettings(),
		backend:  backend,
		channel:  channel,
		job:      &sidecar.SmtpProofJob{SendId: []byte("synthetic-send-id")},
		session:  session,
		preamble: session.preamble,
		// the connection's C and rho, as the run drew them after the handshake
		keyCommitment:     statement.keyCommitment,
		keyBlind:          witness.keyBlind,
		serverIn:          make(chan *proverServerEvent, 1),
		records:           make([]*proverServerRecord, statement.serverRecordCount),
		nextPart:          5,
		nextRecord:        statement.lastRecord + 1,
		covered:           statement.serverRecordCount,
		repliesProven:     statement.repliesProven,
		mode:              statement.mode,
		headerRecordCount: statement.headerRecordCount,
		messageStarted:    true,
		result: &tlsHandshakeResult{
			version: session.version, handshakeSecret: witness.handshakeSecret,
			clientKey: witness.clientKey, clientIv: witness.clientIv, serverKey: witness.serverKey, serverIv: witness.serverIv,
		},
	}
	// the records before part 4's count are covered already; only their number matters from here
	for i := range run.records {
		run.records[i] = &proverServerRecord{public: &partRecord{}}
	}
	seq := statement.serverRecordCount
	record := &partRecord{seq: seq, raw: tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 1))}
	testSeal(t, statement, record, witness.serverKey, witness.serverIv, plaintext)
	recordType := plaintext[len(plaintext)-1]
	run.serverIn <- &proverServerEvent{record: &tlsServerRecord{seq: seq, raw: record.raw, recordType: recordType, content: plaintext[:len(plaintext)-1]}}
	return run, backend, channel
}

func TestATicketReadDuringTheBodyTakesAPartBeforeTheNext(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		capture := testLaterPartCapture(t, leg)
		run, backend, channel := testProverAfterPart4(t, capture, testTicket(96))
		// part 5 as the capture sealed it, which now goes after a part over the ticket
		next, witness := capture.part(t, 5)
		spec := &proverPart{
			last:          next.last,
			plaintexts:    witness.clientPlaintexts,
			carryIn:       next.carryIn,
			carryInState:  witness.carryInState,
			carryInBlind:  witness.carryInBlind,
			carryOut:      next.carryOut,
			carryOutBlind: witness.carryOutBlind,
			wireCarry:     true,
		}
		for _, record := range next.clientRecords {
			spec.sealed = append(spec.sealed, &tlsSealedRecord{seq: record.seq, raw: record.raw})
		}
		if err := run.proveAfterLateRecords(context.Background(), spec); err != nil {
			t.Fatalf("%s: %v", leg.name, err)
		}
		if len(channel.parts) != 2 {
			t.Fatalf("%s: %d parts, want one over the ticket and then part 5's records", leg.name, len(channel.parts))
		}
		cover, body := channel.parts[0], channel.parts[1]
		if cover.Index != 5 || len(cover.Records) != 0 || cover.ServerRecordCount != next.previousServerRecordCount+1 {
			t.Errorf("%s: the part over the ticket is %+v", leg.name, cover)
		}
		if body.Index != 6 || body.ServerRecordCount != cover.ServerRecordCount || len(body.Records) != len(next.clientRecords) {
			t.Errorf("%s: the body part is %+v", leg.name, body)
		}
		for _, statement := range backend.statements {
			if _, err := partShapeFor(DefaultProofSettings(), statement); err != nil {
				t.Errorf("%s: no production shape for part %d: %v", leg.name, statement.index, err)
			}
		}
	}
}

func TestAReplyDuringTheBodyEndsTheSendWithItsCode(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		capture := testLaterPartCapture(t, leg)
		run, _, _ := testProverAfterPart4(t, capture, append([]byte("451 4.4.2 Timeout\r\n"), tlsRecordApplicationData))
		reply, err := run.drainServerRecords()
		if err != nil || reply == nil || reply.code != "451" {
			t.Errorf("%s: reply %v, %v", leg.name, reply, err)
		}
	}
}

func TestSendDataOf100KiBInPartsThroughTheGate(t *testing.T) {
	// D-SMTP-16's DATA size: every octet opened, in parts of DataPartBytes, leading dots stuffed, through
	// the real gate with the relation as its verifier, to the MX as one transaction of the message
	// itself. Every part finds a production shape, so the circuits as built hold such a send
	var body strings.Builder
	for i := 0; body.Len() < 100*1024; i += 1 {
		if i%25 == 0 {
			body.WriteString(".a line that begins with a dot, which DATA stuffs and the MX unstuffs\r\n")
		} else {
			body.WriteString("a line of a hundred-kibibyte message, whole and under RFC 5322's 998 octets\r\n")
		}
	}
	for _, leg := range testTlsLegs() {
		job := testJob(body.String(), "bob", "carol")
		job.Preamble.MessageByteCount = uint64(len(dotStuffed(job.Message)))
		settings := DefaultProverSettings()
		settings.ForceData = true
		send := testRunSend(t, leg, testMxDefaults(), settings, job)
		testExpectOneTransaction(t, leg, send, job)
		if send.result.Mode != partModeData {
			t.Errorf("%s: mode %d", leg.name, send.result.Mode)
		}
		// the key part, the envelope's, the header block's, then a body part each body record the body
		// shape holds, the end mark and QUIT on the last
		parts := len(send.backend.statements)
		family := suiteFamily(leg.suites[0])
		body := settings.Proof.shape(ShapeKindBody, family, 0)
		least := 3 + (int(job.Preamble.MessageByteCount)+body.BodyBlocks*body.blockBytes()-1)/(body.BodyBlocks*body.blockBytes())
		if parts < least {
			t.Errorf("%s: %d parts for %d octets, want at least %d", leg.name, parts, job.Preamble.MessageByteCount, least)
		}
		for _, statement := range send.backend.statements {
			if _, err := partShapeFor(DefaultProofSettings(), statement); err != nil {
				t.Errorf("%s: part %d: %v", leg.name, statement.index, err)
			}
		}
		t.Logf("%s: %d octets in %d parts", leg.name, job.Preamble.MessageByteCount, parts)
	}
}
