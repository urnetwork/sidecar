// A later DATA part over a late NewSessionTicket: the body's parts go on behind it, since a ticket is
// no reply, while any reply in a later part stays unprovable (Z7, Z8). The circuit runs on a quick
// shape with the same blocks, and the production shapes are checked to hold such a part.

package smtpproof

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A DATA send cut into several later parts, so part 4 is a body part that is not the last.
func testLaterPartCapture(t *testing.T, leg *testTlsLeg) *testCapturedParts {
	t.Helper()
	settings := DefaultProverSettings()
	settings.ForceData = true
	settings.DataPartBytes = 12
	return testCapture(t, leg, testMxDefaults(), settings, testJob("one line\r\nanother line\r\nand a third\r\n", "bob", "carol"))
}

// Part 4 with one more server record after its count, holding plaintext as the MX would have sealed it.
func testLaterPartWithServerRecord(t *testing.T, capture *testCapturedParts, plaintext []byte) (*partStatement, *partWitness) {
	t.Helper()
	statement, witness := capture.part(t, 4)
	if statement.last || 0 < len(statement.serverRecords) {
		t.Fatalf("part 4 is the last or covers %d server records", len(statement.serverRecords))
	}
	statement.serverRecords = []*partRecord{{seq: statement.previousServerRecordCount, raw: tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 1))}}
	statement.serverRecordCount = statement.previousServerRecordCount + 1
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

func TestALaterDataPartCoversALateTicketAndNoReply(t *testing.T) {
	t.Parallel()
	for _, leg := range testTlsLegs()[:2] {
		shape := &partShape{kind: partKindBody, version: tlsVersion13, suite: leg.suites[0], clientBlocks: 2, serverBlocks: 7, bodyBlocks: 2, withoutKeySchedule: true}
		if leg.suites[0] == tlsSuiteChacha20Poly1305Sha256 {
			shape.serverBlocks = 2
			shape.bodyBlocks = 1
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
			statement, witness := testLaterPartWithServerRecord(t, capture, c.plaintext)
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

func TestProductionShapesHoldALateTicketInALaterDataPart(t *testing.T) {
	// finding a shape builds an assignment and compiles nothing, so this runs in both legs
	for _, leg := range testTlsLegs()[:2] {
		capture := testLaterPartCapture(t, leg)
		plain, _ := capture.part(t, 4)
		withTicket, _ := testLaterPartWithServerRecord(t, capture, testTicket(250))
		plainShape, err := partShapeFor(plain)
		if err != nil || plainShape.serverBlocks != 0 {
			t.Errorf("%s: a part with no server record takes %+v, %v", leg.name, plainShape, err)
		}
		ticketShape, err := partShapeFor(withTicket)
		if err != nil || ticketShape.serverBlocks == 0 || ticketShape.kind != partKindBody {
			t.Errorf("%s: a part over a ticket takes %+v, %v", leg.name, ticketShape, err)
		}
		// past one ticket of 255 octets there is no shape, and the send fails closed
		tooLong, _ := testLaterPartWithServerRecord(t, capture, testTicket(300))
		if shape, err := partShapeFor(tooLong); err == nil {
			t.Errorf("%s: a 300-octet ticket took %+v", leg.name, shape)
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
		serverIn: make(chan *proverServerEvent, 1),
		records:  make([]*proverServerRecord, statement.serverRecordCount),
		covered:  statement.serverRecordCount,
		nextPart: 5,
		result: &tlsHandshakeResult{
			version: session.version, handshakeSecret: witness.handshakeSecret,
			clientKey: witness.clientKey, clientIv: witness.clientIv, serverKey: witness.serverKey, serverIv: witness.serverIv,
		},
	}
	// the records before pi4's count are covered already; only their number matters from here
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

func TestTheNextDataPartCoversATicketReadDuringTheBody(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		capture := testLaterPartCapture(t, leg)
		run, backend, channel := testProverAfterPart4(t, capture, testTicket(96))
		if reply, err := run.drainServerRecords(); reply != nil || err != nil {
			t.Fatalf("%s: reply %v, %v", leg.name, reply, err)
		}
		// part 5 as the capture sealed it, now over the ticket as well
		next, witness := capture.part(t, 5)
		var sealed []*tlsSealedRecord
		for _, record := range next.clientRecords {
			sealed = append(sealed, &tlsSealedRecord{seq: record.seq, raw: record.raw})
		}
		if err := run.prove(context.Background(), partModeData, next.last, sealed, next.lastRecord, witness.clientPlaintexts); err != nil {
			t.Fatalf("%s: part 5 over the ticket: %v", leg.name, err)
		}
		part := channel.parts[len(channel.parts)-1]
		if part.ServerRecordCount != next.previousServerRecordCount+1 {
			t.Errorf("%s: part 5 covers %d server records, want %d", leg.name, part.ServerRecordCount, next.previousServerRecordCount+1)
		}
		statement := backend.statements[len(backend.statements)-1]
		if len(statement.serverRecords) != 1 {
			t.Errorf("%s: the statement holds %d server records", leg.name, len(statement.serverRecords))
		}
		if _, err := partShapeFor(statement); err != nil {
			t.Errorf("%s: no production shape for the part: %v", leg.name, err)
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
		// pi1, pi2, then parts of at most DataPartBytes of the stuffed message, the end mark and QUIT on
		// the last
		parts := len(send.backend.statements)
		least := 2 + (int(job.Preamble.MessageByteCount)+settings.DataPartBytes-1)/settings.DataPartBytes
		if parts < least {
			t.Errorf("%s: %d parts for %d octets, want at least %d", leg.name, parts, job.Preamble.MessageByteCount, least)
		}
		for _, statement := range send.backend.statements {
			if _, err := partShapeFor(statement); err != nil {
				t.Errorf("%s: part %d: %v", leg.name, statement.index, err)
			}
		}
		t.Logf("%s: %d octets in %d parts", leg.name, job.Preamble.MessageByteCount, parts)
	}
}
