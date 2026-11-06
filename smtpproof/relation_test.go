// A mutated witness per check (§22.10): each test starts from a real connection's statement and
// witness, changes one thing a malicious sidecar could change, and requires that exactly one check
// refuses it. Where an attack needs a ciphertext of its own, the sidecar authors one, as it can.

package smtpproof

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// One honest connection's parts, by index, for mutation.
type testCapturedParts struct {
	leg        *testTlsLeg
	statements []*partStatement
	witnesses  []*partWitness
}

func testCapture(t *testing.T, leg *testTlsLeg, mxSettings *testMxSettings, settings *ProverSettings, job *sidecar.SmtpProofJob) *testCapturedParts {
	t.Helper()
	send := testRunSend(t, leg, mxSettings, settings, job)
	testExpectOneTransaction(t, leg, send, job)
	return &testCapturedParts{leg: leg, statements: send.backend.statements, witnesses: send.backend.proved}
}

// A statement and witness the test may change without touching the capture.
func (self *testCapturedParts) part(t *testing.T, index uint32) (*partStatement, *partWitness) {
	t.Helper()
	for i, statement := range self.statements {
		if statement.index == index {
			return testCloneStatement(statement), testCloneWitness(self.witnesses[i])
		}
	}
	t.Fatalf("no part %d", index)
	return nil, nil
}

func testCloneRecords(records []*partRecord) []*partRecord {
	clones := make([]*partRecord, 0, len(records))
	for _, record := range records {
		clones = append(clones, &partRecord{seq: record.seq, raw: bytes.Clone(record.raw)})
	}
	return clones
}

func testCloneStatement(statement *partStatement) *partStatement {
	clone := *statement
	session := *statement.session
	preamble := *statement.session.preamble
	session.preamble = &preamble
	clone.session = &session
	clone.clientRecords = testCloneRecords(statement.clientRecords)
	clone.serverRecords = testCloneRecords(statement.serverRecords)
	return &clone
}

func testClonePlaintexts(plaintexts [][]byte) [][]byte {
	clones := make([][]byte, 0, len(plaintexts))
	for _, plaintext := range plaintexts {
		clones = append(clones, bytes.Clone(plaintext))
	}
	return clones
}

func testCloneWitness(witness *partWitness) *partWitness {
	clone := *witness
	clone.handshakeSecret = bytes.Clone(witness.handshakeSecret)
	clone.masterSecret = bytes.Clone(witness.masterSecret)
	clone.clientKey = bytes.Clone(witness.clientKey)
	clone.clientPlaintexts = testClonePlaintexts(witness.clientPlaintexts)
	clone.serverPlaintexts = testClonePlaintexts(witness.serverPlaintexts)
	return &clone
}

// Rewrites a record so that it opens to plaintext under key and iv, as its author can. The tag is
// left as filler: the relation does not read it (SPEC.md Z2).
func testSeal(t *testing.T, statement *partStatement, record *partRecord, key []byte, iv []byte, plaintext []byte) {
	t.Helper()
	version := statement.session.version
	nonce, err := recordNonce(version, iv, record)
	if err != nil {
		t.Fatal(err)
	}
	keystream, err := recordKeystream(statement.session.suite, key, nonce, len(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{}
	if version == tlsVersion12 {
		payload = append(payload, record.raw[tlsRecordHeaderBytes:tlsRecordHeaderBytes+tlsExplicitNonceBytes]...)
	}
	for i := range plaintext {
		payload = append(payload, plaintext[i]^keystream[i])
	}
	payload = append(payload, make([]byte, tlsAeadTagBytes)...)
	record.raw = tlsFrameRecord(record.raw[0], tlsVersion12, payload)
}

// Replaces client record i's content under the true key: what a malicious sidecar sends.
func testAuthorClientRecord(t *testing.T, statement *partStatement, witness *partWitness, i int, content []byte) {
	t.Helper()
	plaintext := bytes.Clone(content)
	if statement.session.version == tlsVersion13 {
		plaintext = append(plaintext, tlsRecordApplicationData)
	}
	witness.clientPlaintexts[i] = plaintext
	testSeal(t, statement, statement.clientRecords[i], witness.clientKey, witness.clientIv, plaintext)
}

// Replaces server record i as the MX might have said it.
func testAuthorServerRecord(t *testing.T, statement *partStatement, witness *partWitness, i int, plaintext []byte) {
	t.Helper()
	witness.serverPlaintexts[i] = plaintext
	testSeal(t, statement, statement.serverRecords[i], witness.serverKey, witness.serverIv, plaintext)
}

func testServerContent(statement *partStatement, content string) []byte {
	plaintext := []byte(content)
	if statement.session.version == tlsVersion13 {
		plaintext = append(plaintext, tlsRecordApplicationData)
	}
	return plaintext
}

// Requires exactly one failing check, the named one.
func testExpectOnly(t *testing.T, name string, statement *partStatement, witness *partWitness, check relationCheck) {
	t.Helper()
	failures := relationCheckPart(statement, witness)
	if len(failures) != 1 || failures[0].check != check {
		t.Errorf("%s: want only %s to refuse, got %v", name, check, failures)
	}
}

func testBdatCapture(t *testing.T, leg *testTlsLeg) *testCapturedParts {
	t.Helper()
	return testCapture(t, leg, testMxDefaults(), DefaultProverSettings(), testJob("one line\r\n", "bob", "carol"))
}

func testDataCapture(t *testing.T, leg *testTlsLeg) *testCapturedParts {
	t.Helper()
	settings := DefaultProverSettings()
	settings.ForceData = true
	return testCapture(t, leg, testMxDefaults(), settings, testJob("one line\r\nanother line\r\n", "bob", "carol"))
}

func TestHonestWitnessesSatisfyEveryCheck(t *testing.T) {
	for _, leg := range testTlsLegs() {
		for _, capture := range []*testCapturedParts{testBdatCapture(t, leg), testDataCapture(t, leg)} {
			for i, statement := range capture.statements {
				if failures := relationCheckPart(statement, capture.witnesses[i]); len(failures) != 0 {
					t.Errorf("%s: %s: %v", leg.name, testFormat(statement), failures)
				}
			}
		}
	}
}

// Z1

func TestZ1RefusesKeySubstitution(t *testing.T) {
	// the headline attack (SPEC.md 9.2): a ciphertext authored to open to a benign EHLO under a key of
	// the sidecar's choosing, while the real key opens it to something else. No other check can see
	// it, because under the substituted key every plaintext is exactly what the part claims.
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 1)
		substitute := bytes.Clone(witness.clientKey)
		substitute[0] ^= 1
		benign := bytes.Clone(witness.clientPlaintexts[0])
		testSeal(t, statement, statement.clientRecords[0], substitute, witness.clientIv, benign)
		witness.clientKey = substitute
		testExpectOnly(t, leg.name, statement, witness, checkZ1)
	}
}

func TestZ1RefusesASubstitutedIv(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 1)
		substitute := bytes.Clone(witness.clientIv)
		substitute[0] ^= 1
		testSeal(t, statement, statement.clientRecords[0], witness.clientKey, substitute, witness.clientPlaintexts[0])
		witness.clientIv = substitute
		testExpectOnly(t, leg.name, statement, witness, checkZ1)
	}
}

func TestZ1RefusesASubstitutedServerKey(t *testing.T) {
	// forging an MX reply needs the MX's key, and any other key fails here
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 2)
		substitute := bytes.Clone(witness.serverKey)
		substitute[0] ^= 1
		for i, record := range statement.serverRecords {
			testSeal(t, statement, record, substitute, witness.serverIv, witness.serverPlaintexts[i])
		}
		witness.serverKey = substitute
		testExpectOnly(t, leg.name, statement, witness, checkZ1)
	}
}

func TestZ1RefusesAnUnrelatedSecret(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 1)
		other := make([]byte, 48)
		rand.Read(other)
		if statement.session.version == tlsVersion13 {
			witness.handshakeSecret = other[:tlsSecretBytes]
		} else {
			witness.masterSecret = other
		}
		testExpectOnly(t, leg.name, statement, witness, checkZ1)
	}
}

func TestZ1BindsTheHandshakeInputs(t *testing.T) {
	// the same keys under another observed handshake are not this connection's
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 1)
		session := statement.session
		if session.version == tlsVersion13 {
			session.helloHash = bytes.Clone(session.helloHash)
			session.helloHash[0] ^= 1
			testExpectOnly(t, leg.name, statement, witness, checkZ1)
			statement, witness = capture.part(t, 1)
			session = statement.session
			session.finishedHash = bytes.Clone(session.finishedHash)
			session.finishedHash[0] ^= 1
			testExpectOnly(t, leg.name, statement, witness, checkZ1)
			continue
		}
		session.serverRandom = bytes.Clone(session.serverRandom)
		session.serverRandom[0] ^= 1
		testExpectOnly(t, leg.name, statement, witness, checkZ1)
		statement, witness = capture.part(t, 1)
		session = statement.session
		session.serverFinishedRecord = bytes.Clone(session.serverFinishedRecord)
		session.serverFinishedRecord[tlsRecordHeaderBytes+tlsExplicitNonceBytes] ^= 1
		testExpectOnly(t, leg.name, statement, witness, checkZ1)
	}
}

// Z2

func TestZ2RefusesAClaimedPlaintextTheCiphertextDoesNotHold(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 1)
		// the witness still claims the true EHLO, over a ciphertext that does not hold it
		record := statement.clientRecords[0]
		record.raw[len(record.raw)-tlsAeadTagBytes-2] ^= 1
		testExpectOnly(t, leg.name, statement, witness, checkZ2)
	}
}

func TestZ2RefusesAClaimedServerPlaintext(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 3)
		record := statement.serverRecords[0]
		record.raw[len(record.raw)-tlsAeadTagBytes-2] ^= 1
		testExpectOnly(t, leg.name, statement, witness, checkZ2)
	}
}

func TestZ2BindsTheSequenceNumberIn13(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 2)
		// a record proved at one position opens differently at another, so it cannot be replayed there
		statement.clientRecords[0].seq += 1
		testExpectOnly(t, leg.name, statement, witness, checkZ2)
	}
}

// Z3

func TestZ3RefusesAnotherInnerType(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 1)
		plaintext := witness.clientPlaintexts[0]
		// a handshake record, as a KeyUpdate would be
		plaintext[len(plaintext)-1] = tlsRecordHandshake
		testSeal(t, statement, statement.clientRecords[0], witness.clientKey, witness.clientIv, plaintext)
		testExpectOnly(t, leg.name, statement, witness, checkZ3)
	}
}

func TestZ3RefusesAnotherOuterTypeIn12(t *testing.T) {
	leg := testTlsLegs()[2]
	capture := testBdatCapture(t, leg)
	statement, witness := capture.part(t, 1)
	statement.clientRecords[0].raw[0] = tlsRecordHandshake
	testExpectOnly(t, leg.name, statement, witness, checkZ3)
}

// Z4

func TestZ4RefusesEveryWrongCommand(t *testing.T) {
	cases := []struct {
		name    string
		index   uint32
		record  int
		content string
	}{
		{name: "another HELO name", index: 1, record: 0, content: "EHLO attacker.example\r\n"},
		{name: "HELO for EHLO", index: 1, record: 0, content: "HELO " + testHeloName + "\r\n"},
		{name: "MAIL from another domain", index: 2, record: 0, content: "MAIL FROM:<bounce-1@victim.example>\r\n"},
		{name: "MAIL with a smuggled parameter", index: 2, record: 0, content: "MAIL FROM:<bounce-1@" + testEnvelopeDomain + "> AUTH=<>\r\n"},
		{name: "RCPT at another domain", index: 2, record: 1, content: "RCPT TO:<bob@other.example>\r\n"},
		{name: "RCPT with a second address in its local part", index: 2, record: 1, content: "RCPT TO:<a,b@" + testRecipientDomain + ">\r\n"},
		{name: "RCPT by percent routing", index: 2, record: 1, content: "RCPT TO:<bob%other.example@" + testRecipientDomain + ">\r\n"},
		{name: "RCPT by a bang path", index: 2, record: 1, content: "RCPT TO:<other.example!bob@" + testRecipientDomain + ">\r\n"},
		{name: "RCPT by a source route", index: 2, record: 1, content: "RCPT TO:<@other.example:bob@" + testRecipientDomain + ">\r\n"},
		{name: "two commands in one record", index: 2, record: 1, content: "RCPT TO:<bob@" + testRecipientDomain + ">\r\nMAIL FROM:<x@" + testEnvelopeDomain + ">\r\n"},
		{name: "a command split across records", index: 2, record: 1, content: "RCPT TO:<bob@recip"},
		{name: "BDAT of another size", index: 3, record: 0, content: "BDAT 1 LAST\r\n"},
		{name: "BDAT that is not LAST", index: 3, record: 0, content: "BDAT 1000\r\n"},
	}
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		for _, c := range cases {
			statement, witness := capture.part(t, c.index)
			testAuthorClientRecord(t, statement, witness, c.record, []byte(c.content))
			testExpectOnly(t, leg.name+": "+c.name, statement, witness, checkZ4)
		}
	}
}

func TestZ4RefusesAWrongRecipientCount(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 2)
		// a declared count below the commands sent: what a quota evader would try
		statement.session.preamble.recipientCount -= 1
		testExpectOnly(t, leg.name, statement, witness, checkZ4)
	}
}

func TestZ4RefusesAPipelinedSecondTransaction(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 2)
		extra := &partRecord{seq: statement.clientRecords[len(statement.clientRecords)-1].seq + 1, raw: bytes.Clone(statement.clientRecords[0].raw)}
		statement.clientRecords = append(statement.clientRecords, extra)
		witness.clientPlaintexts = append(witness.clientPlaintexts, nil)
		testAuthorClientRecord(t, statement, witness, len(statement.clientRecords)-1, []byte("MAIL FROM:<second@"+testEnvelopeDomain+">\r\n"))
		testExpectOnly(t, leg.name, statement, witness, checkZ4)
	}
}

// Z5

// Authors a header block under a declared count that fits it, as a malicious sidecar would, so that
// the block itself is all that differs.
func testAuthorHeaderBlock(t *testing.T, statement *partStatement, witness *partWitness, block string) {
	t.Helper()
	statement.session.preamble.messageByteCount = 100000
	testAuthorClientRecord(t, statement, witness, 0, []byte("BDAT 100000 LAST\r\n"))
	testAuthorClientRecord(t, statement, witness, 1, []byte(block))
}

// One header block a malicious sidecar might author, which Z5 must refuse.
type testHeaderCase struct {
	name  string
	block string
}

// Every smuggled header, shared with the circuit's differential test.
func testSmuggledHeaders(t *testing.T) []testHeaderCase {
	t.Helper()
	header := testHeaderBlock()
	fromLine := "From: Alice Example <alice@" + testNetworkDomain + ">\r\n"
	replaced := func(old string, new string) string {
		if !strings.Contains(header, old) {
			t.Fatalf("fixture lacks %q", old)
		}
		return strings.Replace(header, old, new, 1)
	}
	return []testHeaderCase{
		{name: "a second From", block: fromLine + header},
		{name: "a second From in another case", block: "FROM: <x@victim.example>\r\n" + header},
		{name: "From before a colon-spaced name", block: "From : <x@victim.example>\r\n" + header},
		{name: "From in another domain", block: replaced(fromLine, "From: Alice <alice@victim.example>\r\n")},
		{name: "two addresses in From", block: replaced(fromLine, "From: <x@victim.example>, <alice@"+testNetworkDomain+">\r\n")},
		{name: "an address hidden in the phrase", block: replaced(fromLine, "From: x@victim.example <alice@"+testNetworkDomain+">\r\n")},
		{name: "a continued From", block: replaced(fromLine, fromLine+" <x@victim.example>\r\n")},
		{name: "no From", block: replaced(fromLine, "")},
		{name: "another Message-ID", block: replaced(testMessageId, "other@"+testNetworkDomain)},
		{name: "a second Message-ID", block: "Message-ID: <x@" + testNetworkDomain + ">\r\n" + header},
		{name: "another X-UR-Ref", block: replaced(testXUrRef, "1.ZZZZ")},
		{name: "another Feedback-ID", block: replaced(testFeedbackId, "x:y:z:urnetwork")},
		{name: "no fixed DKIM signature", block: replaced("DKIM-Signature: v=1;", "X-Not-Dkim: v=1;")},
		{name: "DKIM under another d=", block: replaced("d="+testNetworkDomain, "d=victim.example")},
		{name: "DKIM under another s=", block: replaced("s="+testSelector, "s=other")},
		{name: "DKIM not covering the reference", block: replaced("x-ur-ref:", "")},
		{name: "a second fixed signature", block: replaced("DKIM-Signature: v=1;", "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; d=x\r\nDKIM-Signature: v=1;")},
		{name: "a bare LF", block: replaced("Subject: A", "Subject:\nFrom: <x@victim.example>\r\nX: A")},
		{name: "a bare CR", block: replaced("Subject: A", "Subject:\rA")},
		{name: "an early end of the header block", block: replaced("Subject: A", "\r\nSubject: A")},
		{name: "an octet outside the class", block: replaced("Subject: A", "Subject: \x00A")},
		{name: "a line with no field name", block: replaced("Subject: A", "no field name here")},
		{name: "a first line that is a continuation", block: " folded\r\n" + header},
		{name: "no end of the header block", block: strings.TrimSuffix(header, "\r\n")},
	}
}

func TestZ5RefusesEverySmuggledHeader(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		for _, c := range testSmuggledHeaders(t) {
			statement, witness := capture.part(t, 3)
			testAuthorHeaderBlock(t, statement, witness, c.block)
			testExpectOnly(t, leg.name+": "+c.name, statement, witness, checkZ5)
		}
	}
}

func TestZ5RequiresUnsubscribeOnBulk(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 3)
		statement.session.preamble.flags |= preambleFlagBulk
		testExpectOnly(t, leg.name, statement, witness, checkZ5)

		testAuthorHeaderBlock(t, statement, witness, literalUnsubscribePost+"\r\n"+testHeaderBlock())
		if failures := relationCheckPart(statement, witness); len(failures) != 0 {
			t.Errorf("%s: %v", leg.name, failures)
		}
	}
}

func TestZ5AcceptsFormsAnHonestMessageUses(t *testing.T) {
	preamble := &sessionPreamble{
		messageId: testMessageId, headerFromDomain: testNetworkDomain, dkimSelector: testSelector,
		xUrRef: testXUrRef, feedbackId: testFeedbackId,
	}
	header := testHeaderBlock()
	fromLine := "From: Alice Example <alice@" + testNetworkDomain + ">\r\n"
	for _, block := range []string{
		header,
		strings.Replace(header, fromLine, "From: <alice@"+testNetworkDomain+">\r\n", 1),
		strings.Replace(header, fromLine, "From: =?utf-8?q?Al=C3=ADce?= <alice@"+testNetworkDomain+">\r\n", 1),
		// a folded field the relation does not constrain
		strings.Replace(header, "Subject: A synthetic", "Subject: A\r\n synthetic", 1),
		// the fuller signature beside the fixed one
		"DKIM-Signature: v=1; d=" + testNetworkDomain + "; s=" + testSelector + "; h=from:to:subject; bh=A; b=B\r\n" + header,
	} {
		if err := checkHeaderBlock([]byte(block), preamble); err != nil {
			t.Errorf("%q: %v", block, err)
		}
	}
}

// Z6

func TestZ6RefusesABdatEndThatIsNotQuit(t *testing.T) {
	cases := []string{"RSET\r\n", "QUIT\r\nMAIL FROM:<x@" + testEnvelopeDomain + ">\r\n", "QUIT"}
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		for _, content := range cases {
			statement, witness := capture.part(t, 3)
			testAuthorClientRecord(t, statement, witness, 2, []byte(content))
			testExpectOnly(t, leg.name+": "+content, statement, witness, checkZ6)
		}
	}
}

func TestZ6RefusesAHeaderBlockPastTheDeclaredCount(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 3)
		// n stays in the BDAT line's literal by re-authoring it, so only the count is out
		statement.session.preamble.messageByteCount = 10
		testAuthorClientRecord(t, statement, witness, 0, []byte("BDAT 10 LAST\r\n"))
		testExpectOnly(t, leg.name, statement, witness, checkZ6)
	}
}

func TestZ6RefusesEverySmuggledDataEnd(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{name: "the end mark inside the record", content: "first\r\n.\r\nMAIL FROM:<x@" + testEnvelopeDomain + ">\r\n"},
		{name: "an end mark at the record's start", content: ".\r\nMAIL FROM:<x@" + testEnvelopeDomain + ">\r\n"},
		{name: "a bare-LF end", content: "first\n.\nMAIL FROM:<x@" + testEnvelopeDomain + ">\r\n"},
		{name: "a bare-LF dot before CRLF", content: "first\n.\r\n"},
		{name: "a bare-CR end", content: "first\r.\r\n"},
		{name: "a record ending inside a line", content: "first\r\nunfinished"},
	}
	for _, leg := range testTlsLegs() {
		capture := testDataCapture(t, leg)
		for _, c := range cases {
			statement, witness := capture.part(t, 3)
			testAuthorClientRecord(t, statement, witness, 1, []byte(c.content))
			testExpectOnly(t, leg.name+": "+c.name, statement, witness, checkZ6)
		}
	}
}

func TestZ6RefusesABadEndOfData(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testDataCapture(t, leg)
		statement, witness := capture.part(t, 3)
		end := len(statement.clientRecords) - 2
		testAuthorClientRecord(t, statement, witness, end, []byte(".\n"))
		testExpectOnly(t, leg.name, statement, witness, checkZ6)
	}
}

func TestZ6AcceptsADotStuffedLine(t *testing.T) {
	if err := checkDataLines([]byte("first\r\n..\r\n.leading dot\r\n")); err != nil {
		t.Error(err)
	}
}

// Z7

func TestZ7RefusesAServerKeyUpdate(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 2)
		content := append([]byte{tlsHandshakeKeyUpdate, 0, 0, 1, 0}, tlsRecordHandshake)
		testAuthorServerRecord(t, statement, witness, 0, content)
		// Z8 and Z9 have nothing they can parse, so they leave the record to Z7
		testExpectOnly(t, leg.name, statement, witness, checkZ7)
	}
}

func TestZ7RefusesAnAlert(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 2)
		testAuthorServerRecord(t, statement, witness, 0, []byte{1, 0, tlsRecordAlert})
		testExpectOnly(t, leg.name, statement, witness, checkZ7)
	}
}

func TestZ7RefusesAnOuterTypeIn12(t *testing.T) {
	leg := testTlsLegs()[2]
	capture := testBdatCapture(t, leg)
	statement, witness := capture.part(t, 2)
	statement.serverRecords[0].raw[0] = tlsRecordHandshake
	testExpectOnly(t, leg.name, statement, witness, checkZ7)
}

func TestZ7SkipsATicket(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 3)
		// a late ticket among the part's records leaves the reply stream as it was
		ticket := &partRecord{seq: statement.serverRecords[len(statement.serverRecords)-1].seq + 1, raw: bytes.Clone(statement.serverRecords[0].raw)}
		statement.serverRecords = append(statement.serverRecords, ticket)
		witness.serverPlaintexts = append(witness.serverPlaintexts, nil)
		testAuthorServerRecord(t, statement, witness, len(statement.serverRecords)-1, []byte{tlsHandshakeNewSessionTicket, 0, 0, 0, tlsRecordHandshake})
		if failures := relationCheckPart(statement, witness); len(failures) != 0 {
			t.Errorf("%s: %v", leg.name, failures)
		}
	}
}

// Z8

func TestZ8RefusesEveryReplyTheFlowCannotTreatAsAccepted(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{name: "a refused MAIL", content: "550 5.7.1 Refused\r\n250 2.1.5 Ok\r\n250 2.1.5 Ok\r\n"},
		{name: "a refused RCPT", content: "250 2.1.0 Ok\r\n550 5.1.1 Unknown\r\n250 2.1.5 Ok\r\n"},
		{name: "a deferred RCPT", content: "250 2.1.0 Ok\r\n451 4.3.0 Later\r\n250 2.1.5 Ok\r\n"},
		{name: "a missing reply", content: "250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n"},
		{name: "an extra reply", content: "250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n250 2.1.5 Ok\r\n250 Ok\r\n"},
		{name: "a truncated reply", content: "250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n250 2.1"},
		{name: "a reply ending inside a multiline", content: "250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n250-more\r\n"},
		{name: "a malformed code", content: "250 2.1.0 Ok\r\n25x bad\r\n250 2.1.5 Ok\r\n"},
		{name: "a bare LF", content: "250 2.1.0 Ok\n250 2.1.5 Ok\r\n250 2.1.5 Ok\r\n"},
	}
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		for _, c := range cases {
			statement, witness := capture.part(t, 3)
			// the whole stream as the first record, the rest emptied, so the replies alone differ
			statement.serverRecords = statement.serverRecords[:1]
			witness.serverPlaintexts = witness.serverPlaintexts[:1]
			testAuthorServerRecord(t, statement, witness, 0, testServerContent(statement, c.content))
			testExpectOnly(t, leg.name+": "+c.name, statement, witness, checkZ8)
		}
	}
}

func TestZ8RefusesAnEhloReplyOfAnotherCode(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 2)
		statement.serverRecords = statement.serverRecords[:1]
		witness.serverPlaintexts = witness.serverPlaintexts[:1]
		testAuthorServerRecord(t, statement, witness, 0, testServerContent(statement, "251-mx\r\n250-CHUNKING\r\n250 OK\r\n"))
		testExpectOnly(t, leg.name, statement, witness, checkZ8)
	}
}

func TestZ8RequiresThe354(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testDataCapture(t, leg)
		statement, witness := capture.part(t, 3)
		statement.serverRecords = statement.serverRecords[:1]
		witness.serverPlaintexts = witness.serverPlaintexts[:1]
		testAuthorServerRecord(t, statement, witness, 0, testServerContent(statement, "250 Ok\r\n250 Ok\r\n250 Ok\r\n250 Ok\r\n"))
		testExpectOnly(t, leg.name, statement, witness, checkZ8)
	}
}

func TestZ8RefusesAReplyDuringTheMessage(t *testing.T) {
	settings := DefaultProverSettings()
	settings.ForceData = true
	settings.DataPartBytes = 64
	for _, leg := range testTlsLegs() {
		capture := testCapture(t, leg, testMxDefaults(), settings, testJob(strings.Repeat("a body line here\r\n", 12), "bob"))
		statement, witness := capture.part(t, 4)
		sample := testCloneRecords(capture.statements[2].serverRecords[:1])
		statement.serverRecords = sample
		witness.serverPlaintexts = [][]byte{nil}
		testAuthorServerRecord(t, statement, witness, 0, testServerContent(statement, "421 4.3.2 Closing\r\n"))
		testExpectOnly(t, leg.name, statement, witness, checkZ8)
	}
}

// Z9

func TestZ9RefusesBdatToAnMxWithoutChunking(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{name: "not offered", content: "250-mx\r\n250-PIPELINING\r\n250 SMTPUTF8\r\n"},
		{name: "only in the MX's name line", content: "250-CHUNKING\r\n250 SMTPUTF8\r\n"},
		{name: "inside another keyword", content: "250-mx\r\n250-XCHUNKINGX\r\n250 SMTPUTF8\r\n"},
		{name: "a one-line reply", content: "250 mx\r\n"},
	}
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		for _, c := range cases {
			statement, witness := capture.part(t, 2)
			statement.serverRecords = statement.serverRecords[:1]
			witness.serverPlaintexts = witness.serverPlaintexts[:1]
			testAuthorServerRecord(t, statement, witness, 0, testServerContent(statement, c.content))
			testExpectOnly(t, leg.name+": "+c.name, statement, witness, checkZ9)
		}
	}
}

func TestZ9AcceptsChunkingInAnyCaseAndPosition(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testBdatCapture(t, leg)
		for _, content := range []string{"250-mx\r\n250 chunking\r\n", "250-mx\r\n250-ChUnKiNg\r\n250 OK\r\n"} {
			statement, witness := capture.part(t, 2)
			statement.serverRecords = statement.serverRecords[:1]
			witness.serverPlaintexts = witness.serverPlaintexts[:1]
			testAuthorServerRecord(t, statement, witness, 0, testServerContent(statement, content))
			if failures := relationCheckPart(statement, witness); len(failures) != 0 {
				t.Errorf("%s: %q: %v", leg.name, content, failures)
			}
		}
	}
}

func TestZ9LeavesDataToAnyMx(t *testing.T) {
	for _, leg := range testTlsLegs() {
		capture := testDataCapture(t, leg)
		statement, witness := capture.part(t, 2)
		statement.serverRecords = statement.serverRecords[:1]
		witness.serverPlaintexts = witness.serverPlaintexts[:1]
		testAuthorServerRecord(t, statement, witness, 0, testServerContent(statement, "250 mx\r\n"))
		if failures := relationCheckPart(statement, witness); len(failures) != 0 {
			t.Errorf("%s: %v", leg.name, failures)
		}
	}
}

func TestAnEmptyWitnessSatisfiesNothing(t *testing.T) {
	for _, index := range []uint32{1, 2, 3, 4} {
		statement := &partStatement{
			session: &sessionStatement{version: tlsVersion13, preamble: &sessionPreamble{}},
			index:   index,
		}
		if len(relationCheckPart(statement, &partWitness{})) == 0 {
			t.Errorf("part %d: an empty witness satisfied the relation", index)
		}
	}
}
