// E3 under every order the network can give: client records, server records, parts, a late server
// record and a part that opens no client record over it, interleaved as a fuzzer chooses
// (DESIGN-DETAILS 3.2.5). Whatever the order, a message record goes only behind verified coverage of
// every server record relayed before it, records go in their stream order and only under a verified
// part, no verified part is replaced, and the MAIL record is reported forwarded exactly when it was
// handed out. And the gate's twins of ProofParts.tla's runs, one test a fence.

package smtpproof

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Where an order is in its run: what has been fed, what has come back.
type testOrderRun struct {
	t        *testing.T
	fixture  *testGateFixture
	gate     *edgeSession
	client   [][]byte
	server   [][]byte
	fedParts int
	// The latest part the gate took, as it was submitted.
	latest *sidecar.SmtpProofPart
	// Records handed back so far, which must be the client's stream in order.
	handed [][]byte
	ended  bool
	// Which relayed server records were the harness's own, a late ticket's stand-ins.
	injectedAt []bool
	// part 2's last record, and the final QUIT's: records between the two are message records.
	envelopeLast uint64
	mailSeq      uint64
	quitSeq      uint64
	firstSeq     uint64
}

func newTestOrderRun(t *testing.T, fixture *testGateFixture) *testOrderRun {
	t.Helper()
	gate := fixture.gate(&testFixedVerifier{})
	next := fixture.replayHandshake(t, gate)
	run := &testOrderRun{
		t:            t,
		fixture:      fixture,
		gate:         gate,
		client:       fixture.clientRecords(next),
		server:       fixture.serverRecords(next),
		envelopeLast: fixture.parts[1].LastRecord,
		mailSeq:      fixture.parts[1].FirstRecord,
		quitSeq:      fixture.parts[len(fixture.parts)-1].LastRecord,
	}
	if fixture.version() == tlsVersion12 {
		run.firstSeq = 1
	}
	// the handshake left server records the gate already holds as application records
	gate.stateLock.Lock()
	run.injectedAt = make([]bool, len(gate.serverRecords))
	gate.stateLock.Unlock()
	return run
}

// Checks what one call handed back, against the gate's state just after it.
func (self *testOrderRun) check(forwarded [][]byte, err error) {
	t := self.t
	t.Helper()
	if self.ended && len(forwarded) != 0 {
		t.Fatalf("%d records passed after the gate ended", len(forwarded))
	}
	if err != nil {
		self.ended = true
		return
	}
	gate := self.gate
	gate.stateLock.Lock()
	covered := gate.coveredServer
	relayed := uint64(len(gate.serverRecords))
	var lastCovered uint64
	for _, part := range gate.parts {
		if 0 < len(part.part.Records) {
			lastCovered = max(lastCovered, part.part.LastRecord)
		}
	}
	gate.stateLock.Unlock()
	for _, record := range forwarded {
		position := len(self.handed)
		if len(self.client) <= position || !bytes.Equal(record, self.client[position]) {
			t.Fatalf("record %d handed out of the stream's order", position)
		}
		seq := self.firstSeq + uint64(position)
		if lastCovered < seq {
			t.Fatalf("record %d passed with no verified part over it", seq)
		}
		// no server record arrives during a call in this one-goroutine harness, so the count after the
		// call is the count before the record went
		if self.envelopeLast < seq && seq < self.quitSeq && covered < relayed {
			t.Fatalf("message record %d passed with %d of %d server records covered", seq, covered, relayed)
		}
		self.handed = append(self.handed, record)
	}
	if mailHanded := self.mailSeq < self.firstSeq+uint64(len(self.handed)); gate.MailForwarded() != mailHanded {
		t.Fatalf("MailForwarded %v with %d records handed", gate.MailForwarded(), len(self.handed))
	}
}

// The relayed position just past the trace's count-th server record, with the harness's own records
// among them: what a fixture part's count is once late records came in between.
func (self *testOrderRun) relayedThrough(count uint64) (uint64, bool) {
	trace := uint64(0)
	for position, injected := range self.injectedAt {
		if trace == count {
			return uint64(position), true
		}
		if !injected {
			trace += 1
		}
	}
	return uint64(len(self.injectedAt)), trace == count
}

// Runs one order: each octet picks the next event.
func (self *testOrderRun) run(choices []byte) {
	for _, choice := range choices {
		switch choice % 7 {
		case 0:
			if len(self.handed) < len(self.client) {
				// records arrive in stream order, so the next is the first not yet fed: the gate holds or
				// hands those it has, and the harness feeds each once
				fed := self.fedClient()
				if fed < len(self.client) {
					self.check(self.gate.ClientRecord(self.client[fed]))
				}
			}
		case 1:
			fed := self.fedServer()
			if fed < len(self.server) {
				self.injectedAt = append(self.injectedAt, false)
				self.check(nil, self.gate.ServerRecord(self.server[fed]))
			}
		case 2:
			// a part only once its server records have been relayed, as an honest prover's is; it covers
			// the late records relayed among them, and takes the next index
			if self.fedParts < len(self.fixture.parts) {
				part := testClonePart(self.fixture.parts[self.fedParts])
				count, relayed := self.relayedThrough(part.ServerRecordCount)
				if relayed {
					self.gate.stateLock.Lock()
					part.Index = uint32(len(self.gate.parts) + 1)
					part.ServerRecordCount = max(count, self.gate.coveredServer)
					self.gate.stateLock.Unlock()
					self.fedParts += 1
					self.latest = part
					self.check(self.gate.VerifyPart(context.Background(), part))
				}
			}
		case 3:
			// a late record from the MX, as a ticket would be, which no part yet covers
			if self.injectedCount() < 3 && 0 < self.fedServer() {
				self.injectedAt = append(self.injectedAt, true)
				self.check(nil, self.gate.ServerRecord(tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 40))))
			}
		case 4:
			// a part that opens no client record, over every late record relayed past the covered count,
			// once part 2 has landed and only late records are uncovered
			self.gate.stateLock.Lock()
			covered := self.gate.coveredServer
			relayed := uint64(len(self.gate.serverRecords))
			landed := len(self.gate.parts)
			nextRecord := self.gate.nextRecord
			self.gate.stateLock.Unlock()
			onlyLate := covered < relayed && 2 <= landed
			for position := covered; onlyLate && position < relayed; position += 1 {
				onlyLate = self.injectedAt[position]
			}
			if onlyLate {
				part := &sidecar.SmtpProofPart{
					SendId:            self.fixture.parts[0].SendId,
					Index:             uint32(landed + 1),
					Mode:              self.fixture.parts[1].Mode,
					FirstRecord:       nextRecord,
					LastRecord:        nextRecord - 1,
					ServerRecordCount: relayed,
					Proof:             []byte{byte(relayed)},
				}
				self.latest = part
				self.check(self.gate.VerifyPart(context.Background(), part))
			}
		case 5:
			// an exact resend of the latest part, which changes nothing
			if self.latest != nil {
				self.check(self.gate.VerifyPart(context.Background(), testClonePart(self.latest)))
			}
		case 6:
			// a stray client record past the stream, such as a close_notify after QUIT
			if self.fedClient() == len(self.client) {
				self.check(self.gate.ClientRecord(tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 30))))
			}
		}
	}
}

// Client records fed so far: those handed out and those the gate holds.
func (self *testOrderRun) fedClient() int {
	self.gate.stateLock.Lock()
	defer self.gate.stateLock.Unlock()
	return len(self.handed) + len(self.gate.heldRecords)
}

// The harness's own late records fed so far.
func (self *testOrderRun) injectedCount() int {
	count := 0
	for _, injected := range self.injectedAt {
		if injected {
			count += 1
		}
	}
	return count
}

// The trace's server records fed so far, those the handshake left included.
func (self *testOrderRun) fedServer() int {
	self.gate.stateLock.Lock()
	defer self.gate.stateLock.Unlock()
	return len(self.gate.serverRecords) - self.injectedCount()
}

func FuzzEdgeRecordOrder(f *testing.F) {
	// the honest order of a pipelined BDAT and DATA send on each leg, then that order with a late
	// record before the message and a part that opens no record over it, and parts racing ahead of
	// their records
	for leg := range 3 {
		f.Add([]byte{byte(leg), 2, 0, 1, 2, 0, 0, 0, 1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 1, 2, 0, 2, 0, 2, 0, 2, 0})
		f.Add([]byte{byte(leg) | 4, 2, 0, 1, 2, 0, 0, 0, 1, 1, 1, 2, 0, 0, 2, 0, 2, 0, 2, 0, 1, 2, 0, 2, 0})
		f.Add([]byte{byte(leg), 2, 0, 1, 2, 0, 0, 0, 1, 1, 1, 3, 2, 0, 0, 0, 4, 0, 0, 5, 2, 0, 2, 0, 6})
		f.Add([]byte{byte(leg), 0, 0, 0, 0, 0, 0, 0, 2, 1, 2, 1, 1, 1, 2, 1, 2, 2, 2, 2, 2})
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 {
			return
		}
		fixture := testCachedFixture(t, int(input[0]&3), input[0]&4 != 0)
		newTestOrderRun(t, fixture).run(input[1:])
	})
}

func TestMailForwardedOnlyOnceTheMailRecordIsHanded(t *testing.T) {
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		open := testOpen(t, fixture, &testFixedVerifier{})
		if open.gate.MailForwarded() {
			t.Fatalf("%s: forwarded before any part", leg.name)
		}
		open.verifyThrough(t, 2)
		if open.gate.MailForwarded() {
			t.Errorf("%s: forwarded once pi2 verified, before its record came", leg.name)
		}
		if forwarded, err := open.gate.ClientRecord(open.client[0]); err != nil || len(forwarded) != 1 {
			t.Fatalf("%s: EHLO: %d forwarded, %v", leg.name, len(forwarded), err)
		}
		if open.gate.MailForwarded() {
			t.Errorf("%s: forwarded with only EHLO handed", leg.name)
		}
		if forwarded, err := open.gate.ClientRecord(open.client[1]); err != nil || len(forwarded) != 1 {
			t.Fatalf("%s: MAIL: %d forwarded, %v", leg.name, len(forwarded), err)
		}
		if !open.gate.MailForwarded() {
			t.Errorf("%s: MAIL handed and not reported", leg.name)
		}
		// it never turns back, not even once the gate ends
		open.gate.ClientRecord(tlsFrameRecord(tlsRecordHandshake, tlsVersion12, make([]byte, 40)))
		if !open.gate.MailForwarded() {
			t.Errorf("%s: MailForwarded turned false", leg.name)
		}
	}
}

func TestMailForwardedIsNotSetByACutThatTookTheBatch(t *testing.T) {
	// MAIL cleared in the same call that cuts on the next record is never handed out, so it never
	// reaches the MX, and the connection owes no unit for it
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		open := testOpen(t, fixture, &testFixedVerifier{})
		open.verifyThrough(t, 1)
		if _, err := open.gate.ClientRecord(open.client[0]); err != nil {
			t.Fatal(err)
		}
		for uint64(len(open.gate.serverRecords)) < fixture.parts[1].ServerRecordCount {
			if err := open.gate.ServerRecord(open.server[0]); err != nil {
				t.Fatal(err)
			}
			open.server = open.server[1:]
		}
		// MAIL honest, the first RCPT tampered, both held for pi2
		tampered := bytes.Clone(open.client[2])
		tampered[len(tampered)-1] ^= 1
		for _, record := range [][]byte{open.client[1], tampered} {
			if forwarded, err := open.gate.ClientRecord(record); err != nil || len(forwarded) != 0 {
				t.Fatalf("%s: %d forwarded before pi2, %v", leg.name, len(forwarded), err)
			}
		}
		forwarded, err := open.gate.VerifyPart(context.Background(), fixture.parts[1])
		testExpectCut(t, leg.name, err)
		if len(forwarded) != 0 || open.gate.MailForwarded() {
			t.Errorf("%s: a cut call handed %d records, MailForwarded %v", leg.name, len(forwarded), open.gate.MailForwarded())
		}
	}
}

func TestE3RefusesAServerRecordCountThatFalls(t *testing.T) {
	// a new part may cover more server records than the last, never fewer: the records it would give
	// up were the reason earlier message records were released
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		open := testOpen(t, fixture, &testFixedVerifier{})
		open.verifyThrough(t, 2)
		for uint64(len(open.gate.serverRecords)) < fixture.parts[2].ServerRecordCount {
			if err := open.gate.ServerRecord(open.server[0]); err != nil {
				t.Fatal(err)
			}
			open.server = open.server[1:]
		}
		fallen := *fixture.parts[2]
		fallen.ServerRecordCount = fixture.parts[1].ServerRecordCount - 1
		_, err := open.gate.VerifyPart(context.Background(), &fallen)
		testExpectCheck(t, leg.name, err, checkE3)
	}
}

func TestE3CutsAChunkOneOctetPastNAndPassesOneThatEndsAtN(t *testing.T) {
	// E3 step 4 at its boundary: the relayed body records bring BDAT's chunk to octet n exactly, and
	// pass with QUIT after them; the same records with the last one octet longer pass n by one and cut
	// there, forwarding nothing more
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		for _, over := range []bool{false, true} {
			open := testOpen(t, fixture, &testFixedVerifier{})
			open.verifyThrough(t, 3)
			// EHLO, MAIL, RCPT, BDAT and the header block, then the unopened body, then QUIT
			lastBody := len(open.client) - 2
			if lastBody < 5 {
				t.Fatalf("%s: %d client records, no body between the head and QUIT", leg.name, len(open.client))
			}
			handed := 0
			for i, record := range open.client {
				if over && i == lastBody {
					longer := append(bytes.Clone(record), 0)
					size := len(longer) - tlsRecordHeaderBytes
					longer[3], longer[4] = byte(size>>8), byte(size)
					forwarded, err := open.gate.ClientRecord(longer)
					if len(forwarded) != 0 {
						t.Errorf("%s: %d records passed with the chunk one octet past n", leg.name, len(forwarded))
					}
					testExpectCut(t, leg.name, err)
					break
				}
				forwarded, err := open.gate.ClientRecord(record)
				if err != nil {
					t.Fatalf("%s: record %d: %v", leg.name, i, err)
				}
				handed += len(forwarded)
			}
			if over {
				continue
			}
			open.gate.stateLock.Lock()
			chunkOctets, finished := open.gate.chunkOctets, open.gate.finished
			open.gate.stateLock.Unlock()
			if handed != len(open.client) || chunkOctets != open.fixture.preamble.messageByteCount || !finished {
				t.Errorf("%s: %d of %d records handed, chunk at %d of %d, finished %v",
					leg.name, handed, len(open.client), chunkOctets, open.fixture.preamble.messageByteCount, finished)
			}
		}
	}
}

// A part as the sidecar might send it, a copy the test can change.
func testClonePart(part *sidecar.SmtpProofPart) *sidecar.SmtpProofPart {
	clone := *part
	clone.Records = testCloneByteSlices(part.Records)
	clone.KeyCommitment = bytes.Clone(part.KeyCommitment)
	clone.Carry = bytes.Clone(part.Carry)
	return &clone
}

// A gate through part index-1 of a fixture, with every server record the part at index covers relayed,
// and what the gate says to that part changed as mutate changes it.
func testGateVerdictOn(t *testing.T, fixture *testGateFixture, index uint32, verifier partVerifier, mutate func(part *sidecar.SmtpProofPart)) error {
	t.Helper()
	open := testOpen(t, fixture, verifier)
	if 1 < index {
		open.verifyThrough(t, index-1)
	}
	part := testClonePart(fixture.parts[index-1])
	mutate(part)
	for uint64(len(open.gate.serverRecords)) < max(part.ServerRecordCount, fixture.parts[index-1].ServerRecordCount) && 0 < len(open.server) {
		if err := open.gate.ServerRecord(open.server[0]); err != nil {
			t.Fatal(err)
		}
		open.server = open.server[1:]
	}
	_, err := open.gate.VerifyPart(context.Background(), part)
	return err
}

// A send whose header block takes two records under every family: the single fields and the fixed
// signature first, then fields that bring it past what a msg shape's head holds.
func testTwoRecordHeaderGateCapture(t *testing.T, leg *testTlsLeg, data bool) *testGateFixture {
	t.Helper()
	settings := DefaultProverSettings()
	settings.ForceData = data
	job := testJob("", "bob")
	job.Message = []byte(testOrderedHeaderBlock(24) + "one line\r\n")
	job.Preamble.MessageByteCount = uint64(len(job.Message))
	if data {
		job.Preamble.MessageByteCount = uint64(len(dotStuffed(job.Message)))
	}
	fixture := testGateCapture(t, leg, testMxDefaults(), settings, job)
	if fixture.parts[2].HeaderRecordCount != 2 {
		t.Fatalf("%s: the header block takes %d records", leg.name, fixture.parts[2].HeaderRecordCount)
	}
	return fixture
}

func TestGateStep1RefusesAfterTheEndAndHoldsAPartMootOnceTheMxCloses(t *testing.T) {
	leg := testTlsLegs()[0]
	fixture := testBdatGateCapture(t, leg)
	open := testOpen(t, fixture, &testFixedVerifier{})
	open.verifyThrough(t, 1)
	open.gate.ServerClosed()
	if forwarded, err := open.gate.VerifyPart(context.Background(), fixture.parts[1]); err != nil || len(forwarded) != 0 {
		t.Errorf("a part once the MX closed: %d forwarded, %v", len(forwarded), err)
	}
	open = testOpen(t, fixture, &testFixedVerifier{})
	open.gate.end()
	if _, err := open.gate.VerifyPart(context.Background(), fixture.parts[0]); err == nil {
		t.Error("a part after the session ended passed")
	}
}

func TestGateStep2RefusesAPartBeforeTheHandshakesInputs(t *testing.T) {
	fixture := testBdatGateCapture(t, testTlsLegs()[0])
	gate := fixture.gate(&testFixedVerifier{})
	_, err := gate.VerifyPart(context.Background(), fixture.parts[0])
	testExpectCheck(t, "before the handshake", err, checkE3)
}

func TestGateStep3PassesAnExactResendAndRefusesAnyOther(t *testing.T) {
	fixture := testBdatGateCapture(t, testTlsLegs()[0])
	open := testOpen(t, fixture, &testFixedVerifier{})
	open.verifyThrough(t, 2)
	if forwarded, err := open.gate.VerifyPart(context.Background(), testClonePart(fixture.parts[1])); err != nil || len(forwarded) != 0 {
		t.Errorf("an exact resend: %d forwarded, %v", len(forwarded), err)
	}
	changed := testClonePart(fixture.parts[1])
	changed.Proof = []byte("another proof")
	_, err := open.gate.VerifyPart(context.Background(), changed)
	testExpectCheck(t, "a changed resend", err, checkE3)
	for _, index := range []uint32{0, 4} {
		err := testGateVerdictOn(t, fixture, 3, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.Index = index })
		testExpectCheck(t, fmt.Sprintf("index %d at 3", index), err, checkE3)
	}
}

func TestGateStep4HoldsTheKeyPartToEhloAndCToItAlone(t *testing.T) {
	fixture := testBdatGateCapture(t, testTlsLegs()[0])
	for name, mutate := range map[string]func(part *sidecar.SmtpProofPart){
		"a mode":                 func(part *sidecar.SmtpProofPart) { part.Mode = partModeBdat },
		"a reply count":          func(part *sidecar.SmtpProofPart) { part.ReplyCount = 1 },
		"a header record count":  func(part *sidecar.SmtpProofPart) { part.HeaderRecordCount = 1 },
		"a carry":                func(part *sidecar.SmtpProofPart) { part.Carry = bytes.Clone(part.KeyCommitment) },
		"last":                   func(part *sidecar.SmtpProofPart) { part.Last = true },
		"a short commitment":     func(part *sidecar.SmtpProofPart) { part.KeyCommitment = part.KeyCommitment[1:] },
		"a commitment off curve": func(part *sidecar.SmtpProofPart) { part.KeyCommitment[63] ^= 1 },
	} {
		testExpectCheck(t, "the key part with "+name, testGateVerdictOn(t, fixture, 1, &testFixedVerifier{}, mutate), checkE3)
	}
	err := testGateVerdictOn(t, fixture, 2, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.KeyCommitment = bytes.Clone(fixture.parts[0].KeyCommitment) })
	testExpectCheck(t, "part 2 with a key commitment", err, checkE3)
}

func TestGateStep5HoldsTheClientRange(t *testing.T) {
	fixture := testBdatGateCapture(t, testTlsLegs()[0])
	for name, c := range map[string]struct {
		index  uint32
		mutate func(part *sidecar.SmtpProofPart)
	}{
		"a gap before the first record":        {index: 2, mutate: func(part *sidecar.SmtpProofPart) { part.FirstRecord += 1; part.LastRecord += 1 }},
		"no record with another last_record":   {index: 3, mutate: func(part *sidecar.SmtpProofPart) { part.Records = nil; part.Last = false; part.Carry = nil }},
		"records not reaching last_record":     {index: 2, mutate: func(part *sidecar.SmtpProofPart) { part.LastRecord += 1 }},
		"more records than a part may open":    {index: 2, mutate: func(part *sidecar.SmtpProofPart) { part.Records = slices.Repeat(part.Records[:1], 65) }},
		"a record that is no application data": {index: 2, mutate: func(part *sidecar.SmtpProofPart) { part.Records[0][0] = tlsRecordHandshake }},
	} {
		testExpectCheck(t, name, testGateVerdictOn(t, fixture, c.index, &testFixedVerifier{}, c.mutate), checkE3)
	}
	// after the last part, a part may open no record
	open := testOpen(t, fixture, &testFixedVerifier{})
	open.verifyThrough(t, uint32(len(fixture.parts)))
	after := testClonePart(fixture.parts[1])
	after.Index = uint32(len(fixture.parts) + 1)
	after.FirstRecord = fixture.parts[len(fixture.parts)-1].LastRecord + 1
	after.LastRecord = after.FirstRecord + uint64(len(after.Records)) - 1
	after.ReplyCount = 0
	_, err := open.gate.VerifyPart(context.Background(), after)
	testExpectCheck(t, "a record after the last part", err, checkE3)
}

func TestGateStep6HoldsTheServerRange(t *testing.T) {
	fixture := testBdatGateCapture(t, testTlsLegs()[0])
	err := testGateVerdictOn(t, fixture, 3, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.ServerRecordCount = 0 })
	testExpectCheck(t, "a count that fell", err, checkE3)
	err = testGateVerdictOn(t, fixture, 3, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.ServerRecordCount += 100 })
	testExpectCheck(t, "a count past what was relayed", err, checkE3)
	// a part that opens no record covers at least one more
	open := testOpen(t, fixture, &testFixedVerifier{})
	open.verifyThrough(t, 2)
	empty := &sidecar.SmtpProofPart{SendId: fixture.parts[1].SendId, Index: 3, Mode: fixture.parts[1].Mode, FirstRecord: fixture.parts[1].LastRecord + 1, LastRecord: fixture.parts[1].LastRecord, ServerRecordCount: fixture.parts[1].ServerRecordCount}
	_, err = open.gate.VerifyPart(context.Background(), empty)
	testExpectCheck(t, "a part over nothing", err, checkE3)
}

func TestGateStep7HoldsTheMode(t *testing.T) {
	fixture := testBdatGateCapture(t, testTlsLegs()[0])
	testExpectCheck(t, "an unknown mode", testGateVerdictOn(t, fixture, 2, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.Mode = 3 }), checkE3)
	testExpectCheck(t, "a changed mode", testGateVerdictOn(t, fixture, 3, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.Mode = partModeData }), checkE3)
}

func TestGateStep8HoldsRolesKindsAndK(t *testing.T) {
	fixture := testBdatGateCapture(t, testTlsLegs()[0])
	for name, c := range map[string]struct {
		index  uint32
		mutate func(part *sidecar.SmtpProofPart)
	}{
		"k on an env part":        {index: 2, mutate: func(part *sidecar.SmtpProofPart) { part.HeaderRecordCount = 1 }},
		"no k on the msg part":    {index: 3, mutate: func(part *sidecar.SmtpProofPart) { part.HeaderRecordCount = 0 }},
		"k past the most records": {index: 3, mutate: func(part *sidecar.SmtpProofPart) { part.HeaderRecordCount = 17 }},
		"BDAT's header without QUIT": {index: 3, mutate: func(part *sidecar.SmtpProofPart) {
			part.Records = part.Records[:2]
			part.LastRecord = part.FirstRecord + 1
			part.Last = false
		}},
		"an envelope part that is last": {index: 2, mutate: func(part *sidecar.SmtpProofPart) { part.Last = true }},
	} {
		testExpectCheck(t, name, testGateVerdictOn(t, fixture, c.index, &testFixedVerifier{}, c.mutate), checkE3)
	}
}

func TestGateStep9CountsReplies(t *testing.T) {
	fixture := testBdatGateCapture(t, testTlsLegs()[0])
	testExpectCheck(t, "part 2 of two replies", testGateVerdictOn(t, fixture, 2, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.ReplyCount = 2 }), checkE3)
	testExpectCheck(t, "more replies than commands", testGateVerdictOn(t, fixture, 3, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.ReplyCount += 1 }), checkE3)
	testExpectCheck(t, "a message before the envelope's replies", testGateVerdictOn(t, fixture, 3, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.ReplyCount -= 1 }), checkE3)
}

func TestGateStep10HoldsLengths(t *testing.T) {
	leg := testTlsLegs()[0]
	fixture := testTwoRecordHeaderGateCapture(t, leg, false)
	// the first of two header records in 127 octets, which a literal could straddle twice
	err := testGateVerdictOn(t, fixture, 3, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) {
		part.Records[1] = tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 127+tlsInnerTypeBytes+tlsAeadTagBytes))
	})
	testExpectCheck(t, "a header record of 127 octets that is not the last", err, checkE3)
	data := testTwoRecordHeaderGateCapture(t, leg, true)
	short := *data.preamble
	short.messageByteCount -= 1
	data.preamble = &short
	err = testGateVerdictOn(t, data, uint32(len(data.parts)), &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) {})
	testExpectCheck(t, "DATA past the declared count", err, checkE3)
}

func TestGateStep11HoldsTheCarry(t *testing.T) {
	fixture := testBdatGateCapture(t, testTlsLegs()[0])
	testExpectCheck(t, "no carry on the msg part", testGateVerdictOn(t, fixture, 3, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.Carry = nil }), checkE3)
	testExpectCheck(t, "a carry off the curve", testGateVerdictOn(t, fixture, 3, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.Carry[63] ^= 1 }), checkE3)
	testExpectCheck(t, "a carry on an env part", testGateVerdictOn(t, fixture, 2, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.Carry = bytes.Clone(fixture.parts[2].Carry) }), checkE3)
}

func TestGateStep12RefusesAPartNoShapeHolds(t *testing.T) {
	fixture := testBdatGateCapture(t, testTlsLegs()[0])
	// a header record longer than the msg shape's head, named as the block's one record
	err := testGateVerdictOn(t, fixture, 3, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) {
		part.Records[1] = tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 2000+tlsInnerTypeBytes+tlsAeadTagBytes))
	})
	testExpectCheck(t, "a part no shape holds", err, checkE3)
}

func TestGateStep13CutsOnAFailedProof(t *testing.T) {
	fixture := testBdatGateCapture(t, testTlsLegs()[0])
	testExpectCut(t, "a proof that fails", testGateVerdictOn(t, fixture, 1, &testFixedVerifier{err: errors.New("no")}, func(part *sidecar.SmtpProofPart) {}))
}

// What each verification was handed: the statement the gate built.
type testStatementLog struct {
	statements []*partStatement
}

func (self *testStatementLog) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	self.statements = append(self.statements, statement)
	return nil
}

// ProofParts.tla's KeyFromPart: a later part's statement takes C from the gate, the key part's, and a
// part that names its own is refused (DESIGN-DETAILS 3.3 S2).
func TestGateSuppliesTheKeyCommitment(t *testing.T) {
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		log := &testStatementLog{}
		open := testOpen(t, fixture, log)
		open.verifyThrough(t, uint32(len(fixture.parts)))
		for _, statement := range log.statements {
			if !bytes.Equal(statement.keyCommitment, fixture.parts[0].KeyCommitment) {
				t.Errorf("%s: part %d verified under another C", leg.name, statement.index)
			}
		}
		other, err := newCommitBlind("test_blind")
		if err != nil {
			t.Fatal(err)
		}
		commitment, err := commitKeys(make([]byte, 16), make([]byte, 12), make([]byte, 16), make([]byte, 12), other)
		if err != nil {
			t.Fatal(err)
		}
		err = testGateVerdictOn(t, fixture, 2, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) { part.KeyCommitment = encodeCommitment(commitment) })
		testExpectCheck(t, leg.name+": part 2 naming its own C", err, checkE3)
	}
}

// ProofParts.tla's CarryFromPart: a hdr or body part's statement opens the carry the part before
// published, never one of its own, and after the header block's last record the start constant.
func TestGateSuppliesTheCarry(t *testing.T) {
	for _, leg := range testTlsLegs() {
		for _, data := range []bool{false, true} {
			fixture := testTwoRecordHeaderGateCapture(t, leg, data)
			log := &testStatementLog{}
			open := testOpen(t, fixture, log)
			open.verifyThrough(t, uint32(len(fixture.parts)))
			previous := []byte(nil)
			for i, statement := range log.statements {
				part := fixture.parts[i]
				if statement.carryIn != nil && !bytes.Equal(statement.carryIn, previous) {
					t.Errorf("%s data %v: part %d opens another carry than the gate kept", leg.name, data, part.Index)
				}
				if 0 < len(part.Carry) {
					previous = part.Carry
					if part.HeaderRecordCount == 0 && i == 3 {
						// header record 2 is the block's last: the body's scan starts again
						previous = scanStartCarry()
					}
				}
			}
		}
	}
}

// ProofParts.tla's NoReplyTotal: the first message record waits for 2 + R replies (3 + R in DATA mode),
// which a part can only claim of the server records it covers.
func TestGateCountsRepliesBeforeTheMessage(t *testing.T) {
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		err := testGateVerdictOn(t, fixture, 3, &testFixedVerifier{}, func(part *sidecar.SmtpProofPart) {
			part.ReplyCount = 0
			part.ServerRecordCount = fixture.parts[1].ServerRecordCount
		})
		testExpectCheck(t, leg.name+": the message before its replies", err, checkE3)
	}
}

// ProofParts.tla's ReleaseUncovered: a record relayed past the parts' counts holds the message records
// behind it until a part, here one that opens no client record, covers it.
func TestGateHoldsMessageRecordsBehindALateRecord(t *testing.T) {
	TestE3HoldsAMessageRecordBehindAnUncoveredServerRecord(t)
}

// ProofParts.tla's NoCommitRecheck: of two parts that verified against one state, the second to commit
// ends the connection, and the first stands.
func TestGateRefusesASecondPartThatVerifiedBesideTheFirst(t *testing.T) {
	TestE3APartVerifiedBesideAnotherCannotReplaceIt(t)
}
