// E3 under every order the network can give: client records, server records, parts, a late server
// record and the part proven again over it, interleaved as a fuzzer chooses. Whatever the order, a
// message record goes only behind verified coverage of every server record relayed before it, records
// go in their stream order and only under a verified part, and the MAIL record is reported forwarded
// exactly when it was handed out.

package smtpproof

import (
	"bytes"
	"context"
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
	// The latest part the gate took, as it was last submitted.
	latest *sidecar.SmtpProofPart
	// Records handed back so far, which must be the client's stream in order.
	handed   [][]byte
	ended    bool
	injected int
	// pi2's first and last record, and the final QUIT's: records between the two are message records.
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
		lastCovered = max(lastCovered, part.part.LastRecord)
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
				self.check(nil, self.gate.ServerRecord(self.server[fed]))
			}
		case 2:
			// a part only once its server records have been relayed, as an honest prover's is
			if self.fedParts < len(self.fixture.parts) {
				part := self.fixture.parts[self.fedParts]
				if part.ServerRecordCount <= uint64(self.fedServer()+self.injected) {
					self.fedParts += 1
					self.latest = part
					self.check(self.gate.VerifyPart(context.Background(), part))
				}
			}
		case 3:
			// a late record from the MX, as a ticket would be, which no part yet covers
			if self.injected < 3 && 0 < self.fedServer() {
				self.injected += 1
				self.check(nil, self.gate.ServerRecord(tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 40))))
			}
		case 4:
			// the latest part proven again over every server record relayed
			if self.latest != nil {
				again := *self.latest
				again.ServerRecordCount = uint64(self.fedServer() + self.injected)
				again.Proof = []byte{byte(again.ServerRecordCount)}
				if self.latest.ServerRecordCount < again.ServerRecordCount {
					self.latest = &again
					self.check(self.gate.VerifyPart(context.Background(), &again))
				}
			}
		case 5:
			// an exact resend of the latest part, which changes nothing
			if self.latest != nil {
				self.check(self.gate.VerifyPart(context.Background(), self.latest))
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

// The trace's server records fed so far.
func (self *testOrderRun) fedServer() int {
	self.gate.stateLock.Lock()
	defer self.gate.stateLock.Unlock()
	return len(self.gate.serverRecords) - self.injected
}

func FuzzEdgeRecordOrder(f *testing.F) {
	// the honest order of a pipelined BDAT and DATA send on each leg, then that order with a late
	// record before the message, and parts racing ahead of their records
	for leg := range 3 {
		f.Add([]byte{byte(leg), 2, 0, 1, 2, 0, 0, 0, 1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 1})
		f.Add([]byte{byte(leg) | 4, 2, 0, 1, 2, 0, 0, 0, 1, 1, 1, 2, 0, 0, 2, 0, 2, 0, 2, 0, 1})
		f.Add([]byte{byte(leg), 2, 0, 1, 2, 0, 0, 0, 1, 1, 1, 3, 2, 0, 0, 0, 4, 0, 0, 5, 6})
		f.Add([]byte{byte(leg), 0, 0, 0, 0, 0, 0, 0, 2, 1, 2, 1, 1, 1, 2, 1, 2, 2, 2})
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
