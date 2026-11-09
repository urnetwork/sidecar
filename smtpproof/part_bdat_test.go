// BDAT's unopened body against a sidecar that pads or rekeys inside it (SPEC.md 9.5, FS-31's row).
// The edge counts each body record by its length, as carrying len - 17 octets, so the MX's count of
// chunk octets can only lag the edge's: whatever the MX then makes of the proven QUIT, no body octet
// reaches its command parser and no second transaction starts. The honest prover writes neither, so
// the relay re-seals its body records under the client's own keys, as a malicious sidecar holding them
// could, keeping each record's length.

package smtpproof

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A malicious sidecar's body records, in a BDAT send over TLS 1.3. The honest prover sends the proven
// QUIT only once the MX has answered the chunk; this one sends it straight after the last body record,
// as a sidecar trying to end the chunk early would, so the MX meets it whatever its count.
type testBodyRewriter struct {
	t       *testing.T
	suite   uint16
	backend *testWitnessBackend
	edge    *testEdge
	// The new inner plaintext of a body record, the first being 0: its type octet and any padding
	// included, as long as the honest record's content and type octet.
	rewrite func(body int, content []byte) []byte

	// Client records of outer type application_data so far, the client's Finished the first of them.
	applicationRecords int
	bodies             int
}

// The client's application keys: pi1's witness holds them.
func (self *testWitnessBackend) firstWitness() *partWitness {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.proved) == 0 {
		return nil
	}
	return self.proved[0]
}

// The latest part the prover submitted with this index, or nil.
func (self *testEdge) lastPart(index uint32) *sidecar.SmtpProofPart {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, part := range slices.Backward(self.parts) {
		if part.Index == index {
			return part
		}
	}
	return nil
}

// The relay's view of a client record: the honest prover wrote it, and this sends it instead. pi3 is
// submitted before its records are written, so a body record arrives when its part is known.
func (self *testBodyRewriter) client(record []byte) [][]byte {
	if record[0] != tlsRecordApplicationData {
		return [][]byte{record}
	}
	self.applicationRecords += 1
	if self.applicationRecords == 1 {
		// the client's Finished, under the handshake keys
		return [][]byte{record}
	}
	seq := uint64(self.applicationRecords - 2)
	message := self.edge.lastPart(3)
	// pi3 opens BDAT at first_record, the header block after it, and QUIT at last_record; the body lies
	// between
	if message == nil || seq <= message.FirstRecord+1 || message.LastRecord <= seq {
		return [][]byte{record}
	}
	keys := self.backend.firstWitness()
	opener, err := newTlsCipher(tlsVersion13, self.suite, keys.clientKey, keys.clientIv)
	if err != nil {
		self.t.Error(err)
		return [][]byte{record}
	}
	opener.seq = seq
	recordType, content, err := opener.open(record)
	if err != nil || recordType != tlsRecordApplicationData {
		self.t.Errorf("body record %d: %v", seq, err)
		return [][]byte{record}
	}
	inner := self.rewrite(self.bodies, content)
	self.bodies += 1
	if len(inner) != len(content)+tlsInnerTypeBytes {
		self.t.Errorf("a rewritten body record of %d octets for %d", len(inner), len(content)+tlsInnerTypeBytes)
		return [][]byte{record}
	}
	header := bytes.Clone(record[:tlsRecordHeaderBytes])
	sent := [][]byte{opener.aead.Seal(header, tls13Nonce(keys.clientIv, seq), inner, header)}
	if seq+1 == message.LastRecord {
		// the proven QUIT, exactly as pi3 holds it, without waiting for the MX
		sent = append(sent, message.Records[len(message.Records)-1])
	}
	return sent
}

// What an MX made of a BDAT send whose body a sidecar rewrote, and whether the gate let QUIT through.
type testRewrittenSend struct {
	send          *testSend
	job           *sidecar.SmtpProofJob
	quitForwarded bool
}

func testSendRewritingTheBody(t *testing.T, leg *testTlsLeg, rewrite func(body int, content []byte) []byte) *testRewrittenSend {
	t.Helper()
	job := testJob(strings.Repeat("a body line, unopened as BDAT's body is\r\n", 8), "bob", "carol")
	backend := newTestWitnessBackend()
	result := &testRewrittenSend{job: job}
	result.send = testRunSendThrough(t, leg, testMxDefaults(), DefaultProverSettings(), job, backend, backend, func(edge *testEdge) {
		rewriter := &testBodyRewriter{t: t, suite: leg.suites[0], backend: backend, edge: edge, rewrite: rewrite}
		edge.rewriteClient = rewriter.client
		// once the gate has let the final QUIT through, nothing more passes (E3 step 6), and the honest
		// prover waits for replies the MX may never write: close, and let the MX read what it was sent
		edge.afterForward = func() {
			edge.session.stateLock.Lock()
			finished := edge.session.finished
			edge.session.stateLock.Unlock()
			if finished {
				result.quitForwarded = true
				edge.fail(nil)
			}
		}
	})
	result.send.backend = backend
	return result
}

// The commands the parts proved, which an MX may see and nothing past them.
func testProvenCommands(job *sidecar.SmtpProofJob) []string {
	commands := []string{"EHLO " + testHeloName, "MAIL FROM:<" + job.SenderLocal + "@" + testEnvelopeDomain + ">"}
	for _, local := range job.RecipientLocals {
		commands = append(commands, "RCPT TO:<"+local+"@"+testRecipientDomain+">")
	}
	return append(commands, fmt.Sprintf("BDAT %d LAST", job.Preamble.MessageByteCount))
}

func TestBdatBodyRecordsPaddedPastQuitSmuggleNothing(t *testing.T) {
	// the MX's chunk is 64 octets short when the proven QUIT arrives, so QUIT is chunk data and the MX
	// waits for octets that never come. What the padded record carries is a second transaction, which
	// the MX reads as chunk data too
	for _, leg := range testTlsLegs()[:2] {
		send := testSendRewritingTheBody(t, leg, func(body int, content []byte) []byte {
			smuggled := "\r\n.\r\nMAIL FROM:<mallory@other.example>\r\nRCPT TO:<victim@other.example>\r\nDATA\r\n"
			carried := len(content) - 64
			inner := []byte(smuggled + strings.Repeat("x", carried-len(smuggled)))
			return append(append(inner, tlsRecordApplicationData), make([]byte, 64)...)
		})
		if !send.quitForwarded {
			t.Errorf("%s: the gate did not forward QUIT (%v)", leg.name, send.send.edge.failure())
		}
		if send.send.err == nil && send.send.result.Accepted {
			t.Errorf("%s: the send was reported accepted", leg.name)
		}
		if transactions := send.send.mx.transactions(); len(transactions) != 0 {
			t.Errorf("%s: the MX accepted %d transactions", leg.name, len(transactions))
		}
		if commands := send.send.mx.seen(); !slices.Equal(commands, testProvenCommands(send.job)) {
			t.Errorf("%s: the MX read the commands %q", leg.name, commands)
		}
	}
}

func TestBdatBodyRecordsPaddedShortOfQuitLeaveTheMxFiveOctets(t *testing.T) {
	// 2 octets of padding: the chunk ends inside QUIT's record, after "QU", so the MX accepts a message
	// of the declared length whose proven header block is intact, and reads "IT" as a command, which
	// is no transaction (SPEC.md 9.5)
	for _, leg := range testTlsLegs()[:2] {
		send := testSendRewritingTheBody(t, leg, func(body int, content []byte) []byte {
			inner := bytes.Clone(content[:len(content)-2])
			return append(append(inner, tlsRecordApplicationData), 0, 0)
		})
		if !send.quitForwarded {
			t.Errorf("%s: the gate did not forward QUIT (%v)", leg.name, send.send.edge.failure())
		}
		transactions := send.send.mx.transactions()
		if len(transactions) != 1 {
			t.Fatalf("%s: the MX accepted %d transactions", leg.name, len(transactions))
		}
		message := transactions[0].message
		headerBlock := []byte(testHeaderBlock())
		if uint64(len(message)) != send.job.Preamble.MessageByteCount || !bytes.HasPrefix(message, headerBlock) || !bytes.HasSuffix(message, []byte("QU")) {
			t.Errorf("%s: the MX took a message of %d octets: %q", leg.name, len(message), message)
		}
		if len(transactions[0].recipients) != 2 {
			t.Errorf("%s: %d recipients", leg.name, len(transactions[0].recipients))
		}
		if commands := send.send.mx.seen(); !slices.Equal(commands, append(testProvenCommands(send.job), "IT")) {
			t.Errorf("%s: the MX read the commands %q", leg.name, commands)
		}
	}
}

func TestBdatBodyWithAKeyUpdateSmugglesNothing(t *testing.T) {
	// a KeyUpdate in place of the body record, padded to its length: the MX takes the new key, so the
	// proven QUIT, sealed under the old one, fails its tag, and the connection dies mid-chunk
	for _, leg := range testTlsLegs()[:2] {
		send := testSendRewritingTheBody(t, leg, func(body int, content []byte) []byte {
			keyUpdate := []byte{tlsHandshakeKeyUpdate, 0, 0, 1, 0, tlsRecordHandshake}
			return append(keyUpdate, make([]byte, len(content)+tlsInnerTypeBytes-len(keyUpdate))...)
		})
		if !send.quitForwarded {
			t.Errorf("%s: the gate did not forward QUIT (%v)", leg.name, send.send.edge.failure())
		}
		if transactions := send.send.mx.transactions(); len(transactions) != 0 {
			t.Errorf("%s: the MX accepted %d transactions", leg.name, len(transactions))
		}
		if commands := send.send.mx.seen(); !slices.Equal(commands, testProvenCommands(send.job)) {
			t.Errorf("%s: the MX read the commands %q", leg.name, commands)
		}
	}
}
