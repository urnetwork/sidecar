// The checker on its own: its key schedule against RFC 8448, and fixed transcripts of honest
// connections, which it must pass, broken one way at a time, which it must refuse by the right check.
// Nothing here imports smtpproof; checker_agreement_test.go there holds the checker against the gate.

package checker

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func testOctets(t *testing.T, spaced string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.Join(strings.Fields(spaced), ""))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestKeyScheduleReproducesRfc8448(t *testing.T) {
	// RFC 8448 section 3: HS, SHTS from H_sh, MS and the server's handshake key, which is Z1's chain
	hs := testOctets(t, "1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac")
	helloHash := testOctets(t, "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8")
	shts := expandLabel(hs, "s hs traffic", helloHash, secretBytes)
	if !bytes.Equal(shts, testOctets(t, "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38")) {
		t.Errorf("SHTS %x", shts)
	}
	if ms := masterSecret13(hs); !bytes.Equal(ms, testOctets(t, "18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19")) {
		t.Errorf("MS %x", ms)
	}
	key, iv := trafficKeys13(suiteAes128GcmSha256, shts)
	if !bytes.Equal(key, testOctets(t, "3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc")) || !bytes.Equal(iv, testOctets(t, "5d 31 3e b2 67 12 76 ee 13 00 0b 30")) {
		t.Errorf("server handshake key %x iv %x", key, iv)
	}
	// and the TLS 1.2 PRF's published vector
	prf := prf12(testOctets(t, "9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35"), "test label", testOctets(t, "a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c"), 16)
	if !bytes.Equal(prf, testOctets(t, "e3 f2 29 ba 72 7b e1 7b 8d 12 26 20 55 7c d4 53")) {
		t.Errorf("PRF %x", prf)
	}
}

// A fixed transcript of an honest connection, as checker_agreement_test.go wrote it: per leg and mode,
// one whose header block is one record, and one (-split-name) whose header block takes two, the first
// ending inside a field's name.
type testConnection struct {
	name       string
	Transcript *Transcript
	Witnesses  map[int]*PartWitness
}

func testConnections(t *testing.T) []*testConnection {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil || len(paths) != 12 {
		t.Fatalf("%d fixed transcripts, %v", len(paths), err)
	}
	var connections []*testConnection
	for _, path := range paths {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		connection := &testConnection{name: filepath.Base(path)}
		if err := json.Unmarshal(encoded, connection); err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
	}
	return connections
}

func (self *testConnection) tls12() bool {
	return strings.HasPrefix(self.name, "tls12")
}

func (self *testConnection) data() bool {
	return strings.Contains(self.name, "-data")
}

func (self *testConnection) splitName() bool {
	return strings.Contains(self.name, "-split-name")
}

// The first application record's sequence number in each direction.
func (self *testConnection) firstSeq() uint64 {
	if self.tls12() {
		return 1
	}
	return 0
}

// The witness of a part by its index.
func (self *testConnection) witness(t *testing.T, index uint32) *PartWitness {
	t.Helper()
	return self.Witnesses[self.partEvent(t, index)]
}

// Seals a server record's plaintext again under the part's witness's server key, at the record's place in
// the stream and in the part's witness, as the MX would have sent it: 1.3's nonce the IV XOR the
// sequence number under the record's header, 1.2's the salt and the record's own explicit nonce under the
// sequence number, type, version and length.
func (self *testConnection) resealServerRecord(t *testing.T, index uint32, i int, plaintext []byte) {
	t.Helper()
	witness := self.witness(t, index)
	previous := uint64(0)
	if 1 < index {
		previous = self.Transcript.Events[self.partEvent(t, index-1)].Part.ServerRecordCount
	}
	position := previous + uint64(i)
	seq := self.firstSeq() + position
	var aead cipher.AEAD
	var err error
	if len(witness.ServerKey) == chacha20poly1305.KeySize {
		aead, err = chacha20poly1305.New(witness.ServerKey)
	} else {
		var block cipher.Block
		if block, err = aes.NewCipher(witness.ServerKey); err == nil {
			aead, err = cipher.NewGCM(block)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	var events []*Event
	keyPart := false
	for _, event := range self.Transcript.Events {
		keyPart = keyPart || (event.Part != nil && event.Part.Index == 1)
		if keyPart && event.ServerRecord != nil {
			events = append(events, event)
		}
	}
	event := events[position]
	var sealed []byte
	if self.tls12() {
		explicit := event.ServerRecord[recordHeaderBytes : recordHeaderBytes+explicitNonceBytes]
		additional := binary.BigEndian.AppendUint64(nil, seq)
		additional = append(additional, recordApplicationData, 3, 3, byte(len(plaintext)>>8), byte(len(plaintext)))
		size := explicitNonceBytes + len(plaintext) + tagBytes
		sealed = append([]byte{recordApplicationData, 3, 3, byte(size >> 8), byte(size)}, explicit...)
		sealed = aead.Seal(sealed, append(slices.Clone(witness.ServerIv), explicit...), plaintext, additional)
	} else {
		nonce := slices.Clone(witness.ServerIv)
		for j := range 8 {
			nonce[len(nonce)-1-j] ^= byte(seq >> (8 * j))
		}
		size := len(plaintext) + tagBytes
		header := []byte{recordApplicationData, 3, 3, byte(size >> 8), byte(size)}
		sealed = aead.Seal(header, nonce, plaintext, header)
	}
	event.ServerRecord = sealed
	witness.ServerPlaintexts = slices.Clone(witness.ServerPlaintexts)
	witness.ServerPlaintexts[i] = plaintext
}

// The event of a part by its index.
func (self *testConnection) partEvent(t *testing.T, index uint32) int {
	t.Helper()
	for i, event := range self.Transcript.Events {
		if event.Part != nil && event.Part.Index == index {
			return i
		}
	}
	t.Fatalf("%s: no part %d", self.name, index)
	return 0
}

func testChecks(failures []*Failure) []string {
	var checks []string
	for _, failure := range failures {
		if !strings.Contains(strings.Join(checks, " "), failure.Check) {
			checks = append(checks, failure.Check)
		}
	}
	return checks
}

func TestEveryFixedHonestConnectionPasses(t *testing.T) {
	for _, connection := range testConnections(t) {
		for _, failure := range Check(connection.Transcript, connection.Witnesses) {
			t.Errorf("%s: %v", connection.name, failure)
		}
	}
}

func TestTheCheckerRefusesEachBreakByItsCheck(t *testing.T) {
	cases := []struct {
		name  string
		check string
		// Whether the break applies to a connection. Nil is every one.
		applies func(connection *testConnection) bool
		mutate  func(t *testing.T, connection *testConnection)
	}{
		{name: "a preamble with a path in its domain", check: "preamble", mutate: func(t *testing.T, connection *testConnection) {
			connection.Transcript.Preamble.RecipientDomain = "a.example>\r\nRCPT TO:<victim@other.example"
		}},
		{name: "SNI naming another host", check: "E1", mutate: func(t *testing.T, connection *testConnection) {
			connection.Transcript.Preamble.MxHost = "mx.other.example"
		}},
		{name: "a client record of another type after the handshake", check: "E1", mutate: func(t *testing.T, connection *testConnection) {
			for _, event := range connection.Transcript.Events[connection.partEvent(t, 1):] {
				if event.ClientRecord != nil {
					event.ClientRecord = append([]byte{}, event.ClientRecord...)
					event.ClientRecord[0] = recordAlert
					return
				}
			}
		}},
		{name: "another witness HS or master secret", check: "Z1", mutate: func(t *testing.T, connection *testConnection) {
			witness := connection.Witnesses[connection.partEvent(t, 1)]
			if connection.tls12() {
				witness.MasterSecret[0] ^= 1
			} else {
				witness.HandshakeSecret[0] ^= 1
			}
		}},
		{name: "a server plaintext the record does not hold", check: "Z2", mutate: func(t *testing.T, connection *testConnection) {
			witness := connection.Witnesses[connection.partEvent(t, 2)]
			// a digit of the reply's text, so the reply still parses and only the keystream fails
			witness.ServerPlaintexts[0][len("250-")] ^= 1
		}},
		{name: "a part that skips an index", check: "E3", mutate: func(t *testing.T, connection *testConnection) {
			connection.Transcript.Events[connection.partEvent(t, 2)].Part.Index = 3
		}},
		{name: "the MX's reply relayed twice", check: "E3", mutate: func(t *testing.T, connection *testConnection) {
			// the env part then claims more server records than were relayed by its time
			envelope := connection.partEvent(t, 2)
			connection.Transcript.Events[envelope].Part.ServerRecordCount += 1
		}},

		// DESIGN-DETAILS 3.6's cells, as far as a fixed transcript holds them without this module
		{name: "a later part opening C under another blind", check: "Z1", mutate: func(t *testing.T, connection *testConnection) {
			witness := connection.witness(t, 2)
			witness.KeyBlind = slices.Clone(witness.KeyBlind)
			witness.KeyBlind[len(witness.KeyBlind)-1] ^= 1
		}},
		{name: "header record 2 scanned from the start state", check: "Z5", applies: (*testConnection).splitName, mutate: func(t *testing.T, connection *testConnection) {
			witness := connection.witness(t, 4)
			if witness.CarryInState == scanPosLf {
				t.Fatalf("%s: record 1 left the start state", connection.name)
			}
			witness.CarryInState = scanPosLf
		}},
		{name: "body record 2 scanned from the start state", check: "Z6", applies: func(connection *testConnection) bool { return connection.data() && !connection.splitName() }, mutate: func(t *testing.T, connection *testConnection) {
			witness := connection.witness(t, 5)
			if witness.CarryInState == scanPosLf {
				t.Fatalf("%s: body record 1 left the start state", connection.name)
			}
			witness.CarryInState = scanPosLf
		}},
		{name: "a reply_count one more than the records hold", check: "Z8", mutate: func(t *testing.T, connection *testConnection) {
			// MAIL's reply continued into the first RCPT's, in its length
			plaintext := connection.witness(t, 3).ServerPlaintexts[0]
			if !bytes.HasPrefix(plaintext, []byte("250 ")) {
				t.Fatalf("%s: a MAIL reply of %q", connection.name, plaintext)
			}
			continued := slices.Clone(plaintext)
			continued[len("250")] = '-'
			connection.resealServerRecord(t, 3, 0, continued)
		}},
		{name: "a first message record before 2 + R replies are proven", check: "E3", mutate: func(t *testing.T, connection *testConnection) {
			message := connection.Transcript.Events[connection.partEvent(t, 3)].Part
			message.ServerRecordCount = connection.Transcript.Events[connection.partEvent(t, 2)].Part.ServerRecordCount
			message.ReplyCount = 0
			connection.witness(t, 3).ServerPlaintexts = nil
		}},
	}
	for _, c := range cases {
		for _, connection := range testConnections(t) {
			if c.applies != nil && !c.applies(connection) {
				continue
			}
			c.mutate(t, connection)
			checks := testChecks(Check(connection.Transcript, connection.Witnesses))
			if len(checks) != 1 || checks[0] != c.check {
				t.Errorf("%s, %s: %v, want %s", c.name, connection.name, checks, c.check)
			}
		}
	}
}

func TestTheCheckerReadsTheHeaderBlockAsSpecDoes(t *testing.T) {
	preamble := &Preamble{
		HeaderFromDomain: "net.root.example", DkimSelector: "s1", MessageId: "id@net.root.example",
		XUrRef: "1.ref", FeedbackId: "n:c:token:urnetwork",
	}
	header := "From: Alice Example <alice@net.root.example>\r\n" +
		"Message-ID: <id@net.root.example>\r\n" +
		"X-UR-Ref: 1.ref\r\n" +
		"Feedback-ID: n:c:token:urnetwork\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; d=net.root.example; s=s1; b=x\r\n" +
		"\r\n"
	if err := checkHeaderBlock(DefaultCheckSettings(), preamble, []byte(header)); err != nil {
		t.Fatalf("an honest header block: %v", err)
	}
	for name, block := range map[string]string{
		"From :":              strings.Replace(header, "From: ", "From : ", 1),
		"a second From":       "From: <x@victim.example>\r\n" + header,
		"a folded From":       strings.Replace(header, "example>\r\n", "example>\r\n <x@victim.example>\r\n", 1),
		"a field behind .":    ".From: <x@victim.example>\r\n" + header,
		"a bare LF":           strings.Replace(header, "X-UR-Ref", "X:\nX-UR-Ref", 1),
		"an early end":        "X: y\r\n\r\n" + header,
		"no Feedback-ID":      strings.Replace(header, "Feedback-ID: n:c:token:urnetwork\r\n", "", 1),
		"another s=":          strings.Replace(header, "s=s1", "s=s2", 1),
		"two addresses":       strings.Replace(header, "<alice@", "<a@b>, <alice@", 1),
		"an address phrase":   strings.Replace(header, "Alice Example ", "x@victim.example ", 1),
		"a lowercase from:":   strings.Replace(header, "From: ", "from: ", 1),
		"a DKIM prefix twice": header[:len(header)-2] + "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; d=net.root.example; s=s1; \r\n\r\n",
	} {
		if err := checkHeaderBlock(DefaultCheckSettings(), preamble, []byte(block)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// BULK wants its header once
	bulk := *preamble
	bulk.Flags = flagBulk
	if err := checkHeaderBlock(DefaultCheckSettings(), &bulk, []byte(header)); err == nil {
		t.Error("BULK without List-Unsubscribe-Post")
	}
	if err := checkHeaderBlock(DefaultCheckSettings(), &bulk, []byte("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"+header)); err != nil {
		t.Errorf("BULK with it: %v", err)
	}
}

func TestTheCheckerReadsDataAndRepliesAsSpecDoes(t *testing.T) {
	for name, record := range map[string]string{"a lone dot": "a\r\n.\r\nb\r\n", "a bare LF": "a\nb\r\n", "a bare CR": "a\rb\r\n", "no CRLF at the end": "a"} {
		if checkDataRecord([]byte(record)) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := checkDataRecord([]byte("..stuffed\r\nline\r\n")); err != nil {
		t.Errorf("a stuffed line: %v", err)
	}
	replies, err := parseReplies([]byte("250-mx.example\r\n250-CHUNKING\r\n250 SMTPUTF8\r\n354 go\r\n"))
	if err != nil || len(replies) != 2 || len(replies[0].codes) != 3 {
		t.Fatalf("%d replies, %v", len(replies), err)
	}
	if _, err := parseReplies([]byte("250-mx.example\r\n")); err == nil {
		t.Error("a stream ending inside a reply parsed")
	}
	if offersChunking([][]byte{[]byte("250-mx\r\n250-PIPELINING\r\n"), []byte("250 CHUNKING\r\n")}) {
		t.Error("CHUNKING counted across records, without its CRLF before it")
	}
	if !offersChunking([][]byte{[]byte("250-mx\r\n250 chunking\r\n")}) {
		t.Error("CHUNKING in lower case not found")
	}
}

func TestTheCheckerImportsNothingFromTheProverTree(t *testing.T) {
	// SMTP-M9-28: written apart, and kept apart, so that it can disagree
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range parsed.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(name, ".") && !strings.HasPrefix(name, "golang.org/x/crypto/") {
				t.Errorf("%s imports %s", path, name)
			}
		}
	}
}

func TestTheCheckerHoldsTheIssuedValuesToTheirSpelling(t *testing.T) {
	preamble := func() *Preamble {
		return &Preamble{
			RecipientDomain: "recipient.example", RecipientCount: 1, MessageId: "a@b", HeaderFromDomain: "net.example",
			DkimSelector: "s1", HeloName: "o1.example", EnvelopeDomain: "b.net.example",
			XUrRef: "1.aeibceqtcqkrmfyydenbxifbukr2jjngu4", FeedbackId: "n:c:gaytemzugu3doobzhi5typj6h4:urnetwork",
		}
	}
	if err := checkPreambleForms(DefaultCheckSettings(), preamble()); err != nil {
		t.Fatalf("honest values: %v", err)
	}
	for name, mutate := range map[string]func(p *Preamble){
		"a reference with a set unused bit": func(p *Preamble) { p.XUrRef = p.XUrRef[:len(p.XUrRef)-1] + "5" },
		"a reference in upper case":         func(p *Preamble) { p.XUrRef = strings.ToUpper(p.XUrRef) },
		"a short reference":                 func(p *Preamble) { p.XUrRef = p.XUrRef[:len(p.XUrRef)-1] },
		"another tier":                      func(p *Preamble) { p.FeedbackId = "n:x" + p.FeedbackId[3:] },
		"a token of 15 octets":              func(p *Preamble) { p.FeedbackId = "n:c:gaytemzugu3doobzhi5typj6:urnetwork" },
	} {
		value := preamble()
		mutate(value)
		if checkPreambleForms(DefaultCheckSettings(), value) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The scan's state between records, read from DESIGN-DETAILS 3.2.4's definition over the octets so far:
// pos, an unfinished name, the run of a line that began in the record and the literals it may still be,
// and whether a single field's line ended at the record's end.
func TestTheCheckerReadsTheScanStateByItsDefinition(t *testing.T) {
	const first = "From: <alice@net.root.example>\r\n"
	run := func(octets int) uint32 { return uint32(octets) << 3 }
	prefix := func(literal int) uint32 { return 1 << (10 + literal) }
	for _, c := range []struct {
		name        string
		header      string
		recordStart int
		first       bool
		want        uint32
	}{
		{name: "a name unfinished", header: first + "X-Spa", want: 1<<2 | run(5)},
		{name: "a single field's name begun", header: first + "Feedb", want: 1<<2 | run(5) | prefix(3)},
		{name: "a name begun in another case", header: first + "MESSAGE-", want: 1<<2 | run(8) | prefix(1)},
		{name: "the fixed signature's prefix begun", header: first + "DKIM-Signature: v=1; a", want: run(22) | prefix(5)},
		{name: "the fixed signature's prefix in another case", header: first + "dkim-signature: v=1; a", want: run(22)},
		{name: "a line past its colon", header: first + "Subject: hi", want: run(11)},
		{name: "a line begun in an earlier record", header: first + "X-Long-name: v", recordStart: len(first) + 6, want: run(127)},
		{name: "a line past 126 octets", header: first + "X: " + strings.Repeat("v", 200), want: run(127)},
		{name: "a continuation", header: first + "X: v\r\n continued", want: 0},
		{name: "a CR at the end", header: first + "A: b\r", want: scanPosCr | run(5)},
		{name: "a single field's line ended in the first record", header: first, first: true, want: scanPosLf | 1<<16},
		{name: "a single field's line ended in a later record", header: first, want: scanPosLf},
		{name: "another line ended", header: first + "Subject: hi\r\n", first: true, want: scanPosLf},
	} {
		if got := headerState([]byte(c.header), c.recordStart, c.first, false); got != c.want {
			t.Errorf("%s: state %#x, want %#x", c.name, got, c.want)
		}
	}
	// the one-click field is a single field on BULK alone
	post := first + "List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
	if got := headerState([]byte(post), 0, true, false); got != scanPosLf {
		t.Errorf("List-Unsubscribe-Post ended, not BULK: state %#x", got)
	}
	if got := headerState([]byte(post), 0, true, true); got != scanPosLf|1<<16 {
		t.Errorf("List-Unsubscribe-Post ended, BULK: state %#x", got)
	}
	for body, want := range map[string]uint32{"": scanPosLf, "a": scanPosLine, "a\r": scanPosCr, "a\r\n": scanPosLf, "a\r\n.": scanPosDot, ".": scanPosDot, "a.": scanPosLine, "..": scanPosLine} {
		if got := bodyState([]byte(body)); got != want {
			t.Errorf("body %q: state %d, want %d", body, got, want)
		}
	}
}

// DESIGN-DETAILS 3.2.4 states Z5 record by record, so a rule is refused at the record that breaks it and
// not when the block is whole: an empty line before the block's end (H3), and a single field's line that
// ended with the first record continued by the second (H6).
func TestTheCheckerRefusesEachHeaderRuleAtItsRecord(t *testing.T) {
	preamble := &Preamble{
		HeaderFromDomain: "net.root.example", DkimSelector: "s1", MessageId: "id@net.root.example",
		XUrRef: "1.ref", FeedbackId: "n:c:token:urnetwork",
	}
	record := "From: Alice Example <alice@net.root.example>\r\n" +
		"Message-ID: <id@net.root.example>\r\n" +
		"X-UR-Ref: 1.ref\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; d=net.root.example; s=s1; b=x\r\n" +
		"Feedback-ID: n:c:token:urnetwork\r\n"
	settings := DefaultCheckSettings()
	if err := checkHeaderSoFar(settings, preamble, []byte(record), len(record), false); err != nil {
		t.Fatalf("an honest first record: %v", err)
	}
	if err := checkHeaderSoFar(settings, preamble, []byte(record+"\r\n"), len(record)+2, true); err != nil {
		t.Fatalf("an honest one-record block: %v", err)
	}
	// H3: the empty line in the first of two records is refused there
	early := record + "\r\nX: y\r\n"
	if err := checkHeaderSoFar(settings, preamble, []byte(early), len(early), false); err == nil {
		t.Error("an empty line inside the first of two records: accepted at that record")
	}
	// and in a later record that is not the last
	later := record + "X: y\r\n\r\nX: z\r\n"
	if err := checkHeaderSoFar(settings, preamble, []byte(later), len(record), false); err == nil {
		t.Error("an empty line inside a later record that is not the last: accepted at that record")
	}
	// H6: Feedback-ID ends the first record, and the second continues it
	continued := record + " a continuation\r\nX: y\r\n"
	if err := checkHeaderSoFar(settings, preamble, []byte(continued), len(record), false); err == nil {
		t.Error("a single field continued across the first boundary: accepted at the second record")
	}
	if err := checkHeaderSoFar(settings, preamble, []byte(record+"X: y\r\n"), len(record), false); err != nil {
		t.Errorf("a field after the single field across the first boundary: %v", err)
	}
	// a continuation of a field that is no single one, across the boundary
	other := record + "Subject: hi\r\n"
	if err := checkHeaderSoFar(settings, preamble, []byte(other+" there\r\n"), len(other), false); err != nil {
		t.Errorf("Subject continued across the first boundary: %v", err)
	}
}

// An adversarial witness whose keys or IVs are not the session's widths is refused, never a crash: Z2
// opens nothing under them, and they open no C.
func TestTheCheckerRefusesKeysOfOtherWidths(t *testing.T) {
	for name, mutate := range map[string]func(witness *PartWitness){
		"a short client IV":         func(witness *PartWitness) { witness.ClientIv = witness.ClientIv[:3] },
		"a long server IV":          func(witness *PartWitness) { witness.ServerIv = append(slices.Clone(witness.ServerIv), 0) },
		"a client key of 24 octets": func(witness *PartWitness) { witness.ClientKey = make([]byte, 24) },
		"no server key":             func(witness *PartWitness) { witness.ServerKey = nil },
		"a client key twice over":   func(witness *PartWitness) { witness.ClientKey = append(slices.Clone(witness.ClientKey), witness.ClientKey...) },
	} {
		for _, connection := range testConnections(t) {
			mutate(connection.witness(t, 2))
			checks := testChecks(Check(connection.Transcript, connection.Witnesses))
			if !slices.Contains(checks, "Z1") {
				t.Errorf("%s, %s: %v, want Z1 among them", name, connection.name, checks)
			}
		}
	}
}
