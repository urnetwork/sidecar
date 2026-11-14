// The checker on its own: its key schedule against RFC 8448, and fixed transcripts of honest
// connections, which it must pass, broken one way at a time, which it must refuse by the right check.
// Nothing here imports smtpproof; checker_agreement_test.go there holds the checker against the gate.

package checker

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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

// A fixed transcript of an honest connection, as checker_agreement_test.go wrote it.
type testConnection struct {
	name       string
	Transcript *Transcript
	Witnesses  map[int]*PartWitness
}

func testConnections(t *testing.T) []*testConnection {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil || len(paths) != 6 {
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
		name   string
		check  string
		mutate func(t *testing.T, connection *testConnection)
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
			// pi2 then claims more server records than were relayed by its time
			envelope := connection.partEvent(t, 2)
			connection.Transcript.Events[envelope].Part.ServerRecordCount += 1
		}},
	}
	for _, c := range cases {
		for _, connection := range testConnections(t) {
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
