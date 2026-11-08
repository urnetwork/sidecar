// smtpproof/checker against the gate and the relation, as an outside party would hold them: the same
// connections, honest and then broken in one place each, and the same checks named on both sides. This
// is an external test package, so it may import the checker; the captures come through
// export_test.go.

package smtpproof_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/urnetwork/sidecar/smtpproof"
	"github.com/urnetwork/sidecar/smtpproof/checker"
)

// A capture in the checker's own types.
func testCheckerInput(capture *smtpproof.ExportedCapture) (*checker.Transcript, map[int]*checker.PartWitness) {
	p := capture.Preamble
	transcript := &checker.Transcript{Preamble: &checker.Preamble{
		RecipientDomain: p.RecipientDomain, RecipientCount: p.RecipientCount, MessageId: p.MessageId,
		HeaderFromDomain: p.HeaderFromDomain, DkimSelector: p.DkimSelector, MessageByteCount: p.MessageByteCount,
		Flags: p.Flags, HeloName: p.HeloName, XUrRef: p.XUrRef, FeedbackId: p.FeedbackId,
		EnvelopeDomain: p.EnvelopeDomain, MxHost: p.MxHost,
	}}
	for _, event := range capture.Events {
		converted := &checker.Event{ClientRecord: event.ClientRecord, ServerRecord: event.ServerRecord, Shts: event.Shts}
		if part := event.Part; part != nil {
			converted.Part = &checker.Part{
				Index: part.Index, Mode: part.Mode, FirstRecord: part.FirstRecord, LastRecord: part.LastRecord,
				Last: part.Last, ServerRecordCount: part.ServerRecordCount, Records: part.Records,
			}
		}
		transcript.Events = append(transcript.Events, converted)
	}
	witnesses := map[int]*checker.PartWitness{}
	for i, witness := range capture.Witnesses {
		witnesses[i] = &checker.PartWitness{
			HandshakeSecret: witness.HandshakeSecret, MasterSecret: witness.MasterSecret,
			ClientKey: witness.ClientKey, ClientIv: witness.ClientIv, ServerKey: witness.ServerKey, ServerIv: witness.ServerIv,
			ClientPlaintexts: witness.ClientPlaintexts, ServerPlaintexts: witness.ServerPlaintexts,
		}
	}
	return transcript, witnesses
}

// The checks the checker names, as a sorted set.
func testCheckerVerdict(capture *smtpproof.ExportedCapture) []string {
	var checks []string
	for _, failure := range checker.Check(testCheckerInput(capture)) {
		if !slices.Contains(checks, failure.Check) {
			checks = append(checks, failure.Check)
		}
	}
	slices.Sort(checks)
	return checks
}

func testGateVerdict(capture *smtpproof.ExportedCapture) []string {
	checks := smtpproof.ExportGateVerdict(capture)
	slices.Sort(checks)
	return checks
}

type testLegCase struct {
	name  string
	leg   int
	data  bool
	tls12 bool
}

func testLegCases() []*testLegCase {
	var cases []*testLegCase
	for leg, name := range []string{"tls13 aes", "tls13 chacha", "tls12 aes"} {
		for _, data := range []bool{false, true} {
			mode := "bdat"
			if data {
				mode = "data"
			}
			cases = append(cases, &testLegCase{name: name + " " + mode, leg: leg, data: data, tls12: leg == 2})
		}
	}
	return cases
}

func TestCheckerAgreesThatEveryHonestSendPasses(t *testing.T) {
	for _, c := range testLegCases() {
		capture := smtpproof.ExportCapture(t, c.leg, c.data)
		if verdict := testGateVerdict(capture); len(verdict) != 0 {
			t.Fatalf("%s: the gate refuses an honest send: %v", c.name, verdict)
		}
		for _, failure := range checker.Check(testCheckerInput(capture)) {
			t.Errorf("%s: the checker refuses an honest send: %v", c.name, failure)
		}
	}
}

// The event of each part, by index, in its order: a capture names each once.
func testPartEvents(capture *smtpproof.ExportedCapture) map[uint32]int {
	events := map[uint32]int{}
	for i, event := range capture.Events {
		if event.Part != nil {
			events[event.Part.Index] = i
		}
	}
	return events
}

// Seals a record as the MX or the sidecar would have, under a direction's key, so a mutation can
// change what a record says while its ciphertext stays honest under that key.
func testSealRecord(t *testing.T, tls12 bool, key []byte, iv []byte, seq uint64, plaintext []byte) []byte {
	t.Helper()
	var aead cipher.AEAD
	var err error
	if len(key) == chacha20poly1305.KeySize {
		aead, err = chacha20poly1305.New(key)
	} else {
		var block cipher.Block
		if block, err = aes.NewCipher(key); err == nil {
			aead, err = cipher.NewGCM(block)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if !tls12 {
		nonce := bytes.Clone(iv)
		for i := range 8 {
			nonce[len(nonce)-1-i] ^= byte(seq >> (8 * i))
		}
		size := len(plaintext) + 16
		header := []byte{23, 3, 3, byte(size >> 8), byte(size)}
		return aead.Seal(header, nonce, plaintext, header)
	}
	explicit := binary.BigEndian.AppendUint64(nil, seq)
	additional := append(bytes.Clone(explicit), 23, 3, 3, byte(len(plaintext)>>8), byte(len(plaintext)))
	size := 8 + len(plaintext) + 16
	record := append([]byte{23, 3, 3, byte(size >> 8), byte(size)}, explicit...)
	return aead.Seal(record, append(bytes.Clone(iv), explicit...), plaintext, additional)
}

// The event positions of the server's application records, in order: those after pi1.
func testServerApplicationEvents(capture *smtpproof.ExportedCapture) []int {
	var events []int
	seenEhloPart := false
	for i, event := range capture.Events {
		if event.Part != nil && event.Part.Index == 1 {
			seenEhloPart = true
		}
		if seenEhloPart && event.ServerRecord != nil {
			events = append(events, i)
		}
	}
	return events
}

// Replaces the plaintext of the client record a part opens at position i, sealed again under the
// client key, in the part, its witness and the stream.
func testRewriteClientRecord(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture, partEvent int, i int, content []byte) {
	t.Helper()
	part := capture.Events[partEvent].Part
	witness := capture.Witnesses[partEvent]
	seq := part.FirstRecord + uint64(i)
	if part.Mode == 1 && part.Index == 3 && i == len(part.Records)-1 {
		seq = part.LastRecord
	}
	plaintext := bytes.Clone(content)
	if !c.tls12 {
		plaintext = append(plaintext, 23)
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

func TestCheckerAndTheGateNameTheSameChecks(t *testing.T) {
	type mutation struct {
		name   string
		want   func(c *testLegCase) []string
		mutate func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture)
	}
	fixed := func(checks ...string) func(c *testLegCase) []string {
		return func(c *testLegCase) []string { return checks }
	}
	mutations := []mutation{
		{name: "no recipient", want: fixed("preamble"), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			preamble := *capture.Preamble
			preamble.RecipientCount = 0
			capture.Preamble = &preamble
		}},
		{name: "another HS or master secret", want: fixed("Z1"), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			witness := capture.Witnesses[testPartEvents(capture)[1]]
			if c.tls12 {
				witness.MasterSecret = bytes.Clone(witness.MasterSecret)
				witness.MasterSecret[0] ^= 1
			} else {
				witness.HandshakeSecret = bytes.Clone(witness.HandshakeSecret)
				witness.HandshakeSecret[0] ^= 1
			}
		}},
		{name: "another client key", want: fixed("Z1", "Z2"), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			witness := capture.Witnesses[testPartEvents(capture)[1]]
			witness.ClientKey = bytes.Clone(witness.ClientKey)
			witness.ClientKey[0] ^= 1
		}},
		{name: "a claimed plaintext the record does not hold", want: fixed("Z2"), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			witness := capture.Witnesses[testPartEvents(capture)[2]]
			witness.ClientPlaintexts = slices.Clone(witness.ClientPlaintexts)
			// a local part's octet, so the template still holds and only the keystream equation fails
			plaintext := bytes.Clone(witness.ClientPlaintexts[0])
			plaintext[len("MAIL FROM:<")] ^= 'b' ^ 'c'
			witness.ClientPlaintexts[0] = plaintext
		}},
		{name: "a record unequal to what its part proved", want: fixed("E3"), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			record := capture.Events[testPartEvents(capture)[2]].Part.Records[0]
			for _, event := range capture.Events {
				if bytes.Equal(event.ClientRecord, record) {
					event.ClientRecord = bytes.Clone(record)
					event.ClientRecord[len(record)-1] ^= 1
				}
			}
		}},
		{name: "parts out of order", want: fixed("E3"), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			events := testPartEvents(capture)
			first, second := events[1], events[2]
			capture.Events[first], capture.Events[second] = capture.Events[second], capture.Events[first]
			capture.Witnesses[first], capture.Witnesses[second] = capture.Witnesses[second], capture.Witnesses[first]
		}},
		{name: "a client record of another type after the handshake", want: fixed("E1"), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			record := capture.Events[testPartEvents(capture)[1]].Part.Records[0]
			for _, event := range capture.Events {
				if bytes.Equal(event.ClientRecord, record) {
					event.ClientRecord = bytes.Clone(record)
					event.ClientRecord[0] = 22
				}
			}
		}},
		{name: "a refused EHLO", want: func(c *testLegCase) []string {
			if c.data {
				return []string{"Z8"}
			}
			return []string{"Z8", "Z9"}
		}, mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			envelope := testPartEvents(capture)[2]
			witness := capture.Witnesses[envelope]
			plaintext := []byte("550 5.7.1 refused\r\n")
			if !c.tls12 {
				plaintext = append(plaintext, 23)
			}
			seq := uint64(0)
			if c.tls12 {
				seq = 1
			}
			sealed := testSealRecord(t, c.tls12, witness.ServerKey, witness.ServerIv, seq, plaintext)
			capture.Events[testServerApplicationEvents(capture)[0]].ServerRecord = sealed
			witness.ServerPlaintexts = slices.Clone(witness.ServerPlaintexts)
			witness.ServerPlaintexts[0] = plaintext
		}},
		{name: "a header block without its Feedback-ID", want: fixed("Z5"), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			message := testPartEvents(capture)[3]
			part := capture.Events[message].Part
			header := 0
			if part.Mode == 1 {
				header = 1
			}
			plaintext := capture.Witnesses[message].ClientPlaintexts[header]
			if !c.tls12 {
				plaintext = plaintext[:len(plaintext)-1]
			}
			lines := strings.SplitAfter(string(plaintext), "\r\n")
			lines = slices.DeleteFunc(lines, func(line string) bool { return strings.HasPrefix(line, "Feedback-ID:") })
			testRewriteClientRecord(t, c, capture, message, header, []byte(strings.Join(lines, "")))
		}},
		{name: "a command of its template's length that says another", want: fixed("Z4"), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			if c.data {
				envelope := testPartEvents(capture)[2]
				last := len(capture.Events[envelope].Part.Records) - 1
				testRewriteClientRecord(t, c, capture, envelope, last, []byte("DATB\r\n"))
				return
			}
			// the count's last digit changed, so the record keeps its length
			message := testPartEvents(capture)[3]
			command := string(capture.Witnesses[message].ClientPlaintexts[0])
			digit := strings.Index(command, " LAST") - 1
			changed := []byte(command[:digit] + string('0'+('9'-command[digit])) + command[digit+1:])
			if !c.tls12 {
				changed = changed[:len(changed)-1]
			}
			testRewriteClientRecord(t, c, capture, message, 0, changed)
		}},
		{name: "a command no template of its length can fill", want: fixed("E3"), mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			if c.data {
				envelope := testPartEvents(capture)[2]
				last := len(capture.Events[envelope].Part.Records) - 1
				testRewriteClientRecord(t, c, capture, envelope, last, []byte("DATA \r\n"))
				return
			}
			message := testPartEvents(capture)[3]
			testRewriteClientRecord(t, c, capture, message, 0, []byte("BDAT 1 LAST\r\n"))
		}},
	}
	if !testing.Short() {
		mutations = append(mutations, mutation{name: "a disclosed SHTS one bit off", want: func(c *testLegCase) []string {
			if c.tls12 {
				return nil
			}
			return []string{"E2"}
		}, mutate: func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture) {
			for _, event := range capture.Events {
				if event.Shts != nil {
					event.Shts = bytes.Clone(event.Shts)
					event.Shts[0] ^= 1
				}
			}
		}})
	}
	for _, m := range mutations {
		for _, c := range testLegCases() {
			capture := smtpproof.ExportCapture(t, c.leg, c.data)
			m.mutate(t, c, capture)
			want := m.want(c)
			slices.Sort(want)
			gate := testGateVerdict(capture)
			ours := testCheckerVerdict(capture)
			if !slices.Equal(gate, want) || !slices.Equal(ours, want) {
				t.Errorf("%s, %s: the gate names %v and the checker %v, want %v", m.name, c.name, gate, ours, want)
			}
		}
	}
}

// Writes the checker's fixed transcripts, one honest connection per leg and mode, which its own
// tests read without this package. Set SMTPPROOF_WRITE_CHECKER_VECTORS to rewrite them.
func TestWriteCheckerVectors(t *testing.T) {
	if os.Getenv("SMTPPROOF_WRITE_CHECKER_VECTORS") == "" {
		t.Skip("set SMTPPROOF_WRITE_CHECKER_VECTORS to rewrite checker/testdata")
	}
	directory := filepath.Join("checker", "testdata")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range testLegCases() {
		transcript, witnesses := testCheckerInput(smtpproof.ExportCapture(t, c.leg, c.data))
		encoded, err := json.MarshalIndent(struct {
			Transcript *checker.Transcript
			Witnesses  map[int]*checker.PartWitness
		}{Transcript: transcript, Witnesses: witnesses}, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		name := strings.ReplaceAll(c.name, " ", "-") + ".json"
		if err := os.WriteFile(filepath.Join(directory, name), encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
