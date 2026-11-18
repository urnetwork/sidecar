// smtpproof/checker against the gate and the relation, as an outside party would hold them: the same
// connections, honest and then broken in one place each, and the same checks named on both sides. This
// is an external test package, so it may import the checker; the captures come through
// export_test.go, from this package's own MX and from sidecartest's ScriptedMx and RecordMx, the
// latter a TLS server none of the three shares code with.

package smtpproof_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/urnetwork/sidecar/sidecartest"
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
				KeyCommitment: part.KeyCommitment, ReplyCount: part.ReplyCount, HeaderRecordCount: part.HeaderRecordCount,
				Carry: part.Carry,
			}
		}
		transcript.Events = append(transcript.Events, converted)
	}
	witnesses := map[int]*checker.PartWitness{}
	for i, witness := range capture.Witnesses {
		witnesses[i] = &checker.PartWitness{
			HandshakeSecret: witness.HandshakeSecret, MasterSecret: witness.MasterSecret,
			ClientKey: witness.ClientKey, ClientIv: witness.ClientIv, ServerKey: witness.ServerKey, ServerIv: witness.ServerIv,
			KeyBlind: witness.KeyBlind, CarryInState: witness.CarryInState, CarryInBlind: witness.CarryInBlind,
			CarryOutBlind: witness.CarryOutBlind, ClientPlaintexts: witness.ClientPlaintexts, ServerPlaintexts: witness.ServerPlaintexts,
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

// One break of an honest capture, and the checks it must fail, which may depend on the leg and mode.
type testCheckerMutation struct {
	name   string
	want   func(c *testLegCase) []string
	mutate func(t *testing.T, c *testLegCase, capture *smtpproof.ExportedCapture)
}

// The breaks the gate and the checker must name alike, each in one place.
func testCheckerMutations() []*testCheckerMutation {
	type mutation = testCheckerMutation
	fixed := func(checks ...string) func(c *testLegCase) []string {
		return func(c *testLegCase) []string { return checks }
	}
	mutations := []*mutation{
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
		mutations = append(mutations, &mutation{name: "a disclosed SHTS one bit off", want: func(c *testLegCase) []string {
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
	return mutations
}

// Breaks one capture with m and holds the gate and the checker to the same checks.
func testExpectSameChecks(t *testing.T, m *testCheckerMutation, c *testLegCase, capture *smtpproof.ExportedCapture) {
	t.Helper()
	m.mutate(t, c, capture)
	want := m.want(c)
	slices.Sort(want)
	gate := testGateVerdict(capture)
	ours := testCheckerVerdict(capture)
	if !slices.Equal(gate, want) || !slices.Equal(ours, want) {
		t.Errorf("%s, %s: the gate names %v and the checker %v, want %v", m.name, c.name, gate, ours, want)
	}
}

func TestCheckerAndTheGateNameTheSameChecks(t *testing.T) {
	for _, m := range testCheckerMutations() {
		for _, c := range testLegCases() {
			testExpectSameChecks(t, m, c, smtpproof.ExportCapture(t, c.leg, c.data))
		}
	}
}

// Writes the checker's fixed transcripts, which its own tests read without this package: one honest
// connection per leg and mode, and one per leg and mode whose header block takes two records, the first
// cut inside a field's name (-split-name). Set SMTPPROOF_WRITE_CHECKER_VECTORS to rewrite them.
func TestWriteCheckerVectors(t *testing.T) {
	if os.Getenv("SMTPPROOF_WRITE_CHECKER_VECTORS") == "" {
		t.Skip("set SMTPPROOF_WRITE_CHECKER_VECTORS to rewrite checker/testdata")
	}
	directory := filepath.Join("checker", "testdata")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range testLegCases() {
		for suffix, capture := range map[string]func(t *testing.T, legIndex int, data bool) *smtpproof.ExportedCapture{
			"":            smtpproof.ExportCapture,
			"-split-name": smtpproof.ExportSplitNameCapture,
		} {
			transcript, witnesses := testCheckerInput(capture(t, c.leg, c.data))
			encoded, err := json.MarshalIndent(struct {
				Transcript *checker.Transcript
				Witnesses  map[int]*checker.PartWitness
			}{Transcript: transcript, Witnesses: witnesses}, "", " ")
			if err != nil {
				t.Fatal(err)
			}
			name := strings.ReplaceAll(c.name, " ", "-") + suffix + ".json"
			if err := os.WriteFile(filepath.Join(directory, name), encoded, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// An MX of each of sidecartest's kinds for a leg: ScriptedMx behind crypto/tls's server, and RecordMx
// behind the server written apart from both.
func testAgreementMxs(t *testing.T, leg *smtpproof.ExportedMxLeg) map[string]sidecartest.MxServer {
	t.Helper()
	scripted, err := sidecartest.NewScriptedMx("mx.recipient.example", nil, &sidecartest.ScriptedMxSettings{
		MinVersion:   leg.Version,
		MaxVersion:   leg.Version,
		CipherSuites: []uint16{leg.Suite},
		RsaKey:       leg.Suite == tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := sidecartest.NewRecordMx("mx.recipient.example", nil, &sidecartest.RecordMxSettings{Version: leg.Version, Suite: leg.Suite})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]sidecartest.MxServer{"scripted": scripted, "record": record}
}

// SMTP-M9-02's fixtures as the honest corpus: every leg, both modes, both MXs, whose TLS the checker
// and this module share no code with, and the gate and the checker each pass every send, with a header
// block of one record and of two, the first ending inside a field's name, so that a carry crosses.
func TestCheckerAgreesOnHonestSendsThroughSidecartestsMxs(t *testing.T) {
	for _, leg := range smtpproof.ExportMxLegs() {
		for _, data := range []bool{false, true} {
			for _, splitName := range []bool{false, true} {
				for kind, mx := range testAgreementMxs(t, leg) {
					capture := smtpproof.ExportMxCapture
					if splitName {
						capture = smtpproof.ExportSplitNameMxCapture
					}
					honest := capture(t, leg.Name, data, mx)
					name := fmt.Sprintf("%s %s data=%t split=%t", leg.Name, kind, data, splitName)
					if verdict := testGateVerdict(honest); len(verdict) != 0 {
						t.Errorf("%s: the gate refuses an honest send: %v", name, verdict)
					}
					for _, failure := range checker.Check(testCheckerInput(honest)) {
						t.Errorf("%s: the checker refuses an honest send: %v", name, failure)
					}
				}
			}
		}
	}
}

// What only RecordMx sends: a NewSessionTicket the client never asked for, which Z7 skips, ahead of
// each of the first replies, and replies split across records. The gate and the checker pass each. The
// split is into records of 16 octets, which every env shape's server blocks hold as the EHLO reply's;
// finer, ChaCha20's env shape holds too few, and the send ends before MAIL by design (DESIGN-DETAILS 3.5).
func TestCheckerAgreesThroughALateTicketAndSplitReplies(t *testing.T) {
	for _, leg := range smtpproof.ExportMxLegs() {
		if leg.Version != tls.VersionTLS13 {
			continue
		}
		for _, settings := range []*sidecartest.RecordMxSettings{
			{TicketBeforeReply: 1}, {TicketBeforeReply: 2}, {TicketBeforeReply: 3}, {SplitRepliesAt: 16},
		} {
			settings.Version, settings.Suite = leg.Version, leg.Suite
			mx, err := sidecartest.NewRecordMx("mx.recipient.example", nil, settings)
			if err != nil {
				t.Fatal(err)
			}
			capture := smtpproof.ExportMxCapture(t, leg.Name, false, mx)
			name := fmt.Sprintf("%s ticket before reply %d, split at %d", leg.Name, settings.TicketBeforeReply, settings.SplitRepliesAt)
			if verdict := testGateVerdict(capture); len(verdict) != 0 {
				t.Errorf("%s: the gate refuses an honest send: %v", name, verdict)
			}
			for _, failure := range checker.Check(testCheckerInput(capture)) {
				t.Errorf("%s: the checker refuses an honest send: %v", name, failure)
			}
		}
	}
}

// The same breaks over captures through RecordMx, a TLS server written apart from the checker and
// from this module, on every leg, ECDHE-RSA included, which this package's own MX never runs.
func TestCheckerAndTheGateNameTheSameChecksThroughARecordMx(t *testing.T) {
	for _, leg := range smtpproof.ExportMxLegs() {
		certificate, err := sidecartest.NewMxCertificate("mx.recipient.example", leg.Suite == tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		if err != nil {
			t.Fatal(err)
		}
		for _, data := range []bool{false, true} {
			c := &testLegCase{name: fmt.Sprintf("%s record data=%t", leg.Name, data), data: data, tls12: leg.Version == tls.VersionTLS12}
			for _, m := range testCheckerMutations() {
				mx, err := sidecartest.NewRecordMx("mx.recipient.example", nil, &sidecartest.RecordMxSettings{Version: leg.Version, Suite: leg.Suite, Certificate: &certificate})
				if err != nil {
					t.Fatal(err)
				}
				testExpectSameChecks(t, m, c, smtpproof.ExportMxCapture(t, leg.Name, data, mx))
			}
		}
	}
}

// DESIGN-DETAILS 3.6's cells through RecordMx as well, on every leg, ECDHE-RSA included: each break
// mutate_test.go's registry fills a cell with is named alike by the gate and the checker, from a send
// through a TLS server written apart from both.
func TestCheckerAndTheGateNameTheSameChecksOnTheDetailsCellsThroughARecordMx(t *testing.T) {
	for _, leg := range smtpproof.ExportMxLegs() {
		certificate, err := sidecartest.NewMxCertificate("mx.recipient.example", leg.Suite == tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		if err != nil {
			t.Fatal(err)
		}
		for _, data := range []bool{false, true} {
			c := &testLegCase{name: fmt.Sprintf("%s record data=%t", leg.Name, data), data: data, tls12: leg.Version == tls.VersionTLS12}
			for _, m := range testMutations() {
				if m.cell == "" || (m.applies != nil && !m.applies(c)) {
					continue
				}
				mx, err := sidecartest.NewRecordMx("mx.recipient.example", nil, &sidecartest.RecordMxSettings{Version: leg.Version, Suite: leg.Suite, Certificate: &certificate})
				if err != nil {
					t.Fatal(err)
				}
				capture := smtpproof.ExportMxCapture
				if m.splitName {
					capture = smtpproof.ExportSplitNameMxCapture
				}
				testExpectSameChecks(t, &testCheckerMutation{name: m.name, want: func(*testLegCase) []string { return []string{m.check} }, mutate: m.mutate}, c, capture(t, leg.Name, data, mx))
			}
		}
	}
}

// A tail of header lines that take the scan's state through each of its fields: a name unfinished and
// past its colon, a CR and a line's start, a continuation, names that begin a single field's literal and
// then leave it, and the full DKIM signature, which runs with the fixed one's prefix up to its h= tag.
const testCarryTail = "X-Spanning-Name: v\r\n\tcontinued\r\nFrom-Like: x\r\nMessage-Idx: y\r\n" +
	"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:to:subject:date:message-id:x-ur-ref:feedback-id; d=net.root.example; s=s1; t=1; bh=AAAA; b=BBBB\r\n"

// Holds an honest capture to both readers' passing it.
func testExpectHonestAgreement(t *testing.T, name string, capture *smtpproof.ExportedCapture) {
	t.Helper()
	if verdict := testGateVerdict(capture); len(verdict) != 0 {
		t.Errorf("%s: the gate refuses an honest send: %v", name, verdict)
	}
	for _, failure := range checker.Check(testCheckerInput(capture)) {
		t.Errorf("%s: the checker refuses an honest send: %v", name, failure)
	}
}

// Forges, on an honest capture, the state a part's scan starts from to the start state, where the record
// before left another, holds the gate and the checker to naming check alone, and puts the state back.
// A part whose record does start at the start state has no such forgery, and is passed over.
func testExpectForgedStartAgreement(t *testing.T, name string, capture *smtpproof.ExportedCapture, index uint32, check string) {
	t.Helper()
	witness := capture.Witnesses[testPartEvents(capture)[index]]
	honest := witness.CarryInState
	if honest == smtpproof.ExportScanStart {
		return
	}
	witness.CarryInState = smtpproof.ExportScanStart
	defer func() { witness.CarryInState = honest }()
	want := []string{check}
	gate := testGateVerdict(capture)
	ours := testCheckerVerdict(capture)
	if !slices.Equal(gate, want) || !slices.Equal(ours, want) {
		t.Errorf("%s, part %d scanned from the start state: the gate names %v and the checker %v, want %v", name, index, gate, ours, want)
	}
}

// The carry between a header block's two records, read by the checker from the state's definition and by
// the prover and the gate from the relation's scan, at every octet of testCarryTail on one leg and mode
// and at every seventh on the rest: an honest send passes both at each cut, so the two readers' states
// agree there, and its second record scanned from the start state is Z5 to both wherever the first left
// another state.
func TestCheckerAgreesOnTheHeaderCarryAtEveryCut(t *testing.T) {
	for _, c := range testLegCases() {
		step := 1
		if c.leg != 0 || c.data {
			step = 7
		}
		for cut := 0; cut+len("\r\n") <= len(testCarryTail); cut += step {
			capture := smtpproof.ExportCutHeaderCapture(t, c.leg, c.data, testCarryTail, cut)
			name := fmt.Sprintf("%s, the first record ending %q", c.name, testCarryTail[max(0, cut-16):cut])
			testExpectHonestAgreement(t, name, capture)
			testExpectForgedStartAgreement(t, name, capture, 4, "Z5")
		}
	}
}

// DATA's body records, 12 octets each in these captures, with the body shifted by 0 to 11 octets so that a
// boundary falls at each octet of lines that take the body's scan through its states: a stuffed dot at a
// line's start, a line of one dot stuffed, an empty line, a dot inside a line, CR and LF. Every shift passes
// both readers, and each body record after the first scanned from the start state is Z6 to both wherever
// the record before left another.
func TestCheckerAgreesOnTheBodyCarryAtEveryCut(t *testing.T) {
	for _, c := range testLegCases() {
		if !c.data {
			continue
		}
		for shift := range 12 {
			body := strings.Repeat("s", shift) + "\r\n.a\r\n.\r\n\r\nb.\r\nend\r\n"
			capture := smtpproof.ExportBodyCapture(t, c.leg, true, body)
			name := fmt.Sprintf("%s, the body shifted %d", c.name, shift)
			testExpectHonestAgreement(t, name, capture)
			events := testPartEvents(capture)
			// part 4 opens the body's first record, whose scan the gate starts itself
			for index := uint32(5); int(index) <= len(events); index += 1 {
				testExpectForgedStartAgreement(t, name, capture, index, "Z6")
			}
		}
	}
}

// A single field's line that ends the header block's first record, each single field in turn: an honest
// send passes both readers, whose states at the cut agree that a single field's line just ended; the
// second record scanned from the start state is Z5 to both; and the second record opening with a
// continuation of that field, in its length, is Z5 to both at that record (DESIGN-DETAILS 3.2.4's H6).
func TestCheckerAgreesOnASingleFieldEndingTheFirstRecord(t *testing.T) {
	for _, field := range []string{"From", "Message-ID", "X-UR-Ref", "Feedback-ID"} {
		for _, c := range testLegCases() {
			block := smtpproof.ExportSingleEndsHeaderBlock(c.leg, field)
			if block == "" {
				t.Fatalf("no header block ends its first record with %s", field)
			}
			name := fmt.Sprintf("%s, %s ending the first record", c.name, field)
			capture := smtpproof.ExportMessageCapture(t, c.leg, c.data, block+"one line\r\n", 2)
			testExpectHonestAgreement(t, name, capture)
			testExpectForgedStartAgreement(t, name, capture, 4, "Z5")

			header := testPartEvents(capture)[4]
			plaintext := capture.Witnesses[header].ClientPlaintexts[0]
			content := []byte(plaintext)
			if !c.tls12 {
				content = content[:len(content)-1]
			}
			continued := append([]byte(" "), content[1:]...)
			testRewriteClientRecord(t, c, capture, header, 0, continued)
			want := []string{"Z5"}
			if gate, ours := testGateVerdict(capture), testCheckerVerdict(capture); !slices.Equal(gate, want) || !slices.Equal(ours, want) {
				t.Errorf("%s, then continued: the gate names %v and the checker %v, want %v", name, gate, ours, want)
			}
		}
	}
}
