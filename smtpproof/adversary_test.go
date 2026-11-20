// FS-31's malicious sender (SMTP-M9-30; D-SMTP-16's adversarial corpus): this package's honest Prover with the
// means a sender holding its own keys has. The prover's own (proverAdversary) prove a part its check refuses,
// force a mode, go on past a refusal, send other envelope commands and seal other content, every record still
// under the connection's real keys and every part proven over what its records hold. Around the prover, the hooks
// here change each part's witness after it is proven, each part on its way to the edge, and each record on its way
// out: dropped, kept, re-sealed under the client's keys or joined by others. The hooks see the connection's keys
// once the key part is proven, which is before any application record is written.
//
// What refuses each such send is the edge's checks alone, before the MX reads any record the refused part opens.

package smtpproof

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A malicious sender's means, beside the prover's own.
type fs31Adversary struct {
	prover *proverAdversary
	// Changes a part's witness after the prover checked it, if the prover did.
	witness func(attack *fs31Attack, statement *partStatement, witness *partWitness)
	// Changes a part on its way to the edge.
	part func(attack *fs31Attack, part *sidecar.SmtpProofPart)
	// The records sent in place of the client application record at seq: none, it, or others.
	record func(attack *fs31Attack, seq uint64, record []byte) [][]byte
}

// One connection's attack in progress: what the hooks share. Safe for concurrent use.
type fs31Attack struct {
	t         *testing.T
	cell      *fs31Cell
	backend   *fs31Backend
	adversary *fs31Adversary

	stateLock sync.Mutex
	// Every part as submitted, in order.
	parts []*sidecar.SmtpProofPart
	// Records the attack sealed in place of the prover's, by the prover's record, in parts and on the wire alike.
	replacements map[string][]byte
}

func newFs31Attack(t *testing.T, cell *fs31Cell, backend *fs31Backend, adversary *fs31Adversary) *fs31Attack {
	return &fs31Attack{t: t, cell: cell, backend: backend, adversary: adversary, replacements: map[string][]byte{}}
}

// The connection's TLS version, as this package spells it.
func (self *fs31Attack) version() uint16 {
	if self.cell.tls12() {
		return tlsVersion12
	}
	return tlsVersion13
}

// The witness backend.provePart calls, with the attack's hook in it.
func (self *fs31Attack) mutateWitness(statement *partStatement, witness *partWitness) {
	if self.adversary.witness != nil {
		self.adversary.witness(self, statement, witness)
	}
}

// A client record at seq, sealed under key and iv from the plaintext a witness holds (1.3's with its type octet).
func (self *fs31Attack) seal(key []byte, iv []byte, seq uint64, plaintext []byte) []byte {
	self.t.Helper()
	cipher, err := newTlsCipher(self.version(), self.cell.leg.suites[0], key, iv)
	if err != nil {
		self.t.Fatal(err)
	}
	cipher.seq = seq
	recordType, content := uint8(tlsRecordApplicationData), plaintext
	if self.version() == tlsVersion13 {
		recordType, content = plaintext[len(plaintext)-1], plaintext[:len(plaintext)-1]
	}
	record, err := cipher.seal(recordType, content)
	if err != nil {
		self.t.Fatal(err)
	}
	return record
}

// A client record at seq under the connection's own keys.
func (self *fs31Attack) sealClient(seq uint64, plaintext []byte) []byte {
	self.t.Helper()
	keys := self.backend.connectionKeys()
	if keys == nil {
		self.t.Fatal("a record sealed before the key part was proven")
	}
	return self.seal(keys.clientKey, keys.clientIv, seq, plaintext)
}

// A client record's plaintext at seq under the connection's own keys, as a witness holds it.
func (self *fs31Attack) openClient(seq uint64, record []byte) []byte {
	self.t.Helper()
	keys := self.backend.connectionKeys()
	cipher, err := newTlsCipher(self.version(), self.cell.leg.suites[0], keys.clientKey, keys.clientIv)
	if err != nil {
		self.t.Fatal(err)
	}
	cipher.seq = seq
	recordType, content, err := cipher.open(record)
	if err != nil {
		self.t.Fatalf("a client record at %d: %v", seq, err)
	}
	if self.version() == tlsVersion13 {
		return append(content, recordType)
	}
	return content
}

// Sends replacement in parts and on the wire wherever the prover sent record.
func (self *fs31Attack) replace(record []byte, replacement []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.replacements[string(record)] = bytes.Clone(replacement)
}

func (self *fs31Attack) replacement(record []byte) []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if replacement, ok := self.replacements[string(record)]; ok {
		return replacement
	}
	return record
}

// The latest part submitted with this index, or nil.
func (self *fs31Attack) part(index uint32) *sidecar.SmtpProofPart {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, part := range slices.Backward(self.parts) {
		if part.Index == index {
			return part
		}
	}
	return nil
}

// The last part submitted, the one with Last set, or nil.
func (self *fs31Attack) lastPart() *sidecar.SmtpProofPart {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, part := range slices.Backward(self.parts) {
		if part.Last {
			return part
		}
	}
	return nil
}

// The stream as the sender writes it, through the attack.
func (self *fs31Attack) conn(conn net.Conn) net.Conn {
	return &fs31AttackConn{Conn: conn, attack: self}
}

// The channel as the sender submits parts on it, through the attack.
func (self *fs31Attack) channel(channel sidecar.SmtpProofChannel) sidecar.SmtpProofChannel {
	return &fs31AttackChannel{inner: channel, attack: self}
}

// The sidecar's end of the connection as a malicious sender writes it: each whole record the prover writes goes
// out as the attack has it. Reads pass untouched.
type fs31AttackConn struct {
	net.Conn
	attack *fs31Attack

	writeLock sync.Mutex
	pending   []byte
	// Client records of outer type application_data so far, 1.3's Finished the first of them.
	applicationRecords int
}

func (self *fs31AttackConn) Write(data []byte) (int, error) {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	self.pending = append(self.pending, data...)
	for tlsRecordHeaderBytes <= len(self.pending) {
		size := tlsRecordHeaderBytes + int(binary.BigEndian.Uint16(self.pending[3:5]))
		if len(self.pending) < size {
			break
		}
		record := bytes.Clone(self.pending[:size])
		self.pending = self.pending[size:]
		for _, sent := range self.sent(record) {
			if _, err := self.Conn.Write(sent); err != nil {
				return 0, err
			}
		}
	}
	return len(data), nil
}

// What goes out for one record the prover wrote.
func (self *fs31AttackConn) sent(record []byte) [][]byte {
	if record[0] != tlsRecordApplicationData {
		return [][]byte{record}
	}
	self.applicationRecords += 1
	// 1.3's first is the client's Finished under the handshake keys; 1.2's Finished took sequence number 0
	seq := uint64(self.applicationRecords)
	if self.attack.version() == tlsVersion13 {
		if self.applicationRecords == 1 {
			return [][]byte{record}
		}
		seq = uint64(self.applicationRecords - 2)
	}
	record = self.attack.replacement(record)
	if self.attack.adversary.record != nil {
		return self.attack.adversary.record(self.attack, seq, record)
	}
	return [][]byte{record}
}

// The parts as a malicious sender submits them.
type fs31AttackChannel struct {
	inner  sidecar.SmtpProofChannel
	attack *fs31Attack
}

func (self *fs31AttackChannel) DiscloseShts(ctx context.Context, shts []byte) error {
	return self.inner.DiscloseShts(ctx, shts)
}

func (self *fs31AttackChannel) SubmitPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	clone := *part
	clone.Records = make([][]byte, 0, len(part.Records))
	for _, record := range part.Records {
		clone.Records = append(clone.Records, self.attack.replacement(record))
	}
	if self.attack.adversary.part != nil {
		self.attack.adversary.part(self.attack, &clone)
	}
	func() {
		self.attack.stateLock.Lock()
		defer self.attack.stateLock.Unlock()
		self.attack.parts = append(self.attack.parts, &clone)
	}()
	return self.inner.SubmitPart(ctx, &clone)
}

// Seals each client record a part's statement opens again under its witness's client key with one bit off, the
// plaintexts kept, so the part proves a benign plaintext under keys other than the key part committed to: only Z1's
// opening can refuse it (DESIGN-DETAILS 3.6's later-keys cell).
func fs31OtherKeysWitness(attack *fs31Attack, statement *partStatement, witness *partWitness) {
	key := bytes.Clone(witness.clientKey)
	key[0] ^= 1
	witness.clientKey = key
	for i, record := range statement.clientRecords {
		attack.replace(record.raw, attack.seal(key, witness.clientIv, record.seq, witness.clientPlaintexts[i]))
	}
}

// Forges the state a hdr or body part's scan starts from to where every scan does, where the record before left
// another: the part's own record scans from there, so only the carry it opens can refuse it (DESIGN-DETAILS 3.6's
// forged-scan cells).
func fs31ForgedCarryWitness(attack *fs31Attack, statement *partStatement, witness *partWitness) {
	if witness.carryInState == scanStart {
		attack.t.Errorf("part %d starts its scan where every scan does, so its carry cannot be forged", statement.index)
	}
	witness.carryInState = scanStart
}

// A forged server record of an edge holding no key: content sealed under a key of its own, framed as the MX's
// record at seq would be, which the prover's TLS client must refuse.
func fs31ForgedServerRecord(version uint16, suite uint16, seq uint64, content []byte) ([]byte, error) {
	key := make([]byte, tlsKeyBytes(suite))
	iv := make([]byte, 12)
	if version == tlsVersion12 {
		iv = make([]byte, tlsSalt12Bytes)
	}
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	cipher, err := newTlsCipher(version, suite, key, iv)
	if err != nil {
		return nil, err
	}
	cipher.seq = seq
	if len(content) == 0 {
		return nil, errors.New("no content to forge")
	}
	return cipher.seal(tlsRecordApplicationData, content)
}

// FuzzSmtpTranscript (SMTP-M9-30; the seeds SMTP-M0-02 deferred here): an honest connection's whole transcript, the
// records both ways, the disclosed SHTS and every part with the witness its prover held, edited by a fuzzer and
// replayed into a fresh gate whose verifier holds each part to the relation over that witness. Edits flip, cut, drop,
// repeat and swap events as FuzzEdgeHandshake's do, and change every field of a part: its records, its range, its
// counts, its index, mode and last flag, its carry and its key commitment. The oracle is the MX's own view: it opens
// each application record the gate hands it under the client's keys, at its own sequence number, and reads the
// plaintext of each that authenticates, its TLS failing at the first that does not, as a tag a bit off makes it, which
// no part proves (SPEC.md Z2). Whatever the edit, what the MX reads is a prefix of the honest sender's plaintexts, the
// client's Finished under 1.3 aside: no edit makes the MX read a command the honest parts did not prove. The gate also
// holds to its bounds, panics on nothing and passes nothing after its first refusal.

// One event of a transcript replay: a record either way, a disclosed SHTS, or a part with its prover's witness.
type fs31TranscriptEvent struct {
	fromClient bool
	record     []byte
	shts       []byte
	part       *sidecar.SmtpProofPart
	witness    *partWitness
}

// An honest connection with its parts' witnesses, captured once per process and shared read-only.
type fs31Transcript struct {
	fixture   *testGateFixture
	witnesses []*partWitness
}

var fs31Transcripts = struct {
	stateLock sync.Mutex
	byKey     map[string]*fs31Transcript
}{byKey: map[string]*fs31Transcript{}}

// A BDAT or DATA connection on one of testTlsLegs' legs, with several DATA parts, its witnesses kept.
func fs31CachedTranscript(t *testing.T, legIndex int, data bool) *fs31Transcript {
	t.Helper()
	leg := testTlsLegs()[legIndex%len(testTlsLegs())]
	key := leg.name + " " + strconv.FormatBool(data)
	fs31Transcripts.stateLock.Lock()
	defer fs31Transcripts.stateLock.Unlock()
	if transcript, ok := fs31Transcripts.byKey[key]; ok {
		return transcript
	}
	settings := DefaultProverSettings()
	job := testJob("one line\r\nanother line\r\nand a third\r\n", "bob", "carol")
	if data {
		settings.ForceData = true
		settings.testDataRecordByteCount = 12
		job.Preamble.MessageByteCount = uint64(len(dotStuffed(job.Message)))
	}
	send := testRunSend(t, leg, testMxDefaults(), settings, job)
	testExpectOneTransaction(t, leg, send, job)
	if len(send.backend.proved) != len(send.edge.parts) {
		t.Fatalf("%d witnesses for %d parts", len(send.backend.proved), len(send.edge.parts))
	}
	transcript := &fs31Transcript{
		fixture:   &testGateFixture{leg: leg, preamble: newSessionPreamble(job.Preamble, DefaultProofSettings()), trace: send.edge.trace, parts: send.edge.parts},
		witnesses: send.backend.proved,
	}
	fs31Transcripts.byKey[key] = transcript
	return transcript
}

// The transcript's events, each part placed before the first client record it opens, as testReplayEvents places it.
func (self *fs31Transcript) events() []*fs31TranscriptEvent {
	var events []*fs31TranscriptEvent
	for _, event := range testReplayEvents(self.fixture) {
		if event.part != 0 {
			part := *self.fixture.parts[event.part-1]
			part.Records = slices.Clone(part.Records)
			events = append(events, &fs31TranscriptEvent{part: &part, witness: self.witnesses[event.part-1]})
			continue
		}
		events = append(events, &fs31TranscriptEvent{fromClient: event.fromClient, record: bytes.Clone(event.record), shts: bytes.Clone(event.shts)})
	}
	return events
}

// The client records of type application_data the honest sender wrote, in order, under 1.3 less the client's
// Finished, which is the first of them.
func (self *fs31Transcript) honestApplicationRecords() [][]byte {
	var records [][]byte
	for _, entry := range self.fixture.trace {
		if entry.fromClient && entry.record != nil && entry.record[0] == tlsRecordApplicationData {
			records = append(records, entry.record)
		}
	}
	if self.fixture.version() == tlsVersion13 && 0 < len(records) {
		records = records[1:]
	}
	return records
}

// What the MX makes of the client's application records: each opened in turn under the client's keys from the first
// application sequence number, as the MX's TLS opens them, until one fails, after which it reads nothing.
type fs31MxReader struct {
	cipher *tlsCipher
	failed bool
}

func (self *fs31Transcript) mxReader(t *testing.T) *fs31MxReader {
	t.Helper()
	keys := self.witnesses[0]
	cipher, err := newTlsCipher(self.fixture.version(), self.fixture.leg.suites[0], keys.clientKey, keys.clientIv)
	if err != nil {
		t.Fatal(err)
	}
	cipher.seq = firstApplicationSeq(self.fixture.version())
	return &fs31MxReader{cipher: cipher}
}

// The plaintext the MX reads of the next record, type octet included, or nil where its TLS has failed.
func (self *fs31MxReader) read(record []byte) []byte {
	if self.failed {
		return nil
	}
	recordType, content, err := self.cipher.open(record)
	if err != nil {
		self.failed = true
		return nil
	}
	return append(bytes.Clone(content), recordType)
}

// The plaintexts the MX reads of the honest sender's application records, in order.
func (self *fs31Transcript) honestPlaintexts(t *testing.T) [][]byte {
	t.Helper()
	reader := self.mxReader(t)
	var plaintexts [][]byte
	for _, record := range self.honestApplicationRecords() {
		plaintext := reader.read(record)
		if plaintext == nil {
			t.Fatalf("%s: the honest sender's record %d does not open", self.fixture.leg.name, len(plaintexts))
		}
		plaintexts = append(plaintexts, plaintext)
	}
	return plaintexts
}

// Applies a fuzzer's edits to a transcript: each four octets name an edit, an event, a position and a value. A part's
// edit changes one of its fields; a record's or the SHTS's flips, drops, repeats, cuts short or swaps it, as
// testEditReplay does.
func fs31EditTranscript(events []*fs31TranscriptEvent, edits []byte) []*fs31TranscriptEvent {
	for count := 0; 4 <= len(edits) && count < 8 && 0 < len(events); count += 1 {
		kind, index, position, value := int(edits[0]), int(edits[1]), int(edits[2]), edits[3]
		edits = edits[4:]
		target := index % len(events)
		event := events[target]
		switch {
		case kind%4 == 1:
			events = append(events[:target:target], events[target+1:]...)
		case kind%4 == 2:
			repeat := *event
			events = append(events[:target+1:target+1], append([]*fs31TranscriptEvent{&repeat}, events[target+1:]...)...)
		case kind%4 == 3:
			if target+1 < len(events) {
				events[target], events[target+1] = events[target+1], events[target]
			}
		case event.part != nil:
			part := *event.part
			part.Records = slices.Clone(part.Records)
			fs31EditPart(&part, kind/4, position, value)
			edited := *event
			edited.part = &part
			events[target] = &edited
		default:
			edited := *event
			octets := bytes.Clone(event.record)
			if event.shts != nil {
				octets = bytes.Clone(event.shts)
			}
			switch {
			case len(octets) == 0:
			case (kind/4)%2 == 0:
				octets[position%len(octets)] ^= value | 1
			case event.record != nil && tlsRecordHeaderBytes < len(octets):
				// cut short, with the framing kept true so the cut reaches what reads inside the record
				payload := octets[tlsRecordHeaderBytes:]
				octets = tlsFrameRecord(octets[0], tlsVersion12, payload[:position%len(payload)])
			default:
				octets = octets[:position%len(octets)]
			}
			if event.shts != nil {
				edited.shts = octets
			} else {
				edited.record = octets
			}
			events[target] = &edited
		}
	}
	return events
}

// One field of a part changed: a record's octet, a record dropped or repeated, the range, a count, the index, mode or
// last flag, or an octet of the carry or the key commitment.
func fs31EditPart(part *sidecar.SmtpProofPart, field int, position int, value byte) {
	delta := uint64(1)
	if value&1 != 0 {
		delta = ^uint64(0)
	}
	switch field % 10 {
	case 0:
		if 0 < len(part.Records) {
			i := position % len(part.Records)
			record := bytes.Clone(part.Records[i])
			record[(position/len(part.Records))%len(record)] ^= value | 1
			part.Records[i] = record
		}
	case 1:
		if 0 < len(part.Records) {
			i := position % len(part.Records)
			part.Records = append(part.Records[:i:i], part.Records[i+1:]...)
		}
	case 2:
		if 0 < len(part.Records) {
			i := position % len(part.Records)
			part.Records = append(part.Records[:i+1:i+1], part.Records[i:]...)
		}
	case 3:
		part.FirstRecord += delta
	case 4:
		part.LastRecord += delta
	case 5:
		part.ServerRecordCount += delta
	case 6:
		part.ReplyCount += uint32(delta)
	case 7:
		part.HeaderRecordCount += uint32(delta)
	case 8:
		switch position % 3 {
		case 0:
			part.Index += uint32(delta)
		case 1:
			part.Mode ^= 3
		default:
			part.Last = !part.Last
		}
	default:
		octets := &part.Carry
		if len(part.KeyCommitment) != 0 && position%2 == 0 {
			octets = &part.KeyCommitment
		}
		if 0 < len(*octets) {
			*octets = bytes.Clone(*octets)
			(*octets)[position%len(*octets)] ^= value | 1
		}
	}
}

// Holds each part to the relation over the witness its honest prover held, whatever the part now says.
type fs31TranscriptVerifier struct {
	witness *partWitness
}

func (self *fs31TranscriptVerifier) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	if self.witness == nil {
		return errors.New("no witness")
	}
	if failures := relationCheckPart(statement, self.witness); 0 < len(failures) {
		return failures[0]
	}
	return nil
}

// Replays events into a fresh gate under verifier, failing the test unless the gate passes nothing after its first
// refusal and keeps to its bounds, and returns an error unless what the MX reads of what the gate hands it is a prefix
// of the honest sender's plaintexts. verifier is fs31TranscriptVerifier's but where a test shows the oracle is not
// vacuous.
func fs31ReplayTranscript(t *testing.T, transcript *fs31Transcript, events []*fs31TranscriptEvent, verifier partVerifier) error {
	t.Helper()
	gate := transcript.fixture.gate(verifier)
	honest := transcript.honestPlaintexts(t)
	reader := transcript.mxReader(t)
	finishedLeft := transcript.fixture.version() == tlsVersion13
	read := 0
	refused := false
	for _, event := range events {
		var forwarded [][]byte
		var err error
		switch {
		case event.part != nil:
			if witnessed, ok := verifier.(*fs31TranscriptVerifier); ok {
				witnessed.witness = event.witness
			}
			forwarded, err = gate.VerifyPart(context.Background(), event.part)
		case event.shts != nil:
			forwarded, err = gate.DiscloseShts(event.shts)
		case event.fromClient:
			forwarded, err = gate.ClientRecord(event.record)
		default:
			err = gate.ServerRecord(event.record)
		}
		if refused && len(forwarded) != 0 {
			t.Fatalf("%d records passed after a refusal", len(forwarded))
		}
		for _, record := range forwarded {
			if record[0] != tlsRecordApplicationData {
				continue
			}
			if finishedLeft {
				// the client's Finished, under the handshake keys, which no part covers
				finishedLeft = false
				continue
			}
			plaintext := reader.read(record)
			if plaintext == nil {
				continue
			}
			if len(honest) <= read || !bytes.Equal(plaintext, honest[read]) {
				return fmt.Errorf("the MX reads application record %d as %q, which the honest sender did not write", read, plaintext)
			}
			read += 1
		}
		refused = refused || err != nil
		testExpectGateBounds(t, gate)
	}
	return nil
}

func FuzzSmtpTranscript(f *testing.F) {
	// each leg's honest transcript, BDAT and DATA, then every field of each part edited both ways, FS-31's bound-part
	// rows among them: a reply count one off, a server record count fallen, a carry or the key commitment one bit
	// off, a record it opens one bit off, dropped or repeated, and the part under another index or mode. A part sits
	// before the first record it opens: under 1.3 the key part at event 9, part 2 at 12 and part 3 at 19 in BDAT, 21 in
	// DATA, with DATA's second body part at 25; under 1.2 each one later
	for leg := range 3 {
		for _, data := range []byte{0, 4} {
			head := byte(leg) | data
			f.Add([]byte{head})
			parts := []byte{9, 12, 19}
			if data != 0 {
				parts = []byte{9, 12, 21, 25}
			}
			for _, partEvent := range parts {
				if leg == 2 {
					partEvent += 1
				}
				for field := range 10 {
					f.Add([]byte{head, byte(field * 4), partEvent, 1, 0x01})
					f.Add([]byte{head, byte(field * 4), partEvent, 2, 0x80})
				}
			}
			// a dropped, repeated and swapped event after the handshake, and a client record cut short
			f.Add([]byte{head, 1, 14, 0, 0})
			f.Add([]byte{head, 2, 15, 0, 0})
			f.Add([]byte{head, 3, 16, 0, 0})
			f.Add([]byte{head, 4, 17, 9, 0})
		}
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 {
			return
		}
		transcript := fs31CachedTranscript(t, int(input[0]&3), input[0]&4 != 0)
		if err := fs31ReplayTranscript(t, transcript, fs31EditTranscript(transcript.events(), input[1:]), &fs31TranscriptVerifier{}); err != nil {
			t.Fatal(err)
		}
	})
}

// The oracle sees what it is for: a part's MAIL record and the stream's sealed again under the client's own key over
// another sender local part of MAIL's length, which only the relation refuses, pass a gate whose verifier takes every
// part, and the oracle names the command the MX would have read; under the relation the same records go nowhere.
func TestFs31TranscriptOracleSeesARecordTheSenderDidNotWrite(t *testing.T) {
	for legIndex := range testTlsLegs() {
		transcript := fs31CachedTranscript(t, legIndex, false)
		keys := transcript.witnesses[0]
		version := transcript.fixture.version()
		events := transcript.events()
		var original, forged []byte
		for _, event := range events {
			if event.part == nil || event.part.Index != 2 {
				continue
			}
			original = event.part.Records[0]
			cipher, err := newTlsCipher(version, transcript.fixture.leg.suites[0], keys.clientKey, keys.clientIv)
			if err != nil {
				t.Fatal(err)
			}
			cipher.seq = event.part.FirstRecord
			recordType, content, err := cipher.open(original)
			if err != nil || !bytes.HasPrefix(content, []byte(literalMailPrefix)) {
				t.Fatalf("%s: part 2's first record is no MAIL: %v", transcript.fixture.leg.name, err)
			}
			mallory := bytes.Replace(content, []byte("bounce-1"), []byte("mallory1"), 1)
			sealer, err := newTlsCipher(version, transcript.fixture.leg.suites[0], keys.clientKey, keys.clientIv)
			if err != nil {
				t.Fatal(err)
			}
			sealer.seq = event.part.FirstRecord
			if forged, err = sealer.seal(recordType, mallory); err != nil {
				t.Fatal(err)
			}
			event.part.Records[0] = forged
		}
		for _, event := range events {
			if event.fromClient && bytes.Equal(event.record, original) {
				event.record = forged
			}
		}
		if err := fs31ReplayTranscript(t, transcript, events, &testFixedVerifier{}); err == nil {
			t.Errorf("%s: the oracle passed a MAIL the sender did not write", transcript.fixture.leg.name)
		}
		if err := fs31ReplayTranscript(t, transcript, events, &fs31TranscriptVerifier{}); err != nil {
			t.Errorf("%s: the relation let the same record through: %v", transcript.fixture.leg.name, err)
		}
	}
}
