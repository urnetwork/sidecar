package smtpproof

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The host's own DATA speed (D-SMTP-20). A later DATA part's circuit is fixed, so proving one costs the
// same whatever it carries: the host proves one full part per suite it holds keys for, over a session
// made up for the purpose, and the slowest suite sets smtp_data_proof_bytes and whether DATA is open
// to this host at all. The host records the result at p/ (§15.7), and later sends use it. Before any
// of that it proves one part of each suite's largest shape, DATA's pi3, so that a host whose memory
// cannot hold that proof records nothing and only queues (plan-SMTP-small-readings #19).

// The index a measuring part takes: any later DATA part's, all of which share a shape.
const measurePartIndex = 4

// One line of the filler a measuring part carries. Its content does not change the cost.
const measureLine = "a line of DATA text as a later part carries it, whole and ending CRLF\r\n"

// What a Prover's last Measure found, which overrides its settings' DATA limits.
type proverMeasured struct {
	measure       *sidecar.SmtpProverMeasure
	dataPartBytes int
}

// Measure of sidecar.SmtpProver. It proves a part of each suite's largest shape, then a later DATA
// part, per suite with keys, which takes seconds to minutes, so a host runs it at idle and when its
// keys or hardware change. With no keys at all it fails, and the settings' limits stand. A proof that
// fails ends it with no result; one the host has no memory for ends the process, and so leaves none.
func (self *Prover) Measure(ctx context.Context) (*sidecar.SmtpProverMeasure, error) {
	for _, shape := range measureLargestShapes() {
		statement, witness, err := newMeasureMessagePart(shape)
		if err != nil {
			return nil, err
		}
		if failures := relationCheckPart(statement, witness); 0 < len(failures) {
			return nil, failures[0]
		}
		// a suite with no keys sends nothing, so its largest shape is no bar
		if _, err := self.backend.provePart(ctx, statement, witness); err != nil && !errors.Is(err, errNoKeys) {
			return nil, err
		}
	}
	var slowest time.Duration
	capacity := 0
	measured := false
	for _, shape := range partShapes() {
		// a shape over a late ticket proves only the rare part that covers one, so it sets no cap
		if shape.kind != partKindBody || 0 < shape.serverBlocks {
			continue
		}
		statement, witness, err := newMeasurePart(shape)
		if err != nil {
			return nil, err
		}
		if failures := relationCheckPart(statement, witness); 0 < len(failures) {
			return nil, failures[0]
		}
		start := self.now()
		_, err = self.backend.provePart(ctx, statement, witness)
		elapsed := self.now().Sub(start)
		if errors.Is(err, errNoKeys) {
			continue
		}
		if err != nil {
			return nil, err
		}
		// what one record of this shape can carry, which a part costs the same however much it uses
		contentBytes := shape.bodyBlocks * shape.blockBytes()
		if shape.version == tlsVersion13 {
			contentBytes -= tlsInnerTypeBytes
		}
		if !measured || slowest < elapsed {
			slowest = elapsed
		}
		if !measured || contentBytes < capacity {
			capacity = contentBytes
		}
		measured = true
	}
	if !measured {
		return nil, errNoKeys
	}

	// a part must prove inside the MX's timeout, or this host sends nothing in DATA mode
	slowest = max(slowest, time.Millisecond)
	bytesPerSecond := uint64(float64(capacity) / slowest.Seconds())
	result := &sidecar.SmtpProverMeasure{
		DataBytesPerSecond: bytesPerSecond,
		MeasureTime:        self.now(),
	}
	dataPartBytes := 0
	if slowest <= self.settings.DataPartTime {
		dataPartBytes = capacity
		result.DataProofBytes = uint64(float64(bytesPerSecond) * self.settings.DataConnectionTime.Seconds())
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.measured = &proverMeasured{measure: result, dataPartBytes: dataPartBytes}
	}()
	return result, nil
}

// The settings a send runs under: the Prover's own, with the last Measure's limits over them.
func (self *Prover) sendSettings() *ProverSettings {
	settings := *self.settings
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.measured != nil {
		settings.DataProofBytes = int(min(self.measured.measure.DataProofBytes, uint64(1<<31-1)))
		settings.DataPartBytes = self.measured.dataPartBytes
	}
	return &settings
}

func (self *Prover) now() time.Time {
	if self.clock != nil {
		return self.clock()
	}
	return time.Now()
}

// Each suite's largest shape: the one with the most keystream blocks, which with Z1 is what a part's
// cost and memory grow with. For every suite that is DATA's pi3, whose header and body blocks both
// count (SPEC.md 11.4).
func measureLargestShapes() []*partShape {
	var largest []*partShape
	blocks := func(shape *partShape) int {
		return shape.clientBlocks + shape.serverBlocks + shape.headerBlocks + shape.bodyBlocks
	}
	for _, shape := range partShapes() {
		at := slices.IndexFunc(largest, func(other *partShape) bool { return other.suite == shape.suite })
		switch {
		case at < 0:
			largest = append(largest, shape)
		case blocks(largest[at]) < blocks(shape):
			largest[at] = shape
		}
	}
	return largest
}

// A session no MX took part in, under a shape's version and suite: its secrets are fresh, honest for
// the relation, and protect nothing.
func newMeasureSession(shape *partShape, preamble *sessionPreamble) (*sessionStatement, *partWitness, error) {
	random := func(size int) []byte {
		value := make([]byte, size)
		rand.Read(value)
		return value
	}
	session := &sessionStatement{version: shape.version, suite: shape.suite, preamble: preamble}
	witness := &partWitness{}
	if shape.version == tlsVersion13 {
		witness.handshakeSecret = random(tlsSecretBytes)
		testHookSecret("measure_handshake_secret", witness.handshakeSecret)
		session.helloHash = random(sha256.Size)
		session.finishedHash = random(sha256.Size)
		shtsHash := sha256.Sum256(tls13TrafficSecret(witness.handshakeSecret, "s hs traffic", session.helloHash))
		session.shtsHash = shtsHash[:]
		masterSecret := tls13MasterSecret(witness.handshakeSecret)
		witness.clientKey, witness.clientIv = tls13TrafficKeys(shape.suite, tls13TrafficSecret(masterSecret, "c ap traffic", session.finishedHash))
		witness.serverKey, witness.serverIv = tls13TrafficKeys(shape.suite, tls13TrafficSecret(masterSecret, "s ap traffic", session.finishedHash))
	} else {
		witness.masterSecret = random(tlsMasterSecretBytes)
		testHookSecret("measure_master_secret", witness.masterSecret)
		session.clientRandom = random(tlsRandomBytes)
		session.serverRandom = random(tlsRandomBytes)
		state, err := newSha256State(random(3 * sha256.BlockSize / 2))
		if err != nil {
			return nil, nil, err
		}
		session.preFinishedState = state
		finishedHash, err := state.finish(nil)
		if err != nil {
			return nil, nil, err
		}
		resumedHash, err := state.finish(tls12FinishedMessage(witness.masterSecret, tlsLabelClientFinished, finishedHash))
		if err != nil {
			return nil, nil, err
		}
		block := tls12DeriveKeyBlock(witness.masterSecret, session.clientRandom, session.serverRandom)
		witness.clientKey, witness.clientIv = block.clientKey, block.clientSalt
		witness.serverKey, witness.serverIv = block.serverKey, block.serverSalt
		serverCipher, err := newTlsCipher(tlsVersion12, shape.suite, block.serverKey, block.serverSalt)
		if err != nil {
			return nil, nil, err
		}
		if session.serverFinishedRecord, err = serverCipher.seal(tlsRecordHandshake, tls12FinishedMessage(witness.masterSecret, tlsLabelServerFinished, resumedHash)); err != nil {
			return nil, nil, err
		}
	}
	testHookSecret("measure_client_key", witness.clientKey)
	testHookSecret("measure_client_iv", witness.clientIv)
	testHookSecret("measure_server_key", witness.serverKey)
	testHookSecret("measure_server_iv", witness.serverIv)
	return session, witness, nil
}

// Seals each content as an application record of one direction from seq on, returning the records
// and the plaintexts the relation reads, 1.3's type octet included.
func newMeasureRecords(shape *partShape, key []byte, iv []byte, seq uint64, contents ...string) ([]*partRecord, [][]byte, error) {
	sealer, err := newTlsCipher(shape.version, shape.suite, key, iv)
	if err != nil {
		return nil, nil, err
	}
	sealer.seq = seq
	var records []*partRecord
	var plaintexts [][]byte
	for _, content := range contents {
		record := &partRecord{seq: sealer.seq}
		if record.raw, err = sealer.seal(tlsRecordApplicationData, []byte(content)); err != nil {
			return nil, nil, err
		}
		plaintext := []byte(content)
		if shape.version == tlsVersion13 {
			plaintext = append(plaintext, tlsRecordApplicationData)
		}
		records = append(records, record)
		plaintexts = append(plaintexts, plaintext)
	}
	return records, plaintexts, nil
}

// A later DATA part filling a shape, over a session made up for it.
func newMeasurePart(shape *partShape) (*partStatement, *partWitness, error) {
	content := strings.Repeat(measureLine, shape.bodyBlocks*shape.blockBytes()/len(measureLine))
	session, witness, err := newMeasureSession(shape, &sessionPreamble{recipientCount: 1, messageByteCount: uint64(len(content))})
	if err != nil {
		return nil, nil, err
	}
	firstRecord := uint64(measurePartIndex)
	records, plaintexts, err := newMeasureRecords(shape, witness.clientKey, witness.clientIv, firstRecord, content)
	if err != nil {
		return nil, nil, err
	}
	witness.clientPlaintexts = plaintexts
	statement := &partStatement{
		session:       session,
		index:         measurePartIndex,
		mode:          partModeData,
		firstRecord:   firstRecord,
		lastRecord:    firstRecord,
		clientRecords: records,
	}
	return statement, witness, nil
}

// The values a measuring session declares, of the forms SPEC.md section 6 requires, which its header
// block repeats. They name no real network or sender.
const (
	measureDomain    = "measure.example"
	measureSelector  = "m1"
	measureMessageId = "measure@" + measureDomain
)

// pi3 in DATA mode filling a shape: a header block of Z5's form, then a body record of whole lines,
// over the replies to MAIL, one RCPT and DATA in one server record, in a session made up for it.
func newMeasureMessagePart(shape *partShape) (*partStatement, *partWitness, error) {
	preamble := &sessionPreamble{
		recipientDomain:  measureDomain,
		recipientCount:   1,
		messageId:        measureMessageId,
		headerFromDomain: measureDomain,
		dkimSelector:     measureSelector,
		heloName:         measureDomain,
		envelopeDomain:   "b." + measureDomain,
		// each of the issued values' exact forms, its octets all zero
		xUrRef:     "1." + strings.Repeat("a", 34),
		feedbackId: "n:c:" + strings.Repeat("a", 26) + ":urnetwork",
	}
	headerBlock := literalFromPrefix + "<measure@" + measureDomain + ">" + literalCrlf +
		literalMessageIdPrefix + measureMessageId + ">" + literalCrlf +
		literalXUrRefPrefix + preamble.xUrRef + literalCrlf +
		literalFeedbackPrefix + preamble.feedbackId + literalCrlf +
		literalDkimPrefix + literalDkimDomain + measureDomain + literalDkimSelector + measureSelector + literalDkimEnd + "b=" + literalCrlf +
		literalCrlf
	// the body record fills the shape's body blocks, its inner type octet included
	bodyBytes := shape.bodyBlocks * shape.blockBytes()
	if shape.version == tlsVersion13 {
		bodyBytes -= tlsInnerTypeBytes
	}
	body := strings.Repeat(measureLine, bodyBytes/len(measureLine))
	preamble.messageByteCount = uint64(len(headerBlock) + len(body))
	session, witness, err := newMeasureSession(shape, preamble)
	if err != nil {
		return nil, nil, err
	}
	// as if pi1 had opened EHLO, pi2 MAIL, RCPT and DATA, and pi2 had covered the EHLO reply
	firstRecord := uint64(5)
	firstServer := uint64(0)
	if shape.version == tlsVersion12 {
		// the Finished records took sequence number 0
		firstRecord += 1
		firstServer += 1
	}
	clientRecords, clientPlaintexts, err := newMeasureRecords(shape, witness.clientKey, witness.clientIv, firstRecord, headerBlock, body)
	if err != nil {
		return nil, nil, err
	}
	serverRecords, serverPlaintexts, err := newMeasureRecords(shape, witness.serverKey, witness.serverIv, firstServer+1, "250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n354 Go ahead\r\n")
	if err != nil {
		return nil, nil, err
	}
	witness.clientPlaintexts = clientPlaintexts
	witness.serverPlaintexts = serverPlaintexts
	statement := &partStatement{
		session:                   session,
		index:                     3,
		mode:                      partModeData,
		firstRecord:               firstRecord,
		lastRecord:                firstRecord + 1,
		previousServerRecordCount: 1,
		serverRecordCount:         2,
		clientRecords:             clientRecords,
		serverRecords:             serverRecords,
	}
	return statement, witness, nil
}
