package smtpproof

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The host's own DATA speed (D-SMTP-20). A body part's circuit is fixed, so proving one costs the same
// whatever it carries: the host proves one full body record per family it holds keys for, over a session
// made up for the purpose, and the slowest family sets smtp_data_proof_bytes and whether DATA is open to
// this host at all. The host records the result at p/ (§15.7), and later sends use it. Before any of that
// it proves one msg part of each family, so that a host whose memory cannot hold a unit's proof records
// nothing and only queues (plan-SMTP-small-readings #19). Every catalog shape fills one domain, so any
// shape stands for the rest (DESIGN-DETAILS 3.2.6); measuring by unit is SMTP-M9-39's.

// The index a measuring body part takes: any part past the message's first.
const measurePartIndex = 5

// One line of the filler a measuring part carries. Its content does not change the cost.
const measureLine = "a line of DATA text as a later part carries it, whole and ending CRLF\r\n"

// What a Prover's last Measure found, which overrides its settings' DATA limits.
type proverMeasured struct {
	measure       *sidecar.SmtpProverMeasure
	dataPartBytes int
}

// Measure of sidecar.SmtpProver. It proves a msg part, then a body part, per family with keys, which
// takes seconds to minutes, so a host runs it at idle and when its keys or hardware change. With no keys
// at all it fails, and the settings' limits stand. A proof that fails ends it with no result; one the host
// has no memory for ends the process, and so leaves none.
func (self *Prover) Measure(ctx context.Context) (*sidecar.SmtpProverMeasure, error) {
	proof := self.settings.Proof
	for _, shape := range partShapes(proof) {
		if shape.kind != partKindMessage {
			continue
		}
		statement, witness, err := newMeasureMessagePart(proof, shape)
		if err != nil {
			return nil, err
		}
		if failures := relationCheckPart(statement, witness); 0 < len(failures) {
			return nil, failures[0]
		}
		// a family with no keys sends nothing, so its shape is no bar
		if _, err := self.backend.provePart(ctx, statement, witness); err != nil && !errors.Is(err, errNoKeys) {
			return nil, err
		}
	}
	var slowest time.Duration
	capacity := 0
	measured := false
	for _, shape := range partShapes(proof) {
		if shape.kind != partKindBody {
			continue
		}
		statement, witness, err := newMeasurePart(proof, shape)
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
		// what one body record of this shape carries under 1.3, which a part costs the same however much
		// it uses
		contentBytes := shape.bodyBlocks*shape.blockBytes() - tlsInnerTypeBytes
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

// The TLS 1.3 suite a family's measuring session runs under: the family's circuits serve 1.2 alike.
func measureSuite(family ShapeFamily) uint16 {
	if family == ShapeFamilyChacha20 {
		return tlsSuiteChacha20Poly1305Sha256
	}
	return tlsSuiteAes128GcmSha256
}

// A session no MX took part in, under a version and suite: its secrets are fresh, honest for the
// relation, and protect nothing.
func newMeasureSession(version uint16, suite uint16, preamble *sessionPreamble) (*sessionStatement, *partWitness, error) {
	random := func(size int) []byte {
		value := make([]byte, size)
		rand.Read(value)
		return value
	}
	session := &sessionStatement{version: version, suite: suite, preamble: preamble}
	witness := &partWitness{}
	if version == tlsVersion13 {
		witness.handshakeSecret = random(tlsSecretBytes)
		testHookSecret("measure_handshake_secret", witness.handshakeSecret)
		session.helloHash = random(sha256.Size)
		session.finishedHash = random(sha256.Size)
		shtsHash := sha256.Sum256(tls13TrafficSecret(witness.handshakeSecret, "s hs traffic", session.helloHash))
		session.shtsHash = shtsHash[:]
		masterSecret := tls13MasterSecret(witness.handshakeSecret)
		witness.clientKey, witness.clientIv = tls13TrafficKeys(suite, tls13TrafficSecret(masterSecret, "c ap traffic", session.finishedHash))
		witness.serverKey, witness.serverIv = tls13TrafficKeys(suite, tls13TrafficSecret(masterSecret, "s ap traffic", session.finishedHash))
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
		serverCipher, err := newTlsCipher(tlsVersion12, suite, block.serverKey, block.serverSalt)
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
	blind, err := newCommitBlind("measure_key_blind")
	if err != nil {
		return nil, nil, err
	}
	witness.keyBlind = blind
	return session, witness, nil
}

// The C a made-up session's key part would publish, which its later parts open.
func newMeasureKeyCommitment(witness *partWitness) ([]byte, error) {
	commitment, err := commitKeys(witness.clientKey, witness.clientIv, witness.serverKey, witness.serverIv, witness.keyBlind)
	if err != nil {
		return nil, err
	}
	return encodeCommitment(commitment), nil
}

// Seals each content as an application record of one direction from seq on, returning the records
// and the plaintexts the relation reads, 1.3's type octet included.
func newMeasureRecords(session *sessionStatement, key []byte, iv []byte, seq uint64, contents ...string) ([]*partRecord, [][]byte, error) {
	sealer, err := newTlsCipher(session.version, session.suite, key, iv)
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
		if session.version == tlsVersion13 {
			plaintext = append(plaintext, tlsRecordApplicationData)
		}
		records = append(records, record)
		plaintexts = append(plaintexts, plaintext)
	}
	return records, plaintexts, nil
}

// The values a measuring session declares, of the forms SPEC.md section 6 requires, which its header
// block repeats. They name no real network or sender.
const (
	measureDomain    = "measure.example"
	measureSelector  = "m1"
	measureMessageId = "measure@" + measureDomain
)

// A measuring session's preamble: one recipient, and each of the issued values' exact forms.
func newMeasurePreamble(proof *ProofSettings) *sessionPreamble {
	return &sessionPreamble{
		proof:            proof,
		recipientDomain:  measureDomain,
		recipientCount:   1,
		messageId:        measureMessageId,
		headerFromDomain: measureDomain,
		dkimSelector:     measureSelector,
		heloName:         measureDomain,
		envelopeDomain:   "b." + measureDomain,
		xUrRef:           "1." + strings.Repeat("a", 34),
		feedbackId:       "n:c:" + strings.Repeat("a", 26) + ":urnetwork",
	}
}

// A body part filling a body shape, one record of whole lines after a one-record header block, over a
// session made up for it.
func newMeasurePart(proof *ProofSettings, shape *partShape) (*partStatement, *partWitness, error) {
	content := strings.Repeat(measureLine, (shape.bodyBlocks*shape.blockBytes()-tlsInnerTypeBytes)/len(measureLine))
	preamble := newMeasurePreamble(proof)
	preamble.messageByteCount = uint64(len(content))
	session, witness, err := newMeasureSession(tlsVersion13, measureSuite(shape.family), preamble)
	if err != nil {
		return nil, nil, err
	}
	// EHLO, MAIL, RCPT, DATA and the header block's one record came before
	firstRecord := uint64(measurePartIndex)
	records, plaintexts, err := newMeasureRecords(session, witness.clientKey, witness.clientIv, firstRecord, content)
	if err != nil {
		return nil, nil, err
	}
	witness.clientPlaintexts = plaintexts
	keyCommitment, err := newMeasureKeyCommitment(witness)
	if err != nil {
		return nil, nil, err
	}
	in := proverStartCarry()
	state, err := scanBodyRecord([]byte(content), in.state, false)
	if err != nil {
		return nil, nil, err
	}
	out, err := newProverCarry(state)
	if err != nil {
		return nil, nil, err
	}
	witness.carryInState = in.state
	witness.carryInBlind = in.blind
	witness.carryOutBlind = out.blind
	statement := &partStatement{
		session:           session,
		keyCommitment:     keyCommitment,
		index:             measurePartIndex,
		mode:              partModeData,
		firstRecord:       firstRecord,
		lastRecord:        firstRecord,
		repliesProven:     4,
		headerRecordCount: 1,
		carryIn:           in.commitment,
		carryOut:          out.commitment,
		clientRecords:     records,
	}
	return statement, witness, nil
}

// The msg part in DATA mode: a header block of Z5's form in one record, over the replies to MAIL, one
// RCPT and DATA in one server record, in a session made up for it.
func newMeasureMessagePart(proof *ProofSettings, shape *partShape) (*partStatement, *partWitness, error) {
	preamble := newMeasurePreamble(proof)
	headerBlock := literalFromPrefix + "<measure@" + measureDomain + ">" + literalCrlf +
		literalMessageIdPrefix + measureMessageId + ">" + literalCrlf +
		literalXUrRefPrefix + preamble.xUrRef + literalCrlf +
		literalFeedbackPrefix + preamble.feedbackId + literalCrlf +
		literalDkimPrefix + literalDkimDomain + measureDomain + literalDkimSelector + measureSelector + literalDkimEnd + "b=" + literalCrlf +
		literalCrlf
	preamble.messageByteCount = uint64(len(headerBlock))
	session, witness, err := newMeasureSession(tlsVersion13, measureSuite(shape.family), preamble)
	if err != nil {
		return nil, nil, err
	}
	// as if part 1 had opened EHLO and part 2 MAIL, RCPT and DATA over the EHLO reply
	firstRecord := uint64(4)
	clientRecords, clientPlaintexts, err := newMeasureRecords(session, witness.clientKey, witness.clientIv, firstRecord, headerBlock)
	if err != nil {
		return nil, nil, err
	}
	serverRecords, serverPlaintexts, err := newMeasureRecords(session, witness.serverKey, witness.serverIv, 1, "250 2.1.0 Ok\r\n250 2.1.5 Ok\r\n354 Go ahead\r\n")
	if err != nil {
		return nil, nil, err
	}
	witness.clientPlaintexts = clientPlaintexts
	witness.serverPlaintexts = serverPlaintexts
	keyCommitment, err := newMeasureKeyCommitment(witness)
	if err != nil {
		return nil, nil, err
	}
	state, err := scanHeaderRecord(preamble, []byte(headerBlock), scanStart, true, true)
	if err != nil {
		return nil, nil, err
	}
	out, err := newProverCarry(state)
	if err != nil {
		return nil, nil, err
	}
	witness.carryOutBlind = out.blind
	statement := &partStatement{
		session:                   session,
		keyCommitment:             keyCommitment,
		index:                     3,
		mode:                      partModeData,
		firstRecord:               firstRecord,
		lastRecord:                firstRecord,
		previousServerRecordCount: 1,
		serverRecordCount:         2,
		replyCount:                3,
		repliesProven:             1,
		headerRecordCount:         1,
		carryOut:                  out.commitment,
		clientRecords:             clientRecords,
		serverRecords:             serverRecords,
	}
	return statement, witness, nil
}
