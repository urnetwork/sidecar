package smtpproof

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The host's own speed (D-SMTP-20; DESIGN-DETAILS 3.2.6, 3.2.8). Every catalog shape fills one 2^20 domain,
// a unit, so a unit of any shape stands for the rest: the host proves one body unit per ready family, a
// DATA body record that fills its shape, over a session made up for the purpose, and the family whose unit
// takes longest prices a send here, in units at its UnitTime, and sets smtp_data_proof_bytes and whether
// DATA is open to this host at all. A unit's proof needs a unit's memory, so a host whose budget cannot
// hold one fails here, records nothing and only queues (QD-483). The host records the result at p/
// (§15.7), and later sends use it.

// One line of the filler a measuring part carries. Its content does not change the cost.
const measureLine = "a line of DATA text as a later part carries it, whole and ending CRLF\r\n"

// The measurement and the ready catalog families it covered.
type proverMeasured struct {
	measure  sidecar.SmtpProverMeasure
	proof    *ProofSettings
	families []ShapeFamily
}

// Measure of sidecar.SmtpProver. It proves a body unit per ready family, which takes seconds to minutes,
// so a host runs it at idle and when its keys or hardware change. A host without a completed unit only queues.
func (self *Prover) Measure(ctx context.Context) (measure *sidecar.SmtpProverMeasure, err error) {
	proof, families := self.measureFamilies()
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if err == nil {
			self.measured = &proverMeasured{measure: *measure, proof: proof, families: families}
		} else if ctx.Err() == nil {
			// A failed unit closes local proving until a later measurement succeeds. Idle work interrupted
			// for an already admitted send retains the last successful measurement of the same families.
			self.measured = nil
		}
	}()
	var slowest time.Duration
	var slowestFamily ShapeFamily
	capacity := 0
	measured := false
	for _, family := range families {
		entry := proof.shape(ShapeKindBody, family, 0)
		if entry == nil {
			continue
		}
		statement, witness, err := newMeasurePart(proof, newPartShape(proof, entry))
		if err != nil {
			return nil, err
		}
		if failures := relationCheckPart(statement, witness); 0 < len(failures) {
			return nil, failures[0]
		}
		start := self.now()
		_, err = self.backend.provePart(ctx, statement, witness)
		elapsed := self.now().Sub(start)
		if self.keys == nil && errors.Is(err, errNoKeys) {
			// a family with no keys sends nothing, so its unit is no bar
			continue
		}
		if err != nil {
			return nil, err
		}
		// what one body record of this shape carries under 1.3, which a part costs the same however much it
		// uses
		contentBytes := entry.recordContentBytes(entry.BodyBlocks, tlsVersion13)
		if !measured || slowest < elapsed {
			slowest = elapsed
			slowestFamily = family
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
	unitTime := max(slowest, time.Millisecond)
	bytesPerSecond := uint64(float64(capacity) / unitTime.Seconds())
	result := &sidecar.SmtpProverMeasure{
		DataBytesPerSecond: bytesPerSecond,
		MeasureTime:        self.now(),
		UnitTime:           slowest,
	}
	if message := proof.shape(ShapeKindMessage, slowestFamily, 0); message != nil {
		result.HeadByteCount = uint64(message.recordContentBytes(message.HeadBlocks, tlsVersion13))
	}
	if header := proof.shape(ShapeKindHeader, slowestFamily, 0); header != nil {
		result.HeaderRecordByteCount = uint64(header.recordContentBytes(header.RestBlocks, tlsVersion13))
	}
	if envelope := proof.shape(ShapeKindEnvelope, slowestFamily, 0); envelope != nil {
		// a later group's commands, each a RCPT of the measuring session's form, under the first group's
		// estimate
		preamble := newMeasurePreamble(proof)
		commandByteCounts := make([]int, 0, proof.RecipientMaxCount)
		for i := range proof.RecipientMaxCount {
			command := literalRcptPrefix + "r" + strconv.Itoa(i) + "@" + preamble.recipientDomain + ">" + literalCrlf
			commandByteCounts = append(commandByteCounts, len(command))
		}
		result.EnvelopeGroupCount = uint64(envelopeGroupSize(envelope, tlsVersion13, commandByteCounts, self.settings.ReplyEstimateByteCount, self.settings.EnvelopeGroupMaxCount))
	}
	if slowest <= self.settings.DataPartTime {
		result.DataProofBytes = uint64(float64(bytesPerSecond) * self.settings.DataConnectionTime.Seconds())
	}
	return result, nil
}

// The catalog a Measure proves under and the families it measures: with keys, the newest pinned set's,
// and its ready families; with a test's backend and no keys, the settings' catalog and every family in it.
func (self *Prover) measureFamilies() (*ProofSettings, []ShapeFamily) {
	if self.keys == nil {
		var families []ShapeFamily
		for _, entry := range self.settings.Proof.Shapes {
			if !slices.Contains(families, entry.Family) {
				families = append(families, entry.Family)
			}
		}
		return self.settings.Proof, families
	}
	keySet := self.keys.current()
	if keySet == nil {
		return self.settings.Proof, nil
	}
	var families []ShapeFamily
	for _, entry := range keySet.proof.Shapes {
		if slices.Contains(families, entry.Family) {
			continue
		}
		if ready, _ := keySet.familyReady(entry.Family); ready {
			families = append(families, entry.Family)
		}
	}
	return keySet.proof, families
}

// A send uses the current ready families' measurement. A measured zero admits BDAT only.
func (self *Prover) sendSettings() *ProverSettings {
	proof, families := self.measureFamilies()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	m := self.measured
	if m == nil || self.keys != nil && (m.proof != proof || !slices.Equal(m.families, families)) {
		return nil
	}
	settings := *self.settings
	settings.DataProofBytes = int(min(m.measure.DataProofBytes, uint64(math.MaxInt)))
	if self.keys != nil {
		settings.SuiteOrder = slices.DeleteFunc(slices.Clone(settings.SuiteOrder), func(suite uint16) bool {
			return !slices.Contains(m.families, suiteFamily(suite))
		})
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
// session made up for it: the made-up connection's fourth part, after its key part, one env part (MAIL,
// one RCPT and DATA, over the EHLO reply) and its msg part (header record 1, over the three replies).
func newMeasurePart(proof *ProofSettings, shape *partShape) (*partStatement, *partWitness, error) {
	content := strings.Repeat(measureLine, (shape.bodyBlocks*shape.blockBytes()-tlsInnerTypeBytes)/len(measureLine))
	preamble := newMeasurePreamble(proof)
	preamble.messageByteCount = uint64(len(content))
	session, witness, err := newMeasureSession(tlsVersion13, measureSuite(shape.family), preamble)
	if err != nil {
		return nil, nil, err
	}
	// EHLO, MAIL, the RCPT, DATA and the header block's one record came before
	headerRecordCount := uint32(1)
	firstRecord := firstApplicationSeq(tlsVersion13) + 3 + uint64(preamble.recipientCount) + uint64(headerRecordCount)
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
		index:             4,
		mode:              partModeData,
		firstRecord:       firstRecord,
		lastRecord:        firstRecord,
		repliesProven:     3 + preamble.recipientCount,
		headerRecordCount: headerRecordCount,
		carryIn:           in.commitment,
		carryOut:          out.commitment,
		clientRecords:     records,
	}
	return statement, witness, nil
}
