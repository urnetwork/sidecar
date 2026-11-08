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

// The host's own DATA speed (D-SMTP-20). A later DATA part's circuit is fixed, so proving one costs the
// same whatever it carries: the host proves one full part per suite it holds keys for, over a session
// made up for the purpose, and the slowest suite sets smtp_data_proof_bytes and whether DATA is open
// to this host at all. The host records the result at p/ (§15.7), and later sends use it.

// The index a measuring part takes: any later DATA part's, all of which share a shape.
const measurePartIndex = 4

// One line of the filler a measuring part carries. Its content does not change the cost.
const measureLine = "a line of DATA text as a later part carries it, whole and ending CRLF\r\n"

// What a Prover's last Measure found, which overrides its settings' DATA limits.
type proverMeasured struct {
	measure       *sidecar.SmtpProverMeasure
	dataPartBytes int
}

// Measure of sidecar.SmtpProver. It proves one part per suite with keys, which takes seconds to
// minutes, so a host runs it at idle and when its keys or hardware change. With no keys at all it
// fails, and the settings' limits stand.
func (self *Prover) Measure(ctx context.Context) (*sidecar.SmtpProverMeasure, error) {
	var slowest time.Duration
	capacity := 0
	measured := false
	for _, shape := range partShapes() {
		if shape.kind != partKindBody {
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

// A later DATA part filling a shape, over a session no MX took part in: its secrets are fresh, honest
// for the relation, and protect nothing.
func newMeasurePart(shape *partShape) (*partStatement, *partWitness, error) {
	random := func(size int) []byte {
		value := make([]byte, size)
		rand.Read(value)
		return value
	}
	content := strings.Repeat(measureLine, shape.bodyBlocks*shape.blockBytes()/len(measureLine))
	preamble := &sessionPreamble{recipientCount: 1, messageByteCount: uint64(len(content))}
	session := &sessionStatement{version: shape.version, suite: shape.suite, preamble: preamble}
	witness := &partWitness{}
	firstRecord := uint64(measurePartIndex)
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
	clientCipher, err := newTlsCipher(shape.version, shape.suite, witness.clientKey, witness.clientIv)
	if err != nil {
		return nil, nil, err
	}
	clientCipher.seq = firstRecord
	raw, err := clientCipher.seal(tlsRecordApplicationData, []byte(content))
	if err != nil {
		return nil, nil, err
	}
	plaintext := []byte(content)
	if shape.version == tlsVersion13 {
		plaintext = append(plaintext, tlsRecordApplicationData)
	}
	witness.clientPlaintexts = [][]byte{plaintext}
	statement := &partStatement{
		session:       session,
		index:         measurePartIndex,
		mode:          partModeData,
		firstRecord:   firstRecord,
		lastRecord:    firstRecord,
		clientRecords: []*partRecord{{seq: firstRecord, raw: raw}},
	}
	return statement, witness, nil
}
