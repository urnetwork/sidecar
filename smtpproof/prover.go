package smtpproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// The prover: runs one connection through the TLS client, in the shape SPEC.md section 4 fixes, and
// proves each part before its records are sent. It holds every key and all plaintext of the
// connection, so it runs only on the sending device, and it logs nothing.
//
// Before proving anything it checks its own witness against the reference relation. A send that
// cannot satisfy the relation stops here, with no effect at the MX.

// Turns a satisfied statement into a proof. The real one refuses a part with no circuit behind it.
type partProver interface {
	provePart(ctx context.Context, statement *partStatement, witness *partWitness) ([]byte, error)
}

// How a Prover behaves. Start from DefaultProverSettings.
type ProverSettings struct {
	// The proofs' catalog and limits, which the verifier's must equal (DESIGN-DETAILS 3.2.8).
	Proof *ProofSettings
	// Largest content of one client record. The protocol's limit is 16 KiB.
	MaxRecordContentBytes int
	// DATA octets proven per part at most: a body record is cut at this or at what the family's body
	// shape holds, whichever is less. A part's circuit is fixed, so it costs the same however much it
	// carries: Measure sets this to a whole body record, or 0 when a part cannot prove within
	// DataPartTime. Until a Measure, this default stands.
	DataPartBytes int
	// smtp_data_proof_bytes: a larger message to an MX without CHUNKING is too_large before MAIL
	// (§14.5). Measure replaces this unmeasured default with the host's own figure. Non-positive refuses
	// every DATA send.
	DataProofBytes int
	// How long one DATA part may take to prove: §14.5's 2 minutes, inside the MX's 5-minute timeout. A
	// host whose part takes longer sends nothing in DATA mode.
	DataPartTime time.Duration
	// How long a DATA connection proves for: §14.4's 2 h. With the measured rate it gives
	// smtp_data_proof_bytes.
	DataConnectionTime time.Duration
	// Server octets held for parts to cover, as VerifierSettings.MaxServerBytes. A reply that never ends
	// stops here rather than growing what this send holds.
	MaxServerBytes int
	// Sends in DATA mode even where the MX offers CHUNKING, as D-SMTP-16's interop runs do.
	ForceData bool
}

func DefaultProverSettings() *ProverSettings {
	return &ProverSettings{
		Proof:                 DefaultProofSettings(),
		MaxRecordContentBytes: 16 * 1024,
		DataPartBytes:         16 * 1024,
		DataProofBytes:        1024 * 1024,
		DataPartTime:          2 * time.Minute,
		DataConnectionTime:    2 * time.Hour,
		MaxServerBytes:        256 * 1024,
	}
}

// Implements sidecar.SmtpProver. Safe for concurrent use: all state is per send, except the last
// Measure's limits under stateLock.
type Prover struct {
	settings *ProverSettings
	backend  partProver
	// The suites offered, or nil for the client's default. Tests pin one to cover each.
	tlsSuites []uint16
	// Measure's clock, or nil for the wall clock. Tests give a fake one.
	clock func() time.Time

	stateLock sync.Mutex
	measured  *proverMeasured
}

// A server record as the prover keeps it: its public form, and its plaintext for the witness.
type proverServerRecord struct {
	public    *partRecord
	plaintext []byte
}

// What one send holds. Not safe for concurrent use, except that the reader goroutine owns serverIn.
type proverRun struct {
	settings *ProverSettings
	backend  partProver
	job      *sidecar.SmtpProofJob
	channel  sidecar.SmtpProofChannel
	client   *tlsClient
	result   *tlsHandshakeResult
	preamble *sessionPreamble
	session  *sessionStatement
	// rho, drawn once for the connection, and C, the commitment to both directions' keys under it that
	// part 1 publishes and every later part opens (DESIGN-DETAILS 3.2.2).
	keyBlind      *big.Int
	keyCommitment []byte

	serverIn chan *proverServerEvent
	records  []*proverServerRecord
	// Octets of records, against settings.MaxServerBytes.
	serverBytes int
	stream      []byte
	// What the gate holds of this connection's parts, which each next part's statement takes
	// (DESIGN-DETAILS 3.2.5): the next part's index, the next client record a part opens, the server
	// records covered, the replies proven, the mode and k.
	nextPart          uint32
	nextRecord        uint64
	covered           uint64
	repliesProven     uint32
	mode              uint32
	headerRecordCount uint32
	// Whether the message's first part was proven, after which a late server record is covered by a part
	// of its own, since the message's parts hold none.
	messageStarted bool
}

// A record from the reader goroutine, or how it ended.
type proverServerEvent struct {
	record *tlsServerRecord
	err    error
}

// The declared values of a job, in the relation's form, checked against proof.
func newSessionPreamble(preamble *sidecar.SmtpProofPreamble, proof *ProofSettings) *sessionPreamble {
	return &sessionPreamble{
		proof:            proof,
		recipientDomain:  preamble.RecipientDomain,
		recipientCount:   preamble.RecipientCount,
		messageId:        preamble.MessageId,
		headerFromDomain: preamble.HeaderFromDomain,
		dkimSelector:     preamble.DkimSelector,
		messageByteCount: preamble.MessageByteCount,
		flags:            preamble.Flags,
		heloName:         preamble.HeloName,
		xUrRef:           preamble.XUrRef,
		feedbackId:       preamble.FeedbackId,
		envelopeDomain:   preamble.EnvelopeDomain,
	}
}

// Z1's public inputs from the prover's side, which must equal what the edge computes.
func newProverSessionStatement(result *tlsHandshakeResult, preamble *sessionPreamble) (*sessionStatement, error) {
	session := &sessionStatement{version: result.version, suite: result.suite, preamble: preamble}
	if result.version == tlsVersion13 {
		shtsHash := sha256.Sum256(result.shts)
		session.shtsHash = shtsHash[:]
		session.helloHash = result.helloHash
		session.finishedHash = result.finishedHash
		return session, nil
	}
	state, err := newSha256State(result.preFinishedMessages)
	if err != nil {
		return nil, err
	}
	session.clientRandom = result.clientRandom
	session.serverRandom = result.serverRandom
	session.preFinishedState = state
	session.serverFinishedRecord = result.serverFinishedRecord
	return session, nil
}

// KeySet of sidecar.SmtpProver. Until key sets of version 2 and their pins exist (SMTP-M9-40) this
// prover is pinned to none, so it names none and a host with it only queues (D-SMTP-18).
func (self *Prover) KeySet() []byte {
	return nil
}

// PrepareKeys of sidecar.SmtpProver. With no pinned key set of version 2 (SMTP-M9-40) there is nothing to
// check: nothing is ready, and nothing is left to do until a release pins a set.
func (self *Prover) PrepareKeys(ctx context.Context) (*sidecar.SmtpProverReadiness, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &sidecar.SmtpProverReadiness{Done: true}, nil
}

// SendSmtp of sidecar.SmtpProver.
func (self *Prover) SendSmtp(ctx context.Context, conn net.Conn, job *sidecar.SmtpProofJob, channel sidecar.SmtpProofChannel) (*sidecar.SmtpProofResult, error) {
	// a set this prover cannot prove under is refused before any octet goes out; until SMTP-M9-40 that is
	// every named set, and a job naming none proves as before
	if len(job.KeySet) != 0 {
		return nil, sidecar.ErrSmtpProofKeySet
	}
	if job.Preamble == nil || uint32(len(job.RecipientLocals)) != job.Preamble.RecipientCount || len(job.RecipientLocals) == 0 {
		return nil, errors.New("smtpproof: job's recipients do not match its preamble")
	}
	// the edge refuses the same, so nothing here should reach it
	if err := checkSessionPreamble(newSessionPreamble(job.Preamble, self.settings.Proof)); err != nil {
		return nil, fmt.Errorf("smtpproof: %w", err)
	}
	declared := job.Preamble.MessageByteCount
	if declared != uint64(len(job.Message)) && declared != uint64(len(dotStuffed(job.Message))) {
		return nil, errors.New("smtpproof: job's message does not match its declared octet count")
	}
	settings := defaultTlsClientSettings()
	settings.serverName = job.Preamble.MxHost
	settings.verifyPeer = job.VerifyPeer
	if self.tlsSuites != nil {
		settings.suites = self.tlsSuites
	}
	run := &proverRun{
		settings: self.sendSettings(),
		backend:  self.backend,
		job:      job,
		channel:  channel,
		client:   newTlsClient(conn, settings),
		preamble: newSessionPreamble(job.Preamble, self.settings.Proof),
		serverIn: make(chan *proverServerEvent),
		nextPart: 1,
	}
	return run.run(ctx)
}

func (self *proverRun) run(ctx context.Context) (*sidecar.SmtpProofResult, error) {
	result, err := self.client.handshake(ctx)
	if err != nil {
		return nil, err
	}
	self.result = result
	if self.session, err = newProverSessionStatement(result, self.preamble); err != nil {
		return nil, err
	}
	if self.keyBlind, err = newCommitBlind("smtp_key_blind"); err != nil {
		return nil, err
	}
	commitment, err := commitKeys(result.clientKey, result.clientIv, result.serverKey, result.serverIv, self.keyBlind)
	if err != nil {
		return nil, err
	}
	self.keyCommitment = encodeCommitment(commitment)
	if result.version == tlsVersion13 {
		if err := self.channel.DiscloseShts(ctx, result.shts); err != nil {
			return nil, err
		}
	}
	// the one reader of the connection: it ends when the connection or ctx does
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		for {
			record, err := self.client.readRecord(runCtx)
			select {
			case self.serverIn <- &proverServerEvent{record: record, err: err}:
			case <-runCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	// the key part: EHLO, which the gate takes as the first application record
	ehloCommand := literalEhloPrefix + self.preamble.heloName + literalCrlf
	ehlo, err := self.seal([]byte(ehloCommand))
	if err != nil {
		return nil, err
	}
	self.nextRecord = ehlo.seq
	if err := self.prove(ctx, &proverPart{sealed: []*tlsSealedRecord{ehlo}, plaintexts: [][]byte{self.opened(ehlo, ehloCommand)}}); err != nil {
		return nil, err
	}
	if err := self.client.writeSealed(ehlo); err != nil {
		return nil, err
	}
	replies, err := self.awaitReplies(ctx, 1)
	if err != nil {
		return nil, err
	}
	if replies[0].code != "250" {
		return &sidecar.SmtpProofResult{RefusedCode: replies[0].code}, nil
	}

	// the mode is what Z9 can prove, which is the keyword inside one record, and not merely what the
	// reply says: an MX whose line spans two records gets DATA (SPEC.md reading 17)
	mode := partModeData
	received := make([][]byte, 0, len(self.records))
	for _, record := range self.records {
		received = append(received, record.plaintext)
	}
	if offersChunking(self.result.version, received) && !self.settings.ForceData {
		mode = partModeBdat
	}
	pipelining := false
	for i, text := range replies[0].lines {
		if 0 < i && asciiLower([]byte(text)) == "pipelining" {
			pipelining = true
		}
	}
	// the count was declared before the mode was known, for the mode the sidecar expected
	// (plan-SMTP-preamble-byte-count). BDAT's n is the message's length and DATA's count its stuffed
	// length, which differ when a line starts with a dot. The mode is chosen above and never by the
	// count: where it cannot meet the count, nothing goes past EHLO and a new connection declares this
	// mode's. So an MX offering CHUNKING gets BDAT unless DATA is forced for interop, and too_large means
	// DATA was the only mode
	stuffed := dotStuffed(self.job.Message)
	count := uint64(len(self.job.Message))
	if mode == partModeData {
		count = uint64(len(stuffed))
		// a host whose part cannot prove within its time has no DATA part size, and sends no DATA
		if self.settings.DataPartBytes <= 0 || uint64(max(self.settings.DataProofBytes, 0)) < count {
			return &sidecar.SmtpProofResult{Mode: mode, TooLarge: true}, nil
		}
	}
	if self.preamble.messageByteCount != count {
		return &sidecar.SmtpProofResult{Mode: mode, ReconnectByteCount: count}, nil
	}
	self.mode = mode

	// part 2, an env part: the EHLO reply, and the envelope's commands. SMTP-M9-39's planner sends them
	// in groups; until then one group holds the envelope, and an envelope no env shape holds is refused
	// here, before MAIL, as one no landed shape held was
	mailSuffix := "@" + self.preamble.envelopeDomain + ">"
	if self.preamble.flags&preambleFlagRequireTls != 0 {
		mailSuffix += literalRequireTls
	}
	commands := []string{literalMailPrefix + self.job.SenderLocal + mailSuffix + literalCrlf}
	for _, local := range self.job.RecipientLocals {
		commands = append(commands, literalRcptPrefix+local+"@"+self.preamble.recipientDomain+">"+literalCrlf)
	}
	if mode == partModeData {
		commands = append(commands, literalData)
	}
	envelope := &proverPart{replyCount: 1}
	for _, command := range commands {
		record, err := self.seal([]byte(command))
		if err != nil {
			return nil, err
		}
		envelope.sealed = append(envelope.sealed, record)
		envelope.plaintexts = append(envelope.plaintexts, self.opened(record, command))
	}
	if err := self.prove(ctx, envelope); err != nil {
		return nil, err
	}
	// without PIPELINING each command waits for the last one's reply, still under this part (14.4)
	var answers []*smtpReply
	for i, record := range envelope.sealed {
		if err := self.client.writeSealed(record); err != nil {
			return nil, err
		}
		if !pipelining {
			replies, err := self.awaitReplies(ctx, 1)
			if err != nil {
				return nil, err
			}
			answers = append(answers, replies...)
			if smtpReplyRefuses(replies[0], mode == partModeData && i == len(envelope.sealed)-1) {
				return &sidecar.SmtpProofResult{Mode: mode, RefusedCode: replies[0].code}, nil
			}
		}
	}
	if pipelining {
		if answers, err = self.awaitReplies(ctx, len(envelope.sealed)); err != nil {
			return nil, err
		}
		for i, reply := range answers {
			if smtpReplyRefuses(reply, mode == partModeData && i == len(envelope.sealed)-1) {
				return &sidecar.SmtpProofResult{Mode: mode, RefusedCode: reply.code}, nil
			}
		}
	}

	headerEnd := bytes.Index(self.job.Message, []byte(literalCrlf+literalCrlf))
	if headerEnd < 0 {
		return nil, errors.New("smtpproof: message has no header block")
	}
	headerEnd += 2 * len(literalCrlf)
	headerBlock := self.job.Message[:headerEnd]
	// the envelope's replies the message's first part covers: MAIL's, each RCPT's, and DATA's 354
	envelopeReplies := uint32(len(commands))
	if mode == partModeBdat {
		return self.sendBdat(ctx, headerBlock, self.job.Message[headerEnd:], envelopeReplies)
	}
	return self.sendData(ctx, headerBlock, stuffed[headerEnd:], envelopeReplies)
}

// A message as DATA carries it: a leading dot doubled on each line (RFC 5321 §4.5.2). Z5.3 refuses a
// header line that starts with a dot, so a header block that can be proven comes through unchanged.
func dotStuffed(message []byte) []byte {
	stuffed := make([]byte, 0, len(message))
	lineStart := true
	for _, octet := range message {
		if lineStart && octet == '.' {
			stuffed = append(stuffed, '.')
		}
		stuffed = append(stuffed, octet)
		lineStart = octet == '\n'
	}
	return stuffed
}

// Whether a reply ends the send. Only DATA's own reply is 354; every other must be 2xx.
func smtpReplyRefuses(reply *smtpReply, expectsData bool) bool {
	if expectsData {
		return reply.code != "354"
	}
	return reply.code[0] != '2'
}

// The plaintext a record's witness holds: in 1.3 its content and type octet.
func (self *proverRun) opened(record *tlsSealedRecord, content string) []byte {
	plaintext := []byte(content)
	if self.result.version == tlsVersion13 {
		plaintext = append(plaintext, tlsRecordApplicationData)
	}
	return plaintext
}

func (self *proverRun) seal(content []byte) (*tlsSealedRecord, error) {
	return self.client.sealApplication(content)
}

// One part as the prover builds it: the records it opens and what the gate will hold it to.
type proverPart struct {
	sealed     []*tlsSealedRecord
	plaintexts [][]byte
	// Opens QUIT, which BDAT's carries at its own sequence number, past the unopened body.
	last bool
	// The replies its server records hold.
	replyCount uint32
	// On the part that opens the header block's first record: k.
	headerRecordCount uint32
	// The scan's carries, on a part that opens a header or body record (DESIGN-DETAILS 3.2.4): the state
	// the gate's carry opens to and its blind, and the state the part leaves and the blind of its own.
	// wireCarry is false on an empty body's last part, which carries none.
	carryIn       []byte
	carryInState  scanState
	carryInBlind  *big.Int
	carryOut      []byte
	carryOutBlind *big.Int
	wireCarry     bool
}

// One scan record's carry: the state it leaves and a fresh blind, drawn once a carry, and the
// commitment the part publishes.
type proverCarry struct {
	state      scanState
	blind      *big.Int
	commitment []byte
}

func newProverCarry(state scanState) (*proverCarry, error) {
	blind, err := newCommitBlind("smtp_carry_blind")
	if err != nil {
		return nil, err
	}
	commitment, err := commitCarry(uint32(state), blind)
	if err != nil {
		return nil, err
	}
	return &proverCarry{state: state, blind: blind, commitment: encodeCommitment(commitment)}, nil
}

// Where a scan starts: the start state under the zero blind, which the gate supplies as the constant
// carry (DESIGN-DETAILS 3.2.4).
func proverStartCarry() *proverCarry {
	return &proverCarry{state: scanStart, blind: new(big.Int), commitment: scanStartCarry()}
}

// The header block's records by headerSplit, each with the carry of the state it leaves.
func (self *proverRun) headerRecords(headerBlock []byte) ([][]byte, []*proverCarry, error) {
	sizes, err := self.settings.Proof.headerSplit(len(headerBlock), suiteFamily(self.result.suite), self.result.version)
	if err != nil {
		return nil, nil, fmt.Errorf("smtpproof: %w", err)
	}
	var contents [][]byte
	var carries []*proverCarry
	state := scanStart
	offset := 0
	for i, size := range sizes {
		content := headerBlock[offset : offset+size]
		offset += size
		if state, err = scanHeaderRecord(self.preamble, content, state, i == 0, i == len(sizes)-1); err != nil {
			// the relation refuses this header block; the part that would open it says so
			state = 0
		}
		carry, err := newProverCarry(state)
		if err != nil {
			return nil, nil, err
		}
		contents = append(contents, content)
		carries = append(carries, carry)
	}
	return contents, carries, nil
}

// The part that opens the header block's first record, and any part before it that the envelope's
// replies need: when the msg shape's server blocks cannot hold them, an env part that opens no client
// record covers them first (DESIGN-DETAILS 3.2.4).
func (self *proverRun) proveMessageFirst(ctx context.Context, message *proverPart, envelopeReplies uint32) error {
	message.replyCount = envelopeReplies
	statement, _ := self.statementOf(message)
	if _, err := partShapeFor(self.settings.Proof, statement); err != nil {
		if err := self.prove(ctx, &proverPart{replyCount: envelopeReplies}); err != nil {
			return err
		}
		message.replyCount = 0
	}
	if err := self.prove(ctx, message); err != nil {
		return err
	}
	self.messageStarted = true
	return nil
}

// BDAT's parts (DESIGN-DETAILS 3.2.6): the msg part opens BDAT's command and the header block's first
// record, each later header record takes a hdr part, and the part that opens the last one also opens
// QUIT, which fixes QUIT's sequence number, so every body record is sealed before it. The body then
// streams unopened (SPEC.md 9.5).
func (self *proverRun) sendBdat(ctx context.Context, headerBlock []byte, body []byte, envelopeReplies uint32) (*sidecar.SmtpProofResult, error) {
	result, err := self.sendBdatParts(ctx, headerBlock, body, envelopeReplies)
	var refused *proverRefused
	if errors.As(err, &refused) {
		return &sidecar.SmtpProofResult{Mode: partModeBdat, RefusedCode: refused.reply.code}, nil
	}
	return result, err
}

func (self *proverRun) sendBdatParts(ctx context.Context, headerBlock []byte, body []byte, envelopeReplies uint32) (*sidecar.SmtpProofResult, error) {
	command := literalBdatPrefix + strconv.FormatUint(self.preamble.messageByteCount, 10) + literalBdatSuffix
	commandRecord, err := self.seal([]byte(command))
	if err != nil {
		return nil, err
	}
	contents, carries, err := self.headerRecords(headerBlock)
	if err != nil {
		return nil, err
	}
	var headerRecords []*tlsSealedRecord
	for _, content := range contents {
		record, err := self.seal(content)
		if err != nil {
			return nil, err
		}
		headerRecords = append(headerRecords, record)
	}
	var bodyRecords []*tlsSealedRecord
	for offset := 0; offset < len(body); offset += self.settings.MaxRecordContentBytes {
		end := min(offset+self.settings.MaxRecordContentBytes, len(body))
		record, err := self.seal(body[offset:end])
		if err != nil {
			return nil, err
		}
		bodyRecords = append(bodyRecords, record)
	}
	quitRecord, err := self.seal([]byte(literalQuit))
	if err != nil {
		return nil, err
	}
	k := len(headerRecords)
	for i, record := range headerRecords {
		part := &proverPart{
			sealed:        []*tlsSealedRecord{record},
			plaintexts:    [][]byte{self.opened(record, string(contents[i]))},
			carryOut:      carries[i].commitment,
			carryOutBlind: carries[i].blind,
			wireCarry:     true,
		}
		if i == 0 {
			part.sealed = append([]*tlsSealedRecord{commandRecord}, part.sealed...)
			part.plaintexts = append([][]byte{self.opened(commandRecord, command)}, part.plaintexts...)
			part.headerRecordCount = uint32(k)
		} else {
			part.carryIn = carries[i-1].commitment
			part.carryInState = carries[i-1].state
			part.carryInBlind = carries[i-1].blind
		}
		last := i == k-1
		if last {
			part.sealed = append(part.sealed, quitRecord)
			part.plaintexts = append(part.plaintexts, self.opened(quitRecord, literalQuit))
			part.last = true
		}
		if i == 0 {
			err = self.proveMessageFirst(ctx, part, envelopeReplies)
		} else {
			err = self.proveAfterLateRecords(ctx, part)
		}
		if err != nil {
			return nil, err
		}
		writes := part.sealed
		if last {
			// the body streams unopened under the last part, and QUIT waits for the chunk's reply
			writes = append(writes[:len(writes)-1:len(writes)-1], bodyRecords...)
		}
		for _, record := range writes {
			if err := self.client.writeSealed(record); err != nil {
				return nil, err
			}
		}
	}
	return self.finish(ctx, partModeBdat, quitRecord)
}

// A later message part, after any server record read since the part before: the message's parts cover
// none, so a late ticket takes an env part of its own first, which opens no client record (DESIGN-DETAILS
// 3.2.6). A reply here is the MX ending the send.
func (self *proverRun) proveAfterLateRecords(ctx context.Context, part *proverPart) error {
	if reply, err := self.drainServerRecords(); err != nil {
		return err
	} else if reply != nil {
		return &proverRefused{reply: reply}
	}
	if err := self.proveLateRecords(ctx); err != nil {
		return err
	}
	return self.prove(ctx, part)
}

// The MX answered during the message, which ends the send with its code.
type proverRefused struct {
	reply *smtpReply
}

func (self *proverRefused) Error() string {
	return "smtpproof: the MX replied during the message"
}

// Covers every server record read since the last part by an env part that opens no client record, when
// there is one, so that the edge's hold on message records behind it lifts (E3 step 5).
func (self *proverRun) proveLateRecords(ctx context.Context) error {
	if uint64(len(self.records)) == self.covered {
		return nil
	}
	return self.prove(ctx, &proverPart{})
}

// DATA opens every octet (D-SMTP-20): the msg part the header block's first record over the envelope's
// replies, a hdr part each later header record, and a body part each body record, cut at what the body
// shape holds; the last body part also opens the end mark and QUIT. An empty body's last part opens the
// end mark and QUIT alone.
func (self *proverRun) sendData(ctx context.Context, headerBlock []byte, body []byte, envelopeReplies uint32) (*sidecar.SmtpProofResult, error) {
	result, err := self.sendDataParts(ctx, headerBlock, body, envelopeReplies)
	var refused *proverRefused
	if errors.As(err, &refused) {
		return &sidecar.SmtpProofResult{Mode: partModeData, RefusedCode: refused.reply.code}, nil
	}
	return result, err
}

// The body octets one body record holds: the family's body shape's, less 1.3's type octet, and no more
// than DataPartBytes.
func (self *proverRun) bodyRecordBytes() int {
	shape := self.settings.Proof.shape(ShapeKindBody, suiteFamily(self.result.suite), 0)
	if shape == nil {
		return 0
	}
	return min(shape.recordContentBytes(shape.BodyBlocks, self.result.version), self.settings.DataPartBytes, self.settings.MaxRecordContentBytes)
}

func (self *proverRun) sendDataParts(ctx context.Context, headerBlock []byte, body []byte, envelopeReplies uint32) (*sidecar.SmtpProofResult, error) {
	contents, carries, err := self.headerRecords(headerBlock)
	if err != nil {
		return nil, err
	}
	recordBytes := self.bodyRecordBytes()
	if recordBytes <= 0 {
		return nil, errors.New("smtpproof: no body shape holds a DATA body record")
	}
	var bodyContents [][]byte
	for offset := 0; offset < len(body); offset += recordBytes {
		bodyContents = append(bodyContents, body[offset:min(offset+recordBytes, len(body))])
	}
	k := len(contents)
	for i, content := range contents {
		record, err := self.seal(content)
		if err != nil {
			return nil, err
		}
		part := &proverPart{
			sealed:        []*tlsSealedRecord{record},
			plaintexts:    [][]byte{self.opened(record, string(content))},
			carryOut:      carries[i].commitment,
			carryOutBlind: carries[i].blind,
			wireCarry:     true,
		}
		if i == 0 {
			part.headerRecordCount = uint32(k)
			err = self.proveMessageFirst(ctx, part, envelopeReplies)
		} else {
			part.carryIn = carries[i-1].commitment
			part.carryInState = carries[i-1].state
			part.carryInBlind = carries[i-1].blind
			err = self.proveAfterLateRecords(ctx, part)
		}
		if err != nil {
			return nil, err
		}
		if err := self.client.writeSealed(record); err != nil {
			return nil, err
		}
	}
	// the body scans from the start again: the gate's carry after the header block's last record
	carry := proverStartCarry()
	for i := 0; i < len(bodyContents) || i == 0; i += 1 {
		last := len(bodyContents) <= i+1
		part := &proverPart{carryIn: carry.commitment, carryInState: carry.state, carryInBlind: carry.blind}
		if i < len(bodyContents) {
			record, err := self.seal(bodyContents[i])
			if err != nil {
				return nil, err
			}
			state, err := scanBodyRecord(bodyContents[i], carry.state, last)
			if err != nil {
				// the relation refuses this body; the part that opens it says so
				state = 0
			}
			next, err := newProverCarry(state)
			if err != nil {
				return nil, err
			}
			part.sealed = []*tlsSealedRecord{record}
			part.plaintexts = [][]byte{self.opened(record, string(bodyContents[i]))}
			part.carryOut = next.commitment
			part.carryOutBlind = next.blind
			part.wireCarry = true
			carry = next
		} else {
			// an empty body's last part leaves the start state as it was, and carries none
			part.carryOut = carry.commitment
			part.carryOutBlind = carry.blind
		}
		var quitRecord *tlsSealedRecord
		if last {
			endRecord, err := self.seal([]byte(literalEndMark))
			if err != nil {
				return nil, err
			}
			if quitRecord, err = self.seal([]byte(literalQuit)); err != nil {
				return nil, err
			}
			part.sealed = append(part.sealed, endRecord, quitRecord)
			part.plaintexts = append(part.plaintexts, self.opened(endRecord, literalEndMark), self.opened(quitRecord, literalQuit))
			part.last = true
		}
		if err := self.proveAfterLateRecords(ctx, part); err != nil {
			return nil, err
		}
		writes := part.sealed
		if last {
			writes = writes[:len(writes)-1]
		}
		for _, record := range writes {
			if err := self.client.writeSealed(record); err != nil {
				return nil, err
			}
		}
		if last {
			return self.finish(ctx, partModeData, quitRecord)
		}
	}
	return nil, errors.New("smtpproof: a DATA send with no last part")
}

// Waits for the message's reply, then sends the proven QUIT.
func (self *proverRun) finish(ctx context.Context, mode uint32, quitRecord *tlsSealedRecord) (*sidecar.SmtpProofResult, error) {
	replies, err := self.awaitReplies(ctx, 1)
	if err != nil {
		return nil, err
	}
	if replies[0].code[0] != '2' {
		return &sidecar.SmtpProofResult{Mode: mode, RefusedCode: replies[0].code}, nil
	}
	// QUIT is no message record, so a reply past the part's count never holds it (E3 step 5)
	if err := self.client.writeSealed(quitRecord); err != nil {
		return nil, err
	}
	return &sidecar.SmtpProofResult{Mode: mode, Accepted: true}, nil
}

// Reads server records until the stream holds count whole replies, which it consumes and returns.
//
// A ticket arriving once the message's parts have begun holds its message records at the edge (E3 step
// 5), and no message part covers a server record, so an env part that opens no client record covers it
// at once (DESIGN-DETAILS 3.2.6), after the last part too.
func (self *proverRun) awaitReplies(ctx context.Context, count int) ([]*smtpReply, error) {
	for {
		if replies, consumed := splitReplies(self.stream, count); replies != nil {
			self.stream = self.stream[consumed:]
			return replies, nil
		}
		var event *proverServerEvent
		select {
		case event = <-self.serverIn:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		ticket, err := self.takeServerRecord(event)
		if err != nil {
			return nil, err
		}
		if ticket && self.messageStarted {
			if err := self.proveLateRecords(ctx); err != nil {
				return nil, err
			}
		}
	}
}

// Keeps a server record for the parts to cover, and says whether it is a ticket, which holds no reply.
func (self *proverRun) takeServerRecord(event *proverServerEvent) (bool, error) {
	if event.err != nil {
		return false, event.err
	}
	record := event.record
	self.serverBytes += len(record.raw)
	if self.settings.MaxServerBytes < self.serverBytes {
		return false, errors.New("smtpproof: MX sent more than any part could cover")
	}
	plaintext, err := self.plaintextOf(record)
	if err != nil {
		return false, err
	}
	self.records = append(self.records, &proverServerRecord{
		public:    &partRecord{seq: record.seq, raw: record.raw},
		plaintext: plaintext,
	})
	switch record.recordType {
	case tlsRecordApplicationData:
		self.stream = append(self.stream, record.content...)
		return false, nil
	case tlsRecordHandshake:
		if len(record.content) == 0 || record.content[0] != tlsHandshakeNewSessionTicket {
			return false, errors.New("smtpproof: MX sent a handshake record other than a ticket")
		}
		return true, nil
	default:
		return false, fmt.Errorf("smtpproof: MX sent a record of type %d", record.recordType)
	}
}

// Takes every server record the reader already holds, without waiting, so the next part covers them. A
// reply during the message is the MX ending the send, and is returned. A record still on its way is
// covered once it arrives, while the final reply is awaited.
func (self *proverRun) drainServerRecords() (*smtpReply, error) {
	for {
		select {
		case event := <-self.serverIn:
			if _, err := self.takeServerRecord(event); err != nil {
				return nil, err
			}
		default:
			if replies, consumed := splitReplies(self.stream, 1); replies != nil {
				self.stream = self.stream[consumed:]
				return replies[0], nil
			}
			return nil, nil
		}
	}
}

// The first count whole replies in a stream and the octets they fill, or nil if more are needed.
func splitReplies(stream []byte, count int) ([]*smtpReply, int) {
	offset := 0
	found := 0
	for found < count {
		end := bytes.Index(stream[offset:], []byte(literalCrlf))
		if end < 0 {
			return nil, 0
		}
		line := stream[offset : offset+end]
		offset += end + len(literalCrlf)
		if len(line) <= 3 || line[3] != '-' {
			found += 1
		}
	}
	replies, err := parseReplies(stream[:offset])
	if err != nil {
		// a reply this far malformed is unprovable, so the send ends where it is reported
		return []*smtpReply{{code: "000", lineCodes: []string{"000"}, lines: []string{""}}}, offset
	}
	return replies, offset
}

// A record's witness plaintext, which in 1.3 is the inner plaintext with its type octet.
func (self *proverRun) plaintextOf(record *tlsServerRecord) ([]byte, error) {
	if self.result.version == tlsVersion12 {
		return record.content, nil
	}
	// a padded record's raw length exceeds its content's: such a record is unprovable (Z7)
	ciphertext, err := recordCiphertext(tlsVersion13, record.raw)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) != len(record.content)+tlsInnerTypeBytes {
		return nil, errors.New("smtpproof: MX padded a record, which no part can prove")
	}
	plaintext := make([]byte, 0, len(ciphertext))
	plaintext = append(plaintext, record.content...)
	return append(plaintext, record.recordType), nil
}

// The part on the wire and its statement and witness, from the gate's state as this prover mirrors it:
// the next index and record, the server records read since the last part, the replies proven, and k.
func (self *proverRun) statementOf(spec *proverPart) (*partStatement, *sidecar.SmtpProofPart) {
	part := &sidecar.SmtpProofPart{
		SendId:            self.job.SendId,
		Index:             self.nextPart,
		Mode:              self.mode,
		FirstRecord:       self.nextRecord,
		LastRecord:        self.nextRecord - 1,
		Last:              spec.last,
		ServerRecordCount: uint64(len(self.records)),
		ReplyCount:        spec.replyCount,
		HeaderRecordCount: spec.headerRecordCount,
	}
	if part.Index == 1 {
		part.Mode = partModeNone
		part.KeyCommitment = self.keyCommitment
	}
	if spec.wireCarry {
		part.Carry = spec.carryOut
	}
	headerRecordCount := self.headerRecordCount
	if spec.headerRecordCount != 0 {
		headerRecordCount = spec.headerRecordCount
	}
	statement := &partStatement{
		session:                   self.session,
		keyCommitment:             self.keyCommitment,
		index:                     part.Index,
		mode:                      part.Mode,
		last:                      part.Last,
		previousServerRecordCount: self.covered,
		serverRecordCount:         part.ServerRecordCount,
		replyCount:                part.ReplyCount,
		repliesProven:             self.repliesProven,
		headerRecordCount:         headerRecordCount,
		carryIn:                   spec.carryIn,
		carryOut:                  spec.carryOut,
	}
	for _, record := range spec.sealed {
		part.Records = append(part.Records, record.raw)
		statement.clientRecords = append(statement.clientRecords, &partRecord{seq: record.seq, raw: record.raw})
	}
	if 0 < len(spec.sealed) {
		part.FirstRecord = spec.sealed[0].seq
		part.LastRecord = spec.sealed[len(spec.sealed)-1].seq
	}
	statement.firstRecord = part.FirstRecord
	statement.lastRecord = part.LastRecord
	for _, record := range self.records[self.covered:part.ServerRecordCount] {
		statement.serverRecords = append(statement.serverRecords, record.public)
	}
	return statement, part
}

// Checks a part against the relation, proves it and submits it, then advances the gate's state as the
// gate will once the part is verified.
func (self *proverRun) prove(ctx context.Context, spec *proverPart) error {
	statement, part := self.statementOf(spec)
	witness := &partWitness{
		handshakeSecret:  self.result.handshakeSecret,
		clientKey:        self.result.clientKey,
		clientIv:         self.result.clientIv,
		serverKey:        self.result.serverKey,
		serverIv:         self.result.serverIv,
		keyBlind:         self.keyBlind,
		carryInState:     spec.carryInState,
		carryInBlind:     spec.carryInBlind,
		carryOutBlind:    spec.carryOutBlind,
		clientPlaintexts: spec.plaintexts,
	}
	if self.result.version == tlsVersion12 {
		witness.masterSecret = self.result.masterSecret
	}
	for _, record := range self.records[self.covered:part.ServerRecordCount] {
		witness.serverPlaintexts = append(witness.serverPlaintexts, record.plaintext)
	}
	if failures := relationCheckPart(statement, witness); 0 < len(failures) {
		return fmt.Errorf("smtpproof: part %d does not satisfy the relation: %w", part.Index, failures[0])
	}
	// a part no catalog shape holds is refused at the edge before verification, so it is not sent
	if _, err := partShapeFor(self.settings.Proof, statement); err != nil {
		return fmt.Errorf("smtpproof: part %d: %w", part.Index, err)
	}
	proof, err := self.backend.provePart(ctx, statement, witness)
	if err != nil {
		return err
	}
	part.Proof = proof
	if err := self.channel.SubmitPart(ctx, part); err != nil {
		return err
	}
	self.nextPart += 1
	if 0 < len(spec.sealed) {
		self.nextRecord = part.LastRecord + 1
	}
	self.covered = part.ServerRecordCount
	self.repliesProven += part.ReplyCount
	if spec.headerRecordCount != 0 {
		self.headerRecordCount = spec.headerRecordCount
	}
	return nil
}
