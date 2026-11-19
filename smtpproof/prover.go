package smtpproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
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
	// The TLS suites the client offers, in its order, less those whose family has no ready keys (DESIGN-DETAILS
	// 3.2.6, 3.2.7): ChaCha20-Poly1305 first, since an octet under it costs 341 constraints of keystream
	// against AES-128-GCM's 729 and an MX that follows the client's preference then halves a header's cost,
	// then TLS 1.3's AES-128-GCM and TLS 1.2's two AES-128-GCM suites.
	SuiteOrder []uint16
	// The memory proving may take (DESIGN-DETAILS 3.2.8), kept by charging: loaded shapes times
	// ShapeMemoryByteCount plus proofs in flight times PartMemoryByteCount stay at or under it. 2,240 MiB:
	// two loaded shapes, the one proving and the next, and one proof, which an 8 GB host can give. A budget
	// that cannot hold one shape and one proof refuses every part, and the host only queues.
	MemoryMaxByteCount int64
	// What a loaded shape is charged, its compiled circuit and its proving key's dump: 768 MiB, above the
	// 617 to 737 MiB measured for a unit's.
	ShapeMemoryByteCount int64
	// What a proof in flight is charged over its loaded shape: 704 MiB, the first proof's 662 MiB measured
	// with a collection after each. BenchmarkPartMemory holds it to the peak it finds.
	PartMemoryByteCount int64
	// Proofs at once in one send, each PartMemoryByteCount more: 1. Non-positive is 1.
	ProveConcurrency int
	// A loaded shape no proof has used for this long is unloaded, and when the last goes the heap is
	// returned to the system: 2 min, longer than the gap between a send's parts. Non-positive unloads a
	// shape once no proof holds it.
	ShapeIdleTimeout time.Duration
	// Commands one envelope group holds at most, below what fits the env shape: 0 for what fits. A job's
	// own EnvelopeGroupMaxCount, the sender's retry after EnvelopeRetry, bounds it too.
	EnvelopeGroupMaxCount int
	// What each reply to the first envelope group is taken to fill, a record of its own, when the group is
	// sized: 40 octets. Later groups take the mean reply of the records that held the group before's
	// replies, a public value, plus ReplyMarginByteCount, 8 octets (DESIGN-DETAILS 3.2.4).
	ReplyEstimateByteCount int
	ReplyMarginByteCount   int
	// smtp_data_proof_bytes: a larger message to an MX without CHUNKING is too_large before MAIL (§14.5). Measure
	// replaces this unmeasured default with the host's own figure, 0 where a unit cannot prove within
	// DataPartTime. Non-positive refuses every DATA send.
	DataProofBytes int
	// How long one DATA part may take to prove: §14.5's 2 minutes, inside the MX's 5-minute timeout. A
	// host whose unit takes longer sends nothing in DATA mode.
	DataPartTime time.Duration
	// How long a DATA connection proves for: §14.4's 2 h. With the measured rate it gives
	// smtp_data_proof_bytes.
	DataConnectionTime time.Duration
	// Server octets held for parts to cover, as VerifierSettings.MaxServerBytes. A reply that never ends
	// stops here rather than growing what this send holds.
	MaxServerBytes int
	// Sends in DATA mode even where the MX offers CHUNKING, as D-SMTP-16's interop runs do.
	ForceData bool

	// A test's cut of DATA's body below what the body shape holds, so that a short body takes several
	// parts. 0, the only value outside tests, cuts each body record at the shape's capacity.
	testDataRecordByteCount int
}

func DefaultProverSettings() *ProverSettings {
	return &ProverSettings{
		Proof:                  DefaultProofSettings(),
		SuiteOrder:             defaultTlsSuiteOrder(),
		MemoryMaxByteCount:     2240 * 1024 * 1024,
		ShapeMemoryByteCount:   768 * 1024 * 1024,
		PartMemoryByteCount:    704 * 1024 * 1024,
		ProveConcurrency:       1,
		ShapeIdleTimeout:       2 * time.Minute,
		ReplyEstimateByteCount: 40,
		ReplyMarginByteCount:   8,
		DataProofBytes:         1024 * 1024,
		DataPartTime:           2 * time.Minute,
		DataConnectionTime:     2 * time.Hour,
		MaxServerBytes:         256 * 1024,
	}
}

// Implements sidecar.SmtpProver. Safe for concurrent use: all state is per send, except the last
// Measure's limits under stateLock and the key sets' readiness, which keys guards.
type Prover struct {
	settings *ProverSettings
	// What Measure proves with. With keys, the newest pinned set with a ready family; a test may give one
	// of its own and no keys, and then a job naming no key set proves under it.
	backend partProver
	// The release's pinned key sets on this host (DESIGN-DETAILS 3.2.7), or nil for a test's backend.
	keys *proverKeys
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

// What one send holds. Not safe for concurrent use, except that the reader goroutine owns serverIn and
// the message's proofs run beside the submitting goroutine, reading only what is fixed by then.
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
	// The replies to the envelope's last group, and the server records read once they were whole, which
	// the message's first part, or env parts before it, cover.
	envelopeReplyCount uint32
	envelopeEnd        uint64
	// Whether the message's first part was submitted, after which a late server record is covered by a
	// part of its own, since the message's parts hold none.
	messageStarted bool
	// Every reply code read inside TLS, in order, and each RCPT's, once any was read, for the result.
	replyCodes          []uint32
	recipientReplyCodes []uint32
}

// The gate's state when a part reaches it, as this prover mirrors it, which the part's statement takes.
type proverGateState struct {
	index             uint32
	covered           uint64
	repliesProven     uint32
	headerRecordCount uint32
}

func (self *proverRun) gateState() proverGateState {
	return proverGateState{
		index:             self.nextPart,
		covered:           self.covered,
		repliesProven:     self.repliesProven,
		headerRecordCount: self.headerRecordCount,
	}
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

// KeySet of sidecar.SmtpProver: the newest pinned set with a family ready on this host, or none, and
// then the host only queues (D-SMTP-18).
func (self *Prover) KeySet() []byte {
	if self.keys == nil {
		return nil
	}
	if keySet := self.keys.current(); keySet != nil {
		return keySet.Id()
	}
	return nil
}

// PrepareKeys of sidecar.SmtpProver: the host's check of its pinned key sets, one shape at most a call
// (DESIGN-DETAILS 3.2.7). It fetches transcripts, so a host calls it only once mail is enabled on it
// (§2.8 smtp-7). With no pin there is nothing to check. The readiness is returned with any error.
func (self *Prover) PrepareKeys(ctx context.Context) (*sidecar.SmtpProverReadiness, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if self.keys == nil {
		return &sidecar.SmtpProverReadiness{Done: true}, nil
	}
	return self.keys.prepare(ctx)
}

// What a job proves under: the backend, the catalog and the suites of the key set it names, which must be
// a pinned set with a ready family, the suites SuiteOrder's that it can prove. A Prover with no keys proves
// a job naming none under its own backend, offering SuiteOrder.
func (self *Prover) jobKeys(keySet []byte) (partProver, *ProofSettings, []uint16, error) {
	if self.keys == nil {
		if len(keySet) != 0 {
			return nil, nil, nil, sidecar.ErrSmtpProofKeySet
		}
		suites := self.settings.SuiteOrder
		if self.tlsSuites != nil {
			suites = self.tlsSuites
		}
		return self.backend, self.settings.Proof, suites, nil
	}
	set, suites, ok := self.keys.forJob(keySet)
	if !ok {
		return nil, nil, nil, sidecar.ErrSmtpProofKeySet
	}
	if self.tlsSuites != nil {
		suites = slices.DeleteFunc(slices.Clone(suites), func(suite uint16) bool { return !slices.Contains(self.tlsSuites, suite) })
		if len(suites) == 0 {
			return nil, nil, nil, sidecar.ErrSmtpProofKeySet
		}
	}
	return set.backend, set.proof, suites, nil
}

// SendSmtp of sidecar.SmtpProver.
func (self *Prover) SendSmtp(ctx context.Context, conn net.Conn, job *sidecar.SmtpProofJob, channel sidecar.SmtpProofChannel) (*sidecar.SmtpProofResult, error) {
	// a set this prover cannot prove under is refused before any octet goes out, and the client offers
	// only the suites of the families ready in the set it names (DESIGN-DETAILS 3.2.7)
	backend, proof, suites, err := self.jobKeys(job.KeySet)
	if err != nil {
		return nil, err
	}
	if job.Preamble == nil || uint32(len(job.RecipientLocals)) != job.Preamble.RecipientCount || len(job.RecipientLocals) == 0 {
		return nil, errors.New("smtpproof: job's recipients do not match its preamble")
	}
	// the edge refuses the same, so nothing here should reach it
	if err := checkSessionPreamble(newSessionPreamble(job.Preamble, proof)); err != nil {
		return nil, fmt.Errorf("smtpproof: %w", err)
	}
	declared := job.Preamble.MessageByteCount
	if declared != uint64(len(job.Message)) && declared != uint64(len(dotStuffed(job.Message))) {
		return nil, errors.New("smtpproof: job's message does not match its declared octet count")
	}
	settings := defaultTlsClientSettings()
	settings.serverName = job.Preamble.MxHost
	settings.verifyPeer = job.VerifyPeer
	settings.recordContentMaxByteCount = proof.RecordContentMaxByteCount
	settings.recordCiphertextMaxByteCount = proof.RecordCiphertextMaxByteCount
	if len(suites) == 0 {
		return nil, errors.New("smtpproof: no TLS suite to offer")
	}
	settings.suites = suites
	sendSettings := self.sendSettings()
	sendSettings.Proof = proof
	run := &proverRun{
		settings: sendSettings,
		backend:  backend,
		job:      job,
		channel:  channel,
		client:   newTlsClient(conn, settings),
		preamble: newSessionPreamble(job.Preamble, proof),
		serverIn: make(chan *proverServerEvent),
		nextPart: 1,
	}
	result, err := run.run(ctx)
	if result != nil {
		result.ReplyCodes = run.replyCodes
		result.RecipientReplyCodes = run.recipientReplyCodes
	}
	return result, err
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
	if err := self.prove(ctx, &proverPart{sealed: []*tlsSealedRecord{ehlo}, plaintexts: [][]byte{self.opened(ehlo, ehloCommand)}}, 0); err != nil {
		return nil, err
	}
	if err := self.client.writeSealed(ehlo); err != nil {
		return nil, err
	}
	replies, err := self.awaitReplies(ctx, 1)
	if err != nil {
		return nil, err
	}
	self.noteReply(-1, replies[0])
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
		// a host whose unit cannot prove within its time has no DATA cap, and sends no DATA
		if uint64(max(self.settings.DataProofBytes, 0)) < count {
			return &sidecar.SmtpProofResult{Mode: mode, TooLarge: true, DataProofByteCount: uint64(max(self.settings.DataProofBytes, 0))}, nil
		}
	}
	if self.preamble.messageByteCount != count {
		return &sidecar.SmtpProofResult{Mode: mode, ReconnectByteCount: count}, nil
	}
	self.mode = mode

	// the envelope's commands go in groups, each with the part that covers the replies to the one before
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
	if result, err := self.sendEnvelope(ctx, commands, pipelining); result != nil || err != nil {
		return result, err
	}

	headerEnd := bytes.Index(self.job.Message, []byte(literalCrlf+literalCrlf))
	if headerEnd < 0 {
		return nil, errors.New("smtpproof: message has no header block")
	}
	headerEnd += 2 * len(literalCrlf)
	body := self.job.Message[headerEnd:]
	if mode == partModeData {
		body = stuffed[headerEnd:]
	}
	return self.sendMessage(ctx, self.job.Message[:headerEnd], body)
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
	// The records written once the part's answer is OK: what it opens, but QUIT, which waits for the
	// message's reply, with BDAT's unopened body after the last header record and DATA's end mark.
	writes []*tlsSealedRecord
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

// Covers every server record read since the last part by env parts that open no client record, when there
// is one, so that the edge's hold on message records behind them lifts (E3 step 5).
func (self *proverRun) proveLateRecords(ctx context.Context) error {
	through := uint64(len(self.records))
	if through == self.covered {
		return nil
	}
	covered, err := self.coverServerRecords(ctx, through)
	if err != nil {
		return err
	}
	if !covered {
		return errors.New("smtpproof: the MX sent a record no part can cover")
	}
	return nil
}

// The body octets one DATA body record holds: the family's body shape's, less 1.3's type octet, within
// the record bound.
func (self *proverRun) bodyRecordBytes() int {
	shape := self.settings.Proof.shape(ShapeKindBody, suiteFamily(self.result.suite), 0)
	if shape == nil {
		return 0
	}
	recordBytes := min(shape.recordContentBytes(shape.BodyBlocks, self.result.version), self.settings.Proof.RecordContentMaxByteCount)
	if 0 < self.settings.testDataRecordByteCount {
		recordBytes = min(recordBytes, self.settings.testDataRecordByteCount)
	}
	return recordBytes
}

// Waits for the message's reply, then sends the proven QUIT.
func (self *proverRun) finish(ctx context.Context, mode uint32, quitRecord *tlsSealedRecord) (*sidecar.SmtpProofResult, error) {
	replies, err := self.awaitReplies(ctx, 1)
	if err != nil {
		return nil, err
	}
	self.noteReply(-1, replies[0])
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

// The part on the wire and its statement, from the gate's state as this prover mirrors it when the part
// reaches it, covering the server records from that state's to serverRecordCount.
func (self *proverRun) statementOf(spec *proverPart, state proverGateState, serverRecordCount uint64) (*partStatement, *sidecar.SmtpProofPart) {
	part := &sidecar.SmtpProofPart{
		SendId:            self.job.SendId,
		Index:             state.index,
		Mode:              self.mode,
		FirstRecord:       self.nextRecord,
		LastRecord:        self.nextRecord - 1,
		Last:              spec.last,
		ServerRecordCount: serverRecordCount,
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
	headerRecordCount := state.headerRecordCount
	if spec.headerRecordCount != 0 {
		headerRecordCount = spec.headerRecordCount
	}
	statement := &partStatement{
		session:                   self.session,
		keyCommitment:             self.keyCommitment,
		index:                     part.Index,
		mode:                      part.Mode,
		last:                      part.Last,
		previousServerRecordCount: state.covered,
		serverRecordCount:         part.ServerRecordCount,
		replyCount:                part.ReplyCount,
		repliesProven:             state.repliesProven,
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
	if state.covered <= serverRecordCount && serverRecordCount <= uint64(len(self.records)) {
		for _, record := range self.records[state.covered:serverRecordCount] {
			statement.serverRecords = append(statement.serverRecords, record.public)
		}
	}
	return statement, part
}

// A part's witness: the connection's keys and blind, the part's plaintexts and carries, and the plaintext
// of each server record its statement covers.
func (self *proverRun) witnessOf(spec *proverPart, statement *partStatement) *partWitness {
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
	if statement.previousServerRecordCount <= statement.serverRecordCount && statement.serverRecordCount <= uint64(len(self.records)) {
		for _, record := range self.records[statement.previousServerRecordCount:statement.serverRecordCount] {
			witness.serverPlaintexts = append(witness.serverPlaintexts, record.plaintext)
		}
	}
	return witness
}

// Checks a part against the relation and proves it. A part no catalog shape holds is refused at the edge
// before it verifies, so it is never sent.
func (self *proverRun) proveStatement(ctx context.Context, statement *partStatement, witness *partWitness) ([]byte, error) {
	if failures := relationCheckPart(statement, witness); 0 < len(failures) {
		return nil, fmt.Errorf("smtpproof: part %d does not satisfy the relation: %w", statement.index, failures[0])
	}
	if _, err := partShapeFor(self.settings.Proof, statement); err != nil {
		return nil, fmt.Errorf("smtpproof: part %d: %w", statement.index, err)
	}
	return self.backend.provePart(ctx, statement, witness)
}

// Submits a proven part, then advances the gate's state as the gate does once the part is verified.
func (self *proverRun) submit(ctx context.Context, spec *proverPart, part *sidecar.SmtpProofPart) error {
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

// Proves a part over the server records from the last covered to serverRecordCount, and submits it.
func (self *proverRun) prove(ctx context.Context, spec *proverPart, serverRecordCount uint64) error {
	statement, part := self.statementOf(spec, self.gateState(), serverRecordCount)
	proof, err := self.proveStatement(ctx, statement, self.witnessOf(spec, statement))
	if err != nil {
		return err
	}
	part.Proof = proof
	return self.submit(ctx, spec, part)
}
