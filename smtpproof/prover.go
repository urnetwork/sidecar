package smtpproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

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
	// Largest content of one client record. The protocol's limit is 16 KiB.
	MaxRecordContentBytes int
	// DATA octets proven per part, which must fit a shape's body blocks. The sidecar sizes this by its
	// measured speed to prove within 2 minutes (§14.5). partShapes holds 2 KiB, one octet of it for
	// TLS 1.3's inner type.
	DataPartBytes int
	// smtp_data_proof_bytes, measured on each host: a larger message to an MX without CHUNKING is
	// too_large before MAIL (§14.5). Non-positive refuses every DATA send.
	DataProofBytes int
	// Sends in DATA mode even where the MX offers CHUNKING, as D-SMTP-16's interop runs do.
	ForceData bool
}

func DefaultProverSettings() *ProverSettings {
	return &ProverSettings{
		MaxRecordContentBytes: 16 * 1024,
		DataPartBytes:         2*1024 - 1,
		DataProofBytes:        1024 * 1024,
	}
}

// Implements sidecar.SmtpProver. Safe for concurrent use: all state is per send.
type Prover struct {
	settings *ProverSettings
	backend  partProver
	// The suites offered, or nil for the client's default. Tests pin one to cover each.
	tlsSuites []uint16
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

	serverIn  chan *proverServerEvent
	records   []*proverServerRecord
	stream    []byte
	nextPart  uint32
	covered   uint64
	lastPart  *sidecar.SmtpProofPart
	lastOpen  [][]byte
	lastPrior uint64
}

// A record from the reader goroutine, or how it ended.
type proverServerEvent struct {
	record *tlsServerRecord
	err    error
}

// The declared values of a job, in the relation's form.
func newSessionPreamble(preamble *sidecar.SmtpProofPreamble) *sessionPreamble {
	return &sessionPreamble{
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

// SendSmtp of sidecar.SmtpProver.
func (self *Prover) SendSmtp(ctx context.Context, conn net.Conn, job *sidecar.SmtpProofJob, channel sidecar.SmtpProofChannel) (*sidecar.SmtpProofResult, error) {
	if job.Preamble == nil || uint32(len(job.RecipientLocals)) != job.Preamble.RecipientCount || len(job.RecipientLocals) == 0 {
		return nil, errors.New("smtpproof: job's recipients do not match its preamble")
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
		settings: self.settings,
		backend:  self.backend,
		job:      job,
		channel:  channel,
		client:   newTlsClient(conn, settings),
		preamble: newSessionPreamble(job.Preamble),
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

	// pi1: EHLO
	ehlo, err := self.seal([]byte(literalEhloPrefix + self.preamble.heloName + literalCrlf))
	if err != nil {
		return nil, err
	}
	if err := self.prove(ctx, partModeNone, false, []*tlsSealedRecord{ehlo}, ehlo.seq, [][]byte{self.opened(ehlo, literalEhloPrefix+self.preamble.heloName+literalCrlf)}); err != nil {
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

	mode := partModeData
	pipelining := false
	for i, text := range replies[0].lines {
		keyword := strings.ToLower(text)
		if 0 < i && keyword == keywordChunking && !self.settings.ForceData {
			mode = partModeBdat
		}
		if 0 < i && keyword == "pipelining" {
			pipelining = true
		}
	}
	// the count was declared before the mode was known (plan-SMTP-preamble-byte-count). BDAT's n and
	// DATA's stuffed count differ when a line starts with a dot: a count only DATA can meet means
	// DATA, and a count only BDAT can meet at an MX that needs DATA means a new connection
	stuffed := dotStuffed(self.job.Message)
	declared := self.preamble.messageByteCount
	if declared != uint64(len(self.job.Message)) {
		mode = partModeData
	}
	if mode == partModeData && uint64(max(self.settings.DataProofBytes, 0)) < uint64(len(stuffed)) {
		return &sidecar.SmtpProofResult{Mode: mode, TooLarge: true}, nil
	}
	if mode == partModeData && declared != uint64(len(stuffed)) {
		return &sidecar.SmtpProofResult{Mode: mode, ReconnectByteCount: uint64(len(stuffed))}, nil
	}

	// pi2: the envelope
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
	var sealed []*tlsSealedRecord
	var plaintexts [][]byte
	for _, command := range commands {
		record, err := self.seal([]byte(command))
		if err != nil {
			return nil, err
		}
		sealed = append(sealed, record)
		plaintexts = append(plaintexts, self.opened(record, command))
	}
	if err := self.prove(ctx, mode, false, sealed, sealed[len(sealed)-1].seq, plaintexts); err != nil {
		return nil, err
	}
	// without PIPELINING each command waits for the last one's reply, still under this part (14.4)
	var envelope []*smtpReply
	for i, record := range sealed {
		if err := self.client.writeSealed(record); err != nil {
			return nil, err
		}
		if !pipelining {
			replies, err := self.awaitReplies(ctx, 1)
			if err != nil {
				return nil, err
			}
			envelope = append(envelope, replies...)
			if smtpReplyRefuses(replies[0], mode == partModeData && i == len(sealed)-1) {
				return &sidecar.SmtpProofResult{Mode: mode, RefusedCode: replies[0].code}, nil
			}
		}
	}
	if pipelining {
		if envelope, err = self.awaitReplies(ctx, len(sealed)); err != nil {
			return nil, err
		}
		for i, reply := range envelope {
			if smtpReplyRefuses(reply, mode == partModeData && i == len(sealed)-1) {
				return &sidecar.SmtpProofResult{Mode: mode, RefusedCode: reply.code}, nil
			}
		}
	}

	headerEnd := bytes.Index(self.job.Message, []byte(literalCrlf+literalCrlf))
	if headerEnd < 0 {
		return nil, errors.New("smtpproof: message has no header block")
	}
	headerEnd += 2 * len(literalCrlf)
	if self.settings.MaxRecordContentBytes < headerEnd {
		return nil, errors.New("smtpproof: header block is longer than one record")
	}
	headerBlock := self.job.Message[:headerEnd]
	if mode == partModeBdat {
		return self.sendBdat(ctx, headerBlock, self.job.Message[headerEnd:])
	}
	return self.sendData(ctx, headerBlock, stuffed[headerEnd:])
}

// A message as DATA carries it: a leading dot doubled on each line (RFC 5321 §4.5.2). The header
// block is unchanged, since Z5 keeps a dot from starting a line there.
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

// BDAT's pi3 opens the head and QUIT, and fixes QUIT's sequence number, so every body record is
// sealed before it. The body then streams unopened (SPEC.md 9.5).
func (self *proverRun) sendBdat(ctx context.Context, headerBlock []byte, body []byte) (*sidecar.SmtpProofResult, error) {
	command := literalBdatPrefix + strconv.FormatUint(self.preamble.messageByteCount, 10) + literalBdatSuffix
	commandRecord, err := self.seal([]byte(command))
	if err != nil {
		return nil, err
	}
	headerRecord, err := self.seal(headerBlock)
	if err != nil {
		return nil, err
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
	opened := []*tlsSealedRecord{commandRecord, headerRecord, quitRecord}
	plaintexts := [][]byte{
		self.opened(commandRecord, command),
		self.opened(headerRecord, string(headerBlock)),
		self.opened(quitRecord, literalQuit),
	}
	if err := self.prove(ctx, partModeBdat, true, opened, quitRecord.seq, plaintexts); err != nil {
		return nil, err
	}
	for _, record := range append([]*tlsSealedRecord{commandRecord, headerRecord}, bodyRecords...) {
		if err := self.client.writeSealed(record); err != nil {
			return nil, err
		}
	}
	return self.finish(ctx, partModeBdat, quitRecord)
}

// Splits content into runs of whole lines of at most limit octets each. A line longer than the
// limit is its own run: RFC 5322's 998 octets keeps that within any sane limit.
func splitLines(content []byte, limit int) [][]byte {
	var runs [][]byte
	for 0 < len(content) {
		end := 0
		for {
			next := bytes.Index(content[end:], []byte(literalCrlf))
			if next < 0 {
				end = len(content)
				break
			}
			lineEnd := end + next + len(literalCrlf)
			if limit < lineEnd && 0 < end {
				break
			}
			end = lineEnd
			if end == len(content) {
				break
			}
		}
		runs = append(runs, content[:end])
		content = content[end:]
	}
	return runs
}

// DATA opens every octet, in parts the sidecar sizes to prove within the MX's timeout (D-SMTP-20).
func (self *proverRun) sendData(ctx context.Context, headerBlock []byte, body []byte) (*sidecar.SmtpProofResult, error) {
	runs := splitLines(body, min(self.settings.DataPartBytes, self.settings.MaxRecordContentBytes))
	// pi3 holds the header block and the first body run; each later part one run; the last part also
	// ends the message. A message of one record still ends in pi3.
	contents := [][]byte{headerBlock}
	if 0 < len(runs) {
		contents = append(contents, runs[0])
		runs = runs[1:]
	}
	for {
		last := len(runs) == 0
		var sealed []*tlsSealedRecord
		var plaintexts [][]byte
		for _, content := range contents {
			record, err := self.seal(content)
			if err != nil {
				return nil, err
			}
			sealed = append(sealed, record)
			plaintexts = append(plaintexts, self.opened(record, string(content)))
		}
		var quitRecord *tlsSealedRecord
		var endRecord *tlsSealedRecord
		if last {
			var err error
			if endRecord, err = self.seal([]byte(literalEndMark)); err != nil {
				return nil, err
			}
			if quitRecord, err = self.seal([]byte(literalQuit)); err != nil {
				return nil, err
			}
			sealed = append(sealed, endRecord, quitRecord)
			plaintexts = append(plaintexts, self.opened(endRecord, literalEndMark), self.opened(quitRecord, literalQuit))
		}
		if err := self.prove(ctx, partModeData, last, sealed, sealed[len(sealed)-1].seq, plaintexts); err != nil {
			return nil, err
		}
		if last {
			for _, record := range sealed[:len(sealed)-1] {
				if err := self.client.writeSealed(record); err != nil {
					return nil, err
				}
			}
			return self.finish(ctx, partModeData, quitRecord)
		}
		for _, record := range sealed {
			if err := self.client.writeSealed(record); err != nil {
				return nil, err
			}
		}
		contents = [][]byte{runs[0]}
		runs = runs[1:]
	}
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
// A ticket arriving meanwhile holds this part's message records at the edge (E3 step 5), so the part
// is proven again over it, which is the only way a late ticket gets past that hold.
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
		if event.err != nil {
			return nil, event.err
		}
		record := event.record
		plaintext, err := self.plaintextOf(record)
		if err != nil {
			return nil, err
		}
		self.records = append(self.records, &proverServerRecord{
			public:    &partRecord{seq: record.seq, raw: record.raw},
			plaintext: plaintext,
		})
		switch record.recordType {
		case tlsRecordApplicationData:
			self.stream = append(self.stream, record.content...)
		case tlsRecordHandshake:
			if len(record.content) == 0 || record.content[0] != tlsHandshakeNewSessionTicket {
				return nil, errors.New("smtpproof: MX sent a handshake record other than a ticket")
			}
			if self.lastPart != nil && self.lastPart.Mode != partModeNone && 3 <= self.lastPart.Index {
				if err := self.proveAgain(ctx); err != nil {
					return nil, err
				}
			}
		default:
			return nil, fmt.Errorf("smtpproof: MX sent a record of type %d", record.recordType)
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

// Checks and proves a part over the given records, then submits it. The server records it adds are
// every one received since the previous part.
func (self *proverRun) prove(ctx context.Context, mode uint32, last bool, sealed []*tlsSealedRecord, lastRecord uint64, plaintexts [][]byte) error {
	raws := make([][]byte, 0, len(sealed))
	for _, record := range sealed {
		raws = append(raws, record.raw)
	}
	part := &sidecar.SmtpProofPart{
		SendId:            self.job.SendId,
		Index:             self.nextPart,
		Mode:              mode,
		FirstRecord:       sealed[0].seq,
		LastRecord:        lastRecord,
		Last:              last,
		ServerRecordCount: uint64(len(self.records)),
		Records:           raws,
	}
	if err := self.proveAndSubmit(ctx, part, self.covered, sealed, plaintexts); err != nil {
		return err
	}
	self.lastPrior = self.covered
	self.covered = part.ServerRecordCount
	self.lastPart = part
	self.lastOpen = plaintexts
	self.nextPart += 1
	return nil
}

// Proves the latest part again over every server record received since, which replaces it at the
// edge. Its client records are unchanged.
func (self *proverRun) proveAgain(ctx context.Context) error {
	part := *self.lastPart
	part.ServerRecordCount = uint64(len(self.records))
	sealed := make([]*tlsSealedRecord, 0, len(part.Records))
	for i, raw := range part.Records {
		seq := part.FirstRecord + uint64(i)
		if part.Mode == partModeBdat && i == len(part.Records)-1 {
			seq = part.LastRecord
		}
		sealed = append(sealed, &tlsSealedRecord{seq: seq, raw: raw})
	}
	if err := self.proveAndSubmit(ctx, &part, self.lastPrior, sealed, self.lastOpen); err != nil {
		return err
	}
	self.covered = part.ServerRecordCount
	self.lastPart = &part
	return nil
}

func (self *proverRun) proveAndSubmit(ctx context.Context, part *sidecar.SmtpProofPart, priorCount uint64, sealed []*tlsSealedRecord, plaintexts [][]byte) error {
	statement := &partStatement{
		session:                   self.session,
		index:                     part.Index,
		mode:                      part.Mode,
		firstRecord:               part.FirstRecord,
		lastRecord:                part.LastRecord,
		last:                      part.Last,
		previousServerRecordCount: priorCount,
		serverRecordCount:         part.ServerRecordCount,
	}
	for _, record := range sealed {
		statement.clientRecords = append(statement.clientRecords, &partRecord{seq: record.seq, raw: record.raw})
	}
	witness := &partWitness{
		handshakeSecret:  self.result.handshakeSecret,
		clientKey:        self.result.clientKey,
		clientIv:         self.result.clientIv,
		serverKey:        self.result.serverKey,
		serverIv:         self.result.serverIv,
		clientPlaintexts: plaintexts,
	}
	if self.result.version == tlsVersion12 {
		witness.masterSecret = self.result.masterSecret
	}
	for _, record := range self.records[priorCount:part.ServerRecordCount] {
		statement.serverRecords = append(statement.serverRecords, record.public)
		witness.serverPlaintexts = append(witness.serverPlaintexts, record.plaintext)
	}
	if failures := relationCheckPart(statement, witness); 0 < len(failures) {
		return fmt.Errorf("smtpproof: part %d does not satisfy the relation: %w", part.Index, failures[0])
	}
	proof, err := self.backend.provePart(ctx, statement, witness)
	if err != nil {
		return err
	}
	part.Proof = proof
	return self.channel.SubmitPart(ctx, part)
}
