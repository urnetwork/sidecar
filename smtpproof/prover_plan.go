package smtpproof

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/urnetwork/sidecar"
)

// The planner in proverRun (DESIGN-DETAILS 3.2.4, 3.2.6). A send's parts follow its size, planned as the
// connection goes, since replies decide the next step:
//
//	after the handshake       part 1 (key): EHLO
//	after the EHLO reply      part 2 (env): the EHLO reply's records; envelope group 1
//	after group j's replies   while commands remain, an env part: those replies; group j+1
//	after the last group's    every message record sealed in order, every scan state computed and every
//	replies                   blind drawn; the msg part covers the replies when its shape holds them, else
//	                          env parts that open no client record cover them first; then msg, hdr and
//	                          body parts, proven up to ProveConcurrency at once and submitted in index order
//	a late server record      an env part that opens no client record, submitted next, covers it
//
// Every choice that shapes a part is a function of public values, the lengths the edge sees and the reply
// counts the parts name, so the part structure tells the edge nothing it does not see already (3.3, K3).
// The one exception is where a run of server records is cut between parts that open no client record: at a
// record's end that is also a reply's end, which the edge learns of an MX that spread one group's replies
// over records too many for one part.

// The keystream blocks one record of contentBytes takes, its own from its first octet: TLS 1.3's inner type
// octet takes one more octet, and a ChaCha20 block holds 64 octets where an AES-128-GCM one holds 16.
func recordBlocks(family ShapeFamily, version uint16, contentBytes int) int {
	blockBytes := 16
	if family == ShapeFamilyChacha20 {
		blockBytes = 64
	}
	if version == tlsVersion13 {
		contentBytes += tlsInnerTypeBytes
	}
	return (contentBytes + blockBytes - 1) / blockBytes
}

// How many of the commands left go in the next envelope group (DESIGN-DETAILS 3.2.4's group): in order,
// while their records fit the env shape's client blocks, while their replies at estimate octets each, each
// a record of its own, fit its server blocks, and up to groupMax when that is positive. 0 when no command
// fits.
func envelopeGroupSize(shape *ShapeSettings, version uint16, commandByteCounts []int, estimate int, groupMax int) int {
	replyBlocks := recordBlocks(shape.Family, version, estimate)
	clientBlocks := 0
	count := 0
	for _, commandBytes := range commandByteCounts {
		clientBlocks += recordBlocks(shape.Family, version, commandBytes)
		switch {
		case shape.ClientBlocks < clientBlocks:
		case shape.ServerBlocks < (count+1)*replyBlocks:
		case 0 < groupMax && groupMax <= count:
		default:
			count += 1
			continue
		}
		break
	}
	return count
}

// The most commands a group holds: the smaller of the settings' bound and the job's, where each is set.
func envelopeGroupMax(settingsMax int, jobMax int) int {
	switch {
	case settingsMax <= 0:
		return max(jobMax, 0)
	case jobMax <= 0:
		return settingsMax
	}
	return min(settingsMax, jobMax)
}

// The content octets of a server record, from its length alone: 1.3 less the inner type octet.
func serverContentBytes(version uint16, raw []byte) int {
	ciphertext, err := recordCiphertext(version, raw)
	if err != nil {
		return 0
	}
	if version == tlsVersion13 {
		return max(len(ciphertext)-tlsInnerTypeBytes, 0)
	}
	return len(ciphertext)
}

// The estimate the group after takes (DESIGN-DETAILS 3.2.4): the mean reply of the records that hold the
// group before's replies, rounded up, plus the margin. With no reply to go by, the first group's.
func replyEstimate(settings *ProverSettings, version uint16, records []*partRecord, replyCount int) int {
	if replyCount <= 0 {
		return settings.ReplyEstimateByteCount
	}
	contentBytes := 0
	for _, record := range records {
		contentBytes += serverContentBytes(version, record.raw)
	}
	return (contentBytes+replyCount-1)/replyCount + settings.ReplyMarginByteCount
}

// Where a run of server records may end a part: for each count of the run's first records, the whole
// replies they hold when they end at a reply's end, else -1. A part covers whole replies (Z8), and the run
// starts at a reply's start, where the part before ended. A ticket holds no reply.
func replyCuts(version uint16, plaintexts [][]byte) []int {
	cuts := make([]int, len(plaintexts)+1)
	for count := 1; count <= len(plaintexts); count += 1 {
		cuts[count] = -1
		stream, err := serverContents(version, plaintexts[:count])
		if err != nil {
			continue
		}
		if replies, ok := wholeReplyCount(stream); ok {
			cuts[count] = replies
		}
	}
	return cuts
}

// The replies a stream holds, and whether it ends where a reply does.
func wholeReplyCount(stream []byte) (int, bool) {
	replies := 0
	offset := 0
	for offset < len(stream) {
		end := -1
		for i := offset; i+1 < len(stream); i += 1 {
			if stream[i] == '\r' && stream[i+1] == '\n' {
				end = i
				break
			}
		}
		if end < 0 {
			return replies, false
		}
		line := stream[offset:end]
		offset = end + len(literalCrlf)
		if len(line) <= 3 || line[3] != '-' {
			replies += 1
		} else if offset == len(stream) {
			return replies, false
		}
	}
	return replies, true
}

// The envelope in groups (DESIGN-DETAILS 3.2.4), from part 2 on. Each part covers the replies to the group
// before and opens the next; part 2 covers the EHLO reply. Where the MX offers PIPELINING a group goes at
// once, otherwise command by command under its part. A result ends the send here: a refused command, or a
// group's replies no part can hold.
func (self *proverRun) sendEnvelope(ctx context.Context, commands []string, pipelining bool) (*sidecar.SmtpProofResult, error) {
	version := self.result.version
	shape := self.settings.Proof.shape(ShapeKindEnvelope, suiteFamily(self.result.suite), 0)
	if shape == nil {
		return nil, errors.New("smtpproof: no env shape of this suite's family")
	}
	groupMax := envelopeGroupMax(self.settings.EnvelopeGroupMaxCount, self.job.EnvelopeGroupMaxCount)
	estimate := self.settings.ReplyEstimateByteCount
	// part 2 covers the EHLO reply, one reply
	replyCount := uint32(1)
	for sent := 0; sent < len(commands); {
		commandByteCounts := make([]int, 0, len(commands)-sent)
		for _, command := range commands[sent:] {
			commandByteCounts = append(commandByteCounts, len(command))
		}
		size := envelopeGroupSize(shape, version, commandByteCounts, estimate, groupMax)
		if size == 0 {
			return nil, fmt.Errorf("smtpproof: envelope command %d fits no env part", sent)
		}
		part := &proverPart{replyCount: replyCount}
		for _, command := range commands[sent : sent+size] {
			record, err := self.seal([]byte(command))
			if err != nil {
				return nil, err
			}
			part.sealed = append(part.sealed, record)
			part.plaintexts = append(part.plaintexts, self.opened(record, command))
		}
		through := uint64(len(self.records))
		// part 2 proves the EHLO reply alone and opens MAIL (3.2.5 step 9), so a reply no env shape holds
		// ends the send before MAIL; a later part may leave the replies to parts before it
		if self.nextPart != 2 {
			result, err := self.coverBefore(ctx, part, through)
			if result != nil || err != nil {
				return result, err
			}
		}
		if err := self.prove(ctx, part, through); err != nil {
			return nil, err
		}
		groupFrom := self.covered
		refused, err := self.sendGroup(ctx, part.sealed, pipelining, sent, len(commands))
		if err != nil {
			return nil, err
		}
		if refused != nil {
			return &sidecar.SmtpProofResult{Mode: self.mode, RefusedCode: refused.code}, nil
		}
		sent += size
		replyCount = uint32(size)
		publics := make([]*partRecord, 0, len(self.records)-int(groupFrom))
		for _, record := range self.records[groupFrom:] {
			publics = append(publics, record.public)
		}
		estimate = replyEstimate(self.settings, version, publics, size)
	}
	// the message's first part, or env parts before it, cover the last group's replies
	self.envelopeReplyCount = replyCount
	self.envelopeEnd = uint64(len(self.records))
	return nil, nil
}

// Writes a group's records and reads its replies, and returns the first that refuses. Without PIPELINING
// each command waits for the reply before it, and a refusal sends no more (§14.4). first is the group's
// first command's place among count commands, MAIL being 0.
func (self *proverRun) sendGroup(ctx context.Context, records []*tlsSealedRecord, pipelining bool, first int, count int) (*smtpReply, error) {
	// only DATA's reply is 354, and DATA ends the envelope in DATA mode; a test's adversary goes on past a
	// refusal
	refuses := func(command int, reply *smtpReply) bool {
		if adversary := self.settings.testAdversary; adversary != nil && adversary.ignoreRefusals {
			return false
		}
		return smtpReplyRefuses(reply, self.mode == partModeData && command == count-1)
	}
	if !pipelining {
		for i, record := range records {
			if err := self.client.writeSealed(record); err != nil {
				return nil, err
			}
			replies, err := self.awaitReplies(ctx, 1)
			if err != nil {
				return nil, err
			}
			self.noteReply(first+i, replies[0])
			if refuses(first+i, replies[0]) {
				return replies[0], nil
			}
		}
		return nil, nil
	}
	for _, record := range records {
		if err := self.client.writeSealed(record); err != nil {
			return nil, err
		}
	}
	replies, err := self.awaitReplies(ctx, len(records))
	if err != nil {
		return nil, err
	}
	var refused *smtpReply
	for i, reply := range replies {
		self.noteReply(first+i, reply)
		if refused == nil && refuses(first+i, reply) {
			refused = reply
		}
	}
	return refused, nil
}

// Keeps a reply's code for the result: every reply inside TLS in order, and each RCPT's beside its
// recipient. command is the envelope command's place, MAIL being 0, or -1 for a reply to none of them.
func (self *proverRun) noteReply(command int, reply *smtpReply) {
	code, err := strconv.ParseUint(reply.code, 10, 32)
	if err != nil {
		code = 0
	}
	self.replyCodes = append(self.replyCodes, uint32(code))
	recipientCount := len(self.job.RecipientLocals)
	if 1 <= command && command <= recipientCount {
		if self.recipientReplyCodes == nil {
			self.recipientReplyCodes = make([]uint32, recipientCount)
		}
		self.recipientReplyCodes[command-1] = uint32(code)
	}
}

// Leaves part to cover the server records from the last covered to through: when part's shape holds them
// all, part covers them; else env parts that open no client record cover them first, and part covers none
// and names no reply (DESIGN-DETAILS 3.2.4). EnvelopeRetry when a record fits no part, which ends the send
// before any message record (3.5).
func (self *proverRun) coverBefore(ctx context.Context, part *proverPart, through uint64) (*sidecar.SmtpProofResult, error) {
	statement, _ := self.statementOf(part, self.gateState(), through)
	if _, err := partShapeFor(self.settings.Proof, statement); err == nil {
		return nil, nil
	}
	covered, err := self.coverServerRecords(ctx, through)
	if err != nil {
		return nil, err
	}
	if !covered {
		return &sidecar.SmtpProofResult{Mode: self.mode, EnvelopeRetry: true}, nil
	}
	part.replyCount = 0
	return nil, nil
}

// Covers the server records up to through by env parts that open no client record, each the longest run
// that ends at a reply's end and that the shape holds. False when a run of one record fits no part.
func (self *proverRun) coverServerRecords(ctx context.Context, through uint64) (bool, error) {
	for self.covered < through {
		start := self.covered
		plaintexts := make([][]byte, 0, through-start)
		for _, record := range self.records[start:through] {
			plaintexts = append(plaintexts, record.plaintext)
		}
		cuts := replyCuts(self.result.version, plaintexts)
		var best *proverPart
		bestEnd := start
		for count := 1; count <= len(plaintexts); count += 1 {
			if cuts[count] < 0 {
				continue
			}
			candidate := &proverPart{replyCount: uint32(cuts[count])}
			statement, _ := self.statementOf(candidate, self.gateState(), start+uint64(count))
			if _, err := partShapeFor(self.settings.Proof, statement); err != nil {
				// a longer run only takes more blocks
				break
			}
			best = candidate
			bestEnd = start + uint64(count)
		}
		if best == nil {
			return false, nil
		}
		if err := self.prove(ctx, best, bestEnd); err != nil {
			return false, err
		}
	}
	return true, nil
}

// The message (DESIGN-DETAILS 3.2.6): its records sealed in order, the last group's replies covered, then
// the msg, hdr and body parts proven up to ProveConcurrency at once and submitted in index order, each
// part's records written once its own answer is OK. A server record read meanwhile is covered by an env
// part that opens no client record, submitted next, and a reply then is the MX ending the send.
func (self *proverRun) sendMessage(ctx context.Context, headerBlock []byte, body []byte) (*sidecar.SmtpProofResult, error) {
	parts, quitRecord, err := self.sealMessage(headerBlock, body)
	if err != nil {
		return nil, err
	}
	message := parts[0]
	message.replyCount = self.envelopeReplyCount
	result, err := self.coverBefore(ctx, message, self.envelopeEnd)
	if result != nil || err != nil {
		return result, err
	}

	// each part's statement as the gate will hold it, no later part covering a server record before it:
	// no statement of these kinds holds its index, and only the msg part covers server records
	state := self.gateState()
	plannedParts := make([]*proverPlannedPart, 0, len(parts))
	serverRecordCount := self.envelopeEnd
	for _, part := range parts {
		statement, wire := self.statementOf(part, state, serverRecordCount)
		plannedParts = append(plannedParts, &proverPlannedPart{
			spec:      part,
			statement: statement,
			wire:      wire,
			witness:   self.witnessOf(part, statement),
			done:      make(chan struct{}),
		})
		state.index += 1
		state.covered = serverRecordCount
		state.repliesProven += part.replyCount
		if part.headerRecordCount != 0 {
			state.headerRecordCount = part.headerRecordCount
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	slots := make(chan struct{}, max(self.settings.ProveConcurrency, 1))
	go func() {
		for i, planned := range plannedParts {
			select {
			case slots <- struct{}{}:
			case <-runCtx.Done():
				for _, unstarted := range plannedParts[i:] {
					unstarted.err = runCtx.Err()
					close(unstarted.done)
				}
				return
			}
			go func() {
				defer func() {
					<-slots
				}()
				defer close(planned.done)
				planned.proof, planned.err = self.proveStatement(runCtx, planned.statement, planned.witness)
			}()
		}
	}()

	for i, planned := range plannedParts {
		if 0 < i {
			reply, err := self.drainServerRecords()
			if err != nil {
				return nil, err
			}
			if reply != nil {
				self.noteReply(-1, reply)
				return &sidecar.SmtpProofResult{Mode: self.mode, RefusedCode: reply.code}, nil
			}
			if err := self.proveLateRecords(ctx); err != nil {
				return nil, err
			}
		}
		select {
		case <-planned.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if planned.err != nil {
			return nil, planned.err
		}
		// a part takes its index, and covers what was covered before it, as it goes in
		wire := planned.wire
		wire.Index = self.nextPart
		wire.Proof = planned.proof
		if 0 < i {
			wire.ServerRecordCount = self.covered
		}
		if err := self.submit(ctx, planned.spec, wire); err != nil {
			return nil, err
		}
		self.messageStarted = true
		for _, record := range planned.spec.writes {
			if err := self.client.writeSealed(record); err != nil {
				return nil, err
			}
		}
	}
	return self.finish(ctx, self.mode, quitRecord)
}

// A message part on its way: what the gate will hold it to, and its proof once made.
type proverPlannedPart struct {
	spec      *proverPart
	statement *partStatement
	wire      *sidecar.SmtpProofPart
	witness   *partWitness
	// Closed once the proof is made or failed.
	done  chan struct{}
	proof []byte
	err   error
}

// The message's records in sequence order and the parts that open them. BDAT: BDAT's command and header
// record 1 in the msg part, each later header record in a hdr part, the body cut at the record bound and
// streamed unopened after the last header record, and QUIT opened by the part of the last header record.
// DATA: header record 1 in the msg part, a hdr part each later one, a body part each body record cut at
// what the body shape holds, the last opening the end mark and QUIT; an empty body's last part opens those
// alone. Every carry is drawn here, in order. QUIT is returned beside the parts: it goes once the message's
// reply is read.
func (self *proverRun) sealMessage(headerBlock []byte, body []byte) ([]*proverPart, *tlsSealedRecord, error) {
	var commandRecord *tlsSealedRecord
	command := literalBdatPrefix + strconv.FormatUint(self.preamble.messageByteCount, 10) + literalBdatSuffix
	if self.mode == partModeBdat {
		record, err := self.seal([]byte(command))
		if err != nil {
			return nil, nil, err
		}
		commandRecord = record
	}
	contents, carries, err := self.headerRecords(headerBlock)
	if err != nil {
		return nil, nil, err
	}
	headerRecords := make([]*tlsSealedRecord, 0, len(contents))
	for _, content := range contents {
		record, err := self.seal(content)
		if err != nil {
			return nil, nil, err
		}
		headerRecords = append(headerRecords, record)
	}
	k := len(headerRecords)
	var parts []*proverPart
	for i, record := range headerRecords {
		part := &proverPart{
			sealed:        []*tlsSealedRecord{record},
			plaintexts:    [][]byte{self.opened(record, string(contents[i]))},
			carryOut:      carries[i].commitment,
			carryOutBlind: carries[i].blind,
			wireCarry:     true,
		}
		if i == 0 {
			part.headerRecordCount = uint32(k)
			if commandRecord != nil {
				part.sealed = append([]*tlsSealedRecord{commandRecord}, part.sealed...)
				part.plaintexts = append([][]byte{self.opened(commandRecord, command)}, part.plaintexts...)
			}
		} else {
			part.carryIn = carries[i-1].commitment
			part.carryInState = carries[i-1].state
			part.carryInBlind = carries[i-1].blind
		}
		part.writes = part.sealed
		parts = append(parts, part)
	}

	if self.mode == partModeBdat {
		var bodyRecords []*tlsSealedRecord
		recordBytes := self.settings.Proof.RecordContentMaxByteCount
		if recordBytes <= 0 {
			return nil, nil, errors.New("smtpproof: no record bound to cut the body at")
		}
		for offset := 0; offset < len(body); offset += recordBytes {
			record, err := self.seal(body[offset:min(offset+recordBytes, len(body))])
			if err != nil {
				return nil, nil, err
			}
			bodyRecords = append(bodyRecords, record)
		}
		quitRecord, err := self.seal([]byte(literalQuit))
		if err != nil {
			return nil, nil, err
		}
		// the body streams unopened under the last part, and QUIT waits for the chunk's reply
		last := parts[k-1]
		last.writes = append(append([]*tlsSealedRecord{}, last.sealed...), bodyRecords...)
		last.sealed = append(last.sealed, quitRecord)
		last.plaintexts = append(last.plaintexts, self.opened(quitRecord, literalQuit))
		last.last = true
		return parts, quitRecord, nil
	}

	recordBytes := self.bodyRecordBytes()
	if recordBytes <= 0 {
		return nil, nil, errors.New("smtpproof: no body shape holds a DATA body record")
	}
	var bodyContents [][]byte
	for offset := 0; offset < len(body); offset += recordBytes {
		bodyContents = append(bodyContents, body[offset:min(offset+recordBytes, len(body))])
	}
	// the body scans from the start again: the gate's carry after the header block's last record
	carry := proverStartCarry()
	for i := 0; i < len(bodyContents) || i == 0; i += 1 {
		last := len(bodyContents) <= i+1
		part := &proverPart{carryIn: carry.commitment, carryInState: carry.state, carryInBlind: carry.blind}
		if i < len(bodyContents) {
			record, err := self.seal(bodyContents[i])
			if err != nil {
				return nil, nil, err
			}
			state, err := scanBodyRecord(bodyContents[i], carry.state, last)
			if err != nil {
				// the relation refuses this body; the part that opens it says so
				state = 0
			}
			next, err := newProverCarry(state)
			if err != nil {
				return nil, nil, err
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
		part.writes = part.sealed
		if last {
			endRecord, err := self.seal([]byte(literalEndMark))
			if err != nil {
				return nil, nil, err
			}
			quitRecord, err := self.seal([]byte(literalQuit))
			if err != nil {
				return nil, nil, err
			}
			part.writes = append(append([]*tlsSealedRecord{}, part.sealed...), endRecord)
			part.sealed = append(part.sealed, endRecord, quitRecord)
			part.plaintexts = append(part.plaintexts, self.opened(endRecord, literalEndMark), self.opened(quitRecord, literalQuit))
			part.last = true
			parts = append(parts, part)
			return parts, quitRecord, nil
		}
		parts = append(parts, part)
	}
	return nil, nil, errors.New("smtpproof: a DATA send with no last part")
}
