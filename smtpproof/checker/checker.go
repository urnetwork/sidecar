package checker

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
)

// Check runs SPEC.md's checks over one connection: the preamble's forms, E1 and E2 over the handshake,
// E3 over the order of records and parts, and Z1 to Z9 over each part the edge would verify, against
// the witness at that part's event position. Like the edge, it stops at the first event where anything
// fails, and returns every check failing there, so a mutation that breaks one check names one check.
// An empty result is an honest connection.
func Check(transcript *Transcript, witnesses map[int]*PartWitness) []*Failure {
	return CheckWith(DefaultCheckSettings(), transcript, witnesses)
}

// The limits the checker reads a connection by (QD-702): protocol and format values, each set only by
// DefaultCheckSettings to the value SPEC.md and DESIGN-DETAILS 3.2.5 state, so a caller that changes one
// passes the whole.
type CheckSettings struct {
	// RFC 5321's: a local part, a domain and a label.
	LocalMaxByteCount  int
	DomainMaxByteCount int
	LabelMaxByteCount  int
	// DESIGN-DETAILS 3.2.5's: the records one part opens, the records a header block takes, and the
	// least a header record holds, the block's last and any other.
	PartRecordMaxCount           int
	HeaderRecordMaxCount         int
	HeaderRecordMinByteCount     int
	HeaderLastRecordMinByteCount int
}

// A fresh value each call.
func DefaultCheckSettings() *CheckSettings {
	return &CheckSettings{
		LocalMaxByteCount:            64,
		DomainMaxByteCount:           255,
		LabelMaxByteCount:            63,
		PartRecordMaxCount:           64,
		HeaderRecordMaxCount:         16,
		HeaderRecordMinByteCount:     128,
		HeaderLastRecordMinByteCount: 4,
	}
}

// Check under the given settings.
func CheckWith(settings *CheckSettings, transcript *Transcript, witnesses map[int]*PartWitness) []*Failure {
	run := &checkRun{settings: settings, transcript: transcript, witnesses: witnesses, shake: &handshake{preamble: transcript.Preamble}}
	if err := checkPreambleForms(settings, transcript.Preamble); err != nil {
		return []*Failure{{Check: "preamble", Reason: err.Error()}}
	}
	for i, event := range transcript.Events {
		run.event = i
		run.step(event)
		if 0 < len(run.failures) {
			break
		}
	}
	return run.failures
}

// One part the edge took, with what E3 worked out for it.
type acceptedPart struct {
	part  *Part
	event int
	// Each record's sequence number, what it holds, and the kind of part that makes it.
	seqs  []uint64
	roles []role
	kind  string
	// The server record count this part covers from, and the replies proven before it.
	previousCount uint64
	repliesProven uint32
	// k as this part's statement holds it, and the carries it opens and publishes.
	k        uint32
	carryIn  []byte
	carryOut []byte
	// What landing it adds to the edge's state.
	commands        uint32
	opensFirst      bool
	opensScan       bool
	opensLastHeader bool
	dataOctets      uint64
	// The header and body octets with this part's, once its relation holds.
	header []byte
	body   []byte
}

type checkRun struct {
	settings   *CheckSettings
	transcript *Transcript
	witnesses  map[int]*PartWitness
	shake      *handshake
	failures   []*Failure
	event      int

	firstSeq uint64
	// Application records in each direction, in order.
	clientRecords [][]byte
	serverRecords [][]byte
	closed        bool
	parts         []*acceptedPart
	// The edge's state over parts (DESIGN-DETAILS 3.2.5): the next record a part opens, the server
	// records covered, the replies proven and commands opened, the mode, k, the carry the next scan
	// opens and DATA's octets so far.
	nextRecord      uint64
	covered         uint64
	repliesProven   uint32
	commandsCovered uint32
	mode            uint32
	k               uint32
	carry           []byte
	dataOctets      uint64
	// The header block's records and DATA's body records opened so far, which the scans run over.
	header       []byte
	headerStarts int
	firstEnd     int
	body         []byte
	// E3's walk over client records: how many went, the chunk octets so far, and whether QUIT went.
	released    int
	chunkOctets uint64
	finished    bool
}

func (self *checkRun) fail(check string, part uint32, err error) {
	self.failures = append(self.failures, &Failure{Check: check, Event: self.event, Part: part, Reason: err.Error()})
}

func (self *checkRun) handshakeFailure(err error) {
	var e2 *e2Failure
	if errors.As(err, &e2) {
		self.fail("E2", 0, err)
		return
	}
	self.fail("E1", 0, err)
}

func (self *checkRun) step(event *Event) {
	shake := self.shake
	switch {
	case event.ServerClosed:
		self.closed = true
	case event.Shts != nil:
		if err := shake.disclose(event.Shts); err != nil {
			self.fail("E2", 0, err)
			return
		}
		if err := shake.finishFlight13(); err != nil {
			self.fail("E1", 0, err)
			return
		}
		self.adoptAfterFlight()
	case event.ClientRecord != nil:
		if shake.phase != phaseApplication {
			if err := shake.clientRecord(event.ClientRecord); err != nil {
				self.handshakeFailure(err)
			}
			self.adoptAfterFlight()
			return
		}
		if self.finished {
			self.fail("E3", 0, errors.New("a client record after the final QUIT"))
			return
		}
		recordType, version, _, err := splitRecord(event.ClientRecord)
		if err != nil || recordType != recordApplicationData || version != versionTls12 {
			self.fail("E1", 0, errors.New("a client record after the handshake that is not application_data at 0303"))
			return
		}
		self.clientRecords = append(self.clientRecords, event.ClientRecord)
		self.release()
	case event.ServerRecord != nil:
		if shake.phase != phaseApplication {
			if err := shake.serverRecord(event.ServerRecord); err != nil {
				self.handshakeFailure(err)
			}
			self.adoptAfterFlight()
			return
		}
		recordType, _, _, err := splitRecord(event.ServerRecord)
		switch {
		case err != nil:
			self.fail("E1", 0, err)
		case recordType == recordApplicationData:
			self.serverRecords = append(self.serverRecords, event.ServerRecord)
		case recordType == recordAlert && shake.version == versionTls12:
			self.closed = true
		default:
			self.fail("E1", 0, fmt.Errorf("a server record of type %d after the handshake", recordType))
		}
	case event.Part != nil:
		// once the MX has closed, an outstanding part is moot
		if self.closed {
			return
		}
		accepted, err := self.acceptPart(event.Part)
		if err != nil {
			self.fail("E3", event.Part.Index, err)
			return
		}
		if accepted == nil {
			return
		}
		self.failures = append(self.failures, self.relation(accepted)...)
		if len(self.failures) == 0 {
			self.commit(accepted)
			self.release()
		}
	}
}

// Server records the 1.3 flight check found after the server's Finished are application records.
func (self *checkRun) adoptAfterFlight() {
	shake := self.shake
	if shake.flightChecked && 0 < len(shake.afterFlight) {
		self.serverRecords = append(self.serverRecords, shake.afterFlight...)
		shake.afterFlight = nil
	}
	if shake.phase == phaseApplication && shake.version == versionTls12 && self.firstSeq == 0 {
		// the client's Finished took sequence number 0 in each direction
		self.firstSeq = 1
		self.nextRecord = 1
	}
}

// Whether the session's inputs exist: 1.3's once E2 has passed, 1.2's once the server's Finished is in.
func (self *checkRun) sessionReady() bool {
	if self.shake.version == versionTls13 {
		return self.shake.flightChecked
	}
	return self.shake.phase == phaseApplication
}

// Whether two parts are one part resent: every field the same.
func samePart(a *Part, b *Part) bool {
	return a.Index == b.Index && a.Mode == b.Mode && a.FirstRecord == b.FirstRecord && a.LastRecord == b.LastRecord &&
		a.Last == b.Last && a.ServerRecordCount == b.ServerRecordCount && slices.EqualFunc(a.Records, b.Records, bytes.Equal) &&
		bytes.Equal(a.KeyCommitment, b.KeyCommitment) && a.ReplyCount == b.ReplyCount && a.HeaderRecordCount == b.HeaderRecordCount &&
		bytes.Equal(a.Carry, b.Carry)
}

// E3's rules for a part (DESIGN-DETAILS 3.2.5 steps 2 to 11): its order, its client and server ranges,
// its mode, the roles of what it opens and the kind they make, its replies against the commands opened,
// its lengths and its carry. It returns nil and no error for an exact resend of the latest part, which
// changes nothing; a part never replaces another.
func (self *checkRun) acceptPart(part *Part) (*acceptedPart, error) {
	preamble := self.transcript.Preamble
	if !self.sessionReady() {
		return nil, errors.New("a part before the handshake's inputs exist")
	}
	switch {
	case part.Index != 0 && int(part.Index) == len(self.parts):
		if samePart(part, self.parts[len(self.parts)-1].part) {
			return nil, nil
		}
		return nil, errors.New("a verified part sent again changed")
	case int(part.Index) != len(self.parts)+1:
		return nil, fmt.Errorf("part %d after part %d", part.Index, len(self.parts))
	}
	finished := 0 < len(self.parts) && self.parts[len(self.parts)-1].part.Last
	if part.Index == 1 {
		if len(part.Records) != 1 || part.FirstRecord != self.firstSeq || part.LastRecord != self.firstSeq || part.Mode != 0 ||
			part.ServerRecordCount != 0 || part.ReplyCount != 0 || part.HeaderRecordCount != 0 || len(part.Carry) != 0 || part.Last {
			return nil, errors.New("the key part opens EHLO alone and covers and names nothing else")
		}
		if _, err := parseKeyCommitment(part.KeyCommitment); err != nil {
			return nil, err
		}
	} else if len(part.KeyCommitment) != 0 {
		return nil, errors.New("a part after the key part carries a key commitment")
	}
	if part.FirstRecord != self.nextRecord {
		return nil, fmt.Errorf("first_record %d, want %d", part.FirstRecord, self.nextRecord)
	}
	accepted := &acceptedPart{part: part, event: self.event, previousCount: self.covered, repliesProven: self.repliesProven, dataOctets: self.dataOctets}
	if len(part.Records) == 0 {
		if part.LastRecord+1 != part.FirstRecord || part.Last {
			return nil, errors.New("a part that opens nothing has last_record one before first_record, and is not the last")
		}
	} else {
		if finished {
			return nil, errors.New("a part that opens a record after the last")
		}
		if self.settings.PartRecordMaxCount < len(part.Records) {
			return nil, fmt.Errorf("more than %d records in one part", self.settings.PartRecordMaxCount)
		}
		for i, record := range part.Records {
			recordType, _, payload, err := splitRecord(record)
			if err != nil || recordType != recordApplicationData {
				return nil, errors.New("a part's record is not a whole application_data record")
			}
			minimum := tagBytes + 1
			if self.shake.version == versionTls12 {
				minimum = explicitNonceBytes + tagBytes
			}
			if len(payload) < minimum {
				return nil, errors.New("a part's record holds no content")
			}
			seq := part.FirstRecord + uint64(i)
			// BDAT's last part opens QUIT at its own number, past the unopened body
			if part.Mode == modeBdat && part.Last && i == len(part.Records)-1 {
				if part.LastRecord < seq {
					return nil, errors.New("QUIT before the part's other records")
				}
				seq = part.LastRecord
			}
			accepted.seqs = append(accepted.seqs, seq)
		}
		if accepted.seqs[len(accepted.seqs)-1] != part.LastRecord {
			return nil, errors.New("the part's records do not reach last_record")
		}
	}
	switch {
	case part.ServerRecordCount < self.covered:
		return nil, errors.New("server_record_count fell")
	case uint64(len(self.serverRecords)) < part.ServerRecordCount:
		return nil, errors.New("server_record_count passes what was relayed")
	case len(part.Records) == 0 && part.ServerRecordCount == self.covered:
		return nil, errors.New("a part that opens nothing covers no new server record")
	case part.Index == 2 && part.Mode != modeBdat && part.Mode != modeData:
		return nil, fmt.Errorf("mode %d", part.Mode)
	case 2 < part.Index && part.Mode != self.mode:
		return nil, errors.New("the mode changed after part 2")
	}

	// roles and kind, with k as the part that opens the header block's first record names it
	recipients := uint64(preamble.RecipientCount)
	headerFirst := self.firstSeq + 3 + recipients
	accepted.k = self.k
	for _, seq := range accepted.seqs {
		if 1 < part.Index && seq == headerFirst {
			accepted.opensFirst = true
		}
	}
	switch {
	case accepted.opensFirst && (part.HeaderRecordCount < 1 || uint32(self.settings.HeaderRecordMaxCount) < part.HeaderRecordCount):
		return nil, fmt.Errorf("header_record_count %d", part.HeaderRecordCount)
	case !accepted.opensFirst && part.HeaderRecordCount != 0:
		return nil, errors.New("header_record_count away from the header block's first record")
	case accepted.opensFirst:
		accepted.k = part.HeaderRecordCount
	}
	roles, kind, err := partShape(preamble, self.shake.version, part, accepted.seqs, accepted.k)
	if err != nil {
		return nil, err
	}
	accepted.roles = roles
	accepted.kind = kind

	// replies, against the commands opened and not yet answered
	opensFirstMessage := false
	for i, r := range roles {
		switch r {
		case roleEhlo, roleMail, roleRcpt, roleData:
			accepted.commands += 1
		case roleBdat:
			opensFirstMessage = true
		case roleHeader:
			accepted.opensScan = true
			if accepted.seqs[i] == headerFirst && part.Mode == modeData {
				opensFirstMessage = true
			}
			if accepted.seqs[i] == headerFirst+uint64(accepted.k)-1 {
				accepted.opensLastHeader = true
			}
		case roleBody:
			accepted.opensScan = true
		}
	}
	coversMore := self.covered < part.ServerRecordCount
	switch {
	case part.Index == 1:
	case part.Index == 2:
		if part.ReplyCount != 1 || !coversMore || roles[0] != roleMail {
			return nil, errors.New("part 2 proves the EHLO reply as one reply and opens MAIL")
		}
	case self.commandsCovered-self.repliesProven < part.ReplyCount:
		return nil, errors.New("more replies than commands awaiting them")
	case !coversMore && part.ReplyCount != 0:
		return nil, errors.New("replies with no new server record")
	}
	if opensFirstMessage {
		want := 2 + recipients
		if part.Mode == modeData {
			want += 1
		}
		if uint64(self.repliesProven)+uint64(part.ReplyCount) != want {
			return nil, errors.New("the first message record before the envelope's replies are proven")
		}
	}

	// lengths: each record a template can fill, header records their least, DATA's count
	for i, r := range roles {
		content := self.contentBytes(part.Records[i])
		if !templateFits(self.settings, r, preamble, content) {
			return nil, fmt.Errorf("no template of record %d's length", accepted.seqs[i])
		}
		switch r {
		case roleHeader:
			least := self.settings.HeaderRecordMinByteCount
			if accepted.seqs[i] == headerFirst+uint64(accepted.k)-1 {
				least = self.settings.HeaderLastRecordMinByteCount
			}
			if content < least {
				return nil, fmt.Errorf("a header record of %d octets", content)
			}
			if part.Mode == modeData {
				accepted.dataOctets += uint64(content)
			}
		case roleBody:
			if content <= 0 {
				return nil, errors.New("an empty body record")
			}
			accepted.dataOctets += uint64(content)
		}
	}
	if preamble.MessageByteCount < accepted.dataOctets {
		return nil, errors.New("DATA octets pass the declared count")
	}
	if part.Mode == modeData && part.Last && accepted.dataOctets != preamble.MessageByteCount {
		return nil, errors.New("the last DATA part leaves the declared count short")
	}

	// the carry: on a part that opens a header or body record, and no other
	if accepted.opensScan {
		if _, err := parseCommitment(part.Carry); err != nil {
			return nil, err
		}
	} else if len(part.Carry) != 0 {
		return nil, errors.New("a carry on a part that opens no header or body record")
	}
	if kind == "hdr" || kind == "body" {
		accepted.carryIn = self.carry
	}
	accepted.carryOut = part.Carry
	if kind == "body" && !accepted.opensScan {
		// an empty body's end mark: the state is as it was
		accepted.carryOut = self.carry
	}
	return accepted, nil
}

// The content length of an opened record of this connection.
func (self *checkRun) contentBytes(record []byte) int {
	if self.shake.version == versionTls12 {
		return len(record) - recordHeaderBytes - explicitNonceBytes - tagBytes
	}
	return len(record) - recordHeaderBytes - tagBytes - 1
}

// Z1 to Z9 over one part and its witness, against the statement the edge's state gives it.
func (self *checkRun) relation(accepted *acceptedPart) []*Failure {
	part := accepted.part
	witness := self.witnesses[accepted.event]
	var failures []*Failure
	fail := func(check string, err error) {
		failures = append(failures, &Failure{Check: check, Event: accepted.event, Part: part.Index, Reason: err.Error()})
	}
	if witness == nil {
		fail("Z1", errors.New("no witness"))
		return failures
	}
	shake := self.shake
	preamble := self.transcript.Preamble
	serverRecords := self.serverRecords[accepted.previousCount:part.ServerRecordCount]

	// Z1: the key part derives both directions and commits to them; every part's keys open the key
	// part's C (DESIGN-DETAILS 3.2.3)
	keyCommitment := part.KeyCommitment
	if part.Index != 1 {
		keyCommitment = self.parts[0].part.KeyCommitment
	}
	if part.Index == 1 {
		if err := self.checkKeys(witness); err != nil {
			fail("Z1", err)
		}
	}
	if err := checkKeyCommitment(witness, keyCommitment); err != nil {
		fail("Z1", err)
	}

	// Z2, client and server
	if len(witness.ClientPlaintexts) != len(part.Records) || len(witness.ServerPlaintexts) != len(serverRecords) {
		fail("Z2", errors.New("the witness holds another count of plaintexts"))
		return failures
	}
	for i, record := range part.Records {
		opened, err := openRecord(shake.version, shake.suite, witness.ClientKey, witness.ClientIv, accepted.seqs[i], record)
		if err != nil || !bytes.Equal(opened, witness.ClientPlaintexts[i]) {
			fail("Z2", fmt.Errorf("client record %d is not its plaintext under the witness key", accepted.seqs[i]))
			break
		}
	}
	for i, record := range serverRecords {
		seq := self.firstSeq + accepted.previousCount + uint64(i)
		opened, err := openRecord(shake.version, shake.suite, witness.ServerKey, witness.ServerIv, seq, record)
		if err != nil || !bytes.Equal(opened, witness.ServerPlaintexts[i]) {
			fail("Z2", fmt.Errorf("server record %d is not its plaintext under the witness key", seq))
			break
		}
	}

	// Z3 to Z6 over each client record by its role, the scans running over the records before it
	headerFirst := self.firstSeq + 3 + uint64(preamble.RecipientCount)
	bulk := preamble.Flags&flagBulk != 0
	accepted.header = self.header
	accepted.body = self.body
	bodyOpened := false
	for i, r := range accepted.roles {
		content, err := clientContent(shake.version, witness.ClientPlaintexts[i])
		if err != nil {
			fail("Z3", err)
			continue
		}
		switch r {
		case roleEhlo, roleMail, roleRcpt, roleBdat, roleData:
			if err := checkCommand(self.settings, r, preamble, content); err != nil {
				fail("Z4", err)
			}
		case roleHeader:
			ordinal := accepted.seqs[i] - headerFirst + 1
			if 1 < ordinal {
				if witness.CarryInState != headerState(self.header, self.lastRecordStart(), ordinal == 2, bulk) {
					fail("Z5", errors.New("the part starts its scan from another state than the record before left"))
				} else if err := checkCarry(accepted.carryIn, witness.CarryInState, witness.CarryInBlind); err != nil {
					fail("Z5", err)
				}
			}
			start := len(self.header)
			header := append(bytes.Clone(self.header), content...)
			firstEnd := self.firstEnd
			if ordinal == 1 {
				firstEnd = len(header)
			}
			if err := checkHeaderSoFar(self.settings, preamble, header, firstEnd); err != nil {
				fail("Z5", err)
			} else if ordinal == uint64(accepted.k) {
				if err := checkHeaderBlock(self.settings, preamble, header); err != nil {
					fail("Z5", err)
				}
			}
			if !hasFailed(failures, "Z5") {
				if err := checkCarry(accepted.carryOut, headerState(header, start, ordinal == 1, bulk), witness.CarryOutBlind); err != nil {
					fail("Z5", err)
				}
			}
			accepted.header = header
			if part.Mode == modeBdat && preamble.MessageByteCount < uint64(len(content)) {
				fail("Z6", errors.New("a header record passes the declared count"))
			}
		case roleBody:
			bodyOpened = true
			if witness.CarryInState != bodyState(self.body) {
				fail("Z6", errors.New("the body record starts its scan from another state than the record before left"))
			} else if err := checkCarry(accepted.carryIn, witness.CarryInState, witness.CarryInBlind); err != nil {
				fail("Z6", err)
			}
			body := append(bytes.Clone(self.body), content...)
			if err := checkBodySoFar(body); err != nil {
				fail("Z6", err)
			} else if part.Last {
				if err := checkDataRecord(body); err != nil {
					fail("Z6", err)
				}
			}
			if !hasFailed(failures, "Z6") {
				if err := checkCarry(accepted.carryOut, bodyState(body), witness.CarryOutBlind); err != nil {
					fail("Z6", err)
				}
			}
			accepted.body = body
		case roleEndMark:
			if string(content) != "."+crlf {
				fail("Z6", errors.New("the end mark is not exactly . CRLF"))
			}
		case roleQuit:
			if string(content) != "QUIT"+crlf {
				fail("Z6", errors.New("the last record is not exactly QUIT CRLF"))
			}
		}
	}
	if part.Mode == modeData && part.Last && !bodyOpened {
		// an empty body: the end mark at the start state, which the part leaves as it was
		if witness.CarryInState != scanPosLf || checkCarry(accepted.carryIn, witness.CarryInState, witness.CarryInBlind) != nil ||
			checkCarry(accepted.carryOut, witness.CarryInState, witness.CarryOutBlind) != nil {
			fail("Z6", errors.New("an empty body's end mark does not start a line"))
		}
	}

	// Z7, Z8 and Z9 over the server records this part adds
	var stream []byte
	var applicationContents [][]byte
	for _, plaintext := range witness.ServerPlaintexts {
		content, isReply, err := serverContent(shake.version, plaintext)
		if err != nil {
			fail("Z7", err)
			return failures
		}
		if isReply {
			stream = append(stream, content...)
			applicationContents = append(applicationContents, content)
		}
	}
	replies, err := parseReplies(stream)
	if err != nil {
		fail("Z8", err)
		return failures
	}
	last354 := part.Mode == modeData && 0 < part.ReplyCount && uint64(accepted.repliesProven)+uint64(part.ReplyCount) == 3+uint64(preamble.RecipientCount)
	ok := uint64(len(replies)) == uint64(part.ReplyCount)
	for i := 0; ok && i < len(replies); i += 1 {
		final := replies[i].codes[len(replies[i].codes)-1]
		switch {
		case part.Index == 2 && !replies[i].coded(func(code string) bool { return code == "250" }):
			ok = false
		case last354 && i == len(replies)-1:
			ok = final == "354"
		default:
			ok = final[0] == '2'
		}
	}
	if !ok {
		fail("Z8", errors.New("the part's replies are not its count of the flow's acceptances"))
	}
	if part.Index == 2 && part.Mode == modeBdat && !offersChunking(applicationContents) {
		fail("Z9", errors.New("BDAT to an MX whose reply holds no CHUNKING line in one record"))
	}
	return failures
}

// Whether a check is among the failures.
func hasFailed(failures []*Failure, check string) bool {
	return slices.ContainsFunc(failures, func(failure *Failure) bool { return failure.Check == check })
}

// Where the header block's last record so far starts.
func (self *checkRun) lastRecordStart() int {
	return self.headerStarts
}

// A part's effect on the edge's state, once it verifies (DESIGN-DETAILS 3.2.5 step 15).
func (self *checkRun) commit(accepted *acceptedPart) {
	part := accepted.part
	self.parts = append(self.parts, accepted)
	if 0 < len(part.Records) {
		self.nextRecord = part.LastRecord + 1
	}
	self.covered = part.ServerRecordCount
	self.repliesProven += part.ReplyCount
	self.commandsCovered += accepted.commands
	if part.Index == 2 {
		self.mode = part.Mode
	}
	if accepted.opensFirst {
		self.k = part.HeaderRecordCount
		self.firstEnd = len(accepted.header)
	}
	if len(accepted.header) != len(self.header) {
		self.headerStarts = len(self.header)
	}
	if accepted.opensScan {
		self.carry = part.Carry
	}
	if accepted.opensLastHeader {
		self.carry = startCarry()
	}
	self.dataOctets = accepted.dataOctets
	self.header = accepted.header
	self.body = accepted.body
}

// Z1's first step: the witness's keys, both directions, are those its secret gives under the edge's own
// handshake inputs.
func (self *checkRun) checkKeys(witness *PartWitness) error {
	shake := self.shake
	if shake.version == versionTls13 {
		if len(witness.HandshakeSecret) != secretBytes {
			return errors.New("no HS")
		}
		shtsHash := sha256.Sum256(expandLabel(witness.HandshakeSecret, "s hs traffic", shake.helloHash, secretBytes))
		if !bytes.Equal(shtsHash[:], shake.shtsHash) {
			return errors.New("HS does not give the disclosed SHTS under H_sh")
		}
		ms := masterSecret13(witness.HandshakeSecret)
		key, iv := trafficKeys13(shake.suite, expandLabel(ms, "c ap traffic", shake.finishedHash, secretBytes))
		if !bytes.Equal(key, witness.ClientKey) || !bytes.Equal(iv, witness.ClientIv) {
			return errors.New("the client key is not MS's under H_sf")
		}
		key, iv = trafficKeys13(shake.suite, expandLabel(ms, "s ap traffic", shake.finishedHash, secretBytes))
		if !bytes.Equal(key, witness.ServerKey) || !bytes.Equal(iv, witness.ServerIv) {
			return errors.New("the server key is not MS's under H_sf")
		}
		return nil
	}
	ms := witness.MasterSecret
	if len(ms) != 48 {
		return errors.New("no master secret")
	}
	block := prf12(ms, "key expansion", append(append([]byte{}, shake.serverRandom...), shake.clientRandom...), 40)
	if !bytes.Equal(block[0:16], witness.ClientKey) || !bytes.Equal(block[32:36], witness.ClientIv) {
		return errors.New("the client key is not the key block's")
	}
	if !bytes.Equal(block[16:32], witness.ServerKey) || !bytes.Equal(block[36:40], witness.ServerIv) {
		return errors.New("the server key is not the key block's")
	}
	finishedHash := sha256.Sum256(shake.preFinished)
	clientFinished := finished12(ms, "client finished", finishedHash[:])
	resumedHash := sha256.Sum256(append(append([]byte{}, shake.preFinished...), clientFinished...))
	opened, err := openRecord(versionTls12, shake.suite, block[16:32], block[36:40], 0, shake.serverFinished12)
	if err != nil || !bytes.Equal(opened, finished12(ms, "server finished", resumedHash[:])) {
		return errors.New("SF does not open to the verify_data the secret gives the handshake")
	}
	return nil
}

// E3's walk over the client's records in stream order: each under a part that opens a record and covers
// it, an opened one equal to what the part proved, BDAT's body counted to octet n, a message record held
// behind any server record no part covers, and nothing after the final QUIT.
func (self *checkRun) release() {
	preamble := self.transcript.Preamble
	for self.released < len(self.clientRecords) {
		seq := self.firstSeq + uint64(self.released)
		var part *acceptedPart
		for _, candidate := range self.parts {
			if 0 < len(candidate.part.Records) && candidate.part.FirstRecord <= seq && seq <= candidate.part.LastRecord {
				part = candidate
			}
		}
		if part == nil {
			return
		}
		record := self.clientRecords[self.released]
		opened := slices.Index(part.seqs, seq)
		carried := uint64(0)
		message := true
		quit := false
		if 0 <= opened {
			if !bytes.Equal(record, part.part.Records[opened]) {
				self.fail("E3", part.part.Index, fmt.Errorf("record %d is not the ciphertext its part proved", seq))
				return
			}
			switch part.roles[opened] {
			case roleHeader:
				if self.mode == modeBdat {
					carried = uint64(self.contentBytes(record))
				}
			case roleEhlo, roleMail, roleRcpt, roleData:
				message = false
			case roleQuit:
				message = false
				quit = true
			}
		} else {
			// BDAT's unopened body: at most this many octets reach the MX (SPEC.md 9.5)
			content := self.contentBytes(record)
			if content < 0 {
				self.fail("E3", part.part.Index, errors.New("a body record too short to carry an octet"))
				return
			}
			carried = uint64(content)
		}
		if preamble.MessageByteCount < self.chunkOctets+carried {
			self.fail("E3", part.part.Index, errors.New("a chunk record passes octet n"))
			return
		}
		if message && self.covered < uint64(len(self.serverRecords)) {
			return
		}
		self.chunkOctets += carried
		if quit {
			if self.mode == modeBdat && self.chunkOctets != preamble.MessageByteCount {
				self.fail("E3", part.part.Index, errors.New("the chunk is short of octet n at QUIT"))
				return
			}
			self.finished = true
		}
		self.released += 1
	}
}
