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
	run := &checkRun{transcript: transcript, witnesses: witnesses, shake: &handshake{preamble: transcript.Preamble}}
	if err := checkPreambleForms(transcript.Preamble); err != nil {
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
	// Each record's sequence number, and what it holds.
	seqs  []uint64
	roles []role
	// The server record count this part covers from.
	previousCount uint64
}

type checkRun struct {
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
		// a part outside its roles or the DATA count is refused before any verification
		if check, err := self.checkPart(accepted); err != nil {
			self.fail(check, event.Part.Index, err)
			return
		}
		self.failures = append(self.failures, self.relation(accepted)...)
		if len(self.failures) == 0 {
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
	if shake.phase == phaseApplication && shake.version == versionTls12 {
		// the client's Finished took sequence number 0 in each direction
		self.firstSeq = 1
	}
}

// Whether the session's inputs exist: 1.3's once E2 has passed, 1.2's once the server's Finished is in.
func (self *checkRun) sessionReady() bool {
	if self.shake.version == versionTls13 {
		return self.shake.flightChecked
	}
	return self.shake.phase == phaseApplication
}

// E3's order rules for a part (SPEC.md section 6), and its statement's record numbers. It returns nil
// and no error for an exact resend, which changes nothing.
func (self *checkRun) acceptPart(part *Part) (*acceptedPart, error) {
	if !self.sessionReady() {
		return nil, errors.New("a part before the handshake's inputs exist")
	}
	var latest *acceptedPart
	if 0 < len(self.parts) {
		latest = self.parts[len(self.parts)-1]
	}
	replacing := latest != nil && part.Index == latest.part.Index
	switch {
	case part.Index == 0:
		return nil, errors.New("part index 0")
	case latest == nil && part.Index != 1:
		return nil, errors.New("the first part is not pi1")
	case latest != nil && !replacing && part.Index != latest.part.Index+1:
		return nil, fmt.Errorf("part %d after part %d", part.Index, latest.part.Index)
	case latest != nil && !replacing && latest.part.Last:
		return nil, errors.New("a part after the last")
	}
	if replacing {
		original := latest.part
		same := part.FirstRecord == original.FirstRecord && part.LastRecord == original.LastRecord &&
			part.Mode == original.Mode && part.Last == original.Last && slices.EqualFunc(part.Records, original.Records, bytes.Equal)
		if same && part.ServerRecordCount == original.ServerRecordCount {
			return nil, nil
		}
		if !same || part.ServerRecordCount <= original.ServerRecordCount {
			return nil, errors.New("a part proven again must open the same records over later server records")
		}
	}
	switch {
	case part.Index == 1 && part.Mode != 0:
		return nil, errors.New("pi1 carries a mode")
	case 2 <= part.Index && part.Mode != modeBdat && part.Mode != modeData:
		return nil, fmt.Errorf("mode %d", part.Mode)
	case 3 <= part.Index && part.Mode != self.parts[1].part.Mode:
		return nil, errors.New("the mode changed after pi2")
	}
	var previous *acceptedPart
	if replacing {
		if 2 <= len(self.parts) {
			previous = self.parts[len(self.parts)-2]
		}
	} else {
		previous = latest
	}
	first := self.firstSeq
	previousCount := uint64(0)
	if previous != nil {
		first = previous.part.LastRecord + 1
		previousCount = previous.part.ServerRecordCount
	}
	switch {
	case part.FirstRecord != first:
		return nil, fmt.Errorf("first_record %d, want %d", part.FirstRecord, first)
	case part.LastRecord < part.FirstRecord || len(part.Records) == 0:
		return nil, errors.New("the part covers no record")
	case part.ServerRecordCount < previousCount:
		return nil, errors.New("server_record_count fell")
	case uint64(len(self.serverRecords)) < part.ServerRecordCount:
		return nil, errors.New("server_record_count passes what was relayed")
	case part.Index == 1 && part.ServerRecordCount != 0:
		return nil, errors.New("pi1 covers a server record")
	}
	accepted := &acceptedPart{part: part, event: self.event, previousCount: previousCount}
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
		// BDAT's QUIT names its own number, past the unopened body
		if part.Mode == modeBdat && part.Index == 3 && i == len(part.Records)-1 {
			seq = part.LastRecord
		}
		if 0 < i && seq <= accepted.seqs[i-1] {
			return nil, errors.New("the part's records are not in sequence order")
		}
		accepted.seqs = append(accepted.seqs, seq)
	}
	if accepted.seqs[len(accepted.seqs)-1] != part.LastRecord {
		return nil, errors.New("the part's records do not reach last_record")
	}
	if replacing {
		self.parts[len(self.parts)-1] = accepted
	} else {
		self.parts = append(self.parts, accepted)
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

// Roles, and E3's DATA count: the octets of header and body records may not pass n, and reach it at
// the last part.
func (self *checkRun) checkPart(accepted *acceptedPart) (string, error) {
	preamble := self.transcript.Preamble
	roles, check, err := partRoles(preamble, accepted.part)
	if err != nil {
		return check, err
	}
	// SPEC.md section 5: a template no plaintext of the record's length can fill, such as a local run
	// outside 1 to 64 octets, is refused at the edge without a verification
	for i, r := range roles {
		if !templateFits(r, preamble, self.contentBytes(accepted.part.Records[i])) {
			return "E3", fmt.Errorf("no template of record %d's length", accepted.seqs[i])
		}
	}
	accepted.roles = roles
	if accepted.part.Mode != modeData {
		return "", nil
	}
	octets := uint64(0)
	for _, other := range self.parts {
		for i, r := range other.roles {
			if r == roleHeader || r == roleBody {
				octets += uint64(self.contentBytes(other.part.Records[i]))
			}
		}
	}
	n := preamble.MessageByteCount
	if n < octets {
		return "E3", errors.New("DATA octets pass the declared count")
	}
	if accepted.part.Last && octets != n {
		return "E3", errors.New("the last DATA part leaves the declared count short")
	}
	return "", nil
}

// Z1 to Z9 over one part and its witness.
func (self *checkRun) relation(accepted *acceptedPart) []*Failure {
	if accepted.roles == nil {
		return nil
	}
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
	needServerKeys := 0 < len(serverRecords)

	// Z1
	if err := self.checkKeys(witness, needServerKeys); err != nil {
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

	// Z3 to Z6 over each client record by its role
	for i, r := range accepted.roles {
		content, err := clientContent(shake.version, witness.ClientPlaintexts[i])
		if err != nil {
			fail("Z3", err)
			continue
		}
		switch r {
		case roleEhlo, roleMail, roleRcpt, roleBdat, roleData:
			if err := checkCommand(r, preamble, content); err != nil {
				fail("Z4", err)
			}
		case roleHeader:
			if err := checkHeaderBlock(preamble, content); err != nil {
				fail("Z5", err)
			}
			if part.Mode == modeBdat && preamble.MessageByteCount < uint64(len(content)) {
				fail("Z6", errors.New("the header block passes the declared count"))
			}
			if part.Mode == modeData {
				if err := checkDataRecord(content); err != nil {
					fail("Z6", err)
				}
			}
		case roleBody:
			if err := checkDataRecord(content); err != nil {
				fail("Z6", err)
			}
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
	is250 := func(code string) bool { return code == "250" }
	is2xx := func(code string) bool { return code[0] == '2' }
	switch {
	case part.Index == 2:
		if len(replies) != 1 || !replies[0].coded(is250) {
			fail("Z8", errors.New("pi2's server records are not one 250 reply"))
		}
		if part.Mode == modeBdat && !offersChunking(applicationContents) {
			fail("Z9", errors.New("BDAT to an MX whose reply holds no CHUNKING line in one record"))
		}
	case part.Index == 3:
		want := 1 + int(preamble.RecipientCount)
		if part.Mode == modeData {
			want += 1
		}
		ok := len(replies) == want
		for i := 0; ok && i < 1+int(preamble.RecipientCount); i += 1 {
			ok = replies[i].coded(is2xx)
		}
		if ok && part.Mode == modeData {
			ok = replies[want-1].coded(func(code string) bool { return code == "354" })
		}
		if !ok {
			fail("Z8", errors.New("pi3's replies are not the envelope's acceptance"))
		}
	case 3 < part.Index && 0 < len(replies):
		fail("Z8", errors.New("a later part covers a reply"))
	}
	return failures
}

// Z1: the witness's keys are those its secret gives under the edge's own handshake inputs.
func (self *checkRun) checkKeys(witness *PartWitness, needServerKeys bool) error {
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
		if needServerKeys {
			key, iv = trafficKeys13(shake.suite, expandLabel(ms, "s ap traffic", shake.finishedHash, secretBytes))
			if !bytes.Equal(key, witness.ServerKey) || !bytes.Equal(iv, witness.ServerIv) {
				return errors.New("the server key is not MS's under H_sf")
			}
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
	if needServerKeys && (!bytes.Equal(block[16:32], witness.ServerKey) || !bytes.Equal(block[36:40], witness.ServerIv)) {
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

// E3's walk over the client's records in stream order: each under a part that covers it, an opened
// one equal to what the part proved, BDAT's body counted to octet n, a message record held behind any
// server record no part covers, and nothing after the final QUIT.
func (self *checkRun) release() {
	preamble := self.transcript.Preamble
	covered := uint64(0)
	for _, part := range self.parts {
		covered = max(covered, part.part.ServerRecordCount)
	}
	for self.released < len(self.clientRecords) {
		seq := self.firstSeq + uint64(self.released)
		var part *acceptedPart
		for _, candidate := range self.parts {
			if candidate.part.FirstRecord <= seq && seq <= candidate.part.LastRecord {
				part = candidate
			}
		}
		if part == nil || part.roles == nil {
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
				if part.part.Mode == modeBdat {
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
		if message && covered < uint64(len(self.serverRecords)) {
			return
		}
		self.chunkOctets += carried
		if quit {
			if part.part.Mode == modeBdat && self.chunkOctets != preamble.MessageByteCount {
				self.fail("E3", part.part.Index, errors.New("the chunk is short of octet n at QUIT"))
				return
			}
			self.finished = true
		}
		self.released += 1
	}
}
