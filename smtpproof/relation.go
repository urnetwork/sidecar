package smtpproof

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/chacha20"
)

// The relation of SPEC.md section 7, as plain Go over a statement and a witness: the definition the
// circuits must agree with, and the check a prover runs before it proves anything.
//
// Each check reads only what it names, so that a mutated witness can be pinned on the one check
// that refuses it (§22.10). In particular the witness carries the keys beside the secret they come
// from: Z1 ties them together, and Z2 onward use the keys as given.

// A check of SPEC.md section 6 or 7.
type relationCheck string

const (
	checkE1 relationCheck = "E1"
	checkE2 relationCheck = "E2"
	checkE3 relationCheck = "E3"
	checkZ1 relationCheck = "Z1"
	checkZ2 relationCheck = "Z2"
	checkZ3 relationCheck = "Z3"
	checkZ4 relationCheck = "Z4"
	checkZ5 relationCheck = "Z5"
	checkZ6 relationCheck = "Z6"
	checkZ7 relationCheck = "Z7"
	checkZ8 relationCheck = "Z8"
	checkZ9 relationCheck = "Z9"
)

// An edge check's refusal, or a relation check's in the reference relation.
type relationFailure struct {
	check relationCheck
	err   error
}

func (self *relationFailure) Error() string {
	return fmt.Sprintf("%s: %v", self.check, self.err)
}

func (self *relationFailure) Unwrap() error {
	return self.err
}

const (
	partModeNone uint32 = 0
	partModeBdat uint32 = 1
	partModeData uint32 = 2

	preambleFlagBulk       uint32 = 1
	preambleFlagRequireTls uint32 = 2
	preambleFlagBurner     uint32 = 4

	localMaxBytes = 64
	// What every 1.3 server record after Finished holds as its first octet if it is a ticket.
	tlsInnerTypeBytes = 1
)

const (
	literalCrlf            = "\r\n"
	literalEhloPrefix      = "EHLO "
	literalMailPrefix      = "MAIL FROM:<"
	literalRcptPrefix      = "RCPT TO:<"
	literalBdatPrefix      = "BDAT "
	literalBdatSuffix      = " LAST\r\n"
	literalData            = "DATA\r\n"
	literalQuit            = "QUIT\r\n"
	literalEndMark         = ".\r\n"
	literalRequireTls      = " REQUIRETLS"
	literalFromPrefix      = "From: "
	literalMessageIdPrefix = "Message-ID: <"
	literalXUrRefPrefix    = "X-UR-Ref: "
	literalFeedbackPrefix  = "Feedback-ID: "
	literalDkimPrefix      = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d="
	literalDkimSelector    = "; s="
	literalDkimCovered     = "; h=from:date:message-id:x-ur-ref:feedback-id; "
	literalUnsubscribePost = "List-Unsubscribe-Post: List-Unsubscribe=One-Click"
	keywordChunking        = "chunking"
)

// The declared and issued values every part of a connection shares (SPEC.md section 5).
type sessionPreamble struct {
	recipientDomain  string
	recipientCount   uint32
	messageId        string
	headerFromDomain string
	dkimSelector     string
	messageByteCount uint64
	flags            uint32
	heloName         string
	xUrRef           string
	feedbackId       string
	envelopeDomain   string
}

// The SHA-256 state S_ckx: chaining value, unhashed tail and length. Its marshaled form is what
// resumes it, which keeps this to crypto/sha256 and no second hash implementation.
type sha256State struct {
	chaining [8]uint32
	tail     []byte
	length   uint64
	marshal  []byte
}

// The state after hashing data.
func newSha256State(data []byte) (*sha256State, error) {
	hash := sha256.New()
	full := len(data) - len(data)%sha256.BlockSize
	hash.Write(data[:full])
	marshaler, ok := hash.(encoding.BinaryMarshaler)
	if !ok {
		return nil, errors.New("sha256 state cannot be marshaled")
	}
	marshaled, err := marshaler.MarshalBinary()
	if err != nil {
		return nil, err
	}
	state := &sha256State{tail: bytes.Clone(data[full:]), length: uint64(len(data)), marshal: marshaled}
	const magicBytes = 4
	for i := range state.chaining {
		state.chaining[i] = binary.BigEndian.Uint32(marshaled[magicBytes+4*i:])
	}
	return state, nil
}

// The hash of the state's input followed by more.
func (self *sha256State) finish(more []byte) ([]byte, error) {
	hash := sha256.New()
	unmarshaler, ok := hash.(encoding.BinaryUnmarshaler)
	if !ok {
		return nil, errors.New("sha256 state cannot be unmarshaled")
	}
	if err := unmarshaler.UnmarshalBinary(self.marshal); err != nil {
		return nil, err
	}
	hash.Write(self.tail)
	hash.Write(more)
	return hash.Sum(nil), nil
}

// Z1's handshake inputs and what else is fixed for a connection (SPEC.md section 5).
type sessionStatement struct {
	version  uint16
	suite    uint16
	preamble *sessionPreamble

	// 1.3.
	shtsHash     []byte
	helloHash    []byte
	finishedHash []byte

	// 1.2.
	clientRandom         []byte
	serverRandom         []byte
	preFinishedState     *sha256State
	serverFinishedRecord []byte
}

// A record a part names, whole as relayed.
type partRecord struct {
	seq uint64
	raw []byte
}

// The public statement of one part (SPEC.md section 5).
type partStatement struct {
	session     *sessionStatement
	index       uint32
	mode        uint32
	firstRecord uint64
	lastRecord  uint64
	last        bool
	// The count this part's server records start from, and the count it reaches.
	previousServerRecordCount uint64
	serverRecordCount         uint64
	// Ciphertext of each client record the part opens, in sequence order.
	clientRecords []*partRecord
	// Each server record past previousServerRecordCount, in sequence order.
	serverRecords []*partRecord
}

// A part's private witness.
type partWitness struct {
	// 1.3.
	handshakeSecret []byte
	// 1.2.
	masterSecret []byte

	clientKey []byte
	clientIv  []byte
	serverKey []byte
	serverIv  []byte

	// Plaintext of each client record the part opens: in 1.3 the inner plaintext, type octet included.
	clientPlaintexts [][]byte
	// Plaintext of each server record, likewise.
	serverPlaintexts [][]byte
}

// What an opened client record holds (SPEC.md 4.2).
type recordRole uint8

const (
	recordRoleEhlo recordRole = iota + 1
	recordRoleMail
	recordRoleRcpt
	recordRoleBdat
	recordRoleData
	recordRoleHeaderBlock
	recordRoleBody
	recordRoleEndMark
	recordRoleQuit
)

// The role of each client record a part opens, from public values alone. A part whose record count
// does not fit its index has no roles, and so no satisfying witness.
func partRoles(statement *partStatement) ([]recordRole, error) {
	recordCount := len(statement.clientRecords)
	preamble := statement.session.preamble
	switch {
	case statement.index == 1:
		if recordCount != 1 {
			return nil, errors.New("pi1 opens exactly the EHLO record")
		}
		return []recordRole{recordRoleEhlo}, nil
	case statement.index == 2:
		roles := []recordRole{recordRoleMail}
		for range preamble.recipientCount {
			roles = append(roles, recordRoleRcpt)
		}
		if statement.mode == partModeData {
			roles = append(roles, recordRoleData)
		}
		if recordCount != len(roles) {
			return nil, fmt.Errorf("pi2 opens %d records, want %d", recordCount, len(roles))
		}
		return roles, nil
	case statement.index == 3 && statement.mode == partModeBdat:
		if recordCount != 3 || !statement.last {
			return nil, errors.New("pi3 in BDAT mode opens BDAT, the header block and QUIT, and is last")
		}
		return []recordRole{recordRoleBdat, recordRoleHeaderBlock, recordRoleQuit}, nil
	case 3 <= statement.index && statement.mode == partModeData:
		if recordCount == 0 {
			return nil, errors.New("a DATA part opens at least one record")
		}
		roles := make([]recordRole, recordCount)
		for i := range roles {
			roles[i] = recordRoleBody
		}
		if statement.index == 3 {
			roles[0] = recordRoleHeaderBlock
		}
		if statement.last {
			if recordCount < 2 || (statement.index == 3 && recordCount < 3) {
				return nil, errors.New("the last DATA part ends with the end mark and QUIT")
			}
			roles[recordCount-2] = recordRoleEndMark
			roles[recordCount-1] = recordRoleQuit
		}
		return roles, nil
	default:
		return nil, fmt.Errorf("part %d has no shape in mode %d", statement.index, statement.mode)
	}
}

// Whether an octet may appear in a path's local part or a phrase (SPEC.md 4.2). This is RFC 5321's
// atext and dot, less the two octets that route on an MX that honors them.
func localOctet(octet byte) bool {
	switch {
	case 'a' <= octet && octet <= 'z', 'A' <= octet && octet <= 'Z', '0' <= octet && octet <= '9':
		return true
	}
	return bytes.IndexByte([]byte("#$&'*+-/=?^_`{|}~."), octet) != -1
}

// A record's AEAD ciphertext, without framing, explicit nonce or tag. The AEAD plaintext has this
// same length.
func recordCiphertext(version uint16, raw []byte) ([]byte, error) {
	overhead := tlsRecordHeaderBytes + tlsAeadTagBytes
	start := tlsRecordHeaderBytes
	if version == tlsVersion12 {
		overhead += tlsExplicitNonceBytes
		start += tlsExplicitNonceBytes
	}
	if len(raw) < overhead {
		return nil, errors.New("record too short")
	}
	return raw[start : len(raw)-tlsAeadTagBytes], nil
}

// A record's nonce: the IV and the public sequence number in 1.3, the salt and the record's own
// explicit nonce in 1.2.
func recordNonce(version uint16, iv []byte, record *partRecord) ([]byte, error) {
	if version == tlsVersion13 {
		return tls13Nonce(iv, record.seq), nil
	}
	if len(record.raw) < tlsRecordHeaderBytes+tlsExplicitNonceBytes {
		return nil, errors.New("record too short")
	}
	nonce := make([]byte, 0, tlsSalt12Bytes+tlsExplicitNonceBytes)
	nonce = append(nonce, iv...)
	return append(nonce, record.raw[tlsRecordHeaderBytes:tlsRecordHeaderBytes+tlsExplicitNonceBytes]...), nil
}

// The keystream for a record's plaintext from its first octet (SPEC.md Z2).
func recordKeystream(suite uint16, key []byte, nonce []byte, size int) ([]byte, error) {
	keystream := make([]byte, size)
	if suite == tlsSuiteChacha20Poly1305Sha256 {
		stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			return nil, err
		}
		stream.SetCounter(1)
		stream.XORKeyStream(keystream, keystream)
		return keystream, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	counterBlock := make([]byte, aes.BlockSize)
	copy(counterBlock, nonce)
	out := make([]byte, aes.BlockSize)
	for offset := 0; offset < size; offset += aes.BlockSize {
		binary.BigEndian.PutUint32(counterBlock[12:], uint32(2+offset/aes.BlockSize))
		block.Encrypt(out, counterBlock)
		copy(keystream[offset:], out)
	}
	return keystream, nil
}

// Whether a part opens server records and so needs the server direction's keys. Only pi1 does not.
func partNeedsServerKeys(statement *partStatement) bool {
	return statement.index != 1
}

// Z1: the witness's keys are the ones the observed handshake fixes.
func relationZ1(statement *partStatement, witness *partWitness) error {
	session := statement.session
	if session.version == tlsVersion13 {
		shts := tls13TrafficSecret(witness.handshakeSecret, "s hs traffic", session.helloHash)
		shtsHash := sha256.Sum256(shts)
		if !bytes.Equal(shtsHash[:], session.shtsHash) {
			return errors.New("HS does not yield the disclosed SHTS")
		}
		masterSecret := tls13MasterSecret(witness.handshakeSecret)
		cats := tls13TrafficSecret(masterSecret, "c ap traffic", session.finishedHash)
		clientKey, clientIv := tls13TrafficKeys(session.suite, cats)
		if !bytes.Equal(clientKey, witness.clientKey) || !bytes.Equal(clientIv, witness.clientIv) {
			return errors.New("client key or IV is not HS's")
		}
		if partNeedsServerKeys(statement) {
			sats := tls13TrafficSecret(masterSecret, "s ap traffic", session.finishedHash)
			serverKey, serverIv := tls13TrafficKeys(session.suite, sats)
			if !bytes.Equal(serverKey, witness.serverKey) || !bytes.Equal(serverIv, witness.serverIv) {
				return errors.New("server key or IV is not HS's")
			}
		}
		return nil
	}
	keyBlock := tls12DeriveKeyBlock(witness.masterSecret, session.clientRandom, session.serverRandom)
	if !bytes.Equal(keyBlock.clientKey, witness.clientKey) || !bytes.Equal(keyBlock.clientSalt, witness.clientIv) {
		return errors.New("client key or salt is not the master secret's")
	}
	if !bytes.Equal(keyBlock.serverKey, witness.serverKey) || !bytes.Equal(keyBlock.serverSalt, witness.serverIv) {
		return errors.New("server key or salt is not the master secret's")
	}
	clientHash, err := session.preFinishedState.finish(nil)
	if err != nil {
		return err
	}
	clientFinished := tls12FinishedMessage(witness.masterSecret, tlsLabelClientFinished, clientHash)
	serverHash, err := session.preFinishedState.finish(clientFinished)
	if err != nil {
		return err
	}
	want := tls12FinishedMessage(witness.masterSecret, tlsLabelServerFinished, serverHash)
	record := &partRecord{raw: session.serverFinishedRecord}
	nonce, err := recordNonce(tlsVersion12, keyBlock.serverSalt, record)
	if err != nil {
		return err
	}
	ciphertext, err := recordCiphertext(tlsVersion12, record.raw)
	if err != nil {
		return err
	}
	if len(ciphertext) != len(want) {
		return errors.New("server finished record has the wrong length")
	}
	keystream, err := recordKeystream(session.suite, keyBlock.serverKey, nonce, len(ciphertext))
	if err != nil {
		return err
	}
	for i := range ciphertext {
		if ciphertext[i]^keystream[i] != want[i] {
			return errors.New("server finished does not open to this master secret's verify_data")
		}
	}
	return nil
}

// Z2: each plaintext is its ciphertext XOR the keystream at its record.
func relationZ2(statement *partStatement, witness *partWitness) error {
	session := statement.session
	check := func(records []*partRecord, plaintexts [][]byte, key []byte, iv []byte) error {
		if len(records) != len(plaintexts) {
			return errors.New("witness holds the wrong number of plaintexts")
		}
		for i, record := range records {
			ciphertext, err := recordCiphertext(session.version, record.raw)
			if err != nil {
				return err
			}
			if len(ciphertext) != len(plaintexts[i]) {
				return fmt.Errorf("record %d: plaintext has the wrong length", record.seq)
			}
			nonce, err := recordNonce(session.version, iv, record)
			if err != nil {
				return err
			}
			keystream, err := recordKeystream(session.suite, key, nonce, len(ciphertext))
			if err != nil {
				return err
			}
			for j := range ciphertext {
				if ciphertext[j]^keystream[j] != plaintexts[i][j] {
					return fmt.Errorf("record %d: plaintext is not the ciphertext's", record.seq)
				}
			}
		}
		return nil
	}
	if err := check(statement.clientRecords, witness.clientPlaintexts, witness.clientKey, witness.clientIv); err != nil {
		return fmt.Errorf("client %w", err)
	}
	if err := check(statement.serverRecords, witness.serverPlaintexts, witness.serverKey, witness.serverIv); err != nil {
		return fmt.Errorf("server %w", err)
	}
	return nil
}

// The content of an opened client record, with 1.3's type octet off.
func clientContent(version uint16, plaintext []byte) []byte {
	if version == tlsVersion13 && 0 < len(plaintext) {
		return plaintext[:len(plaintext)-tlsInnerTypeBytes]
	}
	return plaintext
}

// Z3: each opened client record is unpadded application_data.
func relationZ3(statement *partStatement, witness *partWitness) error {
	version := statement.session.version
	for i, plaintext := range witness.clientPlaintexts {
		if i < len(statement.clientRecords) && statement.clientRecords[i].raw[0] != tlsRecordApplicationData {
			return errors.New("record's outer type is not application_data")
		}
		if version == tlsVersion13 && (len(plaintext) == 0 || plaintext[len(plaintext)-1] != tlsRecordApplicationData) {
			return errors.New("record does not end in the application_data type octet")
		}
	}
	return nil
}

// Literal octets of a command, or a position class (SPEC.md section 5). Grammar stays out of the
// circuit because every offset below is a function of public lengths.
type templateOctet struct {
	kind    uint8
	literal byte
}

const (
	templateFree uint8 = iota
	templateLiteral
	templateLocal
)

func templateOf(literal string) []templateOctet {
	template := make([]templateOctet, len(literal))
	for i := range template {
		template[i] = templateOctet{kind: templateLiteral, literal: literal[i]}
	}
	return template
}

// prefix, then a local part filling the record, then suffix. No template exists if the record's
// length leaves the local part outside 1 to 64 octets.
func localTemplate(contentBytes int, prefix string, suffix string) ([]templateOctet, error) {
	localBytes := contentBytes - len(prefix) - len(suffix)
	if localBytes < 1 || localMaxBytes < localBytes {
		return nil, fmt.Errorf("a %d-octet record leaves %d octets for a local part", contentBytes, localBytes)
	}
	template := templateOf(prefix)
	for range localBytes {
		template = append(template, templateOctet{kind: templateLocal})
	}
	return append(template, templateOf(suffix)...), nil
}

// The template of a command record of the given content length. Nil for a role with no template:
// the header block and body have their own checks.
func commandTemplate(role recordRole, preamble *sessionPreamble, contentBytes int) ([]templateOctet, error) {
	literal := func(content string) ([]templateOctet, error) {
		if len(content) != contentBytes {
			return nil, fmt.Errorf("a %d-octet record cannot hold a %d-octet command", contentBytes, len(content))
		}
		return templateOf(content), nil
	}
	switch role {
	case recordRoleEhlo:
		return literal(literalEhloPrefix + preamble.heloName + literalCrlf)
	case recordRoleMail:
		suffix := "@" + preamble.envelopeDomain + ">"
		if preamble.flags&preambleFlagRequireTls != 0 {
			suffix += literalRequireTls
		}
		return localTemplate(contentBytes, literalMailPrefix, suffix+literalCrlf)
	case recordRoleRcpt:
		return localTemplate(contentBytes, literalRcptPrefix, "@"+preamble.recipientDomain+">"+literalCrlf)
	case recordRoleBdat:
		return literal(literalBdatPrefix + strconv.FormatUint(preamble.messageByteCount, 10) + literalBdatSuffix)
	case recordRoleData:
		return literal(literalData)
	case recordRoleEndMark:
		return literal(literalEndMark)
	case recordRoleQuit:
		return literal(literalQuit)
	default:
		return nil, nil
	}
}

// Whether content matches a template.
func templateMatches(template []templateOctet, content []byte) error {
	if len(template) != len(content) {
		return errors.New("content does not fit the template's length")
	}
	for i, position := range template {
		switch position.kind {
		case templateLiteral:
			if content[i] != position.literal {
				return fmt.Errorf("octet %d is %#x, want %#x", i, content[i], position.literal)
			}
		case templateLocal:
			if !localOctet(content[i]) {
				return fmt.Errorf("octet %d is %#x, outside the local part's set", i, content[i])
			}
		}
	}
	return nil
}

// Z4: the opened records are the envelope's commands.
func relationZ4(statement *partStatement, witness *partWitness) error {
	roles, err := partRoles(statement)
	if err != nil {
		return err
	}
	if len(roles) != len(witness.clientPlaintexts) {
		return errors.New("witness holds the wrong number of plaintexts")
	}
	session := statement.session
	for i, role := range roles {
		if role != recordRoleEhlo && role != recordRoleMail && role != recordRoleRcpt && role != recordRoleBdat && role != recordRoleData {
			continue
		}
		content := clientContent(session.version, witness.clientPlaintexts[i])
		template, err := commandTemplate(role, session.preamble, len(content))
		if err != nil {
			return err
		}
		if err := templateMatches(template, content); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
	}
	return nil
}

// Z5's rules over a header block (SPEC.md Z5).
func checkHeaderBlock(block []byte, preamble *sessionPreamble) error {
	// rule 1: the octet class, and CR exactly before LF
	for i, octet := range block {
		switch {
		case octet == '\t', ' ' <= octet && octet <= '~':
		case octet == '\r':
			if i+1 == len(block) || block[i+1] != '\n' {
				return errors.New("bare CR")
			}
		case octet == '\n':
			if i == 0 || block[i-1] != '\r' {
				return errors.New("bare LF")
			}
		default:
			return fmt.Errorf("octet %#x in the header block", octet)
		}
	}
	// rule 2: ends in CRLF CRLF, and no line before that is empty
	end := []byte(literalCrlf + literalCrlf)
	if !bytes.HasSuffix(block, end) {
		return errors.New("header block does not end in CRLF CRLF")
	}
	lines := bytes.Split(block[:len(block)-len(end)], []byte(literalCrlf))
	counts := map[string]int{}
	var dkimCount, unsubscribeCount int
	dkimLiteral := []byte(literalDkimPrefix + preamble.headerFromDomain + literalDkimSelector + preamble.dkimSelector + literalDkimCovered)
	for i, line := range lines {
		if len(line) == 0 {
			return errors.New("empty line before the end of the header block")
		}
		// rule 3: a field name directly followed by a colon, or a continuation of a field
		if line[0] == ' ' || line[0] == '\t' {
			if i == 0 {
				return errors.New("header block starts with a continuation")
			}
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 1 {
			return errors.New("line has no field name")
		}
		for _, octet := range line[:colon] {
			if octet <= ' ' || '~' < octet {
				return errors.New("field name holds an octet outside 21-7E")
			}
		}
		name := string(bytes.ToLower(line[:colon]))
		continued := i+1 < len(lines) && 0 < len(lines[i+1]) && (lines[i+1][0] == ' ' || lines[i+1][0] == '\t')
		// rule 4: the four single fields and their literal forms
		var literal string
		switch name {
		case "from":
			if err := checkFromLine(line, preamble); err != nil {
				return err
			}
		case "message-id":
			literal = literalMessageIdPrefix + preamble.messageId + ">"
		case "x-ur-ref":
			literal = literalXUrRefPrefix + preamble.xUrRef
		case "feedback-id":
			literal = literalFeedbackPrefix + preamble.feedbackId
		default:
			name = ""
		}
		if name != "" {
			counts[name] += 1
			if continued {
				return fmt.Errorf("%s is continued", name)
			}
			if literal != "" && string(line) != literal {
				return fmt.Errorf("%s is not its declared value", name)
			}
		}
		// rule 5: §14.6's fixed signature
		if bytes.HasPrefix(line, dkimLiteral) {
			dkimCount += 1
		}
		// rule 6
		if string(line) == literalUnsubscribePost {
			unsubscribeCount += 1
		}
	}
	for _, name := range []string{"from", "message-id", "x-ur-ref", "feedback-id"} {
		if counts[name] != 1 {
			return fmt.Errorf("%d %s fields, want 1", counts[name], name)
		}
	}
	if dkimCount != 1 {
		return fmt.Errorf("%d fixed DKIM signatures, want 1", dkimCount)
	}
	if preamble.flags&preambleFlagBulk != 0 && unsubscribeCount != 1 {
		return fmt.Errorf("%d List-Unsubscribe-Post fields on a BULK message, want 1", unsubscribeCount)
	}
	return nil
}

// Z5.4's From form: From: [phrase SP] < local @ domain >.
func checkFromLine(line []byte, preamble *sessionPreamble) error {
	if !bytes.HasPrefix(line, []byte(literalFromPrefix)) {
		return errors.New("from is not in its literal form")
	}
	value := line[len(literalFromPrefix):]
	suffix := []byte("@" + preamble.headerFromDomain + ">")
	if !bytes.HasSuffix(value, suffix) {
		return errors.New("from is not in the declared domain")
	}
	value = value[:len(value)-len(suffix)]
	angle := bytes.IndexByte(value, '<')
	if angle < 0 {
		return errors.New("from has no angle address")
	}
	local := value[angle+1:]
	if len(local) < 1 || localMaxBytes < len(local) {
		return errors.New("from's local part has the wrong length")
	}
	for _, octet := range local {
		if !localOctet(octet) {
			return errors.New("from's local part holds a refused octet")
		}
	}
	if 0 < angle {
		if value[angle-1] != ' ' {
			return errors.New("from's phrase is not followed by SP")
		}
		for _, octet := range value[:angle] {
			if octet != ' ' && !localOctet(octet) {
				return errors.New("from's phrase holds a refused octet")
			}
		}
	}
	return nil
}

// Z5: the header block.
func relationZ5(statement *partStatement, witness *partWitness) error {
	roles, err := partRoles(statement)
	if err != nil {
		// the part's shape is Z4's to refuse
		return nil
	}
	session := statement.session
	for i, role := range roles {
		if role != recordRoleHeaderBlock {
			continue
		}
		if len(witness.clientPlaintexts) <= i {
			return errors.New("witness holds no header block")
		}
		return checkHeaderBlock(clientContent(session.version, witness.clientPlaintexts[i]), session.preamble)
	}
	return nil
}

// Z6's scan of one DATA record: whole lines, no bare CR or LF, no line that is exactly ".".
func checkDataLines(content []byte) error {
	if len(content) < len(literalCrlf) || !bytes.HasSuffix(content, []byte(literalCrlf)) {
		return errors.New("record does not end in CRLF")
	}
	lineStart := true
	for i, octet := range content {
		switch octet {
		case '\r':
			if i+1 == len(content) || content[i+1] != '\n' {
				return errors.New("bare CR")
			}
		case '\n':
			if i == 0 || content[i-1] != '\r' {
				return errors.New("bare LF")
			}
		case '.':
			if lineStart && i+2 < len(content) && content[i+1] == '\r' && content[i+2] == '\n' {
				return errors.New("a line that is exactly the end mark")
			}
		}
		lineStart = octet == '\n'
	}
	return nil
}

// Z6: the end of the message.
func relationZ6(statement *partStatement, witness *partWitness) error {
	roles, err := partRoles(statement)
	if err != nil || len(roles) != len(witness.clientPlaintexts) {
		// the part's shape is Z4's to refuse
		return nil
	}
	session := statement.session
	for i, role := range roles {
		content := clientContent(session.version, witness.clientPlaintexts[i])
		switch role {
		case recordRoleQuit, recordRoleEndMark:
			template, err := commandTemplate(role, session.preamble, len(content))
			if err != nil {
				return err
			}
			if err := templateMatches(template, content); err != nil {
				return err
			}
		case recordRoleHeaderBlock:
			if session.preamble.messageByteCount < uint64(len(content)) {
				return errors.New("the header block alone passes the declared octet count")
			}
			if statement.mode == partModeData {
				if err := checkDataLines(content); err != nil {
					return err
				}
			}
		case recordRoleBody:
			if err := checkDataLines(content); err != nil {
				return err
			}
		}
	}
	return nil
}

// Splits a part's server plaintexts into application content, skipping tickets. Anything else fails.
// 1.2 has no inner type: the edge passes only application_data there, so a record's plaintext is
// its content.
func serverContents(version uint16, plaintexts [][]byte) ([]byte, error) {
	var stream []byte
	for _, plaintext := range plaintexts {
		if version == tlsVersion12 {
			stream = append(stream, plaintext...)
			continue
		}
		if len(plaintext) == 0 {
			return nil, errors.New("empty server record")
		}
		content := plaintext[:len(plaintext)-tlsInnerTypeBytes]
		switch plaintext[len(plaintext)-1] {
		case tlsRecordApplicationData:
			stream = append(stream, content...)
		case tlsRecordHandshake:
			if len(content) == 0 || content[0] != tlsHandshakeNewSessionTicket {
				return nil, errors.New("server handshake record is not a ticket")
			}
		default:
			return nil, fmt.Errorf("server record of inner type %d", plaintext[len(plaintext)-1])
		}
	}
	return stream, nil
}

// Z7: every server record is application data or a skipped ticket, unpadded.
func relationZ7(statement *partStatement, witness *partWitness) error {
	if statement.session.version == tlsVersion12 {
		for _, record := range statement.serverRecords {
			if record.raw[0] != tlsRecordApplicationData {
				return errors.New("server record's outer type is not application_data")
			}
		}
		return nil
	}
	_, err := serverContents(statement.session.version, witness.serverPlaintexts)
	return err
}

// One reply of the stream: its final line's code, and each line's code and text in order.
type smtpReply struct {
	code      string
	lineCodes []string
	lines     []string
}

// Parses a whole reply stream by SPEC.md Z8's grammar. A trailing partial line fails: a part covers
// whole replies.
func parseReplies(stream []byte) ([]*smtpReply, error) {
	var replies []*smtpReply
	var current *smtpReply
	for 0 < len(stream) {
		end := bytes.Index(stream, []byte(literalCrlf))
		if end < 0 {
			return nil, errors.New("reply line has no CRLF")
		}
		line := stream[:end]
		stream = stream[end+len(literalCrlf):]
		if len(line) < 3 || bytes.ContainsAny(line, "\r\n") {
			return nil, errors.New("malformed reply line")
		}
		for _, octet := range line[:3] {
			if octet < '0' || '9' < octet {
				return nil, errors.New("reply code is not three digits")
			}
		}
		final := true
		text := ""
		if 3 < len(line) {
			switch line[3] {
			case '-':
				final = false
			case ' ':
			default:
				return nil, errors.New("malformed reply separator")
			}
			text = string(line[4:])
		}
		if current == nil {
			current = &smtpReply{code: string(line[:3])}
		}
		current.lineCodes = append(current.lineCodes, string(line[:3]))
		current.lines = append(current.lines, text)
		if final {
			current.code = string(line[:3])
			replies = append(replies, current)
			current = nil
		}
	}
	if current != nil {
		return nil, errors.New("reply stream ends inside a reply")
	}
	return replies, nil
}

// Z8: the replies are the ones the flow treats as accepted.
func relationZ8(statement *partStatement, witness *partWitness) error {
	session := statement.session
	stream, err := serverContents(session.version, witness.serverPlaintexts)
	if err != nil {
		// Z7's to refuse: nothing here can parse it
		return nil
	}
	replies, err := parseReplies(stream)
	if err != nil {
		return err
	}
	switch {
	case statement.index == 1:
		if len(replies) != 0 {
			return errors.New("pi1 covers no reply")
		}
	case statement.index == 2:
		if len(replies) != 1 {
			return errors.New("pi2 covers exactly one reply")
		}
		for _, code := range replies[0].lineCodes {
			if code != "250" {
				return fmt.Errorf("EHLO reply line coded %s, want 250", code)
			}
		}
	case statement.index == 3:
		want := 1 + int(session.preamble.recipientCount)
		if statement.mode == partModeData {
			want += 1
		}
		if len(replies) != want {
			return fmt.Errorf("pi3 covers %d replies, want %d", len(replies), want)
		}
		for i, reply := range replies {
			if statement.mode == partModeData && i == want-1 {
				if reply.code != "354" {
					return fmt.Errorf("DATA got %s, want 354", reply.code)
				}
			} else if reply.code[0] != '2' {
				return fmt.Errorf("reply %d is %s, want 2xx", i, reply.code)
			}
		}
	default:
		if len(replies) != 0 {
			return errors.New("a reply arrived during the message")
		}
	}
	return nil
}

// Z9: BDAT only to an MX whose post-TLS EHLO reply offers CHUNKING.
func relationZ9(statement *partStatement, witness *partWitness) error {
	if statement.index != 2 || statement.mode != partModeBdat {
		return nil
	}
	stream, err := serverContents(statement.session.version, witness.serverPlaintexts)
	if err != nil {
		return nil
	}
	replies, err := parseReplies(stream)
	if err != nil || len(replies) != 1 {
		// Z8's to refuse
		return nil
	}
	for i, text := range replies[0].lines {
		// the first line is the MX's name, never a keyword
		if 0 < i && string(bytes.ToLower([]byte(text))) == keywordChunking {
			return nil
		}
	}
	return errors.New("BDAT to an MX whose EHLO reply lacks CHUNKING")
}

// Every failing check of Z1-Z9 over a part, in order: empty means the witness satisfies the relation.
func relationCheckPart(statement *partStatement, witness *partWitness) []*relationFailure {
	var failures []*relationFailure
	for _, entry := range []struct {
		check relationCheck
		run   func(*partStatement, *partWitness) error
	}{
		{check: checkZ1, run: relationZ1},
		{check: checkZ2, run: relationZ2},
		{check: checkZ3, run: relationZ3},
		{check: checkZ4, run: relationZ4},
		{check: checkZ5, run: relationZ5},
		{check: checkZ6, run: relationZ6},
		{check: checkZ7, run: relationZ7},
		{check: checkZ8, run: relationZ8},
		{check: checkZ9, run: relationZ9},
	} {
		if err := entry.run(statement, witness); err != nil {
			failures = append(failures, &relationFailure{check: entry.check, err: err})
		}
	}
	return failures
}
