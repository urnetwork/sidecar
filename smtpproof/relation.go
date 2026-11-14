package smtpproof

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

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

	// What every 1.3 record holds after its content: its inner type octet.
	tlsInnerTypeBytes = 1

	// X-UR-Ref's bytes (§14.6, plan-SMTP-small-readings #3): the version, then lowercase unpadded
	// base32 of key_id (1 octet), send_id (12) and the HMAC's first 8 octets.
	xUrRefVersion = "1."
	xUrRefOctets  = 1 + 12 + 8
	// Feedback-ID's fields (§14.6, plan-SMTP-small-readings #4): class, tier, the network's report
	// token in lowercase unpadded base32 of 16 octets (plan-SMTP-net-token), and this constant.
	feedbackIdSuffix = "urnetwork"
	netTokenOctets   = 16
)

// Unpadded base32 (RFC 4648 §6). X-UR-Ref and the network token write it in lowercase.
var unpaddedBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Whether a value is the lowercase unpadded base32 of exactly octetCount octets, its unused low bits
// zero, so that each value has one spelling. Go's decoder ignores those bits, so the octets are
// encoded again and compared.
func lowerBase32Form(value string, octetCount int) bool {
	if len(value) != unpaddedBase32.EncodedLen(octetCount) {
		return false
	}
	for i := range len(value) {
		if !('a' <= value[i] && value[i] <= 'z' || '2' <= value[i] && value[i] <= '7') {
			return false
		}
	}
	upper := strings.ToUpper(value)
	decoded, err := unpaddedBase32.DecodeString(upper)
	return err == nil && len(decoded) == octetCount && unpaddedBase32.EncodeToString(decoded) == upper
}

// Whether a value is X-UR-Ref's 36 characters.
func xUrRefForm(value string) bool {
	token, found := strings.CutPrefix(value, xUrRefVersion)
	return found && lowerBase32Form(token, xUrRefOctets)
}

// Whether a value is Feedback-ID's 40 characters: n or b, then c, p or t, then the token.
func feedbackIdForm(value string) bool {
	fields := strings.Split(value, ":")
	return len(fields) == 4 &&
		(fields[0] == "n" || fields[0] == "b") &&
		(fields[1] == "c" || fields[1] == "p" || fields[1] == "t") &&
		lowerBase32Form(fields[2], netTokenOctets) &&
		fields[3] == feedbackIdSuffix
}

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
	// §14.6's second signature. h= comes first so that this constant alone identifies it.
	literalDkimPrefix      = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; "
	literalDkimDomain      = "d="
	literalDkimSelector    = "; s="
	literalDkimEnd         = "; "
	literalUnsubscribePost = "List-Unsubscribe-Post: List-Unsubscribe=One-Click"
	keywordChunking        = "chunking"
)

// The declared and issued values every part of a connection shares (SPEC.md section 5), and the
// settings their forms and every template are checked against.
type sessionPreamble struct {
	proof            *ProofSettings
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

// Whether a name is RFC 5321's Domain: labels of letters, digits and hyphens, with a letter or digit
// at each end, so that nothing in it can close a path or end a line. RFC 5321 §4.5.3.1.2 and RFC 1035
// §2.3.4 bound the name and each label (ProofSettings).
func domainForm(proof *ProofSettings, name string) bool {
	if name == "" || proof.DomainMaxByteCount < len(name) {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || proof.LabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			octet := label[i]
			if !('a' <= octet && octet <= 'z' || 'A' <= octet && octet <= 'Z' || '0' <= octet && octet <= '9' || octet == '-') {
				return false
			}
		}
	}
	return true
}

// Refuses a preamble no template may be built from (SPEC.md section 6). A template is a literal, and
// the circuit proves a record equals it, so a declared value holding the end of a path or a line
// would have the proof vouch for a command of the sidecar's own.
func checkSessionPreamble(preamble *sessionPreamble) error {
	if preamble.proof == nil {
		return errors.New("preamble has no settings to check it by")
	}
	if preamble.recipientCount == 0 {
		return errors.New("preamble declares no recipient")
	}
	if uint32(preamble.proof.RecipientMaxCount) < preamble.recipientCount {
		return fmt.Errorf("preamble declares %d recipients, more than a connection holds", preamble.recipientCount)
	}
	// without its angle brackets: one @, with a run of the local set on either side
	messageIdForm := func(value string) bool {
		left, right, found := strings.Cut(value, "@")
		if !found || left == "" || right == "" {
			return false
		}
		for _, half := range []string{left, right} {
			for i := range len(half) {
				if !localOctet(half[i]) {
					return false
				}
			}
		}
		return true
	}
	for _, entry := range []struct {
		name string
		ok   bool
	}{
		{name: "recipient_domain", ok: domainForm(preamble.proof, preamble.recipientDomain)},
		{name: "header_from_domain", ok: domainForm(preamble.proof, preamble.headerFromDomain)},
		{name: "dkim_selector", ok: domainForm(preamble.proof, preamble.dkimSelector)},
		{name: "envelope_domain", ok: domainForm(preamble.proof, preamble.envelopeDomain)},
		{name: "helo_name", ok: domainForm(preamble.proof, preamble.heloName)},
		{name: "message_id", ok: messageIdForm(preamble.messageId)},
		// the edge issues both, so these check the edge itself; their exact forms keep each line's
		// length fixed before the mode is known (plan-SMTP-preamble-byte-count)
		{name: "x_ur_ref", ok: xUrRefForm(preamble.xUrRef)},
		{name: "feedback_id", ok: feedbackIdForm(preamble.feedbackId)},
	} {
		if !entry.ok {
			return fmt.Errorf("preamble's %s is outside its form", entry.name)
		}
	}
	return nil
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
	session *sessionStatement
	// C, 64 octets: the key part's own, which it carries, or for every later part the one the edge kept
	// from the key part, never a value the part carries (DESIGN-DETAILS 3.2.5).
	keyCommitment []byte
	index         uint32
	mode          uint32
	firstRecord   uint64
	lastRecord    uint64
	last          bool
	// The count this part's server records start from, and the count it reaches.
	previousServerRecordCount uint64
	serverRecordCount         uint64
	// The replies this part's server records hold (Z8), and the replies the parts before it proved.
	replyCount    uint32
	repliesProven uint32
	// k: the client records the header block takes, as the part that opens its first record names it; 0
	// before that part.
	headerRecordCount uint32
	// The gate's carry, which a hdr or body part opens to the state it starts from, never a value the
	// part carries; and the part's own, of the state it leaves, on a part that opens a header or body
	// record (DESIGN-DETAILS 3.2.4). 64 octets each.
	carryIn  []byte
	carryOut []byte
	// Ciphertext of each client record the part opens, in sequence order.
	clientRecords []*partRecord
	// Each server record past previousServerRecordCount, in sequence order.
	serverRecords []*partRecord
}

// Part 2 alone covers the post-TLS EHLO reply, every line of it coded 250 (Z8).
func (self *partStatement) ehloRule() bool {
	return self.index == 2
}

// Part 2 names the mode, and in BDAT mode its EHLO reply offers CHUNKING (Z9).
func (self *partStatement) requireChunking() bool {
	return self.index == 2 && self.mode == partModeBdat
}

// In DATA mode the replies that complete the envelope's, 3 + R with the EHLO reply's, end in 354 (Z8).
func (self *partStatement) last354() bool {
	want := 3 + uint64(self.session.preamble.recipientCount)
	return self.mode == partModeData && 0 < self.replyCount && uint64(self.repliesProven)+uint64(self.replyCount) == want
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
	// rho: C's blind, drawn once for the connection (DESIGN-DETAILS 3.2.2).
	keyBlind *big.Int
	// The state a hdr or body part starts from, which the gate's carry opens to under carryInBlind, and
	// the blind of the part's own carry. Each blind is drawn once a carry.
	carryInState  scanState
	carryInBlind  *big.Int
	carryOutBlind *big.Int

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

// The first application record's sequence number in each direction: 0 in TLS 1.3, and 1 in 1.2, whose
// Finished took 0.
func firstApplicationSeq(version uint16) uint64 {
	if version == tlsVersion12 {
		return 1
	}
	return 0
}

// The role of each client record a part opens, by its position alone (DESIGN-DETAILS 3.2.5): the edge
// assigns every template with no word from the prover but k. On the last part the final record is QUIT
// and, in DATA mode, the one before it the end mark; each sits where the message's body does, past the
// header block.
func partRoles(statement *partStatement) ([]recordRole, error) {
	preamble := statement.session.preamble
	// BDAT with no RCPT draws a refusal, and an MX that then reads the chunk as commands would run an
	// unopened body, so a transaction holds a recipient whatever else its statement says
	if preamble.recipientCount == 0 {
		return nil, errors.New("a transaction names at least one recipient")
	}
	first := firstApplicationSeq(statement.session.version)
	count := len(statement.clientRecords)
	roles := make([]recordRole, count)
	for i, record := range statement.clientRecords {
		if record.seq < first {
			return nil, fmt.Errorf("record %d precedes the first application record", record.seq)
		}
		position, err := recordRoleAt(record.seq-first, preamble.recipientCount, statement.mode, statement.headerRecordCount)
		if err != nil {
			return nil, err
		}
		switch {
		case statement.last && i == count-1:
			if position != recordRoleBody {
				return nil, errors.New("QUIT before the message's body")
			}
			roles[i] = recordRoleQuit
		case statement.last && statement.mode == partModeData && i == count-2:
			if position != recordRoleBody {
				return nil, errors.New("the end mark before the message's body")
			}
			roles[i] = recordRoleEndMark
		default:
			roles[i] = position
		}
	}
	return roles, nil
}

// A header record's ordinal in the header block, from 1.
func headerOrdinal(statement *partStatement, seq uint64) int {
	offset := seq - firstApplicationSeq(statement.session.version)
	return int(offset - 2 - uint64(statement.session.preamble.recipientCount))
}

// A part's kind by what it opens (DESIGN-DETAILS 3.2.5 step 8). Part 1 opens EHLO. Any other part opens
// records of one kind: envelope commands, or none, is env; header record 1, after BDAT's command in BDAT
// mode, is msg; a later header record is hdr; a body record, or an empty body's end mark, is body. A part
// opens at most one header or body record. QUIT rides the last part of the three message kinds: in BDAT
// mode the one that opens the header block's last record, which must, and in DATA mode a body part after
// the end mark.
func partKindOf(statement *partStatement, roles []recordRole) (partKind, error) {
	if statement.index == 1 {
		if len(roles) != 1 || roles[0] != recordRoleEhlo {
			return 0, errors.New("the key part opens exactly the EHLO record")
		}
		return partKindKey, nil
	}
	kind := partKind(0)
	records := 0
	ordinal := 0
	bdat := false
	endMark := false
	quit := false
	for i, role := range roles {
		var roleKind partKind
		switch role {
		case recordRoleMail, recordRoleRcpt, recordRoleData:
			roleKind = partKindEnvelope
		case recordRoleBdat:
			roleKind = partKindMessage
			bdat = true
		case recordRoleHeaderBlock:
			records += 1
			ordinal = headerOrdinal(statement, statement.clientRecords[i].seq)
			roleKind = partKindHeader
			if ordinal == 1 {
				roleKind = partKindMessage
			}
		case recordRoleBody:
			records += 1
			roleKind = partKindBody
		case recordRoleEndMark:
			endMark = true
			roleKind = partKindBody
		case recordRoleQuit:
			quit = true
			continue
		default:
			return 0, fmt.Errorf("a later part opens a record of role %d", role)
		}
		if kind != 0 && kind != roleKind {
			return 0, errors.New("a part opens records of more than one kind")
		}
		kind = roleKind
	}
	if kind == 0 {
		if quit {
			return 0, errors.New("QUIT rides a message part")
		}
		// a part that opens no client record covers server records alone
		return partKindEnvelope, nil
	}
	if 1 < records {
		return 0, errors.New("a part opens at most one header or body record")
	}
	headerLast := ordinal != 0 && ordinal == int(statement.headerRecordCount)
	switch kind {
	case partKindEnvelope:
		if quit {
			return 0, errors.New("QUIT rides a message part")
		}
	case partKindMessage:
		if records != 1 {
			return 0, errors.New("BDAT's command is opened with the header block's first record")
		}
		if statement.mode == partModeBdat && (!bdat || roles[0] != recordRoleBdat) {
			return 0, errors.New("in BDAT mode the header block's first record follows BDAT's command in its part")
		}
	case partKindBody:
		if statement.mode != partModeData {
			return 0, errors.New("body records are opened in DATA mode alone")
		}
		if records == 0 && !endMark {
			return 0, errors.New("a body part opens a body record or the end mark")
		}
	}
	if statement.mode == partModeBdat && (kind == partKindMessage || kind == partKindHeader) && headerLast != quit {
		return 0, errors.New("in BDAT mode the part that opens the header block's last record opens QUIT, and no other")
	}
	if statement.mode == partModeData && quit && !endMark {
		return 0, errors.New("in DATA mode QUIT follows the end mark")
	}
	return kind, nil
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

// Letters in lower case and every other octet as it is, which is what forcing bit 5 does in the
// circuit. bytes.ToLower is no substitute: it also folds the Kelvin sign's three octets to k.
func asciiLower(octets []byte) string {
	lower := bytes.Clone(octets)
	for i, octet := range lower {
		if 'A' <= octet && octet <= 'Z' {
			lower[i] = octet + 'a' - 'A'
		}
	}
	return string(lower)
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

// Z1 in two steps (DESIGN-DETAILS 3.2.3): the key part's keys are the ones the observed handshake
// fixes, both directions always, and C commits to them under rho; every later part's keys open the C
// the edge kept, and nothing of the handshake enters it.
func relationZ1(statement *partStatement, witness *partWitness) error {
	if statement.index == 1 {
		if err := relationZ1Derive(statement, witness); err != nil {
			return err
		}
	}
	return relationZ1Open(statement, witness)
}

// Z1's second step: the witness's keys and IVs, under its blind, are what C commits to.
func relationZ1Open(statement *partStatement, witness *partWitness) error {
	want, err := decodeCommitment(statement.keyCommitment)
	if err != nil {
		return fmt.Errorf("the statement's key commitment: %w", err)
	}
	if witness.keyBlind == nil {
		return errors.New("no blind")
	}
	commitment, err := commitKeys(witness.clientKey, witness.clientIv, witness.serverKey, witness.serverIv, witness.keyBlind)
	if err != nil {
		return err
	}
	if !commitment.Equal(&want) {
		return errors.New("the keys and blind do not open the key commitment")
	}
	return nil
}

// Z1's first step, the key part's: the witness's keys are the ones the observed handshake fixes.
func relationZ1Derive(statement *partStatement, witness *partWitness) error {
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
		sats := tls13TrafficSecret(masterSecret, "s ap traffic", session.finishedHash)
		serverKey, serverIv := tls13TrafficKeys(session.suite, sats)
		if !bytes.Equal(serverKey, witness.serverKey) || !bytes.Equal(serverIv, witness.serverIv) {
			return errors.New("server key or IV is not HS's")
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
// length leaves the local part outside 1 to LocalMaxByteCount octets.
func localTemplate(proof *ProofSettings, contentBytes int, prefix string, suffix string) ([]templateOctet, error) {
	localBytes := contentBytes - len(prefix) - len(suffix)
	if localBytes < 1 || proof.LocalMaxByteCount < localBytes {
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
		return localTemplate(preamble.proof, contentBytes, literalMailPrefix, suffix+literalCrlf)
	case recordRoleRcpt:
		return localTemplate(preamble.proof, contentBytes, literalRcptPrefix, "@"+preamble.recipientDomain+">"+literalCrlf)
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

// Z4: the opened records are the envelope's commands, each where its position puts it, in a part of one
// kind (DESIGN-DETAILS 3.2.5).
func relationZ4(statement *partStatement, witness *partWitness) error {
	roles, err := partRoles(statement)
	if err != nil {
		return err
	}
	if _, err := partKindOf(statement, roles); err != nil {
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
	singleNames := []string{"from", "message-id", "x-ur-ref", "feedback-id"}
	bulk := preamble.flags&preambleFlagBulk != 0
	if bulk {
		singleNames = append(singleNames, "list-unsubscribe-post")
	}
	dkimCount := 0
	dkimPrefix := []byte(literalDkimPrefix)
	dkimLiteral := []byte(literalDkimPrefix + dkimTags(preamble))
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
		// an MX reading DATA deletes a line's leading dot (RFC 5321 §4.5.2), so what Z5 read as some
		// other field would reach it as the field after the dot
		if line[0] == '.' {
			return errors.New("field name starts with a dot")
		}
		name := asciiLower(line[:colon])
		continued := i+1 < len(lines) && 0 < len(lines[i+1]) && (lines[i+1][0] == ' ' || lines[i+1][0] == '\t')
		// rule 4: the single fields and their literal forms
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
		case "list-unsubscribe-post":
			// rule 6: on a BULK message this field is single too, since a continuation or a second
			// field leaves it no longer RFC 8058's single key/value pair
			if !bulk {
				name = ""
			}
			literal = literalUnsubscribePost
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
		// rule 5: §14.6's fixed signature, whose prefix nothing else may carry
		if bytes.HasPrefix(line, dkimPrefix) {
			dkimCount += 1
			if !bytes.HasPrefix(line, dkimLiteral) {
				return errors.New("the fixed DKIM signature has another d= or s=")
			}
		}
	}
	for _, name := range singleNames {
		if counts[name] != 1 {
			return fmt.Errorf("%d %s fields, want 1", counts[name], name)
		}
	}
	if dkimCount != 1 {
		return fmt.Errorf("%d fixed DKIM signatures, want 1", dkimCount)
	}
	return nil
}

// The tags that follow the fixed signature's constant prefix.
func dkimTags(preamble *sessionPreamble) string {
	return literalDkimDomain + preamble.headerFromDomain + literalDkimSelector + preamble.dkimSelector + literalDkimEnd
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
	if len(local) < 1 || preamble.proof.LocalMaxByteCount < len(local) {
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

// Whether a carry on the wire opens to state under blind.
func checkCarryOpens(encoded []byte, state scanState, blind *big.Int) error {
	want, err := decodeCommitment(encoded)
	if err != nil {
		return err
	}
	if blind == nil {
		return errors.New("no blind")
	}
	commitment, err := commitCarry(uint32(state), blind)
	if err != nil {
		return err
	}
	if !commitment.Equal(&want) {
		return errors.New("the state and blind do not open the carry")
	}
	return nil
}

// Whether two octets agree as Z5 compares a field name: bit 5 forced on the record's octet, which
// lowercases a letter and keeps each octet rule 1 and H4 let a name hold. The literal's names are
// lowercase already.
func scanOctetMatches(octet byte, want byte, folded bool) bool {
	if folded {
		return octet|0x20 == want
	}
	return octet == want
}

// Whether content from start holds a literal's first count octets, every one inside the content.
func scanMatches(content []byte, start int, literal scanLiteral, count int) bool {
	if len(content) < start+count {
		return false
	}
	for j := range count {
		if !scanOctetMatches(content[start+j], literal.octets[j], literal.folded) {
			return false
		}
	}
	return true
}

// Z5 over one header record, DESIGN-DETAILS 3.2.4's H1 to H13, from the state in; the state it leaves.
// first is the header block's first record and last its last. The circuit computes the same state from
// the same octets, octet for octet, so a carry this commits to is the one the circuit opens.
func scanHeaderRecord(preamble *sessionPreamble, content []byte, in scanState, first bool, last bool) (scanState, error) {
	n := len(content)
	if n == 0 {
		return 0, errors.New("an empty header record")
	}
	// H13: the block ends in CR LF CR LF, the last two outside Field
	if last && !bytes.HasSuffix(content, []byte(literalCrlf+literalCrlf)) {
		return 0, errors.New("the header block does not end in CRLF CRLF")
	}
	field := func(i int) bool {
		return !last || i < n-len(literalCrlf)
	}
	bulk := preamble.flags&preambleFlagBulk != 0
	isWsp := func(octet byte) bool {
		return octet == ' ' || octet == '\t'
	}
	for i, octet := range content {
		// H1: HTAB, SP through ~, CR or LF
		switch {
		case octet == '\t', ' ' <= octet && octet <= '~', octet == '\r', octet == '\n':
		default:
			return 0, fmt.Errorf("octet %#x in the header block", octet)
		}
		// H2: LF exactly after CR, across the boundary by in's pos
		previousCr := in.pos() == scanPosCr
		if 0 < i {
			previousCr = content[i-1] == '\r'
		}
		if (octet == '\n') != previousCr {
			return 0, errors.New("a bare CR or LF")
		}
	}
	// H6, and H8 in the first record: no continuation after a single field or at the block's start
	if (in.single() || first) && isWsp(content[0]) {
		return 0, errors.New("a continuation where a field must start")
	}

	// H3 and H4
	lineStart := make([]bool, n)
	nameStart := make([]bool, n)
	inName := in.name()
	for i, octet := range content {
		previousLf := in.pos() == scanPosLf
		if 0 < i {
			previousLf = content[i-1] == '\n'
		}
		lineStart[i] = field(i) && previousLf
		if lineStart[i] && octet == '\r' {
			return 0, errors.New("an empty line before the end of the header block")
		}
		nameStart[i] = lineStart[i] && !isWsp(octet)
		// an MX reading DATA deletes a line's leading dot (RFC 5321 §4.5.2), so what Z5 read as some other
		// field would reach it as the field after the dot
		if nameStart[i] && (octet == ':' || octet == '.') {
			return 0, errors.New("a field name starts with a colon or a dot")
		}
		naming := inName || nameStart[i]
		if naming && (isWsp(octet) || octet == '\r') {
			return 0, errors.New("a field name holds SP, HTAB or CR before its colon")
		}
		inName = naming && octet != ':'
	}

	// H5: each literal at each name start, whole inside the record or running off its end
	var full, partial [scanLiteralCount][]bool
	for literal, entry := range scanLiterals {
		full[literal] = make([]bool, n)
		partial[literal] = make([]bool, n)
		for i := range n {
			if !nameStart[i] {
				continue
			}
			if i+len(entry.octets) <= n {
				full[literal][i] = scanMatches(content, i, entry, len(entry.octets))
			} else {
				partial[literal][i] = scanMatches(content, i, entry, n-i)
			}
		}
	}

	single := false
	if first {
		var err error
		if single, err = scanFirstHeaderRecord(preamble, content, &full, bulk); err != nil {
			return 0, err
		}
	} else {
		// H12: no literal whole in a later record, and none crossing in from the record before
		for literal, entry := range scanLiterals {
			if !scanLiteralCounts(literal, bulk) {
				continue
			}
			for i := range n {
				if full[literal][i] {
					return 0, fmt.Errorf("%q begins a line past the header block's first record", entry.octets)
				}
			}
			run := in.run()
			if in.prefix(literal) && 1 <= run && run < len(entry.octets) {
				rest := scanLiteral{octets: entry.octets[run:], folded: entry.folded}
				if scanMatches(content, 0, rest, len(rest.octets)) {
					return 0, fmt.Errorf("%q crosses into a later header record", entry.octets)
				}
			}
		}
	}

	// H7: the state after the last octet
	pos := uint32(scanPosLine)
	switch content[n-1] {
	case '\r':
		pos = scanPosCr
	case '\n':
		pos = scanPosLf
	}
	run := 0
	if pos != scanPosLf {
		lastStart := -1
		for i := range n {
			if lineStart[i] {
				lastStart = i
			}
		}
		switch {
		case 0 <= lastStart && nameStart[lastStart]:
			run = min(n-lastStart, scanRunMore)
		case lastStart < 0 && in.run() != 0:
			// a line that began in an earlier record and is no continuation
			run = scanRunMore
		}
	}
	var prefix [scanLiteralCount]bool
	for literal := range scanLiterals {
		for i := range n {
			if partial[literal][i] {
				prefix[literal] = true
			}
		}
	}
	return newScanState(pos, inName, run, prefix, single), nil
}

// H9 to H11 over the header block's first record: each single field and the fixed signature's prefix
// begins exactly one of its lines (the one-click field on a BULK message alone), each in its literal
// form, every such line whole inside the record and uncontinued there. Returns whether a single field's
// line ends at the record's last octet.
func scanFirstHeaderRecord(preamble *sessionPreamble, content []byte, full *[scanLiteralCount][]bool, bulk bool) (bool, error) {
	n := len(content)
	for literal, entry := range scanLiterals {
		if !scanLiteralCounts(literal, bulk) {
			continue
		}
		count := 0
		for i := range n {
			if full[literal][i] {
				count += 1
			}
		}
		if count != 1 {
			return false, fmt.Errorf("%d lines begin %q in the header block's first record, want 1", count, entry.octets)
		}
	}
	// H10: each literal form whole inside the record, at its one position
	at := func(literal int) int {
		for i := range n {
			if full[literal][i] {
				return i
			}
		}
		return -1
	}
	exact := func(start int, literal string) error {
		if start < 0 || n < start+len(literal) || string(content[start:start+len(literal)]) != literal {
			return fmt.Errorf("%q is not in its literal form inside the header block's first record", strings.TrimSuffix(literal, literalCrlf))
		}
		return nil
	}
	forms := []struct {
		literal int
		form    string
	}{
		{literal: scanLiteralMessageId, form: literalMessageIdPrefix + preamble.messageId + ">" + literalCrlf},
		{literal: scanLiteralXUrRef, form: literalXUrRefPrefix + preamble.xUrRef + literalCrlf},
		{literal: scanLiteralFeedbackId, form: literalFeedbackPrefix + preamble.feedbackId + literalCrlf},
	}
	if bulk {
		forms = append(forms, struct {
			literal int
			form    string
		}{literal: scanLiteralUnsubscribe, form: literalUnsubscribePost + literalCrlf})
	}
	for _, entry := range forms {
		if err := exact(at(entry.literal), entry.form); err != nil {
			return false, err
		}
	}
	if err := exact(at(scanLiteralDkim)+len(literalDkimPrefix), dkimTags(preamble)); err != nil {
		return false, errors.New("the fixed DKIM signature has another d= or s=, or runs past the first record")
	}
	from := at(scanLiteralFrom)
	fromEnd := bytes.Index(content[from:], []byte(literalCrlf))
	if fromEnd < 0 {
		return false, errors.New("From's line runs past the header block's first record")
	}
	if err := checkFromLine(content[from:from+fromEnd], preamble); err != nil {
		return false, err
	}

	// H11: a single field's line is not continued inside the record; whether one ends at its end
	inField := false
	single := false
	for i, octet := range content {
		for literal := range scanLiterals {
			if full[literal][i] && scanLiteralSingle(literal, bulk) {
				inField = true
			}
		}
		if octet != '\n' || !inField {
			continue
		}
		inField = false
		if i+1 == n {
			single = true
		} else if content[i+1] == ' ' || content[i+1] == '\t' {
			return false, errors.New("a single field is continued")
		}
	}
	return single, nil
}

// Z6 over one DATA body record, DESIGN-DETAILS 3.2.4's B1 to B3, from the state in; the state it leaves.
// last is the body's last record, which ends in LF so that the end mark starts a line.
func scanBodyRecord(content []byte, in scanState, last bool) (scanState, error) {
	if in != newScanState(in.pos(), false, 0, [scanLiteralCount]bool{}, false) {
		return 0, errors.New("a body's scan state holds its pos alone")
	}
	n := len(content)
	// B2 at the boundary: a "." that began the record before's last line is not followed by CR
	if 0 < n && in.pos() == scanPosDot && content[0] == '\r' {
		return 0, errors.New("a line that is exactly the end mark")
	}
	pos := in.pos()
	for i, octet := range content {
		// B1: LF exactly after CR, across the boundary by in's pos
		previousCr := in.pos() == scanPosCr
		lineStart := in.pos() == scanPosLf
		if 0 < i {
			previousCr = content[i-1] == '\r'
			lineStart = content[i-1] == '\n'
		}
		if (octet == '\n') != previousCr {
			return 0, errors.New("a bare CR or LF")
		}
		// B2: a "." at a line's start is not followed by CR
		dotStart := lineStart && octet == '.'
		if dotStart && i+1 < n && content[i+1] == '\r' {
			return 0, errors.New("a line that is exactly the end mark")
		}
		// B3
		switch {
		case octet == '\r':
			pos = scanPosCr
		case octet == '\n':
			pos = scanPosLf
		case dotStart:
			pos = scanPosDot
		default:
			pos = scanPosLine
		}
	}
	if last && (n == 0 || content[n-1] != '\n') {
		return 0, errors.New("the body does not end in CRLF")
	}
	return newScanState(pos, false, 0, [scanLiteralCount]bool{}, false), nil
}

// Z6's rules over a whole DATA body in one pass: it ends in CRLF, holds no bare CR or LF, and no line
// that is exactly ".". The relation checks a body a record at a time (scanBodyRecord); this is the
// definition those records must agree with, across every cut, which the tests hold them to.
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

// Z5: the header record a part opens, scanned from the start state or the gate's carry, leaving the
// state the part's own carry commits to (DESIGN-DETAILS 3.2.4).
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
			return errors.New("witness holds no header record")
		}
		ordinal := headerOrdinal(statement, statement.clientRecords[i].seq)
		in := scanStart
		if 1 < ordinal {
			in = witness.carryInState
			if err := checkCarryOpens(statement.carryIn, in, witness.carryInBlind); err != nil {
				return fmt.Errorf("the carry in: %w", err)
			}
		}
		content := clientContent(session.version, witness.clientPlaintexts[i])
		out, err := scanHeaderRecord(session.preamble, content, in, ordinal == 1, ordinal == int(statement.headerRecordCount))
		if err != nil {
			return err
		}
		if err := checkCarryOpens(statement.carryOut, out, witness.carryOutBlind); err != nil {
			return fmt.Errorf("the carry out: %w", err)
		}
	}
	return nil
}

// Z6: the end of the message. QUIT and the end mark are exact; in BDAT mode the header block alone
// stays within the declared count; DATA's body records scan across their boundaries by the carries, the
// last ending in CRLF, and an empty body's end mark starts a line.
func relationZ6(statement *partStatement, witness *partWitness) error {
	roles, err := partRoles(statement)
	if err != nil || len(roles) != len(witness.clientPlaintexts) {
		// the part's shape is Z4's to refuse
		return nil
	}
	session := statement.session
	opened := false
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
			if statement.mode == partModeBdat && session.preamble.messageByteCount < uint64(len(content)) {
				return errors.New("a header record alone passes the declared octet count")
			}
		case recordRoleBody:
			opened = true
			if err := checkCarryOpens(statement.carryIn, witness.carryInState, witness.carryInBlind); err != nil {
				return fmt.Errorf("the carry in: %w", err)
			}
			out, err := scanBodyRecord(content, witness.carryInState, statement.last)
			if err != nil {
				return err
			}
			if err := checkCarryOpens(statement.carryOut, out, witness.carryOutBlind); err != nil {
				return fmt.Errorf("the carry out: %w", err)
			}
		}
	}
	// an empty body's last part opens the end mark alone, at a line's start, and leaves the state as it was
	if statement.mode == partModeData && statement.last && !opened {
		if err := checkCarryOpens(statement.carryIn, witness.carryInState, witness.carryInBlind); err != nil {
			return fmt.Errorf("the carry in: %w", err)
		}
		if witness.carryInState.pos() != scanPosLf {
			return errors.New("the end mark does not start a line")
		}
		if err := checkCarryOpens(statement.carryOut, witness.carryInState, witness.carryOutBlind); err != nil {
			return fmt.Errorf("the carry out: %w", err)
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

// Z8, per part (DESIGN-DETAILS 3.2.3): the server records the part covers hold exactly its reply_count
// whole replies; part 2's one reply has every line coded 250; every reply is coded 2xx, except that on
// the part whose replies complete DATA mode's envelope the last is coded 354.
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
	if uint64(len(replies)) != uint64(statement.replyCount) {
		return fmt.Errorf("the server records hold %d replies, the part names %d", len(replies), statement.replyCount)
	}
	for i, reply := range replies {
		if statement.ehloRule() {
			for _, code := range reply.lineCodes {
				if code != "250" {
					return fmt.Errorf("EHLO reply line coded %s, want 250", code)
				}
			}
		}
		if statement.last354() && i == len(replies)-1 {
			if reply.code != "354" {
				return fmt.Errorf("DATA got %s, want 354", reply.code)
			}
		} else if reply.code[0] != '2' {
			return fmt.Errorf("reply %d is %s, want 2xx", i, reply.code)
		}
	}
	return nil
}

// Whether an application record among a part's server plaintexts holds a whole CHUNKING line that is
// not its reply's first. The circuit matches CR LF, 250, a separator, the keyword and CR LF at positions
// inside one record, so a line at a record's edge does not count (SPEC.md reading 17), and this is that
// same test, so that the two agree. A ticket's octets are no part of the reply stream.
func offersChunking(version uint16, plaintexts [][]byte) bool {
	const prefix = "\r\n250"
	windowBytes := len(prefix) + 1 + len(keywordChunking) + len(literalCrlf)
	matches := func(window []byte) bool {
		separator := window[len(prefix)]
		word := window[len(prefix)+1 : windowBytes-len(literalCrlf)]
		return string(window[:len(prefix)]) == prefix && (separator == '-' || separator == ' ') &&
			asciiLower(word) == keywordChunking && string(window[windowBytes-len(literalCrlf):]) == literalCrlf
	}
	for _, plaintext := range plaintexts {
		content := plaintext
		if version == tlsVersion13 {
			if len(plaintext) == 0 || plaintext[len(plaintext)-1] != tlsRecordApplicationData {
				continue
			}
			content = plaintext[:len(plaintext)-tlsInnerTypeBytes]
		}
		for i := 0; i+windowBytes <= len(content); i += 1 {
			if matches(content[i : i+windowBytes]) {
				return true
			}
		}
	}
	return false
}

// Z9: BDAT only to an MX whose post-TLS EHLO reply offers CHUNKING.
func relationZ9(statement *partStatement, witness *partWitness) error {
	if !statement.requireChunking() {
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
	if offersChunking(statement.session.version, witness.serverPlaintexts) {
		return nil
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
