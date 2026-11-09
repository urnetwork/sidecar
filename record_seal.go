// RECORD.md section 5.2's sealing, in section 5.3's order, and its opening, on every leg: the writer's RecordSeal, and
// RecordOpen for readers (section 5.5's body step) and ingesters (section 5.4's body step).
//
// An entry is built in one order: the caller redacts (§16.7), then RecordSeal marshals the body once with
// Deterministic: true and keeps those bytes, draws the entry_id, the key, the salt and the nonce, commits, seals the
// body, takes the next (seq, prev_sha256) of its log's chain, signs, and journals (record_chain.go), all before the
// entry can leave the daemon. The key and salt are 32 random bytes each, per entry, never reused (owner decision
// 61): together they are the entry's slot row, key || salt, which leaves the daemon only wrapped, under fek_g in a
// slot object (§11.6) or sealed to a drop key in a deposit (§11.12), and an ERASE that names the row erases the body
// for good (§16.8). The entry file holding the RecordEntry is sealed again by the binding under the file's own key,
// which erasing this one leaves alone, so headers and chains still verify after erasure.
//
// sealed_body is 24 random nonce bytes || XChaCha20-Poly1305(key, nonce, body, aad), §11.6's AEAD in one shot, aad
// "urnetwork-sidecar-v1/record-seal" || log_id || entry_id, so a body moved to another entry or log does not open.
// Only the identity key signs the header (§6.9): agent ids stay sealed inside it, and from M6 an agent subkey signs
// inside the body (RecordEntry.version 2), never the header.
//
// Package-level functions are safe for concurrent use. A RecordSealedEntry is not: it holds its key and salt, which
// Clear wipes once the entry is pushed or deposited.

package sidecar

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// RECORD.md section 5.2's sizes and domain, which are format values.
const (
	// An entry's body key, drawn per entry and never reused (owner decision 61).
	RecordKeyByteCount = chacha20poly1305.KeySize
	// key || salt, the plaintext of an entry's slot row: 64 bytes, 104 wrapped with its nonce and tag, so 64 rows fit
	// a slot object inside 8 KiB (§11.6).
	RecordSlotRowByteCount = RecordKeyByteCount + RecordSaltByteCount
	// sealed_body's leading nonce.
	RecordSealNonceByteCount = chacha20poly1305.NonceSizeX

	recordSealDomain = "urnetwork-sidecar-v1/record-seal"
	// The RecordEntry.version this build writes. 2 is M6's agent-signed body (RECORD.md section 5.3's agent key row).
	recordEntryVersion = 1
	// RecordEntry's field numbers (§16.8), which EntryBytes writes by hand so an entry's bytes never move with how
	// protobuf encodes (record_seal_test.go holds them to the descriptor).
	recordEntryHeaderField     = 1
	recordEntrySealedBodyField = 2
	recordEntryKeySlotIdField  = 3
	recordEntryVersionField    = 4
	recordEntryKeyIndexField   = 5
)

var (
	// What a writer asked to seal breaks a rule a header or body holds, or its signer answered as another sidecar:
	// nothing was journaled, and the log's next seq is still the one it was.
	ErrRecordSealInvalid = errors.New("record seal invalid")
	// A sealed_body that does not open under its key and aad, or a body whose commitment is not the header's: RECORD.md
	// section 5.5's invalid body, which a reader alarms on and shows as invalid, its header standing, and section 5.4's,
	// which an ingester consumes unrecorded.
	ErrRecordBodyInvalid = errors.New("record body invalid")
)

// One entry for one log, as RecordSeal takes it: every header field the writer chooses. Sealing sets the rest:
// entry_id, writer_sidecar_id, seq, prev_sha256 and body_commitment. Routing, taint and the run belong to the writer
// (RECORD.md sections 4.2 and 5.3), which fills these from them.
type RecordSealArgs struct {
	// The log's repo id.
	LogId Id
	// A kind RECORD.md section 6.3 names, never a derived name.
	Kind RecordKind
	// Section 6.3's source for the kind's writer: never 0.
	Source RecordSource
	// None exactly when AgentId is nil (section 6.2).
	AgentSource RecordAgentSource
	AgentId     *Id
	RunId       *Id
	// 32 bytes (§16.6's action_id, or a tool's, section 4.4), or empty.
	ActionId []byte
	// The capture time on this writer's clock: for spooled capture, when it was captured, not when it is sealed.
	// Order never rests on it (section 5.3's time row).
	TimeMillis int64
	// The run's bit at sealing, failing closed (section 5.3's tainted row).
	Tainted bool
	Content []*protocol.ContentRef
	// The writer's AuthPin version.
	PolicyVersion uint64
	// The grant the action ran under (AclGrantId, 32 bytes), or empty.
	GrantId []byte
	// The kind's one body message (section 6.4), marshaled once here with Deterministic: true: for approval_decision,
	// approval_cancel and retention a Signed of the kind's own type.
	Body proto.Message
}

// What RecordSeal needs of its sidecar.
type RecordSealEnv struct {
	// The record component's chain store, whose writer this sidecar is.
	Chain *RecordChainStore
	// Sidecar.Sign: the identity key signs every header, purpose record-entry, SIGNED_RECORD_HEADER (§6.9).
	Sign func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error)
	// crypto/rand's reader when nil. A test fixes it to seal golden entries: an entry draws, in order, its entry_id
	// (16 bytes), key (32), salt (32) and nonce (24).
	Random io.Reader
}

// One entry sealed, signed and journaled (RECORD.md section 5.3), which the writer pushes or deposits as it is. A
// retry sends these bytes again, and nothing signs the entry a second time (D-MCP-10); only a rebuilt push's slot id
// and key index, which lie outside the signed header, may differ (§16.8).
type RecordSealedEntry struct {
	LogId   Id
	EntryId Id
	Seq     uint64
	// RFC 9162's leaf over the header's stored bytes: the chain's next prev_sha256, and the entry's leaf in M6's log.
	Leaf [sha256.Size]byte
	// The header's Signed, as marshaled once at signing and stored since.
	Signed []byte
	// 24 nonce bytes || XChaCha20-Poly1305 of the body under Key.
	SealedBody []byte
	// The slot row's halves, secrets: wrapped before they leave the daemon, and cleared once the entry is pushed or
	// deposited.
	Key  []byte
	Salt []byte
}

// The stored header, parsed from the entry's Signed with the bytes its leaf and signature cover.
func (self *RecordSealedEntry) Header() (*StoredRecordHeader, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(self.Signed, signed); err != nil {
		return nil, fmt.Errorf("%w: header's Signed: %v", ErrRecordStoredInvalid, err)
	}
	return ParseStoredRecordHeader(signed.GetBody())
}

// The entry's slot row at keyIndex of its push's slot object: key || salt, before the binding wraps it under fek_g.
// A copy.
func (self *RecordSealedEntry) SlotRow(keyIndex uint32) *RecordSlotRow {
	row := make([]byte, 0, RecordSlotRowByteCount)
	row = append(row, self.Key...)
	return &RecordSlotRow{KeyIndex: keyIndex, Row: append(row, self.Salt...)}
}

// The RecordEntry's bytes for a stream file: the stored Signed and sealed_body, version 1, and the slot row's place,
// slotId nil and keyIndex 0 for a deposit, where the ingester re-slots it (RECORD.md section 5.4). The same arguments
// give the same bytes, however protobuf comes to encode, so a retried push carries exactly what it carried before.
func (self *RecordSealedEntry) EntryBytes(slotId *Id, keyIndex uint32) []byte {
	entry := make([]byte, 0, len(self.Signed)+len(self.SealedBody)+48)
	entry = protowire.AppendTag(entry, recordEntryHeaderField, protowire.BytesType)
	entry = protowire.AppendBytes(entry, self.Signed)
	entry = protowire.AppendTag(entry, recordEntrySealedBodyField, protowire.BytesType)
	entry = protowire.AppendBytes(entry, self.SealedBody)
	if slotId != nil {
		entry = protowire.AppendTag(entry, recordEntryKeySlotIdField, protowire.BytesType)
		entry = protowire.AppendBytes(entry, slotId[:])
	}
	entry = protowire.AppendTag(entry, recordEntryVersionField, protowire.VarintType)
	entry = protowire.AppendVarint(entry, recordEntryVersion)
	if keyIndex != 0 {
		entry = protowire.AppendTag(entry, recordEntryKeyIndexField, protowire.VarintType)
		entry = protowire.AppendVarint(entry, uint64(keyIndex))
	}
	return entry
}

// The entry as one RecordDeposit of a deposit batch: its RecordEntry with no slot, and the key and salt the ingester
// re-slots (RECORD.md section 5.4). Copies.
func (self *RecordSealedEntry) Deposit() *protocol.RecordDeposit {
	return &protocol.RecordDeposit{
		Entry: self.EntryBytes(nil, 0),
		Key:   bytes.Clone(self.Key),
		Salt:  bytes.Clone(self.Salt),
	}
}

// Wipes the key and salt. The signed header and sealed body stay, since they are what a retry sends.
func (self *RecordSealedEntry) Clear() {
	clear(self.Key)
	clear(self.Salt)
	self.Key = nil
	self.Salt = nil
}

// "urnetwork-sidecar-v1/record-seal" || log_id || entry_id, both 16 bytes, so the concatenation is unambiguous.
func recordSealAad(logId []byte, entryId []byte) []byte {
	aad := make([]byte, 0, len(recordSealDomain)+len(logId)+len(entryId))
	aad = append(aad, recordSealDomain...)
	aad = append(aad, logId...)
	return append(aad, entryId...)
}

// The rules a header and body hold before anything is drawn: a kind a v1 writer may write, a source and agent source
// section 6.2 names, ids, hashes and content refs at their lengths, a capture time, and the kind's one body message.
func (self *RecordSealArgs) check() error {
	if self.LogId == (Id{}) {
		return fmt.Errorf("%w: no log", ErrRecordSealInvalid)
	}
	if !self.Kind.Writable() {
		return fmt.Errorf("%w: kind %d is not one a v1 writer writes", ErrRecordSealInvalid, uint32(self.Kind))
	}
	if !self.Source.Known() || self.Source == RecordSourceUnknown {
		return fmt.Errorf("%w: source %d", ErrRecordSealInvalid, uint32(self.Source))
	}
	if !self.AgentSource.Known() {
		return fmt.Errorf("%w: agent source %d", ErrRecordSealInvalid, uint32(self.AgentSource))
	}
	if (self.AgentId == nil) != (self.AgentSource == RecordAgentSourceNone) {
		return fmt.Errorf("%w: agent source %s with agent id set %t", ErrRecordSealInvalid, self.AgentSource, self.AgentId != nil)
	}
	if len(self.ActionId) != 0 && len(self.ActionId) != recordHashByteCount {
		return fmt.Errorf("%w: action_id of %d bytes", ErrRecordSealInvalid, len(self.ActionId))
	}
	if len(self.GrantId) != 0 && len(self.GrantId) != recordHashByteCount {
		return fmt.Errorf("%w: grant_id of %d bytes", ErrRecordSealInvalid, len(self.GrantId))
	}
	if self.TimeMillis <= 0 {
		return fmt.Errorf("%w: no capture time", ErrRecordSealInvalid)
	}
	for _, content := range self.Content {
		if content == nil || len(content.GetRepoId()) != recordIdByteCount || len(content.GetObjectId()) != recordIdByteCount ||
			len(content.GetCommitment()) != recordHashByteCount {
			return fmt.Errorf("%w: a content ref whose ids or commitment are not their lengths", ErrRecordSealInvalid)
		}
	}
	if self.Body == nil {
		return fmt.Errorf("%w: no body", ErrRecordSealInvalid)
	}
	wantBody, _ := self.Kind.NewBody()
	if proto.MessageName(self.Body) != proto.MessageName(wantBody) {
		return fmt.Errorf("%w: kind %s takes %s, not %s", ErrRecordSealInvalid, self.Kind, proto.MessageName(wantBody), proto.MessageName(self.Body))
	}
	if _, signedType, ok := self.Kind.NewSignedBody(); ok {
		signed, _ := self.Body.(*bridge.Signed)
		if signed == nil || signed.GetType() != uint32(signedType) {
			return fmt.Errorf("%w: kind %s takes a Signed of type %#x", ErrRecordSealInvalid, self.Kind, int32(signedType))
		}
	}
	return nil
}

// The header the args and the chain's (seq, prev_sha256) make, marshaled once.
func (self *RecordSealArgs) header(entryId Id, writerSidecarId Id, seq uint64, prev [sha256.Size]byte, commitment [sha256.Size]byte) ([]byte, error) {
	header := &protocol.RecordHeader{
		EntryId:         entryId.Bytes(),
		LogId:           self.LogId.Bytes(),
		WriterSidecarId: writerSidecarId.Bytes(),
		Seq:             seq,
		PrevSha256:      bytes.Clone(prev[:]),
		ActionId:        bytes.Clone(self.ActionId),
		Kind:            uint32(self.Kind),
		TimeMillis:      self.TimeMillis,
		Source:          uint32(self.Source),
		Tainted:         self.Tainted,
		BodyCommitment:  bytes.Clone(commitment[:]),
		PolicyVersion:   self.PolicyVersion,
		GrantId:         bytes.Clone(self.GrantId),
		AgentSource:     uint32(self.AgentSource),
	}
	if self.AgentId != nil {
		header.AgentId = self.AgentId.Bytes()
	}
	if self.RunId != nil {
		header.RunId = self.RunId.Bytes()
	}
	for _, content := range self.Content {
		header.Content = append(header.Content, proto.CloneOf(content))
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(header)
}

// Seals args as the next entry of its log's chain, in RECORD.md section 5.3's order, and returns it once its journal
// record is fsynced, before it can leave the daemon. A refusal before signing draws, signs and journals nothing; a
// failure to sign or journal leaves the chain where it was, so the draft takes that seq again and no seq is burned.
// While the daemon is locked, Sign answers ErrSidecarStoreLocked and the writer spools (§16.7).
func RecordSeal(env *RecordSealEnv, args *RecordSealArgs) (*RecordSealedEntry, error) {
	if env == nil || env.Chain == nil || env.Sign == nil {
		return nil, fmt.Errorf("%w: no chain or signer", ErrRecordSealInvalid)
	}
	if args == nil {
		return nil, fmt.Errorf("%w: no entry", ErrRecordSealInvalid)
	}
	if err := args.check(); err != nil {
		return nil, err
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(args.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrRecordSealInvalid, err)
	}

	random := env.Random
	if random == nil {
		random = cryptorand.Reader
	}
	var entryId Id
	key := make([]byte, RecordKeyByteCount)
	salt := make([]byte, RecordSaltByteCount)
	nonce := make([]byte, RecordSealNonceByteCount)
	for _, draw := range [][]byte{entryId[:], key, salt, nonce} {
		if _, err := io.ReadFull(random, draw); err != nil {
			return nil, fmt.Errorf("record seal: draw: %w", err)
		}
	}
	testHookSecret("record_entry_key", key)
	testHookSecret("record_entry_salt", salt)

	commitment, err := RecordBodyCommitment(salt, body)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("record seal: %w", err)
	}
	sealedBody := aead.Seal(nonce, nonce, body, recordSealAad(args.LogId[:], entryId[:]))

	writerSidecarId := env.Chain.WriterSidecarId()
	return env.Chain.append(args.LogId, func(seq uint64, prev [sha256.Size]byte) (*RecordSealedEntry, error) {
		headerBytes, err := args.header(entryId, writerSidecarId, seq, prev, commitment)
		if err != nil {
			return nil, fmt.Errorf("%w: header: %v", ErrRecordSealInvalid, err)
		}
		// what every reader parses first, so a header it would refuse never reaches the signer
		if _, err := ParseStoredRecordHeader(headerBytes); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRecordSealInvalid, err)
		}
		// nil: only the identity key signs a header, whatever agent filed the entry (§6.9)
		signed, err := env.Sign(RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, headerBytes, nil)
		if err != nil {
			return nil, fmt.Errorf("record seal: sign: %w", err)
		}
		if signed.GetType() != uint32(bridge.SignedType_SIGNED_RECORD_HEADER) || !bytes.Equal(signed.GetBody(), headerBytes) ||
			!bytes.Equal(signed.GetSignerId(), writerSidecarId[:]) {
			// a reader refuses a header whose signer is not its writer, so such an entry must never go out
			return nil, fmt.Errorf("%w: the signer did not sign this header as its writer", ErrRecordSealInvalid)
		}
		signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil {
			return nil, fmt.Errorf("record seal: %w", err)
		}
		return &RecordSealedEntry{
			LogId:      args.LogId,
			EntryId:    entryId,
			Seq:        seq,
			Leaf:       RecordLeafHash(headerBytes),
			Signed:     signedBytes,
			SealedBody: sealedBody,
			Key:        key,
			Salt:       salt,
		}, nil
	})
}

// Opens an entry's sealed_body with its slot row's key and salt, from a slot the binding unwrapped or a deposit: the
// AEAD under the verified header's log_id and entry_id, then body_commitment recomputed over the opened bytes and
// held to the header's. Returns the body as stored, which the reader parses as its kind's one message keeping these
// bytes (RECORD.md section 5.5's kind step). ErrRecordBodyInvalid for a body that does not open or does not commit;
// the header stands either way. The caller verifies the header's signature first.
func RecordOpen(header *StoredRecordHeader, sealedBody []byte, key []byte, salt []byte) ([]byte, error) {
	if header == nil || header.Header == nil {
		return nil, fmt.Errorf("%w: no header", ErrRecordBodyInvalid)
	}
	if len(key) != RecordKeyByteCount || len(salt) != RecordSaltByteCount {
		return nil, fmt.Errorf("%w: a key of %d bytes and a salt of %d", ErrRecordBodyInvalid, len(key), len(salt))
	}
	testHookSecret("record_entry_key", key)
	testHookSecret("record_entry_salt", salt)
	if len(sealedBody) < RecordSealNonceByteCount+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("%w: a sealed body of %d bytes", ErrRecordBodyInvalid, len(sealedBody))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordBodyInvalid, err)
	}
	nonce := sealedBody[:RecordSealNonceByteCount]
	aad := recordSealAad(header.Header.GetLogId(), header.Header.GetEntryId())
	body, err := aead.Open(nil, nonce, sealedBody[RecordSealNonceByteCount:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: it does not open", ErrRecordBodyInvalid)
	}
	commitment, err := RecordBodyCommitment(salt, body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordBodyInvalid, err)
	}
	if !bytes.Equal(commitment[:], header.Header.GetBodyCommitment()) {
		return nil, fmt.Errorf("%w: its commitment is not the header's", ErrRecordBodyInvalid)
	}
	return body, nil
}

// key || salt as one slot row's plaintext, for a binding to wrap. Copies.
func RecordSlotRowJoin(key []byte, salt []byte) ([]byte, error) {
	if len(key) != RecordKeyByteCount || len(salt) != RecordSaltByteCount {
		return nil, fmt.Errorf("%w: a key of %d bytes and a salt of %d", ErrRecordStoredInvalid, len(key), len(salt))
	}
	row := make([]byte, 0, RecordSlotRowByteCount)
	row = append(row, key...)
	return append(row, salt...), nil
}

// The key and salt of a slot row the binding unwrapped: the record's own unwrap of an entry's keys, where the privacy
// harness learns them on a reader. Copies.
func RecordSlotRowSplit(row []byte) (key []byte, salt []byte, err error) {
	if len(row) != RecordSlotRowByteCount {
		return nil, nil, fmt.Errorf("%w: a slot row of %d bytes", ErrRecordStoredInvalid, len(row))
	}
	key = bytes.Clone(row[:RecordKeyByteCount])
	salt = bytes.Clone(row[RecordKeyByteCount:])
	testHookSecret("record_entry_key", key)
	testHookSecret("record_entry_salt", salt)
	return key, salt, nil
}
