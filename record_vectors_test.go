// record.proto's freeze vectors (RECORD-M3-11; D-MCP-6, X20; §23.8): testdata/record/vectors.json holds, over stored
// bytes, one entry of every kind M3 writes, sealed in one writer's chain in one log, with each entry's header, Signed,
// sealed body, commitment and leaf, its slot row, a deposit batch of the first two, the approval decision as its
// Signed, and one action of each kind NewCanonicalAction builds. The file is embedded, so every §4.7 leg checks the
// same bytes: this file reads them and computes each value again on the leg it runs on, and
// record_vectors_fixture_test.go, off the js leg, seals the fixture again to the same bytes and rewrites the file.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/record/vectors.json
var testRecordFreezeVectorBytes []byte

// One sealed entry of the vectors, in lowercase hex.
type testRecordFreezeEntry struct {
	Kind   string `json:"kind"`
	KindNo uint32 `json:"kind_no"`
	// the entry's draws in order: entry_id (16 bytes), key (32), salt (32), nonce (24)
	Random         string `json:"random"`
	Body           string `json:"body"`
	Seq            uint64 `json:"seq"`
	PrevSha256     string `json:"prev_sha256"`
	Header         string `json:"header"`
	Signed         string `json:"signed"`
	SealedBody     string `json:"sealed_body"`
	BodyCommitment string `json:"body_commitment"`
	Leaf           string `json:"leaf"`
	KeyIndex       uint32 `json:"key_index"`
	SlotRow        string `json:"slot_row"`
	Entry          string `json:"entry"`
}

// One stored action of the vectors.
type testRecordFreezeAction struct {
	Name          string `json:"name"`
	KindNo        uint32 `json:"kind_no"`
	Stored        string `json:"stored"`
	PayloadSha256 string `json:"payload_sha256"`
}

// testdata/record/vectors.json.
type testRecordFreezeVectors struct {
	Comment         string                   `json:"comment"`
	IdentitySeed    string                   `json:"identity_seed"`
	WriterSidecarId string                   `json:"writer_sidecar_id"`
	LogId           string                   `json:"log_id"`
	SlotId          string                   `json:"slot_id"`
	Entries         []*testRecordFreezeEntry `json:"entries"`
	// a RecordDepositBatch of the first two entries, as a depositor sends them
	DepositBatch string `json:"deposit_batch"`
	// the approver's seed, the decision's Signed as stored, and what it binds
	ApproverSeed          string                    `json:"approver_seed"`
	Decision              string                    `json:"decision"`
	DecisionRequestSha256 string                    `json:"decision_request_sha256"`
	DecisionPayloadSha256 string                    `json:"decision_payload_sha256"`
	Actions               []*testRecordFreezeAction `json:"actions"`
}

// The kinds M3 writes (RECORD.md section 20's M3 row), ascending.
var testRecordFreezeKinds = []RecordKind{
	RecordKindClaim, RecordKindHandoff, RecordKindAsk, RecordKindAnswer, RecordKindCheck, RecordKindNote,
	RecordKindContext, RecordKindChange, RecordKindPermission, RecordKindApproval, RecordKindApprovalDecision,
	RecordKindApprovalCancel, RecordKindApprovalUse, RecordKindRestore,
	RecordKindMembership, RecordKindKey, RecordKindCoverage, RecordKindRead, RecordKindErasure, RecordKindInventory,
	RecordKindTranscript, RecordKindToolCall, RecordKindHookEvent, RecordKindBlob,
}

// Hex as bytes.
func testRecordFreezeHex(t *testing.T, text string) []byte {
	t.Helper()
	value, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// The embedded vectors, parsed.
func testRecordFreezeLoad(t *testing.T) *testRecordFreezeVectors {
	t.Helper()
	vectors := &testRecordFreezeVectors{}
	if err := json.Unmarshal(testRecordFreezeVectorBytes, vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

// Every M3 kind has its entry, and each entry's bytes stand on their own on this leg: the header verifies under the
// seed's key and signs again to the same signature, its leaf is the next one's prev_sha256 from 32 zero bytes, its
// body opens under the key and salt of its slot row and commits to the header's commitment, and its RecordEntry holds
// exactly its Signed and sealed body at its slot.
func TestRecordFreezeVectorsVerifyOnThisLeg(t *testing.T) {
	vectors := testRecordFreezeLoad(t)
	key := ed25519.NewKeyFromSeed(testRecordFreezeHex(t, vectors.IdentitySeed))
	publicKey := key.Public().(ed25519.PublicKey)
	writer := testRecordFreezeHex(t, vectors.WriterSidecarId)
	logId := testRecordFreezeHex(t, vectors.LogId)
	slotId := testRecordFreezeHex(t, vectors.SlotId)
	kinds := []RecordKind{}
	prev := make([]byte, 32)
	for index, c := range vectors.Entries {
		kinds = append(kinds, RecordKind(c.KindNo))
		if RecordKind(c.KindNo).String() != c.Kind {
			t.Errorf("entry %d: kind %d is named %s here, %s in the file", index, c.KindNo, RecordKind(c.KindNo), c.Kind)
		}
		headerBytes := testRecordFreezeHex(t, c.Header)
		signedBytes := testRecordFreezeHex(t, c.Signed)
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(signedBytes, signed); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(signed.GetBody(), headerBytes) || !bytes.Equal(signed.GetSignerId(), writer) {
			t.Errorf("%s: the Signed holds another header or signer", c.Kind)
		}
		if err := bridge.VerifySigned(signed, RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, bridge.SignedKeyAlgEd25519, publicKey); err != nil {
			t.Errorf("%s: %v", c.Kind, err)
		}
		// Ed25519 signs deterministically: this leg signs the stored header to the stored signature
		if again := ed25519.Sign(key, bridge.SignedBytes(RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, headerBytes)); !bytes.Equal(again, signed.GetSignature()) {
			t.Errorf("%s: this leg signs the header to another signature", c.Kind)
		}
		header, err := ParseStoredRecordHeader(headerBytes)
		if err != nil {
			t.Fatal(err)
		}
		if header.Header.GetKind() != c.KindNo || header.Header.GetSeq() != uint64(index+1) || c.Seq != uint64(index+1) {
			t.Errorf("%s: kind %d at seq %d", c.Kind, header.Header.GetKind(), header.Header.GetSeq())
		}
		if !bytes.Equal(header.Header.GetPrevSha256(), prev) || c.PrevSha256 != hex.EncodeToString(prev) {
			t.Errorf("%s does not chain", c.Kind)
		}
		leaf := RecordLeafHash(headerBytes)
		if hex.EncodeToString(leaf[:]) != c.Leaf {
			t.Errorf("%s: leaf %x", c.Kind, leaf)
		}
		prev = leaf[:]
		// the stored header is canonical: this leg's deterministic encoding of what it parsed is the same bytes
		if again, err := (proto.MarshalOptions{Deterministic: true}).Marshal(header.Header); err != nil || !bytes.Equal(again, headerBytes) {
			t.Errorf("%s: this leg encodes the header to other bytes: %v", c.Kind, err)
		}
		random := testRecordFreezeHex(t, c.Random)
		if len(random) != 16+RecordKeyByteCount+RecordSaltByteCount+RecordSealNonceByteCount {
			t.Fatalf("%s: %d random bytes", c.Kind, len(random))
		}
		entryId, bodyKey, salt, nonce := random[:16], random[16:48], random[48:80], random[80:]
		if !bytes.Equal(header.Header.GetEntryId(), entryId) || !bytes.Equal(header.Header.GetLogId(), logId) ||
			!bytes.Equal(header.Header.GetWriterSidecarId(), writer) {
			t.Errorf("%s names another entry, log or writer", c.Kind)
		}
		body := testRecordFreezeHex(t, c.Body)
		sealedBody := testRecordFreezeHex(t, c.SealedBody)
		opened, err := RecordOpen(header, sealedBody, bodyKey, salt)
		if err != nil {
			t.Fatalf("%s: %v", c.Kind, err)
		}
		if !bytes.Equal(opened, body) || !bytes.Equal(sealedBody[:RecordSealNonceByteCount], nonce) {
			t.Errorf("%s opened to another body, or under another nonce", c.Kind)
		}
		commitment, err := RecordBodyCommitment(salt, body)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(commitment[:]) != c.BodyCommitment || !bytes.Equal(header.Header.GetBodyCommitment(), commitment[:]) {
			t.Errorf("%s: commitment %x", c.Kind, commitment)
		}
		if err := RecordBodyValidateStored(RecordKind(c.KindNo), body); err != nil {
			t.Errorf("%s: its stored body: %v", c.Kind, err)
		}
		// the slot row is key || salt, split and joined alike
		row := testRecordFreezeHex(t, c.SlotRow)
		rowKey, rowSalt, err := RecordSlotRowSplit(row)
		if err != nil {
			t.Fatal(err)
		}
		joined, err := RecordSlotRowJoin(bodyKey, salt)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rowKey, bodyKey) || !bytes.Equal(rowSalt, salt) || !bytes.Equal(joined, row) || c.KeyIndex != uint32(index) {
			t.Errorf("%s: its slot row is not its key and salt at index %d", c.Kind, index)
		}
		entryBytes := testRecordFreezeHex(t, c.Entry)
		entry := &protocol.RecordEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(entry.GetHeader(), signed) || !bytes.Equal(entry.GetSealedBody(), sealedBody) || !bytes.Equal(entry.GetKeySlotId(), slotId) ||
			entry.GetKeyIndex() != c.KeyIndex || entry.GetVersion() != 1 {
			t.Errorf("%s: its RecordEntry does not hold what was sealed", c.Kind)
		}
		// the hand decoder reads the same fields as proto.Unmarshal, the Signed's bytes as stored
		fields := &recordEntryFields{}
		if err := fields.parse(entryBytes); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(fields.signed, signedBytes) || !bytes.Equal(fields.sealedBody, sealedBody) || !bytes.Equal(fields.keySlotId, slotId) ||
			fields.keyIndex != c.KeyIndex || fields.version != 1 {
			t.Errorf("%s: the entry's fields read by hand differ from its message", c.Kind)
		}
	}
	if !slices.Equal(kinds, testRecordFreezeKinds) {
		t.Errorf("the vectors hold kinds %v, M3 writes %v", kinds, testRecordFreezeKinds)
	}
}

// Each kind's stored body parses as its one message, and for a kind whose body is a message this build encodes, the
// stored bytes are that message's deterministic encoding: a re-encoding on this leg changes nothing.
func TestRecordFreezeBodiesAreCanonicalOnThisLeg(t *testing.T) {
	vectors := testRecordFreezeLoad(t)
	for _, c := range vectors.Entries {
		kind := RecordKind(c.KindNo)
		body := testRecordFreezeHex(t, c.Body)
		message, ok := kind.NewBody()
		if !ok {
			t.Fatalf("%s has no body message", c.Kind)
		}
		if err := proto.Unmarshal(body, message); err != nil {
			t.Fatalf("%s: %v", c.Kind, err)
		}
		if len(message.ProtoReflect().GetUnknown()) != 0 {
			t.Errorf("%s: its body holds fields its message does not name", c.Kind)
		}
		if again, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message); err != nil || !bytes.Equal(again, body) {
			t.Errorf("%s: this leg encodes its body to other bytes: %v", c.Kind, err)
		}
	}
}

// The deposit batch of the first two entries parses to their stored Signed, sealed bodies, keys and salts, each entry
// with no slot fields.
func TestRecordFreezeDepositBatchOnThisLeg(t *testing.T) {
	vectors := testRecordFreezeLoad(t)
	deposited, err := RecordDepositBatchParse(testRecordFreezeHex(t, vectors.DepositBatch), DefaultSidecarSettings().Record.DepositByteCount)
	if err != nil {
		t.Fatal(err)
	}
	if len(deposited) != 2 {
		t.Fatalf("%d deposited entries", len(deposited))
	}
	for index, entry := range deposited {
		c := vectors.Entries[index]
		random := testRecordFreezeHex(t, c.Random)
		if !bytes.Equal(entry.Signed, testRecordFreezeHex(t, c.Signed)) || !bytes.Equal(entry.SealedBody, testRecordFreezeHex(t, c.SealedBody)) ||
			!bytes.Equal(entry.Key, random[16:48]) || !bytes.Equal(entry.Salt, random[48:80]) {
			t.Errorf("deposited entry %d is not the %s entry as sealed", index, c.Kind)
		}
		message := &protocol.RecordEntry{}
		if err := proto.Unmarshal(entry.Entry, message); err != nil {
			t.Fatal(err)
		}
		if len(message.GetKeySlotId()) != 0 || message.GetKeyIndex() != 0 || message.GetVersion() != 1 {
			t.Errorf("deposited entry %d names a slot", index)
		}
		// an ingester re-slots it to the stream's bytes, every other field as it came
		reslotted, err := recordEntryReslot(entry.Entry, (*Id)(testRecordFreezeHex(t, vectors.SlotId)), c.KeyIndex)
		if err != nil {
			t.Fatal(err)
		}
		again := &protocol.RecordEntry{}
		want := &protocol.RecordEntry{}
		if proto.Unmarshal(reslotted, again) != nil || proto.Unmarshal(testRecordFreezeHex(t, c.Entry), want) != nil || !proto.Equal(again, want) {
			t.Errorf("deposited entry %d re-slots to another entry", index)
		}
	}
}

// The decision's Signed verifies under the approver's key as stored, binds the request and payload the file names,
// and is the approval_decision entry's body byte for byte.
func TestRecordFreezeDecisionOnThisLeg(t *testing.T) {
	vectors := testRecordFreezeLoad(t)
	approverKey := ed25519.NewKeyFromSeed(testRecordFreezeHex(t, vectors.ApproverSeed))
	stored := testRecordFreezeHex(t, vectors.Decision)
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(stored, signed); err != nil {
		t.Fatal(err)
	}
	if err := bridge.VerifySigned(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, bridge.SignedKeyAlgEd25519, approverKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	decision := &protocol.ApprovalDecision{}
	if err := proto.Unmarshal(signed.GetBody(), decision); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(decision.GetRequestSha256()) != vectors.DecisionRequestSha256 || hex.EncodeToString(decision.GetPayloadSha256()) != vectors.DecisionPayloadSha256 {
		t.Error("the decision binds another request or payload")
	}
	found := false
	for _, c := range vectors.Entries {
		if RecordKind(c.KindNo) == RecordKindApprovalDecision {
			found = c.Body == vectors.Decision
		}
		if RecordKind(c.KindNo) == RecordKindApproval {
			request, err := ParseStoredApprovalRequest(testRecordFreezeHex(t, c.Body))
			if err != nil {
				t.Fatal(err)
			}
			requestSha256 := request.Sha256()
			payloadSha256 := request.Action.PayloadSha256()
			if hex.EncodeToString(requestSha256[:]) != vectors.DecisionRequestSha256 || hex.EncodeToString(payloadSha256[:]) != vectors.DecisionPayloadSha256 {
				t.Error("the approval entry's request is not the one the decision binds")
			}
		}
	}
	if !found {
		t.Error("the approval_decision entry's body is not the decision's Signed")
	}
}

// One stored action of each kind the builder makes: each parses, and hashes on this leg to its payload_sha256.
func TestRecordFreezeActionsOnThisLeg(t *testing.T) {
	vectors := testRecordFreezeLoad(t)
	if len(vectors.Actions) == 0 {
		t.Fatal("no actions")
	}
	kinds := map[uint32]bool{}
	for _, c := range vectors.Actions {
		stored := testRecordFreezeHex(t, c.Stored)
		action, err := ParseStoredCanonicalAction(stored)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		payloadSha256 := action.PayloadSha256()
		if hex.EncodeToString(payloadSha256[:]) != c.PayloadSha256 || action.Action.GetKind() != c.KindNo {
			t.Errorf("%s: payload_sha256 %x of kind %d", c.Name, payloadSha256, action.Action.GetKind())
		}
		kinds[c.KindNo] = true
	}
	if len(kinds) < 2 {
		t.Errorf("actions of %d kinds", len(kinds))
	}
}

// Re-encoding changes nothing a verifier checks: an entry whose RecordEntry fields are reordered, or whose version is
// a non-minimal varint, still yields the stored Signed and sealed body byte for byte, so its signature, leaf and
// commitment stand; a header whose own bytes are re-encoded is another header, with another leaf and no signature.
func TestRecordFreezeReencodingChangesNothingAVerifierChecks(t *testing.T) {
	vectors := testRecordFreezeLoad(t)
	c := vectors.Entries[0]
	entryBytes := testRecordFreezeHex(t, c.Entry)
	signedBytes := testRecordFreezeHex(t, c.Signed)
	sealedBody := testRecordFreezeHex(t, c.SealedBody)
	fields := [][]byte{}
	for rest := entryBytes; 0 < len(rest); {
		number, wireType, tagLength := protowire.ConsumeTag(rest)
		valueLength := protowire.ConsumeFieldValue(number, wireType, rest[tagLength:])
		if tagLength < 0 || valueLength < 0 {
			t.Fatal("the entry does not parse")
		}
		field := rest[:tagLength+valueLength]
		if number == recordEntryVersionField {
			// the same value in two bytes
			field = protowire.AppendTag(nil, number, wireType)
			field = append(field, 0x81, 0x00)
		}
		fields = append(fields, field)
		rest = rest[tagLength+valueLength:]
	}
	slices.Reverse(fields)
	reencoded := bytes.Join(fields, nil)
	if bytes.Equal(reencoded, entryBytes) {
		t.Fatal("the re-encoding is the entry")
	}
	read := &recordEntryFields{}
	if err := read.parse(reencoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read.signed, signedBytes) || !bytes.Equal(read.sealedBody, sealedBody) || read.version != 1 || read.keyIndex != c.KeyIndex {
		t.Fatal("a re-encoded entry yields other signed bytes, body or slot")
	}
	message := &protocol.RecordEntry{}
	want := &protocol.RecordEntry{}
	if proto.Unmarshal(reencoded, message) != nil || proto.Unmarshal(entryBytes, want) != nil || !proto.Equal(message, want) {
		t.Fatal("a re-encoded entry decodes to another message")
	}
	// the header's own bytes are what is signed and hashed: swapping two of its fields is another header
	headerBytes := testRecordFreezeHex(t, c.Header)
	_, _, firstLength := protowire.ConsumeField(headerBytes)
	_, _, secondLength := protowire.ConsumeField(headerBytes[firstLength:])
	swapped := slices.Concat(headerBytes[firstLength:firstLength+secondLength], headerBytes[:firstLength], headerBytes[firstLength+secondLength:])
	swappedHeader := &protocol.RecordHeader{}
	original := &protocol.RecordHeader{}
	if proto.Unmarshal(swapped, swappedHeader) != nil || proto.Unmarshal(headerBytes, original) != nil || !proto.Equal(swappedHeader, original) {
		t.Fatal("the swapped header decodes to another message")
	}
	if RecordLeafHash(swapped) == RecordLeafHash(headerBytes) {
		t.Fatal("a re-encoded header keeps its leaf")
	}
	key := ed25519.NewKeyFromSeed(testRecordFreezeHex(t, vectors.IdentitySeed))
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		t.Fatal(err)
	}
	signed.Body = swapped
	if err := bridge.VerifySigned(signed, RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, bridge.SignedKeyAlgEd25519, key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("a re-encoded header verifies under the old signature")
	}
}

// A v1 reader keeps an entry of a kind and a header field it does not know: the header parses with its bytes as
// stored, its leaf covers the unknown field, the kind shows generically, and its body is held to no kind's rules.
func TestRecordFreezeReaderKeepsAnUnknownFieldAndKind(t *testing.T) {
	vectors := testRecordFreezeLoad(t)
	c := vectors.Entries[0]
	header := &protocol.RecordHeader{}
	if err := proto.Unmarshal(testRecordFreezeHex(t, c.Header), header); err != nil {
		t.Fatal(err)
	}
	header.Kind = 1500
	later, err := proto.MarshalOptions{Deterministic: true}.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	withoutField := bytes.Clone(later)
	later = protowire.AppendTag(later, 99, protowire.BytesType)
	later = protowire.AppendBytes(later, []byte("a later field"))
	stored, err := ParseStoredRecordHeader(later)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.Bytes, later) || stored.LeafHash() != RecordLeafHash(later) || stored.LeafHash() == RecordLeafHash(withoutField) {
		t.Fatal("the unknown field is not kept under the leaf")
	}
	kind := stored.Kind()
	if kind != RecordKind(1500) || kind.Known() || kind.String() != "kind 1500" {
		t.Fatalf("an unknown kind reads as %s", kind)
	}
	if _, ok := kind.NewBody(); ok {
		t.Fatal("an unknown kind has a body message")
	}
	if err := RecordBodyValidateStored(kind, []byte("any bytes at all")); err != nil {
		t.Fatalf("an unknown kind's body is held to a rule: %v", err)
	}
	// the writer's key signs it as any header, and the Signed verifies over the bytes as stored
	key := ed25519.NewKeyFromSeed(testRecordFreezeHex(t, vectors.IdentitySeed))
	signed := &bridge.Signed{
		Body:      later,
		SignerId:  testRecordFreezeHex(t, vectors.WriterSidecarId),
		Signature: ed25519.Sign(key, bridge.SignedBytes(RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, later)),
		Type:      uint32(bridge.SignedType_SIGNED_RECORD_HEADER),
	}
	if err := bridge.VerifySigned(signed, RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, bridge.SignedKeyAlgEd25519, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}
