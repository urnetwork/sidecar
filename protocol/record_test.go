// §22.6's record.proto target: every hash and signature covers stored bytes, so a reader built before a field or a
// kind existed still verifies an entry that carries it (§16.8's what freezes). It sits here because RecordHeader
// is protocol's and protocol/bridge sees none of protocol.

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §6.9's purpose for a header and a RetentionPolicy (§16.8).
const testRecordPurpose = "record-entry"

// A kind no registry holds: readers keep it, verify it and show it generically, never refuse it.
const testUnknownRecordKind = 60000

// A header of a kind this reader does not know, its other fields synthetic.
func testRecordHeader() *RecordHeader {
	return &RecordHeader{
		EntryId:         bytes.Repeat([]byte{0x01}, 16),
		LogId:           bytes.Repeat([]byte{0x02}, 16),
		WriterSidecarId: bytes.Repeat([]byte{0x03}, 16),
		Seq:             7,
		PrevSha256:      bytes.Repeat([]byte{0x04}, 32),
		Kind:            testUnknownRecordKind,
		TimeMillis:      1,
		BodyCommitment:  bytes.Repeat([]byte{0x05}, 32),
	}
}

// A header as a later writer signs it: one this reader's kinds do not name, with a field it cannot name.
func testLaterRecordEntry(t *testing.T, key ed25519.PrivateKey) []byte {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(testRecordHeader())
	if err != nil {
		t.Fatal(err)
	}
	body = protowire.AppendVarint(protowire.AppendTag(body, 1000, protowire.VarintType), 1)
	headerType := bridge.SignedType_SIGNED_RECORD_HEADER
	stored, err := proto.Marshal(&RecordEntry{
		Header: &bridge.Signed{
			Body:      body,
			Signature: ed25519.Sign(key, bridge.SignedBytes(testRecordPurpose, headerType, body)),
			Type:      uint32(headerType),
		},
		SealedBody: []byte("sealed"),
		Version:    1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// §22.6: a v1 reader verifies a later writer's header over the bytes it received, unknown field and kind included.
func TestRecordHeaderWithUnknownFieldAndKindVerifies(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)

	entry := &RecordEntry{}
	if err := proto.Unmarshal(testLaterRecordEntry(t, key), entry); err != nil {
		t.Fatal(err)
	}
	err := bridge.VerifySigned(
		entry.GetHeader(), testRecordPurpose, bridge.SignedType_SIGNED_RECORD_HEADER,
		bridge.SignedKeyAlgEd25519, publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	header := &RecordHeader{}
	if err := proto.Unmarshal(entry.GetHeader().GetBody(), header); err != nil {
		t.Fatal(err)
	}
	if header.GetKind() != testUnknownRecordKind {
		t.Errorf("the kind read %d", header.GetKind())
	}
	if len(header.ProtoReflect().GetUnknown()) == 0 {
		t.Error("the unknown field is gone, so a re-encoding would no longer match the signature")
	}

	// Re-encoding changes nothing a verifier checks.
	reencoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, entry.GetHeader().GetBody()) {
		t.Error("a re-encoding left the stored bytes")
	}
	known := proto.Clone(header).(*RecordHeader)
	known.ProtoReflect().SetUnknown(nil)
	if !proto.Equal(known, testRecordHeader()) {
		t.Errorf("the fields a verifier reads changed: %v", known)
	}

	// The verifiable log's leaf hash (RFC 9162) is over the stored header, and so differs from a re-marshal that
	// dropped what the reader could not name.
	leaf := sha256.Sum256(append([]byte{0x00}, entry.GetHeader().GetBody()...))
	withoutUnknown, err := proto.MarshalOptions{Deterministic: true}.Marshal(known)
	if err != nil {
		t.Fatal(err)
	}
	if leaf == sha256.Sum256(append([]byte{0x00}, withoutUnknown...)) {
		t.Error("the leaf hash does not cover the unknown field")
	}
}

// The unknown field is signed like any other, so a server cannot strip or change it.
func TestRecordHeaderSignatureCoversAnUnknownField(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)

	entry := &RecordEntry{}
	if err := proto.Unmarshal(testLaterRecordEntry(t, key), entry); err != nil {
		t.Fatal(err)
	}
	body := entry.GetHeader().GetBody()
	body[len(body)-1] ^= 0x01
	err := bridge.VerifySigned(
		entry.GetHeader(), testRecordPurpose, bridge.SignedType_SIGNED_RECORD_HEADER,
		bridge.SignedKeyAlgEd25519, publicKey,
	)
	if !errors.Is(err, bridge.ErrSignedSignature) {
		t.Errorf("a changed unknown field: %v", err)
	}
}

// DESIGN-COMPUTE §24.5's body_apart (CTXH-M11-01): a session entry's RecordEntry carries its header with sealed_body
// empty and body_apart set, its body apart at s/<n>. The leaf covers the signed header alone, so filing the body apart
// changes no leaf, and a reader that knows no field 6 keeps it unknown and still verifies the header (format 1's row).
func TestSessionEntryHeaderVerifiesWithItsBodyApart(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x54}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	header := testRecordHeader()
	header.Kind = 54
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	headerType := bridge.SignedType_SIGNED_RECORD_HEADER
	signed := &bridge.Signed{
		Body:      body,
		Signature: ed25519.Sign(key, bridge.SignedBytes(testRecordPurpose, headerType, body)),
		Type:      uint32(headerType),
	}
	apart, err := proto.Marshal(&RecordEntry{Header: signed, Version: 1, BodyApart: true})
	if err != nil {
		t.Fatal(err)
	}
	whole, err := proto.Marshal(&RecordEntry{Header: signed, SealedBody: []byte("sealed"), Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	read := &RecordEntry{}
	if err := proto.Unmarshal(apart, read); err != nil {
		t.Fatal(err)
	}
	if !read.GetBodyApart() || len(read.GetSealedBody()) != 0 {
		t.Errorf("body_apart %v and a sealed body of %d bytes", read.GetBodyApart(), len(read.GetSealedBody()))
	}
	leafOf := func(stored []byte) [sha256.Size]byte {
		entry := &RecordEntry{}
		if err := proto.Unmarshal(stored, entry); err != nil {
			t.Fatal(err)
		}
		if err := bridge.VerifySigned(entry.GetHeader(), testRecordPurpose, headerType, bridge.SignedKeyAlgEd25519, publicKey); err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(append([]byte{0x00}, entry.GetHeader().GetBody()...))
	}
	if leafOf(apart) != leafOf(whole) {
		t.Error("filing the body apart changed the entry's leaf")
	}
	// a reader before field 6: the field stays unknown beside a header that verifies
	older := protowire.AppendTag(nil, 1, protowire.BytesType)
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	older = protowire.AppendBytes(older, signedBytes)
	older = protowire.AppendVarint(protowire.AppendTag(older, 4, protowire.VarintType), 1)
	older = protowire.AppendVarint(protowire.AppendTag(older, 6, protowire.VarintType), 1)
	if !bytes.Equal(older, apart) {
		t.Errorf("a body-apart entry is not fields 1, 4 and 6 in order: %x", apart)
	}
}
