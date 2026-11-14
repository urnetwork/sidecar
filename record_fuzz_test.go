//go:build !js

// FuzzRecordHeader (RECORD-M3-03): whatever bytes a header's Signed carries, and whatever bytes arrive as an entry, a
// reader's steps 2 and 3 never panic; what passes is kept as received, byte for byte, its leaf over those bytes, and
// passes ParseStoredRecordHeader. Its seeds, run in every test run, hold a valid header, one with an unknown field and
// kind, a field repeated, and cut and empty ones. A long campaign is the review phase's.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A state that admits one writer to one log at one pin, every answer fixed.
type fuzzRecordAuth struct {
	pin       *bridge.AuthPin
	writerId  Id
	logId     Id
	publicKey []byte
}

func (self *fuzzRecordAuth) Pin() *bridge.AuthPin {
	return self.pin
}

func (self *fuzzRecordAuth) At(pin *bridge.AuthPin) (RecordAuthView, error) {
	if pin.GetVersion() != self.pin.GetVersion() || !bytes.Equal(pin.GetChain(), self.pin.GetChain()) {
		return nil, ErrRecordAuthOffChain
	}
	return self, nil
}

func (self *fuzzRecordAuth) AtPosition(version uint64) (RecordAuthView, error) {
	if version == 0 || self.pin.GetVersion() < version {
		return nil, ErrRecordAuthAhead
	}
	return self, nil
}

func (self *fuzzRecordAuth) RightEnded(repoId Id, sidecarId Id, after uint64) (int64, bool) {
	return 0, false
}

func (self *fuzzRecordAuth) IdentityKey(sidecarId Id) []byte {
	if sidecarId == self.writerId {
		return self.publicKey
	}
	return nil
}

func (self *fuzzRecordAuth) Member(sidecarId Id) (Id, bool) {
	return Id{}, false
}

func (self *fuzzRecordAuth) Sponsor(sidecarId Id) (Id, bool) {
	return Id{}, false
}

func (self *fuzzRecordAuth) Consented(repoId Id, sidecarId Id) bool {
	return repoId == self.logId && sidecarId == self.writerId
}

func (self *fuzzRecordAuth) Reads(repoId Id, sidecarId Id) bool {
	return repoId == self.logId
}

func (self *fuzzRecordAuth) Writes(repoId Id, sidecarId Id) bool {
	return repoId == self.logId && sidecarId == self.writerId
}

func (self *fuzzRecordAuth) Admins(repoId Id, sidecarId Id) bool {
	return false
}

func (self *fuzzRecordAuth) Deposits(repoId Id, sidecarId Id) bool {
	return false
}

func (self *fuzzRecordAuth) ReceiptOnly(repoId Id, sidecarId Id) bool {
	return false
}

func (self *fuzzRecordAuth) CompromisedSince(sidecarId Id) (uint64, bool) {
	return 0, false
}

func (self *fuzzRecordAuth) Logs() *RecordLogIds {
	return &RecordLogIds{}
}

func (self *fuzzRecordAuth) Vault(memberId Id) (Id, bool) {
	return Id{}, false
}

func FuzzRecordHeader(f *testing.F) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x46}, ed25519.SeedSize))
	auth := &fuzzRecordAuth{
		pin:       &bridge.AuthPin{Version: 7, Chain: bytes.Repeat([]byte{0x07}, 32)},
		writerId:  Id(bytes.Repeat([]byte{0x57}, 16)),
		logId:     Id(bytes.Repeat([]byte{0x4c}, 16)),
		publicKey: key.Public().(ed25519.PublicKey),
	}
	header := &protocol.RecordHeader{
		EntryId:         bytes.Repeat([]byte{0x45}, 16),
		LogId:           auth.logId.Bytes(),
		WriterSidecarId: auth.writerId.Bytes(),
		Seq:             1,
		PrevSha256:      make([]byte, 32),
		Kind:            uint32(RecordKindNote),
		TimeMillis:      1762387200000,
		Source:          uint32(RecordSourceAgent),
		Tainted:         true,
		BodyCommitment:  bytes.Repeat([]byte{0x43}, 32),
		PolicyVersion:   7,
	}
	valid, _ := proto.Marshal(header)
	f.Add(valid)
	unknown := proto.Clone(header).(*protocol.RecordHeader)
	unknown.Kind = 1500
	withField, _ := proto.Marshal(unknown)
	withField = protowire.AppendTag(withField, 99, protowire.BytesType)
	withField = protowire.AppendBytes(withField, []byte("later"))
	f.Add(withField)
	repeated := append(bytes.Clone(valid), valid...)
	f.Add(repeated)
	f.Add(valid[:len(valid)/2])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, headerBytes []byte) {
		signed := &bridge.Signed{
			Body:      headerBytes,
			SignerId:  auth.writerId.Bytes(),
			Signature: ed25519.Sign(key, bridge.SignedBytes(RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, headerBytes)),
			Type:      uint32(bridge.SignedType_SIGNED_RECORD_HEADER),
		}
		signedBytes, err := proto.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := VerifyRecordEntry(auth, auth.logId, signedBytes, &RecordEntryArrival{StreamSidecarId: auth.writerId, PushPin: auth.pin})
		if err == nil {
			if !bytes.Equal(verified.Header.Bytes, headerBytes) || verified.Header.LeafHash() != RecordLeafHash(headerBytes) {
				t.Fatal("a verified header is not its received bytes")
			}
			if _, err := ParseStoredRecordHeader(headerBytes); err != nil {
				t.Fatalf("a verified header does not parse: %v", err)
			}
			if !bytes.Equal(verified.Header.Header.GetWriterSidecarId(), auth.writerId[:]) || !bytes.Equal(verified.Header.Header.GetLogId(), auth.logId[:]) {
				t.Fatal("a header of another writer or log verified")
			}
		}
		// the same bytes arriving as a whole entry
		fields := &recordEntryFields{}
		if fields.parse(headerBytes) == nil && fields.signed == nil {
			t.Fatal("an entry with no header parsed")
		}
	})
}

// FuzzRecordEntry (RECORD-M3-11): whatever bytes arrive as a RecordEntry, reading its fields by hand never panics,
// and what the hand decoder accepts is what proto.Unmarshal reads of the same bytes (§22.6): the header's Signed and
// the sealed body byte for byte, the slot and the version. An accepted entry re-slots with its Signed and sealed body
// unchanged, and a deposit batch holding the bytes parses or is refused, never more. The seeds in
// testdata/fuzz/FuzzRecordEntry, run in every test run, hold a valid entry and the same with its fields reordered,
// one repeated, unknown fields packed and unpacked, and a non-minimal varint; FuzzRecordHeader's hold the like of a
// header.
func FuzzRecordEntry(f *testing.F) {
	slotId := Id(bytes.Repeat([]byte{0x53}, 16))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, entryBytes []byte) {
		// a deposit of these bytes parses or is refused
		batch, err := proto.Marshal(&protocol.RecordDepositBatch{Entries: []*protocol.RecordDeposit{{
			Entry: entryBytes,
			Key:   bytes.Repeat([]byte{0x4b}, RecordKeyByteCount),
			Salt:  bytes.Repeat([]byte{0x5a}, RecordSaltByteCount),
		}}})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = RecordDepositBatchParse(batch, DefaultSidecarSettings().Record.DepositByteCount)

		fields := &recordEntryFields{}
		if fields.parse(entryBytes) != nil {
			return
		}
		message := &protocol.RecordEntry{}
		if proto.Unmarshal(entryBytes, message) == nil {
			signed := &bridge.Signed{}
			if err := proto.Unmarshal(fields.signed, signed); err != nil {
				t.Fatalf("the message parses and its header's bytes do not: %v", err)
			}
			if !proto.Equal(signed, message.GetHeader()) || !bytes.Equal(fields.sealedBody, message.GetSealedBody()) ||
				!bytes.Equal(fields.keySlotId, message.GetKeySlotId()) || fields.keyIndex != message.GetKeyIndex() || fields.version != message.GetVersion() {
				t.Fatal("the fields read by hand are not proto.Unmarshal's")
			}
		}
		reslotted, err := recordEntryReslot(entryBytes, &slotId, 7)
		if err != nil {
			t.Fatalf("an accepted entry does not re-slot: %v", err)
		}
		again := &recordEntryFields{}
		if err := again.parse(reslotted); err != nil {
			t.Fatalf("a re-slotted entry does not parse: %v", err)
		}
		if !bytes.Equal(again.signed, fields.signed) || !bytes.Equal(again.sealedBody, fields.sealedBody) || again.version != fields.version ||
			!bytes.Equal(again.keySlotId, slotId[:]) || again.keyIndex != 7 {
			t.Fatal("re-slotting changed what was signed or sealed, or named another slot")
		}
	})
}
