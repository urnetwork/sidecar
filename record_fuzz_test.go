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
