//go:build !js

// FuzzDirectoryDecode (§22.6's directory.proto target, RECORD-M6-11, RECORD-M10-02): whatever bytes arrive as an
// announce entry, a request, a decision, a notice, an erasure request, a card or a repo file, its decoder never panics
// and answers either a refusal wrapping ErrDirectoryFormatInvalid or what it took; it refuses bytes past its bound,
// whatever they hold; and what it takes passes its check again, keeps the bytes as received, and decodes again, equal,
// from its own canonical encoding. Seeds in testdata/fuzz/FuzzDirectoryDecode, run in every test run, hold each fixture
// of directory_fields_test.go, one past a cap and cut ones; those in code add one past each bound and a card and a
// repo file signed by the fuzz's key. A long campaign is the review phase's.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// FuzzDirectoryDecode's selectors, taken modulo their count.
const (
	testDirectoryDecodeAnnouncement uint = iota
	testDirectoryDecodeRequest
	testDirectoryDecodeDecision
	testDirectoryDecodeNotice
	testDirectoryDecodeErasureRequest
	testDirectoryDecodeCard
	testDirectoryDecodeRepoFile
	testDirectoryDecodeCount
)

// Decodes data as selector names: what was taken, the bound, and the refusal.
func testDirectoryDecode(selector uint, data []byte) (proto.Message, []byte, int, error) {
	switch selector % testDirectoryDecodeCount {
	case testDirectoryDecodeAnnouncement:
		item, err := DirectoryDecodeAnnouncement(data)
		return item, bytes.Clone(data), DirectoryEntryBodyMaxByteCount, err
	case testDirectoryDecodeRequest:
		stored, err := DirectoryDecodeRequest(data)
		if err != nil {
			return nil, nil, DirectoryEntryBodyMaxByteCount, err
		}
		return stored.Request, stored.Bytes, DirectoryEntryBodyMaxByteCount, nil
	case testDirectoryDecodeDecision:
		stored, err := DirectoryDecodeDecision(data)
		if err != nil {
			return nil, nil, DirectoryEntryBodyMaxByteCount, err
		}
		return stored.Decision, stored.Bytes, DirectoryEntryBodyMaxByteCount, nil
	case testDirectoryDecodeNotice:
		notice, err := DirectoryDecodeNotice(data)
		return notice, bytes.Clone(data), DirectoryNoticeByteCount, err
	case testDirectoryDecodeErasureRequest:
		request, err := DirectoryDecodeErasureRequest(data)
		return request, bytes.Clone(data), DirectoryEntryBodyMaxByteCount, err
	case testDirectoryDecodeCard:
		bound := DefaultDirectoryCardSettings().CardFileByteCount
		stored, err := DirectoryDecodeCard(data, nil)
		if err != nil {
			return nil, nil, bound, err
		}
		return stored.Signed, stored.Bytes, bound, nil
	default:
		bound := DefaultDirectoryCardSettings().RepoFileByteCount
		stored, err := DirectoryDecodeRepoFile(data, nil)
		if err != nil {
			return nil, nil, bound, err
		}
		return stored.Signed, stored.Bytes, bound, nil
	}
}

// body Signed by key as signerId, of signedType under purpose directory.
func testDirectorySignedFile(key ed25519.PrivateKey, signerId []byte, signedType bridge.SignedType, body []byte) *bridge.Signed {
	return &bridge.Signed{
		Body: body, SignerId: signerId, Type: uint32(signedType),
		Signature: ed25519.Sign(key, bridge.SignedBytes(DirectorySignedPurpose, signedType, body)),
	}
}

// A card every check takes: the run fixture's sidecar's, holding that run.
func testDirectoryCardFile(t testing.TB, key ed25519.PrivateKey) *bridge.Signed {
	t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.DirectoryCard{
		NetworkId: testDirectoryId(0x51), SidecarId: testDirectoryId(0x22), Seq: 7,
		At:            &bridge.AuthPin{Version: 12, Chain: bytes.Repeat([]byte{0x52}, 32)},
		WrittenMillis: testDirectoryRenewedMillis, Items: []*protocol.Announcement{testDirectoryRunItem()}, Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return testDirectorySignedFile(key, testDirectoryId(0x22), bridge.SignedType_SIGNED_DIRECTORY_CARD, body)
}

// A repo file every check takes: the repo fixture's item, signed as its who.
func testDirectoryRepoFile(t testing.TB, key ed25519.PrivateKey) *bridge.Signed {
	t.Helper()
	item := testDirectoryRepoItem(t)
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.RepoAnnouncement{
		NetworkId: testDirectoryId(0x51), RepoId: item.GetWhere().GetRepoId(), Seq: 3,
		At: &bridge.AuthPin{Version: 12, Chain: bytes.Repeat([]byte{0x52}, 32)}, Item: item,
	})
	if err != nil {
		t.Fatal(err)
	}
	return testDirectorySignedFile(key, item.GetWho().GetSidecarId(), bridge.SignedType_SIGNED_DIRECTORY_REPO, body)
}

func FuzzDirectoryDecode(f *testing.F) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		f.Fatal(err)
	}
	// one past each bound, built from a fixture with an unknown field a v1 reader would otherwise keep
	for selector, message := range map[uint]proto.Message{
		testDirectoryDecodeAnnouncement:   testDirectoryRunItem(),
		testDirectoryDecodeRequest:        testDirectoryRepoRequest(),
		testDirectoryDecodeDecision:       testDirectoryReachApproval(f, key),
		testDirectoryDecodeNotice:         testDirectoryNotice(),
		testDirectoryDecodeErasureRequest: testDirectoryErasureRequest(),
		testDirectoryDecodeCard:           testDirectoryCardFile(f, key),
		testDirectoryDecodeRepoFile:       testDirectoryRepoFile(f, key),
	} {
		_, _, bound, _ := testDirectoryDecode(selector, nil)
		grown := proto.Clone(message)
		grown.ProtoReflect().SetUnknown(protowire.AppendBytes(protowire.AppendTag(nil, 99, protowire.BytesType), make([]byte, bound-proto.Size(message))))
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(grown)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(selector, encoded)
	}
	// a card and a repo file the decoders take, whose cut and grown forms the fuzzer reaches from them
	for selector, message := range map[uint]proto.Message{
		testDirectoryDecodeCard:     testDirectoryCardFile(f, key),
		testDirectoryDecodeRepoFile: testDirectoryRepoFile(f, key),
	} {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(selector, encoded)
	}
	f.Fuzz(func(t *testing.T, selector uint, data []byte) {
		taken, kept, bound, err := testDirectoryDecode(selector, data)
		if err != nil {
			if !errors.Is(err, ErrDirectoryFormatInvalid) {
				t.Fatalf("selector %d refused as %v", selector, err)
			}
			return
		}
		if bound < len(data) {
			t.Fatalf("selector %d took %d bytes past its bound %d", selector, len(data), bound)
		}
		if !bytes.Equal(kept, data) {
			t.Fatalf("selector %d did not keep the bytes as received", selector)
		}
		var check error
		switch typed := taken.(type) {
		case *protocol.Announcement:
			check = directoryCheckAnnounceEntry(typed, proto.Size(typed))
		case *protocol.DirectoryRequest:
			check = DirectoryCheckRequest(typed)
		case *protocol.DirectoryDecision:
			check = DirectoryCheckDecision(typed)
		case *protocol.DirectoryNotice:
			check = DirectoryCheckNotice(typed)
		case *protocol.DirectoryErasureRequest:
			check = DirectoryCheckErasureRequest(typed)
		case *bridge.Signed:
			if selector%testDirectoryDecodeCount == testDirectoryDecodeCard {
				card := &protocol.DirectoryCard{}
				check = errors.Join(proto.Unmarshal(typed.GetBody(), card), DirectoryCheckCard(card, nil))
			} else {
				file := &protocol.RepoAnnouncement{}
				check = errors.Join(proto.Unmarshal(typed.GetBody(), file), DirectoryCheckRepoFile(file))
			}
		default:
			t.Fatalf("selector %d took a %T", selector, taken)
		}
		if check != nil {
			t.Fatalf("selector %d took what its check refuses: %v", selector, check)
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(taken)
		if err != nil {
			t.Fatal(err)
		}
		again, _, _, err := testDirectoryDecode(selector, encoded)
		if err != nil {
			t.Fatalf("selector %d took %x and refused its canonical encoding: %v", selector, data, err)
		}
		if !proto.Equal(again, taken) {
			t.Fatalf("selector %d decoded its canonical encoding to another message", selector)
		}
	})
}
