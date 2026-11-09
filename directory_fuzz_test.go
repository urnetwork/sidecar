//go:build !js

// FuzzDirectoryDecode (§22.6's directory.proto target, RECORD-M6-11): whatever bytes arrive as an announce entry, a
// request, a decision, a notice or an erasure request, its decoder never panics and answers either a refusal wrapping
// ErrDirectoryFormatInvalid or what it took; it refuses bytes past its bound, whatever they hold; and what it takes
// passes its check again, keeps the bytes as received, and decodes again, equal, from its own canonical encoding. Seeds
// in testdata/fuzz/FuzzDirectoryDecode, run in every test run, hold each fixture of directory_fields_test.go, one past
// a cap and cut ones; those in code add one past each bound. A long campaign is the review phase's, and cards and repo
// files join this target with RECORD-M10-02.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// FuzzDirectoryDecode's selectors, taken modulo their count.
const (
	testDirectoryDecodeAnnouncement uint = iota
	testDirectoryDecodeRequest
	testDirectoryDecodeDecision
	testDirectoryDecodeNotice
	testDirectoryDecodeErasureRequest
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
	default:
		request, err := DirectoryDecodeErasureRequest(data)
		return request, bytes.Clone(data), DirectoryEntryBodyMaxByteCount, err
	}
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
