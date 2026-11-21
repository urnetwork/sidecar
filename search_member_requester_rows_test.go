//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

func TestRemoteRequesterRecordUsesTheSignedStreamCopy(t *testing.T) {
	writer, ref := NewId(), NewId()
	leaf := [32]byte{7}
	entry := &RecordReadEntry{State: RecordEntryLive,
		Header: &StoredRecordHeader{Header: &protocol.RecordHeader{WriterSidecarId: writer.Bytes(), Kind: uint32(RecordKindNote)}},
		Copies: []*RecordEntryCopy{{StreamSidecarId: writer, Path: "e/0/0/1", Version: 7, TimeMillis: 1888}}}
	log := &recordReadLog{streamRefIds: map[Id]Id{writer: ref},
		streamPushes: map[Id][]*RecordReadPush{writer: {{Version: 7, Leaves: []RecordReadPushLeaf{{Leaf: leaf}}}}},
		leafEntries:  map[[32]byte]*RecordReadEntry{leaf: entry}}
	hit := SearchHit{Ref: ref, Path: "e/0/0/1", Version: 7, Signer: writer, Time: time.UnixMilli(1000)}
	if class := log.remoteRecordClass(protocol.RepoKind_REPO_KIND_VAULT, hit); class != RecordClassCoordination {
		t.Fatalf("signed note class %d", class)
	}
	for _, change := range []func(*SearchHit){
		func(h *SearchHit) { h.Ref = NewId() }, func(h *SearchHit) { h.Path = "e/0/0/2" },
		func(h *SearchHit) { h.Version++ }, func(h *SearchHit) { h.Signer = NewId() },
		func(h *SearchHit) { h.Time = h.Time.Add(time.Second) },
	} {
		other := hit
		change(&other)
		if log.remoteRecordClass(protocol.RepoKind_REPO_KIND_VAULT, other) != RecordClassUnspecified {
			t.Fatalf("accepted changed record %+v", other)
		}
	}
	if log.remoteRecordClass(protocol.RepoKind_REPO_KIND_TEAM_RECORD, hit) != RecordClassUnspecified {
		t.Fatal("a team record indexed a raw entry")
	}
	entry.State = RecordEntryErased
	if log.remoteRecordClass(protocol.RepoKind_REPO_KIND_VAULT, hit) != RecordClassUnspecified {
		t.Fatal("an erased record remained")
	}
}
