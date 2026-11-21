//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The phone's held copy still decides the writer, stream, version and erasure of a shared record.
func TestMemberRequesterAcceptsVerifiedSharedRecord(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	net := team.net
	now := time.UnixMilli(net.timeMs)
	repo, reader, writer := team.danaVault, team.benPhone.sidecarId, team.danaLaptop.sidecarId
	ref, leaf := NewId(), [32]byte{1}
	path, err := RecordStreamPath(1)
	if err != nil {
		t.Fatal(err)
	}
	hit := SearchHit{Repo: repo, Ref: ref, Signer: writer, Version: 1, Time: now, Path: path, DocKind: int(IndexDocRecord)}
	copy := &RecordEntryCopy{StreamSidecarId: writer, Version: 1, Path: path, TimeMillis: now.UnixMilli()}
	entry := &RecordReadEntry{Header: &StoredRecordHeader{Header: &protocol.RecordHeader{WriterSidecarId: writer.Bytes(), Kind: uint32(RecordKindNote)}},
		State: RecordEntryLive, Copies: []*RecordEntryCopy{copy}}
	log := &recordReadLog{complete: true, streamRefIds: map[Id]Id{writer: ref},
		streamPushes: map[Id][]*RecordReadPush{writer: {{Version: 1, Leaves: []RecordReadPushLeaf{{Leaf: leaf}}}}},
		leafEntries:  map[[32]byte]*RecordReadEntry{leaf: entry}}
	source := &memberSearchSource{
		host: &memberSearchHost{running: &Sidecar{clock: &testConfigClock{now: now}}},
		record: &SidecarRecord{writer: &recordWriter{sidecarId: reader, authFunc: func() RecordAuthView { return NewRecordAuthView(net.log.State()) }},
			reader: &RecordReader{logs: map[Id]*recordReadLog{repo: log}}},
	}
	judge := func() func(SearchHit) bool {
		return source.remoteRowsFor(t.Context(), net.log.State(), repo, &SearchRequest{}, map[Id]func() bool{})
	}
	accept := judge()
	if accept == nil || !accept(hit) {
		t.Fatal("the owner's indexed note remained unavailable to its read-only share")
	}
	other := hit
	other.Signer = reader
	if accept(other) {
		t.Fatal("a different writer's claim passed")
	}
	card := hit
	card.DocKind = int(IndexDocDerived)
	card.Path = string(indexRunCardName(NewId()))
	if accept(card) {
		t.Fatal("a derived run without a verified fold passed")
	}
	entry.State = RecordEntryErased
	if accept(hit) {
		t.Fatal("an erased note passed")
	}
	entry.State = RecordEntryLive
	source.record.writer.sidecarId = team.auditorLaptop.sidecarId
	if audit := judge(); audit != nil && audit(hit) {
		t.Fatal("an audit reader without an EvsShare accepted a remote claim")
	}
	source.record.writer.sidecarId = reader
	net.mustPost(team.danaLaptop, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{Header: net.header(), RepoId: repo.Bytes(), Subject: reader.Bytes()})
	if revoked := judge(); revoked != nil && revoked(hit) {
		t.Fatal("the revoked share accepted another remote claim")
	}
}
