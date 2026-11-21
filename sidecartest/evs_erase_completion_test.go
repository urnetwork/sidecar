// QD-1132's completion ERASE end to end, as QD-1137 has evs read it (§11.12's push and reconcile rows): sidecar.EvsClient
// devices in the format2 gate against an evsservice.EvsEngine over FakeHost's stores, on the versionless world
// (evs_write_versionless_test.go).

package sidecartest

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// An erasure's ERASE destroys a path's key without saying complete, and another device reads it rewriting. Its
// completion ERASE, a format-2 statement flagged COMPLETION and naming that key, commits and destroys nothing, and the
// other device reads the erasure done, the completion completing it. A second completion naming the key answers as
// nothing to erase, and so does one naming a key no ERASE destroyed; neither commits. Another erasure's completion
// naming a key a third erasure's ERASE destroyed commits, since evs cannot see whose ERASE that was, and readers read
// it as completing nothing.
func TestEvsCompletionEraseEndsAnErasureEndToEnd(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	ctx := world.ctx
	w := world.format2Device("w")
	keysOf := func(path string) []*sidecar.EvsErasedKey {
		t.Helper()
		if _, err := w.writeSetting(path, versionlessContent(path, 2*1024), sidecar.EvsVersioningOff); err != nil {
			t.Fatalf("the write of %s: %v", path, err)
		}
		keys, err := w.repo.SlotKeysOf(ctx, nil, []string{path})
		if err != nil || len(keys) != 1 {
			t.Fatalf("the slot keys of %s: %v %v", path, keys, err)
		}
		return keys
	}
	draft, other := keysOf("notes/draft.bin"), keysOf("notes/other.bin")
	erasureId, otherId, strayId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	erase := func(erasureId sidecar.Id, keys []*sidecar.EvsErasedKey, complete bool, completion bool) uint64 {
		t.Helper()
		// past evs's refusal fence, so a refusal is recorded and answered rather than waited (§11.8's refuse row)
		world.clock.Advance(evsservice.DefaultEvsSettings().RefusalFenceInterval)
		result, err := w.repo.Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: erasureId, Keys: keys, Complete: complete, Completion: completion, Note: []byte("note")})
		if err != nil {
			t.Fatalf("an ERASE: %v", err)
		}
		return result.Version
	}
	stateOf := func(erasureId sidecar.Id) string {
		t.Helper()
		erasures, err := world.format2Device("v").repo.Erasures(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, erasure := range erasures {
			if erasure.ErasureId == erasureId {
				return erasure.State
			}
		}
		return ""
	}
	if version := erase(erasureId, draft, false, false); version != 1 || world.slotKeyCount(draft[0].SlotId) != 0 {
		t.Fatalf("the ERASE committed at %d, its slot holding %d keys", version, world.slotKeyCount(draft[0].SlotId))
	}
	if state := stateOf(erasureId); state != "rewriting" {
		t.Fatalf("before its completion the erasure reads %q", state)
	}
	if _, err := w.repo.Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: erasureId, Keys: draft, Completion: true}); err == nil {
		t.Fatal("a completion saying nothing complete was sent")
	}
	if version := erase(erasureId, draft, true, true); version != 2 {
		t.Fatalf("the completion committed at %d", version)
	}
	if state := stateOf(erasureId); state != "done" {
		t.Fatalf("after its completion the erasure reads %q", state)
	}
	if version := erase(erasureId, draft, true, true); version != 0 {
		t.Fatalf("a second completion committed at %d", version)
	}
	unknown := []*sidecar.EvsErasedKey{{SlotId: sidecar.NewEvsSlotId(), KeyIndex: 0}}
	if version := erase(erasureId, unknown, true, true); version != 0 {
		t.Fatalf("a completion of a key no ERASE destroyed committed at %d", version)
	}
	// another erasure's key, which a stray completion names: evs takes it, and readers read it as completing nothing
	if version := erase(otherId, other, false, false); version != 3 {
		t.Fatalf("the other erasure's ERASE committed at %d", version)
	}
	if version := erase(strayId, other, true, true); version != 4 {
		t.Fatalf("the stray completion committed at %d", version)
	}
	erasures, err := world.format2Device("v").repo.ReadErasures(ctx, 0)
	if err != nil || len(erasures) != 4 {
		t.Fatalf("%d ERASEs read back: %v", len(erasures), err)
	}
	if first, completion, stray := erasures[0], erasures[1], erasures[3]; first.Completion || first.Complete ||
		!completion.Completion || !completion.Complete || !stray.Completion || stray.Complete {
		t.Fatalf("the ERASEs as read: %+v, %+v, %+v", first, completion, stray)
	}
	if state := stateOf(strayId); state != "" {
		t.Fatalf("a completion claiming another erasure's key created state %q", state)
	}
	reader := world.format2Device("r")
	streams, err := sidecar.NewRecordEvsStreams(&sidecar.RecordEvsStreamsArgs{Client: reader.client, Store: reader.store})
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := streams.ReadErasures(ctx, world.repoId, 1)
	if err != nil || len(recorded) != 3 || !recorded[0].Complete || !recorded[0].Completion ||
		recorded[1].Completion || !recorded[2].Completion || recorded[2].Complete || len(recorded[2].Keys) != 1 {
		t.Fatalf("record erasure audit: %+v, %v", recorded, err)
	}
	late := keysOf("notes/late.bin")
	if version := erase(erasureId, late, false, false); version != 5 || stateOf(erasureId) != "rewriting" {
		t.Fatal("a late key destruction did not reopen the erasure")
	}
	if version := erase(erasureId, late, true, true); version != 6 || stateOf(erasureId) != "done" {
		t.Fatal("the late key's matching completion did not end its erasure")
	}
}
