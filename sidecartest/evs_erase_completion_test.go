// QD-1132's completion ERASE end to end, as QD-1137 has evs read it (§11.12's push and reconcile rows): sidecar.EvsClient
// devices in the format2 gate against an evsservice.EvsEngine over FakeHost's stores, on the versionless world
// (evs_write_versionless_test.go).

package sidecartest

import (
	"net/http"
	"strings"
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
	if state := stateOf(strayId); state == "done" {
		t.Fatal("a completion naming another erasure's key ended its own")
	}
}

// Overlapping erasures select their completion keys from the whole ref. Two runners of the record's index
// eraser meet on one completion. After an ERASE of a late copy the second runner can end it again.
func TestEvsRecordIndexCompletesIndependentErasuresEndToEnd(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	ctx := world.ctx
	w, other := world.format2Device("w"), world.format2Device("w")
	auth := NewFakeRecordAuth()
	auth.Append(&FakeRecordAuthFixture{Repos: map[sidecar.Id]*FakeRecordRepoAuth{
		world.repoId: {Admins: []sidecar.Id{w.signer.SidecarId}},
	}})
	open := func(device *epochDevice) sidecar.RecordEraseIndex {
		t.Helper()
		openIndex, err := sidecar.NewRecordEvsEraseIndex(&sidecar.RecordEvsEraseIndexArgs{Client: device.client, Auth: auth.Tip})
		if err != nil {
			t.Fatal(err)
		}
		index, err := openIndex(ctx, world.repoId)
		if err != nil || index == nil {
			t.Fatalf("opening the record's index: %v", err)
		}
		return index
	}
	first, second := open(w), open(other)
	keyOf := func(path string) *sidecar.EvsErasedKey {
		t.Helper()
		if _, err := w.writeSetting(path, versionlessContent(path, 1024), sidecar.EvsVersioningOff); err != nil {
			t.Fatal(err)
		}
		keys, err := w.repo.SlotKeysOf(ctx, nil, []string{path})
		if err != nil || len(keys) != 1 {
			t.Fatalf("%s has %d keys: %v", path, len(keys), err)
		}
		return keys[0]
	}
	shared, own, independent := keyOf("notes/shared"), keyOf("notes/first"), keyOf("notes/second")
	a, b := sidecar.NewId(), sidecar.NewId()
	erase := func(id sidecar.Id, keys ...*sidecar.EvsErasedKey) {
		t.Helper()
		world.clock.Advance(evsservice.DefaultEvsSettings().RefusalFenceInterval)
		result, err := w.repo.Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: id, Keys: keys})
		if err != nil || result.Version == 0 {
			t.Fatalf("committing an erasure: %v, %v", result, err)
		}
	}
	for _, id := range []sidecar.Id{a, b} {
		key, err := first.DocKey(world.mainRefId(w), id.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		_, err = first.Cut(ctx, &sidecar.IndexCutArgs{ErasureId: id, Documents: []*sidecar.IndexCutDocument{{Key: key, Version: 1}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	erase(a, shared)
	erase(a, own)
	erase(b, shared, independent)
	rewrite := func(index sidecar.RecordEraseIndex, id sidecar.Id) {
		t.Helper()
		result, err := index.Rewrite(ctx, &sidecar.IndexRewriteArgs{ErasureId: id, Complete: true, Completion: true})
		if err != nil || result == nil || result.Erasure == nil || result.Unproven || result.Erasure.State != sidecar.SidecarErasureDone {
			t.Fatalf("ending the record index erasure: %+v, %v", result, err)
		}
	}
	// The first runner has read the ref and chosen its key. The other commits its own completion before
	// that first push reaches the engine. Both runners must confirm the same terminal statement.
	raced := false
	world.setIntercept(func(device *epochDevice, request *http.Request) error {
		if device == w && request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/slots/delete") && !raced {
			raced = true
			rewrite(second, a)
			world.clock.Advance(evsservice.DefaultEvsSettings().RefusalFenceInterval)
		}
		return nil
	})
	rewrite(first, a)
	world.setIntercept(nil)
	if !raced {
		t.Fatal("neither runner sent a completion")
	}
	rewrite(second, b)
	late := keyOf("notes/late")
	erase(a, late)
	rewrite(second, a)
	committed, err := other.repo.ReadErasures(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantKeys := []*sidecar.EvsErasedKey{own, independent, late}
	wantIds := []sidecar.Id{a, b, a}
	count := 0
	for _, entry := range committed {
		if !entry.Completion {
			continue
		}
		if count >= len(wantKeys) || !entry.Complete || entry.ErasureId != wantIds[count] || len(entry.Keys) != 1 || *entry.Keys[0] != *wantKeys[count] {
			t.Fatalf("completion %d: %+v", count, entry)
		}
		count++
	}
	if count != len(wantKeys) {
		t.Fatalf("the erasure ref has %d completions, want %d", count, len(wantKeys))
	}
}
