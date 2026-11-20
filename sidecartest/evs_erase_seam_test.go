// SlotKeysOf on the real engine (QD-1109; question mail-m10-04-closure-of-a-file-born-past-version-1; EVS2-M10-12):
// sidecar.EvsClient devices in the format2 gate against an evsservice.EvsEngine over FakeHost's stores, on the
// path-epoch world (evs_epoch_world_test.go), in a slot-keyed repo, where each versionless file keeps its key in a
// slot of its own.
//
//	born at N  a file first created by the repo's second push starts at version 2 (§11.7's versions row); its walk
//	           ends at that creation, below which evs answers nothing, so SlotKeysOf lists its slot, and a CLOSURE
//	           and the ERASE of that list leave no prior version opening, as an index file of a mailbox's later
//	           push needs
//	again      such a file removed and created again: the walk crosses the second creation into the removal and
//	           the first life, born at 2, and lists both lives' slots, newest first, which one ERASE destroys

package sidecartest

import (
	"bytes"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

func TestEvsSlotKeysOfAPathBornPastVersionOneEndToEnd(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	w := world.format2Device("w")
	if _, err := w.writeSetting("index/first.bin", versionlessContent("first", 2*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	before := world.slotKeys()
	path := "index/later.bin"
	if _, err := w.writeSetting(path, versionlessContent("later one", 2*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	if _, err := w.writeSetting(path, versionlessContent("later two", 3*1024), ""); err != nil {
		t.Fatal(err)
	}
	added := epochNewSlots(before, world.slotKeys())
	if len(added) != 1 {
		t.Fatalf("the later file added %d slots", len(added))
	}
	history, err := w.repo.History(world.ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true})
	if err != nil || len(history.Versions) != 2 || history.Versions[1].Version != 2 || !history.Versions[1].Created || !history.Whole {
		t.Fatalf("the later file's history: %+v %v", history, err)
	}
	keys, err := w.repo.SlotKeysOf(world.ctx, nil, []string{path})
	if err != nil || len(keys) != 1 || keys[0].SlotId != added[0] || keys[0].KeyIndex != 0 {
		t.Fatalf("the later file's slot keys: %v %v", keys, err)
	}

	// the CLOSURE rewrites it under a fresh key in a new slot, and the ERASE of the list takes every prior version
	closed := versionlessContent("later without the entry", 1500)
	erasureId := sidecar.NewId()
	if _, err := w.repo.Closure(world.ctx, &sidecar.EvsClosureArgs{
		ErasureId: erasureId, Writes: []*sidecar.EvsPathWrite{{Path: path, Content: bytes.NewReader(closed)}}, Erased: keys,
	}); err != nil {
		t.Fatalf("the CLOSURE: %v", err)
	}
	if _, err := w.repo.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: erasureId, Keys: keys, Complete: true, Note: []byte("the later file")}); err != nil {
		t.Fatalf("the ERASE: %v", err)
	}
	if count := world.slotKeyCount(added[0]); count != 0 {
		t.Fatalf("the later file's old slot holds %d keys after the ERASE", count)
	}
	world.requireReads("after the ERASE", path, closed)
	world.requireNoPriorVersionOpens("after the ERASE", path, 3)
	// the file the first push created is untouched
	world.requireReads("after the ERASE", "index/first.bin", versionlessContent("first", 2*1024))
}

func TestEvsSlotKeysOfAPathBornPastVersionOneCreatedAgainEndToEnd(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	w := world.format2Device("w")
	if _, err := w.writeSetting("index/first.bin", versionlessContent("first", 2*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	path := "index/again.bin"
	before := world.slotKeys()
	if _, err := w.writeSetting(path, versionlessContent("first life", 2*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatal(err)
	}
	firstLife := epochNewSlots(before, world.slotKeys())
	if _, err := w.repo.Write(world.ctx, &sidecar.EvsWriteArgs{Path: path, Remove: true}); err != nil {
		t.Fatalf("the removal: %v", err)
	}
	before = world.slotKeys()
	second := versionlessContent("second life", 2*1024)
	if _, err := w.writeSetting(path, second, sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the second creation: %v", err)
	}
	secondLife := epochNewSlots(before, world.slotKeys())
	if len(firstLife) != 1 || len(secondLife) != 1 {
		t.Fatalf("the lives' slots: %v, %v", firstLife, secondLife)
	}
	// the second creation at max(3, 3) + 1 = 4, the removal at 3, the first life's creation at 2
	history, err := w.repo.History(world.ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true})
	if err != nil || len(history.Versions) != 3 || !history.Whole || history.Versions[2].Version != 2 || !history.Versions[2].Created ||
		!history.Versions[1].Removed || !history.Versions[0].Created {
		t.Fatalf("the history across both lives: %+v %v", history, err)
	}
	keys, err := w.repo.SlotKeysOf(world.ctx, nil, []string{path})
	if err != nil || len(keys) != 2 || keys[0].SlotId != secondLife[0] || keys[1].SlotId != firstLife[0] {
		t.Fatalf("the slot keys across both lives: %v %v", keys, err)
	}
	if _, err := w.repo.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: keys, Complete: true, Note: []byte("both lives")}); err != nil {
		t.Fatalf("the ERASE: %v", err)
	}
	for _, slotId := range []sidecar.Id{firstLife[0], secondLife[0]} {
		if count := world.slotKeyCount(slotId); count != 0 {
			t.Fatalf("slot %s holds %d keys after the ERASE", slotId, count)
		}
	}
	world.requireNoVersionOpens("after the ERASE", path, 3)
}
