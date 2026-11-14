// History of a removed path end to end on T2 (QD-672; question mail-m8-02-history-of-a-removed-path): an
// sidecar.EvsClient device against evsservice over FakeHost's stores, in a record repo, where every version's chain
// sits under a slot key of its own. A fresh reader's History of a path written three times and then removed walks the
// removal and every version below it, each with the slots its entry names, so an erasure of a removed path names
// every retained version's slot keys (§11.12's closure row). History's stop and alarm on a walk that does not descend
// are evs_history_test.go's, on the stand-in that repeats the removal.

package sidecartest

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

func TestEvsHistoryOfARemovedPathWalksItsVersionsOnTheEngine(t *testing.T) {
	world := newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	w := world.device("w", nil)
	for _, content := range []string{"one", "two", "three"} {
		if _, err := w.write("notes/a.md", bytes.Repeat([]byte("version "+content+"; "), 200)); err != nil {
			t.Fatalf("version %s: %v", content, err)
		}
	}
	if _, err := w.write("notes/a.md", nil); err != nil {
		t.Fatalf("the removal: %v", err)
	}
	fresh := world.device("r", nil)
	history, err := fresh.repo.History(world.ctx, &sidecar.EvsReadArgs{Path: "notes/a.md"})
	if err != nil {
		t.Fatal(err)
	}
	versions := []string{}
	for _, version := range history.Versions {
		label := fmt.Sprint(version.Version)
		if version.Removed {
			label += "/removed"
		}
		versions = append(versions, label)
	}
	if fmt.Sprint(versions) != "[4/removed 3 2 1]" {
		t.Fatalf("versions %v", versions)
	}
	slotIds := map[sidecar.Id]bool{}
	for _, version := range history.Versions[1:] {
		if len(version.SlotIds) == 0 {
			t.Fatalf("version %d names no slot", version.Version)
		}
		for _, slotId := range version.SlotIds {
			slotIds[slotId] = true
		}
	}
	if len(slotIds) < 1 {
		t.Fatalf("slots %v", slotIds)
	}
}
