//go:build !ios_extension

// History of a removed path (QD-672; question mail-m8-02-history-of-a-removed-path) on the evs stand-in: the walk
// takes the removal, then each version below it by number, each verified against its own statement; and a server that
// answers a read by number with the removal again, as evs did before QD-672, stops the walk at once with a tamper
// alarm rather than repeating the removal HistoryVersionCount times.
//
// History across a path's lives (QD-888, question mail-m7-04-recreated-record-history; owner decision 380): below
// each creation the walk reads by number alone into the removal that ended the earlier life and on through it, to
// the first creation, below which evs answers nothing; a creation whose number names a removal below it that evs does
// not serve raises the version-rule alarm; a read below a creation that evs refuses 503 ends the walk with
// BelowUnknown; and a version asked by number that the path holds none at reads absent, whatever evs serves below it.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The versions History gave, each as version/removed or version/created, newest first.
func evsTestHistoryVersions(history *EvsHistory) string {
	versions := []string{}
	for _, version := range history.Versions {
		label := fmt.Sprint(version.Version)
		if version.Removed {
			label += "/removed"
		}
		if version.Created {
			label += "/created"
		}
		versions = append(versions, label)
	}
	return fmt.Sprint(versions)
}

// a.txt through three lives, the first two ended by removals: one, two, removed at 3; three created at max(3, 3) + 1
// = 4, four, removed at 6; five created at 7. Then b.txt, created over nothing at max(7, 0) + 1 = 8.
func newEvsTestThreeLives(t *testing.T) *evsTestWorld {
	t.Helper()
	world := newEvsTestWorld(t)
	for _, content := range []string{"one", "two", "", "three", "four", "", "five"} {
		if content == "" {
			world.push(&evsTestChange{path: "a.txt"})
			continue
		}
		world.push(&evsTestChange{path: "a.txt", content: []byte(content)})
	}
	world.push(&evsTestChange{path: "b.txt", content: []byte("b")})
	return world
}

func TestEvsHistoryWalksARemovedPathsVersions(t *testing.T) {
	world := newEvsTestWorld(t)
	for _, content := range []string{"one", "two", "three"} {
		world.push(&evsTestChange{path: "a.txt", content: []byte(content)})
	}
	world.push(&evsTestChange{path: "a.txt"})
	reader := world.reader(t, evsTestId("reader"))
	history, err := reader.client.Repo(world.repoId).History(context.Background(), &EvsReadArgs{Path: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if got := evsTestHistoryVersions(history); got != "[4/removed 3 2 1/created]" {
		t.Fatalf("versions %s", got)
	}
	for _, version := range history.Versions[1:] {
		if version.State != "kept" || version.SignerSidecarId != world.signer.sidecarId || version.CommitVersion != version.Version {
			t.Errorf("version %+v", version)
		}
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// A server repeating a removed path's removal for every read by number gives History the removal once, then stops
// with an alarm, never a second copy and never HistoryVersionCount reads.
func TestEvsHistoryStopsAWalkThatDoesNotDescend(t *testing.T) {
	world := newEvsTestWorld(t)
	for _, content := range []string{"one", "two", "three"} {
		world.push(&evsTestChange{path: "a.txt", content: []byte(content)})
	}
	world.push(&evsTestChange{path: "a.txt"})
	world.repeatRemoval = true
	reader := world.reader(t, evsTestId("reader"))
	readsBefore := world.reads
	history, err := reader.client.Repo(world.repoId).History(context.Background(), &EvsReadArgs{Path: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if got := evsTestHistoryVersions(history); got != "[4/removed]" {
		t.Fatalf("versions %s", got)
	}
	alarms := reader.eventsOf(SidecarEventEvsAlarm)
	if len(alarms) != 1 || alarms[0].EvsAlarm != SidecarEvsAlarmTamper || alarms[0].Path != "a.txt" {
		t.Fatalf("alarms %v", alarms)
	}
	if reads := world.reads - readsBefore; reader.client.settings.HistoryVersionCount <= reads || 4 < reads {
		t.Errorf("%d reads for a walk that stopped at its second", reads)
	}
	// asked from version 3 by number, the repeated removal stops the walk before it gives anything
	history, err = reader.client.Repo(world.repoId).History(context.Background(), &EvsReadArgs{Path: "a.txt", Version: 3})
	if err != nil || len(history.Versions) != 0 {
		t.Fatalf("from version 3: %s %v", evsTestHistoryVersions(history), err)
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 2 {
		t.Fatalf("alarms %v", alarms)
	}
	// once the server serves the versions, the same walk descends to the first
	world.repeatRemoval = false
	history, err = reader.client.Repo(world.repoId).History(context.Background(), &EvsReadArgs{Path: "a.txt", Version: 3})
	if err != nil || evsTestHistoryVersions(history) != "[3 2 1/created]" {
		t.Fatalf("from version 3 served: %s %v", evsTestHistoryVersions(history), err)
	}
}

// History of a path made three times walks every life, newest first, each creation marked and nothing alarmed: below
// a creation, by number alone, the removal that ended the life before it. A path created once over nothing walks to
// its creation and one more read, which evs answers with nothing below it. A walk asked from a number inside an
// earlier life starts at that number.
func TestEvsHistoryWalksAcrossCreationsIntoEarlierLives(t *testing.T) {
	world := newEvsTestThreeLives(t)
	reader := world.reader(t, evsTestId("reader"))
	repo := reader.client.Repo(world.repoId)
	history, err := repo.History(context.Background(), &EvsReadArgs{Path: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if got := evsTestHistoryVersions(history); got != "[7/created 6/removed 5 4/created 3/removed 2 1/created]" {
		t.Fatalf("versions %s", got)
	}
	if history.BelowUnknown {
		t.Error("a whole walk marked as stopped below")
	}
	for _, version := range history.Versions {
		if version.CommitVersion != version.Version || version.SignerSidecarId != world.signer.sidecarId {
			t.Errorf("version %+v", version)
		}
	}
	readsBefore := world.reads
	history, err = repo.History(context.Background(), &EvsReadArgs{Path: "b.txt"})
	if err != nil || evsTestHistoryVersions(history) != "[8/created]" {
		t.Fatalf("b.txt: %s %v", evsTestHistoryVersions(history), err)
	}
	if reads := world.reads - readsBefore; reads != 2 {
		t.Errorf("%d reads for a creation and the number below it", reads)
	}
	history, err = repo.History(context.Background(), &EvsReadArgs{Path: "a.txt", Version: 5})
	if err != nil || evsTestHistoryVersions(history) != "[5 4/created 3/removed 2 1/created]" {
		t.Fatalf("from 5: %s %v", evsTestHistoryVersions(history), err)
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// A creation based on a head older than the removal before it took max(b, m) + 1 = m + 1 past b + 1, which names that
// removal (I-EVS-8): an evs that answers the number below it with nothing, as evs did before QD-888, ends the walk
// with the version-rule alarm, while one that serves the removal walks on with none.
func TestEvsHistoryAlarmsWhereACreationNamesARemovalEvsDoesNotServe(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("one")})
	world.push(&evsTestChange{path: "a.txt"})
	world.nextBaseVersion = 1
	world.push(&evsTestChange{path: "a.txt", content: []byte("again")})
	reader := world.reader(t, evsTestId("reader"))
	history, err := reader.client.Repo(world.repoId).History(context.Background(), &EvsReadArgs{Path: "a.txt"})
	if err != nil || evsTestHistoryVersions(history) != "[3/created 2/removed 1/created]" {
		t.Fatalf("served: %s %v", evsTestHistoryVersions(history), err)
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Fatalf("alarms %v", alarms)
	}
	world.exactNumbers = true
	history, err = reader.client.Repo(world.repoId).History(context.Background(), &EvsReadArgs{Path: "a.txt"})
	if err != nil || evsTestHistoryVersions(history) != "[3/created]" || history.Whole {
		t.Fatalf("hidden: %s %v, whole %v", evsTestHistoryVersions(history), err, history != nil && history.Whole)
	}
	alarms := reader.eventsOf(SidecarEventEvsAlarm)
	if len(alarms) != 1 || alarms[0].EvsAlarm != SidecarEvsAlarmVersionRule || alarms[0].Path != "a.txt" {
		t.Fatalf("alarms %v", alarms)
	}
}

// A path first created past its ref's first push starts above version 1 (§11.7's versions row gives a creation its
// push's base + 1): its walk is whole once evs answers that nothing stands below the creation, and an erasure's list
// of it is a list (evs_erase.go's SlotKeysOf).
func TestEvsHistoryIsWholeAtAFirstCreationPastVersionOne(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("one")})
	world.push(&evsTestChange{path: "b.txt", content: []byte("two")})
	reader := world.reader(t, evsTestId("reader"))
	repo := reader.client.Repo(world.repoId)
	history, err := repo.History(context.Background(), &EvsReadArgs{Path: "b.txt"})
	if err != nil || evsTestHistoryVersions(history) != "[2/created]" || !history.Whole || history.BelowUnknown {
		t.Fatalf("a first creation at 2: %s %v, whole %v", evsTestHistoryVersions(history), err, history != nil && history.Whole)
	}
	if keys, err := repo.SlotKeysOf(context.Background(), nil, []string{"b.txt"}); err != nil || len(keys) != 0 {
		t.Fatalf("slot keys of a path first created at 2: %v %v", keys, err)
	}
	history, err = repo.History(context.Background(), &EvsReadArgs{Path: "a.txt"})
	if err != nil || evsTestHistoryVersions(history) != "[1/created]" || !history.Whole {
		t.Fatalf("a first creation at 1: %s %v", evsTestHistoryVersions(history), err)
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// A signed lower entry can still be displayed. Reaching version 1 through it proves no coverage of the missing
// file before a removal or the removal a re-creation named.
func TestEvsHistoryKeepsASkippedPredecessorIncomplete(t *testing.T) {
	ctx := t.Context()
	for _, missing := range []string{"file", "removal"} {
		world := newEvsTestWorld(t)
		path := "history.txt"
		world.push(&evsTestChange{path: path, content: []byte("first")})
		world.push(&evsTestChange{path: path, content: []byte("second")})
		world.push(&evsTestChange{path: path})
		partial := "[3/removed 1/created]"
		state := world.paths[path]
		var restore func()
		if missing == "removal" {
			world.nextBaseVersion = 1
			world.push(&evsTestChange{path: path, content: []byte("new life")})
			removal := state.removals[3]
			delete(state.removals, 3)
			restore = func() { state.removals[3] = removal }
			partial = "[4/created 2 1/created]"
		} else {
			file := state.versions[2]
			delete(state.versions, 2)
			restore = func() { state.versions[2] = file }
		}
		reader := world.reader(t, evsTestId("history reader"))
		repo := reader.client.Repo(world.repoId)
		history, err := repo.History(ctx, &EvsReadArgs{Path: path})
		if err != nil || evsTestHistoryVersions(history) != partial || history.Whole {
			t.Fatalf("missing %s, displayed history %+v: %v", missing, history, err)
		}
		if keys, err := repo.SlotKeysOf(ctx, nil, []string{path}); !errors.Is(err, ErrEvsSlotKeysIncomplete) || keys != nil {
			t.Fatalf("missing %s, destructive history %v: %v", missing, keys, err)
		}
		restore()
		if _, err := repo.SlotKeysOf(ctx, nil, []string{path}); err != nil {
			t.Fatalf("restored %s: %v", missing, err)
		}
	}
}

// A read below a creation that evs refuses 503, as it refuses a read past its scan bound, ends the walk there with
// BelowUnknown set and no error, and the walk asked from inside the life it could not reach fails as any read does.
func TestEvsHistoryEndsBelowACreationEvsCannotRead(t *testing.T) {
	world := newEvsTestThreeLives(t)
	world.belowRefused = true
	reader := world.reader(t, evsTestId("reader"))
	repo := reader.client.Repo(world.repoId)
	history, err := repo.History(context.Background(), &EvsReadArgs{Path: "a.txt"})
	if err != nil || evsTestHistoryVersions(history) != "[7/created]" || !history.BelowUnknown || history.Whole {
		t.Fatalf("history %s %v, below unknown %v", evsTestHistoryVersions(history), err, history != nil && history.BelowUnknown)
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	if _, err := repo.History(context.Background(), &EvsReadArgs{Path: "a.txt", Version: 6}); !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE) {
		t.Fatalf("from inside the earlier life: %v", err)
	}
	// an erasure's list of a walk that stopped there is no list (evs_erase.go's SlotKeysOf)
	if keys, err := repo.SlotKeysOf(context.Background(), nil, []string{"a.txt"}); !errors.Is(err, ErrEvsSlotKeysIncomplete) || keys != nil {
		t.Fatalf("slot keys of a walk stopped below: %v %v", keys, err)
	}
	world.belowRefused = false
	if keys, err := repo.SlotKeysOf(context.Background(), nil, []string{"a.txt"}); err != nil || len(keys) != 0 {
		t.Fatalf("slot keys of the whole walk: %v %v", keys, err)
	}
}

// A version asked for by number that the path holds none at reads absent, though evs answers its newest version or
// removal below the number; one it holds reads whole, in any life.
func TestEvsReadVersionOfANumberThePathHoldsNoneAt(t *testing.T) {
	world := newEvsTestThreeLives(t)
	reader := world.reader(t, evsTestId("reader"))
	repo := reader.client.Repo(world.repoId)
	for _, version := range []uint64{3, 6, 9} {
		if _, err := repo.ReadVersion(context.Background(), &EvsReadArgs{Path: "a.txt", Version: version}, &bytes.Buffer{}); !errors.Is(err, ErrEvsPathAbsent) {
			t.Fatalf("version %d: %v", version, err)
		}
	}
	for version, content := range map[uint64]string{2: "two", 4: "three", 7: "five"} {
		out := &bytes.Buffer{}
		if _, err := repo.ReadVersion(context.Background(), &EvsReadArgs{Path: "a.txt", Version: version}, out); err != nil || out.String() != content {
			t.Fatalf("version %d: %q %v", version, out.String(), err)
		}
	}
}
