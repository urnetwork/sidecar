//go:build !ios_extension

// History of a removed path (QD-672; question mail-m8-02-history-of-a-removed-path) on the evs stand-in: the walk
// takes the removal, then each version below it by number, each verified against its own statement; and a server that
// answers a read by number with the removal again, as evs did before QD-672, stops the walk at once with a tamper
// alarm rather than repeating the removal HistoryVersionCount times.

package sidecar

import (
	"context"
	"fmt"
	"testing"
)

// The versions History gave, each as version/removed, newest first.
func evsTestHistoryVersions(history *EvsHistory) string {
	versions := []string{}
	for _, version := range history.Versions {
		label := fmt.Sprint(version.Version)
		if version.Removed {
			label += "/removed"
		}
		versions = append(versions, label)
	}
	return fmt.Sprint(versions)
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
	if got := evsTestHistoryVersions(history); got != "[4/removed 3 2 1]" {
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
	if err != nil || evsTestHistoryVersions(history) != "[3 2 1]" {
		t.Fatalf("from version 3 served: %s %v", evsTestHistoryVersions(history), err)
	}
}
