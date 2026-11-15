// ur evs log's lines (EVS1-M2-38; DESIGN-DETAILS 16.2.5's History row and 16.2.7's metadata row; QD-833): each version
// with its state, one this device ignores marked so, and one a later repair wrote over marked with that repair's
// version. What History answers against evs, and which versions it marks, is the root's (evs_prefix_repair_test.go).

package main

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// Two repairs, at versions 6 and 3, each over the ignored versions below it: those versions carry their own repair's
// mark, and the repairs, the version the first one repaired to and an ignored version no repair named carry none.
func TestEvsLogMarksTheVersionsARepairWroteOver(t *testing.T) {
	admin, err := sidecar.ParseId("0199a1b2c3d4e5f60718293a4b5c6d7e")
	if err != nil {
		t.Fatal(err)
	}
	held, err := sidecar.ParseId("0199a1b2c3d4e5f60718293a4b5c6d7f")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	version := func(number uint64, signer sidecar.Id, ignored bool, writtenOverBy uint64) *sidecar.EvsHistoryVersion {
		return &sidecar.EvsHistoryVersion{
			Version: number, CommitVersion: number + 10, SignerSidecarId: signer, Time: at.Add(time.Duration(number) * time.Minute),
			State: "kept", Ignored: ignored, WrittenOverBy: writtenOverBy,
		}
	}
	history := &sidecar.EvsHistory{Versions: []*sidecar.EvsHistoryVersion{
		version(7, held, true, 0),
		version(6, admin, false, 0),
		version(5, held, true, 6),
		version(4, held, true, 6),
		version(3, admin, false, 0),
		version(2, held, true, 3),
		version(1, admin, false, 0),
	}}
	history.Versions[5].Removed = true
	line := func(number uint64, signer sidecar.Id, what string, marks string) string {
		return fmt.Sprintf("version %d at ref version %d by sidecar %s, 2026-11-15 12:%02d:00Z, %s%s", number, number+10, signer, number, what, marks)
	}
	want := []string{
		line(7, held, "kept", ", ignored: prefix rule"),
		line(6, admin, "kept", ""),
		line(5, held, "kept", ", ignored: prefix rule, written over by version 6"),
		line(4, held, "kept", ", ignored: prefix rule, written over by version 6"),
		line(3, admin, "kept", ""),
		line(2, held, "removed", ", ignored: prefix rule, written over by version 3"),
		line(1, admin, "kept", ""),
	}
	if got := urEvsLogLines(history); !slices.Equal(got, want) {
		t.Errorf("ur evs log:\n got %q\nwant %q", got, want)
	}
}

// A path with no prefix rules, or no repair, prints as it did before the marks: each version and its state alone.
func TestEvsLogPrintsAnUnmarkedHistoryAsBefore(t *testing.T) {
	signer, err := sidecar.ParseId("0199a1b2c3d4e5f60718293a4b5c6d7e")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	history := &sidecar.EvsHistory{Versions: []*sidecar.EvsHistoryVersion{
		{Version: 2, CommitVersion: 3, SignerSidecarId: signer, Time: at, State: "collected"},
		{Version: 1, CommitVersion: 1, SignerSidecarId: signer, Time: at, State: "kept"},
	}}
	want := []string{
		fmt.Sprintf("version 2 at ref version 3 by sidecar %s, 2026-11-15 12:00:00Z, collected", signer),
		fmt.Sprintf("version 1 at ref version 1 by sidecar %s, 2026-11-15 12:00:00Z, kept", signer),
	}
	if got := urEvsLogLines(history); !slices.Equal(got, want) {
		t.Errorf("ur evs log:\n got %q\nwant %q", got, want)
	}
	if got := urEvsLogLines(&sidecar.EvsHistory{}); len(got) != 0 {
		t.Errorf("no versions: %q", got)
	}
}
