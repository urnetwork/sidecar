// ur history (EVS2-M10-23): each part reaches its method over a target that hosts a Sidecar, the daemon's refusal
// printed; a cancel asks on the terminal before anything is sent, and with no terminal sends nothing; the drop and the
// cancel are Confirm methods, which only a control session a person answered for runs, so no agent's session reaches
// them; and the dry run's, the drop's and the listing's lines. What the drop does against evs is the root's
// (evs_drop_push_test.go).

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

func TestHistoryReachesTheDaemonsMethods(t *testing.T) {
	repoId := sidecar.NewId()
	target := &testUrEvsTarget{err: errors.New("the evs client is not up")}
	daemon := startTestControlDaemon(t, target, nil)
	for _, args := range [][]string{
		{"ur", "history", "drop", repoId.String() + ":notes/plan.md", "--dry-run"},
		{"ur", "history", "drop", repoId.String() + ":notes/plan.md", "--detach"},
		{"ur", "history", "drops", repoId.String()},
	} {
		cli, _, stderr := newTestUrCli(daemon.socketPath)
		if code := cli.main(context.Background(), args); code == urExitOk || !strings.Contains(stderr.String(), "the evs client is not up") {
			t.Errorf("%v: exit %d: %s", args, code, stderr.String())
		}
	}
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "history", "drop", "not-a-repo:a.txt"}); code == urExitOk || !strings.Contains(stderr.String(), "is no repo id") {
		t.Errorf("a bad repo id: exit %d: %s", code, stderr.String())
	}
	cli, _, stderr = newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "history", "drop", repoId.String() + ":a.txt", sidecar.NewId().String() + ":b.txt"}); code == urExitOk || !strings.Contains(stderr.String(), "one repo at a time") {
		t.Errorf("two repos: exit %d: %s", code, stderr.String())
	}
	// a cancel asks on the terminal first: with none, nothing is sent
	cli, _, stderr = newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return nil, errors.New("no terminal") }
	if code := cli.main(context.Background(), []string{"ur", "history", "cancel", repoId.String(), "00112233445566778899aabbccddeeff"}); code == urExitOk || strings.Contains(stderr.String(), "the evs client is not up") {
		t.Errorf("a cancel with no terminal: exit %d: %s", code, stderr.String())
	}
}

// The drop and the cancel run only as Confirm methods; the dry run and the listing are any control call's.
func TestHistoryDropAndCancelAreConfirmMethods(t *testing.T) {
	methods := urHistoryMethods(&testUrEvsTarget{err: errors.New("down")})
	confirm := map[string]bool{}
	for _, method := range methods {
		confirm[method.Name] = method.Confirm
	}
	if !confirm[urMethodHistoryDrop] || !confirm[urMethodHistoryCancel] || confirm[urMethodHistoryPreview] || confirm[urMethodHistoryDrops] {
		t.Fatalf("Confirm methods %v", confirm)
	}
	if len(methods) != 4 {
		t.Fatalf("%d methods", len(methods))
	}
}

func TestHistoryLines(t *testing.T) {
	preview := &sidecar.EvsDropPreview{
		Lineages: []*sidecar.EvsDropLineage{
			{Path: "notes/plan.md", DropPath: &protocol.EvsDropPath{Boundary: sidecar.EvsDropBoundaryWritten, Count: 5}},
			{Path: "old.txt", DropPath: &protocol.EvsDropPath{Boundary: sidecar.EvsDropBoundaryRemoved, Count: 3}},
		},
		Batches:    []*sidecar.EvsDropPreviewBatch{{}, {}},
		FreedBytes: 4096, SharedBytes: 512, InlineBytes: 100, PackedBytes: 7, YoungBytes: 9,
	}
	lines := strings.Join(urHistoryPreviewLines(preview), "\n")
	for _, want := range []string{"notes/plan.md: 5 older version(s) dropped, its head stays", "old.txt: 3 older version(s) dropped, removed",
		"frees 4096 bytes", "512 bytes stay shared", "in 2 DROP pushes"} {
		if !strings.Contains(lines, want) {
			t.Errorf("the dry run does not show %q:\n%s", want, lines)
		}
	}
	dropId := sidecar.NewId()
	notBefore := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	result := &sidecar.EvsDropHistoryResult{Pushes: []*sidecar.EvsDropPushResult{{DropId: dropId, Version: 9, NotBefore: notBefore}}}
	dropped := strings.Join(urHistoryDropLines(result), "\n")
	if !strings.Contains(dropped, "at ref version 9, pending until 2026-11-25 12:00:00Z") || !strings.Contains(dropped, "left to the backfill") {
		t.Errorf("the drop shows:\n%s", dropped)
	}
	drops := []*sidecar.EvsDrop{
		{Status: &protocol.EvsDropStatus{DropId: dropId.Bytes(), Version: 9, State: protocol.EvsDropState_EVS_DROP_PENDING, NotBeforeMs: notBefore.UnixMilli()}, Paths: []string{"notes/plan.md"}},
		{Status: &protocol.EvsDropStatus{DropId: sidecar.NewId().Bytes(), Version: 4, State: protocol.EvsDropState_EVS_DROP_OBSERVED}},
	}
	listed, listedLines := urHistoryDropsOf(drops)
	text := strings.Join(listedLines, "\n")
	if len(listed) != 2 || listed[1].State != string(sidecar.SidecarDropDone) || !strings.Contains(text, "pending, until 2026-11-25") || !strings.Contains(text, "  notes/plan.md") {
		t.Errorf("the listing:\n%s", text)
	}
	if _, empty := urHistoryDropsOf(nil); len(empty) != 1 || empty[0] != "no drops" {
		t.Errorf("an empty listing %v", empty)
	}
}
