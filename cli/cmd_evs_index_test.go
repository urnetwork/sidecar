// ur evs index (SEARCH-M10-15; D-MCP-17): the settings and rebuild methods are Confirm ones, so no MCP or hook session
// and no unconfirmed control call runs them, and status is not; from a terminal a yes reaches the method and a no
// changes nothing; a window that is no number is refused before anything is sent; and the lines name each root's
// state. What the methods do against evs is the root package's (evs_index_build_test.go).

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestEvsIndexSettingsAndRebuildAreConfirmOnly(t *testing.T) {
	repoId := sidecar.NewId()
	target := &testUrEvsTarget{err: errors.New("the evs client is not up")}
	confirm := map[string]bool{}
	for _, method := range urEvsIndexMethods(target) {
		confirm[method.Name] = method.Confirm
	}
	if !confirm[urMethodEvsIndexSettings] || !confirm[urMethodEvsIndexRebuild] {
		t.Error("a settings write or a rebuild runs unconfirmed")
	}
	if confirm[urMethodEvsIndexStatus] {
		t.Error("status asks for a confirmation")
	}
	if methods := urEvsIndexMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no Sidecar serves the index methods")
	}

	daemon := startTestControlDaemon(t, target, nil)
	// an unconfirmed call, as every MCP session's is, is refused before its handler runs
	cli, _, _ := newTestUrCli(daemon.socketPath)
	err := cli.callDaemon(context.Background(), urMethodEvsIndexSettings, &urEvsIndexParams{RepoId: repoId.String(), Action: sidecar.EvsIndexOff}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("an unconfirmed off: %v", err)
	}

	// from a terminal: a yes reaches the method, whose refusal prints
	for _, args := range [][]string{
		{"ur", "evs", "index", repoId.String(), "off"},
		{"ur", "evs", "index", repoId.String(), "on", "--ref", "notes"},
		{"ur", "evs", "index", repoId.String(), "window", "14"},
		{"ur", "evs", "index", repoId.String(), "rebuild", "--companion"},
	} {
		cli, _, stderr := newTestUrCli(daemon.socketPath)
		cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
		if code := cli.main(context.Background(), args); code == urExitOk || !strings.Contains(stderr.String(), "the evs client is not up") {
			t.Errorf("%v: exit %d: %s", args, code, stderr.String())
		}
	}
	// status asks nothing
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return nil, errors.New("no terminal") }
	if code := cli.main(context.Background(), []string{"ur", "evs", "index", repoId.String(), "status"}); code == urExitOk || !strings.Contains(stderr.String(), "the evs client is not up") {
		t.Errorf("status: exit %d: %s", code, stderr.String())
	}
	// a no changes nothing, and nothing is sent
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "evs", "index", repoId.String(), "off"}); code != urExitOk || !strings.Contains(stdout.String(), "nothing changed") {
		t.Errorf("a no: exit %d: %s", code, stdout.String())
	}
	cli, _, stderr = newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "evs", "index", repoId.String(), "window", "fortnight"}); code == urExitOk || !strings.Contains(stderr.String(), "whole number of days") {
		t.Errorf("a window of words: exit %d: %s", code, stderr.String())
	}
}

func TestEvsIndexLinesNameEachRoot(t *testing.T) {
	refId := sidecar.NewId()
	settings := strings.Join(urEvsIndexSettingsLines(&sidecar.EvsIndexSettingsResult{Roots: []*sidecar.EvsIndexRootSettings{
		{RefId: refId, RootNumber: 1, Off: true, Version: 9, RemovedCount: 12},
		{RefId: refId, Companion: true, RootNumber: 1, Waiting: true, RemovedCount: 4},
		{RefId: refId, RootNumber: 1, WindowDays: 14, Version: 3},
	}}), "\n")
	for _, want := range []string{
		"ref " + refId.String() + " .ur-index/i1: off at settings version 9, 12 file(s) removed",
		"ur/index i1: 4 file(s) removed; the off version waits",
		"on, 14-day windows at settings version 3",
	} {
		if !strings.Contains(settings, want) {
			t.Errorf("settings lines lack %q:\n%s", want, settings)
		}
	}
	status := strings.Join(urEvsIndexStatusLines(&sidecar.EvsIndexStatus{Roots: []*sidecar.EvsIndexRootStatus{
		{RefId: refId, RootNumber: 1, State: sidecar.EvsIndexStateOn, FileCount: 7, ByteCount: 70000, BucketCount: 2, AllShardCount: 1,
			Coverage: []*sidecar.EvsIndexCoverage{{RefId: refId, Through: 40, IndexedThrough: 38, UnindexedCount: 2}}},
		{RefId: refId, Companion: true, RootNumber: 1, State: sidecar.EvsIndexStateUpdate},
		{RefId: refId, Companion: true, RootNumber: 2, State: sidecar.EvsIndexStateNone},
	}}), "\n")
	for _, want := range []string{
		"30-day windows, 7 file(s), 70000 B of index apart from content, 2 bucket(s), 1 all shard(s)",
		"searchable through version 38 of 40, 2 change(s) not yet searchable",
		"ur/index i1: in a newer format",
		"ur/index i2: on, 30-day windows, not built",
	} {
		if !strings.Contains(status, want) {
			t.Errorf("status lines lack %q:\n%s", want, status)
		}
	}
}
