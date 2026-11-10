//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's attribution rows as a table on the pure function, then on the point: another run's activity, a restart's
// interval, and restorable's four conditions on a real worktree.

package mcp

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/urnetwork/sidecar"
)

func restoreTestState(content string) *RestoreFileState {
	return &RestoreFileState{Kind: RestoreKindFile, Sha256: sha256Of([]byte(content)), Mode: restoreModeFile, Size: int64(len(content))}
}

// The three rows, hand edits, unknown befores and other runs among them.
func TestAttributionTable(t *testing.T) {
	runId := sidecar.NewId()
	a, b, c := restoreTestState("a"), restoreTestState("b"), restoreTestState("c")
	edit := func(before *RestoreFileState, after *RestoreFileState, known bool) *RestoreObservation {
		return &RestoreObservation{Kind: RestoreObservationEdit, RunId: runId, BeforeKnown: known, Before: before, After: after}
	}
	cases := []struct {
		name string
		args *restoreAttributeArgs
		want RestoreAttribution
	}{
		{"one hooked edit chaining from the scan's before", &restoreAttributeArgs{edits: []*RestoreObservation{edit(a, b, true)}, before: a, beforeKnown: true, after: b}, RestoreAttributionEdit},
		{"two hooked edits chaining", &restoreAttributeArgs{edits: []*RestoreObservation{edit(a, b, true), edit(b, c, true)}, before: a, beforeKnown: true, after: c}, RestoreAttributionEdit},
		{"a hand edit then a hooked edit in one interval", &restoreAttributeArgs{edits: []*RestoreObservation{edit(b, c, true)}, before: a, beforeKnown: true, after: c}, RestoreAttributionForeign},
		{"a hooked edit then a hand edit", &restoreAttributeArgs{edits: []*RestoreObservation{edit(a, b, true)}, before: a, beforeKnown: true, after: c}, RestoreAttributionForeign},
		{"an edit whose before is unknown counts as a non-path tool", &restoreAttributeArgs{edits: []*RestoreObservation{edit(nil, b, false)}, before: a, beforeKnown: true, after: b}, RestoreAttributionShell},
		{"a shell tool alone", &restoreAttributeArgs{before: a, beforeKnown: true, after: b, ownTool: true}, RestoreAttributionShell},
		{"another run named the path", &restoreAttributeArgs{edits: []*RestoreObservation{edit(a, b, true)}, before: a, beforeKnown: true, after: b, otherNamed: true, otherAny: true}, RestoreAttributionForeign},
		{"another run's tool activity makes a shell change foreign", &restoreAttributeArgs{before: a, beforeKnown: true, after: b, ownTool: true, otherAny: true}, RestoreAttributionForeign},
		{"another run's unrelated tool activity leaves a chained edit", &restoreAttributeArgs{edits: []*RestoreObservation{edit(a, b, true)}, before: a, beforeKnown: true, after: b, otherAny: true}, RestoreAttributionEdit},
		{"no activity of this run", &restoreAttributeArgs{before: a, beforeKnown: true, after: b}, RestoreAttributionForeign},
		{"the scan's before unknown", &restoreAttributeArgs{edits: []*RestoreObservation{edit(a, b, true)}, before: nil, beforeKnown: false, after: b}, RestoreAttributionForeign},
	}
	for _, c := range cases {
		if got := restoreAttribute(c.args); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// Another run's hook on the same worktree in the interval makes the change foreign, and the interval spanning a
// daemon restart is foreign whatever this run did.
func TestOtherRunAndRestartAreForeign(t *testing.T) {
	env := newRestoreTestEnv(t)
	env.write("committed.txt", "one\n")
	env.open()
	ctx := context.Background()
	path := filepath.Join(env.dir, "committed.txt")
	// another run's shell hook on this worktree, then this run's chained edit: foreign
	otherRunId := sidecar.NewId()
	otherPayload := env.claudePayload("PostToolUse", "Bash", "toolu_other", map[string]any{"command": "make"})
	if _, err := env.points.NoteEvent(ctx, env.network, env.networkId, otherRunId, env.parse("claude-code", otherPayload), otherPayload); err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"file_path": path, "old_string": "one", "new_string": "1"}
	env.preToolUse("Edit", "toolu_1", input)
	env.write("committed.txt", "1\n")
	scan := env.postToolUse("Edit", "toolu_1", input)
	if len(scan.Changes) != 1 || scan.Changes[0].Attribution != RestoreAttributionEdit {
		// the other run's hook came before this run's scan interval started, since this point's first scan runs
		// from its base: the edit chains and nothing else named the path, so it is this run's
		t.Fatalf("the first scan: %+v", scan.Changes)
	}
	// the other run's edit of the same path inside this run's next interval
	otherEdit := env.claudePayload("PostToolUse", "Edit", "toolu_other2", map[string]any{"file_path": path, "old_string": "1", "new_string": "x"})
	env.write("committed.txt", "x\n")
	if _, err := env.points.NoteEvent(ctx, env.network, env.networkId, otherRunId, env.parse("claude-code", otherEdit), otherEdit); err != nil {
		t.Fatal(err)
	}
	input = map[string]any{"file_path": path, "old_string": "x", "new_string": "y"}
	env.preToolUse("Edit", "toolu_2", input)
	env.write("committed.txt", "y\n")
	scan = env.postToolUse("Edit", "toolu_2", input)
	if len(scan.Changes) != 1 || scan.Changes[0].Attribution != RestoreAttributionForeign {
		t.Fatalf("with another run naming the path: %+v", scan.Changes)
	}
	point, _ := env.points.Point(env.networkId, env.runId)
	if ok, reason, _ := point.Restorable(ctx, "committed.txt"); ok || reason != RestoreReasonForeign {
		t.Errorf("restorable %t %q", ok, reason)
	}
	// a restart: the registry reads the point back, and the next scan's interval is foreign
	env.runId = sidecar.NewId()
	env.write("dir/nested.txt", "n1\n")
	env.open()
	nested := filepath.Join(env.dir, "dir/nested.txt")
	env.points = env.newPoints()
	input = map[string]any{"file_path": nested, "old_string": "n1", "new_string": "n2"}
	env.preToolUse("Edit", "toolu_3", input)
	env.write("dir/nested.txt", "n2\n")
	scan = env.postToolUse("Edit", "toolu_3", input)
	if len(scan.Changes) != 1 || scan.Changes[0].Attribution != RestoreAttributionForeign {
		t.Fatalf("after a restart: %+v", scan.Changes)
	}
}

// restorable(R, p): every change this run's attributed edit, the chain unbroken from an exact base, and the
// current bytes equal to the last after; each condition failing in turn.
func TestRestorableFourConditions(t *testing.T) {
	env := newRestoreTestEnv(t)
	env.write("committed.txt", "one\ntwo\n")
	point := env.open()
	ctx := context.Background()
	path := filepath.Join(env.dir, "committed.txt")
	edit := func(id string, oldString string, newString string, after string) *RestoreScan {
		t.Helper()
		input := map[string]any{"file_path": path, "old_string": oldString, "new_string": newString}
		env.preToolUse("Edit", id, input)
		env.write("committed.txt", after)
		return env.postToolUse("Edit", id, input)
	}
	if ok, reason, err := point.Restorable(ctx, "committed.txt"); ok || reason != RestoreReasonUnchanged || err != nil {
		t.Fatalf("before any change: %t %q %v", ok, reason, err)
	}
	edit("toolu_1", "one", "1", "1\ntwo\n")
	edit("toolu_2", "two", "2", "1\n2\n")
	if ok, reason, err := point.Restorable(ctx, "committed.txt"); !ok || err != nil {
		t.Fatalf("two chained edits: %t %q %v", ok, reason, err)
	}
	if base, _ := point.BaseBytes(ctx, "committed.txt"); string(base) != "one\ntwo\n" {
		t.Errorf("the base bytes: %q", base)
	}
	// changed since: a hand edit after the last scan
	env.write("committed.txt", "1\n2\nby hand\n")
	if ok, reason, _ := point.Restorable(ctx, "committed.txt"); ok || reason != RestoreReasonChangedSince {
		t.Errorf("changed since the last scan: %t %q", ok, reason)
	}
	// the next hook's scan finds that hand edit in an interval with no edit of the path: foreign from then on
	shell := env.claudePayload("PostToolUse", "Bash", "toolu_3", map[string]any{"command": "ls"})
	if _, err := env.points.NoteEvent(ctx, env.network, env.networkId, env.runId, env.parse("claude-code", shell), shell); err != nil {
		t.Fatal(err)
	}
	if ok, reason, _ := point.Restorable(ctx, "committed.txt"); ok || reason != RestoreReasonShell {
		t.Errorf("a shell interval's change: %t %q", ok, reason)
	}
	// chain-broken: an edit whose own before chains, but the scan's record says otherwise
	env.runId = sidecar.NewId()
	env.write("dir/nested.txt", "n\n")
	point = env.open()
	nested := filepath.Join(env.dir, "dir/nested.txt")
	input := map[string]any{"file_path": nested, "old_string": "n", "new_string": "N"}
	env.preToolUse("Edit", "toolu_4", input)
	env.write("dir/nested.txt", "N\n")
	env.postToolUse("Edit", "toolu_4", input)
	if ok, _, _ := point.Restorable(ctx, "dir/nested.txt"); !ok {
		t.Fatal("a chained edit is not restorable")
	}
	point.stateLock.Lock()
	point.ledger.Paths["dir/nested.txt"][1].Before = restoreTestState("elsewhere")
	point.stateLock.Unlock()
	if ok, reason, _ := point.Restorable(ctx, "dir/nested.txt"); ok || reason != RestoreReasonChainBroken {
		t.Errorf("a broken chain: %t %q", ok, reason)
	}
	// not exact: a hash-only base
	env.runId = sidecar.NewId()
	env.settings.FileByteCount = 2
	env.write("untracked.txt", "long enough\n")
	point = env.open()
	if ok, reason, _ := point.Restorable(ctx, "untracked.txt"); ok || reason != RestoreReasonNotExact {
		t.Errorf("a hash-only base: %t %q", ok, reason)
	}
	// a worktree that is no repository: nothing restorable, and edits still recorded
	env.settings.FileByteCount = 8 * 1024 * 1024
	bare := t.TempDir()
	env.dir = bare
	env.runId = sidecar.NewId()
	env.write("plain.txt", "p\n")
	point = env.open()
	if _, err := point.BaseOf(ctx, "plain.txt"); err != ErrRestoreNoRepository {
		t.Errorf("no repository: %v", err)
	}
	plain := filepath.Join(bare, "plain.txt")
	input = map[string]any{"file_path": plain, "old_string": "p", "new_string": "P"}
	env.preToolUse("Edit", "toolu_5", input)
	env.write("plain.txt", "P\n")
	env.postToolUse("Edit", "toolu_5", input)
	if observations := point.Observations(plain); len(observations) == 0 || !observations[0].BeforeKnown || !bytes.Equal(observations[0].Before.Sha256, sha256Of([]byte("p\n"))) {
		t.Errorf("edits outside a repository: %+v", observations)
	}
	if ok, reason, _ := point.Restorable(ctx, plain); ok || reason != RestoreReasonNotExact {
		t.Errorf("restorable outside a repository: %t %q", ok, reason)
	}
}

// A clean path's base is its blob in the commit HEAD named at the run's start. A commit the run's interval hid from
// git status is still found by the next scan, through the two heads' difference, and the edit that follows it
// chains from the committed bytes, not the base, so nothing is restorable to the wrong bytes (RV2).
func TestBaseIsStartingHeadNotIndex(t *testing.T) {
	env := newRestoreTestEnv(t)
	point := env.open()
	ctx := context.Background()
	// a change staged and committed with no hook between: the index and HEAD both move past the start
	env.write("committed.txt", "staged\n")
	env.git("add", "-A")
	env.git("commit", "-q", "-m", "second")
	path := filepath.Join(env.dir, "committed.txt")
	input := map[string]any{"file_path": path, "old_string": "staged", "new_string": "edited"}
	env.preToolUse("Edit", "toolu_1", input)
	env.write("committed.txt", "edited\n")
	scan := env.postToolUse("Edit", "toolu_1", input)
	base, err := point.BaseOf(ctx, "committed.txt")
	if err != nil || !base.Exact || !bytes.Equal(base.State.Sha256, sha256Of([]byte("one\ntwo\nthree\n"))) {
		t.Fatalf("the base is not the starting commit's blob: %+v %v", base, err)
	}
	if len(scan.Changes) != 1 || scan.Changes[0].Attribution == RestoreAttributionEdit {
		t.Fatalf("an edit over a commit the run did not make by a path tool: %+v", scan.Changes)
	}
	if len(scan.Commits) != 1 {
		t.Errorf("the scan's commits: %v", scan.Commits)
	}
	if ok, reason, err := point.Restorable(ctx, "committed.txt"); ok || err != nil {
		t.Errorf("restorable past a commit: %t %q %v", ok, reason, err)
	}
	// a commit alone, the worktree clean after it: the scan still names the path
	env.write("dir/nested.txt", "committed again\n")
	env.git("add", "-A")
	env.git("commit", "-q", "-m", "third")
	shell := env.claudePayload("PostToolUse", "Bash", "toolu_2", map[string]any{"command": "git commit"})
	scan, err = env.points.NoteEvent(ctx, env.network, env.networkId, env.runId, env.parse("claude-code", shell), shell)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, change := range scan.Changes {
		if change.Path == "dir/nested.txt" {
			found = true
			if change.Attribution != RestoreAttributionShell || !change.BeforeKnown || !bytes.Equal(change.Before.Sha256, sha256Of([]byte("nested\n"))) {
				t.Errorf("the committed path's change: %+v", change)
			}
		}
	}
	if !found {
		t.Errorf("a committed change was not scanned: %+v", scan.Changes)
	}
}

// A path .gitignore hides was never walked, so its start is unknown: an edit that finds it absent is not chained
// to an absent base, and the path is never restorable, which would delete bytes the walk did not see.
func TestIgnoredPathBaseNotExact(t *testing.T) {
	env := newRestoreTestEnv(t)
	env.write("debug.log", "bytes the walk never saw\n")
	point := env.open()
	ctx := context.Background()
	// removed with no hook between, then written by the run
	env.remove("debug.log")
	path := filepath.Join(env.dir, "debug.log")
	input := map[string]any{"file_path": path, "content": "written\n"}
	env.preToolUse("Write", "toolu_1", input)
	env.write("debug.log", "written\n")
	scan := env.postToolUse("Write", "toolu_1", input)
	if len(scan.Changes) != 1 || scan.Changes[0].BeforeKnown || scan.Changes[0].Attribution == RestoreAttributionEdit {
		t.Fatalf("an ignored path's change: %+v", scan.Changes)
	}
	base, err := point.BaseOf(ctx, "debug.log")
	if err != nil || base.Exact {
		t.Fatalf("an ignored path's base: %+v %v", base, err)
	}
	if ok, reason, err := point.Restorable(ctx, "debug.log"); ok || reason != RestoreReasonNotExact || err != nil {
		t.Errorf("restorable on an ignored path: %t %q %v", ok, reason, err)
	}
	if _, err := point.BaseBytes(ctx, "debug.log"); err == nil {
		t.Error("an ignored path's base bytes were answered")
	}
}

// A hold belongs to the process that took it: after a restart its sealed copy is removed, its bytes no longer count
// against the point, and the edit's before is unknown.
func TestRestartDropsHolds(t *testing.T) {
	env := newRestoreTestEnv(t)
	env.write("untracked.txt", "kept in the base\n")
	point := env.open()
	path := filepath.Join(env.dir, "committed.txt")
	input := map[string]any{"file_path": path, "old_string": "one", "new_string": "1"}
	env.preToolUse("Edit", "toolu_1", input)
	if !point.Holds("toolu_1", path) {
		t.Fatal("the path is not held")
	}
	held, err := point.store.List(restoreHoldCopyPrefix)
	if err != nil || len(held) != 1 {
		t.Fatalf("the hold's copy: %v %v", held, err)
	}
	if err := point.saveManifest(); err != nil {
		t.Fatal(err)
	}
	env.points = env.newPoints()
	point = env.open()
	if point.Holds("toolu_1", path) {
		t.Error("a hold outlived its process")
	}
	if held, err := point.store.List(restoreHoldCopyPrefix); err != nil || len(held) != 0 {
		t.Errorf("the hold's copy after a restart: %v %v", held, err)
	}
	point.stateLock.Lock()
	byteCount := point.manifest.ByteCount
	point.stateLock.Unlock()
	if byteCount != int64(len("kept in the base\n")) {
		t.Errorf("the point's byte count after a restart: %d", byteCount)
	}
	env.write("committed.txt", "1\ntwo\nthree\n")
	scan := env.postToolUse("Edit", "toolu_1", input)
	if observations := point.Observations("committed.txt"); len(observations) == 0 || observations[0].BeforeKnown {
		t.Errorf("the edit after a restart: %+v", observations)
	}
	if len(scan.Changes) != 1 || scan.Changes[0].Attribution != RestoreAttributionForeign {
		t.Errorf("the restart's interval: %+v", scan.Changes)
	}
}
