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
