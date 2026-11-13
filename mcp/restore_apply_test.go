//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's dry run and apply (MCP-M3-21) on a real git worktree under t.TempDir(): the preview id binding each kind and
// hash, an apply needing its preview, a change after the preview put back as changed, each conflict name as its own
// result, a parent symlink out of the worktree refused, a restart after the aside and after the install, copies never
// over an existing name, and a volume taking neither rename nor link moving nothing. The OS calls are the platform's,
// wrapped where a test stands in for a concurrent writer or a volume (restoreTestFs). The race schedules are
// MCP-M3-27's.

package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// The apply's OS calls with a test's hooks around them: before each no-replace rename (an error answers it), after
// it, and a volume that takes no such rename or no hard link.
type restoreTestFs struct {
	beforeRename      func(from string, to string) error
	afterRename       func(from string, to string)
	renameUnsupported bool
	linkUnsupported   bool
	renames           [][2]string
}

func (self *restoreTestFs) fs() *restoreFs {
	return &restoreFs{
		renameNoReplace: func(dir *os.File, dirPath string, from string, to string) error {
			if self.beforeRename != nil {
				if err := self.beforeRename(from, to); err != nil {
					return err
				}
			}
			if self.renameUnsupported {
				return &os.LinkError{Op: "rename", Old: from, New: to, Err: errRestoreRenameUnsupported}
			}
			err := restoreRenameNoReplace(dir, dirPath, from, to)
			if err == nil {
				self.renames = append(self.renames, [2]string{from, to})
				if self.afterRename != nil {
					self.afterRename(from, to)
				}
			}
			return err
		},
		link: func(parent *os.Root, from string, to string) error {
			if self.linkUnsupported {
				return &os.LinkError{Op: "link", Old: from, New: to, Err: errRestoreLinkUnsupported}
			}
			return parent.Link(from, to)
		},
	}
}

// Whether name is an install: a staged name renamed to a path's own name.
func restoreTestInstall(from string, to string) bool {
	return strings.HasPrefix(from, restoreHiddenPrefix+restoreStageInfix) && !strings.HasPrefix(to, restoreHiddenPrefix)
}

// The run writes path's whole content through a hooked Write, so the next scan attributes the change to it: edit.
func (self *restoreTestEnv) hookedWrite(toolUseId string, path string, after string) {
	self.t.Helper()
	input := map[string]any{"file_path": filepath.Join(self.dir, filepath.FromSlash(path)), "content": after}
	self.preToolUse("Write", toolUseId, input)
	self.write(path, after)
	self.postToolUse("Write", toolUseId, input)
}

// Every hidden name an apply left anywhere in the worktree.
func (self *restoreTestEnv) hiddenNames() []string {
	self.t.Helper()
	found := []string{}
	filepath.WalkDir(self.dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if strings.HasPrefix(entry.Name(), restoreHiddenPrefix) {
			found = append(found, path)
		}
		return nil
	})
	return found
}

// Whether path exists in the worktree.
func (self *restoreTestEnv) exists(path string) bool {
	_, err := os.Lstat(filepath.Join(self.dir, filepath.FromSlash(path)))
	return err == nil
}

// The copy name §16.7 gives path's copy of infix for the env's run.
func (self *restoreTestEnv) copyName(path string, infix string) string {
	return path + infix + hex.EncodeToString(self.runId.Bytes())[:restoreCopyRunHexCount]
}

// The plan's entry for path, nil for none.
func restoreTestEntry(plan *RestorePlan, path string) *RestorePreviewEntry {
	for _, entry := range plan.Entries {
		if entry.Path == path {
			return entry
		}
	}
	return nil
}

// The result's outcome for path.
func restoreTestOutcome(t *testing.T, result *RestoreApplyResult, path string) *RestorePathResult {
	t.Helper()
	for _, outcome := range result.Paths {
		if outcome.Path == path {
			return outcome
		}
	}
	t.Fatalf("no outcome for %s in %+v", path, result.Paths)
	return nil
}

// A hooked edit of a committed file, a new file and a nested file restore byte-exact, the new file removed, no hidden
// name left behind; the apply again answers its recorded result and moves nothing.
func TestApplyRestoresEditedFiles(t *testing.T) {
	env := newRestoreTestEnv(t)
	point := env.open()
	ctx := context.Background()
	env.hookedWrite("toolu_1", "committed.txt", "edited\n")
	env.hookedWrite("toolu_2", "new.txt", "created\n")
	env.hookedWrite("toolu_3", "dir/nested.txt", "nested edited\n")
	plan, err := point.Plan(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Paths(); !slices.Equal(got, []string{"committed.txt", "dir/nested.txt", "new.txt"}) {
		t.Fatalf("restorable %v, refused %+v", got, plan.Refusals)
	}
	if entry := restoreTestEntry(plan, "new.txt"); entry.Target.Kind != RestoreKindAbsent || entry.Current.Kind != RestoreKindFile {
		t.Errorf("a created file's entry %+v %+v", entry.Current, entry.Target)
	}
	result, err := point.Apply(ctx, plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	if result.RestoredCount() != 3 || result.ConflictCount() != 0 || result.Replayed {
		t.Fatalf("result %+v", result.Paths)
	}
	if got := string(env.read("committed.txt")); got != "one\ntwo\nthree\n" {
		t.Errorf("committed.txt %q", got)
	}
	if got := string(env.read("dir/nested.txt")); got != "nested\n" {
		t.Errorf("dir/nested.txt %q", got)
	}
	if env.exists("new.txt") {
		t.Error("the created file is still there")
	}
	if hidden := env.hiddenNames(); len(hidden) != 0 {
		t.Errorf("hidden names left %v", hidden)
	}
	// a retry finds the journal ended: its result again, nothing moved
	env.write("committed.txt", "written after the restore\n")
	again, err := point.Apply(ctx, plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Replayed || again.RestoredCount() != 3 {
		t.Errorf("the retry %+v", again)
	}
	if got := string(env.read("committed.txt")); got != "written after the restore\n" {
		t.Errorf("the retry moved a finished path: %q", got)
	}
}

// preview_id binds each path's current kind and hash and its target's kind, mode and hash, and whether it is a shell
// path; a dry run over the same state gives the same id.
func TestPreviewBindsKindAndHash(t *testing.T) {
	runId := sidecar.NewId()
	base := func() []*RestorePreviewEntry {
		return []*RestorePreviewEntry{{
			Path:    "a.txt",
			Current: restoreTestState("now"),
			Target:  restoreTestState("then"),
		}}
	}
	id := restorePreviewId(runId, base())
	changes := []func(entries []*RestorePreviewEntry){
		func(entries []*RestorePreviewEntry) { entries[0].Path = "b.txt" },
		func(entries []*RestorePreviewEntry) { entries[0].Current = restoreTestState("other") },
		func(entries []*RestorePreviewEntry) { entries[0].Current.Kind = RestoreKindSymlink },
		func(entries []*RestorePreviewEntry) { entries[0].Target = restoreTestState("other") },
		func(entries []*RestorePreviewEntry) { entries[0].Target.Kind = RestoreKindAbsent },
		func(entries []*RestorePreviewEntry) { entries[0].Target.Mode = restoreModeExecutable },
		func(entries []*RestorePreviewEntry) { entries[0].Shell = true },
	}
	for index, change := range changes {
		entries := base()
		change(entries)
		if bytes.Equal(restorePreviewId(runId, entries), id) {
			t.Errorf("change %d leaves the id", index)
		}
	}
	if bytes.Equal(restorePreviewId(sidecar.NewId(), base()), id) {
		t.Error("another run's preview has the same id")
	}
	if !bytes.Equal(restorePreviewId(runId, base()), id) {
		t.Error("the same entries give another id")
	}

	env := newRestoreTestEnv(t)
	point := env.open()
	env.hookedWrite("toolu_1", "committed.txt", "edited\n")
	first, err := point.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := point.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.PreviewId, second.PreviewId) || len(first.Entries) != 1 {
		t.Errorf("two dry runs over one state: %x %x", first.PreviewId, second.PreviewId)
	}
	kept, err := point.Preview(first.PreviewId)
	if err != nil || len(kept.Entries) != 1 {
		t.Errorf("the kept preview: %v", err)
	}
}

// An apply needs a preview this point keeps: an unknown id or one of the wrong length moves nothing.
func TestApplyNeedsPreview(t *testing.T) {
	env := newRestoreTestEnv(t)
	point := env.open()
	env.hookedWrite("toolu_1", "committed.txt", "edited\n")
	for _, previewId := range [][]byte{bytes.Repeat([]byte{7}, 16), bytes.Repeat([]byte{7}, 32), {1, 2, 3}, nil} {
		if _, err := point.Apply(context.Background(), previewId); !errors.Is(err, ErrRestorePreviewUnknown) {
			t.Errorf("preview %x: %v", previewId, err)
		}
	}
	if got := string(env.read("committed.txt")); got != "edited\n" {
		t.Errorf("committed.txt %q", got)
	}
}

// A write after the preview is what the aside moves, so the check finds it and it goes back: changed, the hand bytes
// at p, the target kept beside it.
func TestChangeAfterPreviewConflicts(t *testing.T) {
	env := newRestoreTestEnv(t)
	point := env.open()
	env.hookedWrite("toolu_1", "committed.txt", "edited\n")
	plan, err := point.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	env.write("committed.txt", "by hand after the preview\n")
	result, err := point.Apply(context.Background(), plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	outcome := restoreTestOutcome(t, result, "committed.txt")
	copyName := env.copyName("committed.txt", restoreRestoredInfix)
	if outcome.Result != RestoreConflictChanged || !slices.Equal(outcome.Copies, []string{copyName}) {
		t.Fatalf("outcome %+v", outcome)
	}
	if got := string(env.read("committed.txt")); got != "by hand after the preview\n" {
		t.Errorf("p %q", got)
	}
	if got := string(env.read(copyName)); got != "one\ntwo\nthree\n" {
		t.Errorf("the restored copy %q", got)
	}
	if hidden := env.hiddenNames(); len(hidden) != 0 {
		t.Errorf("hidden names left %v", hidden)
	}
}

// Each of §16.7's conflict names, with not-exact and dropped beside them, is a result of its own on a real worktree:
// what p holds after, and the copies kept.
func TestEachConflictNameIsDistinct(t *testing.T) {
	type conflictCase struct {
		name string
		// what happens after the dry run, before the apply
		setup func(env *restoreTestEnv, testFs *restoreTestFs)
		// the result, and p's bytes after ("" for absent)
		want     string
		wantP    string
		wantCopy string
	}
	cases := []conflictCase{
		{
			name:  "changed",
			setup: func(env *restoreTestEnv, testFs *restoreTestFs) { env.write("committed.txt", "hand\n") },
			want:  RestoreConflictChanged, wantP: "hand\n", wantCopy: restoreRestoredInfix,
		},
		{
			name:  "deleted",
			setup: func(env *restoreTestEnv, testFs *restoreTestFs) { env.remove("committed.txt") },
			want:  RestoreConflictDeleted, wantP: "", wantCopy: restoreRestoredInfix,
		},
		{
			name: "recreated",
			setup: func(env *restoreTestEnv, testFs *restoreTestFs) {
				testFs.beforeRename = func(from string, to string) error {
					if restoreTestInstall(from, to) {
						env.write("committed.txt", "recreated meanwhile\n")
					}
					return nil
				}
			},
			want: RestoreConflictRecreated, wantP: "recreated meanwhile\n", wantCopy: restoreRestoredInfix,
		},
		{
			name: "kind",
			setup: func(env *restoreTestEnv, testFs *restoreTestFs) {
				env.remove("committed.txt")
				if err := os.Mkdir(filepath.Join(env.dir, "committed.txt"), 0o755); err != nil {
					env.t.Fatal(err)
				}
			},
			want: RestoreConflictKind, wantCopy: restoreRestoredInfix,
		},
		{
			name: "in-use",
			setup: func(env *restoreTestEnv, testFs *restoreTestFs) {
				testFs.beforeRename = func(from string, to string) error {
					if from == "committed.txt" {
						return &os.LinkError{Op: "rename", Old: from, New: to, Err: errRestoreInUse}
					}
					return nil
				}
			},
			want: RestoreConflictInUse, wantP: "edited\n", wantCopy: restoreRestoredInfix,
		},
		{
			name: "unsupported",
			setup: func(env *restoreTestEnv, testFs *restoreTestFs) {
				testFs.renameUnsupported = true
				testFs.linkUnsupported = true
			},
			want: RestoreConflictUnsupported, wantP: "edited\n",
		},
		{
			name: "written",
			setup: func(env *restoreTestEnv, testFs *restoreTestFs) {
				// a writer holding p open before the apply writes through its handle after the install
				handle, err := os.OpenFile(filepath.Join(env.dir, "committed.txt"), os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					env.t.Fatal(err)
				}
				env.t.Cleanup(func() { handle.Close() })
				testFs.afterRename = func(from string, to string) {
					if restoreTestInstall(from, to) {
						handle.Write([]byte("late\n"))
					}
				}
			},
			want: RestoreConflictWritten, wantP: "one\ntwo\nthree\n", wantCopy: restoreConflictInfix,
		},
		{
			name: "error",
			setup: func(env *restoreTestEnv, testFs *restoreTestFs) {
				testFs.beforeRename = func(from string, to string) error {
					if from == "committed.txt" {
						return &os.LinkError{Op: "rename", Old: from, New: to, Err: fs.ErrPermission}
					}
					return nil
				}
			},
			want: RestoreConflictError, wantP: "edited\n",
		},
	}
	for _, c := range cases {
		env := newRestoreTestEnv(t)
		point := env.open()
		env.hookedWrite("toolu_1", "committed.txt", "edited\n")
		plan, err := point.Plan(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		testFs := &restoreTestFs{}
		env.points.fs = testFs.fs()
		c.setup(env, testFs)
		result, err := point.Apply(context.Background(), plan.PreviewId)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		outcome := restoreTestOutcome(t, result, "committed.txt")
		if outcome.Result != c.want {
			t.Errorf("%s: result %q", c.name, outcome.Result)
		}
		if c.want != RestoreConflictKind {
			if c.wantP == "" {
				if env.exists("committed.txt") {
					t.Errorf("%s: p is there", c.name)
				}
			} else if got := string(env.read("committed.txt")); got != c.wantP {
				t.Errorf("%s: p %q", c.name, got)
			}
		} else if info, err := os.Lstat(filepath.Join(env.dir, "committed.txt")); err != nil || !info.IsDir() {
			t.Errorf("%s: the directory at p was moved", c.name)
		}
		if c.wantCopy == "" {
			if len(outcome.Copies) != 0 {
				t.Errorf("%s: copies %v", c.name, outcome.Copies)
			}
		} else {
			copyName := env.copyName("committed.txt", c.wantCopy)
			if !slices.Contains(outcome.Copies, copyName) || !env.exists(copyName) {
				t.Errorf("%s: copies %v, want %s", c.name, outcome.Copies, copyName)
			}
		}
		if hidden := env.hiddenNames(); len(hidden) != 0 {
			t.Errorf("%s: hidden names left %v", c.name, hidden)
		}
	}
	// written keeps the late bytes beside p, and recreated removes the preview's current bytes it moved
	env := newRestoreTestEnv(t)
	point := env.open()
	env.hookedWrite("toolu_1", "committed.txt", "edited\n")
	plan, _ := point.Plan(context.Background(), nil)
	testFs := &restoreTestFs{}
	env.points.fs = testFs.fs()
	handle, err := os.OpenFile(filepath.Join(env.dir, "committed.txt"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	testFs.afterRename = func(from string, to string) {
		if restoreTestInstall(from, to) {
			handle.Write([]byte("late\n"))
		}
	}
	if _, err := point.Apply(context.Background(), plan.PreviewId); err != nil {
		t.Fatal(err)
	}
	if got := string(env.read(env.copyName("committed.txt", restoreConflictInfix))); got != "edited\nlate\n" {
		t.Errorf("the written bytes kept %q", got)
	}
}

// A target that cannot be had exactly moves nothing: not-exact for a sealed copy whose bytes differ from the target,
// dropped for one an executed drop removed.
func TestTargetNotExactOrDropped(t *testing.T) {
	for _, want := range []string{RestoreConflictNotExact, RestoreConflictDropped} {
		env := newRestoreTestEnv(t)
		// dirty at the run's start, so its base is a sealed copy in the point
		env.write("untracked.txt", "before the run\n")
		point := env.open()
		env.hookedWrite("toolu_1", "untracked.txt", "edited\n")
		plan, err := point.Plan(context.Background(), nil)
		if err != nil || len(plan.Entries) != 1 {
			t.Fatalf("plan %v %+v", err, plan)
		}
		base, err := point.BaseOf(context.Background(), "untracked.txt")
		if err != nil || base.Copy == "" {
			t.Fatalf("base %+v %v", base, err)
		}
		if want == RestoreConflictDropped {
			if err := point.store.Remove(base.Copy); err != nil {
				t.Fatal(err)
			}
		} else if err := writeRestoreBytes(point.store, base.Copy, []byte("not the target\n")); err != nil {
			t.Fatal(err)
		}
		result, err := point.Apply(context.Background(), plan.PreviewId)
		if err != nil {
			t.Fatal(err)
		}
		if outcome := restoreTestOutcome(t, result, "untracked.txt"); outcome.Result != want || len(outcome.Copies) != 0 {
			t.Errorf("%s: outcome %+v", want, outcome)
		}
		if got := string(env.read("untracked.txt")); got != "edited\n" {
			t.Errorf("%s: p %q", want, got)
		}
		if hidden := env.hiddenNames(); len(hidden) != 0 {
			t.Errorf("%s: hidden names left %v", want, hidden)
		}
		// a later dry run names the dropped path dropped
		if want == RestoreConflictDropped {
			again, err := point.Plan(context.Background(), nil)
			if err != nil || len(again.Entries) != 0 || len(again.Refusals) != 1 || again.Refusals[0].Reason != RestoreReasonDropped {
				t.Errorf("the dry run after the drop: %v %+v", err, again)
			}
		}
	}
}

// A target that p's preview found absent, where a file stands at the apply: exists, p kept, the target beside it.
func TestExistsWhereThePreviewFoundNone(t *testing.T) {
	env := newRestoreTestEnv(t)
	point := env.open()
	base, err := point.BaseOf(context.Background(), "committed.txt")
	if err != nil {
		t.Fatal(err)
	}
	// a shell path whose preview found p deleted
	entries := []*RestorePreviewEntry{{Path: "committed.txt", Current: &RestoreFileState{Kind: RestoreKindAbsent}, Target: base.State.clone(), Shell: true}}
	plan := &RestorePlan{Version: restorePreviewVersion, RunId: env.runId, PreviewId: restorePreviewId(env.runId, entries), Entries: entries, Refusals: []*RestoreRefusal{}}
	if err := point.savePreview(plan); err != nil {
		t.Fatal(err)
	}
	env.write("committed.txt", "made by someone else\n")
	result, err := point.Apply(context.Background(), plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	outcome := restoreTestOutcome(t, result, "committed.txt")
	copyName := env.copyName("committed.txt", restoreRestoredInfix)
	if outcome.Result != RestoreConflictExists || !slices.Equal(outcome.Copies, []string{copyName}) {
		t.Fatalf("outcome %+v", outcome)
	}
	if got := string(env.read("committed.txt")); got != "made by someone else\n" {
		t.Errorf("p %q", got)
	}
	if got := string(env.read(copyName)); got != "one\ntwo\nthree\n" {
		t.Errorf("the target beside p %q", got)
	}
	// with p still absent at the apply, such a preview installs the target
	fresh := newRestoreTestEnv(t)
	freshPoint := fresh.open()
	fresh.remove("committed.txt")
	freshBase, _ := freshPoint.BaseOf(context.Background(), "committed.txt")
	freshEntries := []*RestorePreviewEntry{{Path: "committed.txt", Current: &RestoreFileState{Kind: RestoreKindAbsent}, Target: freshBase.State.clone(), Shell: true}}
	freshPlan := &RestorePlan{Version: restorePreviewVersion, RunId: fresh.runId, PreviewId: restorePreviewId(fresh.runId, freshEntries), Entries: freshEntries, Refusals: []*RestoreRefusal{}}
	if err := freshPoint.savePreview(freshPlan); err != nil {
		t.Fatal(err)
	}
	freshResult, err := freshPoint.Apply(context.Background(), freshPlan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	if restoreTestOutcome(t, freshResult, "committed.txt").Result != RestoreResultRestored || string(fresh.read("committed.txt")) != "one\ntwo\nthree\n" {
		t.Errorf("a deleted file not restored: %+v", freshResult.Paths)
	}
}

// A parent replaced by a symlink to a directory outside the worktree after the dry run is kind: nothing is written
// through it, outside or in.
func TestParentSymlinkEscapeRefused(t *testing.T) {
	env := newRestoreTestEnv(t)
	point := env.open()
	env.hookedWrite("toolu_1", "dir/nested.txt", "edited\n")
	plan, err := point.Plan(context.Background(), nil)
	if err != nil || len(plan.Entries) != 1 {
		t.Fatalf("plan %v %+v", err, plan)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "nested.txt"), []byte("outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(env.dir, "dir"), filepath.Join(env.dir, "dir-moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(env.dir, "dir")); err != nil {
		t.Fatal(err)
	}
	result, err := point.Apply(context.Background(), plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := restoreTestOutcome(t, result, "dir/nested.txt"); outcome.Result != RestoreConflictKind || len(outcome.Copies) != 0 {
		t.Errorf("outcome %+v", outcome)
	}
	entries, _ := os.ReadDir(outside)
	if content, _ := os.ReadFile(filepath.Join(outside, "nested.txt")); len(entries) != 1 || string(content) != "outside\n" {
		t.Errorf("outside the worktree: %d entries, %q", len(entries), content)
	}
	if got := string(env.read("dir-moved/nested.txt")); got != "edited\n" {
		t.Errorf("the moved directory's file %q", got)
	}
}

// A kill after the aside, before the install: the next process's load puts the moved bytes back, removes the staged
// name, and the apply's next call restores the path.
func TestRestartPutsBytesBack(t *testing.T) {
	env := newRestoreTestEnv(t)
	point := env.open()
	env.hookedWrite("toolu_1", "committed.txt", "edited\n")
	plan, err := point.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	testFs := &restoreTestFs{beforeRename: func(from string, to string) error {
		if restoreTestInstall(from, to) {
			panic("killed before the install")
		}
		return nil
	}}
	env.points.fs = testFs.fs()
	func() {
		defer func() { recover() }()
		point.Apply(context.Background(), plan.PreviewId)
	}()
	if env.exists("committed.txt") || len(env.hiddenNames()) != 2 {
		t.Fatalf("after the kill: p there %t, hidden %v", env.exists("committed.txt"), env.hiddenNames())
	}
	// the restart: a fresh registry over the same store
	env.points = env.newPoints()
	restarted, err := env.points.OpenExisting(context.Background(), env.network, env.networkId, env.runId)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(env.read("committed.txt")); got != "edited\n" {
		t.Errorf("p after the restart %q", got)
	}
	if hidden := env.hiddenNames(); len(hidden) != 0 {
		t.Errorf("hidden names left %v", hidden)
	}
	result, err := restarted.Apply(context.Background(), plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := restoreTestOutcome(t, result, "committed.txt"); outcome.Result != RestoreResultRestored || result.Replayed {
		t.Errorf("the retry %+v", outcome)
	}
	if got := string(env.read("committed.txt")); got != "one\ntwo\nthree\n" {
		t.Errorf("p after the retry %q", got)
	}
}

// A kill after the install, before end: the next process's load finishes the path as restored and runs end's rule,
// removing the preview's current bytes it moved; the apply's next call ends it without moving the path again.
func TestRestartAfterInstallAppliesEnd(t *testing.T) {
	env := newRestoreTestEnv(t)
	point := env.open()
	env.hookedWrite("toolu_1", "committed.txt", "edited\n")
	env.hookedWrite("toolu_2", "dir/nested.txt", "nested edited\n")
	plan, err := point.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	testFs := &restoreTestFs{afterRename: func(from string, to string) {
		if restoreTestInstall(from, to) && to == "committed.txt" {
			panic("killed after the install")
		}
	}}
	env.points.fs = testFs.fs()
	func() {
		defer func() { recover() }()
		point.Apply(context.Background(), plan.PreviewId)
	}()
	if got := string(env.read("committed.txt")); got != "one\ntwo\nthree\n" || len(env.hiddenNames()) != 1 {
		t.Fatalf("after the kill: p %q, hidden %v", got, env.hiddenNames())
	}
	env.points = env.newPoints()
	restarted, err := env.points.OpenExisting(context.Background(), env.network, env.networkId, env.runId)
	if err != nil {
		t.Fatal(err)
	}
	if hidden := env.hiddenNames(); len(hidden) != 0 {
		t.Errorf("end's rule left %v", hidden)
	}
	if got := string(env.read("dir/nested.txt")); got != "nested edited\n" {
		t.Errorf("the path the kill never reached %q", got)
	}
	begun, ended, _, err := restarted.ApplyState(plan.PreviewId)
	if err != nil || !begun || ended {
		t.Errorf("the journal after recovery: begun %t ended %t %v", begun, ended, err)
	}
	result, err := restarted.Apply(context.Background(), plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	if result.RestoredCount() != 2 || result.Replayed {
		t.Errorf("the retry %+v", result.Paths)
	}
	if got := string(env.read("dir/nested.txt")); got != "nested\n" {
		t.Errorf("the second path after the retry %q", got)
	}
}

// A copy never takes a name that exists: with <name>.ur-restored-<h> taken, the target goes to -2, and the file
// already there is untouched.
func TestNoRenameOverExistingName(t *testing.T) {
	env := newRestoreTestEnv(t)
	point := env.open()
	env.hookedWrite("toolu_1", "committed.txt", "edited\n")
	plan, err := point.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	taken := env.copyName("committed.txt", restoreRestoredInfix)
	env.write(taken, "someone's own file\n")
	env.write("committed.txt", "hand\n")
	result, err := point.Apply(context.Background(), plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	outcome := restoreTestOutcome(t, result, "committed.txt")
	if outcome.Result != RestoreConflictChanged || !slices.Equal(outcome.Copies, []string{taken + "-2"}) {
		t.Fatalf("outcome %+v", outcome)
	}
	if got := string(env.read(taken)); got != "someone's own file\n" {
		t.Errorf("the taken name's file %q", got)
	}
	if got := string(env.read(taken + "-2")); got != "one\ntwo\nthree\n" {
		t.Errorf("the copy %q", got)
	}
}

// A volume taking neither a no-replace rename nor a hard link is unsupported before anything moves, every path as it
// was; one taking a hard link alone restores through it.
func TestUnsupportedVolumeMovesNothing(t *testing.T) {
	env := newRestoreTestEnv(t)
	point := env.open()
	env.hookedWrite("toolu_1", "committed.txt", "edited\n")
	env.hookedWrite("toolu_2", "new.txt", "created\n")
	plan, err := point.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	testFs := &restoreTestFs{renameUnsupported: true, linkUnsupported: true}
	env.points.fs = testFs.fs()
	result, err := point.Apply(context.Background(), plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range result.Paths {
		if outcome.Result != RestoreConflictUnsupported || len(outcome.Copies) != 0 {
			t.Errorf("outcome %+v", outcome)
		}
	}
	if string(env.read("committed.txt")) != "edited\n" || string(env.read("new.txt")) != "created\n" || len(env.hiddenNames()) != 0 {
		t.Error("an unsupported volume moved something")
	}

	linkOnly := newRestoreTestEnv(t)
	linkPoint := linkOnly.open()
	linkOnly.hookedWrite("toolu_1", "committed.txt", "edited\n")
	linkOnly.hookedWrite("toolu_2", "new.txt", "created\n")
	linkPlan, err := linkPoint.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	linkOnly.points.fs = (&restoreTestFs{renameUnsupported: true}).fs()
	linkResult, err := linkPoint.Apply(context.Background(), linkPlan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	if linkResult.RestoredCount() != 2 || string(linkOnly.read("committed.txt")) != "one\ntwo\nthree\n" || linkOnly.exists("new.txt") {
		t.Errorf("a link-only volume: %+v", linkResult.Paths)
	}
	if hidden := linkOnly.hiddenNames(); len(hidden) != 0 {
		t.Errorf("hidden names left %v", hidden)
	}
}

// A shell-attributed change is listed shell and left out, until the call names it, when it joins the preview as a
// shell path; a named path with nothing to restore answers unchanged, and one outside the worktree is refused.
func TestDryRunShellPathOnlyWhenNamed(t *testing.T) {
	env := newRestoreTestEnv(t)
	point := env.open()
	ctx := context.Background()
	// a Bash call changing the file: a shell tool in the interval
	env.write("committed.txt", "by the shell\n")
	shell := env.claudePayload("PostToolUse", "Bash", "toolu_1", map[string]any{"command": "echo"})
	if _, err := env.points.NoteEvent(ctx, env.network, env.networkId, env.runId, env.parse("claude-code", shell), shell); err != nil {
		t.Fatal(err)
	}
	plan, err := point.Plan(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 0 || len(plan.Refusals) != 1 || plan.Refusals[0].Reason != RestoreReasonShell {
		t.Fatalf("unnamed: %+v %+v", plan.Entries, plan.Refusals)
	}
	named, err := point.Plan(ctx, []string{"committed.txt", "dir/nested.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(named.Entries) != 1 || !named.Entries[0].Shell || !slices.Equal(named.ShellPaths(), []string{"committed.txt"}) {
		t.Fatalf("named: %+v", named.Entries)
	}
	if len(named.Refusals) != 1 || named.Refusals[0].Path != "dir/nested.txt" || named.Refusals[0].Reason != RestoreReasonUnchanged {
		t.Errorf("the unchanged named path: %+v", named.Refusals)
	}
	if bytes.Equal(named.PreviewId, plan.PreviewId) {
		t.Error("the named preview has the unnamed one's id")
	}
	for _, outside := range []string{"../escape.txt", "/etc/hosts", "", ".ur-restore-stage-00"} {
		if _, err := point.Plan(ctx, []string{outside}); !errors.Is(err, ErrRestorePathInvalid) {
			t.Errorf("%q: %v", outside, err)
		}
	}
}
