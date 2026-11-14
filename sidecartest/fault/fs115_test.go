//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-115 (§22.8; §16.7's apply, D-MCP-8, RV1-RV4, FI-8; MCP-M3-27) on T2, on fs26_test.go's restore world: a run's
// apply held at its barriers (restore.stage, restore.check, restore.install, restore.end, keyed by the run's id)
// while a process taking no daemon lock writes the path, each case beside a twin with no writer that restores.
//
// Every world starts as FS-115's: run A (Claude Code unless a case says otherwise) edits a.txt from a0 to a1, and a
// hand edits h.txt that A then edits in the same scan interval, FS-26's before-edit case, which every dry run here
// must refuse and every apply leave as A left it. The registered case:
//
//   - Fs115WriteAfterCheck: the apply held after its aside's hash check, the writer writes a.txt in place: the
//     install finds the path made again and leaves it, recreated, the writer's bytes at the path and the target
//     beside it; the twin, with no writer, restores a.txt.
//
// The row's other clauses run by TestFs115Clauses under the same rules:
//
//   - after the stage, after the check and after the install, the writer writing in place, saving by a temporary
//     file and a rename, deleting, or deleting and recreating: changed or deleted before the aside, the bytes at the
//     path; recreated after the check, the bytes at the path, a delete finding no file and the restore going on; and
//     after the install the write landing over the restored bytes, which the point keeps (Fs115AtBarrier);
//   - two selected paths, only the second written to before its install: the first restored, the second recreated
//     with its restored copy beside it (Fs115TwoPaths);
//   - a target of absent, recreated before end: recreated (Fs115TargetAbsentRecreated); a current of absent, a
//     file created before the install: exists (Fs115CurrentAbsentExists, A under Codex, whose apply_patch deletes);
//   - a parent replaced by a symlink to outside the worktree, and a file replaced by a directory or a symlink: kind,
//     nothing written outside and nothing removed (Fs115ParentSymlink, Fs115FileReplaced);
//   - a writer holding the file open and writing before end: written, its bytes in the conflict copy, which its
//     handle keeps writing (Fs115HeldOpen);
//   - the daemon killed after the aside: the restart puts the bytes back, or, the path made again meanwhile, keeps
//     both and finishes it recreated; killed after the install: the restart applies end's rule (Fs115Kill*).
//
// Windows's in-use refusal and a volume with neither a no-replace rename nor a hard link need the apply's OS calls
// replaced, which only mcp's own tests can: mcp/restore_conformance_test.go runs both. FI-8 after every step.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/mcp"
	"github.com/urnetwork/sidecar/sidecartest"
)

// FS-115's worktree.
func fs115Files() map[string]string {
	return map[string]string{
		"a.txt":     "a0\n",
		"d.txt":     "d0\n",
		"h.txt":     "h0\n",
		"dir/n.txt": "n0\n",
	}
}

// The writer's ways of writing a path, each taking no daemon lock.
const (
	fs115Write    = "write"
	fs115Save     = "save"
	fs115Delete   = "delete"
	fs115Recreate = "recreate"
)

// The writer's bytes.
const fs115WriterLine = "by the writer"

// The writer does how to path: writes in place, saves by a temporary file and a rename, deletes, or deletes and
// recreates. A delete that finds no file changes nothing.
func (self *fsRestoreWorld) writerAct(how string, relative string) error {
	absolute := self.absolute(relative)
	remove := func() error {
		err := os.Remove(absolute)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		self.ledger.Removed(fsRestoreWriter, relative, false)
		return nil
	}
	switch how {
	case fs115Write:
		return self.writeLine(fsRestoreWriter, relative, fs115WriterLine, false)
	case fs115Save:
		self.noteNewPath(relative)
		content := []byte(fs115WriterLine + "\n")
		temporary := absolute + ".writer-save"
		if err := os.WriteFile(temporary, content, 0o644); err != nil {
			return err
		}
		if err := os.Rename(temporary, absolute); err != nil {
			return err
		}
		self.ledger.Wrote(fsRestoreWriter, relative, content, false)
		return nil
	case fs115Delete:
		return remove()
	case fs115Recreate:
		if err := remove(); err != nil {
			return err
		}
		return self.writeLine(fsRestoreWriter, relative, fs115WriterLine, false)
	}
	return fmt.Errorf("no way %q", how)
}

// A's apply_patch deleting path, under Codex.
func (self *fsRestoreWorld) deleteByPatch(relative string) error {
	harness, err := self.harness(fsRestoreRunA)
	if err != nil {
		return err
	}
	if harness.kind != sidecartest.FakeHarnessCodex {
		return errors.New("a hooked delete is Codex's apply_patch")
	}
	patch := "*** Begin Patch\n*** Delete File: " + relative + "\n*** End Patch\n"
	return self.toolCall(harness, "apply_patch", map[string]any{"command": patch}, func() error {
		if err := os.Remove(self.absolute(relative)); err != nil {
			return err
		}
		self.ledger.Removed(fsRestoreRunA, relative, true)
		return nil
	})
}

// FS-115's start, A under kind: a.txt edited, FS-26's before-edit case on h.txt, then prepare's own edits and the dry
// run, which must offer every path in offered and refuse h.txt.
func fs115Start(world **fsRestoreWorld, kind string, prepare func(ctx context.Context, world *fsRestoreWorld) error, offered []string) []*Step {
	return []*Step{
		{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
			made, err := newFsRestoreWorld(ctx, net, fs115Files())
			if err != nil {
				return err
			}
			*world = made
			if err := made.startHarness(ctx, fsRestoreRunA, kind, "sA"); err != nil {
				return err
			}
			if err := made.edit(fsRestoreRunA, "a.txt", "a1"); err != nil {
				return err
			}
			if err := made.handWrite("h.txt", "h-hand"); err != nil {
				return err
			}
			if err := made.edit(fsRestoreRunA, "h.txt", "h-a"); err != nil {
				return err
			}
			if prepare != nil {
				return prepare(ctx, made)
			}
			return nil
		}},
		fsRestoreStep(fsRestoreDaemon, world, func(ctx context.Context, world *fsRestoreWorld) error {
			plan, err := world.dryRun(ctx, "r", fsRestoreRunA, nil)
			if err != nil {
				return err
			}
			if !slices.Equal(plan.Paths(), offered) {
				return fmt.Errorf("offered %v, want %v; refused %v", plan.Paths(), offered, fsRestoreRefusals(plan))
			}
			return fsRestoreRefused(plan, "h.txt")
		}),
	}
}

// The apply of the dry run, held at site's skip+1-th arrival.
func fs115HeldApply(world **fsRestoreWorld, site string, skip int) *Step {
	step := fsRestoreStep(fsRestoreDaemon, world, func(ctx context.Context, world *fsRestoreWorld) error {
		_, err := world.apply(ctx, "r", fsRestoreRunA)
		return err
	})
	step.Await = site
	step.AwaitSkip = skip
	return step
}

// What a path's outcome and bytes must be: result, and line at the path, "" for absent; a conflict keeps the target
// beside the path unless noCopy, as a restart's recovery removes the staged names it finds.
type fs115Want struct {
	result string
	line   string
	noCopy bool
}

// Whether the apply answered want for path, and the path holds its line.
func (self *fsRestoreWorld) wantOutcome(relative string, want fs115Want) error {
	result, err := self.result("r")
	if err != nil {
		return err
	}
	outcome, err := fsRestoreOutcome(result, relative)
	if err != nil {
		return err
	}
	errs := []error{}
	if outcome.Result != want.result {
		errs = append(errs, fmt.Errorf("%s: %s, want %s", relative, outcome.Result, want.result))
	}
	if want.line == "" {
		if _, exists := self.line(relative); exists {
			errs = append(errs, fmt.Errorf("%s is there, want absent", relative))
		}
	} else {
		errs = append(errs, self.wantLine(relative, want.line))
	}
	if want.result != mcp.RestoreResultRestored && want.result != mcp.RestoreConflictWritten && want.result != mcp.RestoreConflictKind && !want.noCopy {
		// a conflict keeps the target beside the path
		if !slices.ContainsFunc(outcome.Copies, func(copied string) bool { return filepath.Base(copied) != relative }) {
			errs = append(errs, fmt.Errorf("%s: %s with no copy beside it: %v", relative, outcome.Result, outcome.Copies))
		}
	}
	return errors.Join(errs...)
}

// A schedule of FS-115's start, then steps, then a judge; with a twin, steps' writer leaving everything alone and
// twinJudge judging.
func fs115Schedule(id string, refuses string, start []*Step, steps []*Step, judge *Step, twin Builder) *Schedule {
	schedule := &Schedule{
		Id:    id,
		Steps: append(append(slices.Clone(start), steps...), judge),
		Check: []Invariant{FI(8)},
		Tiers: []Tier{TierT2},
	}
	if refuses != "" {
		schedule.Refuses = refuses
		schedule.Twin = twin
	}
	return schedule
}

// The writer's how at site, or nothing at all for the twin: what FS-115's first sentences ask, on a.txt.
func Fs115AtBarrier(site string, how string) Builder {
	return func(net *Net) *Schedule {
		return fs115AtBarrier(site, how)
	}
}

func fs115AtBarrier(site string, how string) *Schedule {
	var world *fsRestoreWorld
	start := fs115Start(&world, sidecartest.FakeHarnessClaudeCode, nil, []string{"a.txt"})
	want := fs115Want{result: mcp.RestoreResultRestored, line: "a0"}
	if how != "" {
		want = map[string]map[string]fs115Want{
			"restore.stage.after": {
				fs115Write:    {result: mcp.RestoreConflictChanged, line: fs115WriterLine},
				fs115Save:     {result: mcp.RestoreConflictChanged, line: fs115WriterLine},
				fs115Delete:   {result: mcp.RestoreConflictDeleted},
				fs115Recreate: {result: mcp.RestoreConflictChanged, line: fs115WriterLine},
			},
			"restore.check.after": {
				fs115Write:    {result: mcp.RestoreConflictRecreated, line: fs115WriterLine},
				fs115Save:     {result: mcp.RestoreConflictRecreated, line: fs115WriterLine},
				fs115Delete:   {result: mcp.RestoreResultRestored, line: "a0"},
				fs115Recreate: {result: mcp.RestoreConflictRecreated, line: fs115WriterLine},
			},
			"restore.install.after": {
				fs115Write:    {result: mcp.RestoreResultRestored, line: fs115WriterLine},
				fs115Save:     {result: mcp.RestoreResultRestored, line: fs115WriterLine},
				fs115Delete:   {result: mcp.RestoreResultRestored},
				fs115Recreate: {result: mcp.RestoreResultRestored, line: fs115WriterLine},
			},
		}[site][how]
	}
	steps := []*Step{
		fs115HeldApply(&world, site, 0),
		fsRestoreStep(fsRestoreWriter, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if how == "" {
				return nil
			}
			return world.writerAct(how, "a.txt")
		}),
		{Release: []string{site}},
		{Actor: fsRestoreDaemon, Join: true},
	}
	judge := fsRestoreStep("judge", &world, func(ctx context.Context, world *fsRestoreWorld) error {
		return errors.Join(world.wantOutcome("a.txt", want), world.wantLine("h.txt", "h-a"))
	})
	id := "FS-115 " + how + " at " + site
	refuses := ""
	if how != "" {
		refuses = "the writer's " + how + " of a.txt at " + site + " lost or reported restored over"
	}
	if how == fs115Delete && site != "restore.stage.after" {
		// the writer's delete after the aside finds no file, or after the install removes what the restore wrote:
		// the restore itself goes through, so there is nothing refused, only bytes the check keeps
		refuses = ""
	}
	return fs115Schedule(id, refuses, start, steps, judge, func(net *Net) *Schedule { return fs115AtBarrier(site, "") })
}

var Fs115 = Register("FS-115", "", []Tier{TierT2}, Twin(Fs115WriteAfterCheck, Fs115NoWriter))

// See the file header.
func Fs115WriteAfterCheck(net *Net) *Schedule {
	return fs115AtBarrier("restore.check.after", fs115Write)
}

// See the file header.
func Fs115NoWriter(net *Net) *Schedule {
	return fs115AtBarrier("restore.check.after", "")
}

// Two selected paths, a.txt and dir/n.txt, only the second written after its check, or not at all in the twin.
func Fs115TwoPaths(net *Net) *Schedule {
	return fs115TwoPaths(true)
}

func fs115TwoPaths(written bool) *Schedule {
	var world *fsRestoreWorld
	start := fs115Start(&world, sidecartest.FakeHarnessClaudeCode, func(ctx context.Context, world *fsRestoreWorld) error {
		return world.edit(fsRestoreRunA, "dir/n.txt", "n1")
	}, []string{"a.txt", "dir/n.txt"})
	steps := []*Step{
		fs115HeldApply(&world, "restore.check.after", 1),
		fsRestoreStep(fsRestoreWriter, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if !written {
				return nil
			}
			return world.writerAct(fs115Write, "dir/n.txt")
		}),
		{Release: []string{"restore.check.after"}},
		{Actor: fsRestoreDaemon, Join: true},
	}
	judge := fsRestoreStep("judge", &world, func(ctx context.Context, world *fsRestoreWorld) error {
		second := fs115Want{result: mcp.RestoreResultRestored, line: "n0"}
		if written {
			second = fs115Want{result: mcp.RestoreConflictRecreated, line: fs115WriterLine}
		}
		return errors.Join(world.wantOutcome("a.txt", fs115Want{result: mcp.RestoreResultRestored, line: "a0"}), world.wantOutcome("dir/n.txt", second))
	})
	refuses := ""
	if written {
		refuses = "the second of two paths, written before its install, restored over"
	}
	return fs115Schedule("FS-115 two paths", refuses, start, steps, judge, func(net *Net) *Schedule { return fs115TwoPaths(false) })
}

// A file A created, so its target is absent, made again by the writer before end.
func Fs115TargetAbsentRecreated(net *Net) *Schedule {
	return fs115TargetAbsent(true)
}

func fs115TargetAbsent(recreated bool) *Schedule {
	var world *fsRestoreWorld
	start := fs115Start(&world, sidecartest.FakeHarnessClaudeCode, func(ctx context.Context, world *fsRestoreWorld) error {
		return world.edit(fsRestoreRunA, "new.txt", "new1")
	}, []string{"a.txt", "new.txt"})
	steps := []*Step{
		fs115HeldApply(&world, "restore.end.before", 0),
		fsRestoreStep(fsRestoreWriter, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if !recreated {
				return nil
			}
			return world.writerAct(fs115Write, "new.txt")
		}),
		{Release: []string{"restore.end.before"}},
		{Actor: fsRestoreDaemon, Join: true},
	}
	judge := fsRestoreStep("judge", &world, func(ctx context.Context, world *fsRestoreWorld) error {
		want := fs115Want{result: mcp.RestoreResultRestored}
		if recreated {
			want = fs115Want{result: mcp.RestoreConflictRecreated, line: fs115WriterLine}
		}
		result, err := world.result("r")
		if err != nil {
			return err
		}
		outcome, err := fsRestoreOutcome(result, "new.txt")
		if err != nil {
			return err
		}
		errs := []error{world.wantOutcome("a.txt", fs115Want{result: mcp.RestoreResultRestored, line: "a0"})}
		if outcome.Result != want.result {
			errs = append(errs, fmt.Errorf("new.txt: %s, want %s", outcome.Result, want.result))
		}
		line, exists := world.line("new.txt")
		if recreated && (!exists || line != fs115WriterLine) {
			errs = append(errs, fmt.Errorf("new.txt holds %q (%t), want the writer's", line, exists))
		}
		if !recreated && exists {
			errs = append(errs, errors.New("new.txt is still there"))
		}
		return errors.Join(errs...)
	})
	refuses := ""
	if recreated {
		refuses = "a path made again before end, removed by a restore whose target is absent"
	}
	return fs115Schedule("FS-115 target of absent", refuses, start, steps, judge, func(net *Net) *Schedule { return fs115TargetAbsent(false) })
}

// A file A deleted, so its current is absent, made by the writer before the install.
func Fs115CurrentAbsentExists(net *Net) *Schedule {
	return fs115CurrentAbsent(true)
}

func fs115CurrentAbsent(created bool) *Schedule {
	var world *fsRestoreWorld
	start := fs115Start(&world, sidecartest.FakeHarnessCodex, func(ctx context.Context, world *fsRestoreWorld) error {
		return world.deleteByPatch("d.txt")
	}, []string{"a.txt", "d.txt"})
	steps := []*Step{
		fs115HeldApply(&world, "restore.stage.after", 1),
		fsRestoreStep(fsRestoreWriter, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if !created {
				return nil
			}
			return world.writerAct(fs115Write, "d.txt")
		}),
		{Release: []string{"restore.stage.after"}},
		{Actor: fsRestoreDaemon, Join: true},
	}
	judge := fsRestoreStep("judge", &world, func(ctx context.Context, world *fsRestoreWorld) error {
		want := fs115Want{result: mcp.RestoreResultRestored, line: "d0"}
		if created {
			want = fs115Want{result: mcp.RestoreConflictExists, line: fs115WriterLine}
		}
		return errors.Join(world.wantOutcome("a.txt", fs115Want{result: mcp.RestoreResultRestored, line: "a0"}), world.wantOutcome("d.txt", want))
	})
	refuses := ""
	if created {
		refuses = "a file made where the preview found none, installed over"
	}
	return fs115Schedule("FS-115 current of absent", refuses, start, steps, judge, func(net *Net) *Schedule { return fs115CurrentAbsent(false) })
}

// dir/n.txt's parent replaced, after the dry run, by a symlink to the directory outside the worktree.
func Fs115ParentSymlink(net *Net) *Schedule {
	return fs115Replaced("parent", true)
}

// a.txt replaced, after the dry run, by a directory or a symlink.
func Fs115FileReplaced(kind string) Builder {
	return func(net *Net) *Schedule {
		return fs115Replaced(kind, true)
	}
}

// replaced is parent, directory or symlink; with replace false, the twin, which replaces nothing.
func fs115Replaced(replaced string, replace bool) *Schedule {
	var world *fsRestoreWorld
	start := fs115Start(&world, sidecartest.FakeHarnessClaudeCode, func(ctx context.Context, world *fsRestoreWorld) error {
		return world.edit(fsRestoreRunA, "dir/n.txt", "n1")
	}, []string{"a.txt", "dir/n.txt"})
	steps := []*Step{
		fsRestoreStep(fsRestoreWriter, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if !replace {
				return nil
			}
			switch replaced {
			case "parent":
				if err := os.Rename(world.absolute("dir"), world.absolute("dir-moved")); err != nil {
					return err
				}
				world.ledger.Wrote(fsRestoreWriter, "dir-moved/n.txt", []byte("n1\n"), false)
				return os.Symlink(world.outside, world.absolute("dir"))
			case "directory":
				if err := os.Remove(world.absolute("a.txt")); err != nil {
					return err
				}
				world.ledger.Removed(fsRestoreWriter, "a.txt", false)
				return os.Mkdir(world.absolute("a.txt"), 0o755)
			default:
				if err := os.Remove(world.absolute("a.txt")); err != nil {
					return err
				}
				world.ledger.Removed(fsRestoreWriter, "a.txt", false)
				return os.Symlink("h.txt", world.absolute("a.txt"))
			}
		}),
		fsRestoreStep(fsRestoreDaemon, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			_, err := world.apply(ctx, "r", fsRestoreRunA)
			return err
		}),
	}
	judge := fsRestoreStep("judge", &world, func(ctx context.Context, world *fsRestoreWorld) error {
		if !replace {
			return errors.Join(world.wantOutcome("a.txt", fs115Want{result: mcp.RestoreResultRestored, line: "a0"}),
				world.wantOutcome("dir/n.txt", fs115Want{result: mcp.RestoreResultRestored, line: "n0"}))
		}
		result, err := world.result("r")
		if err != nil {
			return err
		}
		errs := []error{}
		switch replaced {
		case "parent":
			outcome, err := fsRestoreOutcome(result, "dir/n.txt")
			if err != nil {
				return err
			}
			if outcome.Result != mcp.RestoreConflictKind || len(outcome.Copies) != 0 {
				errs = append(errs, fmt.Errorf("dir/n.txt: %+v", outcome))
			}
			errs = append(errs, world.wantLine("dir-moved/n.txt", "n1"), world.wantOutcome("a.txt", fs115Want{result: mcp.RestoreResultRestored, line: "a0"}))
		default:
			outcome, err := fsRestoreOutcome(result, "a.txt")
			if err != nil {
				return err
			}
			if outcome.Result != mcp.RestoreConflictKind {
				errs = append(errs, fmt.Errorf("a.txt: %+v", outcome))
			}
			info, err := os.Lstat(world.absolute("a.txt"))
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("the %s at a.txt was removed: %w", replaced, err))
			case replaced == "directory" && !info.IsDir():
				errs = append(errs, errors.New("the directory at a.txt was replaced"))
			case replaced == "symlink" && info.Mode()&os.ModeSymlink == 0:
				errs = append(errs, errors.New("the symlink at a.txt was replaced"))
			}
		}
		return errors.Join(errs...)
	})
	refuses := ""
	if replace {
		refuses = "a path whose parent or itself became another kind, written through or removed"
	}
	return fs115Schedule("FS-115 "+replaced+" replaced", refuses, start, steps, judge, func(net *Net) *Schedule { return fs115Replaced(replaced, false) })
}

// A writer holding a.txt open from before the apply writes through its handle after the install, and again after end.
func Fs115HeldOpen(net *Net) *Schedule {
	return fs115HeldOpen(true)
}

func fs115HeldOpen(held bool) *Schedule {
	var world *fsRestoreWorld
	start := fs115Start(&world, sidecartest.FakeHarnessClaudeCode, nil, []string{"a.txt"})
	handleWrite := func(world *fsRestoreWorld, line string) error {
		world.stateLock.Lock()
		handle := world.handles["a.txt"]
		world.stateLock.Unlock()
		if _, err := handle.Write([]byte(line + "\n")); err != nil {
			return err
		}
		info, err := handle.Stat()
		if err != nil {
			return err
		}
		inode := make([]byte, info.Size())
		if _, err := handle.ReadAt(inode, 0); err != nil {
			return err
		}
		world.ledger.WroteThroughHandle("a.txt", inode)
		return nil
	}
	steps := []*Step{
		fsRestoreStep(fsRestoreWriter, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if !held {
				return nil
			}
			handle, err := os.OpenFile(world.absolute("a.txt"), os.O_RDWR|os.O_APPEND, 0)
			if err != nil {
				return err
			}
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			world.handles["a.txt"] = handle
			return nil
		}),
		fs115HeldApply(&world, "restore.install.after", 0),
		fsRestoreStep(fsRestoreWriter, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if !held {
				return nil
			}
			return handleWrite(world, "late")
		}),
		{Release: []string{"restore.install.after"}},
		{Actor: fsRestoreDaemon, Join: true},
		fsRestoreStep(fsRestoreWriter, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if !held {
				return nil
			}
			return handleWrite(world, "later")
		}),
	}
	judge := fsRestoreStep("judge", &world, func(ctx context.Context, world *fsRestoreWorld) error {
		if !held {
			return world.wantOutcome("a.txt", fs115Want{result: mcp.RestoreResultRestored, line: "a0"})
		}
		result, err := world.result("r")
		if err != nil {
			return err
		}
		outcome, err := fsRestoreOutcome(result, "a.txt")
		if err != nil {
			return err
		}
		errs := []error{world.wantLine("a.txt", "a0")}
		if outcome.Result != mcp.RestoreConflictWritten || len(outcome.Copies) != 1 {
			errs = append(errs, fmt.Errorf("a.txt: %+v", outcome))
		} else if content, err := os.ReadFile(world.absolute(outcome.Copies[0])); err != nil || string(content) != "a1\nlate\nlater\n" {
			errs = append(errs, fmt.Errorf("the conflict copy holds %q (%v), the handle's every write", content, err))
		}
		return errors.Join(errs...)
	})
	refuses := ""
	if held {
		refuses = "bytes written through a handle opened before the apply, discarded at end"
	}
	return fs115Schedule("FS-115 held open", refuses, start, steps, judge, func(net *Net) *Schedule { return fs115HeldOpen(false) })
}

// The daemon killed with the apply held at site, the writer making a.txt again while it is down when meanwhile is
// set, then the restart's recovery and the apply's retry.
func Fs115Kill(site string, meanwhile bool) Builder {
	return func(net *Net) *Schedule {
		return fs115Kill(site, meanwhile)
	}
}

func fs115Kill(site string, meanwhile bool) *Schedule {
	var world *fsRestoreWorld
	start := fs115Start(&world, sidecartest.FakeHarnessClaudeCode, nil, []string{"a.txt"})
	steps := []*Step{
		fs115HeldApply(&world, site, 0),
		{Actor: fsRestoreDaemon, Kill: true},
		fsRestoreStep(fsRestoreWriter, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if !meanwhile {
				return nil
			}
			return world.writerAct(fs115Write, "a.txt")
		}),
		{Actor: fsRestoreDaemon, Restart: fsRestoreDaemon},
		// the restart's recovery, at the network's first point it opens
		fsRestoreStep(fsRestoreDaemon, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if _, err := world.point(ctx, fsRestoreRunA); err != nil {
				return err
			}
			hidden, err := world.ledger.hiddenNames()
			if err != nil {
				return err
			}
			errs := []error{}
			if len(hidden) != 0 {
				errs = append(errs, fmt.Errorf("recovery left hidden names %v", hidden))
			}
			switch {
			case meanwhile:
				errs = append(errs, world.wantLine("a.txt", fs115WriterLine))
			case site == "restore.install.after":
				// the install took: end's rule removed the preview's current bytes, and the target stands
				errs = append(errs, world.wantLine("a.txt", "a0"))
			default:
				// the moved bytes went back
				errs = append(errs, world.wantLine("a.txt", "a1"))
			}
			return errors.Join(errs...)
		}),
		fsRestoreStep(fsRestoreDaemon, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			_, err := world.apply(ctx, "r", fsRestoreRunA)
			return err
		}),
	}
	judge := fsRestoreStep("judge", &world, func(ctx context.Context, world *fsRestoreWorld) error {
		if meanwhile {
			// the moved bytes were the preview's current ones, which end's rule lets go (RV4), and the restart removed
			// the staged target, whose bytes the point keeps
			return world.wantOutcome("a.txt", fs115Want{result: mcp.RestoreConflictRecreated, line: fs115WriterLine, noCopy: true})
		}
		return world.wantOutcome("a.txt", fs115Want{result: mcp.RestoreResultRestored, line: "a0"})
	})
	id := "FS-115 killed at " + site
	refuses := ""
	if meanwhile {
		id += ", a.txt made again"
		refuses = "a path made again while the daemon was down after its aside, restored over at the restart"
	}
	return fs115Schedule(id, refuses, start, steps, judge, func(net *Net) *Schedule { return fs115Kill(site, false) })
}

func TestFs115(t *testing.T) {
	fsRestoreNeeds(t)
	RunRow(t, "FS-115", "", nil)
}

// FS-115's other clauses, each under the rules: the schedule, its twin, and three of the explorer's seeds, since a
// clause's writer acts while the apply is held and no step runs beside another, so more seeds draw the same order.
func TestFs115Clauses(t *testing.T) {
	fsRestoreNeeds(t)
	builders := []Builder{}
	for _, site := range []string{"restore.stage.after", "restore.check.after", "restore.install.after"} {
		for _, how := range []string{fs115Write, fs115Save, fs115Delete, fs115Recreate} {
			if site == "restore.check.after" && how == fs115Write {
				// the registered case
				continue
			}
			builders = append(builders, Fs115AtBarrier(site, how))
		}
	}
	builders = append(builders,
		Fs115TwoPaths,
		Fs115TargetAbsentRecreated,
		Fs115CurrentAbsentExists,
		Fs115ParentSymlink,
		Fs115FileReplaced("directory"),
		Fs115FileReplaced("symlink"),
		Fs115HeldOpen,
		Fs115Kill("restore.aside.after", false),
		Fs115Kill("restore.aside.after", true),
		Fs115Kill("restore.install.after", false),
	)
	for _, builder := range builders {
		fsRestoreCheckClause(t, builder, 3)
	}
}
