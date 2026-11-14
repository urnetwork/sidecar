//go:build !js && !ios && !android && !sdk_mobile_bind

// §22.9's Restore row (MCP-M3-27; FS-115, D-MCP-8, RV1-RV4): FS-115's apply on one volume, through that volume's own
// no-replace rename, through its hard-link fallback, and unsupported where it has neither, with Windows's in-use
// refusal, so the matrix (darwin on APFS; linux on ext4, xfs and an NFS mount; windows on NTFS; a FAT volume on each;
// symlinks on each, Windows with and without the symlink privilege) runs this one test on each volume it holds.
//
// UR_RESTORE_VOLUME names a directory on the volume under test; unset, the test runs in its temporary directory,
// which is APFS on this build's darwin hosts. What the volume takes, rename, link and symlink, is probed first and
// logged, and each case expects what §16.7 gives that volume: a volume that takes the platform's no-replace rename
// restores by it, one that takes only hard links restores by them, one that takes neither is unsupported before
// anything moves. The in-use case is a real handle opened without FILE_SHARE_DELETE on Windows; elsewhere no open
// handle refuses a rename, so the apply's own in-use answer is checked through its OS seam.

package mcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// The environment variable naming the volume under test (§22.9's Restore row).
const restoreConformanceVolumeEnv = "UR_RESTORE_VOLUME"

// What the volume under test takes.
type restoreVolume struct {
	directory string
	rename    bool
	link      bool
	symlink   bool
}

// The volume under test, probed: a directory on it the test removes.
func probeRestoreVolume(t *testing.T) *restoreVolume {
	t.Helper()
	parent := os.Getenv(restoreConformanceVolumeEnv)
	if parent == "" {
		parent = t.TempDir()
	}
	directory, err := os.MkdirTemp(parent, "ur-restore-conformance-")
	if err != nil {
		t.Fatalf("%s: %s", restoreConformanceVolumeEnv, err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	probe := filepath.Join(directory, "probe")
	if err := os.Mkdir(probe, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(probe)
	if err := os.WriteFile(filepath.Join(probe, "from"), []byte("probe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	volume := &restoreVolume{directory: directory}
	dir, err := os.Open(probe)
	if err != nil {
		t.Fatal(err)
	}
	renameErr := restoreRenameNoReplace(dir, probe, "from", "to")
	dir.Close()
	switch {
	case renameErr == nil:
		volume.rename = true
		if err := os.Rename(filepath.Join(probe, "to"), filepath.Join(probe, "from")); err != nil {
			t.Fatal(err)
		}
	case !restoreRenameUnsupported(renameErr):
		t.Fatalf("the rename probe: %s", renameErr)
	}
	root, err := os.OpenRoot(probe)
	if err != nil {
		t.Fatal(err)
	}
	linkErr := root.Link("from", "linked")
	root.Close()
	switch {
	case linkErr == nil:
		volume.link = true
	case !restoreLinkUnsupported(linkErr):
		t.Fatalf("the link probe: %s", linkErr)
	}
	volume.symlink = os.Symlink("from", filepath.Join(probe, "symlinked")) == nil
	t.Logf("volume %s: no-replace rename %t, hard link %t, symlink %t", parent, volume.rename, volume.link, volume.symlink)
	return volume
}

// A worktree on the volume, its committed.txt edited by a hooked Write and a new.txt created, dry-run.
func (self *restoreVolume) editedWorktree(t *testing.T, name string) (*restoreTestEnv, *RestorePoint, *RestorePlan) {
	t.Helper()
	worktree := filepath.Join(self.directory, name)
	if err := os.Mkdir(worktree, 0o755); err != nil {
		t.Fatal(err)
	}
	env := newRestoreTestEnvIn(t, worktree)
	point := env.open()
	env.hookedWrite("toolu_1", "committed.txt", "edited\n")
	env.hookedWrite("toolu_2", "new.txt", "created\n")
	plan, err := point.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Paths(), []string{"committed.txt", "new.txt"}) {
		t.Fatalf("the preview %v, refused %+v", plan.Paths(), plan.Refusals)
	}
	return env, point, plan
}

// What an apply on a volume taking rename (or else link) answers: restored, or unsupported before anything moved.
func (self *restoreVolume) wantApplied(t *testing.T, label string, env *restoreTestEnv, result *RestoreApplyResult, rename bool, link bool) {
	t.Helper()
	if !rename && !link {
		for _, outcome := range result.Paths {
			if outcome.Result != RestoreConflictUnsupported || len(outcome.Copies) != 0 {
				t.Errorf("%s: %+v", label, outcome)
			}
		}
		if string(env.read("committed.txt")) != "edited\n" || string(env.read("new.txt")) != "created\n" {
			t.Errorf("%s: an unsupported volume moved something", label)
		}
	} else {
		if result.RestoredCount() != 2 {
			t.Errorf("%s: %+v", label, result.Paths)
		}
		if string(env.read("committed.txt")) != "one\ntwo\nthree\n" || env.exists("new.txt") {
			t.Errorf("%s: not restored", label)
		}
	}
	if hidden := env.hiddenNames(); len(hidden) != 0 {
		t.Errorf("%s: hidden names left %v", label, hidden)
	}
}

// FS-115's apply on the volume under test: through its own calls, through the hard-link fallback, with neither, with
// a writer's bytes landing before the install, with a file in use, and with a file replaced by a symlink.
func TestRestoreConformanceVolume(t *testing.T) {
	volume := probeRestoreVolume(t)
	ctx := context.Background()

	// the volume's own calls
	env, point, plan := volume.editedWorktree(t, "own")
	result, err := point.Apply(ctx, plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	volume.wantApplied(t, "the volume's own calls", env, result, volume.rename, volume.link)

	// the hard-link fallback: the rename refused as a volume without it refuses it
	env, point, plan = volume.editedWorktree(t, "link")
	env.points.fs = (&restoreTestFs{renameUnsupported: true}).fs()
	result, err = point.Apply(ctx, plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	volume.wantApplied(t, "the hard-link fallback", env, result, false, volume.link)

	// neither: unsupported before any aside
	env, point, plan = volume.editedWorktree(t, "neither")
	env.points.fs = (&restoreTestFs{renameUnsupported: true, linkUnsupported: true}).fs()
	result, err = point.Apply(ctx, plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	volume.wantApplied(t, "neither", env, result, false, false)

	// a writer taking no lock writes committed.txt just before its install: never overwritten
	if volume.rename || volume.link {
		env, point, plan = volume.editedWorktree(t, "writer")
		testFs := &restoreTestFs{renameUnsupported: !volume.rename, linkUnsupported: !volume.link}
		testFs.beforeRename = func(from string, to string) error {
			if restoreTestInstall(from, to) && to == "committed.txt" {
				testFs.beforeRename = nil
				env.write("committed.txt", "the writer's\n")
			}
			return nil
		}
		env.points.fs = testFs.fs()
		if !volume.rename {
			// with links alone, the install's no-replace step is the link, which the hook above never sees
			env.points.fs = &restoreFs{
				renameNoReplace: testFs.fs().renameNoReplace,
				link: func(parent *os.Root, from string, to string) error {
					if to == "committed.txt" {
						env.write("committed.txt", "the writer's\n")
					}
					return parent.Link(from, to)
				},
			}
		}
		result, err = point.Apply(ctx, plan.PreviewId)
		if err != nil {
			t.Fatal(err)
		}
		outcome := restoreTestOutcome(t, result, "committed.txt")
		if outcome.Result != RestoreConflictRecreated || string(env.read("committed.txt")) != "the writer's\n" {
			t.Errorf("a write before the install: %+v %q", outcome, env.read("committed.txt"))
		}
	}

	// in use: on Windows a handle opened without FILE_SHARE_DELETE, which Go's os.Open is; elsewhere through the seam
	if volume.rename || volume.link {
		env, point, plan = volume.editedWorktree(t, "in-use")
		if runtime.GOOS == "windows" {
			handle, err := os.Open(filepath.Join(env.dir, "committed.txt"))
			if err != nil {
				t.Fatal(err)
			}
			defer handle.Close()
		} else {
			env.points.fs = (&restoreTestFs{
				renameUnsupported: !volume.rename,
				linkUnsupported:   !volume.link,
				beforeRename: func(from string, to string) error {
					if from == "committed.txt" {
						return &os.LinkError{Op: "rename", Old: from, New: to, Err: errRestoreInUse}
					}
					return nil
				},
			}).fs()
		}
		result, err = point.Apply(ctx, plan.PreviewId)
		if err != nil {
			t.Fatal(err)
		}
		outcome := restoreTestOutcome(t, result, "committed.txt")
		if outcome.Result != RestoreConflictInUse || string(env.read("committed.txt")) != "edited\n" {
			t.Errorf("a file in use: %+v %q", outcome, env.read("committed.txt"))
		}
	}

	// a file replaced by a symlink after the dry run: kind, nothing removed
	if volume.symlink && (volume.rename || volume.link) {
		env, point, plan = volume.editedWorktree(t, "symlink")
		env.remove("committed.txt")
		if err := os.Symlink("new.txt", filepath.Join(env.dir, "committed.txt")); err != nil {
			t.Fatal(err)
		}
		result, err = point.Apply(ctx, plan.PreviewId)
		if err != nil {
			t.Fatal(err)
		}
		outcome := restoreTestOutcome(t, result, "committed.txt")
		info, statErr := os.Lstat(filepath.Join(env.dir, "committed.txt"))
		if outcome.Result != RestoreConflictKind || statErr != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Errorf("a file replaced by a symlink: %+v %v", outcome, errors.Join(statErr))
		}
	}
}
