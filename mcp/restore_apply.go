//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's apply (R-MCP-4, D-MCP-8, D-MCP-15, RV1-RV4, FI-8): Apply takes a dry run's preview_id and, holding the
// worktree's apply lock, restores each path of the preview in its order, journaling each step in the point before it
// takes it (restore_journal.go):
//
//	resolve  p through os.Root on the worktree: every parent a real directory on the worktree's device, created
//	         where missing, never a symlink or .., so nothing leads outside it; the parent then opened through the
//	         root, and the steps below act on that directory alone
//	stage    the target (its bytes and executable bit, a link as a link) under a fresh hidden name in p's directory,
//	         fsynced and hashed against the target, else not-exact; then probed, renamed to a second fresh name by the
//	         platform's no-replace rename, else hard-linked there, else unsupported, all before anything moves; a
//	         target of absent stages an empty probe alone, removed once the volume answers
//	aside    where the preview found p: p renamed to a fresh hidden name, which moves whatever p holds at that
//	         instant; check then hashes those bytes against the preview's current kind and hash
//	install  on a match, or where the preview found p absent: the staged name renamed to p only while no p exists,
//	         or linked there and the staged name removed; a target of absent installs nothing
//	back     on a mismatch: the moved bytes renamed back to p the same way, keeping their inode, so a writer holding
//	         p open still writes to p; a moved directory goes back by a plain rename where only a hard link serves,
//	         which replaces no file and no non-empty directory
//	end      after the last path: each path's moved-aside bytes hashed again, removed if still the preview's current
//	         ones, else kept beside p as a conflict copy and the path written
//
// Each conflict is a result of its own: changed, recreated, deleted, exists, in-use, kind, unsupported, written and
// error, beside not-exact and dropped for a target that cannot be had exactly. A conflict keeps the staged target
// beside p as <name>.ur-restored-<h> and moved bytes it keeps as <name>.ur-conflict-<h>, h being run_id's first 8 hex,
// -2 and on when taken, each renamed with its inode and never over a name that exists; unsupported, error, not-exact
// and dropped remove the staged name instead. No byte but the preview's current ones is ever removed (RV4), and none
// but the target's exact bytes is ever written (RV2): targets come from the point's local copies and git's blobs, never
// the vault's redacted copy, so no redaction marker is written, and git merge-file is never run.
//
// The apply lock orders restores alone: editors, shells and other harnesses take none, so apply checks the bytes it
// displaces, never an earlier read, and installs by a rename that replaces nothing, since a hash check then a rename
// over p would lose a write between them (D-MCP-8's trap). An apply the journal holds as ended answers its recorded
// result and moves nothing, so a retry never moves a finished path again (MCP-M3-22's effect). Barriers restore.stage,
// restore.aside, restore.check, restore.install, restore.back and restore.end, each with .before and .after and keyed
// by the run's id, sit at each step, which MCP-M3-27's schedules hold.

package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

// §16.7's results: restored, and each conflict name.
const (
	RestoreResultRestored      = "restored"
	RestoreConflictChanged     = "changed"
	RestoreConflictRecreated   = "recreated"
	RestoreConflictDeleted     = "deleted"
	RestoreConflictExists      = "exists"
	RestoreConflictInUse       = "in-use"
	RestoreConflictKind        = "kind"
	RestoreConflictUnsupported = "unsupported"
	RestoreConflictWritten     = "written"
	RestoreConflictError       = "error"
	// A target whose bytes do not hash to the preview's, which RV2 forbids writing.
	RestoreConflictNotExact = RestoreReasonNotExact
	// A target an executed drop removed since the dry run (FI-8).
	RestoreConflictDropped = RestoreReasonDropped
)

// The apply's names, format values: hidden names start with restoreHiddenPrefix, which scans and dry runs skip, and
// copies are <name><infix><h>.
const (
	restoreHiddenPrefix  = ".ur-restore-"
	restoreStageInfix    = "stage-"
	restoreAsideInfix    = "aside-"
	restoreRestoredInfix = ".ur-restored-"
	restoreConflictInfix = ".ur-conflict-"
	// §16.7's h: run_id's first 8 hex
	restoreCopyRunHexCount = 8
	// how a volume was proved to take a rename that replaces nothing
	restoreMethodRename = "rename"
	restoreMethodLink   = "link"
)

var (
	// The platform takes no rename that replaces nothing, here or on this volume.
	errRestoreRenameUnsupported = errors.New("no no-replace rename")
	// The volume takes no hard link.
	errRestoreLinkUnsupported = errors.New("no hard link")
	// The file is open where it cannot move (Windows' FILE_SHARE_DELETE rule).
	errRestoreInUse = errors.New("the file is in use")
)

// The OS calls an apply makes that a test replaces: the platform's no-replace rename in one directory, and a hard
// link in one directory through its root.
type restoreFs struct {
	renameNoReplace func(dir *os.File, dirPath string, from string, to string) error
	link            func(parent *os.Root, from string, to string) error
}

// The platform's calls.
func defaultRestoreFs() *restoreFs {
	return &restoreFs{
		renameNoReplace: restoreRenameNoReplace,
		link: func(parent *os.Root, from string, to string) error {
			return parent.Link(from, to)
		},
	}
}

// One path's outcome.
type RestorePathResult struct {
	// Relative to the worktree's root, with / between segments.
	Path string `json:"path"`
	// restored, or a conflict's name.
	Result string `json:"result"`
	// The copies kept beside the path, relative to the root: its restored target, the bytes it moved and kept, or a
	// hidden name where no free copy name was found.
	Copies []string `json:"copies,omitempty"`
}

// What one apply did.
type RestoreApplyResult struct {
	RunId     sidecar.Id
	PreviewId []byte
	// In preview order.
	Paths []*RestorePathResult
	// The journal held this apply as ended: its recorded result, nothing moved by this call.
	Replayed bool
	// The apply's restore entry was appended (RestorePoint.NoteRecorded).
	Recorded bool
}

// The paths restored.
func (self *RestoreApplyResult) RestoredCount() int {
	count := 0
	for _, result := range self.Paths {
		if result.Result == RestoreResultRestored {
			count += 1
		}
	}
	return count
}

// The paths with a conflict.
func (self *RestoreApplyResult) ConflictCount() int {
	return len(self.Paths) - self.RestoredCount()
}

// Whether a path, as a scan or the walk reads it, is one of an apply's hidden names, which are no change of the
// worktree.
func restoreHiddenPath(relative string) bool {
	return strings.HasPrefix(path.Base(filepath.ToSlash(relative)), restoreHiddenPrefix)
}

// Takes the worktree's apply lock, which orders restores and dry runs on one worktree alone (§16.7's apply row),
// answering its release. An empty root, a point with no repository, takes its own lock.
func (self *RestorePoints) lockApply(root string) func() {
	lock := func() *sync.Mutex {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		lock, ok := self.rootApplyLocks[root]
		if !ok {
			lock = &sync.Mutex{}
			self.rootApplyLocks[root] = lock
		}
		return lock
	}()
	lock.Lock()
	return lock.Unlock
}

// What a path is on disk.
func restoreKindOf(info os.FileInfo) RestoreKind {
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return RestoreKindSymlink
	case info.Mode().IsRegular():
		return RestoreKindFile
	}
	return RestoreKindOther
}

// Whether two states are the same bytes of the same kind, which is what check compares (§16.7's aside row).
func restoreSameContent(a *RestoreFileState, b *RestoreFileState) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Kind != b.Kind {
		return false
	}
	if a.Kind == RestoreKindAbsent {
		return true
	}
	return string(a.Sha256) == string(b.Sha256)
}

// name's state in parent: its kind, and for a file or a link the hash of its bytes or its text and git's mode. A file
// replaced between the Lstat and the open reads as another kind, never as the bytes of what replaced it.
func restoreStateIn(parent *os.Root, name string) (*RestoreFileState, error) {
	info, err := parent.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return &RestoreFileState{Kind: RestoreKindAbsent}, nil
	}
	if err != nil {
		return nil, err
	}
	switch restoreKindOf(info) {
	case RestoreKindSymlink:
		target, err := parent.Readlink(name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(target))
		return &RestoreFileState{Kind: RestoreKindSymlink, Sha256: sum[:], Mode: restoreModeSymlink, Size: int64(len(target))}, nil
	case RestoreKindOther:
		return &RestoreFileState{Kind: RestoreKindOther}, nil
	}
	file, err := parent.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(opened, info) {
		return &RestoreFileState{Kind: RestoreKindOther}, nil
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return nil, err
	}
	mode := uint32(restoreModeFile)
	if info.Mode()&0o111 != 0 {
		mode = restoreModeExecutable
	}
	return &RestoreFileState{Kind: RestoreKindFile, Sha256: hash.Sum(nil), Mode: mode, Size: size}, nil
}

// One apply in progress. Not safe for concurrent use: the worktree's apply lock is held across it.
type restoreApply struct {
	point    *RestorePoint
	plan     *RestorePlan
	journal  *restoreJournal
	fs       *restoreFs
	settings *sidecar.SidecarIngestSettings
	// the worktree's top level, opened as a root; nil for a plan with nothing to restore
	worktree     *os.Root
	worktreePath string
	device       uint64
	deviceKnown  bool
	// §16.7's h
	copyTag    string
	barrierKey string
}

// One path's run through the steps.
type restorePathRun struct {
	index int
	entry *RestorePreviewEntry
	// p's directory relative to the root, "." for the top, and p's last name, in the OS's form
	dirRel string
	name   string
	// p's directory, opened through the worktree's root, and its path for a platform that renames by path
	parent    *os.Root
	ownParent bool
	dir       *os.File
	dirPath   string
	// the staged target's hidden name and how the volume renames it; "" for none
	staged string
	method string
	// the moved-aside bytes' hidden name, "" for none
	aside string
	// the moved bytes await end's rule
	pending bool
	result  string
	copies  []string
}

// Closes what the run opened.
func (self *restorePathRun) close() {
	if self.dir != nil {
		self.dir.Close()
	}
	if self.ownParent && self.parent != nil {
		self.parent.Close()
	}
}

// A copy's path as a result names it, relative to the root with / between segments.
func (self *restorePathRun) relative(name string) string {
	return path.Join(path.Dir(self.entry.Path), name)
}

// §16.7's apply of the preview previewId names. See the file's header. ErrRestorePreviewUnknown for a preview this
// point does not keep; an error that is not a path's conflict leaves the journal open, and the next call, or the next
// process's recovery, finishes what this one began.
func (self *RestorePoint) Apply(ctx context.Context, previewId []byte) (*RestoreApplyResult, error) {
	root := self.Root()
	unlock := self.points.lockApply(root)
	defer unlock()
	journal, err := self.openJournal(previewId)
	if err != nil {
		return nil, err
	}
	if journal.ended() {
		result := journal.result(self.runId)
		result.Replayed = true
		return result, nil
	}
	plan := journal.plan
	if plan == nil {
		plan, err = self.Preview(previewId)
		if err != nil {
			return nil, err
		}
	}
	apply, err := self.newApply(plan, journal)
	if err != nil {
		return nil, err
	}
	defer apply.close()
	if journal.begun() {
		if err := apply.recover(); err != nil {
			return nil, err
		}
	} else if err := journal.append(&restoreJournalRecord{Op: restoreJournalBegin, Plan: plan}); err != nil {
		return nil, err
	}
	for index, entry := range plan.Entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if journal.path(index).done != nil {
			continue
		}
		if err := apply.applyPath(ctx, index, entry); err != nil {
			return nil, err
		}
	}
	if err := apply.end(); err != nil {
		return nil, err
	}
	if err := journal.append(&restoreJournalRecord{Op: restoreJournalEnd}); err != nil {
		return nil, err
	}
	return journal.result(self.runId), nil
}

// The apply of plan over the worktree, opened as a root. A plan with nothing to restore opens nothing.
func (self *RestorePoint) newApply(plan *RestorePlan, journal *restoreJournal) (*restoreApply, error) {
	apply := &restoreApply{
		point:      self,
		plan:       plan,
		journal:    journal,
		fs:         self.points.fs,
		settings:   self.points.settings,
		copyTag:    hex.EncodeToString(self.runId.Bytes())[:restoreCopyRunHexCount],
		barrierKey: self.runId.String(),
	}
	if len(plan.Entries) == 0 {
		return apply, nil
	}
	root := self.Root()
	if root == "" {
		return nil, ErrRestoreNoRepository
	}
	worktree, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("the worktree cannot be opened: %w", errRestoreIo)
	}
	info, err := worktree.Stat(".")
	if err != nil {
		worktree.Close()
		return nil, fmt.Errorf("the worktree cannot be read: %w", errRestoreIo)
	}
	apply.worktree = worktree
	apply.worktreePath = root
	apply.device, apply.deviceKnown = restoreDevice(info)
	return apply, nil
}

// Closes the worktree's root.
func (self *restoreApply) close() {
	if self.worktree != nil {
		self.worktree.Close()
	}
}

// A fresh hidden name in p's directory: the prefix, the step's infix and random hex.
func (self *restoreApply) hiddenName(infix string) (string, error) {
	random := make([]byte, max(self.settings.RestoreHiddenNameByteCount, 1))
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return restoreHiddenPrefix + infix + hex.EncodeToString(random), nil
}

// One path through §16.7's steps, its outcome journaled as done. An error is the journal's or the context's alone: a
// path's own failure is its conflict.
func (self *restoreApply) applyPath(ctx context.Context, index int, entry *RestorePreviewEntry) error {
	run := &restorePathRun{index: index, entry: entry}
	defer run.close()
	if conflict := self.resolve(run, entry.Target.Kind != RestoreKindAbsent); conflict != "" {
		return self.finish(run, conflict)
	}

	testHookBarrier("restore.stage.before", self.barrierKey)
	conflict, err := self.stage(ctx, run)
	testHookBarrier("restore.stage.after", self.barrierKey)
	if err != nil {
		return err
	}
	if conflict != "" {
		return self.finish(run, conflict)
	}

	if entry.Current.Kind != RestoreKindAbsent {
		testHookBarrier("restore.aside.before", self.barrierKey)
		conflict, err := self.moveAside(run)
		testHookBarrier("restore.aside.after", self.barrierKey)
		if err != nil {
			return err
		}
		if conflict != "" {
			return self.finish(run, conflict)
		}
		testHookBarrier("restore.check.before", self.barrierKey)
		moved, readErr := restoreStateIn(run.parent, run.aside)
		testHookBarrier("restore.check.after", self.barrierKey)
		if readErr != nil || !restoreSameContent(moved, entry.Current) {
			// a mismatch, or bytes that cannot be read to tell: they go back to p, never discarded (RV4)
			result := RestoreConflictChanged
			if readErr == nil && moved.Kind != entry.Current.Kind {
				result = RestoreConflictKind
			}
			result, err := self.back(run, result)
			if err != nil {
				return err
			}
			return self.finish(run, result)
		}
	}

	if entry.Target.Kind == RestoreKindAbsent {
		// a target of absent installs nothing; the moved bytes wait for end, which also finds a p made since
		run.pending = run.aside != ""
		return self.finish(run, RestoreResultRestored)
	}
	testHookBarrier("restore.install.before", self.barrierKey)
	result, err := self.install(run)
	testHookBarrier("restore.install.after", self.barrierKey)
	if err != nil {
		return err
	}
	return self.finish(run, result)
}

// §16.7's resolve: p's parents, each a real directory on the worktree's device, created where missing when create
// is set, then p's directory opened through the root. A conflict's name, or "".
func (self *restoreApply) resolve(run *restorePathRun, create bool) string {
	clean := filepath.FromSlash(run.entry.Path)
	run.dirRel = filepath.Dir(clean)
	run.name = filepath.Base(clean)
	run.dirPath = filepath.Join(self.worktreePath, run.dirRel)
	last, err := self.worktree.Stat(".")
	if err != nil {
		return RestoreConflictError
	}
	if run.dirRel != "." {
		current := ""
		for _, part := range strings.Split(run.dirRel, string(filepath.Separator)) {
			current = filepath.Join(current, part)
			info, err := self.worktree.Lstat(current)
			if errors.Is(err, fs.ErrNotExist) {
				if !create {
					// nothing can stand at p, and nothing need be written
					return RestoreConflictDeleted
				}
				if err := self.worktree.Mkdir(current, 0o777); err != nil && !errors.Is(err, fs.ErrExist) {
					return RestoreConflictError
				}
				info, err = self.worktree.Lstat(current)
			}
			if err != nil {
				return RestoreConflictError
			}
			if restoreKindOf(info) != RestoreKindOther || !info.IsDir() {
				// a symlink or a file where a directory stood
				return RestoreConflictKind
			}
			if device, known := restoreDevice(info); known && self.deviceKnown && device != self.device {
				// a mount point
				return RestoreConflictKind
			}
			last = info
		}
		parent, err := self.worktree.OpenRoot(run.dirRel)
		if err != nil {
			return RestoreConflictKind
		}
		run.parent = parent
		run.ownParent = true
	} else {
		run.parent = self.worktree
	}
	dir, err := run.parent.Open(".")
	if err != nil {
		return RestoreConflictError
	}
	run.dir = dir
	opened, err := dir.Stat()
	if err != nil {
		return RestoreConflictError
	}
	if !os.SameFile(opened, last) {
		// the directory was swapped between its check and its open
		return RestoreConflictKind
	}
	return ""
}

// The exact bytes of a file target, or a link's text: the point's sealed copy or HEAD's blob, hashed against the
// target. A conflict's name where they cannot be had: dropped for a copy an executed drop removed, not-exact for bytes
// that do not hash to the preview's target.
func (self *restoreApply) targetBytes(ctx context.Context, entry *RestorePreviewEntry) ([]byte, string) {
	base, err := self.point.BaseOf(ctx, entry.Path)
	if err != nil {
		return nil, RestoreConflictError
	}
	var content []byte
	switch {
	case base.Copy != "":
		content, err = self.point.readCopy(base.Copy)
		if errors.Is(err, sidecar.ErrSidecarStoreAbsent) {
			return nil, RestoreConflictDropped
		}
	case base.Blob != "":
		content, err = self.point.points.runGit(ctx, self.point.Root(), "cat-file", "blob", base.Blob)
	default:
		return nil, RestoreConflictNotExact
	}
	if err != nil {
		return nil, RestoreConflictError
	}
	sum := sha256.Sum256(content)
	if string(sum[:]) != string(entry.Target.Sha256) {
		return nil, RestoreConflictNotExact
	}
	return content, ""
}

// §16.7's stage: the target under a fresh hidden name, fsynced and hashed, then the volume probed by a rename to a
// second fresh name, else a hard link there. A target of absent stages an empty probe alone, removed once the volume
// answers, since back may need the same rename. A conflict's name, or "" with run.staged and run.method set.
func (self *restoreApply) stage(ctx context.Context, run *restorePathRun) (string, error) {
	target := run.entry.Target
	var content []byte
	switch target.Kind {
	case RestoreKindFile, RestoreKindSymlink:
		var conflict string
		content, conflict = self.targetBytes(ctx, run.entry)
		if conflict != "" {
			return conflict, nil
		}
	}
	first, err := self.hiddenName(restoreStageInfix)
	if err != nil {
		return "", err
	}
	second, err := self.hiddenName(restoreStageInfix)
	if err != nil {
		return "", err
	}
	if err := self.journal.append(&restoreJournalRecord{Op: restoreJournalStage, Index: run.index, Names: []string{first, second}}); err != nil {
		return "", err
	}
	if target.Kind == RestoreKindSymlink {
		if err := run.parent.Symlink(string(content), first); err != nil {
			return RestoreConflictError, nil
		}
	} else {
		perm := os.FileMode(0o666)
		if target.Mode == restoreModeExecutable {
			perm = 0o777
		}
		file, err := run.parent.OpenFile(first, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			return RestoreConflictError, nil
		}
		_, writeErr := file.Write(content)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			run.parent.Remove(first)
			return RestoreConflictError, nil
		}
	}
	if target.Kind != RestoreKindAbsent {
		staged, err := restoreStateIn(run.parent, first)
		if err != nil || !restoreSameContent(staged, target) || staged.Mode != target.Mode {
			run.parent.Remove(first)
			return RestoreConflictNotExact, nil
		}
	}
	// the probe: before anything moves, the volume answers how it renames into a name that must stay free
	err = self.fs.renameNoReplace(run.dir, run.dirPath, first, second)
	switch {
	case err == nil:
		run.method = restoreMethodRename
	case restoreRenameUnsupported(err):
		linkErr := self.fs.link(run.parent, first, second)
		switch {
		case linkErr == nil:
			run.method = restoreMethodLink
			if err := run.parent.Remove(first); err != nil {
				run.parent.Remove(second)
				return RestoreConflictError, nil
			}
		case restoreLinkUnsupported(linkErr):
			run.parent.Remove(first)
			return RestoreConflictUnsupported, nil
		default:
			run.parent.Remove(first)
			return RestoreConflictError, nil
		}
	default:
		run.parent.Remove(first)
		return RestoreConflictError, nil
	}
	run.dir.Sync()
	if err := self.journal.append(&restoreJournalRecord{Op: restoreJournalStaged, Index: run.index, Names: []string{second}, Method: run.method}); err != nil {
		run.parent.Remove(second)
		return "", err
	}
	if target.Kind == RestoreKindAbsent {
		run.parent.Remove(second)
		return "", nil
	}
	run.staged = second
	return "", nil
}

// §16.7's aside: p, still the preview's kind and on-disk name, renamed to a fresh hidden name, moving whatever p holds
// at that instant. A conflict's name, or "" with run.aside set.
func (self *restoreApply) moveAside(run *restorePathRun) (string, error) {
	info, err := run.parent.Lstat(run.name)
	if errors.Is(err, fs.ErrNotExist) {
		return RestoreConflictDeleted, nil
	}
	if err != nil {
		return RestoreConflictError, nil
	}
	if restoreKindOf(info) != run.entry.Current.Kind || !self.nameOnDisk(run) {
		return RestoreConflictKind, nil
	}
	if device, known := restoreDevice(info); known && self.deviceKnown && device != self.device {
		return RestoreConflictKind, nil
	}
	aside, err := self.hiddenName(restoreAsideInfix)
	if err != nil {
		return "", err
	}
	if err := self.journal.append(&restoreJournalRecord{Op: restoreJournalAside, Index: run.index, Names: []string{aside}}); err != nil {
		return "", err
	}
	err = self.fs.renameNoReplace(run.dir, run.dirPath, run.name, aside)
	if err != nil && restoreRenameUnsupported(err) {
		// a fresh random name is free, so a plain rename moves p and replaces nothing
		err = run.parent.Rename(run.name, aside)
	}
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return RestoreConflictDeleted, nil
	case restoreInUse(err):
		return RestoreConflictInUse, nil
	default:
		return RestoreConflictError, nil
	}
	run.aside = aside
	run.dir.Sync()
	return "", nil
}

// Whether p's name on disk is the one the preview names, case and all: a case-insensitive volume answers Lstat for a
// name that differs in case, which is §16.7's kind. A directory that cannot be listed answers true.
func (self *restoreApply) nameOnDisk(run *restorePathRun) bool {
	listing, err := run.parent.Open(".")
	if err != nil {
		return true
	}
	defer listing.Close()
	names, err := listing.Readdirnames(-1)
	if err != nil {
		return true
	}
	for _, name := range names {
		if name == run.name {
			return true
		}
	}
	return false
}

// from renamed to to in the run's directory only while no to exists: the platform's rename, else, on a volume the
// probe found taking a hard link alone, the link and from's removal, or a plain rename for a directory, which
// replaces no file and no non-empty directory.
func (self *restoreApply) place(run *restorePathRun, from string, to string) error {
	err := self.fs.renameNoReplace(run.dir, run.dirPath, from, to)
	if err == nil || !restoreRenameUnsupported(err) {
		return err
	}
	info, statErr := run.parent.Lstat(from)
	if statErr != nil {
		return statErr
	}
	if info.IsDir() {
		if _, err := run.parent.Lstat(to); err == nil {
			return fs.ErrExist
		}
		return run.parent.Rename(from, to)
	}
	if err := self.fs.link(run.parent, from, to); err != nil {
		return err
	}
	return run.parent.Remove(from)
}

// §16.7's install: the staged name renamed to p only while no p exists. A conflict's name, or restored.
func (self *restoreApply) install(run *restorePathRun) (string, error) {
	if err := self.journal.append(&restoreJournalRecord{Op: restoreJournalInstall, Index: run.index}); err != nil {
		if run.aside != "" {
			// the journal takes nothing more, so the moved bytes go back unjournaled, which recovery reads from the disk
			self.place(run, run.aside, run.name)
		}
		return "", err
	}
	err := self.place(run, run.staged, run.name)
	switch {
	case err == nil:
		run.staged = ""
		run.pending = run.aside != ""
		run.dir.Sync()
		return RestoreResultRestored, nil
	case errors.Is(err, fs.ErrExist):
		// p reappeared: p is kept, and the moved bytes, the preview's current ones, wait for end's rule
		run.pending = run.aside != ""
		if run.entry.Current.Kind == RestoreKindAbsent {
			return RestoreConflictExists, nil
		}
		return RestoreConflictRecreated, nil
	}
	if run.aside == "" {
		return RestoreConflictError, nil
	}
	return self.back(run, RestoreConflictError)
}

// §16.7's back: the moved bytes renamed back to p the same way, keeping their inode. Answers result once they are
// back; recreated where p reappeared, p then kept and the moved bytes kept beside it unless they are the preview's
// current ones, which wait for end's rule; error where they cannot go back, kept beside p.
func (self *restoreApply) back(run *restorePathRun, result string) (string, error) {
	if err := self.journal.append(&restoreJournalRecord{Op: restoreJournalBack, Index: run.index}); err != nil {
		self.place(run, run.aside, run.name)
		return "", err
	}
	testHookBarrier("restore.back.before", self.barrierKey)
	err := self.place(run, run.aside, run.name)
	testHookBarrier("restore.back.after", self.barrierKey)
	switch {
	case err == nil:
		run.aside = ""
		run.dir.Sync()
		return result, nil
	case errors.Is(err, fs.ErrExist):
		moved, readErr := restoreStateIn(run.parent, run.aside)
		if readErr == nil && restoreSameContent(moved, run.entry.Current) {
			run.pending = true
			return RestoreConflictRecreated, nil
		}
		if err := self.keepCopy(run, run.aside, restoreConflictInfix); err != nil {
			return "", err
		}
		run.aside = ""
		return RestoreConflictRecreated, nil
	}
	if err := self.keepCopy(run, run.aside, restoreConflictInfix); err != nil {
		return "", err
	}
	run.aside = ""
	return RestoreConflictError, nil
}

// Keeps hidden beside p as <name><infix><h>, then -2 and on, renamed with its inode and never over a name that
// exists; where no name is free the bytes stay under their hidden name, which the result names. The copy's path joins
// run.copies.
func (self *restoreApply) keepCopy(run *restorePathRun, hidden string, infix string) error {
	base := run.name + infix + self.copyTag
	for attempt := 1; attempt <= max(self.settings.RestoreCopyNameCount, 1); attempt += 1 {
		name := base
		if 1 < attempt {
			name = base + "-" + strconv.Itoa(attempt)
		}
		if err := self.journal.append(&restoreJournalRecord{Op: restoreJournalCopy, Index: run.index, From: hidden, To: name}); err != nil {
			return err
		}
		err := self.place(run, hidden, name)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			break
		}
		run.copies = append(run.copies, run.relative(name))
		run.dir.Sync()
		return nil
	}
	run.copies = append(run.copies, run.relative(hidden))
	return nil
}

// A path's outcome: a conflict keeps the staged target beside p, or removes it where it is no copy worth keeping;
// then the outcome is journaled as done, the moved bytes awaiting end's rule named in it.
func (self *restoreApply) finish(run *restorePathRun, result string) error {
	run.result = result
	if run.staged != "" {
		switch result {
		case RestoreResultRestored:
		case RestoreConflictUnsupported, RestoreConflictError, RestoreConflictNotExact, RestoreConflictDropped:
			run.parent.Remove(run.staged)
		default:
			if err := self.keepCopy(run, run.staged, restoreRestoredInfix); err != nil {
				return err
			}
		}
		run.staged = ""
	}
	record := &restoreJournalRecord{Op: restoreJournalDone, Index: run.index, Result: result, Copies: run.copies}
	if run.pending && run.aside != "" {
		record.Names = []string{run.aside}
	}
	return self.journal.append(record)
}

// §16.7's end, after the last path: each done path's moved-aside bytes hashed again, removed if still the preview's
// current ones, else kept beside p as a conflict copy and a restored path written; a target of absent whose p was made
// since is recreated. Each outcome is journaled as ended.
func (self *restoreApply) end() error {
	testHookBarrier("restore.end.before", self.barrierKey)
	defer testHookBarrier("restore.end.after", self.barrierKey)
	for index, entry := range self.plan.Entries {
		state := self.journal.path(index)
		if state.done == nil || state.ended != nil {
			continue
		}
		result := state.done.Result
		run := &restorePathRun{index: index, entry: entry, copies: append([]string{}, state.done.Copies...)}
		pending := ""
		if 0 < len(state.done.Names) {
			pending = state.done.Names[0]
		}
		if pending != "" || (entry.Target.Kind == RestoreKindAbsent && result == RestoreResultRestored) {
			if conflict := self.resolve(run, false); conflict != "" {
				// p's directory moved or changed: the moved bytes stay where they are, never removed
				result = RestoreConflictError
				pending = ""
			}
		}
		if pending != "" {
			moved, err := restoreStateIn(run.parent, pending)
			switch {
			case err == nil && moved.Kind == RestoreKindAbsent:
			case err == nil && restoreSameContent(moved, entry.Current):
				if err := self.journal.append(&restoreJournalRecord{Op: restoreJournalRemove, Index: index, Names: []string{pending}}); err != nil {
					run.close()
					return err
				}
				run.parent.Remove(pending)
			default:
				// written through a handle opened earlier: kept (RV4)
				if err := self.keepCopy(run, pending, restoreConflictInfix); err != nil {
					run.close()
					return err
				}
				if result == RestoreResultRestored {
					result = RestoreConflictWritten
				}
			}
		}
		if entry.Target.Kind == RestoreKindAbsent && result == RestoreResultRestored && run.parent != nil {
			if _, err := run.parent.Lstat(run.name); err == nil {
				result = RestoreConflictRecreated
			}
		}
		if run.dir != nil {
			run.dir.Sync()
		}
		run.close()
		if err := self.journal.append(&restoreJournalRecord{Op: restoreJournalEnded, Index: index, Result: result, Copies: run.copies}); err != nil {
			return err
		}
	}
	return nil
}
