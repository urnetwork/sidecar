//go:build !ios_extension && !sidecar_http

// The worktree (DESIGN-COMPUTE §13.4's workspace, modes and collisions rows, §13.7; GIT-M13-01): the files a tree
// checks out, the index that records them, and what the file system they live on does with names, modes and links.
//
//	habits      probed once per worktree when it is made, never assumed from the OS (§13.4's trap), and kept in
//	            .git/ur/habits: whether the file system keeps an executable bit, makes symbolic links, folds case
//	            and folds Unicode normalization. Phones, the browser and Windows keep no executable bit this git reads
//	            and phones and the browser make no links, by leg; a desktop's file system answers for itself
//	modes       100644, 100755 and 120000 as git stores them; the executable bit read from the file system where it
//	            keeps one, else kept from the index, so a checkout never flips a mode; a gitlink (160000) kept in the
//	            index and checked out as an empty directory, never as content
//	links       a symbolic link is checked out as a link only when its target, resolved through the links the same
//	            checkout writes, stays inside the worktree and passes through no .git, within
//	            GitSettings.SymlinkHopCount links; else, and on a file system that makes none, as a small text file
//	            holding the target, which status reads back as the link (git's core.symlinks=false)
//	collisions  where two paths fold to one name on this file system, the first in index order is written, the other
//	            left unwritten with its entry marked (GitIndexEntry.Unwritten) and both named in the result; status
//	            takes the unwritten side's missing file as unchanged, never as deleted
//	safety      every path is held to gitCheckPath before anything is written, the whole checkout refused if one fails;
//	            every leading directory is read with Lstat and a link or a file there refuses the write, so nothing is
//	            ever written through a link; a blob is streamed to .git/ur/tmp, held to its oid, and only then renamed
//	            into place, so a corrupt or lazily fetched blob never lands unchecked
//	limits      GitSettings.FileCount entries and FileByteCount bytes a file, checked before anything is written; the
//	            workspace's cap by the file system's budget (git_fs.go)
//
// Checkout makes the worktree and index match a tree, removing what the index held that the tree does not; it does
// not ask whether a file held changes first, which the porcelain's commands check before they call it (GIT-M13-05).
// Not safe for concurrent use: the index lock orders this git's commands and stock git's.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"runtime"
	"slices"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// The worktree's own files under .git.
const (
	gitUrDirectory     = ".git/ur"
	gitUrTempDirectory = ".git/ur/tmp"
	gitHabitsName      = ".git/ur/habits"
)

var (
	// The index lock another git holds.
	ErrGitIndexLocked = errors.New("git: .git/index.lock stands: another git is running in this worktree")
	// A write a link, a file or an unknown kind of file stands in the way of.
	ErrGitWorktreeBlocked = errors.New("git: something in the worktree stands where a checkout writes")
)

// What the worktree's file system does with names, modes and links: see the file header's habits row.
type GitWorktreeHabits struct {
	ExecBit           bool `json:"exec_bit"`
	Symlinks          bool `json:"symlinks"`
	CaseFold          bool `json:"case_fold"`
	NormalizationFold bool `json:"normalization_fold"`
}

// Whether this leg reads an executable bit and makes links at all: phones and the browser neither, Windows no
// executable bit (§13.4's modes row, §13.7).
func gitLegHabits() (bool, bool) {
	switch runtime.GOOS {
	case "android", "ios", "js":
		return false, false
	case "windows":
		return false, true
	}
	return true, true
}

// Probes the file system's habits in a scratch directory under .git/ur, removing what it made.
func gitProbeHabits(fileSystem GitFileSystem) (*GitWorktreeHabits, error) {
	probe := gitUrDirectory + "/probe-" + NewId().String()
	if err := fileSystem.MkdirAll(probe, 0o755); err != nil {
		return nil, err
	}
	defer func() {
		entries, _ := fileSystem.ReadDir(probe)
		for _, entry := range entries {
			fileSystem.Remove(probe + "/" + entry.Name())
		}
		fileSystem.Remove(probe)
	}()
	execBit, symlinks := gitLegHabits()
	habits := &GitWorktreeHabits{}
	if execBit {
		if err := gitWriteFile(fileSystem, probe+"/exec", nil, 0o644); err != nil {
			return nil, err
		}
		if fileSystem.Chmod(probe+"/exec", 0o755) == nil {
			if info, err := fileSystem.Lstat(probe + "/exec"); err == nil && info.Mode().Perm()&0o100 != 0 {
				habits.ExecBit = true
			}
		}
	}
	if symlinks && fileSystem.Symlink("target", probe+"/link") == nil {
		if info, err := fileSystem.Lstat(probe + "/link"); err == nil && info.Mode()&fs.ModeSymlink != 0 {
			habits.Symlinks = true
		}
	}
	if err := gitWriteFile(fileSystem, probe+"/case-Ab", nil, 0o644); err != nil {
		return nil, err
	}
	if _, err := fileSystem.Lstat(probe + "/case-aB"); err == nil {
		habits.CaseFold = true
	}
	if err := gitWriteFile(fileSystem, probe+"/norm-é", nil, 0o644); err != nil {
		return nil, err
	}
	if _, err := fileSystem.Lstat(probe + "/norm-é"); err == nil {
		habits.NormalizationFold = true
	}
	return habits, nil
}

// The worktree on a file system.
type GitWorktree struct {
	fileSystem GitFileSystem
	settings   *GitSettings
	objects    *GitObjectStore
	habits     *GitWorktreeHabits
}

// The worktree on fileSystem with its probed habits.
func newGitWorktree(fileSystem GitFileSystem, settings *GitSettings, objects *GitObjectStore, habits *GitWorktreeHabits) *GitWorktree {
	return &GitWorktree{fileSystem: fileSystem, settings: settings, objects: objects, habits: habits}
}

// The habits the worktree was probed with.
func (self *GitWorktree) Habits() GitWorktreeHabits {
	return *self.habits
}

// The name a path takes on this file system, for comparing two paths: Unicode-normalized where it folds
// normalization, case-folded where it folds case.
func (self *GitWorktree) Fold(name string) string {
	if self.habits.NormalizationFold {
		name = norm.NFC.String(name)
	}
	if self.habits.CaseFold {
		name = cases.Fold().String(name)
	}
	return name
}

// The index as .git/index holds it, empty where none stands.
func (self *GitWorktree) ReadIndex() (*GitIndex, error) {
	content, err := gitReadFile(self.fileSystem, gitIndexName, self.settings.IndexByteCount)
	if errors.Is(err, fs.ErrNotExist) {
		return &GitIndex{}, nil
	}
	if err != nil {
		return nil, err
	}
	return GitIndexDecode(content, self.settings)
}

// The index's lock, held from before a command reads what it changes to after it writes the index.
type GitIndexLock struct {
	worktree *GitWorktree
	file     GitFile
	done     bool
}

// Takes .git/index.lock, made exclusively as git makes it: ErrGitIndexLocked when another git holds it.
func (self *GitWorktree) LockIndex() (*GitIndexLock, error) {
	file, err := self.fileSystem.Create(gitIndexLockName, 0o644, true)
	if errors.Is(err, fs.ErrExist) {
		return nil, ErrGitIndexLocked
	}
	if err != nil {
		return nil, err
	}
	return &GitIndexLock{worktree: self, file: file}, nil
}

// Writes index through the lock and renames it into place, releasing the lock.
func (self *GitIndexLock) Commit(index *GitIndex) error {
	if self.done {
		return fmt.Errorf("%w: a lock already released", ErrGitIndexInvalid)
	}
	self.done = true
	fileSystem := self.worktree.fileSystem
	encoded, err := index.Encode()
	if err != nil {
		self.file.Close()
		fileSystem.Remove(gitIndexLockName)
		return err
	}
	if _, err := self.file.Write(encoded); err != nil {
		self.file.Close()
		fileSystem.Remove(gitIndexLockName)
		return err
	}
	if err := self.file.Close(); err != nil {
		fileSystem.Remove(gitIndexLockName)
		return err
	}
	if err := fileSystem.Rename(gitIndexLockName, gitIndexName); err != nil {
		fileSystem.Remove(gitIndexLockName)
		return err
	}
	return nil
}

// Releases the lock with the index as it was; nothing after Commit.
func (self *GitIndexLock) Abandon() {
	if self.done {
		return
	}
	self.done = true
	self.file.Close()
	self.worktree.fileSystem.Remove(gitIndexLockName)
}

// One collision a checkout met: the path it wrote and the path it left unwritten, which fold to one name here.
type GitCollision struct {
	Written   string
	Unwritten string
}

// What a checkout is asked to do.
type GitCheckoutArgs struct {
	// The tree to check out.
	Tree EvsGitOid
	// Writes only the paths under this prefix (`docs/`), the rest left unwritten and marked, as GIT-M13-02's sparse
	// checkout asks; "" for every path.
	SparsePrefix string
}

// What a checkout did.
type GitCheckoutResult struct {
	// The index it wrote.
	Index *GitIndex
	// The folding collisions it met, each pair named.
	Collisions []GitCollision
	// The links checked out as text files: their targets leave the worktree or pass through .git, or this file system
	// makes no links.
	LinksAsText []string
	// The paths outside the sparse prefix it left unwritten.
	SparseCount int
	// The files it wrote or rewrote.
	WrittenCount int
}

// One file a tree holds.
type gitTreeFile struct {
	path string
	mode uint32
	oid  EvsGitOid
}

// Every file of a tree, in git's index order, refused past FileCount.
func (self *GitWorktree) treeFiles(ctx context.Context, tree EvsGitOid) ([]gitTreeFile, error) {
	files := []gitTreeFile{}
	var walk func(prefix string, oid EvsGitOid) error
	walk = func(prefix string, oid EvsGitOid) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := self.objects.ReadTree(ctx, oid)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			name := prefix + string(entry.Name)
			if entry.CanonMode == EvsGitModeDirectory {
				if err := walk(name+"/", entry.Oid); err != nil {
					return err
				}
				continue
			}
			if self.settings.FileCount <= len(files) {
				return fmt.Errorf("%w: a tree of more than %d files", ErrGitFileTooLarge, self.settings.FileCount)
			}
			files = append(files, gitTreeFile{path: name, mode: gitIndexMode(entry.CanonMode), oid: entry.Oid})
		}
		return nil
	}
	if err := walk("", tree); err != nil {
		return nil, err
	}
	slices.SortFunc(files, func(a gitTreeFile, b gitTreeFile) int { return strings.Compare(a.path, b.path) })
	return files, nil
}

// Makes the worktree and index match args.Tree: see the file header. The caller holds the index lock and commits
// the result's index through it.
func (self *GitWorktree) Checkout(ctx context.Context, args *GitCheckoutArgs, held *GitIndex) (*GitCheckoutResult, error) {
	files, err := self.treeFiles(ctx, args.Tree)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if err := gitCheckPath(file.path, file.mode); err != nil {
			return nil, err
		}
	}
	result := &GitCheckoutResult{Index: &GitIndex{}}

	// which paths the worktree writes: the first of each folded name, every path under the sparse prefix
	foldedFiles := map[string]string{}
	foldedDirectories := map[string]string{}
	unwritten := map[string]bool{}
	for _, file := range files {
		if args.SparsePrefix != "" && !strings.HasPrefix(file.path, args.SparsePrefix) {
			unwritten[file.path] = true
			result.SparseCount += 1
			continue
		}
		key := self.Fold(file.path)
		collidesWith := foldedFiles[key]
		if collidesWith == "" {
			collidesWith = foldedDirectories[key]
		}
		// a directory this path needs that folds to a file written already
		for directory := path.Dir(file.path); collidesWith == "" && directory != "."; directory = path.Dir(directory) {
			collidesWith = foldedFiles[self.Fold(directory)]
		}
		if collidesWith != "" {
			unwritten[file.path] = true
			result.Collisions = append(result.Collisions, GitCollision{Written: collidesWith, Unwritten: file.path})
			continue
		}
		foldedFiles[key] = file.path
		for directory := path.Dir(file.path); directory != "."; directory = path.Dir(directory) {
			if _, ok := foldedDirectories[self.Fold(directory)]; !ok {
				foldedDirectories[self.Fold(directory)] = file.path
			}
		}
	}

	// which links are written as links: those resolving inside through the links written, to a fixed point
	links, err := self.linkTargets(ctx, files, unwritten)
	if err != nil {
		return nil, err
	}
	asLinks := map[string]string{}
	if self.habits.Symlinks {
		for linkPath, target := range links {
			asLinks[linkPath] = target
		}
		for {
			escaping := []string{}
			for linkPath, target := range asLinks {
				if !self.linkStaysInside(linkPath, target, asLinks) {
					escaping = append(escaping, linkPath)
				}
			}
			if len(escaping) == 0 {
				break
			}
			for _, linkPath := range escaping {
				delete(asLinks, linkPath)
			}
		}
	}
	for linkPath := range links {
		if _, ok := asLinks[linkPath]; !ok {
			result.LinksAsText = append(result.LinksAsText, linkPath)
		}
	}
	slices.Sort(result.LinksAsText)

	// what is held already, unchanged, need not be written again
	heldByPath := map[string]*GitIndexEntry{}
	if held != nil {
		for _, entry := range held.Entries {
			if entry.Stage == 0 {
				heldByPath[entry.Path] = entry
			}
		}
	}
	wanted := map[string]gitTreeFile{}
	for _, file := range files {
		wanted[file.path] = file
	}

	// the blobs the written files need, fetched at once where they are promised (GIT-M13-02)
	needed := []EvsGitOid{}
	for _, file := range files {
		if !unwritten[file.path] && file.mode != EvsGitModeGitlink {
			needed = append(needed, file.oid)
		}
	}
	if err := self.objects.FetchPromised(ctx, needed); err != nil {
		return nil, err
	}
	for _, file := range files {
		if unwritten[file.path] || file.mode == EvsGitModeGitlink || file.mode == EvsGitModeSymlink {
			continue
		}
		if err := self.checkBlobSize(ctx, file.oid); err != nil {
			return nil, err
		}
	}

	// the worktree's first byte: the run is tainted already where the fetch asked it (GIT-M13-02's barrier)
	testHookBarrier("git.worktree_write", "")

	// what the index held that the tree does not, holds as another kind or now leaves unwritten is removed first; a
	// link is always written again, since whether it is a link may change; an unwritten entry has no file of its own
	if held != nil {
		for _, entry := range held.Entries {
			if entry.Unwritten {
				continue
			}
			file, ok := wanted[entry.Path]
			if ok && !unwritten[entry.Path] && gitFileKind(file.mode) == gitFileKind(entry.Mode) && file.mode != EvsGitModeSymlink {
				continue
			}
			if err := self.removeHeld(entry); err != nil {
				return nil, err
			}
		}
	}

	written := map[string]*GitIndexEntry{}
	// files and gitlinks first, in index order; links last, once every directory they might name stands
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if unwritten[file.path] || file.mode == EvsGitModeSymlink {
			continue
		}
		if entry := heldByPath[file.path]; entry != nil && !entry.Unwritten && entry.Mode == file.mode && entry.Oid == file.oid {
			if state, err := self.EntryState(ctx, entry, nil); err == nil && state == GitEntryUnchanged {
				written[file.path] = entry
				continue
			}
		}
		entry, err := self.writeFile(ctx, file)
		if err != nil {
			return nil, err
		}
		written[file.path] = entry
		result.WrittenCount += 1
	}
	for _, file := range files {
		if unwritten[file.path] || file.mode != EvsGitModeSymlink {
			continue
		}
		target, asLink := asLinks[file.path]
		if !asLink {
			target = links[file.path]
		}
		entry, err := self.writeLink(file, target, asLink)
		if err != nil {
			return nil, err
		}
		written[file.path] = entry
		result.WrittenCount += 1
	}
	for _, file := range files {
		entry := written[file.path]
		if entry == nil {
			entry = &GitIndexEntry{Path: file.path, Mode: file.mode, Oid: file.oid, Unwritten: true}
		}
		result.Index.Entries = append(result.Index.Entries, entry)
	}
	return result, nil
}

// A mode's kind as the worktree holds it: a file, a link or a gitlink's directory.
func gitFileKind(mode uint32) uint32 {
	switch mode {
	case EvsGitModeSymlink, EvsGitModeGitlink:
		return mode
	}
	return EvsGitModeFile
}

// Refuses a blob past FileByteCount before anything is written.
func (self *GitWorktree) checkBlobSize(ctx context.Context, oid EvsGitOid) error {
	kind, size, reader, err := self.objects.OpenGitObject(ctx, oid)
	if err != nil {
		return err
	}
	reader.Close()
	if kind != evsGitBlobKind {
		return fmt.Errorf("%w: a %s where a blob was named", ErrEvsGitObjectInvalid, kind)
	}
	if self.settings.FileByteCount < size {
		return fmt.Errorf("%w: a file of %d bytes, past %d", ErrGitFileTooLarge, size, self.settings.FileByteCount)
	}
	return nil
}

// Each link's target, read from its blob, for the links the checkout writes.
func (self *GitWorktree) linkTargets(ctx context.Context, files []gitTreeFile, unwritten map[string]bool) (map[string]string, error) {
	links := map[string]string{}
	for _, file := range files {
		if unwritten[file.path] || file.mode != EvsGitModeSymlink {
			continue
		}
		if err := self.objects.FetchPromised(ctx, []EvsGitOid{file.oid}); err != nil {
			return nil, err
		}
		kind, content, err := self.objects.ReadGitObject(ctx, file.oid)
		if err != nil {
			return nil, err
		}
		if kind != evsGitBlobKind {
			return nil, fmt.Errorf("%w: a link that is no blob", ErrEvsGitObjectInvalid)
		}
		links[file.path] = string(content)
	}
	return links, nil
}

// Whether a link at linkPath holding target resolves inside the worktree through the links in links, passing through
// no .git and following at most SymlinkHopCount links (see the file header's links row).
func (self *GitWorktree) linkStaysInside(linkPath string, target string, links map[string]string) bool {
	if target == "" || strings.HasPrefix(target, "/") || strings.ContainsAny(target, "\\\x00") || gitDrivePrefix(target) {
		return false
	}
	resolved := []string{}
	if directory := path.Dir(linkPath); directory != "." {
		resolved = strings.Split(directory, "/")
	}
	pending := strings.Split(target, "/")
	hops := 0
	for 0 < len(pending) {
		name := pending[0]
		pending = pending[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			if len(resolved) == 0 {
				return false
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}
		if gitDotGitName(name) {
			return false
		}
		candidate := strings.Join(append(slices.Clone(resolved), name), "/")
		if next, ok := links[candidate]; ok {
			hops += 1
			if self.settings.SymlinkHopCount < hops || next == "" || strings.HasPrefix(next, "/") ||
				strings.ContainsAny(next, "\\\x00") || gitDrivePrefix(next) {
				return false
			}
			pending = append(strings.Split(next, "/"), pending...)
			continue
		}
		resolved = append(resolved, name)
	}
	return true
}

// Makes each leading directory of name, reading each with Lstat: a link or a file there refuses the write.
func (self *GitWorktree) ensureDirectories(name string) error {
	directory := path.Dir(name)
	if directory == "." {
		return nil
	}
	at := ""
	for _, component := range strings.Split(directory, "/") {
		if at == "" {
			at = component
		} else {
			at += "/" + component
		}
		info, err := self.fileSystem.Lstat(at)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := self.fileSystem.MkdirAll(at, 0o755); err != nil {
				return err
			}
		case err != nil:
			return err
		case info.Mode()&fs.ModeSymlink != 0:
			return &GitPathError{Path: name, Rule: "a path through a symbolic link"}
		case !info.IsDir():
			return fmt.Errorf("%w: a file stands where a directory goes", ErrGitWorktreeBlocked)
		}
	}
	return nil
}

// Clears name for a write: a file or link there is removed (never followed); a directory refuses.
func (self *GitWorktree) clear(name string) error {
	info, err := self.fileSystem.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%w: a directory stands where a file goes", ErrGitWorktreeBlocked)
	}
	return self.fileSystem.Remove(name)
}

// Writes one file or gitlink: a blob streamed to .git/ur/tmp, held to its oid, then renamed into place; a gitlink an
// empty directory. Answers its index entry with the stat values written.
func (self *GitWorktree) writeFile(ctx context.Context, file gitTreeFile) (*GitIndexEntry, error) {
	if err := self.ensureDirectories(file.path); err != nil {
		return nil, err
	}
	entry := &GitIndexEntry{Path: file.path, Mode: file.mode, Oid: file.oid}
	if file.mode == EvsGitModeGitlink {
		info, err := self.fileSystem.Lstat(file.path)
		if err == nil && !info.IsDir() {
			if err := self.clear(file.path); err != nil {
				return nil, err
			}
		}
		if err := self.fileSystem.MkdirAll(file.path, 0o755); err != nil {
			return nil, err
		}
		return entry, nil
	}
	kind, size, reader, err := self.objects.OpenGitObject(ctx, file.oid)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	if kind != evsGitBlobKind {
		return nil, fmt.Errorf("%w: a %s where a blob was named", ErrEvsGitObjectInvalid, kind)
	}
	if self.settings.FileByteCount < size {
		return nil, fmt.Errorf("%w: a file of %d bytes, past %d", ErrGitFileTooLarge, size, self.settings.FileByteCount)
	}
	perm := fs.FileMode(0o644)
	if file.mode == EvsGitModeExecutable {
		perm = 0o755
	}
	if err := self.fileSystem.MkdirAll(gitUrTempDirectory, 0o755); err != nil {
		return nil, err
	}
	temp, out, err := gitCreateTemp(self.fileSystem, gitUrTempDirectory, perm)
	if err != nil {
		return nil, err
	}
	landed := false
	defer func() {
		if !landed {
			self.fileSystem.Remove(temp)
		}
	}()
	// the reader holds the content to its oid at its end, before the rename below
	if _, err := io.Copy(out, reader); err != nil {
		out.Close()
		return nil, err
	}
	if err := out.Close(); err != nil {
		return nil, err
	}
	if perm&0o100 != 0 && self.habits.ExecBit {
		if err := self.fileSystem.Chmod(temp, perm); err != nil {
			return nil, err
		}
	}
	if err := self.clear(file.path); err != nil {
		return nil, err
	}
	if err := self.fileSystem.Rename(temp, file.path); err != nil {
		return nil, err
	}
	landed = true
	info, err := self.fileSystem.Lstat(file.path)
	if err != nil {
		return nil, err
	}
	entry.Stat = gitStatDataOf(info)
	return entry, nil
}

// Writes one link: as a link holding target, or as a text file holding it.
func (self *GitWorktree) writeLink(file gitTreeFile, target string, asLink bool) (*GitIndexEntry, error) {
	if err := self.ensureDirectories(file.path); err != nil {
		return nil, err
	}
	if err := self.clear(file.path); err != nil {
		return nil, err
	}
	if asLink {
		if err := self.fileSystem.Symlink(target, file.path); err != nil {
			return nil, err
		}
	} else if err := gitWriteFile(self.fileSystem, file.path, []byte(target), 0o644); err != nil {
		return nil, err
	}
	info, err := self.fileSystem.Lstat(file.path)
	if err != nil {
		return nil, err
	}
	return &GitIndexEntry{Path: file.path, Mode: file.mode, Oid: file.oid, Stat: gitStatDataOf(info)}, nil
}

// Removes what an index entry put in the worktree, a gitlink's directory only when empty, then the directories it
// leaves empty, as git does.
func (self *GitWorktree) removeHeld(entry *GitIndexEntry) error {
	info, err := self.fileSystem.Lstat(entry.Path)
	if errors.Is(err, fs.ErrNotExist) {
		self.pruneDirectories(path.Dir(entry.Path))
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() && entry.Mode != EvsGitModeGitlink {
		return nil
	}
	if err := self.fileSystem.Remove(entry.Path); err != nil && !info.IsDir() {
		return err
	}
	self.pruneDirectories(path.Dir(entry.Path))
	return nil
}

// Removes directory and its parents while they are empty.
func (self *GitWorktree) pruneDirectories(directory string) {
	for directory != "." && directory != "" {
		entries, err := self.fileSystem.ReadDir(directory)
		if err != nil || 0 < len(entries) {
			return
		}
		if self.fileSystem.Remove(directory) != nil {
			return
		}
		directory = path.Dir(directory)
	}
}

// How a worktree file stands against its index entry.
type GitEntryState int

const (
	GitEntryUnchanged GitEntryState = iota
	GitEntryModified
	GitEntryDeleted
	// A file where a link stood, a link where a file stood, or a directory where either stood.
	GitEntryTypeChanged
)

// The mode the worktree gives a file it holds, by the file header's modes row: a link 120000, a gitlink's directory
// 160000, a regular file 100755 or 100644 by its executable bit where the file system keeps one, else by the held
// entry's; a regular file where the entry holds a link checked out as text stays 120000.
func (self *GitWorktree) FileMode(info fs.FileInfo, held *GitIndexEntry) uint32 {
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return EvsGitModeSymlink
	case info.IsDir():
		return EvsGitModeGitlink
	case held != nil && held.Mode == EvsGitModeSymlink:
		return EvsGitModeSymlink
	case self.habits.ExecBit:
		if info.Mode().Perm()&0o100 != 0 {
			return EvsGitModeExecutable
		}
		return EvsGitModeFile
	case held != nil && held.Mode == EvsGitModeExecutable:
		return EvsGitModeExecutable
	}
	return EvsGitModeFile
}

// The blob oid of a worktree file: a link's target, a text-file link's or a regular file's content, held to
// FileByteCount.
func (self *GitWorktree) HashFile(name string, info fs.FileInfo) (EvsGitOid, error) {
	if info.Mode()&fs.ModeSymlink != 0 {
		target, err := self.fileSystem.Readlink(name)
		if err != nil {
			return EvsGitOid{}, err
		}
		return gitBlobOid([]byte(target)), nil
	}
	if !info.Mode().IsRegular() {
		return EvsGitOid{}, fmt.Errorf("%w: neither a file nor a link", ErrGitWorktreeBlocked)
	}
	if self.settings.FileByteCount < info.Size() {
		return EvsGitOid{}, fmt.Errorf("%w: a file of %d bytes, past %d", ErrGitFileTooLarge, info.Size(), self.settings.FileByteCount)
	}
	file, err := self.fileSystem.Open(name)
	if err != nil {
		return EvsGitOid{}, err
	}
	defer file.Close()
	return EvsGitBlobOid(io.LimitReader(file, info.Size()), info.Size())
}

// How a stage-0 entry's file stands in the worktree: the stat values compared first, the content hashed where they
// differ or the entry is racy (its mtime not before indexTime, nil for every entry racy). An unwritten entry's missing
// file is unchanged, never deleted (§13.4's collisions row, GIT-M13-02's sparse checkout).
func (self *GitWorktree) EntryState(ctx context.Context, entry *GitIndexEntry, indexTime *GitStatData) (GitEntryState, error) {
	info, err := self.fileSystem.Lstat(entry.Path)
	if errors.Is(err, fs.ErrNotExist) {
		if entry.Unwritten {
			return GitEntryUnchanged, nil
		}
		return GitEntryDeleted, nil
	}
	if err != nil {
		return 0, err
	}
	if entry.Unwritten {
		// what stands there is another path's file where this one folds to it, so not this entry's
		spelled, err := self.spelledExactly(entry.Path)
		if err != nil {
			return 0, err
		}
		if !spelled {
			return GitEntryUnchanged, nil
		}
	}
	// a path under a link is not this entry's file
	if directory := path.Dir(entry.Path); directory != "." {
		for at := directory; at != "."; at = path.Dir(at) {
			if linkInfo, err := self.fileSystem.Lstat(at); err == nil && linkInfo.Mode()&fs.ModeSymlink != 0 {
				return GitEntryDeleted, nil
			}
		}
	}
	mode := self.FileMode(info, entry)
	if gitFileKind(mode) != gitFileKind(entry.Mode) {
		return GitEntryTypeChanged, nil
	}
	if entry.Mode == EvsGitModeGitlink {
		return GitEntryUnchanged, nil
	}
	if mode != entry.Mode {
		return GitEntryModified, nil
	}
	stat := gitStatDataOf(info)
	racy := indexTime == nil || indexTime.MtimeSeconds < stat.MtimeSeconds ||
		(indexTime.MtimeSeconds == stat.MtimeSeconds && indexTime.MtimeNanoseconds <= stat.MtimeNanoseconds)
	if stat == entry.Stat && !racy {
		return GitEntryUnchanged, nil
	}
	oid, err := self.HashFile(entry.Path, info)
	if err != nil {
		return 0, err
	}
	if oid != entry.Oid {
		return GitEntryModified, nil
	}
	return GitEntryUnchanged, nil
}

// Whether every component of name stands in its directory spelled exactly so, byte for byte, as a directory listing
// shows names: false where a folding file system finds it only by another spelling.
func (self *GitWorktree) spelledExactly(name string) (bool, error) {
	directory := "."
	for _, component := range strings.Split(name, "/") {
		entries, err := self.fileSystem.ReadDir(directory)
		if err != nil {
			return false, err
		}
		if !slices.ContainsFunc(entries, func(entry fs.DirEntry) bool { return entry.Name() == component }) {
			return false, nil
		}
		if directory == "." {
			directory = component
		} else {
			directory += "/" + component
		}
	}
	return true, nil
}

// One file or directory a walk of the worktree met.
type GitWorktreeFile struct {
	Path string
	Info fs.FileInfo
	// Excluded by the ignore rules; a directory so excluded is not walked into.
	Ignored bool
}

// Visits every file and link of the worktree below directory ("" for all), sorted by path, with whether the ignore
// rules exclude it; .git, in any spelling, is never entered, and an excluded directory is visited once, not walked.
func (self *GitWorktree) Walk(directory string, ignore *GitIgnore, visit func(*GitWorktreeFile) error) error {
	name := directory
	if name == "" {
		name = "."
	}
	entries, err := self.fileSystem.ReadDir(name)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if gitDotGitName(entry.Name()) {
			continue
		}
		child := entry.Name()
		if directory != "" {
			child = directory + "/" + entry.Name()
		}
		info, err := self.fileSystem.Lstat(child)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		ignored := false
		if ignore != nil {
			if ignored, err = ignore.Ignored(child, info.IsDir()); err != nil {
				return err
			}
		}
		if info.IsDir() && !ignored {
			if err := self.Walk(child, ignore, visit); err != nil {
				return err
			}
			continue
		}
		if err := visit(&GitWorktreeFile{Path: child, Info: info, Ignored: ignored}); err != nil {
			return err
		}
	}
	return nil
}

// Reads the habits .git/ur/habits keeps, nil where none stands.
func gitReadHabits(fileSystem GitFileSystem, settings *GitSettings) (*GitWorktreeHabits, error) {
	content, err := gitReadFile(fileSystem, gitHabitsName, settings.StateFileByteCount)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	habits := &GitWorktreeHabits{}
	if err := json.Unmarshal(content, habits); err != nil {
		return nil, fmt.Errorf("%w: .git/ur/habits does not read", ErrGitIndexInvalid)
	}
	return habits, nil
}

// Keeps habits in .git/ur/habits.
func gitWriteHabits(fileSystem GitFileSystem, habits *GitWorktreeHabits) error {
	content, err := json.Marshal(habits)
	if err != nil {
		return err
	}
	return gitWriteFileAtomic(fileSystem, gitUrDirectory, gitHabitsName, content, 0o644, false)
}
