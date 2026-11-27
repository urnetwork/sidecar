//go:build !ios_extension && !sidecar_http

// The file system a bundled git worktree lives on (DESIGN-COMPUTE §13.4's workspace row, §7.5's workspace; GIT-M13-01):
// the worktree's files and its .git directory both, by names relative to the worktree's root, '/'-separated, "." for
// the root itself. A desktop's or a phone's is a directory of the agent's workspace (NewGitOsFileSystem), the page
// Worker's an in-memory one (GIT-M13-08), and a test's a fake whose case folding, exec bit and links it chooses.
//
//	root     the OS file system opens every name beneath its root through an os.Root, so no name, and no link inside
//	         the root, reaches out of it; the worktree still refuses to write through any link (git_worktree.go)
//	budget   every byte a write adds is reserved first from the workspace's budget (GitByteBudget), and what a
//	         remove or a truncation frees is released, so a write past the workspace's cap fails before it lands
//	         and leaves what was there; a nil budget reserves nothing past GitSettings' own limits
//
// Safe for concurrent use as os.Root is; a GitFile is its caller's alone.

package sidecar

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sync"
)

// A write the workspace's budget refused before it landed.
var ErrGitWorkspaceFull = errors.New("git: the write would pass the workspace's cap")

// A file open to write.
type GitFile interface {
	io.Writer
	io.Closer
	// Makes what was written durable before it returns.
	Sync() error
}

// What a worktree reads and writes through: see the file header. Every name is relative to the worktree's root.
type GitFileSystem interface {
	// The name's own information, never a link's target's; fs.ErrNotExist for none.
	Lstat(name string) (fs.FileInfo, error)
	// A regular file to read.
	Open(name string) (io.ReadCloser, error)
	// A file to write with perm: made, or truncated where it stands; exclusive refuses one that stands with
	// fs.ErrExist, as a lock file's create must.
	Create(name string, perm fs.FileMode, exclusive bool) (GitFile, error)
	// Moves oldName onto newName, replacing a file there.
	Rename(oldName string, newName string) error
	// Removes a file, a link or an empty directory.
	Remove(name string) error
	// Makes a directory and its missing parents.
	MkdirAll(name string, perm fs.FileMode) error
	// A directory's entries, sorted by name.
	ReadDir(name string) ([]fs.DirEntry, error)
	// Makes name a symbolic link holding target.
	Symlink(target string, name string) error
	// A link's target.
	Readlink(name string) (string, error)
	// Sets a file's permission bits.
	Chmod(name string, mode fs.FileMode) error
}

// The workspace's budget a worktree's writes count against (DESIGN-COMPUTE §7.5's caps).
type GitByteBudget interface {
	// Takes byteCount more bytes, or refuses with an error wrapping ErrGitWorkspaceFull, holding nothing.
	Reserve(byteCount int64) error
	// Gives back byteCount bytes a remove or a truncation freed.
	Release(byteCount int64)
}

// A budget of a fixed cap counted from what its owner holds now: the simplest workspace budget, and the page leg's.
// Safe for concurrent use.
type GitCapBudget struct {
	capByteCount int64

	stateLock sync.Mutex
	used      int64
}

// A budget of capByteCount with usedByteCount already held.
func NewGitCapBudget(capByteCount int64, usedByteCount int64) *GitCapBudget {
	return &GitCapBudget{capByteCount: capByteCount, used: usedByteCount}
}

// Takes byteCount, or refuses past the cap.
func (self *GitCapBudget) Reserve(byteCount int64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.capByteCount < self.used+byteCount {
		return fmt.Errorf("%w: %d bytes held, %d asked, %d allowed", ErrGitWorkspaceFull, self.used, byteCount, self.capByteCount)
	}
	self.used += byteCount
	return nil
}

// Gives back byteCount, never below nothing.
func (self *GitCapBudget) Release(byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.used = max(0, self.used-byteCount)
}

// What the budget holds now.
func (self *GitCapBudget) Used() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.used
}

// A directory of this host as a worktree's file system.
type gitOsFileSystem struct {
	root   *os.Root
	budget GitByteBudget
}

// The directory dir, which must stand, as a worktree's file system, its writes counted against budget (nil for
// none). Close releases the directory.
func NewGitOsFileSystem(dir string, budget GitByteBudget) (GitFileSystem, func() error, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, err
	}
	return &gitOsFileSystem{root: root, budget: budget}, root.Close, nil
}

// A name in the host's separators, which os.Root takes.
func gitOsName(name string) string {
	return filepath.FromSlash(path.Clean(name))
}

func (self *gitOsFileSystem) Lstat(name string) (fs.FileInfo, error) {
	return self.root.Lstat(gitOsName(name))
}

func (self *gitOsFileSystem) Open(name string) (io.ReadCloser, error) {
	return self.root.Open(gitOsName(name))
}

func (self *gitOsFileSystem) Create(name string, perm fs.FileMode, exclusive bool) (GitFile, error) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if exclusive {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	freed := int64(0)
	if info, err := self.root.Lstat(gitOsName(name)); err == nil && info.Mode().IsRegular() && !exclusive {
		freed = info.Size()
	}
	file, err := self.root.OpenFile(gitOsName(name), flags, perm)
	if err != nil {
		return nil, err
	}
	if self.budget == nil {
		return file, nil
	}
	self.budget.Release(freed)
	return &gitBudgetFile{file: file, budget: self.budget}, nil
}

func (self *gitOsFileSystem) Rename(oldName string, newName string) error {
	freed := int64(0)
	if info, err := self.root.Lstat(gitOsName(newName)); err == nil && info.Mode().IsRegular() {
		freed = info.Size()
	}
	if err := self.root.Rename(gitOsName(oldName), gitOsName(newName)); err != nil {
		return err
	}
	if self.budget != nil {
		self.budget.Release(freed)
	}
	return nil
}

func (self *gitOsFileSystem) Remove(name string) error {
	freed := int64(0)
	if info, err := self.root.Lstat(gitOsName(name)); err == nil && info.Mode().IsRegular() {
		freed = info.Size()
	}
	if err := self.root.Remove(gitOsName(name)); err != nil {
		return err
	}
	if self.budget != nil {
		self.budget.Release(freed)
	}
	return nil
}

func (self *gitOsFileSystem) MkdirAll(name string, perm fs.FileMode) error {
	return self.root.MkdirAll(gitOsName(name), perm)
}

func (self *gitOsFileSystem) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(self.root.FS(), path.Clean(name))
}

func (self *gitOsFileSystem) Symlink(target string, name string) error {
	return self.root.Symlink(filepath.FromSlash(target), gitOsName(name))
}

func (self *gitOsFileSystem) Readlink(name string) (string, error) {
	target, err := self.root.Readlink(gitOsName(name))
	return filepath.ToSlash(target), err
}

func (self *gitOsFileSystem) Chmod(name string, mode fs.FileMode) error {
	return self.root.Chmod(gitOsName(name), mode)
}

// A file whose every write is reserved from a budget first: a write the budget refuses writes nothing.
type gitBudgetFile struct {
	file   *os.File
	budget GitByteBudget
}

func (self *gitBudgetFile) Write(p []byte) (int, error) {
	if err := self.budget.Reserve(int64(len(p))); err != nil {
		return 0, err
	}
	n, err := self.file.Write(p)
	if n < len(p) {
		self.budget.Release(int64(len(p) - n))
	}
	return n, err
}

func (self *gitBudgetFile) Close() error {
	return self.file.Close()
}

func (self *gitBudgetFile) Sync() error {
	return self.file.Sync()
}

// Writes content whole to name through fs, made or truncated with perm.
func gitWriteFile(fileSystem GitFileSystem, name string, content []byte, perm fs.FileMode) error {
	file, err := fileSystem.Create(name, perm, false)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// Reads name whole through fs, refusing past limit bytes with what it read discarded.
func gitReadFile(fileSystem GitFileSystem, name string, limit int64) ([]byte, error) {
	file, err := fileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if limit < int64(len(content)) {
		return nil, fmt.Errorf("%w: past %d bytes", ErrGitFileTooLarge, limit)
	}
	return content, nil
}

// A file past a limit the settings set.
var ErrGitFileTooLarge = errors.New("git: a file past its limit")

// Writes content to name atomically: a temporary file beside it in dir, synced when sync is set, then renamed over
// it, so a reader sees the old bytes or the new ones whole.
func gitWriteFileAtomic(fileSystem GitFileSystem, tempDir string, name string, content []byte, perm fs.FileMode, sync bool) error {
	temp, file, err := gitCreateTemp(fileSystem, tempDir, perm)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		fileSystem.Remove(temp)
		return err
	}
	if sync {
		if err := file.Sync(); err != nil {
			file.Close()
			fileSystem.Remove(temp)
			return err
		}
	}
	if err := file.Close(); err != nil {
		fileSystem.Remove(temp)
		return err
	}
	if err := fileSystem.Rename(temp, name); err != nil {
		fileSystem.Remove(temp)
		return err
	}
	return nil
}

// A new file of a fresh random name in dir, made exclusively: its name and the file. An id's 80 random bits make a
// name that stands already a fault, refused as such.
func gitCreateTemp(fileSystem GitFileSystem, dir string, perm fs.FileMode) (string, GitFile, error) {
	name := path.Join(dir, "tmp-"+NewId().String())
	file, err := fileSystem.Create(name, perm, true)
	return name, file, err
}
