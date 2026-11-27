//go:build !ios_extension && !sidecar_http

// A worktree's file system faked in memory (GIT-M13-01's tests): one whose case folding, Unicode normalization
// folding, executable bit and links a test chooses, so TestCaseFoldCollision and TestModeKeptWithoutExecBit run the
// same on every host. Names fold to a key; a node keeps the spelling it was made with, as a case-preserving file
// system does. Times come from a counter, so nothing reads a clock.

package sidecar

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// What a fake file system does.
type gitFakeHabits struct {
	caseFold          bool
	normalizationFold bool
	execBit           bool
	symlinks          bool
}

// One file, link or directory.
type gitFakeNode struct {
	name    string
	mode    fs.FileMode
	content []byte
	target  string
	tick    int64
}

// The fake: nodes by their folded path, "." the root.
type gitFakeFileSystem struct {
	habits gitFakeHabits

	stateLock sync.Mutex
	nodes     map[string]*gitFakeNode
	ticks     int64
}

func newGitFakeFileSystem(habits gitFakeHabits) *gitFakeFileSystem {
	return &gitFakeFileSystem{
		habits: habits,
		nodes:  map[string]*gitFakeNode{".": {name: ".", mode: fs.ModeDir | 0o755}},
	}
}

// A name's key: cleaned, then folded as the habits say.
func (self *gitFakeFileSystem) key(name string) string {
	name = path.Clean(name)
	if self.habits.normalizationFold {
		name = norm.NFC.String(name)
	}
	if self.habits.caseFold {
		name = cases.Fold().String(name)
	}
	return name
}

// The node at name, nil for none, with its parent required to be a directory.
func (self *gitFakeFileSystem) nodeWithLock(name string) *gitFakeNode {
	return self.nodes[self.key(name)]
}

// The parent of name must be a directory that stands.
func (self *gitFakeFileSystem) parentWithLock(name string) error {
	parent := self.nodeWithLock(path.Dir(path.Clean(name)))
	if parent == nil {
		return fs.ErrNotExist
	}
	if !parent.mode.IsDir() {
		return errors.New("fake: a parent that is no directory")
	}
	return nil
}

func (self *gitFakeFileSystem) nextTickWithLock() int64 {
	self.ticks += 1
	return self.ticks
}

// fs.FileInfo of a node.
type gitFakeInfo struct {
	node *gitFakeNode
}

func (self gitFakeInfo) Name() string {
	return path.Base(self.node.name)
}

func (self gitFakeInfo) Size() int64 {
	if self.node.mode&fs.ModeSymlink != 0 {
		return int64(len(self.node.target))
	}
	return int64(len(self.node.content))
}

func (self gitFakeInfo) Mode() fs.FileMode {
	return self.node.mode
}

func (self gitFakeInfo) ModTime() time.Time {
	return time.Unix(1700000000+self.node.tick, 0)
}

func (self gitFakeInfo) IsDir() bool {
	return self.node.mode.IsDir()
}

func (self gitFakeInfo) Sys() any {
	return nil
}

func (self *gitFakeFileSystem) Lstat(name string) (fs.FileInfo, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	node := self.nodeWithLock(name)
	if node == nil {
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrNotExist}
	}
	copied := *node
	return gitFakeInfo{node: &copied}, nil
}

func (self *gitFakeFileSystem) Open(name string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	node := self.nodeWithLock(name)
	if node == nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if !node.mode.IsRegular() {
		return nil, errors.New("fake: opens regular files alone")
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(node.content))), nil
}

// A file being written: its bytes land when it closes.
type gitFakeFile struct {
	fileSystem *gitFakeFileSystem
	name       string
	buffer     bytes.Buffer
}

func (self *gitFakeFile) Write(p []byte) (int, error) {
	return self.buffer.Write(p)
}

func (self *gitFakeFile) Sync() error {
	return nil
}

func (self *gitFakeFile) Close() error {
	self.fileSystem.stateLock.Lock()
	defer self.fileSystem.stateLock.Unlock()
	node := self.fileSystem.nodeWithLock(self.name)
	if node == nil {
		return fs.ErrNotExist
	}
	node.content = bytes.Clone(self.buffer.Bytes())
	node.tick = self.fileSystem.nextTickWithLock()
	return nil
}

// The permission bits a fake keeps: without an executable bit, none of the execute bits.
func (self *gitFakeFileSystem) perm(perm fs.FileMode) fs.FileMode {
	if !self.habits.execBit {
		return perm &^ 0o111
	}
	return perm
}

func (self *gitFakeFileSystem) Create(name string, perm fs.FileMode, exclusive bool) (GitFile, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.parentWithLock(name); err != nil {
		return nil, &fs.PathError{Op: "create", Path: name, Err: err}
	}
	node := self.nodeWithLock(name)
	switch {
	case node != nil && exclusive:
		return nil, &fs.PathError{Op: "create", Path: name, Err: fs.ErrExist}
	case node != nil && !node.mode.IsRegular():
		return nil, errors.New("fake: creates over regular files alone")
	case node == nil:
		node = &gitFakeNode{name: path.Clean(name), mode: self.perm(perm)}
		self.nodes[self.key(name)] = node
	}
	node.content = nil
	node.tick = self.nextTickWithLock()
	return &gitFakeFile{fileSystem: self, name: name}, nil
}

func (self *gitFakeFileSystem) Rename(oldName string, newName string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	node := self.nodeWithLock(oldName)
	if node == nil {
		return &fs.PathError{Op: "rename", Path: oldName, Err: fs.ErrNotExist}
	}
	if node.mode.IsDir() {
		return errors.New("fake: renames files alone")
	}
	if err := self.parentWithLock(newName); err != nil {
		return err
	}
	if target := self.nodeWithLock(newName); target != nil && target.mode.IsDir() {
		return errors.New("fake: a rename onto a directory")
	}
	delete(self.nodes, self.key(oldName))
	// a rename onto a name that folds to one standing keeps the standing spelling, as a folding file system does
	if target := self.nodeWithLock(newName); target != nil {
		node.name = target.name
	} else {
		node.name = path.Clean(newName)
	}
	self.nodes[self.key(newName)] = node
	return nil
}

// Whether a directory holds anything.
func (self *gitFakeFileSystem) childrenWithLock(name string) []*gitFakeNode {
	directoryKey := self.key(name)
	children := []*gitFakeNode{}
	for key, node := range self.nodes {
		if key != "." && self.key(path.Dir(key)) == directoryKey && key != directoryKey {
			children = append(children, node)
		}
	}
	slices.SortFunc(children, func(a *gitFakeNode, b *gitFakeNode) int { return strings.Compare(a.name, b.name) })
	return children
}

func (self *gitFakeFileSystem) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	node := self.nodeWithLock(name)
	if node == nil {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
	}
	if node.mode.IsDir() && 0 < len(self.childrenWithLock(name)) {
		return errors.New("fake: a directory that is not empty")
	}
	delete(self.nodes, self.key(name))
	return nil
}

func (self *gitFakeFileSystem) MkdirAll(name string, perm fs.FileMode) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	at := ""
	for _, component := range strings.Split(path.Clean(name), "/") {
		if at == "" {
			at = component
		} else {
			at += "/" + component
		}
		node := self.nodeWithLock(at)
		switch {
		case node == nil:
			self.nodes[self.key(at)] = &gitFakeNode{name: at, mode: fs.ModeDir | 0o755, tick: self.nextTickWithLock()}
		case !node.mode.IsDir():
			return errors.New("fake: a file where a directory goes")
		}
	}
	return nil
}

func (self *gitFakeFileSystem) ReadDir(name string) ([]fs.DirEntry, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	node := self.nodeWithLock(name)
	if node == nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	if !node.mode.IsDir() {
		return nil, errors.New("fake: reads directories alone")
	}
	entries := []fs.DirEntry{}
	for _, child := range self.childrenWithLock(name) {
		copied := *child
		entries = append(entries, fs.FileInfoToDirEntry(gitFakeInfo{node: &copied}))
	}
	return entries, nil
}

func (self *gitFakeFileSystem) Symlink(target string, name string) error {
	if !self.habits.symlinks {
		return errors.New("fake: no links here")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.parentWithLock(name); err != nil {
		return err
	}
	if self.nodeWithLock(name) != nil {
		return &fs.PathError{Op: "symlink", Path: name, Err: fs.ErrExist}
	}
	self.nodes[self.key(name)] = &gitFakeNode{name: path.Clean(name), mode: fs.ModeSymlink | 0o777, target: target, tick: self.nextTickWithLock()}
	return nil
}

func (self *gitFakeFileSystem) Readlink(name string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	node := self.nodeWithLock(name)
	if node == nil || node.mode&fs.ModeSymlink == 0 {
		return "", errors.New("fake: no link")
	}
	return node.target, nil
}

func (self *gitFakeFileSystem) Chmod(name string, mode fs.FileMode) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	node := self.nodeWithLock(name)
	if node == nil {
		return fs.ErrNotExist
	}
	node.mode = node.mode.Type() | self.perm(mode.Perm())
	return nil
}

// The spelling a name was made with, "" for none: what a folding file system shows of it.
func (self *gitFakeFileSystem) spelling(name string) string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	node := self.nodeWithLock(name)
	if node == nil {
		return ""
	}
	return node.name
}

// The bytes of a file, nil for none.
func (self *gitFakeFileSystem) content(name string) []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	node := self.nodeWithLock(name)
	if node == nil {
		return nil
	}
	return bytes.Clone(node.content)
}
