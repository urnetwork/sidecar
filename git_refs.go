//go:build !ios_extension && !sidecar_http

// The worktree's refs (DESIGN-COMPUTE §13.4's workspace row, D-GIT-1; GIT-M13-01), in git's own layout so stock git
// reads them:
//
//	HEAD      .git/HEAD: `ref: refs/heads/<branch>` for a branch checked out, born or not, or a commit's hex for a
//	          detached head
//	loose     .git/refs/heads/<branch>, refs/tags/<tag> and refs/remotes/origin/<branch>, each a commit's hex and a
//	          newline; a loose ref may be symbolic, `ref: <name>`, as stock git's refs/remotes/origin/HEAD is, followed
//	          at most GitSettings.SymbolicRefHopCount times
//	packed    .git/packed-refs, which only stock git writes in a worktree, is read beneath the loose refs and rewritten
//	          only to delete a ref it holds
//	update    under `<name>.lock`, made exclusively as git makes it, the ref read again and compared with what the
//	          caller read (the compare-and-swap every porcelain command updates through), then the lock renamed over
//	          it; a lock that stands is another git's, refused, never broken
//
// A name is held to git's check-ref-format and, since it becomes a path under .git, to gitCheckPath. No reflog is
// written: the porcelain's commands that read one (stash, M14) write their own.
//
// Safe for concurrent use as its file system is: the lock orders writers.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
)

// The ref names and prefixes git's layout fixes.
const (
	gitHeadName       = ".git/HEAD"
	gitPackedRefsName = ".git/packed-refs"
	gitRefsPrefix     = "refs/"
	GitHeadRef        = "HEAD"
	GitBranchPrefix   = "refs/heads/"
	GitTagPrefix      = "refs/tags/"
	GitRemoteName     = "origin"
	GitRemotePrefix   = "refs/remotes/origin/"
	gitSymbolicPrefix = "ref: "
	gitLockSuffix     = ".lock"
)

var (
	// A ref name git's check-ref-format refuses, or one that is no safe path under .git.
	ErrGitRefInvalid = errors.New("git: a ref name git refuses")
	// An update whose ref no longer holds what the caller read: the compare-and-swap's refusal.
	ErrGitRefMoved = errors.New("git: the ref moved since it was read")
	// A ref whose lock another git holds.
	ErrGitRefLocked = errors.New("git: the ref's lock is held by another git")
	// A ref file that is neither an oid nor a symbolic ref, or a symbolic chain past its hop count.
	ErrGitRefCorrupt = errors.New("git: a ref that does not read")
)

// HEAD: a branch, born or not, or a detached commit.
type GitHead struct {
	// The ref HEAD names, refs/heads/<branch>; "" when detached.
	Symbolic string
	// The detached commit; nil when symbolic.
	Oid *EvsGitOid
}

// One ref and the commit it names.
type GitRef struct {
	Name string
	Oid  EvsGitOid
}

// The worktree's refs.
type GitRefs struct {
	fileSystem GitFileSystem
	settings   *GitSettings
}

// The refs of the worktree on fileSystem.
func newGitRefs(fileSystem GitFileSystem, settings *GitSettings) *GitRefs {
	return &GitRefs{fileSystem: fileSystem, settings: settings}
}

// Holds a full ref name, refs/..., to check-ref-format's rules and gitCheckPath's.
func GitCheckRefName(name string) error {
	refused := func(rule string) error {
		return fmt.Errorf("%w: %s", ErrGitRefInvalid, rule)
	}
	if !strings.HasPrefix(name, gitRefsPrefix) {
		return refused("a ref outside refs/")
	}
	if strings.Contains(name, "..") || strings.Contains(name, "@{") || name == "@" {
		return refused("a ref holding .. or @{")
	}
	if strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".") {
		return refused("a ref ending in / or .")
	}
	for _, c := range []byte(name) {
		if c < 0x20 || c == 0x7f || strings.IndexByte(" ~^:?*[\\", c) != -1 {
			return refused("a ref holding a control character, a space or one of ~^:?*[\\")
		}
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || strings.HasPrefix(component, ".") || strings.HasSuffix(component, gitLockSuffix) {
			return refused("a ref whose name is empty, opens with . or ends with .lock")
		}
	}
	if err := gitCheckPath(name, 0); err != nil {
		return refused("a ref that is no safe path")
	}
	return nil
}

// A loose ref's or HEAD's contents: an oid, or the name a symbolic ref names.
func gitParseRefContents(content []byte) (*EvsGitOid, string, error) {
	text := strings.TrimRight(string(content), " \t\r\n")
	if target, found := strings.CutPrefix(text, "ref:"); found {
		target = strings.TrimLeft(target, " \t")
		if target == "" || strings.ContainsAny(target, " \t\n") {
			return nil, "", ErrGitRefCorrupt
		}
		return nil, target, nil
	}
	if len(text) != 2*len(EvsGitOid{}) {
		return nil, "", ErrGitRefCorrupt
	}
	oid := EvsGitOid{}
	if _, err := hex.Decode(oid[:], []byte(text)); err != nil {
		return nil, "", ErrGitRefCorrupt
	}
	return &oid, "", nil
}

// HEAD as it stands.
func (self *GitRefs) Head() (*GitHead, error) {
	content, err := gitReadFile(self.fileSystem, gitHeadName, self.settings.RefByteCount)
	if err != nil {
		return nil, err
	}
	oid, target, err := gitParseRefContents(content)
	if err != nil {
		return nil, err
	}
	if oid != nil {
		return &GitHead{Oid: oid}, nil
	}
	if err := GitCheckRefName(target); err != nil {
		return nil, err
	}
	return &GitHead{Symbolic: target}, nil
}

// Points HEAD at a branch, or detaches it at a commit, under HEAD's lock.
func (self *GitRefs) SetHead(head *GitHead) error {
	content := ""
	switch {
	case head.Oid != nil:
		content = head.Oid.String() + "\n"
	case head.Symbolic != "":
		if err := GitCheckRefName(head.Symbolic); err != nil {
			return err
		}
		content = gitSymbolicPrefix + head.Symbolic + "\n"
	default:
		return fmt.Errorf("%w: a HEAD naming nothing", ErrGitRefInvalid)
	}
	return self.writeLocked(gitHeadName, []byte(content))
}

// The commit HEAD names, nil for a branch not born yet.
func (self *GitRefs) ResolveHead() (*EvsGitOid, error) {
	head, err := self.Head()
	if err != nil {
		return nil, err
	}
	if head.Oid != nil {
		return head.Oid, nil
	}
	return self.Read(head.Symbolic)
}

// The commit a ref names, loose before packed, a symbolic ref followed: nil for none.
func (self *GitRefs) Read(name string) (*EvsGitOid, error) {
	for hop := 0; hop <= self.settings.SymbolicRefHopCount; hop += 1 {
		if err := GitCheckRefName(name); err != nil {
			return nil, err
		}
		content, err := gitReadFile(self.fileSystem, ".git/"+name, self.settings.RefByteCount)
		if errors.Is(err, fs.ErrNotExist) {
			refs, err := self.packed()
			if err != nil {
				return nil, err
			}
			for _, ref := range refs {
				if ref.Name == name {
					oid := ref.Oid
					return &oid, nil
				}
			}
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		oid, target, err := gitParseRefContents(content)
		if err != nil {
			return nil, err
		}
		if oid != nil {
			return oid, nil
		}
		name = target
	}
	return nil, fmt.Errorf("%w: a symbolic ref past %d hops", ErrGitRefCorrupt, self.settings.SymbolicRefHopCount)
}

// The refs packed-refs holds, peeled lines passed over; none where it stands not.
func (self *GitRefs) packed() ([]GitRef, error) {
	content, err := gitReadFile(self.fileSystem, gitPackedRefsName, self.settings.PackedRefsByteCount)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	refs := []GitRef{}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "^") {
			continue
		}
		hexOid, name, found := strings.Cut(line, " ")
		oid, _, err := gitParseRefContents([]byte(hexOid))
		if !found || err != nil || oid == nil || GitCheckRefName(name) != nil {
			return nil, fmt.Errorf("%w: a packed-refs line that is no ref", ErrGitRefCorrupt)
		}
		refs = append(refs, GitRef{Name: name, Oid: *oid})
	}
	return refs, nil
}

// Every ref under prefix (refs/heads/, say), loose over packed, sorted by name; a symbolic loose ref is passed over.
func (self *GitRefs) List(prefix string) ([]GitRef, error) {
	named := map[string]EvsGitOid{}
	packed, err := self.packed()
	if err != nil {
		return nil, err
	}
	for _, ref := range packed {
		if strings.HasPrefix(ref.Name, prefix) {
			named[ref.Name] = ref.Oid
		}
	}
	var walk func(directory string) error
	walk = func(directory string) error {
		entries, err := self.fileSystem.ReadDir(".git/" + directory)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			name := path.Join(directory, entry.Name())
			switch {
			case entry.IsDir():
				if err := walk(name); err != nil {
					return err
				}
			case entry.Type().IsRegular() && strings.HasPrefix(name, prefix) && !strings.HasSuffix(name, gitLockSuffix):
				if GitCheckRefName(name) != nil {
					continue
				}
				content, err := gitReadFile(self.fileSystem, ".git/"+name, self.settings.RefByteCount)
				if err != nil {
					return err
				}
				oid, _, err := gitParseRefContents(content)
				if err != nil {
					return err
				}
				if oid != nil {
					named[name] = *oid
				}
			}
		}
		return nil
	}
	if err := walk(strings.TrimSuffix(gitRefsPrefix, "/")); err != nil {
		return nil, err
	}
	refs := make([]GitRef, 0, len(named))
	for name, oid := range named {
		refs = append(refs, GitRef{Name: name, Oid: oid})
	}
	slices.SortFunc(refs, func(a GitRef, b GitRef) int { return strings.Compare(a.Name, b.Name) })
	return refs, nil
}

// Sets a ref to oid under its lock when it still holds old (nil: none), the compare-and-swap; ErrGitRefMoved when it
// holds something else.
func (self *GitRefs) Update(name string, oid EvsGitOid, old *EvsGitOid) error {
	return self.update(name, &oid, old, true)
}

// Sets a ref to oid under its lock, whatever it held.
func (self *GitRefs) Set(name string, oid EvsGitOid) error {
	return self.update(name, &oid, nil, false)
}

// Deletes a ref, loose and packed, when it still holds old (nil: whatever it holds).
func (self *GitRefs) Delete(name string, old *EvsGitOid) error {
	return self.update(name, nil, old, old != nil)
}

// One locked update: the ref read again under its lock, compared when check is set, then written or, for a nil oid,
// deleted.
func (self *GitRefs) update(name string, oid *EvsGitOid, old *EvsGitOid, check bool) error {
	if err := GitCheckRefName(name); err != nil {
		return err
	}
	file := ".git/" + name
	if err := self.fileSystem.MkdirAll(path.Dir(file), 0o755); err != nil {
		return err
	}
	lock := file + gitLockSuffix
	lockFile, err := self.fileSystem.Create(lock, 0o644, true)
	if errors.Is(err, fs.ErrExist) {
		return ErrGitRefLocked
	}
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		if !renamed {
			self.fileSystem.Remove(lock)
		}
	}()
	current, err := self.readDirect(name)
	if err != nil {
		lockFile.Close()
		return err
	}
	if check && !gitOidEqual(current, old) {
		lockFile.Close()
		return ErrGitRefMoved
	}
	if oid == nil {
		lockFile.Close()
		if err := self.fileSystem.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := self.unpack(name); err != nil {
			return err
		}
		self.pruneDirectories(path.Dir(file))
		return nil
	}
	if _, err := lockFile.Write([]byte(oid.String() + "\n")); err != nil {
		lockFile.Close()
		return err
	}
	if err := lockFile.Close(); err != nil {
		return err
	}
	if err := self.fileSystem.Rename(lock, file); err != nil {
		return err
	}
	renamed = true
	return nil
}

// A ref's own value, loose over packed, no symbolic ref followed: what a compare-and-swap compares.
func (self *GitRefs) readDirect(name string) (*EvsGitOid, error) {
	content, err := gitReadFile(self.fileSystem, ".git/"+name, self.settings.RefByteCount)
	if err == nil {
		oid, target, err := gitParseRefContents(content)
		if err != nil {
			return nil, err
		}
		if target != "" {
			return nil, fmt.Errorf("%w: a compare-and-swap on a symbolic ref", ErrGitRefInvalid)
		}
		return oid, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	refs, err := self.packed()
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		if ref.Name == name {
			oid := ref.Oid
			return &oid, nil
		}
	}
	return nil, nil
}

// Rewrites packed-refs without name, under its lock, when it holds it.
func (self *GitRefs) unpack(name string) error {
	content, err := gitReadFile(self.fileSystem, gitPackedRefsName, self.settings.PackedRefsByteCount)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	lines := strings.SplitAfter(string(content), "\n")
	kept := make([]string, 0, len(lines))
	dropped := false
	for index := 0; index < len(lines); index += 1 {
		line := lines[index]
		_, refName, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		if !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "^") && refName == name {
			dropped = true
			// its peeled line goes with it
			if index+1 < len(lines) && strings.HasPrefix(lines[index+1], "^") {
				index += 1
			}
			continue
		}
		kept = append(kept, line)
	}
	if !dropped {
		return nil
	}
	return self.writeLocked(gitPackedRefsName, []byte(strings.Join(kept, "")))
}

// Removes the empty directories from directory up to the ref kind's own directory, as git does after a delete.
func (self *GitRefs) pruneDirectories(directory string) {
	for strings.Count(directory, "/") > 2 {
		if err := self.fileSystem.Remove(directory); err != nil {
			return
		}
		directory = path.Dir(directory)
	}
}

// Writes a file under its lock, `<name>.lock` made exclusively and renamed over it.
func (self *GitRefs) writeLocked(name string, content []byte) error {
	lock := name + gitLockSuffix
	lockFile, err := self.fileSystem.Create(lock, 0o644, true)
	if errors.Is(err, fs.ErrExist) {
		return ErrGitRefLocked
	}
	if err != nil {
		return err
	}
	if _, err := lockFile.Write(content); err != nil {
		lockFile.Close()
		self.fileSystem.Remove(lock)
		return err
	}
	if err := lockFile.Close(); err != nil {
		self.fileSystem.Remove(lock)
		return err
	}
	if err := self.fileSystem.Rename(lock, name); err != nil {
		self.fileSystem.Remove(lock)
		return err
	}
	return nil
}

// Whether two optional oids are both nil or equal.
func gitOidEqual(a *EvsGitOid, b *EvsGitOid) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return bytes.Equal(a[:], b[:])
}
