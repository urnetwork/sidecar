// FI-8, attribution (§22.8; §16.7's restore, D-MCP-8, D-MCP-15, RV1-RV4; MCP-M3-27): read after every step from each
// restore ledger the Net holds. A restore schedule keeps one per worktree: what the worktree held at the restored
// run's start, and every write each writer made since, the restored run's hooked edits apart from everything else
// (another run's edits, a person's hand, a process taking no daemon lock, the run's own shell), then the apply's
// answer. The check reads the worktree itself:
//
//   - a path any write other than the restored run's hooked edits touched is never the restore's to discard: its
//     newest bytes are still at the path, or beside it in a conflict copy (<name>.ur-conflict-<h>) or, while an apply
//     is under way, under one of the apply's hidden names in its directory; a path that writer deleted is still
//     absent, nothing having been restored over the delete (RV1, RV4);
//   - bytes a writer put through a handle opened before the apply are still somewhere beside the path, the handle's
//     inode having moved or not (§16.7's written row);
//   - restore writes exact original bytes or nothing: every path the apply answered restored that no other writer
//     touched holds its base bytes, or is absent for a base of absent, and every restored copy
//     (<name>.ur-restored-<h>) holds its path's base bytes (RV2); a path another writer touched is the first
//     clause's, since that writer's newest bytes, written before the install or after it, must still be there;
//   - nothing outside the worktree changes: the directory a schedule puts beyond it reads as it did;
//   - at the end, once the apply has ended, no hidden name of the apply is left anywhere in the worktree.
//
// Which bytes the preview bound, and whether the apply checked them on the bytes it moved aside, the schedules show by
// writing at the apply's barriers: a check on an earlier read would lose a write the first clause then finds missing
// (RV3). A schedule with no ledger reads nothing here.

package fault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

var _ = RegisterInvariant(8, func(ctx context.Context, oracle *Oracle) error {
	errs := []error{}
	for _, ledger := range restoreLedgersOf(oracle.Net) {
		if err := ledger.Check(oracle.Final); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ledger.name, err))
		}
	}
	return errors.Join(errs...)
})

// The names an apply gives what it keeps beside a path and what it moves (mcp's restore_apply.go): format values.
const (
	restoreLedgerHiddenPrefix   = ".ur-restore-"
	restoreLedgerRestoredInfix  = ".ur-restored-"
	restoreLedgerConflictInfix  = ".ur-conflict-"
	restoreLedgerGitDirectory   = ".git"
	restoreLedgerResultRestored = "restored"
)

// One write to a path, as the ledger keeps it.
type RestoreLedgerWrite struct {
	Writer string
	// The bytes the path then held; nil with Absent.
	Content []byte
	Absent  bool
	// A hooked edit of the restored run, which its restore may discard.
	RunEdit bool
}

// What a restore schedule's writers did to one worktree, and what its apply answered. Safe for concurrent use.
type RestoreLedger struct {
	name string
	root string
	// beyond the worktree, which nothing may write; empty for none
	outside       string
	outsideDigest []byte

	stateLock sync.Mutex
	// each path's bytes at the restored run's start; absent where nil
	pathBases map[string][]byte
	// each path's writes since, oldest first
	pathWrites map[string][]*RestoreLedgerWrite
	// the bytes a handle opened earlier left in its file, newest, by the path the handle was opened at
	pathHandleContents map[string][]byte
	// the apply's answer per path once it returned, and whether its journal ended
	pathResults map[string]string
	applyEnded  bool
}

// A ledger of worktree root, root and outside each an absolute path, named for a check's message.
func NewRestoreLedger(name string, root string, outside string) (*RestoreLedger, error) {
	self := &RestoreLedger{
		name:               name,
		root:               root,
		outside:            outside,
		pathBases:          map[string][]byte{},
		pathWrites:         map[string][]*RestoreLedgerWrite{},
		pathHandleContents: map[string][]byte{},
		pathResults:        map[string]string{},
	}
	if outside != "" {
		digest, err := restoreLedgerDigest(outside)
		if err != nil {
			return nil, err
		}
		self.outsideDigest = digest
	}
	return self, nil
}

// Keeps ledger on net, for FI-8 to read until net closes.
func AttachRestoreLedger(net *Net, ledger *RestoreLedger) {
	restoreLedgerLock.Lock()
	defer restoreLedgerLock.Unlock()
	restoreLedgerNets[net] = append(restoreLedgerNets[net], ledger)
	context.AfterFunc(net.Context(), func() {
		restoreLedgerLock.Lock()
		defer restoreLedgerLock.Unlock()
		delete(restoreLedgerNets, net)
	})
}

var (
	restoreLedgerLock sync.Mutex
	restoreLedgerNets = map[*Net][]*RestoreLedger{}
)

func restoreLedgersOf(net *Net) []*RestoreLedger {
	restoreLedgerLock.Lock()
	defer restoreLedgerLock.Unlock()
	return slices.Clone(restoreLedgerNets[net])
}

// Notes path's bytes at the restored run's start; nil for absent.
func (self *RestoreLedger) Base(relative string, content []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pathBases[relative] = bytes.Clone(content)
}

// Notes that writer left content at path; runEdit for a hooked edit of the restored run.
func (self *RestoreLedger) Wrote(writer string, relative string, content []byte, runEdit bool) {
	self.note(relative, &RestoreLedgerWrite{Writer: writer, Content: bytes.Clone(content), RunEdit: runEdit})
}

// Notes that writer deleted path; runEdit for the restored run's hooked edit.
func (self *RestoreLedger) Removed(writer string, relative string, runEdit bool) {
	self.note(relative, &RestoreLedgerWrite{Writer: writer, Absent: true, RunEdit: runEdit})
}

func (self *RestoreLedger) note(relative string, write *RestoreLedgerWrite) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pathWrites[relative] = append(self.pathWrites[relative], write)
}

// Notes that a handle opened at path before the apply now leaves content in its file, wherever that file now is.
func (self *RestoreLedger) WroteThroughHandle(relative string, content []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pathHandleContents[relative] = bytes.Clone(content)
}

// Notes the apply's answer, each path's result, and whether its journal ended.
func (self *RestoreLedger) Applied(pathResults map[string]string, ended bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for relative, result := range pathResults {
		self.pathResults[relative] = result
	}
	self.applyEnded = self.applyEnded || ended
}

// The newest bytes path holds by the ledger, and whether anything but the restored run's hooked edits wrote it.
func (self *RestoreLedger) Newest(relative string) (*RestoreLedgerWrite, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	writes := self.pathWrites[relative]
	if len(writes) == 0 {
		return nil, false
	}
	foreign := slices.ContainsFunc(writes, func(write *RestoreLedgerWrite) bool { return !write.RunEdit })
	return writes[len(writes)-1], foreign
}

// FI-8 now: see the file's header. final adds the end's clause.
func (self *RestoreLedger) Check(final bool) error {
	type pathState struct {
		writes        []*RestoreLedgerWrite
		base          []byte
		baseKnown     bool
		handleContent []byte
		result        string
	}
	pathStates := map[string]*pathState{}
	ended := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for relative, writes := range self.pathWrites {
			pathStates[relative] = &pathState{writes: slices.Clone(writes)}
		}
		for relative := range self.pathHandleContents {
			if _, ok := pathStates[relative]; !ok {
				pathStates[relative] = &pathState{}
			}
		}
		for relative := range self.pathResults {
			if _, ok := pathStates[relative]; !ok {
				pathStates[relative] = &pathState{}
			}
		}
		for relative, state := range pathStates {
			state.base, state.baseKnown = self.pathBases[relative]
			state.handleContent = self.pathHandleContents[relative]
			state.result = self.pathResults[relative]
		}
		ended = self.applyEnded
	}()
	errs := []error{}
	relatives := []string{}
	for relative := range pathStates {
		relatives = append(relatives, relative)
	}
	slices.Sort(relatives)
	for _, relative := range relatives {
		state := pathStates[relative]
		current, absent, err := self.read(relative)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", relative, err))
			continue
		}
		foreign := slices.ContainsFunc(state.writes, func(write *RestoreLedgerWrite) bool { return !write.RunEdit })
		if foreign {
			newest := state.writes[len(state.writes)-1]
			switch {
			case newest.Absent && !absent:
				errs = append(errs, fmt.Errorf("%s: %s deleted it, and it holds %d bytes again", relative, newest.Writer, len(current)))
			case !newest.Absent:
				found, err := self.findBeside(relative, newest.Content)
				if err != nil {
					errs = append(errs, err)
				} else if !found {
					errs = append(errs, fmt.Errorf("%s: %s's newest bytes are lost: neither at the path nor beside it", relative, newest.Writer))
				}
			}
		}
		if state.handleContent != nil {
			found, err := self.findBeside(relative, state.handleContent)
			if err != nil {
				errs = append(errs, err)
			} else if !found {
				errs = append(errs, fmt.Errorf("%s: bytes written through a handle opened before the apply are lost", relative))
			}
		}
		if state.result == restoreLedgerResultRestored && !foreign && state.baseKnown {
			switch {
			case state.base == nil && !absent:
				errs = append(errs, fmt.Errorf("%s: answered restored to absent, and it holds %d bytes", relative, len(current)))
			case state.base != nil && (absent || !bytes.Equal(current, state.base)):
				errs = append(errs, fmt.Errorf("%s: answered restored, and it does not hold its base's bytes", relative))
			}
		}
		if state.baseKnown && state.base != nil {
			copies, err := self.besideNames(relative, restoreLedgerRestoredInfix)
			if err != nil {
				errs = append(errs, err)
			}
			for _, name := range copies {
				content, err := os.ReadFile(filepath.Join(self.root, filepath.FromSlash(name)))
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", name, err))
				} else if !bytes.Equal(content, state.base) {
					errs = append(errs, fmt.Errorf("%s: a restored copy that is not its path's base bytes (RV2)", name))
				}
			}
		}
	}
	if self.outside != "" {
		digest, err := restoreLedgerDigest(self.outside)
		if err != nil {
			errs = append(errs, err)
		} else if !bytes.Equal(digest, self.outsideDigest) {
			errs = append(errs, errors.New("the directory outside the worktree changed"))
		}
	}
	if final && ended {
		hidden, err := self.hiddenNames()
		if err != nil {
			errs = append(errs, err)
		} else if len(hidden) != 0 {
			errs = append(errs, fmt.Errorf("the ended apply left hidden names %v", hidden))
		}
	}
	return errors.Join(errs...)
}

// path's bytes now, or absent where no regular file stands at it: a directory or a symlink there is no file's bytes,
// and neither is a path whose parent is no directory.
func (self *RestoreLedger) read(relative string) ([]byte, bool, error) {
	absolute := filepath.Join(self.root, filepath.FromSlash(relative))
	info, err := os.Lstat(absolute)
	if err != nil {
		var pathErr *fs.PathError
		if errors.Is(err, fs.ErrNotExist) || errors.As(err, &pathErr) {
			return nil, true, nil
		}
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, true, nil
	}
	content, err := os.ReadFile(absolute)
	if err != nil {
		return nil, false, err
	}
	return content, false, nil
}

// Whether content is at path, in one of its conflict copies or under a hidden name of an apply in its directory.
func (self *RestoreLedger) findBeside(relative string, content []byte) (bool, error) {
	current, absent, err := self.read(relative)
	if err != nil {
		return false, err
	}
	if !absent && bytes.Equal(current, content) {
		return true, nil
	}
	names, err := self.besideNames(relative, restoreLedgerConflictInfix)
	if err != nil {
		return false, err
	}
	hidden, err := self.hiddenIn(path.Dir(relative))
	if err != nil {
		return false, err
	}
	for _, name := range append(names, hidden...) {
		candidate, err := os.ReadFile(filepath.Join(self.root, filepath.FromSlash(name)))
		if err != nil {
			continue
		}
		if bytes.Equal(candidate, content) {
			return true, nil
		}
	}
	return false, nil
}

// The names beside path that start with its name and infix, relative to the root.
func (self *RestoreLedger) besideNames(relative string, infix string) ([]string, error) {
	directory := path.Dir(relative)
	entries, err := os.ReadDir(filepath.Join(self.root, filepath.FromSlash(directory)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		// a directory the schedule replaced with a file or a link reads as holding nothing beside
		return nil, nil
	}
	prefix := path.Base(relative) + infix
	names := []string{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			names = append(names, path.Join(directory, entry.Name()))
		}
	}
	return names, nil
}

// The apply's hidden names directly in directory, relative to the root.
func (self *RestoreLedger) hiddenIn(directory string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(self.root, filepath.FromSlash(directory)))
	if err != nil {
		return nil, nil
	}
	names := []string{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), restoreLedgerHiddenPrefix) {
			names = append(names, path.Join(directory, entry.Name()))
		}
	}
	return names, nil
}

// Every hidden name of an apply in the worktree, relative to the root.
func (self *RestoreLedger) hiddenNames() ([]string, error) {
	names := []string{}
	err := filepath.WalkDir(self.root, func(absolute string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() && entry.Name() == restoreLedgerGitDirectory {
			return filepath.SkipDir
		}
		if strings.HasPrefix(entry.Name(), restoreLedgerHiddenPrefix) {
			relative, _ := filepath.Rel(self.root, absolute)
			names = append(names, filepath.ToSlash(relative))
		}
		return nil
	})
	return names, err
}

// SHA-256 over every name, kind and file's bytes under directory, in walk order.
func restoreLedgerDigest(directory string) ([]byte, error) {
	hash := sha256.New()
	err := filepath.WalkDir(directory, func(absolute string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(directory, absolute)
		fmt.Fprintf(hash, "%s %s\n", relative, entry.Type())
		if entry.Type().IsRegular() {
			content, err := os.ReadFile(absolute)
			if err != nil {
				return err
			}
			hash.Write(content)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}
