//go:build !ios_extension && !sidecar_http && !js

// A local agent's workspace (DESIGN-COMPUTE §7.5, R-HARN-4, CO-6, IC-7, D-HARN-13): a temp directory the Harness makes
// for the agent, the OS temp directory on desktops and the app's cache directory on phones (HarnessHost,
// HARN-M11-10), removed when the agent's run ends; what is kept leaves through git push or evs_write.
//
//   - Paths resolve beneath the workspace's root one component at a time without following a link out: the root is an
//     os.Root, which opens each component relative to its parent and refuses a symbolic link that resolves outside, so
//     there is no check-then-open race. Before that, a path is held to its form: `..`, an absolute host path, a drive
//     letter, a UNC path, a colon (an alternate data stream) and every .git component in every spelling git refuses
//     (harness_git_path.go) are refused, each by the component that fails, never by a host path.
//   - The cap (HarnessSettings.WorkspaceDesktopByteCount, WorkspacePhoneByteCount) counts every file beneath the root,
//     the bundled git's worktrees among them, and is checked before a write lands, never after.
//   - Writes to one path go one at a time through the workspace's mutation queue, as Pi's withFileMutationQueue does.
//   - Nothing here starts a process or opens a socket (IC-7).
//
// Safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

var (
	// A path the workspace refuses: its message names the rule, never a host path.
	ErrHarnessWorkspacePath = errors.New("the path is outside the workspace or names .git")
	// A write past the workspace's cap, refused before it landed.
	ErrHarnessWorkspaceFull = errors.New("the write would pass the workspace's cap")
	// The workspace was removed with its run.
	ErrHarnessWorkspaceRemoved = errors.New("the workspace was removed with its run")
)

// What a workspace is made with.
type harnessWorkspaceArgs struct {
	// The directory the workspace is made in: the OS temp directory on desktops, the app's cache directory on phones.
	Parent string
	// The most it may hold, files and worktrees together.
	CapByteCount int64
}

// One agent's workspace.
type harnessWorkspace struct {
	hostPath     string
	root         *os.Root
	capByteCount int64

	stateLock sync.Mutex
	removed   bool
	// the mutation queue: one write at a time per path
	pathLocks map[string]*sync.Mutex
}

// A fresh workspace in args.Parent.
func newHarnessWorkspace(args *harnessWorkspaceArgs) (*harnessWorkspace, error) {
	parent := args.Parent
	if parent == "" {
		parent = os.TempDir()
	}
	hostPath, err := os.MkdirTemp(parent, "ur-harness-")
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(hostPath)
	if err != nil {
		os.RemoveAll(hostPath)
		return nil, err
	}
	return &harnessWorkspace{
		hostPath:     hostPath,
		root:         root,
		capByteCount: args.CapByteCount,
		pathLocks:    map[string]*sync.Mutex{},
	}, nil
}

// The workspace's root on this host, for the bundled git's worktrees, which live beneath it; never shown to a model.
func (self *harnessWorkspace) HostPath() string {
	return self.hostPath
}

// The most it may hold.
func (self *harnessWorkspace) CapByteCount() int64 {
	return self.capByteCount
}

// Removes the workspace and everything in it, as its run ends. Every later use is refused.
func (self *harnessWorkspace) Remove() error {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.removed {
			return false
		}
		self.removed = true
		return true
	}()
	if !first {
		return nil
	}
	self.root.Close()
	return os.RemoveAll(self.hostPath)
}

// Nil while the workspace stands.
func (self *harnessWorkspace) usable() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.removed {
		return ErrHarnessWorkspaceRemoved
	}
	return nil
}

// A path held to its form, as the root names it: its components joined by /, "." for the root itself. Refuses `..`,
// an absolute host path, a drive letter, a UNC path, a colon and every .git spelling, by the rule, never echoing a host
// path. Both / and \ separate components on every host.
func harnessWorkspacePath(name string) (string, error) {
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: a NUL in the path", ErrHarnessWorkspacePath)
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") || strings.HasPrefix(name, "~") {
		return "", fmt.Errorf("%w: an absolute path; paths are relative to the workspace", ErrHarnessWorkspacePath)
	}
	components := strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' })
	kept := []string{}
	for _, component := range components {
		switch {
		case component == ".":
			continue
		case component == "..":
			return "", fmt.Errorf("%w: a .. component", ErrHarnessWorkspacePath)
		case strings.ContainsRune(component, ':'):
			return "", fmt.Errorf("%w: a colon, a drive letter or a stream", ErrHarnessWorkspacePath)
		case harnessGitPathComponent(component):
			return "", fmt.Errorf("%w: a .git component, which only git writes", ErrHarnessWorkspacePath)
		}
		kept = append(kept, component)
	}
	if len(kept) == 0 {
		return ".", nil
	}
	return strings.Join(kept, "/"), nil
}

// The root's name for a held path, in the host's separators.
func harnessWorkspaceHostName(held string) string {
	return filepath.FromSlash(held)
}

// What the workspace holds now, every regular file beneath its root counted, the bundled git's worktrees among them.
func (self *harnessWorkspace) Usage() (int64, error) {
	if err := self.usable(); err != nil {
		return 0, err
	}
	total := int64(0)
	err := fs.WalkDir(self.root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			// a file gone since the listing counts nothing
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total, err
}

// held's mutation lock, the queue a write to it waits in.
func (self *harnessWorkspace) pathLock(held string) *sync.Mutex {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lock, ok := self.pathLocks[held]
	if !ok {
		lock = &sync.Mutex{}
		self.pathLocks[held] = lock
	}
	return lock
}

// Runs mutate with held's mutation lock: one write at a time to a path, in the order they came.
func (self *harnessWorkspace) withMutation(held string, mutate func() error) error {
	lock := self.pathLock(held)
	lock.Lock()
	defer lock.Unlock()
	return mutate()
}

// Opens a file of the workspace to read.
func (self *harnessWorkspace) Open(name string) (*os.File, string, error) {
	if err := self.usable(); err != nil {
		return nil, "", err
	}
	held, err := harnessWorkspacePath(name)
	if err != nil {
		return nil, "", err
	}
	file, err := self.root.Open(harnessWorkspaceHostName(held))
	return file, held, harnessWorkspaceError(err)
}

// The file information of a path of the workspace, following a link that stays inside.
func (self *harnessWorkspace) Stat(name string) (fs.FileInfo, string, error) {
	if err := self.usable(); err != nil {
		return nil, "", err
	}
	held, err := harnessWorkspacePath(name)
	if err != nil {
		return nil, "", err
	}
	info, err := self.root.Stat(harnessWorkspaceHostName(held))
	return info, held, harnessWorkspaceError(err)
}

// The bytes of a file of the workspace, at most limit of them; refuses a larger one.
func (self *harnessWorkspace) ReadFile(name string, limit int64) ([]byte, string, error) {
	file, held, err := self.Open(name)
	if err != nil {
		return nil, held, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, held, harnessWorkspaceError(err)
	}
	if limit < int64(len(data)) {
		return nil, held, fmt.Errorf("%s is larger than %d bytes", held, limit)
	}
	return data, held, nil
}

// Writes data whole to a file of the workspace, making its parents, through the path's mutation queue; the cap is
// checked first, counting what the file holds now as freed, so a write past it never lands.
func (self *harnessWorkspace) WriteFile(name string, data []byte) (string, error) {
	if err := self.usable(); err != nil {
		return "", err
	}
	held, err := harnessWorkspacePath(name)
	if err != nil {
		return "", err
	}
	if held == "." {
		return "", fmt.Errorf("%w: the workspace itself is no file", ErrHarnessWorkspacePath)
	}
	return held, self.withMutation(held, func() error {
		return self.writeWithMutation(held, data)
	})
}

// Writes held with its mutation lock held.
func (self *harnessWorkspace) writeWithMutation(held string, data []byte) error {
	usage, err := self.Usage()
	if err != nil {
		return err
	}
	existing := int64(0)
	if info, err := self.root.Lstat(harnessWorkspaceHostName(held)); err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", held)
		}
		if info.Mode().IsRegular() {
			existing = info.Size()
		}
	}
	if self.capByteCount < usage-existing+int64(len(data)) {
		return fmt.Errorf("%w: %d bytes held, %d asked, %d allowed", ErrHarnessWorkspaceFull, usage-existing,
			len(data), self.capByteCount)
	}
	if parent := path.Dir(held); parent != "." {
		if err := self.root.MkdirAll(harnessWorkspaceHostName(parent), 0o700); err != nil {
			return harnessWorkspaceError(err)
		}
	}
	return harnessWorkspaceError(self.root.WriteFile(harnessWorkspaceHostName(held), data, 0o600))
}

// The entries of a directory of the workspace.
func (self *harnessWorkspace) ReadDir(name string) ([]fs.DirEntry, string, error) {
	if err := self.usable(); err != nil {
		return nil, "", err
	}
	held, err := harnessWorkspacePath(name)
	if err != nil {
		return nil, "", err
	}
	entries, err := fs.ReadDir(self.root.FS(), held)
	return entries, held, harnessWorkspaceError(err)
}

// err with any host path an os error names taken out, so a model never reads where the workspace is.
func harnessWorkspaceError(err error) error {
	if err == nil {
		return nil
	}
	pathError := &fs.PathError{}
	if errors.As(err, &pathError) {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("%w: not found", fs.ErrNotExist)
		case errors.Is(err, fs.ErrPermission):
			return fmt.Errorf("%w: not permitted", fs.ErrPermission)
		}
		return fmt.Errorf("%s: %w", pathError.Op, pathError.Err)
	}
	return err
}
