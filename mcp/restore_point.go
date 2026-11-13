//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's restore points (R-MCP-4, D-MCP-8, D-MCP-15, RV1): local and exact, one per run, under
// <state>/net/<network_id>/restore/<run_id>/ in file class restore, within Ingest.RestorePointByteCount. A point
// holds:
//
//	base      HEAD's commit id and, for every file differing from HEAD at the run's start (modified, staged or
//	          untracked, .gitignore honored, found through `git status --porcelain=v2 -z`), its state and an exact
//	          sealed copy; a file over Ingest.FileByteCount, or past the point's cap, is hash-only; a clean file's
//	          base is HEAD's blob, read when first asked and kept in the manifest
//	start_ns  the walk's start on the OS's clock; a file whose ctime (restore_ctime_*.go) is later when the walk
//	          reaches it has an unknown base, not exact
//	ledger    restore_ledger.go's chain of observations per path
//	holds     restore_hold.go's bytes of each path a PreToolUse names, until its PostToolUse
//
// Every path is relative to the worktree's top level, with / between segments, so the ledger's keys match what git
// reports; a path outside the worktree keeps its absolute form and is never restorable. A worktree that is no git
// repository has no base: its point records edits for the ledger and nothing is restorable. The point reads the
// local copies alone, never the vault's redacted ones (D-MCP-8).
//
// A RestorePoint is safe for concurrent use: stateLock guards its manifest and holds, scanLock orders scans, and
// neither is held across a call out to git or the store. Scans and attribution are restore_attribute.go's.

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// §5.9's directory and file class, and the point's own file names: format values of its local state.
const (
	restoreDirectoryName   = "restore"
	restoreClass           = "restore"
	restoreManifestName    = "manifest"
	restoreLedgerName      = "ledger"
	restoreBaseCopyPrefix  = "base/"
	restoreHoldCopyPrefix  = "hold/"
	restoreManifestVersion = 1
	restoreLedgerVersion   = 1
	// git's modes, as ChangedPath.mode carries them
	restoreModeFile       = 0100644
	restoreModeExecutable = 0100755
	restoreModeSymlink    = 0120000
)

var (
	// The worktree is no git repository, or git is not on PATH: the point has no base.
	ErrRestoreNoRepository = errors.New("restore point has no git repository")
	// A path the point never saw.
	ErrRestorePathUnknown = errors.New("restore path unknown")
)

// What a path is on disk.
type RestoreKind string

const (
	RestoreKindAbsent  RestoreKind = "absent"
	RestoreKindFile    RestoreKind = "file"
	RestoreKindSymlink RestoreKind = "symlink"
	// A directory, device or other kind, which restore never writes.
	RestoreKindOther RestoreKind = "other"
)

// One path's state at one moment: its kind, the SHA-256 of its bytes (a symlink's target), git's mode and its size.
// An absent path has no hash.
type RestoreFileState struct {
	Kind   RestoreKind `json:"kind"`
	Sha256 []byte      `json:"sha256,omitempty"`
	Mode   uint32      `json:"mode,omitempty"`
	Size   int64       `json:"size,omitempty"`
}

// Whether two states are the same bytes and kind. Mode is part of it, since git tracks it.
func (self *RestoreFileState) Equal(other *RestoreFileState) bool {
	if self == nil || other == nil {
		return self == other
	}
	return self.Kind == other.Kind && bytes.Equal(self.Sha256, other.Sha256) && self.Mode == other.Mode
}

// A copy.
func (self *RestoreFileState) clone() *RestoreFileState {
	if self == nil {
		return nil
	}
	cloned := *self
	cloned.Sha256 = bytes.Clone(self.Sha256)
	return &cloned
}

// One path's base (§16.7's base row): its state at the run's start, whether that is exact, and where its bytes are.
type RestoreBaseFile struct {
	State *RestoreFileState `json:"state"`
	// The state is the bytes at the walk, which no later change touched: the ctime was not past start_ns, and the
	// bytes were copied or are HEAD's blob. Not exact: a hash-only file, one changed during the walk, or one whose
	// ctime could not be read.
	Exact bool `json:"exact"`
	// Over the cap: the hash alone was kept.
	HashOnly bool `json:"hash_only,omitempty"`
	// The sealed copy's name in the point, empty for none.
	Copy string `json:"copy,omitempty"`
	// HEAD's blob id for a path clean at the start, whose bytes git holds.
	Blob string `json:"blob,omitempty"`
	// The base was learned from HEAD after the walk, not seen dirty at it.
	FromHead bool `json:"from_head,omitempty"`
}

// The point's manifest file.
type restoreManifest struct {
	Version int `json:"version"`
	// The worktree's top level, as git reports it; empty with no repository.
	Root string `json:"root"`
	// HEAD's commit id at the run's start; empty on an unborn branch or with no repository.
	HeadCommit string `json:"head_commit"`
	NoRepo     bool   `json:"no_repo,omitempty"`
	StartNs    int64  `json:"start_ns"`
	// Copied bytes so far, against Ingest.RestorePointByteCount.
	ByteCount int64 `json:"byte_count"`
	// The next copy's number.
	NextCopy uint64 `json:"next_copy"`
	// Each path's base, by path.
	Files map[string]*RestoreBaseFile `json:"files"`
}

// One run's restore point. See the file's header.
type RestorePoint struct {
	points    *RestorePoints
	networkId sidecar.Id
	runId     sidecar.Id
	// the directory the run works in, and the worktree's top level
	cwd  string
	root string
	// restore/<run_id>/, class restore
	store sidecar.SidecarStore

	// one scan at a time (restore_attribute.go)
	scanLock sync.Mutex

	stateLock sync.Mutex
	manifest  *restoreManifest
	ledger    *restoreLedgerState
	// a scan after a restart or a coverage gap attributes every change foreign
	foreignPending bool
	// by tool_use_id
	holds map[string]*restoreHold
}

// What a restore point needs: the daemon's clock and settings, git, and the OS's clock for ctimes.
type RestorePointsArgs struct {
	Clock  sidecar.Clock
	Ingest *sidecar.SidecarIngestSettings
	Log    sidecar.Logger
	// The git program; empty is "git" on PATH.
	Git string
	// The OS's clock, which file ctimes are compared against: a fake clock cannot stand in for it, since the
	// filesystem stamps real time. Nil is sidecar.RealClock's.
	WallClock func() time.Time
}

// The daemon's restore points: one per (network, run), opened at a run's first event and read by the ledger,
// Ingest's scans and run_restore (MCP-M3-21, MCP-M3-22). Safe for concurrent use.
type RestorePoints struct {
	clock     sidecar.Clock
	settings  *sidecar.SidecarIngestSettings
	log       sidecar.Logger
	git       string
	wallClock func() time.Time

	stateLock sync.Mutex
	points    map[restorePointKey]*RestorePoint
	// every hook's activity by worktree root, for attribution (restore_attribute.go)
	rootActivities map[string][]*restoreActivity
	// the next activity's number: scans and edits are ordered by it, never by the clock
	nextSeq uint64
	// a test seam, called with each path before the base walk reads it
	walkHook func(path string)
	// each worktree's apply lock, by its root (restore_apply.go)
	rootApplyLocks map[string]*sync.Mutex
	// the networks whose interrupted applies this process has recovered (restore_journal.go)
	recoveredNetworkIds map[sidecar.Id]bool
	recoverLock         sync.Mutex
	// the OS calls an apply makes, which a test replaces
	fs *restoreFs
}

// A (network, run) pair.
type restorePointKey struct {
	networkId sidecar.Id
	runId     sidecar.Id
}

// The registry.
func NewRestorePoints(args *RestorePointsArgs) *RestorePoints {
	clock := args.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	log := args.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	git := args.Git
	if git == "" {
		git = "git"
	}
	wallClock := args.WallClock
	if wallClock == nil {
		wallClock = sidecar.RealClock{}.Now
	}
	settings := args.Ingest
	if settings == nil {
		settings = sidecar.DefaultSidecarSettings().Ingest
	}
	return &RestorePoints{
		clock:               clock,
		settings:            settings,
		log:                 log,
		git:                 git,
		wallClock:           wallClock,
		points:              map[restorePointKey]*RestorePoint{},
		rootActivities:      map[string][]*restoreActivity{},
		rootApplyLocks:      map[string]*sync.Mutex{},
		recoveredNetworkIds: map[sidecar.Id]bool{},
		fs:                  defaultRestoreFs(),
	}
}

// The point of a run this process opened, if any.
func (self *RestorePoints) Point(networkId sidecar.Id, runId sidecar.Id) (*RestorePoint, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	point, ok := self.points[restorePointKey{networkId: networkId, runId: runId}]
	return point, ok
}

// The run's point, opened: read from the network's store where one was written, which marks the interval since as
// foreign (a restart), else its base walked now from cwd. An error when the store cannot be used, Locked among the
// reasons.
func (self *RestorePoints) Open(ctx context.Context, network McpNetwork, networkId sidecar.Id, runId sidecar.Id, cwd string) (*RestorePoint, error) {
	key := restorePointKey{networkId: networkId, runId: runId}
	if point, ok := self.Point(networkId, runId); ok {
		return point, nil
	}
	store, err := network.LocalStore().Directory(restoreDirectoryName, restoreClass)
	if err != nil {
		return nil, err
	}
	store, err = store.Directory(runId.String(), "")
	if err != nil {
		return nil, err
	}
	point := &RestorePoint{
		points:    self,
		networkId: networkId,
		runId:     runId,
		cwd:       cwd,
		store:     store,
		holds:     map[string]*restoreHold{},
	}
	// an apply a killed process left in a worktree goes back before anything reads it (restore_journal.go)
	if err := self.recoverNetwork(ctx, network, networkId); err != nil {
		return nil, err
	}
	loaded, err := point.load()
	if err != nil {
		return nil, err
	}
	if !loaded {
		if err := point.walkBase(ctx); err != nil {
			return nil, err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if existing, ok := self.points[key]; ok {
		return existing, nil
	}
	self.points[key] = point
	return point, nil
}

// Drops a run's point from memory and its files from the store: an executed drop's deletion (MCP-M10-01), or a
// test's. Nothing there is not an error.
func (self *RestorePoints) Remove(networkId sidecar.Id, runId sidecar.Id) error {
	point, ok := func() (*RestorePoint, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		key := restorePointKey{networkId: networkId, runId: runId}
		point, ok := self.points[key]
		delete(self.points, key)
		return point, ok
	}()
	if !ok {
		return nil
	}
	entries, err := point.store.List("")
	if err != nil {
		return err
	}
	errs := []error{}
	for _, entry := range entries {
		errs = append(errs, point.store.Remove(entry.Name))
	}
	return errors.Join(errs...)
}

// Runs git in dir with args, answering its stdout. The environment is the daemon's own, with no prompt.
func (self *RestorePoints) runGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, self.git, append([]string{"-C", dir}, args...)...)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
	stdout := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		// git's text can name a path (I-13), so only the exit is kept
		return nil, fmt.Errorf("git %s: %w", args[0], err)
	}
	return stdout.Bytes(), nil
}

// The run's id.
func (self *RestorePoint) RunId() sidecar.Id {
	return self.runId
}

// The worktree's top level, empty with no repository.
func (self *RestorePoint) Root() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.manifest.Root
}

// HEAD's commit id at the run's start.
func (self *RestorePoint) HeadCommit() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.manifest.HeadCommit
}

// The walk's start on the OS's clock.
func (self *RestorePoint) StartNs() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.manifest.StartNs
}

// Reads the manifest and ledger written before, answering whether there were any. A point read this way marks its
// next scan foreign: the interval spans a restart.
func (self *RestorePoint) load() (bool, error) {
	manifest := &restoreManifest{}
	found, err := readRestoreJson(self.store, restoreManifestName, manifest, self.points.settings.RestoreManifestByteCount)
	if err != nil || !found {
		return false, err
	}
	if manifest.Version != restoreManifestVersion {
		return false, fmt.Errorf("%w: restore manifest version %d", sidecar.ErrSidecarStoreFailed, manifest.Version)
	}
	if manifest.Files == nil {
		manifest.Files = map[string]*RestoreBaseFile{}
	}
	ledger := newRestoreLedgerState()
	if _, err := readRestoreJson(self.store, restoreLedgerName, ledger, self.points.settings.RestoreManifestByteCount); err != nil {
		return false, err
	}
	if ledger.Version != restoreLedgerVersion {
		return false, fmt.Errorf("%w: restore ledger version %d", sidecar.ErrSidecarStoreFailed, ledger.Version)
	}
	if ledger.Paths == nil {
		ledger.Paths = map[string][]*RestoreObservation{}
	}
	// a hold lives with the process that took it: one left by the last process is removed, its edit's before
	// unknown, and the point's byte count is its base copies alone again
	held, err := self.store.List(restoreHoldCopyPrefix)
	if err != nil {
		return false, err
	}
	for _, entry := range held {
		if err := self.store.Remove(entry.Name); err != nil {
			return false, err
		}
	}
	manifest.ByteCount = 0
	for _, file := range manifest.Files {
		if file.Copy != "" && file.State != nil {
			manifest.ByteCount += file.State.Size
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.manifest = manifest
	self.root = manifest.Root
	self.ledger = ledger
	self.foreignPending = true
	return true, nil
}

// A JSON file of the point of at most byteCount bytes, false when absent.
func readRestoreJson(store sidecar.SidecarStore, name string, value any, byteCount int64) (bool, error) {
	reader, err := store.Open(name)
	if errors.Is(err, sidecar.ErrSidecarStoreAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(io.LimitReader(reader, byteCount+1))
	if err != nil {
		return false, err
	}
	if byteCount < int64(len(encoded)) {
		return false, fmt.Errorf("%w: a restore file past its bound", sidecar.ErrSidecarStoreFailed)
	}
	if err := json.Unmarshal(encoded, value); err != nil {
		return false, fmt.Errorf("%w: a restore file that does not parse", sidecar.ErrSidecarStoreFailed)
	}
	return true, nil
}

// Writes a JSON file of the point whole, fsynced.
func writeRestoreJson(store sidecar.SidecarStore, name string, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeRestoreBytes(store, name, encoded)
}

// Writes a file of the point whole, fsynced.
func writeRestoreBytes(store sidecar.SidecarStore, name string, content []byte) error {
	writer, err := store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// Writes the manifest as it stands.
func (self *RestorePoint) saveManifest() error {
	manifest := func() *restoreManifest {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.manifest
	}()
	return writeRestoreJson(self.store, restoreManifestName, manifest)
}

// §16.7's base row: HEAD's id, then every dirty path's state and copy, with start_ns taken before the first.
func (self *RestorePoint) walkBase(ctx context.Context) error {
	manifest := &restoreManifest{
		Version: restoreManifestVersion,
		Files:   map[string]*RestoreBaseFile{},
	}
	root, err := self.points.runGit(ctx, self.cwd, "rev-parse", "--show-toplevel")
	if err != nil {
		manifest.NoRepo = true
	} else {
		manifest.Root = filepath.Clean(strings.TrimRight(string(root), "\r\n"))
		if head, err := self.points.runGit(ctx, manifest.Root, "rev-parse", "--verify", "HEAD"); err == nil {
			manifest.HeadCommit = strings.TrimSpace(string(head))
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.manifest = manifest
		self.root = manifest.Root
		self.ledger = newRestoreLedgerState()
	}()
	if manifest.NoRepo {
		return self.saveAll()
	}
	manifest.StartNs = self.points.wallClock().UnixNano()
	dirty, err := self.statusPaths(ctx)
	if err != nil {
		return err
	}
	for _, path := range dirty {
		if err := ctx.Err(); err != nil {
			return err
		}
		if hook := self.points.walkHook; hook != nil {
			hook(path)
		}
		file, err := self.baseFileNow(path, manifest.StartNs)
		if err != nil {
			return err
		}
		manifest.Files[path] = file
	}
	return self.saveAll()
}

// Both files, the manifest last.
func (self *RestorePoint) saveAll() error {
	if err := self.saveLedger(); err != nil {
		return err
	}
	return self.saveManifest()
}

// The paths `git status --porcelain=v2 -z` names, each relative to the root with / between segments, a rename's
// old name among them: every file that differs from HEAD, .gitignore honored.
func (self *RestorePoint) statusPaths(ctx context.Context) ([]string, error) {
	output, err := self.points.runGit(ctx, self.root, "status", "--porcelain=v2", "-z", "--untracked-files=all", "--no-renames")
	if err != nil {
		return nil, err
	}
	// an apply's own hidden names, staged or moved aside for the moment, are no change of the worktree's
	paths := restoreStatusPaths(output)
	return slices.DeleteFunc(paths, restoreHiddenPath), nil
}

// The paths of a porcelain v2 listing with NUL terminators: ordinary and unmerged entries carry the path last,
// after eight or ten fields; a rename entry's new path is followed by its old one in the next record; an
// untracked or ignored entry is "? path". A rename record is only read where --no-renames is off.
func restoreStatusPaths(output []byte) []string {
	paths := []string{}
	records := bytes.Split(output, []byte{0})
	seen := map[string]bool{}
	add := func(path string) {
		if path != "" && !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	for i := 0; i < len(records); i += 1 {
		record := string(records[i])
		if record == "" {
			continue
		}
		switch record[0] {
		case '1':
			if fields := strings.SplitN(record, " ", 9); len(fields) == 9 {
				add(fields[8])
			}
		case '2':
			if fields := strings.SplitN(record, " ", 10); len(fields) == 10 {
				add(fields[9])
				if i+1 < len(records) {
					i += 1
					add(string(records[i]))
				}
			}
		case 'u':
			if fields := strings.SplitN(record, " ", 11); len(fields) == 11 {
				add(fields[10])
			}
		case '?', '!':
			if len(record) > 2 {
				add(record[2:])
			}
		}
	}
	return paths
}

// path on disk, relative paths under the root.
func (self *RestorePoint) absolutePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(self.root, filepath.FromSlash(path))
}

// A path as the point keys it: relative to the root with / between segments, or absolute for one outside it.
func (self *RestorePoint) relativePath(path string) string {
	if path == "" {
		return path
	}
	// root is set once, at load or the walk, before the point is shared
	root := self.root
	if root == "" || !filepath.IsAbs(path) {
		return filepath.ToSlash(path)
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(relative)
}

// A file's current state, and its bytes where it is a file of at most byteCount and bytes are wanted. The hash
// covers the whole file whatever the cap. Nil bytes with an absent, symlink or other kind.
func (self *RestorePoint) stateOf(path string, wantBytes bool, byteCount int64) (*RestoreFileState, []byte, error) {
	return restoreStateOf(self.absolutePath(path), wantBytes, byteCount)
}

// A path's state on disk, as stateOf reads it, with the file's info for the walk.
func restoreStateOf(absolute string, wantBytes bool, byteCount int64) (*RestoreFileState, []byte, error) {
	state, content, _, err := restoreStateAndInfo(absolute, wantBytes, byteCount)
	return state, content, err
}

func restoreStateAndInfo(absolute string, wantBytes bool, byteCount int64) (*RestoreFileState, []byte, os.FileInfo, error) {
	info, err := os.Lstat(absolute)
	if errors.Is(err, os.ErrNotExist) {
		return &RestoreFileState{Kind: RestoreKindAbsent}, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("a path could not be read: %w", errRestoreIo)
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(absolute)
		if err != nil {
			return nil, nil, info, fmt.Errorf("a link could not be read: %w", errRestoreIo)
		}
		sum := sha256.Sum256([]byte(target))
		return &RestoreFileState{Kind: RestoreKindSymlink, Sha256: sum[:], Mode: restoreModeSymlink, Size: int64(len(target))}, nil, info, nil
	case !info.Mode().IsRegular():
		return &RestoreFileState{Kind: RestoreKindOther}, nil, info, nil
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, nil, info, fmt.Errorf("a file could not be opened: %w", errRestoreIo)
	}
	defer file.Close()
	hash := sha256.New()
	var content []byte
	size := int64(0)
	if wantBytes && info.Size() <= byteCount {
		content, err = io.ReadAll(io.LimitReader(file, byteCount+1))
		if err != nil {
			return nil, nil, info, fmt.Errorf("a file could not be read: %w", errRestoreIo)
		}
		if byteCount < int64(len(content)) {
			// grown past the cap since the stat: hash the rest without keeping it
			hash.Write(content)
			size = int64(len(content))
			content = nil
			rest, err := io.Copy(hash, file)
			if err != nil {
				return nil, nil, info, fmt.Errorf("a file could not be read: %w", errRestoreIo)
			}
			size += rest
		} else {
			hash.Write(content)
			size = int64(len(content))
		}
	} else {
		size, err = io.Copy(hash, file)
		if err != nil {
			return nil, nil, info, fmt.Errorf("a file could not be read: %w", errRestoreIo)
		}
	}
	mode := uint32(restoreModeFile)
	if info.Mode()&0111 != 0 {
		mode = restoreModeExecutable
	}
	return &RestoreFileState{Kind: RestoreKindFile, Sha256: hash.Sum(nil), Mode: mode, Size: size}, content, info, nil
}

// An I/O error on a path, with no path in it.
var errRestoreIo = errors.New("restore io")

// One dirty path's base at the walk: its state now, copied sealed when within the caps, exact when its ctime is not
// past startNs and its bytes are kept.
func (self *RestorePoint) baseFileNow(path string, startNs int64) (*RestoreBaseFile, error) {
	state, content, info, err := restoreStateAndInfo(self.absolutePath(path), true, self.points.settings.FileByteCount)
	if err != nil {
		return nil, err
	}
	file := &RestoreBaseFile{State: state}
	switch state.Kind {
	case RestoreKindAbsent:
		// a deletion since HEAD: an absent base is exact
		file.Exact = true
		return file, nil
	case RestoreKindOther:
		return file, nil
	}
	changeNs, known := restoreChangeTimeNs(info)
	if !known || startNs < changeNs {
		file.Exact = false
	} else {
		file.Exact = true
	}
	if state.Kind == RestoreKindSymlink {
		return file, nil
	}
	if content == nil {
		file.HashOnly = true
		file.Exact = false
		return file, nil
	}
	copied, name, err := self.copyBytes(restoreBaseCopyPrefix, content)
	if err != nil {
		return nil, err
	}
	if !copied {
		file.HashOnly = true
		file.Exact = false
		return file, nil
	}
	file.Copy = name
	return file, nil
}

// Seals content into the point under prefix, within the point's cap: false, and nothing written, past it.
func (self *RestorePoint) copyBytes(prefix string, content []byte) (bool, string, error) {
	name, ok := func() (string, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.points.settings.RestorePointByteCount < self.manifest.ByteCount+int64(len(content)) {
			return "", false
		}
		self.manifest.ByteCount += int64(len(content))
		name := prefix + strconv.FormatUint(self.manifest.NextCopy, 10)
		self.manifest.NextCopy += 1
		return name, true
	}()
	if !ok {
		return false, "", nil
	}
	if err := writeRestoreBytes(self.store, name, content); err != nil {
		return false, "", err
	}
	return true, name, nil
}

// The sealed bytes of a copy the point holds, by its name.
func (self *RestorePoint) readCopy(name string) ([]byte, error) {
	reader, err := self.store.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, self.points.settings.FileByteCount+1))
	if err != nil {
		return nil, err
	}
	if self.points.settings.FileByteCount < int64(len(content)) {
		return nil, fmt.Errorf("%w: a copy past the cap", sidecar.ErrSidecarStoreFailed)
	}
	return content, nil
}

// A path's base: what the walk saw, or, for a path clean at the start, its blob in the commit HEAD named then,
// learned from git when first asked and kept. A path that commit never held has an absent base, exact unless
// .gitignore hides the path. ErrRestoreNoRepository with no repository.
func (self *RestorePoint) BaseOf(ctx context.Context, path string) (*RestoreBaseFile, error) {
	path = self.relativePath(path)
	file, noRepo := func() (*RestoreBaseFile, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.manifest.Files[path], self.manifest.NoRepo
	}()
	if file != nil {
		return file, nil
	}
	if noRepo {
		return nil, ErrRestoreNoRepository
	}
	if filepath.IsAbs(path) {
		// outside the worktree: nothing to restore from
		file = &RestoreBaseFile{State: &RestoreFileState{Kind: RestoreKindOther}}
	} else {
		learned, err := self.headBase(ctx, path)
		if err != nil {
			return nil, err
		}
		file = learned
	}
	self.stateLock.Lock()
	if existing, ok := self.manifest.Files[path]; ok {
		self.stateLock.Unlock()
		return existing, nil
	}
	self.manifest.Files[path] = file
	self.stateLock.Unlock()
	return file, self.saveManifest()
}

// A clean path's base from the commit HEAD named at the run's start, never the index or a later HEAD, which a
// `git add` or a commit during the run moves: `git ls-tree` names its blob and mode there, and `git cat-file blob`
// its bytes, hashed here. A path that commit does not hold was untracked, so the walk would have copied it had it
// existed, unless .gitignore hides it: an ignored path's start is unknown, so its base is not exact. A tree or a
// submodule there is another kind, never restored.
func (self *RestorePoint) headBase(ctx context.Context, path string) (*RestoreBaseFile, error) {
	absent := func() (*RestoreBaseFile, error) {
		ignored, err := self.points.gitIgnores(ctx, self.root, path)
		if err != nil {
			return nil, err
		}
		// an ignored path may have held bytes the walk never saw
		return &RestoreBaseFile{State: &RestoreFileState{Kind: RestoreKindAbsent}, Exact: !ignored, FromHead: true}, nil
	}
	head := self.HeadCommit()
	if head == "" {
		// an unborn branch: every indexed or untracked file was dirty at the walk
		return absent()
	}
	listing, err := self.points.runGit(ctx, self.root, "ls-tree", "-z", head, "--", path)
	if err != nil {
		return nil, err
	}
	entry := string(bytes.TrimRight(listing, "\x00"))
	if entry == "" {
		return absent()
	}
	header, name, found := strings.Cut(entry, "\t")
	fields := strings.Fields(header)
	if !found || len(fields) != 3 || strings.ContainsRune(name, 0) {
		return nil, fmt.Errorf("%w: ls-tree", ErrRestoreNoRepository)
	}
	mode, err := strconv.ParseUint(fields[0], 8, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: ls-tree mode", ErrRestoreNoRepository)
	}
	if fields[1] != "blob" || name != path {
		return &RestoreBaseFile{State: &RestoreFileState{Kind: RestoreKindOther}, FromHead: true}, nil
	}
	blob := fields[2]
	content, err := self.points.runGit(ctx, self.root, "cat-file", "blob", blob)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	kind := RestoreKindFile
	if uint32(mode) == restoreModeSymlink {
		kind = RestoreKindSymlink
	}
	return &RestoreBaseFile{
		State:    &RestoreFileState{Kind: kind, Sha256: sum[:], Mode: uint32(mode), Size: int64(len(content))},
		Exact:    true,
		Blob:     blob,
		FromHead: true,
	}, nil
}

// Whether .gitignore hides path in the worktree at root: `git check-ignore -q` exits 0 for an ignored path and 1
// for one that is not.
func (self *RestorePoints) gitIgnores(ctx context.Context, root string, path string) (bool, error) {
	_, err := self.runGit(ctx, root, "check-ignore", "-q", "--", path)
	if err == nil {
		return true, nil
	}
	exit := &exec.ExitError{}
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

// The exact bytes a path had at the run's start: the point's sealed copy, or HEAD's blob, for the apply (MCP-M3-21).
// Refused for a base that is not exact, which RV2 forbids writing.
func (self *RestorePoint) BaseBytes(ctx context.Context, path string) ([]byte, error) {
	file, err := self.BaseOf(ctx, path)
	if err != nil {
		return nil, err
	}
	if !file.Exact || file.State.Kind != RestoreKindFile {
		return nil, fmt.Errorf("%w: not exact", ErrRestorePathUnknown)
	}
	if file.Copy != "" {
		return self.readCopy(file.Copy)
	}
	if file.Blob != "" {
		return self.points.runGit(ctx, self.root, "cat-file", "blob", file.Blob)
	}
	return nil, fmt.Errorf("%w: no bytes", ErrRestorePathUnknown)
}

// Every path the point knows a base for, sorted: those dirty at the start, and those asked about since.
func (self *RestorePoint) BasePaths() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	paths := make([]string, 0, len(self.manifest.Files))
	for path := range self.manifest.Files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

// Hex of a hash, for names and errors that carry no path.
func restoreHex(sum []byte) string {
	return hex.EncodeToString(sum)
}
