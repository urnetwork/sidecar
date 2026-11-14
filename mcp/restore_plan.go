//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's dry run (R-MCP-4, D-MCP-8, D-MCP-15, RV1, RV3): Plan reads one run's restore point and the worktree now and
// answers the restorable paths, and every other changed path with its reason, plus a preview_id binding what an apply
// may do:
//
//	restorable  every change of p since its base is this run's attributed edit, the chain unbroken from the base, the
//	            base exact, and p's bytes now the run's last after (restorable(R, p), restore_attribute.go)
//	shell       the same, but some change was shell-attributed to this run: restorable only when the call names p
//	            in paths, and then only as an O action, a decision in any run (§16.7's shell paths row)
//	reasons     foreign, shell, chain-broken, changed-since, not-exact and dropped: a target whose sealed copy an
//	            executed drop removed with its version (§11.7, D-CORE-19), never partly restored (FI-8)
//
// A path whose bytes equal its base has nothing to restore and is left out; named in paths, it is answered unchanged.
//
// preview_id is SHA-256 over the run and each entry in preview order: (path, current kind and hash, target kind,
// mode and hash, and whether it is a shell path), a kind being absent, file or symlink, cut to an id's 16 bytes, the
// width RestoreBody.preview_id has (record_body.go) as §11.13's drop preview_id does. The preview is kept sealed
// in the point under preview/, at most Ingest.RestorePreviewCount of them, so an apply (restore_apply.go) acts on
// exactly what the dry run showed and checks the bytes it displaces against it, never against an earlier read (RV3).
// A dry run only reads the worktree and git; it holds the worktree's apply lock while it plans, so no apply's hidden
// names are read as changes.

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar"
)

// §16.7's dry_run reason for a target an executed drop removed (MCP-M10-01 deletes the local copies with it).
const RestoreReasonDropped = "dropped"

// The preview store's names and format values.
const (
	restorePreviewPrefix    = "preview/"
	restorePreviewIndexName = "previews"
	restorePreviewVersion   = 1
	// the preview_id's domain, so no other hash of the same bytes is one
	restorePreviewIdLabel = "urnetwork-sidecar-v1/restore-preview"
	// a preview_id is an id's width, record.proto's RestoreBody.preview_id
	restorePreviewIdByteCount = len(sidecar.Id{})
)

var (
	// No point for that run was ever written on this device.
	ErrRestorePointUnknown = errors.New("restore point unknown")
	// The preview_id names no preview this point keeps: a dry run comes first, and a removed one is previewed again.
	ErrRestorePreviewUnknown = errors.New("restore preview unknown")
	// A named path that is no path inside the worktree.
	ErrRestorePathInvalid = errors.New("restore path invalid")
)

// One path a preview binds (§16.7's dry_run row): what p is now and what restore would make it.
type RestorePreviewEntry struct {
	// Relative to the worktree's root, with / between segments.
	Path string `json:"path"`
	// Kind and hash at the dry run: absent, file or symlink.
	Current *RestoreFileState `json:"current"`
	// Kind, mode and hash of the base, which restore writes back.
	Target *RestoreFileState `json:"target"`
	// Restorable only as an O action: a change was shell-attributed to the run, and the call named the path.
	Shell bool `json:"shell,omitempty"`
}

// A changed path a dry run leaves out, and why.
type RestoreRefusal struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// A dry run's answer: the preview, kept sealed in the point under its id.
type RestorePlan struct {
	Version int        `json:"version"`
	RunId   sidecar.Id `json:"run_id"`
	// SHA-256 over the run and the entries, an id's 16 bytes of it.
	PreviewId []byte `json:"preview_id"`
	// The daemon's clock at the dry run, Unix milliseconds.
	CreatedMillis int64 `json:"created_millis"`
	// The restorable paths, in preview order, which is by path.
	Entries []*RestorePreviewEntry `json:"entries"`
	// Every other changed path, by path.
	Refusals []*RestoreRefusal `json:"refusals"`
}

// The paths an apply restores only as an O action, sorted: what restore_paths names (§16.8's field 31).
func (self *RestorePlan) ShellPaths() []string {
	paths := []string{}
	for _, entry := range self.Entries {
		if entry.Shell {
			paths = append(paths, entry.Path)
		}
	}
	return paths
}

// Every path the preview restores, in preview order.
func (self *RestorePlan) Paths() []string {
	paths := make([]string, 0, len(self.Entries))
	for _, entry := range self.Entries {
		paths = append(paths, entry.Path)
	}
	return paths
}

// The list of a point's previews, oldest first.
type restorePreviewIndex struct {
	Version    int      `json:"version"`
	PreviewIds []string `json:"preview_ids"`
}

// The point of runId as some process wrote it, loaded, never walked: what run_restore reads, since a dry run of a run
// this device holds no point for has nothing to restore. ErrRestorePointUnknown for none.
func (self *RestorePoints) OpenExisting(ctx context.Context, network McpNetwork, networkId sidecar.Id, runId sidecar.Id) (*RestorePoint, error) {
	if point, ok := self.Point(networkId, runId); ok {
		return point, nil
	}
	if err := self.recoverNetwork(ctx, network, networkId); err != nil {
		return nil, err
	}
	point, err := self.loadPoint(ctx, network, networkId, runId)
	if err != nil {
		return nil, err
	}
	if point == nil {
		return nil, ErrRestorePointUnknown
	}
	return point, nil
}

// The point of runId read from the network's store and published, nil when none was written. A point loaded here has
// its interrupted applies recovered before it is published (restore_journal.go).
func (self *RestorePoints) loadPoint(ctx context.Context, network McpNetwork, networkId sidecar.Id, runId sidecar.Id) (*RestorePoint, error) {
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
		store:     store,
		holds:     map[string]*restoreHold{},
	}
	loaded, err := point.load()
	if err != nil {
		return nil, err
	}
	if !loaded {
		return nil, nil
	}
	if err := point.Recover(ctx); err != nil {
		return nil, err
	}
	key := restorePointKey{networkId: networkId, runId: runId}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if existing, ok := self.points[key]; ok {
		return existing, nil
	}
	self.points[key] = point
	return point, nil
}

// A path a call names, as the point keys it: relative to the root, cleaned, with / between segments. An absolute path
// must lie under the root. ErrRestorePathInvalid for an empty one, one outside the worktree or one of the apply's
// hidden names.
func (self *RestorePoint) namedPath(named string) (string, error) {
	if named == "" || strings.ContainsRune(named, 0) {
		return "", ErrRestorePathInvalid
	}
	relative := self.relativePath(named)
	if filepath.IsAbs(filepath.FromSlash(relative)) || strings.HasPrefix(relative, "/") {
		return "", ErrRestorePathInvalid
	}
	relative = path.Clean(relative)
	if relative == "." || relative == ".." || strings.HasPrefix(relative, "../") || restoreHiddenPath(relative) {
		return "", ErrRestorePathInvalid
	}
	return relative, nil
}

// §16.7's dry run over every changed path the point knows, or over named alone when it is not nil, a named shell path
// then becoming restorable as an O action. The preview is kept in the point under its id.
func (self *RestorePoint) Plan(ctx context.Context, named []string) (*RestorePlan, error) {
	root := self.Root()
	unlock := self.points.lockApply(root)
	defer unlock()
	namedPaths := map[string]bool{}
	for _, text := range named {
		relative, err := self.namedPath(text)
		if err != nil {
			return nil, err
		}
		namedPaths[relative] = true
	}
	candidates := map[string]bool{}
	if named != nil {
		for relative := range namedPaths {
			candidates[relative] = true
		}
	} else {
		for _, path := range self.LedgerPaths() {
			candidates[path] = true
		}
		for _, path := range self.BasePaths() {
			candidates[path] = true
		}
		if root != "" {
			dirty, err := self.statusPaths(ctx)
			if err != nil {
				return nil, err
			}
			for _, path := range dirty {
				candidates[path] = true
			}
		}
	}
	paths := make([]string, 0, len(candidates))
	for path := range candidates {
		// an edit outside the worktree keeps its absolute form, and restore never writes there
		if strings.HasPrefix(path, "/") || filepath.IsAbs(filepath.FromSlash(path)) {
			if namedPaths[path] {
				return nil, ErrRestorePathInvalid
			}
			continue
		}
		paths = append(paths, path)
	}
	slices.Sort(paths)
	symlinks := self.gitSymlinks(ctx)
	plan := &RestorePlan{
		Version:       restorePreviewVersion,
		RunId:         self.runId,
		CreatedMillis: self.points.clock.Now().UnixMilli(),
		Entries:       []*RestorePreviewEntry{},
		Refusals:      []*RestoreRefusal{},
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry, reason, err := self.planPath(ctx, path, namedPaths[path], symlinks)
		if err != nil {
			return nil, err
		}
		switch {
		case entry != nil:
			plan.Entries = append(plan.Entries, entry)
		case reason != "":
			plan.Refusals = append(plan.Refusals, &RestoreRefusal{Path: path, Reason: reason})
		}
	}
	plan.PreviewId = restorePreviewId(self.runId, plan.Entries)
	if err := self.savePreview(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

// Whether git writes symlinks as links in this worktree: core.symlinks, true unless it says false. Where it is false
// git writes a link's text as a file, and restore stages it so (§16.7's stage row).
func (self *RestorePoint) gitSymlinks(ctx context.Context) bool {
	if self.root == "" {
		return true
	}
	value, err := self.points.runGit(ctx, self.root, "config", "--bool", "core.symlinks")
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(value)) != "false"
}

// One path's place in the dry run: an entry, a refusal's reason, or neither for a path with nothing to restore that
// the call did not name.
func (self *RestorePoint) planPath(ctx context.Context, path string, named bool, symlinks bool) (*RestorePreviewEntry, string, error) {
	base, err := self.BaseOf(ctx, path)
	if errors.Is(err, ErrRestoreNoRepository) {
		return nil, RestoreReasonNotExact, nil
	}
	if err != nil {
		return nil, "", err
	}
	current, _, err := self.stateOf(path, false, 0)
	if err != nil {
		return nil, "", err
	}
	if base.State != nil && current.Equal(base.State) {
		if named {
			return nil, RestoreReasonUnchanged, nil
		}
		return nil, "", nil
	}
	shell, reason := self.evaluate(path, base, current)
	if reason != "" {
		return nil, reason, nil
	}
	if shell && !named {
		return nil, RestoreReasonShell, nil
	}
	target := base.State.clone()
	switch target.Kind {
	case RestoreKindSymlink:
		if base.Blob == "" {
			// a link dirty at the walk keeps no text, so there is nothing exact to write back
			return nil, RestoreReasonNotExact, nil
		}
		if !symlinks {
			target.Kind = RestoreKindFile
			target.Mode = restoreModeFile
		}
	case RestoreKindFile:
		if base.Copy != "" {
			present, err := self.copyPresent(base.Copy)
			if err != nil {
				return nil, "", err
			}
			if !present {
				return nil, RestoreReasonDropped, nil
			}
		}
	}
	if current.Kind == RestoreKindOther {
		// a directory or other kind stands at p now, which restore never displaces
		return nil, RestoreReasonChangedSince, nil
	}
	return &RestorePreviewEntry{Path: path, Current: current.clone(), Target: target, Shell: shell}, "", nil
}

// restorable(R, p) with the shell row beside it: "" and whether a shell change is among the run's, else the reason
// the path is not restorable. The base and the state now are the caller's.
func (self *RestorePoint) evaluate(path string, base *RestoreBaseFile, current *RestoreFileState) (bool, string) {
	if !base.Exact || base.HashOnly || base.State == nil || base.State.Kind == RestoreKindOther {
		return false, RestoreReasonNotExact
	}
	scans := []*RestoreObservation{}
	for _, observation := range self.Observations(path) {
		if observation.Kind == RestoreObservationScan {
			scans = append(scans, observation)
		}
	}
	if len(scans) == 0 {
		// the bytes differ from the base and no scan saw the change: nothing attributes it to the run
		return false, RestoreReasonChangedSince
	}
	last := base.State
	shell := false
	foreign := false
	broken := false
	for _, scan := range scans {
		switch scan.Attribution {
		case RestoreAttributionEdit:
		case RestoreAttributionShell:
			shell = true
		default:
			foreign = true
		}
		if scan.RunId != self.runId || !scan.BeforeKnown || !scan.Before.Equal(last) {
			broken = true
		}
		last = scan.After
	}
	switch {
	case foreign:
		return false, RestoreReasonForeign
	case broken:
		return false, RestoreReasonChainBroken
	case !current.Equal(last):
		return false, RestoreReasonChangedSince
	}
	return shell, ""
}

// Whether a sealed copy of the point is still there.
func (self *RestorePoint) copyPresent(name string) (bool, error) {
	entries, err := self.store.List(name)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// SHA-256 over the run and the entries in order, each part length-prefixed, an id's width of it (see the file's
// header).
func restorePreviewId(runId sidecar.Id, entries []*RestorePreviewEntry) []byte {
	hash := sha256.New()
	write := func(part []byte) {
		hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(part))))
		hash.Write(part)
	}
	write([]byte(restorePreviewIdLabel))
	write(runId.Bytes())
	for _, entry := range entries {
		write([]byte(entry.Path))
		write([]byte(entry.Current.Kind))
		write(entry.Current.Sha256)
		write([]byte(entry.Target.Kind))
		write(binary.BigEndian.AppendUint32(nil, entry.Target.Mode))
		write(entry.Target.Sha256)
		shell := byte(0)
		if entry.Shell {
			shell = 1
		}
		write([]byte{shell})
	}
	return hash.Sum(nil)[:restorePreviewIdByteCount]
}

// The preview's file name.
func restorePreviewName(previewId []byte) string {
	return restorePreviewPrefix + hex.EncodeToString(previewId)
}

// Keeps plan under its id, the oldest previews past Ingest.RestorePreviewCount removed. The caller holds the apply
// lock, so previews are written one at a time.
func (self *RestorePoint) savePreview(plan *RestorePlan) error {
	if err := writeRestoreJson(self.store, restorePreviewName(plan.PreviewId), plan); err != nil {
		return err
	}
	index := &restorePreviewIndex{}
	byteCount := self.points.settings.RestoreManifestByteCount
	if _, err := readRestoreJson(self.store, restorePreviewIndexName, index, byteCount); err != nil {
		return err
	}
	id := hex.EncodeToString(plan.PreviewId)
	index.Version = restorePreviewVersion
	index.PreviewIds = append(slices.DeleteFunc(index.PreviewIds, func(other string) bool { return other == id }), id)
	removed := []string{}
	if count := max(self.points.settings.RestorePreviewCount, 1); count < len(index.PreviewIds) {
		removed = slices.Clone(index.PreviewIds[:len(index.PreviewIds)-count])
		index.PreviewIds = index.PreviewIds[len(index.PreviewIds)-count:]
	}
	if err := writeRestoreJson(self.store, restorePreviewIndexName, index); err != nil {
		return err
	}
	errs := []error{}
	for _, old := range removed {
		errs = append(errs, self.store.Remove(restorePreviewPrefix+old))
	}
	return errors.Join(errs...)
}

// The preview kept under previewId, its id checked against its entries. ErrRestorePreviewUnknown for none.
func (self *RestorePoint) Preview(previewId []byte) (*RestorePlan, error) {
	if len(previewId) != restorePreviewIdByteCount {
		return nil, ErrRestorePreviewUnknown
	}
	plan := &RestorePlan{}
	found, err := readRestoreJson(self.store, restorePreviewName(previewId), plan, self.points.settings.RestoreManifestByteCount)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrRestorePreviewUnknown
	}
	if err := checkRestorePlan(plan, self.runId, previewId); err != nil {
		return nil, err
	}
	return plan, nil
}

// Holds a preview read back to what its id binds: its version, its run, and entries that hash to its id, each with
// its states.
func checkRestorePlan(plan *RestorePlan, runId sidecar.Id, previewId []byte) error {
	if plan.Version != restorePreviewVersion || plan.RunId != runId || !bytes.Equal(plan.PreviewId, previewId) {
		return fmt.Errorf("%w: a preview that is not this run's", sidecar.ErrSidecarStoreFailed)
	}
	for _, entry := range plan.Entries {
		if entry == nil || entry.Current == nil || entry.Target == nil {
			return fmt.Errorf("%w: a preview entry with no state", sidecar.ErrSidecarStoreFailed)
		}
	}
	if !bytes.Equal(restorePreviewId(runId, plan.Entries), previewId) {
		return fmt.Errorf("%w: a preview whose entries do not hash to its id", sidecar.ErrSidecarStoreFailed)
	}
	return nil
}
