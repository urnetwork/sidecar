//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// Imports (DESIGN-DETAILS 8.2.6; QD-603, QD-604): `ur evs import <dir> [<ref>]` brings history whose committers are
// not this sidecar's into a ref of a mounted repo. A repo admin's device runs it, by the daemon itself and not through
// the hook, and it ends as ordinary descending pushes, each carrying its own EvsImport over its own commits.
//
//	refuse   a sha256 <dir>; a caller that is no repo admin at its newest verified state; a target that is a shared
//	         ref with a tip this import did not put there, an owned ref of another sidecar, or a ref under
//	         ur/<this sidecar>/import/; a source tip that does not descend from an owned target's own, without force
//	fetch    git fetch --no-tags <dir> <ref>:refs/ur/import/<id> into the bare repository, with no fsck
//	record   local/<repo>/import/<id>, EvsImportRecord {dir, ref, source tip, target, cuts, force, helpers},
//	         rewritten whole and durable before a helper's first push; a rerun of the command resumes it
//	run      the target brought to the source tip by cut pushes along the tip's first-parent line past what evs's
//	         tips hold, a step at a time, step j what c_j brings that c_(j-1) and evs's other tips do not hold:
//	         before a step, a push that
//	         would pass ImportPushPartCount by ImportCommitEstimate is cut before it; after a step, a push past it
//	         or a step ending at one of cuts is cut after it; each cut published (EvsLocalPublish, Import) under the
//	         ref's publish lock alone and replayed before the next is built
//	split    a step past ImportStepPartCount alone is never sent: the push before it is cut, and the parent of its
//	         merge that alone brings the most, own(q) counted against refs/ur/evs/* and never local refs, gets a
//	         helper ref ur/<sidecar_id>/import/<id>/<n>, brought to q by the same run, nested to ImportHelperDepth
//	         and at most ImportHelperCount; then the step is taken again, its push naming the helpers as sources by
//	         8.2.3's ordinary rule. A step of one commit, or whose parents bring nothing, stops the import naming
//	         the commit, as past either bound
//	clean    once the target is at the source tip, every helper deleted by a DELETE push, the most deeply nested
//	         first, a helper evs shows deleted already skipped; then refs/ur/import/<id> and the record go
//	resume   a helper is found by its (merge, parent) pair, never its number: one done returns at once, one open
//	         goes on from its own tip, one whose ref was deleted while open is abandoned and its pair numbered again
//	abandon  `--abandon` runs clean, drops refs/ur/import/<id> and the record, and leaves the target at its cut
//	status   each unfinished import with its target, the cut reached and its helpers; each helper ref of this
//	         sidecar no record names, which its owner removes with git push --delete (ur status)
//
// The import holds one publish lock at a time, P_d around each push to d and no longer, so a sub-import runs with no
// lock of the ref above it held (8.2.9's order). Replay, settle and the ref locks are the sync engine's (EVS1-M2-35),
// reached through EvsGitSync; until a sync engine is registered with the mount registry, Import refuses. A push that
// carries no commit, its tip held through its sources, signs no EvsImport. Not built here: the journal's kind-3
// entries for an import's pushes (EVS1-M2-36); the push-size bounds that need content sizes or a measured upload
// rate, ImportPushByteCount, ImportPostTime, ImportStepPostTime and ImportStepUploadTime, the commit-count estimate
// bounding every cut and step meanwhile; and the hard bound on a step needing more than 16 sources, which the
// publish's carried set meets by carrying past the sixteenth rather than refusing.
//
// Desktop legs only. One import of a mount runs at a time; not safe for concurrent use beyond that.

package sidecar

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// An import refused before anything is fetched or sent: a sha256 repository, a caller that is no repo admin, a
	// target it may not write, or a source that does not descend from the target without force.
	ErrEvsImportRefused = errors.New("evs: import refused")
	// A first-parent step no helper can bring within a push's bounds (DESIGN-DETAILS 8.2.6's hard bounds): stopped
	// before any evs write for the step, naming the commit and the bound. What the import brought stays.
	ErrEvsImportStepBound = errors.New("evs: an import step past a push's bounds")
)

// The ref prefix in a mount's bare repository at which an import keeps its source tip (8.2.2).
const evsLocalImportRefPrefix = evsLocalDaemonRefPrefix + "/import/"

// A helper ref's states in its import's record.
const (
	EvsImportHelperOpen      = "open"
	EvsImportHelperDone      = "done"
	EvsImportHelperAbandoned = "abandoned"
	EvsImportHelperDeleted   = "deleted"
)

// What the local tier's sync engine (EVS1-M2-35) gives an import, the receive path and an owned ref's queue: replay's
// state, replay itself with settle, and the publish lock (DESIGN-DETAILS 8.2.7, 8.2.9).
type EvsGitSync interface {
	EvsGitSourceState
	// The ref as replay applied it, read under its apply lock (EvsGitRef): version 0 for a ref never applied.
	Ref(ctx context.Context, refId Id) (*EvsGitRefState, error)
	// Replays the ref to its head and settles it, so a version this device's push committed is applied (8.2.5's 200
	// row): its tips log, its refs/ur/evs/ tip and its local ref then hold it.
	Replay(ctx context.Context, refId Id) error
	// Takes the ref's publish lock, P_r, which one device's pushes to one ref hold in turn; the answer releases it.
	LockPublish(ctx context.Context, refId Id) (func(), error)
}

// A ref as replay applied it (8.2.2's ref row).
type EvsGitRefState struct {
	Version uint64
	Chain   [32]byte
	// Its tip, nil for none; a deleted ref's last tip, nil for none.
	Tip     *EvsGitOid
	LastTip *EvsGitOid
	Deleted bool
	// An overlay's base, nil for none.
	Base *protocol.EvsOverlay
}

// An import's record (8.2.2's import row): its arguments and its helper refs, so a rerun resumes it. Oids are hex.
type EvsImportRecord struct {
	ImportId  string   `json:"import_id"`
	Dir       string   `json:"dir"`
	SourceRef string   `json:"source_ref"`
	SourceTip string   `json:"source_tip"`
	Target    []byte   `json:"target"`
	Cuts      []string `json:"cuts,omitempty"`
	Force     bool     `json:"force,omitempty"`
	// In the order first needed.
	Helpers []*EvsImportHelper `json:"helpers,omitempty"`
}

// One helper ref of an import (8.2.6): ur/<sidecar_id>/import/<id>/<n>, found by its (merge, parent) pair.
type EvsImportHelper struct {
	N uint32 `json:"n"`
	// The merge whose step was oversized and the parent the helper brings.
	Merge  string `json:"merge"`
	Parent string `json:"parent"`
	// The helper the merge is on, 0 for the target, and how deeply this one nests, from 1.
	Under uint32 `json:"under,omitempty"`
	Depth int    `json:"depth"`
	State string `json:"state"`
}

// What `ur status` reads of a mount's imports (8.2.6): each unfinished import, and each helper ref of this sidecar no
// record names.
type EvsImportStatus struct {
	Unfinished []*EvsUnfinishedImport
	Leftover   [][]byte
}

// An import that did not finish.
type EvsUnfinishedImport struct {
	ImportId EvsImportId
	Dir      string
	Target   []byte
	// The target's tip as replayed, nil for none.
	Reached *EvsGitOid
	// Its helper refs not yet deleted.
	Helpers [][]byte
}

// A test's hook at each of an import's kill points, nil outside tests: an error stops the import there, as a kill
// would, with what it wrote kept.
var evsImportKillHook func(point string) error

// Registers the sync engine imports run through (EVS1-M2-35's); nil removes it.
func (self *EvsMounts) SetSync(sync EvsGitSync) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sync = sync
}

// The registered sync engine, nil for none.
func (self *EvsMounts) gitSync() EvsGitSync {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sync
}

// EvsRepo.Import on a desktop leg: see the file header.
func (self *EvsMounts) importRepo(ctx context.Context, repo *EvsRepo, args *EvsImportArgs) (*EvsImportResult, error) {
	mount, ok := self.Get(repo.repoId)
	if !ok {
		return nil, fmt.Errorf("%w: an import into a repo no mount serves", ErrEvsImportRefused)
	}
	sync := self.gitSync()
	if sync == nil {
		return nil, fmt.Errorf("%w: an import runs through the sync engine (EVS1-M2-35)", ErrEvsNotBuilt)
	}
	importer := &evsImporter{
		mount: mount, repo: repo, sync: sync, settings: repo.client.settings, store: repo.client.args.Store,
		sidecarId: repo.client.args.Identity().SidecarId,
	}
	return importer.importRepo(ctx, args)
}

// One import's run.
type evsImporter struct {
	mount     *EvsLocalRepo
	repo      *EvsRepo
	sync      EvsGitSync
	settings  *EvsSettings
	store     SidecarStore
	sidecarId Id

	importId EvsImportId
	record   *EvsImportRecord
	objects  *EvsLocalObjects
	result   *EvsImportResult
}

// See the file header.
func (self *evsImporter) importRepo(ctx context.Context, args *EvsImportArgs) (*EvsImportResult, error) {
	target := args.Target
	if target == nil {
		target = EvsMainRefName
	}
	sourceRef := args.Ref
	if sourceRef == "" {
		sourceRef = "HEAD"
	}
	if !filepath.IsAbs(args.Dir) {
		return nil, fmt.Errorf("%w: a repository by a relative path", ErrEvsImportRefused)
	}
	records, err := self.records()
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.Dir == args.Dir && record.SourceRef == sourceRef && string(record.Target) == string(target) {
			self.record = record
		}
	}
	if args.Abandon {
		if self.record == nil {
			return nil, fmt.Errorf("%w: no unfinished import of that repository into that ref", ErrEvsImportRefused)
		}
		if err := self.open(ctx); err != nil {
			return nil, err
		}
		defer self.objects.Close()
		return self.result, self.abandon(ctx)
	}
	if err := self.checkAdmin(); err != nil {
		return nil, err
	}
	if self.record == nil {
		if err := self.begin(ctx, args, sourceRef, target); err != nil {
			return nil, err
		}
	}
	if err := self.open(ctx); err != nil {
		return nil, err
	}
	defer self.objects.Close()
	sourceTip, err := evsGitOidDecodeHex([]byte(self.record.SourceTip))
	if err != nil {
		return nil, fmt.Errorf("%w: an import record's source tip", ErrEvsMirrorObjectInvalid)
	}
	cuts := []EvsGitOid{}
	for _, text := range self.record.Cuts {
		cut, err := evsGitOidDecodeHex([]byte(text))
		if err != nil {
			return nil, fmt.Errorf("%w: an import record's cut", ErrEvsMirrorObjectInvalid)
		}
		cuts = append(cuts, cut)
	}
	if err := self.run(ctx, self.record.Target, sourceTip, cuts, 0, 0); err != nil {
		return self.result, err
	}
	if err := self.clean(ctx); err != nil {
		return self.result, err
	}
	targetId, err := self.repo.resolveRefId(ctx, self.record.Target, nil)
	if err != nil {
		return self.result, err
	}
	state, err := self.sync.Ref(ctx, targetId)
	if err != nil {
		return self.result, err
	}
	if state.Tip != nil {
		self.result.Tip = *state.Tip
	}
	return self.result, self.finish(ctx)
}

// Opens the bare repository's object reader and the result.
func (self *evsImporter) open(ctx context.Context) error {
	importId, err := ParseEvsImportId(self.record.ImportId)
	if err != nil {
		return err
	}
	self.importId = importId
	self.result = &EvsImportResult{ImportId: importId}
	objects, err := self.mount.Objects(ctx)
	if err != nil {
		return err
	}
	self.objects = objects
	return nil
}

// The caller is a repo admin at its newest verified state.
func (self *evsImporter) checkAdmin() error {
	state, err := self.repo.client.verifier.config()
	if err != nil {
		return err
	}
	repo := state.Repo(self.repo.repoId)
	if repo == nil || !evsRepoAdmin(state, repo, self.sidecarId) {
		return fmt.Errorf("%w: this sidecar is no admin of the repo", ErrEvsImportRefused)
	}
	return nil
}

// A new import's refusals, its fetch and its record.
func (self *evsImporter) begin(ctx context.Context, args *EvsImportArgs, sourceRef string, target []byte) error {
	format, err := self.mount.git.Run(ctx, args.Dir, "rev-parse", "--show-object-format")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(format)) != "sha1" {
		return fmt.Errorf("%w: a %s repository (plan-EVS1-format-bytes#4)", ErrEvsImportRefused, strings.TrimSpace(string(format)))
	}
	if _, _, _, ok := ParseEvsImportHelperRefName(target); ok {
		return fmt.Errorf("%w: a target under ur/<sidecar>/import/", ErrEvsImportRefused)
	}
	owned := false
	if ownerId, ok := EvsOwnedRefOwner(target); ok {
		if ownerId != self.sidecarId {
			return fmt.Errorf("%w: another sidecar's owned ref", ErrEvsImportRefused)
		}
		owned = true
	}
	if bytes := target; len(bytes) == 0 || strings.HasPrefix(string(bytes), evsGitTagRefPrefix) {
		return fmt.Errorf("%w: a tag or empty target", ErrEvsImportRefused)
	}
	targetId, err := self.repo.resolveRefId(ctx, target, nil)
	if err != nil {
		return err
	}
	state, err := self.sync.Ref(ctx, targetId)
	if err != nil {
		return err
	}
	if !owned && state.Tip != nil {
		return fmt.Errorf("%w: a shared ref with a tip this import did not put there", ErrEvsImportRefused)
	}
	importId := NewEvsImportId()
	sourceTipRef := evsLocalImportRefPrefix + importId.String()
	if _, err := self.mount.Git(ctx, "fetch", "--no-tags", "--quiet", args.Dir, "+"+sourceRef+":"+sourceTipRef); err != nil {
		return err
	}
	out, err := self.mount.Git(ctx, "rev-parse", "--verify", sourceTipRef+"^{commit}")
	if err != nil {
		return err
	}
	sourceTip, err := evsGitOidDecodeHex([]byte(strings.TrimSpace(string(out))))
	if err != nil {
		return fmt.Errorf("%w: rev-parse answered no oid", ErrEvsGitFailed)
	}
	if state.Tip != nil && !args.Force {
		descends, err := self.mount.reachedBy(ctx, *state.Tip, []EvsGitOid{sourceTip})
		if err != nil {
			return err
		}
		if !descends {
			self.mount.Git(ctx, "update-ref", "-d", sourceTipRef)
			return fmt.Errorf("%w: a source tip that does not descend from the target's, without force", ErrEvsImportRefused)
		}
	}
	self.record = &EvsImportRecord{
		ImportId: importId.String(), Dir: args.Dir, SourceRef: sourceRef, SourceTip: hex.EncodeToString(sourceTip[:]),
		Target: target, Force: args.Force,
	}
	for _, cut := range args.Cuts {
		self.record.Cuts = append(self.record.Cuts, hex.EncodeToString(cut[:]))
	}
	return self.write()
}

// Brings the ref of name to tip by cut pushes (the file header's run), nesting helpers at depth, under the helper
// numbered under, 0 for the target.
func (self *evsImporter) run(ctx context.Context, name []byte, tip EvsGitOid, cuts []EvsGitOid, depth int, under uint32) error {
	refId, err := self.repo.resolveRefId(ctx, name, nil)
	if err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, err := self.sync.Ref(ctx, refId)
		if err != nil {
			return err
		}
		var at *EvsGitOid
		if state.Tip != nil {
			peeled, _, err := evsGitPeel(ctx, self.objects, *state.Tip)
			if err != nil {
				return err
			}
			if peeled == tip {
				return nil
			}
			at = &peeled
		}
		cut, err := self.nextCut(ctx, name, at, tip, cuts, depth, under)
		if err != nil {
			return err
		}
		if cut == nil {
			// a split brought helpers in: the step is taken again
			continue
		}
		if err := self.publish(ctx, name, refId, cut); err != nil {
			return err
		}
		point := "step_sent"
		if under != 0 || depth != 0 {
			point = "helper_pushed"
		}
		if err := self.kill(point, name); err != nil {
			return err
		}
	}
}

// The commit the next push of the ref brings it to, from at (nil for none) toward tip: see the file header's run.
// nil after a split, which the caller follows by taking the step again.
func (self *evsImporter) nextCut(ctx context.Context, name []byte, at *EvsGitOid, tip EvsGitOid, cuts []EvsGitOid, depth int, under uint32) (*EvsGitOid, error) {
	// the line past what the ref's tip and evs's other tips hold, so no push carries a commit a reader holds
	args := []string{"rev-list", "--first-parent", "--reverse", hex.EncodeToString(tip[:]), "--not"}
	if at != nil {
		args = append(args, hex.EncodeToString(at[:]))
	}
	args = append(args, "--glob="+evsLocalEvsRefPrefix+"*")
	out, err := self.mount.Git(ctx, args...)
	if err != nil {
		return nil, err
	}
	line := []EvsGitOid{}
	for _, text := range strings.Fields(string(out)) {
		oid, err := evsGitOidDecodeHex([]byte(text))
		if err != nil {
			return nil, fmt.Errorf("%w: rev-list answered no oid", ErrEvsGitFailed)
		}
		line = append(line, oid)
	}
	if len(line) == 0 {
		return &tip, nil
	}
	pushCommits := int64(0)
	prev := at
	for _, commit := range line {
		step, err := self.stepCount(ctx, commit, prev)
		if err != nil {
			return nil, err
		}
		if self.oversized(step) {
			if 0 < pushCommits {
				return prev, nil
			}
			if err := self.split(ctx, name, commit, prev, depth, under); err != nil {
				return nil, err
			}
			return nil, nil
		}
		if 0 < pushCommits && self.passes(pushCommits+step) {
			return prev, nil
		}
		pushCommits += step
		if self.passes(pushCommits) || slices.Contains(cuts, commit) {
			cut := commit
			return &cut, nil
		}
		at := commit
		prev = &at
	}
	return &tip, nil
}

// How many commits commit's step brings: commit and what its other parents bring that prev and evs's other tips do
// not hold, rev-list --count commit --not prev --glob=refs/ur/evs/*; a commit of one parent brings itself.
func (self *evsImporter) stepCount(ctx context.Context, commit EvsGitOid, prev *EvsGitOid) (int64, error) {
	parents, err := self.parents(ctx, commit)
	if err != nil {
		return 0, err
	}
	if len(parents) <= 1 {
		return 1, nil
	}
	args := []string{"rev-list", "--count", hex.EncodeToString(commit[:]), "--not"}
	if prev != nil {
		args = append(args, hex.EncodeToString(prev[:]))
	}
	args = append(args, "--glob="+evsLocalEvsRefPrefix+"*")
	return self.count(ctx, args...)
}

// A commit's parents, by git's own reading.
func (self *evsImporter) parents(ctx context.Context, commit EvsGitOid) ([]EvsGitOid, error) {
	kind, object, err := self.objects.ReadGitObject(ctx, commit)
	if err != nil {
		return nil, err
	}
	if kind != evsGitCommitKind {
		return nil, fmt.Errorf("%w: object %x is a %s, not a commit", ErrEvsGitObjectInvalid, commit[:], kind)
	}
	_, parents, err := EvsGitCommitGraph(object)
	if err != nil {
		return nil, fmt.Errorf("commit %x: %w", commit[:], err)
	}
	return parents, nil
}

// A git rev-list --count's answer.
func (self *evsImporter) count(ctx context.Context, args ...string) (int64, error) {
	out, err := self.mount.Git(ctx, args...)
	if err != nil {
		return 0, err
	}
	count, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: rev-list answered no count", ErrEvsGitFailed)
	}
	return count, nil
}

// The parts commitCount commits' sealed metadata takes by ImportCommitEstimate.
func (self *evsImporter) estimatedParts(commitCount int64) int64 {
	byteCount := commitCount * max(1, self.settings.ImportCommitEstimate)
	return (byteCount + EvsPartMaxByteCount - 1) / EvsPartMaxByteCount
}

// Whether a push of commitCount commits passes ImportPushPartCount.
func (self *evsImporter) passes(commitCount int64) bool {
	return int64(self.settings.ImportPushPartCount) < self.estimatedParts(commitCount)
}

// Whether a step of commitCount commits passes ImportStepPartCount, so no push can hold it.
func (self *evsImporter) oversized(commitCount int64) bool {
	return int64(self.settings.ImportStepPartCount) < self.estimatedParts(commitCount)
}

// Brings helper refs in for merge's oversized step, on the ref of name at prev (the file header's split), until the
// step fits.
func (self *evsImporter) split(ctx context.Context, name []byte, merge EvsGitOid, prev *EvsGitOid, depth int, under uint32) error {
	for {
		step, err := self.stepCount(ctx, merge, prev)
		if err != nil {
			return err
		}
		if !self.oversized(step) {
			return nil
		}
		parents, err := self.parents(ctx, merge)
		if err != nil {
			return err
		}
		if len(parents) < 2 {
			return fmt.Errorf("%w: commit %x alone passes ImportStepPartCount", ErrEvsImportStepBound, merge[:])
		}
		// the parent after the first that alone brings the most, counted against evs's tips, never local refs
		var parent EvsGitOid
		most := int64(0)
		for _, candidate := range parents[1:] {
			own, err := self.count(ctx, "rev-list", "--count", hex.EncodeToString(candidate[:]), "--not",
				hex.EncodeToString(parents[0][:]), "--glob="+evsLocalEvsRefPrefix+"*")
			if err != nil {
				return err
			}
			if most < own {
				parent, most = candidate, own
			}
		}
		switch {
		case most == 0:
			return fmt.Errorf("%w: commit %x's step brings nothing a helper can hold", ErrEvsImportStepBound, merge[:])
		case self.settings.ImportHelperDepth <= depth:
			return fmt.Errorf("%w: commit %x needs helpers past ImportHelperDepth", ErrEvsImportStepBound, merge[:])
		}
		helper := self.helperFor(merge, parent)
		if helper == nil {
			if self.settings.ImportHelperCount <= len(self.liveHelpers()) {
				return fmt.Errorf("%w: commit %x needs helpers past ImportHelperCount", ErrEvsImportStepBound, merge[:])
			}
			helper = &EvsImportHelper{
				N: self.nextHelperNumber(), Merge: hex.EncodeToString(merge[:]), Parent: hex.EncodeToString(parent[:]),
				Under: under, Depth: depth + 1, State: EvsImportHelperOpen,
			}
			self.record.Helpers = append(self.record.Helpers, helper)
			if err := self.write(); err != nil {
				return err
			}
			if err := self.kill("helper_recorded", name); err != nil {
				return err
			}
		}
		helperName := EvsImportHelperRefName(self.sidecarId, self.importId, helper.N)
		if helper.State == EvsImportHelperOpen {
			helperId, err := self.repo.resolveRefId(ctx, helperName, nil)
			if err != nil {
				return err
			}
			state, err := self.sync.Ref(ctx, helperId)
			if err != nil {
				return err
			}
			if state.Deleted {
				// its owner deleted it mid-import: abandoned, and its pair numbered again
				helper.State = EvsImportHelperAbandoned
				if err := self.write(); err != nil {
					return err
				}
				continue
			}
			if !slices.ContainsFunc(self.result.Helpers, func(made []byte) bool { return string(made) == string(helperName) }) {
				self.result.Helpers = append(self.result.Helpers, helperName)
			}
			if err := self.run(ctx, helperName, parent, nil, depth+1, helper.N); err != nil {
				return err
			}
			helper.State = EvsImportHelperDone
			if err := self.write(); err != nil {
				return err
			}
			if err := self.kill("helper_done", name); err != nil {
				return err
			}
		}
		if helper.State == EvsImportHelperDone {
			// a done helper's tip is its parent: the step no longer holds what it reaches, unless the helper was
			// deleted, which the next pass of this loop finds oversized again and numbers anew
			helperId, err := self.repo.resolveRefId(ctx, helperName, nil)
			if err != nil {
				return err
			}
			state, err := self.sync.Ref(ctx, helperId)
			if err != nil {
				return err
			}
			if state.Deleted {
				helper.State = EvsImportHelperAbandoned
				if err := self.write(); err != nil {
					return err
				}
			}
		}
	}
}

// The record's helper for a (merge, parent) pair that is not abandoned or deleted, nil for none.
func (self *evsImporter) helperFor(merge EvsGitOid, parent EvsGitOid) *EvsImportHelper {
	mergeText, parentText := hex.EncodeToString(merge[:]), hex.EncodeToString(parent[:])
	for _, helper := range self.record.Helpers {
		if helper.Merge == mergeText && helper.Parent == parentText &&
			(helper.State == EvsImportHelperOpen || helper.State == EvsImportHelperDone) {
			return helper
		}
	}
	return nil
}

// The helpers open or done.
func (self *evsImporter) liveHelpers() []*EvsImportHelper {
	live := []*EvsImportHelper{}
	for _, helper := range self.record.Helpers {
		if helper.State == EvsImportHelperOpen || helper.State == EvsImportHelperDone {
			live = append(live, helper)
		}
	}
	return live
}

// The next helper number, from 1 in the order first needed.
func (self *evsImporter) nextHelperNumber() uint32 {
	n := uint32(0)
	for _, helper := range self.record.Helpers {
		n = max(n, helper.N)
	}
	return n + 1
}

// One push of the ref of name to new, nil deleting it, under its publish lock alone, from the state replay holds,
// then replayed: an import push carries its commits under its own EvsImport.
func (self *evsImporter) publish(ctx context.Context, name []byte, refId Id, new *EvsGitOid) error {
	release, err := self.sync.LockPublish(ctx, refId)
	if err != nil {
		return err
	}
	defer release()
	state, err := self.sync.Ref(ctx, refId)
	if err != nil {
		return err
	}
	result, err := EvsLocalPublish(ctx, &EvsLocalPublishArgs{
		Mount: self.mount, Repo: self.repo, RefName: name, Old: state.Tip, New: new, BaseVersion: state.Version,
		BaseChain: state.Chain, Deleted: state.Deleted, LastTip: state.LastTip, Base: state.Base, Import: new != nil,
		State: self.sync,
	})
	if err != nil {
		return err
	}
	self.result.PushIds = append(self.result.PushIds, result.PushId)
	return self.sync.Replay(ctx, refId)
}

// Deletes every helper open or done, the most deeply nested first, by a DELETE push of the import; one evs shows
// deleted already is skipped.
func (self *evsImporter) clean(ctx context.Context) error {
	helpers := self.liveHelpers()
	slices.SortStableFunc(helpers, func(a *EvsImportHelper, b *EvsImportHelper) int { return b.Depth - a.Depth })
	for _, helper := range helpers {
		helperName := EvsImportHelperRefName(self.sidecarId, self.importId, helper.N)
		helperId, err := self.repo.resolveRefId(ctx, helperName, nil)
		if err != nil {
			return err
		}
		state, err := self.sync.Ref(ctx, helperId)
		if err != nil {
			return err
		}
		if 0 < state.Version && !state.Deleted {
			if err := self.publish(ctx, helperName, helperId, nil); err != nil {
				return err
			}
		}
		if err := self.kill("clean_deleted", helperName); err != nil {
			return err
		}
		helper.State = EvsImportHelperDeleted
		if err := self.write(); err != nil {
			return err
		}
	}
	return nil
}

// Abandons the import: clean, then its source ref and record dropped, the target left at its cut.
func (self *evsImporter) abandon(ctx context.Context) error {
	if err := self.clean(ctx); err != nil {
		return err
	}
	return self.finish(ctx)
}

// Drops the import's source ref and record, once its helpers are deleted.
func (self *evsImporter) finish(ctx context.Context) error {
	if _, err := self.mount.Git(ctx, "update-ref", "-d", evsLocalImportRefPrefix+self.importId.String()); err != nil {
		return err
	}
	name, err := self.recordName(self.importId)
	if err != nil {
		return err
	}
	return self.store.Remove(name)
}

// A kill point: the harness's barrier, and the test's hook.
func (self *evsImporter) kill(point string, name []byte) error {
	testHookBarrier("evs.local.import."+point, evsUrlId(self.repo.repoId)+"/"+string(name))
	if evsImportKillHook != nil {
		return evsImportKillHook(point)
	}
	return nil
}

// The record's name in the evs component's store.
func (self *evsImporter) recordName(importId EvsImportId) (string, error) {
	name, err := EvsLocalKey{Family: EvsLocalImports, ImportId: importId}.Name()
	if err != nil {
		return "", err
	}
	return evsLocalStatePrefix(self.repo.repoId) + name, nil
}

// Writes the record whole, durable once Commit answers.
func (self *evsImporter) write() error {
	importId, err := ParseEvsImportId(self.record.ImportId)
	if err != nil {
		return err
	}
	name, err := self.recordName(importId)
	if err != nil {
		return err
	}
	data, err := json.Marshal(self.record)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// Every import record of the repo.
func (self *evsImporter) records() ([]*EvsImportRecord, error) {
	return evsImportRecords(self.store, self.repo.repoId)
}

// Every import record of repoId in store.
func evsImportRecords(store SidecarStore, repoId Id) ([]*EvsImportRecord, error) {
	prefix := evsLocalStatePrefix(repoId) + string(EvsLocalImports) + "/"
	entries, err := store.List(prefix)
	if err != nil {
		return nil, err
	}
	records := []*EvsImportRecord{}
	for _, entry := range entries {
		if _, err := ParseEvsLocalName(strings.TrimPrefix(entry.Name, evsLocalStatePrefix(repoId))); err != nil {
			continue
		}
		reader, err := store.Open(entry.Name)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return nil, err
		}
		record := &EvsImportRecord{}
		if err := json.Unmarshal(data, record); err != nil {
			return nil, fmt.Errorf("%w: an import record that does not parse", ErrSidecarStoreFailed)
		}
		records = append(records, record)
	}
	return records, nil
}

// The facts `ur status` reads of the mount's imports: see the file header's status row.
func (self *EvsMounts) ImportStatus(ctx context.Context, repoId Id) (*EvsImportStatus, error) {
	mount, ok := self.Get(repoId)
	if !ok {
		return nil, fmt.Errorf("%w: a repo no mount serves", ErrEvsImportRefused)
	}
	sidecarId := self.client.args.Identity().SidecarId
	records, err := evsImportRecords(self.client.args.Store, repoId)
	if err != nil {
		return nil, err
	}
	status := &EvsImportStatus{}
	named := map[EvsImportId]bool{}
	sync := self.gitSync()
	repo := self.client.Repo(repoId)
	for _, record := range records {
		importId, err := ParseEvsImportId(record.ImportId)
		if err != nil {
			return nil, err
		}
		named[importId] = true
		unfinished := &EvsUnfinishedImport{ImportId: importId, Dir: record.Dir, Target: record.Target}
		if sync != nil {
			targetId, err := repo.resolveRefId(ctx, record.Target, nil)
			if err != nil {
				return nil, err
			}
			state, err := sync.Ref(ctx, targetId)
			if err != nil {
				return nil, err
			}
			unfinished.Reached = state.Tip
		}
		for _, helper := range record.Helpers {
			if helper.State == EvsImportHelperOpen || helper.State == EvsImportHelperDone {
				unfinished.Helpers = append(unfinished.Helpers, EvsImportHelperRefName(sidecarId, importId, helper.N))
			}
		}
		status.Unfinished = append(status.Unfinished, unfinished)
	}
	out, err := mount.Git(ctx, "for-each-ref", "--format=%(refname)", evsGitBranchPrefix+string(EvsOwnedRefName(sidecarId, evsImportRefInfix)))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Fields(string(out)) {
		refName := []byte(strings.TrimPrefix(line, evsGitBranchPrefix))
		owner, importId, _, ok := ParseEvsImportHelperRefName(refName)
		if ok && owner == sidecarId && !named[importId] {
			status.Leftover = append(status.Leftover, refName)
		}
	}
	return status, nil
}
