//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's attribution and restorable rules (D-MCP-15, RV1). At each hook of a run the registry notes the hook's
// activity on the worktree, then the run's point scans: every path git reports dirty, every path the ledger or base
// knows, hashed now and compared with what the ledger last knew, each change attributed over the interval since the
// last scan:
//
//	edit     file-edit hooks of this run in the interval name the path, their before and after hashes chain from
//	         the scan's before to its after, and no other run on this worktree named the path in the interval; an
//	         edit whose before is unknown counts as a non-path tool
//	shell    this run ran a shell or other non-path tool in the interval, and no other run on this worktree had any
//	         tool activity in it
//	foreign  anything else: another run active, no activity of this run, a coverage gap, or the interval spanning a
//	         daemon restart
//
// restorable(R, p) is the row's four conditions: every change of p since base is R's attributed edit, the chain is
// unbroken from the base, base(p) is exact, and the current bytes equal R's last after. The trap D-MCP-15 names:
// an after-hash alone would absorb a person's earlier edit of the path, so the chain starts at the scan's before.
//
// Activities and scans are ordered by the registry's sequence, so two hooks at one clock instant still order, and a
// test on a fake clock is deterministic.

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// What a hook did on a worktree, for attribution.
type restoreActivityKind int

const (
	// a file-edit hook naming paths, with its before known
	restoreActivityEdit restoreActivityKind = iota
	// a shell, MCP or other tool, or an edit whose before is unknown
	restoreActivityTool
)

// One hook's activity.
type restoreActivity struct {
	seq   uint64
	runId sidecar.Id
	kind  restoreActivityKind
	// the paths an edit named, relative to the root
	paths []string
}

// One change a scan found.
type RestoreChange struct {
	Path        string
	BeforeKnown bool
	Before      *RestoreFileState
	After       *RestoreFileState
	Attribution RestoreAttribution
	// The after bytes of a file within Ingest.FileByteCount, for the blob entry; nil past it or for another kind.
	AfterBytes []byte
}

// What one scan found (§16.7's Diffs row): the interval, HEAD and the commits since the last scan, and each change.
type RestoreScan struct {
	RunId      sidecar.Id
	FromSeq    uint64
	ToSeq      uint64
	FromMillis int64
	ToMillis   int64
	HeadCommit string
	// Commits made since the last scan's HEAD, newest first, at most Ingest.ChangePathCount's neighbour cap of 64
	// (RECORD.md's ChangeBody).
	Commits []string
	Changes []*RestoreChange
	// Whether changes past Ingest.ChangePathCount were left off, a truncation gap for the run.
	Truncated bool
	// Changed paths in all, Truncated or not.
	PathCount int
}

// The most commits a scan lists: RECORD.md's ChangeBody cap, a format value.
const restoreScanCommitCount = 64

// Takes the next activity number.
func (self *RestorePoints) takeSeq() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nextSeq += 1
	return self.nextSeq
}

// Notes an activity on a worktree root.
func (self *RestorePoints) noteActivity(root string, activity *restoreActivity) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rootActivities[root] = append(self.rootActivities[root], activity)
}

// The activities of other runs on root in (fromSeq, toSeq]: whether any named path, and whether any had tool
// activity at all.
func (self *RestorePoints) otherActivity(root string, runId sidecar.Id, path string, fromSeq uint64, toSeq uint64) (named bool, any bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, activity := range self.rootActivities[root] {
		if activity.runId == runId || activity.seq <= fromSeq || toSeq < activity.seq {
			continue
		}
		any = true
		if slices.Contains(activity.paths, path) {
			named = true
		}
	}
	return named, any
}

// Whether runId had a non-path tool activity on root in (fromSeq, toSeq].
func (self *RestorePoints) ownToolActivity(root string, runId sidecar.Id, fromSeq uint64, toSeq uint64) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, activity := range self.rootActivities[root] {
		if activity.runId == runId && activity.kind == restoreActivityTool && fromSeq < activity.seq && activity.seq <= toSeq {
			return true
		}
	}
	return false
}

// Drops activities no live point's next scan can reach: those at or before every point's last scan on the root.
func (self *RestorePoints) pruneActivitiesWithLock(root string) {
	floor := uint64(0)
	first := true
	for _, point := range self.points {
		if point.Root() != root {
			continue
		}
		lastScan := func() uint64 {
			point.stateLock.Lock()
			defer point.stateLock.Unlock()
			return point.ledger.LastScanSeq
		}()
		if first || lastScan < floor {
			floor = lastScan
			first = false
		}
	}
	if first {
		return
	}
	self.rootActivities[root] = slices.DeleteFunc(self.rootActivities[root], func(activity *restoreActivity) bool {
		return activity.seq <= floor
	})
}

// Marks the run's next scan foreign: a coverage gap on the run, which Ingest reports as it counts one.
func (self *RestorePoints) NoteGap(networkId sidecar.Id, runId sidecar.Id) {
	point, ok := self.Point(networkId, runId)
	if !ok {
		return
	}
	point.stateLock.Lock()
	defer point.stateLock.Unlock()
	point.foreignPending = true
}

// A hook event's hash for the ledger's edit row: SHA-256 over the harness, session id, tool_use_id and the arguments
// hash, each length-prefixed.
func restoreEventSha256(event *HookEvent) []byte {
	hash := sha256.New()
	for _, part := range [][]byte{[]byte(event.Harness), []byte(event.SessionId), []byte(event.ToolUseId), event.ToolInputSha256} {
		hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(part))))
		hash.Write(part)
	}
	return hash.Sum(nil)
}

// One hook event of a run, after its binding (§16.7's How): a PostToolUse's edits go to the ledger with their befores
// checked against the held bytes, every tool's activity is noted on the worktree, and the point then scans. The scan
// is answered for Ingest's change and blob entries; nil for an event that scans nothing. The point is opened at the
// run's first event. An error leaves the ledger as it was.
func (self *RestorePoints) NoteEvent(ctx context.Context, network McpNetwork, networkId sidecar.Id, runId sidecar.Id, event *HookEvent, payload []byte) (*RestoreScan, error) {
	if runId == (sidecar.Id{}) || event.Cwd == "" {
		return nil, nil
	}
	point, err := self.Open(ctx, network, networkId, runId, event.Cwd)
	if err != nil {
		return nil, err
	}
	if event.Kind != HookEventPostToolUse {
		return nil, nil
	}
	seq := self.takeSeq()
	now := self.clock.Now()
	activity := &restoreActivity{seq: seq, runId: runId, kind: restoreActivityTool}
	if event.ToolKind == HookToolEdit {
		edits, err := point.recordEdits(ctx, seq, now, event, payload)
		if err != nil {
			return nil, err
		}
		if edits.allKnown {
			activity.kind = restoreActivityEdit
		}
		activity.paths = edits.paths
	}
	root := point.Root()
	self.noteActivity(root, activity)
	scan, err := point.scan(ctx, seq, now)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pruneActivitiesWithLock(root)
	return scan, nil
}

// The run's point scans now, outside a hook: what Ingest calls at a run's end.
func (self *RestorePoints) Scan(ctx context.Context, networkId sidecar.Id, runId sidecar.Id) (*RestoreScan, error) {
	point, ok := self.Point(networkId, runId)
	if !ok {
		return nil, ErrRestorePathUnknown
	}
	return point.scan(ctx, self.takeSeq(), self.clock.Now())
}

// §16.7's scan: each candidate path's state now against what the ledger last knew, each change attributed over
// (LastScanSeq, seq], the ledger then written.
func (self *RestorePoint) scan(ctx context.Context, seq uint64, now time.Time) (*RestoreScan, error) {
	self.scanLock.Lock()
	defer self.scanLock.Unlock()
	testHookBarrier("restore.scan.before", self.runId.String())
	defer testHookBarrier("restore.scan.after", self.runId.String())
	fromSeq, fromMillis, lastHead, foreign, noRepo := func() (uint64, int64, string, bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.ledger.LastScanSeq, self.ledger.LastScanMillis, self.ledger.LastHead, self.foreignPending, self.manifest.NoRepo
	}()
	scan := &RestoreScan{
		RunId:      self.runId,
		FromSeq:    fromSeq,
		ToSeq:      seq,
		FromMillis: fromMillis,
		ToMillis:   now.UnixMilli(),
	}
	candidates := map[string]bool{}
	for _, path := range self.LedgerPaths() {
		candidates[path] = true
	}
	for _, path := range self.BasePaths() {
		candidates[path] = true
	}
	if !noRepo {
		dirty, err := self.statusPaths(ctx)
		if err != nil {
			return nil, err
		}
		for _, path := range dirty {
			candidates[path] = true
		}
		head, err := self.points.runGit(ctx, self.root, "rev-parse", "--verify", "HEAD")
		if err == nil {
			scan.HeadCommit = strings.TrimSpace(string(head))
		}
		if lastHead == "" {
			lastHead = self.HeadCommit()
		}
		if scan.HeadCommit != "" && lastHead != "" && scan.HeadCommit != lastHead {
			listing, err := self.points.runGit(ctx, self.root, "rev-list", "--max-count="+strconv.Itoa(restoreScanCommitCount), lastHead+".."+scan.HeadCommit)
			if err == nil {
				scan.Commits = strings.Fields(string(listing))
			}
		}
	}
	paths := make([]string, 0, len(candidates))
	for path := range candidates {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	root := self.Root()
	changes := []*RestoreChange{}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.HasPrefix(path, "/") || (len(path) > 1 && path[1] == ':') {
			// outside the worktree: never scanned
			continue
		}
		current, content, err := self.stateOf(path, true, self.points.settings.FileByteCount)
		if err != nil {
			return nil, err
		}
		last, known, err := self.lastStateOf(ctx, path, noRepo)
		if err != nil {
			return nil, err
		}
		if known && last.Equal(current) {
			continue
		}
		change := &RestoreChange{Path: path, BeforeKnown: known, After: current, AfterBytes: content}
		if known {
			change.Before = last.clone()
		}
		change.Attribution = self.attribute(root, path, fromSeq, seq, change, foreign)
		changes = append(changes, change)
		self.stateLock.Lock()
		observation := &RestoreObservation{
			Kind:        RestoreObservationScan,
			RunId:       self.runId,
			Seq:         seq,
			FromSeq:     fromSeq,
			AtMillis:    now.UnixMilli(),
			BeforeKnown: known,
			After:       current.clone(),
			Attribution: change.Attribution,
		}
		if known {
			observation.Before = last.clone()
		}
		self.appendObservationWithLock(path, observation)
		self.stateLock.Unlock()
	}
	scan.PathCount = len(changes)
	if cap := self.points.settings.ChangePathCount; 0 < cap && cap < len(changes) {
		scan.Truncated = true
		changes = changes[:cap]
	}
	scan.Changes = changes
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.ledger.LastScanSeq = seq
		self.ledger.LastScanMillis = now.UnixMilli()
		if scan.HeadCommit != "" {
			self.ledger.LastHead = scan.HeadCommit
		}
		self.foreignPending = false
	}()
	if err := self.saveLedger(); err != nil {
		return nil, err
	}
	return scan, nil
}

// The state the ledger last knew for path, else its base: known false when neither says, as for a path outside a
// repository that was never observed.
func (self *RestorePoint) lastStateOf(ctx context.Context, path string, noRepo bool) (*RestoreFileState, bool, error) {
	last, known := func() (*RestoreFileState, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.lastKnownWithLock(path)
	}()
	if known {
		return last, true, nil
	}
	if noRepo {
		return nil, false, nil
	}
	base, err := self.BaseOf(ctx, path)
	if errors.Is(err, ErrRestoreNoRepository) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if base.State == nil || base.State.Kind == RestoreKindOther {
		return nil, false, nil
	}
	return base.State, true, nil
}

// §16.7's three rows for one change over (fromSeq, toSeq].
func (self *RestorePoint) attribute(root string, path string, fromSeq uint64, toSeq uint64, change *RestoreChange, foreignInterval bool) RestoreAttribution {
	if foreignInterval {
		return RestoreAttributionForeign
	}
	edits := func() []*RestoreObservation {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		edits := []*RestoreObservation{}
		for _, observation := range self.ledger.Paths[path] {
			if observation.Kind == RestoreObservationEdit && observation.RunId == self.runId && fromSeq < observation.Seq && observation.Seq <= toSeq {
				edits = append(edits, observation)
			}
		}
		return edits
	}()
	otherNamed, otherAny := self.points.otherActivity(root, self.runId, path, fromSeq, toSeq)
	return restoreAttribute(&restoreAttributeArgs{
		edits:       edits,
		before:      change.Before,
		beforeKnown: change.BeforeKnown,
		after:       change.After,
		ownTool:     self.points.ownToolActivity(root, self.runId, fromSeq, toSeq),
		otherNamed:  otherNamed,
		otherAny:    otherAny,
	})
}

// What the attribution rules read.
type restoreAttributeArgs struct {
	// this run's edit observations of the path in the interval, in order
	edits []*RestoreObservation
	// the scan's before and after
	before      *RestoreFileState
	beforeKnown bool
	after       *RestoreFileState
	// this run ran a shell or other non-path tool in the interval, an unknown-before edit included
	ownTool bool
	// another run on this worktree named the path in the interval
	otherNamed bool
	// another run on this worktree had any tool activity in the interval
	otherAny bool
}

// §16.7's edit, shell and foreign rows, as a pure function. The interval's own foreignness (a gap or restart) is the
// caller's to apply first.
func restoreAttribute(args *restoreAttributeArgs) RestoreAttribution {
	allKnown := len(args.edits) != 0
	for _, edit := range args.edits {
		if !edit.BeforeKnown {
			allKnown = false
		}
	}
	if allKnown && args.beforeKnown && !args.otherNamed && restoreEditsChain(args.edits, args.before, args.after) {
		return RestoreAttributionEdit
	}
	ownTool := args.ownTool
	if !allKnown && len(args.edits) != 0 {
		ownTool = true
	}
	if ownTool && !args.otherAny {
		return RestoreAttributionShell
	}
	return RestoreAttributionForeign
}

// Why a path is not restorable, as dry_run names it (§16.7).
const (
	RestoreReasonForeign      = "foreign"
	RestoreReasonShell        = "shell"
	RestoreReasonChainBroken  = "chain-broken"
	RestoreReasonChangedSince = "changed-since"
	RestoreReasonNotExact     = "not-exact"
	// Nothing changed since the base: there is nothing to restore.
	RestoreReasonUnchanged = "unchanged"
)

// restorable(R, p): true with an empty reason, else false and §16.7's reason. Reads the ledger and the point's base,
// and hashes the path now for the fourth condition.
func (self *RestorePoint) Restorable(ctx context.Context, path string) (bool, string, error) {
	path = self.relativePath(path)
	base, err := self.BaseOf(ctx, path)
	if errors.Is(err, ErrRestoreNoRepository) {
		return false, RestoreReasonNotExact, nil
	}
	if err != nil {
		return false, "", err
	}
	if !base.Exact || base.HashOnly || base.State == nil || base.State.Kind == RestoreKindOther {
		return false, RestoreReasonNotExact, nil
	}
	scans := []*RestoreObservation{}
	for _, observation := range self.Observations(path) {
		if observation.Kind == RestoreObservationScan {
			scans = append(scans, observation)
		}
	}
	if len(scans) == 0 {
		return false, RestoreReasonUnchanged, nil
	}
	last := base.State
	for _, scan := range scans {
		switch scan.Attribution {
		case RestoreAttributionEdit:
		case RestoreAttributionShell:
			return false, RestoreReasonShell, nil
		default:
			return false, RestoreReasonForeign, nil
		}
		if scan.RunId != self.runId || !scan.BeforeKnown || !scan.Before.Equal(last) {
			return false, RestoreReasonChainBroken, nil
		}
		last = scan.After
	}
	current, _, err := self.stateOf(path, false, 0)
	if err != nil {
		return false, "", err
	}
	if !current.Equal(last) {
		return false, RestoreReasonChangedSince, nil
	}
	if last.Equal(base.State) {
		return false, RestoreReasonUnchanged, nil
	}
	return true, "", nil
}
