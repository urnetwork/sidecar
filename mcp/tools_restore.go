//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's run_restore (MCP-M3-22; R-MCP-4, D-MCP-8, D-MCP-11, I-9, FI-8) and §16.6's restore effect component:
//
//	run_restore(run_id, paths?, dry_run, preview_id?) -> diff, restored, conflicts (path, reason, copies), preview_id
//
//   - dry_run: the run's local restore point planned now (restore_plan.go): diff names each restorable path's current
//     and target kind, hash and size, never its bytes, which may hold a secret; conflicts names every other changed
//     path with its reason; preview_id binds them. paths, when given, limits the plan to those paths, and a shell path
//     among them then joins it.
//   - apply (dry_run false): the preview_id a dry run answered is required. In an untainted run whose preview holds
//     edit-attributed paths alone the call is W, rate-limited and recorded, and the apply runs at once. Otherwise it
//     is an action through §5.4's gate (Sidecar.Authorize), kind restore with restore_run_id, restore_paths and
//     restore_preview_id: when the calling run or the restored run is tainted, or when the preview holds shell paths,
//     which paths must name again (§16.7's shell paths row), a decision in any run. Pending answers approval_pending
//     with the request's id.
//   - record: every apply appends one restore entry, source observed (RECORD.md section 6.3's row 26), through
//     RecordWriter.Append, which spools while evs is down, so the tool needs no network: the apply reads the local
//     point and the worktree alone.
//
// The restore effect (restoreEffect) is the apply of the preview its action names, which converges on the target
// hashes: its journal makes a retry after a crash finish or report, never move a finished path again, and the apply's
// next call answers the recorded result. Its Lookup (NewRestoreEffectLookup) reads that journal: done once it ended,
// not_done where it never began, uncertain between. The tool registers it on a network's gate at its first outward
// apply; RegisterRestoreEffectLookup is what a daemon's gate wiring calls at its start (until it does, a restart's
// reconcile of a restore use reads uncertain until its retry).
//
// Trap: never a foreign path, never bytes changed since the preview: both are the apply's (restore_apply.go), which
// checks the bytes it moves aside, so no tool argument widens what a preview binds.

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The restore effect's reference domain, so no other hash of the same bytes is one.
const restoreEffectRefLabel = "urnetwork-sidecar-v1/restore-effect"

// The tool's refusals, each constant.
var (
	errMcpRestoreUnavailable = NewMcpError(McpCodeUnavailable, "this daemon keeps no restore points: run ur status in your own terminal", false)
	errMcpRestoreRunId       = NewMcpError(McpCodeInvalidArguments, "run_id is a run's id", false)
	errMcpRestoreNoPoint     = NewMcpError(McpCodeFailedPrecondition, "this device holds no restore point for that run", false)
	errMcpRestorePath        = NewMcpError(McpCodeInvalidArguments, "paths names paths inside the run's worktree", false)
	errMcpRestorePreviewId   = NewMcpError(McpCodeInvalidArguments, "an apply takes the preview_id its dry run answered, and a dry run takes none", false)
	errMcpRestorePreview     = NewMcpError(McpCodeFailedPrecondition, "preview_id names no preview of that run: dry run first", false)
	errMcpRestoreShell       = NewMcpError(McpCodeRefused,
		"the preview holds shell paths, which are restored only when paths names each of them, as an outward action", false)
	errMcpRestoreHeld = NewMcpError(McpCodeRefused,
		"this restore needs an approval, and none could be spent: a person may approve it on another device", false)
	errMcpRestoreUncertain = NewMcpError(McpCodeFailed, "the restore's outcome is uncertain: call run_restore again with the same preview_id", true)
	errMcpRestoreNotDone   = NewMcpError(McpCodeFailed, "the restore did not happen: dry run again", false)
)

// run_restore's arguments.
type mcpRunRestoreIn struct {
	RunId string `json:"run_id"`
	// Limits a dry run to these paths, a shell path among them joining its preview; an apply whose preview holds shell
	// paths names each of them again.
	Paths  []string `json:"paths,omitempty"`
	DryRun bool     `json:"dry_run"`
	// An apply's: the dry run's preview_id, hex.
	PreviewId string `json:"preview_id,omitempty"`
}

// A path's kind, hash and size as diff names them: no bytes.
type mcpRestoreStateOut struct {
	// absent, file or symlink.
	Kind   string `json:"kind"`
	Sha256 string `json:"sha256,omitempty"`
	// git's mode, octal digits as git writes them; empty for absent.
	Mode string `json:"mode,omitempty"`
	Size int64  `json:"size,omitempty"`
}

// One restorable path: what it is now and what restore makes it.
type mcpRestoreDiffOut struct {
	Path string              `json:"path"`
	From *mcpRestoreStateOut `json:"from"`
	To   *mcpRestoreStateOut `json:"to"`
	// Restored only as an outward action (§16.7's shell paths row).
	Shell bool `json:"shell,omitempty"`
}

// A path left as it is: a dry run's reason, or an apply's conflict and the copies kept beside it.
type mcpRestoreConflictOut struct {
	Path   string   `json:"path"`
	Reason string   `json:"reason"`
	Copies []string `json:"copies,omitempty"`
}

// run_restore's data.
type mcpRunRestoreOut struct {
	// preview for a dry run, applied for an apply, approval_pending with approval_id while a decision is awaited.
	Status     string `json:"status"`
	PreviewId  string `json:"preview_id"`
	ApprovalId string `json:"approval_id,omitempty"`
	// The preview's paths: each one's current and target state.
	Diff []*mcpRestoreDiffOut `json:"diff"`
	// The paths an apply restored.
	Restored  []string                 `json:"restored"`
	Conflicts []*mcpRestoreConflictOut `json:"conflicts"`
}

// What registers a kind's Lookup on a network's gate: *sidecar.Sidecar is one.
type McpEffectRegistrar interface {
	RegisterEffectLookup(kind sidecar.SidecarActionKind, lookup sidecar.SidecarEffectLookup) func()
}

// Sets the restore points run_restore reads: NewIngest's (MCP-M3-20). Nil answers unavailable.
func (self *McpServer) SetRestorePoints(points *RestorePoints) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.restorePoints = points
}

// The restore points as set.
func (self *McpServer) RestorePoints() *RestorePoints {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.restorePoints
}

func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		addRestoreTool(catalog, server.RestorePoints, nil)
	})
}

// run_restore's state: the networks whose gates hold the restore Lookup, and where each apply's entry goes.
type mcpRestoreTool struct {
	points  func() *RestorePoints
	writers func(network McpNetwork) (sidecar.RecordWriter, error)

	stateLock            sync.Mutex
	registeredNetworkIds map[sidecar.Id]bool
}

// Registers run_restore on catalog over what points answers per call, each apply's entry going to writers' writer, nil
// reading McpRecordNetwork off the network.
func addRestoreTool(catalog *McpCatalog, points func() *RestorePoints, writers func(network McpNetwork) (sidecar.RecordWriter, error)) {
	if writers == nil {
		writers = mcpNetworkRecordWriter
	}
	tool := &mcpRestoreTool{points: points, writers: writers, registeredNetworkIds: map[sidecar.Id]bool{}}
	AddTool(catalog, &McpToolSpec[mcpRunRestoreIn]{
		Name:   "run_restore",
		Tier:   McpTierWrite,
		MayAct: true,
		Description: "Restores a run's own edits from its local restore point: dry_run answers each restorable path's change, every " +
			"other changed path's reason and a preview_id; an apply takes that preview_id. Shell paths, and any restore in a " +
			"tainted run, need an approval.",
		Access: func(call *McpCall, in *mcpRunRestoreIn) ([]McpAccess, error) { return nil, nil },
	}, tool.handle)
}

// The writer of a network that exposes its record.
func mcpNetworkRecordWriter(network McpNetwork) (sidecar.RecordWriter, error) {
	recordNetwork, ok := network.(McpRecordNetwork)
	if !ok {
		return nil, errors.New("the network has no record writer")
	}
	record, err := recordNetwork.Record()
	if err != nil {
		return nil, err
	}
	return record.Writer(), nil
}

// One call. See the file's header.
func (self *mcpRestoreTool) handle(ctx context.Context, call *McpCall, in *mcpRunRestoreIn, result *McpResult) (*mcpRunRestoreOut, error) {
	points := self.points()
	if points == nil {
		return nil, errMcpRestoreUnavailable
	}
	runId, err := sidecar.ParseId(in.RunId)
	if err != nil {
		return nil, errMcpRestoreRunId
	}
	if in.DryRun == (in.PreviewId != "") {
		return nil, errMcpRestorePreviewId
	}
	point, err := points.OpenExisting(ctx, call.Network, call.NetworkId, runId)
	if errors.Is(err, ErrRestorePointUnknown) {
		return nil, errMcpRestoreNoPoint
	}
	if err != nil {
		return nil, err
	}
	result.SetSource("restore:" + runId.String())
	if in.DryRun {
		plan, err := point.Plan(ctx, in.Paths)
		if errors.Is(err, ErrRestorePathInvalid) {
			return nil, errMcpRestorePath
		}
		if err != nil {
			return nil, err
		}
		out := mcpRestorePlanOut(plan)
		out.Status = "preview"
		for _, refusal := range plan.Refusals {
			out.Conflicts = append(out.Conflicts, &mcpRestoreConflictOut{Path: refusal.Path, Reason: refusal.Reason})
		}
		return out, nil
	}
	previewId, err := hex.DecodeString(in.PreviewId)
	if err != nil || len(previewId) != restorePreviewIdByteCount {
		return nil, errMcpRestorePreviewId
	}
	plan, err := point.AppliedPlan(previewId)
	if errors.Is(err, ErrRestorePreviewUnknown) {
		return nil, errMcpRestorePreview
	}
	if err != nil {
		return nil, err
	}
	shellPaths := plan.ShellPaths()
	for _, shellPath := range shellPaths {
		named := false
		for _, text := range in.Paths {
			if relative, err := point.namedPath(text); err == nil && relative == shellPath {
				named = true
			}
		}
		if !named {
			return nil, errMcpRestoreShell
		}
	}
	tainted := call.Tainted() || mcpRunTainted(call.Network, runId)
	if !tainted && len(shellPaths) == 0 {
		// W: the run's own edit-attributed paths in an untainted run, no decision
		applied, err := point.Apply(ctx, previewId)
		if err != nil {
			return nil, mcpRestoreApplyError(err)
		}
		self.record(call.Network, call.RunId, point, applied, nil, nil)
		return mcpRestoreApplyOut(plan, applied), nil
	}

	// a decision: §5.4's gate, whose effect is the apply
	authorizer, ok := call.Network.(mcpAuthorizer)
	if !ok {
		return nil, errMcpRestoreHeld
	}
	self.registerLookup(points, call.Network, call.NetworkId)
	stored, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind:             uint32(sidecar.SidecarActionRestore),
		RestoreRunId:     runId.Bytes(),
		RestorePaths:     shellPaths,
		RestorePreviewId: previewId,
	})
	if err != nil {
		return nil, errMcpRestoreHeld
	}
	callRunId := call.RunId
	action, err := sidecar.NewSidecarAction(stored, sidecar.SidecarRiskNormal, sidecar.SidecarRiskNormal, &callRunId, nil)
	if err != nil {
		return nil, errMcpRestoreHeld
	}
	effect := &restoreEffect{tool: self, network: call.Network, runId: callRunId, point: point, previewId: previewId, stored: stored}
	action.Effect = effect
	if err := authorizer.Authorize(ctx, action, nil); err != nil {
		var pending *sidecar.ApprovalPendingError
		if errors.As(err, &pending) {
			out := mcpRestorePlanOut(plan)
			out.Status = "approval_pending"
			out.ApprovalId = pending.ApprovalId.String()
			return out, nil
		}
		return nil, errMcpRestoreHeld
	}
	if action.Outcome == nil {
		return nil, errMcpRestoreUncertain
	}
	switch action.Outcome.State {
	case sidecar.ApprovalOutcomeNotDone:
		return nil, errMcpRestoreNotDone
	case sidecar.ApprovalOutcomeDone:
	default:
		return nil, errMcpRestoreUncertain
	}
	applied := effect.applied()
	if applied == nil {
		// the gate answered the use's recorded outcome without running the effect again (AU4): the journal holds it
		_, ended, replayed, err := point.ApplyState(previewId)
		if err != nil || !ended {
			return nil, errMcpRestoreUncertain
		}
		applied = replayed
		self.record(call.Network, callRunId, point, applied, nil, nil)
	}
	return mcpRestoreApplyOut(plan, applied), nil
}

// Whether runId's run reads tainted on network: true where its run file is missing or does not read.
func mcpRunTainted(network McpNetwork, runId sidecar.Id) bool {
	runs, err := network.Runs()
	if err != nil {
		return true
	}
	return runs.Tainted(runId)
}

// An apply's error as the tool answers it.
func mcpRestoreApplyError(err error) error {
	switch {
	case errors.Is(err, ErrRestorePreviewUnknown):
		return errMcpRestorePreview
	case errors.Is(err, ErrRestoreNoRepository):
		return errMcpRestoreNoPoint
	}
	return err
}

// A state as diff names it.
func mcpRestoreStateOutOf(state *RestoreFileState) *mcpRestoreStateOut {
	if state == nil {
		return &mcpRestoreStateOut{Kind: string(RestoreKindAbsent)}
	}
	out := &mcpRestoreStateOut{Kind: string(state.Kind), Size: state.Size}
	if state.Kind != RestoreKindAbsent {
		out.Sha256 = hex.EncodeToString(state.Sha256)
		out.Mode = strconv.FormatUint(uint64(state.Mode), 8)
	}
	return out
}

// A plan's preview_id and diff, with empty lists to fill.
func mcpRestorePlanOut(plan *RestorePlan) *mcpRunRestoreOut {
	out := &mcpRunRestoreOut{
		PreviewId: hex.EncodeToString(plan.PreviewId),
		Diff:      []*mcpRestoreDiffOut{},
		Restored:  []string{},
		Conflicts: []*mcpRestoreConflictOut{},
	}
	for _, entry := range plan.Entries {
		out.Diff = append(out.Diff, &mcpRestoreDiffOut{
			Path:  entry.Path,
			From:  mcpRestoreStateOutOf(entry.Current),
			To:    mcpRestoreStateOutOf(entry.Target),
			Shell: entry.Shell,
		})
	}
	return out
}

// An apply's data: the plan's diff, the paths restored, and each conflict with its copies.
func mcpRestoreApplyOut(plan *RestorePlan, applied *RestoreApplyResult) *mcpRunRestoreOut {
	out := mcpRestorePlanOut(plan)
	out.Status = "applied"
	for _, path := range applied.Paths {
		if path.Result == RestoreResultRestored {
			out.Restored = append(out.Restored, path.Path)
			continue
		}
		out.Conflicts = append(out.Conflicts, &mcpRestoreConflictOut{Path: path.Path, Reason: path.Result, Copies: slices.Clone(path.Copies)})
	}
	return out
}

// Appends the apply's restore entry once (RECORD.md section 6.3's row 26), source observed, bound to the calling run,
// with the approval and action it spent where a decision ran it, then notes it in the journal. A writer that cannot
// take it leaves the journal unnoted, so the apply's next call appends it; nothing here fails the restore.
func (self *mcpRestoreTool) record(network McpNetwork, callRunId sidecar.Id, point *RestorePoint, applied *RestoreApplyResult, approvalId *sidecar.Id, actionId []byte) {
	if applied.Recorded {
		return
	}
	writer, err := self.writers(network)
	if err != nil {
		return
	}
	body := &protocol.RestoreBody{
		RestoredRunId: applied.RunId.Bytes(),
		PreviewId:     applied.PreviewId,
		RestoredCount: uint32(applied.RestoredCount()),
		ConflictCount: uint32(applied.ConflictCount()),
		Paths:         []*protocol.RestoredPath{},
	}
	if approvalId != nil {
		body.ApprovalId = approvalId.Bytes()
	}
	pathCount := point.points.settings.ChangePathCount
	for _, path := range applied.Paths {
		if 0 < pathCount && pathCount <= len(body.Paths) {
			// the body's cap; the counts still say how many there were
			break
		}
		body.Paths = append(body.Paths, &protocol.RestoredPath{Path: path.Path, Result: path.Result, Copies: slices.Clone(path.Copies)})
	}
	runId := callRunId
	if _, err := writer.Append(&sidecar.RecordDraft{
		Kind:       sidecar.RecordKindRestore,
		Source:     sidecar.RecordSourceObserved,
		RunId:      &runId,
		ActionId:   actionId,
		TimeMillis: point.points.clock.Now().UnixMilli(),
		Body:       body,
	}); err != nil {
		point.points.log.Warningf("[restore]the restore entry of run %s was not appended: %s", applied.RunId, err)
		return
	}
	if err := point.NoteRecorded(applied.PreviewId); err != nil {
		point.points.log.Warningf("[restore]the restore entry of run %s is not noted: %s", applied.RunId, err)
	}
}

// Registers the restore Lookup on network's gate once per network in this process, where the network takes one.
func (self *mcpRestoreTool) registerLookup(points *RestorePoints, network McpNetwork, networkId sidecar.Id) {
	registrar, ok := network.(McpEffectRegistrar)
	if !ok {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.registeredNetworkIds[networkId] {
		return
	}
	RegisterRestoreEffectLookup(registrar, points, network, networkId)
	self.registeredNetworkIds[networkId] = true
}

// §16.6's restore component for one apply: Run applies the preview, the spend it runs under named in its entry.
type restoreEffect struct {
	tool      *mcpRestoreTool
	network   McpNetwork
	runId     sidecar.Id
	point     *RestorePoint
	previewId []byte
	stored    *sidecar.StoredCanonicalAction

	stateLock sync.Mutex
	result    *RestoreApplyResult
}

var _ sidecar.SidecarEffect = (*restoreEffect)(nil)

// The apply under effectKey: idempotent, since the journal keyed by the preview finishes an interrupted apply and
// answers an ended one's result. A preview the point no longer keeps, with no apply begun, proves no effect.
func (self *restoreEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	applied, err := self.point.Apply(ctx, self.previewId)
	if errors.Is(err, ErrRestorePreviewUnknown) {
		return nil, errors.Join(sidecar.ErrSidecarEffectNotDone, err)
	}
	if err != nil {
		return nil, err
	}
	var approvalId *sidecar.Id
	var actionId []byte
	if spend, ok := sidecar.ApprovalSpendFromContext(ctx); ok {
		id := spend.ApprovalId
		approvalId = &id
		sum := self.stored.ActionId(id)
		actionId = sum[:]
	}
	self.tool.record(self.network, self.runId, self.point, applied, approvalId, actionId)
	self.stateLock.Lock()
	self.result = applied
	self.stateLock.Unlock()
	return restoreEffectRef(applied), nil
}

// What Run applied in this call, nil when it did not run.
func (self *restoreEffect) applied() *RestoreApplyResult {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.result
}

// The effect's reference: SHA-256 over the preview and each path's outcome, opaque to the gate.
func restoreEffectRef(applied *RestoreApplyResult) []byte {
	hash := sha256.New()
	write := func(part []byte) {
		hash.Write(binary.BigEndian.AppendUint32(nil, uint32(len(part))))
		hash.Write(part)
	}
	write([]byte(restoreEffectRefLabel))
	write(applied.PreviewId)
	for _, path := range applied.Paths {
		write([]byte(path.Path))
		write([]byte(path.Result))
		for _, copy := range path.Copies {
			write([]byte(copy))
		}
	}
	return hash.Sum(nil)
}

// §16.6's restore Lookup over network's points: from the stored action alone, done once the apply its preview names
// ended, not_done where it never began, uncertain between, or where the point is gone.
func NewRestoreEffectLookup(points *RestorePoints, network McpNetwork, networkId sidecar.Id) sidecar.SidecarEffectLookup {
	return func(ctx context.Context, canonical []byte, effectKey []byte) (*sidecar.SidecarOutcome, error) {
		stored, err := sidecar.ParseStoredCanonicalAction(canonical)
		if err != nil {
			return nil, err
		}
		if sidecar.SidecarActionKind(stored.Action.GetKind()) != sidecar.SidecarActionRestore {
			return nil, errors.New("the action is no restore")
		}
		runId, err := sidecar.IdFromBytes(stored.Action.GetRestoreRunId())
		if err != nil {
			return nil, err
		}
		point, err := points.OpenExisting(ctx, network, networkId, runId)
		if errors.Is(err, ErrRestorePointUnknown) {
			return &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeUncertain}, nil
		}
		if err != nil {
			return nil, err
		}
		begun, ended, applied, err := point.ApplyState(stored.Action.GetRestorePreviewId())
		switch {
		case errors.Is(err, ErrRestorePreviewUnknown):
			return &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeNotDone}, nil
		case err != nil:
			return nil, err
		case ended:
			return &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeDone, EffectRef: restoreEffectRef(applied)}, nil
		case !begun:
			return &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeNotDone}, nil
		}
		return &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeUncertain}, nil
	}
}

// Registers the restore Lookup for kind restore on registrar's gate, network's points answering it; the answer
// removes it. What a daemon's gate wiring calls for each network at its start.
func RegisterRestoreEffectLookup(registrar McpEffectRegistrar, points *RestorePoints, network McpNetwork, networkId sidecar.Id) func() {
	return registrar.RegisterEffectLookup(sidecar.SidecarActionRestore, NewRestoreEffectLookup(points, network, networkId))
}
