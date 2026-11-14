//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's run_restore (MCP-M3-22) on the tool framework over a real git worktree's restore point: a dry run then an
// apply restoring byte-exact, W and recorded; a tainted run's restore asking §5.4's gate and spending its decision; a
// shell path refused unless named after a dry run and decided (§22.7's actions row); the restore effect converging on
// its target hashes across retries and a kill, its Lookup answering done, not_done and uncertain from the journal; the
// restore entry appended once with the run, preview and outcomes; the apply working with evs down and no network
// call; and the tool's wire and output schemas at every MCP version. The gate is a stand-in that pends until a test
// decides, then runs the effect under a key as §16.6's spend step 5 does; the real gate's spend is MCP-M3-06's.

package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A tool network with a stand-in §5.4 gate: it records each action, answers pending until a test approves, then runs
// the action's effect under a fixed key and sets its outcome, as spend step 5 does. It keeps the Lookups registered.
type fakeMcpRestoreNetwork struct {
	*fakeMcpToolNetwork

	stateLock  sync.Mutex
	approved   bool
	authorized []*sidecar.SidecarAction
	lookups    map[sidecar.SidecarActionKind]sidecar.SidecarEffectLookup
}

// The key the stand-in gate runs every effect under.
var testRestoreEffectKey = bytes.Repeat([]byte{0x6b}, 32)

func (self *fakeMcpRestoreNetwork) Authorize(ctx context.Context, action *sidecar.SidecarAction, decision *bridge.Signed) error {
	approved := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.authorized = append(self.authorized, action)
		return self.approved
	}()
	if !approved {
		return &sidecar.ApprovalPendingError{ApprovalId: sidecar.NewId()}
	}
	effectRef, err := action.Effect.Run(ctx, testRestoreEffectKey)
	switch {
	case err == nil:
		action.Outcome = &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeDone, EffectRef: effectRef}
	case errors.Is(err, sidecar.ErrSidecarEffectNotDone):
		action.Outcome = &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeNotDone, Err: err}
	default:
		action.Outcome = &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeUncertain, Err: err}
	}
	return nil
}

func (self *fakeMcpRestoreNetwork) RegisterEffectLookup(kind sidecar.SidecarActionKind, lookup sidecar.SidecarEffectLookup) func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lookups[kind] = lookup
	return func() {}
}

func (self *fakeMcpRestoreNetwork) approve() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.approved = true
}

func (self *fakeMcpRestoreNetwork) actions() []*sidecar.SidecarAction {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*sidecar.SidecarAction{}, self.authorized...)
}

func (self *fakeMcpRestoreNetwork) lookup(kind sidecar.SidecarActionKind) sidecar.SidecarEffectLookup {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.lookups[kind]
}

// A record writer keeping each draft, answering it spooled while evs is down.
type fakeRestoreRecordWriter struct {
	stateLock sync.Mutex
	drafts    []*sidecar.RecordDraft
	evsDown   bool
}

func (self *fakeRestoreRecordWriter) Append(draft *sidecar.RecordDraft) ([]*sidecar.RecordEntryRef, error) {
	if err := sidecar.RecordBodyValidate(draft.Kind, draft.Body); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.drafts = append(self.drafts, draft)
	if self.evsDown {
		return []*sidecar.RecordEntryRef{{Spooled: true}}, nil
	}
	return []*sidecar.RecordEntryRef{{LogId: sidecar.NewId(), EntryId: sidecar.NewId(), Seq: uint64(len(self.drafts))}}, nil
}

// The restore entries appended so far.
func (self *fakeRestoreRecordWriter) restores() []*protocol.RestoreBody {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	bodies := []*protocol.RestoreBody{}
	for _, draft := range self.drafts {
		if draft.Kind == sidecar.RecordKindRestore {
			bodies = append(bodies, draft.Body.(*protocol.RestoreBody))
		}
	}
	return bodies
}

// A server with run_restore over a git worktree's restore point for a harness session's run.
type testRestoreToolEnv struct {
	*hookTestEnv
	network *fakeMcpRestoreNetwork
	catalog *McpCatalog
	sink    *testCallSink
	writer  *fakeRestoreRecordWriter
	claude  *sidecartest.FakeHarness
	runId   sidecar.Id
	// the worktree, its registry and the run's point
	work  *restoreTestEnv
	point *RestorePoint
}

func newTestRestoreToolEnv(t *testing.T) *testRestoreToolEnv {
	t.Helper()
	env := &testRestoreToolEnv{hookTestEnv: newHookTestEnv(t), sink: &testCallSink{}, writer: &fakeRestoreRecordWriter{}}
	env.network = &fakeMcpRestoreNetwork{
		fakeMcpToolNetwork: newFakeMcpToolNetwork(env.hookTestEnv.network, testToolCredential),
		lookups:            map[sidecar.SidecarActionKind]sidecar.SidecarEffectLookup{},
	}
	env.daemon.hostNetwork(env.networkId, env.network)
	work := newRestoreTestEnv(t)
	work.clock = env.clock
	work.network = env.hookTestEnv.network
	work.networkId = env.networkId
	work.points = work.newPoints()
	env.work = work
	env.catalog = NewMcpCatalog(env.server.settings.Mcp, env.clock, env.sink)
	addRestoreTool(env.catalog, func() *RestorePoints { return env.work.points }, func(network McpNetwork) (sidecar.RecordWriter, error) {
		return env.writer, nil
	})
	env.catalog.Install(env.server)
	env.claude = env.harness(sidecartest.FakeHarnessClaudeCode)
	if err := env.claude.SessionStart("restore session", "startup"); err != nil {
		t.Fatal(err)
	}
	env.runId = env.runOf("claude-code", "restore session")
	work.runId = env.runId
	env.point = work.open()
	return env
}

// A session at version, 2026-07-28's taking none.
func (self *testRestoreToolEnv) conn(version string) *testMcpConn {
	self.t.Helper()
	conn := startTestMcpConn(self.t, self.server, self.claude.RelayHello("builder"))
	if version != "2026-07-28" {
		conn.initialize(version)
	}
	return conn
}

// A run_restore call at version.
func (self *testRestoreToolEnv) call(conn *testMcpConn, version string, arguments map[string]any) *testMcpResponse {
	self.t.Helper()
	params := map[string]any{"name": "run_restore", "arguments": arguments}
	if version == "2026-07-28" {
		params["_meta"] = testMcpLatestMeta()
	}
	return conn.call("tools/call", params)
}

// A call's data.
func (self *testRestoreToolEnv) data(response *testMcpResponse) *mcpRunRestoreOut {
	self.t.Helper()
	out := &mcpRunRestoreOut{}
	envelope := testEnvelopeOf(self.t, response)
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		self.t.Fatalf("data %s: %v", envelope.Data, err)
	}
	return out
}

// A dry run, then an apply of its preview_id: the edits restored byte-exact, the call W and sunk, a restore entry
// naming the run, the preview and each outcome, and no gate asked.
func TestDryRunThenApply(t *testing.T) {
	env := newTestRestoreToolEnv(t)
	env.work.hookedWrite("toolu_1", "committed.txt", "edited\n")
	env.work.hookedWrite("toolu_2", "new.txt", "created\n")
	conn := env.conn("2025-06-18")
	preview := env.data(env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": true}))
	if preview.Status != "preview" || len(preview.Diff) != 2 || len(preview.PreviewId) != 32 {
		t.Fatalf("dry run %+v", preview)
	}
	if diff := preview.Diff[0]; diff.Path != "committed.txt" || diff.From.Kind != "file" || diff.To.Mode != "100644" ||
		diff.To.Sha256 != hex.EncodeToString(sha256Of([]byte("one\ntwo\nthree\n"))) {
		t.Errorf("diff %+v %+v %+v", diff, diff.From, diff.To)
	}
	if string(env.work.read("committed.txt")) != "edited\n" || len(env.writer.restores()) != 0 {
		t.Fatal("a dry run moved something or recorded an apply")
	}
	applied := env.data(env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": false, "preview_id": preview.PreviewId}))
	if applied.Status != "applied" || !slices.Equal(applied.Restored, []string{"committed.txt", "new.txt"}) || len(applied.Conflicts) != 0 {
		t.Fatalf("apply %+v", applied)
	}
	if string(env.work.read("committed.txt")) != "one\ntwo\nthree\n" || env.work.exists("new.txt") {
		t.Error("the edits are not restored")
	}
	if len(env.network.actions()) != 0 {
		t.Error("an untainted run's edit restore asked the gate")
	}
	restores := env.writer.restores()
	if len(restores) != 1 || restores[0].GetRestoredCount() != 2 || !bytes.Equal(restores[0].GetRestoredRunId(), env.runId.Bytes()) ||
		hex.EncodeToString(restores[0].GetPreviewId()) != preview.PreviewId || len(restores[0].GetApprovalId()) != 0 {
		t.Errorf("restore entries %+v", restores)
	}
	sunk := env.sink.sunk()
	if len(sunk) != 2 || sunk[1].toolName != "run_restore" || sunk[1].err != nil {
		t.Errorf("sunk %+v", sunk)
	}
	// the same apply again answers the recorded result, appending nothing
	again := env.data(env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": false, "preview_id": preview.PreviewId}))
	if !slices.Equal(again.Restored, applied.Restored) || len(env.writer.restores()) != 1 {
		t.Errorf("the second apply %+v, %d entries", again, len(env.writer.restores()))
	}
}

// A tainted run's restore is an action through §5.4's gate, kind restore naming the run and the preview: pending until
// a person decides, then applied under the decision, the entry naming nothing it did not spend.
func TestTaintedRestoreNeedsDecision(t *testing.T) {
	env := newTestRestoreToolEnv(t)
	env.work.hookedWrite("toolu_1", "committed.txt", "edited\n")
	conn := env.conn("2025-06-18")
	preview := env.data(env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": true}))
	if err := env.hookTestEnv.network.runs.Taint(context.Background(), env.runId, sidecar.RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	arguments := map[string]any{"run_id": env.runId.String(), "dry_run": false, "preview_id": preview.PreviewId}
	pending := env.data(env.call(conn, "2025-06-18", arguments))
	if pending.Status != "approval_pending" || pending.ApprovalId == "" {
		t.Fatalf("tainted %+v", pending)
	}
	if string(env.work.read("committed.txt")) != "edited\n" {
		t.Fatal("a pending restore moved something")
	}
	actions := env.network.actions()
	if len(actions) != 1 || actions[0].Kind != sidecar.SidecarActionRestore || actions[0].RunId == nil || *actions[0].RunId != env.runId {
		t.Fatalf("actions %+v", actions)
	}
	stored, err := sidecar.ParseStoredCanonicalAction(actions[0].Canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.Action.GetRestoreRunId(), env.runId.Bytes()) || hex.EncodeToString(stored.Action.GetRestorePreviewId()) != preview.PreviewId ||
		len(stored.Action.GetRestorePaths()) != 0 {
		t.Errorf("the canonical action %+v", stored.Action)
	}
	if env.network.lookup(sidecar.SidecarActionRestore) == nil {
		t.Error("the restore Lookup is not registered on the gate")
	}
	env.network.approve()
	applied := env.data(env.call(conn, "2025-06-18", arguments))
	if applied.Status != "applied" || !slices.Equal(applied.Restored, []string{"committed.txt"}) {
		t.Fatalf("decided %+v", applied)
	}
	if string(env.work.read("committed.txt")) != "one\ntwo\nthree\n" {
		t.Error("the decided restore did not restore")
	}
	if len(env.writer.restores()) != 1 {
		t.Errorf("%d restore entries", len(env.writer.restores()))
	}
}

// §22.7: a shell-attributed path is left out of a dry run with its reason; named in paths it joins the preview, and
// its apply is refused unless paths names it again, and then asks the gate, a decision in an untainted run too.
func TestShellPathRefusedWithoutPathsAndDecision(t *testing.T) {
	env := newTestRestoreToolEnv(t)
	ctx := context.Background()
	env.work.write("committed.txt", "by the shell\n")
	shell := env.work.claudePayload("PostToolUse", "Bash", "toolu_1", map[string]any{"command": "echo"})
	if _, err := env.work.points.NoteEvent(ctx, env.work.network, env.networkId, env.runId, env.work.parse("claude-code", shell), shell); err != nil {
		t.Fatal(err)
	}
	conn := env.conn("2025-06-18")
	unnamed := env.data(env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": true}))
	if len(unnamed.Diff) != 0 || len(unnamed.Conflicts) != 1 || unnamed.Conflicts[0].Reason != RestoreReasonShell {
		t.Fatalf("unnamed dry run %+v", unnamed)
	}
	named := env.data(env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": true, "paths": []string{"committed.txt"}}))
	if len(named.Diff) != 1 || !named.Diff[0].Shell {
		t.Fatalf("named dry run %+v", named)
	}
	wantMcpError(t, env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": false, "preview_id": named.PreviewId}),
		McpCodeRefused, "shell paths")
	if len(env.network.actions()) != 0 || string(env.work.read("committed.txt")) != "by the shell\n" {
		t.Fatal("an unnamed shell path acted")
	}
	pending := env.data(env.call(conn, "2025-06-18", map[string]any{
		"run_id": env.runId.String(), "dry_run": false, "preview_id": named.PreviewId, "paths": []string{"committed.txt"},
	}))
	if pending.Status != "approval_pending" {
		t.Fatalf("a named shell path in an untainted run: %+v", pending)
	}
	actions := env.network.actions()
	stored, err := sidecar.ParseStoredCanonicalAction(actions[0].Canonical)
	if err != nil || !slices.Equal(stored.Action.GetRestorePaths(), []string{"committed.txt"}) {
		t.Fatalf("the action names %v: %v", stored.Action.GetRestorePaths(), err)
	}
	// twin: decided, the shell path restores
	env.network.approve()
	applied := env.data(env.call(conn, "2025-06-18", map[string]any{
		"run_id": env.runId.String(), "dry_run": false, "preview_id": named.PreviewId, "paths": []string{"committed.txt"},
	}))
	if !slices.Equal(applied.Restored, []string{"committed.txt"}) || string(env.work.read("committed.txt")) != "one\ntwo\nthree\n" {
		t.Errorf("decided shell restore %+v", applied)
	}
}

// The effect converges on its target hashes: a second run under the same key answers the same reference and moves
// nothing; a kill mid-apply then a retry finishes it; and the Lookup answers not_done before, uncertain while the
// journal is open, done once it ended, all from the stored action alone.
func TestRetryConvergesOnTargetHashes(t *testing.T) {
	env := newTestRestoreToolEnv(t)
	ctx := context.Background()
	env.work.hookedWrite("toolu_1", "committed.txt", "edited\n")
	env.work.hookedWrite("toolu_2", "dir/nested.txt", "nested edited\n")
	plan, err := env.point.Plan(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(sidecar.SidecarActionRestore), RestoreRunId: env.runId.Bytes(), RestorePreviewId: plan.PreviewId,
	})
	if err != nil {
		t.Fatal(err)
	}
	lookup := NewRestoreEffectLookup(env.work.points, env.network, env.networkId)
	outcome, err := lookup(ctx, stored.Bytes, testRestoreEffectKey)
	if err != nil || outcome.State != sidecar.ApprovalOutcomeNotDone {
		t.Fatalf("before the apply: %+v %v", outcome, err)
	}
	tool := &mcpRestoreTool{writers: func(network McpNetwork) (sidecar.RecordWriter, error) { return env.writer, nil }, registeredNetworkIds: map[sidecar.Id]bool{}}
	effect := &restoreEffect{tool: tool, network: env.network, runId: env.runId, point: env.point, previewId: plan.PreviewId, stored: stored}
	// killed after the first path's install
	env.work.points.fs = (&restoreTestFs{afterRename: func(from string, to string) {
		if restoreTestInstall(from, to) && to == "committed.txt" {
			panic("killed")
		}
	}}).fs()
	func() {
		defer func() { recover() }()
		effect.Run(ctx, testRestoreEffectKey)
	}()
	if outcome, err := lookup(ctx, stored.Bytes, testRestoreEffectKey); err != nil || outcome.State != sidecar.ApprovalOutcomeUncertain {
		t.Fatalf("mid-apply: %+v %v", outcome, err)
	}
	env.work.points.fs = defaultRestoreFs()
	first, err := effect.Run(ctx, testRestoreEffectKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(env.work.read("committed.txt")) != "one\ntwo\nthree\n" || string(env.work.read("dir/nested.txt")) != "nested\n" {
		t.Fatal("the retry did not converge")
	}
	env.work.write("committed.txt", "written after\n")
	second, err := effect.Run(ctx, testRestoreEffectKey)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("a second run: %x %x %v", first, second, err)
	}
	if string(env.work.read("committed.txt")) != "written after\n" {
		t.Error("a second run moved a finished path")
	}
	outcome, err = lookup(ctx, stored.Bytes, testRestoreEffectKey)
	if err != nil || outcome.State != sidecar.ApprovalOutcomeDone || !bytes.Equal(outcome.EffectRef, first) {
		t.Errorf("after: %+v %v", outcome, err)
	}
	if len(env.writer.restores()) != 1 {
		t.Errorf("%d restore entries over three runs", len(env.writer.restores()))
	}
	// a preview the point never kept, with no apply begun, proves no effect
	missing := &restoreEffect{tool: tool, network: env.network, runId: env.runId, point: env.point, previewId: bytes.Repeat([]byte{1}, 16), stored: stored}
	if _, err := missing.Run(ctx, testRestoreEffectKey); !errors.Is(err, sidecar.ErrSidecarEffectNotDone) {
		t.Errorf("an unknown preview: %v", err)
	}
}

// The restore entry carries the run restored, the preview, the counts and each path's outcome and copies, bound to the
// calling run, source observed.
func TestRestoreEntryAppended(t *testing.T) {
	env := newTestRestoreToolEnv(t)
	env.work.hookedWrite("toolu_1", "committed.txt", "edited\n")
	env.work.hookedWrite("toolu_2", "dir/nested.txt", "nested edited\n")
	conn := env.conn("2025-06-18")
	preview := env.data(env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": true}))
	env.work.write("dir/nested.txt", "by hand\n")
	applied := env.data(env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": false, "preview_id": preview.PreviewId}))
	if len(applied.Conflicts) != 1 || applied.Conflicts[0].Reason != RestoreConflictChanged || len(applied.Conflicts[0].Copies) != 1 {
		t.Fatalf("apply %+v", applied)
	}
	env.writer.stateLock.Lock()
	drafts := append([]*sidecar.RecordDraft{}, env.writer.drafts...)
	env.writer.stateLock.Unlock()
	if len(drafts) != 1 || drafts[0].Kind != sidecar.RecordKindRestore || drafts[0].Source != sidecar.RecordSourceObserved ||
		drafts[0].RunId == nil || *drafts[0].RunId != env.runId {
		t.Fatalf("drafts %+v", drafts)
	}
	body := drafts[0].Body.(*protocol.RestoreBody)
	if body.GetRestoredCount() != 1 || body.GetConflictCount() != 1 || len(body.GetPaths()) != 2 {
		t.Fatalf("body %+v", body)
	}
	if path := body.GetPaths()[1]; path.GetPath() != "dir/nested.txt" || path.GetResult() != RestoreConflictChanged ||
		!slices.Equal(path.GetCopies(), applied.Conflicts[0].Copies) {
		t.Errorf("the conflict's path %+v", path)
	}
}

// With evs down the apply still restores, its entry spooled, and the tool makes no call beyond the device: the
// network's gate is never asked and nothing but the local point and the worktree is read.
func TestWorksOffline(t *testing.T) {
	env := newTestRestoreToolEnv(t)
	env.writer.evsDown = true
	env.work.hookedWrite("toolu_1", "committed.txt", "edited\n")
	conn := env.conn("2025-06-18")
	preview := env.data(env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": true}))
	applied := env.data(env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": false, "preview_id": preview.PreviewId}))
	if !slices.Equal(applied.Restored, []string{"committed.txt"}) || string(env.work.read("committed.txt")) != "one\ntwo\nthree\n" {
		t.Fatalf("offline apply %+v", applied)
	}
	if len(env.writer.restores()) != 1 || len(env.network.actions()) != 0 {
		t.Errorf("entries %d, gate asked %d times", len(env.writer.restores()), len(env.network.actions()))
	}
}

// The tool's refusals, each constant: no point for the run, a preview it never answered, an apply with no preview_id
// or a dry run with one, a path outside the worktree.
func TestRunRestoreRefusals(t *testing.T) {
	env := newTestRestoreToolEnv(t)
	conn := env.conn("2025-06-18")
	wantMcpError(t, env.call(conn, "2025-06-18", map[string]any{"run_id": sidecar.NewId().String(), "dry_run": true}), McpCodeFailedPrecondition, "no restore point")
	wantMcpError(t, env.call(conn, "2025-06-18", map[string]any{"run_id": "not an id", "dry_run": true}), McpCodeInvalidArguments, "run_id")
	wantMcpError(t, env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": false}), McpCodeInvalidArguments, "preview_id")
	wantMcpError(t, env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": true, "preview_id": hex.EncodeToString(bytes.Repeat([]byte{1}, 16))}),
		McpCodeInvalidArguments, "preview_id")
	wantMcpError(t, env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": false, "preview_id": hex.EncodeToString(bytes.Repeat([]byte{1}, 32))}),
		McpCodeInvalidArguments, "preview_id")
	wantMcpError(t, env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": false, "preview_id": hex.EncodeToString(bytes.Repeat([]byte{1}, 16))}),
		McpCodeFailedPrecondition, "dry run first")
	wantMcpError(t, env.call(conn, "2025-06-18", map[string]any{"run_id": env.runId.String(), "dry_run": true, "paths": []string{"../outside.txt"}}),
		McpCodeInvalidArguments, "paths")
}

// §22.5: at every MCP version run_restore's result validates against that version's wire schema, and its
// structuredContent against the tool's declared outputSchema, a dry run's and an apply's both; the tool is W with
// openWorldHint, since it may act outward, and the daemon's catalog holds it registered.
func TestRunRestoreSchemasAtEveryVersion(t *testing.T) {
	env := newTestRestoreToolEnv(t)
	env.work.hookedWrite("toolu_1", "committed.txt", "edited\n")
	for index, version := range testMcpVersions {
		conn := env.conn(version)
		if index != 0 {
			// each version applies a fresh change
			env.work.hookedWrite("toolu_v"+version, "committed.txt", "edited at "+version+"\n")
		}
		preview := env.call(conn, version, map[string]any{"run_id": env.runId.String(), "dry_run": true})
		if preview.Error != nil {
			t.Fatalf("%s: %s", version, preview.Error.Message)
		}
		previewId := env.data(preview).PreviewId
		applied := env.call(conn, version, map[string]any{"run_id": env.runId.String(), "dry_run": false, "preview_id": previewId})
		if applied.Error != nil {
			t.Fatalf("%s: %s", version, applied.Error.Message)
		}
		for _, response := range []*testMcpResponse{preview, applied} {
			testValidateWire(t, version, response.Result)
			result := testWireResult{}
			json.Unmarshal(response.Result, &result)
			var structured any
			json.Unmarshal(result.StructuredContent, &structured)
			if err := testOutputSchema(t, conn, version, "run_restore").Validate(structured); err != nil {
				t.Errorf("%s: structuredContent against outputSchema: %v", version, err)
			}
		}
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	catalog := NewDaemonMcpCatalog(newTestMcpServer(newFakeMcpDaemon(), clock), nil)
	if err := checkMcpCatalog(catalog); err != nil {
		t.Error(err)
	}
	if !slices.Contains(catalog.Names(), "run_restore") {
		t.Error("run_restore is not in the daemon's catalog")
	}
}
