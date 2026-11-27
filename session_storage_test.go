//go:build !ios_extension && !sidecar_http && !js

// CTXH-M11-06's storage view, retention and pruning (DESIGN-COMPUTE §24.10, §24.16's Erasure and Sizes rows; R-CTXH-8,
// D-CTXH-8) on sidecartest's streams: retention's expiry keeps every node a live run's path needs, the run itself and
// the run it continues, while another run's nodes expire; a part pruned by `ur record erase --run --blobs-only` reads
// as its marker in a rebuild and in a continued run's context, unverifiable and never a fault; and §24.10's Harness
// rows measured on a synthetic corpus fall within the estimate. External, on session_journal_test.go's world.

package sidecar_test

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A session journal world whose device administers the vault, as an erasure and a retention pass ask.
func newTestSessionAdminWorld(t *testing.T) *testSessionJournalWorld {
	t.Helper()
	recordWorld := newTestRecordWorld(t)
	eraser, _ := recordWorld.eraserDevice()
	world := &testSessionJournalWorld{t: t, world: recordWorld, device: eraser, store: testSessionStore(t), ingest: sidecar.DefaultSidecarSettings().Ingest}
	world.open(nil)
	return world
}

// Expiry keeps a node while a live run's path needs it: with capture kept a day, two days on a pass expires a finished
// run's nodes, but keeps a live run's and the nodes of the run it continues.
func TestSessionExpiryKeepsLivePathNode(t *testing.T) {
	world := newTestSessionAdminWorld(t)
	finished, _ := testSessionContinueSource(t, world, "An old question.", "An old answer.")
	continued, _ := testSessionContinueSource(t, world, "The question a live run took up.", "Its answer.")
	live, _ := testSessionContinueSource(t, world, "The live run's question.", "Its answer so far.")
	// the live run continues the other, as its stage-2 context entry says
	testRecordAppend(t, world.record, &sidecar.RecordDraft{Kind: sidecar.RecordKindContext, Source: sidecar.RecordSourceObserved, RunId: &live.run.RunId,
		Body: &protocol.ContextBody{Stage: 2, Harness: sidecar.HarnessRunHarnessName, ContinuesRunId: continued.run.RunId.Bytes(), ContinuesEntryId: sidecar.NewId().Bytes()}})
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := world.record.Retention().Set(t.Context(), &sidecar.RecordRetentionSetArgs{LogId: world.world.vaultId, Class: sidecar.RecordClassCapture,
		KeepDays: 1, Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	storage, err := sidecar.NewSessionStorage(&sidecar.SessionStorageArgs{Record: world.record, Live: &testSessionRunLiveness{live: live.run.RunId}})
	if err != nil {
		t.Fatal(err)
	}
	world.record.Retention().SetHold(storage.LiveHold)
	world.world.clock.Advance(48 * time.Hour)
	pass, err := world.record.Retention().Expire(t.Context(), &sidecar.RecordRetentionExpireArgs{LogId: world.world.vaultId})
	if err != nil {
		t.Fatal(err)
	}
	if len(pass.Expired) == 0 {
		t.Fatal("the pass expired nothing")
	}
	for _, check := range []struct {
		recorder *testSessionRecorder
		kept     bool
	}{{finished, false}, {continued, true}, {live, true}} {
		states := testSessionCapStates(testSessionCapRead(t, world, check.recorder.run.RunId), sidecar.RecordKindSessionEntry)
		gone := slices.ContainsFunc(states, func(state sidecar.RecordEntryState) bool { return state.KeyGone() })
		if gone == check.kept || len(states) == 0 {
			t.Errorf("run %s: nodes %v, kept %v", check.recorder.run.RunId, states, check.kept)
		}
	}
}

// A status a test sets: one run live, every other idle in no run of its own.
type testSessionRunLiveness struct {
	live sidecar.Id
}

func (self *testSessionRunLiveness) RunState(ctx context.Context, agentId sidecar.Id, runId sidecar.Id) (sidecar.AgentState, error) {
	if runId == self.live {
		return sidecar.AgentStateWorking, nil
	}
	return sidecar.AgentStateOffline, nil
}

// A part `ur record erase --run --blobs-only` pruned reads [pruned: <size>, sha256 <8 hex>] in the call's rebuild,
// which reads unverifiable there with no alarm, and in a continued run's context; the run's nodes stay.
func TestSessionPrunedPartRendersMarker(t *testing.T) {
	world := newTestSessionAdminWorld(t)
	recorder, result := testSessionCapRun(t, world, 256*1024)
	pruned, err := world.record.SessionPrune(t.Context(), &sidecar.SessionPruneSpec{RunId: &recorder.run.RunId, Scope: sidecar.RecordEraseRunBlobs}, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned.Erased) == 0 {
		t.Fatal("the prune erased no blob")
	}
	part := recorder.nodes[result].journaled.Parts[0]
	marker := sidecar.SessionPartMarker(part)
	if !strings.HasPrefix(marker, "[pruned: ") {
		t.Fatalf("the marker %q", marker)
	}
	device := world.world.device(true)
	sessions := device.open().SessionReader()
	view, err := sessions.Open(t.Context(), world.world.vaultId, recorder.run.RunId)
	if err != nil {
		t.Fatal(err)
	}
	call, _ := view.Call(1)
	rebuilt, err := sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: view, Call: call})
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Check != sidecar.SessionCheckUnverifiable || rebuilt.Fault != "" || rebuilt.Request == nil {
		t.Fatalf("the pruned call's rebuild: %s %s", rebuilt.Check, rebuilt.Fault)
	}
	shown := ""
	for _, message := range rebuilt.Request.Messages {
		shown += message.Text()
	}
	if !strings.Contains(shown, marker) || !slices.ContainsFunc(rebuilt.Path, func(node *sidecar.SessionRebuiltNode) bool {
		return strings.Contains(node.Why, marker)
	}) {
		t.Fatalf("the rebuild does not show the marker %s", marker)
	}
	for _, reason := range device.alarmReasons() {
		t.Errorf("an alarm: %s", reason)
	}
	// a continued run's context carries the marker where the part stood
	desktop := newTestSessionHarnessHost(t, world.world, false)
	desktop.live.set(sidecar.AgentStateIdle, nil)
	continued, err := desktop.continues.Continue(t.Context(), &sidecar.SessionContinueSpec{RunId: recorder.run.RunId, Model: testSessionContinueModel})
	if err != nil {
		t.Fatal(err)
	}
	if continued.Plan.PrunedPartCount != 1 {
		t.Fatalf("the plan counts %d pruned parts", continued.Plan.PrunedPartCount)
	}
	agent, _ := desktop.harness.Agent(continued.AgentId)
	desktop.prompt(agent, "Go on without it.")
	sent := ""
	for _, message := range desktop.router.made()[0].Messages {
		sent += message.Text()
	}
	if !strings.Contains(sent, marker) || strings.Contains(sent, "a log line of the build a log line") {
		t.Fatal("the continued context does not carry the marker where the part stood")
	}
}

// §24.10's Harness rows on a synthetic corpus, by the storage view's reckoning (each node's header and its body's
// padded size, sealed): a 30-turn task, ~150 messages with a ~25 KiB system message and ~8 KiB of results a turn,
// within 0.5-1 MiB; a research run of 20 fetches, its pages whole, within 1.5-3 MiB. Each estimate is by inference, so
// a run passes within a factor of two either side of its row, the bytes logged against it.
func TestSessionSizesSyntheticCorpusWithinEstimate(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	task := newTestSessionRecorder(t, world)
	system := task.message("", testSessionRebuildSystem(strings.Repeat("Work in small steps and say what you change. ", 570)), "")
	leaf := system
	for turn := range 30 {
		leaf = task.message(leaf, testSessionRebuildUser("Turn "+string(rune('A'+turn%26))+": "+strings.Repeat("look at the next module ", 8)), "")
		callId := "call-" + sidecar.NewHarnessPiEntryId()
		leaf = task.message(leaf, testSessionRebuildAssistant("", strings.Repeat("thinking about it ", 20),
			&sidecar.HarnessPiToolCall{Id: callId, Name: "evs_read", Arguments: []byte(`{"path":"src/module.go"}`)}), "")
		leaf = task.message(leaf, testSessionRebuildResult(callId, "evs_read", strings.Repeat("func step() { return } // ", 8*1024/26)), "")
		leaf = task.message(leaf, testSessionRebuildAssistant(strings.Repeat("The module reads cleanly. ", 30), ""), "")
		leaf = task.message(leaf, testSessionRebuildUser("ok"), "")
	}
	research := newTestSessionRecorder(t, world)
	leaf = research.message("", testSessionRebuildSystem("Research the venues."), "")
	for page := range 20 {
		callId := "call-" + sidecar.NewHarnessPiEntryId()
		leaf = research.message(leaf, testSessionRebuildAssistant("", "", &sidecar.HarnessPiToolCall{Id: callId, Name: "web_fetch",
			Arguments: []byte(`{"url":"https://venues.example/page"}`)}), "")
		// each page its own, so no part names another's blobs
		text := strings.Repeat(fmt.Sprintf("Venue %02d's page, its rooms and prices. ", page), 100*1024/38)
		leaf = research.message(leaf, testSessionRebuildResult(callId, "web_fetch", text), "")
	}
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	reader := world.world.device(true).open()
	storage, err := sidecar.NewSessionStorage(&sidecar.SessionStorageArgs{Record: reader})
	if err != nil {
		t.Fatal(err)
	}
	sizes, err := storage.Sizes(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name     string
		runId    sidecar.Id
		low      int64
		high     int64
		messages int
	}{
		{"a 30-turn Harness task", task.run.RunId, 512 * 1024, 1024 * 1024, 151},
		{"a research run with 20 fetches", research.run.RunId, 1536 * 1024, 3 * 1024 * 1024, 41},
	} {
		index := slices.IndexFunc(sizes.Runs, func(run *sidecar.SessionRunSize) bool { return run.RunId == row.runId })
		if index < 0 {
			t.Fatalf("%s is not in the view", row.name)
		}
		run := sizes.Runs[index]
		t.Logf("%s: %d nodes, %d bytes of nodes and %d of blobs, against %d-%d", row.name, run.NodeCount, run.NodeByteCount, run.BlobByteCount, row.low, row.high)
		if run.NodeCount != row.messages || run.ByteCount() < row.low/2 || 2*row.high < run.ByteCount() {
			t.Errorf("%s holds %d bytes in %d nodes, outside %d-%d", row.name, run.ByteCount(), run.NodeCount, row.low, row.high)
		}
	}
	if sizes.NodeByteCount+sizes.BlobByteCount == 0 || sizes.VaultByteCount < sizes.NodeByteCount+sizes.BlobByteCount || len(sizes.ByDevice) != 1 {
		t.Fatalf("the totals: %+v", sizes)
	}
	if !bytes.Equal(sizes.ByDevice[0].Id.Bytes(), world.device.sidecarId.Bytes()) {
		t.Fatal("the history is not the writing device's")
	}
}
