//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's ingest on sidecartest's FakeHarness and a collecting record writer: a scripted run per harness, every cut
// a gap, redaction before the seal, the transcript's tail across a restart, idle coverage, instruction files by
// hash, the run-hour cap and a scan's change and blob entries.

package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A synthetic secret the redactor's ur_sk_ rule matches. Never a real one.
const ingestTestSecret = "ur_sk_0123456789abcdef0123456789abcdef"

// A record writer that keeps each draft, checking its body as the real one does, and answers a growing seq.
type testRecordWriter struct {
	stateLock sync.Mutex
	drafts    []*sidecar.RecordDraft
	refs      []*sidecar.RecordEntryRef
	nextSeq   uint64
	logId     sidecar.Id
}

func newTestRecordWriter() *testRecordWriter {
	return &testRecordWriter{logId: sidecar.NewId()}
}

func (self *testRecordWriter) Append(draft *sidecar.RecordDraft) ([]*sidecar.RecordEntryRef, error) {
	if err := sidecar.RecordBodyValidate(draft.Kind, draft.Body); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nextSeq += 1
	ref := &sidecar.RecordEntryRef{LogId: self.logId, EntryId: sidecar.NewId(), Seq: self.nextSeq}
	self.drafts = append(self.drafts, draft)
	self.refs = append(self.refs, ref)
	return []*sidecar.RecordEntryRef{ref}, nil
}

// The drafts of kind, in order.
func (self *testRecordWriter) of(kind sidecar.RecordKind) []*sidecar.RecordDraft {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	drafts := []*sidecar.RecordDraft{}
	for _, draft := range self.drafts {
		if draft.Kind == kind {
			drafts = append(drafts, draft)
		}
	}
	return drafts
}

// Every draft's kind, in order.
func (self *testRecordWriter) kinds() []sidecar.RecordKind {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kinds := []sidecar.RecordKind{}
	for _, draft := range self.drafts {
		kinds = append(kinds, draft.Kind)
	}
	return kinds
}

// The hook env with an Ingest over it.
type ingestTestEnv struct {
	*hookTestEnv
	writer   *testRecordWriter
	redactor *sidecar.Redactor
	ingest   *Ingest
	restore  *RestorePoints
	// the project directory the harnesses work in, a real one
	cwd string
}

// The env, ingest installed, over a real temporary project directory.
func newIngestTestEnv(t *testing.T) *ingestTestEnv {
	t.Helper()
	hook := newHookTestEnv(t)
	redactor, err := sidecar.NewRedactor(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cwd := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
		cwd = resolved
	}
	env := &ingestTestEnv{hookTestEnv: hook, writer: newTestRecordWriter(), redactor: redactor, cwd: cwd}
	env.install()
	return env
}

// Installs a new Ingest on the current server, as a daemon's start does.
func (self *ingestTestEnv) install() {
	self.ingest = NewIngest(&IngestArgs{
		Server:    self.server,
		Writers:   func(network McpNetwork) (sidecar.RecordWriter, error) { return self.writer, nil },
		Redactors: func(network McpNetwork) (*sidecar.Redactor, error) { return self.redactor, nil },
		Restore:   self.restore,
		Record:    sidecar.DefaultSidecarSettings().Record,
	})
}

// A daemon's restart: a new server and a new Ingest over the same stores.
func (self *ingestTestEnv) restartIngest() {
	self.ingest.detach()
	self.restart()
	self.install()
}

// A harness of kind working in the env's directory.
func (self *ingestTestEnv) harnessIn(kind string) *sidecartest.FakeHarness {
	return sidecartest.NewFakeHarness(self.table, self.terminal.Identity.Pid, kind, self.cwd, self.sink)
}

// The run file as it stands.
func (self *ingestTestEnv) runFile(runId sidecar.Id) *sidecar.RunFile {
	self.t.Helper()
	file, err := self.network.runs.Get(runId)
	if err != nil {
		self.t.Fatalf("run %s: %s", runId, err)
	}
	return file
}

// Whether the run's gaps hold code.
func (self *ingestTestEnv) hasGap(runId sidecar.Id, code string) bool {
	for _, gap := range self.runFile(runId).Gaps {
		if gapCode, _, ok := sidecar.RecordCoverageGapParse(gap); ok && gapCode == code {
			return true
		}
	}
	return false
}

// Writes the transcript file a Claude Code or Codex harness names for sessionId.
func (self *ingestTestEnv) writeTranscript(sessionId string, content string) string {
	self.t.Helper()
	path := filepath.Join(self.cwd, ".transcripts", sessionId+".jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		self.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		self.t.Fatal(err)
	}
	return path
}

// A scripted run on each harness: the entries by kind and source, the title, the coverage and the run file's note
// of it.
func TestScriptedRunPerHarness(t *testing.T) {
	for _, kind := range []string{sidecartest.FakeHarnessClaudeCode, sidecartest.FakeHarnessCodex, sidecartest.FakeHarnessCursor} {
		env := newIngestTestEnv(t)
		env.writeTranscript("s1", "{\"type\":\"user\",\"text\":\"hello\"}\n{\"type\":\"assistant\",\"text\":\"hi\"}\n")
		harness := env.harnessIn(kind)
		if kind == sidecartest.FakeHarnessClaudeCode {
			if err := harness.SessionStart("s1", "startup"); err != nil {
				t.Fatal(err)
			}
		}
		promptEvent := "UserPromptSubmit"
		if kind == sidecartest.FakeHarnessCursor {
			promptEvent = "beforeSubmitPrompt"
		}
		if err := harness.Hook(harness.Payload("s1", promptEvent, map[string]any{"prompt": "Fix the build\nand then more"})); err != nil {
			t.Fatal(err)
		}
		editInput := map[string]any{"file_path": filepath.Join(env.cwd, "main.go"), "old_string": "a", "new_string": "b"}
		if kind != sidecartest.FakeHarnessCursor {
			// Cursor has no pre-edit event
			if err := harness.ToolCall("s1", true, "Edit", editInput); err != nil {
				t.Fatal(err)
			}
		}
		if err := harness.ToolCall("s1", false, "Edit", editInput); err != nil {
			t.Fatal(err)
		}
		if err := harness.ToolCall("s1", false, "mcp__ur__evs_read", map[string]any{"repo": "notes", "path": "plan.md"}); err != nil {
			t.Fatal(err)
		}
		if kind != sidecartest.FakeHarnessCursor {
			if err := harness.Hook(harness.Payload("s1", "PermissionRequest", map[string]any{"tool_name": "mcp__ur__mail_send", "tool_input": map[string]any{"to": "a@mail.example"}})); err != nil {
				t.Fatal(err)
			}
		}
		if err := harness.SessionEnd("s1", "exit"); err != nil {
			t.Fatal(err)
		}
		runId := env.runOf(kind, "s1")
		if kind == sidecartest.FakeHarnessCursor {
			// Cursor's stop is no SessionEnd: the run ends by idling
			env.clock.Advance(sidecar.DefaultSidecarSettings().Record.CoverageIdleTimeout + time.Second)
		}
		contexts := env.writer.of(sidecar.RecordKindContext)
		if len(contexts) == 0 || contexts[0].Source != sidecar.RecordSourceHook || contexts[0].Body.(*protocol.ContextBody).Stage != 1 {
			t.Fatalf("%s: context entries %+v", kind, contexts)
		}
		if harnessName := contexts[0].Body.(*protocol.ContextBody).Harness; harnessName != kind {
			t.Errorf("%s: the context names harness %q", kind, harnessName)
		}
		toolCalls := env.writer.of(sidecar.RecordKindToolCall)
		if len(toolCalls) != 2 {
			t.Fatalf("%s: %d tool calls", kind, len(toolCalls))
		}
		for _, call := range toolCalls {
			if call.Source != sidecar.RecordSourceHook || len(call.ActionId) != 32 || *call.RunId != runId {
				t.Errorf("%s: a tool call's header %+v", kind, call)
			}
		}
		edit := toolCalls[0].Body.(*protocol.ToolCallBody)
		if edit.ToolClass != ingestToolClassEdit || !slices.Equal(edit.Paths, []string{"main.go"}) {
			t.Errorf("%s: the edit's body %+v", kind, edit)
		}
		if mcpCall := toolCalls[1].Body.(*protocol.ToolCallBody); mcpCall.ToolClass != ingestToolClassMcp || mcpCall.ToolName != "ur/evs_read" {
			t.Errorf("%s: the MCP call's body %+v", kind, mcpCall)
		}
		if kind != sidecartest.FakeHarnessCursor {
			if edit.ToolUseId == "" {
				t.Errorf("%s: no tool_use_id", kind)
			}
			if env.hasGap(runId, sidecar.RecordCoverageGapNoToolId) {
				t.Errorf("%s: a no_tool_id gap with ids given", kind)
			}
			permissions := env.writer.of(sidecar.RecordKindPermission)
			if len(permissions) != 1 || permissions[0].Body.(*protocol.PermissionBody).ToolName != "mail_send" || permissions[0].Body.(*protocol.PermissionBody).Decision != ingestPermissionAsked {
				t.Errorf("%s: permission entries %+v", kind, permissions)
			}
			transcripts := env.writer.of(sidecar.RecordKindTranscript)
			if len(transcripts) != 1 || transcripts[0].Body.(*protocol.TranscriptBody).LineCount != 2 || transcripts[0].Body.(*protocol.TranscriptBody).FirstLine != 1 {
				t.Errorf("%s: transcript entries %+v", kind, transcripts)
			}
		} else if !env.hasGap(runId, sidecar.RecordCoverageGapMissedEvent) {
			t.Errorf("%s: a null transcript path is no gap", kind)
		}
		hookEvents := env.writer.of(sidecar.RecordKindHookEvent)
		if len(hookEvents) == 0 {
			t.Errorf("%s: no hook_event entries", kind)
		}
		for _, hookEvent := range hookEvents {
			if hookEvent.Body.(*protocol.HookEventBody).Event == "PostToolUse" || hookEvent.Body.(*protocol.HookEventBody).Event == "afterMCPExecution" {
				t.Errorf("%s: a PostToolUse became a hook_event too", kind)
			}
		}
		coverages := env.writer.of(sidecar.RecordKindCoverage)
		if len(coverages) != 1 || coverages[0].Source != sidecar.RecordSourceObserved {
			t.Fatalf("%s: coverage entries %+v", kind, coverages)
		}
		coverage := coverages[0].Body.(*protocol.Coverage)
		if !bytes.Equal(coverage.RunId, runId[:]) || coverage.Harness != kind || !slices.Contains(coverage.Sources, sidecar.RecordCoverageSourceHooks) || coverage.FirstSeq == 0 || coverage.LastSeq < coverage.FirstSeq {
			t.Errorf("%s: the coverage body %+v", kind, coverage)
		}
		if file := env.runFile(runId); file.CoverageMillis == 0 || file.FirstSeq != coverage.FirstSeq || file.LastSeq != coverage.LastSeq {
			t.Errorf("%s: the run file after coverage %+v", kind, file)
		}
		if capture := env.ingest.Capture(env.networkId, runId); capture == nil || capture.Title != "Fix the build" || capture.ToolCounts["Edit"]+capture.ToolCounts["edit"] != 1 || capture.EndedMillis == 0 {
			t.Errorf("%s: the run capture %+v", kind, capture)
		}
	}
}

// Every cut, missed event, redaction, bypass mode, changed config, downtime and oversize payload is a gap on the
// run file where it occurred, and the coverage names it.
func TestEveryCutIsAGap(t *testing.T) {
	cases := []struct {
		name string
		code string
		run  func(env *ingestTestEnv, harness *sidecartest.FakeHarness)
	}{
		{"an oversize payload", sidecar.RecordCoverageGapOversize, func(env *ingestTestEnv, harness *sidecartest.FakeHarness) {
			payload := harness.Payload("s1", "Stop", nil)
			hook := harness.ShellChild("ur")
			env.server.HandleHook(context.Background(), &sidecar.DaemonHello{Mode: sidecar.DaemonModeHook, Harness: "claude-code", Cwd: env.cwd, Pid: int64(hook.Identity.Pid), PeerPid: int64(hook.Identity.Pid)},
				env.networkId, env.network, &HookEventParams{Payload: payload, ByteCount: 2 * 1024 * 1024, Oversize: true})
		}},
		{"a tool body past the cap", sidecar.RecordCoverageGapTruncation, func(env *ingestTestEnv, harness *sidecartest.FakeHarness) {
			env.server.settings.Ingest.PayloadByteCount = 64
			session := env.server.newSession(harness.RelayHello(""))
			env.ingest.RecordMcpCall(context.Background(), env.call(session), "evs_read", []byte(`{}`), []byte(strings.Repeat("x", 200)), 1, 2, nil)
			if calls := env.writer.of(sidecar.RecordKindToolCall); len(calls) != 1 || !calls[0].Body.(*protocol.ToolCallBody).Truncated || 64 < len(calls[0].Body.(*protocol.ToolCallBody).Output) {
				env.t.Errorf("the cut body: %+v", calls)
			}
			env.server.settings.Ingest.PayloadByteCount = 1024 * 1024
		}},
		{"a transcript line past the cap", sidecar.RecordCoverageGapTruncation, func(env *ingestTestEnv, harness *sidecartest.FakeHarness) {
			env.writeTranscript("s1", "{\"short\":1}\n{\"long\":\""+strings.Repeat("y", 2000)+"\"}\n{\"after\":3}\n")
			env.server.settings.Ingest.PayloadByteCount = 1024
			harness.Hook(harness.Payload("s1", "Stop", nil))
			transcripts := env.writer.of(sidecar.RecordKindTranscript)
			if len(transcripts) != 3 || !transcripts[1].Body.(*protocol.TranscriptBody).Truncated || transcripts[2].Body.(*protocol.TranscriptBody).FirstLine != 3 {
				env.t.Errorf("the cut line: %d entries %+v", len(transcripts), transcripts)
			}
		}},
		{"a missed event while Locked", sidecar.RecordCoverageGapMissedEvent, func(env *ingestTestEnv, harness *sidecartest.FakeHarness) {
			env.network.setState(sidecar.SidecarStateLocked)
			harness.Hook(harness.Payload("s1", "Stop", nil))
			env.network.setState(sidecar.SidecarStateOnline)
			harness.Hook(harness.Payload("s1", "Stop", nil))
		}},
		{"a changed config", sidecar.RecordCoverageGapConfigChanged, func(env *ingestTestEnv, harness *sidecartest.FakeHarness) {
			env.server.Binder().SetConfigCheck(func(ctx context.Context, harness string, cwd string) (bool, error) { return true, nil })
			env.clock.Advance(env.server.settings.Ingest.ConfigCheckInterval + time.Second)
			harness.Hook(harness.Payload("s1", "Stop", nil))
		}},
		{"downtime", sidecar.RecordCoverageGapDowntime, func(env *ingestTestEnv, harness *sidecartest.FakeHarness) {
			env.restartIngest()
			harness.Hook(harness.Payload("s1", "Stop", nil))
		}},
		{"a bypass mode", sidecar.RecordCoverageGapBypassMode, func(env *ingestTestEnv, harness *sidecartest.FakeHarness) {
			harness.Hook(harness.Payload("s1", "Stop", map[string]any{"permission_mode": "bypassPermissions"}))
		}},
		{"a redaction", sidecar.RecordCoverageGapRedaction, func(env *ingestTestEnv, harness *sidecartest.FakeHarness) {
			harness.Hook(harness.Payload("s1", "PostToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "echo"}, "tool_response": "key=" + ingestTestSecret, "tool_use_id": "toolu_1"}))
		}},
	}
	for _, c := range cases {
		env := newIngestTestEnv(t)
		env.writeTranscript("s1", "{}\n")
		harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
		if err := harness.SessionStart("s1", "startup"); err != nil {
			t.Fatal(err)
		}
		runId := env.runOf("claude-code", "s1")
		c.run(env, harness)
		if !env.hasGap(runId, c.code) {
			t.Errorf("%s: no %s gap: %v", c.name, c.code, env.runFile(runId).Gaps)
			continue
		}
		harness.SessionEnd("s1", "exit")
		coverages := env.writer.of(sidecar.RecordKindCoverage)
		if len(coverages) == 0 {
			t.Errorf("%s: no coverage", c.name)
			continue
		}
		found := false
		for _, gap := range coverages[len(coverages)-1].Body.(*protocol.Coverage).Gaps {
			if code, _, ok := sidecar.RecordCoverageGapParse(gap); ok && code == c.code {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: the coverage does not name %s", c.name, c.code)
		}
	}
}

// A secret in a tool response, a hook payload, a prompt or the transcript is redacted before anything is sealed.
func TestSecretRedactedBeforeSeal(t *testing.T) {
	env := newIngestTestEnv(t)
	env.writeTranscript("s1", "{\"text\":\"token "+ingestTestSecret+"\"}\n")
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	harness.SessionStart("s1", "startup")
	harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": "use " + ingestTestSecret + " please"}))
	harness.Hook(harness.Payload("s1", "PreToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "export K=" + ingestTestSecret}, "tool_use_id": "toolu_1"}))
	harness.Hook(harness.Payload("s1", "PostToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "export K=" + ingestTestSecret}, "tool_response": "K=" + ingestTestSecret, "tool_use_id": "toolu_1"}))
	harness.SessionEnd("s1", "exit")
	for _, draft := range env.writer.drafts {
		encoded, err := proto.Marshal(draft.Body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte(ingestTestSecret)) {
			t.Errorf("a %s entry carries the secret", draft.Kind)
		}
	}
	toolCalls := env.writer.of(sidecar.RecordKindToolCall)
	if len(toolCalls) != 1 || !bytes.Contains(toolCalls[0].Body.(*protocol.ToolCallBody).Output, []byte("[REDACTED:")) {
		t.Errorf("the tool call's output: %+v", toolCalls)
	}
	if capture := env.ingest.Capture(env.networkId, env.runOf("claude-code", "s1")); strings.Contains(capture.Title, ingestTestSecret) || strings.Contains(capture.Prompts, ingestTestSecret) {
		t.Errorf("the run card carries the secret: %+v", capture)
	}
	runId := env.runOf("claude-code", "s1")
	if !env.hasGap(runId, sidecar.RecordCoverageGapRedaction) {
		t.Error("no redaction gap")
	}
}

// The transcript's tail takes whole lines only, and resumes after a restart from the byte it reached.
func TestTailResumesAfterRestart(t *testing.T) {
	env := newIngestTestEnv(t)
	path := env.writeTranscript("s1", "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n{\"part")
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	harness.SessionStart("s1", "startup")
	harness.Hook(harness.Payload("s1", "Stop", nil))
	transcripts := env.writer.of(sidecar.RecordKindTranscript)
	if len(transcripts) != 1 {
		t.Fatalf("%d transcript entries", len(transcripts))
	}
	first := transcripts[0].Body.(*protocol.TranscriptBody)
	if first.FirstLine != 1 || first.LineCount != 3 || !bytes.HasSuffix(first.Lines, []byte("{\"n\":3}\n")) || bytes.Contains(first.Lines, []byte("part")) {
		t.Errorf("the first tail: %+v", first)
	}
	env.restartIngest()
	harness = env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := os.WriteFile(path, []byte("{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n{\"partial\":4}\n{\"n\":5}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	harness.Hook(harness.Payload("s1", "Stop", nil))
	transcripts = env.writer.of(sidecar.RecordKindTranscript)
	if len(transcripts) != 2 {
		t.Fatalf("%d transcript entries after the restart", len(transcripts))
	}
	second := transcripts[1].Body.(*protocol.TranscriptBody)
	if second.FirstLine != 4 || second.LineCount != 2 || string(second.Lines) != "{\"partial\":4}\n{\"n\":5}\n" {
		t.Errorf("the tail after a restart: %+v", second)
	}
	// the periodic tail, on the clock
	if err := os.WriteFile(path, []byte("{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n{\"partial\":4}\n{\"n\":5}\n{\"n\":6}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(env.server.settings.Ingest.TranscriptTailInterval + time.Second)
	if transcripts = env.writer.of(sidecar.RecordKindTranscript); len(transcripts) != 3 || transcripts[2].Body.(*protocol.TranscriptBody).FirstLine != 6 {
		t.Errorf("the periodic tail: %d entries", len(transcripts))
	}
}

// A run with no SessionEnd is covered after CoverageIdleTimeout, and a later event re-opens it: its next coverage
// supersedes, and the run file's note moves to it.
func TestIdleCoverageThenContinues(t *testing.T) {
	env := newIngestTestEnv(t)
	env.writeTranscript("s1", "{}\n")
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	harness.SessionStart("s1", "startup")
	runId := env.runOf("claude-code", "s1")
	idle := sidecar.DefaultSidecarSettings().Record.CoverageIdleTimeout
	env.clock.Advance(idle / 2)
	harness.Hook(harness.Payload("s1", "Stop", nil))
	env.clock.Advance(idle / 2)
	if len(env.writer.of(sidecar.RecordKindCoverage)) != 0 {
		t.Fatal("covered before the idle timeout since the last event")
	}
	env.clock.Advance(idle/2 + time.Second)
	coverages := env.writer.of(sidecar.RecordKindCoverage)
	if len(coverages) != 1 {
		t.Fatalf("%d coverages after idling", len(coverages))
	}
	firstMillis := env.runFile(runId).CoverageMillis
	if firstMillis == 0 {
		t.Fatal("the run file does not note the coverage")
	}
	env.clock.Advance(time.Minute)
	harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": "again"}))
	harness.SessionEnd("s1", "exit")
	coverages = env.writer.of(sidecar.RecordKindCoverage)
	if len(coverages) != 2 {
		t.Fatalf("%d coverages after the run continued", len(coverages))
	}
	if file := env.runFile(runId); file.CoverageMillis <= firstMillis {
		t.Errorf("the run file's coverage did not move: %d then %d", firstMillis, file.CoverageMillis)
	}
	if first, second := coverages[0].Body.(*protocol.Coverage), coverages[1].Body.(*protocol.Coverage); second.LastSeq <= first.LastSeq {
		t.Errorf("the later coverage's range: %+v then %+v", first, second)
	}
}

// Instruction files reach the context entry by base name, hash and size, never by text.
func TestInstructionFilesByHashOnly(t *testing.T) {
	env := newIngestTestEnv(t)
	instructions := "Always run the tests. The deploy key is " + ingestTestSecret + ".\n"
	if err := os.WriteFile(filepath.Join(env.cwd, "CLAUDE.md"), []byte(instructions), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(env.cwd, ".cursor", "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.cwd, ".cursor", "rules", "go.mdc"), []byte("rules\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	harness.SessionStart("s1", "startup")
	contexts := env.writer.of(sidecar.RecordKindContext)
	if len(contexts) != 1 {
		t.Fatalf("%d context entries", len(contexts))
	}
	body := contexts[0].Body.(*protocol.ContextBody)
	names := map[string]*protocol.InstructionFile{}
	for _, file := range body.InstructionFiles {
		names[file.Name] = file
	}
	sum := sha256.Sum256([]byte(instructions))
	if file := names["CLAUDE.md"]; file == nil || !bytes.Equal(file.Sha256, sum[:]) || file.Size != uint64(len(instructions)) || file.Scope != ingestInstructionScopeProject {
		t.Errorf("CLAUDE.md: %+v", file)
	}
	if file := names["go.mdc"]; file == nil {
		t.Error("a rules directory's file is not listed")
	}
	encoded, _ := proto.Marshal(body)
	if bytes.Contains(encoded, []byte("Always run")) || bytes.Contains(encoded, []byte(ingestTestSecret)) {
		t.Error("the context entry carries an instruction file's text")
	}
	if body.Project != filepath.Base(env.cwd) {
		t.Errorf("the project: %q", body.Project)
	}
}

// Past RunHourByteCount in an hour the rest of that hour's bodies are dropped, oversize, and the next hour takes
// them again.
func TestRunHourCap(t *testing.T) {
	env := newIngestTestEnv(t)
	env.server.settings.Ingest.RunHourByteCount = 150
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	harness.SessionStart("s1", "startup")
	runId := env.runOf("claude-code", "s1")
	call := func(id string) {
		harness.Hook(harness.Payload("s1", "PostToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}, "tool_response": strings.Repeat("y", 60), "tool_use_id": id}))
	}
	call("toolu_1")
	call("toolu_2")
	if calls := env.writer.of(sidecar.RecordKindToolCall); len(calls) != 1 {
		t.Fatalf("%d tool calls within the hour's cap", len(calls))
	}
	if !env.hasGap(runId, sidecar.RecordCoverageGapOversize) {
		t.Error("the dropped body is no gap")
	}
	env.clock.Advance(time.Hour + time.Second)
	call("toolu_3")
	if calls := env.writer.of(sidecar.RecordKindToolCall); len(calls) != 2 || calls[1].Body.(*protocol.ToolCallBody).ToolUseId != "toolu_3" {
		t.Errorf("the next hour: %d tool calls", len(calls))
	}
}

// The daemon's own MCP call is a tool_call of source observed, and the coverage names mcp among its sources.
func TestMcpCallObserved(t *testing.T) {
	env := newIngestTestEnv(t)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	harness.SessionStart("s1", "startup")
	session := env.server.newSession(harness.RelayHello(""))
	call := env.call(session)
	env.ingest.RecordMcpCall(context.Background(), call, "evs_read", []byte(`{"repo":"notes"}`), []byte(`{"text":"`+ingestTestSecret+`"}`), 1, 2, nil)
	calls := env.writer.of(sidecar.RecordKindToolCall)
	if len(calls) != 1 || calls[0].Source != sidecar.RecordSourceObserved || calls[0].Body.(*protocol.ToolCallBody).ToolName != "ur/evs_read" {
		t.Fatalf("the observed call: %+v", calls)
	}
	if bytes.Contains(calls[0].Body.(*protocol.ToolCallBody).Output, []byte(ingestTestSecret)) {
		t.Error("the result carries the secret")
	}
	harness.SessionEnd("s1", "exit")
	coverages := env.writer.of(sidecar.RecordKindCoverage)
	if len(coverages) != 1 || !slices.Contains(coverages[0].Body.(*protocol.Coverage).Sources, sidecar.RecordCoverageSourceMcp) {
		t.Errorf("the coverage's sources: %+v", coverages)
	}
}

// A hook's scan of the restore point writes a change entry with hashes and attribution, and a blob of the after
// bytes, once per hash.
func TestScanWritesChangeAndBlob(t *testing.T) {
	restoreEnv := newRestoreTestEnv(t)
	env := newIngestTestEnv(t)
	env.cwd = restoreEnv.dir
	env.restore = NewRestorePoints(&RestorePointsArgs{Clock: env.clock, Ingest: env.server.settings.Ingest})
	env.install()
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	harness.SessionStart("s1", "startup")
	runId := env.runOf("claude-code", "s1")
	path := filepath.Join(env.cwd, "committed.txt")
	input := map[string]any{"file_path": path, "old_string": "two", "new_string": "2"}
	harness.ToolCall("s1", true, "Edit", input)
	restoreEnv.write("committed.txt", "one\n2\nthree\n")
	harness.ToolCall("s1", false, "Edit", input)
	changes := env.writer.of(sidecar.RecordKindChange)
	if len(changes) != 1 || changes[0].Source != sidecar.RecordSourceObserved {
		t.Fatalf("change entries: %+v", changes)
	}
	change := changes[0].Body.(*protocol.ChangeBody)
	if change.EditCount != 1 || len(change.Paths) != 1 || change.Paths[0].Path != "committed.txt" || change.Paths[0].Attribution != uint32(RestoreAttributionEdit) ||
		!bytes.Equal(change.Paths[0].AfterSha256, sha256Of([]byte("one\n2\nthree\n"))) || !bytes.Equal(change.Paths[0].BeforeSha256, sha256Of([]byte("one\ntwo\nthree\n"))) || change.BaseCommit == "" {
		t.Errorf("the change body: %+v", change)
	}
	blobs := env.writer.of(sidecar.RecordKindBlob)
	if len(blobs) != 1 || string(blobs[0].Body.(*protocol.BlobBody).Content) != "one\n2\nthree\n" || len(change.Paths[0].BlobEntryId) != 16 {
		t.Fatalf("blob entries: %+v", blobs)
	}
	// the same bytes again store no second blob
	harness.ToolCall("s1", false, "Bash", map[string]any{"command": "true"})
	if len(env.writer.of(sidecar.RecordKindBlob)) != 1 {
		t.Error("an unchanged tree wrote a blob")
	}
	point, _ := env.restore.Point(env.networkId, runId)
	if ok, reason, err := point.Restorable(context.Background(), "committed.txt"); !ok || err != nil {
		t.Errorf("restorable %t %q %v", ok, reason, err)
	}
	harness.SessionEnd("s1", "exit")
	if coverage := env.writer.of(sidecar.RecordKindCoverage); len(coverage) != 1 || !slices.Contains(coverage[0].Body.(*protocol.Coverage).Sources, sidecar.RecordCoverageSourceScan) {
		t.Errorf("the coverage's sources: %+v", coverage)
	}
}
