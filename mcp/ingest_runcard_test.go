//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M10-02's tests of the run-card inputs and cadence (§16.10's run card row; RECORD.md 7.4; D-MCP-24): a card's
// inputs, the title, agent label, model, project, tool names, touched paths and prompts, redacted before they are
// sealed, within their caps, and RunCapture mirroring what the entries carry; a label the record's grammar refuses
// written as none, the context entry sealing all the same; and the dues, at once at a run's first source entry and at
// the coverage entry that ends it, at most every Record.CardInterval while it gains source entries, none for an event
// that writes no source entry and none after the end. All on the fake clock.

package mcp

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A schedule that keeps each due with the clock's time at it.
type testRunCardSchedule struct {
	clock sidecar.Clock

	stateLock sync.Mutex
	dues      []*testRunCardDue
}

// One due a schedule heard.
type testRunCardDue struct {
	networkId sidecar.Id
	reason    RunCardDueReason
	capture   *RunCapture
	at        time.Time
}

func (self *testRunCardSchedule) RunCardDue(ctx context.Context, networkId sidecar.Id, reason RunCardDueReason, capture *RunCapture) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dues = append(self.dues, &testRunCardDue{networkId: networkId, reason: reason, capture: capture, at: self.clock.Now()})
}

// The dues so far, in order.
func (self *testRunCardSchedule) taken() []*testRunCardDue {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*testRunCardDue{}, self.dues...)
}

// The ingest env with a run-card schedule installed in place of the env's Ingest.
func newRunCardTestEnv(t *testing.T) (*ingestTestEnv, *testRunCardSchedule) {
	t.Helper()
	env := newIngestTestEnv(t)
	schedule := &testRunCardSchedule{clock: env.clock}
	env.ingest = NewIngest(&IngestArgs{
		Server:    env.server,
		Writers:   func(network McpNetwork) (sidecar.RecordWriter, error) { return env.writer, nil },
		Redactors: func(network McpNetwork) (*sidecar.Redactor, error) { return env.redactor, nil },
		Record:    sidecar.DefaultSidecarSettings().Record,
		RunCards:  schedule,
	})
	return env, schedule
}

// The reasons of dues, in order.
func testRunCardReasons(dues []*testRunCardDue) string {
	reasons := []string{}
	for _, due := range dues {
		reasons = append(reasons, string(due.reason))
	}
	return strings.Join(reasons, ",")
}

// §16.10's run card row and RECORD.md 7.4's cadence on the fake clock: a start due at once at the run's first source
// entry; the source entries after it due at most every CardInterval, at its end, or at once when it passed already;
// none for an event that writes no source entry or for an interval with none; an end due at once at the coverage entry
// that ends the run, its moved timer stopped, and nothing after. Each due carries the run's capture as of it.
func TestRunCardCadence(t *testing.T) {
	env, schedule := newRunCardTestEnv(t)
	interval := sidecar.DefaultSidecarSettings().Record.CardInterval
	if interval != 5*time.Minute {
		t.Fatalf("CardInterval is %s, want §16.10's 5 min", interval)
	}
	start := env.clock.Now()
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	edit := func() {
		t.Helper()
		if err := harness.ToolCall("s1", false, "Edit", map[string]any{"file_path": filepath.Join(env.cwd, "main.go")}); err != nil {
			t.Fatal(err)
		}
	}
	at := func(offset time.Duration) {
		t.Helper()
		env.clock.AdvanceTo(start.Add(offset))
	}
	want := func(reasons string, offsets ...time.Duration) []*testRunCardDue {
		t.Helper()
		dues := schedule.taken()
		if got := testRunCardReasons(dues); got != reasons || len(dues) != len(offsets) {
			t.Fatalf("dues %s, want %s", got, reasons)
		}
		for index, offset := range offsets {
			if !dues[index].at.Equal(start.Add(offset)) || dues[index].networkId != env.networkId {
				t.Fatalf("due %d at %s, want %s", index, dues[index].at.Sub(start), offset)
			}
		}
		return dues
	}

	// the run's first source entry, its stage 1 context: a start due at once
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	runId := env.runOf("claude-code", "s1")
	dues := want("start", 0)
	if dues[0].capture.RunId != runId || dues[0].capture.Harness != "claude-code" || dues[0].capture.StartedMillis != start.UnixMilli() {
		t.Fatalf("the start's capture %+v", dues[0].capture)
	}

	// two tool calls inside the interval: one moved due at its end
	at(time.Second)
	edit()
	at(2 * time.Minute)
	edit()
	want("start", 0)
	at(interval - time.Second)
	want("start", 0)
	at(interval)
	dues = want("start,moved", 0, interval)
	if dues[1].capture.ToolCounts["Edit"] != 2 || dues[1].capture.EndedMillis != 0 {
		t.Fatalf("the moved due's capture %+v", dues[1].capture)
	}

	// an interval with no source entry gives none; a prompt then is due at the next interval's end
	at(9 * time.Minute)
	want("start,moved", 0, interval)
	if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": "Fix the limiter\nand its tests"})); err != nil {
		t.Fatal(err)
	}
	at(2 * interval)
	dues = want("start,moved,moved", 0, interval, 2*interval)
	if dues[2].capture.Prompts != "Fix the limiter\nand its tests" || dues[2].capture.Title != "Fix the limiter" {
		t.Fatalf("the prompt's capture %+v", dues[2].capture)
	}

	// a PreToolUse writes a hook_event and no source entry: no due
	at(11 * time.Minute)
	if err := harness.ToolCall("s1", true, "Edit", map[string]any{"file_path": filepath.Join(env.cwd, "main.go")}); err != nil {
		t.Fatal(err)
	}
	at(3 * interval)
	want("start,moved,moved", 0, interval, 2*interval)

	// a source entry once the interval has passed is due at once
	edit()
	want("start,moved,moved,moved", 0, interval, 2*interval, 3*interval)

	// the end: due at once, the armed moved due stopped, nothing after
	at(16 * time.Minute)
	edit()
	at(17 * time.Minute)
	if err := harness.SessionEnd("s1", "exit"); err != nil {
		t.Fatal(err)
	}
	dues = want("start,moved,moved,moved,end", 0, interval, 2*interval, 3*interval, 17*time.Minute)
	if dues[4].capture.EndedMillis != start.Add(17*time.Minute).UnixMilli() || dues[4].capture.ToolCounts["Edit"] != 4 {
		t.Fatalf("the end's capture %+v", dues[4].capture)
	}
	at(40 * time.Minute)
	want("start,moved,moved,moved,end", 0, interval, 2*interval, 3*interval, 17*time.Minute)
}

// §16.10's run card row (D-MCP-24), RECORD.md 6.4's classes and §16.7's redact before seal: a card's inputs reach it
// through the record redacted, the identifier fields as the prose, within their caps, and RunCapture holds the same
// values; no entry sealed holds the secret, each redaction counted; an agent label the record's grammar refuses is
// written as none, and the context entry carrying the rest seals all the same.
func TestRunCardInputsRedacted(t *testing.T) {
	env, schedule := newRunCardTestEnv(t)
	settings := env.server.settings.Ingest
	if sidecar.DefaultSidecarSettings().Ingest.RunCardPathCount != 256 || settings.ContextTitleByteCount != 120 || settings.RunCardPromptByteCount != 2*1024 {
		t.Fatal("a card's caps are not §16.10's 256 paths, 120 B title and 2 KiB of prompts")
	}
	// the path cap at 3 here, so a few calls pass it
	settings.RunCardPathCount = 3
	secret := ingestTestSecret
	// the worktree's name, the project a run in it names, holds the secret, as does `.ur`'s agent label's grammar
	cwd := filepath.Join(env.cwd, secret)
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, ".ur"), []byte("agent = \"Builder_Two\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	harness := sidecartest.NewFakeHarness(env.table, env.terminal.Identity.Pid, sidecartest.FakeHarnessClaudeCode, cwd, env.sink)
	if err := harness.Hook(harness.Payload("s1", "SessionStart", map[string]any{"source": "startup", "model": "model-" + secret})); err != nil {
		t.Fatal(err)
	}
	prompt := "deploy with " + secret + " now\n" + strings.Repeat("and then more ", 300)
	if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": prompt})); err != nil {
		t.Fatal(err)
	}
	if err := harness.ToolCall("s1", false, "lookup:"+secret, map[string]any{"query": "harbor"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{secret + "/main.go", "a.go", "b.go", "c.go"} {
		if err := harness.ToolCall("s1", false, "Edit", map[string]any{"file_path": filepath.Join(cwd, name)}); err != nil {
			t.Fatal(err)
		}
	}
	runId := env.runOf("claude-code", "s1")
	capture := env.ingest.Capture(env.networkId, runId)
	if capture == nil {
		t.Fatal("no capture of the run")
	}

	// nothing a card reads holds the secret, and what held it holds a marker
	texts := []string{capture.Title, capture.AgentLabel, capture.Model, capture.Project, capture.Branch, capture.Prompts}
	texts = append(texts, capture.TouchedPaths...)
	for name := range capture.ToolCounts {
		texts = append(texts, name)
	}
	for _, text := range texts {
		if strings.Contains(text, secret) {
			t.Fatalf("a card input holds the secret: %q", text)
		}
	}
	// prose in place, with §16.7's marker; an identifier field whole, as its first match's shared marker
	for name, text := range map[string]string{"title": capture.Title, "prompts": capture.Prompts} {
		if !strings.Contains(text, "[REDACTED:") {
			t.Errorf("the %s holds no redaction marker: %q", name, text)
		}
	}
	for name, text := range map[string]string{"model": capture.Model, "project": capture.Project, "path": capture.TouchedPaths[0]} {
		if !strings.HasPrefix(text, "[REDACTED:") || !strings.HasSuffix(text, "]") || strings.Count(text, "[REDACTED:") != 1 {
			t.Errorf("the %s is not its marker alone: %q", name, text)
		}
	}
	// an identifier field redacted whole: the tool's name is its marker alone
	redactedTool := ""
	for name := range capture.ToolCounts {
		if strings.HasPrefix(name, "[REDACTED:") && strings.HasSuffix(name, "]") {
			redactedTool = name
		}
	}
	if redactedTool == "" || capture.ToolCounts["Edit"] != 4 {
		t.Fatalf("the tool counts %+v", capture.ToolCounts)
	}
	// the caps: a title's 120 B, 2 KiB of prompts, the path cap, and a label the record refuses as none
	if 120 < len(capture.Title) || 2*1024 < len(capture.Prompts) || len(capture.TouchedPaths) != 3 || capture.AgentLabel != "" {
		t.Fatalf("the capture past its caps: title %d B, prompts %d B, %d paths, label %q", len(capture.Title), len(capture.Prompts), len(capture.TouchedPaths), capture.AgentLabel)
	}
	if !env.hasGap(runId, sidecar.RecordCoverageGapRedaction) {
		t.Fatal("no redaction gap on the run")
	}

	// no entry sealed holds the secret, and the entries carry what the capture holds
	drafts := func() []*sidecar.RecordDraft {
		env.writer.stateLock.Lock()
		defer env.writer.stateLock.Unlock()
		return append([]*sidecar.RecordDraft{}, env.writer.drafts...)
	}()
	for _, draft := range drafts {
		encoded, err := proto.Marshal(draft.Body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("a %s entry was sealed holding the secret", draft.Kind)
		}
	}
	contexts := env.writer.of(sidecar.RecordKindContext)
	if len(contexts) == 0 {
		t.Fatal("no context entry sealed: the refused label lost it")
	}
	newest := contexts[len(contexts)-1].Body.(*protocol.ContextBody)
	if newest.Model != capture.Model || newest.Project != capture.Project || newest.Title != capture.Title || newest.AgentLabel != "" {
		t.Fatalf("the context entry %+v, the capture %+v", newest, capture)
	}
	toolNames, toolPaths := map[string]bool{}, map[string]bool{}
	for _, draft := range env.writer.of(sidecar.RecordKindToolCall) {
		body := draft.Body.(*protocol.ToolCallBody)
		toolNames[body.ToolName] = true
		for _, path := range body.Paths {
			toolPaths[path] = true
		}
	}
	if !toolNames[redactedTool] || !toolNames["Edit"] {
		t.Fatalf("the tool_call entries' names %v, the capture's %v", toolNames, capture.ToolCounts)
	}
	for _, path := range capture.TouchedPaths {
		if !toolPaths[path] {
			t.Fatalf("a captured path %q no tool_call entry carries", path)
		}
	}
	// the capture each due carried was the same redacted inputs
	for _, due := range schedule.taken() {
		if strings.Contains(due.capture.Title+due.capture.Model+due.capture.Project+due.capture.Prompts, secret) {
			t.Fatalf("a %s due's capture holds the secret", due.reason)
		}
	}
}
