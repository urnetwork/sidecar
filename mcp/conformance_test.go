//go:build !js && !ios && !android && !sdk_mobile_bind

// Hook conformance (MCP-M3-28; R-MCP-2, R-MCP-4, D-MCP-5; §22.5's pinned Claude Code, Codex and Cursor; M3's exit).
// Each recorded harness version is a directory testdata/harness/<harness>/<version>/: a manifest naming the version, the
// published schema the payloads were written from and the date it was read, the worktree a session starts in and the
// edit it makes; events/, one session's payloads in the order the harness sends them, synthetic in every value; and
// expected.json, the HookEvent each payload must read as. A session holds an edit, a shell call, a PermissionRequest
// (Cursor's beforeMCPExecution), an O tool and an end.
//
//   - every payload parses to its expected event through its harness's adapter, unknown to none and drifted from
//     none (TestHookConformanceRecorded);
//   - the whole session, replayed through sidecartest's FakeHarness into the daemon's hook path, binds one run that
//     stays untainted with no gap but those the manifest names, whose edit is the run's restorable edit, whose asking
//     event stands as harness evidence for the O tool's call, and whose end writes the run's Coverage
//     (TestHookConformanceSessionReplay);
//   - an event no adapter version reads is a missed event: the hook is acked, never an error to the harness, and the
//     run is tainted with a missed_event gap, so a harness prompt no longer counts under evidenceDefault
//     (TestUnknownEventIsAGapNotAnError);
//   - a payload naming a field its event's pinned schema does not, an added required field among them, is drift: acked,
//     the run tainted with a hook_failure gap, and an asking event that drifted never stands as evidence
//     (TestSchemaDriftTaints);
//   - the live mode runs a real harness build where UR_CONFORMANCE_HARNESS names its harness and
//     UR_CONFORMANCE_COMMAND the command that runs it once, its hooks pointing at this test binary, which writes each
//     payload it is handed; every payload must parse, unknown to none and drifted from none (TestHookConformanceLive).
//     It is for the external run, where pinned builds are installed; here it is skipped.

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A recorded version's manifest.
type conformanceManifest struct {
	Harness string `json:"harness"`
	Version string `json:"version"`
	// What the version is: a pinned release, or the schema as published on the read date.
	Pinned   string `json:"pinned"`
	Schema   string `json:"schema"`
	Read     string `json:"read"`
	Recorded string `json:"recorded"`
	// The directories the payloads name, which a replay replaces with its worktree and a home of its own.
	Cwd  string `json:"cwd"`
	Home string `json:"home"`
	// The transcript the harness keeps, which a replay writes before the session.
	Transcript *conformanceTranscript `json:"transcript"`
	// The worktree's committed files.
	Files map[string]string `json:"files"`
	// The session's edit: the path, its bytes after, and the payload the replay writes them before.
	Edit *conformanceEdit `json:"edit"`
	// The coverage gaps a conforming session still counts, by code.
	Gaps []string `json:"gaps"`
	// Whether the session's end writes the run's Coverage.
	Coverage bool `json:"coverage"`
}

type conformanceTranscript struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type conformanceEdit struct {
	Path        string `json:"path"`
	After       string `json:"after"`
	BeforeEvent string `json:"before_event"`
}

// One payload's expected event.
type conformanceEvent struct {
	File           string   `json:"file"`
	Kind           string   `json:"kind"`
	HarnessEvent   string   `json:"harness_event"`
	SessionId      string   `json:"session_id"`
	Start          string   `json:"start"`
	Cwd            string   `json:"cwd"`
	PermissionMode string   `json:"permission_mode"`
	Model          string   `json:"model"`
	Transcript     bool     `json:"transcript"`
	ToolKind       string   `json:"tool_kind"`
	ToolName       string   `json:"tool_name"`
	ToolServer     string   `json:"tool_server"`
	ToolUseId      string   `json:"tool_use_id"`
	Paths          []string `json:"paths"`
	WebTool        bool     `json:"web_tool"`
	InputHashed    bool     `json:"input_hashed"`
}

// One recorded harness version.
type conformanceVersion struct {
	directory string
	manifest  *conformanceManifest
	expected  []*conformanceEvent
	// by file name
	payloads map[string][]byte
}

func (self *conformanceVersion) String() string {
	return self.manifest.Harness + " " + self.manifest.Version
}

// Every recorded version under testdata/harness/, each harness ur hooks holding at least one.
func loadConformanceVersions(t *testing.T) []*conformanceVersion {
	t.Helper()
	root := filepath.Join("..", "testdata", "harness")
	manifests, err := filepath.Glob(filepath.Join(root, "*", "*", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	versions := []*conformanceVersion{}
	for _, manifestPath := range manifests {
		directory := filepath.Dir(manifestPath)
		version := &conformanceVersion{directory: directory, manifest: &conformanceManifest{}, payloads: map[string][]byte{}}
		readConformanceJson(t, manifestPath, version.manifest)
		readConformanceJson(t, filepath.Join(directory, "expected.json"), &version.expected)
		if version.manifest.Harness != filepath.Base(filepath.Dir(directory)) || version.manifest.Version != filepath.Base(directory) {
			t.Fatalf("%s names %s %s", directory, version.manifest.Harness, version.manifest.Version)
		}
		entries, err := os.ReadDir(filepath.Join(directory, "events"))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			payload, err := os.ReadFile(filepath.Join(directory, "events", entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			version.payloads[entry.Name()] = payload
		}
		if len(version.payloads) != len(version.expected) {
			t.Fatalf("%s: %d payloads, %d expected events", version, len(version.payloads), len(version.expected))
		}
		versions = append(versions, version)
	}
	for _, harness := range HookHarnesses() {
		if !slices.ContainsFunc(versions, func(version *conformanceVersion) bool { return version.manifest.Harness == harness }) {
			t.Errorf("no recorded version of %s", harness)
		}
	}
	return versions
}

func readConformanceJson(t *testing.T, path string, value any) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, value); err != nil {
		t.Fatalf("%s: %s", path, err)
	}
}

// SHA-256 of the RFC 8785 form of a payload's tool_input, read apart from the adapters: Cursor's MCP events give it
// as a string of JSON.
func conformanceInputSha256(t *testing.T, payload []byte) []byte {
	t.Helper()
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	input := fields["tool_input"]
	text := ""
	if json.Unmarshal(input, &text) == nil {
		input = json.RawMessage(text)
	}
	canonical, err := sidecar.CanonicalJson(input)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	return sum[:]
}

// Every recorded payload reads as its expected event, unknown to none and drifted from none.
func TestHookConformanceRecorded(t *testing.T) {
	ingest := sidecar.DefaultSidecarSettings().Ingest
	for _, version := range loadConformanceVersions(t) {
		adapter, ok := HookAdapterFor(version.manifest.Harness)
		if !ok {
			t.Errorf("%s: no adapter", version)
			continue
		}
		for _, want := range version.expected {
			payload := version.payloads[want.File]
			event, err := adapter.Parse(payload, ingest)
			if err != nil {
				t.Errorf("%s %s: %s", version, want.File, err)
				continue
			}
			label := version.String() + " " + want.File
			if event.Unknown || event.Drifted {
				t.Errorf("%s: unknown %t, drifted %t", label, event.Unknown, event.Drifted)
			}
			got := &conformanceEvent{
				File:           want.File,
				Kind:           string(event.Kind),
				HarnessEvent:   event.HarnessEvent,
				SessionId:      event.SessionId,
				Start:          string(event.Start),
				Cwd:            event.Cwd,
				PermissionMode: event.PermissionMode,
				Model:          event.Model,
				Transcript:     event.TranscriptPath != "",
				ToolKind:       string(event.ToolKind),
				ToolName:       event.ToolName,
				ToolServer:     event.ToolServer,
				ToolUseId:      event.ToolUseId,
				Paths:          event.Paths,
				WebTool:        event.WebTool,
				InputHashed:    event.ToolInputSha256 != nil,
			}
			if len(got.Paths) == 0 {
				got.Paths = nil
			}
			gotJson, _ := json.Marshal(got)
			wantJson, _ := json.Marshal(want)
			if !bytes.Equal(gotJson, wantJson) {
				t.Errorf("%s:\n got  %s\n want %s", label, gotJson, wantJson)
			}
			if want.InputHashed && !bytes.Equal(event.ToolInputSha256, conformanceInputSha256(t, payload)) {
				t.Errorf("%s: the arguments' hash is not the RFC 8785 form's", label)
			}
			if event.AdapterVersion != adapter.Version() || event.Harness != version.manifest.Harness {
				t.Errorf("%s: adapter %s %d", label, event.Harness, event.AdapterVersion)
			}
		}
	}
}

// The whole session replayed through FakeHarness into the daemon's hook path, over a git worktree: one run, untainted,
// with the manifest's gaps alone; its edit the run's restorable edit; its asking event standing as evidence for the O
// tool's call; its end writing the Coverage.
func TestHookConformanceSessionReplay(t *testing.T) {
	for _, version := range loadConformanceVersions(t) {
		manifest := version.manifest
		repo := newRestoreTestEnv(t)
		names := []string{}
		for name := range manifest.Files {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			repo.write(name, manifest.Files[name])
		}
		repo.git("add", "-A")
		repo.git("commit", "-q", "-m", "the session's start")
		env := newIngestTestEnv(t)
		env.cwd = repo.dir
		env.restore = NewRestorePoints(&RestorePointsArgs{Clock: env.clock, Ingest: env.server.settings.Ingest})
		env.install()
		evidence := NewHarnessEvidenceStore(env.server.settings.Ingest, env.clock)
		evidence.Install(env.server)
		harness := env.harnessIn(manifest.Harness)
		home := t.TempDir()
		// the recorded directories' replacements, as JSON strings' text
		replace := func(text string) string {
			for recorded, local := range map[string]string{manifest.Cwd: repo.dir, manifest.Home: home} {
				quoted, _ := json.Marshal(local)
				text = strings.ReplaceAll(text, recorded, string(quoted[1:len(quoted)-1]))
			}
			return text
		}
		if manifest.Transcript != nil {
			path := replace(manifest.Transcript.Path)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(manifest.Transcript.Content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, want := range version.expected {
			if manifest.Edit != nil && want.File == manifest.Edit.BeforeEvent {
				repo.write(manifest.Edit.Path, manifest.Edit.After)
			}
			payload := []byte(replace(string(version.payloads[want.File])))
			if err := harness.Hook(payload); err != nil {
				t.Errorf("%s %s: the hook answered %s", version, want.File, err)
			}
		}
		sessionId := version.expected[0].SessionId
		runId := env.runOf(manifest.Harness, sessionId)
		run := env.runFile(runId)
		if run.Tainted {
			t.Errorf("%s: a conforming session's run is tainted: %v", version, run.TaintReasons)
		}
		codes := []string{}
		for _, gap := range run.Gaps {
			code, _, _ := sidecar.RecordCoverageGapParse(gap)
			codes = append(codes, code)
		}
		slices.Sort(codes)
		wantCodes := slices.Clone(manifest.Gaps)
		slices.Sort(wantCodes)
		if !slices.Equal(codes, wantCodes) {
			t.Errorf("%s: gaps %v, want %v", version, run.Gaps, manifest.Gaps)
		}
		if manifest.Edit != nil {
			point, ok := env.restore.Point(env.networkId, runId)
			if !ok {
				t.Errorf("%s: no restore point", version)
			} else if plan, err := point.Plan(context.Background(), nil); err != nil || !slices.Equal(plan.Paths(), []string{manifest.Edit.Path}) {
				t.Errorf("%s: the edit is not the run's restorable edit: %v %+v", version, err, plan)
			}
		}
		// the asking event, as harness_ok's event half keeps it
		var asking *conformanceEvent
		for _, want := range version.expected {
			if want.Kind == string(HookEventPermissionRequest) || want.HarnessEvent == harnessEvidenceEvents[manifest.Harness] {
				asking = want
				break
			}
		}
		if asking == nil {
			t.Errorf("%s: the session asks about no call", version)
		} else {
			hash := conformanceInputSha256(t, version.payloads[asking.File])
			kept := func() bool {
				evidence.stateLock.Lock()
				defer evidence.stateLock.Unlock()
				for _, event := range evidence.networkIdEvents[env.networkId] {
					if event.runId == runId && event.toolName == asking.ToolName && bytes.Equal(event.argumentsSha256, hash) && !event.void {
						return true
					}
				}
				return false
			}()
			if !kept {
				t.Errorf("%s: %s is not kept as harness evidence", version, asking.File)
			}
		}
		if coverages := env.writer.of(sidecar.RecordKindCoverage); manifest.Coverage != (len(coverages) == 1) {
			t.Errorf("%s: %d coverage entries", version, len(coverages))
		}
		if calls := env.writer.of(sidecar.RecordKindToolCall); len(calls) == 0 {
			t.Errorf("%s: no tool call captured", version)
		}
	}
}

// A harness of kind's session started in env, as the harness reports one.
func conformanceStart(t *testing.T, env *ingestTestEnv, kind string, sessionId string) *sidecartest.FakeHarness {
	t.Helper()
	harness := env.harnessIn(kind)
	var err error
	switch kind {
	case sidecartest.FakeHarnessClaudeCode:
		err = harness.SessionStart(sessionId, "startup")
	case sidecartest.FakeHarnessCodex:
		err = harness.Hook(harness.Payload(sessionId, "UserPromptSubmit", map[string]any{"prompt": "a fixture task"}))
	default:
		err = harness.Hook(harness.Payload(sessionId, "beforeSubmitPrompt", map[string]any{"prompt": "a fixture task"}))
	}
	if err != nil {
		t.Fatal(err)
	}
	return harness
}

// A payload of kind's asking about a mail_send call, with extra fields beside its own.
func conformanceAsking(harness *sidecartest.FakeHarness, kind string, sessionId string, extra map[string]any) []byte {
	input := map[string]any{"to": []string{"someone@mail.example"}, "subject": "a report"}
	fields := map[string]any{}
	if kind == sidecartest.FakeHarnessCursor {
		encoded, _ := json.Marshal(input)
		fields = map[string]any{"tool_name": "mail_send", "tool_input": string(encoded), "command": "/tmp/sidecartest/bin/ur mcp"}
	} else {
		fields = map[string]any{"tool_name": "mcp__ur__mail_send", "tool_input": input}
	}
	for name, value := range extra {
		fields[name] = value
	}
	return harness.Payload(sessionId, harnessEvidenceEvents[kind], fields)
}

// The asking events the store keeps for a run.
func conformanceKept(store *HarnessEvidenceStore, networkId sidecar.Id, runId sidecar.Id) int {
	store.stateLock.Lock()
	defer store.stateLock.Unlock()
	count := 0
	for _, event := range store.networkIdEvents[networkId] {
		if event.runId == runId && !event.void {
			count += 1
		}
	}
	return count
}

// The event names no adapter version reads, one per harness.
var conformanceUnknownEvents = map[string]string{
	sidecartest.FakeHarnessClaudeCode: "PostToolBatch",
	sidecartest.FakeHarnessCodex:      "PreModelSample",
	sidecartest.FakeHarnessCursor:     "beforeTabFileRead",
}

// An event the adapter does not read is a missed event: acked, the run tainted with a missed_event gap, and the asking
// event it might have been is never kept.
func TestUnknownEventIsAGapNotAnError(t *testing.T) {
	for _, kind := range []string{sidecartest.FakeHarnessClaudeCode, sidecartest.FakeHarnessCodex, sidecartest.FakeHarnessCursor} {
		env := newIngestTestEnv(t)
		evidence := NewHarnessEvidenceStore(env.server.settings.Ingest, env.clock)
		evidence.Install(env.server)
		harness := conformanceStart(t, env, kind, "s1")
		runId := env.runOf(kind, "s1")
		if env.runFile(runId).Tainted {
			t.Fatalf("%s: tainted at the start", kind)
		}
		payload := harness.Payload("s1", conformanceUnknownEvents[kind], map[string]any{"tool_name": "mcp__ur__mail_send"})
		adapter, _ := HookAdapterFor(kind)
		if event, err := adapter.Parse(payload, env.server.settings.Ingest); err != nil || !event.Unknown || event.Kind != HookEventOther {
			t.Errorf("%s: parsed %+v %v", kind, event, err)
		}
		if err := harness.Hook(payload); err != nil {
			t.Errorf("%s: an unknown event answered the harness %s", kind, err)
		}
		run := env.runFile(runId)
		if !run.Tainted || !slices.Contains(run.TaintReasons, sidecar.RunTaintCoverageLapse) || !env.hasGap(runId, sidecar.RecordCoverageGapMissedEvent) {
			t.Errorf("%s: after an unknown event: tainted %t %v, gaps %v", kind, run.Tainted, run.TaintReasons, run.Gaps)
		}
		if !env.taintedOnDisk(runId) {
			t.Errorf("%s: the taint is not on disk", kind)
		}
		if conformanceKept(evidence, env.networkId, runId) != 0 {
			t.Errorf("%s: an unknown event kept as evidence", kind)
		}
	}
}

// A payload naming a field its event's pinned schema does not, as a harness adds a required field, drifted: acked,
// the run tainted with a hook_failure gap, and the drifted asking event never kept as evidence, while the same event
// without the field is.
func TestSchemaDriftTaints(t *testing.T) {
	for _, kind := range []string{sidecartest.FakeHarnessClaudeCode, sidecartest.FakeHarnessCodex, sidecartest.FakeHarnessCursor} {
		env := newIngestTestEnv(t)
		evidence := NewHarnessEvidenceStore(env.server.settings.Ingest, env.clock)
		evidence.Install(env.server)
		harness := conformanceStart(t, env, kind, "s1")
		runId := env.runOf(kind, "s1")
		adapter, _ := HookAdapterFor(kind)
		plain := conformanceAsking(harness, kind, "s1", nil)
		if event, err := adapter.Parse(plain, env.server.settings.Ingest); err != nil || event.Drifted {
			t.Fatalf("%s: the pinned schema's payload: %+v %v", kind, event, err)
		}
		drifted := conformanceAsking(harness, kind, "s1", map[string]any{"approval_scope": "session"})
		if event, err := adapter.Parse(drifted, env.server.settings.Ingest); err != nil || !event.Drifted || event.Unknown {
			t.Errorf("%s: an added field read as %+v %v", kind, event, err)
		}
		if err := harness.Hook(drifted); err != nil {
			t.Errorf("%s: a drifted payload answered the harness %s", kind, err)
		}
		run := env.runFile(runId)
		if !run.Tainted || !slices.Contains(run.TaintReasons, sidecar.RunTaintCoverageLapse) || !env.hasGap(runId, sidecar.RecordCoverageGapHookFailure) {
			t.Errorf("%s: after drift: tainted %t %v, gaps %v", kind, run.Tainted, run.TaintReasons, run.Gaps)
		}
		if conformanceKept(evidence, env.networkId, runId) != 0 {
			t.Errorf("%s: a drifted asking event kept as evidence", kind)
		}
		// the same event as the pinned schema gives it is kept, in a fresh run
		fresh := newIngestTestEnv(t)
		freshEvidence := NewHarnessEvidenceStore(fresh.server.settings.Ingest, fresh.clock)
		freshEvidence.Install(fresh.server)
		freshHarness := conformanceStart(t, fresh, kind, "s2")
		if err := freshHarness.Hook(conformanceAsking(freshHarness, kind, "s2", nil)); err != nil {
			t.Fatal(err)
		}
		if conformanceKept(freshEvidence, fresh.networkId, fresh.runOf(kind, "s2")) != 1 {
			t.Errorf("%s: the pinned schema's asking event is not kept", kind)
		}
	}
}

// The live mode's environment: the harness, the command line that runs it once in the project with HOME the fixture
// home, and, on the hook processes the run starts, the directory each payload is written to.
const (
	conformanceHarnessEnv = "UR_CONFORMANCE_HARNESS"
	conformanceCommandEnv = "UR_CONFORMANCE_COMMAND"
	conformanceCaptureEnv = "UR_CONFORMANCE_CAPTURE"
)

// The live run's bounds: the harness's one run, and a payload the capture keeps. Test values.
const (
	conformanceLiveTimeout   = 10 * time.Minute
	conformanceCaptureLimit  = 16 * 1024 * 1024
	conformanceCaptureFormat = "%020d-%d.json"
)

// The test binary, run as a live harness's hook, writes the payload on stdin to the capture directory and exits 0, as
// `ur hook` does; else the tests run.
func TestMain(m *testing.M) {
	if directory := os.Getenv(conformanceCaptureEnv); directory != "" {
		payload, err := io.ReadAll(io.LimitReader(os.Stdin, conformanceCaptureLimit))
		if err == nil {
			name := fmt.Sprintf(conformanceCaptureFormat, time.Now().UnixNano(), os.Getpid())
			os.WriteFile(filepath.Join(directory, name), payload, 0o600)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// A single-quoted shell word.
func conformanceShellQuote(word string) string {
	return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
}

// The hooks config a live run gives its harness, every event ur's install hooks pointing at command.
func conformanceHooksConfig(t *testing.T, harness string, home string, project string, command string) {
	t.Helper()
	write := func(path string, value any) {
		encoded, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	groups := func(events []harnessHookEvent) map[string]any {
		hooks := map[string]any{}
		for _, event := range events {
			group := map[string]any{"hooks": []map[string]any{{"type": "command", "command": command}}}
			if event.matcher != "" {
				group["matcher"] = event.matcher
			}
			hooks[event.name] = []map[string]any{group}
		}
		return map[string]any{"hooks": hooks}
	}
	switch harness {
	case claudeHookHarness:
		write(filepath.Join(project, ".claude", "settings.json"), groups(claudeHookEvents))
	case codexHookHarness:
		write(filepath.Join(home, ".codex", "hooks.json"), groups(codexHookEvents))
	case cursorHookHarness:
		hooks := map[string]any{}
		for _, event := range cursorHookEvents {
			hooks[event.name] = []map[string]any{{"command": command}}
		}
		write(filepath.Join(home, ".cursor", "hooks.json"), map[string]any{"version": cursorHooksVersion, "hooks": hooks})
	default:
		t.Fatalf("no harness %s", harness)
	}
}

// A real harness build run once, its hooks captured: every payload parses through its adapter, unknown to none and
// drifted from none. Skipped unless the external run names a harness and its command.
func TestHookConformanceLive(t *testing.T) {
	harness := os.Getenv(conformanceHarnessEnv)
	command := os.Getenv(conformanceCommandEnv)
	if harness == "" || command == "" {
		t.Skip("the live mode runs where " + conformanceHarnessEnv + " and " + conformanceCommandEnv + " name a pinned harness build")
	}
	adapter, ok := HookAdapterFor(harness)
	if !ok {
		t.Fatalf("%s names no harness ur hooks: %v", conformanceHarnessEnv, HookHarnesses())
	}
	home := t.TempDir()
	project := t.TempDir()
	capture := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	conformanceHooksConfig(t, harness, home, project, conformanceCaptureEnv+"="+conformanceShellQuote(capture)+" "+conformanceShellQuote(self))
	ctx, cancel := context.WithTimeout(context.Background(), conformanceLiveTimeout)
	defer cancel()
	run := exec.CommandContext(ctx, "sh", "-c", command)
	run.Dir = project
	run.Env = append(os.Environ(), "HOME="+home)
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("the harness run: %s: %s", err, output)
	}
	entries, err := os.ReadDir(capture)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("the harness ran no hook")
	}
	ingest := sidecar.DefaultSidecarSettings().Ingest
	seen := []string{}
	for _, entry := range entries {
		payload, err := os.ReadFile(filepath.Join(capture, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		event, err := adapter.Parse(payload, ingest)
		if err != nil {
			t.Errorf("%s: %s", entry.Name(), err)
			continue
		}
		if event.Unknown || event.Drifted {
			t.Errorf("%s: %s unknown %t, drifted %t", entry.Name(), event.HarnessEvent, event.Unknown, event.Drifted)
		}
		seen = append(seen, event.HarnessEvent)
	}
	t.Logf("%s: %d hooks, events %v", harness, len(entries), seen)
}
