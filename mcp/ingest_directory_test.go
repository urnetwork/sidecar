//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's Run announcement row (MCP-M6-02): the ingest's lifecycle over the real DirectoryRuns, whose announce entries
// a test writer keeps. Hook events arrive as a harness sends them, through HandleHook, so the session's claims are
// read from the hook's hello. The tests hold what reaches the directory to a run's who, what and where, with canaries
// in a prompt past its first line, a tool's body, a path and a diff (FS-88's I-20 clause); that off, an unread value,
// a personal network and a start with no caller announce nothing; that a run starts once, under the value read at its
// start; that a prompt run is held, not announced; and that a run ended by idling starts again when it moves.

package mcp

import (
	"context"
	"fmt"
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

// The run store's taint as the directory's runs read it.
type testDirectoryRunView struct {
	runs *sidecar.RunStore
}

func (self testDirectoryRunView) RunTainted(runId sidecar.Id) bool {
	return self.runs.Tainted(runId)
}

// Every draft a writer was handed, in order.
func directoryAllDrafts(writer *testRecordWriter) []*sidecar.RecordDraft {
	writer.stateLock.Lock()
	defer writer.stateLock.Unlock()
	return append([]*sidecar.RecordDraft{}, writer.drafts...)
}

// The directory's runs, each call kept before it is passed on.
type recordingDirectoryRuns struct {
	inner     McpDirectoryRuns
	stateLock sync.Mutex
	starts    []*sidecar.DirectoryRunStart
	moved     []sidecar.Id
	ended     []sidecar.Id
}

func (self *recordingDirectoryRuns) Started(start *sidecar.DirectoryRunStart) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		kept := *start
		self.starts = append(self.starts, &kept)
	}()
	return self.inner.Started(start)
}

func (self *recordingDirectoryRuns) Moved(runId sidecar.Id) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.moved = append(self.moved, runId)
	}()
	self.inner.Moved(runId)
}

func (self *recordingDirectoryRuns) Ended(runId sidecar.Id) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.ended = append(self.ended, runId)
	}()
	return self.inner.Ended(runId)
}

func (self *recordingDirectoryRuns) started() []*sidecar.DirectoryRunStart {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*sidecar.DirectoryRunStart{}, self.starts...)
}

func (self *recordingDirectoryRuns) counts() (int, int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.starts), len(self.moved), len(self.ended)
}

// The ingest env with the directory lifecycle installed over the real DirectoryRuns of a member's device in a team
// network, and the claims value each new run reads.
type directoryLifecycleEnv struct {
	*ingestTestEnv
	announces *testRecordWriter
	runs      *recordingDirectoryRuns
	lifecycle *DirectoryLifecycle

	stateLock sync.Mutex
	// what a session's claims resolve to now; nil reads none
	resolution *sidecar.SidecarClaimsResolution
	// the hellos the resolver was asked for
	asked []*sidecar.DaemonHello
	// with none set the network has no directory
	noDirectory bool
}

func newDirectoryLifecycleEnv(t *testing.T, claims sidecar.SidecarClaims) *directoryLifecycleEnv {
	t.Helper()
	env := &directoryLifecycleEnv{
		ingestTestEnv: newIngestTestEnv(t),
		announces:     newTestRecordWriter(),
		resolution:    &sidecar.SidecarClaimsResolution{Claims: claims, ProjectKey: "example.test/team/app", ProjectLabel: "team-app"},
	}
	sidecarId, memberId, directoryId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	auth := sidecartest.NewFakeDirectoryAuth()
	auth.Append(&sidecartest.FakeDirectoryAuthFixture{
		Sidecars:    map[sidecar.Id]*sidecartest.FakeDirectorySidecar{sidecarId: {MemberId: &memberId}},
		DirectoryId: &directoryId,
	})
	runs, err := sidecar.NewDirectoryRuns(&sidecar.DirectoryRunsArgs{
		SidecarId: sidecarId,
		Writer:    env.announces,
		Runs:      testDirectoryRunView{runs: env.network.runs},
		Auth:      func() sidecar.DirectoryAuthView { return auth.Tip() },
		Store:     sidecartest.NewFakeStore().Root(),
		Clock:     env.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.runs = &recordingDirectoryRuns{inner: runs}
	env.lifecycle = NewDirectoryLifecycle(&DirectoryLifecycleArgs{
		Runs: func(networkId sidecar.Id) (McpDirectoryRuns, error) {
			env.stateLock.Lock()
			defer env.stateLock.Unlock()
			if networkId != env.networkId || env.noDirectory {
				return nil, sidecar.ErrDirectoryNone
			}
			return env.runs, nil
		},
		Claims: func(ctx context.Context, hello *sidecar.DaemonHello, networkId sidecar.Id) *sidecar.SidecarClaimsResolution {
			env.stateLock.Lock()
			defer env.stateLock.Unlock()
			env.asked = append(env.asked, hello)
			if env.resolution == nil {
				return nil
			}
			resolved := *env.resolution
			return &resolved
		},
	})
	// the ingest again, with the lifecycle, as the daemon's start builds it
	env.ingest.detach()
	env.ingest = NewIngest(&IngestArgs{
		Server:    env.server,
		Writers:   func(network McpNetwork) (sidecar.RecordWriter, error) { return env.writer, nil },
		Redactors: func(network McpNetwork) (*sidecar.Redactor, error) { return env.redactor, nil },
		Lifecycle: env.lifecycle,
		Record:    sidecar.DefaultSidecarSettings().Record,
	})
	return env
}

func (self *directoryLifecycleEnv) setClaims(claims sidecar.SidecarClaims) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.resolution.Claims = claims
}

func (self *directoryLifecycleEnv) askedCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.asked)
}

// The announce items written so far, in order.
func (self *directoryLifecycleEnv) items(t *testing.T) []*protocol.Announcement {
	t.Helper()
	items := []*protocol.Announcement{}
	for _, draft := range self.announces.of(sidecar.RecordKindAnnounce) {
		item, ok := draft.Body.(*protocol.Announcement)
		if !ok {
			t.Fatalf("an announce draft's body %T", draft.Body)
		}
		if err := sidecar.DirectoryCheckItem(item); err != nil {
			t.Fatalf("an item the readers would refuse: %v", err)
		}
		items = append(items, item)
	}
	return items
}

// Every byte that reached the directory's side: each start handed to the runs and each entry they wrote.
func (self *directoryLifecycleEnv) reached(t *testing.T) string {
	t.Helper()
	parts := []string{}
	for _, start := range self.runs.started() {
		parts = append(parts, fmt.Sprintf("%+v", *start))
	}
	for _, draft := range directoryAllDrafts(self.announces) {
		parts = append(parts, fmt.Sprintf("%+v", *draft))
		if message, ok := draft.Body.(proto.Message); ok {
			encoded, err := proto.Marshal(message)
			if err != nil {
				t.Fatal(err)
			}
			parts = append(parts, string(encoded))
		}
	}
	return strings.Join(parts, "\n")
}

// The canaries a session carries beside its who, what and where.
const (
	directoryCanaryPrompt = "CANARY-PROMPT-PAST-THE-FIRST-LINE"
	directoryCanaryTool   = "CANARY-TOOL-BODY"
	directoryCanaryPath   = "CANARY-PATH-SEGMENT"
	directoryCanaryDiff   = "CANARY-DIFF-HUNK"
)

// A session's events with a canary in each place I-20 keeps in the vault: a prompt past its first line, a tool's
// arguments and result, a path, and a diff.
func (self *directoryLifecycleEnv) session(t *testing.T, harness *sidecartest.FakeHarness, sessionId string) {
	t.Helper()
	steps := []error{
		harness.Hook(harness.Payload(sessionId, "UserPromptSubmit", map[string]any{
			"prompt": "Fix the login flow\n" + directoryCanaryPrompt + " and the rest of the prompt",
		})),
		harness.ToolCall(sessionId, true, "Bash", map[string]any{"command": "cat notes # " + directoryCanaryTool}),
		harness.Hook(harness.Payload(sessionId, "PostToolUse", map[string]any{
			"tool_name": "Bash", "tool_use_id": "toolu_bash",
			"tool_input":    map[string]any{"command": "cat notes # " + directoryCanaryTool},
			"tool_response": map[string]any{"stdout": directoryCanaryTool + " in the output"},
		})),
		harness.Hook(harness.Payload(sessionId, "PostToolUse", map[string]any{
			"tool_name": "Edit", "tool_use_id": "toolu_edit",
			"tool_input": map[string]any{
				"file_path":  filepath.Join(self.cwd, directoryCanaryPath, "login.go"),
				"old_string": "before " + directoryCanaryDiff,
				"new_string": "after " + directoryCanaryDiff,
			},
			"tool_response": map[string]any{"structuredPatch": "@@ -1 +1 @@ " + directoryCanaryDiff},
		})),
		harness.Hook(harness.Payload(sessionId, "UserPromptSubmit", map[string]any{"prompt": "and now " + directoryCanaryPrompt})),
	}
	for index, err := range steps {
		if err != nil {
			t.Fatalf("step %d: %v", index, err)
		}
	}
}

// The start delay of the directory's runs, after which an auto run's item is written.
func directoryStartDelay() time.Duration {
	return sidecar.DefaultDirectoryRunsSettings().StartDelay + time.Second
}

// FS-88's I-20 clause: an auto run's announcement carries its who, what and where, the title the first line of its
// first prompt, and nothing else of the session. The canaries reach neither a start handed to the directory's runs
// nor an entry they write, while the vault's own entries do hold what the session did.
func TestLifecycleCarriesOnlyWhoWhatWhere(t *testing.T) {
	env := newDirectoryLifecycleEnv(t, sidecar.SidecarClaimsAuto)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	runId := env.runOf("claude-code", "s1")
	env.session(t, harness, "s1")
	env.clock.Advance(directoryStartDelay())
	if err := harness.SessionEnd("s1", "exit"); err != nil {
		t.Fatal(err)
	}

	items := env.items(t)
	if len(items) < 2 {
		t.Fatalf("%d announce entries for a run that started and ended", len(items))
	}
	first, last := items[0], items[len(items)-1]
	if first.GetWhat().GetTitle() != "Fix the login flow" || sidecar.Id(first.GetWhat().GetRunId()) != runId {
		t.Errorf("the item's what: %v", first.GetWhat())
	}
	if first.GetWho().GetHarness() != "claude-code" || first.GetWho().GetModel() != "test-model" {
		t.Errorf("the item's who: %v", first.GetWho())
	}
	if first.GetWhere().GetProject() != "team-app" || first.GetWhere().GetPrivate() {
		t.Errorf("the item's where: %v", first.GetWhere())
	}
	if first.GetState() != uint32(sidecar.DirectoryAnnouncementStateActive) || last.GetState() != uint32(sidecar.DirectoryAnnouncementStateEnded) {
		t.Errorf("the item's states: %d then %d", first.GetState(), last.GetState())
	}

	reached := env.reached(t)
	for _, canary := range []string{directoryCanaryPrompt, directoryCanaryTool, directoryCanaryPath, directoryCanaryDiff, "and the rest of the prompt", "login.go", env.cwd} {
		if strings.Contains(reached, canary) {
			t.Errorf("%q reached the directory", canary)
		}
	}
	// every start names only the run's who, what and where
	for _, start := range env.runs.started() {
		if start.RunId != runId || start.Claims != sidecar.DirectoryRunClaimsAuto || start.ProjectKey != "example.test/team/app" ||
			start.Harness != "claude-code" || start.Project != "team-app" || start.AgentId != nil || start.RepoId != nil {
			t.Errorf("a start: %+v", *start)
		}
		if start.Title != "" && start.Title != "Fix the login flow" {
			t.Errorf("a start's title: %q", start.Title)
		}
	}
	// the vault's own entries did see the session, so the canaries were there to leak
	vault := ""
	for _, draft := range directoryAllDrafts(env.writer) {
		vault += fmt.Sprintf("%+v", *draft)
		if message, ok := draft.Body.(proto.Message); ok {
			encoded, _ := proto.Marshal(message)
			vault += string(encoded)
		}
	}
	if !strings.Contains(vault, "login.go") {
		t.Error("the vault's entries name no touched path, so the canaries prove nothing")
	}
	if len(env.announces.of(sidecar.RecordKindAnnounce)) != len(directoryAllDrafts(env.announces)) {
		t.Error("the directory's runs wrote an entry that is no announce")
	}
}

// A title is its first line, cut to the directory's bound at a rune's edge.
func TestLifecycleTitleIsOneBoundedLine(t *testing.T) {
	long := strings.Repeat("é", sidecar.DirectoryRunTitleByteCount)
	cases := map[string]string{
		"Fix the build\nand then more": "Fix the build",
		"  Fix the build\r\nmore":      "Fix the build",
		"":                             "",
		long:                           strings.Repeat("é", sidecar.DirectoryRunTitleByteCount/2),
		"a" + long:                     "a" + strings.Repeat("é", (sidecar.DirectoryRunTitleByteCount-1)/2),
	}
	for title, want := range cases {
		got := directoryLifecycleTitle(title)
		if got != want || sidecar.DirectoryRunTitleByteCount < len(got) {
			t.Errorf("the title of %d B: %d B %q, want %q", len(title), len(got), got, want)
		}
	}
}

// With claims off the directory hears the setting alone, and nothing is announced: no title, project, branch, label
// or model is handed on, and no entry is written, through a whole session. A value that cannot be read, a network
// with no directory and a start with no caller hand on nothing at all. Its twin, auto, announces.
func TestClaimsOffAnnouncesNothing(t *testing.T) {
	env := newDirectoryLifecycleEnv(t, sidecar.SidecarClaimsOff)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	runId := env.runOf("claude-code", "s1")
	env.session(t, harness, "s1")
	env.clock.Advance(directoryStartDelay())
	if err := harness.SessionEnd("s1", "exit"); err != nil {
		t.Fatal(err)
	}
	if entries := directoryAllDrafts(env.announces); len(entries) != 0 {
		t.Fatalf("claims off wrote %d entries", len(entries))
	}
	starts := env.runs.started()
	if len(starts) != 1 {
		t.Fatalf("%d starts under off", len(starts))
	}
	want := sidecar.DirectoryRunStart{RunId: runId, Claims: sidecar.DirectoryRunClaimsOff, ProjectKey: "example.test/team/app"}
	if got := *starts[0]; got != want {
		t.Errorf("the start under off: %+v", got)
	}
	if reached := env.reached(t); strings.Contains(reached, "Fix the login flow") || strings.Contains(reached, "team-app") {
		t.Errorf("a title or a project reached the directory under off: %s", reached)
	}

	// a value that cannot be read
	unread := newDirectoryLifecycleEnv(t, sidecar.SidecarClaimsAuto)
	unread.stateLock.Lock()
	unread.resolution = nil
	unread.stateLock.Unlock()
	// a network with no directory
	personal := newDirectoryLifecycleEnv(t, sidecar.SidecarClaimsAuto)
	personal.stateLock.Lock()
	personal.noDirectory = true
	personal.stateLock.Unlock()
	for name, closed := range map[string]*directoryLifecycleEnv{"an unread value": unread, "no directory": personal} {
		harness := closed.harnessIn(sidecartest.FakeHarnessClaudeCode)
		if err := harness.SessionStart("s1", "startup"); err != nil {
			t.Fatal(err)
		}
		closed.session(t, harness, "s1")
		closed.clock.Advance(directoryStartDelay())
		harness.SessionEnd("s1", "exit")
		if started, _, _ := closed.runs.counts(); started != 0 || len(directoryAllDrafts(closed.announces)) != 0 {
			t.Errorf("%s: %d starts, %d entries", name, started, len(directoryAllDrafts(closed.announces)))
		}
	}
	// a start with no caller on its context, as no hook's is
	auto := newDirectoryLifecycleEnv(t, sidecar.SidecarClaimsAuto)
	auto.lifecycle.RunStarted(context.Background(), auto.networkId, &RunLifecycleStart{RunId: sidecar.NewId(), Harness: "claude-code", Title: "Fix the login flow"})
	if started, _, _ := auto.runs.counts(); started != 0 || auto.askedCount() != 0 {
		t.Errorf("a start with no caller: %d starts, %d values read", started, auto.askedCount())
	}

	// twin: the same session under auto is announced
	harness = auto.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	auto.session(t, harness, "s1")
	auto.clock.Advance(directoryStartDelay())
	if items := auto.items(t); len(items) != 1 || items[0].GetWhat().GetTitle() != "Fix the login flow" {
		t.Errorf("the twin under auto: %d items", len(items))
	}
}

// A run starts once: its SessionStart, a resumed session's SessionStart and every event after make one announcement
// at version 1, under the claims value read when it started, which a later change of the setting leaves alone. The
// title its first prompt sets reaches the same item, and its end ends that item once.
func TestStartedOncePerRun(t *testing.T) {
	env := newDirectoryLifecycleEnv(t, sidecar.SidecarClaimsAuto)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	runId := env.runOf("claude-code", "s1")
	if started, _, _ := env.runs.counts(); started != 1 || env.askedCount() != 1 {
		t.Fatalf("after the start: %d starts, %d values read", started, env.askedCount())
	}
	if asked := env.asked[0]; asked == nil || asked.Harness != "claude-code" {
		t.Fatalf("the value was read for %+v", asked)
	}
	// the setting changes under the open run, and the session resumes
	env.setClaims(sidecar.SidecarClaimsOff)
	for range 2 {
		if err := harness.SessionStart("s1", "resume"); err != nil {
			t.Fatal(err)
		}
	}
	if started, _, _ := env.runs.counts(); started != 1 {
		t.Fatalf("a resumed session started the run again: %d starts", started)
	}
	env.session(t, harness, "s1")
	if err := harness.SessionStart("s1", "resume"); err != nil {
		t.Fatal(err)
	}
	starts := env.runs.started()
	if len(starts) != 2 || starts[1].Title != "Fix the login flow" || starts[0].Title != "" {
		t.Fatalf("%d starts after the title was set", len(starts))
	}
	for _, start := range starts {
		if start.RunId != runId || start.Claims != sidecar.DirectoryRunClaimsAuto {
			t.Errorf("a start under the value read at the run's start: %+v", *start)
		}
	}
	if env.askedCount() != 1 {
		t.Errorf("the value was read %d times for one run", env.askedCount())
	}
	env.clock.Advance(directoryStartDelay())
	items := env.items(t)
	if len(items) != 1 || items[0].GetVersion() != 1 || items[0].GetWhat().GetTitle() != "Fix the login flow" {
		t.Fatalf("%d items after the start delay", len(items))
	}
	_, moved, _ := env.runs.counts()
	if moved == 0 {
		t.Error("no hook event of the started run moved it")
	}
	if err := harness.SessionEnd("s1", "exit"); err != nil {
		t.Fatal(err)
	}
	items = env.items(t)
	_, _, ended := env.runs.counts()
	if ended != 1 || len(items) != 2 || items[1].GetState() != uint32(sidecar.DirectoryAnnouncementStateEnded) ||
		string(items[1].GetAnnouncementId()) != string(items[0].GetAnnouncementId()) {
		t.Fatalf("%d ends, %d items", ended, len(items))
	}
}

// A prompt run is handed on with its who, what and where and held: nothing is announced until the person claims.
func TestPromptRunIsHeldNotAnnounced(t *testing.T) {
	env := newDirectoryLifecycleEnv(t, sidecar.SidecarClaimsPrompt)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	env.session(t, harness, "s1")
	env.clock.Advance(directoryStartDelay())
	starts := env.runs.started()
	if len(starts) == 0 {
		t.Fatal("a prompt run was not handed on")
	}
	last := starts[len(starts)-1]
	if last.Claims != sidecar.DirectoryRunClaimsPrompt || last.Title != "Fix the login flow" || last.Project != "team-app" {
		t.Errorf("the prompt run's start: %+v", *last)
	}
	if entries := directoryAllDrafts(env.announces); len(entries) != 0 {
		t.Errorf("a prompt run announced %d entries with no claim", len(entries))
	}
}

// A run its Coverage ended by idling starts again when it moves: the directory hears its end, then a start with the
// same who, what and where, under the value its session starts under then.
func TestRunEndedByIdlingStartsAgainWhenItMoves(t *testing.T) {
	env := newDirectoryLifecycleEnv(t, sidecar.SidecarClaimsAuto)
	env.writeTranscript("s1", "{}\n")
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	runId := env.runOf("claude-code", "s1")
	if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": "Fix the login flow"})); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(directoryStartDelay())
	env.clock.Advance(sidecar.DefaultSidecarSettings().Record.CoverageIdleTimeout + time.Second)
	started, _, ended := env.runs.counts()
	if ended != 1 {
		t.Fatalf("%d ends after idling", ended)
	}
	if items := env.items(t); len(items) < 2 || items[len(items)-1].GetState() != uint32(sidecar.DirectoryAnnouncementStateEnded) {
		t.Fatalf("%d items after idling", len(items))
	}
	asked := env.askedCount()

	if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": "again"})); err != nil {
		t.Fatal(err)
	}
	starts := env.runs.started()
	if len(starts) != started+1 {
		t.Fatalf("%d starts after the run moved again, %d before", len(starts), started)
	}
	again := starts[len(starts)-1]
	if again.RunId != runId || again.Claims != sidecar.DirectoryRunClaimsAuto || again.Title != "Fix the login flow" || again.Project != "team-app" {
		t.Errorf("the start again: %+v", *again)
	}
	if env.askedCount() != asked+1 {
		t.Errorf("the value was read %d times for the start again", env.askedCount()-asked)
	}
	before := len(env.items(t))
	env.clock.Advance(directoryStartDelay())
	items := env.items(t)
	if len(items) != before+1 || items[len(items)-1].GetState() != uint32(sidecar.DirectoryAnnouncementStateActive) {
		t.Errorf("%d items after the start again, %d before", len(items), before)
	}
}
