//go:build !js && !ios && !android && !sdk_mobile_bind

// QD-900's prompts in the record: each UserPromptSubmit writes its prompt, redacted, in a stage 2 context entry of its
// own as it arrives, carrying the run's title, a session title winning over the first prompt's line; only the run's
// first RunCardPromptByteCount of prompts is written, joined one a line as a card joins them; nothing unredacted is
// written, a secret across the budget's cut included; and ingestCut keeps a rune whole, so a title or prompt cut
// inside a rune still seals (its regression test).

package mcp

import (
	"bytes"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The context drafts that carry prompts, in order.
func testPromptedContexts(env *ingestTestEnv) []*protocol.ContextBody {
	prompted := []*protocol.ContextBody{}
	for _, draft := range env.writer.of(sidecar.RecordKindContext) {
		if body := draft.Body.(*protocol.ContextBody); len(body.Prompts) != 0 {
			prompted = append(prompted, body)
		}
	}
	return prompted
}

// Each prompt, as it arrives, is a stage 2 context entry of its own holding it whole, a full restatement carrying the
// run's harness, model and title, the title the first prompt's first line; the run's capture holds the same prompts one
// a line. A restatement with no prompt carries none.
func TestPromptsWrittenAsTheyArrive(t *testing.T) {
	env := newIngestTestEnv(t)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	prompts := []string{"Split the parser\ninto two files", "keep the old names", "and add the tests"}
	for i, prompt := range prompts {
		if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": prompt})); err != nil {
			t.Fatal(err)
		}
		if prompted := testPromptedContexts(env); len(prompted) != i+1 {
			t.Fatalf("after prompt %d: %d prompted entries", i+1, len(prompted))
		}
	}
	contexts := env.writer.of(sidecar.RecordKindContext)
	if len(contexts) != 1+len(prompts) || len(contexts[0].Body.(*protocol.ContextBody).Prompts) != 0 {
		t.Fatalf("%d context entries, the first carrying prompts %v", len(contexts), contexts[0].Body.(*protocol.ContextBody).Prompts)
	}
	for i, body := range testPromptedContexts(env) {
		if body.Stage != 2 || !slices.Equal(body.Prompts, []string{prompts[i]}) || body.Title != "Split the parser" ||
			body.Harness != sidecartest.FakeHarnessClaudeCode || body.Model != "test-model" {
			t.Errorf("prompt %d's entry: %+v", i+1, body)
		}
	}
	runId := env.runOf("claude-code", "s1")
	if capture := env.ingest.Capture(env.networkId, runId); capture.Prompts != strings.Join(prompts, "\n") {
		t.Errorf("the capture's prompts %q", capture.Prompts)
	}
	if env.hasGap(runId, sidecar.RecordCoverageGapMissedEvent) {
		t.Error("a prompt's entry was refused")
	}
}

// Claude Code's session_title, set by --name or /rename, is the run's title, and a prompt's entry carries it rather
// than the prompt's own first line (§16.7's title row).
func TestPromptEntriesCarryTheSessionTitle(t *testing.T) {
	env := newIngestTestEnv(t)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.Hook(harness.Payload("s1", "SessionStart", map[string]any{"source": "startup", "model": "test-model", "session_title": "Named by the person"})); err != nil {
		t.Fatal(err)
	}
	if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": "Not the title"})); err != nil {
		t.Fatal(err)
	}
	prompted := testPromptedContexts(env)
	if len(prompted) != 1 || prompted[0].Title != "Named by the person" || !slices.Equal(prompted[0].Prompts, []string{"Not the title"}) {
		t.Fatalf("the prompt's entry: %+v", prompted)
	}
}

// Only the run's first RunCardPromptByteCount of prompts is written, joined one a line as a card joins them: the
// prompt that crosses the bound is cut to what is left, and one past it writes nothing, so the entries' prompts, joined,
// never pass a card's bound and every entry is within the format's cap. A restart keeps the count.
func TestPromptsStopAtTheCardBound(t *testing.T) {
	env := newIngestTestEnv(t)
	bound := env.server.settings.Ingest.RunCardPromptByteCount
	if bound != 2*1024 || bound > sidecar.DefaultRecordBodySettings().ContextPromptByteCount {
		t.Fatalf("the capture's bound %d against the format's %d", bound, sidecar.DefaultRecordBodySettings().ContextPromptByteCount)
	}
	harness := env.harnessIn(sidecartest.FakeHarnessCodex)
	first := strings.Repeat("a", bound-48)
	if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": first})); err != nil {
		t.Fatal(err)
	}
	env.restartIngest()
	harness = env.harnessIn(sidecartest.FakeHarnessCodex)
	for _, prompt := range []string{strings.Repeat("b", 100), "past the bound"} {
		if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": prompt})); err != nil {
			t.Fatal(err)
		}
	}
	prompted := testPromptedContexts(env)
	// 48 B were left: the line that joins it, then 47 of the second prompt's
	if len(prompted) != 2 || !slices.Equal(prompted[0].Prompts, []string{first}) || !slices.Equal(prompted[1].Prompts, []string{strings.Repeat("b", 47)}) {
		t.Fatalf("the prompted entries: %d", len(prompted))
	}
	joined := []string{}
	for _, body := range prompted {
		joined = append(joined, body.Prompts...)
	}
	runId := env.runOf("codex", "s1")
	capture := env.ingest.Capture(env.networkId, runId)
	if text := strings.Join(joined, "\n"); len(text) != bound || capture.Prompts != text {
		t.Errorf("the entries' prompts, joined, are %d bytes; the capture's %d", len(text), len(capture.Prompts))
	}
	if env.hasGap(runId, sidecar.RecordCoverageGapMissedEvent) {
		t.Error("a prompt's entry was refused")
	}
}

// Nothing unredacted is written: a prompt's secret becomes the redactor's marker in its entry and the capture, and a
// secret that crosses the bound's cut is redacted whole before the cut, so no part of it is written.
func TestPromptsNeverUnredacted(t *testing.T) {
	env := newIngestTestEnv(t)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": "deploy with " + ingestTestSecret + " now"})); err != nil {
		t.Fatal(err)
	}
	bound := env.server.settings.Ingest.RunCardPromptByteCount
	filler := strings.Repeat("f", bound-len(testPromptedContexts(env)[0].Prompts[0])-1-18)
	if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": filler})); err != nil {
		t.Fatal(err)
	}
	// 17 B are left after the line that joins it: the secret's first 17 bytes, had the cut come first
	if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": ingestTestSecret + " tail"})); err != nil {
		t.Fatal(err)
	}
	prompted := testPromptedContexts(env)
	if len(prompted) != 3 {
		t.Fatalf("%d prompted entries", len(prompted))
	}
	if !strings.Contains(prompted[0].Prompts[0], "[REDACTED:") || len(prompted[2].Prompts[0]) != 17 || !strings.HasPrefix(prompted[2].Prompts[0], "[REDACTED:") {
		t.Errorf("the redacted prompts %q and %q", prompted[0].Prompts[0], prompted[2].Prompts[0])
	}
	for _, draft := range env.writer.drafts {
		encoded, err := proto.Marshal(draft.Body)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte(ingestTestSecret)) || bytes.Contains(encoded, []byte(ingestTestSecret[:17])) {
			t.Errorf("a %s entry holds the secret or its start", draft.Kind)
		}
	}
	capture := env.ingest.Capture(env.networkId, env.runOf("claude-code", "s1"))
	if strings.Contains(capture.Prompts, ingestTestSecret[:17]) || strings.Contains(capture.Title, ingestTestSecret[:17]) {
		t.Errorf("the capture holds the secret: %q", capture.Title)
	}
	if !env.hasGap(env.runOf("claude-code", "s1"), sidecar.RecordCoverageGapRedaction) {
		t.Error("no redaction gap")
	}
}

// ingestCut keeps a rune whole: a cut inside a rune, or just past a whole one, ends at a rune's start, so a cut string
// is valid UTF-8; bytes that are no UTF-8 are cut where asked, and a non-positive count cuts everything.
func TestIngestCutKeepsRunesWhole(t *testing.T) {
	cases := []struct {
		text      string
		byteCount int64
		want      string
		cut       bool
	}{
		{text: "a€b", byteCount: 5, want: "a€b", cut: false},
		{text: "a€b", byteCount: 4, want: "a€", cut: true},
		{text: "a€b", byteCount: 3, want: "a", cut: true},
		{text: "a€b", byteCount: 2, want: "a", cut: true},
		{text: "a€b", byteCount: 1, want: "a", cut: true},
		{text: "aé", byteCount: 2, want: "a", cut: true},
		{text: "a😀", byteCount: 4, want: "a", cut: true},
		{text: "a😀b", byteCount: 5, want: "a😀", cut: true},
		{text: "\x80\x80\x80\x80\x80\x80", byteCount: 4, want: "\x80\x80\x80\x80", cut: true},
		{text: "abc", byteCount: 0, want: "", cut: true},
		{text: "abc", byteCount: -1, want: "", cut: true},
	}
	for _, c := range cases {
		got, cut := ingestCut([]byte(c.text), c.byteCount)
		if string(got) != c.want || cut != c.cut {
			t.Errorf("%q cut at %d: %q, %v; want %q, %v", c.text, c.byteCount, got, cut, c.want, c.cut)
		}
		if utf8.ValidString(c.text) && !utf8.Valid(got) {
			t.Errorf("%q cut at %d is no UTF-8: %q", c.text, c.byteCount, got)
		}
	}
}

// The regression on the hook path: a first prompt whose line crosses the title's 120 B inside a rune, and a later one
// crossing the prompts' bound inside a rune, each still seal: the title and the prompt end before the rune, and no
// entry is refused. With ingestCut leaving a rune's lead byte, the title was no UTF-8, every context entry carrying it
// failed to marshal, and each was a missed_event.
func TestPromptCutInsideARuneStillSeals(t *testing.T) {
	env := newIngestTestEnv(t)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	first := strings.Repeat("a", 119) + "é and more"
	if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": first})); err != nil {
		t.Fatal(err)
	}
	bound := env.server.settings.Ingest.RunCardPromptByteCount
	// one byte is left for the third prompt, inside its first rune
	second := strings.Repeat("s", bound-len(first)-1-2)
	third := "€uro"
	for _, prompt := range []string{second, third} {
		if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": prompt})); err != nil {
			t.Fatal(err)
		}
	}
	runId := env.runOf("claude-code", "s1")
	if env.hasGap(runId, sidecar.RecordCoverageGapMissedEvent) {
		t.Fatal("an entry was refused")
	}
	prompted := testPromptedContexts(env)
	if len(prompted) != 2 || prompted[0].Title != strings.Repeat("a", 119) || !slices.Equal(prompted[0].Prompts, []string{first}) ||
		!slices.Equal(prompted[1].Prompts, []string{second}) {
		t.Fatalf("the prompted entries %d", len(prompted))
	}
	if capture := env.ingest.Capture(env.networkId, runId); !utf8.ValidString(capture.Title) || !utf8.ValidString(capture.Prompts) {
		t.Errorf("the capture is no UTF-8: %q", capture.Title)
	}
}
