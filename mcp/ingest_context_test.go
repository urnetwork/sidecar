//go:build !js && !ios && !android && !sdk_mobile_bind

// ingest_context.go's caps as Ingest's settings (QD-702): a context entry is cut to what the instance holds, set
// lower than the format's.

package mcp

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The context entry's caps are read from Ingest's settings: set lower than the format's, the title, model, permission
// mode, project and session ids are cut to them, the instruction files to their count, and each one left out is a
// truncation warning naming it within its bound; and a run-hour is RunHourInterval long.
func TestContextCapsAreSettings(t *testing.T) {
	env := newIngestTestEnv(t)
	for _, name := range []string{"CLAUDE.md", "AGENTS.md"} {
		if err := os.WriteFile(filepath.Join(env.cwd, name), []byte("rules\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	settings := env.server.settings.Ingest
	settings.ContextTitleByteCount = 5
	settings.ContextModelByteCount = 4
	settings.ContextPermissionModeByteCount = 3
	settings.ContextSessionIdByteCount = 2
	settings.ProjectByteCount = 2
	settings.ContextInstructionFileCount = 1
	settings.ContextTruncationNameByteCount = 4
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.SessionStart("session-1", "startup"); err != nil {
		t.Fatal(err)
	}
	if err := harness.Hook(harness.Payload("session-1", "UserPromptSubmit", map[string]any{"prompt": "Hello world"})); err != nil {
		t.Fatal(err)
	}
	contexts := env.writer.of(sidecar.RecordKindContext)
	if len(contexts) != 2 {
		t.Fatalf("%d context entries", len(contexts))
	}
	body := contexts[1].Body.(*protocol.ContextBody)
	if body.Title != "Hello" || body.Model != "test" || body.PermissionMode != "def" || !slices.Equal(body.SessionIds, []string{"se"}) ||
		body.Project != filepath.Base(env.cwd)[:2] {
		t.Errorf("the restated context: %+v", body)
	}
	if len(body.InstructionFiles) != 1 || body.InstructionFiles[0].Name != "CLAUDE.md" || !slices.Equal(body.Truncations, []string{"AGEN: not listed"}) {
		t.Errorf("the instruction files %+v and truncations %v", body.InstructionFiles, body.Truncations)
	}

	hourEnv := newIngestTestEnv(t)
	hourEnv.server.settings.Ingest.RunHourByteCount = 100
	hourEnv.server.settings.Ingest.RunHourInterval = 10 * time.Minute
	hourHarness := hourEnv.harnessIn(sidecartest.FakeHarnessClaudeCode)
	hourHarness.SessionStart("s1", "startup")
	call := func(id string) {
		hourHarness.Hook(hourHarness.Payload("s1", "PostToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}, "tool_response": strings.Repeat("y", 60), "tool_use_id": id}))
	}
	call("toolu_1")
	call("toolu_2")
	hourEnv.clock.Advance(10*time.Minute + time.Second)
	call("toolu_3")
	if calls := hourEnv.writer.of(sidecar.RecordKindToolCall); len(calls) != 2 || calls[1].Body.(*protocol.ToolCallBody).ToolUseId != "toolu_3" {
		t.Errorf("a ten-minute run-hour: %d tool calls", len(calls))
	}
}
