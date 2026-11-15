//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.18's model calls (MCP-M6-03) on the hook env: Codex's PostModelRequest and OTLP/HTTP JSON telemetry each become a
// model_call entry, source hook, every string redacted; the telemetry receiver, served on loopback, refuses a caller
// without its token and records nothing for it; an export it cannot read, or a call naming no live run, is a gap. A
// Codex call comes from its hook alone (QD-835): one PostModelRequest is one model_call with its request id and tokens,
// which RunCostBody's calls counts once, a Codex export of the same call adding nothing, and MCP-M3-28's recorded
// PostModelRequest reads so.

package mcp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The hook env with model calls on and a telemetry receiver on a loopback listener, its token a fresh one.
func newModelCallEnv(t *testing.T) (*ingestTestEnv, *IngestTelemetry, *httptest.Server, string) {
	t.Helper()
	env := newIngestTestEnv(t)
	env.server.settings.Ingest.ModelCalls = true
	env.ingest.detach()
	env.install()
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	encoded := hex.EncodeToString(token)
	telemetry := NewIngestTelemetry(env.ingest, []byte(encoded))
	listener := httptest.NewServer(telemetry.Handler())
	t.Cleanup(listener.Close)
	return env, telemetry, listener, encoded
}

// An OTLP JSON logs export of one Claude Code api_request record for session, its model the given text.
func testOtlpExport(session string, model string) []byte {
	attribute := func(key string, value map[string]any) map[string]any {
		return map[string]any{"key": key, "value": value}
	}
	export := map[string]any{
		"resourceLogs": []any{map[string]any{
			"resource": map[string]any{"attributes": []any{attribute("service.name", map[string]any{"stringValue": "claude-code"})}},
			"scopeLogs": []any{map[string]any{"logRecords": []any{map[string]any{
				"timeUnixNano": "1767323045000000000",
				"body":         map[string]any{"stringValue": "claude_code.api_request"},
				"attributes": []any{
					attribute("event.name", map[string]any{"stringValue": "api_request"}),
					attribute("session.id", map[string]any{"stringValue": session}),
					attribute("model", map[string]any{"stringValue": model}),
					attribute("input_tokens", map[string]any{"intValue": "1200"}),
					attribute("output_tokens", map[string]any{"intValue": "340"}),
					attribute("cache_read_tokens", map[string]any{"intValue": "800"}),
					attribute("cost_usd", map[string]any{"doubleValue": 0.0125}),
					attribute("duration_ms", map[string]any{"intValue": "2100"}),
				},
			}}}},
		}},
	}
	encoded, _ := json.Marshal(export)
	return encoded
}

// POSTs body to the receiver's logs path with authorization, "" for none, answering the status.
func testTelemetryPost(t *testing.T, listener *httptest.Server, authorization string, body []byte) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, listener.URL+ingestTelemetryLogsPath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := listener.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	return response.StatusCode
}

// A Codex PostModelRequest and an OTLP record each become a model_call entry, source hook, their strings redacted and
// their numbers kept.
func TestModelCallRedacted(t *testing.T) {
	env, _, listener, token := newModelCallEnv(t)
	codex := env.harnessIn(sidecartest.FakeHarnessCodex)
	if err := codex.Hook(codex.Payload("c1", "PostModelRequest", map[string]any{
		"model":       "test-model " + ingestTestSecret,
		"provider":    "test-provider",
		"request_id":  "req-1",
		"duration_ms": 900,
		"usage":       map[string]any{"input_tokens": 10, "output_tokens": 20, "cached_input_tokens": 5},
	})); err != nil {
		t.Fatal(err)
	}
	claude := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := claude.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	if status := testTelemetryPost(t, listener, "Bearer "+token, testOtlpExport("s1", "claude-test "+ingestTestSecret)); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	calls := env.writer.of(sidecar.RecordKindModelCall)
	if len(calls) != 2 {
		t.Fatalf("%d model_call entries", len(calls))
	}
	for _, call := range calls {
		body := call.Body.(*protocol.ModelCallBody)
		if call.Source != sidecar.RecordSourceHook || strings.Contains(body.Model, ingestTestSecret) || !strings.Contains(body.Model, "[REDACTED:") {
			t.Errorf("a model call kept %+v from source %v", body, call.Source)
		}
	}
	codexBody := calls[0].Body.(*protocol.ModelCallBody)
	if codexBody.InputTokens != 10 || codexBody.OutputTokens != 20 || codexBody.CacheReadTokens != 5 || codexBody.DurationMillis != 900 || codexBody.Provider != "test-provider" {
		t.Errorf("Codex's call %+v", codexBody)
	}
	otelBody := calls[1].Body.(*protocol.ModelCallBody)
	if otelBody.InputTokens != 1200 || otelBody.OutputTokens != 340 || otelBody.CacheReadTokens != 800 || otelBody.ReportedMicroUsd != 12500 ||
		otelBody.DurationMillis != 2100 || otelBody.StartedMillis != 1767323045000 {
		t.Errorf("the telemetry call %+v", otelBody)
	}
	claudeRun := env.runFile(env.runOf("claude-code", "s1"))
	if !env.hasGap(claudeRun.RunId, sidecar.RecordCoverageGapRedaction) {
		t.Errorf("no redaction gap: %v", claudeRun.Gaps)
	}
}

// A caller without the token, or with another, is refused 401 and nothing is recorded.
func TestOtelListenerRefusesUnauthenticated(t *testing.T) {
	env, telemetry, listener, token := newModelCallEnv(t)
	claude := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := claude.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	export := testOtlpExport("s1", "claude-test")
	for _, authorization := range []string{"", "Bearer " + strings.Repeat("0", len(token)), "Basic " + token, token} {
		if status := testTelemetryPost(t, listener, authorization, export); status != http.StatusUnauthorized {
			t.Errorf("authorization %q: status %d", authorization, status)
		}
	}
	if calls := env.writer.of(sidecar.RecordKindModelCall); len(calls) != 0 {
		t.Errorf("an unauthenticated caller recorded %d calls", len(calls))
	}
	if refused := telemetry.Counts().Refused; refused != 4 {
		t.Errorf("%d refused", refused)
	}
	if status := testTelemetryPost(t, listener, "Bearer "+token, export); status != http.StatusOK || len(env.writer.of(sidecar.RecordKindModelCall)) != 1 {
		t.Errorf("the token's caller: status %d", status)
	}
}

// An export that does not parse, one past the cap, and a call naming no live run are dropped exports: each a
// missed_event gap on the live runs, and nothing recorded.
func TestDroppedExportIsGap(t *testing.T) {
	env, telemetry, listener, token := newModelCallEnv(t)
	env.server.settings.Ingest.TelemetryByteCount = 4096
	claude := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := claude.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	runId := env.runOf("claude-code", "s1")
	gaps := func() int {
		for _, gap := range env.runFile(runId).Gaps {
			if code, count, ok := sidecar.RecordCoverageGapParse(gap); ok && code == sidecar.RecordCoverageGapMissedEvent {
				return count
			}
		}
		return 0
	}
	exports := [][]byte{
		[]byte(`{"resourceLogs": [`),
		bytes.Repeat([]byte(" "), 8192),
		testOtlpExport("no-such-session", "claude-test"),
	}
	for i, export := range exports {
		before := gaps()
		if status := testTelemetryPost(t, listener, "Bearer "+token, export); status != http.StatusOK {
			t.Errorf("export %d: status %d", i, status)
		}
		if gaps() != before+1 {
			t.Errorf("export %d: missed_event gaps %d, then %d", i, before, gaps())
		}
	}
	if calls := env.writer.of(sidecar.RecordKindModelCall); len(calls) != 0 {
		t.Errorf("dropped exports recorded %d calls", len(calls))
	}
	if dropped := telemetry.Counts().Dropped; dropped != len(exports) {
		t.Errorf("%d dropped", dropped)
	}
}

// The run's model_call entries summed as RECORD.md 13.1's cost has them (sidecar.RecordRunCost), beside the run's gaps.
func testRunCostBody(t *testing.T, env *ingestTestEnv, runId sidecar.Id) *protocol.RunCostBody {
	t.Helper()
	cost := &sidecar.RecordRunCost{}
	for _, call := range env.writer.of(sidecar.RecordKindModelCall) {
		if call.RunId != nil && *call.RunId == runId {
			cost.AddCall(call.Body.(*protocol.ModelCallBody), nil)
		}
	}
	body, ok := cost.Body(env.runFile(runId).Gaps)
	if !ok {
		t.Fatal("the run reported no model call")
	}
	return body
}

// One Codex PostModelRequest records one model_call, source hook, with its request id, tokens and duration, and the
// run's cost counts it once; Codex's own export of the same call, reaching the receiver with the token, is refused
// with nothing recorded, so the count stays one (QD-835).
func TestCodexPostModelRequestCountsOnce(t *testing.T) {
	env, telemetry, listener, token := newModelCallEnv(t)
	codex := env.harnessIn(sidecartest.FakeHarnessCodex)
	if err := codex.Hook(codex.Payload("c1", "PostModelRequest", map[string]any{
		"model":       "codex-test",
		"provider":    "test-provider",
		"request_id":  "req-once",
		"duration_ms": 1200,
		"usage":       map[string]any{"input_tokens": 300, "output_tokens": 40, "cached_input_tokens": 200},
	})); err != nil {
		t.Fatal(err)
	}
	runId := env.runOf("codex", "c1")
	calls := env.writer.of(sidecar.RecordKindModelCall)
	if len(calls) != 1 {
		t.Fatalf("%d model_call entries", len(calls))
	}
	body := calls[0].Body.(*protocol.ModelCallBody)
	if calls[0].Source != sidecar.RecordSourceHook || body.RequestId != "req-once" || body.Model != "codex-test" ||
		body.InputTokens != 300 || body.OutputTokens != 40 || body.CacheReadTokens != 200 || body.DurationMillis != 1200 {
		t.Errorf("the call %+v from source %v", body, calls[0].Source)
	}

	export := testOtlpRecords("codex_cli_rs", map[string]string{
		"event.name": "codex.api_request", "session.id": "c1", "model": "codex-test", "request_id": "req-once",
		"input_tokens": "300", "output_tokens": "40", "duration_ms": "1200",
	})
	if status := testTelemetryPost(t, listener, "Bearer "+token, export); status != http.StatusUnauthorized {
		t.Errorf("codex's export: status %d", status)
	}
	if after := env.writer.of(sidecar.RecordKindModelCall); len(after) != 1 {
		t.Errorf("%d model_call entries after codex's export", len(after))
	}
	if counts := telemetry.Counts(); counts.Refused != 1 || counts.Dropped != 0 {
		t.Errorf("counts %+v", counts)
	}
	cost := testRunCostBody(t, env, runId)
	if len(cost.Usage) != 1 || cost.Usage[0].Calls != 1 || cost.Usage[0].Model != "codex-test" || cost.Usage[0].InputTokens != 300 ||
		cost.Usage[0].OutputTokens != 40 || cost.Usage[0].CacheReadTokens != 200 || !cost.Usage[0].Complete {
		t.Errorf("the run's cost %+v", cost.Usage)
	}
	// the run's one model-call source is its hooks, never telemetry
	if err := codex.SessionEnd("c1", "exit"); err != nil {
		t.Fatal(err)
	}
	coverages := env.writer.of(sidecar.RecordKindCoverage)
	if len(coverages) != 1 {
		t.Fatalf("%d coverage entries", len(coverages))
	}
	if sources := coverages[0].Body.(*protocol.Coverage).Sources; !slices.Contains(sources, sidecar.RecordCoverageSourceHooks) ||
		slices.Contains(sources, sidecar.RecordCoverageSourceTelemetry) {
		t.Errorf("the run's sources %v", sources)
	}
}

// MCP-M3-28's recorded Codex session holds a PostModelRequest, and each one, through the hook path, records one
// model_call with the payload's request id and tokens while model calls are on, and none, and no gap, while they are
// off, the hook event standing either way.
func TestCodexRecordedPostModelRequestRecordsItsCall(t *testing.T) {
	var codex *conformanceVersion
	for _, version := range loadConformanceVersions(t) {
		if version.manifest.Harness == codexHookHarness {
			codex = version
		}
	}
	if codex == nil {
		t.Fatal("no recorded codex session")
	}
	payloads := [][]byte{}
	for _, want := range codex.expected {
		if want.HarnessEvent == "PostModelRequest" {
			payloads = append(payloads, codex.payloads[want.File])
		}
	}
	if len(payloads) == 0 {
		t.Fatal("codex's recorded session holds no PostModelRequest")
	}
	for _, modelCalls := range []bool{true, false} {
		env := newIngestTestEnv(t)
		env.server.settings.Ingest.ModelCalls = modelCalls
		env.ingest.detach()
		env.install()
		harness := env.harnessIn(sidecartest.FakeHarnessCodex)
		home := t.TempDir()
		sessionId := ""
		for _, payload := range payloads {
			text := strings.ReplaceAll(string(payload), codex.manifest.Cwd, env.cwd)
			text = strings.ReplaceAll(text, codex.manifest.Home, home)
			if err := harness.Hook([]byte(text)); err != nil {
				t.Fatal(err)
			}
			read := &codexModelRequestPayload{}
			fields := struct {
				SessionId string `json:"session_id"`
			}{}
			if err := json.Unmarshal(payload, read); err != nil || json.Unmarshal(payload, &fields) != nil {
				t.Fatalf("the recorded payload: %v", err)
			}
			sessionId = fields.SessionId
		}
		runId := env.runOf(codexHookHarness, sessionId)
		calls := env.writer.of(sidecar.RecordKindModelCall)
		if !modelCalls {
			if len(calls) != 0 || 0 < len(env.runFile(runId).Gaps) {
				t.Errorf("model calls off: %d calls, gaps %v", len(calls), env.runFile(runId).Gaps)
			}
		} else if len(calls) != len(payloads) {
			t.Fatalf("%d model_call entries for %d recorded calls", len(calls), len(payloads))
		}
		for i := range calls {
			read := &codexModelRequestPayload{}
			json.Unmarshal(payloads[i], read)
			body := calls[i].Body.(*protocol.ModelCallBody)
			if body.RequestId != read.RequestId || body.Model != read.Model || body.Provider != read.Provider ||
				body.InputTokens != read.Usage.InputTokens || body.OutputTokens != read.Usage.OutputTokens ||
				body.CacheReadTokens != read.Usage.CachedInputTokens || uint64(body.DurationMillis) != read.DurationMs {
				t.Errorf("recorded call %d: %+v from %+v", i, body, read)
			}
		}
		if modelCalls {
			if cost := testRunCostBody(t, env, runId); len(cost.Usage) != 1 || cost.Usage[0].Calls != uint64(len(payloads)) {
				t.Errorf("the run's cost %+v", cost.Usage)
			}
		}
		if events := env.writer.of(sidecar.RecordKindHookEvent); len(events) != len(payloads) {
			t.Errorf("model calls %t: %d hook events", modelCalls, len(events))
		}
	}
}
