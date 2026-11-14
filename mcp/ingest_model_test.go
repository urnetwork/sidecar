//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.18's model calls (MCP-M6-03) on the hook env: Codex's PostModelRequest and OTLP/HTTP JSON telemetry each become a
// model_call entry, source hook, every string redacted; the telemetry receiver, served on loopback, refuses a caller
// without its token and records nothing for it; an export it cannot read, or a call naming no live run, is a gap.

package mcp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	if refused, _ := telemetry.Counts(); refused != 4 {
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
	if _, dropped := telemetry.Counts(); dropped != len(exports) {
		t.Errorf("%d dropped", dropped)
	}
}
