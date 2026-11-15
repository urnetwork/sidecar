//go:build !js && !ios && !android && !sdk_mobile_bind

// The daemon's telemetry listener (QD-822) on the hook env: served on 127.0.0.1 at the sealed pair's port, it takes a
// model_call with the pair's token and refuses one without it, with another, or with no model call, recording
// nothing; it binds loopback alone and refuses another Host; it serves nothing without a pair, while capture is off,
// or where the port will not bind, and says why; a reload serves a new pair; the token reaches the logs path alone,
// at Ingest.TelemetryRequestRate; and Codex's records stay passed over, its hook's calls standing.

package mcp

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A port the loopback interface has free now.
func testFreeLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// The hook env with model calls on, a pair sealed under a fresh state on a free loopback port, and no listener yet.
func newTelemetryEnv(t *testing.T) (*ingestTestEnv, string, *HarnessTelemetry) {
	t.Helper()
	env := newIngestTestEnv(t)
	env.server.settings.Ingest.ModelCalls = true
	env.ingest.detach()
	env.install()
	state := t.TempDir()
	pair := testTelemetryPair(testFreeLoopbackPort(t), "synthetic listener token")
	if err := writeHarnessTelemetry(state, pair); err != nil {
		t.Fatal(err)
	}
	return env, state, pair
}

// The env's listener over state, closed at the test's end.
func testTelemetryListener(t *testing.T, env *ingestTestEnv, state string) *IngestTelemetryListener {
	t.Helper()
	listener := NewIngestTelemetryListener(&IngestTelemetryListenerArgs{Ingest: env.ingest, StateDirectory: state})
	t.Cleanup(listener.Close)
	return listener
}

// One request to address: its path, method, Host and authorization ("" for none), answering the status, or 0 where
// nothing answers.
func testTelemetryRequest(t *testing.T, address string, method string, path string, host string, authorization string, body []byte) int {
	t.Helper()
	request, err := http.NewRequest(method, "http://"+address+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if host != "" {
		request.Host = host
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		return 0
	}
	response.Body.Close()
	return response.StatusCode
}

// An OTLP JSON logs export of records under service's resource, each record its attributes.
func testOtlpRecords(service string, records ...map[string]string) []byte {
	logRecords := []any{}
	for _, record := range records {
		attributes := []any{}
		for key, value := range record {
			attributes = append(attributes, map[string]any{"key": key, "value": map[string]any{"stringValue": value}})
		}
		logRecords = append(logRecords, map[string]any{"timeUnixNano": "1767323045000000000", "attributes": attributes})
	}
	export := map[string]any{"resourceLogs": []any{map[string]any{
		"resource": map[string]any{"attributes": []any{
			map[string]any{"key": "service.name", "value": map[string]any{"stringValue": service}},
		}},
		"scopeLogs": []any{map[string]any{"logRecords": logRecords}},
	}}}
	encoded, _ := json.Marshal(export)
	return encoded
}

// The missed_event gaps a run's file counts.
func testMissedEventGaps(env *ingestTestEnv, runId sidecar.Id) int {
	for _, gap := range env.runFile(runId).Gaps {
		if code, count, ok := sidecar.RecordCoverageGapParse(gap); ok && code == sidecar.RecordCoverageGapMissedEvent {
			return count
		}
	}
	return 0
}

// The listener takes a model_call with the sealed token, labeled source hook, and refuses 401 one without a token,
// one with another, and one holding no model call, recording nothing for them: no entry and no gap.
func TestTelemetryListenerTakesModelCallsWithItsToken(t *testing.T) {
	env, state, pair := newTelemetryEnv(t)
	listener := testTelemetryListener(t, env, state)
	status := listener.Status()
	if !status.Serving || status.Port != pair.Port || status.Address != "127.0.0.1:"+strconv.Itoa(pair.Port) {
		t.Fatalf("status %+v", status)
	}
	claude := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := claude.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	runId := env.runOf("claude-code", "s1")
	gaps := testMissedEventGaps(env, runId)
	drafts := len(env.writer.kinds())
	export := testOtlpExport("s1", "claude-test")
	prompt := testOtlpRecords("claude-code", map[string]string{"event.name": "user_prompt", "session.id": "s1", "prompt_length": "12"})
	refusals := []struct {
		authorization string
		body          []byte
	}{
		{authorization: "", body: export},
		{authorization: "Bearer " + strings.Repeat("0", len(pair.Token)), body: export},
		{authorization: pair.Authorization(), body: prompt},
	}
	for i, refusal := range refusals {
		if code := testTelemetryRequest(t, status.Address, http.MethodPost, ingestTelemetryLogsPath, "", refusal.authorization, refusal.body); code != http.StatusUnauthorized {
			t.Errorf("refusal %d: status %d", i, code)
		}
	}
	if len(env.writer.kinds()) != drafts || testMissedEventGaps(env, runId) != gaps {
		t.Errorf("a refused request recorded: %v", env.writer.kinds()[drafts:])
	}
	if refused := listener.Status().Counts.Refused; refused != len(refusals) {
		t.Errorf("%d refused", refused)
	}
	if code := testTelemetryRequest(t, status.Address, http.MethodPost, ingestTelemetryLogsPath, "", pair.Authorization(), export); code != http.StatusOK {
		t.Fatalf("the token's model call: status %d", code)
	}
	calls := env.writer.of(sidecar.RecordKindModelCall)
	if len(calls) != 1 || calls[0].Source != sidecar.RecordSourceHook || calls[0].Body.(*protocol.ModelCallBody).InputTokens != 1200 {
		t.Errorf("the token's model call recorded %v", calls)
	}
}

// The listener asks the loopback address alone of its bind, answers there, and refuses 401 a request whose Host names
// anything else, recording nothing.
func TestTelemetryListenerBindsLoopbackOnly(t *testing.T) {
	env, state, pair := newTelemetryEnv(t)
	var bindLock sync.Mutex
	binds := []string{}
	listener := NewIngestTelemetryListener(&IngestTelemetryListenerArgs{
		Ingest:         env.ingest,
		StateDirectory: state,
		Listen: func(network string, address string) (net.Listener, error) {
			bindLock.Lock()
			binds = append(binds, network+" "+address)
			bindLock.Unlock()
			return net.Listen(network, address)
		},
	})
	t.Cleanup(listener.Close)
	if len(binds) != 1 || binds[0] != "tcp 127.0.0.1:"+strconv.Itoa(pair.Port) {
		t.Fatalf("binds %q", binds)
	}
	host, _, err := net.SplitHostPort(listener.Status().Address)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatalf("serving on %q", listener.Status().Address)
	}
	claude := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := claude.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	export := testOtlpExport("s1", "claude-test")
	port := strconv.Itoa(pair.Port)
	for _, misdirected := range []string{"192.0.2.1:" + port, "rebound.example:" + port, "127.0.0.1:1"} {
		if code := testTelemetryRequest(t, pair.Address(), http.MethodPost, ingestTelemetryLogsPath, misdirected, pair.Authorization(), export); code != http.StatusUnauthorized {
			t.Errorf("Host %q: status %d", misdirected, code)
		}
	}
	if calls := env.writer.of(sidecar.RecordKindModelCall); len(calls) != 0 {
		t.Errorf("a misdirected request recorded %d calls", len(calls))
	}
	if code := testTelemetryRequest(t, pair.Address(), http.MethodPost, ingestTelemetryLogsPath, "localhost:"+port, pair.Authorization(), export); code != http.StatusOK {
		t.Errorf("Host localhost: status %d", code)
	}
}

// With no pair, a pair that does not read, capture off, or a port in use, the listener serves nothing and says why;
// once the port is free, a reload serves.
func TestTelemetryListenerServesNothingAndSaysWhy(t *testing.T) {
	env, state, pair := newTelemetryEnv(t)

	none := testTelemetryListener(t, env, t.TempDir())
	if status := none.Status(); status.Serving || status.Port != 0 || !strings.Contains(status.Reason, "ur install-harness") {
		t.Errorf("no pair: %+v", status)
	}

	unreadable := t.TempDir()
	if err := harnessWriteFile(HarnessTelemetryPath(unreadable), []byte(`{"version": 1, "port": "x"}`), 0o600, true); err != nil {
		t.Fatal(err)
	}
	if status := testTelemetryListener(t, env, unreadable).Status(); status.Serving || !strings.Contains(status.Reason, "does not read") {
		t.Errorf("a pair that does not read: %+v", status)
	}

	occupier, err := net.Listen("tcp", pair.Address())
	if err != nil {
		t.Fatal(err)
	}
	busy := testTelemetryListener(t, env, state)
	if status := busy.Status(); status.Serving || status.Port != pair.Port || !strings.Contains(status.Reason, "did not bind") {
		t.Errorf("a port in use: %+v", status)
	}
	occupier.Close()
	if status := busy.Reload(); !status.Serving {
		t.Errorf("the reload once the port is free: %+v", status)
	}
	busy.Close()
	if status := busy.Status(); status.Serving {
		t.Errorf("a closed listener serves: %+v", status)
	}
	if code := testTelemetryRequest(t, pair.Address(), http.MethodPost, ingestTelemetryLogsPath, "", pair.Authorization(), nil); code != 0 {
		t.Errorf("a closed listener answered %d", code)
	}

	env.server.settings.Ingest.ModelCalls = false
	off := testTelemetryListener(t, env, state)
	if status := off.Status(); status.Serving || status.Port != pair.Port || !strings.Contains(status.Reason, "model calls are off") {
		t.Errorf("capture off: %+v", status)
	}
}

// A reload serves a pair sealed since the start, and another pair's reload stops the old port and the old token.
func TestTelemetryListenerReloadServesNewPair(t *testing.T) {
	env, _, first := newTelemetryEnv(t)
	state := t.TempDir()
	listener := testTelemetryListener(t, env, state)
	if listener.Status().Serving {
		t.Fatal("serving before any pair")
	}
	if err := writeHarnessTelemetry(state, first); err != nil {
		t.Fatal(err)
	}
	if status := listener.Reload(); !status.Serving || status.Port != first.Port {
		t.Fatalf("the reload: %+v", status)
	}
	// the same pair again changes nothing
	if status := listener.Reload(); !status.Serving || status.Port != first.Port {
		t.Fatalf("the same pair's reload: %+v", status)
	}
	claude := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := claude.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	export := testOtlpExport("s1", "claude-test")
	if code := testTelemetryRequest(t, first.Address(), http.MethodPost, ingestTelemetryLogsPath, "", first.Authorization(), export); code != http.StatusOK {
		t.Fatalf("the first pair: status %d", code)
	}

	second := testTelemetryPair(testFreeLoopbackPort(t), "another synthetic listener token")
	if err := writeHarnessTelemetry(state, second); err != nil {
		t.Fatal(err)
	}
	if status := listener.Reload(); !status.Serving || status.Port != second.Port {
		t.Fatalf("the second reload: %+v", status)
	}
	if code := testTelemetryRequest(t, first.Address(), http.MethodPost, ingestTelemetryLogsPath, "", first.Authorization(), export); code != 0 {
		t.Errorf("the old port answered %d", code)
	}
	if code := testTelemetryRequest(t, second.Address(), http.MethodPost, ingestTelemetryLogsPath, "", first.Authorization(), export); code != http.StatusUnauthorized {
		t.Errorf("the old token on the new port: status %d", code)
	}
	if code := testTelemetryRequest(t, second.Address(), http.MethodPost, ingestTelemetryLogsPath, "", second.Authorization(), export); code != http.StatusOK {
		t.Errorf("the new pair: status %d", code)
	}
	if calls := env.writer.of(sidecar.RecordKindModelCall); len(calls) != 2 {
		t.Errorf("%d model calls", len(calls))
	}
}

// The token reaches a POST to the logs path alone: another path or method is refused 401, and so is any request while
// capture is off, each recording nothing.
func TestTelemetryTokenScopedToLogsRoute(t *testing.T) {
	env, telemetry, listener, token := newModelCallEnv(t)
	claude := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := claude.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	export := testOtlpExport("s1", "claude-test")
	address := strings.TrimPrefix(listener.URL, "http://")
	for _, request := range [][2]string{
		{http.MethodPost, "/v1/metrics"},
		{http.MethodPost, "/v1/traces"},
		{http.MethodPost, "/"},
		{http.MethodGet, ingestTelemetryLogsPath},
		{http.MethodPut, ingestTelemetryLogsPath},
	} {
		if code := testTelemetryRequest(t, address, request[0], request[1], "", "Bearer "+token, export); code != http.StatusUnauthorized {
			t.Errorf("%s %s: status %d", request[0], request[1], code)
		}
	}
	env.server.settings.Ingest.ModelCalls = false
	if code := testTelemetryRequest(t, address, http.MethodPost, ingestTelemetryLogsPath, "", "Bearer "+token, export); code != http.StatusUnauthorized {
		t.Errorf("capture off: status %d", code)
	}
	if calls := env.writer.of(sidecar.RecordKindModelCall); len(calls) != 0 {
		t.Errorf("an out-of-scope request recorded %d calls", len(calls))
	}
	if counts := telemetry.Counts(); counts.Refused != 6 || counts.Dropped != 0 {
		t.Errorf("counts %+v", counts)
	}
}

// Past Ingest.TelemetryRequestRate an export is answered 429 and records nothing, and the bucket refills on the clock.
func TestTelemetryRateLimited(t *testing.T) {
	env, state, pair := newTelemetryEnv(t)
	env.server.settings.Ingest.TelemetryRequestRate = sidecar.SidecarRate{Count: 1, Burst: 2, Interval: time.Second}
	listener := testTelemetryListener(t, env, state)
	claude := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := claude.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	export := testOtlpExport("s1", "claude-test")
	post := func() int {
		return testTelemetryRequest(t, pair.Address(), http.MethodPost, ingestTelemetryLogsPath, "", pair.Authorization(), export)
	}
	for i := range 2 {
		if code := post(); code != http.StatusOK {
			t.Fatalf("export %d within the burst: status %d", i, code)
		}
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Errorf("past the burst: status %d", code)
	}
	if calls := env.writer.of(sidecar.RecordKindModelCall); len(calls) != 2 {
		t.Errorf("%d model calls after the 429", len(calls))
	}
	env.clock.Advance(time.Second)
	if code := post(); code != http.StatusOK {
		t.Errorf("after the refill: status %d", code)
	}
	if counts := listener.Status().Counts; counts.Limited != 1 {
		t.Errorf("counts %+v", counts)
	}
}

// An export holding a model call and other records takes the call alone; one holding only Codex's records is refused
// 401 with nothing recorded, and Codex's PostModelRequest hook still records its call.
func TestTelemetryTakesModelCallsAlone(t *testing.T) {
	env, telemetry, listener, token := newModelCallEnv(t)
	address := strings.TrimPrefix(listener.URL, "http://")
	claude := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := claude.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	drafts := len(env.writer.kinds())
	mixed := testOtlpRecords("claude-code",
		map[string]string{"event.name": "api_request", "session.id": "s1", "model": "claude-test", "input_tokens": "5"},
		map[string]string{"event.name": "tool_result", "session.id": "s1", "tool_name": "Bash", "success": "true"},
		map[string]string{"event.name": "user_prompt", "session.id": "s1", "prompt_length": "12"},
	)
	if code := testTelemetryRequest(t, address, http.MethodPost, ingestTelemetryLogsPath, "", "Bearer "+token, mixed); code != http.StatusOK {
		t.Fatalf("the mixed export: status %d", code)
	}
	if kinds := env.writer.kinds()[drafts:]; len(kinds) != 1 || kinds[0] != sidecar.RecordKindModelCall {
		t.Errorf("the mixed export recorded %v", kinds)
	}

	codex := env.harnessIn(sidecartest.FakeHarnessCodex)
	if err := codex.Hook(codex.Payload("c1", "PostModelRequest", map[string]any{
		"model": "codex-test", "request_id": "req-1", "usage": map[string]any{"input_tokens": 10, "output_tokens": 20},
	})); err != nil {
		t.Fatal(err)
	}
	calls := len(env.writer.of(sidecar.RecordKindModelCall))
	codexExport := testOtlpRecords("codex_cli_rs",
		map[string]string{"event.name": "codex.api_request", "session.id": "c1", "model": "codex-test", "duration_ms": "900"},
	)
	if code := testTelemetryRequest(t, address, http.MethodPost, ingestTelemetryLogsPath, "", "Bearer "+token, codexExport); code != http.StatusUnauthorized {
		t.Errorf("codex's export: status %d", code)
	}
	if after := len(env.writer.of(sidecar.RecordKindModelCall)); after != calls || calls != 2 {
		t.Errorf("model calls %d, then %d after codex's export", calls, after)
	}
	if counts := telemetry.Counts(); counts.Refused != 1 || counts.Dropped != 0 {
		t.Errorf("counts %+v", counts)
	}
}
