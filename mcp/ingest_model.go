//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.18's model calls (MCP-M6-03; R-MCP-4, D-MCP-5; RECORD.md section 12's call row and section 13's sources row): a
// model_call entry, source hook, in the author's vault, per call a harness reports, from either of two places:
//
//   - Codex's PostModelRequest hook, which the hook path reads as any event (HookEventModelCall) and Ingest captures
//     beside it, the Coverage naming hooks;
//   - harness OpenTelemetry: OTLP/HTTP JSON log records POSTed to IngestTelemetry's handler, which the daemon serves on
//     a loopback listener. The handler authenticates its caller (I-17) by the bearer token the exporter's settings
//     carry, compared in constant time, and refuses any other caller 401, recording nothing. A record maps to the
//     live run of its harness (the resource's service.name) and session (session.id, else gen_ai.conversation.id);
//     the Coverage names telemetry.
//
// A record is a model call when it names an API request (event.name api_request, any harness's prefix) or carries
// gen_ai.usage tokens: model, provider, request id, tokens, the harness's own cost and the duration, under the
// harness's names and the GenAI semantic conventions' (RECORD.md's otel row). Every string passes the redactor and is
// cut to Record.ModelCallFieldByteCount, RECORD.md's 128 B. An export that cannot be read whole, past
// Ingest.TelemetryByteCount or not OTLP JSON, and a call that names no live run, are dropped exports: a missed_event
// gap on the runs of its harness, or on every live run when the harness is unknown, since a lost call may hide cost.
// Off unless Ingest.ModelCalls is set: M6's capture, off by default.

package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// OTLP/HTTP's path for logs, a format value.
const ingestTelemetryLogsPath = "/v1/logs"

// One call as a harness reports it.
type ingestModelCall struct {
	model           string
	provider        string
	requestId       string
	inputTokens     uint64
	outputTokens    uint64
	cacheReadTokens uint64
	cacheWrite      uint64
	microUsd        uint64
	startedMillis   int64
	durationMillis  uint32
}

// A Codex PostModelRequest's fields this version reads (§16.18), its usage under OpenAI's names.
type codexModelRequestPayload struct {
	Model      string `json:"model"`
	Provider   string `json:"provider"`
	RequestId  string `json:"request_id"`
	DurationMs uint64 `json:"duration_ms"`
	Usage      struct {
		InputTokens       uint64 `json:"input_tokens"`
		OutputTokens      uint64 `json:"output_tokens"`
		CachedInputTokens uint64 `json:"cached_input_tokens"`
	} `json:"usage"`
}

// The model call a Codex PostModelRequest reports, false for a payload that names no model.
func codexModelCall(payload []byte) (*ingestModelCall, bool) {
	read := &codexModelRequestPayload{}
	if json.Unmarshal(payload, read) != nil || read.Model == "" {
		return nil, false
	}
	return &ingestModelCall{
		model:           read.Model,
		provider:        read.Provider,
		requestId:       read.RequestId,
		inputTokens:     read.Usage.InputTokens,
		outputTokens:    read.Usage.OutputTokens,
		cacheReadTokens: read.Usage.CachedInputTokens,
		durationMillis:  uint32(min(read.DurationMs, math.MaxUint32)),
	}, true
}

// A model call as a model_call entry of run's, source hook, each string redacted and cut. The run's lock is held.
func (self *Ingest) captureModelCallWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, call *ingestModelCall, coverageSource string) {
	text := func(value string) string {
		redacted := self.redact(ctx, run, redactor, []byte(value))
		cut, truncated := ingestCut(redacted, self.record.ModelCallFieldByteCount)
		if truncated {
			self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapTruncation)
		}
		return string(cut)
	}
	started := call.startedMillis
	if started == 0 {
		started = self.clock.Now().UnixMilli()
	}
	self.appendWithLock(ctx, run, &ingestEntry{
		kind:   sidecar.RecordKindModelCall,
		source: sidecar.RecordSourceHook,
		body: &protocol.ModelCallBody{
			Model:            text(call.model),
			Provider:         text(call.provider),
			RequestId:        text(call.requestId),
			InputTokens:      call.inputTokens,
			OutputTokens:     call.outputTokens,
			CacheReadTokens:  call.cacheReadTokens,
			CacheWriteTokens: call.cacheWrite,
			ReportedMicroUsd: call.microUsd,
			StartedMillis:    started,
			DurationMillis:   call.durationMillis,
		},
		coverageSource: coverageSource,
	})
}

// A Codex PostModelRequest, captured: nothing for another event, or while model calls are off.
func (self *Ingest) captureHookModelCallWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, event *HookEvent, payload []byte) {
	if event.Kind != HookEventModelCall || !self.settings.ModelCalls {
		return
	}
	call, ok := codexModelCall(payload)
	if !ok {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		return
	}
	self.captureModelCallWithLock(ctx, run, redactor, call, sidecar.RecordCoverageSourceHooks)
}

// The telemetry receiver: its handler, the token its callers hold, and what it refused. Safe for concurrent use.
type IngestTelemetry struct {
	ingest *Ingest
	token  []byte

	stateLock    sync.Mutex
	refusedCount int
	droppedCount int
}

// A receiver over ingest whose callers must hold token, the exporter settings' bearer value (§16.18; I-17).
func NewIngestTelemetry(ingest *Ingest, token []byte) *IngestTelemetry {
	return &IngestTelemetry{ingest: ingest, token: append([]byte(nil), token...)}
}

// The callers refused for want of the token, and the exports dropped.
func (self *IngestTelemetry) Counts() (refused int, dropped int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refusedCount, self.droppedCount
}

// OTLP/HTTP JSON's logs export, the fields this receiver reads.
type otlpLogsExport struct {
	ResourceLogs []struct {
		Resource struct {
			Attributes []*otlpAttribute `json:"attributes"`
		} `json:"resource"`
		ScopeLogs []struct {
			LogRecords []struct {
				TimeUnixNano string           `json:"timeUnixNano"`
				Body         *otlpValue       `json:"body"`
				Attributes   []*otlpAttribute `json:"attributes"`
			} `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

type otlpAttribute struct {
	Key   string     `json:"key"`
	Value *otlpValue `json:"value"`
}

// An OTLP AnyValue: int64 and uint64 travel as strings in OTLP JSON.
type otlpValue struct {
	StringValue *string          `json:"stringValue"`
	IntValue    *json.RawMessage `json:"intValue"`
	DoubleValue *float64         `json:"doubleValue"`
}

func (self *otlpValue) text() string {
	switch {
	case self == nil:
		return ""
	case self.StringValue != nil:
		return *self.StringValue
	case self.IntValue != nil:
		return strings.Trim(string(*self.IntValue), `"`)
	case self.DoubleValue != nil:
		return strconv.FormatFloat(*self.DoubleValue, 'f', -1, 64)
	}
	return ""
}

func (self *otlpValue) number() float64 {
	value, err := strconv.ParseFloat(self.text(), 64)
	if err != nil || value < 0 || math.IsInf(value, 0) || math.IsNaN(value) {
		return 0
	}
	return value
}

// The attributes by key, the first of a key standing.
func otlpAttributes(attributes []*otlpAttribute) map[string]*otlpValue {
	values := map[string]*otlpValue{}
	for _, attribute := range attributes {
		if attribute == nil || attribute.Value == nil {
			continue
		}
		if _, ok := values[attribute.Key]; !ok {
			values[attribute.Key] = attribute.Value
		}
	}
	return values
}

// The first of keys a record names.
func otlpFirst(values map[string]*otlpValue, keys ...string) *otlpValue {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value
		}
	}
	return nil
}

// The harness a resource's service.name names, "" for none ur hooks.
func otlpHarness(resource map[string]*otlpValue) string {
	name := strings.ToLower(otlpFirst(resource, "service.name").text())
	switch {
	case strings.Contains(name, "claude"):
		return claudeHookHarness
	case strings.Contains(name, "codex"):
		return codexHookHarness
	case strings.Contains(name, "cursor"):
		return cursorHookHarness
	}
	return ""
}

// One record's call and session, false for a record that is no model call.
func otlpModelCall(record map[string]*otlpValue, body *otlpValue, timeUnixNano string) (*ingestModelCall, string, bool) {
	event := otlpFirst(record, "event.name").text()
	if event == "" {
		event = body.text()
	}
	usage := otlpFirst(record, "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens") != nil
	if !usage && event != "api_request" && !strings.HasSuffix(event, ".api_request") {
		return nil, "", false
	}
	call := &ingestModelCall{
		model:           otlpFirst(record, "gen_ai.request.model", "model").text(),
		provider:        otlpFirst(record, "gen_ai.provider.name", "gen_ai.system").text(),
		requestId:       otlpFirst(record, "gen_ai.response.id", "request_id").text(),
		inputTokens:     uint64(otlpFirst(record, "gen_ai.usage.input_tokens", "input_tokens").number()),
		outputTokens:    uint64(otlpFirst(record, "gen_ai.usage.output_tokens", "output_tokens").number()),
		cacheReadTokens: uint64(otlpFirst(record, "cache_read_tokens").number()),
		cacheWrite:      uint64(otlpFirst(record, "cache_creation_tokens").number()),
		microUsd:        uint64(math.Round(otlpFirst(record, "cost_usd").number() * 1_000_000)),
		durationMillis:  uint32(min(otlpFirst(record, "duration_ms").number(), math.MaxUint32)),
	}
	if nanos, err := strconv.ParseInt(timeUnixNano, 10, 64); err == nil && 0 < nanos {
		call.startedMillis = nanos / 1_000_000
	}
	session := otlpFirst(record, "session.id", "gen_ai.conversation.id").text()
	return call, session, true
}

// The OTLP/HTTP JSON logs handler: the caller authenticated, the export read whole, each model call captured on its
// run, every other record passed over. See the file header.
func (self *IngestTelemetry) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(ingestTelemetryLogsPath, func(writer http.ResponseWriter, request *http.Request) {
		if !self.authenticated(request) {
			self.count(&self.refusedCount)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx := request.Context()
		ingest := self.ingest
		limit := ingest.settings.TelemetryByteCount
		body, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
		export := &otlpLogsExport{}
		if err == nil && limit < int64(len(body)) {
			err = errors.New("past the cap")
		}
		if err == nil {
			err = json.Unmarshal(body, export)
		}
		if err != nil || !ingest.settings.ModelCalls {
			self.dropped(ctx, "")
			// answered as taken, so the exporter does not send the same bytes again
			writer.WriteHeader(http.StatusOK)
			writer.Write([]byte("{}"))
			return
		}
		for _, resourceLogs := range export.ResourceLogs {
			harness := otlpHarness(otlpAttributes(resourceLogs.Resource.Attributes))
			for _, scopeLogs := range resourceLogs.ScopeLogs {
				for _, record := range scopeLogs.LogRecords {
					call, session, ok := otlpModelCall(otlpAttributes(record.Attributes), record.Body, record.TimeUnixNano)
					if !ok {
						continue
					}
					if !self.capture(ctx, harness, session, call) {
						self.dropped(ctx, harness)
					}
				}
			}
		}
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("{}"))
	})
	return mux
}

// Whether the request carries the token: `Authorization: Bearer <token>`, compared in constant time.
func (self *IngestTelemetry) authenticated(request *http.Request) bool {
	presented, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !ok || len(self.token) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), self.token) == 1
}

func (self *IngestTelemetry) count(counter *int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	*counter += 1
}

// A model call on the live run of harness and session: false when none is live.
func (self *IngestTelemetry) capture(ctx context.Context, harness string, session string, call *ingestModelCall) bool {
	if harness == "" || session == "" {
		return false
	}
	ingest := self.ingest
	var run *ingestRun
	for _, candidate := range ingest.liveRuns() {
		candidate.runLock.Lock()
		if candidate.state.Harness == harness && candidate.state.SessionId == session && candidate.state.EndedMillis == 0 {
			// held for the capture below
			run = candidate
			break
		}
		candidate.runLock.Unlock()
	}
	if run == nil {
		return false
	}
	defer run.runLock.Unlock()
	defer ingest.saveRunWithLock(run)
	redactor, err := ingest.redactor(run.network)
	if err != nil {
		ingest.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		return true
	}
	ingest.captureModelCallWithLock(ctx, run, redactor, call, sidecar.RecordCoverageSourceTelemetry)
	return true
}

// A dropped export: a missed_event gap on the live runs of harness, or on every live run where harness is unknown.
func (self *IngestTelemetry) dropped(ctx context.Context, harness string) {
	self.count(&self.droppedCount)
	ingest := self.ingest
	for _, run := range ingest.liveRuns() {
		matches := func() bool {
			run.runLock.Lock()
			defer run.runLock.Unlock()
			return run.state.EndedMillis == 0 && (harness == "" || run.state.Harness == harness)
		}()
		if matches {
			ingest.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		}
	}
}

// The runs this process holds, each read under its own lock by the caller.
func (self *Ingest) liveRuns() []*ingestRun {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	runs := []*ingestRun{}
	for _, run := range self.runs {
		runs = append(runs, run)
	}
	return runs
}
