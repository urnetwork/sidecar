//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension && !windows

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// GW-M12-03's tests: the Responses front (DESIGN-COMPUTE §8.4, §8.5). Each request is shaped from what Codex sends at
// openai/codex 5f645d73 (research_notes' gateway_harness_compat.md); each stream is a scripted router's, played as
// computetest.ScriptedModel plays a turn (start, reasoning, text, each tool call's start, argument deltas and end,
// usage, then the end or a failure), since a test inside the package cannot import computetest. Every model name,
// id and text is synthetic.

// How long a test waits on the gateway's goroutines before it fails: a guard, never the proof.
const testGatewayWait = 10 * time.Second

// A reader of the big-endian 64-bit words 0, 1, 2 and on, so every id and nonce a test draws repeats. Safe for
// concurrent use.
type testGatewayCounter struct {
	stateLock sync.Mutex
	next      uint64
	pending   []byte
}

func (self *testGatewayCounter) Read(buffer []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for len(self.pending) < len(buffer) {
		self.pending = binary.BigEndian.AppendUint64(self.pending, self.next)
		self.next++
	}
	count := copy(buffer, self.pending)
	self.pending = self.pending[count:]
	return count, nil
}

// A clock whose waits fire as a test moves it, each wait's length sent on armed, and given to onArm, as it is made.
type testGatewayFrontClock struct {
	stateLock sync.Mutex
	now       time.Time
	waits     []*testGatewayFrontWait
	armed     chan time.Duration
	onArm     func(timeout time.Duration)
}

type testGatewayFrontWait struct {
	at   time.Time
	fire chan time.Time
}

func newTestGatewayFrontClock() *testGatewayFrontClock {
	return &testGatewayFrontClock{
		now:   time.Date(2026, time.November, 27, 9, 0, 0, 0, time.UTC),
		armed: make(chan time.Duration, 1024),
	}
}

func (self *testGatewayFrontClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *testGatewayFrontClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	wait := &testGatewayFrontWait{at: self.now.Add(timeout), fire: make(chan time.Time, 1)}
	if timeout <= 0 {
		wait.fire <- self.now
	} else {
		self.waits = append(self.waits, wait)
	}
	select {
	case self.armed <- timeout:
	default:
	}
	if self.onArm != nil {
		self.onArm(timeout)
	}
	return wait.fire
}

func (self *testGatewayFrontClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	fire := self.After(timeout)
	stopped := make(chan struct{})
	go func() {
		select {
		case <-fire:
			function()
		case <-stopped:
		}
	}()
	once := sync.Once{}
	return func() bool {
		result := false
		once.Do(func() { close(stopped); result = true })
		return result
	}
}

// Moves the clock by, firing every wait it reaches.
func (self *testGatewayFrontClock) advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(by)
	kept := self.waits[:0]
	for _, wait := range self.waits {
		if wait.at.After(self.now) {
			kept = append(kept, wait)
			continue
		}
		wait.fire <- self.now
	}
	self.waits = kept
}

// Waits until a wait of length is armed.
func (self *testGatewayFrontClock) awaitArmed(t *testing.T, length time.Duration) {
	t.Helper()
	guard := time.After(testGatewayWait)
	for {
		select {
		case armed := <-self.armed:
			if armed == length {
				return
			}
		case <-guard:
			t.Fatalf("no wait of %s was armed", length)
		}
	}
}

// One tool call a turn makes, with its argument deltas.
type testGatewayToolCall struct {
	id     string
	name   string
	deltas []string
}

// One scripted call: a refusal, a first event that is an error, or a stream played as ScriptedModel plays a turn.
type testGatewayTurn struct {
	refuse    *InferError
	first     *InferError
	reasoning []string
	text      []string
	tools     []*testGatewayToolCall
	usage     *InferUsage
	attest    *protocol.AttestationResult
	// fails after failAfter deltas where fail is set
	fail      *InferError
	failAfter int
	// holds after stallAfter deltas until release closes, closing stalled when it does
	release    chan struct{}
	stallAfter int
	stalled    chan struct{}
}

// A router a test scripts (see the file header): each Infer takes the next turn and records its request; Check answers
// checkRefusal; the catalog holds the scripted models.
type testGatewayRouter struct {
	catalog *InferCatalog

	stateLock    sync.Mutex
	checkRefusal *InferError
	turns        []*testGatewayTurn
	requests     []*InferRequest
	checked      []*InferRequest
}

func newTestGatewayRouter(t *testing.T) *testGatewayRouter {
	t.Helper()
	catalog, err := NewInferCatalog([]*InferCatalogEntry{
		testInferRemoteEntry("chutes", "kimi-k3-tee", ComputeLabelAp, InferEffortHigh),
		testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortOff, InferEffortHigh),
	}, DefaultInferSettings())
	if err != nil {
		t.Fatal(err)
	}
	return &testGatewayRouter{catalog: catalog}
}

// Adds turns to the script.
func (self *testGatewayRouter) script(turns ...*testGatewayTurn) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.turns = append(self.turns, turns...)
}

// The requests Infer took.
func (self *testGatewayRouter) inferred() []*InferRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.requests)
}

func (self *testGatewayRouter) Catalog(ctx context.Context) (*InferCatalog, error) {
	return self.catalog, nil
}

func (self *testGatewayRouter) Check(ctx context.Context, request *InferRequest) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.checked = append(self.checked, request)
	if self.checkRefusal != nil {
		return self.checkRefusal
	}
	return nil
}

func (self *testGatewayRouter) Infer(ctx context.Context, request *InferRequest) (<-chan *InferEvent, error) {
	turn := func() *testGatewayTurn {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, request)
		if len(self.turns) == 0 {
			return &testGatewayTurn{first: newInferError(InferErrorEngineFailed, "the script ran out")}
		}
		turn := self.turns[0]
		self.turns = self.turns[1:]
		return turn
	}()
	if turn.refuse != nil {
		return nil, turn.refuse
	}
	events := make(chan *InferEvent, 1024)
	go func() {
		defer close(events)
		if turn.first != nil {
			events <- &InferEvent{Kind: InferEventError, Error: turn.first}
			return
		}
		canceled := func() {
			events <- &InferEvent{Kind: InferEventError, Error: newInferError(InferErrorCanceled, "the call's context ended")}
		}
		events <- &InferEvent{Kind: InferEventStart}
		deltas := 0
		// the stall and the failure sit between deltas, as ScriptedModel's do
		at := func() bool {
			if turn.release != nil && turn.stallAfter == deltas {
				close(turn.stalled)
				select {
				case <-turn.release:
				case <-ctx.Done():
					canceled()
					return false
				}
			}
			if turn.fail != nil && turn.failAfter == deltas {
				events <- &InferEvent{Kind: InferEventError, Error: turn.fail}
				return false
			}
			return true
		}
		delta := func(event *InferEvent) bool {
			if !at() {
				return false
			}
			events <- event
			deltas++
			return true
		}
		for _, text := range turn.reasoning {
			if !delta(&InferEvent{Kind: InferEventReasoning, Text: text}) {
				return
			}
		}
		for _, text := range turn.text {
			if !delta(&InferEvent{Kind: InferEventText, Text: text}) {
				return
			}
		}
		for _, tool := range turn.tools {
			events <- &InferEvent{Kind: InferEventToolCallStart, ToolCall: &InferToolCall{Id: tool.id, Name: tool.name}}
			for _, arguments := range tool.deltas {
				if !delta(&InferEvent{Kind: InferEventToolCallArgs, ToolCall: &InferToolCall{Id: tool.id, Arguments: arguments}}) {
					return
				}
			}
			events <- &InferEvent{Kind: InferEventToolCallEnd, ToolCall: &InferToolCall{Id: tool.id, Name: tool.name, Arguments: strings.Join(tool.deltas, "")}}
		}
		if !at() {
			return
		}
		if turn.attest != nil {
			events <- &InferEvent{Kind: InferEventAttestation, Attest: turn.attest}
		}
		if turn.usage != nil {
			usage := *turn.usage
			events <- &InferEvent{Kind: InferEventUsage, Usage: &usage}
		}
		if ctx.Err() != nil {
			canceled()
			return
		}
		events <- &InferEvent{Kind: InferEventEnd}
	}()
	return events, nil
}

// One entry of the order a call's record and its frames took.
type testGatewayOrder struct {
	stateLock sync.Mutex
	entries   []string
}

func (self *testGatewayOrder) add(entry string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.entries = append(self.entries, entry)
}

func (self *testGatewayOrder) all() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.entries)
}

// A recorder a test reads: every Begin, item and End, in the order log too; a Begin or an item fails where a test sets
// it to.
type testGatewayRecorder struct {
	order *testGatewayOrder

	stateLock sync.Mutex
	beginErr  error
	itemErr   error
	begins    []*GatewayRecordBegin
	items     [][]byte
	ends      []*GatewayRecordEnd
	cuts      []*GatewayRecordCut
}

type testGatewayRecordCall struct {
	recorder *testGatewayRecorder
}

func (self *testGatewayRecorder) Begin(ctx context.Context, begin *GatewayRecordBegin) (GatewayRecordCall, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.beginErr != nil {
		return nil, self.beginErr
	}
	self.begins = append(self.begins, begin)
	self.order.add("begin")
	return &testGatewayRecordCall{recorder: self}, nil
}

func (self *testGatewayRecorder) Cut(ctx context.Context, cut *GatewayRecordCut) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cuts = append(self.cuts, cut)
	return nil
}

func (self *testGatewayRecordCall) ResponseItem(ctx context.Context, item []byte) (Id, error) {
	recorder := self.recorder
	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	if recorder.itemErr != nil {
		return Id{}, recorder.itemErr
	}
	recorder.items = append(recorder.items, item)
	parsed := &struct {
		Id string `json:"id"`
	}{}
	json.Unmarshal(item, parsed)
	recorder.order.add("record:" + parsed.Id)
	// a node id that repeats: the item's index, as the journal's would be fixed
	nodeId := Id{}
	nodeId[15] = byte(len(recorder.items))
	return nodeId, nil
}

func (self *testGatewayRecordCall) End(ctx context.Context, end *GatewayRecordEnd) error {
	recorder := self.recorder
	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	recorder.ends = append(recorder.ends, end)
	recorder.order.add("end")
	return nil
}

// What the recorder holds now.
func (self *testGatewayRecorder) snapshot() ([]*GatewayRecordBegin, [][]byte, []*GatewayRecordEnd) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.begins), slices.Clone(self.items), slices.Clone(self.ends)
}

// A test network with a router and a reasoning key, beside the grant world's runs and grants.
type testGatewayFrontNetwork struct {
	*testGatewayNetwork
	router InferRouter
	key    []byte
}

func (self *testGatewayFrontNetwork) InferRouter() (InferRouter, error) {
	if self.router == nil {
		return nil, ErrComputeComponentUnavailable
	}
	return self.router, nil
}

func (self *testGatewayFrontNetwork) GatewayKey(purpose string) ([]byte, error) {
	if self.key == nil {
		return nil, ErrGatewayKeyUnavailable
	}
	return bytes.Clone(self.key), nil
}

// A network that also gives its disclosures' summary lines (CTRUST's check).
type testGatewayDisclosureNetwork struct {
	*testGatewayFrontNetwork
	check *ComputeDisclosureCheck
}

func (self *testGatewayDisclosureNetwork) ComputeDisclosureCheck() (*ComputeDisclosureCheck, error) {
	return self.check, nil
}

// The fronts over one test network: a codex grant, a run handle's token and its caller, a scripted router, a recorder,
// a binder that binds every call to one run, and a fake clock.
type testGatewayFrontWorld struct {
	*testGatewayWorld
	router   *testGatewayRouter
	recorder *testGatewayRecorder
	order    *testGatewayOrder
	binder   *testGatewayBinder
	clock    *testGatewayFrontClock
	front    *testGatewayFrontNetwork
	fronts   *GatewayFronts
	grant    *GatewayGrant
	handle   *GatewayRunHandle
	token    string
	caller   *GatewayCaller
	// each frame a caller wrote, as it wrote it
	written chan string
}

// The world, with settings changed before the fronts mount.
func newTestGatewayFrontWorld(t *testing.T, change func(settings *GatewaySettings)) *testGatewayFrontWorld {
	t.Helper()
	base := newTestGatewayWorld(t, false)
	if change != nil {
		change(base.settings)
	}
	order := &testGatewayOrder{}
	world := &testGatewayFrontWorld{
		testGatewayWorld: base,
		router:           newTestGatewayRouter(t),
		order:            order,
		recorder:         &testGatewayRecorder{order: order},
		clock:            newTestGatewayFrontClock(),
		handle:           &GatewayRunHandle{Process: ProcessIdentity{Pid: 4242, StartMillis: 7}},
		written:          make(chan string, 4096),
	}
	world.grant = base.make(&GatewayGrantsParams{Harness: "codex"}).Grants[0].Grant
	world.binder = &testGatewayBinder{runId: NewId(), union: &GatewayRunUnion{}}
	base.server.SetRunBinder(world.binder)
	world.front = &testGatewayFrontNetwork{
		testGatewayNetwork: base.network,
		router:             world.router,
		key:                bytes.Repeat([]byte{0x5a}, gatewayKeyByteCount),
	}
	base.hosts.networks[0].Network = world.front
	token, _, err := base.network.grants.Mint(context.Background(), world.grant.GrantId, world.handle)
	if err != nil {
		t.Fatal(err)
	}
	world.token = token
	world.caller = world.callerOf(token)
	world.fronts = base.server.MountFronts(&GatewayFrontsArgs{
		Recorder: world.recorder,
		Random:   &testGatewayCounter{},
		Clock:    world.clock,
	})
	world.clock.onArm = func(timeout time.Duration) {
		select {
		case world.written <- fmt.Sprintf("armed:%s", timeout):
		default:
		}
	}
	world.fronts.followWritten = func(frame []byte) {
		text := string(frame)
		order.add("frame:" + testGatewayFrameKey(text))
		select {
		case world.written <- text:
		default:
		}
	}
	t.Cleanup(world.fronts.Close)
	return world
}

// The caller token names, as the server authenticates it.
func (self *testGatewayFrontWorld) callerOf(token string) *GatewayCaller {
	self.t.Helper()
	grant, record, err := self.network.grants.Authenticate(GatewayTokenSha256(token))
	if err != nil {
		self.t.Fatal(err)
	}
	return &GatewayCaller{NetworkId: testNetworkId, Network: self.front, Store: self.network.grants, Grant: grant, Token: record}
}

// A frame's event type and the item id it names, for the order log.
func testGatewayFrameKey(frame string) string {
	event := &struct {
		Type   string `json:"type"`
		ItemId string `json:"item_id"`
		Item   *struct {
			Id string `json:"id"`
		} `json:"item"`
	}{}
	_, data, _ := strings.Cut(frame, "data: ")
	json.Unmarshal([]byte(strings.TrimSpace(data)), event)
	id := event.ItemId
	if event.Item != nil {
		id = event.Item.Id
	}
	return event.Type + ":" + id
}

// Serves one request to path through front, the caller the world's, and answers what was written once the answer
// ended.
func (self *testGatewayFrontWorld) serve(front gatewayFront, body string, headers map[string]string) *httptest.ResponseRecorder {
	self.t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/responses", strings.NewReader(body))
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	self.fronts.serve(recorder, request, self.caller, front)
	return recorder
}

// A Responses request as Codex sends one: its base instructions as a developer message, the person's text, its shell
// tool, high effort, store false, the whole history, encrypted reasoning asked for.
func testGatewayCodexBody(stream bool, extra ...string) string {
	members := []string{
		`"model":"chutes-kimi-k3-tee-high"`,
		`"input":[{"type":"message","role":"developer","content":[{"type":"input_text","text":"synthetic base instructions"}]},` +
			`{"type":"message","role":"user","content":[{"type":"input_text","text":"list the files"}]}]`,
		`"tools":[{"type":"function","name":"shell","description":"runs a command","strict":false,"parameters":{"type":"object","properties":{"command":{"type":"array","items":{"type":"string"}}},"required":["command"]}}]`,
		`"tool_choice":"auto"`,
		`"parallel_tool_calls":true`,
		`"reasoning":{"effort":"high","summary":"auto"}`,
		`"store":false`,
		`"stream":` + strconv.FormatBool(stream),
		`"include":["reasoning.encrypted_content"]`,
		`"prompt_cache_key":"synthetic-thread"`,
	}
	return "{" + strings.Join(append(members, extra...), ",") + "}"
}

// Fails unless got equals the golden file name under testdata/gateway/<dir>/, which
// SIDECAR_REGENERATE_GATEWAY_GOLDENS=1 writes instead.
func testGatewayGolden(t *testing.T, dir string, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "gateway", dir, name)
	if os.Getenv("SIDECAR_REGENERATE_GATEWAY_GOLDENS") != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (SIDECAR_REGENERATE_GATEWAY_GOLDENS=1 writes it)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs:\n%s\nwant:\n%s", path, got, want)
	}
}

// One event of a stream: its event line's name and its data, decoded.
type testGatewaySseEvent struct {
	name string
	data map[string]any
}

// The events of a stream, failing on a frame that is not an event or a keepalive.
func testGatewayEvents(t *testing.T, stream string) []*testGatewaySseEvent {
	t.Helper()
	events := []*testGatewaySseEvent{}
	for _, frame := range strings.Split(strings.TrimSuffix(stream, "\n\n"), "\n\n") {
		if frame == "" || strings.HasPrefix(frame, ":") {
			continue
		}
		name, data, ok := strings.Cut(frame, "\ndata: ")
		name, named := strings.CutPrefix(name, "event: ")
		if !ok || !named {
			t.Fatalf("a frame that is no event: %q", frame)
		}
		decoded := map[string]any{}
		if err := json.Unmarshal([]byte(data), &decoded); err != nil {
			t.Fatalf("an event whose data is no JSON object: %q", data)
		}
		events = append(events, &testGatewaySseEvent{name: name, data: decoded})
	}
	return events
}

// Open Responses' rules for a stream (openresponses.org/specification, 2026-04-24), as fixtures every golden passes:
// each event field equals its body's type; no id lines; sequence numbers count from 0 by one; response.created first
// and exactly one terminal, last; every item carries id, type and status; each item's lifecycle runs added, its
// parts' added, deltas, done, its parts' done, then the item's done, which carries it whole; and response.completed
// carries the response's id and integer usage.
func testGatewayOpenResponsesConformance(t *testing.T, stream string) {
	t.Helper()
	if strings.Contains(stream, "\nid:") || strings.HasPrefix(stream, "id:") {
		t.Error("a stream names an id field")
	}
	events := testGatewayEvents(t, stream)
	if len(events) == 0 || events[0].name != "response.created" {
		t.Fatalf("a stream that does not open with response.created")
	}
	terminals := 0
	itemState := map[string]string{}
	for i, event := range events {
		if event.data["type"] != event.name {
			t.Errorf("event %d: its field %q is not its type %v", i, event.name, event.data["type"])
		}
		if sequence, ok := event.data["sequence_number"].(float64); !ok || int(sequence) != i {
			t.Errorf("event %d: sequence_number %v", i, event.data["sequence_number"])
		}
		switch event.name {
		case "response.completed", "response.failed", "response.incomplete":
			terminals++
			if i != len(events)-1 {
				t.Errorf("a terminal event at %d of %d", i, len(events))
			}
			response, _ := event.data["response"].(map[string]any)
			if id, _ := response["id"].(string); !strings.HasPrefix(id, "resp_") {
				t.Errorf("a terminal response without its id: %v", response["id"])
			}
			usage, _ := response["usage"].(map[string]any)
			for _, member := range []string{"input_tokens", "output_tokens", "total_tokens"} {
				value, ok := usage[member].(float64)
				if !ok || value != float64(int64(value)) {
					t.Errorf("usage.%s is not an integer: %v", member, usage[member])
				}
			}
		case "response.output_item.added", "response.output_item.done":
			item, _ := event.data["item"].(map[string]any)
			id, _ := item["id"].(string)
			if id == "" || item["type"] == nil || item["status"] == nil {
				t.Errorf("an item without id, type and status: %v", item)
			}
			if event.name == "response.output_item.added" {
				if itemState[id] != "" {
					t.Errorf("item %s added twice", id)
				}
				itemState[id] = "added"
			} else {
				if itemState[id] != "added" {
					t.Errorf("item %s done before it was added", id)
				}
				itemState[id] = "done"
			}
		default:
			if id, ok := event.data["item_id"].(string); ok && itemState[id] != "added" {
				t.Errorf("%s for item %s outside its lifecycle (%q)", event.name, id, itemState[id])
			}
		}
	}
	if terminals != 1 {
		t.Errorf("%d terminal events", terminals)
	}
	for id, state := range itemState {
		if state != "done" && events[len(events)-1].name == "response.completed" {
			t.Errorf("item %s never done in a completed response", id)
		}
	}
}

// Golden transcripts of scripted streams: text alone; reasoning then text, its blob sealed naming the recorded node;
// two tool calls in parallel, each with its call_id; and usage on the terminal response. Each passes Open Responses'
// rules, and its items were recorded whole before their output_item.done.
func TestResponsesGoldenTranscripts(t *testing.T) {
	cases := []struct {
		name string
		turn *testGatewayTurn
	}{
		{name: "text.sse", turn: &testGatewayTurn{
			text:  []string{"Here are ", "the files."},
			usage: &InferUsage{InputTokens: 1200, OutputTokens: 4, CachedTokens: 1024},
		}},
		{name: "reasoning.sse", turn: &testGatewayTurn{
			reasoning: []string{"The person wants ", "a listing."},
			text:      []string{"Listing them now."},
			usage:     &InferUsage{InputTokens: 1200, OutputTokens: 20, ReasoningTokens: 12},
		}},
		{name: "parallel_tool_calls.sse", turn: &testGatewayTurn{
			reasoning: []string{"Two commands at once."},
			tools: []*testGatewayToolCall{
				{id: "call_1_1", name: "shell", deltas: []string{`{"command":`, `["ls"]}`}},
				{id: "call_1_2", name: "shell", deltas: []string{`{"command":["pwd"]}`}},
			},
			usage: &InferUsage{InputTokens: 1300, OutputTokens: 40, ReasoningTokens: 6},
		}},
	}
	for _, each := range cases {
		world := newTestGatewayFrontWorld(t, nil)
		world.router.script(each.turn)
		answer := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
		if answer.Code != http.StatusOK || answer.Header().Get("Content-Type") != gatewayContentTypeEventStream {
			t.Fatalf("%s: %d %s", each.name, answer.Code, answer.Body.String())
		}
		testGatewayGolden(t, "responses", each.name, answer.Body.Bytes())
		testGatewayOpenResponsesConformance(t, answer.Body.String())
		order := world.order.all()
		for i, entry := range order {
			id, done := strings.CutPrefix(entry, "frame:response.output_item.done:")
			if done && !slices.Contains(order[:i], "record:"+id) {
				t.Errorf("%s: item %s's done was written before it was recorded: %v", each.name, id, order)
			}
		}
		_, items, ends := world.recorder.snapshot()
		if len(ends) != 1 || ends[0].Outcome != GatewayRecordCompleted || ends[0].Usage == nil || ends[0].Usage.InputTokens != each.turn.usage.InputTokens {
			t.Errorf("%s: the record's end %+v", each.name, ends)
		}
		for _, item := range items {
			if bytes.Contains(item, []byte("encrypted_content")) {
				t.Errorf("%s: a recorded item holds the blob: %s", each.name, item)
			}
		}
	}
}

// A whole answer: one JSON body, the response with every item and its usage, each item recorded before it.
func TestResponsesNotStreaming(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.router.script(&testGatewayTurn{
		reasoning: []string{"Short."},
		text:      []string{"Done."},
		tools:     []*testGatewayToolCall{{id: "call_9", name: "shell", deltas: []string{`{"command":["ls"]}`}}},
		usage:     &InferUsage{InputTokens: 10, OutputTokens: 5},
	})
	answer := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(false), nil)
	if answer.Code != http.StatusOK || answer.Header().Get("Content-Type") != gatewayContentTypeJson {
		t.Fatalf("%d %s", answer.Code, answer.Body.String())
	}
	testGatewayGolden(t, "responses", "not_streaming.json", answer.Body.Bytes())
	response := map[string]any{}
	if err := json.Unmarshal(answer.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	output, _ := response["output"].([]any)
	if response["status"] != "completed" || len(output) != 3 {
		t.Errorf("the whole answer: %v", response)
	}
	if _, items, _ := world.recorder.snapshot(); len(items) != 3 {
		t.Errorf("%d items recorded", len(items))
	}
}

// A model that fails after its output began ends the stream with response.failed, whose code Codex does not retry, the
// items completed before it whole in its output; the record ends failed. One that fails as its first event is answered
// in its API's status, 503 tee_unverified naming the model, nothing streamed.
func TestTerminalEventAfterUpstreamFailure(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.router.script(&testGatewayTurn{
		reasoning: []string{"Thinking."},
		text:      []string{"Partial ", "answer"},
		fail:      &InferError{Code: InferErrorEngineFailed, Message: "the provider's stream broke"},
		failAfter: 2,
	})
	answer := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	events := testGatewayEvents(t, answer.Body.String())
	last := events[len(events)-1]
	if last.name != "response.failed" {
		t.Fatalf("the stream ends with %s", last.name)
	}
	testGatewayOpenResponsesConformance(t, answer.Body.String())
	response, _ := last.data["response"].(map[string]any)
	failure, _ := response["error"].(map[string]any)
	if failure["code"] != gatewayErrorCodeNotRetried || !strings.Contains(failure["message"].(string), "the provider's stream broke") {
		t.Errorf("the failure: %v", failure)
	}
	if output, _ := response["output"].([]any); len(output) != 1 {
		t.Errorf("the failed response's output: %v", output)
	}
	if _, _, ends := world.recorder.snapshot(); len(ends) != 1 || ends[0].Outcome != GatewayRecordFailed {
		t.Errorf("the record's end: %+v", ends)
	}

	world.router.script(&testGatewayTurn{first: &InferError{Code: InferErrorTeeUnverified, Model: "chutes-kimi-k3-tee-high", Message: "no instance verified"}})
	first := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	if first.Code != http.StatusServiceUnavailable || !strings.Contains(first.Body.String(), `"code":"tee_unverified"`) ||
		!strings.Contains(first.Body.String(), "chutes-kimi-k3-tee-high") {
		t.Errorf("a first-event failure: %d %s", first.Code, first.Body.String())
	}
}

// A paused stream carries `: ping` every KeepaliveInterval on the gateway's clock, and none before its head; the
// stream then goes on and ends. The test reads the frames written and the waits armed in the order they happened, so
// it moves the clock only once the follower's own wait is armed.
func TestKeepaliveEveryFifteenSeconds(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	turn := &testGatewayTurn{
		text:       []string{"before ", "after"},
		stallAfter: 1,
		release:    make(chan struct{}),
		stalled:    make(chan struct{}),
	}
	world.router.script(turn)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	}()
	interval := world.settings.KeepaliveInterval
	if interval != 15*time.Second {
		t.Fatalf("the keepalive is %s", interval)
	}
	await := func(what string, match func(written string) bool) {
		t.Helper()
		guard := time.After(testGatewayWait)
		for {
			select {
			case written := <-world.written:
				if match(written) {
					return
				}
			case <-guard:
				t.Fatalf("never %s", what)
			}
		}
	}
	armed := fmt.Sprintf("armed:%s", interval)
	await("streamed the first delta", func(written string) bool { return strings.Contains(written, `"delta":"before "`) })
	for range 2 {
		await("armed the keepalive", func(written string) bool { return written == armed })
		world.clock.advance(interval)
		await("pinged", func(written string) bool { return written == gatewaySseKeepaliveComment })
	}
	close(turn.release)
	var answer *httptest.ResponseRecorder
	select {
	case answer = <-done:
	case <-time.After(testGatewayWait):
		t.Fatal("the stream never ended")
	}
	if strings.Count(answer.Body.String(), ": ping\n\n") != 2 || !strings.Contains(answer.Body.String(), "event: response.completed") {
		t.Errorf("the stream: %s", answer.Body.String())
	}
	testGatewayOpenResponsesConformance(t, answer.Body.String())
}

// What needs stored state is refused 400 unsupported_parameter, naming the member, before anything is recorded or
// sent: store true, previous_response_id, conversation, background, a stored prompt, an item_reference.
func TestStoreTrueRefused(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	for _, each := range []struct {
		body  string
		param string
	}{
		{body: strings.Replace(testGatewayCodexBody(true), `"store":false`, `"store":true`, 1), param: "store"},
		{body: testGatewayCodexBody(true, `"previous_response_id":"resp_synthetic"`), param: "previous_response_id"},
		{body: testGatewayCodexBody(true, `"conversation":"conv_synthetic"`), param: "conversation"},
		{body: testGatewayCodexBody(true, `"background":true`), param: "background"},
		{body: testGatewayCodexBody(true, `"prompt":{"id":"pmpt_synthetic"}`), param: "prompt"},
		{body: `{"model":"chutes-kimi-k3-tee-high","input":[{"type":"item_reference","id":"msg_synthetic"}]}`, param: "input[0]"},
	} {
		answer := world.serve(gatewayResponsesFront{}, each.body, nil)
		decoded := &struct {
			Error struct {
				Type  string `json:"type"`
				Code  string `json:"code"`
				Param string `json:"param"`
			} `json:"error"`
		}{}
		json.Unmarshal(answer.Body.Bytes(), decoded)
		if answer.Code != http.StatusBadRequest || decoded.Error.Code != GatewayErrorCodeUnsupportedParameter ||
			decoded.Error.Param != each.param || decoded.Error.Type != gatewayErrorTypeInvalidRequest {
			t.Errorf("%s: %d %s", each.param, answer.Code, answer.Body.String())
		}
	}
	if begins, _, _ := world.recorder.snapshot(); len(begins) != 0 || len(world.router.inferred()) != 0 {
		t.Error("a refused request was recorded or sent")
	}
}

// Members, items and parts the gateway does not know are accepted and ignored: the router receives the request it
// would without them.
func TestUnknownFieldsIgnored(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.router.script(&testGatewayTurn{text: []string{"one"}}, &testGatewayTurn{text: []string{"two"}})
	plain := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	unknown := testGatewayCodexBody(true,
		`"access_programs":["synthetic"]`, `"request_country":"ZZ"`, `"client_metadata":{"x":1}`,
		`"prompt_cache_options":{"retention":"24h"}`, `"stream_options":{"include_obfuscation":false}`,
		`"service_tier":"auto"`, `"metadata":{"k":"v"}`, `"safety_identifier":"synthetic"`)
	unknown = strings.Replace(unknown,
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"list the files"}]}`,
		`{"type":"message","role":"user","id":"msg_harness_own","status":"completed","content":[{"type":"input_text","text":"list the files","x_unknown":true},{"type":"x_future_part","text":"ignored"}]},`+
			`{"type":"compaction","encrypted_content":"opaque"},{"type":"x_future_item","payload":1}`, 1)
	answer := world.serve(gatewayResponsesFront{}, unknown, nil)
	if plain.Code != http.StatusOK || answer.Code != http.StatusOK {
		t.Fatalf("%d %d %s", plain.Code, answer.Code, answer.Body.String())
	}
	requests := world.router.inferred()
	if len(requests) != 2 {
		t.Fatalf("%d requests", len(requests))
	}
	strip := func(request *InferRequest) []byte {
		copied := *request
		copied.RunId, copied.AgentId, copied.Binding, copied.Budget = nil, nil, nil, nil
		encoded, _ := json.Marshal(&copied)
		return encoded
	}
	if !bytes.Equal(strip(requests[0]), strip(requests[1])) {
		t.Errorf("unknown members changed the request:\n%s\n%s", strip(requests[0]), strip(requests[1]))
	}
}

// A call the router refuses for an unacknowledged disclosure, a model labeled none, answers 403 disclosure_required
// naming the disclosure, its summary line and the fix, before any provider is called: the router's own checks, its
// remote paths fakes that saw no request, and nothing recorded.
func TestDisclosureRequiredBeforeAnyProvider(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	checkWorld := newTestInferCheckWorld(t, nil)
	world.front.router = checkWorld.router
	disclosures := newTestDisclosureAckWorld(t)
	world.caller.Network = &testGatewayDisclosureNetwork{testGatewayFrontNetwork: world.front, check: disclosures.check}
	body := strings.Replace(testGatewayCodexBody(true), "chutes-kimi-k3-tee-high", "engy-glm-5.2-high", 1)
	answer := world.serve(gatewayResponsesFront{}, body, nil)
	decoded := &struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{}
	json.Unmarshal(answer.Body.Bytes(), decoded)
	if answer.Code != http.StatusForbidden || decoded.Error.Code != string(InferErrorDisclosureRequired) {
		t.Fatalf("%d %s", answer.Code, answer.Body.String())
	}
	summary, _ := disclosures.registry.Line("inference:engy", "")
	if summary == "" || !strings.Contains(decoded.Error.Message, summary) || !strings.Contains(decoded.Error.Message, "inference:engy") ||
		!strings.Contains(decoded.Error.Message, "ur disclosures ack inference:engy") {
		t.Errorf("the message names not the id, its summary %q and the fix: %s", summary, decoded.Error.Message)
	}
	if checkWorld.dispatched() != 0 {
		t.Error("a provider saw the call")
	}
	if begins, _, _ := world.recorder.snapshot(); len(begins) != 0 {
		t.Error("a refused call was recorded")
	}

	// without the summary's source the router's own words still name the id and the fix
	world.caller.Network = world.front
	again := world.serve(gatewayResponsesFront{}, body, nil)
	if again.Code != http.StatusForbidden || !strings.Contains(again.Body.String(), "ur disclosures ack inference:engy") {
		t.Errorf("%d %s", again.Code, again.Body.String())
	}
}

// An empty balance is 429 insufficient_quota, as OpenAI words it, both as a refusal and, once a stream began, as the
// terminal's code, which Codex does not retry; Messages' words are a 402 billing_error.
func TestInsufficientQuotaShape(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.router.checkRefusal = &InferError{Code: InferErrorInsufficientQuota, Reason: InferQuotaReasonBalance, Message: "the network cannot pay"}
	answer := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	if answer.Code != http.StatusTooManyRequests ||
		!strings.Contains(answer.Body.String(), `"type":"insufficient_quota"`) || !strings.Contains(answer.Body.String(), `"code":"insufficient_quota"`) {
		t.Errorf("%d %s", answer.Code, answer.Body.String())
	}
	world.router.checkRefusal = nil
	world.router.script(&testGatewayTurn{
		text:      []string{"partial"},
		fail:      &InferError{Code: InferErrorInsufficientQuota, Reason: InferQuotaReasonBalance, Message: "the hold could not be extended"},
		failAfter: 1,
	})
	streamed := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	if !strings.Contains(streamed.Body.String(), `"code":"insufficient_quota"`) {
		t.Errorf("the stream's terminal: %s", streamed.Body.String())
	}
	messages := gatewayErrorOfInfer(context.Background(), &InferError{Code: InferErrorInsufficientQuota, Reason: InferQuotaReasonBalance, Message: "empty"}, nil, time.Time{})
	if messages.Status != http.StatusTooManyRequests || !strings.Contains(string(messages.body(SessionGatewayApiMessages)), `"type":"billing_error"`) {
		t.Errorf("Messages' words: %s", messages.body(SessionGatewayApiMessages))
	}
}

// A hosted tool, anything but a function tool, never reaches a model: hosted search is SRCH's filter's to drop and
// count in its notice, and an MCP server, a custom freeform apply_patch, file search and a computer are dropped here.
func TestHostedToolDropped(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.router.script(&testGatewayTurn{text: []string{"ok"}})
	body := strings.Replace(testGatewayCodexBody(true), `"tools":[`,
		`"tools":[{"type":"web_search","external_web_access":false},{"type":"mcp","server_label":"x","server_url":"https://mcp.example/"},`+
			`{"type":"custom","name":"apply_patch","format":{"type":"grammar","syntax":"lark","definition":"start: x"}},`+
			`{"type":"file_search","vector_store_ids":["vs_synthetic"]},{"type":"computer_use_preview","display_width":1,"display_height":1,"environment":"browser"},`, 1)
	answer := world.serve(gatewayResponsesFront{}, body, nil)
	if answer.Code != http.StatusOK {
		t.Fatalf("%d %s", answer.Code, answer.Body.String())
	}
	requests := world.router.inferred()
	if len(requests) != 1 || len(requests[0].Tools) != 1 || requests[0].Tools[0].Name != "shell" {
		t.Errorf("the model was offered %+v", requests[0].Tools)
	}
	if warnings := world.fronts.Status().HostedSearchWarnings; len(warnings) != 1 || !strings.Contains(warnings[0], "codex") {
		t.Errorf("hosted search's notice: %v", warnings)
	}
	begins, _, _ := world.recorder.snapshot()
	if len(begins) != 1 || bytes.Contains(begins[0].Body, []byte(`"web_search"`)) {
		t.Errorf("the recorded body holds hosted search: %s", begins[0].Body)
	}
}

// With no recorder every call is refused 503 and nothing is sent (IC-19); a Begin that fails refuses the call too, and
// an item that cannot be recorded ends the call before it is sent.
func TestCallRefusedWhenNotRecorded(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.fronts.SetRecorder(nil)
	answer := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	if answer.Code != http.StatusServiceUnavailable || !strings.Contains(answer.Body.String(), GatewayErrorCodeRecordUnavailable) {
		t.Errorf("no recorder: %d %s", answer.Code, answer.Body.String())
	}
	world.fronts.SetRecorder(world.recorder)
	world.recorder.beginErr = errors.New("the journal is full")
	answer = world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	if answer.Code != http.StatusServiceUnavailable || len(world.router.inferred()) != 0 {
		t.Errorf("a failed Begin: %d %s", answer.Code, answer.Body.String())
	}
	world.recorder.beginErr = nil
	world.recorder.itemErr = errors.New("the journal is full")
	world.router.script(&testGatewayTurn{text: []string{"never ", "sent"}, tools: []*testGatewayToolCall{{id: "call_x", name: "shell", deltas: []string{`{}`}}}})
	answer = world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	if strings.Contains(answer.Body.String(), "response.output_item.done") || !strings.Contains(answer.Body.String(), "response.failed") {
		t.Errorf("an unrecorded item was sent: %s", answer.Body.String())
	}
}

// A grant with a model list admits only the canonical names its globs match; an alias resolves first.
func TestModelOutsideGrantRefused(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.caller.Grant.Models = []string{"engy-*"}
	answer := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	if answer.Code != http.StatusForbidden || !strings.Contains(answer.Body.String(), GatewayErrorCodeModelNotInGrant) {
		t.Errorf("%d %s", answer.Code, answer.Body.String())
	}
	world.caller.Grant.Models = []string{"chutes-*-tee-*"}
	world.router.script(&testGatewayTurn{text: []string{"ok"}})
	alias := strings.Replace(testGatewayCodexBody(true), "chutes-kimi-k3-tee-high", "chutes-kimi-k3-tee", 1)
	if answer := world.serve(gatewayResponsesFront{}, alias, nil); answer.Code != http.StatusOK {
		t.Errorf("an alias the grant allows: %d %s", answer.Code, answer.Body.String())
	}
}

// A call no binder can bind is refused before anything is sent; the call that binds carries its run, agent, the
// grant as its budget and the binding the router checks; the harness's session header names its session.
func TestCallBindsBeforeTheRouter(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.server.SetRunBinder(nil)
	if answer := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil); answer.Code != http.StatusServiceUnavailable {
		t.Errorf("unbound: %d %s", answer.Code, answer.Body.String())
	}
	world.server.SetRunBinder(world.binder)
	world.router.script(&testGatewayTurn{text: []string{"ok"}})
	if answer := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), map[string]string{"session-id": "synthetic-session"}); answer.Code != http.StatusOK {
		t.Fatalf("%d %s", answer.Code, answer.Body.String())
	}
	request := world.router.inferred()[0]
	if request.RunId == nil || *request.RunId != world.binder.runId || request.AgentId == nil || *request.AgentId != world.grant.AgentId ||
		request.Binding == nil || request.Binding.Handle != world.handle.Key() || request.Budget == nil ||
		request.Budget.Kind != InferBudgetGrant || request.Budget.Id != world.grant.GrantId {
		t.Errorf("the request: %+v", request)
	}
}

// Through the listener: the route answers only with the grant's token, and a stream ends in response.completed.
func TestResponsesThroughTheListener(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.router.script(&testGatewayTurn{text: []string{"over the wire"}, usage: &InferUsage{InputTokens: 3, OutputTokens: 3}})
	status := world.server.Status()
	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(status.Port)) + "/v1/responses"
	post := func(token string) (int, string) {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(testGatewayCodexBody(true)))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := (&http.Transport{Proxy: nil}).RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}
	if code, _ := post(""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	code, body := post(world.token)
	if code != http.StatusOK || !strings.HasSuffix(body, "\n\n") || !strings.Contains(body, "event: response.completed") {
		t.Errorf("%d %s", code, body)
	}
	testGatewayOpenResponsesConformance(t, body)
}

// A drain refuses new calls 503 and waits for the calls running, which end whole.
func TestPlannedRestartRefusesNewCalls(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	turn := &testGatewayTurn{text: []string{"held"}, stallAfter: 1, release: make(chan struct{}), stalled: make(chan struct{})}
	world.router.script(turn)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	}()
	select {
	case <-turn.stalled:
	case <-time.After(testGatewayWait):
		t.Fatal("never stalled")
	}
	drained := make(chan int, 1)
	go func() {
		drained <- world.fronts.Drain(context.Background())
	}()
	world.clock.awaitArmed(t, world.settings.PlannedRestartWait)
	refused := world.serve(gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	if refused.Code != http.StatusServiceUnavailable || refused.Header().Get("Retry-After") == "" {
		t.Errorf("a call during the drain: %d %s", refused.Code, refused.Body.String())
	}
	close(turn.release)
	select {
	case running := <-drained:
		if running != 0 {
			t.Errorf("%d calls still ran", running)
		}
	case <-time.After(testGatewayWait):
		t.Fatal("the drain never ended")
	}
	if answer := <-done; !strings.Contains(answer.Body.String(), "event: response.completed") {
		t.Errorf("the call in flight: %s", answer.Body.String())
	}
}

// The answer's members never carry a byte of the token, and the error shapes hold no HTML escapes.
func TestGatewayErrorShapes(t *testing.T) {
	refusal := gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "model", "a <synthetic> & value")
	openai := string(refusal.body(SessionGatewayApiResponses))
	if openai != `{"error":{"code":"invalid_value","message":"a <synthetic> & value","param":"model","type":"invalid_request_error"}}` {
		t.Errorf("OpenAI's shape: %s", openai)
	}
	anthropic := string(refusal.body(SessionGatewayApiMessages))
	if anthropic != `{"error":{"message":"invalid_value: a <synthetic> & value","type":"invalid_request_error"},"type":"error"}` {
		t.Errorf("Anthropic's shape: %s", anthropic)
	}
	overflow := gatewayErrorOfInfer(context.Background(), &InferError{Code: InferErrorContextLength, Message: "too long"}, nil, time.Time{})
	if overflow.Code != GatewayErrorCodeContextLength || overflow.streamCode(true) != GatewayErrorCodeContextLength {
		t.Errorf("overflow: %+v", overflow)
	}
	if gatewayMessagesOverflow(210000, 200000) != "prompt is too long: 210000 tokens > 200000 maximum" {
		t.Error("Messages' overflow words")
	}
	if fmt.Sprint(gatewayUnescapeHtml([]byte(`"\\u003c\u003c"`))) != fmt.Sprint([]byte(`"\\u003c<"`)) {
		t.Error("a literal backslash-u was undone")
	}
}
