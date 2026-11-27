//go:build !ios_extension && !sidecar_http && !js

package sidecar

// web_search, the Harness's tool (SRCH-M13-10): the policy, the network's switch, modes and compute:search, the
// search:parallel disclosure attended and not, the limits, the result as the model, the UI and the record take it, the
// run's taint, and the tool's absence without a search line. The searcher here is a fake: the client's own tests run
// it on the fake gateway (websearch_client_test.go).

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A searcher that answers a fixed answer, recording each query.
type testWebSearchSearcher struct {
	stateLock sync.Mutex
	queries   []*WebSearchQuery
	answer    *WebSearchAnswer
	err       error
	payments  []*WebSearchPayment
}

func (self *testWebSearchSearcher) Search(ctx context.Context, query *WebSearchQuery) (*WebSearchAnswer, error) {
	self.stateLock.Lock()
	self.queries = append(self.queries, query)
	answer, err := self.answer, self.err
	self.stateLock.Unlock()
	if err != nil {
		return nil, err
	}
	if query.BeforePay != nil {
		payment := &WebSearchPayment{RequestId: make([]byte, 16), Attempt: 1, Nonce: answer.Nonce, MinuteS: answer.MinuteS}
		if err := query.BeforePay(payment); err != nil {
			return nil, err
		}
		self.stateLock.Lock()
		self.payments = append(self.payments, payment)
		self.stateLock.Unlock()
	}
	return answer, nil
}

func (self *testWebSearchSearcher) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.queries)
}

// A policy that offers a line or not.
type testWebSearchToolPolicy struct {
	offered bool
}

func (self *testWebSearchToolPolicy) Line(ctx context.Context) (*WebSearchPolicyLine, error) {
	if !self.offered {
		return nil, webSearchRefusal(WebSearchCodeSearchOff, nil, "the signed policy carries no search line")
	}
	return &WebSearchPolicyLine{Host: "parallelmpp.example"}, nil
}

func (self *testWebSearchToolPolicy) Price(ctx context.Context, engine string, mode string) (*WebSearchPrice, error) {
	return &WebSearchPrice{CatalogVersion: 1, NanoUsdPerSearch: 12_000_000}, nil
}

func (self *testWebSearchToolPolicy) RefreshCatalog(ctx context.Context) error {
	return nil
}

func (self *testWebSearchToolPolicy) Offered() bool {
	return self.offered
}

// The network's policy: search on, every mode, compute:search held, unless set.
type testWebSearchNetwork struct {
	search *ComputeSearchPolicy
	unread bool
	denied bool
}

func (self *testWebSearchNetwork) Search(ctx context.Context) (*ComputeSearchPolicy, error) {
	if self.unread {
		return nil, ErrComputePolicyUnread
	}
	if self.search == nil {
		return &ComputeSearchPolicy{Enabled: true}, nil
	}
	return self.search, nil
}

func (self *testWebSearchNetwork) MayQuery(ctx context.Context) (bool, error) {
	return !self.denied, nil
}

// search:parallel's state: acknowledged at a version, the current one, and whose scope covers the sidecar.
type testWebSearchDisclosures struct {
	stateLock    sync.Mutex
	version      uint32
	acknowledged uint32
	scope        ComputeDisclosureScope
}

func (self *testWebSearchDisclosures) Check(ctx context.Context, id string) (*ComputeDisclosureVerdict, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	scope := self.scope
	if scope == "" {
		scope = ComputeDisclosureScopePerson
	}
	covered := self.version <= self.acknowledged
	return &ComputeDisclosureVerdict{Id: id, Version: self.version, Asks: true, Scope: scope, Acknowledged: self.acknowledged,
		Covered: covered, Askable: !covered && scope == ComputeDisclosureScopePerson}, nil
}

func (self *testWebSearchDisclosures) Line(id string, locale string) (string, error) {
	return "Parallel reads this search and may train on it; URnetwork does not see it", nil
}

func (self *testWebSearchDisclosures) ack(version uint32) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.acknowledged = version
}

// A fetch list that lists what it was given.
type testWebSearchRunUrls struct {
	stateLock sync.Mutex
	urls      map[string]bool
	hosts     map[string]bool
	added     [][]string
}

func (self *testWebSearchRunUrls) UrlListed(runId Id, rawUrl string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.urls[rawUrl]
}

func (self *testWebSearchRunUrls) HostListed(runId Id, host string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.hosts[host]
}

func (self *testWebSearchRunUrls) AddSearchResults(runId Id, urls []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.added = append(self.added, urls)
}

// The answer a fake search gives: two results in Parallel's shape.
func testWebSearchToolAnswer() *WebSearchAnswer {
	answer := &WebSearchAnswer{
		Results: []*WebSearchResult{
			{Url: "https://one.search.example/a", Title: "One", PublishDate: "2026-01-02", Excerpts: []string{"first excerpt"}},
			{Url: "https://two.search.example/b", Title: "Two", Excerpts: []string{"second excerpt", "more"}},
		},
		Warnings:     []string{"a synthetic warning"},
		Nonce:        make([]byte, 32),
		MinuteS:      1767225600,
		Transaction:  make([]byte, 32),
		Amount:       10000,
		PriceNanoUsd: 12_000_000,
		Mode:         WebSearchModeFast,
	}
	answer.AnswerSha256[0] = 0xaa
	return answer
}

// The tool's world: a run, a call on it, and the fakes.
type testWebSearchToolWorld struct {
	t           *testing.T
	clock       *recordTestClock
	run         *HarnessRun
	runs        *RunStore
	searcher    *testWebSearchSearcher
	policy      *testWebSearchToolPolicy
	network     *testWebSearchNetwork
	disclosures *testWebSearchDisclosures
	runUrls     *testWebSearchRunUrls
	tool        *WebSearchTool
	// the person's view, nil for none; its answers to each request
	attached bool
	asked    []*HarnessUiRequest
	answer   func(request *HarnessUiRequest) (*HarnessUiResponse, error)
	updates  []*HarnessToolUpdate
}

func newTestWebSearchToolWorld(t *testing.T) *testWebSearchToolWorld {
	t.Helper()
	_, runs, clock := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	world := &testWebSearchToolWorld{
		t:           t,
		clock:       clock,
		runs:        runs,
		run:         newHarnessTestRun(t, runs, nil),
		searcher:    &testWebSearchSearcher{answer: testWebSearchToolAnswer()},
		policy:      &testWebSearchToolPolicy{offered: true},
		network:     &testWebSearchNetwork{},
		disclosures: &testWebSearchDisclosures{version: 1, acknowledged: 1},
		runUrls:     &testWebSearchRunUrls{urls: map[string]bool{}, hosts: map[string]bool{}},
	}
	tool, err := NewWebSearchTool(&WebSearchToolArgs{
		Searcher:    world.searcher,
		Policy:      world.policy,
		Network:     world.network,
		Disclosures: world.disclosures,
		RunUrls:     world.runUrls,
		Clock:       clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	world.tool = tool
	return world
}

// A call on the world's run, its person attached or not.
func (self *testWebSearchToolWorld) call() *HarnessCall {
	return NewHarnessCall(&HarnessCallArgs{
		Run:        self.run,
		Profile:    HarnessProfileLocal,
		ToolCallId: "call-1",
		ToolName:   WebSearchToolName,
		Ask: func(ctx context.Context, request *HarnessUiRequest) (*HarnessUiResponse, error) {
			if !self.attached {
				if request.Method == HarnessUiDisclosure {
					return nil, harnessDisclosureRequired(request, InferDisclosureReasonUnacknowledged, "no person is attached to the run")
				}
				return nil, ErrHarnessUiUnattached
			}
			self.asked = append(self.asked, request)
			return self.answer(request)
		},
		Attached: func() bool {
			return self.attached
		},
	})
}

// One call through the Harness's own path (harnessRunToolCall): the tier, Execute, and the taint before the result.
func (self *testWebSearchToolWorld) execute(args string) (*harnessToolCallResult, error) {
	spec := &HarnessToolSpec{Name: WebSearchToolName, Profiles: []HarnessProfile{HarnessProfileLocal}, BuiltIn: true,
		New: func(*Harness) (HarnessTool, error) { return self.tool, nil }}
	return harnessRunToolCall(context.Background(), self.call(), spec, self.tool, []byte(args), func(update *HarnessToolUpdate) {
		self.updates = append(self.updates, update)
	})
}

const testWebSearchToolArgs = `{"objective":"synthetic objective","queries":["synthetic keyword query"]}`

// A person attached to the run is asked search:parallel's disclosure by id and version alone, and the search goes once
// CTRUST holds their acknowledgment; "Not now" fails the call alone, and a view's answer that is no acknowledgment
// acknowledges nothing.
func TestWebSearchToolDisclosureAttached(t *testing.T) {
	world := newTestWebSearchToolWorld(t)
	world.disclosures.acknowledged = 0
	world.attached = true
	world.answer = func(request *HarnessUiRequest) (*HarnessUiResponse, error) {
		// the broker sets Acknowledged only once CTRUST's store holds the person's own act
		world.disclosures.ack(request.DisclosureVersion)
		return &HarnessUiResponse{Id: request.Id, Acknowledged: true}, nil
	}
	if _, err := world.execute(testWebSearchToolArgs); err != nil {
		t.Fatal(err)
	}
	if len(world.asked) != 1 || world.asked[0].Method != HarnessUiDisclosure || world.asked[0].DisclosureId != "search:parallel" ||
		world.asked[0].DisclosureVersion != 1 || world.asked[0].Title != "" || world.asked[0].Message != "" {
		t.Fatalf("asked %+v", world.asked)
	}
	if world.searcher.count() != 1 {
		t.Fatal("the acknowledged search did not go")
	}

	// Not now: the call fails, naming the disclosure, and nothing is searched
	world = newTestWebSearchToolWorld(t)
	world.disclosures.acknowledged = 0
	world.attached = true
	world.answer = func(request *HarnessUiRequest) (*HarnessUiResponse, error) {
		return nil, harnessDisclosureRequired(request, InferDisclosureReasonDeclined, "the person declined")
	}
	_, err := world.execute(testWebSearchToolArgs)
	if InferErrorCodeOf(err) != InferErrorDisclosureRequired || world.searcher.count() != 0 {
		t.Fatalf("Not now: %v", err)
	}
	if world.run.Tainted() {
		t.Fatal("a declined call tainted its run")
	}

	// a view's answer that is no acknowledgment
	world = newTestWebSearchToolWorld(t)
	world.disclosures.acknowledged = 0
	world.attached = true
	world.answer = func(request *HarnessUiRequest) (*HarnessUiResponse, error) {
		understood := "I understand"
		return &HarnessUiResponse{Id: request.Id, Value: &understood}, nil
	}
	if _, err := world.execute(testWebSearchToolArgs); !errors.Is(err, ErrDisclosureRequired) || world.searcher.count() != 0 {
		t.Fatalf("a ui_response acknowledged: %v", err)
	}
}

// A run no person is attached to gets disclosure_required at once, naming search:parallel, its summary and the fix,
// and nothing is searched; a tagged or cloud sidecar's network scope is never asked; a new version past its grace asks
// again.
func TestWebSearchToolDisclosureUnattended(t *testing.T) {
	world := newTestWebSearchToolWorld(t)
	world.disclosures.acknowledged = 0
	_, err := world.execute(testWebSearchToolArgs)
	var required *DisclosureRequiredError
	if !errors.As(err, &required) || required.Id != "search:parallel" || required.Version != 1 ||
		!strings.Contains(required.Summary, "Parallel reads this search") || required.Fix() == "" {
		t.Fatalf("unattended: %v", err)
	}
	if world.searcher.count() != 0 || len(world.asked) != 0 {
		t.Fatal("an unattended run searched or asked")
	}
	// a tagged sidecar: the network's acknowledgment, never asked of a person even with one watching
	world = newTestWebSearchToolWorld(t)
	world.disclosures.acknowledged = 0
	world.disclosures.scope = ComputeDisclosureScopeNetwork
	world.attached = true
	if _, err := world.execute(testWebSearchToolArgs); !errors.Is(err, ErrDisclosureRequired) || len(world.asked) != 0 {
		t.Fatalf("a tagged sidecar: %v, asked %d", err, len(world.asked))
	}
	// version 2 past its grace: covered no more, asked again
	world = newTestWebSearchToolWorld(t)
	world.disclosures.version = 2
	world.attached = true
	world.answer = func(request *HarnessUiRequest) (*HarnessUiResponse, error) {
		world.disclosures.ack(request.DisclosureVersion)
		return &HarnessUiResponse{Id: request.Id, Acknowledged: true}, nil
	}
	if _, err := world.execute(testWebSearchToolArgs); err != nil || len(world.asked) != 1 || world.asked[0].DisclosureVersion != 2 {
		t.Fatalf("a new version: %v, asked %+v", err, world.asked)
	}
}

// The result reaches the model untrusted, so the run taints before it returns, through the Harness's own path.
func TestWebSearchToolTaints(t *testing.T) {
	world := newTestWebSearchToolWorld(t)
	ran, err := world.execute(testWebSearchToolArgs)
	if err != nil {
		t.Fatal(err)
	}
	if ran.result.Trust != HarnessToolUntrusted || !world.run.Tainted() {
		t.Fatal("the run read untrusted results and is not tainted")
	}
	if !slices.Contains(world.runs.TaintReasons(world.run.Id()), RunTaintUntrustedData) {
		t.Fatalf("taint reasons %v", world.runs.TaintReasons(world.run.Id()))
	}
}

// The record keeps the stub and never a result: the result's details say keep: false, which a built-in's are honored
// in, and its SearchStub holds the call, the count, the answer's hash, the nonce, the transaction and the price; the
// payment's nonce and minute went out as the tool's update before the paid retry.
func TestWebSearchToolStubRecorded(t *testing.T) {
	world := newTestWebSearchToolWorld(t)
	ran, err := world.execute(testWebSearchToolArgs)
	if err != nil {
		t.Fatal(err)
	}
	if ran.keep {
		t.Fatal("the details are kept")
	}
	stub := &WebSearchStub{}
	if err := json.Unmarshal(ran.result.SearchStub, stub); err != nil {
		t.Fatal(err)
	}
	answer := testWebSearchToolAnswer()
	if stub.Call.Objective != "synthetic objective" || !slices.Equal(stub.Call.Queries, []string{"synthetic keyword query"}) ||
		stub.Call.Mode != "fast" || stub.Results != 2 || stub.AnswerSha256[:2] != "aa" || len(stub.Nonce) != 64 ||
		len(stub.Transaction) != 64 || stub.PriceNanoUsd != 12_000_000 || stub.Text != "[web_search: 2 results; not kept]" {
		t.Fatalf("the stub %+v", stub)
	}
	for _, result := range answer.Results {
		for _, kept := range []string{result.Title, result.Excerpts[0]} {
			if strings.Contains(string(ran.result.SearchStub), kept) {
				t.Fatalf("the stub holds %q", kept)
			}
		}
	}
	// the journal's form: a built-in's keep: false keeps the stub alone (§24.9)
	redactor, err := NewRedactor(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	value, counts, err := sessionApplyExceptions(map[string]any{"message": map[string]any{"role": "toolResult",
		"toolCallId": "call-1", "content": []any{map[string]any{"type": "text", "text": ran.result.Text}},
		"details": json.RawMessage(ran.result.Details)}},
		&SessionToolResult{Name: WebSearchToolName, BuiltIn: true, KeepFalse: !ran.keep, SearchStub: ran.result.SearchStub}, redactor)
	if err != nil {
		t.Fatal(err)
	}
	journaled, _ := json.Marshal(value)
	if counts.stubs != 1 || strings.Contains(string(journaled), "first excerpt") || !strings.Contains(string(journaled), `"answer_sha256"`) {
		t.Fatalf("the journal kept %s", journaled)
	}
	if len(world.updates) != 1 || !strings.Contains(string(world.updates[0].Details), `"kind":"web_search_payment"`) ||
		!strings.Contains(string(world.updates[0].Details), `"minute_s":1767225600`) {
		t.Fatalf("updates %+v", world.updates)
	}
}

// 50 searches a run, then limit; 30 a minute an agent across its runs, then limit until the window passes.
func TestWebSearchToolLimits(t *testing.T) {
	world := newTestWebSearchToolWorld(t)
	settings := DefaultWebSearchSettings()
	for i := range settings.AgentSearchMaxCount {
		if _, err := world.execute(testWebSearchToolArgs); err != nil {
			t.Fatalf("search %d: %v", i, err)
		}
	}
	_, err := world.execute(testWebSearchToolArgs)
	var refusal *WebSearchError
	if !errors.As(err, &refusal) || refusal.Code != WebSearchCodeLimit || refusal.RetryAfter != settings.AgentSearchWindow {
		t.Fatalf("the agent's 31st in a minute: %v", err)
	}
	world.clock.advance(settings.AgentSearchWindow)
	for i := settings.AgentSearchMaxCount; i < settings.RunSearchMaxCount; i += 1 {
		if _, err := world.execute(testWebSearchToolArgs); err != nil {
			t.Fatalf("search %d: %v", i, err)
		}
	}
	world.clock.advance(settings.AgentSearchWindow)
	if _, err := world.execute(testWebSearchToolArgs); WebSearchErrorCode(err) != WebSearchCodeLimit || !strings.Contains(err.Error(), "a run") {
		t.Fatalf("the run's 51st: %v", err)
	}
	if world.searcher.count() != settings.RunSearchMaxCount {
		t.Fatalf("%d searches", world.searcher.count())
	}
	// another run of the same agent starts its own count
	other := newHarnessTestRun(t, world.runs, &HarnessRunArgs{AgentId: world.run.AgentId()})
	world.run = other
	if _, err := world.execute(testWebSearchToolArgs); err != nil {
		t.Fatalf("another run: %v", err)
	}
}

// With no search line, or no ticket, the tool is offered to no agent: a tool set leaves it out whether the agent named
// it or took the profile's whole set; and a call that comes anyway answers search_off, nothing searched.
func TestWebSearchToolAbsentWithoutSearchLine(t *testing.T) {
	world := newTestWebSearchToolWorld(t)
	world.policy.offered = false
	settings := DefaultHarnessSettings()
	registry := &HarnessToolRegistry{nameTools: map[string]*harnessRegisteredTool{
		WebSearchToolName: {spec: &HarnessToolSpec{Name: WebSearchToolName, Profiles: []HarnessProfile{HarnessProfileLocal}, BuiltIn: true}, tool: world.tool},
	}}
	for _, named := range [][]string{nil, {WebSearchToolName}} {
		set, err := newHarnessToolSet(settings, registry, HarnessProfileLocal, named, "", 1<<30)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok := set.tool(WebSearchToolName); ok {
			t.Fatalf("offered with no search line (named %v)", named)
		}
	}
	if _, err := world.execute(testWebSearchToolArgs); WebSearchErrorCode(err) != WebSearchCodeSearchOff || world.searcher.count() != 0 {
		t.Fatalf("a call anyway: %v", err)
	}
	world.policy.offered = true
	set, err := newHarnessToolSet(settings, registry, HarnessProfileLocal, nil, "", 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := set.tool(WebSearchToolName); !ok {
		t.Fatal("not offered with a search line")
	}
}

// The network's switch, its modes and compute:search: search off and compute:search refused answer search_off, a mode
// outside the block's modes mode_refused, a head not yet read search_off; nothing searched.
func TestWebSearchToolModes(t *testing.T) {
	cases := []struct {
		name    string
		network *testWebSearchNetwork
		args    string
		code    string
	}{
		{name: "off", network: &testWebSearchNetwork{search: &ComputeSearchPolicy{Enabled: false}}, args: testWebSearchToolArgs, code: WebSearchCodeSearchOff},
		{name: "mode", network: &testWebSearchNetwork{search: &ComputeSearchPolicy{Enabled: true, Modes: []string{"fast"}}},
			args: `{"queries":["synthetic"],"mode":"advanced"}`, code: WebSearchCodeModeRefused},
		{name: "query", network: &testWebSearchNetwork{denied: true}, args: testWebSearchToolArgs, code: WebSearchCodeSearchOff},
		{name: "unread", network: &testWebSearchNetwork{unread: true}, args: testWebSearchToolArgs, code: WebSearchCodeSearchOff},
		{name: "unknown mode", network: &testWebSearchNetwork{}, args: `{"queries":["synthetic"],"mode":"news"}`, code: WebSearchCodeInvalid},
		{name: "no queries", network: &testWebSearchNetwork{}, args: `{"queries":[]}`, code: WebSearchCodeInvalid},
		{name: "long objective", network: &testWebSearchNetwork{}, args: `{"queries":["synthetic"],"objective":"` + strings.Repeat("o", 1001) + `"}`, code: WebSearchCodeInvalid},
	}
	for _, c := range cases {
		world := newTestWebSearchToolWorld(t)
		world.tool.network = c.network
		if _, err := world.execute(c.args); WebSearchErrorCode(err) != c.code {
			t.Errorf("%s: %v", c.name, err)
		}
		if world.searcher.count() != 0 {
			t.Errorf("%s: searched", c.name)
		}
	}
	// a mode the block allows goes, and the search is asked in it
	world := newTestWebSearchToolWorld(t)
	world.tool.network = &testWebSearchNetwork{search: &ComputeSearchPolicy{Enabled: true, Modes: []string{"advanced"}}}
	if _, err := world.execute(`{"queries":["synthetic"],"mode":"advanced"}`); err != nil {
		t.Fatal(err)
	}
	if world.searcher.queries[0].Mode != "advanced" {
		t.Fatalf("asked in %q", world.searcher.queries[0].Mode)
	}
}

// The results' URLs go to the run's fetch list as its latest search results; the query reached the searcher as the
// model wrote it, charged to the run's agent.
func TestWebSearchToolListsResults(t *testing.T) {
	world := newTestWebSearchToolWorld(t)
	if _, err := world.execute(testWebSearchToolArgs); err != nil {
		t.Fatal(err)
	}
	if len(world.runUrls.added) != 1 || !slices.Equal(world.runUrls.added[0], []string{"https://one.search.example/a", "https://two.search.example/b"}) {
		t.Fatalf("listed %v", world.runUrls.added)
	}
	query := world.searcher.queries[0]
	if query.Objective != "synthetic objective" || !slices.Equal(query.Queries, []string{"synthetic keyword query"}) ||
		query.AgentId == nil || *query.AgentId != world.run.AgentId() {
		t.Fatalf("the query %+v", query)
	}
}

// The description names the last price read, and the schema's limits are the settings'.
func TestWebSearchToolDescriptionAndSchema(t *testing.T) {
	world := newTestWebSearchToolWorld(t)
	if !strings.Contains(world.tool.Description(), "Each search costs the catalog's price per search") {
		t.Fatalf("before a search: %s", world.tool.Description())
	}
	if _, err := world.execute(testWebSearchToolArgs); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(world.tool.Description(), "Each search costs $0.012 from the compute balance") {
		t.Fatalf("after a search: %s", world.tool.Description())
	}
	var schema map[string]any
	if err := json.Unmarshal(world.tool.Schema(), &schema); err != nil {
		t.Fatal(err)
	}
	properties := schema["properties"].(map[string]any)
	if properties["objective"].(map[string]any)["maxLength"] != float64(1000) || properties["queries"].(map[string]any)["maxItems"] != float64(5) {
		t.Fatalf("the schema %s", world.tool.Schema())
	}
	if world.tool.Tier() != HarnessToolTierRead || world.tool.Name() != "web_search" {
		t.Fatal("the tool's tier or name")
	}
}

// Through a whole Harness run, recorded: the model calls web_search, reads the results, and the session entries keep
// SRCH's stub (the answer's hash, the nonce, the price) and never a result's text or its details.
func TestWebSearchToolStubRecordedInSession(t *testing.T) {
	toolWorld := newTestWebSearchToolWorld(t)
	router := newHarnessScriptedRouter(t, testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortHigh))
	world := newHarnessRecordTestWorld(t, router, map[string]*HarnessToolSpec{WebSearchToolName: harnessTestSpec(toolWorld.tool, true, HarnessProfileLocal)})
	router.script(harnessToolsCall([3]string{"call_s", WebSearchToolName, testWebSearchToolArgs}), harnessTextCall("found"))
	agent := world.agent(t, &HarnessAgentSpec{Name: "searcher"})
	log := harnessCollect(t, agent)
	if err := agent.Prompt(context.Background(), "search", nil); err != nil {
		t.Fatal(err)
	}
	log.until(t, HarnessEventAgentSettled)
	sessionDrafts, _ := world.record.ofKind(RecordKindSessionEntry)
	stubbed := false
	for _, draft := range sessionDrafts {
		entry := harnessRecordBody(t, draft, &protocol.SessionEntryBody{})
		item := string(entry.GetItem())
		for _, result := range []string{"first excerpt", "second excerpt", "one.search.example", "a synthetic warning"} {
			if strings.Contains(item, result) {
				t.Fatalf("a session entry keeps a result: %s", item)
			}
		}
		if strings.Contains(item, `"answer_sha256":"aa`) && strings.Contains(item, `"price_nano_usd":12000000`) {
			stubbed = true
		}
	}
	if !stubbed {
		t.Fatal("no session entry keeps the search's stub")
	}
	requests := router.made()
	if text := requests[len(requests)-1].Messages[len(requests[len(requests)-1].Messages)-1].Text(); !strings.Contains(text, "first excerpt") {
		t.Fatalf("the model read %q", text)
	}
}
