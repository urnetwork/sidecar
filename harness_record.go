//go:build !ios_extension && !sidecar_http

// Recording a Harness run (DESIGN-COMPUTE §7.7, §24.4-§24.6, §6.8, §21.6, D-HARN-3, R-HARN-8, R-CTXH-1, IC-19;
// HARN-M11-08): a Harness run is a recURd run, recorded natively, never through hooks (DESIGN §16.7's table gains its
// row, Appendix D). Two parts:
//
//	journal   harnessSessionJournal is the Harness's HarnessContextJournal over CTXH's SessionJournal and the harness-1
//	          renderer: each node the loop journals becomes a session_entry of its run (SessionNodeOfHarness), its tool
//	          result kept in the form its tool's registration gives (§24.9: a built-in's keep: false a stub, web
//	          search's among them, whose stub is SRCH's), durable before Journal returns; each request is harness-1's
//	          render of the run's path from the input node to its root, as the loop journaled it, so what is sent is
//	          what the record rebuilds wherever no redaction or stub marks a node, and the call's CallContext names
//	          its input and system nodes, harness-1, the params and the request_sha256 of the path as recorded
//	recorder  harnessRecorder writes the run's own entries beside them, observing the Harness's events in their
//	          order: a stage-1 context at the run's first prompt (harness ur-harness, its version, the agent's label,
//	          the model, the title) and a stage-2 at each model change, carrying the run's prompts (RECORD.md section
//	          4.3); each tool call a tool_call with empty input and output, its header's content a ContentRef to the
//	          session entry that holds its result and details, the action id joining them (RecordToolActionId); each
//	          model call a model_call (InferModelCall, §6.8) with its CallContext, written only after its context's
//	          nodes and its response's node are journaled; at each idle a coverage entry, source harness, and a cost
//	          entry. Prompts and titles are redacted before they seal (DESIGN §16.7); a lost record write is the run's
//	          gap, never silence
//
// On a Sidecar both are wired as Harness sources (RegisterHarnessSources), each reading the network's journal, record
// and spool at use, so a Harness built before enrollment records once the network holds them. An enclave's runs are
// its sponsor's and go to their vault as any of their devices' do, with no code here.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/urnetwork/sidecar/protocol"
)

// The record's name for the Harness, as its runs' context and coverage entries carry it.
const harnessRecordHarness = HarnessRunHarnessName

var (
	// A node the session journal cannot take: its continuation's parent, or the journal itself, is not there.
	ErrHarnessJournalUnwired = errors.New("the session journal is not available, so nothing is journaled or sent")
)

// The session journal as the Harness's journal writes through it: *SessionJournal, or a test's.
type harnessSessionStore interface {
	Journal(ctx context.Context, run *SessionRun, nodes ...*SessionNode) ([]*SessionJournaled, error)
	Node(runId Id, key string) (Id, [sha256.Size]byte, bool)
	TurnEnd(ctx context.Context, runId Id) error
}

var _ harnessSessionStore = (*SessionJournal)(nil)

// One node as the journal holds it in memory: the loop's node, and what the session journal made of it.
type harnessSessionNode struct {
	node      *HarnessJournalNode
	journaled *SessionJournaled
}

// One run's nodes, by key, and its last call's context.
type harnessSessionRun struct {
	keyNodes map[string]*harnessSessionNode
	call     *protocol.CallContext
}

// The Harness's context journal over CTXH's session journal and harness-1.
type harnessSessionJournal struct {
	store    func() (harnessSessionStore, error)
	renderer SessionRenderer
	// told of each node once it is journaled, nil for none
	recorder *harnessRecorder

	stateLock sync.Mutex
	runs      map[Id]*harnessSessionRun
}

var _ HarnessContextJournal = (*harnessSessionJournal)(nil)

// A journal over the store store answers at use, rendering with harness-1.
func newHarnessSessionJournal(store func() (harnessSessionStore, error)) *harnessSessionJournal {
	renderer, err := SessionRendererOf(SessionRendererHarness1)
	if err != nil {
		// every build holds harness-1
		panic(err)
	}
	return &harnessSessionJournal{store: store, renderer: renderer, runs: map[Id]*harnessSessionRun{}}
}

// The tool result a node holds, as the session journal keeps it: its tool's name, whether it is built in and whether
// its details said keep: false.
func harnessSessionToolOf(node *HarnessJournalNode) *SessionToolResult {
	if node.Tool == nil {
		return nil
	}
	return &SessionToolResult{Name: node.Tool.Name, BuiltIn: node.Tool.BuiltIn, KeepFalse: node.Tool.KeepFalse,
		SearchStub: node.Tool.SearchStub}
}

// The run and session node of a loop's node: SessionNodeOfHarness, or for a continuation's root, the other run's node
// it continues as the session journal keyed it.
func (self *harnessSessionJournal) sessionNodeOf(store harnessSessionStore, node *HarnessJournalNode) (*SessionRun, *SessionNode, error) {
	tool := harnessSessionToolOf(node)
	if node.ParentRunId == nil {
		return SessionNodeOfHarness(node, tool)
	}
	parentKey, ok := node.Entry.ParentId()
	if !ok {
		return nil, nil, fmt.Errorf("%w: a continuation's root names no node", ErrSessionNodeRefused)
	}
	parentNodeId, chain, ok := store.Node(*node.ParentRunId, parentKey)
	if held, adopted := self.heldNode(*node.ParentRunId, parentKey); !ok && adopted {
		// a run another device journaled, whose path a continuation took in (session_continue.go)
		parentNodeId, chain, ok = held.journaled.NodeId, held.journaled.ChainSha256, true
	}
	if !ok {
		return nil, nil, fmt.Errorf("%w: the continued run's node is not journaled here", ErrSessionNodeRefused)
	}
	// the root is the continuation's own: its parent named by the other run's node, never by its key in this run
	root := &HarnessJournalNode{RunId: node.RunId, AgentId: node.AgentId, Entry: node.Entry.Clone(), Tainted: node.Tainted,
		Marks: node.Marks, Untrusted: node.Untrusted, Sender: node.Sender, Tool: node.Tool}
	root.Entry.object.remove("parentId")
	run, sessionNode, err := SessionNodeOfHarness(root, tool)
	if err != nil {
		return nil, nil, err
	}
	parentRunId := *node.ParentRunId
	sessionNode.ParentKey = ""
	sessionNode.ParentRunId = &parentRunId
	sessionNode.ParentNodeId = &parentNodeId
	sessionNode.ParentChainSha256 = chain[:]
	return run, sessionNode, nil
}

// Journals node through the session journal, durable when it returns, and tells the recorder.
func (self *harnessSessionJournal) Journal(ctx context.Context, node *HarnessJournalNode) error {
	if node == nil || node.Entry == nil {
		return fmt.Errorf("%w: no entry", ErrSessionNodeRefused)
	}
	store, err := self.store()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHarnessJournalUnwired, err)
	}
	run, sessionNode, err := self.sessionNodeOf(store, node)
	if err != nil {
		return err
	}
	journaled, err := store.Journal(ctx, run, sessionNode)
	if err != nil {
		return err
	}
	if len(journaled) != 1 {
		return fmt.Errorf("%w: the journal answered %d nodes for one", ErrSessionNodeRefused, len(journaled))
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		sessionRun, ok := self.runs[node.RunId]
		if !ok {
			sessionRun = &harnessSessionRun{keyNodes: map[string]*harnessSessionNode{}}
			self.runs[node.RunId] = sessionRun
		}
		sessionRun.keyNodes[node.Entry.Id()] = &harnessSessionNode{node: node, journaled: journaled[0]}
	}()
	if self.recorder != nil {
		self.recorder.journaled(ctx, node, journaled[0])
	}
	return nil
}

// The node of key in run, crossing into another run this journal holds where a continuation's root names one.
func (self *harnessSessionJournal) nodeWithLock(runId Id, key string) (*harnessSessionNode, bool) {
	if sessionRun, ok := self.runs[runId]; ok {
		if node, ok := sessionRun.keyNodes[key]; ok {
			return node, true
		}
	}
	for _, sessionRun := range self.runs {
		if node, ok := sessionRun.keyNodes[key]; ok {
			return node, true
		}
	}
	return nil, false
}

// The path from the input node to its root, root first, as this journal holds it.
func (self *harnessSessionJournal) pathWithLock(runId Id, inputKey string) ([]*harnessSessionNode, error) {
	path := []*harnessSessionNode{}
	seen := map[string]bool{}
	for key := inputKey; key != ""; {
		if seen[key] {
			return nil, fmt.Errorf("%w: the session tree loops", ErrSessionRenderRefused)
		}
		seen[key] = true
		node, ok := self.nodeWithLock(runId, key)
		if !ok {
			return nil, fmt.Errorf("%w: node %s is not journaled here", ErrSessionRenderRefused, key)
		}
		path = append(path, node)
		key, _ = node.node.Entry.ParentId()
	}
	slices.Reverse(path)
	return path, nil
}

// A path's nodes as a render takes them: live, the entries as the loop journaled them, each with its trust, for the
// request sent; or as recorded, the journal's items and parts, for the request's hash.
func harnessRenderNodes(path []*harnessSessionNode, recorded bool) ([]*SessionRenderNode, error) {
	nodes := make([]*SessionRenderNode, 0, len(path))
	for _, node := range path {
		renderNode := &SessionRenderNode{NodeId: node.journaled.NodeId, Type: SessionNodeTypeOfPi(node.node.Entry.Type()),
			Untrusted: node.node.Untrusted, Sender: node.node.Sender}
		if recorded {
			renderNode.Item = node.journaled.Item
			renderNode.Parts = node.journaled.Parts
		} else {
			item, err := SessionHarnessEntryWithTrust(node.node.Entry, node.node.Untrusted, node.node.Sender).Json()
			if err != nil {
				return nil, err
			}
			renderNode.Item = item
		}
		nodes = append(nodes, renderNode)
	}
	return nodes, nil
}

// The call's params as CallContext.params holds them: its model, maxima, run, agent and budget, RFC 8785.
func harnessRenderParams(args *HarnessRenderArgs) ([]byte, error) {
	params := map[string]any{"model": args.Model, "run_id": args.RunId}
	if 0 < args.MaxOutput {
		params["max_output"] = args.MaxOutput
	}
	if args.AgentId != nil {
		params["agent_id"] = *args.AgentId
	}
	if args.Budget != nil {
		params["budget"] = args.Budget
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return CanonicalJson(encoded)
}

// The request for a call: harness-1's render of the run's path as the loop journaled it, with the call's params; and
// the call's context, kept for its model_call: its nodes, harness-1, the params and the hash of the path as recorded.
func (self *harnessSessionJournal) Render(ctx context.Context, args *HarnessRenderArgs) (*InferRequest, error) {
	params, err := harnessRenderParams(args)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	path, err := self.pathWithLock(args.RunId, args.InputNodeId)
	if err != nil {
		return nil, err
	}
	system, ok := self.nodeWithLock(args.RunId, args.SystemNodeId)
	if !ok {
		return nil, fmt.Errorf("%w: the call's system node is not journaled here", ErrSessionRenderRefused)
	}
	systemNodeId := system.journaled.NodeId
	render := func(recorded bool) (*SessionRenderInput, error) {
		nodes, err := harnessRenderNodes(path, recorded)
		if err != nil {
			return nil, err
		}
		byId := map[Id]*SessionRenderNode{}
		for _, node := range nodes {
			byId[node.NodeId] = node
		}
		input, err := self.renderer.Context(nodes, &systemNodeId, func(nodeId Id) (*SessionRenderNode, bool) {
			node, ok := byId[nodeId]
			return node, ok
		})
		if err != nil {
			return nil, err
		}
		input.Params = params
		return input, nil
	}
	live, err := render(false)
	if err != nil {
		return nil, err
	}
	request, err := SessionRenderRequest(self.renderer, live)
	if err != nil {
		return nil, err
	}
	recorded, err := render(true)
	if err != nil {
		return nil, err
	}
	hash, err := SessionRequestSha256(self.renderer, recorded)
	if err != nil {
		return nil, err
	}
	exact := true
	for _, node := range path {
		if 0 < node.journaled.Redactions || 0 < node.journaled.Stubs {
			exact = false
		}
		for _, part := range node.journaled.Parts {
			if part.GetOmitted() {
				exact = false
			}
		}
	}
	input := path[len(path)-1]
	sessionRun := self.runs[args.RunId]
	sessionRun.call = &protocol.CallContext{
		InputNodeId:   input.journaled.NodeId.Bytes(),
		SystemNodeId:  systemNodeId.Bytes(),
		RequestSha256: hash[:],
		Exact:         exact,
		Renderer:      self.renderer.Id(),
		Params:        params,
	}
	return request, nil
}

// The context of the run's last rendered call, with the response's node as its output, nil for none.
func (self *harnessSessionJournal) callContext(runId Id, outputKey string) *protocol.CallContext {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sessionRun, ok := self.runs[runId]
	if !ok || sessionRun.call == nil {
		return nil
	}
	call := &protocol.CallContext{
		InputNodeId: sessionRun.call.InputNodeId, SystemNodeId: sessionRun.call.SystemNodeId,
		RequestSha256: sessionRun.call.RequestSha256, Exact: sessionRun.call.Exact, Renderer: sessionRun.call.Renderer,
		Params: sessionRun.call.Params,
	}
	if node, ok := sessionRun.keyNodes[outputKey]; ok {
		call.OutputNodeIds = [][]byte{node.journaled.NodeId.Bytes()}
	}
	return call
}

// Lets the turn's session entries leave in the run's push.
func (self *harnessSessionJournal) TurnEnd(ctx context.Context, runId Id) error {
	store, err := self.store()
	if err != nil {
		return err
	}
	return store.TurnEnd(ctx, runId)
}

// Forgets a closed run's nodes.
func (self *harnessSessionJournal) forget(runId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.runs, runId)
}

// What a recorder writes through.
type harnessRecorderArgs struct {
	// The network's record writer, read at use.
	Writer func() (RecordWriter, error)
	// The network's capture redactor (DESIGN §16.7), read at use.
	Redactor func() (*Redactor, error)
	// The run files whose gaps a coverage entry names.
	Runs HarnessRunStore
	// The ur-harness version a context and a coverage entry name.
	Version string
	Clock   Clock
	Log     Logger
	// The cost entry's settings; nil takes the defaults.
	Cost *RecordCostSettings
	// The catalog a model_call's entry is read from, at the call.
	Catalog func(ctx context.Context) (*InferCatalog, error)
}

// One run as the recorder follows it.
type harnessRecordRun struct {
	agentId Id
	// a stage-1 context written
	started bool
	model   string
	prompts []string
	// the run's entries' chain positions, for its coverage
	firstSeq uint64
	lastSeq  uint64
	// each tool call's start, by its id
	toolStarted map[string]time.Time
	// the call in flight: its start, its response's node, usage and attestation
	callStarted time.Time
	responseKey string
	usage       *InferUsage
	attestation *protocol.AttestationResult
	cost        *RecordRunCost
}

// The Harness's recorder of its runs' own entries (the file header's recorder row).
type harnessRecorder struct {
	args    *harnessRecorderArgs
	journal *harnessSessionJournal

	// agents' names and models, read from the Harness at use; nil before it binds
	harness atomic.Pointer[Harness]

	stateLock sync.Mutex
	runs      map[Id]*harnessRecordRun
}

// A recorder over args, its calls' contexts from journal.
func newHarnessRecorder(args *harnessRecorderArgs, journal *harnessSessionJournal) *harnessRecorder {
	if args.Clock == nil {
		args.Clock = clockOrReal(nil)
	}
	if args.Log == nil {
		args.Log = NewNoopLogger()
	}
	if args.Cost == nil {
		args.Cost = DefaultRecordCostSettings()
	}
	recorder := &harnessRecorder{args: args, journal: journal, runs: map[Id]*harnessRecordRun{}}
	journal.recorder = recorder
	return recorder
}

// Binds the recorder to the Harness whose events it observes.
func (self *harnessRecorder) bind(harness *Harness) {
	self.harness.Store(harness)
}

// The run of runId, made at its first sight.
func (self *harnessRecorder) runWithLock(runId Id, agentId Id) *harnessRecordRun {
	run, ok := self.runs[runId]
	if !ok {
		run = &harnessRecordRun{agentId: agentId, toolStarted: map[string]time.Time{}, cost: &RecordRunCost{}}
		self.runs[runId] = run
	}
	return run
}

// text redacted by the capture's rules before it seals; where the redactor cannot be read, a marker in its place.
func (self *harnessRecorder) redact(text string) string {
	if self.args.Redactor == nil {
		return text
	}
	redactor, err := self.args.Redactor()
	if err != nil || redactor == nil {
		return "[redacted: the redactor was not available]"
	}
	redacted, _ := redactor.Redact([]byte(text))
	return string(redacted)
}

// Writes one entry of the run, keeping its chain positions; a write that fails is the run's gap.
func (self *harnessRecorder) append(ctx context.Context, runId Id, run *harnessRecordRun, draft *RecordDraft) {
	draft.Source = RecordSourceObserved
	draft.RunId = &runId
	agentId := run.agentId
	draft.AgentId = &agentId
	if self.args.Writer == nil {
		return
	}
	writer, err := self.args.Writer()
	if err == nil {
		var refs []*RecordEntryRef
		if refs, err = writer.Append(draft); err == nil {
			for _, ref := range refs {
				if ref.Spooled || ref.Seq == 0 {
					continue
				}
				if run.firstSeq == 0 || ref.Seq < run.firstSeq {
					run.firstSeq = ref.Seq
				}
				run.lastSeq = max(run.lastSeq, ref.Seq)
			}
			return
		}
	}
	self.args.Log.Warningf("[harness]a run's %s entry did not record: %v", draft.Kind, err)
	if self.args.Runs != nil {
		if runs, ok := self.args.Runs.(interface {
			AddGap(ctx context.Context, runId Id, code string) error
		}); ok {
			runs.AddGap(ctx, runId, RecordCoverageGapMissedEvent)
		}
	}
}

// The agent's registered name and the model its next call runs on, "" where the Harness does not hold it.
func (self *harnessRecorder) agentOf(agentId Id) (string, string) {
	harness := self.harness.Load()
	if harness == nil {
		return "", ""
	}
	agent, ok := harness.Agent(agentId)
	if !ok {
		return "", ""
	}
	return agent.Name(), HarnessAgentModel(agent)
}

// A context entry of the run at stage: its harness, version, agent, model, and the title or the prompts.
func (self *harnessRecorder) writeContextWithLock(ctx context.Context, runId Id, run *harnessRecordRun, stage uint32) {
	label, model := self.agentOf(run.agentId)
	if run.model == "" {
		run.model = model
	}
	body := &protocol.ContextBody{Stage: stage, Harness: harnessRecordHarness, HarnessVersion: self.args.Version,
		AgentLabel: label, Model: run.model}
	if stage == 1 && 0 < len(run.prompts) {
		body.Title = harnessRecordCut(run.prompts[0], 120)
	}
	if stage == 2 {
		body.Prompts = slices.Clone(run.prompts)
	}
	self.append(ctx, runId, run, &RecordDraft{Kind: RecordKindContext, Body: body})
}

// text cut to at most byteCount bytes, on a rune boundary.
func harnessRecordCut(text string, byteCount int) string {
	if len(text) <= byteCount {
		return text
	}
	cut := text[:byteCount]
	for 0 < len(cut) && !harnessUtf8Boundary(text, len(cut)) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// Whether at is a rune boundary of text.
func harnessUtf8Boundary(text string, at int) bool {
	return at == len(text) || text[at]&0xC0 != 0x80
}

// What the journal tells the recorder of each node once it is journaled: a user's prompt, a model change, a tool's
// result, whose tool_call names the session entry that holds it.
func (self *harnessRecorder) journaled(ctx context.Context, node *HarnessJournalNode, journaled *SessionJournaled) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run := self.runWithLock(node.RunId, node.AgentId)
	switch node.Entry.Type() {
	case HarnessPiEntryModelChange:
		model := ""
		node.Entry.object.decode("modelId", &model)
		previous := run.model
		run.model = model
		if previous != "" && previous != model {
			self.writeContextWithLock(ctx, node.RunId, run, 2)
		}
	case HarnessPiEntryMessage:
		message := node.Entry.Message()
		switch message.Role() {
		case HarnessPiRoleUser:
			run.prompts = append(run.prompts, self.redact(message.Text()))
			if !run.started {
				run.started = true
				self.writeContextWithLock(ctx, node.RunId, run, 1)
			}
		case HarnessPiRoleAssistant:
			// the response's node, journaled before its message_end
			run.responseKey = node.Entry.Id()
		case HarnessPiRoleToolResult:
			self.writeToolCallWithLock(ctx, node, run, message, journaled)
		}
	}
}

// A tool call's tool_call entry: empty input and output, its content the session entry holding its result and
// details, and the action id joining them.
func (self *harnessRecorder) writeToolCallWithLock(ctx context.Context, node *HarnessJournalNode, run *harnessRecordRun, message *HarnessPiMessage, journaled *SessionJournaled) {
	toolCallId := message.ToolCallId()
	body := &protocol.ToolCallBody{ToolName: message.ToolName(), ToolUseId: toolCallId, EndedMillis: self.args.Clock.Now().UnixMilli()}
	if started, ok := run.toolStarted[toolCallId]; ok {
		body.StartedMillis = started.UnixMilli()
		delete(run.toolStarted, toolCallId)
	}
	draft := &RecordDraft{Kind: RecordKindToolCall, Body: body}
	if actionId, err := RecordToolActionId(node.RunId, toolCallId); err == nil {
		draft.ActionId = actionId[:]
	}
	if journaled.Entry != nil && !journaled.Entry.Spooled {
		draft.Content = []*RecordContentRef{{LogId: journaled.Entry.LogId, EntryId: journaled.Entry.EntryId, Commitment: journaled.Entry.Commitment}}
	}
	self.append(ctx, node.RunId, run, draft)
}

// One of the Harness's events, in its loop's order: what the recorder reads of calls, tools and idles.
func (self *harnessRecorder) observe(agentId Id, event *HarnessEvent) {
	harness := self.harness.Load()
	if harness == nil {
		return
	}
	agent, ok := harness.Agent(agentId)
	if !ok {
		return
	}
	runId := agent.Run().Id()
	ctx := context.Background()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run := self.runWithLock(runId, agentId)
	now := self.args.Clock.Now()
	switch event.Type {
	case HarnessEventToolExecutionStart:
		toolCallId := ""
		event.Decode("toolCallId", &toolCallId)
		run.toolStarted[toolCallId] = now
	case HarnessEventMessageStart:
		if message := event.Message(); message != nil && message.Role() == HarnessPiRoleAssistant {
			run.callStarted, run.usage, run.attestation, run.responseKey = now, nil, nil, ""
		}
	case HarnessEventUsage:
		usage := &InferUsage{}
		event.Decode("inputTokens", &usage.InputTokens)
		event.Decode("outputTokens", &usage.OutputTokens)
		event.Decode("cachedTokens", &usage.CachedTokens)
		event.Decode("reasoningTokens", &usage.ReasoningTokens)
		event.Decode("chargeNanoUsd", &usage.ChargeNanoUsd)
		run.usage = usage
	case HarnessEventAttestation:
		raw := event.Field("result")
		if raw != nil {
			result := &protocol.AttestationResult{}
			if err := protojson.Unmarshal(raw, result); err == nil {
				run.attestation = result
			}
		}
	case HarnessEventMessageEnd:
		if message := event.Message(); message != nil && message.Role() == HarnessPiRoleAssistant {
			self.writeModelCallWithLock(ctx, runId, run, message, now)
		}
	case HarnessEventAgentSettled:
		self.writeIdleWithLock(ctx, runId, run)
	}
}

// A finished call's model_call: InferModelCall's body of the call as its message names it, with its context, the
// response's node its output. A call the record cannot hold is the run's gap.
func (self *harnessRecorder) writeModelCallWithLock(ctx context.Context, runId Id, run *harnessRecordRun, message *HarnessPiMessage, now time.Time) {
	model := message.Model()
	var entry *InferCatalogEntry
	if self.args.Catalog != nil {
		if catalog, err := self.args.Catalog(ctx); err == nil {
			if resolution, err := catalog.Resolve(model, ""); err == nil {
				entry = resolution.Entry
			}
		}
	}
	gap := func(err error) {
		self.args.Log.Warningf("[harness]a model call did not record: %v", err)
		if runs, ok := self.args.Runs.(interface {
			AddGap(ctx context.Context, runId Id, code string) error
		}); ok {
			runs.AddGap(ctx, runId, RecordCoverageGapMissedEvent)
		}
	}
	if entry == nil {
		gap(fmt.Errorf("%w: the catalog names no %s", ErrInferModelCallInvalid, model))
		return
	}
	args := &InferModelCallArgs{Call: &InferCall{Entry: entry, Name: model}, Usage: run.usage, Attestation: run.attestation,
		StartedAt: run.callStarted}
	if !run.callStarted.IsZero() {
		args.Duration = now.Sub(run.callStarted)
	}
	body, err := InferModelCall(args)
	if err != nil {
		gap(err)
		return
	}
	if self.journal != nil {
		body.Context = self.journal.callContext(runId, run.responseKey)
	}
	run.cost.AddCall(body, self.args.Cost)
	self.append(ctx, runId, run, &RecordDraft{Kind: RecordKindModelCall, Body: body})
}

// At an idle: the run's coverage, source harness, and its cost.
func (self *harnessRecorder) writeIdleWithLock(ctx context.Context, runId Id, run *harnessRecordRun) {
	gaps := []string{}
	if self.args.Runs != nil {
		if file, err := self.args.Runs.Get(runId); err == nil && file != nil {
			for _, gap := range file.Gaps {
				if _, _, ok := RecordCoverageGapParse(gap); ok {
					gaps = append(gaps, gap)
				}
			}
		}
	}
	firstSeq, lastSeq := run.firstSeq, run.lastSeq
	self.append(ctx, runId, run, &RecordDraft{Kind: RecordKindCoverage, Body: &protocol.Coverage{
		RunId: runId.Bytes(), Harness: harnessRecordHarness, Version: self.args.Version,
		Sources: []string{RecordCoverageSourceHarness}, Gaps: gaps, FirstSeq: firstSeq, LastSeq: lastSeq,
	}})
	if body, ok := run.cost.Body(gaps); ok {
		draft := RecordRunCostDraft(runId, body)
		self.append(ctx, runId, run, draft)
	}
}

// Takes a reopened run's nodes back, as the record held them (harness_reopen.go): each one's id and chain as the session
// journal's sealed state keyed them, its item as read, so the run's next call renders from them.
func (self *harnessSessionJournal) Reopened(ctx context.Context, runId Id, nodes []*HarnessJournalNode) error {
	store, err := self.store()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHarnessJournalUnwired, err)
	}
	sessionRun := &harnessSessionRun{keyNodes: map[string]*harnessSessionNode{}}
	for _, node := range nodes {
		key := node.Entry.Id()
		nodeId, chain, ok := store.Node(runId, key)
		if !ok {
			return fmt.Errorf("%w: a node of the run is not in the journal's state", ErrHarnessReopenUnread)
		}
		item, err := SessionHarnessEntryWithTrust(node.Entry, node.Untrusted, node.Sender).Json()
		if err != nil {
			return err
		}
		if item, err = CanonicalJson(item); err != nil {
			return err
		}
		sessionRun.keyNodes[key] = &harnessSessionNode{node: node, journaled: &SessionJournaled{Key: key, NodeId: nodeId,
			ChainSha256: chain, Item: item}}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.runs[runId] = sessionRun
	return nil
}

// The recorder's view of the Harness's events, which a Sidecar's Harness passes as its observer.
func (self *harnessSessionJournal) observe(agentId Id, event *HarnessEvent) {
	if self.recorder != nil {
		self.recorder.observe(agentId, event)
	}
}

// Binds the recorder to the Harness whose events it observes.
func (self *harnessSessionJournal) bind(harness *Harness) {
	if self.recorder != nil {
		self.recorder.bind(harness)
	}
}

// A journal that observes its Harness's events: the session journal, whose recorder writes the run's own entries.
type harnessObservedJournal interface {
	observe(agentId Id, event *HarnessEvent)
	bind(harness *Harness)
}

// A run's nodes read back from the Sidecar's record (CTXH's SessionReader), each item restored with its parts and its
// trust taken from it, for a reopen.
type harnessSidecarRunReader struct {
	sidecar *Sidecar
}

var _ HarnessRunReader = (*harnessSidecarRunReader)(nil)

// The run's nodes in the vault's read order; an error where one is not held, so the run is not reopened on less.
func (self *harnessSidecarRunReader) Nodes(ctx context.Context, runId Id) ([]*HarnessJournalNode, error) {
	record, err := self.sidecar.Record()
	if err != nil {
		return nil, err
	}
	reader := record.SessionReader()
	vaultId, err := reader.VaultId()
	if err != nil {
		return nil, err
	}
	view, err := reader.Open(ctx, vaultId, runId)
	if err != nil {
		return nil, err
	}
	nodes := []*HarnessJournalNode{}
	for _, read := range view.Nodes {
		held, ok := view.itemOf(read)
		if !ok || read.Invalid != nil {
			return nil, fmt.Errorf("%w: a node is not held or did not check", ErrHarnessReopenUnread)
		}
		item, err := SessionItemRestore(held.Body.GetItem(), held.Body.GetParts(), held.PartBytes)
		if err != nil {
			return nil, err
		}
		entry := &HarnessPiEntry{}
		if err := json.Unmarshal(item, entry); err != nil {
			return nil, err
		}
		untrusted, sender := sessionHarnessEntryTrust(entry)
		entry.object.remove(sessionHarnessUntrustedMember)
		nodes = append(nodes, &HarnessJournalNode{RunId: runId, Entry: entry, Tainted: read.Flagged,
			Untrusted: untrusted || read.Untrusted, Sender: sender, Marks: HarnessMark(read.Body.GetMarks())})
	}
	return nodes, nil
}

// Wires the session journal and the recorder into every Sidecar's Harness, each reading the network's journal, record,
// spool and catalog at use.
func init() {
	RegisterHarnessSources("session", func(sidecar *Sidecar, sources *HarnessSources) error {
		journal := newHarnessSessionJournal(func() (harnessSessionStore, error) {
			journal, err := sidecar.SessionJournal()
			if err != nil {
				return nil, err
			}
			return journal, nil
		})
		newHarnessRecorder(&harnessRecorderArgs{
			Writer: func() (RecordWriter, error) {
				record, err := sidecar.Record()
				if err != nil {
					return nil, err
				}
				return record.Writer(), nil
			},
			Redactor: func() (*Redactor, error) {
				spool, err := sidecar.Spool()
				if err != nil {
					return nil, err
				}
				return spool.Redactor(), nil
			},
			Runs:    &harnessSidecarRuns{sidecar: sidecar},
			Version: sidecar.settings.AppVersion,
			Clock:   sidecar.settings.ClockOrReal(),
			Log:     sidecar.log,
			Catalog: func(ctx context.Context) (*InferCatalog, error) {
				router, err := sidecar.InferRouter()
				if err != nil {
					return nil, err
				}
				return router.Catalog(ctx)
			},
		}, journal)
		sources.Journal = journal
		return nil
	})
}
