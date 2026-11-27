//go:build !ios_extension && !sidecar_http

// The Harness (DESIGN-COMPUTE §7.4, R-HARN-1, R-HARN-3, R-HARN-7, D-HARN-1, CF-1): sidecar's own agent harness,
// modeled on Pi's agent core and writing Pi's formats, one per sidecar host. It holds the host's agents, reaches every
// model through the router (§6.4), so the router's checks hold however a model was reached, and is the event sink
// every area emits through (HarnessEventSink).
//
// What it is built on are seams their owners fill: the router (INFER's), the context journal and its renderer (CTXH's
// SessionJournal and harness-1, HarnessContextJournal, wired by HARN-M11-08), the recURd skill and agent registration
// (SKILL's, HarnessSkill), the run store and the gate, the approvals a waiting action watches, CTRUST's acknowledgment
// store, BAL's purchase rights and kind 21's builder for the failure choice, and the host's foreground state on
// phones. A seam left nil fails closed: no skill, no agent; no journal, no call, since a context that cannot be
// journaled is not sent (IC-19); no store, no run.
//
// An agent's events go to its subscribers and to the Harness's, each through its own bounded queue, so a slow view
// never holds a loop: past the queue a message_update is dropped, message_end carrying the whole message, and a view
// that falls further behind is unsubscribed.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"
)

var (
	// The recURd skill is not wired into this Harness, so no agent starts (R-HARN-7).
	ErrHarnessSkillUnavailable = errors.New("the recURd skill is not available, so no agent starts")
	// No context journal is wired, so no context can be journaled and no call is sent (IC-19).
	ErrHarnessJournalUnavailable = errors.New("no context journal is wired, so no call is sent")
	// The agent is running: Prompt is refused; use Steer or FollowUp.
	ErrHarnessAgentRunning = errors.New("the agent is running: steer or follow up instead")
	// The agent was closed.
	ErrHarnessAgentClosed = errors.New("the agent is closed")
	// The Harness was closed.
	ErrHarnessClosed = errors.New("the harness is closed")
	// The spec asks what this Harness does not run: a profile it does not serve, no model.
	ErrHarnessSpecInvalid = errors.New("the agent's spec is not one this harness runs")
)

// The recURd skill as the Harness uses it (§20.5, §20.9): SKILL's SkillText and agent registration.
type HarnessSkill interface {
	// The skill's text for profile, which every agent's system message holds first (R-SKILL-1).
	Text(profile HarnessProfile) (string, error)
	// Registers the agent's name at its start (§20.5), answering the name it got.
	Register(ctx context.Context, registration *HarnessAgentRegistration) (string, error)
}

// What an agent registers with.
type HarnessAgentRegistration struct {
	AgentId Id
	RunId   Id
	// The name asked for; empty to take the harness config's default or one from the task.
	Name    string
	Model   string
	Profile HarnessProfile
	// The launching agent, for a sub-agent.
	Parent *Id
}

// One node the loop journals (§24.4, §24.5): an entry of the run's session tree, which CTXH's journal records as a
// session_entry, with the run's taint and marks at capture, and, for text an untrusted writer wrote, its trust and
// sender, which the renderer reads to place the untrusted-data markers.
type HarnessJournalNode struct {
	RunId   Id
	AgentId Id
	// Pi's v3 entry; its id is the node's within the run, its parentId the previous node, empty at a root.
	Entry *HarnessPiEntry
	// A root whose parent is another run's node (§24.7's continuation): that run.
	ParentRunId *Id
	Tainted     bool
	Marks       HarnessMark
	// Text an untrusted writer wrote: a tool's untrusted result, a tainted run's prompt. Sender names the writer.
	Untrusted bool
	Sender    string
	// A tool result's tool, for the form the record keeps it in (§24.9); nil for any other node.
	Tool *HarnessJournalTool
}

// The tool a journaled tool result came from, as the record's exceptions read it (§24.9): its name, whether it is built
// in, whether its details said keep: false, which only a built-in's honors, and SRCH's stub of a web search.
type HarnessJournalTool struct {
	Name       string
	BuiltIn    bool
	KeepFalse  bool
	SearchStub []byte
}

// What a call's request is rendered from (§24.6): the context's last node and the system message in force, and the
// call's own parameters.
type HarnessRenderArgs struct {
	RunId        Id
	InputNodeId  string
	SystemNodeId string
	// The canonical name the call runs under.
	Model string
	// The most tokens the answer may hold; 0 for the model's own maximum.
	MaxOutput int
	// The agent the call is made for, and the budget it spends from, nil for none: what the loop sets on the request,
	// which the call's params carry so a rebuild equals what was sent (§24.6).
	AgentId *Id
	Budget  *InferBudgetRef
}

// The context journal and the request renderer the loop writes through (§24.4-§24.6, IC-19): CTXH's SessionJournal and
// harness-1 renderer, wired into the Harness by HARN-M11-08. Safe for concurrent use.
type HarnessContextJournal interface {
	// Journals node, durable in the local fsynced journal when it returns; a node that cannot be journaled is an error,
	// and the loop sends nothing that would carry it.
	Journal(ctx context.Context, node *HarnessJournalNode) error
	// The request for a call, rendered from the run's journaled nodes: the path from the input node to its root, the
	// newest compaction on it, the system message and its patches, so a rebuild equals what was sent.
	Render(ctx context.Context, args *HarnessRenderArgs) (*InferRequest, error)
	// Lets the turn's session entries leave in the run's push.
	TurnEnd(ctx context.Context, runId Id) error
}

// BAL's purchase rights as the failure choice reads them (§9.10): whether the person may buy credit, and who may where
// they may not.
type HarnessPurchases interface {
	MayBuy(ctx context.Context) (bool, string, error)
}

// What raising a budget asks (§16.3's kind 21).
type HarnessBudgetRaise struct {
	RunId   Id
	AgentId Id
	Budget  *HarnessBudget
	// day, month or run: the period the router said ran out.
	Period string
}

// Kind 21's builder (BAL's, on CACL's version-5 rules): the compute_budget_raise action for the person to approve, its
// effect raising the budget, which the run presents to the gate.
type HarnessBudgetRaiser interface {
	BudgetRaise(ctx context.Context, raise *HarnessBudgetRaise) (*HarnessAuthorizeRequest, error)
}

// Whether the app is in the foreground (§6.5, §20.7): on a phone, agents answer only then, and pause at an item
// boundary when the app leaves. A desktop's is always.
type HarnessForeground interface {
	Foreground() bool
}

// Called at a turn's start and end and at a tool call past HarnessSettings.ToolCallSlowAfter (§20.6's status line and
// summary reminders), on the loop's goroutine: each must return promptly.
type HarnessTurnHook interface {
	TurnStart(agent HarnessAgent)
	TurnEnd(agent HarnessAgent)
	ToolCallSlow(agent HarnessAgent, toolCallId string, toolName string)
}

// The turn hooks, by name, written only during the package's init.
var harnessTurnHooks = map[string]HarnessTurnHook{}

// Registers a turn hook from an init function in its owner's file (SKILL's status writer and reminders). A name
// registered twice or a nil hook is a build error, which panics.
func RegisterHarnessTurnHook(name string, hook HarnessTurnHook) {
	if _, registered := harnessTurnHooks[name]; name == "" || registered || hook == nil {
		panic(fmt.Sprintf("harness turn hook %q registered twice or without a hook", name))
	}
	harnessTurnHooks[name] = hook
}

// What a Harness is built on.
type HarnessArgs struct {
	// Nil takes DefaultHarnessSettings.
	Settings *HarnessSettings
	Log      Logger
	// The loop's clock, its retries' and held retries' waits among them; nil for real time.
	Clock Clock
	// Required: the router every call goes through.
	Router InferRouter
	// The context journal; nil sends no call.
	Journal HarnessContextJournal
	// The recURd skill; nil starts no agent.
	Skill HarnessSkill
	// The run store; nil starts no run.
	Runs HarnessRunStore
	// The gate and the approvals an O tool waits on; nil refuses every outward action.
	Gate      HarnessGate
	Approvals HarnessApprovals
	// SAFE's verdicts, for an automatic decision's note.
	AutoVerdicts HarnessAutoVerdicts
	// CTRUST's acknowledgment store; nil answers every disclosure request disclosure_required.
	Acks HarnessDisclosureAcks
	// BAL's purchase rights; nil offers no "add credit".
	Purchases HarnessPurchases
	// Kind 21's builder; nil offers no "raise the budget".
	BudgetRaiser HarnessBudgetRaiser
	// The app's foreground state on a phone; nil for a desktop, always in the foreground.
	Foreground HarnessForeground
	// The tools' registrations; nil takes every registered tool.
	Tools map[string]*HarnessToolSpec
	// The turn hooks; nil takes every registered hook.
	TurnHooks map[string]HarnessTurnHook
	// Where local agents' workspaces are made: the OS temp directory on desktops, the app's cache directory on phones
	// (HarnessHost); empty for the OS temp directory.
	WorkspaceParent string
	// The workspace cap; 0 takes the settings' desktop cap.
	WorkspaceByteCount int64
	// Called with each event as it is emitted, on the emitting goroutine, before any subscriber has it: a recorder's or a
	// test's view in the loop's own order. It must not block. Nil for none.
	Observer func(agentId Id, event *HarnessEvent)
	// The network's support client (DESIGN-COMPUTE §28.4), read at use: on a Sidecar its compute component, which
	// constructs after the Harness. Nil while the release's support switch is off, which leaves the support tools,
	// their skill and support_update out (§28.21; harness_support.go).
	Support func() (*SupportClient, error)
	// The network the in-process DESIGN tools act on (harness_tool_design.go): on a Sidecar its own, read at each
	// call. Nil leaves evs_*, search, record_query and record_append out.
	Network harnessDesignNetwork
	// The registry of open runs and the record a restart reads them back from (harness_reopen.go); nil for none,
	// which reopens nothing.
	OpenRuns  HarnessOpenRuns
	RunReader HarnessRunReader
	// SKILL's delivery of a reopened agent's untaken messages; nil leaves them waiting in its inbox.
	Untaken HarnessUntaken
}

// One subscriber: its queue and its goroutine.
type harnessSubscriber struct {
	queue    chan *HarnessEvent
	done     chan struct{}
	listener func(event *HarnessEvent)
	stopOnce sync.Once
}

// A subscriber delivering to listener in order on its own goroutine, its queue bounded by settings.
func newHarnessSubscriber(settings *HarnessSettings, listener func(event *HarnessEvent)) *harnessSubscriber {
	subscriber := &harnessSubscriber{
		queue:    make(chan *HarnessEvent, max(1, settings.EventSubscriberBufferCount)),
		done:     make(chan struct{}),
		listener: listener,
	}
	go subscriber.run()
	return subscriber
}

// Delivers each queued event until stopped.
func (self *harnessSubscriber) run() {
	for {
		select {
		case event := <-self.queue:
			self.listener(event)
		case <-self.done:
			return
		}
	}
}

// Offers event without waiting: false where the queue is full.
func (self *harnessSubscriber) offer(event *HarnessEvent) bool {
	select {
	case self.queue <- event:
		return true
	default:
		return false
	}
}

// Stops the subscriber's goroutine.
func (self *harnessSubscriber) stop() {
	self.stopOnce.Do(func() {
		close(self.done)
	})
}

// A set of subscribers. Safe for concurrent use.
type harnessSubscribers struct {
	settings  *HarnessSettings
	log       Logger
	stateLock sync.Mutex
	nextId    int
	idSubs    map[int]*harnessSubscriber
}

// An empty set, each subscriber's queue bounded by settings.
func newHarnessSubscribers(settings *HarnessSettings, log Logger) *harnessSubscribers {
	return &harnessSubscribers{settings: settings, log: log, idSubs: map[int]*harnessSubscriber{}}
}

// Adds listener; the answer removes it.
func (self *harnessSubscribers) add(listener func(event *HarnessEvent)) func() {
	subscriber := newHarnessSubscriber(self.settings, listener)
	id := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		id := self.nextId
		self.nextId += 1
		self.idSubs[id] = subscriber
		return id
	}()
	return func() {
		self.stateLock.Lock()
		delete(self.idSubs, id)
		self.stateLock.Unlock()
		subscriber.stop()
	}
}

// Hands event to each subscriber without waiting: a full queue drops a message_update, and a subscriber whose queue is
// full for anything else is dropped.
func (self *harnessSubscribers) deliver(event *HarnessEvent) {
	subscribers := func() map[int]*harnessSubscriber {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		copied := make(map[int]*harnessSubscriber, len(self.idSubs))
		for id, subscriber := range self.idSubs {
			copied[id] = subscriber
		}
		return copied
	}()
	for id, subscriber := range subscribers {
		if subscriber.offer(event) || event.Type == HarnessEventMessageUpdate {
			continue
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.idSubs, id)
		}()
		subscriber.stop()
		if self.log != nil {
			self.log.Warningf("[harness]a subscriber fell behind and was dropped")
		}
	}
}

// Stops every subscriber.
func (self *harnessSubscribers) close() {
	self.stateLock.Lock()
	subscribers := self.idSubs
	self.idSubs = map[int]*harnessSubscriber{}
	self.stateLock.Unlock()
	for _, subscriber := range subscribers {
		subscriber.stop()
	}
}

// One sidecar host's Harness.
type Harness struct {
	settings        *HarnessSettings
	log             Logger
	clock           Clock
	router          InferRouter
	journal         HarnessContextJournal
	skill           HarnessSkill
	runs            HarnessRunStore
	gate            HarnessGate
	approvals       HarnessApprovals
	autoVerdicts    HarnessAutoVerdicts
	purchases       HarnessPurchases
	budgetRaiser    HarnessBudgetRaiser
	foreground      HarnessForeground
	tools           *HarnessToolRegistry
	turnHooks       []HarnessTurnHook
	workspaceParent string
	workspaceCap    int64
	observer        func(agentId Id, event *HarnessEvent)
	ui              *HarnessUiBroker
	stamper         *harnessEventStamper
	subscribers     *harnessSubscribers
	support         func() (*SupportClient, error)
	network         harnessDesignNetwork
	openRuns        HarnessOpenRuns
	runReader       HarnessRunReader
	untaken         HarnessUntaken
	// the app's host, nil for none (harness_host.go)
	host atomic.Pointer[harnessHostSlot]
	// the events a view reads after the fact, nil until a view first asks (harness_view_log.go)
	view atomic.Pointer[harnessViewLog]
	// held across one emission: never stateLock
	emitLock sync.Mutex
	// §7.9's agents at work: a token for each running prompt, at most AgentConcurrentCount (harness_launch.go)
	workSlots chan struct{}

	// held across the support listener's add and removal, never with stateLock
	supportLock sync.Mutex
	// removes the support listener; nil until one is added
	supportUnlisten func()

	stateLock sync.Mutex
	agents    map[Id]*harnessAgent
	closed    bool
}

// A Harness over args. Its tools are built for it from their registrations.
func NewHarness(args *HarnessArgs) (*Harness, error) {
	if args == nil || args.Router == nil {
		return nil, fmt.Errorf("%w: a harness needs the router", ErrHarnessSpecInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultHarnessSettings()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	workspaceCap := args.WorkspaceByteCount
	if workspaceCap == 0 {
		workspaceCap = settings.WorkspaceDesktopByteCount
	}
	workspaceParent := args.WorkspaceParent
	if workspaceParent == "" {
		workspaceParent = os.TempDir()
	}
	harness := &Harness{
		settings:        settings,
		log:             log,
		clock:           clockOrReal(args.Clock),
		router:          args.Router,
		journal:         args.Journal,
		skill:           args.Skill,
		runs:            args.Runs,
		gate:            args.Gate,
		approvals:       args.Approvals,
		autoVerdicts:    args.AutoVerdicts,
		purchases:       args.Purchases,
		budgetRaiser:    args.BudgetRaiser,
		foreground:      args.Foreground,
		workspaceParent: workspaceParent,
		workspaceCap:    workspaceCap,
		observer:        args.Observer,
		support:         args.Support,
		network:         args.Network,
		openRuns:        args.OpenRuns,
		runReader:       args.RunReader,
		untaken:         args.Untaken,
		workSlots:       make(chan struct{}, max(settings.AgentConcurrentCount, 0)),
		stamper:         newHarnessEventStamper(),
		subscribers:     newHarnessSubscribers(settings, log),
		agents:          map[Id]*harnessAgent{},
	}
	harness.ui = NewHarnessUiBroker(&HarnessUiBrokerArgs{Emit: harness.Emit, Acks: args.Acks, Clock: harness.clock})
	specs := args.Tools
	if specs == nil {
		specs = harnessToolSpecs
	}
	harness.tools = newHarnessToolRegistry(harness, specs)
	hooks := args.TurnHooks
	if hooks == nil {
		hooks = harnessTurnHooks
	}
	names := []string{}
	for name := range hooks {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		harness.turnHooks = append(harness.turnHooks, hooks[name])
	}
	return harness, nil
}

// The Harness's settings.
func (self *Harness) Settings() *HarnessSettings {
	return self.settings
}

// The ui broker every run's requests go through.
func (self *Harness) UiBroker() *HarnessUiBroker {
	return self.ui
}

// The tools built for this Harness.
func (self *Harness) Tools() *HarnessToolRegistry {
	return self.tools
}

// Emits event as agentId's (HarnessEventSink): stamped with its agent and next seq, refused where its type is not
// registered, and handed to the agent's subscribers and the Harness's.
func (self *Harness) Emit(agentId Id, event *HarnessEvent) error {
	// one emission at a time, so each agent's events reach every queue in their seq's order; nothing below blocks
	self.emitLock.Lock()
	defer self.emitLock.Unlock()
	if err := self.stamper.stamp(agentId, event); err != nil {
		return err
	}
	if self.observer != nil {
		self.observer(agentId, event)
	}
	if view := self.view.Load(); view != nil {
		view.add(agentId, event)
	}
	agent := func() *harnessAgent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.agents[agentId]
	}()
	if agent != nil {
		agent.subscribers.deliver(event)
		// a launched child's events reach its ancestors' subscribers too, nested under its agent_spawned (§7.9)
		for ancestor := agent.parent; ancestor != nil; ancestor = ancestor.parent {
			ancestor.subscribers.deliver(event)
		}
	}
	self.subscribers.deliver(event)
	return nil
}

var _ HarnessEventSink = (*Harness)(nil)

// Adds a listener of every agent's events, in each agent's order; the answer removes it. The listener runs on its own
// goroutine and must not hold it long: a listener that falls behind is dropped.
func (self *Harness) Subscribe(listener func(event *HarnessEvent)) (unsubscribe func()) {
	return self.subscribers.add(listener)
}

// Whether the Harness holds an open run, which keeps its daemon from idling out (§20.7).
func (self *Harness) Active() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, agent := range self.agents {
		if !agent.isClosed() {
			return true
		}
	}
	return false
}

// The agent of id, or false.
func (self *Harness) Agent(id Id) (HarnessAgent, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	agent, ok := self.agents[id]
	return agent, ok
}

// Closes every agent, ending its run and removing its workspace, the support listener and the subscribers.
func (self *Harness) Close() {
	agents := func() []*harnessAgent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		agents := []*harnessAgent{}
		for _, agent := range self.agents {
			agents = append(agents, agent)
		}
		return agents
	}()
	// after closed is set, so no agent's start listens again
	self.unlistenSupport()
	for _, agent := range agents {
		agent.Close()
	}
	self.subscribers.close()
}
