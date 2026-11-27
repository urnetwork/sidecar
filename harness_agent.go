//go:build !ios_extension && !sidecar_http

// An agent of the Harness (DESIGN-COMPUTE §7.4): §7.4's HarnessAgent, the interface value NewAgent returns (the design
// writes *HarnessAgent, a pointer to an interface, whose intended reading is the interface itself). An agent is one
// run: NewAgent registers it (§20.5), opens its run (a RunStore run of ur-harness, harness_run.go), makes its workspace
// in the local profile, picks its tools within the tool budget (harness_tool_set.go), and journals Pi's versioned
// system message, the recURd skill first (R-SKILL-1, R-HARN-7), then the spec's instructions, then each tool's
// schema. The cache salt line §6.6 puts first in a remote call's system text is the remote path's, INFER's, to put.
//
//   - Prompt starts a run of turns and returns once it is accepted, refused while the agent runs (use Steer or
//     FollowUp); WaitForIdle waits for the run to settle.
//   - Steer queues text delivered after the current turn, before the next model request; FollowUp queues text
//     delivered once no tool call or steer remains, before the run ends; each change of the queues emits
//     queue_update.
//   - Abort ends the turn; the run settles with stop reason aborted.
//   - SetModel takes effect at the next call, which passes the router's checks, and journals a model_change naming
//     who changed it.
//   - Compact compacts the context now, with instructions, while the agent is idle.
//   - Close ends the run for good, removing its workspace; its card stays (§20.7).
//
// Safe for concurrent use: the agent's state is under stateLock, and its loop runs on one goroutine at a time.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// §7.4's spec of an agent.
type HarnessAgentSpec struct {
	// Registered at start (§20.5); empty takes the harness config's default.
	Name string
	// A canonical name (§6.3), or an alias.
	Model string
	// local or enclave; empty reads local.
	Profile HarnessProfile
	// A subset of the profile's tools; empty takes the profile's whole set within the tool budget.
	Tools []string
	// The launching agent, for sub-agents (§7.9).
	Parent *Id
	// USD per day, per month and per run (§16.4); nil spends from no agent budget.
	Budget *HarnessBudget
	// After the recURd skill and before the person's prompt.
	Instructions string
	// The turns one prompt runs; 0 takes HarnessSettings.MaxTurnCount.
	MaxTurnCount int
}

// An agent's budget (§16.4), in nano-USD a day, a month and a run; 0 for none on that period. Its id is what a call's
// InferBudgetRef names.
type HarnessBudget struct {
	Id           Id
	DayNanoUsd   uint64
	MonthNanoUsd uint64
	RunNanoUsd   uint64
}

// §7.4's agent.
type HarnessAgent interface {
	// Starts a run of turns on text and images, refused while running: use Steer or FollowUp. The text is trusted, as
	// the person's; PromptAs takes it from another origin.
	Prompt(ctx context.Context, text string, images [][]byte) error
	// Delivered after the current turn, before the next model request, as the person's.
	Steer(text string)
	// Delivered when the agent has no more work, before the run ends, as the person's.
	FollowUp(text string)
	// Prompt, Steer and FollowUp from origin (§7.10's origins, D-HARN-8): text from an origin that is not trusted
	// taints the run first, write-ahead, and reaches the model between untrusted-data markers naming its sender, so a
	// failed taint refuses the text. A prompt refused while running delivers nothing and taints nothing.
	PromptAs(ctx context.Context, origin *HarnessOrigin, text string, images [][]byte) error
	SteerAs(ctx context.Context, origin *HarnessOrigin, text string) error
	FollowUpAs(ctx context.Context, origin *HarnessOrigin, text string) error
	// Whether the agent's run is working on a prompt now, so a new one is refused.
	Running() bool
	// Ends the turn; the stop reason is aborted.
	Abort()
	// Returns once the agent is idle, or ctx ends.
	WaitForIdle(ctx context.Context) error
	// Adds a listener of the agent's events, in order, on its own goroutine; the answer removes it.
	Subscribe(listener func(*HarnessEvent)) (unsubscribe func())
	// Takes effect at the next call, which passes the router's checks.
	SetModel(model string) error
	// Compacts the context now, with instructions, while idle.
	Compact(ctx context.Context, instructions string) error

	// The agent's id, its registered name, and its run.
	Id() Id
	Name() string
	Run() *HarnessRun
	// Takes up a run paused at an item boundary when the app left the foreground (§6.5, §20.7).
	Resume(ctx context.Context) error
	// Ends the run for good: the loop stops, the workspace is removed.
	Close()
}

// One node of the agent's context, as the loop holds it for compaction: its entry and its estimated tokens.
type harnessContextNode struct {
	entry  *HarnessPiEntry
	tokens int64
}

// One agent.
type harnessAgent struct {
	harness     *Harness
	id          Id
	name        string
	spec        *HarnessAgentSpec
	profile     HarnessProfile
	run         *HarnessRun
	workspace   *harnessWorkspace
	toolSet     *harnessToolSet
	subscribers *harnessSubscribers
	maxTurns    int
	// ends with the agent
	lifeCtx    context.Context
	lifeCancel context.CancelFunc

	stateLock sync.Mutex
	model     string
	// a SetModel waiting for the next call, and who asked
	pendingModel     string
	pendingChangedBy string
	running          bool
	closed           bool
	idle             chan struct{}
	cancelRun        context.CancelFunc
	steering         []*harnessQueued
	followUps        []*harnessQueued
	// the session tree: the system node in force, and the leaf the next node hangs from
	systemNodeId string
	leafNodeId   string
	// the context the next request carries, for compaction: the nodes after the system message, oldest first
	contextNodes []*harnessContextNode
	// an item the loop paused before, when the app left the foreground
	paused *harnessPause
	// what the run's calls were charged, in nano-USD
	chargeNanoUsd uint64
	// the agent that launched this one, nil for a root agent; its depth along that chain, 1 at a root (§7.9)
	parent *harnessAgent
	depth  int
	// the children this agent launched, by id
	childIds map[Id]bool
	// whether the agent's prompt holds one of the Harness's work slots (harness_launch.go)
	workSlotHeld bool
	// the last run's final assistant message and its stop reason, which agent_wait answers
	lastMessage    *HarnessPiMessage
	lastStopReason string
}

// Starts an agent on spec: registered, its run opened, its workspace made, its tools picked within the tool budget and
// Pi's versioned system message journaled. Refused without the skill, the journal or the store, for a profile this
// Harness does not serve, and for a spec naming tools past the budget or outside the profile.
func (self *Harness) NewAgent(ctx context.Context, spec *HarnessAgentSpec) (HarnessAgent, error) {
	agent, err := self.startAgent(ctx, spec, &harnessAgentStart{})
	if err != nil {
		return nil, err
	}
	return agent, nil
}

// A continuation's starting context (§24.7, CTXH's continue and fork): the run and node the new run hangs from, the
// rebuilt context's nodes in order, and the taint and marks the nodes it takes give it.
type HarnessContinuation struct {
	ParentRunId  Id
	ParentNodeId string
	Nodes        []*HarnessPiEntry
	TaintReasons []RunTaintReason
	Marks        HarnessMark
}

// Starts an agent's run on a context the journal rebuilt (CTXH's continue and fork): its first node hangs from the
// continued run's node, and it starts tainted and marked as the nodes it takes are.
func (self *Harness) Continue(ctx context.Context, spec *HarnessAgentSpec, continuation *HarnessContinuation) (HarnessAgent, error) {
	if continuation == nil || continuation.ParentRunId == (Id{}) || continuation.ParentNodeId == "" {
		return nil, fmt.Errorf("%w: a continuation names the run and node it continues", ErrHarnessSpecInvalid)
	}
	agent, err := self.startAgent(ctx, spec, &harnessAgentStart{continuation: continuation})
	if err != nil {
		return nil, err
	}
	return agent, nil
}

// How an agent starts beside its spec: a continuation's rebuilt context, or a launch's parent (harness_launch.go),
// which the agent is the child of, its depth along the parent chain the Harness holds, the taint and marks it starts
// with, and its first node, a link back to the parent's run and node, a root, so its context never takes in the
// parent's (§24.4).
type harnessAgentStart struct {
	continuation *HarnessContinuation
	parent       *harnessAgent
	depth        int
	taintReasons []RunTaintReason
	marks        HarnessMark
	// the child's root link, its parent's run and the node it launched from
	link *HarnessPiLink
}

// The tool budget for model: the catalog's entry for it, resolved.
func (self *Harness) modelEntry(ctx context.Context, model string) (*InferCatalogResolution, error) {
	catalog, err := self.router.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	return catalog.Resolve(model, "")
}

// NewAgent, Continue and Launch.
func (self *Harness) startAgent(ctx context.Context, spec *HarnessAgentSpec, start *harnessAgentStart) (*harnessAgent, error) {
	continuation := start.continuation
	if spec == nil || spec.Model == "" {
		return nil, fmt.Errorf("%w: no model", ErrHarnessSpecInvalid)
	}
	profile := spec.Profile
	if profile == "" {
		profile = HarnessProfileLocal
	}
	if profile != HarnessProfileLocal {
		// the enclave profile runs only in an enclave's Harness outside the agents' container (HARN-M14-05)
		return nil, fmt.Errorf("%w: profile %s", ErrHarnessSpecInvalid, profile)
	}
	if self.skill == nil {
		return nil, ErrHarnessSkillUnavailable
	}
	if self.journal == nil {
		return nil, ErrHarnessJournalUnavailable
	}
	if self.runs == nil {
		return nil, fmt.Errorf("%w: no run store", ErrHarnessRunInvalid)
	}
	if func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.closed
	}() {
		return nil, ErrHarnessClosed
	}
	skillText, err := self.skill.Text(profile)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHarnessSkillUnavailable, err)
	}
	resolution, err := self.modelEntry(ctx, spec.Model)
	if err != nil {
		return nil, err
	}
	toolSet, err := newHarnessToolSet(self.settings, self.tools, profile, spec.Tools, skillText,
		harnessToolBudget(self.settings, resolution.Entry))
	if err != nil {
		return nil, err
	}

	agentId, runId := NewId(), NewId()
	name, err := self.skill.Register(ctx, &HarnessAgentRegistration{AgentId: agentId, RunId: runId, Name: spec.Name,
		Model: resolution.Name, Profile: profile, Parent: spec.Parent})
	if err != nil {
		return nil, err
	}
	runArgs := &HarnessRunArgs{RunId: runId, AgentId: agentId, Runs: self.runs, Gate: self.gate, Approvals: self.approvals,
		AutoVerdicts: self.autoVerdicts, Emit: self.Emit, TaintReasons: start.taintReasons, Marks: start.marks}
	if continuation != nil {
		runArgs.TaintReasons = append(runArgs.TaintReasons, continuation.TaintReasons...)
		runArgs.Marks |= continuation.Marks
	}
	run, err := NewHarnessRun(ctx, runArgs)
	if err != nil {
		return nil, err
	}
	workspace, err := newHarnessWorkspace(&harnessWorkspaceArgs{Parent: self.workspaceParent, CapByteCount: self.workspaceCap})
	if err != nil {
		return nil, err
	}
	maxTurns := spec.MaxTurnCount
	if maxTurns == 0 {
		maxTurns = self.settings.MaxTurnCount
	}
	specCopy := *spec
	lifeCtx, lifeCancel := context.WithCancel(context.Background())
	agent := &harnessAgent{
		harness:     self,
		id:          agentId,
		name:        name,
		spec:        &specCopy,
		profile:     profile,
		run:         run,
		workspace:   workspace,
		toolSet:     toolSet,
		subscribers: newHarnessSubscribers(self.settings, self.log),
		maxTurns:    maxTurns,
		lifeCtx:     lifeCtx,
		lifeCancel:  lifeCancel,
		model:       resolution.Name,
		idle:        make(chan struct{}),
		parent:      start.parent,
		depth:       max(start.depth, 1),
	}
	close(agent.idle)
	if err := agent.journalStart(ctx, skillText, resolution, continuation, start.link); err != nil {
		workspace.Remove()
		lifeCancel()
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.agents[agentId] = agent
	}()
	// support_update reaches its agents once the client can be reached (harness_support.go)
	self.listenSupport()
	return agent, nil
}

// Journals the agent's first nodes: Pi's versioned system message (the skill, the instructions, each tool's schema) and
// the run's first model_change, a root, or for a continuation hanging from the continued run's node, or for a launched
// child hanging from its root link back to the parent (§24.4).
func (self *harnessAgent) journalStart(ctx context.Context, skillText string, resolution *InferCatalogResolution, continuation *HarnessContinuation, link *HarnessPiLink) error {
	sections := []*HarnessPiSection{{Name: "skill", Text: skillText}}
	// the skills the agent's tools come with, after recURd's (§28.4's support)
	for _, skill := range self.toolSet.skills {
		sections = append(sections, &HarnessPiSection{Name: skill.Name, Text: skill.Text})
	}
	if self.spec.Instructions != "" {
		sections = append(sections, &HarnessPiSection{Name: "instructions", Text: self.spec.Instructions})
	}
	tools := []*HarnessPiTool{}
	for _, tool := range self.toolSet.tools {
		tools = append(tools, &HarnessPiTool{Name: tool.Name(), Description: tool.Description(), Parameters: tool.Schema()})
	}
	now := self.harness.clock.Now()
	system := NewHarnessPiSystemMessage(sections, tools, now.UnixMilli())
	parentId := ""
	var parentRunId *Id
	if continuation != nil {
		parentId = continuation.ParentNodeId
		continuedRunId := continuation.ParentRunId
		parentRunId = &continuedRunId
		for _, entry := range continuation.Nodes {
			self.contextNodes = append(self.contextNodes, &harnessContextNode{entry: entry, tokens: self.entryTokens(entry)})
		}
	}
	if link != nil && continuation == nil {
		// the child's first node: a root naming its parent's run and node in its item, never as its parent
		linkEntry := NewHarnessPiLinkEntry(NewHarnessPiEntryId(), "", now, link)
		if err := self.journalWith(ctx, linkEntry, nil, false, ""); err != nil {
			return err
		}
		parentId = linkEntry.Id()
	}
	systemEntry := NewHarnessPiMessageEntry(NewHarnessPiEntryId(), parentId, now, system)
	if err := self.journalWith(ctx, systemEntry, parentRunId, false, ""); err != nil {
		return err
	}
	self.systemNodeId = systemEntry.Id()
	change := NewHarnessPiModelChangeEntry(NewHarnessPiEntryId(), self.leafNodeId, now, &HarnessPiModelChange{
		Provider: resolution.Entry.Provider, ModelId: resolution.Name, ChangedBy: HarnessModelChangedByPerson})
	return self.journalWith(ctx, change, nil, false, "")
}

// The tokens an entry's context takes, estimated as Pi does.
func (self *harnessAgent) entryTokens(entry *HarnessPiEntry) int64 {
	encoded, err := entry.Json()
	if err != nil {
		return 0
	}
	return harnessEstimateTokens(self.harness.settings, len(encoded))
}

// Journals entry as the run's next node, hanging from the leaf (its parent set at its build), and makes it the leaf.
func (self *harnessAgent) journalWith(ctx context.Context, entry *HarnessPiEntry, parentRunId *Id, untrusted bool, sender string) error {
	marks, err := self.run.Marks()
	if err != nil {
		// a run whose marks do not read journals every mark
		marks = harnessMarkAll
	}
	node := &HarnessJournalNode{
		RunId:       self.run.Id(),
		AgentId:     self.id,
		Entry:       entry,
		ParentRunId: parentRunId,
		Tainted:     self.run.Tainted(),
		Marks:       marks,
		Untrusted:   untrusted,
		Sender:      sender,
	}
	if err := self.harness.journal.Journal(ctx, node); err != nil {
		return fmt.Errorf("the context did not journal, so nothing is sent: %w", err)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.leafNodeId = entry.Id()
	}()
	return nil
}

// Journals a message as the next node and puts it in the context.
func (self *harnessAgent) journalMessage(ctx context.Context, message *HarnessPiMessage, untrusted bool, sender string) (*HarnessPiEntry, error) {
	leaf := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.leafNodeId
	}()
	entry := NewHarnessPiMessageEntry(NewHarnessPiEntryId(), leaf, self.harness.clock.Now(), message)
	if err := self.journalWith(ctx, entry, nil, untrusted, sender); err != nil {
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.contextNodes = append(self.contextNodes, &harnessContextNode{entry: entry, tokens: self.entryTokens(entry)})
	}()
	return entry, nil
}

// The agent's id.
func (self *harnessAgent) Id() Id {
	return self.id
}

// Its registered name.
func (self *harnessAgent) Name() string {
	return self.name
}

// Its run.
func (self *harnessAgent) Run() *HarnessRun {
	return self.run
}

// Whether the agent was closed.
func (self *harnessAgent) isClosed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

// Emits event as the agent's.
func (self *harnessAgent) emit(event *HarnessEvent) {
	if err := self.harness.Emit(self.id, event); err != nil {
		self.harness.log.Warningf("[harness]an event did not emit: %v", err)
	}
}

// One queued steer or follow-up: its text and where it came from.
type harnessQueued struct {
	text   string
	origin *HarnessOrigin
}

// The texts of queued, in order.
func harnessQueuedTexts(queued []*harnessQueued) []string {
	texts := make([]string, len(queued))
	for i, item := range queued {
		texts[i] = item.text
	}
	return texts
}

// The queues, for queue_update.
func (self *harnessAgent) queues() ([]string, []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return harnessQueuedTexts(self.steering), harnessQueuedTexts(self.followUps)
}

// Starts a run on text and images as the person's, refused while running.
func (self *harnessAgent) Prompt(ctx context.Context, text string, images [][]byte) error {
	return self.PromptAs(ctx, HarnessPersonOrigin(), text, images)
}

// Starts a run on text and images from origin, refused while running. Text from an origin that is not trusted taints
// the run before the run starts, so a failed taint refuses the prompt.
func (self *harnessAgent) PromptAs(ctx context.Context, origin *HarnessOrigin, text string, images [][]byte) error {
	runCtx, err := self.startRun()
	if err != nil {
		return err
	}
	if err := self.admit(ctx, origin); err != nil {
		self.endRun()
		return err
	}
	go self.runPrompt(runCtx, &harnessInput{text: text, images: images, origin: origin})
	return nil
}

// Taints the run, write-ahead, for text from an origin that is not trusted, before the text can reach the model.
func (self *harnessAgent) admit(ctx context.Context, origin *HarnessOrigin) error {
	if origin.Trusted() {
		return nil
	}
	if err := self.run.Taint(ctx, RunTaintUntrustedData); err != nil {
		return fmt.Errorf("the run's taint did not persist, so the text is refused: %w", err)
	}
	return nil
}

// Whether a prompt runs now.
func (self *harnessAgent) Running() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.running
}

// Marks the agent running, answering the run's context; refused while running or closed.
func (self *harnessAgent) startRun() (context.Context, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch {
	case self.closed:
		return nil, ErrHarnessAgentClosed
	case self.running:
		return nil, ErrHarnessAgentRunning
	}
	self.running = true
	self.idle = make(chan struct{})
	runCtx, cancel := context.WithCancel(self.lifeCtx)
	self.cancelRun = cancel
	return runCtx, nil
}

// Marks the agent idle once its run settled.
func (self *harnessAgent) endRun() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.cancelRun != nil {
		self.cancelRun()
		self.cancelRun = nil
	}
	self.running = false
	close(self.idle)
}

// Queues text for after the current turn, as the person's.
func (self *harnessAgent) Steer(text string) {
	self.SteerAs(context.Background(), HarnessPersonOrigin(), text)
}

// Queues text for when no work remains, as the person's.
func (self *harnessAgent) FollowUp(text string) {
	self.FollowUpAs(context.Background(), HarnessPersonOrigin(), text)
}

// Queues text from origin for after the current turn, the run tainted first where origin is not trusted.
func (self *harnessAgent) SteerAs(ctx context.Context, origin *HarnessOrigin, text string) error {
	if err := self.admit(ctx, origin); err != nil {
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.steering = append(self.steering, &harnessQueued{text: text, origin: origin})
	}()
	steering, followUps := self.queues()
	self.emit(NewHarnessQueueUpdateEvent(steering, followUps))
	return nil
}

// Queues text from origin for when no work remains, the run tainted first where origin is not trusted.
func (self *harnessAgent) FollowUpAs(ctx context.Context, origin *HarnessOrigin, text string) error {
	if err := self.admit(ctx, origin); err != nil {
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.followUps = append(self.followUps, &harnessQueued{text: text, origin: origin})
	}()
	steering, followUps := self.queues()
	self.emit(NewHarnessQueueUpdateEvent(steering, followUps))
	return nil
}

// Takes the steering queue.
func (self *harnessAgent) takeSteering() []*harnessQueued {
	taken := func() []*harnessQueued {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		taken := self.steering
		self.steering = nil
		return taken
	}()
	if 0 < len(taken) {
		steering, followUps := self.queues()
		self.emit(NewHarnessQueueUpdateEvent(steering, followUps))
	}
	return taken
}

// Takes the follow-up queue.
func (self *harnessAgent) takeFollowUps() []*harnessQueued {
	taken := func() []*harnessQueued {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		taken := self.followUps
		self.followUps = nil
		return taken
	}()
	if 0 < len(taken) {
		steering, followUps := self.queues()
		self.emit(NewHarnessQueueUpdateEvent(steering, followUps))
	}
	return taken
}

// Ends the turn: the run settles with stop reason aborted.
func (self *harnessAgent) Abort() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.cancelRun != nil {
		self.cancelRun()
	}
}

// Returns once the agent is idle, or ctx ends.
func (self *harnessAgent) WaitForIdle(ctx context.Context) error {
	idle := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.idle
	}()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Adds a listener of the agent's events.
func (self *harnessAgent) Subscribe(listener func(*HarnessEvent)) (unsubscribe func()) {
	return self.subscribers.add(listener)
}

// Takes model at the next call. A model the router refuses outright (model_refused, service_model) or the catalog does
// not name is refused here; one that waits for a disclosure or a balance is taken, and its call asks.
func (self *harnessAgent) SetModel(model string) error {
	return self.setModel(model, HarnessModelChangedByPerson)
}

// SetModel, naming who changed the model.
func (self *harnessAgent) setModel(model string, changedBy string) error {
	ctx := self.lifeCtx
	resolution, err := self.harness.modelEntry(ctx, model)
	if err != nil {
		return err
	}
	runId, agentId := self.run.Id(), self.id
	checkErr := self.harness.router.Check(ctx, &InferRequest{Model: resolution.Name, RunId: &runId, AgentId: &agentId})
	switch InferErrorCodeOf(checkErr) {
	case InferErrorModelRefused, InferErrorServiceModel, InferErrorTeeUnverified:
		return checkErr
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pendingModel = resolution.Name
	self.pendingChangedBy = changedBy
	return nil
}

// Takes a pending model change before a call, journaling its model_change. Answers an *InferError where the catalog
// stopped naming the model after SetModel took it, the call's failure for the failure choice, and any other error where
// the model_change did not journal, which ends the run.
func (self *harnessAgent) applyPendingModel(ctx context.Context) error {
	model, changedBy, previous := func() (string, string, string) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		model, changedBy := self.pendingModel, self.pendingChangedBy
		self.pendingModel, self.pendingChangedBy = "", ""
		return model, changedBy, self.model
	}()
	if model == "" || model == previous {
		return nil
	}
	resolution, err := self.harness.modelEntry(ctx, model)
	if err != nil {
		return &InferError{Code: InferErrorModelRefused, Model: model, Message: "the model does not resolve in the catalog"}
	}
	leaf := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.leafNodeId
	}()
	change := NewHarnessPiModelChangeEntry(NewHarnessPiEntryId(), leaf, self.harness.clock.Now(), &HarnessPiModelChange{
		Provider: resolution.Entry.Provider, ModelId: resolution.Name, PreviousModelId: previous, ChangedBy: changedBy})
	if err := self.journalWith(ctx, change, nil, false, ""); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.model = resolution.Name
	return nil
}

// The model the next call runs on.
func (self *harnessAgent) currentModel() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.model
}

// Compacts the context now, while idle.
func (self *harnessAgent) Compact(ctx context.Context, instructions string) error {
	runCtx, err := self.startRun()
	if err != nil {
		return err
	}
	defer self.endRun()
	return self.compact(runCtx, HarnessCompactionManual, instructions)
}

// Ends the run for good: its loop stops and its workspace is removed. The card stays (§20.7).
func (self *harnessAgent) Close() {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.closed = true
		return true
	}()
	if !first {
		return
	}
	self.lifeCancel()
	idle := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.idle
	}()
	<-idle
	if err := self.workspace.Remove(); err != nil {
		self.harness.log.Warningf("[harness]a workspace did not remove: %v", err)
	}
	self.subscribers.close()
	func() {
		self.harness.stateLock.Lock()
		defer self.harness.stateLock.Unlock()
		delete(self.harness.agents, self.id)
	}()
	// a view waiting on the agent's events hears that no more come (harness_daemon.go)
	self.harness.viewClosed(self.id)
	// a launched child's parent hears it exited (harness_launch.go)
	self.harness.childClosed(self)
}

// What a run was started on, and where it came from.
type harnessInput struct {
	text   string
	images [][]byte
	origin *HarnessOrigin
}

// An item boundary the loop stopped at when the app left the foreground: the tool calls its turn had left.
type harnessPause struct {
	message   *HarnessPiMessage
	remaining []*HarnessPiToolCall
	results   []*HarnessPiMessage
}

// Whether the loop may start an item now: always on a desktop, on a phone only in the foreground.
func (self *harnessAgent) foreground() bool {
	return self.harness.foreground == nil || self.harness.foreground.Foreground()
}

var errHarnessBackgrounded = errors.New("the app left the foreground")
