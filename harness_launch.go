//go:build !ios_extension && !sidecar_http

// Agents launching agents, locally (DESIGN-COMPUTE §7.9, R-HARN-3, D-HARN-8; HARN-M11-07): Harness.Launch starts a child
// agent of a parent in this Harness, the path agent_launch, the sdk and the app all take.
//
//   - where is local; enclave:<name> is the attach link's management mode (HARN-M14-04) and is refused here.
//   - The model is checked as the router will check the child's calls, before the child starts, by the rules of this
//     Harness, under the parent's run, whose marks the child takes: a model the floor, the provider list, the person's
//     allow or the parent's limited_use mark refuses fails the launch with model_refused; a none model whose disclosure
//     is not acknowledged raises the disclosure request in the launching run while the person is attached to it, and
//     otherwise fails with disclosure_required, so the launching agent can pick another model or tell the person (§2.8).
//     The child's own calls pass the router again.
//   - Limits: AgentDepthCount levels counted along the parent chain the Harness holds, never from a child's word; a
//     child's budget comes out of its parent's, each period at most what the parent has, the run's at most what the
//     parent's run has left, the parent's budget's id carried so the child's spending is counted against it; and a
//     spec past the tool budget is refused before the child starts. AgentConcurrentCount agents are at work at once in
//     a local Harness, each running prompt holding a work slot, and a woken one past them waits its turn (§20.7); an
//     agent waiting in agent_wait gives its slot up while it waits, so parents waiting on children never hold the
//     children out.
//   - A refused launch leaves no card: nothing is registered, no run is opened, no event is emitted.
//   - Taint follows the work (D-HARN-8): a child launched by a tainted run starts tainted, its instructions being that
//     run's text, which reach its model between untrusted-data markers as its first prompt; a prompt, steer or follow-up
//     from a tainted run taints its receiver (HarnessOrigin); a child's answer taints the parent that reads it when the
//     child's run is tainted (agent_wait, harness_tool_agents.go); marks follow the same way. DESIGN §16.6's rule for
//     every run of one harness process does not apply, since the Harness tells its runs apart.
//   - The child's first node is a link back, a root naming the parent's run and the node it launched from, so its
//     context never takes in the parent's (§24.4); once the child starts, the parent journals a link naming the
//     child's agent, run and place, and emits agent_spawned, under which the child's events reach the parent's
//     subscribers; agent_exited follows when the child closes.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Where a child runs: this Harness. enclave:<name> is HARN-M14-04's.
const (
	HarnessLaunchWhereLocal         = "local"
	harnessLaunchWhereEnclavePrefix = "enclave:"
)

// A launch's refusal codes (§7.9).
const (
	// The model may not be called by the child: a floor, the provider list, the person's allow or a limited_use mark.
	HarnessLaunchModelRefused = "model_refused"
	// A none model's disclosure is not acknowledged and no person acknowledged it in the launching run.
	HarnessLaunchDisclosureRequired = "disclosure_required"
	// The parent chain is AgentDepthCount levels deep already.
	HarnessLaunchDepthLimit = "depth_limit"
	// The child asks more budget than its parent has.
	HarnessLaunchBudgetLimit = "budget_limit"
	// The child names more tools than its model's tool budget holds, or one its profile does not serve.
	HarnessLaunchToolBudget = "tool_budget"
	// where names a place this Harness does not launch into.
	HarnessLaunchWhereRefused = "where_refused"
)

// A launch's refusal: its code, why, and for disclosure_required the disclosure's id and version. Nothing was
// registered, opened or emitted.
type HarnessLaunchError struct {
	Code    string
	Message string
	Model   string
	// disclosure_required's disclosure and version.
	DisclosureId      string
	DisclosureVersion uint32
	// The refusal under it, where one is: the router's *InferError, the tool budget's error.
	Err error
}

// The code and why.
func (self *HarnessLaunchError) Error() string {
	if self.Model == "" {
		return fmt.Sprintf("launch %s: %s", self.Code, self.Message)
	}
	return fmt.Sprintf("launch %s: %s: %s", self.Code, self.Model, self.Message)
}

// The refusal under it.
func (self *HarnessLaunchError) Unwrap() error {
	return self.Err
}

var (
	// No agent of that id or name is open in this Harness (the daemon's methods and the agent tools answer it).
	ErrHarnessAgentUnknown = errors.New("no such agent is open in this harness")
	// No agent may work in this Harness: its AgentConcurrentCount is not positive.
	ErrHarnessNoWorkSlots = errors.New("this Harness starts no agent's work")
)

// What a launch asks (§7.9's agent_launch).
type HarnessLaunchSpec struct {
	// Registered at start (§20.5).
	Name string
	// A canonical name, or an alias, from models_list.
	Model string
	// The child's task: its first prompt, from the launching run.
	Instructions string
	// A subset of the profile's tools; empty takes the profile's set within the tool budget.
	Tools []string
	// local; empty reads local.
	Where string
	// Out of the parent's: nil takes the parent's whole.
	Budget *HarnessBudget
	// The turns one prompt runs; 0 takes HarnessSettings.MaxTurnCount.
	MaxTurnCount int
}

// Takes one of the Harness's work slots for the agent's prompt, waiting its turn past AgentConcurrentCount, until ctx
// ends. ErrHarnessNoWorkSlots where none may work, ctx's error where it ended first. Each agent holds at most one.
func (self *harnessAgent) takeWorkSlot(ctx context.Context) error {
	slots := self.harness.workSlots
	if cap(slots) == 0 {
		return ErrHarnessNoWorkSlots
	}
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.workSlotHeld = true
	return nil
}

// Gives the agent's work slot back, where it holds one.
func (self *harnessAgent) releaseWorkSlot() {
	held := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		held := self.workSlotHeld
		self.workSlotHeld = false
		return held
	}()
	if held {
		<-self.harness.workSlots
	}
}

// Gives the agent's work slot up while wait runs, where it holds one, and takes one back after, waiting its turn until
// ctx ends: what agent_wait does, so a parent waiting on its child never holds the child out. Where ctx ended first the
// agent holds none, and its prompt's release gives nothing back.
func (self *harnessAgent) yieldWorkSlot(ctx context.Context, wait func()) {
	held := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.workSlotHeld
	}()
	if !held {
		wait()
		return
	}
	self.releaseWorkSlot()
	wait()
	self.takeWorkSlot(ctx)
}

// The run's end where a prompt got no work slot: aborted where its context ended, else the error.
func (self *harnessAgent) slotEnd(ctx context.Context, err error) *harnessRunEnd {
	if ctx.Err() != nil {
		return self.aborted()
	}
	return &harnessRunEnd{stopReason: HarnessStopError, errorMessage: err.Error()}
}

// The agent of id, as this file holds agents.
func (self *Harness) agentOf(id Id) (*harnessAgent, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	agent, ok := self.agents[id]
	return agent, ok
}

// The open agent named by its id or its registered name: ErrHarnessAgentUnknown for none, and for a name two open
// agents hold.
func (self *Harness) agentByIdOrName(name string) (*harnessAgent, error) {
	if id, err := ParseId(name); err == nil {
		if agent, ok := self.agentOf(id); ok && !agent.isClosed() {
			return agent, nil
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var found *harnessAgent
	for _, agent := range self.agents {
		if agent.name != name || agent.closed {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: two agents hold that name; name one by its id", ErrHarnessAgentUnknown)
		}
		found = agent
	}
	if found == nil {
		return nil, ErrHarnessAgentUnknown
	}
	return found, nil
}

// The child's budget out of the parent's (§7.9): each period at most the parent's, a period the child leaves unset
// taking the parent's, and the run's at most what the parent's run has left; the parent's budget's id carried, so the
// child's spending counts against it. A parent with no budget leaves the child's as asked.
func harnessChildBudget(parent *harnessAgent, asked *HarnessBudget) (*HarnessBudget, error) {
	parentBudget := parent.spec.Budget
	if parentBudget == nil {
		return asked, nil
	}
	if asked == nil {
		asked = &HarnessBudget{}
	}
	runCap := uint64(0)
	if 0 < parentBudget.RunNanoUsd {
		spent := parent.runCharge()
		if parentBudget.RunNanoUsd <= spent {
			return nil, &HarnessLaunchError{Code: HarnessLaunchBudgetLimit, Message: "the parent's run budget is spent"}
		}
		runCap = parentBudget.RunNanoUsd - spent
	}
	// a period's budget out of the parent's cap on it, 0 meaning none
	out := func(askedNanoUsd uint64, capNanoUsd uint64) (uint64, bool) {
		switch {
		case askedNanoUsd == 0:
			return capNanoUsd, true
		case capNanoUsd != 0 && capNanoUsd < askedNanoUsd:
			return 0, false
		}
		return askedNanoUsd, true
	}
	child := &HarnessBudget{Id: parentBudget.Id}
	var okDay, okMonth, okRun bool
	child.DayNanoUsd, okDay = out(asked.DayNanoUsd, parentBudget.DayNanoUsd)
	child.MonthNanoUsd, okMonth = out(asked.MonthNanoUsd, parentBudget.MonthNanoUsd)
	child.RunNanoUsd, okRun = out(asked.RunNanoUsd, runCap)
	if !okDay || !okMonth || !okRun {
		return nil, &HarnessLaunchError{Code: HarnessLaunchBudgetLimit, Message: "the child asks more budget than its parent has"}
	}
	return child, nil
}

// The model check a launch makes before the child starts (§7.9): the router's Check under the parent's run, whose marks
// the child takes. A refusing rule is model_refused; a none model's unacknowledged disclosure is asked in the parent's
// run while the person is attached to it, and otherwise is disclosure_required; anything else the child's own calls
// meet again, so it does not refuse the launch.
func (self *Harness) launchModelCheck(ctx context.Context, parent *harnessAgent, model string) error {
	runId, agentId := parent.run.Id(), parent.id
	err := self.router.Check(ctx, &InferRequest{Model: model, RunId: &runId, AgentId: &agentId})
	inferError := &InferError{}
	if err == nil || !errors.As(err, &inferError) {
		return nil
	}
	switch inferError.Code {
	case InferErrorModelRefused, InferErrorServiceModel, InferErrorTeeUnverified:
		return &HarnessLaunchError{Code: HarnessLaunchModelRefused, Message: inferError.Message, Model: model, Err: err}
	case InferErrorDisclosureRequired:
		refused := &HarnessLaunchError{Code: HarnessLaunchDisclosureRequired, Model: model, DisclosureId: inferError.DisclosureId,
			DisclosureVersion: inferError.DisclosureVersion, Err: err,
			Message: "the model's disclosure is not acknowledged: pick another model, or ask the person to acknowledge it"}
		if !self.ui.Attached(runId) {
			return refused
		}
		_, askErr := self.ui.Ask(ctx, runId, agentId, &HarnessUiRequest{Method: HarnessUiDisclosure,
			DisclosureId: inferError.DisclosureId, DisclosureVersion: inferError.DisclosureVersion})
		if askErr != nil {
			refused.Err = askErr
			return refused
		}
		return nil
	}
	return nil
}

// Launches a child of parentId on spec, as the file header says: the child, started and registered, its first prompt
// its instructions from the parent's run, its run tainted and marked as the parent's is; or a *HarnessLaunchError, or
// the start's own error, with nothing registered, opened or emitted.
func (self *Harness) Launch(ctx context.Context, parentId Id, spec *HarnessLaunchSpec) (HarnessAgent, error) {
	child, err := self.launch(ctx, parentId, spec)
	if err != nil {
		return nil, err
	}
	return child, nil
}

// Launch, answering the child as this file holds agents.
func (self *Harness) launch(ctx context.Context, parentId Id, spec *HarnessLaunchSpec) (*harnessAgent, error) {
	if spec == nil || spec.Model == "" {
		return nil, fmt.Errorf("%w: a launch names a model", ErrHarnessSpecInvalid)
	}
	switch {
	case spec.Where == "" || spec.Where == HarnessLaunchWhereLocal:
	case strings.HasPrefix(spec.Where, harnessLaunchWhereEnclavePrefix):
		// the attach link's management mode, HARN-M14-04's: refused until it is built
		return nil, &HarnessLaunchError{Code: HarnessLaunchWhereRefused, Message: "launching into an enclave is not built in this release"}
	default:
		return nil, &HarnessLaunchError{Code: HarnessLaunchWhereRefused, Message: "where is local"}
	}
	parent, ok := self.agentOf(parentId)
	if !ok || parent.isClosed() {
		return nil, ErrHarnessAgentUnknown
	}
	depth := parent.depth + 1
	if self.settings.AgentDepthCount < depth {
		return nil, &HarnessLaunchError{Code: HarnessLaunchDepthLimit,
			Message: fmt.Sprintf("agents may launch agents %d levels deep", max(self.settings.AgentDepthCount, 0))}
	}
	budget, err := harnessChildBudget(parent, spec.Budget)
	if err != nil {
		return nil, err
	}
	if err := self.launchModelCheck(ctx, parent, spec.Model); err != nil {
		return nil, err
	}
	// the child takes the parent's taint and marks, read now: a mark that does not read is every mark
	taintReasons := []RunTaintReason{}
	parentTainted := parent.run.Tainted()
	if parentTainted {
		taintReasons = append(taintReasons, RunTaintUntrustedData)
	}
	marks, err := parent.run.Marks()
	if err != nil {
		marks = harnessMarkAll
	}
	leaf := func() string {
		parent.stateLock.Lock()
		defer parent.stateLock.Unlock()
		return parent.leafNodeId
	}()
	childSpec := &HarnessAgentSpec{Name: spec.Name, Model: spec.Model, Profile: parent.profile, Tools: spec.Tools,
		Parent: &parent.id, Budget: budget, MaxTurnCount: spec.MaxTurnCount}
	child, err := self.startAgent(ctx, childSpec, &harnessAgentStart{
		parent: parent, depth: depth, taintReasons: taintReasons, marks: marks,
		link: &HarnessPiLink{To: "parent", AgentId: parent.id, RunId: parent.run.Id(), Place: HarnessLaunchWhereLocal, NodeId: leaf},
	})
	if err != nil {
		if errors.Is(err, ErrHarnessToolBudget) || errors.Is(err, ErrHarnessToolOutsideProfile) {
			return nil, &HarnessLaunchError{Code: HarnessLaunchToolBudget, Message: err.Error(), Model: spec.Model, Err: err}
		}
		return nil, err
	}
	func() {
		parent.stateLock.Lock()
		defer parent.stateLock.Unlock()
		if parent.childIds == nil {
			parent.childIds = map[Id]bool{}
		}
		parent.childIds[child.id] = true
	}()
	// the parent's tree names the child; the child's context never takes in the parent's
	parentLink := NewHarnessPiLinkEntry(NewHarnessPiEntryId(), leaf, self.clock.Now(), &HarnessPiLink{To: "child",
		AgentId: child.id, RunId: child.run.Id(), Place: HarnessLaunchWhereLocal})
	if err := parent.journalWith(ctx, parentLink, nil, false, ""); err != nil {
		child.Close()
		return nil, err
	}
	parent.emit(NewHarnessAgentSpawnedEvent(child.link()))
	if spec.Instructions != "" {
		origin := HarnessRunOrigin(parent.run.Id(), parent.id, parentTainted)
		if err := child.PromptAs(ctx, origin, spec.Instructions, nil); err != nil {
			child.Close()
			return nil, err
		}
	}
	return child, nil
}

// The child as agent_spawned and agent_exited name it.
func (self *harnessAgent) link() *HarnessAgentLink {
	return &HarnessAgentLink{ChildId: self.id, Name: self.name, Model: self.currentModel(), Where: HarnessLaunchWhereLocal,
		RunId: self.run.Id()}
}

// A closed child's parent hears it exited, with its last run's stop reason.
func (self *Harness) childClosed(child *harnessAgent) {
	parent := child.parent
	if parent == nil || parent.isClosed() {
		return
	}
	stopReason := func() string {
		child.stateLock.Lock()
		defer child.stateLock.Unlock()
		return child.lastStopReason
	}()
	parent.emit(NewHarnessAgentExitedEvent(child.link(), stopReason))
}

// Whether ancestor launched agent, at any depth.
func (self *harnessAgent) launchedBy(ancestor *harnessAgent) bool {
	for parent := self.parent; parent != nil; parent = parent.parent {
		if parent == ancestor {
			return true
		}
	}
	return false
}
