//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.7's resume, continue and fork across the member's devices (CTXH-M11-05; R-CTXH-4, R-CTXH-7,
// D-CTXH-5, D-CTXH-9, D-CTXH-11, CF-18): a run read from the vault on any consented device of the member and started
// again there as a new run that hangs from it, by HARN's Harness.Continue.
//
//	resume    the same run on the device that ran it, its run id kept: Harness.Reopen (harness_reopen.go), from the
//	          daemon's journal and the vault; nothing here
//	continue  a new run whose first node's parent is the old run's tip, the newest node its writer journaled (a failed
//	          or aborted answer aside), on the old run's model unless the person picks another, the change journaled as
//	          the new run's model_change naming the old; refused while the old run is live, its agent running in this
//	          Harness or its status working, waiting or blocked (§20.6), and, failing closed, while that status cannot
//	          be read; refused while the tip's body is not held here (withheld past a cap, dropped or erased), so a run
//	          made past a cap continues only on its own device until its bodies leave it
//	fork      a new run from any node this device reads in the run, of its own runs or another agent's it reviews
//	          (CO-19), never refused for liveness; clone is a fork at the tip, Pi's clone
//	context   the path from that node to its root, into another run where a parent link crosses, cut above the first
//	          node whose body this device does not hold (erased, withheld, dropped), which a rebuild reads unverifiable;
//	          a node that failed the reader's checks refuses the whole continuation. A part not held reads as its marker
//	          (§24.10's after row) and makes the new run's calls inexact. The context is harness-1's of that path: the
//	          system messages on it, then the messages from its newest compaction on
//	taint     the new run starts tainted (reason inherited) if any node of that context is flagged, untrusted (a tagged
//	          sidecar other than the member's own enclave wrote it, D-CTXH-9) or holds the Harness's untrusted member;
//	          a move never clears taint (I-9). It takes the private and limited_use marks of every node of the context
//	bytes     the new run copies no byte of the old: its first node names the old run's node by a parent link alone,
//	          and the Harness's journal holds the path's nodes, as read, in memory to render from (§24.5, Q-CTXH-5)
//	record    the new run's stage-2 context entry names continues_run_id and continues_entry_id, the old run and the
//	          session_entry of the node it continues (RECORD.md section 4.3 as Appendix D amends it), so an erasure
//	          finds the continuation
//	enclave   continuing into an enclave is CTXH-M14-01's, refused here
//
// A continued run gets the context, not the workspace: temp files end with their run, and a web search's results stay
// stubs, so a continued run that needs them searches again (§24.7, §24.9). The run's bodies are fetched only now, as it
// is continued (SessionReader.Open), each held to its header's commitment. A node that a tagged writer alone makes
// untrusted is not fenced in the new run's requests, since a rebuild reads trust from the recorded item alone and must
// equal what was sent: its run starts tainted instead.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// What a continuation does (§24.7's acts).
type SessionContinueAct string

const (
	// A new run from the old run's tip, refused while the old run is live.
	SessionContinueActContinue SessionContinueAct = "continue"
	// A new run from any node this device reads, never refused for liveness.
	SessionContinueActFork SessionContinueAct = "fork"
	// Pi's clone: a fork at the tip.
	SessionContinueActClone SessionContinueAct = "clone"
)

var (
	// The spec names no run, an act or a node a continuation does not take, or no model where the run names none.
	ErrSessionContinueInvalid = errors.New("session continue: not a continuation this device takes")
	// The run is live, its agent at work in this Harness or its status working, waiting or blocked, or its status could
	// not be read: a fork goes on where a continue is refused.
	ErrSessionContinueLive = errors.New("session continue: the run is live; fork it, or continue once it is idle")
	// Into an enclave: CTXH-M14-01's, with HARN-M14-04's harness_continue and the person's confirmation.
	ErrSessionContinueEnclave = errors.New("session continue: continuing a run in an enclave is not built yet")
	// The run's tip is not held on this device: its body is withheld past a cap, dropped or erased, so it continues
	// only on its own device, or as a fork of an earlier node.
	ErrSessionContinueUnheld = errors.New("session continue: the run's newest node is not held here")
	// A node of the context failed the reader's checks, or is no Harness entry: nothing is continued from it.
	ErrSessionContinueRefused = errors.New("session continue: a node of the context cannot be continued")
)

// What a person asks to continue (§24.7; the sdk's Continue takes it as JSON).
type SessionContinueSpec struct {
	RunId Id `json:"run"`
	// The node to fork at: its id, as hex or dashed, or a unique prefix of its hex of at least
	// SessionSettings.NodePrefixMinCount characters. Empty takes the run's tip.
	At string `json:"at,omitempty"`
	// continue (the default), fork or clone.
	Act SessionContinueAct `json:"act,omitempty"`
	// The model the new run takes; empty takes the old run's.
	Model string `json:"model,omitempty"`
	// The new agent's registered name; empty takes the harness config's default.
	Name string `json:"name,omitempty"`
	// An enclave to continue in: refused until CTXH-M14-01.
	Enclave string `json:"enclave,omitempty"`
}

// What a continuation would take before it starts: DESIGN-UI.md's T10, where it last ran, the model, and what carries
// over.
type SessionContinuePlan struct {
	RunId Id                 `json:"run"`
	Act   SessionContinueAct `json:"act"`
	// The node the new run hangs from, and its session_entry, which the new run's stage-2 context entry names.
	NodeId  Id `json:"node"`
	EntryId Id `json:"entry"`
	// The run's writer: the device it last ran on, and the agent it was.
	WriterSidecarId Id `json:"writer"`
	AgentId         Id `json:"agent,omitempty"`
	// The model the new run takes, and the old run's where they differ.
	Model         string `json:"model"`
	PreviousModel string `json:"previous_model,omitempty"`
	// Whether this device's catalog names the old run's model: T10 offers another where it cannot run here.
	PreviousModelHere bool `json:"previous_model_here"`
	// The context's nodes, and of them the flagged and the untrusted (D-CTXH-9).
	NodeCount      int `json:"node_count"`
	FlaggedCount   int `json:"flagged_count"`
	UntrustedCount int `json:"untrusted_count"`
	// The new run starts tainted, and with these marks (§7.8, §25.10).
	Tainted    bool `json:"tainted"`
	Private    bool `json:"private"`
	LimitedUse bool `json:"limited_use"`
	// The path was cut above a node this device does not hold (erased, withheld, dropped), and its parts not held, each
	// reading as its marker: the new run's calls read unverifiable there.
	Cut             bool `json:"cut,omitempty"`
	PrunedPartCount int  `json:"pruned_part_count,omitempty"`
	// A continue's liveness: the run is live, its agent's state, or why it could not be read, each refusing a continue.
	Live        bool       `json:"live,omitempty"`
	LiveState   AgentState `json:"live_state,omitempty"`
	LiveUnknown string     `json:"live_unknown,omitempty"`
}

// A continuation started.
type SessionContinued struct {
	Plan *SessionContinuePlan `json:"plan"`
	// The new agent, its registered name and its run.
	AgentId  Id     `json:"agent"`
	Name     string `json:"name"`
	NewRunId Id     `json:"new_run"`
}

// Whether a run is live (§24.7's refusal): SKILL's agent status on a Sidecar (§20.6), or a test's. The state of the
// run's agent, empty where none stands or its status is of another run, and an error where it cannot be read, which
// refuses a continue.
type SessionRunLiveness interface {
	RunState(ctx context.Context, agentId Id, runId Id) (AgentState, error)
}

// Whether a state shows its run live: working, waiting or blocked, never idle, an open run waiting for its inbox
// (§20.7), nor offline.
func SessionAgentStateLive(state AgentState) bool {
	return state == AgentStateWorking || state == AgentStateWaiting || state == AgentStateBlocked
}

// What a SessionContinue runs on.
type SessionContinueArgs struct {
	// The record's session reader of this device's vault.
	Reader *SessionReader
	// The Harness the new run starts in; nil plans only.
	Harness *Harness
	// SKILL's agent status; nil refuses every continue, failing closed, and forks go on.
	Live     SessionRunLiveness
	Settings *SessionSettings
}

// Continues and forks runs on this device. See the file header.
type SessionContinue struct {
	reader   *SessionReader
	harness  *Harness
	live     SessionRunLiveness
	settings *SessionSettings
}

// A continuer over args.
func NewSessionContinue(args *SessionContinueArgs) (*SessionContinue, error) {
	if args == nil || args.Reader == nil {
		return nil, fmt.Errorf("%w: no session reader", ErrSessionContinueInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSessionSettings()
	}
	return &SessionContinue{reader: args.Reader, harness: args.Harness, live: args.Live, settings: settings}, nil
}

// One node of a continuation's path, as it is adopted into the Harness's journal.
type sessionContinueNode struct {
	runId Id
	read  *SessionReadNode
	// the node whose item and parts read for this one: itself, or the node its same_as names
	itemNode *SessionReadNode
	// the entry as the Harness journal holds it: parts put back, each one not held as its marker, the trust member
	// taken out, its parent the path's node before it
	entry *HarnessPiEntry
	key   string
	// the recorded item's own trust, which the renderer reads
	untrusted bool
	sender    string
	// parts not held here, kept as their markers
	pruned []*protocol.SessionPart
}

// What planning a continuation found.
type sessionContinueWork struct {
	plan *SessionContinuePlan
	// root first
	path    []*sessionContinueNode
	context []*sessionContinueNode
	tip     *sessionContinueNode
	liveErr error
}

// The act a spec asks, continue where it names none.
func (self *SessionContinueSpec) act() (SessionContinueAct, error) {
	switch self.Act {
	case "", SessionContinueActContinue:
		return SessionContinueActContinue, nil
	case SessionContinueActFork, SessionContinueActClone:
		return self.Act, nil
	}
	return "", fmt.Errorf("%w: act %q", ErrSessionContinueInvalid, self.Act)
}

// The node of view that text names: its id in either form, or a unique prefix of its hex.
func (self *SessionContinue) nodeNamed(view *SessionRunView, text string) (*SessionReadNode, error) {
	if nodeId, err := ParseId(text); err == nil {
		node, ok := view.Node(nodeId)
		if !ok {
			return nil, fmt.Errorf("%w: node %s is not held in the run", ErrSessionContinueInvalid, nodeId)
		}
		return node, nil
	}
	prefix := strings.ToLower(strings.ReplaceAll(text, "-", ""))
	if len(prefix) < self.settings.NodePrefixMinCount {
		return nil, fmt.Errorf("%w: a node is named by at least %d hex characters of its id", ErrSessionContinueInvalid, self.settings.NodePrefixMinCount)
	}
	if _, err := hex.DecodeString(prefix[:len(prefix)/2*2]); err != nil {
		return nil, fmt.Errorf("%w: a node is named by its id's hex", ErrSessionContinueInvalid)
	}
	var found *SessionReadNode
	for _, node := range view.Nodes {
		nodeId, ok := node.NodeId()
		if !ok || node.Invalid != nil || !strings.HasPrefix(hex.EncodeToString(nodeId[:]), prefix) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: %q names more than one node", ErrSessionContinueInvalid, text)
		}
		found = node
	}
	if found == nil {
		return nil, fmt.Errorf("%w: no node held in the run starts %q", ErrSessionContinueInvalid, text)
	}
	return found, nil
}

// A held node's Pi entry as recorded, nil for an item that is no Pi entry.
func sessionContinueEntryOf(item []byte) *HarnessPiEntry {
	entry := &HarnessPiEntry{}
	if json.Unmarshal(item, entry) != nil || entry.Id() == "" {
		return nil
	}
	return entry
}

// The run's tip: the newest held node by its writer's seq that is no failed or aborted answer, as Reopen takes a run's
// leaf. ErrSessionContinueUnheld where the run's newest node is not held here.
func sessionContinueTip(view *SessionRunView) (*SessionReadNode, error) {
	nodes := slices.Clone(view.Nodes)
	slices.SortStableFunc(nodes, func(a *SessionReadNode, b *SessionReadNode) int {
		switch {
		case a.Seq < b.Seq:
			return -1
		case b.Seq < a.Seq:
			return 1
		}
		return 0
	})
	for i := len(nodes) - 1; 0 <= i; i -= 1 {
		node := nodes[i]
		if node.Body == nil {
			// the newest node is away: withheld past a cap, dropped or erased
			return nil, fmt.Errorf("%w: its body is %s", ErrSessionContinueUnheld, node.State)
		}
		if node.Invalid != nil {
			continue
		}
		itemNode, ok := view.itemOf(node)
		if !ok {
			return nil, fmt.Errorf("%w: its same_as node is not held", ErrSessionContinueUnheld)
		}
		entry := sessionContinueEntryOf(itemNode.Body.GetItem())
		if entry == nil {
			return nil, fmt.Errorf("%w: a node that is no Harness entry", ErrSessionContinueRefused)
		}
		if message := entry.Message(); message != nil && message.Role() == HarnessPiRoleAssistant &&
			(message.StopReason() == HarnessPiStopError || message.StopReason() == HarnessPiStopAborted) {
			continue
		}
		return node, nil
	}
	return nil, fmt.Errorf("%w: the run holds no node here", ErrSessionContinueUnheld)
}

// The path from start to its root, root first, crossing into another run where a parent link does (each read once
// through open), cut above the first node not held; whether it was cut.
func (self *SessionContinue) walk(ctx context.Context, view *SessionRunView, start *SessionReadNode, open func(runId Id) (*SessionRunView, error)) ([]*sessionContinueNode, bool, error) {
	type visit struct {
		runId  Id
		nodeId Id
	}
	visited := map[visit]bool{}
	path := []*sessionContinueNode{}
	cut := false
	node := start
	for {
		nodeId, _ := node.NodeId()
		if visited[visit{runId: view.RunId, nodeId: nodeId}] {
			return nil, false, fmt.Errorf("%w: the path comes back on itself", ErrSessionContinueRefused)
		}
		visited[visit{runId: view.RunId, nodeId: nodeId}] = true
		if node.Invalid != nil {
			return nil, false, fmt.Errorf("%w: %v", ErrSessionContinueRefused, node.Invalid)
		}
		itemNode, ok := view.itemOf(node)
		if !ok {
			// a same_as node whose item is not held: the path is cut here
			cut = true
			break
		}
		path = append(path, &sessionContinueNode{runId: view.RunId, read: node, itemNode: itemNode})
		parentId := node.Body.GetParentNodeId()
		if len(parentId) == 0 {
			break
		}
		if parentRunId := node.Body.GetParentRunId(); len(parentRunId) != 0 {
			other, err := open(recordIdOf(parentRunId))
			if err != nil {
				if errors.Is(err, ErrSessionRunUnknown) {
					cut = true
					break
				}
				return nil, false, err
			}
			view = other
		}
		parent, ok := view.Node(recordIdOf(parentId))
		if !ok {
			if slices.ContainsFunc(view.Nodes, func(read *SessionReadNode) bool {
				readId, held := read.NodeId()
				return held && read.Invalid != nil && readId == recordIdOf(parentId)
			}) {
				// a parent that failed the reader's checks, alarmed already: nothing continues from it
				return nil, false, fmt.Errorf("%w: a node of the path failed its checks", ErrSessionContinueRefused)
			}
			// erased, withheld or dropped: unverifiable from here up
			cut = true
			break
		}
		node = parent
	}
	slices.Reverse(path)
	return path, cut, ctx.Err()
}

// Each path node's entry: its item with its parts put back, a part not held as its marker; its trust read and taken
// out of the entry, which the renderer stamps again from the node; its parent the node before it on the path, none at
// the top.
func sessionContinueEntries(path []*sessionContinueNode) error {
	for i, node := range path {
		body := node.itemNode.Body
		partBytes := map[string][]byte{}
		for _, part := range body.GetParts() {
			if held, ok := node.itemNode.PartBytes[part.GetPointer()]; ok {
				partBytes[part.GetPointer()] = held
				continue
			}
			partBytes[part.GetPointer()] = []byte(SessionPartMarker(part))
			if !part.GetOmitted() {
				node.pruned = append(node.pruned, part)
			}
		}
		item, err := SessionItemRestore(body.GetItem(), body.GetParts(), partBytes)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrSessionContinueRefused, err)
		}
		entry := sessionContinueEntryOf(item)
		if entry == nil {
			return fmt.Errorf("%w: a node that is no Harness entry (a gateway's tree continues from CTXH-M12-01)", ErrSessionContinueRefused)
		}
		node.untrusted, node.sender = sessionHarnessEntryTrust(entry)
		entry.object.remove(sessionHarnessUntrustedMember)
		if i == 0 {
			entry.object.setRaw("parentId", json.RawMessage("null"))
		} else {
			entry.object.set("parentId", path[i-1].key)
		}
		node.entry = entry
		node.key = entry.Id()
	}
	return nil
}

// The context the new run takes: harness-1's of the path, its system messages and the messages from its newest
// compaction on, by the nodes they are.
func sessionContinueContext(path []*sessionContinueNode) ([]*sessionContinueNode, []*sessionContinueNode, error) {
	renderer, err := SessionRendererOf(SessionRendererHarness1)
	if err != nil {
		return nil, nil, err
	}
	renderPath := []*SessionRenderNode{}
	byId := map[Id]*sessionContinueNode{}
	for _, node := range path {
		nodeId, _ := node.read.NodeId()
		renderPath = append(renderPath, &SessionRenderNode{NodeId: nodeId, Type: SessionNodeType(node.read.Body.GetType()),
			Item: node.itemNode.Body.GetItem(), Parts: node.itemNode.Body.GetParts()})
		byId[nodeId] = node
	}
	input, err := renderer.Context(renderPath, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSessionContinueRefused, err)
	}
	system := []*sessionContinueNode{}
	for _, node := range input.System {
		system = append(system, byId[node.NodeId])
	}
	messages := []*sessionContinueNode{}
	for _, node := range input.Nodes {
		messages = append(messages, byId[node.NodeId])
	}
	return system, messages, nil
}

// The model a path runs on at its end: its newest model_change's, else its last call's params' model, else "".
func sessionContinueModel(view *SessionRunView, path []*sessionContinueNode) string {
	for i := len(path) - 1; 0 <= i; i -= 1 {
		entry := path[i].entry
		if entry.Type() != HarnessPiEntryModelChange {
			continue
		}
		model := ""
		if entry.object.decode("modelId", &model) && model != "" {
			return model
		}
	}
	for i := len(view.Calls) - 1; 0 <= i; i -= 1 {
		call := view.Calls[i]
		if call.Body == nil || call.Body.GetContext() == nil {
			continue
		}
		params := struct {
			Model string `json:"model"`
		}{}
		if json.Unmarshal(call.Body.GetContext().GetParams(), &params) == nil && params.Model != "" {
			return params.Model
		}
	}
	return ""
}

// The run's agent, from its session entries' headers: the agent its writer filed them under.
func (self *SessionContinue) agentOf(view *SessionRunView, writerId Id) Id {
	for _, node := range view.Nodes {
		if node.WriterSidecarId != writerId {
			continue
		}
		if entry, ok := self.reader.record.reader.Entry(view.LogId, node.EntryId); ok {
			if agentId := entry.Header.Header.GetAgentId(); len(agentId) == len(Id{}) {
				return recordIdOf(agentId)
			}
		}
	}
	return Id{}
}

// Whether the run is live, and its state: its agent running in this Harness, else its status (SessionRunLiveness).
func (self *SessionContinue) liveness(ctx context.Context, agentId Id, runId Id) (AgentState, error) {
	if self.harness != nil {
		for _, agent := range self.harness.Agents() {
			if agent.Run().Id() == runId && agent.Running() {
				return AgentStateWorking, nil
			}
		}
	}
	if self.live == nil {
		return "", errors.New("no agent status is read on this device")
	}
	if agentId == (Id{}) {
		// a run filed under no agent has no status to show it live
		return "", nil
	}
	return self.live.RunState(ctx, agentId, runId)
}

// Plans spec: see the file header. Nothing is started.
func (self *SessionContinue) plan(ctx context.Context, spec *SessionContinueSpec) (*sessionContinueWork, error) {
	if spec == nil || spec.RunId == (Id{}) {
		return nil, fmt.Errorf("%w: no run", ErrSessionContinueInvalid)
	}
	if spec.Enclave != "" {
		return nil, ErrSessionContinueEnclave
	}
	act, err := spec.act()
	if err != nil {
		return nil, err
	}
	if act == SessionContinueActFork && spec.At == "" {
		return nil, fmt.Errorf("%w: a fork names the node it forks at", ErrSessionContinueInvalid)
	}
	vaultId, err := self.reader.VaultId()
	if err != nil {
		return nil, err
	}
	views := map[Id]*SessionRunView{}
	open := func(runId Id) (*SessionRunView, error) {
		if view, ok := views[runId]; ok {
			return view, nil
		}
		view, err := self.reader.Open(ctx, vaultId, runId)
		if err != nil {
			return nil, err
		}
		views[runId] = view
		return view, nil
	}
	view, err := open(spec.RunId)
	if err != nil {
		return nil, err
	}
	tip, tipErr := sessionContinueTip(view)
	var start *SessionReadNode
	switch {
	case spec.At != "":
		if start, err = self.nodeNamed(view, spec.At); err != nil {
			return nil, err
		}
		if act != SessionContinueActFork {
			if tipErr != nil {
				return nil, tipErr
			}
			if start != tip {
				return nil, fmt.Errorf("%w: %s takes the run's tip; fork any other node", ErrSessionContinueInvalid, act)
			}
		}
	case tipErr != nil:
		return nil, tipErr
	default:
		start = tip
	}
	path, cut, err := self.walk(ctx, view, start, open)
	if err != nil {
		return nil, err
	}
	if len(path) == 0 {
		return nil, fmt.Errorf("%w: the node's item is not held", ErrSessionContinueUnheld)
	}
	if err := sessionContinueEntries(path); err != nil {
		return nil, err
	}
	system, messages, err := sessionContinueContext(path)
	if err != nil {
		return nil, err
	}
	startNodeId, _ := start.NodeId()
	writerId := sessionRunWriter(view)
	plan := &SessionContinuePlan{
		RunId: spec.RunId, Act: act, NodeId: startNodeId, EntryId: start.EntryId, WriterSidecarId: writerId,
		AgentId: self.agentOf(view, writerId), Cut: cut,
	}
	work := &sessionContinueWork{plan: plan, path: path, tip: path[len(path)-1]}
	marks := uint32(0)
	for _, node := range append(slices.Clone(system), messages...) {
		if node == nil {
			continue
		}
		work.context = append(work.context, node)
		plan.NodeCount += 1
		if node.read.Flagged {
			plan.FlaggedCount += 1
		}
		if node.read.Untrusted || node.untrusted {
			plan.UntrustedCount += 1
		}
		marks |= node.read.Body.GetMarks() | node.itemNode.Body.GetMarks()
		plan.PrunedPartCount += len(node.pruned)
	}
	plan.Tainted = 0 < plan.FlaggedCount || 0 < plan.UntrustedCount
	plan.Private = marks&uint32(HarnessMarkPrivate) != 0
	plan.LimitedUse = marks&uint32(HarnessMarkLimitedUse) != 0
	previous := sessionContinueModel(view, path)
	plan.Model = spec.Model
	if plan.Model == "" {
		plan.Model = previous
	}
	if plan.Model == "" {
		return nil, fmt.Errorf("%w: the run names no model, so name one", ErrSessionContinueInvalid)
	}
	if previous != "" && previous != plan.Model {
		plan.PreviousModel = previous
	}
	if self.harness != nil && previous != "" {
		if catalog, err := self.harness.router.Catalog(ctx); err == nil {
			_, err := catalog.Resolve(previous, "")
			plan.PreviousModelHere = err == nil
		}
	}
	if act == SessionContinueActContinue {
		state, err := self.liveness(ctx, plan.AgentId, spec.RunId)
		switch {
		case err != nil:
			work.liveErr = err
			plan.LiveUnknown = err.Error()
		case SessionAgentStateLive(state):
			plan.Live = true
			plan.LiveState = state
		}
	}
	return work, nil
}

// What continuing spec would take: T10's preview. Nothing is started or sent.
func (self *SessionContinue) Plan(ctx context.Context, spec *SessionContinueSpec) (*SessionContinuePlan, error) {
	work, err := self.plan(ctx, spec)
	if err != nil {
		return nil, err
	}
	return work.plan, nil
}

// Continues or forks spec's run in this device's Harness (see the file header), answering the new agent and its run.
func (self *SessionContinue) Continue(ctx context.Context, spec *SessionContinueSpec) (*SessionContinued, error) {
	if self.harness == nil {
		return nil, ErrHarnessJournalUnavailable
	}
	work, err := self.plan(ctx, spec)
	if err != nil {
		return nil, err
	}
	plan := work.plan
	if plan.Act == SessionContinueActContinue {
		switch {
		case work.liveErr != nil:
			return nil, fmt.Errorf("%w: its agent's status could not be read: %v", ErrSessionContinueLive, work.liveErr)
		case plan.Live:
			return nil, fmt.Errorf("%w: its agent is %s", ErrSessionContinueLive, plan.LiveState)
		}
	}
	adopter, ok := self.harness.journal.(harnessJournalAdopter)
	if !ok {
		return nil, fmt.Errorf("%w: this Harness's journal renders no other run's nodes", ErrHarnessJournalUnwired)
	}
	if err := adopter.adopt(work.path); err != nil {
		return nil, err
	}
	continuation := &HarnessContinuation{
		ParentRunId: work.tip.runId, ParentNodeId: work.tip.key, PreviousModel: plan.PreviousModel,
	}
	for _, node := range work.context {
		if message := node.entry.Message(); message != nil && message.Role() == HarnessPiRoleSystem {
			continue
		}
		continuation.Nodes = append(continuation.Nodes, node.entry.Clone())
	}
	if plan.Tainted {
		continuation.TaintReasons = []RunTaintReason{RunTaintInherited}
	}
	if plan.Private {
		continuation.Marks |= HarnessMarkPrivate
	}
	if plan.LimitedUse {
		continuation.Marks |= HarnessMarkLimitedUse
	}
	agent, err := self.harness.Continue(ctx, &HarnessAgentSpec{Name: spec.Name, Model: plan.Model, Profile: HarnessProfileLocal}, continuation)
	if err != nil {
		return nil, err
	}
	if recorder := adopter.continuationRecorder(); recorder != nil {
		recorder.continued(ctx, agent.Run().Id(), agent.Id(), plan.Model, plan.RunId, plan.EntryId)
	}
	return &SessionContinued{Plan: plan, AgentId: agent.Id(), Name: agent.Name(), NewRunId: agent.Run().Id()}, nil
}

// A Harness journal that renders another run's nodes once it holds them: the session journal's.
type harnessJournalAdopter interface {
	adopt(path []*sessionContinueNode) error
	continuationRecorder() *harnessRecorder
}

var _ harnessJournalAdopter = (*harnessSessionJournal)(nil)

// Takes a continuation's path into the journal, so the new run's renders cross into it: each node as read, its entry
// and its recorded item, parts and chain, held in memory for the process's life. A node the journal holds already
// stays as it is. A part not held is held as omitted, so a call that carries its marker reads inexact, its reference
// in request_sha256 unchanged.
func (self *harnessSessionJournal) adopt(path []*sessionContinueNode) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, node := range path {
		nodeId, ok := node.read.NodeId()
		if !ok {
			return fmt.Errorf("%w: a node not held", ErrSessionContinueRefused)
		}
		sessionRun, ok := self.runs[node.runId]
		if !ok {
			sessionRun = &harnessSessionRun{keyNodes: map[string]*harnessSessionNode{}}
			self.runs[node.runId] = sessionRun
		}
		if _, held := sessionRun.keyNodes[node.key]; held {
			continue
		}
		body := node.read.Body
		parts := []*protocol.SessionPart{}
		for _, part := range node.itemNode.Body.GetParts() {
			if slices.Contains(node.pruned, part) {
				part = &protocol.SessionPart{Pointer: part.GetPointer(), Sha256: part.GetSha256(), Size: part.GetSize(),
					MediaType: part.GetMediaType(), Omitted: true}
			}
			parts = append(parts, part)
		}
		journaled := &SessionJournaled{
			Key: node.key, NodeId: nodeId, Item: node.itemNode.Body.GetItem(), Parts: parts,
			Redactions: int(body.GetRedactions()), Stubs: int(body.GetStubs()),
		}
		copy(journaled.ItemSha256[:], body.GetItemSha256())
		copy(journaled.ChainSha256[:], body.GetChainSha256())
		sessionRun.keyNodes[node.key] = &harnessSessionNode{
			node: &HarnessJournalNode{RunId: node.runId, Entry: node.entry, Tainted: node.read.Flagged, Marks: HarnessMark(body.GetMarks()),
				Untrusted: node.untrusted, Sender: node.sender},
			journaled: journaled,
		}
	}
	return nil
}

// The node of key in run as this journal holds it, its own or adopted.
func (self *harnessSessionJournal) heldNode(runId Id, key string) (*harnessSessionNode, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if sessionRun, ok := self.runs[runId]; ok {
		node, ok := sessionRun.keyNodes[key]
		return node, ok
	}
	return nil, false
}

// The recorder that writes the continuation's stage-2 context, nil for none.
func (self *harnessSessionJournal) continuationRecorder() *harnessRecorder {
	return self.recorder
}

// Writes a continuation's stage-2 context entry: the run it continues and the session_entry of the node it hangs from
// (RECORD.md section 4.3 as Appendix D amends it), at its start, so an erasure of that run finds it.
func (self *harnessRecorder) continued(ctx context.Context, runId Id, agentId Id, model string, continuesRunId Id, continuesEntryId Id) {
	label, _ := self.agentOf(agentId)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	run := self.runWithLock(runId, agentId)
	if run.model == "" {
		run.model = model
	}
	self.append(ctx, runId, run, &RecordDraft{Kind: RecordKindContext, Body: &protocol.ContextBody{
		Stage: 2, Harness: harnessRecordHarness, HarnessVersion: self.args.Version, AgentLabel: label, Model: run.model,
		ContinuesRunId: continuesRunId.Bytes(), ContinuesEntryId: continuesEntryId.Bytes(),
	}})
}

// What a host that builds its own Harness over a session journal wires (an app's test host, a test): the Harness's
// context journal over the session journal and harness-1, as a Sidecar's Harness has it (harness_record.go), its
// recorder writing the run's own entries, the observer the Harness hands its events to, and Bind, called with the
// Harness once it is built.
type SessionHarnessSources struct {
	Journal  HarnessContextJournal
	Observer func(agentId Id, event *HarnessEvent)
	Bind     func(harness *Harness)
}

// What NewSessionHarnessSources builds on.
type SessionHarnessSourcesArgs struct {
	Journal *SessionJournal
	// The record the recorder writes the run's context, tool_call, model_call, coverage and cost entries to; nil writes
	// none.
	Writer RecordWriter
	// The capture redactor the recorder's prompts pass; nil leaves them as they are.
	Redactor *Redactor
	Runs     HarnessRunStore
	Version  string
	Clock    Clock
	// The catalog a model_call's entry is read from; nil records no model call.
	Catalog func(ctx context.Context) (*InferCatalog, error)
}

// The Harness sources over args.
func NewSessionHarnessSources(args *SessionHarnessSourcesArgs) *SessionHarnessSources {
	journal := newHarnessSessionJournal(func() (harnessSessionStore, error) {
		if args.Journal == nil {
			return nil, ErrHarnessJournalUnwired
		}
		return args.Journal, nil
	})
	recorderArgs := &harnessRecorderArgs{Runs: args.Runs, Version: args.Version, Clock: args.Clock, Catalog: args.Catalog}
	if args.Writer != nil {
		recorderArgs.Writer = func() (RecordWriter, error) {
			return args.Writer, nil
		}
	}
	if args.Redactor != nil {
		recorderArgs.Redactor = func() (*Redactor, error) {
			return args.Redactor, nil
		}
	}
	newHarnessRecorder(recorderArgs, journal)
	return &SessionHarnessSources{Journal: journal, Observer: journal.observe, Bind: journal.bind}
}

// A Sidecar's agent status as liveness reads it: the run's agent's card in the member's agents repo and its status.
type sidecarSessionLiveness struct {
	sidecar *Sidecar
}

// The state of agentId's status where it is of runId; empty where the agent holds no card or no status, or its status
// is of another run.
func (self *sidecarSessionLiveness) RunState(ctx context.Context, agentId Id, runId Id) (AgentState, error) {
	client, err := self.sidecar.AgentsClient()
	if err != nil {
		return "", err
	}
	cards, err := client.Cards(ctx, false)
	if err != nil {
		return "", err
	}
	for _, card := range cards {
		if card == nil || card.AgentCardRead == nil || card.Card == nil || card.Card.AgentId != agentId {
			continue
		}
		status, err := client.Status(ctx, card.Card.Name)
		if err != nil {
			return "", err
		}
		if status.Status == nil || (status.Status.RunId != (Id{}) && status.Status.RunId != runId) {
			return "", nil
		}
		return status.State, nil
	}
	return "", nil
}

// This Sidecar's continuer: its record's session reader, its Harness, and its agents' status. An error where the
// record or the Harness is not there yet.
func (self *Sidecar) SessionContinue() (*SessionContinue, error) {
	record, err := self.Record()
	if err != nil {
		return nil, err
	}
	harness, err := self.Harness()
	if err != nil {
		return nil, err
	}
	return NewSessionContinue(&SessionContinueArgs{
		Reader: record.SessionReader(), Harness: harness, Live: &sidecarSessionLiveness{sidecar: self}, Settings: self.settings.Session,
	})
}
