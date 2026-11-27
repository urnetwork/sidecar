//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.8's recording of the gateway's calls (CTXH-M12-01; R-CTXH-5, R-CTXH-6, D-CTXH-2, D-CTXH-6, D-CTXH-9,
// IC-19, CF-3; Q-CTXH-6, Q-CTXH-9): each call's request and response as session entries of the run its binding names,
// written through the session journal at IC-19's two points and deduplicated against what the run holds. GW calls it
// (§8.9, GW-M12-06): Begin before the call goes upstream, ResponseItem as each response item completes, End for the
// call's model_call.
//
//	items      a request's instructions or system text and its tools as one system node; its input items in order;
//	           each response item as GW hands it on completing it; each in its recorded form: the front's item as a
//	           later request carries it back (session_gateway_items.go), then §24.9's exceptions, the journal's
//	           redaction among them
//	system     a system node is a root of its run, outside the chain, so a tool that appears mid-session does not
//	           break matching; a system item the run holds already is that node again
//	binding    a call with a run handle records into the run §8.9 names, under the taint the router checked, which
//	           the run takes write-ahead before anything is journaled; a call with none records into the run GW keeps
//	           the grant's unbound calls in, the run tainted first whatever the union's taint, so every entry of it is
//	           flagged and read untrusted to continue, fork and record_query (D-CTXH-9;
//	           ctxh-m12-01-unbound-call-untrusted-flag)
//	match      chain_sha256 over the recorded input items: the longest prefix the run holds, or a run it continues, is
//	           the parent, so a harness's rewrite of its context branches at its first changed item, and only the items
//	           after the prefix are journaled, one the run holds elsewhere as a same_as node; a request sharing no
//	           prefix starts a tree of its own: a side request, a sub-agent, a compaction with its summary first
//	resume     the runs the binding names as resumed, by RECORD.md section 4.3 or the harness's own report of a resume
//	           or fork, are searched too, and the first new node hangs from the node found there by a parent link,
//	           never its bytes; the request's last item is always the call's own run's, so its context starts there.
//	           With no such run named two sessions of one grant share nothing, whatever their bytes
//	order      Begin returns once the request's new items are durable in the journal, before the call goes upstream;
//	           ResponseItem once its item is, before GW sends the event that completes it (response.output_item.done,
//	           the chunk carrying finish_reason), so a tool the harness starts on it finds it journaled. A join of a
//	           call in flight or an answer from a kept response calls nothing here; a cut call's retry Begins again
//	           and lands on the same context node
//	end        End gives GW the CallContext for the call's model_call: its input, output and system nodes, params,
//	           exact where nothing in the request was redacted, stubbed or kept by hash alone, and request_sha256 by
//	           the renderer GW names where this build holds it (session_render.go); a renderer it does not hold
//	           records none, so a rebuild reads the call unverifiable, never verified, and never alarms on it
//	coverage   a run the gateway recorded a call in has source gateway (Recorded); a hook's or telemetry's model_call
//	           whose request id no call here answered counts the run's gap context_partial (HookModelCall), and the
//	           harness it came from is named until the window passes, for ur status (Q-CTXH-14)
//
// Nothing here is read back to answer a call (D-GW-2), the recorder sees no token, and only sealed entries and the
// index's hashes and ids reach disk. Hooks, telemetry and transcripts stay as DESIGN §16.7 has them beside it
// (Q-CTXH-6).
//
// Safe for concurrent use: the calls of one run are taken one at a time, under that run's lock.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// The journal keys of the gateway's nodes, a format value of the journal's state: a chain node's and a system node's.
const (
	sessionGatewayChainKeyPrefix  = "c"
	sessionGatewaySystemKeyPrefix = "s"
)

// The component's name, and its sealed directory's.
const sessionGatewayComponentName = "session_gateway"

var (
	// A call taken out of order: a response item after End, End twice.
	ErrSessionGatewayCallEnded = errors.New("session gateway call ended")
	// The call has no request_sha256: the renderer GW names is not one this build holds, or it did not render.
	ErrSessionGatewayUnrendered = errors.New("session gateway call unrendered")
)

// What the recorder needs of the network's runs: the record's writer seals each entry's tainted bit from the run's
// taint, so the recorder taints the run, write-ahead, before it journals anything a tainted binding gives.
type SessionGatewayRuns interface {
	// Whether the run reads tainted now, failing closed.
	RunTainted(runId Id) bool
	// Taints the run for good, fsynced before it returns.
	TaintRun(ctx context.Context, runId Id, reason RunTaintReason) error
}

// A gateway call's binding as GW's run handle gives it (§8.9).
type SessionGatewayBinding struct {
	// The run the call records into: the run of the token's harness process §8.9 names, or for an unbound token the
	// run GW keeps the grant's unbound calls in, by harness, agent and time.
	RunId   Id
	AgentId *Id
	// The grant the token belongs to (§8.6).
	GrantId Id
	// The run handle's key, InferBinding.Handle; empty for an unbound token, whose binding is inferred.
	Handle string
	// The taint the router checked the call against: the shared taint of the harness process's runs, or for an
	// unbound token the OR of every run of the grant's live harness processes, failing closed.
	Tainted bool
	// The marks it checked: bit 0 limited_use, bit 1 private (HarnessMark's bits).
	Marks uint32
	// Earlier runs of the same grant this session may take its parent from: the run RECORD.md section 4.3 binds the
	// session to, or the runs the harness reported it resumes or forks. Empty: none, whatever the bytes.
	Resumes []Id
}

// Whether the binding is inferred: no run handle names the call's process.
func (self *SessionGatewayBinding) Inferred() bool {
	return self.Handle == ""
}

// A request as GW hands it to Begin.
type SessionGatewayRequest struct {
	Api SessionGatewayApi
	// The renderer GW's translation registers for the front (gateway-<api>-<version>), which the call's CallContext
	// names and a rebuild runs.
	Renderer string
	// The request body as the harness sent it.
	Body []byte
}

// What a SessionGatewayRecorder runs on.
type SessionGatewayRecorderArgs struct {
	Journal *SessionJournal
	Runs    SessionGatewayRuns
	// The recorder's sealed directory, which holds its index.
	Store SidecarStore
	// The index over Store, where the caller holds one already; nil builds it.
	Index *SessionGatewayIndex
	// The journal's when nil.
	Settings *SessionSettings
	Clock    Clock
	// Counts a coverage gap against a run (RunStore.AddGap): context_partial; nil drops it.
	Gap func(runId Id, code string)
}

// A harness whose model calls the gateway did not see (Q-CTXH-14): ur status names it with the command that sets it to
// the gateway.
type SessionGatewayPartial struct {
	Harness string `json:"harness"`
	// The newest of its runs a call was missed in, and when.
	RunId  Id    `json:"run_id"`
	Millis int64 `json:"millis"`
}

// The gateway's recorder. See the file header.
type SessionGatewayRecorder struct {
	journal  *SessionJournal
	index    *SessionGatewayIndex
	runs     SessionGatewayRuns
	settings *SessionSettings
	clock    Clock
	gap      func(runId Id, code string)

	stateLock  sync.Mutex
	runIdLocks map[Id]*sync.Mutex
	partials   map[string]*SessionGatewayPartial
}

// One item in its recorded form (session_gateway_index.go's forms row).
type sessionGatewayForm struct {
	// SHA-256 of raw: the form's key
	rawSha256 [sha256.Size]byte
	// the item as the journal takes it: the front's item as a later request carries it, before the exceptions
	raw []byte
	// the item as recorded: RFC 8785, after the exceptions, its parts by reference
	item       []byte
	itemSha256 [sha256.Size]byte
	parts      []*protocol.SessionPart
	redactions int
	stubs      int
}

// A recorder over args.
func NewSessionGatewayRecorder(args *SessionGatewayRecorderArgs) (*SessionGatewayRecorder, error) {
	if args == nil || args.Journal == nil || args.Runs == nil || (args.Store == nil && args.Index == nil) {
		return nil, fmt.Errorf("%w: a recorder needs its journal, runs and store", ErrSessionGatewayRefused)
	}
	settings := args.Settings
	if settings == nil {
		settings = args.Journal.settings
	}
	index := args.Index
	if index == nil {
		built, err := NewSessionGatewayIndex(args.Store, settings, args.Clock)
		if err != nil {
			return nil, err
		}
		index = built
	}
	return &SessionGatewayRecorder{
		journal:    args.Journal,
		index:      index,
		runs:       args.Runs,
		settings:   settings,
		clock:      clockOrReal(args.Clock),
		gap:        args.Gap,
		runIdLocks: map[Id]*sync.Mutex{},
		partials:   map[string]*SessionGatewayPartial{},
	}, nil
}

// The index the recorder keeps.
func (self *SessionGatewayRecorder) Index() *SessionGatewayIndex {
	return self.index
}

// The lock of one run's calls.
func (self *SessionGatewayRecorder) runLock(runId Id) *sync.Mutex {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lock, ok := self.runIdLocks[runId]
	if !ok {
		lock = &sync.Mutex{}
		self.runIdLocks[runId] = lock
	}
	return lock
}

// A chain node's journal key.
func sessionGatewayChainKey(chainSha256 [sha256.Size]byte) string {
	return sessionGatewayChainKeyPrefix + hex.EncodeToString(chainSha256[:])
}

// A system node's journal key.
func sessionGatewaySystemKey(chainSha256 [sha256.Size]byte) string {
	return sessionGatewaySystemKeyPrefix + hex.EncodeToString(chainSha256[:])
}

// The recorded form of object, an item of runId: the index's where it keeps one, else made now. stubs counts what the
// caller stubbed in object before (CTXH-M13-01's search stubs).
func (self *SessionGatewayRecorder) formOf(runId Id, grantId Id, object map[string]any, stubs int) (*sessionGatewayForm, error) {
	raw, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionGatewayRefused, err)
	}
	rawSha256 := sha256.Sum256(raw)
	if form := self.index.form(runId, rawSha256); form != nil && form.stubs == stubs {
		return form, nil
	}
	value, err := sessionDecodeJson(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionGatewayRefused, err)
	}
	// the journal's own exceptions and cut, which it runs again on raw as it journals a new node; a node found by its
	// chain hash was recorded with this very item, or its hash would differ
	value, counts, err := sessionApplyExceptions(value, nil, self.journal.redactor)
	if err != nil {
		return nil, err
	}
	item, cuts, err := sessionCutParts(value, self.settings.body(), func(size uint64) bool { return true })
	if err != nil {
		return nil, err
	}
	form := &sessionGatewayForm{
		rawSha256:  rawSha256,
		raw:        raw,
		item:       item,
		itemSha256: sessionItemSha256(item),
		redactions: counts.redactions,
		stubs:      counts.stubs + stubs,
	}
	for _, cut := range cuts {
		form.parts = append(form.parts, cut.part)
	}
	self.index.keepForm(runId, grantId, form)
	return form, nil
}

// Counts a gap against the run.
func (self *SessionGatewayRecorder) countGap(runId Id, code string) {
	if self.gap != nil {
		self.gap(runId, code)
	}
}

// One node of a call: where it is, its chain hash, its recorded form and whether the record keeps it as it was sent.
type sessionGatewayCallNode struct {
	runId       Id
	nodeId      Id
	chainSha256 [sha256.Size]byte
	form        *sessionGatewayForm
	// a part kept by hash alone, or a node the index does not know, whose exactness is unknown
	inexact bool
}

// The run and session_entry a call's first new node hangs from in another run: RECORD.md section 4.3's
// continues_run_id and continues_entry_id, which the run's stage-2 context entry names, as Appendix D amends it.
type SessionGatewayContinues struct {
	RunId  Id
	NodeId Id
	// The node's session_entry, nil where the index does not hold it.
	EntryId *Id
}

// What End gives GW.
type SessionGatewayEnded struct {
	// ModelCallBody.context for the call's model_call (§6.8).
	Context *protocol.CallContext
	// Where the call's first new node hangs from another run, nil for none.
	Continues *SessionGatewayContinues
	// Why Context names no renderer and no request_sha256, nil where it names both: a rebuild reads such a call
	// unverifiable. Context is whole either way.
	Unrendered error
}

// What End takes.
type SessionGatewayEnd struct {
	// The provider's request id the call's model_call names, by which a hook's model_call for the same call merges
	// with the gateway's (§8.9); empty for none.
	RequestId string
}

// One call being recorded: Begin's answer, which GW calls at each response item and once at the end. Safe for
// concurrent use, its steps taken one at a time under its run's lock.
type SessionGatewayCall struct {
	recorder *SessionGatewayRecorder
	binding  SessionGatewayBinding
	run      *SessionRun
	api      SessionGatewayApi
	renderer string

	params         []byte
	paramsRedacted bool
	system         *sessionGatewayCallNode
	inputs         []*sessionGatewayCallNode
	outputs        []*sessionGatewayCallNode
	continues      *SessionGatewayContinues
	// what the call added to the index, written at End
	addedChain  map[[sha256.Size]byte]*sessionGatewayIndexNode
	addedSystem map[[sha256.Size]byte]*sessionGatewayIndexNode
	// a node the journal recorded in another form than the recorder's, by a redactor key turned between them
	formMismatch bool
	ended        bool
}

// Records a request's new items before the call goes upstream (see the file header's binding, match, resume and
// order rows): answers once every item it journaled is durable. An error journals the call's context only in part,
// and GW does not make the call (IC-19).
func (self *SessionGatewayRecorder) Begin(ctx context.Context, binding *SessionGatewayBinding, request *SessionGatewayRequest) (*SessionGatewayCall, error) {
	if binding == nil || binding.RunId == (Id{}) || binding.GrantId == (Id{}) {
		return nil, fmt.Errorf("%w: a call with no run or grant", ErrSessionGatewayRefused)
	}
	if request == nil {
		return nil, fmt.Errorf("%w: no request", ErrSessionGatewayRefused)
	}
	items, err := sessionGatewayItemsOf(request.Api, request.Body)
	if err != nil {
		return nil, err
	}
	if err := self.index.load(); err != nil {
		return nil, err
	}
	// a run past the window leaves the index here; a failed removal is tried again at the next call
	_ = self.index.Sweep()
	if grantId, ok := self.index.grantOf(binding.RunId); ok && grantId != binding.GrantId {
		return nil, fmt.Errorf("%w: run %s is another grant's", ErrSessionGatewayRefused, binding.RunId)
	}
	lock := self.runLock(binding.RunId)
	lock.Lock()
	defer lock.Unlock()

	// taint before data (D-MCP-16): the entries' headers read the run's taint as they seal
	if binding.Tainted {
		if err := self.runs.TaintRun(ctx, binding.RunId, RunTaintInherited); err != nil {
			return nil, err
		}
	}
	if binding.Inferred() {
		if err := self.runs.TaintRun(ctx, binding.RunId, RunTaintUntrustedData); err != nil {
			return nil, err
		}
	}
	call := &SessionGatewayCall{
		recorder: self,
		binding:  *binding,
		run: &SessionRun{
			RunId: binding.RunId, AgentId: binding.AgentId, Tainted: binding.Tainted || binding.Inferred(), Marks: binding.Marks,
		},
		api:         request.Api,
		renderer:    request.Renderer,
		addedChain:  map[[sha256.Size]byte]*sessionGatewayIndexNode{},
		addedSystem: map[[sha256.Size]byte]*sessionGatewayIndexNode{},
	}
	call.binding.Resumes = slices.Clone(binding.Resumes)
	if err := call.takeParams(items.params); err != nil {
		return nil, err
	}
	if items.system != nil {
		if err := call.takeSystem(ctx, items.system); err != nil {
			return nil, err
		}
	}
	if err := call.takeInput(ctx, items.input); err != nil {
		return nil, err
	}
	return call, nil
}

// The request's params, RFC 8785, every string redacted under the secret rules: a match makes the call inexact.
func (self *SessionGatewayCall) takeParams(params map[string]any) error {
	encoded, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSessionGatewayRefused, err)
	}
	value, err := sessionDecodeJson(encoded)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSessionGatewayRefused, err)
	}
	redacted, matches := sessionRedactStrings(value, self.recorder.journal.redactor)
	canonical, err := sessionCanonical(redacted)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSessionGatewayRefused, err)
	}
	self.params = canonical
	self.paramsRedacted = 0 < matches
	return nil
}

// The request's system node: the run's own where it holds this system item, else journaled now as a root.
func (self *SessionGatewayCall) takeSystem(ctx context.Context, system map[string]any) error {
	recorder := self.recorder
	runId := self.binding.RunId
	form, err := recorder.formOf(runId, self.binding.GrantId, system, 0)
	if err != nil {
		return err
	}
	chainSha256 := sessionChainSha256(nil, form.itemSha256[:])
	key := sessionGatewaySystemKey(chainSha256)
	node := &sessionGatewayCallNode{runId: runId, chainSha256: chainSha256, form: form}
	if nodeId, _, ok := recorder.journal.Node(runId, key); ok {
		node.nodeId = nodeId
		indexed := recorder.index.node(runId, chainSha256, true)
		node.inexact = indexed == nil || indexed.Omitted
		self.system = node
		return nil
	}
	journaled, err := recorder.journal.Journal(ctx, self.run, &SessionNode{
		Key: key, Type: SessionNodeMessage, Item: form.raw, FromHarness: true,
	})
	if err != nil {
		return err
	}
	written := journaled[0]
	node.nodeId = written.NodeId
	node.inexact = self.takeJournaled(node, written)
	self.added(chainSha256, true, written, node.inexact)
	self.system = node
	return nil
}

// What the index keeps of a node the journal wrote.
func sessionGatewayIndexNodeOf(written *SessionJournaled, omitted bool) *sessionGatewayIndexNode {
	indexed := &sessionGatewayIndexNode{NodeId: written.NodeId, Omitted: omitted}
	if written.Entry != nil {
		entryId := written.Entry.EntryId
		indexed.EntryId = &entryId
	}
	return indexed
}

// Checks a node the journal wrote against the recorder's form, and answers whether a part of it, or of the node its
// same_as names, was kept by hash alone, or is not known: the node then reads inexact.
func (self *SessionGatewayCall) takeJournaled(node *sessionGatewayCallNode, written *SessionJournaled) bool {
	if written.ItemSha256 != node.form.itemSha256 || written.ChainSha256 != node.chainSha256 {
		// the redactor's key turned between the form and the journal: the record holds the journal's form, which the
		// recorder's hash would not match
		self.formMismatch = true
	}
	if written.SameAs != nil {
		omitted, known := self.recorder.index.omitted(self.binding.RunId, *written.SameAs)
		return omitted || !known
	}
	return sessionPartsOmitted(written.Parts)
}

// Holds a node the call journaled: in the index's memory now, and in the segment its end writes.
func (self *SessionGatewayCall) added(chainSha256 [sha256.Size]byte, system bool, written *SessionJournaled, inexact bool) {
	indexed := sessionGatewayIndexNodeOf(written, inexact)
	if system {
		self.addedSystem[chainSha256] = indexed
	} else {
		self.addedChain[chainSha256] = indexed
	}
	self.recorder.index.note(self.binding.RunId, self.binding.GrantId, chainSha256, system, indexed)
}

// Where a chain hash's node is held: the first of runIds whose journal holds it.
func (self *SessionGatewayCall) heldIn(runIds []Id, chainSha256 [sha256.Size]byte) (Id, Id, bool) {
	key := sessionGatewayChainKey(chainSha256)
	for _, runId := range runIds {
		if nodeId, _, ok := self.recorder.journal.Node(runId, key); ok {
			return runId, nodeId, true
		}
	}
	return Id{}, Id{}, false
}

// Whether a held node reads inexact: a part kept by hash alone, or not known to the index.
func (self *SessionGatewayCall) heldInexact(runId Id, chainSha256 [sha256.Size]byte) bool {
	indexed := self.recorder.index.node(runId, chainSha256, false)
	return indexed == nil || indexed.Omitted
}

// The request's input: each item's form and chain hash, the longest prefix held, then the rest journaled after it.
func (self *SessionGatewayCall) takeInput(ctx context.Context, input []map[string]any) error {
	recorder := self.recorder
	runId := self.binding.RunId
	nodes := []*sessionGatewayCallNode{}
	var parentChain []byte
	for _, object := range input {
		form, err := recorder.formOf(runId, self.binding.GrantId, object, 0)
		if err != nil {
			return err
		}
		chainSha256 := sessionChainSha256(parentChain, form.itemSha256[:])
		nodes = append(nodes, &sessionGatewayCallNode{chainSha256: chainSha256, form: form})
		parentChain = chainSha256[:]
	}
	runIds := recorder.index.candidates(runId, self.binding.Resumes)
	held := 0
	for _, node := range nodes {
		heldRunId, nodeId, ok := self.heldIn(runIds, node.chainSha256)
		if !ok {
			break
		}
		node.runId, node.nodeId = heldRunId, nodeId
		node.inexact = self.heldInexact(heldRunId, node.chainSha256)
		held += 1
	}
	if 0 < held && held == len(nodes) && nodes[held-1].runId != runId {
		// the context's last item is the call's own run's, so its rebuild starts there: it hangs from the other run
		held -= 1
	}
	drafts := []*SessionNode{}
	for i := held; i < len(nodes); i += 1 {
		node := nodes[i]
		draft := &SessionNode{Key: sessionGatewayChainKey(node.chainSha256), Type: SessionNodeMessage, Item: node.form.raw, FromHarness: true}
		if 0 < i {
			parent := nodes[i-1]
			if i == held && parent.runId != runId {
				// a resumed session's first new node: a parent link into the earlier run, never its bytes (§24.7)
				parentRunId, parentNodeId := parent.runId, parent.nodeId
				draft.ParentRunId, draft.ParentNodeId = &parentRunId, &parentNodeId
				draft.ParentChainSha256 = parent.chainSha256[:]
				self.continues = &SessionGatewayContinues{RunId: parent.runId, NodeId: parent.nodeId}
				if indexed := recorder.index.node(parent.runId, parent.chainSha256, false); indexed != nil {
					self.continues.EntryId = indexed.EntryId
				}
			} else {
				draft.ParentKey = sessionGatewayChainKey(parent.chainSha256)
			}
		}
		drafts = append(drafts, draft)
	}
	if 0 < len(drafts) {
		journaled, err := recorder.journal.Journal(ctx, self.run, drafts...)
		if err != nil {
			return err
		}
		for i, written := range journaled {
			node := nodes[held+i]
			node.runId, node.nodeId = runId, written.NodeId
			node.inexact = self.takeJournaled(node, written)
			self.added(node.chainSha256, false, written, node.inexact)
		}
	}
	self.inputs = nodes
	return nil
}

// The node ids of the request's input items, in order: what GW holds a replayed reasoning blob's or thinking
// signature's named node to (§8.5), which matches the item that carried it back.
func (self *SessionGatewayCall) InputNodeIds() []Id {
	nodeIds := []Id{}
	for _, node := range self.inputs {
		nodeIds = append(nodeIds, node.nodeId)
	}
	return nodeIds
}

// The run each input item's node is in, in order: the call's own, or a run it continues.
func (self *SessionGatewayCall) InputRunIds() []Id {
	runIds := []Id{}
	for _, node := range self.inputs {
		runIds = append(runIds, node.runId)
	}
	return runIds
}

// The system node in force, false for a request with no system text and no tools.
func (self *SessionGatewayCall) SystemNodeId() (Id, bool) {
	if self.system == nil {
		return Id{}, false
	}
	return self.system.nodeId, true
}

// Records a response item as GW completes it, before GW sends the event that completes it (§24.5's journal first):
// answers once it is durable, with its node's id, which GW's sealed reasoning blob names (§8.5). The item is the
// front's: a Responses output item, a Chat Completions assistant message. One the run holds at this place already, a
// retry's answer that repeats an earlier one, is that node again.
func (self *SessionGatewayCall) ResponseItem(ctx context.Context, item []byte) (Id, error) {
	recorder := self.recorder
	runId := self.binding.RunId
	lock := recorder.runLock(runId)
	lock.Lock()
	defer lock.Unlock()
	if self.ended {
		return Id{}, ErrSessionGatewayCallEnded
	}
	object, err := sessionGatewayOutputOf(self.api, item, len(self.outputs) == 0)
	if err != nil {
		return Id{}, err
	}
	form, err := recorder.formOf(runId, self.binding.GrantId, object, 0)
	if err != nil {
		return Id{}, err
	}
	var parent *sessionGatewayCallNode
	switch {
	case 0 < len(self.outputs):
		parent = self.outputs[len(self.outputs)-1]
	case 0 < len(self.inputs):
		parent = self.inputs[len(self.inputs)-1]
	}
	var parentChain []byte
	if parent != nil {
		parentChain = parent.chainSha256[:]
	}
	chainSha256 := sessionChainSha256(parentChain, form.itemSha256[:])
	node := &sessionGatewayCallNode{runId: runId, chainSha256: chainSha256, form: form}
	if nodeId, _, ok := recorder.journal.Node(runId, sessionGatewayChainKey(chainSha256)); ok {
		node.nodeId = nodeId
		node.inexact = self.heldInexact(runId, chainSha256)
		self.outputs = append(self.outputs, node)
		return nodeId, nil
	}
	draft := &SessionNode{Key: sessionGatewayChainKey(chainSha256), Type: SessionNodeMessage, Item: form.raw}
	if parent != nil {
		// a response's parent is the call's own run's: the request's last item always is
		draft.ParentKey = sessionGatewayChainKey(parent.chainSha256)
	}
	journaled, err := recorder.journal.Journal(ctx, self.run, draft)
	if err != nil {
		return Id{}, err
	}
	written := journaled[0]
	node.nodeId = written.NodeId
	node.inexact = self.takeJournaled(node, written)
	self.added(chainSha256, false, written, node.inexact)
	self.outputs = append(self.outputs, node)
	return written.NodeId, nil
}

// Whether the recorded request is the one sent: nothing in its system item, its items or its params redacted or
// stubbed, no part kept by hash alone, and every node known to the index.
func (self *SessionGatewayCall) exact() bool {
	if self.paramsRedacted || self.formMismatch {
		return false
	}
	nodes := slices.Clone(self.inputs)
	if self.system != nil {
		nodes = append(nodes, self.system)
	}
	for _, node := range nodes {
		if node.inexact || 0 < node.form.redactions || 0 < node.form.stubs {
			return false
		}
	}
	return true
}

// request_sha256 by the call's renderer (session_render.go), over the request's nodes as recorded.
func (self *SessionGatewayCall) requestSha256() ([sha256.Size]byte, error) {
	if self.formMismatch {
		return [sha256.Size]byte{}, fmt.Errorf("%w: a node recorded in another form than the recorder's", ErrSessionGatewayUnrendered)
	}
	renderer, err := SessionRendererOf(self.renderer)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %w", ErrSessionGatewayUnrendered, err)
	}
	renderNodeOf := func(node *sessionGatewayCallNode) *SessionRenderNode {
		return &SessionRenderNode{NodeId: node.nodeId, Type: SessionNodeMessage, Item: node.form.item, Parts: node.form.parts}
	}
	path := []*SessionRenderNode{}
	nodeIdNodes := map[Id]*SessionRenderNode{}
	for _, node := range self.inputs {
		renderNode := renderNodeOf(node)
		path = append(path, renderNode)
		nodeIdNodes[node.nodeId] = renderNode
	}
	var systemNodeId *Id
	if self.system != nil {
		nodeId := self.system.nodeId
		systemNodeId = &nodeId
		nodeIdNodes[nodeId] = renderNodeOf(self.system)
	}
	input, err := renderer.Context(path, systemNodeId, func(nodeId Id) (*SessionRenderNode, bool) {
		node, ok := nodeIdNodes[nodeId]
		return node, ok
	})
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %w", ErrSessionGatewayUnrendered, err)
	}
	input.Params = self.params
	input.SignInWithheld = false
	requestSha256, err := SessionRequestSha256(renderer, input)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %w", ErrSessionGatewayUnrendered, err)
	}
	return requestSha256, nil
}

// Ends the call: its CallContext for GW's model_call, and its nodes and request id in the index. GW calls it for a
// call cut short too, whose output is what was journaled; a call never ended leaves its nodes in the journal, the index
// learning of them only as a later request meets them.
func (self *SessionGatewayCall) End(ctx context.Context, end *SessionGatewayEnd) (*SessionGatewayEnded, error) {
	recorder := self.recorder
	runId := self.binding.RunId
	lock := recorder.runLock(runId)
	lock.Lock()
	defer lock.Unlock()
	if self.ended {
		return nil, ErrSessionGatewayCallEnded
	}
	self.ended = true
	if end == nil {
		end = &SessionGatewayEnd{}
	}
	callContext := &protocol.CallContext{Exact: self.exact(), Params: self.params}
	if 0 < len(self.inputs) {
		callContext.InputNodeId = self.inputs[len(self.inputs)-1].nodeId.Bytes()
	}
	for _, node := range self.outputs {
		callContext.OutputNodeIds = append(callContext.OutputNodeIds, node.nodeId.Bytes())
	}
	if self.system != nil {
		callContext.SystemNodeId = self.system.nodeId.Bytes()
	}
	ended := &SessionGatewayEnded{Context: callContext, Continues: self.continues}
	if requestSha256, err := self.requestSha256(); err != nil {
		ended.Unrendered = err
	} else {
		callContext.Renderer = self.renderer
		callContext.RequestSha256 = requestSha256[:]
	}
	add := &sessionGatewayIndexAdd{
		runId: runId, grantId: self.binding.GrantId, chain: self.addedChain, system: self.addedSystem, requestId: end.RequestId,
	}
	if self.continues != nil {
		add.continues = []Id{self.continues.RunId}
	}
	if err := recorder.index.add(add); err != nil {
		return nil, err
	}
	return ended, nil
}

// A hook's or telemetry's model_call of harness in runId (DESIGN §16.7): true where a call of the gateway's answered
// requestId, so the hook's entry merges with the gateway's (§8.9, GW-M12-06's merge); false where none did, which
// counts the run's gap context_partial, the call's context being only what the transcript shows (§24.8's coverage row),
// and names the harness for ur status (Q-CTXH-14).
func (self *SessionGatewayRecorder) HookModelCall(ctx context.Context, harness string, runId Id, requestId string) (bool, error) {
	if requestId != "" {
		seen, err := self.index.RequestSeen(requestId)
		if err != nil {
			return false, err
		}
		if seen {
			return true, nil
		}
	}
	self.countGap(runId, RecordCoverageGapContextPartial)
	if harness != "" {
		nowMillis := self.clock.Now().UnixMilli()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.partials[harness] = &SessionGatewayPartial{Harness: harness, RunId: runId, Millis: nowMillis}
		}()
	}
	return false, nil
}

// The harnesses whose model calls the gateway did not see within the index's window, by name: what ur status names
// with the command that sets each to the gateway (Q-CTXH-14).
func (self *SessionGatewayRecorder) ContextPartial() []*SessionGatewayPartial {
	cutoffMillis := self.clock.Now().Add(-self.settings.GatewayIndexWindow).UnixMilli()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	partials := []*SessionGatewayPartial{}
	for _, harness := range slices.Sorted(maps.Keys(self.partials)) {
		partial := self.partials[harness]
		if partial.Millis < cutoffMillis {
			delete(self.partials, harness)
			continue
		}
		copied := *partial
		partials = append(partials, &copied)
	}
	return partials
}

// Whether the gateway recorded a call in the run within the index's window: its coverage then names source gateway.
func (self *SessionGatewayRecorder) Recorded(runId Id) (bool, error) {
	return self.index.Recorded(runId)
}

// The network's runs as the recorder takes them: RunStore's taint.
type sessionGatewayRunStore struct {
	runs *RunStore
}

// RunStore.Tainted: true for a run with no readable file.
func (self sessionGatewayRunStore) RunTainted(runId Id) bool {
	return self.runs.Tainted(runId)
}

// RunStore.Taint: fsynced before it returns.
func (self sessionGatewayRunStore) TaintRun(ctx context.Context, runId Id, reason RunTaintReason) error {
	return self.runs.Taint(ctx, runId, reason)
}

// The component: the index and the recorder once built.
type sidecarSessionGateway struct {
	sidecar *Sidecar

	stateLock sync.Mutex
	index     *SessionGatewayIndex
	recorder  *SessionGatewayRecorder
}

// Registers the component, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(sessionGatewayComponentName, func(sidecar *Sidecar) (*sidecarSessionGateway, error) {
		return &sidecarSessionGateway{sidecar: sidecar}, nil
	}, nil)
}

// The network's gateway index, built at the first call over the component's sealed directory: what a run's coverage
// reads without the journal being built.
func (self *Sidecar) sessionGatewayIndex() (*sidecarSessionGateway, *SessionGatewayIndex, error) {
	component, err := sidecarComputeComponent[sidecarSessionGateway](self, sessionGatewayComponentName)
	if err != nil {
		return nil, nil, err
	}
	component.stateLock.Lock()
	defer component.stateLock.Unlock()
	if component.index != nil {
		return component, component.index, nil
	}
	store, err := self.LocalStore().Directory(sessionGatewayComponentName, sessionComponentName)
	if err != nil {
		return nil, nil, err
	}
	settings := self.settings.Session
	if settings == nil {
		settings = DefaultSessionSettings()
	}
	index, err := NewSessionGatewayIndex(store, settings, self.settings.ClockOrReal())
	if err != nil {
		return nil, nil, err
	}
	component.index = index
	return component, index, nil
}

// The network's gateway recorder: built at the first call over the network's session journal, its run store and the
// component's index, its gaps counted on each run's file. ErrSidecarStoreLocked before enrollment, and the component's
// error where it did not construct.
func (self *Sidecar) SessionGatewayRecorder() (*SessionGatewayRecorder, error) {
	component, index, err := self.sessionGatewayIndex()
	if err != nil {
		return nil, err
	}
	journal, err := self.SessionJournal()
	if err != nil {
		return nil, err
	}
	runs, err := self.Runs()
	if err != nil {
		return nil, err
	}
	component.stateLock.Lock()
	defer component.stateLock.Unlock()
	if component.recorder != nil {
		return component.recorder, nil
	}
	recorder, err := NewSessionGatewayRecorder(&SessionGatewayRecorderArgs{
		Journal:  journal,
		Runs:     sessionGatewayRunStore{runs: runs},
		Index:    index,
		Settings: index.settings,
		Clock:    self.settings.ClockOrReal(),
		Gap: func(runId Id, code string) {
			if err := runs.AddGap(context.Background(), runId, code); err != nil {
				self.log.Warningf("[session]a coverage gap was not counted: %s", err)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	component.recorder = recorder
	return recorder, nil
}

// Whether the gateway recorded a call in the run within the index's window: what a run's coverage reads to name source
// gateway (§24.8), from the index alone, so it builds no journal. False where the index cannot be built or read.
func (self *Sidecar) SessionGatewayRecorded(runId Id) bool {
	_, index, err := self.sessionGatewayIndex()
	if err != nil {
		return false
	}
	recorded, err := index.Recorded(runId)
	return err == nil && recorded
}
