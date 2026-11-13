//go:build !js && !ios && !android && !sdk_mobile_bind

// Harness evidence (§16.6's harness_ok, D-MCP-9, D-MCP-14, Q-MCP-3, Q-MCP-6, I-8, I-9, FS-28; MCP-M3-10): harness_ok's
// event half, and the ApprovalHarnessEvidence that §5.4's gate asks for a harness decision on a request it has just
// found or filed (record_gate.go's step 4). Its state half, and the decision's bytes, are the root's
// (record_harness.go), which app hosts link without this package.
//
//	note   every hook event passes the store once its capture has written it: a PermissionRequest of Claude Code
//	       or Codex, or Cursor's beforeMCPExecution that `ur hook cursor` answered ask, of one of ur's tools, is kept
//	       with its run, tool, the SHA-256 of its arguments' RFC 8785 form, its time and permission mode, and the leaf
//	       of the hook_event entry the capture wrote for it (HookCaptured.EventLeaf); a later event of the same session
//	       reporting a mode not among Ingest.HarnessPromptingModes voids the session's kept ones
//	match  an O call asks with its run, its tool and its arguments' hash, which the tool framework puts in the call's
//	       context (MCP.md's reading 2, so a harness that reorders keys still matches): the newest unused event of the
//	       same run, tool and hash, of this network, under Ingest.HarnessEvidenceTimeout old, whose mode is among
//	       Ingest.HarnessPromptingModes, so auto, dontAsk, bypassPermissions and any mode the list does not name, an
//	       unknown or missing one included, void it (Cursor names none: there the ask ur hook answered is the prompt)
//	tty    or a person typed the command and confirmed it on ur's controlling terminal, which the call's context says
//	       (WithHarnessTtyConfirmation): the daemon first seals a hook_event entry of event ur-tty-confirm, source
//	       observed, holding the command's arguments' hash, and cites its leaf (RECORD.md section 5.1)
//	use    the event is taken before the decision is signed, so it serves one decision even when the signing fails;
//	       the store is memory alone, so a restart loses only evidence, the closed direction
//	sign   sidecar.HarnessOk at P on the request and the run's taint now, then the decision, approve, one use, not
//	       after the event's time plus Ingest.HarnessEvidenceTimeout
//
// The residual is the design's (owner decisions 47, 75): any same-uid process can call ur hook with a forged
// PermissionRequest, so harness evidence shows only that the harness, or a process of the user, reported a prompt
// for that exact call. Records keep hook events source hook, and the decision says channel harness.
//
// Safe for concurrent use.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// No hook event or confirmation stands as evidence for the call.
var ErrHarnessNoEvidence = errors.New("no harness evidence for the call")

// The hook_event entry's event name for a typed command confirmed on /dev/tty (RECORD.md section 5.1).
const harnessTtyConfirmEvent = "ur-tty-confirm"

// The hook events that may stand as evidence, by harness: the ones that ask the person about a call.
var harnessEvidenceEvents = map[string]string{
	claudeHookHarness: "PermissionRequest",
	codexHookHarness:  "PermissionRequest",
	cursorHookHarness: "beforeMCPExecution",
}

// One kept event.
type harnessEvidenceEvent struct {
	runId           sidecar.Id
	harness         string
	sessionId       string
	toolName        string
	argumentsSha256 []byte
	time            time.Time
	permissionMode  string
	// the hook_event entry's leaf, which a decision cites
	leaf []byte
	used bool
	// a later event of its session reported a mode that voids it
	void bool
}

// The daemon's harness evidence, every network's, in memory.
type HarnessEvidenceStore struct {
	settings *sidecar.SidecarIngestSettings
	clock    sidecar.Clock

	stateLock sync.Mutex
	// each network's kept events, oldest first
	networkIdEvents map[sidecar.Id][]*harnessEvidenceEvent
}

// A store on settings and clock, nil the real one.
func NewHarnessEvidenceStore(settings *sidecar.SidecarIngestSettings, clock sidecar.Clock) *HarnessEvidenceStore {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &HarnessEvidenceStore{settings: settings, clock: clock, networkIdEvents: map[sidecar.Id][]*harnessEvidenceEvent{}}
}

// Puts the store on server's hook path, after the capture that writes each event's entry (Ingest's): install it once
// the capture is set.
func (self *HarnessEvidenceStore) Install(server *McpServer) {
	next := server.hookCapture()
	server.SetHookCapture(func(ctx context.Context, captured *HookCaptured) error {
		var err error
		if next != nil {
			err = next(ctx, captured)
		}
		self.Note(captured)
		return err
	})
}

// Whether event is one that asked the person about a call of ur's tools: Claude Code's and Codex's PermissionRequest,
// or Cursor's beforeMCPExecution where ur hook answered ask.
func harnessAskingEvent(event *HookEvent) bool {
	if event == nil || event.ToolServer != urMcpServerName || event.ToolName == "" || event.HarnessEvent != harnessEvidenceEvents[event.Harness] {
		return false
	}
	if event.Harness == cursorHookHarness {
		return CursorHookAnswer(event) != nil
	}
	return event.Kind == HookEventPermissionRequest
}

// Notes one captured event: an asking one kept, and any reporting a mode outside HarnessPromptingModes voiding its
// session's kept ones. Nothing while the event bound no run or the network is Locked.
func (self *HarnessEvidenceStore) Note(captured *HookCaptured) {
	if captured == nil || captured.Event == nil || captured.Locked || captured.RunId == (sidecar.Id{}) {
		return
	}
	event := captured.Event
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	events := self.networkIdEvents[captured.NetworkId]
	// expired and used events go first
	events = slices.DeleteFunc(events, func(kept *harnessEvidenceEvent) bool {
		return kept.used || kept.void || !now.Before(kept.time.Add(self.settings.HarnessEvidenceTimeout))
	})
	if event.PermissionMode != "" && !slices.Contains(self.settings.HarnessPromptingModes, event.PermissionMode) {
		for _, kept := range events {
			if kept.harness == event.Harness && kept.sessionId == event.SessionId {
				kept.void = true
			}
		}
	}
	if harnessAskingEvent(event) && 0 < len(captured.EventLeaf) {
		events = append(events, &harnessEvidenceEvent{
			runId:           captured.RunId,
			harness:         event.Harness,
			sessionId:       event.SessionId,
			toolName:        event.ToolName,
			argumentsSha256: append([]byte(nil), event.ToolInputSha256...),
			time:            now,
			permissionMode:  event.PermissionMode,
			leaf:            append([]byte(nil), captured.EventLeaf...),
		})
	}
	if count := self.settings.HarnessEvidenceEventCount; count < len(events) {
		events = events[len(events)-count:]
	}
	self.networkIdEvents[captured.NetworkId] = events
}

// Takes the newest unused event of networkId's that stands for a call of tool with arguments' hash in run: see the
// file header's match row. nil for none.
func (self *HarnessEvidenceStore) take(networkId sidecar.Id, runId sidecar.Id, toolName string, argumentsSha256 []byte, now time.Time) *harnessEvidenceEvent {
	if len(argumentsSha256) == 0 {
		return nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	events := self.networkIdEvents[networkId]
	for i := len(events) - 1; 0 <= i; i -= 1 {
		event := events[i]
		switch {
		case event.used, event.void, event.runId != runId, event.toolName != toolName,
			string(event.argumentsSha256) != string(argumentsSha256),
			event.time.After(now), !now.Before(event.time.Add(self.settings.HarnessEvidenceTimeout)):
			continue
		}
		if event.harness != cursorHookHarness && !slices.Contains(self.settings.HarnessPromptingModes, event.permissionMode) {
			continue
		}
		testHookBarrier("harness.evidence.before", runId.String())
		event.used = true
		testHookBarrier("harness.evidence.after", runId.String())
		taken := *event
		return &taken
	}
	return nil
}

// The tool and arguments of a call, which the framework puts in its context for the gate's harness evidence.
type mcpToolArguments struct {
	name            string
	argumentsSha256 []byte
}

// The context key of a call's tool and arguments.
type mcpToolArgumentsContextKey struct{}

// ctx carrying the call of tool name with its arguments as sent, by the SHA-256 of their RFC 8785 form, as a hook's
// tool_input hashes (hookToolInputSha256).
func withMcpToolArguments(ctx context.Context, name string, arguments []byte) context.Context {
	return context.WithValue(ctx, mcpToolArgumentsContextKey{}, &mcpToolArguments{
		name:            name,
		argumentsSha256: hookToolInputSha256(json.RawMessage(arguments)),
	})
}

// The tool and arguments' hash of the call ctx runs, false outside one.
func mcpToolArgumentsOf(ctx context.Context) (string, []byte, bool) {
	arguments, ok := ctx.Value(mcpToolArgumentsContextKey{}).(*mcpToolArguments)
	if !ok || arguments == nil {
		return "", nil, false
	}
	return arguments.name, arguments.argumentsSha256, true
}

// The context key of a person's /dev/tty confirmation.
type harnessTtyContextKey struct{}

// ctx carrying a person's confirmation on ur's controlling terminal of the typed command whose arguments' RFC 8785
// form hashes to argumentsSha256: harness_ok's second branch (§16.6). A control-mode method of an outward command sets
// it for its confirmed call.
func WithHarnessTtyConfirmation(ctx context.Context, argumentsSha256 []byte) context.Context {
	return context.WithValue(ctx, harnessTtyContextKey{}, append([]byte(nil), argumentsSha256...))
}

// The confirmed command's arguments' hash, false for none.
func harnessTtyConfirmationOf(ctx context.Context) ([]byte, bool) {
	argumentsSha256, ok := ctx.Value(harnessTtyContextKey{}).([]byte)
	return argumentsSha256, ok && 0 < len(argumentsSha256)
}

// What signs a harness decision: *sidecar.Sidecar.
type HarnessDecisionSigner interface {
	Identity() *sidecar.SidecarIdentity
	SignHarnessDecision(request *sidecar.StoredApprovalRequest, memberId sidecar.Id, pin *bridge.AuthPin, evidenceSha256 []byte, notAfter time.Time) ([]byte, error)
}

// What one network's harness evidence reads.
type HarnessEvidenceArgs struct {
	Store     *HarnessEvidenceStore
	NetworkId sidecar.Id
	Signer    HarnessDecisionSigner
	// P now: NewConfigApprovalStates over the network's verified state and compiled policy, which is a HarnessStates.
	States func() (sidecar.HarnessStates, error)
	// Each run's taint, failing closed: the Sidecar.
	Runs sidecar.RecordRunView
	// Where a typed command's confirmation is sealed as a hook_event entry: the Sidecar's record writer. Nil refuses
	// the /dev/tty branch.
	Record sidecar.RecordWriter
}

// One network's harness evidence, the gate's ApprovalHarnessEvidence.
type HarnessEvidence struct {
	args *HarnessEvidenceArgs
}

var _ sidecar.ApprovalHarnessEvidence = (*HarnessEvidence)(nil)

// The evidence of args.
func NewHarnessEvidence(args *HarnessEvidenceArgs) *HarnessEvidence {
	return &HarnessEvidence{args: args}
}

// A harness decision on request, which this sidecar filed for action, its Signed as stored: harness_ok's state half
// at P first, then the event that asked about the call, taken, then the signature. Any failure is no evidence.
func (self *HarnessEvidence) HarnessDecision(ctx context.Context, action *sidecar.SidecarAction, request *sidecar.StoredApprovalRequest) ([]byte, error) {
	if self.args.Store == nil || self.args.Signer == nil || self.args.States == nil || self.args.Runs == nil {
		return nil, fmt.Errorf("%w: the evidence is not composed", ErrHarnessNoEvidence)
	}
	identity := self.args.Signer.Identity()
	if identity == nil {
		return nil, sidecar.ErrSidecarNoIdentity
	}
	states, err := self.args.States()
	if err != nil {
		return nil, err
	}
	if states == nil {
		return nil, fmt.Errorf("%w: no state", ErrHarnessNoEvidence)
	}
	now := self.args.Store.clock.Now()
	tainted := action.RunId != nil && self.args.Runs.RunTainted(*action.RunId)
	memberId, err := sidecar.HarnessOk(states, &sidecar.HarnessOkArgs{
		Request:    request,
		Requester:  identity.SidecarId,
		RunTainted: tainted,
		Now:        now,
	})
	if err != nil {
		return nil, err
	}
	leaf, eventTime, err := self.evidence(ctx, action, now)
	if err != nil {
		return nil, err
	}
	return self.args.Signer.SignHarnessDecision(request, memberId, states.Pin(), leaf, eventTime.Add(self.args.Store.settings.HarnessEvidenceTimeout))
}

// The evidence for the call ctx runs: a /dev/tty confirmation sealed now, or the hook event that asked, taken. Its
// leaf and time.
func (self *HarnessEvidence) evidence(ctx context.Context, action *sidecar.SidecarAction, now time.Time) ([]byte, time.Time, error) {
	if argumentsSha256, ok := harnessTtyConfirmationOf(ctx); ok {
		leaf, err := self.sealTtyConfirmation(action, argumentsSha256, now)
		return leaf, now, err
	}
	call := McpCallOf(ctx)
	toolName, argumentsSha256, ok := mcpToolArgumentsOf(ctx)
	if call == nil || !ok || call.NetworkId != self.args.NetworkId || action.RunId == nil || *action.RunId != call.RunId {
		return nil, time.Time{}, ErrHarnessNoEvidence
	}
	event := self.args.Store.take(self.args.NetworkId, call.RunId, toolName, argumentsSha256, now)
	if event == nil {
		return nil, time.Time{}, ErrHarnessNoEvidence
	}
	return event.leaf, event.time, nil
}

// Seals the hook_event entry of a typed command's confirmation, source observed, and answers its leaf (RECORD.md
// section 5.1). A writer that spools the entry, a Locked one, gives no leaf, and so no evidence.
func (self *HarnessEvidence) sealTtyConfirmation(action *sidecar.SidecarAction, argumentsSha256 []byte, now time.Time) ([]byte, error) {
	if self.args.Record == nil {
		return nil, fmt.Errorf("%w: nothing seals a confirmation", ErrHarnessNoEvidence)
	}
	draft := &sidecar.RecordDraft{
		Kind:       sidecar.RecordKindHookEvent,
		Source:     sidecar.RecordSourceObserved,
		RunId:      action.RunId,
		NoSession:  action.RunId == nil,
		TimeMillis: now.UnixMilli(),
		Body:       &protocol.HookEventBody{Event: harnessTtyConfirmEvent, ArgumentsSha256: argumentsSha256},
	}
	refs, err := self.args.Record.Append(draft)
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		if !ref.Spooled {
			return append([]byte(nil), ref.Leaf[:]...), nil
		}
	}
	return nil, fmt.Errorf("%w: the confirmation's entry waits in the spool", ErrHarnessNoEvidence)
}
