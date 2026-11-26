//go:build !ios_extension && !sidecar_http

// The Harness's tools (DESIGN-COMPUTE §7.5, R-HARN-4, D-HARN-2): §7.5's interface as written, the call a tool's Execute
// reads from its context, and how one call runs (harnessRunToolCall), which the loop calls for every tool call.
//
//   - R runs; W runs, and the recorder records it (HARN-M11-08); O runs only once HarnessRun.Authorize passes in the
//     before-hook, where the tool names the action the daemon built (HarnessOutwardTool), the gate runs the effect, and
//     Execute reads its outcome. A tool that is W in an untainted run and O in a tainted one (§7.5's table) asks its run
//     through HarnessRunTier. An O tool that names no action is refused, so nothing outward runs ungated.
//   - A result whose Trust is untrusted, or a Trust this build does not read, taints the run before it is returned,
//     write-ahead; a failed taint fails the call and the result never reaches the model.
//   - Only a built-in tool may mark its details keep: false (§24.9): another tool's keep member is dropped, so neither
//     the record nor an app's storage honors it.
//   - A tool registered for one profile never runs in the other's run (§7.5's two columns).
//
// Descriptions are constants of each tool's file, never a variable: the text a model reads is fixed by the build.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// §7.5's tool.
type HarnessTool interface {
	Name() string
	Description() string
	// The JSON schema of the arguments.
	Schema() []byte
	// parallel or sequential: a sequential tool makes its batch sequential (§7.4).
	Mode() string
	// R, W or O (DESIGN §16.5).
	Tier() string
	// Runs one call with the arguments the model wrote, reporting partial results through update. The call it runs in
	// is HarnessCallFromContext(ctx).
	Execute(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error)
}

// A tool's modes, tiers and trusts.
const (
	HarnessToolParallel   = "parallel"
	HarnessToolSequential = "sequential"

	HarnessToolTierRead    = "R"
	HarnessToolTierWrite   = "W"
	HarnessToolTierOutward = "O"

	HarnessToolTrusted   = "trusted"
	HarnessToolUntrusted = "untrusted"
)

// What a call returns (§7.5).
type HarnessToolResult struct {
	// What the model reads.
	Text string
	// Structured JSON for the UI: a diff, a terminal transcript, a file listing.
	Details []byte
	// trusted or untrusted (§7.8).
	Trust string
}

// A call's partial result so far, which the loop emits as tool_execution_update.
type HarnessToolUpdate struct {
	Text    string
	Details []byte
}

// Beside HarnessTool: a tool whose tier turns on its run, W in an untainted run and O in a tainted one (§7.5's
// table): the tier this call runs at.
type HarnessRunTier interface {
	RunTier(call *HarnessCall, args []byte) string
}

// Beside HarnessTool: an O tool's before-hook, the outward action this call would take, built by the daemon from args
// with its effect, which the gate runs once its use is reserved.
type HarnessOutwardTool interface {
	Outward(ctx context.Context, call *HarnessCall, args []byte) (*HarnessAuthorizeRequest, error)
}

var (
	// The call names a tool its profile does not serve, or no tool of the name is registered.
	ErrHarnessToolOutsideProfile = errors.New("the tool is not in this run's profile")
	// An O tool names no action, so it is refused rather than run ungated.
	ErrHarnessToolUngated = errors.New("an outward tool names no action for the gate")
	// A tool answered a tier this build does not read.
	ErrHarnessToolTierInvalid = errors.New("the tool's tier is not R, W or O")
)

// One tool call as its tool sees it: the run (taint, marks, Authorize), the agent and its registered name, the profile,
// the call's id, Emit for the tool's cards and Ask for a ui_request, and whether a person watches. Built by the loop
// for each call; safe for concurrent use.
type HarnessCall struct {
	run        *HarnessRun
	agentId    Id
	agentName  string
	profile    HarnessProfile
	toolCallId string
	toolName   string
	emit       func(event *HarnessEvent) error
	ask        func(ctx context.Context, request *HarnessUiRequest) (*HarnessUiResponse, error)
	attached   func() bool
	workspace  *harnessWorkspace
	// the O tier's gate outcome, set by the before-hook before Execute
	outcome *SidecarOutcome
}

// What a call is built from.
type HarnessCallArgs struct {
	Run *HarnessRun
	// The agent's registered name (§20.5).
	AgentName  string
	Profile    HarnessProfile
	ToolCallId string
	ToolName   string
	// Emits one of the tool's events as the run's agent's. Nil emits nothing.
	Emit func(event *HarnessEvent) error
	// Raises a ui_request on the run. Nil answers unattached.
	Ask func(ctx context.Context, request *HarnessUiRequest) (*HarnessUiResponse, error)
	// Whether a person's view watches the run. Nil reads no.
	Attached func() bool
	// The agent's workspace (§7.5), nil for a profile or a leg with none.
	Workspace *harnessWorkspace
}

// A call over args.
func NewHarnessCall(args *HarnessCallArgs) *HarnessCall {
	call := &HarnessCall{
		run:        args.Run,
		agentName:  args.AgentName,
		profile:    args.Profile,
		toolCallId: args.ToolCallId,
		toolName:   args.ToolName,
		emit:       args.Emit,
		ask:        args.Ask,
		attached:   args.Attached,
		workspace:  args.Workspace,
	}
	if args.Run != nil {
		call.agentId = args.Run.AgentId()
	}
	return call
}

// The context key a call rides under.
type harnessCallContextKey struct{}

// ctx carrying call, for its tool's Execute.
func harnessCallContext(ctx context.Context, call *HarnessCall) context.Context {
	return context.WithValue(ctx, harnessCallContextKey{}, call)
}

// The call ctx carries, and false for none: a tool's Execute reads its run, agent and profile here.
func HarnessCallFromContext(ctx context.Context) (*HarnessCall, bool) {
	call, ok := ctx.Value(harnessCallContextKey{}).(*HarnessCall)
	return call, ok && call != nil
}

// The run the call belongs to: its taint, marks and Authorize.
func (self *HarnessCall) Run() *HarnessRun {
	return self.run
}

// The agent making the call.
func (self *HarnessCall) AgentId() Id {
	return self.agentId
}

// The agent's registered name (§20.5), which support's messages and SKILL's threads name it by.
func (self *HarnessCall) AgentName() string {
	return self.agentName
}

// The profile the run is in.
func (self *HarnessCall) Profile() HarnessProfile {
	return self.profile
}

// The model's id for the tool call.
func (self *HarnessCall) ToolCallId() string {
	return self.toolCallId
}

// The tool's name.
func (self *HarnessCall) ToolName() string {
	return self.toolName
}

// Emits one of the tool's events (a registered card) as the run's agent's.
func (self *HarnessCall) Emit(event *HarnessEvent) error {
	if self.emit == nil {
		return nil
	}
	return self.emit(event)
}

// Raises a ui_request on the run and waits for its answer (harness_ui.go).
func (self *HarnessCall) Ask(ctx context.Context, request *HarnessUiRequest) (*HarnessUiResponse, error) {
	if self.ask == nil {
		if request != nil && request.Method == HarnessUiDisclosure {
			return nil, harnessDisclosureRequired(request, InferDisclosureReasonUnacknowledged, "no person is attached to the run")
		}
		return nil, ErrHarnessUiUnattached
	}
	return self.ask(ctx, request)
}

// Whether a person's view watches the run.
func (self *HarnessCall) Attached() bool {
	return self.attached != nil && self.attached()
}

// The agent's workspace, nil for a profile or a leg with none.
func (self *HarnessCall) Workspace() *harnessWorkspace {
	return self.workspace
}

// What the gate's effect came to, for an O call; nil for the rest.
func (self *HarnessCall) Outcome() *SidecarOutcome {
	return self.outcome
}

// The tier this call runs at: the tool's, or the one its run gives it.
func harnessCallTier(call *HarnessCall, tool HarnessTool, args []byte) (string, error) {
	tier := tool.Tier()
	if runTier, ok := tool.(HarnessRunTier); ok {
		tier = runTier.RunTier(call, args)
	}
	switch tier {
	case HarnessToolTierRead, HarnessToolTierWrite, HarnessToolTierOutward:
		return tier, nil
	}
	return "", fmt.Errorf("%w: %q", ErrHarnessToolTierInvalid, tier)
}

// details with a non-built-in tool's keep member dropped, and whether the details are to be kept: false only for a
// built-in tool's details that say keep: false (§24.9), which the Harness holds in memory only.
func harnessToolDetails(spec *HarnessToolSpec, details []byte) ([]byte, bool) {
	if details == nil {
		return nil, true
	}
	object := harnessPiObject{}
	if err := object.UnmarshalJSON(details); err != nil || !object.has("keep") {
		return details, true
	}
	if spec == nil || !spec.BuiltIn {
		object.remove("keep")
		cleaned, err := object.MarshalJSON()
		if err != nil {
			return details, true
		}
		return cleaned, true
	}
	keep := true
	if !object.decode("keep", &keep) {
		// a keep that is no boolean keeps nothing back
		return details, true
	}
	return details, keep
}

// What one call came to: the result as the model reads it, whether its details are kept, and whether it failed.
type harnessToolCallResult struct {
	result *HarnessToolResult
	// false for a built-in's keep: false details, which are held in memory only
	keep bool
}

// Runs one tool call as the file header says: the profile checked, the tier read, an O call's action authorized in
// the before-hook, Execute run with the call in its context, and an untrusted result's run tainted before it returns.
// An error fails the call: the model reads it as the tool's error.
func harnessRunToolCall(ctx context.Context, call *HarnessCall, spec *HarnessToolSpec, tool HarnessTool, args []byte, update func(*HarnessToolUpdate)) (*harnessToolCallResult, error) {
	if spec == nil || tool == nil || !slices.Contains(spec.Profiles, call.profile) {
		return nil, fmt.Errorf("%w: %s in %s", ErrHarnessToolOutsideProfile, call.toolName, call.profile)
	}
	tier, err := harnessCallTier(call, tool, args)
	if err != nil {
		return nil, err
	}
	if tier == HarnessToolTierOutward {
		outward, ok := tool.(HarnessOutwardTool)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrHarnessToolUngated, call.toolName)
		}
		request, err := outward.Outward(ctx, call, args)
		if err != nil {
			return nil, err
		}
		if call.run == nil {
			return nil, ErrSidecarGateDenied
		}
		outcome, err := call.run.Authorize(ctx, request)
		if err != nil {
			return nil, err
		}
		call.outcome = outcome
	}
	if update == nil {
		update = func(*HarnessToolUpdate) {}
	}
	result, err := tool.Execute(harnessCallContext(ctx, call), call.toolCallId, args, update)
	if err != nil {
		return nil, err
	}
	if result == nil {
		result = &HarnessToolResult{}
	}
	if result.Trust != HarnessToolTrusted {
		// untrusted, or a trust this build does not read: the run is tainted before the result returns
		if call.run == nil {
			return nil, fmt.Errorf("%w: an untrusted result with no run to taint", ErrHarnessRunInvalid)
		}
		if err := call.run.Taint(ctx, RunTaintUntrustedData); err != nil {
			return nil, fmt.Errorf("the run's taint did not persist, so the result is withheld: %w", err)
		}
		result.Trust = HarnessToolUntrusted
	}
	details, keep := harnessToolDetails(spec, result.Details)
	result.Details = details
	return &harnessToolCallResult{result: result, keep: keep}, nil
}

// args decoded into v, refusing what does not decode, for a tool's Execute.
func harnessToolArgs(args []byte, v any) error {
	if len(args) == 0 {
		args = []byte("{}")
	}
	if err := json.Unmarshal(args, v); err != nil {
		return fmt.Errorf("the arguments do not read: %w", err)
	}
	return nil
}
