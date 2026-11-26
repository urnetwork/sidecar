//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A tool a test configures: its tier, mode and schema, and what Execute does.
type harnessTestTool struct {
	name        string
	description string
	schema      []byte
	mode        string
	tier        string
	// W in an untainted run, O in a tainted one
	runTier bool
	// the action an O call names, nil for none
	outward func(call *HarnessCall, args []byte) (*HarnessAuthorizeRequest, error)
	execute func(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error)
}

func (self *harnessTestTool) Name() string {
	return self.name
}

func (self *harnessTestTool) Description() string {
	return self.description
}

func (self *harnessTestTool) Schema() []byte {
	if self.schema == nil {
		return []byte(`{"type":"object"}`)
	}
	return self.schema
}

func (self *harnessTestTool) Mode() string {
	if self.mode == "" {
		return HarnessToolParallel
	}
	return self.mode
}

func (self *harnessTestTool) Tier() string {
	if self.tier == "" {
		return HarnessToolTierRead
	}
	return self.tier
}

func (self *harnessTestTool) Execute(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
	if self.execute == nil {
		return &HarnessToolResult{Text: "ok", Trust: HarnessToolTrusted}, nil
	}
	return self.execute(ctx, callId, args, update)
}

// A tool whose tier turns on its run.
type harnessTestRunTierTool struct {
	*harnessTestTool
}

func (self *harnessTestRunTierTool) RunTier(call *HarnessCall, args []byte) string {
	if call.Run().Tainted() {
		return HarnessToolTierOutward
	}
	return HarnessToolTierWrite
}

// An O tool, naming its action.
type harnessTestOutwardTool struct {
	*harnessTestTool
}

func (self *harnessTestOutwardTool) Outward(ctx context.Context, call *HarnessCall, args []byte) (*HarnessAuthorizeRequest, error) {
	return self.outward(call, args)
}

// A spec registering tool, built in or not, for profiles.
func harnessTestSpec(tool HarnessTool, builtIn bool, profiles ...HarnessProfile) *HarnessToolSpec {
	return &HarnessToolSpec{
		Name:     tool.Name(),
		Profiles: profiles,
		BuiltIn:  builtIn,
		New: func(harness *Harness) (HarnessTool, error) {
			return tool, nil
		},
	}
}

// A registry of specs, built for no Harness.
func harnessTestRegistry(specs ...*HarnessToolSpec) *HarnessToolRegistry {
	byName := map[string]*HarnessToolSpec{}
	for _, spec := range specs {
		byName[spec.Name] = spec
	}
	return newHarnessToolRegistry(nil, byName)
}

// A second registration of a name panics at start, as does a registration with no profile or constructor.
func TestHarnessRegisterToolTwicePanics(t *testing.T) {
	panicked := func(register func()) (panicked bool) {
		defer func() {
			panicked = recover() != nil
		}()
		register()
		return false
	}
	spec := harnessTestSpec(&harnessTestTool{name: "harness_test_twice"}, false, HarnessProfileLocal)
	RegisterHarnessTool(spec)
	defer delete(harnessToolSpecs, spec.Name)
	if !panicked(func() { RegisterHarnessTool(spec) }) {
		t.Fatal("a second registration did not panic")
	}
	if !panicked(func() { RegisterHarnessTool(&HarnessToolSpec{Name: "harness_test_no_profile", New: spec.New}) }) {
		t.Fatal("a registration with no profile did not panic")
	}
	if !panicked(func() {
		RegisterHarnessTool(&HarnessToolSpec{Name: "harness_test_odd_profile", Profiles: []HarnessProfile{"host"}, New: spec.New})
	}) {
		t.Fatal("a registration for an unknown profile did not panic")
	}
	if !panicked(func() {
		RegisterHarnessTool(&HarnessToolSpec{Name: "harness_test_no_constructor", Profiles: []HarnessProfile{HarnessProfileLocal}})
	}) {
		t.Fatal("a registration with no constructor did not panic")
	}
}

// The call a tool's Execute reads carries its run, agent, profile and call id, Emit and Ask; a tool registered for one
// profile never runs in the other's run.
func TestHarnessCallCarriesRunAndAgent(t *testing.T) {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	run := newHarnessTestRun(t, runs, nil)
	emitted := []*HarnessEvent{}
	var seen *HarnessCall
	tool := &harnessTestTool{name: "probe", execute: func(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
		call, ok := HarnessCallFromContext(ctx)
		if !ok {
			return nil, errors.New("no call in the context")
		}
		seen = call
		if callId != call.ToolCallId() {
			return nil, errors.New("the call id differs")
		}
		call.Emit(NewHarnessQueueUpdateEvent(nil, nil))
		update(&HarnessToolUpdate{Text: "halfway"})
		return &HarnessToolResult{Text: "done", Trust: HarnessToolTrusted}, nil
	}}
	spec := harnessTestSpec(tool, true, HarnessProfileLocal)
	updates := []string{}
	call := NewHarnessCall(&HarnessCallArgs{Run: run, Profile: HarnessProfileLocal, ToolCallId: "call_7", ToolName: "probe",
		Emit: func(event *HarnessEvent) error {
			emitted = append(emitted, event)
			return nil
		},
		Attached: func() bool { return true },
	})
	result, err := harnessRunToolCall(context.Background(), call, spec, tool, []byte(`{}`), func(update *HarnessToolUpdate) {
		updates = append(updates, update.Text)
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != call || seen.Run() != run || seen.AgentId() != run.AgentId() || seen.Profile() != HarnessProfileLocal ||
		seen.ToolName() != "probe" || !seen.Attached() {
		t.Fatalf("the call: %+v", seen)
	}
	if result.result.Text != "done" || len(emitted) != 1 || len(updates) != 1 || updates[0] != "halfway" {
		t.Fatalf("result %+v, %d events, updates %v", result.result, len(emitted), updates)
	}
	if run.Tainted() {
		t.Fatal("a trusted result tainted its run")
	}
	// the local tool is refused in an enclave run, before it runs
	seen = nil
	enclaveCall := NewHarnessCall(&HarnessCallArgs{Run: run, Profile: HarnessProfileEnclave, ToolCallId: "call_8", ToolName: "probe"})
	if _, err := harnessRunToolCall(context.Background(), enclaveCall, spec, tool, nil, nil); !errors.Is(err, ErrHarnessToolOutsideProfile) || seen != nil {
		t.Fatalf("a local tool in an enclave run: %v", err)
	}
	if _, _, ok := harnessTestRegistry(spec).Tool("probe", HarnessProfileEnclave); ok {
		t.Fatal("the registry serves a local tool to the enclave profile")
	}
	if names := harnessTestRegistry(spec).Names(HarnessProfileLocal); len(names) != 1 || names[0] != "probe" {
		t.Fatalf("local names: %v", names)
	}
}

// A result whose Trust is untrusted, or one this build does not read, taints the run before it returns; a taint that
// does not persist withholds the result.
func TestHarnessUntrustedResultTaintsBeforeReturn(t *testing.T) {
	backend := &runSyncFaultBackend{SidecarStoreBackend: NewSidecarMemoryBackend()}
	_, runs, _ := newTestRunStoreOn(t, backend)
	for _, trust := range []string{HarnessToolUntrusted, "", "partly"} {
		run := newHarnessTestRun(t, runs, nil)
		tool := &harnessTestTool{name: "fetchy", execute: func(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
			call, _ := HarnessCallFromContext(ctx)
			if call.Run().Tainted() {
				return nil, errors.New("tainted before the tool ran")
			}
			return &HarnessToolResult{Text: "outside words", Trust: trust}, nil
		}}
		call := NewHarnessCall(&HarnessCallArgs{Run: run, Profile: HarnessProfileLocal, ToolCallId: "c", ToolName: "fetchy"})
		result, err := harnessRunToolCall(context.Background(), call, harnessTestSpec(tool, true, HarnessProfileLocal), tool, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !run.Tainted() || result.result.Trust != HarnessToolUntrusted {
			t.Fatalf("trust %q: tainted %v, result trust %q", trust, run.Tainted(), result.result.Trust)
		}
	}
	// a failed taint withholds the result
	run := newHarnessTestRun(t, runs, nil)
	tool := &harnessTestTool{name: "fetchy", execute: func(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
		return &HarnessToolResult{Text: "outside words", Trust: HarnessToolUntrusted}, nil
	}}
	backend.setFailing(true)
	call := NewHarnessCall(&HarnessCallArgs{Run: run, Profile: HarnessProfileLocal, ToolCallId: "c", ToolName: "fetchy"})
	result, err := harnessRunToolCall(context.Background(), call, harnessTestSpec(tool, true, HarnessProfileLocal), tool, nil, nil)
	backend.setFailing(false)
	if err == nil || result != nil {
		t.Fatalf("a failed taint returned the result: %+v", result)
	}
}

// Only a built-in tool's keep: false is honored: another tool's keep member is dropped from its details.
func TestHarnessKeepFalseOnlyFromBuiltIns(t *testing.T) {
	details := []byte(`{"results":3,"keep":false}`)
	builtIn := &HarnessToolSpec{Name: "web_search", BuiltIn: true}
	other := &HarnessToolSpec{Name: "some_extension"}
	kept, keep := harnessToolDetails(builtIn, details)
	if keep || string(kept) != string(details) {
		t.Fatalf("a built-in's keep: false: %s, keep %v", kept, keep)
	}
	kept, keep = harnessToolDetails(other, details)
	if !keep || strings.Contains(string(kept), "keep") || string(kept) != `{"results":3}` {
		t.Fatalf("another tool's keep: false: %s, keep %v", kept, keep)
	}
	if _, keep := harnessToolDetails(builtIn, []byte(`{"keep":true}`)); !keep {
		t.Fatal("a built-in's keep: true held back")
	}
	if _, keep := harnessToolDetails(builtIn, []byte(`{"keep":"no"}`)); !keep {
		t.Fatal("a keep that is no boolean held back")
	}
	// through a call, the non-built-in's details reach the model without the member
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	run := newHarnessTestRun(t, runs, nil)
	tool := &harnessTestTool{name: "some_extension", execute: func(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
		return &HarnessToolResult{Text: "x", Details: details, Trust: HarnessToolTrusted}, nil
	}}
	call := NewHarnessCall(&HarnessCallArgs{Run: run, Profile: HarnessProfileLocal, ToolCallId: "c", ToolName: "some_extension"})
	result, err := harnessRunToolCall(context.Background(), call, harnessTestSpec(tool, false, HarnessProfileLocal), tool, nil, nil)
	if err != nil || !result.keep || string(result.result.Details) != `{"results":3}` {
		t.Fatalf("through a call: %+v, %v", result, err)
	}
}

// An O tool runs only once Authorize passes in its before-hook: Execute waits while the gate waits for a person, then
// runs with the gate's outcome; an O tool naming no action is refused; a tool W untainted and O tainted asks its run.
func TestHarnessOutwardToolWaitsInBeforeHook(t *testing.T) {
	world := newHarnessApprovalWorld(t, nil)
	executed := make(chan *SidecarOutcome, 1)
	base := &harnessTestTool{name: "make_alias", tier: HarnessToolTierOutward,
		outward: func(call *HarnessCall, args []byte) (*HarnessAuthorizeRequest, error) {
			return world.request(t), nil
		},
		execute: func(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
			call, _ := HarnessCallFromContext(ctx)
			executed <- call.Outcome()
			return &HarnessToolResult{Text: "made", Trust: HarnessToolTrusted}, nil
		}}
	tool := &harnessTestOutwardTool{harnessTestTool: base}
	call := NewHarnessCall(&HarnessCallArgs{Run: world.run, Profile: HarnessProfileLocal, ToolCallId: "c", ToolName: "make_alias"})
	done := make(chan error, 1)
	go func() {
		_, err := harnessRunToolCall(context.Background(), call, harnessTestSpec(tool, true, HarnessProfileLocal), tool, nil, nil)
		done <- err
	}()
	if pending := world.emitter.next(t); pending.Type != HarnessEventApprovalPending {
		t.Fatalf("emitted %s", pending.Type)
	}
	select {
	case <-executed:
		t.Fatal("Execute ran before the decision")
	default:
	}
	world.approvals.decide(world.gate.approvalId, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, ApprovalStatusApproved)
	select {
	case outcome := <-executed:
		if outcome == nil || outcome.State != ApprovalOutcomeDone || string(outcome.EffectRef) != "done" {
			t.Fatalf("Execute read outcome %+v", outcome)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Execute never ran")
	}
	if err := <-done; err != nil || world.effect.count() != 1 {
		t.Fatalf("%v, %d effects", err, world.effect.count())
	}

	// an O tool naming no action
	ungated := &harnessTestTool{name: "ungated", tier: HarnessToolTierOutward}
	call = NewHarnessCall(&HarnessCallArgs{Run: world.run, Profile: HarnessProfileLocal, ToolCallId: "d", ToolName: "ungated"})
	if _, err := harnessRunToolCall(context.Background(), call, harnessTestSpec(ungated, true, HarnessProfileLocal), ungated, nil, nil); !errors.Is(err, ErrHarnessToolUngated) {
		t.Fatalf("an ungated O tool: %v", err)
	}

	// W in an untainted run runs at once; O in a tainted one goes to the gate
	dual := &harnessTestRunTierTool{harnessTestTool: &harnessTestTool{name: "send_note"}}
	call = NewHarnessCall(&HarnessCallArgs{Run: world.run, Profile: HarnessProfileLocal, ToolCallId: "e", ToolName: "send_note"})
	if tier, _ := harnessCallTier(call, dual, nil); tier != HarnessToolTierWrite {
		t.Fatalf("untainted tier %s", tier)
	}
	if err := world.run.Taint(context.Background(), RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	if tier, _ := harnessCallTier(call, dual, nil); tier != HarnessToolTierOutward {
		t.Fatalf("tainted tier %s", tier)
	}
	if _, err := harnessRunToolCall(context.Background(), call, harnessTestSpec(dual, true, HarnessProfileLocal), dual, nil, nil); !errors.Is(err, ErrHarnessToolUngated) {
		t.Fatalf("a tainted run's dual tool without an action: %v", err)
	}
	if _, err := harnessCallTier(call, &harnessTestTool{name: "odd", tier: "X"}, nil); !errors.Is(err, ErrHarnessToolTierInvalid) {
		t.Fatalf("an unknown tier: %v", err)
	}
	var _ = json.RawMessage{}
}
