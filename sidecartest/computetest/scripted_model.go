// computetest.ScriptedModel (CTEST-M11-01; DESIGN-COMPUTE §18, with §6.4's router and §6.5's local engine): a model
// behind the router that answers each call from a script of turns. It is INFER's local engine seam,
// sidecar.InferLocalEngine, so it runs behind INFER's own router as a local model its manifest lists (Manifest, and
// Router under sidecar_testhooks), and every caller of the router, the Harness, the gateway, the skill and the
// classifier's callers, runs unchanged against it.
//
//	match    a call takes the first turn not yet taken, in script order, whose ScriptedMatch holds for it: the
//	         canonical name it runs under, and its last message, the person's text or a tool's result naming its call;
//	         a turn with no match takes any call
//	answer   start; the reasoning deltas; the text deltas; each tool call's start, its argument deltas and its end, with
//	         the turn's fixed id and arguments; the usage of fixed counts; then the end. Or a failure: the turn's
//	         InferError once its deltas are out, a cut after n deltas (ScriptedCut), or a stall after n deltas
//	         (ScriptedStall), a barrier holding the stream until the test releases it or the call's context ends
//	record   every call it took, scripted or refused, in full: a deep copy of its request, the turn it took and what it
//	         answered, so a test asserts what a model saw (Calls, Saw): no marked byte of a limited_use run, a stub where
//	         a search result was, a call's whole context
//	refuse   a call no turn matches, a script run out and a call past ScriptedModelSettings.CallMaxCount each answer a
//	         named error, ErrScriptedModelUnmatched, ErrScriptedModelExhausted and ErrScriptedModelCallLimit, each also
//	         an *sidecar.InferError, engine_failed, whose message names it, so the router's error event says which;
//	         never a default answer
//
// Ids and counts are the script's, so goldens hold: a tool call the script gives no id gets call_<turn>_<call>, both
// counted from 1, and a usage is the turn's own. Nothing sleeps.
//
// Safe for concurrent use: two calls take two turns, each played on its caller's goroutine, and a stall holds its own
// call alone.

package computetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The default model's part, and its canonical name at its one effort (§6.3): identifiers.
const (
	ScriptedModelDefault     = "scripted"
	ScriptedModelDefaultName = "local-scripted-off"
)

var (
	// A call came when every turn of the script had been taken.
	ErrScriptedModelExhausted = errors.New("computetest: the scripted model's script ran out")
	// A call came that no turn not yet taken matches.
	ErrScriptedModelUnmatched = errors.New("computetest: no scripted turn matches the call")
	// A call came past ScriptedModelSettings.CallMaxCount.
	ErrScriptedModelCallLimit = errors.New("computetest: the scripted model took its most calls")
	// A turn's stream was cut where its ScriptedCut says.
	ErrScriptedStreamCut = errors.New("computetest: the scripted stream was cut")
	// A turn the model cannot play: an empty delta, a tool call with no name, arguments that are not their deltas, a
	// cut or a stall past the turn's deltas, a stall another turn holds.
	ErrScriptedTurnInvalid = errors.New("computetest: a scripted turn the model cannot play")
	// The untagged build has no seam into INFER's router (scripted_model_router.go).
	ErrScriptedRouterUnlinked = errors.New("computetest: INFER's router seam needs the sidecar_testhooks build")
)

// The model's settings (QD-702).
type ScriptedModelSettings struct {
	// The most calls one model takes, scripted or refused, each recorded in full: 4096, far past any test's turns, so a
	// loop that never ends stops at ErrScriptedModelCallLimit rather than filling memory. A call past it is answered
	// so and not recorded. Non-positive takes no call.
	CallMaxCount int
	// INFER's settings, whose format limits the model's manifest is held to as the router reads it (QD-702: a format's
	// limits stay in the format's own settings). Nil takes DefaultInferSettings.
	Infer *sidecar.InferSettings
}

// The model's defaults, the only place one is set.
func DefaultScriptedModelSettings() *ScriptedModelSettings {
	return &ScriptedModelSettings{
		CallMaxCount: 4096,
		Infer:        sidecar.DefaultInferSettings(),
	}
}

// What NewScriptedModel builds on.
type ScriptedModelArgs struct {
	// Nil takes DefaultScriptedModelSettings.
	Settings *ScriptedModelSettings
	// What each call's record is stamped from; nil takes a FakeClock at sidecartest.DefaultClockStart.
	Clock sidecar.Clock
	// The local models it serves, as the release manifest lists them; nil serves ScriptedModelDefault alone
	// (ScriptedManifestModel's entry).
	Models []*sidecar.InferManifestModel
	// The device it reports (Capabilities); nil reports a linux/amd64 desktop with 64 GiB and a GPU, which each
	// ScriptedManifestModel entry fits.
	Device *sidecar.InferDeviceCapabilities
	// The script's first turns.
	Turns []*ScriptedTurn
}

// What a turn answers: the call it is for. Each field left empty matches any call.
type ScriptedMatch struct {
	// The canonical name the call runs under, its effort included, as local-scripted-off.
	Model string
	// The call's last message is the person's, and its text holds this.
	UserText string
	// The call's last message is a tool's result answering the tool call of this id.
	ToolCallId string
	// The call's last message is a tool's result whose text holds this.
	ToolResultText string
}

// One tool call a turn makes, with the id and arguments goldens read.
type ScriptedToolCall struct {
	// Its id; empty takes call_<turn>_<call>, both counted from 1.
	Id   string
	Name string
	// The arguments, JSON text, as tool_call_end carries them whole.
	Arguments string
	// The argument deltas tool_call_args carries, which join to Arguments; nil sends Arguments as one delta, none
	// where it is empty.
	ArgumentDeltas []string
}

// Where a turn's stream is cut, as a dropped connection or a crashed engine cuts one.
type ScriptedCut struct {
	// The deltas out before the cut: text, reasoning and argument deltas alike.
	AfterDeltas int
	// The code the call fails with; empty is engine_failed.
	Code sidecar.InferErrorCode
}

// A stall: a barrier holding a turn's stream after AfterDeltas deltas until the test releases it, or the call's context
// ends, which answers canceled. One stall holds one turn's stream once. Safe for concurrent use.
type ScriptedStall struct {
	// The deltas out before the stream holds: text, reasoning and argument deltas alike.
	AfterDeltas int

	reached     chan struct{}
	released    chan struct{}
	reachedOnce sync.Once
	releaseOnce sync.Once
}

// A stall holding its turn's stream after afterDeltas deltas.
func NewScriptedStall(afterDeltas int) *ScriptedStall {
	return &ScriptedStall{
		AfterDeltas: afterDeltas,
		reached:     make(chan struct{}),
		released:    make(chan struct{}),
	}
}

// Closed once the stream holds at the stall.
func (self *ScriptedStall) Reached() <-chan struct{} {
	return self.reached
}

// Lets the stream go on, now or as it reaches the stall.
func (self *ScriptedStall) Release() {
	self.releaseOnce.Do(func() {
		close(self.released)
	})
}

// Holds until Release or ctx's end.
func (self *ScriptedStall) hold(ctx context.Context) error {
	self.reachedOnce.Do(func() {
		close(self.reached)
	})
	select {
	case <-self.released:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// One answer of the script (see the file header's answer row).
type ScriptedTurn struct {
	// The call it answers; nil takes any call.
	Match *ScriptedMatch
	// The reasoning deltas, first, each not empty.
	Reasoning []string
	// The text deltas, after the reasoning, each not empty.
	Text []string
	// The tool calls, after the text, in order.
	ToolCalls []*ScriptedToolCall
	// The usage event, after the tool calls; nil sends none.
	Usage *sidecar.InferUsage
	// The error the call fails with once its deltas and usage are out; nil ends the call.
	Fail *sidecar.InferError
	// Cuts the stream; nil plays it whole.
	Cut *ScriptedCut
	// Holds the stream; nil holds nothing.
	Stall *ScriptedStall
}

// One call the model took, as it received it.
type ScriptedCall struct {
	// The model's clock when the call came.
	At time.Time
	// The canonical name it ran under and its effort, as the router resolved them.
	Name   string
	Effort sidecar.InferEffort
	// The request, a deep copy taken when the call came, so a later change by its caller changes nothing here.
	Request *sidecar.InferRequest
	// The index of the turn it took in the script, or -1 for a refused call.
	Turn int
	// What it answered: nil for a turn played whole, the turn's failure or cut, a refusal, or its context's end.
	Err error
}

// One turn of the script and whether a call took it.
type scriptedTurnState struct {
	turn  *ScriptedTurn
	taken bool
}

// See the file header.
type ScriptedModel struct {
	settings *ScriptedModelSettings
	clock    sidecar.Clock
	device   *sidecar.InferDeviceCapabilities
	// the manifest as JSON, which Manifest parses afresh for each caller
	manifestJson []byte

	stateLock sync.Mutex
	turns     []*scriptedTurnState
	calls     []*ScriptedCall
}

var _ sidecar.InferLocalEngine = (*ScriptedModel)(nil)

// A model over args, its manifest held to INFER's format, its turns to ErrScriptedTurnInvalid's rules.
func NewScriptedModel(args *ScriptedModelArgs) (*ScriptedModel, error) {
	if args == nil {
		args = &ScriptedModelArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultScriptedModelSettings()
	}
	if settings.Infer == nil {
		withInfer := *settings
		withInfer.Infer = sidecar.DefaultInferSettings()
		settings = &withInfer
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	}
	device := args.Device
	if device == nil {
		device = &sidecar.InferDeviceCapabilities{
			Platform:        "linux/amd64",
			Class:           sidecar.InferDeviceClassDesktop,
			MemoryByteCount: 64 * 1024 * 1024 * 1024,
			Accelerators:    []sidecar.InferAccelerator{sidecar.InferAcceleratorGpu},
		}
	}
	models := args.Models
	if models == nil {
		models = []*sidecar.InferManifestModel{ScriptedManifestModel(ScriptedModelDefault)}
	}
	manifestJson, err := json.Marshal(&sidecar.InferManifest{Version: 1, Engines: scriptedManifestEngines(), Models: models})
	if err != nil {
		return nil, fmt.Errorf("computetest: the scripted model's manifest: %w", err)
	}
	if _, err := sidecar.ParseInferManifest(manifestJson, settings.Infer); err != nil {
		return nil, fmt.Errorf("computetest: the scripted model's manifest: %w", err)
	}
	deviceCopy := *device
	deviceCopy.Accelerators = slices.Clone(device.Accelerators)
	model := &ScriptedModel{
		settings:     settings,
		clock:        clock,
		device:       &deviceCopy,
		manifestJson: manifestJson,
	}
	if err := model.Script(args.Turns...); err != nil {
		return nil, err
	}
	return model, nil
}

// The platforms a release manifest pins an engine for, GOOS/GOARCH, as INFER's manifest reads them
// (infer_manifest.go): the desktops, whose entries list the helper's library, and the phones, whose apps bundle the
// engine and pin its version alone. Identifiers of the format.
var (
	scriptedDesktopPlatforms = []string{"darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64"}
	scriptedPhonePlatforms   = []string{"ios/arm64", "android/arm64"}
)

// A synthetic SHA-256 for label, in lowercase hex.
func scriptedSha256(label string) string {
	sum := sha256.Sum256([]byte("urnetwork-sidecar computetest " + label))
	return hex.EncodeToString(sum[:])
}

// A synthetic engine for every platform the format knows, so the device's own platform decides as INFER's local view
// does: a desktop's or a phone's runs the model, one with no engine build or an unknown one lists none.
func scriptedManifestEngines() []*sidecar.InferManifestEngine {
	engines := []*sidecar.InferManifestEngine{}
	for _, platform := range scriptedDesktopPlatforms {
		name := "libengine-computetest-" + strings.ReplaceAll(platform, "/", "-") + ".bin"
		engines = append(engines, &sidecar.InferManifestEngine{
			Platform: platform,
			Version:  "v0.0.1",
			Libraries: []*sidecar.InferManifestFile{{
				Name:      name,
				Url:       "https://models.example/computetest/" + name,
				ByteCount: 1024 * 1024,
				Sha256:    scriptedSha256("engine " + platform),
			}},
		})
	}
	for _, platform := range scriptedPhonePlatforms {
		engines = append(engines, &sidecar.InferManifestEngine{Platform: platform, Version: "v0.0.1"})
	}
	return engines
}

// A local model of model part model as the release manifest would list it, every value synthetic: one effort, off; a
// 32k-token window with 8k of output; tools and structured output; text and images; 1 GiB of memory, on a CPU or a
// GPU; one file under models.example with synthetic pins. A test changes what it needs before NewScriptedModel.
func ScriptedManifestModel(model string) *sidecar.InferManifestModel {
	return &sidecar.InferManifestModel{
		Model:              model,
		Efforts:            []sidecar.InferEffort{sidecar.InferEffortOff},
		DefaultEffort:      sidecar.InferEffortOff,
		ContextWindow:      32 * 1024,
		MaxOutput:          8 * 1024,
		Tools:              true,
		StructuredOutput:   true,
		Modalities:         []sidecar.InferModality{sidecar.InferModalityText, sidecar.InferModalityImage},
		License:            "Apache-2.0",
		MinMemoryByteCount: 1024 * 1024 * 1024,
		Accelerators:       []sidecar.InferAccelerator{sidecar.InferAcceleratorCpu, sidecar.InferAcceleratorGpu},
		Files: []*sidecar.InferManifestModelFile{{
			InferManifestFile: sidecar.InferManifestFile{
				Name:      model + ".litertlm",
				Url:       "https://models.example/computetest/" + model + ".litertlm",
				ByteCount: 1024 * 1024,
				Sha256:    scriptedSha256("model " + model),
			},
			IndexSha256: scriptedSha256("model index " + model),
		}},
		DecodeRates: []*sidecar.InferDecodeRate{},
	}
}

// The release manifest that lists the model's models, parsed afresh, so a caller's change reaches no other: what
// INFER's router judges its local view from (sidecar.NewInferRouterForTest).
func (self *ScriptedModel) Manifest() *sidecar.InferManifest {
	// held to the format when the model was built
	manifest, _ := sidecar.ParseInferManifest(self.manifestJson, self.settings.Infer)
	return manifest
}

// The model's clock.
func (self *ScriptedModel) Clock() sidecar.Clock {
	return self.clock
}

// The device it reports, a copy (sidecar.InferLocalEngine). Errs only with ctx.
func (self *ScriptedModel) Capabilities(ctx context.Context) (*sidecar.InferDeviceCapabilities, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	device := *self.device
	device.Accelerators = slices.Clone(self.device.Accelerators)
	return &device, nil
}

// Adds turns to the end of the script, each held to ErrScriptedTurnInvalid's rules: none is added unless all are.
func (self *ScriptedModel) Script(turns ...*ScriptedTurn) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	held := slices.Clone(self.turns)
	for _, turn := range turns {
		if err := scriptedTurnCheck(turn, len(held), held); err != nil {
			return err
		}
		held = append(held, &scriptedTurnState{turn: turn})
	}
	self.turns = held
	return nil
}

// The turns no call has taken yet.
func (self *ScriptedModel) Remaining() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	remaining := 0
	for _, state := range self.turns {
		if !state.taken {
			remaining += 1
		}
	}
	return remaining
}

// Every call the model took, in the order they came, each a copy.
func (self *ScriptedModel) Calls() []*ScriptedCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calls := make([]*ScriptedCall, 0, len(self.calls))
	for _, call := range self.calls {
		copied := *call
		copied.Request = scriptedCloneRequest(call.Request)
		calls = append(calls, &copied)
	}
	return calls
}

// Whether any request the model took holds needle, in any text, reasoning, tool call, tool result, tool definition,
// schema or image byte: what a test asserts a model saw, or never saw. An empty needle is in every request.
func (self *ScriptedModel) Saw(needle []byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, call := range self.calls {
		if scriptedRequestHolds(call.Request, needle) {
			return true
		}
	}
	return false
}

// Runs one call (sidecar.InferLocalEngine): takes its turn, or refuses it with a named error, and plays the turn.
func (self *ScriptedModel) Generate(ctx context.Context, call *sidecar.InferCall, emit sidecar.InferEmit) error {
	turn, index, record, err := self.take(call)
	if err != nil {
		return err
	}
	err = self.play(ctx, turn, index, emit)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		record.Err = err
	}()
	return err
}

// A refusal: sentinel, and the InferError the router turns it into, whose message names it.
func scriptedRefusal(sentinel error, format string, a ...any) error {
	return fmt.Errorf("%w: %w", sentinel, &sidecar.InferError{
		Code:    sidecar.InferErrorEngineFailed,
		Message: sentinel.Error() + ": " + fmt.Sprintf(format, a...),
	})
}

// The turn call takes and its index, with the call's record; or the refusal, recorded too unless it is past the most
// calls.
func (self *ScriptedModel) take(call *sidecar.InferCall) (*ScriptedTurn, int, *ScriptedCall, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.calls) >= self.settings.CallMaxCount {
		return nil, -1, nil, scriptedRefusal(ErrScriptedModelCallLimit, "%d calls taken", len(self.calls))
	}
	record := &ScriptedCall{At: self.clock.Now(), Turn: -1}
	self.calls = append(self.calls, record)
	if call == nil || call.Request == nil {
		record.Err = scriptedRefusal(ErrScriptedModelUnmatched, "a call with no request")
		return nil, -1, nil, record.Err
	}
	record.Name = call.Name
	record.Effort = call.Effort
	record.Request = scriptedCloneRequest(call.Request)
	untaken := 0
	for index, state := range self.turns {
		if state.taken {
			continue
		}
		untaken += 1
		if !state.turn.Match.holds(call) {
			continue
		}
		state.taken = true
		record.Turn = index
		return state.turn, index, record, nil
	}
	if untaken == 0 {
		record.Err = scriptedRefusal(ErrScriptedModelExhausted, "call %d to %s, after %d turns", len(self.calls), call.Name, len(self.turns))
	} else {
		record.Err = scriptedRefusal(ErrScriptedModelUnmatched, "call %d to %s, %d turns left", len(self.calls), call.Name, untaken)
	}
	return nil, -1, nil, record.Err
}

// Whether the match holds for call; a nil match holds for every call.
func (self *ScriptedMatch) holds(call *sidecar.InferCall) bool {
	if self == nil {
		return true
	}
	if self.Model != "" && call.Name != self.Model {
		return false
	}
	var last *sidecar.InferMessage
	for i := len(call.Request.Messages) - 1; 0 <= i; i -= 1 {
		if call.Request.Messages[i] != nil {
			last = call.Request.Messages[i]
			break
		}
	}
	if self.UserText != "" && (last == nil || last.Role != sidecar.InferRoleUser || !strings.Contains(last.Text(), self.UserText)) {
		return false
	}
	if self.ToolCallId != "" || self.ToolResultText != "" {
		if last == nil || last.Role != sidecar.InferRoleTool {
			return false
		}
		if self.ToolCallId != "" && last.ToolCallId != self.ToolCallId {
			return false
		}
		if self.ToolResultText != "" && !strings.Contains(last.Text(), self.ToolResultText) {
			return false
		}
	}
	return true
}

// The argument deltas a tool call sends: its own, else its arguments whole, else none.
func (self *ScriptedToolCall) argumentDeltas() []string {
	if self.ArgumentDeltas != nil {
		return self.ArgumentDeltas
	}
	if self.Arguments == "" {
		return nil
	}
	return []string{self.Arguments}
}

// The deltas a turn sends: text, reasoning and argument deltas alike.
func (self *ScriptedTurn) deltaCount() int {
	count := len(self.Reasoning) + len(self.Text)
	for _, toolCall := range self.ToolCalls {
		count += len(toolCall.argumentDeltas())
	}
	return count
}

// Why turn, the index'th of the script after held, cannot be played, or nil.
func scriptedTurnCheck(turn *ScriptedTurn, index int, held []*scriptedTurnState) error {
	invalid := func(format string, a ...any) error {
		return fmt.Errorf("%w: turn %d: %s", ErrScriptedTurnInvalid, index, fmt.Sprintf(format, a...))
	}
	if turn == nil {
		return invalid("no turn")
	}
	for _, delta := range slices.Concat(turn.Reasoning, turn.Text) {
		// the router drops an empty delta, so a count would not be what a reader sees
		if delta == "" {
			return invalid("an empty delta")
		}
	}
	for i, toolCall := range turn.ToolCalls {
		if toolCall == nil || toolCall.Name == "" {
			return invalid("tool call %d has no name", i+1)
		}
		if toolCall.ArgumentDeltas != nil {
			if slices.Contains(toolCall.ArgumentDeltas, "") || strings.Join(toolCall.ArgumentDeltas, "") != toolCall.Arguments {
				return invalid("tool call %d's argument deltas are empty or do not join to its arguments", i+1)
			}
		}
	}
	if turn.Fail != nil && turn.Fail.Code == "" {
		return invalid("a failure with no code")
	}
	deltaCount := turn.deltaCount()
	if turn.Cut != nil && (turn.Cut.AfterDeltas < 0 || deltaCount < turn.Cut.AfterDeltas) {
		return invalid("a cut after %d of its %d deltas", turn.Cut.AfterDeltas, deltaCount)
	}
	if stall := turn.Stall; stall != nil {
		switch {
		case stall.reached == nil:
			return invalid("a stall not made by NewScriptedStall")
		case stall.AfterDeltas < 0 || deltaCount < stall.AfterDeltas:
			return invalid("a stall after %d of its %d deltas", stall.AfterDeltas, deltaCount)
		case turn.Cut != nil && turn.Cut.AfterDeltas < stall.AfterDeltas:
			return invalid("a stall after its cut, which the stream never reaches")
		case slices.ContainsFunc(held, func(state *scriptedTurnState) bool { return state.turn.Stall == stall }):
			return invalid("a stall another turn holds")
		}
	}
	return nil
}

// Plays turn, the index'th of the script, onto emit (see the file header's answer row).
func (self *ScriptedModel) play(ctx context.Context, turn *ScriptedTurn, index int, emit sidecar.InferEmit) error {
	emit(&sidecar.InferEvent{Kind: sidecar.InferEventStart})
	deltas := 0
	// the stall and the cut sit between deltas: checked before each and once after the last
	at := func() error {
		if turn.Stall != nil && turn.Stall.AfterDeltas == deltas {
			if err := turn.Stall.hold(ctx); err != nil {
				return err
			}
		}
		if turn.Cut != nil && turn.Cut.AfterDeltas == deltas {
			code := turn.Cut.Code
			if code == "" {
				code = sidecar.InferErrorEngineFailed
			}
			return fmt.Errorf("%w: %w", ErrScriptedStreamCut, &sidecar.InferError{
				Code:    code,
				Message: fmt.Sprintf("%s after %d deltas of turn %d", ErrScriptedStreamCut.Error(), deltas, index+1),
			})
		}
		return nil
	}
	delta := func(event *sidecar.InferEvent) error {
		if err := at(); err != nil {
			return err
		}
		emit(event)
		deltas += 1
		return nil
	}
	for _, text := range turn.Reasoning {
		if err := delta(&sidecar.InferEvent{Kind: sidecar.InferEventReasoning, Text: text}); err != nil {
			return err
		}
	}
	for _, text := range turn.Text {
		if err := delta(&sidecar.InferEvent{Kind: sidecar.InferEventText, Text: text}); err != nil {
			return err
		}
	}
	for i, toolCall := range turn.ToolCalls {
		id := toolCall.Id
		if id == "" {
			id = fmt.Sprintf("call_%d_%d", index+1, i+1)
		}
		emit(&sidecar.InferEvent{Kind: sidecar.InferEventToolCallStart, ToolCall: &sidecar.InferToolCall{Id: id, Name: toolCall.Name}})
		for _, arguments := range toolCall.argumentDeltas() {
			if err := delta(&sidecar.InferEvent{Kind: sidecar.InferEventToolCallArgs, ToolCall: &sidecar.InferToolCall{Id: id, Arguments: arguments}}); err != nil {
				return err
			}
		}
		emit(&sidecar.InferEvent{Kind: sidecar.InferEventToolCallEnd, ToolCall: &sidecar.InferToolCall{
			Id:        id,
			Name:      toolCall.Name,
			Arguments: toolCall.Arguments,
		}})
	}
	if err := at(); err != nil {
		return err
	}
	if turn.Usage != nil {
		usage := *turn.Usage
		emit(&sidecar.InferEvent{Kind: sidecar.InferEventUsage, Usage: &usage})
	}
	if turn.Fail != nil {
		failure := *turn.Fail
		return &failure
	}
	return nil
}

// A deep copy of request: every message, part, tool call, tool and schema its own.
func scriptedCloneRequest(request *sidecar.InferRequest) *sidecar.InferRequest {
	if request == nil {
		return nil
	}
	clone := *request
	clone.Messages = nil
	for _, message := range request.Messages {
		if message == nil {
			clone.Messages = append(clone.Messages, nil)
			continue
		}
		copied := *message
		copied.Parts = nil
		for _, part := range message.Parts {
			if part == nil {
				copied.Parts = append(copied.Parts, nil)
				continue
			}
			partCopy := *part
			partCopy.Data = bytes.Clone(part.Data)
			copied.Parts = append(copied.Parts, &partCopy)
		}
		copied.ToolCalls = nil
		for _, toolCall := range message.ToolCalls {
			if toolCall == nil {
				copied.ToolCalls = append(copied.ToolCalls, nil)
				continue
			}
			toolCallCopy := *toolCall
			copied.ToolCalls = append(copied.ToolCalls, &toolCallCopy)
		}
		clone.Messages = append(clone.Messages, &copied)
	}
	clone.Tools = nil
	for _, tool := range request.Tools {
		if tool == nil {
			clone.Tools = append(clone.Tools, nil)
			continue
		}
		toolCopy := *tool
		toolCopy.Schema = json.RawMessage(bytes.Clone(tool.Schema))
		clone.Tools = append(clone.Tools, &toolCopy)
	}
	if request.Schema != nil {
		clone.Schema = json.RawMessage(bytes.Clone(request.Schema))
	}
	if request.Sampling != nil {
		sampling := *request.Sampling
		if request.Sampling.Temperature != nil {
			temperature := *request.Sampling.Temperature
			sampling.Temperature = &temperature
		}
		if request.Sampling.TopP != nil {
			topP := *request.Sampling.TopP
			sampling.TopP = &topP
		}
		sampling.Stops = slices.Clone(request.Sampling.Stops)
		clone.Sampling = &sampling
	}
	if request.RunId != nil {
		runId := *request.RunId
		clone.RunId = &runId
	}
	if request.AgentId != nil {
		agentId := *request.AgentId
		clone.AgentId = &agentId
	}
	if request.Binding != nil {
		binding := *request.Binding
		clone.Binding = &binding
	}
	if request.Budget != nil {
		budget := *request.Budget
		clone.Budget = &budget
	}
	return &clone
}

// Whether request holds needle anywhere a model reads.
func scriptedRequestHolds(request *sidecar.InferRequest, needle []byte) bool {
	if request == nil {
		return false
	}
	holds := func(texts ...string) bool {
		return slices.ContainsFunc(texts, func(text string) bool { return bytes.Contains([]byte(text), needle) })
	}
	if holds(request.Model, request.ToolChoice, request.Reasoning) || bytes.Contains(request.Schema, needle) {
		return true
	}
	if request.Sampling != nil && holds(request.Sampling.Stops...) {
		return true
	}
	for _, message := range request.Messages {
		if message == nil {
			continue
		}
		if holds(message.Reasoning, message.ToolCallId) {
			return true
		}
		for _, part := range message.Parts {
			if part != nil && (holds(part.Text, part.MediaType) || bytes.Contains(part.Data, needle)) {
				return true
			}
		}
		for _, toolCall := range message.ToolCalls {
			if toolCall != nil && holds(toolCall.Id, toolCall.Name, toolCall.Arguments) {
				return true
			}
		}
	}
	for _, tool := range request.Tools {
		if tool != nil && (holds(tool.Name, tool.Description) || bytes.Contains(tool.Schema, needle)) {
			return true
		}
	}
	return false
}
