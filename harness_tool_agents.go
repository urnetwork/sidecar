//go:build !ios_extension && !sidecar_http

// The sub-agent tools, locally (DESIGN-COMPUTE §7.5's agent_launch, agent_prompt, agent_wait and agent_stop row, §7.9,
// R-HARN-3, D-HARN-8; HARN-M11-07): each reaches the agents of this Harness; their remote reach, into an enclave's
// Harness over the attach link's management mode, is HARN-M14-04's, and is refused here.
//
//	agent_launch  W: Harness.Launch (harness_launch.go), with where local; a refused launch answers its code
//	              (model_refused, disclosure_required, depth_limit, budget_limit, tool_budget, where_refused) and leaves
//	              no card
//	agent_prompt  W: a prompt, steer or follow-up from the calling run's origin, which taints its receiver, write-ahead,
//	              where the calling run is tainted, its text reaching the receiver's model between untrusted-data markers
//	agent_wait    R: returns when the agent settles, with its last message, or past the timeout that it is still at
//	              work; the caller gives its work slot up while it waits. An answer from a tainted run taints the
//	              caller (its result untrusted), and the answerer's marks join the caller's, each write-ahead before the
//	              answer returns
//	agent_stop    W: aborts the agent and closes its run, its card staying (§20.7); from a tainted run only for agents
//	              it launched, any other waiting for the person's confirmation in the app or on /dev/tty
//
// An agent is named by its id or its registered name. No tool reaches the calling agent itself.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// The tools' names (§7.9).
const (
	HarnessToolAgentLaunch = "agent_launch"
	HarnessToolAgentPrompt = "agent_prompt"
	HarnessToolAgentWait   = "agent_wait"
	HarnessToolAgentStop   = "agent_stop"
)

// agent_prompt's modes.
const (
	harnessAgentPromptModePrompt   = "prompt"
	harnessAgentPromptModeSteer    = "steer"
	harnessAgentPromptModeFollowUp = "follow_up"
)

// The tools' descriptions, which the model reads: fixed by the build.
const (
	harnessAgentLaunchDescription = "Launches a sub-agent in this Harness on a model from models_list, with instructions it starts on: " +
		"name it for its task, give it the tools it needs (empty for its profile's set), and optionally a budget in USD per " +
		"day, month and run, which comes out of yours. A model a rule refuses answers model_refused, one whose disclosure " +
		"is not acknowledged disclosure_required; pick another model or tell your person. Agents launch at most 4 levels deep."
	harnessAgentPromptDescription = "Sends an agent of this Harness a prompt, or with mode steer delivers it after its current turn, or with " +
		"follow_up once it has no more work. A prompt to an agent at work is refused: steer or follow up instead."
	harnessAgentWaitDescription = "Waits until an agent of this Harness settles and returns its last message, or, past timeout_ms, that it " +
		"is still at work. An answer from a run that read untrusted content comes back marked untrusted."
	harnessAgentStopDescription = "Stops an agent of this Harness: its turn is aborted and its run closed. Stopping one you did not " +
		"launch, after reading untrusted content, waits for your person's confirmation."
)

// The tools' argument schemas.
var (
	harnessAgentLaunchSchema = []byte(`{"type":"object","properties":{` +
		`"name":{"type":"string","description":"The sub-agent's name, for its task."},` +
		`"model":{"type":"string","description":"A model's canonical name, from models_list."},` +
		`"instructions":{"type":"string","description":"What it is to do: its first prompt."},` +
		`"tools":{"type":"array","items":{"type":"string"},"description":"Its tools; empty for its profile's set."},` +
		`"where":{"type":"string","enum":["local"],"description":"local: in this Harness."},` +
		`"budget":{"type":"object","properties":{"day":{"type":"number","minimum":0},"month":{"type":"number","minimum":0},` +
		`"run":{"type":"number","minimum":0}},"additionalProperties":false,"description":"USD per day, month and run, out of yours."}},` +
		`"required":["name","model","instructions"],"additionalProperties":false}`)
	harnessAgentPromptSchema = []byte(`{"type":"object","properties":{` +
		`"agent":{"type":"string","description":"The agent's id or name."},` +
		`"text":{"type":"string"},` +
		`"mode":{"type":"string","enum":["prompt","steer","follow_up"]}},` +
		`"required":["agent","text"],"additionalProperties":false}`)
	harnessAgentWaitSchema = []byte(`{"type":"object","properties":{` +
		`"agent":{"type":"string","description":"The agent's id or name."},` +
		`"timeout_ms":{"type":"integer","minimum":0}},` +
		`"required":["agent"],"additionalProperties":false}`)
	harnessAgentStopSchema = []byte(`{"type":"object","properties":{` +
		`"agent":{"type":"string","description":"The agent's id or name."}},` +
		`"required":["agent"],"additionalProperties":false}`)
)

// The tools' refusals, each constant.
var (
	errHarnessAgentArguments = errors.New("the arguments do not read")
	errHarnessAgentSelf      = errors.New("an agent tool never reaches the calling agent itself")
	errHarnessAgentNoCaller  = errors.New("the calling agent is not open in this Harness")
	errHarnessAgentStopNo    = errors.New("the person did not confirm stopping that agent")
	errHarnessAgentMode      = errors.New("mode is prompt, steer or follow_up")
	errHarnessAgentTimeout   = errors.New("timeout_ms is past the longest agent_wait waits")
)

// Registers the four tools for both profiles.
func init() {
	for _, tool := range []struct {
		name        string
		description string
		schema      []byte
		tier        string
		execute     func(ctx context.Context, tool *harnessAgentTool, call *HarnessCall, caller *harnessAgent, args []byte) (*HarnessToolResult, error)
	}{
		{name: HarnessToolAgentLaunch, description: harnessAgentLaunchDescription, schema: harnessAgentLaunchSchema,
			tier: HarnessToolTierWrite, execute: harnessAgentLaunchCall},
		{name: HarnessToolAgentPrompt, description: harnessAgentPromptDescription, schema: harnessAgentPromptSchema,
			tier: HarnessToolTierWrite, execute: harnessAgentPromptCall},
		{name: HarnessToolAgentWait, description: harnessAgentWaitDescription, schema: harnessAgentWaitSchema,
			tier: HarnessToolTierRead, execute: harnessAgentWaitCall},
		{name: HarnessToolAgentStop, description: harnessAgentStopDescription, schema: harnessAgentStopSchema,
			tier: HarnessToolTierWrite, execute: harnessAgentStopCall},
	} {
		RegisterHarnessTool(&HarnessToolSpec{
			Name:     tool.name,
			Profiles: []HarnessProfile{HarnessProfileLocal, HarnessProfileEnclave},
			BuiltIn:  true,
			New: func(harness *Harness) (HarnessTool, error) {
				if harness == nil {
					return nil, ErrHarnessToolOff
				}
				return &harnessAgentTool{harness: harness, name: tool.name, description: tool.description, schema: tool.schema,
					tier: tool.tier, execute: tool.execute}, nil
			},
		})
	}
}

// One sub-agent tool.
type harnessAgentTool struct {
	harness     *Harness
	name        string
	description string
	schema      []byte
	tier        string
	execute     func(ctx context.Context, tool *harnessAgentTool, call *HarnessCall, caller *harnessAgent, args []byte) (*HarnessToolResult, error)
}

var _ HarnessTool = (*harnessAgentTool)(nil)

// The tool's name.
func (self *harnessAgentTool) Name() string {
	return self.name
}

// One of this file's constants.
func (self *harnessAgentTool) Description() string {
	return self.description
}

// The arguments' JSON schema.
func (self *harnessAgentTool) Schema() []byte {
	return self.schema
}

// Parallel: each call reaches its own agent.
func (self *harnessAgentTool) Mode() string {
	return HarnessToolParallel
}

// §7.5's tier: W, agent_wait R.
func (self *harnessAgentTool) Tier() string {
	return self.tier
}

// Runs one call for the calling agent.
func (self *harnessAgentTool) Execute(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
	call, ok := HarnessCallFromContext(ctx)
	if !ok || call.Run() == nil {
		return nil, errHarnessDesignNoRun
	}
	caller, ok := self.harness.agentOf(call.AgentId())
	if !ok || caller.isClosed() {
		return nil, errHarnessAgentNoCaller
	}
	return self.execute(ctx, self, call, caller, args)
}

// The agent args name, never the caller.
func (self *harnessAgentTool) target(caller *harnessAgent, name string) (*harnessAgent, error) {
	agent, err := self.harness.agentByIdOrName(name)
	if err != nil {
		return nil, err
	}
	if agent == caller {
		return nil, errHarnessAgentSelf
	}
	return agent, nil
}

// A trusted result of out as JSON.
func harnessAgentResult(out any, trust string) (*HarnessToolResult, error) {
	encoded, err := harnessJsonOf(out)
	if err != nil {
		return nil, err
	}
	return &HarnessToolResult{Text: encoded, Details: []byte(encoded), Trust: trust}, nil
}

// v as JSON text.
func harnessJsonOf(v any) (string, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("the result does not encode: %w", err)
	}
	return string(encoded), nil
}

// USD as nano-USD, rounded down; 0 for none.
func harnessNanoUsdOf(usd float64) uint64 {
	if usd <= 0 || math.IsNaN(usd) || math.IsInf(usd, 0) {
		return 0
	}
	return uint64(math.Floor(usd * 1e9))
}

// agent_launch's arguments.
type harnessAgentLaunchIn struct {
	Name         string   `json:"name"`
	Model        string   `json:"model"`
	Instructions string   `json:"instructions"`
	Tools        []string `json:"tools,omitempty"`
	Where        string   `json:"where,omitempty"`
	Budget       *struct {
		Day   float64 `json:"day,omitempty"`
		Month float64 `json:"month,omitempty"`
		Run   float64 `json:"run,omitempty"`
	} `json:"budget,omitempty"`
}

// What a launch, a prompt, a wait or a stop answers.
type harnessAgentOut struct {
	Agent string `json:"agent"`
	Name  string `json:"name,omitempty"`
	Run   string `json:"run,omitempty"`
	Model string `json:"model,omitempty"`
	Where string `json:"where,omitempty"`
	// launched, sent, settled, working or stopped
	Status string `json:"status"`
	// agent_prompt's mode
	Mode string `json:"mode,omitempty"`
	// agent_wait's: the settled run's stop reason and its last message
	StopReason string `json:"stop_reason,omitempty"`
	Message    string `json:"message,omitempty"`
}

// agent_launch: a child of the caller in this Harness.
func harnessAgentLaunchCall(ctx context.Context, tool *harnessAgentTool, call *HarnessCall, caller *harnessAgent, args []byte) (*HarnessToolResult, error) {
	in := &harnessAgentLaunchIn{}
	if err := harnessDesignArgs(args, in); err != nil {
		return nil, errHarnessAgentArguments
	}
	spec := &HarnessLaunchSpec{Name: in.Name, Model: in.Model, Instructions: in.Instructions, Tools: in.Tools, Where: in.Where}
	if in.Budget != nil {
		spec.Budget = &HarnessBudget{DayNanoUsd: harnessNanoUsdOf(in.Budget.Day), MonthNanoUsd: harnessNanoUsdOf(in.Budget.Month),
			RunNanoUsd: harnessNanoUsdOf(in.Budget.Run)}
	}
	child, err := tool.harness.launch(ctx, caller.id, spec)
	if err != nil {
		// a refusal's code leads its text, so the agent reads why and picks another model or tells the person
		return nil, err
	}
	return harnessAgentResult(&harnessAgentOut{Agent: child.id.String(), Name: child.name, Run: child.run.Id().String(),
		Model: child.currentModel(), Where: HarnessLaunchWhereLocal, Status: "launched"}, HarnessToolTrusted)
}

// agent_prompt's arguments.
type harnessAgentPromptIn struct {
	Agent string `json:"agent"`
	Text  string `json:"text"`
	Mode  string `json:"mode,omitempty"`
}

// agent_prompt: text from the calling run's origin, which taints its receiver where the calling run is tainted.
func harnessAgentPromptCall(ctx context.Context, tool *harnessAgentTool, call *HarnessCall, caller *harnessAgent, args []byte) (*HarnessToolResult, error) {
	in := &harnessAgentPromptIn{}
	if err := harnessDesignArgs(args, in); err != nil {
		return nil, errHarnessAgentArguments
	}
	target, err := tool.target(caller, in.Agent)
	if err != nil {
		return nil, err
	}
	// the calling run's origin, its taint read now, as its Harness keeps it
	origin := HarnessRunOrigin(call.Run().Id(), caller.id, call.Run().Tainted())
	mode := in.Mode
	switch mode {
	case "", harnessAgentPromptModePrompt:
		mode = harnessAgentPromptModePrompt
		err = target.PromptAs(ctx, origin, in.Text, nil)
	case harnessAgentPromptModeSteer:
		err = target.SteerAs(ctx, origin, in.Text)
	case harnessAgentPromptModeFollowUp:
		err = target.FollowUpAs(ctx, origin, in.Text)
	default:
		return nil, errHarnessAgentMode
	}
	if err != nil {
		return nil, err
	}
	// marks follow the work as taint does (§7.8): the prompt carries the calling run's into its receiver
	if marks, err := call.Run().Marks(); err != nil || marks != 0 {
		if err != nil {
			marks = harnessMarkAll
		}
		if err := target.run.Mark(ctx, marks); err != nil {
			return nil, err
		}
	}
	return harnessAgentResult(&harnessAgentOut{Agent: target.id.String(), Name: target.name, Status: "sent", Mode: mode}, HarnessToolTrusted)
}

// agent_wait's arguments.
type harnessAgentWaitIn struct {
	Agent     string `json:"agent"`
	TimeoutMs *int64 `json:"timeout_ms,omitempty"`
}

// agent_wait: the agent's last message once it settles, the caller tainted and marked first where the answer's run is.
func harnessAgentWaitCall(ctx context.Context, tool *harnessAgentTool, call *HarnessCall, caller *harnessAgent, args []byte) (*HarnessToolResult, error) {
	in := &harnessAgentWaitIn{}
	if err := harnessDesignArgs(args, in); err != nil {
		return nil, errHarnessAgentArguments
	}
	settings := tool.harness.settings
	timeout := settings.AgentWaitTimeout
	if in.TimeoutMs != nil {
		timeout = time.Duration(*in.TimeoutMs) * time.Millisecond
		if *in.TimeoutMs < 0 || settings.AgentWaitMaxTimeout < timeout {
			return nil, errHarnessAgentTimeout
		}
	}
	target, err := tool.target(caller, in.Agent)
	if err != nil {
		return nil, err
	}
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := tool.harness.clock.AfterFunc(timeout, cancel)
	defer stop()
	settled := false
	caller.yieldWorkSlot(ctx, func() {
		settled = target.WaitForIdle(waitCtx) == nil
	})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	out := &harnessAgentOut{Agent: target.id.String(), Name: target.name, Status: "working"}
	if !settled {
		return harnessAgentResult(out, HarnessToolTrusted)
	}
	out.Status = "settled"
	message, stopReason := func() (*HarnessPiMessage, string) {
		target.stateLock.Lock()
		defer target.stateLock.Unlock()
		return target.lastMessage, target.lastStopReason
	}()
	out.StopReason = stopReason
	if message != nil {
		out.Message = message.Text()
	}
	// marks follow the work: the answerer's join the caller's before its answer returns
	if marks, err := target.run.Marks(); err != nil || marks != 0 {
		if err != nil {
			marks = harnessMarkAll
		}
		if err := call.Run().Mark(ctx, marks); err != nil {
			return nil, err
		}
	}
	trust := HarnessToolTrusted
	if target.run.Tainted() {
		// a tainted run's answer taints its reader: harnessRunToolCall taints the caller, write-ahead, before it returns
		trust = HarnessToolUntrusted
	}
	return harnessAgentResult(out, trust)
}

// agent_stop's arguments.
type harnessAgentStopIn struct {
	Agent string `json:"agent"`
}

// agent_stop: the agent aborted and closed, from a tainted run only for agents it launched without the person.
func harnessAgentStopCall(ctx context.Context, tool *harnessAgentTool, call *HarnessCall, caller *harnessAgent, args []byte) (*HarnessToolResult, error) {
	in := &harnessAgentStopIn{}
	if err := harnessDesignArgs(args, in); err != nil {
		return nil, errHarnessAgentArguments
	}
	target, err := tool.target(caller, in.Agent)
	if err != nil {
		return nil, err
	}
	if call.Run().Tainted() && !target.launchedBy(caller) {
		// another's agent from a tainted run: only the person's confirmation stops it
		response, err := call.Ask(ctx, &HarnessUiRequest{Method: HarnessUiConfirm, Title: "Stop an agent?",
			Message: fmt.Sprintf("An agent that read untrusted content asks to stop agent %s, which it did not launch.", target.name)})
		if err != nil || response == nil || response.Confirmed == nil || !*response.Confirmed {
			return nil, errHarnessAgentStopNo
		}
	}
	target.Abort()
	target.Close()
	return harnessAgentResult(&harnessAgentOut{Agent: target.id.String(), Name: target.name, Status: "stopped"}, HarnessToolTrusted)
}
