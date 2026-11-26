//go:build !ios_extension && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The daemon's Harness methods (DESIGN-COMPUTE §7.11, DESIGN §5.8's remote mode, R-HARN-1, R-HARN-2): `ur harness` is a
// view of the daemon's Harness, so a run it starts stays open after its terminal closes and `/close` closes it, and a
// desktop app in remote mode reaches the same Harness through the same methods (HARN-M11-10). Each acts on one network
// (Network), that network's Sidecar's Harness behind it, and ur's daemon serves them through urDaemonMethodExtensions.
//
//	harness.agent       {agent?, name?, model?}: the open agent of that id, else the open one of that registered name,
//	                    else a new agent of the local profile on model, the catalog's recommended local model where none
//	                    is named. A model given for an open agent is a SetModel, the person's alone. Answers the agent's
//	                    id, name, run and model, whether it was made, and whether it runs a prompt now
//	harness.prompt      {agent, text, mode}: mode prompt (the default), steer or follow_up. The daemon sets the origin,
//	                    never the caller: the person's where the caller confirmed the call, ur having read the text from
//	                    /dev/tty, and no harness process is among its ancestors (Sidecar.HarnessAncestor, the closed
//	                    reading where they cannot be read), else an unknown run's, whose text taints the run before it
//	                    enters it (§7.10's origin). mode abort ends the turn, the person's alone
//	harness.events      {agent, after, wait_ms}: the agent's events past seq after, each its JSON as emitted, at once
//	                    where there are some, else after a wait of at most DaemonViewWait; gap where the view log no
//	                    longer holds, or never held, what follows after; closed once the agent closed and nothing more
//	                    follows; and the ui requests waiting on its run. The person's view marks the person attached to
//	                    the agent's run until its session ends (HarnessUiBroker.AttachPerson), so the run may ask them
//	harness.respond_ui  {agent, response}: a select, confirm or input's answer, or a disclosure's decline, the person's
//	                    alone; a disclosure's acknowledgment is CTRUST's act, never this (D-HARN-10)
//	harness.close       {agent}: ends the agent's run for good, its card staying (§20.7), the person's alone
//
// Nothing here carries a secret, so every reply passes the reply walk. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// The control methods' names (DESIGN §5.8's remote mode).
const (
	HarnessDaemonMethodAgent     = "harness.agent"
	HarnessDaemonMethodPrompt    = "harness.prompt"
	HarnessDaemonMethodEvents    = "harness.events"
	HarnessDaemonMethodRespondUi = "harness.respond_ui"
	HarnessDaemonMethodClose     = "harness.close"
)

// harness.prompt's modes.
const (
	HarnessPromptModePrompt   = "prompt"
	HarnessPromptModeSteer    = "steer"
	HarnessPromptModeFollowUp = "follow_up"
	HarnessPromptModeAbort    = "abort"
)

// harness.prompt's dispositions, Pi's words and abort's.
const (
	HarnessPromptStarted = "started"
	HarnessPromptQueued  = "queued"
	HarnessPromptAborted = "aborted"
)

var (
	// The act is the person's alone: confirmed on /dev/tty or in an app's UI, with no harness process among the
	// caller's ancestors.
	ErrHarnessPersonOnly = errors.New("this is the person's own act, from a terminal or the app with no harness process among its ancestors")
	// No agent of that id is open in the network's Harness.
	ErrHarnessAgentUnknown = errors.New("no such agent is open in this harness")
	// No model was named, and the catalog recommends none for this device.
	ErrHarnessModelUnnamed = errors.New("name a model: this device's catalog recommends none (ur models lists them)")
)

// harness.agent's params.
type HarnessAgentParams struct {
	Network string `json:"network,omitempty"`
	// An open agent's id.
	Agent string `json:"agent,omitempty"`
	// A registered name: the open agent of it, else a new agent registered under it.
	Name  string `json:"name,omitempty"`
	Model string `json:"model,omitempty"`
}

// harness.agent's reply.
type HarnessAgentReply struct {
	Agent   string `json:"agent"`
	Name    string `json:"name"`
	Run     string `json:"run"`
	Model   string `json:"model"`
	Created bool   `json:"created"`
	Running bool   `json:"running"`
}

// harness.prompt's params.
type HarnessPromptParams struct {
	Network string `json:"network,omitempty"`
	Agent   string `json:"agent"`
	Text    string `json:"text,omitempty"`
	// prompt (empty), steer, follow_up or abort
	Mode string `json:"mode,omitempty"`
}

// harness.prompt's reply.
type HarnessPromptReply struct {
	Disposition string `json:"disposition"`
	// The text came from an origin that is not trusted, so it tainted the run and reaches the model fenced.
	Untrusted bool `json:"untrusted,omitempty"`
}

// harness.events' params.
type HarnessEventsParams struct {
	Network string `json:"network,omitempty"`
	Agent   string `json:"agent"`
	// The seq of the last event taken; 0 for none yet.
	After uint64 `json:"after,omitempty"`
	// How long to wait for an event past After where none is there yet, in milliseconds, at most DaemonViewWait.
	// Zero or less answers at once.
	WaitMs int64 `json:"wait_ms,omitempty"`
}

// harness.events' reply.
type HarnessEventsReply struct {
	Events []json.RawMessage `json:"events"`
	// The seq to send as after next.
	Next   uint64 `json:"next"`
	Gap    bool   `json:"gap,omitempty"`
	Closed bool   `json:"closed,omitempty"`
	// The ui requests waiting on the agent's run now, for a view that missed the event that raised one.
	Pending []*HarnessUiRequest `json:"pending,omitempty"`
}

// harness.respond_ui's params.
type HarnessRespondUiParams struct {
	Network  string             `json:"network,omitempty"`
	Agent    string             `json:"agent"`
	Response *HarnessUiResponse `json:"response"`
}

// harness.close's params.
type HarnessCloseParams struct {
	Network string `json:"network,omitempty"`
	Agent   string `json:"agent"`
}

// What the methods are built on: the Harness a call reaches, and whether its caller runs under a harness.
type harnessDaemonSource struct {
	harness      func(call *DaemonCall) (*Harness, error)
	underHarness func(ctx context.Context, call *DaemonCall) bool
}

// The methods over each network's Sidecar: its Harness, and its run files' ancestry rule.
func HarnessDaemonMethods() []*DaemonMethod {
	return harnessDaemonMethods(&harnessDaemonSource{
		harness: func(call *DaemonCall) (*Harness, error) {
			if call.Sidecar == nil {
				return nil, fmt.Errorf("%w: no sidecar runs for this network", ErrComputeComponentUnavailable)
			}
			return call.Sidecar.Harness()
		},
		underHarness: func(ctx context.Context, call *DaemonCall) bool {
			if call.Sidecar == nil || call.Hello == nil || call.Hello.PeerPid <= 0 {
				return true
			}
			return call.Sidecar.HarnessAncestor(ctx, int(call.Hello.PeerPid))
		},
	})
}

// A call's params that do not decode. The text names nothing they held, since a prompt's text may be private.
var errHarnessDaemonParams = errors.New("the params do not decode")

// Decodes a call's params into params, refusing a member it does not know; none is an empty object.
func harnessDaemonParams(call *DaemonCall, params any) error {
	if len(call.Params) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(call.Params))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(params); err != nil {
		return errHarnessDaemonParams
	}
	return nil
}

// The open agent of the id a call names.
func harnessDaemonAgent(harness *Harness, agentId string) (HarnessAgent, error) {
	id, err := ParseId(agentId)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrHarnessAgentUnknown, agentId)
	}
	agent, ok := harness.Agent(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrHarnessAgentUnknown, id)
	}
	return agent, nil
}

// The open agent of the registered name, or nil.
func (self *Harness) agentNamed(name string) HarnessAgent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, agent := range self.agents {
		if agent.name == name && !agent.isClosed() {
			return agent
		}
	}
	return nil
}

// The reply naming agent.
func harnessAgentReplyOf(agent HarnessAgent, created bool) *HarnessAgentReply {
	model := ""
	if inner, ok := agent.(*harnessAgent); ok {
		model = inner.currentModel()
	}
	return &HarnessAgentReply{
		Agent:   agent.Id().String(),
		Name:    agent.Name(),
		Run:     agent.Run().Id().String(),
		Model:   model,
		Created: created,
		Running: agent.Running(),
	}
}

// The methods over source.
func harnessDaemonMethods(source *harnessDaemonSource) []*DaemonMethod {
	// the person's own act: confirmed, and no harness process among the caller's ancestors
	person := func(ctx context.Context, call *DaemonCall) bool {
		return call.Confirmed && !source.underHarness(ctx, call)
	}
	return []*DaemonMethod{
		{
			Name:    HarnessDaemonMethodAgent,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &HarnessAgentParams{}
				if err := harnessDaemonParams(call, params); err != nil {
					return nil, err
				}
				harness, err := source.harness(call)
				if err != nil {
					return nil, err
				}
				view := harness.viewLog()
				var agent HarnessAgent
				switch {
				case params.Agent != "":
					if agent, err = harnessDaemonAgent(harness, params.Agent); err != nil {
						return nil, err
					}
				case params.Name != "":
					agent = harness.agentNamed(params.Name)
				}
				if agent != nil {
					if params.Model != "" {
						if !person(ctx, call) {
							return nil, ErrHarnessPersonOnly
						}
						if err := agent.SetModel(params.Model); err != nil {
							return nil, err
						}
					}
					view.open(agent.Id(), harness.stamper.seqOf(agent.Id()))
					return harnessAgentReplyOf(agent, false), nil
				}
				model := params.Model
				if model == "" {
					catalog, err := harness.router.Catalog(ctx)
					if err != nil {
						return nil, err
					}
					if model, _ = catalog.Recommended(); model == "" {
						return nil, ErrHarnessModelUnnamed
					}
				}
				agent, err = harness.NewAgent(ctx, &HarnessAgentSpec{Name: params.Name, Model: model, Profile: HarnessProfileLocal})
				if err != nil {
					return nil, err
				}
				view.open(agent.Id(), harness.stamper.seqOf(agent.Id()))
				return harnessAgentReplyOf(agent, true), nil
			},
		},
		{
			Name:    HarnessDaemonMethodPrompt,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &HarnessPromptParams{}
				if err := harnessDaemonParams(call, params); err != nil {
					return nil, err
				}
				harness, err := source.harness(call)
				if err != nil {
					return nil, err
				}
				agent, err := harnessDaemonAgent(harness, params.Agent)
				if err != nil {
					return nil, err
				}
				// the origin is the daemon's to set, from the call's confirmation and its caller's ancestry (§7.10)
				origin := HarnessUnknownOrigin("")
				if person(ctx, call) {
					origin = HarnessPersonOrigin()
				}
				reply := &HarnessPromptReply{Untrusted: !origin.Trusted()}
				switch params.Mode {
				case "", HarnessPromptModePrompt:
					if err := agent.PromptAs(ctx, origin, params.Text, nil); err != nil {
						return nil, err
					}
					reply.Disposition = HarnessPromptStarted
				case HarnessPromptModeSteer:
					if err := agent.SteerAs(ctx, origin, params.Text); err != nil {
						return nil, err
					}
					reply.Disposition = HarnessPromptQueued
				case HarnessPromptModeFollowUp:
					if err := agent.FollowUpAs(ctx, origin, params.Text); err != nil {
						return nil, err
					}
					reply.Disposition = HarnessPromptQueued
				case HarnessPromptModeAbort:
					// an unknown run may not stop the person's agents (§7.10's agent_stop rule)
					if !origin.Trusted() {
						return nil, ErrHarnessPersonOnly
					}
					agent.Abort()
					reply.Disposition = HarnessPromptAborted
				default:
					return nil, fmt.Errorf("%w: no mode %q", ErrHarnessSpecInvalid, params.Mode)
				}
				return reply, nil
			},
		},
		{
			Name:    HarnessDaemonMethodEvents,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &HarnessEventsParams{}
				if err := harnessDaemonParams(call, params); err != nil {
					return nil, err
				}
				harness, err := source.harness(call)
				if err != nil {
					return nil, err
				}
				agentId, err := ParseId(params.Agent)
				if err != nil {
					return nil, fmt.Errorf("%w: %q", ErrHarnessAgentUnknown, params.Agent)
				}
				view := harness.viewLog()
				if agent, ok := harness.Agent(agentId); ok {
					view.open(agentId, harness.stamper.seqOf(agentId))
					if person(ctx, call) {
						// the person's view watches the run for the life of its session, so the run may ask them
						defer view.attachSession(harness.UiBroker(), call.SessionDone, agent.Run().Id())()
					}
				}
				settings := harness.settings
				wait := time.Duration(params.WaitMs) * time.Millisecond
				if settings.DaemonViewWait < wait {
					wait = settings.DaemonViewWait
				}
				var timeout chan struct{}
				if 0 < wait {
					timeout = make(chan struct{})
					stop := harness.clock.AfterFunc(wait, func() {
						close(timeout)
					})
					defer stop()
				}
				for {
					read := view.read(agentId, params.After, max(1, settings.DaemonViewReplyEventCount),
						settings.DaemonViewReplyByteCount)
					if !read.known {
						return nil, fmt.Errorf("%w: %s", ErrHarnessAgentUnknown, agentId)
					}
					if 0 < len(read.events) || read.gap || read.closed || timeout == nil {
						reply := &HarnessEventsReply{Events: read.events, Next: read.next, Gap: read.gap, Closed: read.closed}
						if agent, ok := harness.Agent(agentId); ok {
							reply.Pending = harness.UiBroker().Pending(agent.Run().Id())
						}
						return reply, nil
					}
					select {
					case <-read.changed:
					case <-timeout:
						timeout = nil
					case <-call.SessionDone:
						return &HarnessEventsReply{Events: read.events, Next: read.next}, nil
					case <-ctx.Done():
						return &HarnessEventsReply{Events: read.events, Next: read.next}, nil
					}
				}
			},
		},
		{
			Name:    HarnessDaemonMethodRespondUi,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &HarnessRespondUiParams{}
				if err := harnessDaemonParams(call, params); err != nil {
					return nil, err
				}
				// no agent answers a dialog, its own or another's (§7.10's never list)
				if !person(ctx, call) {
					return nil, ErrHarnessPersonOnly
				}
				harness, err := source.harness(call)
				if err != nil {
					return nil, err
				}
				if _, err := harnessDaemonAgent(harness, params.Agent); err != nil {
					return nil, err
				}
				if params.Response == nil {
					return nil, ErrHarnessUiAnswerInvalid
				}
				// Respond refuses an acknowledgment, which only CTRUST's store records
				return nil, harness.UiBroker().Respond(params.Response)
			},
		},
		{
			Name:    HarnessDaemonMethodClose,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &HarnessCloseParams{}
				if err := harnessDaemonParams(call, params); err != nil {
					return nil, err
				}
				if !person(ctx, call) {
					return nil, ErrHarnessPersonOnly
				}
				harness, err := source.harness(call)
				if err != nil {
					return nil, err
				}
				agent, err := harnessDaemonAgent(harness, params.Agent)
				if err != nil {
					return nil, err
				}
				agent.Close()
				return nil, nil
			},
		},
	}
}
