//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's model and inference methods (DESIGN-COMPUTE §6.3-§6.5, §15.1, §15.3; INFER-M11-08): what `ur models`,
// `ur infer` and a remote-mode app's Models() call, on desktop legs only, each on its call's network (§5.8's rule):
//
//	models.list       the catalog for this device and policy by canonical name (InferModelsListing), filtered by
//	                  --local, --tee or --provider
//	models.pull       a local model and, on a desktop, its engine's files, through the instance's one InferPull: a pull
//	                  runs in the daemon until it ends, whoever asked; follow streams its progress as
//	                  models.pull.progress notifications and answers once it ends (ur models pull), else the call
//	                  answers its state at once, which an app polls (Models().Pull); a pull that ended is answered once
//	models.remove     a local model's files, every state of them
//	models.settings   the person's models key, as this device reads it (§16.4; InferModelsSettings)
//	models.set        a change to the models key: a Confirm method, the person's act on /dev/tty or in an app's UI,
//	                  refused to a caller with a harness process among its ancestors (DESIGN §5.8), written through
//	                  CACL's writer (Sidecar.SetModelsKey) and never through MCP
//	infer.run         one prompt through the router in a run the daemon opens for it, its events streamed as
//	                  infer.event notifications, its call recorded as a model_call through InferModelCall (R-INFER-6),
//	                  so ur infer's calls are recorded outside the Harness too
//
// A refusal the router answers, disclosure_required naming its disclosure among them, is infer.run's reply rather than
// an rpc error, so ur infer can take the person's acknowledgment and ask again. ur native-host relays none of these.
// Params are read strictly. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
)

// The methods and their notifications.
const (
	DaemonMethodModelsList     = "models.list"
	DaemonMethodModelsPull     = "models.pull"
	DaemonMethodModelsRemove   = "models.remove"
	DaemonMethodModelsSettings = "models.settings"
	DaemonMethodModelsSet      = "models.set"
	DaemonMethodInferRun       = "infer.run"

	DaemonNotifyModelsPullProgress = "models.pull.progress"
	DaemonNotifyInferEvent         = "infer.event"
)

// A pull's states, InferPulls'.
const (
	DaemonModelsPullRunning = InferPullRunning
	DaemonModelsPullDone    = InferPullDone
	DaemonModelsPullFailed  = InferPullFailed
)

// The harness name of the run infer.run opens.
const daemonInferRunHarness = "ur-infer"

// models.list's params.
type DaemonModelsListParams struct {
	Network string `json:"network,omitempty"`
	InferModelsFilter
}

// models.pull's params.
type DaemonModelsPullParams struct {
	Network string `json:"network,omitempty"`
	// A local model's canonical name or alias.
	Name string `json:"name"`
	// Stream the pull's progress and answer once it ends; else answer its state at once.
	Follow bool `json:"follow,omitempty"`
}

// models.pull's reply, and each of its notifications: where the pull is, InferPulls' status.
type DaemonModelsPullReply = InferPullStatus

// models.remove's params.
type DaemonModelsRemoveParams struct {
	Network string `json:"network,omitempty"`
	Name    string `json:"name"`
}

// Params naming the call's network alone.
type DaemonModelsParams struct {
	Network string `json:"network,omitempty"`
}

// models.set's params: the change.
type DaemonModelsSetParams struct {
	Network string `json:"network,omitempty"`
	InferModelsChange
}

// infer.run's params.
type DaemonInferRunParams struct {
	Network string `json:"network,omitempty"`
	// A canonical name or an alias (§6.3).
	Model string `json:"model"`
	// The person's prompt, the call's one user message.
	Prompt string `json:"prompt"`
	// An alias's effort, none to max; empty for the model's default.
	Reasoning string `json:"reasoning,omitempty"`
}

// infer.run's reply: the run it opened, the canonical name the call ran under, its usage, and its error, the router's
// refusal or the call's failure; and whether its model_call was recorded, or why not.
type DaemonInferRunReply struct {
	RunId       Id          `json:"run_id"`
	Model       string      `json:"model,omitempty"`
	Usage       *InferUsage `json:"usage,omitempty"`
	Error       *InferError `json:"error,omitempty"`
	Recorded    bool        `json:"recorded"`
	RecordError string      `json:"record_error,omitempty"`
}

// What the methods act through.
type DaemonInferArgs struct {
	// The daemon's one pull over the instance's model and engine directories, which every network's models.pull,
	// models.remove and models.list take; nil refuses a pull and a removal and lists no file state.
	Pull *InferPull
	// The daemon's context: a pull runs until it ends or the daemon does, whoever asked.
	Ctx context.Context
	// Nil for the defaults: how often a follower's progress is sent, by chunk and by ModelChunkByteCount of an
	// engine file's bytes.
	Settings *InferSettings
}

// The params of a call that do not decode, or of an unbound call: the text names nothing they held.
var errDaemonInferParams = errors.New("the model params do not decode")

// No pull on this daemon: its state is not on a disk.
var errDaemonInferNoPull = errors.New("this daemon pulls no model: its state is not on a disk")

// models.set where a harness process is among the caller's ancestors (DESIGN §5.8), or where the daemon cannot name the
// caller.
var errDaemonModelsSetUnderHarness = errors.New("the models key is the person's to set, never under a harness process (§16.4)")

// models.set without the person's confirmation.
var errDaemonModelsSetUnconfirmed = errors.New("models.set is a person's act, confirmed on /dev/tty or in an app")

// models.pull on pulls, nil where the daemon pulls nothing: name's pull joined or started; with follow, its news
// streamed as notifications until it ends and the end answered, else its status now. A caller that leaves leaves the
// pull running.
func daemonModelsPull(ctx context.Context, pulls *InferPulls, call *DaemonCall, params *DaemonModelsPullParams) (*DaemonModelsPullReply, error) {
	if pulls == nil {
		return nil, errDaemonInferNoPull
	}
	if params.Name == "" {
		return nil, fmt.Errorf("%w: no model", errDaemonInferParams)
	}
	if !params.Follow {
		return pulls.Status(params.Name), nil
	}
	return pulls.Follow(ctx, params.Name, call.SessionDone, func(status *InferPullStatus) error {
		if call.Notify == nil {
			return nil
		}
		return call.Notify(DaemonNotifyModelsPullProgress, status)
	})
}

// Whether the call's process has a harness process of its network's runs among its ancestors; true where the daemon
// cannot name the caller, the closed reading.
func daemonInferUnderHarness(ctx context.Context, call *DaemonCall) bool {
	if call.Hello == nil || call.Hello.PeerPid <= 0 || call.Sidecar == nil {
		return true
	}
	return call.Sidecar.HarnessAncestor(ctx, int(call.Hello.PeerPid))
}

// What infer.run acts through: a Sidecar's router, its run store and its record's writer, and its clock; a test's in
// place of them.
type daemonInferRunHost struct {
	router  func() (InferRouter, error)
	openRun func(ctx context.Context, run *RunFile) error
	writer  func() (RecordWriter, error)
	clock   Clock
}

// infer.run's host on sidecar.
func daemonInferRunHostOf(sidecar *Sidecar) *daemonInferRunHost {
	return &daemonInferRunHost{
		router: sidecar.InferRouter,
		openRun: func(ctx context.Context, run *RunFile) error {
			runs, err := sidecar.Runs()
			if err != nil {
				return err
			}
			return runs.Create(ctx, run)
		},
		writer: func() (RecordWriter, error) {
			record, err := sidecar.Record()
			if err != nil {
				return nil, err
			}
			return record.Writer(), nil
		},
		clock: sidecar.clock,
	}
}

// infer.run on host: a run opened, the prompt run, each event handed to notify, the call recorded.
func daemonInferRun(ctx context.Context, host *daemonInferRunHost, params *DaemonInferRunParams, notify func(method string, params any) error) (*DaemonInferRunReply, error) {
	if params.Model == "" || params.Prompt == "" {
		return nil, fmt.Errorf("%w: a model and a prompt", errDaemonInferParams)
	}
	router, err := host.router()
	if err != nil {
		return nil, err
	}
	// the call is recorded or it does not run (R-INFER-6): the record's writer and the run first
	writer, err := host.writer()
	if err != nil {
		return nil, fmt.Errorf("no record to keep the call in: %w", err)
	}
	runId := NewId()
	if err := host.openRun(ctx, &RunFile{RunId: runId, Harness: daemonInferRunHarness}); err != nil {
		return nil, fmt.Errorf("no run to record the call in: %w", err)
	}
	clock := clockOrReal(host.clock)
	reply := &DaemonInferRunReply{RunId: runId}
	request := &InferRequest{
		Model:     params.Model,
		Reasoning: params.Reasoning,
		Messages:  []*InferMessage{{Role: InferRoleUser, Parts: []*InferPart{{Kind: InferPartText, Text: params.Prompt}}}},
		RunId:     &runId,
	}
	// what the call ran as, for its record: the catalog resolves it as the router does
	var resolved *InferCall
	if catalog, err := router.Catalog(ctx); err == nil {
		if resolution, err := catalog.Resolve(params.Model, params.Reasoning); err == nil {
			resolved = &InferCall{Request: request, Entry: resolution.Entry, Effort: resolution.Effort, Name: resolution.Name}
			reply.Model = resolution.Name
		}
	}
	startedAt := clock.Now()
	events, err := router.Infer(ctx, request)
	if err != nil {
		reply.Error = inferErrorOf(err)
		return reply, nil
	}
	for event := range events {
		switch event.Kind {
		case InferEventUsage:
			reply.Usage = event.Usage
		case InferEventError:
			reply.Error = event.Error
		}
		if notify != nil {
			notify(DaemonNotifyInferEvent, event)
		}
	}
	if resolved == nil {
		reply.RecordError = "the call's model did not resolve for its record"
		return reply, nil
	}
	body, err := InferModelCall(&InferModelCallArgs{
		Call:      resolved,
		RequestId: NewId().String(),
		Usage:     reply.Usage,
		StartedAt: startedAt,
		Duration:  clock.Now().Sub(startedAt),
	})
	if err == nil {
		_, err = writer.Append(&RecordDraft{
			Kind:   RecordKindModelCall,
			Source: RecordSourceObserved,
			RunId:  &runId,
			Body:   body,
		})
	}
	if err != nil {
		reply.RecordError = err.Error()
		return reply, nil
	}
	reply.Recorded = true
	return reply, nil
}

// The daemon's model and inference methods over args (the file comment). The daemon's composition registers them
// with RegisterMethod.
func DaemonInferMethods(args *DaemonInferArgs) []*DaemonMethod {
	if args == nil {
		args = &DaemonInferArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultInferSettings()
	}
	ctx := args.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	var pulls *InferPulls
	if args.Pull != nil {
		pulls = NewInferPulls(ctx, args.Pull.Pull, settings)
	}
	// the params, strictly, and the call's Sidecar
	open := func(call *DaemonCall, params any) error {
		if err := decodeDaemonSocketParams(call, params); err != nil {
			return fmt.Errorf("%w: %w", errDaemonInferParams, err)
		}
		if call.Sidecar == nil {
			return fmt.Errorf("%w: no network's sidecar", errDaemonInferParams)
		}
		return nil
	}
	return []*DaemonMethod{
		{
			Name:    DaemonMethodModelsList,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonModelsListParams{}
				if err := open(call, params); err != nil {
					return nil, err
				}
				return call.Sidecar.InferModels(ctx, &params.InferModelsFilter, args.Pull)
			},
		},
		{
			Name:    DaemonMethodModelsPull,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonModelsPullParams{}
				if err := open(call, params); err != nil {
					return nil, err
				}
				return daemonModelsPull(ctx, pulls, call, params)
			},
		},
		{
			Name:    DaemonMethodModelsRemove,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonModelsRemoveParams{}
				if err := open(call, params); err != nil {
					return nil, err
				}
				if args.Pull == nil {
					return nil, errDaemonInferNoPull
				}
				if err := args.Pull.Remove(ctx, params.Name); err != nil {
					return nil, err
				}
				return struct{}{}, nil
			},
		},
		{
			Name:    DaemonMethodModelsSettings,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				if err := open(call, &DaemonModelsParams{}); err != nil {
					return nil, err
				}
				return call.Sidecar.InferModelsSettings(ctx)
			},
		},
		{
			Name:    DaemonMethodModelsSet,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				if !call.Confirmed {
					return nil, errDaemonModelsSetUnconfirmed
				}
				params := &DaemonModelsSetParams{}
				if err := open(call, params); err != nil {
					return nil, err
				}
				if daemonInferUnderHarness(ctx, call) {
					return nil, errDaemonModelsSetUnderHarness
				}
				return call.Sidecar.InferSetModels(ctx, &params.InferModelsChange)
			},
		},
		{
			Name:    DaemonMethodInferRun,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonInferRunParams{}
				if err := open(call, params); err != nil {
					return nil, err
				}
				return daemonInferRun(ctx, daemonInferRunHostOf(call.Sidecar), params, call.Notify)
			},
		},
	}
}
