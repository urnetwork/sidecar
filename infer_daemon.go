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
//	models.settings   the person's models key, as this device reads it (§16.4)
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
	"sync"
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

// A pull's states.
const (
	DaemonModelsPullRunning = "running"
	DaemonModelsPullDone    = "done"
	DaemonModelsPullFailed  = "failed"
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

// Why a pull failed: its code (download_corrupt, download_unavailable or download_no_space, model_refused, canceled or
// pull_failed), the chunk download_corrupt names, -1 for the index, and why in the pull's own words.
type DaemonModelsPullError struct {
	Code    string `json:"code"`
	Chunk   *int   `json:"chunk,omitempty"`
	Message string `json:"message"`
}

// models.pull's reply, and each of its notifications: where the pull is.
type DaemonModelsPullReply struct {
	Name string `json:"name"`
	// running, done or failed.
	State    string                 `json:"state"`
	Progress *InferPullProgress     `json:"progress,omitempty"`
	Error    *DaemonModelsPullError `json:"error,omitempty"`
}

// models.remove's params.
type DaemonModelsRemoveParams struct {
	Network string `json:"network,omitempty"`
	Name    string `json:"name"`
}

// Params naming the call's network alone.
type DaemonModelsParams struct {
	Network string `json:"network,omitempty"`
}

// The person's models key as models.settings and models.set answer it (§16.4).
type DaemonModelsSettingsReply struct {
	Default string `json:"default,omitempty"`
	// The globs every model must match one of; null for every model, [] for none.
	Allow      []string `json:"allow"`
	TeeOnly    bool     `json:"tee_only"`
	SignInMail string   `json:"sign_in_mail"`
	// Each harness's tiers, harness to tier to canonical name.
	Harness map[string]map[string]string `json:"harness,omitempty"`
	// Each agent label's default model.
	Agents map[string]string `json:"agents,omitempty"`
	// The key does not read: every model is refused under allow, the closed reading (§16.4).
	Unreadable bool     `json:"unreadable,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// models.set's params: each set field changes, each nil one stays.
type DaemonModelsSetParams struct {
	Network string `json:"network,omitempty"`
	// The default model, a canonical name; empty removes it.
	Default *string `json:"default,omitempty"`
	TeeOnly *bool   `json:"tee_only,omitempty"`
	// withhold or allow.
	SignInMail *string `json:"sign_in_mail,omitempty"`
	// The globs allowed; [] allows none.
	Allow *[]string `json:"allow,omitempty"`
	// A harness's tier's model: all three, or none.
	Harness string `json:"harness,omitempty"`
	Tier    string `json:"tier,omitempty"`
	Model   string `json:"model,omitempty"`
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

// The daemon's pulls, one a model, each running until it ends whoever asked.
type daemonInferPulls struct {
	ctx      context.Context
	pull     *InferPull
	settings *InferSettings

	stateLock  sync.Mutex
	nameStates map[string]*daemonInferPullState
}

// One pull's state: its newest reply, and a channel closed and replaced at each change.
type daemonInferPullState struct {
	reply   *DaemonModelsPullReply
	ended   bool
	changed chan struct{}
}

// The pull's error as models.pull answers it.
func daemonModelsPullError(err error) *DaemonModelsPullError {
	var downloadErr *InferDownloadError
	var inferErr *InferError
	switch {
	case errors.As(err, &downloadErr):
		pullErr := &DaemonModelsPullError{Code: string(downloadErr.Code), Message: downloadErr.Message}
		if downloadErr.Code == InferDownloadErrorCorrupt {
			chunk := downloadErr.Chunk
			pullErr.Chunk = &chunk
		}
		return pullErr
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return &DaemonModelsPullError{Code: string(InferErrorCanceled), Message: "the pull was stopped"}
	case errors.As(err, &inferErr):
		return &DaemonModelsPullError{Code: string(inferErr.Code), Message: inferErr.Message}
	case errors.Is(err, ErrInferModelUnknown) || errors.Is(err, ErrInferModelUnavailable) || errors.Is(err, ErrInferModelNameInvalid):
		return &DaemonModelsPullError{Code: string(InferErrorModelRefused), Message: err.Error()}
	}
	return &DaemonModelsPullError{Code: "pull_failed", Message: err.Error()}
}

// name's pull: the one running, or ended and not yet answered, else a new one started in the daemon. A state taken
// after it ended is forgotten, so it is answered once.
func (self *daemonInferPulls) join(name string) (*daemonInferPullState, *DaemonModelsPullReply, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, ok := self.nameStates[name]
	if !ok {
		state = &daemonInferPullState{
			reply:   &DaemonModelsPullReply{Name: name, State: DaemonModelsPullRunning},
			changed: make(chan struct{}),
		}
		self.nameStates[name] = state
		go self.run(name, state)
	}
	return state, self.takeWithLock(name, state), state.changed
}

// The state's reply now, forgetting the state where it ended. Called with stateLock held.
func (self *daemonInferPulls) takeWithLock(name string, state *daemonInferPullState) *DaemonModelsPullReply {
	reply := *state.reply
	if state.ended && self.nameStates[name] == state {
		delete(self.nameStates, name)
	}
	return &reply
}

// The state's reply now and the channel its next change closes, forgetting it where it ended.
func (self *daemonInferPulls) read(name string, state *daemonInferPullState) (*DaemonModelsPullReply, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.takeWithLock(name, state), state.changed
}

// Sets the state's reply by change, and wakes its followers.
func (self *daemonInferPulls) update(state *daemonInferPullState, change func(reply *DaemonModelsPullReply)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reply := *state.reply
	change(&reply)
	state.reply = &reply
	close(state.changed)
	state.changed = make(chan struct{})
}

// Runs name's pull to its end in the daemon's context.
func (self *daemonInferPulls) run(name string, state *daemonInferPullState) {
	err := self.pull.Pull(self.ctx, name, func(progress *InferPullProgress) {
		copied := *progress
		self.update(state, func(reply *DaemonModelsPullReply) {
			reply.Progress = &copied
		})
	})
	self.update(state, func(reply *DaemonModelsPullReply) {
		if err != nil {
			reply.State = DaemonModelsPullFailed
			reply.Error = daemonModelsPullError(err)
		} else {
			reply.State = DaemonModelsPullDone
		}
	})
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state.ended = true
	}()
	// a follower waiting now reads the end
	self.update(state, func(reply *DaemonModelsPullReply) {})
}

// Whether next's progress is news to a follower that last heard last: another phase, file or chunk, its end, or an
// engine file's bytes past another ModelChunkByteCount.
func (self *daemonInferPulls) news(last *DaemonModelsPullReply, next *DaemonModelsPullReply) bool {
	if last == nil || last.State != next.State || (last.Progress == nil) != (next.Progress == nil) {
		return true
	}
	if next.Progress == nil {
		return false
	}
	a, b := last.Progress, next.Progress
	return a.Phase != b.Phase || a.FileIndex != b.FileIndex || a.DoneChunkCount != b.DoneChunkCount ||
		self.settings.ModelChunkByteCount <= b.DoneByteCount-a.DoneByteCount
}

// models.pull: name's pull joined or started; with follow, its progress streamed until it ends, else its state now.
func (self *daemonInferPulls) answer(ctx context.Context, call *DaemonCall, params *DaemonModelsPullParams) (*DaemonModelsPullReply, error) {
	state, reply, changed := self.join(params.Name)
	if !params.Follow {
		return reply, nil
	}
	var heard *DaemonModelsPullReply
	for reply.State == DaemonModelsPullRunning {
		if self.news(heard, reply) && call.Notify != nil {
			if err := call.Notify(DaemonNotifyModelsPullProgress, reply); err == nil {
				heard = reply
			}
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-call.SessionDone:
			// the caller left: the pull goes on in the daemon
			return nil, errors.New("the caller left; the pull goes on")
		}
		reply, changed = self.read(params.Name, state)
	}
	return reply, nil
}

// The models key's reply for read.
func daemonModelsSettingsReplyOf(key *HarnessModelsKey, read *HarnessModelsKeyRead) *DaemonModelsSettingsReply {
	reply := &DaemonModelsSettingsReply{
		Default:    key.Default,
		Allow:      key.Allow,
		TeeOnly:    key.TeeOnly,
		SignInMail: string(key.SignInMailMode()),
		Harness:    key.Harness,
	}
	if 0 < len(key.Agents) {
		reply.Agents = map[string]string{}
		for label, agent := range key.Agents {
			reply.Agents[label] = agent.Default
		}
	}
	if read != nil {
		reply.Unreadable = read.Unreadable
		reply.Reason = read.Reason
		reply.Warnings = read.Warnings
	}
	return reply
}

// Applies params' changes to key, refusing a harness tier named by halves.
func daemonModelsSetChange(params *DaemonModelsSetParams, key *HarnessModelsKey) error {
	if params.Default != nil {
		key.Default = *params.Default
	}
	if params.TeeOnly != nil {
		key.TeeOnly = *params.TeeOnly
	}
	if params.SignInMail != nil {
		key.SignInMail = HarnessSignInMail(*params.SignInMail)
	}
	if params.Allow != nil {
		key.Allow = append([]string{}, *params.Allow...)
	}
	switch {
	case params.Harness == "" && params.Tier == "" && params.Model == "":
	case params.Harness == "" || params.Tier == "" || params.Model == "":
		return fmt.Errorf("%w: a harness's tier takes the harness, the tier and the model", ErrModelsKeyInvalid)
	default:
		if key.Harness == nil {
			key.Harness = map[string]map[string]string{}
		}
		if key.Harness[params.Harness] == nil {
			key.Harness[params.Harness] = map[string]string{}
		}
		key.Harness[params.Harness][params.Tier] = params.Model
	}
	return nil
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
	pulls := &daemonInferPulls{ctx: ctx, pull: args.Pull, settings: settings, nameStates: map[string]*daemonInferPullState{}}
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
				if args.Pull == nil {
					return nil, errDaemonInferNoPull
				}
				if params.Name == "" {
					return nil, fmt.Errorf("%w: no model", errDaemonInferParams)
				}
				return pulls.answer(ctx, call, params)
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
				read, err := call.Sidecar.ModelsKey(ctx)
				if err != nil {
					return nil, err
				}
				return daemonModelsSettingsReplyOf(read.Key, read), nil
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
				written, err := call.Sidecar.SetModelsKey(ctx, &MemberHarnessConfigUpdateArgs{Origin: SidecarActConfirmed},
					func(key *HarnessModelsKey) error {
						return daemonModelsSetChange(params, key)
					})
				if err != nil {
					return nil, err
				}
				return daemonModelsSettingsReplyOf(written, nil), nil
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
