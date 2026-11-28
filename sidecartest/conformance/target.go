//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// GatewayTarget: the root's gateway in process, the target a test replays a transcript against (see doc.go). It is
// the daemon's own GatewayServer with its fronts mounted, hosting one T2 Sidecar's network (sidecartest.Net's
// AddSidecar), its grant made as `ur install-harness --gateway` makes one and its port held on 127.0.0.1 and [::1] as
// the daemon holds it, so a request passes the listener's Host and browser checks, the token, the run binding, the
// grant, the router and the recorder in their order (§8.4). Beside the daemon's parts it holds two stand-ins, since
// what they stand for lives where a sidecartest package cannot build it:
//
//	binder     mcp's run binder (mcp/hook_bind_gateway.go) binds a call by its harness process and the session its
//	           header names; this one does the same over the T2 Sidecar's own run files: a run per process and
//	           session, made on the session's first call as a hook's first event makes one, and the union of the
//	           process's runs' taint and marks for the router
//	recorder   GW-M12-06's recorder writes each call's session entries and model_call; this one keeps each call's
//	           begin, items and end in memory, so a test reads which run each call was recorded into and what was sent
//
// Each session's token is a run handle for a harness process of its own, as each `codex` a person starts mints its
// own through its credential command. The router is the test's: computetest.ScriptedModel's behind INFER's own
// router, under sidecar_testhooks.
//
// Safe for concurrent use. Close stops the gateway, draining its calls.

package conformance

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest/computetest"
)

// What NewGatewayTarget builds on.
type GatewayTargetArgs struct {
	// The T2 Sidecar whose stores hold the grant, the runs and the kept calls, and its network.
	Sidecar   *sidecar.Sidecar
	NetworkId sidecar.Id
	// The router every call goes through.
	Router sidecar.InferRouter
	// The harness the grant is made for.
	Harness string
	// The gateway's state directory, where the port it holds is kept: a test's temporary directory.
	StateDirectory string
	// Nil takes DefaultGatewaySettings.
	Settings *sidecar.GatewaySettings
	// The gateway's and the fronts' clock; nil is real time.
	Clock sidecar.Clock
	// Scripts the model's answer before each request; nil scripts nothing.
	Script func(ctx context.Context, session *TranscriptSession, request *TranscriptRequest) error
}

// The network the gateway hosts: the T2 Sidecar's, its router the test's.
type targetNetwork struct {
	*sidecar.Sidecar
	router sidecar.InferRouter
}

// See sidecar.GatewayFrontNetwork: the test's router, in place of the Sidecar's own.
func (self *targetNetwork) InferRouter() (sidecar.InferRouter, error) {
	if self.router == nil {
		return nil, sidecar.ErrComputeComponentUnavailable
	}
	return self.router, nil
}

// The hosted networks: the one.
type targetHosts struct {
	networkId sidecar.Id
	network   *targetNetwork
}

// See sidecar.GatewayHosts.
func (self *targetHosts) GatewayNetworks() []sidecar.GatewayHostedNetwork {
	return []sidecar.GatewayHostedNetwork{{NetworkId: self.networkId, Network: self.network}}
}

// See sidecar.GatewayHosts: no network argument, or this network's id, names it.
func (self *targetHosts) ResolveNetwork(hello *sidecar.DaemonHello, network string) (sidecar.Id, error) {
	if network == "" || network == self.networkId.String() {
		return self.networkId, nil
	}
	return sidecar.Id{}, fmt.Errorf("conformance: no network %q", network)
}

// See the file header's binder row. Safe for concurrent use.
type targetBinder struct {
	stateLock sync.Mutex
	// a run per handle's process and session
	keyRunIds map[string]sidecar.Id
	// each process's runs, by its handle's key
	handleRunIds map[string][]sidecar.Id
}

var _ sidecar.GatewayRunBinder = (*targetBinder)(nil)

// See sidecar.GatewayRunBinder: no ancestry is read here, since a target's tokens are minted for their handles.
func (self *targetBinder) HarnessProcess(ctx context.Context, network sidecar.GatewayRunNetwork, pid int) (*sidecar.GatewayHarnessProcess, error) {
	return nil, nil
}

// See sidecar.GatewayRunBinder: the run of handle's process and sessionId, made on its first call.
func (self *targetBinder) BindRun(ctx context.Context, network sidecar.GatewayRunNetwork, harness string, handle *sidecar.GatewayRunHandle, sessionId string) (sidecar.Id, error) {
	key := handle.Key() + "\x00" + sessionId
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if runId, ok := self.keyRunIds[key]; ok {
		return runId, nil
	}
	runs, err := network.Runs()
	if err != nil {
		return sidecar.Id{}, err
	}
	run := &sidecar.RunFile{
		RunId:              sidecar.NewId(),
		Harness:            harness,
		ProcessId:          handle.Process.Pid,
		ProcessStartMillis: handle.Process.StartMillis,
	}
	if sessionId != "" {
		run.SessionIds = []string{sessionId}
	}
	if err := runs.Create(ctx, run); err != nil {
		return sidecar.Id{}, err
	}
	self.keyRunIds[key] = run.RunId
	self.handleRunIds[handle.Key()] = append(self.handleRunIds[handle.Key()], run.RunId)
	return run.RunId, nil
}

// See sidecar.GatewayRunBinder: the taint and marks of every run of each handle's process.
func (self *targetBinder) Union(ctx context.Context, network sidecar.GatewayRunNetwork, handles []*sidecar.GatewayRunHandle) (*sidecar.GatewayRunUnion, error) {
	runs, err := network.Runs()
	if err != nil {
		return nil, err
	}
	runIds := []sidecar.Id{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, handle := range handles {
			runIds = append(runIds, self.handleRunIds[handle.Key()]...)
		}
	}()
	union := &sidecar.GatewayRunUnion{}
	for _, runId := range runIds {
		union.Tainted = union.Tainted || runs.Tainted(runId)
		marks, err := runs.Marks(runId)
		if err != nil {
			return nil, err
		}
		for _, mark := range marks {
			if !slices.Contains(union.Marks, mark) {
				union.Marks = append(union.Marks, mark)
			}
		}
	}
	return union, nil
}

// One call as the target's recorder kept it.
type RecordedCall struct {
	RunId      sidecar.Id
	Handle     string
	Harness    string
	Api        sidecar.SessionGatewayApi
	Renderer   string
	ResponseId string
	Model      string
	// The body as the front routed it: what the model receives.
	Body []byte
	// Each response item recorded, in order.
	Items [][]byte
	// How it ended, nil before.
	End *sidecar.GatewayRecordEnd
}

// See the file header's recorder row. Safe for concurrent use.
type targetRecorder struct {
	stateLock sync.Mutex
	calls     []*RecordedCall
	cuts      []*sidecar.GatewayRecordCut
}

var _ sidecar.GatewayRecorder = (*targetRecorder)(nil)

// One call being recorded.
type targetRecordCall struct {
	recorder *targetRecorder
	call     *RecordedCall
}

// See sidecar.GatewayRecorder.
func (self *targetRecorder) Begin(ctx context.Context, begin *sidecar.GatewayRecordBegin) (sidecar.GatewayRecordCall, error) {
	call := &RecordedCall{
		Harness:    begin.Harness,
		Api:        begin.Api,
		Renderer:   begin.Renderer,
		ResponseId: begin.ResponseId,
		Model:      begin.Model,
		Body:       slices.Clone(begin.Body),
	}
	if begin.Binding != nil {
		call.RunId, call.Handle = begin.Binding.RunId, begin.Binding.Handle
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, call)
	return &targetRecordCall{recorder: self, call: call}, nil
}

// See sidecar.GatewayRecorder.
func (self *targetRecorder) Cut(ctx context.Context, cut *sidecar.GatewayRecordCut) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cuts = append(self.cuts, cut)
	return nil
}

// See sidecar.GatewayRecordCall: a node id of its own.
func (self *targetRecordCall) ResponseItem(ctx context.Context, item []byte) (sidecar.Id, error) {
	self.recorder.stateLock.Lock()
	defer self.recorder.stateLock.Unlock()
	self.call.Items = append(self.call.Items, slices.Clone(item))
	return sidecar.NewId(), nil
}

// See sidecar.GatewayRecordCall.
func (self *targetRecordCall) End(ctx context.Context, end *sidecar.GatewayRecordEnd) error {
	self.recorder.stateLock.Lock()
	defer self.recorder.stateLock.Unlock()
	copied := *end
	self.call.End = &copied
	return nil
}

// See the file header.
type GatewayTarget struct {
	server   *sidecar.GatewayServer
	fronts   *sidecar.GatewayFronts
	network  *targetNetwork
	binder   *targetBinder
	recorder *targetRecorder
	store    *sidecar.GatewayGrantStore
	grant    *sidecar.GatewayGrant
	port     int
	script   func(ctx context.Context, session *TranscriptSession, request *TranscriptRequest) error

	stateLock      sync.Mutex
	sessionHandles map[string]*sidecar.GatewayRunHandle
	closed         bool
}

// The gateway over args, its grant made and its port served; Close stops it.
func NewGatewayTarget(ctx context.Context, args *GatewayTargetArgs) (*GatewayTarget, error) {
	if args == nil || args.Sidecar == nil || args.Router == nil || args.Harness == "" || args.StateDirectory == "" {
		return nil, errors.New("conformance: a target needs a Sidecar, a router, a harness and a state directory")
	}
	network := &targetNetwork{Sidecar: args.Sidecar, router: args.Router}
	server := sidecar.NewGatewayServer(&sidecar.GatewayServerArgs{
		StateDirectory: args.StateDirectory,
		Settings:       args.Settings,
		Clock:          args.Clock,
	})
	server.SetHosts(&targetHosts{networkId: args.NetworkId, network: network})
	binder := &targetBinder{keyRunIds: map[string]sidecar.Id{}, handleRunIds: map[string][]sidecar.Id{}}
	server.SetRunBinder(binder)
	recorder := &targetRecorder{}
	fronts := server.MountFronts(&sidecar.GatewayFrontsArgs{Recorder: recorder, Clock: args.Clock})
	target := &GatewayTarget{
		server:         server,
		fronts:         fronts,
		network:        network,
		binder:         binder,
		recorder:       recorder,
		script:         args.Script,
		sessionHandles: map[string]*sidecar.GatewayRunHandle{},
	}
	reply, err := server.MakeGrant(ctx, &sidecar.DaemonHello{Mode: sidecar.DaemonModeControl}, &sidecar.GatewayGrantsParams{
		Action:  sidecar.GatewayGrantsActionMake,
		Harness: args.Harness,
	})
	if err != nil {
		server.Close()
		return nil, err
	}
	if len(reply.Grants) != 1 || reply.Grants[0].Grant == nil {
		server.Close()
		return nil, errors.New("conformance: the grant was not made")
	}
	target.grant = reply.Grants[0].Grant
	status := server.Reload()
	if !status.Serving {
		server.Close()
		return nil, fmt.Errorf("conformance: the gateway serves nothing: %s", status.Reason)
	}
	target.port = status.Port
	target.store, err = network.GatewayGrants()
	if err != nil {
		server.Close()
		return nil, err
	}
	return target, nil
}

// Stops the gateway, its calls drained first. Safe more than once.
func (self *GatewayTarget) Close() {
	self.stateLock.Lock()
	if self.closed {
		self.stateLock.Unlock()
		return
	}
	self.closed = true
	self.stateLock.Unlock()
	self.server.Close()
}

// The gateway's base URL on its port.
func (self *GatewayTarget) BaseUrl() string {
	return "http://127.0.0.1:" + strconv.Itoa(self.port)
}

// The grant every token is minted under.
func (self *GatewayTarget) Grant() *sidecar.GatewayGrant {
	return self.grant
}

// The calls recorded, in the order begun, copies.
func (self *GatewayTarget) Recorded() []*RecordedCall {
	self.recorder.stateLock.Lock()
	defer self.recorder.stateLock.Unlock()
	calls := []*RecordedCall{}
	for _, call := range self.recorder.calls {
		copied := *call
		copied.Items = slices.Clone(call.Items)
		calls = append(calls, &copied)
	}
	return calls
}

// The run handle a session's token was minted for, nil before its token.
func (self *GatewayTarget) SessionHandle(sessionId string) *sidecar.GatewayRunHandle {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sessionHandles[sessionId]
}

// A token for session: a run handle for a harness process of the session's own, as its credential command mints one.
func (self *GatewayTarget) Token(ctx context.Context, session *TranscriptSession) (string, error) {
	handle := func() *sidecar.GatewayRunHandle {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		handle, ok := self.sessionHandles[session.Id]
		if !ok {
			// a synthetic process of its own, above any pid a test host hands out
			count := len(self.sessionHandles) + 1
			handle = &sidecar.GatewayRunHandle{Process: sidecar.ProcessIdentity{Pid: 4000000 + count, StartMillis: int64(count)}}
			self.sessionHandles[session.Id] = handle
		}
		return handle
	}()
	token, _, err := self.store.Mint(ctx, self.grant.GrantId, handle)
	return token, err
}

// The target a replay sends to.
func (self *GatewayTarget) Target() *Target {
	return &Target{
		BaseUrl:       self.BaseUrl(),
		Token:         self.Token,
		BeforeRequest: self.script,
	}
}

// The model turn a transcript scripts, as computetest.ScriptedModel plays it: its reasoning and text deltas, its tool
// calls with their fixed ids and arguments, its usage, and the failure it ends with; nil for a request whose call never
// reaches a model.
func ScriptedTurnOf(turn *TranscriptModelTurn) *computetest.ScriptedTurn {
	if turn == nil {
		return nil
	}
	scripted := &computetest.ScriptedTurn{
		Reasoning: slices.Clone(turn.Reasoning),
		Text:      slices.Clone(turn.Text),
	}
	for _, call := range turn.ToolCalls {
		scripted.ToolCalls = append(scripted.ToolCalls, &computetest.ScriptedToolCall{Id: call.Id, Name: call.Name, Arguments: call.Arguments})
	}
	if turn.Usage != nil {
		scripted.Usage = &sidecar.InferUsage{InputTokens: turn.Usage.InputTokens, OutputTokens: turn.Usage.OutputTokens}
	}
	if turn.FailCode != "" {
		scripted.Fail = &sidecar.InferError{Code: sidecar.InferErrorCode(turn.FailCode), Message: "the transcript's scripted failure"}
	}
	return scripted
}
