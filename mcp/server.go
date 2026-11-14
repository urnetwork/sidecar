//go:build !js && !ios && !android && !sdk_mobile_bind

// The daemon's MCP server (§16.4, D-MCP-2): Serve is the daemon's mcp mode, one go-sdk ServerSession per relay
// connection over IOTransport on the session's stream. go-sdk copies ServerOptions at NewServer, so a session cannot
// carry instructions of its own (D-MCP-29's trap): the server keeps one go-sdk Server per instructions text, each with
// the same static tool table, and connects a session to the one its text picks at its start, which then stays fixed.
// The text is §16.11's for the session's claims value (MCP-M6-01; D-MCP-29, R-MCP-16): the session's claims are read
// once, at its start, for the network it starts in (McpSessionClaims, the daemon's DaemonSessionClaims), and the
// texts are RECORD-M6-22's, set through SetClaimsInstructions or registered from their file's init. A later change of
// `.ur`, the harness config, the team's default or the member's choice leaves an open session on its Server and its
// value. With no texts set there is one text, empty.
//
// Every request passes the server's middleware, which puts its McpSession in the context. A tools/call or a
// resources/read is a call: it runs under the session's limits (limits.go), after its network resolves by §5.8's
// rules, the call's network argument first (Daemon.ResolveNetwork, per call, one Sidecar per network since
// CORE-M6-01), and after that network's Sidecar is ready. A Locked one answers FAILED_PRECONDITION naming `ur unlock`,
// an Unenrolled one `ur login`, each for the person's own terminal: MCP never asks for the pass and has no admin path.
//
// The capabilities advertise tools and resources with subscribe, and nothing else: no prompts, no sampling, no
// elicitation, no logging. The tool list is static (MCP-M3-12's catalog, through Install). A subscription is refused
// unless the resource map admits it (MCP-M3-14's, through SetSubscribeCheck), so a refused repo refuses at subscribe.
//
// Safe for concurrent use.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
)

// The methods that are calls: they run under the session's limits, on a resolved and ready network.
const (
	mcpMethodToolsCall     = "tools/call"
	mcpMethodResourcesRead = "resources/read"
)

// One hosted network as the server reads it before a call runs: *sidecar.Sidecar is one. MCP-M3-12's tools read
// more of it, and extend this.
type McpNetwork interface {
	// Its state, which decides whether a call may run.
	Status() sidecar.SidecarStatus
	// Its run files (§16.6), where a run's taint lives.
	Runs() (*sidecar.RunStore, error)
	// Its capture spool (§16.7), which holds a taint taken while Locked.
	Spool() (*sidecar.Spool, error)
	// Its sealed local state, net/<network_id>/ (§5.9), where restore points and ingest state live. Every call on
	// it answers ErrSidecarStoreLocked before enrollment and while locked.
	LocalStore() sidecar.SidecarStore
}

// The daemon, as the server reads it (§5.8): DaemonOf wraps *sidecar.Daemon; a test passes a fake.
type McpDaemon interface {
	// The network a call acts on: its network argument, else the project's `.ur`, else the only network hosted. A
	// *sidecar.DaemonNetworkError when none does.
	ResolveNetwork(hello *sidecar.DaemonHello, network string) (sidecar.Id, error)
	// The network's hosted Sidecar.
	Network(networkId sidecar.Id) (McpNetwork, bool)
	// The agent a session acts as: its hello's, else its project's `.ur` default; nil for none.
	Agent(hello *sidecar.DaemonHello) (*sidecar.SidecarAgent, error)
}

// One session's claims values (§16.11; D-CORE-18): each network's resolved at its first ask and the same for the
// session's life, whatever changes after. *sidecar.DaemonSessionClaims is one. Safe for concurrent use.
type McpSessionClaims interface {
	For(ctx context.Context, networkId sidecar.Id) *sidecar.SidecarClaimsResolution
}

// A daemon that reads its sessions' claims, which an McpDaemon may also be: DaemonOf's is one. A daemon that is none
// gives its sessions no claims, and each then runs on the one empty instructions text.
type McpClaimsDaemon interface {
	// The claims of a session of hello's caller, its `.ur` read now, at the session's start.
	SessionClaims(hello *sidecar.DaemonHello) McpSessionClaims
}

// §16.11's instructions text for the claims value a session starts under (RECORD-M6-22's DirectoryInstructions): one
// constant text per value, never a variable (D-MCP-3), since each distinct text is one go-sdk Server kept for the
// daemon's life.
type McpClaimsInstructions func(resolution *sidecar.SidecarClaimsResolution) string

// The texts a build links, which every McpServer starts with: their owner's file's init registers them.
var mcpClaimsInstructionsRegistered struct {
	stateLock sync.Mutex
	texts     McpClaimsInstructions
}

// Registers the build's instructions texts by claims value. Call from the texts' owner's file's init.
func registerMcpClaimsInstructions(texts McpClaimsInstructions) {
	mcpClaimsInstructionsRegistered.stateLock.Lock()
	defer mcpClaimsInstructionsRegistered.stateLock.Unlock()
	mcpClaimsInstructionsRegistered.texts = texts
}

// *sidecar.Daemon as an McpDaemon.
type daemonMcpDaemon struct {
	daemon *sidecar.Daemon
}

// The server's view of daemon.
func DaemonOf(daemon *sidecar.Daemon) McpDaemon {
	return &daemonMcpDaemon{daemon: daemon}
}

func (self *daemonMcpDaemon) ResolveNetwork(hello *sidecar.DaemonHello, network string) (sidecar.Id, error) {
	return self.daemon.ResolveNetwork(hello, network)
}

func (self *daemonMcpDaemon) Network(networkId sidecar.Id) (McpNetwork, bool) {
	hosted, ok := self.daemon.SidecarForNetwork(networkId)
	if !ok {
		return nil, false
	}
	return hosted, true
}

func (self *daemonMcpDaemon) Agent(hello *sidecar.DaemonHello) (*sidecar.SidecarAgent, error) {
	return self.daemon.Agent(hello)
}

func (self *daemonMcpDaemon) SessionClaims(hello *sidecar.DaemonHello) McpSessionClaims {
	return self.daemon.SessionClaims(hello)
}

// What the server runs with: §16's settings, the daemon's line bound, and the seams a test replaces.
type McpServerSettings struct {
	// §16.4's bounds.
	Mcp *sidecar.SidecarMcpSettings
	// §16.7's hook and capture bounds (hook*.go).
	Ingest *sidecar.SidecarIngestSettings
	// The longest line a session reads, the daemon's request bound (SidecarLocalSettings.RequestByteCount): a line
	// past it closes the session, as a control session's does.
	RequestByteCount int64
	// The version the server names itself by, ur's.
	Version string
	// The process table the ancestry rules read (§16.7). Nil is the system's.
	Processes sidecar.ProcessTable
	// Nil is real time.
	Clock sidecar.Clock
	// Nil is no logging. Never stdout.
	Log sidecar.Logger
}

// The server's settings from a Sidecar's, each a fresh value.
func NewMcpServerSettings(settings *sidecar.SidecarSettings, version string) *McpServerSettings {
	mcpSettings := *settings.Mcp
	ingest := *settings.Ingest
	return &McpServerSettings{
		Mcp:              &mcpSettings,
		Ingest:           &ingest,
		RequestByteCount: settings.LocalSettings.RequestByteCount,
		Version:          version,
		Clock:            settings.Clock,
		Log:              settings.Log,
	}
}

// Decides one resources/subscribe of a session's: nil admits it. MCP-M3-14's resource map installs one.
type McpSubscribeCheck func(ctx context.Context, session *McpSession, uri string) error

// The daemon's MCP server.
type McpServer struct {
	daemon    McpDaemon
	settings  *McpServerSettings
	clock     sidecar.Clock
	log       sidecar.Logger
	processes sidecar.ProcessTable
	binder    *RunBinder
	hooks     mcpHooks

	stateLock sync.Mutex
	// one go-sdk Server per instructions text
	instructionsServers map[string]*gomcp.Server
	// the McpSession each go-sdk session serves
	serverSessions map[*gomcp.ServerSession]*McpSession
	// the static tool table, run on each Server as it is made
	installers []func(server *gomcp.Server)
	// picks a session's instructions text at its start; nil is the one empty text
	instructionsFor func(session *McpSession) string
	// nil refuses every subscription
	subscribeCheck McpSubscribeCheck
	// run_restore's points (tools_restore.go); nil answers unavailable
	restorePoints *RestorePoints
	// the bridge tools' filings and listing (tools_bridge.go); nil answers unavailable
	bridges McpBridges
}

// A server for daemon.
func NewMcpServer(daemon McpDaemon, settings *McpServerSettings) *McpServer {
	clock := settings.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	log := settings.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	processes := settings.Processes
	if processes == nil {
		processes = sidecar.SystemProcessTable()
	}
	self := &McpServer{
		daemon:              daemon,
		settings:            settings,
		clock:               clock,
		log:                 log,
		processes:           processes,
		instructionsServers: map[string]*gomcp.Server{},
		serverSessions:      map[*gomcp.ServerSession]*McpSession{},
	}
	self.binder = newRunBinder(self)
	registered := func() McpClaimsInstructions {
		mcpClaimsInstructionsRegistered.stateLock.Lock()
		defer mcpClaimsInstructionsRegistered.stateLock.Unlock()
		return mcpClaimsInstructionsRegistered.texts
	}()
	if registered != nil {
		self.SetClaimsInstructions(registered)
	}
	return self
}

// The run binder, which the daemon's hook method shares with the MCP sessions (hook_bind.go).
func (self *McpServer) Binder() *RunBinder {
	return self.binder
}

// Adds to the static tool table: install runs on every go-sdk Server, made already or later, so every session sees
// the same tools whatever its instructions. Each tool is added once per Server; call before serving.
func (self *McpServer) Install(install func(server *gomcp.Server)) {
	servers := func() []*gomcp.Server {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.installers = append(self.installers, install)
		servers := make([]*gomcp.Server, 0, len(self.instructionsServers))
		for _, server := range self.instructionsServers {
			servers = append(servers, server)
		}
		return servers
	}()
	for _, server := range servers {
		install(server)
	}
}

// Sets the rule that picks each new session's instructions text at its start (MCP-M6-01). A session started already
// keeps its text.
func (self *McpServer) SetInstructionsFor(instructionsFor func(session *McpSession) string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.instructionsFor = instructionsFor
}

// Sets §16.11's texts as the rule: each new session's text is texts' for the claims value it starts under, in the
// network it starts in (McpSession.StartClaims). A session with no such value, since its daemon reads no claims or no
// network resolves at its start, takes the empty text, as every session does once texts is nil. A session started
// already keeps its text and its Server (D-MCP-29).
func (self *McpServer) SetClaimsInstructions(texts McpClaimsInstructions) {
	if texts == nil {
		self.SetInstructionsFor(nil)
		return
	}
	self.SetInstructionsFor(func(session *McpSession) string {
		resolution := session.StartClaims()
		if resolution == nil {
			return ""
		}
		return texts(resolution)
	})
}

// Sets what admits a subscription (MCP-M3-14). Nil refuses every one.
func (self *McpServer) SetSubscribeCheck(check McpSubscribeCheck) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.subscribeCheck = check
}

// The go-sdk Server of an instructions text, made on first use with the static tool table.
func (self *McpServer) ServerFor(instructions string) *gomcp.Server {
	self.stateLock.Lock()
	server, ok := self.instructionsServers[instructions]
	installers := append([]func(server *gomcp.Server){}, self.installers...)
	self.stateLock.Unlock()
	if ok {
		return server
	}
	server = gomcp.NewServer(&gomcp.Implementation{Name: "ur", Version: self.settings.Version}, &gomcp.ServerOptions{
		Instructions: instructions,
		Logger:       slog.New(&mcpLogHandler{log: self.log}),
		Capabilities: &gomcp.ServerCapabilities{
			Tools:     &gomcp.ToolCapabilities{},
			Resources: &gomcp.ResourceCapabilities{Subscribe: true},
		},
		SubscribeHandler:   self.subscribe,
		UnsubscribeHandler: self.unsubscribe,
	})
	server.AddReceivingMiddleware(self.middleware)
	for _, install := range installers {
		install(server)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if made, ok := self.instructionsServers[instructions]; ok {
		// another session made it first
		return made
	}
	// an Install since the copy above runs on this one too
	for _, install := range self.installers[len(installers):] {
		install(server)
	}
	self.instructionsServers[instructions] = server
	return server
}

// Tells every session subscribed to uri that it changed: the notification carries the uri alone.
func (self *McpServer) ResourceUpdated(ctx context.Context, uri string) error {
	servers := func() []*gomcp.Server {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		servers := make([]*gomcp.Server, 0, len(self.instructionsServers))
		for _, server := range self.instructionsServers {
			servers = append(servers, server)
		}
		return servers
	}()
	var errs []error
	for _, server := range servers {
		errs = append(errs, server.ResourceUpdated(ctx, &gomcp.ResourceUpdatedNotificationParams{URI: uri}))
	}
	return errors.Join(errs...)
}

// The session a go-sdk session serves.
func (self *McpServer) sessionOf(serverSession *gomcp.ServerSession) *McpSession {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.serverSessions[serverSession]
}

// Every session open now.
func (self *McpServer) Sessions() []*McpSession {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sessions := make([]*McpSession, 0, len(self.serverSessions))
	for _, session := range self.serverSessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// A session for hello: its agent and instructions read now, and fixed for its life.
func (self *McpServer) newSession(hello *sidecar.DaemonHello) *McpSession {
	return self.newSessionAt(context.Background(), hello)
}

// newSession, its claims read under ctx.
func (self *McpServer) newSessionAt(ctx context.Context, hello *sidecar.DaemonHello) *McpSession {
	session := &McpSession{
		server:            self,
		hello:             *hello,
		limits:            newMcpSessionLimits(self.settings.Mcp, self.clock),
		networkIdBindings: map[sidecar.Id]*mcpSessionBinding{},
	}
	// the relay's place in the process tree, read once: a session's ancestry does not change
	session.caller = self.binder.callerProcessOf(hello)
	session.agent, session.agentErr = self.daemon.Agent(hello)
	// the session's claims, its `.ur` read here, and the value of the network it starts in resolved here, so that
	// nothing after the start moves either (§16.10's claims row: the value is fixed for each session)
	if claimsDaemon, ok := self.daemon.(McpClaimsDaemon); ok {
		session.claims = claimsDaemon.SessionClaims(hello)
		if session.claims != nil {
			if networkId, err := self.daemon.ResolveNetwork(hello, ""); err == nil {
				session.startClaims = session.claims.For(ctx, networkId)
			}
		}
	}
	instructionsFor := func() func(session *McpSession) string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.instructionsFor
	}()
	if instructionsFor != nil {
		session.instructions = instructionsFor(session)
	}
	return session
}

// The daemon's mcp mode (sidecar.DaemonModeHandler): one go-sdk session over stream, which ends when the relay
// closes it, when a line passes RequestByteCount, or when ctx ends.
func (self *McpServer) Serve(ctx context.Context, hello *sidecar.DaemonHello, stream io.ReadWriter) error {
	session := self.newSessionAt(ctx, hello)
	server := self.ServerFor(session.instructions)
	// no request reaches the middleware before the session is known by its go-sdk session
	gate := make(chan struct{})
	reader := &mcpLineReader{reader: stream, gate: gate, maxByteCount: self.settings.RequestByteCount}
	transport := &gomcp.IOTransport{Reader: reader, Writer: &mcpStreamWriter{writer: stream}}
	serverSession, err := server.Connect(ctx, transport, nil)
	if err != nil {
		close(gate)
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.serverSessions[serverSession] = session
	}()
	func() {
		session.stateLock.Lock()
		defer session.stateLock.Unlock()
		session.serverSession = serverSession
	}()
	defer func() {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.serverSessions, serverSession)
		}()
		session.close()
	}()
	close(gate)
	waited := make(chan error, 1)
	go func() {
		waited <- serverSession.Wait()
	}()
	select {
	case <-ctx.Done():
		serverSession.Close()
		<-waited
		return ctx.Err()
	case err := <-waited:
		return err
	}
}

// Every request: its session into the context, and a call through the session's limits and its network's checks.
func (self *McpServer) middleware(next gomcp.MethodHandler) gomcp.MethodHandler {
	return func(ctx context.Context, method string, request gomcp.Request) (gomcp.Result, error) {
		serverSession, _ := request.GetSession().(*gomcp.ServerSession)
		session := self.sessionOf(serverSession)
		if session == nil {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "no session"}
		}
		ctx = context.WithValue(ctx, mcpSessionContextKey{}, session)
		if method != mcpMethodToolsCall && method != mcpMethodResourcesRead {
			return next(ctx, method, request)
		}
		if session.agentErr != nil {
			return nil, newMcpError(McpCodeInvalidSession, "the session's agent label is not one: fix --agent or the project's .ur", false)
		}
		network := ""
		if params, ok := request.GetParams().(*gomcp.CallToolParamsRaw); ok {
			network = mcpNetworkArgument(params.Arguments)
		}
		result, err := session.limits.run(ctx, func(ctx context.Context) (any, error) {
			call, err := self.call(ctx, session, network)
			if err != nil {
				return nil, err
			}
			ctx = context.WithValue(ctx, mcpCallContextKey{}, call)
			return next(ctx, method, request)
		})
		if err != nil {
			return nil, err
		}
		answer, _ := result.(gomcp.Result)
		return answer, nil
	}
}

// A call's network, resolved by §5.8's rules and ready: refused with FAILED_PRECONDITION when none resolves, or when
// its Sidecar is Locked, Unenrolled or Revoked, each naming what the person runs in their own terminal. Then the
// session's run in it is readied (hook_bind.go): a taint taken while Locked applied first, the session bound where a
// hook has opened its harness process's run, and the coverage rules run.
func (self *McpServer) call(ctx context.Context, session *McpSession, network string) (*McpCall, error) {
	hello := session.hello
	networkId, err := self.daemon.ResolveNetwork(&hello, network)
	if err != nil {
		var networkErr *sidecar.DaemonNetworkError
		if errors.As(err, &networkErr) {
			return nil, newMcpError(McpCodeFailedPrecondition, networkErr.Error(), false)
		}
		return nil, newMcpError(McpCodeFailedPrecondition, "no network to act on: name one", false)
	}
	host, ok := self.daemon.Network(networkId)
	if !ok {
		return nil, newMcpError(McpCodeFailedPrecondition, "no sidecar runs for that network: run ur status in your own terminal", false)
	}
	switch host.Status().State {
	case sidecar.SidecarStateLocked:
		return nil, newMcpError(McpCodeFailedPrecondition, "the keychain is locked: run ur unlock in your own terminal", false)
	case sidecar.SidecarStateUnenrolled:
		return nil, newMcpError(McpCodeFailedPrecondition, "this device is not enrolled in the network: run ur login in your own terminal", false)
	case sidecar.SidecarStateRevoked:
		return nil, newMcpError(McpCodeFailedPrecondition, "this device was revoked from the network: run ur login in your own terminal to enroll anew", false)
	}
	call := &McpCall{Session: session, NetworkId: networkId, Network: host}
	if err := self.binder.readyCall(ctx, call); err != nil {
		if _, _, isMcpError := McpErrorCode(err); isMcpError {
			return nil, err
		}
		return nil, newMcpError(McpCodeFailedPrecondition, "the run's taint cannot be read or written: run ur status in your own terminal", true)
	}
	return call, nil
}

// A tools/call's network argument: its arguments object's "network" string, else empty.
func mcpNetworkArgument(arguments json.RawMessage) string {
	var withNetwork struct {
		Network string `json:"network"`
	}
	if len(arguments) == 0 || json.Unmarshal(arguments, &withNetwork) != nil {
		return ""
	}
	return withNetwork.Network
}

// A subscription: refused unless the resource map admits it for the session.
func (self *McpServer) subscribe(ctx context.Context, request *gomcp.SubscribeRequest) error {
	session := self.sessionOf(request.Session)
	check := func() McpSubscribeCheck {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.subscribeCheck
	}()
	if session == nil || check == nil || request.Params == nil {
		return &jsonrpc.Error{Code: gomcp.CodeResourceNotFound, Message: "no such resource"}
	}
	return check(ctx, session, request.Params.URI)
}

// An unsubscription, always taken.
func (self *McpServer) unsubscribe(ctx context.Context, request *gomcp.UnsubscribeRequest) error {
	return nil
}

// A session's input: the stream's bytes once the gate opens, a line past maxByteCount ending the session.
type mcpLineReader struct {
	reader        io.Reader
	gate          <-chan struct{}
	maxByteCount  int64
	lineByteCount int64
}

// The stream's next bytes, or an error once a line passes its bound.
func (self *mcpLineReader) Read(p []byte) (int, error) {
	<-self.gate
	count, err := self.reader.Read(p)
	for _, b := range p[:count] {
		if b == '\n' {
			self.lineByteCount = 0
			continue
		}
		self.lineByteCount += 1
		if self.maxByteCount < self.lineByteCount {
			return 0, errMcpLineTooLong
		}
	}
	return count, err
}

// The daemon closes the stream once Serve returns.
func (self *mcpLineReader) Close() error {
	return nil
}

// A line past the request bound, which closes its session.
var errMcpLineTooLong = errors.New("an mcp line past the request bound")

// A session's output: the stream, which the daemon closes once Serve returns.
type mcpStreamWriter struct {
	writer io.Writer
}

func (self *mcpStreamWriter) Write(p []byte) (int, error) {
	return self.writer.Write(p)
}

func (self *mcpStreamWriter) Close() error {
	return nil
}

// go-sdk's log, as the daemon's: errors only, by their message alone, so no argument, result or path reaches a log
// line (I-13). Never stdout.
type mcpLogHandler struct {
	log sidecar.Logger
}

func (self *mcpLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return slog.LevelError <= level
}

func (self *mcpLogHandler) Handle(ctx context.Context, record slog.Record) error {
	self.log.Warningf("[mcp]%s", record.Message)
	return nil
}

func (self *mcpLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return self
}

func (self *mcpLogHandler) WithGroup(name string) slog.Handler {
	return self
}
