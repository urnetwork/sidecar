//go:build !js && !ios && !android && !sdk_mobile_bind

// The container socket (DESIGN-COMPUTE §11.10, §8.7, §20.4; D-ENC-6, IC-14, I-9; ENC-M14-14): the one socket bound
// into the agents' container, served by the daemon outside it, for the harnesses that run there. It serves MCP's
// tools (§15.2's catalog, through the daemon's mcp mode), `ur gateway token` for the container's gateway grants and
// `ur install-harness`'s request for one (the gateway's, EnclaveContainerGateway), and `ur hook` reports; nothing
// else: no git, git-hook or socket mode, and no control method but the gateway's two and those an area registers
// for it (registerEnclaveContainerSocketMethod). It is never bound into the edit container.
//
//	caller     bound by SO_PEERCRED, never by what it says: its pid must run in the container's PID namespace and
//	           its uid be one the container maps, else it is refused; its ancestry is read as the daemon sees it,
//	           and counts up to the container's entry, the first ancestor outside it (the runtime above its first
//	           process, or an Exec's nsenter, which the daemon's run binder takes for the harness when only shells
//	           stand between), so the Harness and the daemon above never take a container's taint; its harness
//	           process is the nearest of those that is no shell
//	claims     a hello's pid that is not the caller's own pid in the container names another process, and the session
//	           is refused; a hello's working directory is a path in the container's mount namespace, which the
//	           daemon's would misread, so it is dropped; a request asking for a person's confirmation is refused,
//	           since none comes from a container (D-CORE-13)
//	taint      every call is a tainted run's (§11.10, for kinds 23 to 25 and the inbox refusal alike): before the
//	           socket forwards a call, and again before it passes on an answer, it taints, write-ahead, every run
//	           whose harness process is among the caller's ancestors in the container; a caller with none acts in
//	           an unknown run, which reads tainted by itself (RunStore.Tainted). A taint that cannot be written
//	           refuses the call
//	ordering   a hook event may open or move a run of its harness process, which a call of that harness's MCP
//	           session then acts in: per harness process, a hook event holds the harness's lock alone from before
//	           its dispatch to after its answer's taint, and a call holds it shared from before its forwarding to
//	           after its answer's taint (an MCP call to its answer, or its cancellation), so no call of a harness
//	           acts in a run its hook opened before that run's taint is written
//	inbox      evs_write and evs_delete under inbox/ are refused here (§20.4), by SKILL's guard where it is wired and
//	           for every repo until then, the closed side
//	secrets    no key, token or link secret crosses it but the gateway's hour-long tokens (IC-11): control answers
//	           pass the daemon's reply walk, and MCP results its own I-7 rules
//
// Safe for concurrent use.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
)

// The socket's format values: the hook's method (mcp.McpHookMethod), the gateway's two, MCP's tool call and its
// cancellation, the evs tools that write and delete, and the refusal code MCP's refusals take (mcp.McpCodeRefused).
const (
	enclaveContainerHookMethod          = "hook.event"
	EnclaveContainerGatewayTokenMethod  = "gateway.token"
	EnclaveContainerGatewayGrantMethod  = "gateway.grant"
	enclaveContainerMcpToolsCall        = "tools/call"
	enclaveContainerMcpCancelled        = "notifications/cancelled"
	enclaveContainerMcpEvsWrite         = "evs_write"
	enclaveContainerMcpEvsDelete        = "evs_delete"
	enclaveContainerInboxPath           = "inbox"
	enclaveContainerSocketRefusedCode   = -32008
	enclaveContainerSocketClaimError    = "claim"
	enclaveContainerSocketTaintError    = "taint"
	enclaveContainerSocketCallerRefused = "caller"
)

// Why a run was tainted: a call through an enclave's container socket (§11.10).
const RunTaintEnclaveContainer RunTaintReason = "enclave_container"

var (
	// A caller the socket does not serve: no peer credentials, a pid outside the container, a uid it does not map.
	ErrEnclaveContainerCaller = errors.New("the caller is no process of the agents' container")
	// The gateway's container grants are not wired (GW C§8.7), or the harness has no container grant.
	ErrEnclaveContainerNoGrant = errors.New("no container gateway grant for that harness")
)

// What the socket asks of the agents' container: EnclaveContainer is one. Safe for concurrent use.
type EnclaveContainerScope interface {
	// Whether pid, as the daemon sees it, runs in the container, and its pid there.
	Contains(pid int) (int, bool)
	// Whether a uid outside is one the container maps.
	OwnsUid(uid uint32) bool
}

// One caller of the socket: who it is, which run its calls are, and that the run is tainted (§11.10).
type EnclaveContainerCaller struct {
	Peer EnclaveContainerPeer
	// Its pid in the container's PID namespace, which a hello's pid must name.
	NamespacePid int
	// Its ancestors inside the container and the container's entry above them, the caller first, as the daemon sees
	// them.
	Ancestors []ProcessIdentity
	// The nearest of them that is no shell: the harness process whose runs the caller's calls are. Zero for none.
	Harness ProcessIdentity
	// The newest run whose harness process is among Ancestors, as of the caller's last call: the hook-bound run it
	// acts in. Nil for an unknown run, which reads tainted.
	RunId *Id
	// Every call through the socket is a tainted run's.
	Tainted bool
}

// What `ur install-harness <h> --gateway` asks for in the container (§8.7).
type EnclaveContainerGrantRequest struct {
	Harness string `json:"harness"`
	Agent   string `json:"agent,omitempty"`
}

// What `ur gateway token` asks for in the container (§8.6).
type EnclaveContainerTokenRequest struct {
	Harness string `json:"harness"`
	Agent   string `json:"agent,omitempty"`
}

// A gateway grant the socket mints for: the enclave's, made through the socket from the sponsor's settings.
type EnclaveContainerGrant struct {
	Harness string `json:"harness"`
	Agent   string `json:"agent,omitempty"`
	// Made for the container, through the socket: a token is minted only for such a grant.
	Container bool `json:"container"`
}

// An hour-long gateway token (§8.6, IC-11): the one credential a container process may hold.
type EnclaveContainerToken struct {
	Token         string `json:"token"`
	ExpiresMillis int64  `json:"expires_millis"`
}

// The gateway's container grants and tokens (GW C§8.7, GW-M14-01's GatewayContainerListener). Safe for concurrent use.
type EnclaveContainerGateway interface {
	// The grant of harness and agent, nil with no error for none.
	ContainerGrant(ctx context.Context, harness string, agent string) (*EnclaveContainerGrant, error)
	// Makes the container's grant for a harness from the enclave's settings (the sponsor's models key, acknowledged
	// disclosures and the enclave's budget), asking no one.
	MakeContainerGrant(ctx context.Context, caller *EnclaveContainerCaller, request *EnclaveContainerGrantRequest) (*EnclaveContainerGrant, error)
	// Mints an hour-long token of a container grant for the caller.
	MintContainerToken(ctx context.Context, caller *EnclaveContainerCaller, grant *EnclaveContainerGrant) (*EnclaveContainerToken, error)
}

// Whether a write or delete of path in repo is an inbox's (§20.4): SKILL's AgentsInboxGuard, which knows the agent
// and agents repos and the Team inbox.
type EnclaveContainerInboxGuard func(ctx context.Context, repo string, path string) bool

// What the socket serves through: the enclave's daemon (NewEnclaveContainerDaemonHost), or a test's. Safe for
// concurrent use.
type EnclaveContainerSocketHost interface {
	// The run store of the network the container's calls act in.
	Runs() (*RunStore, error)
	// Serves one mcp session: the daemon's mcp mode.
	ServeMcp(ctx context.Context, hello *DaemonHello, stream io.ReadWriter) error
	// A JSON-RPC dispatcher for hello's session through the daemon's methods: each request line answered, nil for a
	// notification.
	RpcSession(hello *DaemonHello) func(ctx context.Context, line []byte) []byte
}

// The enclave's daemon as the socket's host, acting in networkId.
type enclaveContainerDaemonHost struct {
	daemon    *Daemon
	networkId Id
}

// The daemon, hosting the enclave's one network, as the socket's host.
func NewEnclaveContainerDaemonHost(daemon *Daemon, networkId Id) EnclaveContainerSocketHost {
	return &enclaveContainerDaemonHost{daemon: daemon, networkId: networkId}
}

// The hosted network's run store.
func (self *enclaveContainerDaemonHost) Runs() (*RunStore, error) {
	hosted, ok := self.daemon.SidecarForNetwork(self.networkId)
	if !ok {
		return nil, ErrSidecarStoreLocked
	}
	return hosted.Runs()
}

// The daemon's registered mcp mode, which cli/ injects.
func (self *enclaveContainerDaemonHost) ServeMcp(ctx context.Context, hello *DaemonHello, stream io.ReadWriter) error {
	handler, ok := self.daemon.mode(DaemonModeMcp)
	if !ok {
		return fmt.Errorf("%w: no mcp mode", ErrDaemonHello)
	}
	return handler(ctx, hello, stream)
}

// The daemon's own dispatch over a session of hello's, with its network resolution, request bound and reply walk.
func (self *enclaveContainerDaemonHost) RpcSession(hello *DaemonHello) func(ctx context.Context, line []byte) []byte {
	session := &daemonSession{hello: hello}
	return func(ctx context.Context, line []byte) []byte {
		response := self.daemon.dispatch(line, session, self.daemon.runBounded)
		if response == nil {
			return nil
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			return nil
		}
		return encoded
	}
}

// The control and hook methods areas let through the socket beside the gateway's, by mode: the hook's, and what an
// area registers from its own file's init (GIT-M14-01's `ur git`).
var enclaveContainerSocketMethods struct {
	stateLock sync.Mutex
	modeNames map[string][]string
}

// Lets method through the socket in mode, hook or control. Call from the owner's file's init.
func registerEnclaveContainerSocketMethod(mode string, method string) {
	enclaveContainerSocketMethods.stateLock.Lock()
	defer enclaveContainerSocketMethods.stateLock.Unlock()
	if enclaveContainerSocketMethods.modeNames == nil {
		enclaveContainerSocketMethods.modeNames = map[string][]string{}
	}
	if !slices.Contains(enclaveContainerSocketMethods.modeNames[mode], method) {
		enclaveContainerSocketMethods.modeNames[mode] = append(enclaveContainerSocketMethods.modeNames[mode], method)
	}
}

// Whether method is let through in mode.
func enclaveContainerSocketMethodAllowed(mode string, method string) bool {
	enclaveContainerSocketMethods.stateLock.Lock()
	defer enclaveContainerSocketMethods.stateLock.Unlock()
	return slices.Contains(enclaveContainerSocketMethods.modeNames[mode], method)
}

// Lets the hook's method through in hook mode.
func init() {
	registerEnclaveContainerSocketMethod(DaemonModeHook, enclaveContainerHookMethod)
}

// What NewEnclaveContainerSocket takes.
type EnclaveContainerSocketArgs struct {
	// Nil is DefaultEnclaveContainerSocketSettings.
	Settings *EnclaveContainerSocketSettings
	// The daemon's line bounds. Nil is DefaultSidecarSettings'.
	Local *SidecarLocalSettings
	// The ancestry bound and shell names the daemon's run binder reads. Nil is DefaultSidecarSettings'.
	Ingest *SidecarIngestSettings
	// The version a hello must name: the daemon's.
	Version   string
	Host      EnclaveContainerSocketHost
	Container EnclaveContainerScope
	// Nil refuses both gateway calls, the closed side until GW-M14-01 lands.
	Gateway EnclaveContainerGateway
	// Nil refuses every write and delete under inbox/, the closed side until SKILL's guard is wired.
	InboxGuard EnclaveContainerInboxGuard
	// Nil is the build's: the enclave's SO_PEERCRED, else none, refusing every caller.
	Peer func(conn net.Conn) (EnclaveContainerPeer, error)
	// Nil is the system's.
	Processes ProcessTable
	// Nil is no logging.
	Log Logger
}

// One harness process's ordering of hook events against calls.
type enclaveContainerHarnessLock struct {
	lock sync.RWMutex
	// sessions and calls holding or waiting for it; it is dropped at zero
	holderCount int
}

// The container socket.
type EnclaveContainerSocket struct {
	settings   *EnclaveContainerSocketSettings
	local      *SidecarLocalSettings
	ingest     *SidecarIngestSettings
	version    string
	host       EnclaveContainerSocketHost
	container  EnclaveContainerScope
	gateway    EnclaveContainerGateway
	inboxGuard EnclaveContainerInboxGuard
	peer       func(conn net.Conn) (EnclaveContainerPeer, error)
	processes  ProcessTable
	log        Logger

	stateLock    sync.Mutex
	sessionCount int
	harnessLocks map[ProcessIdentity]*enclaveContainerHarnessLock
	// called when a call or hook waits for its harness's lock, a test's seam
	onLockWait func(harness ProcessIdentity)
}

// A socket for args.Container through args.Host.
func NewEnclaveContainerSocket(args *EnclaveContainerSocketArgs) (*EnclaveContainerSocket, error) {
	if args.Host == nil || args.Container == nil {
		return nil, fmt.Errorf("%w: a container socket needs its host and its container", ErrEnclaveContainerSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultEnclaveContainerSocketSettings()
	}
	if err := settings.check(); err != nil {
		return nil, err
	}
	defaults := DefaultSidecarSettings()
	local := args.Local
	if local == nil {
		local = defaults.LocalSettings
	}
	ingest := args.Ingest
	if ingest == nil {
		ingest = defaults.Ingest
	}
	peer := args.Peer
	if peer == nil {
		peer = enclaveContainerBuildPeer
	}
	processes := args.Processes
	if processes == nil {
		processes = SystemProcessTable()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &EnclaveContainerSocket{
		settings:     settings,
		local:        local,
		ingest:       ingest,
		version:      args.Version,
		host:         args.Host,
		container:    args.Container,
		gateway:      args.Gateway,
		inboxGuard:   args.InboxGuard,
		peer:         peer,
		processes:    processes,
		log:          log,
		harnessLocks: map[ProcessIdentity]*enclaveContainerHarnessLock{},
	}, nil
}

// Listens at Settings.Path: its directory 0711 and the socket 0666, since a container's root is an unmapped owner
// there and the directory is reachable only through the container's bind (its parent admits root alone).
func (self *EnclaveContainerSocket) Listen() (net.Listener, error) {
	directory := path.Dir(self.settings.Path)
	if err := os.MkdirAll(directory, 0o711); err != nil {
		return nil, err
	}
	if err := os.Chmod(directory, 0o711); err != nil {
		return nil, err
	}
	if err := os.Remove(self.settings.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", self.settings.Path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(self.settings.Path, 0o666); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// Serves listener's sessions until ctx ends or listener fails, then closes it.
func (self *EnclaveContainerSocket) Serve(ctx context.Context, listener net.Listener) error {
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-serveCtx.Done()
		listener.Close()
	}()
	waitGroup := sync.WaitGroup{}
	defer waitGroup.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if serveCtx.Err() != nil {
				return nil
			}
			return err
		}
		admitted := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.settings.SessionCount <= self.sessionCount {
				return false
			}
			self.sessionCount += 1
			return true
		}()
		if !admitted {
			self.log.Warningf("[enclave]the container socket refused a session past %d", self.settings.SessionCount)
			conn.Close()
			continue
		}
		waitGroup.Go(func() {
			defer func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.sessionCount -= 1
			}()
			sessionCtx, sessionCancel := context.WithCancel(serveCtx)
			defer sessionCancel()
			go func() {
				// a session ends with the socket, and this ends with the session
				<-sessionCtx.Done()
				conn.Close()
			}()
			if err := self.serveConn(sessionCtx, conn); err != nil && self.log.V(1).Enabled() {
				self.log.Infof("[enclave]a container socket session ended: %s", err)
			}
		})
	}
}

// Binds conn's caller by its peer credentials: refused unless it runs in the container under a uid the container
// maps; its ancestry inside the container read, and its harness process found among them.
func (self *EnclaveContainerSocket) bind(conn net.Conn) (*EnclaveContainerCaller, error) {
	if self.peer == nil {
		return nil, fmt.Errorf("%w: this build reads no peer credentials", ErrEnclaveContainerCaller)
	}
	peer, err := self.peer(conn)
	if err != nil || peer.Pid <= 0 {
		return nil, fmt.Errorf("%w: no peer credentials", ErrEnclaveContainerCaller)
	}
	namespacePid, inside := self.container.Contains(peer.Pid)
	if !inside || !self.container.OwnsUid(peer.Uid) {
		return nil, ErrEnclaveContainerCaller
	}
	caller := &EnclaveContainerCaller{Peer: peer, NamespacePid: namespacePid, Tainted: true}
	ancestors, err := ProcessAncestors(self.processes, peer.Pid, self.ingest.AncestorDepthCount)
	if err != nil {
		// its ancestry unread, it acts in an unknown run, which reads tainted
		return caller, nil
	}
	chain := []*ProcessInfo{}
	for _, ancestor := range ancestors {
		chain = append(chain, ancestor)
		caller.Ancestors = append(caller.Ancestors, ancestor.Identity)
		if _, inside := self.container.Contains(ancestor.Identity.Pid); !inside {
			// the container's entry, which the run binder may take for a harness; the daemon and the Harness above it
			// never take a container's taint
			break
		}
	}
	if harness := HarnessProcessOf(chain, self.ingest.ShellNames); harness != nil {
		caller.Harness = harness.Identity
	}
	return caller, nil
}

// Taints, write-ahead, every run whose harness process is among the caller's ancestors up to the container's entry,
// and answers the newest, the caller's run; nil with none, an unknown run. Every run is tried; the answer joins the
// failures.
func (self *EnclaveContainerSocket) taintCaller(ctx context.Context, caller *EnclaveContainerCaller) (*Id, error) {
	runs, err := self.host.Runs()
	if err != nil {
		return nil, err
	}
	files, err := runs.List(ctx)
	if err != nil {
		return nil, err
	}
	errs := []error{}
	var newest *Id
	for _, file := range files {
		process := ProcessIdentity{Pid: file.ProcessId, StartMillis: file.ProcessStartMillis}
		if !process.Known() || !slices.Contains(caller.Ancestors, process) {
			continue
		}
		errs = append(errs, runs.Taint(ctx, file.RunId, RunTaintEnclaveContainer))
		if newest == nil || newest.Less(file.RunId) {
			runId := file.RunId
			newest = &runId
		}
	}
	return newest, errors.Join(errs...)
}

// The ordering lock of a harness process, held by one more holder until released.
func (self *EnclaveContainerSocket) harnessLock(harness ProcessIdentity) (*enclaveContainerHarnessLock, func()) {
	lock := func() *enclaveContainerHarnessLock {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		lock, ok := self.harnessLocks[harness]
		if !ok {
			lock = &enclaveContainerHarnessLock{}
			self.harnessLocks[harness] = lock
		}
		lock.holderCount += 1
		return lock
	}()
	release := func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		lock.holderCount -= 1
		if lock.holderCount == 0 {
			delete(self.harnessLocks, harness)
		}
	}
	return lock, release
}

// Holds harness's lock shared, a call's, until the returned release.
func (self *EnclaveContainerSocket) lockCall(harness ProcessIdentity) func() {
	lock, release := self.harnessLock(harness)
	if !lock.lock.TryRLock() {
		if onLockWait := self.lockWaitHook(); onLockWait != nil {
			onLockWait(harness)
		}
		lock.lock.RLock()
	}
	once := sync.Once{}
	return func() {
		once.Do(func() {
			lock.lock.RUnlock()
			release()
		})
	}
}

// Holds harness's lock alone, a hook event's, until the returned release.
func (self *EnclaveContainerSocket) lockHook(harness ProcessIdentity) func() {
	lock, release := self.harnessLock(harness)
	if !lock.lock.TryLock() {
		if onLockWait := self.lockWaitHook(); onLockWait != nil {
			onLockWait(harness)
		}
		lock.lock.Lock()
	}
	return func() {
		lock.lock.Unlock()
		release()
	}
}

// The lock-wait seam as set.
func (self *EnclaveContainerSocket) lockWaitHook() func(harness ProcessIdentity) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.onLockWait
}

// One session: the caller bound, its hello read and checked, its runs tainted, then its mode served.
func (self *EnclaveContainerSocket) serveConn(ctx context.Context, conn net.Conn) error {
	caller, err := self.bind(conn)
	if err != nil {
		self.log.Warningf("[enclave]the container socket refused a caller: %s", err)
		return err
	}
	reader := bufio.NewReaderSize(conn, self.local.SessionBufferByteCount)
	line, err := readDaemonLine(reader, self.local.HelloByteCount)
	if err != nil {
		return err
	}
	answer := func(code string) error {
		encoded, err := json.Marshal(&daemonHelloAnswer{UrLocal: daemonLocalProtocol, Version: self.version, Error: code})
		if err != nil {
			return err
		}
		_, err = conn.Write(append(encoded, '\n'))
		return err
	}
	hello, code, err := parseDaemonHello(line, self.version, self.local.HelloByteCount)
	if err != nil {
		answer(code)
		return err
	}
	if hello.Mode != DaemonModeMcp && hello.Mode != DaemonModeHook && hello.Mode != DaemonModeControl {
		answer(DaemonHelloErrorMode)
		return fmt.Errorf("%w: mode %s through the container socket", ErrDaemonHello, hello.Mode)
	}
	if hello.Pid != 0 && hello.Pid != int64(caller.NamespacePid) {
		answer(enclaveContainerSocketClaimError)
		return fmt.Errorf("%w: a hello naming another process", ErrEnclaveContainerCaller)
	}
	// the daemon reads the caller as it sees it, never its word
	hello.Pid = int64(caller.Peer.Pid)
	hello.PeerPid = int64(caller.Peer.Pid)
	hello.Cwd = ""
	runId, err := self.taintCaller(ctx, caller)
	if err != nil {
		answer(enclaveContainerSocketTaintError)
		return err
	}
	// fixed before the session's goroutines start, which only read the caller
	caller.RunId = runId
	if err := answer(""); err != nil {
		return err
	}
	if hello.Mode == DaemonModeMcp {
		return self.serveMcp(ctx, caller, hello, reader, conn)
	}
	return self.serveRpc(ctx, caller, hello, reader, conn)
}

// The parts of a JSON-RPC message the socket reads.
type enclaveContainerRpcMessage struct {
	Id          json.RawMessage `json:"id"`
	Method      string          `json:"method"`
	Params      json.RawMessage `json:"params"`
	UrConfirmed bool            `json:"ur_confirmed"`
}

// A message's id as a key: its compact JSON; empty for a notification.
func (self *enclaveContainerRpcMessage) idKey() string {
	if len(self.Id) == 0 || bytes.Equal(self.Id, []byte("null")) {
		return ""
	}
	compact := bytes.Buffer{}
	if err := json.Compact(&compact, self.Id); err != nil {
		return string(self.Id)
	}
	return compact.String()
}

// A JSON-RPC error answer to id, a line.
func enclaveContainerRpcError(id json.RawMessage, code int, message string) []byte {
	encoded, _ := json.Marshal(&daemonRpcResponse{JsonRpc: "2.0", Id: id, Error: &DaemonRpcError{Code: code, Message: message}})
	return append(encoded, '\n')
}

// Whether an MCP request is an evs write or delete under inbox/ that the guard refuses.
func (self *EnclaveContainerSocket) inboxRefused(ctx context.Context, message *enclaveContainerRpcMessage) bool {
	if message.Method != enclaveContainerMcpToolsCall {
		return false
	}
	params := struct {
		Name      string `json:"name"`
		Arguments struct {
			Repo string `json:"repo"`
			Path string `json:"path"`
		} `json:"arguments"`
	}{}
	if err := json.Unmarshal(message.Params, &params); err != nil {
		return false
	}
	if params.Name != enclaveContainerMcpEvsWrite && params.Name != enclaveContainerMcpEvsDelete {
		return false
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+params.Arguments.Path), "/")
	if cleaned != enclaveContainerInboxPath && !strings.HasPrefix(cleaned, enclaveContainerInboxPath+"/") {
		return false
	}
	if self.inboxGuard == nil {
		return true
	}
	return self.inboxGuard(ctx, params.Arguments.Repo, cleaned)
}

// The writer an MCP session's answers go to: each whole line's id matched to its call, the caller's runs tainted
// before the line goes on, and the call's ordering released after.
type enclaveContainerMcpWriter struct {
	socket *EnclaveContainerSocket
	ctx    context.Context
	caller *EnclaveContainerCaller
	conn   io.Writer

	stateLock sync.Mutex
	pending   []byte
	// the release of each call in flight, by its id's key
	releases map[string]func()

	// one line at a time to the caller
	writeLock sync.Mutex
	failed    error
}

// Writes a line to the caller, one at a time; the first failure answers every later write.
func (self *enclaveContainerMcpWriter) writeLine(line []byte) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if self.failed != nil {
		return self.failed
	}
	if _, err := self.conn.Write(line); err != nil {
		self.failed = err
		return err
	}
	return nil
}

// Takes the server's bytes; each whole line is an answer or the server's own notification, which goes on once the
// caller's runs are tainted.
func (self *enclaveContainerMcpWriter) Write(p []byte) (int, error) {
	lines := func() [][]byte {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.pending = append(self.pending, p...)
		lines := [][]byte{}
		for {
			end := bytes.IndexByte(self.pending, '\n')
			if end < 0 {
				return lines
			}
			lines = append(lines, slices.Clone(self.pending[:end+1]))
			self.pending = self.pending[end+1:]
		}
	}()
	for _, line := range lines {
		message := &enclaveContainerRpcMessage{}
		key := ""
		if json.Unmarshal(line, message) == nil && message.Method == "" {
			key = message.idKey()
		}
		// every answer is a tainted run's before it reaches the caller
		if _, err := self.socket.taintCaller(self.ctx, self.caller); err != nil {
			self.releaseKey(key)
			return 0, fmt.Errorf("the run's taint could not be written: %w", err)
		}
		testHookBarrier("enclave_container_socket.answer.before", key)
		err := self.writeLine(line)
		testHookBarrier("enclave_container_socket.answer.after", key)
		self.releaseKey(key)
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Notes a call in flight; a second call of one id releases the first's.
func (self *enclaveContainerMcpWriter) hold(key string, release func()) {
	previous := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		previous := self.releases[key]
		self.releases[key] = release
		return previous
	}()
	if previous != nil {
		previous()
	}
}

// Releases a call in flight: at its answer, or its cancellation.
func (self *enclaveContainerMcpWriter) releaseKey(key string) {
	if key == "" {
		return
	}
	release := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		release := self.releases[key]
		delete(self.releases, key)
		return release
	}()
	if release != nil {
		release()
	}
}

// Releases every call in flight, at the session's end.
func (self *enclaveContainerMcpWriter) releaseAll() {
	releases := func() []func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		releases := []func(){}
		for key, release := range self.releases {
			delete(self.releases, key)
			releases = append(releases, release)
		}
		return releases
	}()
	for _, release := range releases {
		release()
	}
}

// Answers the caller directly, never reaching the server.
func (self *enclaveContainerMcpWriter) answer(line []byte) error {
	return self.writeLine(line)
}

// The stream the daemon's mcp mode serves: the caller's lines the socket let through, and the writer above.
type enclaveContainerMcpStream struct {
	reader io.Reader
	writer io.Writer
}

// The caller's lines the socket let through.
func (self *enclaveContainerMcpStream) Read(p []byte) (int, error) {
	return self.reader.Read(p)
}

// The server's answers, to the writer that taints before it passes them on.
func (self *enclaveContainerMcpStream) Write(p []byte) (int, error) {
	return self.writer.Write(p)
}

// An mcp session: each request held in its harness's order, its runs tainted, an inbox write refused, then passed
// to the daemon's mcp mode; each answer tainted again before it goes on.
func (self *EnclaveContainerSocket) serveMcp(ctx context.Context, caller *EnclaveContainerCaller, hello *DaemonHello, reader *bufio.Reader, conn net.Conn) error {
	pipeReader, pipeWriter := io.Pipe()
	writer := &enclaveContainerMcpWriter{socket: self, ctx: ctx, caller: caller, conn: conn, releases: map[string]func(){}}
	defer writer.releaseAll()
	served := make(chan error, 1)
	go func() {
		err := self.host.ServeMcp(ctx, hello, &enclaveContainerMcpStream{reader: pipeReader, writer: writer})
		pipeReader.CloseWithError(io.ErrClosedPipe)
		served <- err
	}()
	readErr := func() error {
		for {
			line, err := readDaemonLine(reader, self.local.RequestByteCount)
			if err != nil {
				return err
			}
			message := &enclaveContainerRpcMessage{}
			if err := json.Unmarshal(line, message); err != nil {
				// the server answers a parse error itself
				if _, err := pipeWriter.Write(append(line, '\n')); err != nil {
					return err
				}
				continue
			}
			key := message.idKey()
			if message.Method == enclaveContainerMcpCancelled {
				cancelled := struct {
					RequestId json.RawMessage `json:"requestId"`
				}{}
				if json.Unmarshal(message.Params, &cancelled) == nil {
					writer.releaseKey((&enclaveContainerRpcMessage{Id: cancelled.RequestId}).idKey())
				}
			}
			release := func() {}
			if key != "" && message.Method != "" {
				release = self.lockCall(caller.Harness)
				writer.hold(key, release)
			}
			if _, err := self.taintCaller(ctx, caller); err != nil {
				writer.releaseKey(key)
				if key != "" {
					if err := writer.answer(enclaveContainerRpcError(message.Id, enclaveContainerSocketRefusedCode, "the run's taint could not be written, so the call does not run")); err != nil {
						return err
					}
				}
				continue
			}
			if self.inboxRefused(ctx, message) {
				writer.releaseKey(key)
				if key != "" {
					if err := writer.answer(enclaveContainerRpcError(message.Id, enclaveContainerSocketRefusedCode, "writes and deletes under inbox/ are refused: a message goes by agent_send")); err != nil {
						return err
					}
				}
				continue
			}
			if _, err := pipeWriter.Write(append(line, '\n')); err != nil {
				writer.releaseKey(key)
				return err
			}
		}
	}()
	pipeWriter.CloseWithError(readErr)
	serveErr := <-served
	if errors.Is(readErr, io.EOF) {
		return serveErr
	}
	return errors.Join(readErr, serveErr)
}

// A hook or control session: each request line taken in turn, refused unless its method is let through, then run
// with the caller's runs tainted before and after, a hook event alone in its harness's order.
func (self *EnclaveContainerSocket) serveRpc(ctx context.Context, caller *EnclaveContainerCaller, hello *DaemonHello, reader *bufio.Reader, conn net.Conn) error {
	dispatch := self.host.RpcSession(hello)
	for {
		line, err := readDaemonLine(reader, self.local.RequestByteCount)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		response := self.rpcCall(ctx, caller, hello, dispatch, line)
		if response == nil {
			continue
		}
		testHookBarrier("enclave_container_socket.answer.before", hello.Mode)
		_, err = conn.Write(append(bytes.TrimRight(response, "\n"), '\n'))
		testHookBarrier("enclave_container_socket.answer.after", hello.Mode)
		if err != nil {
			return err
		}
	}
}

// One request of a hook or control session, its answer, nil for a notification.
func (self *EnclaveContainerSocket) rpcCall(ctx context.Context, caller *EnclaveContainerCaller, hello *DaemonHello, dispatch func(ctx context.Context, line []byte) []byte, line []byte) []byte {
	message := &enclaveContainerRpcMessage{}
	if err := json.Unmarshal(line, message); err != nil || message.Method == "" {
		return enclaveContainerRpcError(json.RawMessage("null"), daemonRpcInvalidRequest, "invalid request")
	}
	refuse := func(code int, text string) []byte {
		if message.idKey() == "" {
			return nil
		}
		return enclaveContainerRpcError(message.Id, code, text)
	}
	if message.UrConfirmed {
		return refuse(DaemonRpcConfirmationRequired, "a person's confirmation never comes from a container")
	}
	gateway := hello.Mode == DaemonModeControl &&
		(message.Method == EnclaveContainerGatewayTokenMethod || message.Method == EnclaveContainerGatewayGrantMethod)
	if !gateway && !enclaveContainerSocketMethodAllowed(hello.Mode, message.Method) {
		return refuse(daemonRpcMethodNotFound, "method not found")
	}
	var release func()
	if hello.Mode == DaemonModeHook {
		// a hook event may open or move its harness's run: alone in the harness's order to its answer's taint
		release = self.lockHook(caller.Harness)
	} else {
		release = self.lockCall(caller.Harness)
	}
	defer release()
	if _, err := self.taintCaller(ctx, caller); err != nil {
		return refuse(DaemonRpcFailed, "the run's taint could not be written, so the call does not run")
	}
	var response []byte
	if gateway {
		response = self.gatewayCall(ctx, caller, message)
	} else {
		response = dispatch(ctx, line)
	}
	if _, err := self.taintCaller(ctx, caller); err != nil {
		return refuse(DaemonRpcFailed, "the run's taint could not be written, so the answer is withheld")
	}
	return response
}

// The gateway's two calls (§8.6, §8.7): a grant made for the container, and a token minted only for a container grant.
func (self *EnclaveContainerSocket) gatewayCall(ctx context.Context, caller *EnclaveContainerCaller, message *enclaveContainerRpcMessage) []byte {
	answer := func(result any, err error) []byte {
		if message.idKey() == "" {
			return nil
		}
		if err != nil {
			return enclaveContainerRpcError(message.Id, DaemonRpcFailed, err.Error())
		}
		if err := checkDaemonReplyTo(result, self.local.ReplyMaxDepth); err != nil {
			return enclaveContainerRpcError(message.Id, daemonRpcInternalError, "internal error")
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return enclaveContainerRpcError(message.Id, daemonRpcInternalError, "internal error")
		}
		response, _ := json.Marshal(&daemonRpcResponse{JsonRpc: "2.0", Id: message.Id, Result: encoded})
		return response
	}
	if self.gateway == nil {
		return answer(nil, ErrEnclaveContainerNoGrant)
	}
	switch message.Method {
	case EnclaveContainerGatewayGrantMethod:
		request := &EnclaveContainerGrantRequest{}
		if err := json.Unmarshal(message.Params, request); err != nil || request.Harness == "" {
			return answer(nil, errors.New("a grant names its harness"))
		}
		grant, err := self.gateway.MakeContainerGrant(ctx, caller, request)
		if err == nil && (grant == nil || !grant.Container) {
			err = ErrEnclaveContainerNoGrant
		}
		return answer(grant, err)
	default:
		request := &EnclaveContainerTokenRequest{}
		if err := json.Unmarshal(message.Params, request); err != nil || request.Harness == "" {
			return answer(nil, errors.New("a token names its harness"))
		}
		grant, err := self.gateway.ContainerGrant(ctx, request.Harness, request.Agent)
		if err != nil {
			return answer(nil, err)
		}
		// a token only for the container's own grant (§8.7)
		if grant == nil || !grant.Container {
			return answer(nil, ErrEnclaveContainerNoGrant)
		}
		token, err := self.gateway.MintContainerToken(ctx, caller, grant)
		return answer(token, err)
	}
}
