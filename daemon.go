//go:build !js && !ios && !android && !sdk_mobile_bind

// The daemon's local IPC (§5.8, D-CORE-9): one ur daemon per instance, kept single by a flock on <state>/lock, serving
// a Unix socket in a 0700 directory, or on Windows a named pipe whose DACL admits the user's SID alone, to callers of
// its own uid (owner decision 84). Each session opens with §5.8's hello, then speaks JSON-RPC 2.0 for control and hook
// (daemon_rpc.go), carries one §9 stream for socket (daemon_socket.go), or hands its stream to the mode's
// DaemonModeHandler: mcp (§16's go-sdk, which cli/ injects, since the root never imports mcp/) and git (§11.11). The
// mode selects a protocol, never a privilege.
//
// Nothing here writes to stdout, which the MCP relay owns: logs go to settings' Log. A line past the request bound
// closes its session. An auto-spawned daemon exits once no session is open and none has made a request for
// IdleExitTimeout, unless its busy rule holds (mail, sockets, bridge or an indexer); one a unit runs never idles out.
//
// A Daemon is safe for concurrent use: methods and modes register before or while it serves.

package sidecar

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var (
	// Another daemon holds the instance's lock.
	ErrDaemonRunning = errors.New("a daemon is already running for this instance")
	// A method or mode registered twice, or with no name or handler.
	ErrDaemonRegistration = errors.New("daemon registration refused")
)

// What a host runs a Daemon with: the instance's paths and the rules the host decides. Numbers come from Local, the
// settings' only source of defaults.
type DaemonSettings struct {
	// The instance name (§5.9).
	Instance string
	// <state>, holding the lock.
	StateDirectory string
	// The socket or pipe path. Empty: §5.9's for the instance (DaemonSocketPath).
	SocketPath string
	// The request bound, its timeout and the idle exit.
	Local *SidecarLocalSettings
	// The daemon was spawned by a ur that found none running, and exits when idle. A unit-run daemon sets false
	// and never idles out (§5.8).
	AutoSpawned bool
	// Whether something keeps the daemon from idling out: mail, sockets or bridge on, or an indexer (§5.8). Nil:
	// nothing does.
	Busy func() bool
	// The version a hello must name. Empty is a development build's, and matches only another's.
	Version string
	// --listen: the addresses the local services bind, each an IP literal (DaemonLocalListen). Empty: every interface,
	// 0.0.0.0 and :: (owner decision 84), plaintext staying on loopback all the same (owner decision 130).
	Listen []string
	// §12's ResolveNetworkLabel over the networks this client belongs to, which `.ur`, a call's network argument and a
	// git session's <net> resolve through. Nil: only a network id or the only network names one.
	Labels NetworkLabelResolver
	// The user root those labels sit under, such as dns.yml names.
	LabelRoot string
	// $HOME, which bounds the search for `.ur` (§5.8). Empty: the OS's.
	Home string
	// `.ur`'s format limits and the bounds on reading a project's git config (daemon_project.go). Nil:
	// DefaultSidecarProjectSettings().
	Project *SidecarProjectSettings
	// The member's claims setting from the harness config in the author's vault (daemon_claims.go). Nil reads none, so
	// the team's default and `.ur` decide, as plan-MCP-harness-config-schema #3's interim reads no vault config.
	Claims SidecarClaimsConfig
	// Nil is real time.
	Clock Clock
	// Nil is no logging. Never stdout.
	Log Logger
}

// Serves one session of a mode the daemon does not speak itself, mcp or git, from the hello on: stream reads what
// follows the hello and writes the session's answers. Returns when the session ends; the daemon closes the stream.
type DaemonModeHandler func(ctx context.Context, hello *DaemonHello, stream io.ReadWriter) error

// The local daemon of one instance. Construct with NewDaemon, which takes the lock and listens; Run serves.
type Daemon struct {
	settings *DaemonSettings
	clock    Clock
	log      Logger
	lock     io.Closer
	listener net.Listener

	ctx    context.Context
	cancel context.CancelFunc

	stateLock sync.Mutex
	// the peer check, a seam a test replaces to stand for another uid
	peerAllowed func(conn net.Conn) error
	methods     map[string]*DaemonMethod
	modes       map[string]DaemonModeHandler
	sessions    map[net.Conn]bool
	// the last time a session opened or a request arrived, for the idle exit
	lastActivity time.Time
	// raised whenever a session opens or closes or a request arrives, so the idle loop re-reads
	activity *MonitorValue[uint64]
	closed   bool
	// the local services' listeners open, for ur status (daemon_local.go)
	localListeners map[*DaemonLocalListener]bool
	// the Sidecar of each network hosted (daemon_networks.go)
	networkIdSidecars map[Id]*Sidecar
	// the sockets and shares the daemon holds (daemon_socket.go), made on first use
	sockets *DaemonSockets
	// the host's platform authenticator, which the daemon's presence prompt asks (daemon_presence.go); nil for none
	presenceProvider PresenceProvider
}

// Takes the instance's lock and listens on its socket or pipe. ErrDaemonRunning when another daemon holds the lock.
// A stale socket file is removed only once the lock is held, since only the lock's holder may own the path.
func NewDaemon(ctx context.Context, settings *DaemonSettings) (*Daemon, error) {
	if settings == nil || settings.Local == nil || !isSidecarInstanceName(settings.Instance) || settings.StateDirectory == "" {
		return nil, fmt.Errorf("%w: a daemon needs its instance, state directory and local settings", errInvalidSettings)
	}
	lock, err := acquireDaemonLock(settings.StateDirectory)
	if err != nil {
		return nil, err
	}
	socketPath := settings.SocketPath
	if socketPath == "" {
		socketPath, err = DaemonSocketPath(settings.Instance)
		if err != nil {
			lock.Close()
			return nil, err
		}
	}
	listener, err := listenDaemon(socketPath)
	if err != nil {
		lock.Close()
		return nil, err
	}
	return newDaemonOn(ctx, settings, lock, listener), nil
}

// A Daemon on a lock and listener already held.
func newDaemonOn(ctx context.Context, settings *DaemonSettings, lock io.Closer, listener net.Listener) *Daemon {
	cancelCtx, cancel := context.WithCancel(ctx)
	clock := clockOrReal(settings.Clock)
	log := settings.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &Daemon{
		settings:     settings,
		clock:        clock,
		log:          log,
		lock:         lock,
		listener:     listener,
		peerAllowed:  checkDaemonPeer,
		ctx:          cancelCtx,
		cancel:       cancel,
		methods:      map[string]*DaemonMethod{},
		modes:        map[string]DaemonModeHandler{},
		sessions:     map[net.Conn]bool{},
		lastActivity: clock.Now(),
		activity:     NewMonitorValue[uint64](0),
	}
}

// Adds a control method (§5.8). A name taken already is refused, so two areas cannot shadow each other.
func (self *Daemon) RegisterMethod(method *DaemonMethod) error {
	if method == nil || method.Name == "" || method.Handler == nil {
		return fmt.Errorf("%w: a method needs a name and a handler", ErrDaemonRegistration)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.methods[method.Name]; ok {
		return fmt.Errorf("%w: method %s is registered", ErrDaemonRegistration, method.Name)
	}
	copied := *method
	self.methods[method.Name] = &copied
	return nil
}

// Adds the handler of a mode the daemon does not speak itself, mcp or git. control and hook are the daemon's own.
func (self *Daemon) RegisterMode(mode string, handler DaemonModeHandler) error {
	if (mode != DaemonModeMcp && mode != DaemonModeGit && mode != DaemonModeGitHook) || handler == nil {
		return fmt.Errorf("%w: only mcp, git and git-hook take a handler", ErrDaemonRegistration)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.modes[mode]; ok {
		return fmt.Errorf("%w: mode %s is registered", ErrDaemonRegistration, mode)
	}
	self.modes[mode] = handler
	return nil
}

// Replaces the peer check, for a test standing for another uid.
func (self *Daemon) setPeerCheck(check func(conn net.Conn) error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.peerAllowed = check
}

// The method registered under name.
func (self *Daemon) method(name string) (*DaemonMethod, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	method, ok := self.methods[name]
	return method, ok
}

// The handler registered for mode.
func (self *Daemon) mode(mode string) (DaemonModeHandler, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	handler, ok := self.modes[mode]
	return handler, ok
}

// Where the daemon listens.
func (self *Daemon) Addr() net.Addr {
	return self.listener.Addr()
}

// Serves sessions until ctx ends, Close, or an auto-spawned daemon's idle exit, then closes every session and
// releases the lock. Returns nil for an idle exit or a close.
func (self *Daemon) Run() error {
	defer self.shutdown()
	go self.idle()
	for {
		conn, err := self.listener.Accept()
		if err != nil {
			if self.ctx.Err() != nil {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return err
		}
		if !self.openSession(conn) {
			conn.Close()
			continue
		}
		go self.serve(conn)
	}
}

// Stops serving. Safe to call again.
func (self *Daemon) Close() {
	self.cancel()
	self.listener.Close()
}

// Closes the listener and every session, and releases the lock.
func (self *Daemon) shutdown() {
	self.cancel()
	self.listener.Close()
	conns := func() []net.Conn {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		conns := make([]net.Conn, 0, len(self.sessions))
		for conn := range self.sessions {
			conns = append(conns, conn)
		}
		return conns
	}()
	for _, conn := range conns {
		conn.Close()
	}
	sockets := func() *DaemonSockets {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.sockets
	}()
	if sockets != nil {
		sockets.close()
	}
	self.lock.Close()
}

// Notes a session, false once shut down.
func (self *Daemon) openSession(conn net.Conn) bool {
	opened := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.sessions[conn] = true
		self.lastActivity = self.clock.Now()
		return true
	}()
	if opened {
		self.touchActivity()
	}
	return opened
}

// Forgets a session.
func (self *Daemon) closeSession(conn net.Conn) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.sessions, conn)
		self.lastActivity = self.clock.Now()
	}()
	self.touchActivity()
}

// Notes a request, which holds off the idle exit.
func (self *Daemon) noteRequest() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.lastActivity = self.clock.Now()
	}()
	self.touchActivity()
}

// Wakes the idle loop to re-read the sessions and the last activity.
func (self *Daemon) touchActivity() {
	self.activity.Update(func(count uint64) uint64 { return count + 1 })
}

// The idle exit (§5.8): an auto-spawned daemon with IdleExitTimeout set closes once no session is open and none has
// made a request for that long, unless something keeps it busy (daemon_idle.go), which it asks again each timeout.
// Never for a unit-run daemon.
func (self *Daemon) idle() {
	timeout := self.settings.Local.IdleExitTimeout
	if !self.settings.AutoSpawned || timeout <= 0 {
		return
	}
	for {
		_, changed := self.activity.Get()
		wait, idle := self.idleWait()
		if idle && wait <= 0 {
			if self.busy() {
				wait = timeout
			} else {
				self.log.Infof("[daemon]idle for %s, exiting", timeout)
				self.Close()
				return
			}
		}
		if !idle {
			select {
			case <-self.ctx.Done():
				return
			case <-changed:
			}
			continue
		}
		select {
		case <-self.ctx.Done():
			return
		case <-changed:
		case <-self.clock.After(wait):
		}
	}
}

// One session: the peer check, the hello, then the mode's protocol.
func (self *Daemon) serve(conn net.Conn) {
	defer self.closeSession(conn)
	defer conn.Close()
	peerAllowed := func() func(conn net.Conn) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.peerAllowed
	}()
	if err := peerAllowed(conn); err != nil {
		self.log.Warningf("[daemon]refused a session: %s", err)
		return
	}
	reader := bufio.NewReaderSize(conn, self.settings.Local.SessionBufferByteCount)
	line, err := readDaemonLine(reader, self.settings.Local.HelloByteCount)
	if err != nil {
		return
	}
	hello, code, err := parseDaemonHello(line, self.settings.Version, self.settings.Local.HelloByteCount)
	if err == nil {
		hello.PeerPid = int64(daemonPeerPid(conn))
	}
	answer := &daemonHelloAnswer{UrLocal: daemonLocalProtocol, Version: self.settings.Version, Error: code}
	var handler DaemonModeHandler
	if err == nil && (hello.Mode == DaemonModeMcp || hello.Mode == DaemonModeGit || hello.Mode == DaemonModeGitHook) {
		var ok bool
		handler, ok = self.mode(hello.Mode)
		if !ok {
			answer.Error = DaemonHelloErrorMode
		}
	}
	if err == nil && hello.Mode == DaemonModeSocket {
		// the daemon's own, as control and hook are: its sockets live here
		handler = self.Sockets().serveSession
	}
	encoded, _ := json.Marshal(answer)
	if _, err := conn.Write(append(encoded, '\n')); err != nil || answer.Error != "" {
		if answer.Error != "" && self.log.V(1).Enabled() {
			self.log.Infof("[daemon]refused a hello: %s", answer.Error)
		}
		return
	}
	self.noteRequest()
	if handler != nil {
		stream := &daemonSessionStream{reader: reader, conn: conn}
		if err := handler(self.ctx, hello, stream); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[daemon]a %s session ended: %s", hello.Mode, err)
		}
		return
	}
	self.serveRpc(reader, conn, &daemonSession{hello: hello})
}

// control and hook: one JSON-RPC request a line, each answered before the next is read, each under the request
// timeout. A line past the request bound, or one that does not end, closes the session.
func (self *Daemon) serveRpc(reader *bufio.Reader, conn net.Conn, session *daemonSession) {
	writer := bufio.NewWriter(conn)
	for {
		line, err := readDaemonLine(reader, self.settings.Local.RequestByteCount)
		if err != nil {
			if errors.Is(err, errDaemonLineTooLong) {
				self.log.Warningf("[daemon]a request past %d bytes closed its session", self.settings.Local.RequestByteCount)
			}
			return
		}
		self.noteRequest()
		response := self.dispatch(line, session, self.runBounded)
		if response == nil {
			continue
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			return
		}
		if _, err := writer.Write(append(encoded, '\n')); err != nil {
			return
		}
		if err := writer.Flush(); err != nil {
			return
		}
	}
}

// Runs handler under SidecarLocalSettings.RequestTimeout on the daemon's clock, reporting whether it timed out. The
// handler's context ends at the timeout, and a handler that does not return by then is left to finish on its own.
func (self *Daemon) runBounded(handler func(ctx context.Context) (any, error)) (any, error, bool) {
	ctx, cancel := context.WithCancel(self.ctx)
	defer cancel()
	timedOut := make(chan struct{})
	stop := self.clock.AfterFunc(self.settings.Local.RequestTimeout, func() {
		close(timedOut)
		cancel()
	})
	defer stop()
	type outcome struct {
		result any
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := handler(ctx)
		done <- outcome{result: result, err: err}
	}()
	select {
	case finished := <-done:
		return finished.result, finished.err, false
	case <-timedOut:
		return nil, nil, true
	}
}
