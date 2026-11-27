//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's gateway (DESIGN-COMPUTE §8.4, §8.7; R-GW-4, D-GW-3, D-CORE-9, GW-M12-01): the listener a desktop's
// daemon, or an enclave's, serves the gateway's routes on, and the daemon's hold on its port. Phones run none (Q-GW-5):
// this file builds on the daemon's legs alone.
//
//	hold      it serves while the instance's gateway state names a port and a grant stands (gateway_state.go), from
//	          the daemon's start, its keychain locked or not, so no other user's process takes the port while a
//	          harness may call; Reload reads the state again after a grant is made or revoked and binds, rebinds or
//	          lets go
//	busy      Active answers whether a grant stands, which the daemon's busy rule reads (DaemonSettings.Busy), so a
//	          daemon holding a grant never idles out; a state that does not read reads as standing, the direction
//	          that keeps the port
//	unit      the listeners the daemon's unit hands over (launchd's Sockets, a systemd socket unit) are taken for
//	          their addresses (gateway_listener.go) and kept, unused, while nothing is served, since the unit holds the
//	          port through them
//	routes    every request passes the listener's guard first, Host, browser, body and concurrency
//	          (gateway_listener.go); /v1/ur/listener answers the proof (gateway_proof.go); every other route is a
//	          front's, registered through Handle and reached only with a grant's token (gateway_token.go)
//	key       gateway.key, a control method, gives a command a fresh proof key with the port and the addresses the
//	          daemon serves and those another process holds, the daemon's peer check admitting its own uid alone
//
// Safe for concurrent use: reloadLock orders reloads and the close, and is taken before stateLock, which guards what
// Status reads.

package sidecar

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
)

// The daemon methods of this file: a command asks a proof key by gateway.key (§8.4; a reading, since §8.4 names the key
// and not the method), and `ur status` reads gateway.status.
const (
	DaemonMethodGatewayKey    = "gateway.key"
	DaemonMethodGatewayStatus = "gateway.status"
)

var (
	// The gateway serves nothing now: no port, no grant, or no address bound.
	ErrGatewayNotServing = errors.New("the gateway is not serving")
	// The server has closed.
	ErrGatewayClosed = errors.New("the gateway has closed")
)

// What the gateway reads of the daemon: the networks it hosts, and how a call's network argument names one (§5.8).
// GatewayDaemonHosts gives a *Daemon's.
type GatewayHosts interface {
	GatewayNetworks() []GatewayHostedNetwork
	ResolveNetwork(hello *DaemonHello, network string) (Id, error)
}

// One hosted network as the gateway reads it.
type GatewayHostedNetwork struct {
	NetworkId Id
	Network   GatewayNetwork
}

// What the gateway reads of one network: its run files, its grants and its agents' ids. *Sidecar is one.
type GatewayNetwork interface {
	Runs() (*RunStore, error)
	GatewayGrants() (*GatewayGrantStore, error)
	ResolveAgentId(label string) (Id, error)
}

// A daemon's hosted Sidecars as the gateway's hosts.
func GatewayDaemonHosts(daemon *Daemon) GatewayHosts {
	return &gatewayDaemonHosts{daemon: daemon}
}

// GatewayHosts over a *Daemon.
type gatewayDaemonHosts struct {
	daemon *Daemon
}

// See GatewayHosts.
func (self *gatewayDaemonHosts) GatewayNetworks() []GatewayHostedNetwork {
	networks := []GatewayHostedNetwork{}
	for _, hosted := range self.daemon.Sidecars() {
		networks = append(networks, GatewayHostedNetwork{NetworkId: hosted.NetworkId, Network: hosted.Sidecar})
	}
	return networks
}

// See GatewayHosts.
func (self *gatewayDaemonHosts) ResolveNetwork(hello *DaemonHello, network string) (Id, error) {
	if hello == nil {
		hello = &DaemonHello{Mode: DaemonModeControl}
	}
	return self.daemon.ResolveNetwork(hello, network)
}

// What a GatewayServer runs on.
type GatewayServerArgs struct {
	// The instance's <state>, whose gateway/gateway.json holds the port and the hold.
	StateDirectory string
	// Nil is DefaultGatewaySettings.
	Settings *GatewaySettings
	// Listeners the daemon's unit handed over (cli's unit_*.go).
	Inherited []net.Listener
	// How the listener binds: net.Listen, unless a test stands one in.
	Listen func(network string, address string) (net.Listener, error)
	// Who holds an address the bind found in use, where the OS shows it.
	Holder func(address string) string
	// Nil is real time.
	Clock Clock
	// Nil is no logging.
	Log Logger
	// Where keys and tokens are drawn from: crypto/rand's reader when nil.
	Random io.Reader
	// The process table a run handle's liveness reads: the system's when nil.
	Processes ProcessTable
	// The server's default budgets for an agent (§16.4), CACL's view; nil until it lands, and until then a grant names
	// no budget of its own (gateway_grant.go).
	BudgetDefaults func(ctx context.Context, network GatewayNetwork, agentId Id) (*GatewayBudgetCaps, error)
	// Files kind 21 for a grant's raise (§16.3): nil is the network's compute client's RaiseBudget.
	RaiseBudget func(ctx context.Context, network GatewayNetwork, args *ComputeBudgetRaiseArgs) (*ComputeBudgetRaiseResult, error)
	// What a grant's model globs are held to (§16.4): the defaults when nil.
	ModelsKey *ModelsKeySettings
	Infer     *InferSettings
}

// What `ur status` reads of the gateway: the port, whether it holds it, and each address, never a key or a token.
type GatewayServerStatus struct {
	// 0 before an install chose one.
	Port int `json:"port,omitempty"`
	// A grant stands, so the port is held.
	Hold bool `json:"hold,omitempty"`
	// At least one address is served.
	Serving bool `json:"serving,omitempty"`
	// Each of the port's addresses while it is held.
	Addresses []GatewayAddressStatus `json:"addresses,omitempty"`
	// Why nothing is served.
	Reason string `json:"reason,omitempty"`
	// Listeners the unit handed over that were bound elsewhere, each closed.
	RefusedInherited int `json:"refused_inherited,omitempty"`
}

// The daemon's gateway: see the file header.
type GatewayServer struct {
	stateDirectory string
	settings       *GatewaySettings
	listen         func(network string, address string) (net.Listener, error)
	holder         func(address string) string
	clock          Clock
	log            Logger
	random         io.Reader
	proof          *GatewayListenerProof
	// the routes behind the guard; registration is safe while it serves
	mux            *http.ServeMux
	processes      ProcessTable
	budgetDefaults func(ctx context.Context, network GatewayNetwork, agentId Id) (*GatewayBudgetCaps, error)
	raiser         func(ctx context.Context, network GatewayNetwork, args *ComputeBudgetRaiseArgs) (*ComputeBudgetRaiseResult, error)
	modelsKey      *ModelsKeySettings
	infer          *InferSettings

	reloadLock sync.Mutex
	// one writer of the state file at a time, a make's or a revoke's, taken before reloadLock
	stateWriteLock sync.Mutex
	// one unbound call at a time makes a grant's run of unbound calls (gateway_bind.go)
	unboundLock sync.Mutex

	stateLock sync.Mutex
	// the state read last; nil where it did not read
	state *GatewayState
	// why the state did not read, "" where it did
	stateReason string
	listener    *GatewayListener
	server      *http.Server
	// closed once every Serve of the server has returned
	served chan struct{}
	// the unit's sockets, each kept as a file of its own, so a listener made from one closes without letting the unit's
	// port go, and the port can be served again once a grant stands again
	inheritedFiles []*os.File
	// the unit's listeners that could not be kept, each closed
	refusedInherited int
	closed           bool
	// the daemon's networks, set once it is built; nil serves no token
	hosts GatewayHosts
	// mcp's run index, set once the MCP server is built; nil binds no call (gateway_bind.go)
	binder GatewayRunBinder
}

// A server over args. It serves nothing until Start.
func NewGatewayServer(args *GatewayServerArgs) *GatewayServer {
	settings := args.Settings
	if settings == nil {
		settings = DefaultGatewaySettings()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	clock := clockOrReal(args.Clock)
	processes := args.Processes
	if processes == nil {
		processes = SystemProcessTable()
	}
	modelsKey := args.ModelsKey
	if modelsKey == nil {
		modelsKey = DefaultModelsKeySettings()
	}
	infer := args.Infer
	if infer == nil {
		infer = DefaultInferSettings()
	}
	self := &GatewayServer{
		stateDirectory: args.StateDirectory,
		settings:       settings,
		listen:         args.Listen,
		holder:         args.Holder,
		clock:          clock,
		log:            log,
		random:         args.Random,
		proof:          NewGatewayListenerProof(settings, clock, args.Random),
		mux:            http.NewServeMux(),
		processes:      processes,
		budgetDefaults: args.BudgetDefaults,
		raiser:         args.RaiseBudget,
		modelsKey:      modelsKey,
		infer:          infer,
	}
	for _, inherited := range args.Inherited {
		// a copy of the socket the server keeps, and from which each listener is made again
		tcpListener, ok := inherited.(*net.TCPListener)
		var file *os.File
		err := errors.New("not a TCP listener")
		if ok {
			file, err = tcpListener.File()
		}
		inherited.Close()
		if err != nil {
			self.refusedInherited += 1
			self.log.Warningf("[gateway]a listener the unit handed over is not kept: %s", err)
			continue
		}
		self.inheritedFiles = append(self.inheritedFiles, file)
	}
	self.mux.Handle(GatewayListenerPath, self.proof)
	return self
}

// A listener from each of the unit's sockets, each its own copy, to hand a GatewayListener.
func (self *GatewayServer) inheritedListeners() []net.Listener {
	files := func() []*os.File {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.Clone(self.inheritedFiles)
	}()
	listeners := []net.Listener{}
	for _, file := range files {
		listener, err := net.FileListener(file)
		if err != nil {
			self.log.Warningf("[gateway]a socket the unit handed over does not listen: %s", err)
			continue
		}
		listeners = append(listeners, listener)
	}
	return listeners
}

// Reads the state and serves it where it holds: see the file header. The answer is the status after.
func (self *GatewayServer) Start() GatewayServerStatus {
	return self.Reload()
}

// Reads the state again and serves what it says: the same port and hold, already served, change nothing; another
// port, or no hold, stops what is served first. The answer is the status after.
func (self *GatewayServer) Reload() GatewayServerStatus {
	self.reloadLock.Lock()
	defer self.reloadLock.Unlock()
	state, err := ReadGatewayState(self.stateDirectory, self.settings.StateFileByteCount)
	stateReason := ""
	if err != nil {
		// the error names the file's form alone, never a path's contents
		stateReason = fmt.Sprintf("the gateway's state does not read: %s", err)
		state = nil
	}
	var stopping *http.Server
	var stoppingServed chan struct{}
	var stoppingListener *GatewayListener
	keep := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return true
		}
		// a listener that serves nothing binds again, as another process may have let the port go since
		same := self.listener != nil && state.Holds() && self.listener.Port() == state.Port && 0 < len(self.listener.Listeners())
		self.state, self.stateReason = state, stateReason
		if same {
			return true
		}
		stopping, stoppingServed, stoppingListener = self.server, self.served, self.listener
		self.server, self.served, self.listener = nil, nil, nil
		return false
	}()
	if keep {
		return self.Status()
	}
	self.stop(stopping, stoppingServed, stoppingListener)
	if !state.Holds() {
		return self.Status()
	}
	listener := NewGatewayListener(&GatewayListenerArgs{
		Port:      state.Port,
		Inherited: self.inheritedListeners(),
		Listen:    self.listen,
		Holder:    self.holder,
	})
	listeners := listener.Listeners()
	if len(listeners) == 0 {
		self.log.Warningf("[gateway]port %d serves on no loopback address", state.Port)
	}
	server := &http.Server{
		Handler:           newGatewayGuard(self.settings, state.Port, self.mux),
		ReadHeaderTimeout: self.settings.ReadHeaderTimeout,
		IdleTimeout:       self.settings.IdleTimeout,
		MaxHeaderBytes:    self.settings.HeaderByteCount,
	}
	served := make(chan struct{})
	started := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.listener, self.server, self.served = listener, server, served
		return true
	}()
	if !started {
		listener.Close()
		return self.Status()
	}
	go func() {
		defer close(served)
		serves := sync.WaitGroup{}
		for _, each := range listeners {
			serves.Add(1)
			go func() {
				defer serves.Done()
				server.Serve(each)
			}()
		}
		serves.Wait()
	}()
	if self.log.V(1).Enabled() {
		self.log.Infof("[gateway]serving port %d on %d loopback addresses", state.Port, len(listeners))
	}
	return self.Status()
}

// Stops a server: requests in flight get ShutdownTimeout, then their connections close, its goroutines are joined, and
// its listeners close.
func (self *GatewayServer) stop(server *http.Server, served chan struct{}, listener *GatewayListener) {
	if server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), self.settings.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			server.Close()
		}
		<-served
	}
	if listener != nil {
		listener.Close()
	}
}

// Whether a grant stands, which the daemon's busy rule reads: true too where the state does not read, the direction
// that keeps the port. Never blocks on a reload.
func (self *GatewayServer) Active() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return false
	}
	if self.state == nil {
		return self.stateReason != ""
	}
	return self.state.Holds()
}

// The port, the hold and each address, never a key.
func (self *GatewayServer) Status() GatewayServerStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := GatewayServerStatus{Reason: self.stateReason, RefusedInherited: self.refusedInherited}
	if self.state != nil {
		status.Port, status.Hold = self.state.Port, self.state.Hold
	}
	if self.listener != nil {
		status.Addresses = self.listener.Statuses()
		status.RefusedInherited += self.listener.RefusedCount()
		for _, address := range status.Addresses {
			status.Serving = status.Serving || address.Serving
		}
	}
	switch {
	case self.closed:
		status.Reason = "the daemon is ending"
	case status.Reason != "":
	case status.Port == 0:
		status.Reason = "no port: ur install-harness <harness> --gateway chooses one"
	case !status.Hold:
		status.Reason = "no grant stands, so the port is not held"
	case !status.Serving:
		status.Reason = "no loopback address of the port could be bound"
	}
	return status
}

// A fresh proof key for one command's asks (§8.4), with the port, the addresses served and those another process
// holds. ErrGatewayNotServing where nothing is served.
func (self *GatewayServer) ListenerKey() (*GatewayListenerKey, error) {
	status := self.Status()
	if !status.Serving && status.Hold {
		// the port may have been let go since: bind again before refusing
		status = self.Reload()
	}
	if !status.Serving {
		return nil, fmt.Errorf("%w: %s", ErrGatewayNotServing, status.Reason)
	}
	keyId, key, err := self.proof.NewKey()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	reply := &GatewayListenerKey{KeyId: keyId, Key: base64.RawURLEncoding.EncodeToString(key), Port: status.Port}
	for _, address := range status.Addresses {
		if address.Serving {
			reply.Addresses = append(reply.Addresses, address.Address)
		}
		if address.InUse {
			reply.HeldElsewhere = append(reply.HeldElsewhere, address.Address)
		}
	}
	return reply, nil
}

// Sets the daemon's networks, which the daemon builds after the gateway.
func (self *GatewayServer) SetHosts(hosts GatewayHosts) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.hosts = hosts
}

// The daemon's networks, nil while none are set.
func (self *GatewayServer) gatewayHosts() GatewayHosts {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.hosts
}

// The control methods the gateway serves: gateway.key and gateway.status (§8.4); gateway.token, which mints for the
// caller the daemon reads from its socket's peer (gateway_token.go); and gateway.grants, which lists, makes and revokes
// (gateway_grant.go). None is a Confirm method: a grant above the agent's default waits on kind 21's approval instead.
func (self *GatewayServer) DaemonMethods() []*DaemonMethod {
	return []*DaemonMethod{
		{
			Name: DaemonMethodGatewayKey,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				return self.ListenerKey()
			},
		},
		{
			Name: DaemonMethodGatewayStatus,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				status := self.Status()
				return &status, nil
			},
		},
		{
			Name: DaemonMethodGatewayToken,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &GatewayTokenParams{}
				if err := decodeGatewayParams(call, params); err != nil {
					return nil, fmt.Errorf("%w: gateway.token's params do not read", ErrGatewayGrantInvalid)
				}
				return self.MintToken(ctx, call.Hello, params)
			},
		},
		{
			Name: DaemonMethodGatewayGrants,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &GatewayGrantsParams{}
				if err := decodeGatewayParams(call, params); err != nil {
					return nil, fmt.Errorf("%w: gateway.grants' params do not read", ErrGatewayGrantInvalid)
				}
				switch params.Action {
				case "", GatewayGrantsActionList:
					return self.ListGrants(params.Network, call.Hello)
				case GatewayGrantsActionMake:
					return self.MakeGrant(ctx, call.Hello, params)
				case GatewayGrantsActionRevoke:
					if params.GrantId == nil {
						return nil, fmt.Errorf("%w: a revoke names its grant", ErrGatewayGrantInvalid)
					}
					return self.RevokeGrant(ctx, *params.GrantId)
				}
				return nil, fmt.Errorf("%w: no action %q", ErrGatewayGrantInvalid, params.Action)
			},
		},
	}
}

// Stops serving for good: requests in flight get ShutdownTimeout, and the server's copies of the unit's sockets close
// too, the unit keeping its own.
func (self *GatewayServer) Close() {
	self.reloadLock.Lock()
	defer self.reloadLock.Unlock()
	server, served, listener, files := func() (*http.Server, chan struct{}, *GatewayListener, []*os.File) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		server, served, listener, files := self.server, self.served, self.listener, self.inheritedFiles
		self.server, self.served, self.listener, self.inheritedFiles = nil, nil, nil, nil
		return server, served, listener, files
	}()
	self.stop(server, served, listener)
	for _, file := range files {
		file.Close()
	}
}
