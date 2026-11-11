//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's sockets (§9.9, §5.8; SOCK-M5-14): what `ur socket` and §16.5's socket tools run on. Sockets live in the
// daemon, which stays up while any does (§5.8): a listen forward, a dial forward or a live share (socket_share.go)
// keeps an auto-spawned daemon from idling out (Daemon.busy).
//
//   - A listen forward (ur socket listen <addr> [<ip>:]<port>, the socket_listen tool) is a Sidecar.Listen whose
//     accepted conns each splice to a local TCP target, 127.0.0.1 unless the person names an address. While the
//     target refuses, the listener sets serving false, keeping its lease and taking no tickets (§9.5), and dials it
//     again every TargetProbeInterval until it answers. An outward name (tls/, smtp/) passes §5.4's gate inside
//     Listen first, which may answer pending; the reply then names the approval, for ur approve <id>.
//   - A dial forward (ur socket dial <addr> --listen=[<ip>:]<port>) is a DaemonLocalListen of the forward service, on
//     every interface unless <ip> or the daemon's --listen narrows it, raw bytes with no TLS-only rule (D-TRUST-8;
//     owner decisions 84, 130), each local conn spliced to a fresh Sidecar.Dial. ur status lists it, LAN-exposed when
//     it is (daemon_local.go).
//   - The socket hello mode (ur socket dial <addr> with no --listen, for ssh -o ProxyCommand; ur share get) dials once
//     and writes one status line, {"status":"ok"} or the code of §9.9's error the dial ended with, then splices the
//     session to the stream. Each direction's end closes that half alone, so a FIN reaches the far side as io.EOF.
//   - ur socket ls pages GET /socket/list for the network and opens each seal with the network's K_sock here
//     (OpenSocketName), so names are unsealed on this device alone, and a seal that does not open is dropped, never
//     shown raw (D-SOCK-13).
//   - ur socket drain <addr> drains each forward on the address: a listen forward's listener drains as §9.9's Drain
//     does, in the background since it may take ListenDrainTimeout, and a dial forward stops taking local conns and
//     ends with its spliced streams, the rest closed at the same timeout.
//
// A forward is keyed by its network and its canonical name; the daemon holds one listen forward a name, as §9.5 holds
// one registration a client and name. What runs on a network goes through daemonSocketBackend, its Sidecar's sockets
// component in production, so a test stands a fake in. Nothing here logs an address, a name or a target (I-13), and no
// reply holds a key, a seal or a token path. A forward's goroutines end with its listener or the daemon's shutdown.
// Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The control methods ur socket calls (§5.8), each a reading: §9.9 names the commands and not the methods.
const (
	// ur socket listen
	DaemonMethodSocketListen = "socket.listen"
	// ur socket dial --listen
	DaemonMethodSocketDial = "socket.dial"
	// ur socket ls
	DaemonMethodSocketList = "socket.list"
	// ur socket
	DaemonMethodSocketLocal = "socket.local"
	// ur socket drain
	DaemonMethodSocketDrain = "socket.drain"
)

// A daemon socket's kind, as its status names it.
const (
	DaemonSocketKindListen = "listen"
	DaemonSocketKindDial   = "dial"
)

// A socket session's status line beyond §9.9's error codes (SocketErrorCode, and reset).
const (
	DaemonSocketSessionOk = "ok"
	// The address names a network this daemon does not host.
	DaemonSocketSessionNoNetwork = "no_network"
	// The dial failed for a reason §9.9 has no code for, a malformed address among them.
	DaemonSocketSessionFailed = "failed"
	// §9.9's ErrSocketReset, which a dial answers when its stream reset before it was handed back.
	DaemonSocketSessionReset = "reset"
)

var (
	// The daemon already holds a listen forward on the name.
	ErrDaemonSocketListening = errors.New("this daemon already listens on that name")
	// A target or a --listen that is no [<ip>:]<port>.
	ErrDaemonSocketTarget = errors.New("a local address is [<ip>:]<port>")
	// The daemon holds no socket on the name.
	ErrDaemonSocketNone = errors.New("this daemon holds no socket on that name")
)

// socket.listen's params: what ur socket listen sends.
type DaemonSocketListenParams struct {
	// The call's network: the address's <net> when it names one, else empty for .ur's or the only one (§5.8).
	Network string `json:"network,omitempty"`
	// [<net>:]<name> (§9.4).
	Address string `json:"address"`
	// The local target, [<ip>:]<port>: 127.0.0.1 unless an ip is given.
	Target string `json:"target"`
}

// One socket the daemon holds, as ur socket, ur status and socket_status show it: ids, the name and local addresses,
// nothing secret.
type DaemonSocketStatus struct {
	NetworkId Id     `json:"network_id"`
	Kind      string `json:"kind"`
	// The canonical name, which only this device's own person and agents read.
	Name string `json:"name"`
	// A listen forward's local target, host:port.
	Target string `json:"target,omitempty"`
	// A dial forward's bound addresses, host:port each, and whether the LAN can reach them (D-TRUST-8).
	LocalAddresses []string `json:"local_addresses,omitempty"`
	LanExposed     bool     `json:"lan_exposed,omitempty"`
	// A listen forward takes tickets: its target answered the last dial (§9.5).
	Serving bool `json:"serving"`
	// Drain has begun: no new tickets, or for a dial forward no new local conns.
	Draining bool `json:"draining"`
	// The streams in flight.
	Inflight int `json:"inflight"`
}

// socket.listen's reply: the forward, or the approval its outward name waits on.
type DaemonSocketListenReply struct {
	Status *DaemonSocketStatus `json:"status,omitempty"`
	// §5.4's gate is waiting on a person for this tls/ or smtp/ listen: ur approve <id> on an approval-capable device
	// (§16.6), then the listen again.
	ApprovalId *Id `json:"approval_id,omitempty"`
}

// socket.dial's params: what ur socket dial --listen sends.
type DaemonSocketDialParams struct {
	Network string `json:"network,omitempty"`
	// [<net>:]<name> (§9.4).
	Address string `json:"address"`
	// [<ip>:]<port> to listen on: every interface unless an ip is given (D-TRUST-8); port 0 lets the OS choose.
	Listen string `json:"listen"`
}

// socket.list's params: the network to list, empty for .ur's or the only one.
type DaemonSocketListParams struct {
	Network string `json:"network,omitempty"`
}

// One name of a network's listing, unsealed on this device.
type DaemonSocketName struct {
	Name string `json:"name"`
	// This daemon holds a listen forward on it.
	Local bool `json:"local,omitempty"`
}

// socket.list's reply: the network's names, edge names as they are and blinded ones as their seals opened here.
type DaemonSocketListReply struct {
	Names []*DaemonSocketName `json:"names"`
	// Seals this device could not open, dropped and never shown (D-SOCK-13): a seal under another key, one moved to
	// another name, or every seal while no K_sock ring is installed.
	DroppedCount int `json:"dropped_count"`
	// Every page was read. False when a page was refused, Error saying how, or ListPageMaxCount pages were read.
	Complete bool         `json:"complete"`
	Error    *SocketError `json:"error,omitempty"`
}

// socket.local's reply: every socket the daemon holds, on every hosted network, by network then name.
type DaemonSocketLocalReply struct {
	Sockets []*DaemonSocketStatus `json:"sockets"`
}

// socket.drain's params.
type DaemonSocketDrainParams struct {
	Network string `json:"network,omitempty"`
	Address string `json:"address"`
}

// socket.drain's reply: how many forwards on the address began to drain.
type DaemonSocketDrainReply struct {
	DrainedCount int `json:"drained_count"`
}

// The line a socket session's daemon writes once its dial ends, before any byte of the stream.
type DaemonSocketSessionAnswer struct {
	// DaemonSocketSessionOk, or a SocketErrorCode, reset, no_network or failed.
	Status string `json:"status"`
	// How long to wait, for the codes §9.9 gives one.
	RetryAfterMs uint32 `json:"retry_after_ms,omitempty"`
}

// What one hosted network's daemon sockets run on: its Sidecar's sockets component (sidecarSocketBackend), or a
// test's. Safe for concurrent use.
type daemonSocketBackend interface {
	// Sidecar.Listen's registration on address; share lets share/ through, for ur share add's exclusive listen.
	listen(ctx context.Context, address *SocketAddress, settings *SocketListenSettings, share bool) (daemonSocketListener, error)
	// Sidecar.Dial's stream to address. A non-nil listenerSidecarId is ur share get's: share/ is let through, and a
	// listener whose verified Hello names another sidecar is refused before OPEN (§9.9).
	dial(ctx context.Context, address *SocketAddress, listenerSidecarId *Id) (*SocketConn, error)
	// One page of GET /socket/list from cursor.
	listPage(ctx context.Context, cursor string) (*SocketListResult, error)
	// The K_sock ring of the network's verified config head, nil while none is installed.
	keyRing() *SocketKeyRing
	// The network's 10-character label, "" while none is set.
	label() string
	// This sidecar's id, nil before enrollment.
	sidecarId() *Id
	// The network's sealed local state (§5.9), where shares keep their records.
	localStore() SidecarStore
	// The network's socket settings (SidecarSettings.Sockets).
	settings() *SidecarSocketSettings
}

// A listener as the daemon's sockets hold it: *SocketListener.
type daemonSocketListener interface {
	AcceptSocket(ctx context.Context) (*SocketConn, error)
	SetServing(serving bool)
	Drain(ctx context.Context) error
	Close() error
	inflightCount() int
}

// The production backend: a hosted Sidecar and its sockets component, which answer unavailable until the daemon's
// composition adds the component and its host installs labels, a K_sock ring and a policy (socket_component.go).
type sidecarSocketBackend struct {
	sidecar *Sidecar
}

// The Sidecar's sockets component, or unavailable.
func (self *sidecarSocketBackend) component() (*SocketComponent, error) {
	component := self.sidecar.socketComponent()
	if component == nil {
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	return component, nil
}

// See daemonSocketBackend: the component's listen, share/ let through for a share.
func (self *sidecarSocketBackend) listen(ctx context.Context, address *SocketAddress, settings *SocketListenSettings, share bool) (daemonSocketListener, error) {
	component, err := self.component()
	if err != nil {
		return nil, err
	}
	return component.listen(ctx, address, settings, share)
}

// See daemonSocketBackend: the component's dial, or its share dial holding the listener's sidecar.
func (self *sidecarSocketBackend) dial(ctx context.Context, address *SocketAddress, listenerSidecarId *Id) (*SocketConn, error) {
	component, err := self.component()
	if err != nil {
		return nil, err
	}
	if listenerSidecarId != nil {
		return component.dialShare(ctx, address, *listenerSidecarId)
	}
	return component.dial(ctx, address, nil, false)
}

// See daemonSocketBackend: GET /socket/list on the attached generation's token, unavailable between generations.
func (self *sidecarSocketBackend) listPage(ctx context.Context, cursor string) (*SocketListResult, error) {
	component, err := self.component()
	if err != nil {
		return nil, err
	}
	generation, _, _ := component.current()
	if generation == nil || generation.sidecarApi == nil {
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	return generation.sidecarApi.SocketList(ctx, cursor)
}

// See daemonSocketBackend.
func (self *sidecarSocketBackend) keyRing() *SocketKeyRing {
	component, err := self.component()
	if err != nil {
		return nil
	}
	return component.currentKeyRing()
}

// See daemonSocketBackend.
func (self *sidecarSocketBackend) label() string {
	component, err := self.component()
	if err != nil {
		return ""
	}
	_, _, labels := component.current()
	if labels == nil {
		return ""
	}
	return labels.Label
}

// See daemonSocketBackend.
func (self *sidecarSocketBackend) sidecarId() *Id {
	identity := self.sidecar.Identity()
	if identity == nil {
		return nil
	}
	return &identity.SidecarId
}

// See daemonSocketBackend.
func (self *sidecarSocketBackend) localStore() SidecarStore {
	return self.sidecar.LocalStore()
}

// See daemonSocketBackend.
func (self *sidecarSocketBackend) settings() *SidecarSocketSettings {
	return self.sidecar.settings.Sockets
}

// The newest K_sock ring the registrar holds, nil before one is set.
func (self *SocketComponent) currentKeyRing() *SocketKeyRing {
	self.registrar.stateLock.Lock()
	defer self.registrar.stateLock.Unlock()
	return self.registrar.state.ring
}

// The daemon's sockets: every forward it holds, by network, and each network's shares (socket_share.go).
type DaemonSockets struct {
	daemon *Daemon
	clock  Clock
	log    Logger
	// ends with the daemon, or at close
	ctx    context.Context
	cancel context.CancelFunc
	// the backend of a hosted network: its Sidecar's, unless a test stands another in
	backends func(networkId Id) (daemonSocketBackend, error)
	// what a share reads an admitted conn's dialer by: nil is socketConnDialerSidecarId, the Hello's, and a test stands
	// another in before any share starts
	shareDialerSidecarId func(conn *SocketConn) (Id, bool)

	stateLock sync.Mutex
	// each network's listen forwards, by canonical name
	networkIdListens map[Id]map[string]*daemonSocketListen
	// each dial forward
	dials map[*daemonSocketDial]bool
	// each network's shares, made on first use
	networkIdShares map[Id]*socketShares
	closed          bool
}

// The daemon's sockets, made on first use: the socket mode, `ur socket`'s and `ur share`'s methods and §16.5's tools
// all reach this one value.
func (self *Daemon) Sockets() *DaemonSockets {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.sockets == nil {
		ctx, cancel := context.WithCancel(self.ctx)
		sockets := &DaemonSockets{
			daemon:           self,
			clock:            self.clock,
			log:              self.log,
			ctx:              ctx,
			cancel:           cancel,
			networkIdListens: map[Id]map[string]*daemonSocketListen{},
			dials:            map[*daemonSocketDial]bool{},
			networkIdShares:  map[Id]*socketShares{},
		}
		sockets.backends = sockets.sidecarBackend
		self.sockets = sockets
	}
	return self.sockets
}

// Whether a forward or a live share keeps the daemon up (§5.8).
func (self *Daemon) socketsActive() bool {
	sockets := func() *DaemonSockets {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.sockets
	}()
	return sockets != nil && sockets.active()
}

// A hosted network's Sidecar as a backend.
func (self *DaemonSockets) sidecarBackend(networkId Id) (daemonSocketBackend, error) {
	hosted, ok := self.daemon.SidecarForNetwork(networkId)
	if !ok {
		return nil, &DaemonNetworkError{Reason: "unknown", Networks: self.daemon.hostedNetworkNames()}
	}
	return &sidecarSocketBackend{sidecar: hosted}, nil
}

// Whether any forward or live share is held.
func (self *DaemonSockets) active() bool {
	forwarding, shares := func() (bool, []*socketShares) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		forwarding := 0 < len(self.dials)
		for _, listens := range self.networkIdListens {
			forwarding = forwarding || 0 < len(listens)
		}
		shares := make([]*socketShares, 0, len(self.networkIdShares))
		for _, networkShares := range self.networkIdShares {
			shares = append(shares, networkShares)
		}
		return forwarding, shares
	}()
	if forwarding {
		return true
	}
	for _, networkShares := range shares {
		if 0 < networkShares.liveCount() {
			return true
		}
	}
	return false
}

// Ends every forward and share server, at the daemon's shutdown. Records stay for the next daemon.
func (self *DaemonSockets) close() {
	listens, dials, shares := func() ([]*daemonSocketListen, []*daemonSocketDial, []*socketShares) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		listens := []*daemonSocketListen{}
		for _, networkListens := range self.networkIdListens {
			for _, listen := range networkListens {
				listens = append(listens, listen)
			}
		}
		dials := make([]*daemonSocketDial, 0, len(self.dials))
		for dial := range self.dials {
			dials = append(dials, dial)
		}
		shares := make([]*socketShares, 0, len(self.networkIdShares))
		for _, networkShares := range self.networkIdShares {
			shares = append(shares, networkShares)
		}
		return listens, dials, shares
	}()
	self.cancel()
	for _, listen := range listens {
		listen.listener.Close()
	}
	for _, dial := range dials {
		dial.local.Close()
	}
	for _, networkShares := range shares {
		networkShares.stop()
	}
}

// [<ip>:]<port> as an IP, "" when none is given, and a port from 0 to 65535. An IPv6 address with a port takes
// brackets, as net.JoinHostPort writes it.
func parseDaemonSocketHostPort(text string) (string, int, error) {
	host := ""
	portText := text
	if strings.Contains(text, ":") {
		hostText, splitPort, err := net.SplitHostPort(text)
		if err != nil {
			return "", 0, ErrDaemonSocketTarget
		}
		address, err := netip.ParseAddr(hostText)
		if err != nil || address.Zone() != "" {
			return "", 0, ErrDaemonSocketTarget
		}
		host = address.Unmap().String()
		portText = splitPort
	}
	if portText == "" || strings.Trim(portText, "0123456789") != "" || 5 < len(portText) {
		return "", 0, ErrDaemonSocketTarget
	}
	port, err := strconv.Atoi(portText)
	if err != nil || 65535 < port {
		return "", 0, ErrDaemonSocketTarget
	}
	return host, port, nil
}

// The code a socket session's status line names for err, and its wait.
func daemonSocketErrorStatus(err error) (string, uint32) {
	retryAfterMs := uint32(0)
	var codeErr *SocketCodeError
	if errors.As(err, &codeErr) && 0 < codeErr.RetryAfter {
		retryAfterMs = uint32(codeErr.RetryAfter.Milliseconds())
	}
	switch {
	case errors.Is(err, ErrSocketNoListener):
		return string(SocketErrorCodeNoListener), retryAfterMs
	case errors.Is(err, ErrSocketBusy):
		return string(SocketErrorCodeBusy), retryAfterMs
	case errors.Is(err, ErrSocketDenied):
		return string(SocketErrorCodeDenied), 0
	case errors.Is(err, ErrSocketQuota):
		return string(SocketErrorCodeQuota), retryAfterMs
	case errors.Is(err, ErrSocketUnavailable):
		return string(SocketErrorCodeUnavailable), retryAfterMs
	case errors.Is(err, ErrSocketReset):
		return DaemonSocketSessionReset, 0
	}
	var networkErr *DaemonNetworkError
	if errors.As(err, &networkErr) {
		return DaemonSocketSessionNoNetwork, 0
	}
	return DaemonSocketSessionFailed, 0
}

// The error a socket session's status line stands for, as a client reads it: §9.9's value, or a failure that names the
// code. Nil for ok.
func DaemonSocketSessionError(answer *DaemonSocketSessionAnswer) error {
	if answer == nil {
		return errors.New("no socket status")
	}
	codeErr := &SocketCodeError{RetryAfter: time.Duration(answer.RetryAfterMs) * time.Millisecond}
	switch answer.Status {
	case DaemonSocketSessionOk:
		return nil
	case string(SocketErrorCodeNoListener):
		codeErr.Err = ErrSocketNoListener
	case string(SocketErrorCodeBusy):
		codeErr.Err = ErrSocketBusy
	case string(SocketErrorCodeDenied):
		codeErr.Err = ErrSocketDenied
	case string(SocketErrorCodeQuota):
		codeErr.Err = ErrSocketQuota
	case string(SocketErrorCodeUnavailable):
		codeErr.Err = ErrSocketUnavailable
	case DaemonSocketSessionReset:
		codeErr.Err = ErrSocketReset
	case DaemonSocketSessionNoNetwork:
		return errors.New("the daemon hosts no network by that name")
	default:
		return errors.New("the dial failed")
	}
	return codeErr
}

// The backend of networkId, refusing once closed.
func (self *DaemonSockets) backend(networkId Id) (daemonSocketBackend, error) {
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.closed
	}()
	if closed {
		return nil, net.ErrClosed
	}
	return self.backends(networkId)
}

// The hosted network an address with a <net> names: through §12's table as a call's network argument resolves, else
// the hosted network whose own label it is, which a daemon with no table still knows from its sockets.
func (self *DaemonSockets) labelNetwork(label string) (Id, error) {
	networkId, err := self.daemon.resolveNetworkName(label, false, false)
	if err == nil {
		return networkId, nil
	}
	for _, network := range self.daemon.Sidecars() {
		backend, backendErr := self.backends(network.NetworkId)
		if backendErr == nil && backend.label() == label {
			return network.NetworkId, nil
		}
	}
	return Id{}, err
}

// The network a forward or a session acts on: the address's <net>, else the call's, as §5.8 resolves it.
func (self *DaemonSockets) addressNetwork(address *SocketAddress, callNetworkId Id) (Id, error) {
	if address.NetworkLabel == "" {
		return callNetworkId, nil
	}
	networkId, err := self.labelNetwork(address.NetworkLabel)
	if err != nil {
		return Id{}, err
	}
	if networkId != callNetworkId {
		// the call's own network argument named another network than the address's
		return Id{}, &DaemonNetworkError{Reason: "unknown", Networks: self.daemon.hostedNetworkNames()}
	}
	return networkId, nil
}

// A listen forward on address to target (ur socket listen, socket_listen): see the file header. A pending §5.4 gate
// answers the approval and holds nothing.
func (self *DaemonSockets) Listen(ctx context.Context, networkId Id, addressText string, targetText string) (*DaemonSocketListenReply, error) {
	address, err := ParseSocketAddress(addressText)
	if err != nil {
		return nil, err
	}
	networkId, err = self.addressNetwork(address, networkId)
	if err != nil {
		return nil, err
	}
	host, port, err := parseDaemonSocketHostPort(targetText)
	if err != nil || port == 0 {
		return nil, ErrDaemonSocketTarget
	}
	if host == "" {
		host = "127.0.0.1"
	}
	backend, err := self.backend(networkId)
	if err != nil {
		return nil, err
	}
	name := address.Name
	taken := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		_, ok := self.networkIdListens[networkId][name]
		return ok
	}()
	if taken {
		return nil, ErrDaemonSocketListening
	}
	listener, err := backend.listen(ctx, address, &SocketListenSettings{}, false)
	if err != nil {
		var pending *ApprovalPendingError
		if errors.As(err, &pending) {
			approvalId := pending.ApprovalId
			return &DaemonSocketListenReply{ApprovalId: &approvalId}, nil
		}
		return nil, err
	}
	listenCtx, cancel := context.WithCancel(self.ctx)
	listen := &daemonSocketListen{
		sockets:   self,
		networkId: networkId,
		name:      name,
		target:    net.JoinHostPort(host, strconv.Itoa(port)),
		settings:  backend.settings(),
		listener:  listener,
		ctx:       listenCtx,
		cancel:    cancel,
		serving:   true,
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		if _, ok := self.networkIdListens[networkId][name]; ok {
			return false
		}
		if self.networkIdListens[networkId] == nil {
			self.networkIdListens[networkId] = map[string]*daemonSocketListen{}
		}
		self.networkIdListens[networkId][name] = listen
		return true
	}()
	if !kept {
		cancel()
		listener.Close()
		return nil, ErrDaemonSocketListening
	}
	// a target that refuses now takes no tickets until it answers (§9.9)
	if conn, err := listen.dialTarget(); err != nil {
		listen.refused()
	} else {
		conn.Close()
	}
	go listen.run()
	return &DaemonSocketListenReply{Status: listen.status()}, nil
}

// A dial forward on listenText to address (ur socket dial --listen): see the file header.
func (self *DaemonSockets) Dial(ctx context.Context, networkId Id, addressText string, listenText string) (*DaemonSocketStatus, error) {
	address, err := ParseSocketAddress(addressText)
	if err != nil {
		return nil, err
	}
	networkId, err = self.addressNetwork(address, networkId)
	if err != nil {
		return nil, err
	}
	host, port, err := parseDaemonSocketHostPort(listenText)
	if err != nil {
		return nil, err
	}
	backend, err := self.backend(networkId)
	if err != nil {
		return nil, err
	}
	listenArgs := &DaemonLocalListenArgs{Service: DaemonLocalForward, Port: port}
	if host != "" {
		listenArgs.Listen = []string{host}
	}
	local, err := self.daemon.LocalListen(listenArgs)
	if err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithCancel(self.ctx)
	dial := &daemonSocketDial{
		sockets:     self,
		networkId:   networkId,
		name:        address.Name,
		address:     address,
		backend:     backend,
		settings:    backend.settings(),
		local:       local,
		ctx:         dialCtx,
		cancel:      cancel,
		conns:       map[*daemonSocketDialConn]bool{},
		connsChange: make(chan struct{}),
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.dials[dial] = true
		return true
	}()
	if !kept {
		cancel()
		local.Close()
		return nil, net.ErrClosed
	}
	go dial.run()
	return dial.status(), nil
}

// The status of the listen forward this daemon holds on name in networkId, false for none (socket_status).
func (self *DaemonSockets) Status(networkId Id, name string) (*DaemonSocketStatus, bool) {
	canonical, _, err := ParseSocketName(name)
	if err != nil {
		return nil, false
	}
	listen := func() *daemonSocketListen {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.networkIdListens[networkId][canonical]
	}()
	if listen == nil {
		return nil, false
	}
	return listen.status(), true
}

// Closes the listen forward on name at once (socket_unlisten): the registration leaves the set, and spliced streams
// already accepted stay (§9.9's Close). False when there was none.
func (self *DaemonSockets) Unlisten(networkId Id, name string) bool {
	canonical, _, err := ParseSocketName(name)
	if err != nil {
		return false
	}
	listen := func() *daemonSocketListen {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		listen := self.networkIdListens[networkId][canonical]
		if listen != nil {
			delete(self.networkIdListens[networkId], canonical)
		}
		return listen
	}()
	if listen == nil {
		return false
	}
	listen.listener.Close()
	return true
}

// Drains every forward on address in networkId (ur socket drain): each listen forward as §9.9's Drain, in the
// background, and each dial forward by its local listener's close and its spliced streams' end. The count is how
// many began to.
func (self *DaemonSockets) Drain(networkId Id, addressText string) (int, error) {
	address, err := ParseSocketAddress(addressText)
	if err != nil {
		return 0, err
	}
	networkId, err = self.addressNetwork(address, networkId)
	if err != nil {
		return 0, err
	}
	listen, dials := func() (*daemonSocketListen, []*daemonSocketDial) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		dials := []*daemonSocketDial{}
		for dial := range self.dials {
			if dial.networkId == networkId && dial.name == address.Name {
				dials = append(dials, dial)
			}
		}
		return self.networkIdListens[networkId][address.Name], dials
	}()
	count := 0
	if listen != nil && listen.drain() {
		count += 1
	}
	for _, dial := range dials {
		if dial.drain() {
			count += 1
		}
	}
	if count == 0 {
		return 0, ErrDaemonSocketNone
	}
	return count, nil
}

// Every socket the daemon holds, by network, kind and name (ur socket).
func (self *DaemonSockets) Local() []*DaemonSocketStatus {
	listens, dials := func() ([]*daemonSocketListen, []*daemonSocketDial) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		listens := []*daemonSocketListen{}
		for _, networkListens := range self.networkIdListens {
			for _, listen := range networkListens {
				listens = append(listens, listen)
			}
		}
		dials := make([]*daemonSocketDial, 0, len(self.dials))
		for dial := range self.dials {
			dials = append(dials, dial)
		}
		return listens, dials
	}()
	statuses := make([]*DaemonSocketStatus, 0, len(listens)+len(dials))
	for _, listen := range listens {
		statuses = append(statuses, listen.status())
	}
	for _, dial := range dials {
		statuses = append(statuses, dial.status())
	}
	slices.SortFunc(statuses, func(a *DaemonSocketStatus, b *DaemonSocketStatus) int {
		if order := a.NetworkId.Cmp(b.NetworkId); order != 0 {
			return order
		}
		if a.Kind != b.Kind {
			return strings.Compare(a.Kind, b.Kind)
		}
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(strings.Join(a.LocalAddresses, ","), strings.Join(b.LocalAddresses, ","))
	})
	return statuses
}

// One name of a listing as this device reads it: an edge name in the clear as it is, a blinded one only as its seal
// opens under ring and re-derives its token path, else false (D-SOCK-13).
func openDaemonSocketName(entry *SocketListName, ring *SocketKeyRing) (string, bool) {
	if entry.Name != "" {
		name, namespace, err := ParseSocketName(entry.Name)
		if err != nil || namespace.blinded() || namespace == SocketNamespaceReserved || len(entry.NameToken) != 0 {
			return "", false
		}
		return name, true
	}
	if ring == nil {
		return "", false
	}
	return OpenSocketName(ring.Current(), ring.Previous(), entry.NameToken, entry.SealedName)
}

// The network's names (ur socket ls, socket_list): GET /socket/list's pages, at most ListPageMaxCount, each seal opened
// here, a name on two pages listed once, and each marked when this daemon listens on it.
func (self *DaemonSockets) ListNames(ctx context.Context, networkId Id) (*DaemonSocketListReply, error) {
	backend, err := self.backend(networkId)
	if err != nil {
		return nil, err
	}
	ring := backend.keyRing()
	pageMaxCount := backend.settings().Forward.ListPageMaxCount
	reply := &DaemonSocketListReply{Names: []*DaemonSocketName{}}
	seen := map[string]bool{}
	cursor := ""
	for pageIndex := 0; pageIndex < pageMaxCount; pageIndex += 1 {
		page, err := backend.listPage(ctx, cursor)
		if err != nil {
			if pageIndex == 0 {
				return nil, err
			}
			reply.Error = &SocketError{Code: SocketErrorCodeUnavailable}
			break
		}
		if page.Error != nil {
			if pageIndex == 0 {
				return nil, socketFindError(page.Error)
			}
			reply.Error = page.Error
			break
		}
		for _, entry := range page.Names {
			if entry == nil {
				continue
			}
			name, ok := openDaemonSocketName(entry, ring)
			if !ok {
				reply.DroppedCount += 1
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			reply.Names = append(reply.Names, &DaemonSocketName{Name: name})
		}
		if page.NextCursor == "" {
			reply.Complete = true
			break
		}
		cursor = page.NextCursor
	}
	listens := func() map[string]bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		listens := map[string]bool{}
		for name := range self.networkIdListens[networkId] {
			listens[name] = true
		}
		return listens
	}()
	for _, name := range reply.Names {
		name.Local = listens[name.Name]
	}
	slices.SortFunc(reply.Names, func(a *DaemonSocketName, b *DaemonSocketName) int { return strings.Compare(a.Name, b.Name) })
	return reply, nil
}

// The socket hello mode (daemon_hello.go): one dial, its status line, then the session spliced to the stream. Returns
// once both directions end. A refused dial is the session's answer, not the daemon's failure, so it returns nil.
func (self *DaemonSockets) serveSession(ctx context.Context, hello *DaemonHello, stream io.ReadWriter) error {
	answer := func(status string, retryAfterMs uint32) error {
		encoded, err := json.Marshal(&DaemonSocketSessionAnswer{Status: status, RetryAfterMs: retryAfterMs})
		if err != nil {
			return err
		}
		_, err = stream.Write(append(encoded, '\n'))
		return err
	}
	refuse := func(err error) error {
		status, retryAfterMs := daemonSocketErrorStatus(err)
		answer(status, retryAfterMs)
		return nil
	}
	address, err := ParseSocketAddress(hello.Socket)
	if err != nil {
		return refuse(err)
	}
	var networkId Id
	if address.NetworkLabel != "" {
		networkId, err = self.labelNetwork(address.NetworkLabel)
	} else {
		networkId, err = self.daemon.resolveSessionNetwork(&daemonSession{hello: hello}, "")
	}
	if err != nil {
		return refuse(err)
	}
	backend, err := self.backend(networkId)
	if err != nil {
		return refuse(err)
	}
	conn, err := backend.dial(ctx, address, hello.SocketSidecarId)
	if err != nil {
		return refuse(err)
	}
	if err := answer(DaemonSocketSessionOk, 0); err != nil {
		conn.Abort()
		return err
	}
	stop := context.AfterFunc(ctx, func() { conn.Abort() })
	defer stop()
	daemonSocketSplice(&daemonSocketSessionEnd{stream: stream}, &daemonSocketConnEnd{conn: conn}, backend.settings().Forward.SpliceBufferByteCount)
	return nil
}

// Forgets listen, once its listener has closed.
func (self *DaemonSockets) forgetListen(listen *daemonSocketListen) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.networkIdListens[listen.networkId][listen.name] == listen {
		delete(self.networkIdListens[listen.networkId], listen.name)
	}
}

// Forgets dial, once it has ended.
func (self *DaemonSockets) forgetDial(dial *daemonSocketDial) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.dials, dial)
}

// ur socket's control methods (§5.8), which ur daemon registers, and ur share's (socket_share.go).
func (self *DaemonSockets) Methods() []*DaemonMethod {
	methods := []*DaemonMethod{
		{
			Name:    DaemonMethodSocketListen,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonSocketListenParams{}
				if err := decodeDaemonSocketParams(call, params); err != nil {
					return nil, err
				}
				return self.Listen(ctx, call.NetworkId, params.Address, params.Target)
			},
		},
		{
			Name:    DaemonMethodSocketDial,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonSocketDialParams{}
				if err := decodeDaemonSocketParams(call, params); err != nil {
					return nil, err
				}
				return self.Dial(ctx, call.NetworkId, params.Address, params.Listen)
			},
		},
		{
			Name:    DaemonMethodSocketList,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonSocketListParams{}
				if err := decodeDaemonSocketParams(call, params); err != nil {
					return nil, err
				}
				return self.ListNames(ctx, call.NetworkId)
			},
		},
		{
			Name: DaemonMethodSocketLocal,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				return &DaemonSocketLocalReply{Sockets: self.Local()}, nil
			},
		},
		{
			Name:    DaemonMethodSocketDrain,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonSocketDrainParams{}
				if err := decodeDaemonSocketParams(call, params); err != nil {
					return nil, err
				}
				count, err := self.Drain(call.NetworkId, params.Address)
				if err != nil {
					return nil, err
				}
				return &DaemonSocketDrainReply{DrainedCount: count}, nil
			},
		},
	}
	return append(methods, self.shareMethods()...)
}

// A call's params into params, refusing a field it does not know; none is an empty object.
func decodeDaemonSocketParams(call *DaemonCall, params any) error {
	if len(call.Params) == 0 {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(call.Params)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(params); err != nil {
		return errDaemonSocketParams
	}
	return nil
}

// A call's params that do not decode. The text names nothing they held.
var errDaemonSocketParams = errors.New("the params do not decode")

// One listen forward: a listener whose conns splice to a local target.
type daemonSocketListen struct {
	sockets   *DaemonSockets
	networkId Id
	// the canonical name, its key
	name     string
	target   string
	settings *SidecarSocketSettings
	listener daemonSocketListener
	// ends with the listener or the daemon
	ctx    context.Context
	cancel context.CancelFunc

	stateLock sync.Mutex
	serving   bool
	probing   bool
	draining  bool
}

// Takes each admitted conn to the target until the listener closes, then forgets the forward.
func (self *daemonSocketListen) run() {
	defer self.cancel()
	defer self.sockets.forgetListen(self)
	for {
		conn, err := self.listener.AcceptSocket(self.ctx)
		if err != nil {
			return
		}
		go self.forward(conn)
	}
}

// One dial of the target, bounded by TargetDialTimeout.
func (self *daemonSocketListen) dialTarget() (net.Conn, error) {
	dialer := &net.Dialer{Timeout: self.settings.Forward.TargetDialTimeout}
	return dialer.DialContext(self.ctx, "tcp", self.target)
}

// conn spliced to a fresh connection to the target, or reset when the target refuses, which stops tickets until it
// answers again.
func (self *daemonSocketListen) forward(conn *SocketConn) {
	target, err := self.dialTarget()
	if err != nil {
		conn.Abort()
		self.refused()
		return
	}
	stop := context.AfterFunc(self.sockets.ctx, func() {
		conn.Abort()
		target.Close()
	})
	defer stop()
	daemonSocketSplice(&daemonSocketConnEnd{conn: conn}, &daemonSocketTcpEnd{conn: target}, self.settings.Forward.SpliceBufferByteCount)
}

// The target refused: serving false, and one probe loop dialing it again (§9.9).
func (self *daemonSocketListen) refused() {
	startProbe, setServing := func() (bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		setServing := self.serving
		self.serving = false
		if self.probing {
			return false, setServing
		}
		self.probing = true
		return true, setServing
	}()
	if setServing {
		self.listener.SetServing(false)
	}
	if startProbe {
		go self.probe()
	}
}

// Dials the target every TargetProbeInterval until it answers, then serves again. Ends with the forward.
func (self *daemonSocketListen) probe() {
	for {
		select {
		case <-self.ctx.Done():
			return
		case <-self.sockets.clock.After(self.settings.Forward.TargetProbeInterval):
		}
		conn, err := self.dialTarget()
		if err != nil {
			continue
		}
		conn.Close()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.serving = true
			self.probing = false
		}()
		self.listener.SetServing(true)
		return
	}
}

// Begins §9.9's Drain in the background; false when it had begun already.
func (self *daemonSocketListen) drain() bool {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.draining {
			return false
		}
		self.draining = true
		return true
	}()
	if first {
		go self.listener.Drain(self.ctx)
	}
	return first
}

// As ur socket and socket_status show it.
func (self *daemonSocketListen) status() *DaemonSocketStatus {
	self.stateLock.Lock()
	serving, draining := self.serving, self.draining
	self.stateLock.Unlock()
	return &DaemonSocketStatus{
		NetworkId: self.networkId,
		Kind:      DaemonSocketKindListen,
		Name:      self.name,
		Target:    self.target,
		Serving:   serving,
		Draining:  draining,
		Inflight:  self.listener.inflightCount(),
	}
}

// One dial forward: a local listener whose conns each splice to a fresh Dial.
type daemonSocketDial struct {
	sockets   *DaemonSockets
	networkId Id
	name      string
	address   *SocketAddress
	backend   daemonSocketBackend
	settings  *SidecarSocketSettings
	local     *DaemonLocalListener
	ctx       context.Context
	cancel    context.CancelFunc

	stateLock sync.Mutex
	conns     map[*daemonSocketDialConn]bool
	draining  bool
	// closed and replaced at each change of conns, which a drain waits on
	connsChange chan struct{}
}

// One local conn of a dial forward and its stream, once dialed.
type daemonSocketDialConn struct {
	local net.Conn
}

// Takes each local conn until the local listener closes, a drain's or the daemon's end, then drains: the forward ends
// once its last spliced conn has.
func (self *daemonSocketDial) run() {
	for {
		local, err := self.local.Accept()
		if err != nil {
			self.drain()
			return
		}
		tracked := &daemonSocketDialConn{local: local}
		kept := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.draining {
				return false
			}
			self.conns[tracked] = true
			self.notifyConnsWithLock()
			return true
		}()
		if !kept {
			local.Close()
			continue
		}
		go self.forward(tracked)
	}
}

// Wakes a drain waiting on the conns, under the lock.
func (self *daemonSocketDial) notifyConnsWithLock() {
	close(self.connsChange)
	self.connsChange = make(chan struct{})
}

// One local conn spliced to a fresh Dial of the address, or closed when the Dial fails.
func (self *daemonSocketDial) forward(tracked *daemonSocketDialConn) {
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.conns, tracked)
		self.notifyConnsWithLock()
	}()
	remote, err := self.backend.dial(self.ctx, self.address, nil)
	if err != nil {
		tracked.local.Close()
		return
	}
	stop := context.AfterFunc(self.ctx, func() {
		remote.Abort()
		tracked.local.Close()
	})
	defer stop()
	daemonSocketSplice(&daemonSocketTcpEnd{conn: tracked.local}, &daemonSocketConnEnd{conn: remote}, self.settings.Forward.SpliceBufferByteCount)
}

// Stops taking local conns, then ends once the spliced ones have, or after ListenDrainTimeout or at the daemon's end,
// closing the rest, and forgets the forward. False when a drain had begun already.
func (self *daemonSocketDial) drain() bool {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.draining {
			return false
		}
		self.draining = true
		return true
	}()
	if !first {
		return false
	}
	self.local.Close()
	go func() {
		timeout := self.sockets.clock.After(self.settings.ListenDrainTimeout)
		for {
			count, changed := func() (int, chan struct{}) {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				return len(self.conns), self.connsChange
			}()
			if count == 0 {
				break
			}
			ended := false
			select {
			case <-changed:
			case <-timeout:
				ended = true
			case <-self.ctx.Done():
				ended = true
			}
			if ended {
				break
			}
		}
		self.cancel()
		self.sockets.forgetDial(self)
	}()
	return true
}

// As ur socket and ur status show it.
func (self *daemonSocketDial) status() *DaemonSocketStatus {
	self.stateLock.Lock()
	inflight, draining := len(self.conns), self.draining
	self.stateLock.Unlock()
	addresses := []string{}
	for _, address := range self.local.Addrs() {
		addresses = append(addresses, address.String())
	}
	return &DaemonSocketStatus{
		NetworkId:      self.networkId,
		Kind:           DaemonSocketKindDial,
		Name:           self.name,
		LocalAddresses: addresses,
		LanExposed:     self.local.LanExposed(),
		Serving:        !draining,
		Draining:       draining,
		Inflight:       inflight,
	}
}

// One end of a splice: a SocketConn, a local TCP conn or a socket session's stream.
type daemonSpliceEnd interface {
	io.Reader
	io.Writer
	// Ends what this end sends while it reads on: a FIN. An error leaves the splice to end both whole.
	CloseWrite() error
	// Ends it once both directions are done.
	Close() error
	// Ends it at once, a reset where the end has one, after either direction failed.
	Abort()
}

// A SocketConn's end: Abort resets the stream.
type daemonSocketConnEnd struct {
	conn *SocketConn
}

// See daemonSpliceEnd.
func (self *daemonSocketConnEnd) Read(b []byte) (int, error) {
	return self.conn.Read(b)
}

// See daemonSpliceEnd.
func (self *daemonSocketConnEnd) Write(b []byte) (int, error) {
	return self.conn.Write(b)
}

// See daemonSpliceEnd: the stream's FIN.
func (self *daemonSocketConnEnd) CloseWrite() error {
	return self.conn.CloseWrite()
}

// See daemonSpliceEnd.
func (self *daemonSocketConnEnd) Close() error {
	return self.conn.Close()
}

// See daemonSpliceEnd: RST_CANCELLED.
func (self *daemonSocketConnEnd) Abort() {
	self.conn.Abort()
}

// A local TCP conn's end: Abort closes with no linger, a reset.
type daemonSocketTcpEnd struct {
	conn net.Conn
}

// See daemonSpliceEnd.
func (self *daemonSocketTcpEnd) Read(b []byte) (int, error) {
	return self.conn.Read(b)
}

// See daemonSpliceEnd.
func (self *daemonSocketTcpEnd) Write(b []byte) (int, error) {
	return self.conn.Write(b)
}

// See daemonSpliceEnd: TCP's FIN.
func (self *daemonSocketTcpEnd) CloseWrite() error {
	halves, ok := self.conn.(interface{ CloseWrite() error })
	if !ok {
		return ErrDaemonNoHalfClose
	}
	return halves.CloseWrite()
}

// See daemonSpliceEnd.
func (self *daemonSocketTcpEnd) Close() error {
	return self.conn.Close()
}

// See daemonSpliceEnd: a close with no linger, which sends a reset.
func (self *daemonSocketTcpEnd) Abort() {
	if tcpConn, ok := self.conn.(*net.TCPConn); ok {
		tcpConn.SetLinger(0)
	}
	self.conn.Close()
}

// A socket session's end: the daemon closes the session once its handler returns, so Close and Abort leave that to
// it, and a write to a session that ended fails the splice.
type daemonSocketSessionEnd struct {
	stream io.ReadWriter
}

// See daemonSpliceEnd.
func (self *daemonSocketSessionEnd) Read(b []byte) (int, error) {
	return self.stream.Read(b)
}

// See daemonSpliceEnd.
func (self *daemonSocketSessionEnd) Write(b []byte) (int, error) {
	return self.stream.Write(b)
}

// See daemonSpliceEnd: the session's write half, where its connection has one.
func (self *daemonSocketSessionEnd) CloseWrite() error {
	halves, ok := self.stream.(interface{ CloseWrite() error })
	if !ok {
		return ErrDaemonNoHalfClose
	}
	return halves.CloseWrite()
}

// See daemonSpliceEnd: nothing, since the daemon closes the session once its handler returns.
func (self *daemonSocketSessionEnd) Close() error {
	return nil
}

// See daemonSpliceEnd: the session closed now, so its ur sees the stream end.
func (self *daemonSocketSessionEnd) Abort() {
	if closer, ok := self.stream.(io.Closer); ok {
		closer.Close()
	}
}

// Copies a to b and b to a until both directions end: an io.EOF on one side closes that half of the other, and any
// other error, or a half that cannot close, ends both at once with Abort. Then both close.
func daemonSocketSplice(a daemonSpliceEnd, b daemonSpliceEnd, bufferByteCount int) {
	var abortOnce sync.Once
	abort := func() {
		abortOnce.Do(func() {
			a.Abort()
			b.Abort()
		})
	}
	half := func(destination daemonSpliceEnd, source daemonSpliceEnd) {
		buffer := make([]byte, bufferByteCount)
		for {
			count, err := source.Read(buffer)
			if 0 < count {
				if _, writeErr := destination.Write(buffer[:count]); writeErr != nil {
					abort()
					return
				}
			}
			if errors.Is(err, io.EOF) {
				if destination.CloseWrite() != nil {
					abort()
				}
				return
			}
			if err != nil {
				abort()
				return
			}
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		half(b, a)
	}()
	half(a, b)
	<-done
	a.Close()
	b.Close()
}

// The status line a socket session's daemon writes before its bytes, read by its client: the dial's answer as §9.9's
// error, nil for ok. Bounded by maxByteCount, past which the session is no socket session.
func ReadDaemonSocketSessionAnswer(stream io.Reader, maxByteCount int) error {
	line := make([]byte, 0, maxByteCount)
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(stream, one); err != nil {
			return fmt.Errorf("no socket status: %w", net.ErrClosed)
		}
		if one[0] == '\n' {
			break
		}
		if maxByteCount <= len(line) {
			return errors.New("no socket status: the line runs past its bound")
		}
		line = append(line, one[0])
	}
	answer := &DaemonSocketSessionAnswer{}
	if err := json.Unmarshal(line, answer); err != nil {
		return errors.New("no socket status: the line does not read")
	}
	return DaemonSocketSessionError(answer)
}
