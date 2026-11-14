//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's port forwards (§17.11's `ur bridge forward client:port[:local ip]:local port`; BRIDGE-M4-20;
// R-BRIDGE-6, D-BRIDGE-10, D-TRUST-8, owner decisions 74, 84): a local listener whose connections dial a target's
// port over the userspace stack, under a requested dial grant.
//
//   - The grant is BridgeFiler.Forward's, filed before anything binds: a forward waiting on a person's decision binds
//     nothing and answers the approval's id.
//   - The listener binds every interface, 0.0.0.0 and ::, unless the call's listen addresses or the daemon's --listen
//     narrow it (owner decision 84). TCP binds through DaemonLocalListen's forward service, so `ur status` lists it
//     LAN-exposed; UDP, which DaemonLocalListen does not bind, binds the same addresses here and carries the same
//     mark in bridge.status. A forward carries its user's own protocol, so owner decision 130's TLS rule does not
//     apply, and it serves every host that reaches the listener, which the mark and `ur bridge forward`'s warning say.
//   - Each TCP connection, and each UDP source, dials the target's overlay address through the backend's userspace
//     stack, a connect.Tun whose packets run through Bridge.RouteBurst, so a forward needs no tun and no root. The
//     target's own hook admits or refuses each flow by the grant (§17.6): the listener enforces nothing the target
//     does not.
//   - A forward stops at its grant's expiry, by the clock, and when a reread of the grant finds it no longer active
//     (DaemonBridges.GrantsChanged), which is how a GrantRevoke closes its listener. Stopping closes the listener
//     and resets every connection it carries.
//
// Logs name the forward's opaque id alone (I-13).

package sidecar

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// A forward's opaque id: 8 random bytes, hex. A format value.
const daemonBridgeForwardIdByteCount = 8

// One forward as bridge.status lists it. Nothing secret: this host's own listener and the grant's opaque id.
type DaemonBridgeForwardStatus struct {
	// The forward's opaque id, which bridge.close takes.
	ForwardId string `json:"forward_id"`
	NetworkId Id     `json:"network_id"`
	// The sidecar it dials, and the protocol and port there.
	Target   Id     `json:"target"`
	Protocol string `json:"protocol"`
	Port     uint32 `json:"port"`
	// The listener: its port and host:port of each bound address.
	LocalPort      int      `json:"local_port"`
	LocalAddresses []string `json:"local_addresses"`
	// A host on the LAN can reach the listener, and so the target's port (D-BRIDGE-10).
	LanExposed bool `json:"lan_exposed"`
	// Its grant's id, hex; empty under a standing grant.
	GrantId string `json:"grant_id,omitempty"`
	// When its grant ends, in ms; 0 for one that does not.
	ExpiresMs int64 `json:"expires_ms,omitempty"`
	// The TCP connections or UDP sources it carries now.
	ConnCount int `json:"conn_count"`
}

// A UDP source a forward relays: its conn to the target and when a datagram last moved either way.
type daemonBridgeUdpFlow struct {
	remote       net.Conn
	lastActiveMs atomic.Int64
}

// One forward: its listener and what it carries.
type daemonBridgeForward struct {
	bridges   *DaemonBridges
	backend   DaemonBridgeBackend
	id        string
	networkId Id
	request   *BridgeForwardRequest
	protocol  string
	grantId   []byte
	address   netip.AddrPort
	// exactly one is set: TCP's listener, or UDP's conns, one a bound address
	local    *DaemonLocalListener
	udpLocal []net.PacketConn
	ctx      context.Context
	cancel   context.CancelFunc

	stateLock sync.Mutex
	expiresAt time.Time
	// stops the expiry's timer, nil for none
	stopExpiry func() bool
	conns      map[net.Conn]bool
	udpFlows   map[netip.AddrPort]*daemonBridgeUdpFlow
	closed     bool
}

// Files a forward's grant and listens for it (the file's comment). A grant that waits for a decision answers the
// approval's id and binds nothing.
func (self *DaemonBridges) Forward(ctx context.Context, networkId Id, running *Sidecar, origin *BridgeFileOrigin, params *DaemonBridgeForwardParams) (*DaemonBridgeFilingReply, error) {
	backend, err := self.backend(ctx, networkId, running)
	if err != nil {
		return nil, err
	}
	protocolNumber, err := daemonBridgeProtocol(params.Protocol)
	if err != nil {
		return nil, err
	}
	if params.Port == 0 || 65535 < params.Port || 65535 < params.LocalPort || params.Target == "" {
		return nil, fmt.Errorf("%w: a forward names a target, its port and a local port", ErrDaemonBridgeParams)
	}
	for _, address := range params.Listen {
		if _, err := netip.ParseAddr(address); err != nil {
			return nil, fmt.Errorf("%w: a listen address is an ip", ErrDaemonBridgeParams)
		}
	}
	full := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.closed || self.settings.ForwardMaxCount <= len(self.forwards)
	}()
	if full {
		return nil, ErrDaemonBridgeForwardLimit
	}
	target, err := backend.ResolveSidecar(ctx, params.Target)
	if err != nil {
		return nil, err
	}
	request := &BridgeForwardRequest{
		Target:    target,
		Protocol:  protocolNumber,
		Port:      params.Port,
		LocalPort: params.LocalPort,
		Lifetime:  time.Duration(params.LifetimeSeconds) * time.Second,
	}
	filing, err := backend.Forward(ctx, origin, request)
	reply, err := daemonBridgeFilingReply(filing, err)
	if err != nil || reply.ApprovalPendingId != nil {
		return reply, err
	}
	route, err := backend.ForwardRoute(ctx, request, filing.GrantId)
	if err != nil {
		return nil, err
	}
	if route == nil || !route.Live || !route.Address.IsValid() {
		return nil, ErrDaemonBridgeGrantEnded
	}
	now := self.clock.Now()
	if !route.ExpiresAt.IsZero() && !now.Before(route.ExpiresAt) {
		return nil, ErrDaemonBridgeGrantEnded
	}
	idBytes := make([]byte, daemonBridgeForwardIdByteCount)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	forwardCtx, cancel := context.WithCancel(self.ctx)
	forward := &daemonBridgeForward{
		bridges:   self,
		backend:   backend,
		id:        hex.EncodeToString(idBytes),
		networkId: networkId,
		request:   request,
		protocol:  map[uint32]string{bridgeProtocolTcp: daemonBridgeProtocolTcp, bridgeProtocolUdp: daemonBridgeProtocolUdp}[protocolNumber],
		grantId:   filing.GrantId,
		address:   netip.AddrPortFrom(route.Address, uint16(params.Port)),
		ctx:       forwardCtx,
		cancel:    cancel,
		conns:     map[net.Conn]bool{},
		udpFlows:  map[netip.AddrPort]*daemonBridgeUdpFlow{},
	}
	listen := params.Listen
	if len(listen) == 0 {
		listen = self.args.ListenAddresses
	}
	if protocolNumber == bridgeProtocolUdp {
		forward.udpLocal, err = daemonBridgeUdpListen(listen, int(params.LocalPort))
	} else {
		forward.local, err = self.args.Listen(&DaemonLocalListenArgs{Service: DaemonLocalForward, Port: int(params.LocalPort), Listen: listen})
	}
	if err != nil {
		cancel()
		return nil, err
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed || self.settings.ForwardMaxCount <= len(self.forwards) {
			return false
		}
		self.forwards[forward.id] = forward
		return true
	}()
	if !kept {
		forward.closeListeners()
		cancel()
		return nil, ErrDaemonBridgeForwardLimit
	}
	forward.setExpiry(route.ExpiresAt)
	if forward.local != nil {
		go forward.runTcp()
	}
	for _, local := range forward.udpLocal {
		go forward.runUdp(local)
	}
	if 0 < len(forward.udpLocal) {
		go forward.runUdpSweep()
	}
	self.log.Infof("[bridge]forward %s up", forward.id)
	reply.Forward = forward.status()
	return reply, nil
}

// Binds a UDP forward's addresses: every interface, 0.0.0.0 and ::, unless listen narrows it. With port 0 the first
// bind's port is the rest's. A family this host lacks is skipped when nothing narrowed the bind, as long as one bound.
func daemonBridgeUdpListen(listen []string, port int) ([]net.PacketConn, error) {
	narrowed := 0 < len(listen)
	if !narrowed {
		listen = []string{"0.0.0.0", "::"}
	}
	locals := []net.PacketConn{}
	closeLocals := func() {
		for _, local := range locals {
			local.Close()
		}
	}
	for _, address := range listen {
		ip, err := netip.ParseAddr(address)
		if err != nil {
			closeLocals()
			return nil, ErrDaemonLocalArgs
		}
		network := "udp4"
		if ip.Is6() && !ip.Is4In6() {
			network = "udp6"
		}
		local, err := net.ListenPacket(network, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			if !narrowed && 0 < len(locals) {
				continue
			}
			closeLocals()
			return nil, fmt.Errorf("%w", ErrDaemonLocalPortTaken)
		}
		locals = append(locals, local)
		if udpAddress, ok := local.LocalAddr().(*net.UDPAddr); ok && port == 0 {
			port = udpAddress.Port
		}
	}
	if len(locals) == 0 {
		return nil, ErrDaemonLocalArgs
	}
	return locals, nil
}

// Arms the forward's stop at expiresAt, replacing an earlier one; zero is none.
func (self *daemonBridgeForward) setExpiry(expiresAt time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed || self.expiresAt.Equal(expiresAt) && (self.stopExpiry != nil || expiresAt.IsZero()) {
		return
	}
	if self.stopExpiry != nil {
		self.stopExpiry()
		self.stopExpiry = nil
	}
	self.expiresAt = expiresAt
	if expiresAt.IsZero() {
		return
	}
	self.stopExpiry = self.bridges.clock.AfterFunc(expiresAt.Sub(self.bridges.clock.Now()), func() {
		self.close(ErrDaemonBridgeGrantEnded)
	})
}

// Whether the grant's expiry has come, by the clock.
func (self *daemonBridgeForward) expired() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return !self.expiresAt.IsZero() && !self.bridges.clock.Now().Before(self.expiresAt)
}

// Rereads the forward's grant: closes the forward when it is no longer active, and moves its expiry when that
// changed. A reread that fails leaves the forward as it is, since the target's hook refuses what the grant no longer
// admits either way.
func (self *daemonBridgeForward) recheck(ctx context.Context) {
	route, err := self.backend.ForwardRoute(ctx, self.request, self.grantId)
	if err != nil {
		self.bridges.log.Infof("[bridge]forward %s grant unread", self.id)
		return
	}
	if route == nil || !route.Live {
		self.close(ErrDaemonBridgeGrantEnded)
		return
	}
	self.setExpiry(route.ExpiresAt)
	if self.expired() {
		self.close(ErrDaemonBridgeGrantEnded)
	}
}

// Closes the listeners alone.
func (self *daemonBridgeForward) closeListeners() {
	if self.local != nil {
		self.local.Close()
	}
	for _, local := range self.udpLocal {
		local.Close()
	}
}

// Ends the forward: no new connection, and a reset of each it carries. reason is nil for a person's close.
func (self *daemonBridgeForward) close(reason error) {
	testHookBarrier("bridge_daemon.forward.close", self.id)
	conns, ended := func() ([]net.Conn, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return nil, false
		}
		self.closed = true
		if self.stopExpiry != nil {
			self.stopExpiry()
			self.stopExpiry = nil
		}
		conns := make([]net.Conn, 0, len(self.conns)+len(self.udpFlows))
		for conn := range self.conns {
			conns = append(conns, conn)
		}
		for _, flow := range self.udpFlows {
			conns = append(conns, flow.remote)
		}
		clear(self.conns)
		clear(self.udpFlows)
		return conns, true
	}()
	if !ended {
		return
	}
	self.cancel()
	// forgotten and unbound before any connection ends, so whoever sees one end finds the forward gone
	func() {
		self.bridges.stateLock.Lock()
		defer self.bridges.stateLock.Unlock()
		if self.bridges.forwards[self.id] == self {
			delete(self.bridges.forwards, self.id)
		}
	}()
	self.closeListeners()
	for _, conn := range conns {
		(&daemonSocketTcpEnd{conn: conn}).Abort()
	}
	if reason != nil {
		self.bridges.log.Infof("[bridge]forward %s down: %s", self.id, reason)
	} else {
		self.bridges.log.Infof("[bridge]forward %s down", self.id)
	}
}

// Holds conn for the forward's close; false once the forward has closed, and conn is then the caller's to close.
func (self *daemonBridgeForward) track(conn net.Conn) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return false
	}
	self.conns[conn] = true
	return true
}

// Forgets a conn that ended on its own.
func (self *daemonBridgeForward) untrack(conn net.Conn) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.conns, conn)
}

// Dials the target over the userspace stack, within ForwardDialTimeout on the forward's clock.
func (self *daemonBridgeForward) dial() (net.Conn, error) {
	dialCtx, cancel := context.WithCancel(self.ctx)
	defer cancel()
	stop := self.bridges.clock.AfterFunc(self.bridges.settings.ForwardDialTimeout, cancel)
	defer stop()
	return self.backend.DialForward(dialCtx, self.protocol, self.address)
}

// Accepts until the listener closes, each connection spliced to a dial of the target.
func (self *daemonBridgeForward) runTcp() {
	for {
		conn, err := self.local.Accept()
		if err != nil {
			if self.ctx.Err() == nil {
				self.close(err)
			}
			return
		}
		if self.expired() {
			conn.Close()
			self.close(ErrDaemonBridgeGrantEnded)
			return
		}
		go self.serveTcp(conn)
	}
}

// One connection: a dial of the target, then both directions until each ends.
func (self *daemonBridgeForward) serveTcp(conn net.Conn) {
	if !self.track(conn) {
		conn.Close()
		return
	}
	defer self.untrack(conn)
	remote, err := self.dial()
	if err != nil {
		(&daemonSocketTcpEnd{conn: conn}).Abort()
		return
	}
	if !self.track(remote) {
		remote.Close()
		(&daemonSocketTcpEnd{conn: conn}).Abort()
		return
	}
	defer self.untrack(remote)
	testHookBarrier("bridge_daemon.forward.splice", self.id)
	daemonSocketSplice(&daemonSocketTcpEnd{conn: conn}, &daemonSocketTcpEnd{conn: remote}, self.bridges.settings.ForwardSpliceBufferByteCount)
}

// Reads one bound address's datagrams until it closes, each relayed on its source's conn to the target.
func (self *daemonBridgeForward) runUdp(local net.PacketConn) {
	buffer := make([]byte, self.bridges.settings.ForwardUdpPacketByteCount)
	for {
		count, sourceAddress, err := local.ReadFrom(buffer)
		if err != nil {
			if self.ctx.Err() == nil {
				self.close(err)
			}
			return
		}
		udpAddress, ok := sourceAddress.(*net.UDPAddr)
		if !ok {
			continue
		}
		source := udpAddress.AddrPort()
		flow := self.udpFlow(local, sourceAddress, source)
		if flow == nil {
			continue
		}
		flow.lastActiveMs.Store(self.bridges.clock.Now().UnixMilli())
		// a datagram the stack refuses is dropped, as UDP drops
		flow.remote.Write(buffer[:count])
	}
}

// The source's flow, dialed when it is new; nil when the forward has closed, is at its limit of sources, or the dial
// failed, and the datagram is dropped.
func (self *daemonBridgeForward) udpFlow(local net.PacketConn, sourceAddress net.Addr, source netip.AddrPort) *daemonBridgeUdpFlow {
	flow, full := func() (*daemonBridgeUdpFlow, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.udpFlows[source], self.closed || self.bridges.settings.ForwardUdpFlowMaxCount <= len(self.udpFlows)
	}()
	if flow != nil {
		return flow
	}
	if full || self.expired() {
		return nil
	}
	remote, err := self.dial()
	if err != nil {
		return nil
	}
	flow = &daemonBridgeUdpFlow{remote: remote}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.udpFlows[source] = flow
		return true
	}()
	if !kept {
		remote.Close()
		return nil
	}
	go self.runUdpReturn(local, sourceAddress, source, flow)
	return flow
}

// Relays the target's datagrams back to the source until the flow's conn closes.
func (self *daemonBridgeForward) runUdpReturn(local net.PacketConn, sourceAddress net.Addr, source netip.AddrPort, flow *daemonBridgeUdpFlow) {
	defer func() {
		flow.remote.Close()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.udpFlows[source] == flow {
			delete(self.udpFlows, source)
		}
	}()
	buffer := make([]byte, self.bridges.settings.ForwardUdpPacketByteCount)
	for {
		count, err := flow.remote.Read(buffer)
		if err != nil {
			return
		}
		flow.lastActiveMs.Store(self.bridges.clock.Now().UnixMilli())
		if _, err := local.WriteTo(buffer[:count], sourceAddress); err != nil {
			return
		}
	}
}

// Closes each UDP source's conn idle past ForwardUdpIdleTimeout, once an interval, until the forward ends.
func (self *daemonBridgeForward) runUdpSweep() {
	timeout := self.bridges.settings.ForwardUdpIdleTimeout
	if timeout <= 0 {
		return
	}
	for {
		select {
		case <-self.ctx.Done():
			return
		case <-self.bridges.clock.After(timeout):
		}
		idleBefore := self.bridges.clock.Now().Add(-timeout).UnixMilli()
		idle := func() []*daemonBridgeUdpFlow {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			idle := []*daemonBridgeUdpFlow{}
			for source, flow := range self.udpFlows {
				if flow.lastActiveMs.Load() <= idleBefore {
					idle = append(idle, flow)
					delete(self.udpFlows, source)
				}
			}
			return idle
		}()
		for _, flow := range idle {
			flow.remote.Close()
		}
	}
}

// The forward's status.
func (self *daemonBridgeForward) status() *DaemonBridgeForwardStatus {
	status := &DaemonBridgeForwardStatus{
		ForwardId: self.id,
		NetworkId: self.networkId,
		Target:    self.request.Target,
		Protocol:  self.protocol,
		Port:      self.request.Port,
		GrantId:   hex.EncodeToString(self.grantId),
	}
	addresses := []net.Addr{}
	if self.local != nil {
		addresses = self.local.Addrs()
		status.LocalPort = self.local.Port()
		status.LanExposed = self.local.LanExposed()
	}
	for _, local := range self.udpLocal {
		addresses = append(addresses, local.LocalAddr())
		if udpAddress, ok := local.LocalAddr().(*net.UDPAddr); ok {
			status.LocalPort = udpAddress.Port
			if ip, ok := netip.AddrFromSlice(udpAddress.IP); !ok || !ip.Unmap().IsLoopback() {
				status.LanExposed = true
			}
		}
	}
	for _, address := range addresses {
		status.LocalAddresses = append(status.LocalAddresses, address.String())
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.expiresAt.IsZero() {
		status.ExpiresMs = self.expiresAt.UnixMilli()
	}
	// a TCP connection holds two conns, the local one and the dial
	status.ConnCount = (len(self.conns)+1)/2 + len(self.udpFlows)
	return status
}

// A forward the daemon holds, by its id.
func (self *DaemonBridges) ForwardStatus(forwardId string) (*DaemonBridgeForwardStatus, error) {
	forward := func() *daemonBridgeForward {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.forwards[forwardId]
	}()
	if forward == nil {
		return nil, ErrDaemonBridgeNoForward
	}
	return forward.status(), nil
}
