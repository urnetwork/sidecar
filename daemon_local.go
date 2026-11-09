//go:build !js && !ios && !android && !sdk_mobile_bind

// DaemonLocalListen (§5.8, D-TRUST-8, I-17; owner decisions 84, 130): the one way the daemon's local services take
// connections from beyond its control socket: git over http or https and over ssh (§11.11), SMTP submission and IMAP
// (§15), and forwards (§9's socket dial, §17's port forwards). A service listens at --port's first port plus its place
// (plan-CORE-cli-ui-missing #6), on every interface, 0.0.0.0 and ::, unless --listen narrows it (owner decision 84).
//
// Off loopback a listener serves only TLS, or ssh for git (owner decision 130), and plaintext stays on 127.0.0.1 and
// ::1. git's http, submission and IMAP choose by each connection's local address, as RFC 8314 §3's implicit TLS does:
// one arriving at a loopback address is plaintext, any other is a TLS server on the listener's certificate (§13's
// device certificate, else a self-signed one). A listener of those with no certificate stays on loopback, and one asked
// to listen elsewhere without a certificate is refused at setup, so no plaintext setup ever binds off loopback. git's
// ssh carries its own encryption everywhere. A forward carries raw bytes without the TLS rule, and every forward a
// listener could reach from the LAN is marked LanExposed, which ur status prints (§22.5).
//
// The listener does not authenticate: each service does, loopback included (I-17), with its own protocol's
// credential, Basic over TLS or loopback for git's http, ssh keys, SMTP AUTH, IMAP LOGIN. HttpHandler is the HTTP
// half: a request reaches its handler only with a Host the listener answers to, which stops a DNS-rebinding page, and
// a caller authenticate passes.
//
// Safe for concurrent use.

package sidecar

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// A local service the daemon runs (§5.8).
type DaemonLocalService string

const (
	// git's http, https off loopback (§11.11).
	DaemonLocalGitHttp DaemonLocalService = "git-http"
	// git's ssh (§11.11).
	DaemonLocalGitSsh DaemonLocalService = "git-ssh"
	// SMTP submission (§15).
	DaemonLocalSubmission DaemonLocalService = "submission"
	// IMAP (§15).
	DaemonLocalImap DaemonLocalService = "imap"
	// A forward: §9's socket dial or §17's port forward, raw bytes, disclosed as LAN-exposed.
	DaemonLocalForward DaemonLocalService = "forward"
)

var (
	// A plaintext service asked to listen off loopback with no certificate to serve TLS there (owner decision 130).
	ErrDaemonLocalPlaintext = errors.New("plaintext stays on 127.0.0.1 and ::1: off loopback this service serves only tls")
	// A setup the helper cannot take: an unknown service, a forward with no port, or an address that is not an IP.
	ErrDaemonLocalArgs = errors.New("invalid local listener")
	// The port is taken.
	ErrDaemonLocalPortTaken = errors.New("the port is taken: pass another with --port")
)

// The service's place after the first port, a format value of plan-CORE-cli-ui-missing #6, and false for a forward,
// which names its own port.
func daemonLocalPortOffset(service DaemonLocalService) (int, bool) {
	switch service {
	case DaemonLocalGitHttp:
		return 0, true
	case DaemonLocalGitSsh:
		return 1, true
	case DaemonLocalSubmission:
		return 2, true
	case DaemonLocalImap:
		return 3, true
	}
	return 0, false
}

// Whether the service speaks plaintext on loopback and TLS everywhere else.
func daemonLocalTlsOffLoopback(service DaemonLocalService) bool {
	switch service {
	case DaemonLocalGitHttp, DaemonLocalSubmission, DaemonLocalImap:
		return true
	}
	return false
}

// What one local listener is asked for.
type DaemonLocalListenArgs struct {
	Service DaemonLocalService
	// The port. Zero: FirstPort plus the service's place. A forward names its own, which zero leaves to the OS.
	Port int
	// The first port of the local services: SidecarLocalSettings.FirstPort, zero letting the OS choose.
	FirstPort int
	// --listen's addresses, each an IP literal. Empty: every interface, 0.0.0.0 and ::.
	Listen []string
	// The certificate a plaintext service serves off loopback. Nil: such a service stays on loopback, and Listen
	// naming any other address is refused. Read for git's http, submission and IMAP only.
	Tls *tls.Config
}

// One local service's listener: every address it binds, accepting from all of them. Accept hands out each connection
// as the service may speak on it (DaemonLocalConn).
type DaemonLocalListener struct {
	service   DaemonLocalService
	tlsConfig *tls.Config
	listeners []net.Listener
	accepted  chan daemonLocalAccept
	closed    chan struct{}
	closeOnce sync.Once
	// called once at Close, so a daemon that tracks the listener forgets it
	onClose func()
}

// A connection or an error from one of the bound addresses.
type daemonLocalAccept struct {
	conn net.Conn
	err  error
}

// A connection as its service may speak on it.
type DaemonLocalConn struct {
	net.Conn
	// It arrived at a loopback address.
	Loopback bool
	// It is a TLS server on the listener's certificate, its handshake run at the first read or write.
	Tls bool
}

// Binds the service's listener as args ask, refusing a plaintext setup off loopback before binding anything.
func DaemonLocalListen(args *DaemonLocalListenArgs) (*DaemonLocalListener, error) {
	if args == nil {
		return nil, ErrDaemonLocalArgs
	}
	offset, fixed := daemonLocalPortOffset(args.Service)
	if !fixed && args.Service != DaemonLocalForward {
		return nil, fmt.Errorf("%w: no service %q", ErrDaemonLocalArgs, args.Service)
	}
	if args.Port < 0 || 65535 < args.Port || args.FirstPort < 0 || 65535-3 < args.FirstPort {
		return nil, fmt.Errorf("%w: a port outside 0 to 65535", ErrDaemonLocalArgs)
	}
	port := args.Port
	if port == 0 && fixed && args.FirstPort != 0 {
		port = args.FirstPort + offset
	}
	addresses := []netip.Addr{}
	for _, text := range args.Listen {
		address, err := netip.ParseAddr(text)
		if err != nil || address.Zone() != "" {
			return nil, fmt.Errorf("%w: --listen takes IP addresses", ErrDaemonLocalArgs)
		}
		addresses = append(addresses, address.Unmap())
	}
	plaintextOnly := daemonLocalTlsOffLoopback(args.Service) && args.Tls == nil
	if plaintextOnly {
		for _, address := range addresses {
			if !address.IsLoopback() {
				// refused before binding: no plaintext setup reaches beyond this host
				return nil, ErrDaemonLocalPlaintext
			}
		}
		if len(addresses) == 0 {
			// every interface would carry plaintext, so the service stays on loopback
			addresses = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()}
		}
	}

	listeners := []net.Listener{}
	closeAll := func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}
	listen := func(host string) error {
		listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			if 0 < port && errors.Is(err, syscall.EADDRINUSE) {
				return fmt.Errorf("%w: %d", ErrDaemonLocalPortTaken, port)
			}
			return err
		}
		listeners = append(listeners, listener)
		if port == 0 {
			// every address of one service shares the first one's port
			port = listener.Addr().(*net.TCPAddr).Port
		}
		return nil
	}
	if len(addresses) == 0 {
		// Go's wildcard is one socket on 0.0.0.0 and :: alike
		if err := listen(""); err != nil {
			return nil, err
		}
	} else {
		for i, address := range addresses {
			err := listen(address.String())
			if err != nil && plaintextOnly && len(args.Listen) == 0 && 0 < i && address.Is6() {
				// a host with IPv6 off still serves 127.0.0.1
				continue
			}
			if err != nil {
				closeAll()
				return nil, err
			}
		}
	}

	self := &DaemonLocalListener{
		service:   args.Service,
		tlsConfig: args.Tls,
		listeners: listeners,
		accepted:  make(chan daemonLocalAccept),
		closed:    make(chan struct{}),
	}
	for _, listener := range listeners {
		go self.acceptFrom(listener)
	}
	return self, nil
}

// Hands each connection of one bound address to Accept until the listener closes. The bound socket's own Accept blocks
// until a connection or the close, so this never spins.
func (self *DaemonLocalListener) acceptFrom(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-self.closed:
				return
			default:
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			select {
			case self.accepted <- daemonLocalAccept{err: err}:
			case <-self.closed:
			}
			return
		}
		select {
		case self.accepted <- daemonLocalAccept{conn: conn}:
		case <-self.closed:
			conn.Close()
			return
		}
	}
}

// The next connection, as its service may speak on it: a *DaemonLocalConn, a TLS server off loopback for git's http,
// submission and IMAP.
func (self *DaemonLocalListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-self.closed:
			return nil, net.ErrClosed
		case accepted := <-self.accepted:
			if accepted.err != nil {
				return nil, accepted.err
			}
			conn := self.serveAs(accepted.conn)
			if conn == nil {
				continue
			}
			return conn, nil
		}
	}
}

// conn as the service may speak on it, or nil once closed: a plaintext service's off loopback, with no certificate,
// which a listener bound only on loopback never meets.
func (self *DaemonLocalListener) serveAs(conn net.Conn) *DaemonLocalConn {
	loopback := daemonLocalLoopback(conn.LocalAddr())
	if loopback || !daemonLocalTlsOffLoopback(self.service) {
		return &DaemonLocalConn{Conn: conn, Loopback: loopback}
	}
	if self.tlsConfig == nil {
		conn.Close()
		return nil
	}
	return &DaemonLocalConn{Conn: tls.Server(conn, self.tlsConfig), Tls: true}
}

// Whether address is a loopback one, an IPv4 address that arrived on a dual-stack socket included.
func daemonLocalLoopback(address net.Addr) bool {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(tcpAddress.IP)
	return ok && ip.Unmap().IsLoopback()
}

// Stops listening on every address. Safe to call again.
func (self *DaemonLocalListener) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
		for _, listener := range self.listeners {
			listener.Close()
		}
		if self.onClose != nil {
			self.onClose()
		}
	})
	return nil
}

// The first bound address, net.Listener's.
func (self *DaemonLocalListener) Addr() net.Addr {
	return self.listeners[0].Addr()
}

// Every bound address.
func (self *DaemonLocalListener) Addrs() []net.Addr {
	addresses := make([]net.Addr, 0, len(self.listeners))
	for _, listener := range self.listeners {
		addresses = append(addresses, listener.Addr())
	}
	return addresses
}

// The port every address shares.
func (self *DaemonLocalListener) Port() int {
	return self.listeners[0].Addr().(*net.TCPAddr).Port
}

// The service it listens for.
func (self *DaemonLocalListener) Service() DaemonLocalService {
	return self.service
}

// Whether a host on the LAN can reach it: it binds every interface or an address that is not loopback (D-TRUST-8).
// ur status prints each one that is (§22.5).
func (self *DaemonLocalListener) LanExposed() bool {
	for _, listener := range self.listeners {
		tcpAddress, ok := listener.Addr().(*net.TCPAddr)
		if !ok {
			return true
		}
		ip, ok := netip.AddrFromSlice(tcpAddress.IP)
		if !ok || !ip.Unmap().IsLoopback() {
			return true
		}
	}
	return false
}

// Wraps handler so that a request reaches it only with a Host this listener answers to and a caller authenticate
// passes (I-17). The listener answers to localhost, its loopback and bound addresses, and hosts, such as the
// device's §13 names, each with or without its port. A wrong Host answers 421 and an unauthenticated caller 401 with a
// Basic challenge, which git needs before it sends a credential. A nil authenticate refuses every caller.
func (self *DaemonLocalListener) HttpHandler(handler http.Handler, hosts []string, authenticate func(request *http.Request) bool) http.Handler {
	port := strconv.Itoa(self.Port())
	allowed := map[string]bool{}
	allow := func(host string) {
		host = strings.ToLower(host)
		allowed[host] = true
		allowed[net.JoinHostPort(host, port)] = true
	}
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		allow(host)
	}
	for _, address := range self.Addrs() {
		if tcpAddress, ok := address.(*net.TCPAddr); ok && !tcpAddress.IP.IsUnspecified() {
			allow(tcpAddress.IP.String())
		}
	}
	for _, host := range hosts {
		allow(host)
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		host := strings.ToLower(request.Host)
		if strings.HasPrefix(host, "[") {
			// net.JoinHostPort writes an IPv6 host bracketed only beside a port
			if unbracketed, ok := strings.CutSuffix(strings.TrimPrefix(host, "["), "]"); ok {
				host = unbracketed
			}
		}
		if !allowed[host] {
			http.Error(writer, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		if authenticate == nil || !authenticate(request) {
			writer.Header().Set("WWW-Authenticate", `Basic realm="ur"`)
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(writer, request)
	})
}

// One local listener as ur status shows it.
type DaemonLocalListenerStatus struct {
	Service DaemonLocalService `json:"service"`
	// host:port of each bound address.
	Addresses  []string `json:"addresses"`
	LanExposed bool     `json:"lan_exposed"`
}

// The listener's status.
func (self *DaemonLocalListener) status() DaemonLocalListenerStatus {
	addresses := []string{}
	for _, address := range self.Addrs() {
		addresses = append(addresses, address.String())
	}
	return DaemonLocalListenerStatus{Service: self.service, Addresses: addresses, LanExposed: self.LanExposed()}
}

// DaemonLocalListen with the daemon's first port and --listen, which args may override, kept for LocalListeners
// until it closes.
func (self *Daemon) LocalListen(args *DaemonLocalListenArgs) (*DaemonLocalListener, error) {
	if args == nil {
		return nil, ErrDaemonLocalArgs
	}
	withDaemon := *args
	if withDaemon.FirstPort == 0 {
		withDaemon.FirstPort = self.settings.Local.FirstPort
	}
	if len(withDaemon.Listen) == 0 {
		withDaemon.Listen = slices.Clone(self.settings.Listen)
	}
	listener, err := DaemonLocalListen(&withDaemon)
	if err != nil {
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.localListeners == nil {
			self.localListeners = map[*DaemonLocalListener]bool{}
		}
		self.localListeners[listener] = true
	}()
	listener.onClose = func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.localListeners, listener)
	}
	return listener, nil
}

// Each local listener open, by service then first address: what ur status prints, LAN-exposed ones marked.
func (self *Daemon) LocalListeners() []DaemonLocalListenerStatus {
	listeners := func() []*DaemonLocalListener {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		listeners := make([]*DaemonLocalListener, 0, len(self.localListeners))
		for listener := range self.localListeners {
			listeners = append(listeners, listener)
		}
		return listeners
	}()
	statuses := make([]DaemonLocalListenerStatus, 0, len(listeners))
	for _, listener := range listeners {
		statuses = append(statuses, listener.status())
	}
	slices.SortFunc(statuses, func(a DaemonLocalListenerStatus, b DaemonLocalListenerStatus) int {
		if a.Service != b.Service {
			return strings.Compare(string(a.Service), string(b.Service))
		}
		return strings.Compare(strings.Join(a.Addresses, ","), strings.Join(b.Addresses, ","))
	})
	return statuses
}
