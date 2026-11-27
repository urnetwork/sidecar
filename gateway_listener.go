//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The gateway's listener and its local security (DESIGN-COMPUTE §8.4's listener row, §8.7; R-GW-4, I-17, D-GW-3,
// GW-M12-01).
//
//	bind      127.0.0.1:<port> and [::1]:<port>, the instance's port (gateway_state.go), and never another address:
//	          nothing here takes an address, so no flag can widen it, the daemon's --listen included. No Unix socket,
//	          since no harness's base-URL setting takes one. A host with no IPv6 loopback serves IPv4 alone
//	unit      a listener the daemon's unit hands it (launchd's Sockets, a systemd socket unit), so the port stays held
//	          across the daemon's restarts, is taken for the address it is bound to; one bound anywhere else is closed
//	          and never served
//	in use    an address another process holds is not served, and its status names the holder where the OS shows it,
//	          which `ur status` prints and `ur gateway token` refuses on (gateway_proof.go)
//	guard     every request passes, in order: the Host check, Host one of 127.0.0.1:<port>, localhost:<port> or
//	          [::1]:<port> or 421, which stops DNS rebinding (the Ollama CVE-2024-28224 class), before any token is
//	          read, so a rebound page learns nothing; the browser check, an Origin header of any value or a
//	          Sec-Fetch-Site other than none refused 403; the body's bound, GatewaySettings.RequestByteCount, a longer
//	          declared body refused 413 and a longer read failing; and the concurrency bound,
//	          GatewaySettings.ConcurrentRequestCount at once, the next refused 429 at once. No answer carries a CORS
//	          header, whatever a handler sets, so no web page reads one
//
// A GatewayListener is safe for concurrent use after construction.

package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Windows' WSAEADDRINUSE, which a bind there answers for an address in use: an OS error code.
const gatewayWindowsAddressInUse = syscall.Errno(10048)

// The header a browser sends on every request a page makes, and the one fetch metadata sends, with the only value of
// it a page cannot cause.
const (
	gatewayHeaderOrigin        = "Origin"
	gatewayHeaderSecFetchSite  = "Sec-Fetch-Site"
	gatewaySecFetchSiteNone    = "none"
	gatewayCorsHeaderPrefix    = "Access-Control-"
	gatewayLocalhostName       = "localhost"
	gatewayGuardContentType    = "application/json"
	gatewayGuardErrorMisrouted = "misdirected_request"
	gatewayGuardErrorBrowser   = "browser_request_refused"
	gatewayGuardErrorTooLarge  = "request_too_large"
	gatewayGuardErrorBusy      = "too_many_requests"
)

// What a GatewayListener binds from.
type GatewayListenerArgs struct {
	// The instance's port.
	Port int
	// Listeners the daemon's unit handed over: each taken for the loopback address of Port it is bound to, every other
	// closed and never served.
	Inherited []net.Listener
	// How it binds: net.Listen, unless a test stands one in.
	Listen func(network string, address string) (net.Listener, error)
	// Who holds an address the bind found in use, where the OS shows it; "" where it does not. Nil shows none.
	Holder func(address string) string
}

// One loopback address of the port as the listener holds it, which `ur status` prints.
type GatewayAddressStatus struct {
	// 127.0.0.1:<port> or [::1]:<port>.
	Address string `json:"address"`
	// The daemon serves it.
	Serving bool `json:"serving,omitempty"`
	// From the daemon's unit, which holds it across restarts.
	Inherited bool `json:"inherited,omitempty"`
	// Another process holds it, so the daemon cannot.
	InUse bool `json:"in_use,omitempty"`
	// Who holds it, where the OS shows it.
	Holder string `json:"holder,omitempty"`
	// Why it is not served, the bind's error.
	Reason string `json:"reason,omitempty"`
}

// The listener's sockets on the port's loopback addresses: see the file header.
type GatewayListener struct {
	port      int
	listeners []net.Listener
	statuses  []GatewayAddressStatus
	// inherited listeners bound to an address that is not the port's, closed and never served
	refusedCount int
}

// Binds the port's two loopback addresses, or takes a unit's listener for each, answering what it holds; an address it
// cannot bind is in the statuses with why, never an error, so the other one still serves.
func NewGatewayListener(args *GatewayListenerArgs) *GatewayListener {
	listen := args.Listen
	if listen == nil {
		listen = net.Listen
	}
	self := &GatewayListener{port: args.Port}
	addresses := GatewayLoopbackAddresses(args.Port)
	inheritedAddressListeners := map[string]net.Listener{}
	for _, inherited := range args.Inherited {
		address, ok := gatewayLoopbackAddressOf(inherited.Addr(), args.Port)
		if !ok || inheritedAddressListeners[address] != nil {
			inherited.Close()
			self.refusedCount += 1
			continue
		}
		inheritedAddressListeners[address] = inherited
	}
	networks := []string{"tcp4", "tcp6"}
	for i, address := range addresses {
		status := GatewayAddressStatus{Address: address}
		if inherited := inheritedAddressListeners[address]; inherited != nil {
			status.Serving, status.Inherited = true, true
			self.listeners = append(self.listeners, inherited)
			self.statuses = append(self.statuses, status)
			continue
		}
		listener, err := listen(networks[i], address)
		switch {
		case err == nil:
			status.Serving = true
			self.listeners = append(self.listeners, listener)
		case gatewayAddressInUse(err):
			status.InUse = true
			status.Reason = "another process holds it"
			if args.Holder != nil {
				status.Holder = args.Holder(address)
			}
		default:
			// a host with no IPv6 loopback, among others: the bind's error names the address alone
			status.Reason = err.Error()
		}
		self.statuses = append(self.statuses, status)
	}
	return self
}

// Whether a bind's error says another socket holds the address.
func gatewayAddressInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || (runtime.GOOS == "windows" && errors.Is(err, gatewayWindowsAddressInUse))
}

// The port's loopback address a listener's address is, in the form GatewayLoopbackAddresses gives it; false for any
// other address, a port of another number or a listener that is not TCP.
func gatewayLoopbackAddressOf(addr net.Addr, port int) (string, bool) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr.Port != port || tcpAddr.Zone != "" {
		return "", false
	}
	switch {
	case tcpAddr.IP.Equal(net.ParseIP(gatewayLoopbackIpv4)) && tcpAddr.IP.To4() != nil:
		return net.JoinHostPort(gatewayLoopbackIpv4, strconv.Itoa(port)), true
	case tcpAddr.IP.Equal(net.IPv6loopback):
		return net.JoinHostPort(gatewayLoopbackIpv6, strconv.Itoa(port)), true
	}
	return "", false
}

// The port.
func (self *GatewayListener) Port() int {
	return self.port
}

// What it serves on.
func (self *GatewayListener) Listeners() []net.Listener {
	return slices.Clone(self.listeners)
}

// Each of the port's two addresses, IPv4's first.
func (self *GatewayListener) Statuses() []GatewayAddressStatus {
	return slices.Clone(self.statuses)
}

// How many listeners the unit handed over that were bound elsewhere, each closed.
func (self *GatewayListener) RefusedCount() int {
	return self.refusedCount
}

// Closes every listener it serves on. A unit's own copy of a socket stays with the unit.
func (self *GatewayListener) Close() {
	for _, listener := range self.listeners {
		listener.Close()
	}
}

// The guard every request passes before any handler: see the file header.
type gatewayGuard struct {
	settings *GatewaySettings
	// lowercase Host values the listener answers
	allowedHosts map[string]bool
	// one entry per request in flight
	slots chan struct{}
	next  http.Handler
}

// The guard over next for the listener at port.
func newGatewayGuard(settings *GatewaySettings, port int, next http.Handler) *gatewayGuard {
	portText := strconv.Itoa(port)
	return &gatewayGuard{
		settings: settings,
		allowedHosts: map[string]bool{
			net.JoinHostPort(gatewayLoopbackIpv4, portText):  true,
			net.JoinHostPort(gatewayLocalhostName, portText): true,
			net.JoinHostPort(gatewayLoopbackIpv6, portText):  true,
		},
		slots: make(chan struct{}, max(0, settings.ConcurrentRequestCount)),
		next:  next,
	}
}

// See the file header for the order.
func (self *gatewayGuard) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer = &gatewayNoCorsWriter{writer: writer}
	if !self.allowedHosts[strings.ToLower(request.Host)] {
		writeGatewayGuardError(writer, http.StatusMisdirectedRequest, gatewayGuardErrorMisrouted,
			"this listener answers only 127.0.0.1, localhost and [::1] at its port")
		return
	}
	if 0 < len(request.Header.Values(gatewayHeaderOrigin)) {
		writeGatewayGuardError(writer, http.StatusForbidden, gatewayGuardErrorBrowser, "a request from a web page is refused")
		return
	}
	if fetchSites := request.Header.Values(gatewayHeaderSecFetchSite); 0 < len(fetchSites) &&
		(len(fetchSites) != 1 || !strings.EqualFold(strings.TrimSpace(fetchSites[0]), gatewaySecFetchSiteNone)) {
		writeGatewayGuardError(writer, http.StatusForbidden, gatewayGuardErrorBrowser, "a request from a web page is refused")
		return
	}
	if self.settings.RequestByteCount < request.ContentLength {
		writeGatewayGuardError(writer, http.StatusRequestEntityTooLarge, gatewayGuardErrorTooLarge,
			fmt.Sprintf("a request's body is at most %d bytes", self.settings.RequestByteCount))
		return
	}
	select {
	case self.slots <- struct{}{}:
	default:
		writer.Header().Set("Retry-After", strconv.FormatInt(int64(max(time.Second, self.settings.BusyRetryAfter)/time.Second), 10))
		writeGatewayGuardError(writer, http.StatusTooManyRequests, gatewayGuardErrorBusy,
			fmt.Sprintf("the gateway serves %d requests at once", self.settings.ConcurrentRequestCount))
		return
	}
	defer func() { <-self.slots }()
	if request.Body != nil {
		request.Body = http.MaxBytesReader(writer, request.Body, max(0, self.settings.RequestByteCount))
	}
	self.next.ServeHTTP(writer, request)
}

// The guard's refusals, in a shape every front's harness reads as an error: an error object with a code and a message.
func writeGatewayGuardError(writer http.ResponseWriter, status int, code string, message string) {
	encoded, _ := json.Marshal(map[string]any{"error": map[string]string{"type": code, "code": code, "message": message}})
	writer.Header().Set("Content-Type", gatewayGuardContentType)
	writer.WriteHeader(status)
	writer.Write(encoded)
}

// A writer that never sends a CORS header, whatever a handler sets: each is dropped before the header goes out.
type gatewayNoCorsWriter struct {
	writer      http.ResponseWriter
	wroteHeader bool
}

// See http.ResponseWriter.
func (self *gatewayNoCorsWriter) Header() http.Header {
	return self.writer.Header()
}

// Drops every CORS header, once, before the first byte of the answer.
func (self *gatewayNoCorsWriter) stripWithHeader() {
	if self.wroteHeader {
		return
	}
	self.wroteHeader = true
	header := self.writer.Header()
	for name := range header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), gatewayCorsHeaderPrefix) {
			delete(header, name)
		}
	}
}

// See http.ResponseWriter.
func (self *gatewayNoCorsWriter) WriteHeader(status int) {
	self.stripWithHeader()
	self.writer.WriteHeader(status)
}

// See http.ResponseWriter.
func (self *gatewayNoCorsWriter) Write(content []byte) (int, error) {
	self.stripWithHeader()
	return self.writer.Write(content)
}

// See http.Flusher: a stream's front flushes each event.
func (self *gatewayNoCorsWriter) Flush() {
	self.stripWithHeader()
	if flusher, ok := self.writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

// The writer beneath, for http.ResponseController.
func (self *gatewayNoCorsWriter) Unwrap() http.ResponseWriter {
	return self.writer
}
