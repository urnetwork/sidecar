//go:build !sidecar_http && !ios_extension

// §13.7's HTTP front (R-TLS-5, D-TLS-5, I-13, FS-34): one http.Server per endpoint over the front's handshaken
// tls.Conns, h2 or HTTP/1.1 as ALPN chose, and net/http/httputil's ReverseProxy to the local service. Each request,
// in order:
//
//	1  421 unless its Host, :authority and target are the SNI (tls_http_origin.go)
//	2  /.well-known/ur/ is the front's: the callback, the link and the notice; anything else under it is 404, and
//	   none of it reaches the service
//	3  the audience check on the request's counted cookies (tls_audience.go): members without a session reach edge
//	   login and nothing else, a link without its cookie is refused, public passes
//	4  the one-time notice on a Community public endpoint, never on the system publish (tls_http_notice.go)
//	5  the proxy, under the check's pass: the front's own __Host-ur- cookies are stripped, as are every client-sent
//	   Forwarded and X-Forwarded- header (Rewrite's rule); the visitor's address goes only as the service asked, a
//	   Forwarded header or a PROXY v2 header on each target connection; the answer loses its Alt-Svc h3 entries,
//	   since the edge carries no QUIC (D-TLS-10), and any Set-Cookie for the front's cookies
//
// A WebSocket upgrade is a request like any other, so it passes only after the check, and the hijacked stream
// carries bytes only after the target answered it. Each visitor connection has its own target transport, so target
// connections, their PROXY headers and passes never cross visitors. The first request must arrive within
// FirstRequestTimeout of the handshake; later ones within net/http's own RequestHeaderTimeout.
//
// net/http's logs go nowhere, and the front logs no URL, address or cookie (I-13). Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// PROXY protocol version 2 (https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt §2.2): its signature, the
// PROXY command at version 2, and the TCP families.
const (
	tlsProxyV2Signature           = "\r\n\r\n\x00\r\nQUIT\n"
	tlsProxyV2VersionCommandProxy = 0x21
	tlsProxyV2FamilyTcp4          = 0x11
	tlsProxyV2FamilyTcp6          = 0x21
)

// Everything under it is the front's (§13.7): the callback, the link, the notice.
const tlsHttpFrontPathRoot = "/.well-known/ur"

// The ALPN-negotiated HTTP front of one endpoint.
type tlsHttpFront struct {
	front    *TlsFront
	server   *http.Server
	listener *tlsHttpListener
	proxy    *httputil.ReverseProxy
	notice   *tlsHttpNotice
	// each tls.Conn the server holds, to its TlsFrontConn
	tlsConns sync.Map
}

// The HTTP front, serving at once on its own listener. limits reads the network's tier for the notice.
func newTlsHttpFront(front *TlsFront, limits func(ctx context.Context) (*QuotaLimits, error)) *tlsHttpFront {
	self := &tlsHttpFront{
		front:    front,
		listener: newTlsHttpListener(),
		notice:   newTlsHttpNotice(front, limits),
	}
	self.proxy = &httputil.ReverseProxy{
		Rewrite:        self.rewrite,
		Transport:      tlsHttpTargetTransport{},
		ModifyResponse: self.modifyResponse,
		ErrorHandler:   self.proxyError,
		ErrorLog:       log.New(io.Discard, "", 0),
		// what the service sends goes on at once, streams and server-sent events among it
		FlushInterval: -1,
	}
	self.server = &http.Server{
		Handler:                      self,
		ReadHeaderTimeout:            front.settings.RequestHeaderTimeout,
		IdleTimeout:                  front.settings.IdleTimeout,
		MaxHeaderBytes:               front.settings.MaxHeaderByteCount,
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if conn, ok := self.tlsConns.Load(c); ok {
				return context.WithValue(ctx, tlsHttpConnKey{}, conn)
			}
			return ctx
		},
	}
	go self.server.Serve(self.listener)
	return self
}

// Carries a request's TlsFrontConn on its context.
type tlsHttpConnKey struct{}

// The connection a request came on, nil for none.
func tlsHttpConnOf(ctx context.Context) *TlsFrontConn {
	conn, _ := ctx.Value(tlsHttpConnKey{}).(*TlsFrontConn)
	return conn
}

// Hands conn to the server and waits for its stream to end, which bounds its visitor's slot. The first request must
// come within FirstRequestTimeout, or the stream resets with RST_PEER_TIMEOUT.
func (self *tlsHttpFront) serve(conn *TlsFrontConn) {
	stop := self.front.clock.AfterFunc(self.front.settings.FirstRequestTimeout, func() {
		if !conn.requestSeen.Load() {
			conn.reset(protocol.StreamResetCode_RST_PEER_TIMEOUT)
		}
	})
	defer stop()
	self.tlsConns.Store(conn.tlsConn, conn)
	defer self.tlsConns.Delete(conn.tlsConn)
	select {
	case self.listener.conns <- conn.tlsConn:
	case <-self.listener.closed:
		return
	case <-conn.done():
		return
	}
	<-conn.done()
}

// Closes the server and every connection it holds.
func (self *tlsHttpFront) close() {
	self.listener.Close()
	self.server.Close()
}

// One request: see the file header.
func (self *tlsHttpFront) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn := tlsHttpConnOf(r.Context())
	if conn == nil {
		tlsHttpAnswer(w, http.StatusInternalServerError)
		return
	}
	conn.requestSeen.Store(true)
	if !tlsHttpHostMatches(r, conn.ServerName()) {
		tlsHttpAnswer(w, http.StatusMisdirectedRequest)
		return
	}
	view := newTlsHttpSessionView(r, conn.ServerName())
	if tlsHttpFrontPath(r.URL.Path) {
		self.serveFrontPath(w, r, conn, view)
		return
	}
	verdict := self.front.audience.checkHttp(r, conn, view)
	switch verdict.outcome {
	case tlsAudiencePassed:
	case tlsAudienceLogin:
		self.front.login.start(w, r, conn)
		return
	case tlsAudienceUnauthorized:
		tlsHttpAnswer(w, http.StatusUnauthorized)
		return
	default:
		tlsHttpAnswer(w, http.StatusForbidden)
		return
	}
	if self.notice.required(r, verdict.grant, view) {
		self.notice.serve(w, r)
		return
	}
	self.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tlsAudiencePassKey{}, verdict.pass)))
}

// The front's own paths.
func (self *tlsHttpFront) serveFrontPath(w http.ResponseWriter, r *http.Request, conn *TlsFrontConn, view *tlsHttpSessionView) {
	switch r.URL.Path {
	case tlsEdgeLoginCallbackPath:
		self.front.login.callback(w, r, conn, view)
	case tlsLinkPath:
		self.serveLink(w, r, conn)
	case tlsNoticePath:
		self.notice.accept(w, r, view)
	default:
		tlsHttpAnswer(w, http.StatusNotFound)
	}
}

// What reaches the service: the request to the local address, its Host the visitor's, the front's cookies gone, and
// the visitor's address only as Forwarded asks. Rewrite has already dropped every client-sent Forwarded and
// X-Forwarded- header.
func (self *tlsHttpFront) rewrite(proxyRequest *httputil.ProxyRequest) {
	outgoing := proxyRequest.Out
	outgoing.URL.Scheme = "http"
	outgoing.URL.Host = self.front.target.LocalAddress
	outgoing.Host = proxyRequest.In.Host
	outgoing.Header.Del("Host")
	tlsHttpStripFrontCookies(outgoing.Header)
	if self.front.target.Forwarded {
		if pass := tlsAudiencePassOf(proxyRequest.In.Context()); pass != nil {
			outgoing.Header.Set("Forwarded", tlsHttpForwarded(pass.conn.VisitorAddr(), pass.conn.ServerName()))
		}
	}
}

// What reaches the visitor: no Alt-Svc h3 entry and none of the front's cookies.
func (self *tlsHttpFront) modifyResponse(response *http.Response) error {
	tlsHttpStripAltSvcH3(response.Header)
	tlsHttpStripFrontSetCookies(response.Header)
	return nil
}

// A target that failed or refused: 502, naming nothing, and the probe runs early.
func (self *tlsHttpFront) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	self.front.targetRefused()
	tlsHttpAnswer(w, http.StatusBadGateway)
}

// Every request's way to the target: refused without a pass, else the pass's connection's own transport, whose
// dials go through openTarget with the same pass (FI-11).
type tlsHttpTargetTransport struct{}

// See http.RoundTripper.
func (self tlsHttpTargetTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	pass := tlsAudiencePassOf(request.Context())
	if pass == nil || pass.conn == nil {
		return nil, errTlsFrontNoPass
	}
	return pass.conn.targetTransport().RoundTrip(request)
}

// RFC 7239's Forwarded for the visitor, by https, to serverName.
func tlsHttpForwarded(visitor netip.AddrPort, serverName string) string {
	return fmt.Sprintf("for=%q;proto=https;host=%s", visitor.String(), serverName)
}

// PROXY v2's header for a connection from source to the endpoint's port: the destination address is unspecified, as
// the front knows no lb address, in source's family.
func tlsProxyV2Header(source netip.AddrPort, destinationPort uint16) []byte {
	sourceAddr := source.Addr().Unmap()
	family := byte(tlsProxyV2FamilyTcp6)
	destinationAddr := netip.IPv6Unspecified()
	if sourceAddr.Is4() {
		family = tlsProxyV2FamilyTcp4
		destinationAddr = netip.IPv4Unspecified()
	}
	sourceBytes := sourceAddr.AsSlice()
	header := []byte(tlsProxyV2Signature)
	header = append(header, tlsProxyV2VersionCommandProxy, family)
	// both addresses, then both ports
	header = binary.BigEndian.AppendUint16(header, uint16(2*len(sourceBytes)+2*2))
	header = append(header, sourceBytes...)
	header = append(header, destinationAddr.AsSlice()...)
	header = binary.BigEndian.AppendUint16(header, source.Port())
	return binary.BigEndian.AppendUint16(header, destinationPort)
}

// Drops Alt-Svc's h3 entries, h3 and its drafts h3-<n>, from every Alt-Svc header, keeping the rest in order.
func tlsHttpStripAltSvcH3(header http.Header) {
	values := header.Values("Alt-Svc")
	if len(values) == 0 {
		return
	}
	keptAlternatives := []string{}
	for _, value := range values {
		for _, alternative := range tlsHttpSplitAltSvc(value) {
			protocolId, _, _ := strings.Cut(alternative, "=")
			protocolId = strings.ToLower(strings.TrimSpace(protocolId))
			if unescaped, err := url.PathUnescape(protocolId); err == nil {
				protocolId = unescaped
			}
			if protocolId == "h3" || strings.HasPrefix(protocolId, "h3-") {
				continue
			}
			keptAlternatives = append(keptAlternatives, alternative)
		}
	}
	header.Del("Alt-Svc")
	if 0 < len(keptAlternatives) {
		header.Set("Alt-Svc", strings.Join(keptAlternatives, ", "))
	}
}

// One Alt-Svc value's alternatives, split at commas outside quoted strings, each trimmed.
func tlsHttpSplitAltSvc(value string) []string {
	alternatives := []string{}
	quoted := false
	escaped := false
	start := 0
	for i := 0; i < len(value); i += 1 {
		switch {
		case escaped:
			escaped = false
		case quoted && value[i] == '\\':
			escaped = true
		case value[i] == '"':
			quoted = !quoted
		case !quoted && value[i] == ',':
			if alternative := strings.TrimSpace(value[start:i]); alternative != "" {
				alternatives = append(alternatives, alternative)
			}
			start = i + 1
		}
	}
	if alternative := strings.TrimSpace(value[start:]); alternative != "" {
		alternatives = append(alternatives, alternative)
	}
	return alternatives
}

// Whether a path is the front's own, under /.well-known/ur/, cleaned or not, so no spelling of it reaches the
// service.
func tlsHttpFrontPath(requestPath string) bool {
	for _, candidate := range []string{requestPath, path.Clean("/" + requestPath)} {
		if candidate == tlsHttpFrontPathRoot || strings.HasPrefix(candidate, tlsHttpFrontPathRoot+"/") {
			return true
		}
	}
	return false
}

// An answer from the front itself, its text the status's, naming nothing it read.
func tlsHttpAnswer(w http.ResponseWriter, status int) {
	header := w.Header()
	header.Set("Content-Type", "text/plain; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	fmt.Fprintln(w, http.StatusText(status))
}

// The server's listener: the front hands it each handshaken connection.
type tlsHttpListener struct {
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

var _ net.Listener = (*tlsHttpListener)(nil)

// An open listener.
func newTlsHttpListener() *tlsHttpListener {
	return &tlsHttpListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

// See net.Listener.
func (self *tlsHttpListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

// See net.Listener. A second Close does nothing.
func (self *tlsHttpListener) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
	})
	return nil
}

// See net.Listener: ids alone (I-13).
func (self *tlsHttpListener) Addr() net.Addr {
	return &SocketAddr{}
}
