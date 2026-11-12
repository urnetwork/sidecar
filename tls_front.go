//go:build !sidecar_http && !ios_extension

// §13.7's TLS front (R-TLS-4, R-TLS-5, R-TLS-7, D-TLS-5, D-TLS-13, X1, I-5): TLS ends here, in the listening sidecar,
// on the device key (§13.8), for one tls/ registration's streams. tlsedge routed each visitor's ClientHello by SNI
// without terminating it (§13.5), and the front runs crypto/tls over the SocketConn the listener admitted (§9.6), so
// the edge sees only records and the key never leaves this device. early_data is the hello's first bytes, so the
// handshake reads the stream from its first byte and nothing precedes it.
//
// Each accepted stream goes through, in order:
//
//	1  the ticket's dialer_network_id is urnetwork-edge, the open's metadata a TlsEdgeOpen whose expiry is the
//	   ticket's grant expiry and whose server name this endpoint serves; anything else resets (§13.5's last line)
//	2  the visitor's /64 or /32 holds below its share of the endpoint's max_streams (tls_front_limits.go)
//	3  the handshake within HandshakeTimeout, TLS 1.2 or 1.3, X25519MLKEM768 first, dispatched by the signed
//	   registration's AppMode and never by ALPN's absence (tls_dispatch.go, D-TLS-13)
//	4  by route: acme-tls/1 to the responder, which answers in the handshake and closes (tls_alpn_responder.go);
//	   raw to the forward (tls_raw.go); http to the HTTP front (tls_http.go)
//
// FI-11 is built into TlsFrontConn: its only way to the target is openTarget, which takes the pass only
// tlsAudienceCheck gives, for that connection, so whatever the ALPN no application byte reaches the local service
// before its audience check. The audience comes from this device's own evaluation of its config (TlsFrontPolicy),
// never from the ticket or a server's answer. A modified sidecar skips all of it (§21.4), so the front makes no claim
// to any server.
//
// The target drives serving: while the local service refuses connections the listener takes no tickets (§9.9's
// SetServing), so tlsedge tries a backup rather than a target that refuses. A probe connects and closes, carrying no
// byte.
//
// Nothing here logs a name, an address or a URL (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The open is not one the front trusts or can serve: a ticket from another dialer, metadata that is no
	// TlsEdgeOpen, or a server name this endpoint does not serve.
	errTlsFrontUntrusted = errors.New("tls front refused the open")
	// A dial of the target without the pass of an audience check for this connection (FI-11).
	errTlsFrontNoPass = errors.New("tls front target needs an audience pass")
	// The target is not one the front can forward to.
	errTlsFrontTarget = fmt.Errorf("%w: a tls front target", errInvalidSettings)
)

// §13.7's limits on one endpoint, defaults as the design gives them or, where it gives none, as each field says.
// A front refuses settings whose times or counts are not positive, but where a field says otherwise.
type TlsFrontSettings struct {
	// From a stream's accept to the handshake's end: 10 s (§13.7's slow visitors row). Past it the stream resets
	// with RST_PEER_TIMEOUT.
	HandshakeTimeout time.Duration
	// From the handshake's end to an HTTP visitor's first request: 30 s (§13.7). Past it the stream resets with
	// RST_PEER_TIMEOUT.
	FirstRequestTimeout time.Duration
	// One visitor holds at most 1 / this of the endpoint's max_streams: 8 (§13.7), and at least one stream.
	VisitorShareDivisor int
	// A visitor is its address's /32 on IPv4 (§13.7).
	VisitorIpv4PrefixBitCount int
	// And its /64 on IPv6 (§13.7).
	VisitorIpv6PrefixBitCount int
	// The longest one dial of the local service takes before it counts as refusing: 5 s, a reading.
	TargetDialTimeout time.Duration
	// How often the front probes the local service for serving: 10 s, a reading. Non-positive disables the probe,
	// and serving stays as the listener began.
	TargetProbeInterval time.Duration
	// The least time between two probes, so a run of failing dials probes at most this often: 1 s, a reading.
	TargetProbeMinInterval time.Duration
	// net/http's bound on a request's headers after the first request, which FirstRequestTimeout bounds: 30 s,
	// a reading.
	RequestHeaderTimeout time.Duration
	// How long an idle HTTP connection, the visitor's or the target's, stays open: 5 min, a reading inside the lb's
	// 15 min stream idle (§13.3).
	IdleTimeout time.Duration
	// The most a request's headers take: 64 KiB, a reading.
	MaxHeaderByteCount int
	// Idle connections to the target one visitor's connection keeps: 4, a reading. Connections are never shared
	// between visitors, so a PROXY header and the pass stay one visitor's.
	TargetIdleConnectionCount int
	// How far before its making a TLS-ALPN-01 certificate's validity starts, for a validator whose clock runs
	// behind: 1 h, a reading.
	ChallengeBackdate time.Duration

	// A members session's life: 12 h (§7.8).
	SessionLifetime time.Duration
	// A pending edge login's life, its state and its __Host-ur-pre cookie: 10 min, a reading.
	PreLoginLifetime time.Duration
	// Pending edge logins one endpoint holds; past it the oldest is dropped: 4,096, a reading.
	PendingLoginMaxCount int
	// The longest life an ID token may claim, exp less iat: 5 min, a reading past the issuer's 60 s (§7.8).
	IdTokenMaxLifetime time.Duration
	// How far the issuer's clock may run from this device's on an ID token's times: 1 min, a reading.
	IdTokenClockSkew time.Duration
	// One call to the issuer, a code's redemption or a JWKS fetch: 10 s, a reading.
	IssuerRequestTimeout time.Duration
	// The most of an issuer's answer the front reads: 64 KiB, a reading past any token or key set it answers.
	IssuerResponseMaxByteCount int64
	// How long the issuer's id- key set is used before it is fetched again: 1 h, a reading.
	JwksLifetime time.Duration
	// The least time between two fetches of the key set, so tokens under unknown kids fetch at most this often:
	// 1 min, a reading.
	JwksRefetchMinInterval time.Duration
	// The longest path and query a login returns the visitor to; a longer one returns to /: 2 KiB, a reading.
	ReturnPathMaxByteCount int

	// A __Host-ur-link cookie's life, capped by its token's expiry: 12 h (QD-134).
	LinkCookieLifetime time.Duration
	// The most a link token's Signed takes: 1 KiB, a reading past a TlsLinkToken's ~200 B.
	LinkTokenMaxByteCount int

	// How long a visitor's acceptance of the Community notice is kept: 30 days, a reading.
	NoticeLifetime time.Duration
	// How long the network's tier is used before it is read again, for the notice: 5 min, a reading.
	LimitsCacheTimeout time.Duration
	// One read of the network's tier: 5 s, a reading. One that fails reads as Community, which shows the notice.
	LimitsRequestTimeout time.Duration
}

// A fresh value each call.
func DefaultTlsFrontSettings() *TlsFrontSettings {
	return &TlsFrontSettings{
		HandshakeTimeout:           10 * time.Second,
		FirstRequestTimeout:        30 * time.Second,
		VisitorShareDivisor:        8,
		VisitorIpv4PrefixBitCount:  32,
		VisitorIpv6PrefixBitCount:  64,
		TargetDialTimeout:          5 * time.Second,
		TargetProbeInterval:        10 * time.Second,
		TargetProbeMinInterval:     1 * time.Second,
		RequestHeaderTimeout:       30 * time.Second,
		IdleTimeout:                5 * time.Minute,
		MaxHeaderByteCount:         64 * 1024,
		TargetIdleConnectionCount:  4,
		ChallengeBackdate:          1 * time.Hour,
		SessionLifetime:            12 * time.Hour,
		PreLoginLifetime:           10 * time.Minute,
		PendingLoginMaxCount:       4096,
		IdTokenMaxLifetime:         5 * time.Minute,
		IdTokenClockSkew:           1 * time.Minute,
		IssuerRequestTimeout:       10 * time.Second,
		IssuerResponseMaxByteCount: 64 * 1024,
		JwksLifetime:               1 * time.Hour,
		JwksRefetchMinInterval:     1 * time.Minute,
		ReturnPathMaxByteCount:     2 * 1024,
		LinkCookieLifetime:         12 * time.Hour,
		LinkTokenMaxByteCount:      1024,
		NoticeLifetime:             30 * 24 * time.Hour,
		LimitsCacheTimeout:         5 * time.Minute,
		LimitsRequestTimeout:       5 * time.Second,
	}
}

// Refuses what the front cannot run on.
func (self *TlsFrontSettings) validate() error {
	positiveTimes := []time.Duration{
		self.HandshakeTimeout, self.FirstRequestTimeout, self.TargetDialTimeout, self.TargetProbeMinInterval,
		self.RequestHeaderTimeout, self.IdleTimeout, self.ChallengeBackdate, self.SessionLifetime, self.PreLoginLifetime,
		self.IdTokenMaxLifetime, self.IssuerRequestTimeout, self.JwksLifetime, self.JwksRefetchMinInterval,
		self.LinkCookieLifetime, self.NoticeLifetime, self.LimitsCacheTimeout, self.LimitsRequestTimeout,
	}
	for _, positiveTime := range positiveTimes {
		if positiveTime <= 0 {
			return fmt.Errorf("%w: a tls front time is positive", errInvalidSettings)
		}
	}
	switch {
	case self.IdTokenClockSkew < 0:
		return fmt.Errorf("%w: a clock skew is not negative", errInvalidSettings)
	case self.VisitorShareDivisor < 1, self.MaxHeaderByteCount < 1, self.TargetIdleConnectionCount < 1,
		self.PendingLoginMaxCount < 1, self.IssuerResponseMaxByteCount < 1, self.ReturnPathMaxByteCount < 1,
		self.LinkTokenMaxByteCount < 1:
		return fmt.Errorf("%w: a tls front count is positive", errInvalidSettings)
	case self.VisitorIpv4PrefixBitCount < 1 || 32 < self.VisitorIpv4PrefixBitCount,
		self.VisitorIpv6PrefixBitCount < 1 || 128 < self.VisitorIpv6PrefixBitCount:
		return fmt.Errorf("%w: a visitor prefix fits its family", errInvalidSettings)
	}
	return nil
}

// One endpoint as the front serves it: the signed registration's name and mode, the names visitors reach it by, and
// the local service behind it.
type TlsFrontTarget struct {
	// The registration's name, tls/<port>/<host> (§9.4).
	Name string
	// The DNS names visitors reach it by, lowercase: <host>.<net>.<root>, or <net>.<root> for @, and each live
	// alias's (§13.5). A hello's SNI is one of them, or the front refuses it.
	ServerNames []string
	// The signed registration's AppMode (§9.5): "http", the default, or "raw".
	AppMode string
	// raw: the ALPN ids the forward takes besides none.
	Alpn []string
	// The local service, <local ip>:<local port> (§13.10).
	LocalAddress string
	// A PROXY v2 header with the visitor's address ahead of each connection's bytes (§13.7's visitor address row).
	ProxyProtocol bool
	// http: a Forwarded header with the visitor's address on each request.
	Forwarded bool
	// The registration's max_streams, whose share one visitor may hold. 0 takes §9.5's 256.
	MaxStreams int
	// §13.9's system publish of tls/443/mta-sts, which never shows the Community notice.
	SystemPublish bool
}

// --proxy-protocol's behavior (§13.10, a reading): a PROXY v2 header on raw, a Forwarded header on http, where the
// service reads requests. Either is off without the flag, so the visitor's address reaches the service only on
// request.
func TlsFrontVisitorAddressOptions(appMode string, proxyProtocol bool) (proxyV2 bool, forwarded bool) {
	if !proxyProtocol {
		return false, false
	}
	if appMode == socketListenTlsAppModeRaw {
		return true, false
	}
	return false, true
}

// A checked copy of target, its defaults applied and its names lowercase.
func newTlsFrontTarget(target *TlsFrontTarget) (*TlsFrontTarget, error) {
	if target == nil {
		return nil, errTlsFrontTarget
	}
	copied := *target
	copied.ServerNames = make([]string, 0, len(target.ServerNames))
	for _, serverName := range target.ServerNames {
		serverName = strings.ToLower(serverName)
		if !tlsDnsNameCanonical(serverName) {
			return nil, fmt.Errorf("%w: a server name", errTlsFrontTarget)
		}
		copied.ServerNames = append(copied.ServerNames, serverName)
	}
	copied.Alpn = slices.Clone(target.Alpn)
	if copied.AppMode == "" {
		copied.AppMode = socketListenDefaultTlsAppMode
	}
	if copied.MaxStreams == 0 {
		copied.MaxStreams = socketListenDefaultMaxStreams
	}
	name, namespace, err := ParseSocketName(copied.Name)
	if err != nil || namespace != SocketNamespaceTls {
		return nil, fmt.Errorf("%w: a tls/<port>/<host> name", errTlsFrontTarget)
	}
	copied.Name = name
	switch {
	case len(copied.ServerNames) == 0:
		return nil, fmt.Errorf("%w: no server name", errTlsFrontTarget)
	case copied.AppMode != socketListenDefaultTlsAppMode && copied.AppMode != socketListenTlsAppModeRaw:
		return nil, fmt.Errorf("%w: an app mode is http or raw", errTlsFrontTarget)
	case copied.AppMode == socketListenDefaultTlsAppMode && 0 < len(copied.Alpn):
		return nil, fmt.Errorf("%w: http serves h2 and http/1.1 alone", errTlsFrontTarget)
	case copied.AppMode == socketListenTlsAppModeRaw && copied.Forwarded:
		return nil, fmt.Errorf("%w: a Forwarded header is http's", errTlsFrontTarget)
	case slices.Contains(copied.Alpn, tlsAlpnAcme), slices.Contains(copied.Alpn, ""):
		return nil, fmt.Errorf("%w: an ALPN id", errTlsFrontTarget)
	case copied.MaxStreams < 1:
		return nil, fmt.Errorf("%w: max_streams", errTlsFrontTarget)
	}
	if _, err := netip.ParseAddrPort(copied.LocalAddress); err != nil {
		return nil, fmt.Errorf("%w: a local ip and port", errTlsFrontTarget)
	}
	return &copied, nil
}

// The host the name publishes, its last segment (§13.9's dns:<host>).
func (self *TlsFrontTarget) host() string {
	return socketTlsHost(self.Name)
}

// The port the name listens on.
func (self *TlsFrontTarget) port() uint16 {
	segments, err := socketSegments(self.Name)
	if err != nil || len(segments) != 3 {
		return 0
	}
	port, err := strconv.ParseUint(segments[1], 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}

// Whether visitors reach this endpoint by serverName, lowercase.
func (self *TlsFrontTarget) serves(serverName string) bool {
	return slices.Contains(self.ServerNames, serverName)
}

// What the front accepts from: a SocketListener on a tls/ name (Sidecar.Listen), or a test's queue.
type tlsFrontListener interface {
	AcceptSocket(ctx context.Context) (*SocketConn, error)
	SetServing(serving bool)
	Close() error
	// The urnetwork-edge network as the registrar's newest answer names it, which admission's step 3 held the
	// ticket to; false before an answer names it.
	tlsEdgeNetworkId() (Id, bool)
}

// See tlsFrontListener.
func (self *SocketListener) tlsEdgeNetworkId() (Id, bool) {
	admission := self.component.registrar.admission()
	if admission == nil || admission.urnetworkEdge == nil {
		return Id{}, false
	}
	return *admission.urnetworkEdge, true
}

// What NewTlsFront takes.
type TlsFrontArgs struct {
	// Nil takes DefaultTlsFrontSettings.
	Settings *TlsFrontSettings
	Target   *TlsFrontTarget
	// The registration's listener, which the front owns from here: its Close closes it.
	Listener tlsFrontListener
	// This sidecar's network and sidecar, the subject of the endpoint's own grant.
	NetworkId Id
	SidecarId Id
	// This device's own evaluation of its config (NewTlsFrontConfigPolicy).
	Policy TlsFrontPolicy
	// The certificate this device presents for a visitor's server name, on its own key (Sidecar.TlsDeviceCertificate
	// for the names that cover it).
	Certificate func(serverName string) (*tls.Certificate, error)
	// The tls namespace of this network's keychain.ur, which holds the key sessions are sealed under.
	Secrets SidecarSecrets
	// The edge-login issuer, SidecarSettings.AuthUrl: absolute, no trailing slash. Empty refuses every members login.
	IssuerUrl string
	// What reaches the issuer. Nil takes a client of its own.
	IssuerClient *http.Client
	// GET /sidecar/limits, which says whether the network is on Community, for the notice. Nil reads as Community.
	Limits func(ctx context.Context) (*QuotaLimits, error)
	// Dials the local service. Nil dials Target.LocalAddress over TCP.
	DialTarget func(ctx context.Context) (net.Conn, error)
	// Called when the registration's ALPN list changes, as a TLS-ALPN-01 challenge starts or ends, so the owner
	// registers again with ListenSettings. Nil: nothing to tell.
	AlpnChanged func()
	// Nil is real time.
	Clock Clock
	// Nil is the default logger.
	Log Logger
}

// §13.7's front for one endpoint. NewTlsFront makes one, running.
type TlsFront struct {
	ctx         context.Context
	cancel      context.CancelFunc
	settings    *TlsFrontSettings
	target      *TlsFrontTarget
	listener    tlsFrontListener
	networkId   Id
	sidecarId   Id
	policy      TlsFrontPolicy
	certificate func(serverName string) (*tls.Certificate, error)
	dialTarget  func(ctx context.Context) (net.Conn, error)
	alpnChanged func()
	clock       Clock
	log         Logger

	dispatch  *tlsDispatch
	responder *tlsAlpnResponder
	visitors  *tlsFrontVisitors
	audience  *tlsAudienceCheck
	sessions  *tlsSessionSealer
	login     *tlsEdgeLogin
	http      *tlsHttpFront
	// a visitor's dial failed, so the probe runs early
	probeWake chan struct{}

	stateLock sync.Mutex
	closed    bool
	// what the front last told the listener, true as the listener begins
	serving   bool
	liveConns map[*TlsFrontConn]bool
}

// A front on args' listener, accepting at once. Settings, target and args are checked first, and nothing runs when
// one is refused.
func NewTlsFront(ctx context.Context, args *TlsFrontArgs) (*TlsFront, error) {
	if args == nil || args.Listener == nil || args.Policy == nil || args.Certificate == nil || args.Secrets == nil {
		return nil, fmt.Errorf("%w: a tls front needs its listener, policy, certificate and secrets", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultTlsFrontSettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	target, err := newTlsFrontTarget(args.Target)
	if err != nil {
		return nil, err
	}
	sessions, err := newTlsSessionSealer(args.Secrets, args.NetworkId)
	if err != nil {
		return nil, err
	}
	dialTarget := args.DialTarget
	if dialTarget == nil {
		localAddress := target.LocalAddress
		dialTarget = func(ctx context.Context) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "tcp", localAddress)
		}
	}
	alpnChanged := args.AlpnChanged
	if alpnChanged == nil {
		alpnChanged = func() {}
	}
	frontCtx, cancel := context.WithCancel(ctx)
	self := &TlsFront{
		ctx:         frontCtx,
		cancel:      cancel,
		settings:    settings,
		target:      target,
		listener:    args.Listener,
		networkId:   args.NetworkId,
		sidecarId:   args.SidecarId,
		policy:      args.Policy,
		certificate: args.Certificate,
		dialTarget:  dialTarget,
		alpnChanged: alpnChanged,
		clock:       clockOrReal(args.Clock),
		log:         loggerOrDefault(args.Log),
		sessions:    sessions,
		probeWake:   make(chan struct{}, 1),
		serving:     true,
		liveConns:   map[*TlsFrontConn]bool{},
	}
	self.dispatch = &tlsDispatch{front: self}
	self.responder = newTlsAlpnResponder(self.clock, settings, self.alpnChallengeChanged)
	self.visitors = newTlsFrontVisitors(settings, target.MaxStreams)
	self.audience = &tlsAudienceCheck{front: self}
	self.login = newTlsEdgeLogin(self, args.IssuerUrl, args.IssuerClient)
	self.http = newTlsHttpFront(self, args.Limits)
	go self.run()
	go self.runProbe()
	return self, nil
}

// The listen settings the registration takes now (§9.5, §13.7): protocol tls, the signed AppMode, max_streams, and
// the ALPN ids the mode serves, acme-tls/1 among them while a TLS-ALPN-01 challenge is pending.
func (self *TlsFront) ListenSettings() *SocketListenSettings {
	return TlsFrontListenSettings(self.target, self.responder.pending(self.clock.Now()))
}

// The listen settings for target, with acme-tls/1 while a challenge is pending.
func TlsFrontListenSettings(target *TlsFrontTarget, challengePending bool) *SocketListenSettings {
	appMode := target.AppMode
	if appMode == "" {
		appMode = socketListenDefaultTlsAppMode
	}
	alpns := []string{}
	if appMode == socketListenDefaultTlsAppMode {
		alpns = append(alpns, tlsAlpnH2, tlsAlpnHttp11)
	} else {
		alpns = append(alpns, target.Alpn...)
	}
	if challengePending {
		alpns = append(alpns, tlsAlpnAcme)
	}
	return &SocketListenSettings{
		Protocol:   socketListenTlsProtocol,
		Alpn:       alpns,
		AppMode:    appMode,
		MaxStreams: target.MaxStreams,
	}
}

// Sets a pending TLS-ALPN-01 challenge for one of the endpoint's server names (RFC 8737), answered until expireTime
// or ClearAlpnChallenge: keyAuthorization is the ACME token's key authorization, whose digest the certificate
// carries. The registration's ALPN gains acme-tls/1 (AlpnChanged).
func (self *TlsFront) SetAlpnChallenge(serverName string, keyAuthorization string, expireTime time.Time) error {
	serverName = strings.ToLower(serverName)
	if !self.target.serves(serverName) {
		return fmt.Errorf("%w: a challenge for a name this endpoint serves", errInvalidSettings)
	}
	return self.responder.set(serverName, keyAuthorization, expireTime)
}

// Ends a pending challenge, if there is one.
func (self *TlsFront) ClearAlpnChallenge(serverName string) {
	self.responder.clear(strings.ToLower(serverName))
}

// The responder's pending set moved between some and none.
func (self *TlsFront) alpnChallengeChanged() {
	self.alpnChanged()
}

// Stops accepting, closes the listener and every connection, and ends the HTTP front. A second Close does nothing.
func (self *TlsFront) Close() error {
	conns, first := func() ([]*TlsFrontConn, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return nil, false
		}
		self.closed = true
		conns := make([]*TlsFrontConn, 0, len(self.liveConns))
		for conn := range self.liveConns {
			conns = append(conns, conn)
		}
		return conns, true
	}()
	if !first {
		return nil
	}
	self.cancel()
	err := self.listener.Close()
	self.http.close()
	for _, conn := range conns {
		conn.reset(protocol.StreamResetCode_RST_CANCELLED)
	}
	return err
}

// Accepts until the listener closes or the front does.
func (self *TlsFront) run() {
	for {
		socketConn, err := self.listener.AcceptSocket(self.ctx)
		if err != nil {
			return
		}
		go self.serve(socketConn)
	}
}

// One stream, from step 1 to its end.
func (self *TlsFront) serve(socketConn *SocketConn) {
	open, code := self.trust(socketConn)
	if code != protocol.StreamResetCode_RST_UNSPECIFIED {
		socketConn.reset(code)
		return
	}
	release, ok := self.visitors.take(open.GetClientIp())
	if !ok {
		socketConn.reset(protocol.StreamResetCode_RST_CANCELLED)
		return
	}
	defer release()
	conn := newTlsFrontConn(self, socketConn, open)
	if !self.track(conn) {
		socketConn.reset(protocol.StreamResetCode_RST_CANCELLED)
		return
	}
	defer self.untrack(conn)
	defer conn.close()
	if !conn.handshake(self.ctx) {
		return
	}
	switch conn.route {
	case tlsFrontRouteRaw:
		self.serveRaw(conn)
	case tlsFrontRouteHttp:
		self.http.serve(conn)
	}
	// tlsFrontRouteAcme: the responder answered in the handshake, and the validator closes, as this end does
}

// Step 1: the open's metadata as TlsEdgeOpen, trusted only from a ticket whose dialer is urnetwork-edge, which
// admission's step 3 checked against the session's source (§9.6), with its grant expiry and a server name this
// endpoint serves. The code to reset with otherwise.
func (self *TlsFront) trust(socketConn *SocketConn) (*protocol.TlsEdgeOpen, protocol.StreamResetCode) {
	edgeNetworkId, known := self.listener.tlsEdgeNetworkId()
	ticket := socketConn.Ticket()
	if !known || ticket == nil || !bytes.Equal(ticket.GetDialerNetworkId(), edgeNetworkId.Bytes()) {
		return nil, protocol.StreamResetCode_RST_IDENTITY
	}
	open, err := ParseTlsEdgeOpen(socketConn.OpenMetadata())
	if err != nil {
		return nil, protocol.StreamResetCode_RST_PROTOCOL
	}
	if open.GetExpireTimeMillis() != ticket.GetGrantExpireTimeMillis() || !self.target.serves(open.GetServerName()) {
		return nil, protocol.StreamResetCode_RST_PROTOCOL
	}
	return open, protocol.StreamResetCode_RST_UNSPECIFIED
}

// Counts conn among the live ones, false once the front closed.
func (self *TlsFront) track(conn *TlsFrontConn) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return false
	}
	self.liveConns[conn] = true
	return true
}

// Takes conn out of the live ones.
func (self *TlsFront) untrack(conn *TlsFrontConn) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.liveConns, conn)
}

// A dial of the target failed, so the probe runs now rather than at its interval.
func (self *TlsFront) targetRefused() {
	select {
	case self.probeWake <- struct{}{}:
	default:
	}
}

// Probes the target until the front closes: serving follows whether it accepts a connection (§9.9's SetServing).
func (self *TlsFront) runProbe() {
	if self.settings.TargetProbeInterval <= 0 {
		return
	}
	for {
		self.setServing(self.probeTarget())
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.settings.TargetProbeMinInterval):
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.settings.TargetProbeInterval - self.settings.TargetProbeMinInterval):
		case <-self.probeWake:
		}
	}
}

// Whether the target accepts a connection, which closes at once with no byte sent.
func (self *TlsFront) probeTarget() bool {
	ctx, cancel := context.WithCancel(self.ctx)
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.TargetDialTimeout, cancel)
	defer stop()
	target, err := self.dialTarget(ctx)
	if err != nil {
		return false
	}
	target.Close()
	return true
}

// Tells the listener, when it changed.
func (self *TlsFront) setServing(serving bool) {
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed || self.serving == serving {
			return false
		}
		self.serving = serving
		return true
	}()
	if changed {
		self.listener.SetServing(serving)
	}
}

// The stream under a visitor's tls.Conn: its SocketConn, closing once whichever way it ends, so the front knows when a
// connection the HTTP front or a hijack holds has ended.
type tlsFrontStream struct {
	*SocketConn
	endOnce sync.Once
	// closed once the stream has ended
	done chan struct{}
}

var _ net.Conn = (*tlsFrontStream)(nil)

// Marks the stream ended.
func (self *tlsFrontStream) end() {
	self.endOnce.Do(func() {
		close(self.done)
	})
}

// See net.Conn. The stream ends.
func (self *tlsFrontStream) Close() error {
	defer self.end()
	return self.SocketConn.Close()
}

// How one handshake routed.
type tlsFrontRoute int

const (
	// Not routed: the handshake failed or has not finished.
	tlsFrontRouteNone tlsFrontRoute = iota
	// acme-tls/1, to the responder.
	tlsFrontRouteAcme
	// AppMode http, to the HTTP front.
	tlsFrontRouteHttp
	// AppMode raw, to the forward.
	tlsFrontRouteRaw
)

// One visitor's connection through the front: its stream, what the edge said of the visitor, and the handshake.
// The only way from it to the target is openTarget, which takes the pass only tlsAudienceCheck gives for this
// connection (FI-11). Safe for concurrent use once the handshake has ended.
type TlsFrontConn struct {
	front  *TlsFront
	stream *tlsFrontStream
	open   *protocol.TlsEdgeOpen
	// hex of connection_id: the barriers' key, opaque and random (I-13)
	barrierKey string
	tlsConn    *tls.Conn
	// written by dispatch during the handshake, on the handshake's goroutine, and read only after it
	route      tlsFrontRoute
	serverName string
	// an HTTP request has arrived, which stops the first-request bound
	requestSeen atomic.Bool

	transportOnce sync.Once
	transport     *http.Transport
}

// A connection over socketConn for open, its handshake not begun.
func newTlsFrontConn(front *TlsFront, socketConn *SocketConn, open *protocol.TlsEdgeOpen) *TlsFrontConn {
	stream := &tlsFrontStream{SocketConn: socketConn, done: make(chan struct{})}
	conn := &TlsFrontConn{
		front:      front,
		stream:     stream,
		open:       open,
		barrierKey: hex.EncodeToString(open.GetConnectionId()),
	}
	conn.tlsConn = tls.Server(stream, front.dispatch.config(conn))
	return conn
}

// Runs the handshake within HandshakeTimeout, resetting the stream with RST_PEER_TIMEOUT past it. Whether it ended
// in time and routed.
func (self *TlsFrontConn) handshake(ctx context.Context) bool {
	timedOut := atomic.Bool{}
	stop := self.front.clock.AfterFunc(self.front.settings.HandshakeTimeout, func() {
		timedOut.Store(true)
		self.reset(protocol.StreamResetCode_RST_PEER_TIMEOUT)
	})
	err := self.tlsConn.HandshakeContext(ctx)
	stop()
	return err == nil && !timedOut.Load() && self.route != tlsFrontRouteNone
}

// The SNI the handshake took, lowercase: one of the endpoint's server names.
func (self *TlsFrontConn) ServerName() string {
	return self.serverName
}

// The handshake's state.
func (self *TlsFrontConn) ConnectionState() tls.ConnectionState {
	return self.tlsConn.ConnectionState()
}

// The visitor's address as the edge saw it (TlsEdgeOpen's client_ip and client_port): for a PROXY or Forwarded
// header the service asked for, and never for a log or a record (I-13).
func (self *TlsFrontConn) VisitorAddr() netip.AddrPort {
	addr, ok := netip.AddrFromSlice(self.open.GetClientIp())
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(self.open.GetClientPort()))
}

// A copy of the edge's connection_id, which joins abuse reports for 24 h (§13.9).
func (self *TlsFrontConn) ConnectionId() []byte {
	return bytes.Clone(self.open.GetConnectionId())
}

// The ended channel: closed once the stream has ended, however.
func (self *TlsFrontConn) done() <-chan struct{} {
	return self.stream.done
}

// Resets the stream with code: both directions end at once.
func (self *TlsFrontConn) reset(code protocol.StreamResetCode) {
	self.stream.SocketConn.reset(code)
	self.stream.end()
	self.closeTransport()
}

// Sends close_notify and closes the stream.
func (self *TlsFrontConn) close() {
	self.tlsConn.Close()
	self.stream.end()
	self.closeTransport()
}

// Ends this direction: close_notify, then the stream's FIN, reading on.
func (self *TlsFrontConn) closeWrite() {
	self.tlsConn.CloseWrite()
	self.stream.SocketConn.CloseWrite()
}

// The target, through pass, the audience check's for this connection (FI-11). With PROXY v2 on, the header goes
// ahead of every byte. A failed dial runs the probe early, so serving follows a target that refuses.
func (self *TlsFrontConn) openTarget(ctx context.Context, pass *tlsAudiencePass) (net.Conn, error) {
	testHookBarrier("tls.front_target.before", self.barrierKey)
	defer testHookBarrier("tls.front_target.after", self.barrierKey)
	if pass == nil || pass.conn != self {
		return nil, errTlsFrontNoPass
	}
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.front.clock.AfterFunc(self.front.settings.TargetDialTimeout, cancel)
	defer stop()
	target, err := self.front.dialTarget(dialCtx)
	if err != nil {
		self.front.targetRefused()
		return nil, err
	}
	if self.front.target.ProxyProtocol {
		if _, err := target.Write(tlsProxyV2Header(self.VisitorAddr(), self.front.target.port())); err != nil {
			target.Close()
			return nil, err
		}
	}
	return target, nil
}

// This connection's own transport to the target, made on first use: its connections serve this visitor alone, each
// dialed through openTarget with the pass its request carries.
func (self *TlsFrontConn) targetTransport() *http.Transport {
	self.transportOnce.Do(func() {
		settings := self.front.settings
		self.transport = &http.Transport{
			DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
				return self.openTarget(ctx, tlsAudiencePassOf(ctx))
			},
			MaxIdleConns:        settings.TargetIdleConnectionCount,
			MaxIdleConnsPerHost: settings.TargetIdleConnectionCount,
			IdleConnTimeout:     settings.IdleTimeout,
			DisableCompression:  true,
		}
	})
	return self.transport
}

// Closes the target connections this visitor's requests left idle.
func (self *TlsFrontConn) closeTransport() {
	self.transportOnce.Do(func() {})
	if self.transport != nil {
		self.transport.CloseIdleConnections()
	}
}
