//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The fixture's names: an endpoint's SNI under a 10-character network label, and another host of the same network.
const (
	tlsFrontTestServerName = "app.abcdefghij.ur.example"
	tlsFrontTestOtherName  = "blog.abcdefghij.ur.example"
	tlsFrontTestName       = "tls/443/app"
	tlsFrontTestIssuer     = "https://issuer.example"
)

// A guard on real time, whose firing fails the test: never the proof.
const tlsFrontTestGuard = 10 * time.Second

// A clock a test moves by hand: timers fire as advance passes them, on advance's goroutine.
type tlsFrontTestClock struct {
	stateLock sync.Mutex
	now       time.Time
	timers    []*tlsFrontTestTimer
	// closed and replaced as a timer is armed
	changed chan struct{}
}

// One armed timer.
type tlsFrontTestTimer struct {
	at       time.Time
	timeout  time.Duration
	function func()
	done     bool
}

var _ Clock = (*tlsFrontTestClock)(nil)

// A clock at a fixed date.
func newTlsFrontTestClock() *tlsFrontTestClock {
	return &tlsFrontTestClock{
		now:     time.Date(2026, time.November, 11, 9, 0, 0, 0, time.UTC),
		changed: make(chan struct{}),
	}
}

// See Clock.
func (self *tlsFrontTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// See Clock.
func (self *tlsFrontTestClock) After(timeout time.Duration) <-chan time.Time {
	channel := make(chan time.Time, 1)
	self.AfterFunc(timeout, func() {
		channel <- self.Now()
	})
	return channel
}

// See Clock.
func (self *tlsFrontTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	if timeout <= 0 {
		go function()
		return func() bool { return false }
	}
	timer := func() *tlsFrontTestTimer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		timer := &tlsFrontTestTimer{at: self.now.Add(timeout), timeout: timeout, function: function}
		self.timers = append(self.timers, timer)
		close(self.changed)
		self.changed = make(chan struct{})
		return timer
	}()
	return func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if timer.done {
			return false
		}
		timer.done = true
		return true
	}
}

// Moves the clock by by and runs every timer it passes.
func (self *tlsFrontTestClock) advance(by time.Duration) {
	due := func() []*tlsFrontTestTimer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.now = self.now.Add(by)
		due := []*tlsFrontTestTimer{}
		live := []*tlsFrontTestTimer{}
		for _, timer := range self.timers {
			switch {
			case timer.done:
			case !self.now.Before(timer.at):
				timer.done = true
				due = append(due, timer)
			default:
				live = append(live, timer)
			}
		}
		self.timers = live
		return due
	}()
	for _, timer := range due {
		timer.function()
	}
}

// How many live timers of timeout there are.
func (self *tlsFrontTestClock) armed(timeout time.Duration) (int, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, timer := range self.timers {
		if !timer.done && timer.timeout == timeout {
			count += 1
		}
	}
	return count, self.changed
}

// Waits until count live timers of timeout are armed.
func (self *tlsFrontTestClock) waitArmed(t *testing.T, timeout time.Duration, count int) {
	t.Helper()
	for {
		armedCount, changed := self.armed(timeout)
		if count <= armedCount {
			return
		}
		select {
		case <-changed:
		case <-time.After(tlsFrontTestGuard):
			t.Fatalf("%d timers of %s armed, waiting for %d", armedCount, timeout, count)
		}
	}
}

// A listener a test hands streams to.
type tlsFrontTestListener struct {
	edgeNetworkId Id
	conns         chan *SocketConn
	closed        chan struct{}
	closeOnce     sync.Once

	stateLock      sync.Mutex
	servingChanges []bool
	changed        chan struct{}
}

var _ tlsFrontListener = (*tlsFrontTestListener)(nil)

// A listener whose registrar named edgeNetworkId as urnetwork-edge.
func newTlsFrontTestListener(edgeNetworkId Id) *tlsFrontTestListener {
	return &tlsFrontTestListener{
		edgeNetworkId: edgeNetworkId,
		conns:         make(chan *SocketConn, 64),
		closed:        make(chan struct{}),
		changed:       make(chan struct{}),
	}
}

// See tlsFrontListener.
func (self *tlsFrontTestListener) AcceptSocket(ctx context.Context) (*SocketConn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// See tlsFrontListener.
func (self *tlsFrontTestListener) SetServing(serving bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.servingChanges = append(self.servingChanges, serving)
	close(self.changed)
	self.changed = make(chan struct{})
}

// See tlsFrontListener.
func (self *tlsFrontTestListener) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
	})
	return nil
}

// See tlsFrontListener.
func (self *tlsFrontTestListener) tlsEdgeNetworkId() (Id, bool) {
	return self.edgeNetworkId, true
}

// Waits for the count-th serving change and answers it.
func (self *tlsFrontTestListener) waitServing(t *testing.T, count int) bool {
	t.Helper()
	for {
		serving, changed, ok := func() (bool, chan struct{}, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if count <= len(self.servingChanges) {
				return self.servingChanges[count-1], nil, true
			}
			return false, self.changed, false
		}()
		if ok {
			return serving
		}
		select {
		case <-changed:
		case <-time.After(tlsFrontTestGuard):
			t.Fatalf("no serving change %d", count)
		}
	}
}

// A policy a test sets: this sidecar's grant, signers' grants, members and identity keys, whatever name it is asked
// for, since a fixture's front serves one endpoint.
type tlsFrontTestPolicy struct {
	stateLock    sync.Mutex
	grant        *TlsPublishGrant
	signerGrants map[Id]*TlsPublishGrant
	members      map[Id]bool
	identityKeys map[Id][]byte
}

var _ TlsFrontPolicy = (*tlsFrontTestPolicy)(nil)

// A policy holding nothing.
func newTlsFrontTestPolicy() *tlsFrontTestPolicy {
	return &tlsFrontTestPolicy{signerGrants: map[Id]*TlsPublishGrant{}, members: map[Id]bool{}, identityKeys: map[Id][]byte{}}
}

// Sets this sidecar's grant: audience and mode, a fresh grant id, no expiry.
func (self *tlsFrontTestPolicy) setGrant(audience protocol.AclAudience, appMode protocol.AclAppMode, pin []byte) *TlsPublishGrant {
	grant := &TlsPublishGrant{GrantIds: [][]byte{NewId().Bytes()}, Audience: audience, AppMode: appMode, LinkSpkiSha256: pin}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.grant = grant
	return grant
}

// See TlsFrontPolicy.
func (self *tlsFrontTestPolicy) PublishGrant(name string, host string, now time.Time) *TlsPublishGrant {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.grant == nil || (!self.grant.Expires.IsZero() && !now.Before(self.grant.Expires)) {
		return nil
	}
	copied := *self.grant
	return &copied
}

// See TlsFrontPolicy.
func (self *tlsFrontTestPolicy) PublishGrantOf(signerId Id, grantId []byte, name string, host string, now time.Time) *TlsPublishGrant {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	grant := self.signerGrants[signerId]
	if grant == nil || !grant.holds(grantId) || (!grant.Expires.IsZero() && !now.Before(grant.Expires)) {
		return nil
	}
	copied := *grant
	return &copied
}

// See TlsFrontPolicy.
func (self *tlsFrontTestPolicy) MemberActive(memberId Id, now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.members[memberId]
}

// See TlsFrontPolicy.
func (self *tlsFrontTestPolicy) IdentityKey(sidecarId Id) []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.identityKeys[sidecarId]
}

// A keychain namespace in memory.
type tlsFrontTestSecrets struct {
	stateLock sync.Mutex
	values    map[string][]byte
	// every Get answers this when set
	getErr error
}

var _ SidecarSecrets = (*tlsFrontTestSecrets)(nil)

// An empty namespace.
func newTlsFrontTestSecrets() *tlsFrontTestSecrets {
	return &tlsFrontTestSecrets{values: map[string][]byte{}}
}

// See SidecarSecrets.
func (self *tlsFrontTestSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.getErr != nil {
		return nil, self.getErr
	}
	value, ok := self.values[name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return slices.Clone(value), nil
}

// See SidecarSecrets.
func (self *tlsFrontTestSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.values[name] = slices.Clone(value)
	return nil
}

// See SidecarSecrets.
func (self *tlsFrontTestSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.values, name)
	return nil
}

// See SidecarSecrets.
func (self *tlsFrontTestSecrets) List(prefix string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for name := range self.values {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}

// One request the backend served, as it arrived.
type tlsFrontTestRequest struct {
	method string
	host   string
	path   string
	header http.Header
}

// The local service: counts every dial and every byte it reads. raw echoes; http serves each request, recording it.
type tlsFrontTestBackend struct {
	serveHttp bool
	// headers each http answer carries
	answerHeader http.Header
	httpConns    chan net.Conn
	requests     chan *tlsFrontTestRequest
	// raw: what each connection read first, PROXY header included
	firstReads chan []byte

	stateLock sync.Mutex
	dials     int
	byteCount int64
	refusing  bool
}

// A backend, raw or http.
func newTlsFrontTestBackend(serveHttp bool) *tlsFrontTestBackend {
	backend := &tlsFrontTestBackend{
		serveHttp:    serveHttp,
		answerHeader: http.Header{},
		httpConns:    make(chan net.Conn),
		requests:     make(chan *tlsFrontTestRequest, 64),
		firstReads:   make(chan []byte, 64),
	}
	if serveHttp {
		listener := &tlsFrontTestBackendListener{conns: backend.httpConns, closed: make(chan struct{})}
		server := &http.Server{Handler: http.HandlerFunc(backend.serveRequest)}
		go server.Serve(listener)
	}
	return backend
}

// Dials the backend: a pipe whose far end the backend reads.
func (self *tlsFrontTestBackend) dial(ctx context.Context) (net.Conn, error) {
	refusing := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.refusing {
			self.dials += 1
		}
		return self.refusing
	}()
	if refusing {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	}
	near, far := net.Pipe()
	counted := &tlsFrontTestCountingConn{Conn: far, backend: self}
	if self.serveHttp {
		go func() { self.httpConns <- counted }()
	} else {
		go self.echo(counted)
	}
	return near, nil
}

// Echoes what it reads, reporting the first read.
func (self *tlsFrontTestBackend) echo(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 64*1024)
	first := true
	for {
		n, err := conn.Read(buffer)
		if 0 < n {
			if first {
				self.firstReads <- slices.Clone(buffer[:n])
				first = false
			}
			if _, err := conn.Write(buffer[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// One http request: recorded, and answered with answerHeader, or as a WebSocket upgrade that then echoes.
func (self *tlsFrontTestBackend) serveRequest(w http.ResponseWriter, r *http.Request) {
	self.requests <- &tlsFrontTestRequest{method: r.Method, host: r.Host, path: r.URL.RequestURI(), header: r.Header.Clone()}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		conn, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		buffered.Flush()
		io.Copy(conn, buffered)
		return
	}
	for name, values := range self.answerHeader {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	io.WriteString(w, "backend")
}

// Sets whether dials are refused.
func (self *tlsFrontTestBackend) setRefusing(refusing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refusing = refusing
}

// Dials and bytes read so far.
func (self *tlsFrontTestBackend) counts() (int, int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.dials, self.byteCount
}

// The next request the backend served.
func (self *tlsFrontTestBackend) nextRequest(t *testing.T) *tlsFrontTestRequest {
	t.Helper()
	select {
	case request := <-self.requests:
		return request
	case <-time.After(tlsFrontTestGuard):
		t.Fatal("the backend served no request")
		return nil
	}
}

// A backend conn that counts what it reads.
type tlsFrontTestCountingConn struct {
	net.Conn
	backend *tlsFrontTestBackend
}

// See net.Conn.
func (self *tlsFrontTestCountingConn) Read(b []byte) (int, error) {
	n, err := self.Conn.Read(b)
	self.backend.stateLock.Lock()
	self.backend.byteCount += int64(n)
	self.backend.stateLock.Unlock()
	return n, err
}

// The backend's http listener.
type tlsFrontTestBackendListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

// See net.Listener.
func (self *tlsFrontTestBackendListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

// See net.Listener.
func (self *tlsFrontTestBackendListener) Close() error {
	return nil
}

// See net.Listener.
func (self *tlsFrontTestBackendListener) Addr() net.Addr {
	return &SocketAddr{}
}

// A front on fakes, and what a test needs to reach it as a visitor through the edge.
type tlsFrontFixture struct {
	t            *testing.T
	clock        *tlsFrontTestClock
	listener     *tlsFrontTestListener
	policy       *tlsFrontTestPolicy
	secrets      *tlsFrontTestSecrets
	backend      *tlsFrontTestBackend
	certificate  *tls.Certificate
	settings     *TlsFrontSettings
	target       *TlsFrontTarget
	issuerClient *http.Client
	limits       func(ctx context.Context) (*QuotaLimits, error)
	alpnChanges  chan struct{}
	// runs inside each handshake, after dispatch has read the grant, when set before the front starts
	onCertificate func()
	issuerUrl     string
	log           Logger
	edgeNetworkId Id
	networkId     Id
	sidecarId     Id
	// TlsEdgeOpen's and the ticket's grant expiry
	grantExpireMillis uint64
	front             *TlsFront
}

// A fixture whose front serves tls/443/app over http to an http backend, its grant public, configure changing any
// of it before the front starts.
func newTlsFrontFixture(t *testing.T, configure func(fixture *tlsFrontFixture)) *tlsFrontFixture {
	t.Helper()
	clock := newTlsFrontTestClock()
	key, err := newTlsDeviceKey(clock.Now(), TlsKeyRotationNone)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := newTlsSelfSignedCertificate(key, []string{tlsFrontTestServerName}, clock.Now(), DefaultSidecarTlsSettings())
	if err != nil {
		t.Fatal(err)
	}
	settings := DefaultTlsFrontSettings()
	// the probe is its own test's
	settings.TargetProbeInterval = 0
	fixture := &tlsFrontFixture{
		t:             t,
		clock:         clock,
		policy:        newTlsFrontTestPolicy(),
		secrets:       newTlsFrontTestSecrets(),
		backend:       newTlsFrontTestBackend(true),
		certificate:   certificate,
		settings:      settings,
		alpnChanges:   make(chan struct{}, 16),
		edgeNetworkId: NewId(),
		networkId:     NewId(),
		sidecarId:     NewId(),
		target: &TlsFrontTarget{
			Name:         tlsFrontTestName,
			ServerNames:  []string{tlsFrontTestServerName},
			AppMode:      "http",
			LocalAddress: "127.0.0.1:8080",
		},
		grantExpireMillis: uint64(clock.Now().Add(24 * time.Hour).UnixMilli()),
		issuerUrl:         tlsFrontTestIssuer,
	}
	fixture.listener = newTlsFrontTestListener(fixture.edgeNetworkId)
	fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_PUBLIC, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	// the notice is its own tests'
	fixture.limits = func(ctx context.Context) (*QuotaLimits, error) {
		return &QuotaLimits{Tier: "pro"}, nil
	}
	if configure != nil {
		configure(fixture)
	}
	front, err := NewTlsFront(context.Background(), &TlsFrontArgs{
		Settings:  fixture.settings,
		Target:    fixture.target,
		Listener:  fixture.listener,
		NetworkId: fixture.networkId,
		SidecarId: fixture.sidecarId,
		Policy:    fixture.policy,
		Certificate: func(serverName string) (*tls.Certificate, error) {
			if fixture.onCertificate != nil {
				fixture.onCertificate()
			}
			return fixture.certificate, nil
		},
		Secrets:      fixture.secrets,
		IssuerUrl:    fixture.issuerUrl,
		IssuerClient: fixture.issuerClient,
		Limits:       fixture.limits,
		DialTarget:   fixture.backend.dial,
		AlpnChanged: func() {
			fixture.alpnChanges <- struct{}{}
		},
		Clock: clock,
		Log:   fixture.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.front = front
	t.Cleanup(func() { front.Close() })
	return fixture
}

// The visitor's address the fixture's edge reports by default.
func tlsFrontTestVisitor() netip.AddrPort {
	return netip.MustParseAddrPort("[2001:db8::7]:40000")
}

// Hands the front a stream as the edge would open it, mutate changing its ticket or open first, and answers the
// visitor's end.
func (self *tlsFrontFixture) openStream(mutate func(ticket *protocol.SocketTicket, open *protocol.TlsEdgeOpen) []byte) *SocketConn {
	self.t.Helper()
	visitor := tlsFrontTestVisitor()
	ticket := &protocol.SocketTicket{
		DialerNetworkId:       self.edgeNetworkId.Bytes(),
		GrantExpireTimeMillis: self.grantExpireMillis,
	}
	open := &protocol.TlsEdgeOpen{
		ClientIp:         visitor.Addr().AsSlice(),
		ClientPort:       uint32(visitor.Port()),
		ServerName:       tlsFrontTestServerName,
		ConnectionId:     NewId().Bytes(),
		ExpireTimeMillis: self.grantExpireMillis,
	}
	var metadata []byte
	if mutate != nil {
		metadata = mutate(ticket, open)
	}
	if metadata == nil {
		var err error
		metadata, err = proto.Marshal(open)
		if err != nil {
			self.t.Fatal(err)
		}
	}
	listenerEnd, visitorEnd := newSocketStreamPipe(256 * 1024)
	self.listener.conns <- newSocketConn(listenerEnd, &SocketAddr{}, &SocketAddr{}, ticket, metadata)
	return newSocketConn(visitorEnd, &SocketAddr{}, &SocketAddr{}, nil, nil)
}

// A visitor's TLS client on a fresh stream, handshaken.
func (self *tlsFrontFixture) dialTls(config *tls.Config, mutate func(ticket *protocol.SocketTicket, open *protocol.TlsEdgeOpen) []byte) (*tls.Conn, error) {
	self.t.Helper()
	conn := tls.Client(self.openStream(mutate), config)
	if err := conn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	self.t.Cleanup(func() { conn.Close() })
	return conn, nil
}

// A visitor's client config for nextProtos.
func tlsFrontTestClientConfig(nextProtos ...string) *tls.Config {
	return &tls.Config{ServerName: tlsFrontTestServerName, NextProtos: nextProtos, InsecureSkipVerify: true}
}

// An HTTP client whose every connection is a fresh visitor stream offering nextProtos, h2 when it is offered, that
// never follows a redirect.
func (self *tlsFrontFixture) httpClient(nextProtos ...string) *http.Client {
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			return self.dialTls(tlsFrontTestClientConfig(nextProtos...), nil)
		},
		ForceAttemptHTTP2: slices.Contains(nextProtos, tlsAlpnH2),
	}
	self.t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// A request to path on the endpoint, as a browser's top-level navigation typed into the bar.
func tlsFrontTestNavigation(t *testing.T, method string, path string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, "https://"+tlsFrontTestServerName+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(tlsHttpHeaderFetchSite, tlsFetchSiteNone)
	request.Header.Set(tlsHttpHeaderFetchMode, tlsFetchModeNavigate)
	request.Header.Set(tlsHttpHeaderFetchDest, tlsFetchDestDocument)
	return request
}

// client's answer to request, its body read.
func tlsFrontTestDo(t *testing.T, client *http.Client, request *http.Request) (*http.Response, string) {
	t.Helper()
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, string(body)
}

// The reset code a visitor's read ends on, RST_UNSPECIFIED when it ends otherwise.
func tlsFrontTestResetCode(t *testing.T, conn net.Conn) protocol.StreamResetCode {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, conn)
		done <- err
	}()
	select {
	case err := <-done:
		codeErr := &SocketCodeError{}
		if errors.As(err, &codeErr) {
			return codeErr.ResetCode
		}
		return protocol.StreamResetCode_RST_UNSPECIFIED
	case <-time.After(tlsFrontTestGuard):
		t.Fatal("the stream never ended")
		return protocol.StreamResetCode_RST_UNSPECIFIED
	}
}

// Whether an error is the visitor's view of the front's alert.
func tlsFrontTestAlert(err error, alert string) bool {
	return err != nil && strings.Contains(err.Error(), alert)
}

// §13.7's http dispatch: no ALPN, http/1.1 and h2 each reach the HTTP front and through it the service, the mode
// the registration's and the protocol ALPN's.
func TestTlsFrontServesHttpOverEachAlpn(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	for _, c := range []struct {
		offered    []string
		protoMajor int
	}{
		{offered: nil, protoMajor: 1},
		{offered: []string{tlsAlpnHttp11}, protoMajor: 1},
		{offered: []string{tlsAlpnH2}, protoMajor: 2},
		{offered: []string{tlsAlpnHttp11, tlsAlpnH2}, protoMajor: 2},
	} {
		client := fixture.httpClient(c.offered...)
		response, body := tlsFrontTestDo(t, client, tlsFrontTestNavigation(t, http.MethodGet, "/page?x=1"))
		if response.StatusCode != http.StatusOK || body != "backend" || response.ProtoMajor != c.protoMajor {
			t.Errorf("%v: %d %q over HTTP/%d", c.offered, response.StatusCode, body, response.ProtoMajor)
		}
		request := fixture.backend.nextRequest(t)
		if request.path != "/page?x=1" || request.host != tlsFrontTestServerName {
			t.Errorf("%v: the backend saw %s on %s", c.offered, request.path, request.host)
		}
	}
}

// §13.5's trust rule: a ticket whose dialer is not urnetwork-edge never has its TlsEdgeOpen read, and its stream
// resets before a byte reaches anything.
func TestTlsFrontResetsATicketFromAnotherDialer(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	visitorConn := fixture.openStream(func(ticket *protocol.SocketTicket, open *protocol.TlsEdgeOpen) []byte {
		ticket.DialerNetworkId = fixture.networkId.Bytes()
		return nil
	})
	if code := tlsFrontTestResetCode(t, visitorConn); code != protocol.StreamResetCode_RST_IDENTITY {
		t.Errorf("reset %s", code)
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
}

// Metadata that is no TlsEdgeOpen, a server name this endpoint does not serve, or an expiry other than the ticket's
// resets the stream with RST_PROTOCOL.
func TestTlsFrontResetsUntrustedMetadata(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	mutations := []func(ticket *protocol.SocketTicket, open *protocol.TlsEdgeOpen) []byte{
		func(ticket *protocol.SocketTicket, open *protocol.TlsEdgeOpen) []byte {
			return []byte{0xff, 0xff, 0xff}
		},
		func(ticket *protocol.SocketTicket, open *protocol.TlsEdgeOpen) []byte {
			open.ServerName = tlsFrontTestOtherName
			return nil
		},
		func(ticket *protocol.SocketTicket, open *protocol.TlsEdgeOpen) []byte {
			open.ExpireTimeMillis += 1
			return nil
		},
		func(ticket *protocol.SocketTicket, open *protocol.TlsEdgeOpen) []byte {
			open.ClientIp = []byte{1, 2, 3}
			return nil
		},
	}
	for i, mutate := range mutations {
		if code := tlsFrontTestResetCode(t, fixture.openStream(mutate)); code != protocol.StreamResetCode_RST_PROTOCOL {
			t.Errorf("case %d: reset %s", i, code)
		}
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
}

// A hello whose SNI is not the one the edge routed by fails the handshake.
func TestTlsFrontRefusesAHelloForAnotherName(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	config := tlsFrontTestClientConfig(tlsAlpnHttp11)
	config.ServerName = tlsFrontTestOtherName
	if _, err := fixture.dialTls(config, nil); err == nil {
		t.Fatal("a hello for another name completed")
	}
}

// §13.7: a visitor that sends no hello within 10 s on the clock is reset with RST_PEER_TIMEOUT, and not before.
func TestTlsFrontSlowHandshakeResets(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	visitorConn := fixture.openStream(nil)
	fixture.clock.waitArmed(t, fixture.settings.HandshakeTimeout, 1)
	fixture.clock.advance(fixture.settings.HandshakeTimeout - time.Millisecond)
	if armedCount, _ := fixture.clock.armed(fixture.settings.HandshakeTimeout); armedCount != 1 {
		t.Fatalf("the bound went before its time")
	}
	fixture.clock.advance(time.Millisecond)
	if code := tlsFrontTestResetCode(t, visitorConn); code != protocol.StreamResetCode_RST_PEER_TIMEOUT {
		t.Errorf("reset %s", code)
	}
}

// §13.7: an HTTP visitor that sends no request within 30 s of its handshake is reset with RST_PEER_TIMEOUT.
func TestTlsFrontSlowFirstRequestResets(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	conn, err := fixture.dialTls(tlsFrontTestClientConfig(tlsAlpnHttp11), nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.waitArmed(t, fixture.settings.FirstRequestTimeout, 1)
	fixture.clock.advance(fixture.settings.FirstRequestTimeout)
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection outlived its first-request bound")
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
}

// A request in time stops the first-request bound.
func TestTlsFrontFirstRequestStopsItsBound(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	conn, err := fixture.dialTls(tlsFrontTestClientConfig(tlsAlpnHttp11), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+tlsFrontTestServerName+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	fixture.backend.nextRequest(t)
	fixture.clock.advance(fixture.settings.FirstRequestTimeout)
	if _, err := io.WriteString(conn, "GET /again HTTP/1.1\r\nHost: "+tlsFrontTestServerName+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if response, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("the second request: %v", err)
	}
}

// §9.9's SetServing follows the target: false while it refuses, true once a probe reaches it again.
func TestTlsFrontServingFollowsTheTarget(t *testing.T) {
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.settings.TargetProbeInterval = 10 * time.Second
		fixture.backend.setRefusing(true)
	})
	if serving := fixture.listener.waitServing(t, 1); serving {
		t.Fatal("serving while the target refuses")
	}
	fixture.backend.setRefusing(false)
	fixture.clock.waitArmed(t, fixture.settings.TargetProbeMinInterval, 1)
	fixture.clock.advance(fixture.settings.TargetProbeMinInterval)
	rest := fixture.settings.TargetProbeInterval - fixture.settings.TargetProbeMinInterval
	fixture.clock.waitArmed(t, rest, 1)
	fixture.clock.advance(rest)
	if serving := fixture.listener.waitServing(t, 2); !serving {
		t.Fatal("not serving once the target answers")
	}
	if _, byteCount := fixture.backend.counts(); byteCount != 0 {
		t.Errorf("a probe carried %d bytes", byteCount)
	}
}

// §13.7's versions row: a Go client takes X25519MLKEM768, and TLS 1.2 still completes on http.
func TestTlsFrontNegotiatesX25519MLKEM768First(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	conn, err := fixture.dialTls(tlsFrontTestClientConfig(tlsAlpnHttp11), nil)
	if err != nil {
		t.Fatal(err)
	}
	if state := conn.ConnectionState(); state.CurveID != tls.X25519MLKEM768 || state.Version != tls.VersionTLS13 {
		t.Errorf("group %s, version %x", state.CurveID, state.Version)
	}
	config := tlsFrontTestClientConfig(tlsAlpnHttp11)
	config.MaxVersion = tls.VersionTLS12
	if conn, err := fixture.dialTls(config, nil); err != nil || conn.ConnectionState().Version != tls.VersionTLS12 {
		t.Errorf("TLS 1.2: %v", err)
	}
}

// §9.5's registration: protocol tls, the signed mode, what it serves, and acme-tls/1 while a challenge is pending.
func TestTlsFrontListenSettings(t *testing.T) {
	target := &TlsFrontTarget{Name: tlsFrontTestName, AppMode: "raw", Alpn: []string{"mqtt"}, MaxStreams: 32}
	settings := TlsFrontListenSettings(target, false)
	if settings.Protocol != "tls" || settings.AppMode != "raw" || !slices.Equal(settings.Alpn, []string{"mqtt"}) || settings.MaxStreams != 32 {
		t.Errorf("raw: %+v", settings)
	}
	if settings := TlsFrontListenSettings(target, true); !slices.Equal(settings.Alpn, []string{"mqtt", tlsAlpnAcme}) {
		t.Errorf("raw pending: %v", settings.Alpn)
	}
	target = &TlsFrontTarget{Name: tlsFrontTestName}
	if settings := TlsFrontListenSettings(target, false); settings.AppMode != "http" || !slices.Equal(settings.Alpn, []string{tlsAlpnH2, tlsAlpnHttp11}) {
		t.Errorf("http: %+v", settings)
	}
	if _, err := socketListenArgs(tlsFrontTestName, SocketNamespaceTls, TlsFrontListenSettings(target, true)); err != nil {
		t.Errorf("the registration refuses its own settings: %v", err)
	}
}

// A target the front cannot serve is refused before anything runs.
func TestTlsFrontRefusesABadTarget(t *testing.T) {
	good := TlsFrontTarget{Name: tlsFrontTestName, ServerNames: []string{tlsFrontTestServerName}, LocalAddress: "127.0.0.1:8080"}
	if _, err := newTlsFrontTarget(&good); err != nil {
		t.Fatalf("the good target: %v", err)
	}
	mutations := []func(target *TlsFrontTarget){
		func(target *TlsFrontTarget) { target.Name = "app" },
		func(target *TlsFrontTarget) { target.Name = "tls/80/app" },
		func(target *TlsFrontTarget) { target.ServerNames = nil },
		func(target *TlsFrontTarget) { target.ServerNames = []string{"bad name"} },
		func(target *TlsFrontTarget) { target.AppMode = "tcp" },
		func(target *TlsFrontTarget) { target.Alpn = []string{"mqtt"} },
		func(target *TlsFrontTarget) { target.AppMode = "raw"; target.Alpn = []string{tlsAlpnAcme} },
		func(target *TlsFrontTarget) { target.AppMode = "raw"; target.Forwarded = true },
		func(target *TlsFrontTarget) { target.LocalAddress = "localhost:8080" },
		func(target *TlsFrontTarget) { target.MaxStreams = -1 },
	}
	for i, mutate := range mutations {
		target := good
		mutate(&target)
		if _, err := newTlsFrontTarget(&target); err == nil {
			t.Errorf("case %d: refused nothing", i)
		}
	}
}

// --proxy-protocol's reading: PROXY v2 on raw, Forwarded on http, neither without the flag.
func TestTlsFrontVisitorAddressOptions(t *testing.T) {
	for _, c := range []struct {
		appMode       string
		flag          bool
		wantProxyV2   bool
		wantForwarded bool
	}{
		{appMode: "raw", flag: true, wantProxyV2: true},
		{appMode: "http", flag: true, wantForwarded: true},
		{appMode: "raw", flag: false},
		{appMode: "http", flag: false},
	} {
		proxyV2, forwarded := TlsFrontVisitorAddressOptions(c.appMode, c.flag)
		if proxyV2 != c.wantProxyV2 || forwarded != c.wantForwarded {
			t.Errorf("%s %t: %t %t", c.appMode, c.flag, proxyV2, forwarded)
		}
	}
}

// Closing the front ends the listener and every connection it holds.
func TestTlsFrontCloseEndsItsConnections(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	conn, err := fixture.dialTls(tlsFrontTestClientConfig(tlsAlpnHttp11), nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture.front.Close()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection outlived its front")
	}
	select {
	case <-fixture.listener.closed:
	default:
		t.Error("the listener is open")
	}
}

// FS-34 (FI-11): for each private audience, with no, an unknown, http/1.1 and h2 ALPN, and with what the visitor
// sends after the handshake disagreeing with what ALPN chose, no byte reaches the backend before authentication,
// while an explicit public raw service and TLS-ALPN-01 keep working beside them.
func TestTlsFrontZeroBytesBeforeAuthentication(t *testing.T) {
	type audienceCase struct {
		audience protocol.AclAudience
		appMode  protocol.AclAppMode
		raw      bool
	}
	pin := make([]byte, 32)
	audiences := []audienceCase{
		{audience: protocol.AclAudience_ACL_AUDIENCE_MEMBERS, appMode: protocol.AclAppMode_ACL_APP_MODE_HTTP},
		{audience: protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE, appMode: protocol.AclAppMode_ACL_APP_MODE_HTTP},
		{audience: protocol.AclAudience_ACL_AUDIENCE_LINK, appMode: protocol.AclAppMode_ACL_APP_MODE_HTTP},
		{audience: protocol.AclAudience_ACL_AUDIENCE_LINK, appMode: protocol.AclAppMode_ACL_APP_MODE_RAW, raw: true},
	}
	offers := [][]string{nil, {"imap"}, {tlsAlpnHttp11}, {tlsAlpnH2}}
	// what each visitor writes once its handshake ends: HTTP/1.1, the h2 preface, or neither
	payloads := []string{
		"GET / HTTP/1.1\r\nHost: " + tlsFrontTestServerName + "\r\n\r\n",
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
		"\x16\x03\x01 not a protocol at all",
	}
	for _, audience := range audiences {
		fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
			if audience.raw {
				fixture.target.AppMode = "raw"
				fixture.target.Alpn = []string{tlsAlpnHttp11, tlsAlpnH2}
				fixture.backend = newTlsFrontTestBackend(false)
			}
			fixture.policy.setGrant(audience.audience, audience.appMode, pin)
		})
		for _, offered := range offers {
			for _, payload := range payloads {
				conn, err := fixture.dialTls(tlsFrontTestClientConfig(offered...), nil)
				if err != nil {
					// a refused handshake carries no byte either
					continue
				}
				io.WriteString(conn, payload)
				// close_notify after the payload, so every front answers or closes and none waits for more
				conn.CloseWrite()
				conn.SetReadDeadline(time.Now().Add(tlsFrontTestGuard))
				if _, err := io.Copy(io.Discard, conn); errors.Is(err, os.ErrDeadlineExceeded) {
					t.Errorf("%s %s %v: the front never ended the connection", audience.audience, audience.appMode, offered)
				}
				conn.Close()
			}
		}
		if dials, byteCount := fixture.backend.counts(); dials != 0 || byteCount != 0 {
			t.Errorf("%s %s: %d dials, %d bytes before authentication", audience.audience, audience.appMode, dials, byteCount)
		}
	}

	// beside them, an explicit public raw service forwards, and TLS-ALPN-01 answers
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.target.AppMode = "raw"
		fixture.backend = newTlsFrontTestBackend(false)
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_PUBLIC, protocol.AclAppMode_ACL_APP_MODE_RAW, nil)
	})
	conn, err := fixture.dialTls(tlsFrontTestClientConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "ping")
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != "ping" {
		t.Errorf("public raw: %q %v", echo, err)
	}
	if err := fixture.front.SetAlpnChallenge(tlsFrontTestServerName, "token.thumbprint", fixture.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	acmeConn, err := fixture.dialTls(tlsFrontTestClientConfig(tlsAlpnAcme), nil)
	if err != nil || acmeConn.ConnectionState().NegotiatedProtocol != tlsAlpnAcme {
		t.Errorf("TLS-ALPN-01: %v", err)
	}
}
