//go:build sidecar_testhooks

// §13.7's front at the listener's end of the T2 tls suite (TLS-M5-25; S5's visitor half and FS-34 on T2, QD-852): the
// suite's world (tls_suite_test.go) with the production front serving each published host, so a visitor's connection
// runs the whole edge path in one process: tlsedge behind its PROXY listener, the edge's Find through the sockets
// engine on the production gate over the network's real authorization log, the ticket the engine signed and the
// TlsEdgeOpen the edge built, and then the front's own trust step, handshake and audience check, judging the
// audience from the listener device's verified config (NewTlsFrontConfigPolicy over the admission world's state),
// with a recording backend as the local service (recording_backend.go).
//
// What only this composition shows:
//
//   - S5's visitor half: under a members publish the gate passes the edge's Find, which a public-only gate refused, so
//     the visitor reaches the front, and the front, not the gate, sends a visitor with no session to edge login, with
//     no connection made to the service.
//   - FS-34 on T2: no connection and no byte reaches the service of a members, members-device or link host, http or
//     raw, whatever ALPN the visitor offers and whatever it writes, while the front did take the visitor's stream;
//     beside them the public host's service is reached, so a path nothing reaches does not pass for nothing.
//
// Where it stops: the stream is the suite's in-memory pair, handed to the front through TlsFrontTestListener, which
// stands in for §9.6's admission on a ticket the suite's dialer verified, so only the sidecar_testhooks build has
// these tests. The front's certificate is a self-signed one the test makes; certs' chain is the passthrough test's.
// Nothing sleeps: a visitor ends its own direction and reads to the end, and time is the Net's FakeClock.

package sidecartest_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The edge-login issuer the fronts send a members visitor to.
const tlsFrontSuiteIssuer = "https://auth.sidecartest.example"

// The front's end of an edge stream: the listener's end with a stream's half-close and reset, which a net.Conn has
// not.
type tlsFrontSuiteEnd struct {
	stream *tlsSuiteStream
}

var _ sidecar.TlsFrontTestStream = (*tlsFrontSuiteEnd)(nil)

func (self *tlsFrontSuiteEnd) Read(b []byte) (int, error)  { return self.stream.toListener.read(b) }
func (self *tlsFrontSuiteEnd) Write(b []byte) (int, error) { return self.stream.fromListener.write(b) }

func (self *tlsFrontSuiteEnd) CloseWrite() error {
	self.stream.fromListener.closeWrite()
	return nil
}

func (self *tlsFrontSuiteEnd) Close() error {
	self.stream.fromListener.closeWrite()
	self.stream.toListener.fail(net.ErrClosed)
	return nil
}

func (self *tlsFrontSuiteEnd) Reset(code protocol.StreamResetCode) error {
	err := &sidecar.SocketCodeError{Err: sidecar.ErrSocketReset, ResetCode: code}
	self.stream.toListener.fail(err)
	self.stream.fromListener.fail(err)
	return nil
}

func (self *tlsFrontSuiteEnd) SetReadDeadline(t time.Time) error  { return nil }
func (self *tlsFrontSuiteEnd) SetWriteDeadline(t time.Time) error { return nil }

// A keychain namespace in memory.
type tlsFrontSuiteSecrets struct {
	stateLock sync.Mutex
	values    map[string][]byte
}

var _ sidecar.SidecarSecrets = (*tlsFrontSuiteSecrets)(nil)

func (self *tlsFrontSuiteSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.values[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return slices.Clone(value), nil
}

func (self *tlsFrontSuiteSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.values[name] = slices.Clone(value)
	return nil
}

func (self *tlsFrontSuiteSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.values, name)
	return nil
}

func (self *tlsFrontSuiteSecrets) List(prefix string) ([]string, error) {
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

// One published host with its front and the service behind it.
type tlsFrontSuiteEndpoint struct {
	publish  tlsSuitePublish
	listener *sidecar.TlsFrontTestListener
	front    *sidecar.TlsFront
	backend  *sidecartest.RecordingBackend
	// the edge's streams the front accepted
	accepted atomic.Int64
}

// The tls suite's world with a front for each published host at the listener's end of the edge's streams.
type tlsFrontSuite struct {
	*tlsSuiteEdge
	nameEndpoints map[string]*tlsFrontSuiteEndpoint
	// what a visitor trusts: the fronts' one self-signed certificate
	roots *x509.CertPool
}

// What the public host's service answers.
const tlsFrontSuitePage = "the public page"

// The service behind a front: one request read, one page answered.
func tlsFrontSuiteServe(conn net.Conn) {
	if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
		return
	}
	io.WriteString(conn, tlsSuitePage(tlsFrontSuitePage))
}

// A world publishing each of publishes for a day, the listener's lease of each registered in its grant's mode, with a
// front serving each on the listener device's own evaluation of the log and a recording backend behind each front,
// and every stream the edge opens handed to the front of its ticket's name.
func newTlsFrontSuite(t *testing.T, publishes ...tlsSuitePublish) *tlsFrontSuite {
	t.Helper()
	edge := newTlsSuiteEdgeBare(t)
	suite := &tlsFrontSuite{
		tlsSuiteEdge:  edge,
		nameEndpoints: map[string]*tlsFrontSuiteEndpoint{},
		roots:         x509.NewCertPool(),
	}
	edge.savePublishes(edge.net.Clock().Now().Add(24*time.Hour), publishes...)
	registrations := []*sidecar.SocketRegistration{}
	serverNames := []string{}
	for _, publish := range publishes {
		registrations = append(registrations, edge.edgeRegistrationIn(edge.listener, "tls/443/"+publish.host, publish.appMode()))
		serverNames = append(serverNames, edge.serverName(publish.host))
	}
	edge.setVersion += 1
	edge.registerOk(edge.listener, edge.setVersion, registrations...)

	certificate := tlsFrontSuiteCertificate(t, serverNames)
	suite.roots.AddCert(certificate.Leaf)
	listenerSidecarId := sidecar.Id(edge.listener.device.SidecarId)
	for _, publish := range publishes {
		backendSettings := sidecartest.DefaultRecordingBackendSettings()
		backendSettings.Name = "the " + publish.audience + " host " + publish.host + "'s service"
		backendSettings.Serve = tlsFrontSuiteServe
		backendSettings.MustReach = publish.audience == "public"
		backend, err := sidecartest.NewRecordingBackend(edge.net, backendSettings)
		if err != nil {
			t.Fatal(err)
		}
		if publish.audience == "public" {
			backend.SetAudience(sidecartest.RecordingBackendAdmitted, "a public audience admits every visitor")
		}
		target := &sidecar.TlsFrontTarget{
			Name:         "tls/443/" + publish.host,
			ServerNames:  []string{edge.serverName(publish.host)},
			AppMode:      publish.appMode(),
			LocalAddress: backend.Addr().String(),
		}
		if publish.raw {
			target.Alpn = []string{"h2", "http/1.1"}
		}
		settings := sidecar.DefaultTlsFrontSettings()
		// the probe dials the service, which here must see a visitor's bytes alone
		settings.TargetProbeInterval = 0
		endpoint := &tlsFrontSuiteEndpoint{
			publish:  publish,
			listener: sidecar.NewTlsFrontTestListener(sidecar.Id(edge.edgeNetworkId)),
			backend:  backend,
		}
		front, err := sidecar.NewTlsFront(edge.ctx, &sidecar.TlsFrontArgs{
			Settings:  settings,
			Target:    target,
			Listener:  endpoint.listener,
			NetworkId: sidecar.Id(edge.networkId),
			SidecarId: listenerSidecarId,
			Policy:    sidecar.NewTlsFrontConfigPolicy(listenerSidecarId, edge.admission.State),
			Certificate: func(serverName string) (*tls.Certificate, error) {
				return certificate, nil
			},
			Secrets:   &tlsFrontSuiteSecrets{values: map[string][]byte{}},
			IssuerUrl: tlsFrontSuiteIssuer,
			// the Community notice is the front's own tests'
			Limits: func(ctx context.Context) (*sidecar.QuotaLimits, error) {
				return &sidecar.QuotaLimits{Tier: "pro"}, nil
			},
			Clock: edge.net.Clock(),
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { front.Close() })
		endpoint.front = front
		suite.nameEndpoints[target.Name] = endpoint
	}

	// each stream the edge opens goes to the front of its ticket's name, as admission hands a listener its own
	ctx, cancel := context.WithCancel(edge.ctx)
	routed := make(chan struct{})
	go func() {
		defer close(routed)
		for {
			select {
			case <-ctx.Done():
				return
			case stream := <-edge.dialer.opened:
				end := &tlsFrontSuiteEnd{stream: stream}
				endpoint := suite.nameEndpoints[stream.ticket.GetName()]
				if endpoint == nil || !endpoint.listener.Deliver(end, stream.ticket, stream.metadata) {
					end.Reset(protocol.StreamResetCode_RST_CANCELLED)
					continue
				}
				endpoint.accepted.Add(1)
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-routed
	})
	return suite
}

// A self-signed certificate for serverNames on a fresh P-256 key, valid through any clock a test runs on.
func tlsFrontSuiteCertificate(t *testing.T, serverNames []string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "the tls suite's front"},
		DNSNames:     serverNames,
		NotBefore:    time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// The endpoint serving host.
func (self *tlsFrontSuite) endpoint(host string) *tlsFrontSuiteEndpoint {
	self.t.Helper()
	endpoint := self.nameEndpoints["tls/443/"+host]
	if endpoint == nil {
		self.t.Fatalf("no front serves %s", host)
	}
	return endpoint
}

// A visitor's TLS connection to host offering alpnIds, through tlsedge and host's front, or the error its handshake
// ended with.
func (self *tlsFrontSuite) visit(host string, alpnIds []string) (*tls.Conn, error) {
	self.t.Helper()
	handshake := self.awaitHandshake(self.handshake(self.serverName(host), alpnIds, self.roots))
	if handshake.err != nil {
		handshake.conn.Close()
		return nil, handshake.err
	}
	self.t.Cleanup(func() { handshake.conn.Close() })
	return handshake.conn, nil
}

// An HTTP client whose every connection is a fresh visitor's, speaking HTTP/1.1, that follows no redirect.
func (self *tlsFrontSuite) httpClient() *http.Client {
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			label, _, _ := strings.Cut(host, ".")
			return self.visit(label, []string{"http/1.1"})
		},
		DisableKeepAlives: true,
	}
	self.t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// A GET of path on host as a browser's top-level navigation typed into the bar: the answer, its body read.
func (self *tlsFrontSuite) navigate(client *http.Client, host string, path string) (*http.Response, string) {
	self.t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://"+self.serverName(host)+path, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	request.Header.Set("Sec-Fetch-Site", "none")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Dest", "document")
	response, err := client.Do(request)
	if err != nil {
		self.t.Fatalf("a visitor's GET of %s%s: %v", host, path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		self.t.Fatal(err)
	}
	return response, string(body)
}

// Fails unless no connection and no byte reached endpoint's service.
func (self *tlsFrontSuite) wantUnreached(endpoint *tlsFrontSuiteEndpoint, when string) {
	self.t.Helper()
	if arrivals := endpoint.backend.Arrivals(); endpoint.backend.ConnectionCount() != 0 || len(arrivals) != 0 {
		self.t.Fatalf("%s: %d connections reached the %s host's service, with %v", when, endpoint.backend.ConnectionCount(),
			endpoint.publish.audience, arrivals)
	}
}

// S5's visitor half through the front (QD-852): a visitor of a host published to members, with no session, passes
// the edge's Find on the production gate, which judges no audience, reaches the listener's front on the ticket the
// engine signed, and is sent by the front to edge login: a 302 to the issuer's authorize endpoint for this origin,
// with PKCE and the pre-login cookie, and no connection to the service. The public host's visitor, on the same world,
// reads the service's page.
func TestTlsFrontSuiteMembersVisitorWithoutASessionReachesEdgeLogin(t *testing.T) {
	suite := newTlsFrontSuite(t, tlsSuitePublish{host: "team", audience: "members"}, tlsSuitePublish{host: "blog", audience: "public"})
	client := suite.httpClient()
	team := suite.endpoint("team")

	finds := suite.dialer.dials.Load()
	response, _ := suite.navigate(client, "team", "/private?x=1")
	if suite.dialer.dials.Load() != finds+1 || team.accepted.Load() != 1 {
		t.Fatalf("the members visitor made %d Finds and the front took %d streams", suite.dialer.dials.Load()-finds, team.accepted.Load())
	}
	origin := "https://" + suite.serverName("team")
	location, err := url.Parse(response.Header.Get("Location"))
	if response.StatusCode != http.StatusFound || err != nil || location.Scheme+"://"+location.Host != tlsFrontSuiteIssuer ||
		location.Path != "/oauth/authorize" {
		t.Fatalf("a members visitor with no session got %d to %q", response.StatusCode, response.Header.Get("Location"))
	}
	query := location.Query()
	for name, want := range map[string]string{
		"response_type": "code", "client_id": origin, "redirect_uri": origin + "/.well-known/ur/callback", "scope": "openid",
		"code_challenge_method": "S256",
	} {
		if query.Get(name) != want {
			t.Errorf("the login's %s is %q, not %q", name, query.Get(name), want)
		}
	}
	for _, name := range []string{"state", "nonce", "code_challenge"} {
		if len(query.Get(name)) < 43 {
			t.Errorf("the login's %s is %q", name, query.Get(name))
		}
	}
	preCookie := slices.IndexFunc(response.Cookies(), func(cookie *http.Cookie) bool {
		return cookie.Name == "__Host-ur-pre" && cookie.Secure && cookie.HttpOnly
	})
	if preCookie < 0 {
		t.Errorf("the login set no pre-login cookie: %v", response.Cookies())
	}
	suite.wantUnreached(team, "a members visitor with no session")

	// the callback with no pre-login cookie and a state the front never issued opens nothing either
	response, _ = suite.navigate(client, "team", "/.well-known/ur/callback?code=forged&state="+query.Get("state"))
	if response.StatusCode == http.StatusOK || response.Header.Get("Set-Cookie") != "" && strings.Contains(response.Header.Get("Set-Cookie"), "__Host-ur-session") {
		t.Fatalf("a callback with no pre-login cookie answered %d, setting %q", response.StatusCode, response.Header.Get("Set-Cookie"))
	}
	suite.wantUnreached(team, "a callback with no pre-login cookie")

	// the public host on the same world: the service's page
	blog := suite.endpoint("blog")
	response, body := suite.navigate(client, "blog", "/")
	if response.StatusCode != http.StatusOK || body != tlsFrontSuitePage {
		t.Fatalf("the public host's visitor got %d, %q", response.StatusCode, body)
	}
	if !blog.backend.ReachedAdmitted() || blog.backend.ConnectionCount() != 1 {
		t.Fatalf("the public host's service saw %d connections", blog.backend.ConnectionCount())
	}
}

// FS-34 on T2 (§22.8; I-5, D-TEST-10; QD-852): on one world with a members, a members-device and a link host over
// http and a link host over raw, each published and registered, every visitor's connection, whatever ALPN it offers
// and whatever it writes once its handshake ends, passes tlsedge and the production gate's Find and ends at the
// front with no connection made to its host's service and no byte sent to it; the front took streams for each host,
// so each row is a visitor the front refused and not one the gate did. The public host's service, beside them, is
// reached. The clock moves a second after each host, which refills tlsedge's cap on one visitor's new connections.
func TestTlsFrontSuiteNoByteReachesAPrivateAudiencesService(t *testing.T) {
	private := []tlsSuitePublish{
		{host: "team", audience: "members"},
		{host: "vault", audience: "members-device"},
		{host: "share", audience: "link"},
		{host: "drop", audience: "link", raw: true, pin: strings.Repeat("5a", 32)},
	}
	suite := newTlsFrontSuite(t, append(slices.Clone(private), tlsSuitePublish{host: "blog", audience: "public"})...)
	offers := [][]string{{"http/1.1"}, {"h2"}, {"h2", "http/1.1"}, {"imap"}, nil}
	payloads := []string{
		"GET / HTTP/1.1\r\nHost: %s\r\n\r\n",
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
		"\x16\x03\x01 not a protocol at all",
	}
	for _, publish := range private {
		endpoint := suite.endpoint(publish.host)
		handshakes := 0
		for _, offered := range offers {
			for _, payload := range payloads {
				conn, err := suite.visit(publish.host, offered)
				if err != nil {
					// a refused handshake carries no byte either
					continue
				}
				handshakes += 1
				io.WriteString(conn, strings.ReplaceAll(payload, "%s", suite.serverName(publish.host)))
				// close_notify after the payload, so every front answers or closes and none waits for more
				conn.CloseWrite()
				conn.SetReadDeadline(time.Now().Add(tlsSuiteGuard))
				if _, err := io.Copy(io.Discard, conn); errors.Is(err, os.ErrDeadlineExceeded) {
					t.Errorf("%s %v: the front never ended the connection", publish.host, offered)
				}
				conn.Close()
			}
		}
		if endpoint.accepted.Load() == 0 {
			t.Errorf("the %s host %s: no visitor reached its front", publish.audience, publish.host)
		}
		if !publish.raw && handshakes == 0 {
			t.Errorf("the %s host %s: no visitor completed a handshake with its front", publish.audience, publish.host)
		}
		suite.wantUnreached(endpoint, "after every visitor of "+publish.host)
		suite.net.Clock().Advance(time.Second)
	}

	blog := suite.endpoint("blog")
	response, body := suite.navigate(suite.httpClient(), "blog", "/")
	if response.StatusCode != http.StatusOK || body != tlsFrontSuitePage || !blog.backend.ReachedAdmitted() {
		t.Fatalf("the public host's visitor got %d, %q", response.StatusCode, body)
	}
	for _, publish := range private {
		suite.wantUnreached(suite.endpoint(publish.host), "at the end")
	}
}
