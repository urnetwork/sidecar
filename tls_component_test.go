//go:build !sidecar_http && !ios_extension && !js

// The tls component on a generation: its manager reads GET /tls/certs through the generation's SidecarApi, a TlsHint
// from the resident's push on topic tls reads again, and a generation of another network or with no api is refused.
// And §13.15's four routes as SidecarApi sends them: the order routes under the service token, never the client's.
//
// TLS-M8-01's app listeners: a host that stays up runs D-TLS-8's watch and a foreground host none; ListenTls's
// refusals come before any order or registration; a listener serves the network's names on its issued certificate,
// handing Accept only what an audience check passed (FI-11); it ends with its registration and its component; and over
// the real registrar, an app suspended past its 45 s lease lapses there with nothing local closing, and on resume the
// whole set registers it again and a visitor reaches Accept as before.

package sidecar

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

func TestTlsComponentFollowsAGeneration(t *testing.T) {
	fixture := newTlsCertFixture(t)
	fixture.manager.Close()
	reads := make(chan *http.Request, 64)
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			if request.Method != "GET" || request.URL.Path != "/tls/certs" {
				return syntheticResponse(request, 404, "{}", nil), nil
			}
			reads <- request
			return syntheticResponse(request, 200, `{"certs":[]}`, nil), nil
		},
	}
	api := newTestSidecarApi(t, transport)
	subprotocolFixture := newTestSubprotocol(t, nil)
	fetches := make(chan struct{}, 16)
	pushClient, err := newPushClient(t.Context(), &PushClientEnv{
		Subprotocol: subprotocolFixture.subprotocol,
		Store:       newTestPushStore(),
		Clock:       newTestEnvelopeClock(),
		Log:         NewNoopLogger(),
	}, func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		fetches <- struct{}{}
		return &protocol.PollResponse{Reset_: &protocol.PushReset{Epoch: 1, Complete: true}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pushClient.Close()
	testSocketAwait(t, fetches, "the push's first resync")

	var source TlsCertificateSource
	component, err := NewTlsComponent(t.Context(), &TlsComponentArgs{
		Manager: &TlsCertManagerArgs{
			NetworkId: fixture.networkId,
			SidecarId: fixture.sidecarId,
			Settings:  fixture.settings,
			Keys:      fixture.keys,
			Sign:      testTlsSign(fixture.identity, fixture.sidecarId[:]),
			ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
				return "synthetic-service-token", nil
			},
			Names: fixture.names,
			Store: fixture.store,
			Clock: fixture.clock,
			Log:   NewNoopLogger(),
		},
		SetSource: func(installed TlsCertificateSource) error {
			source = installed
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if component.Name() != "tls" || component.Name() != tlsSecretsNamespace {
		t.Errorf("name %q", component.Name())
	}
	// the manager answers TlsDeviceCertificate from the moment the component exists
	if source != TlsCertificateSource(component.CertManager()) {
		t.Errorf("the manager is not installed as the certificate source")
	}

	identity := &SidecarIdentity{NetworkId: fixture.networkId, SidecarId: fixture.sidecarId}
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), SidecarApi: api, Identity: &SidecarIdentity{NetworkId: tlsCertTestId("other network")}}); err == nil {
		t.Errorf("a generation of another network attached")
	}
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), Identity: identity}); err == nil {
		t.Errorf("a generation with no api attached")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err = component.Attach(&SidecarEnv{Ctx: ctx, SidecarApi: api, Identity: identity, Subprotocol: subprotocolFixture.subprotocol, Log: NewNoopLogger()})
	if err != nil {
		t.Fatal(err)
	}
	// the attachment's own pass reads the rows, with the client's token
	first := testSocketAwait(t, reads, "the attachment's read")
	if authorization := first.Header.Get("Authorization"); authorization != "Bearer "+testByJwt {
		t.Errorf("GET /tls/certs was not sent under the client token")
	}
	fixture.clock.awaitTimer(t, fixture.settings.CertHintMinInterval)
	fixture.clock.advance(fixture.settings.CertHintMinInterval)
	fixture.clock.awaitTimer(t, fixture.settings.CertResyncInterval)

	// a hint on topic tls reads them again at once
	certId := NewId()
	hint, err := proto.Marshal(&protocol.TlsHint{Kind: protocol.TlsHintKind_TLS_HINT_ISSUED, CertId: certId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	subprotocolFixture.receive(connect.ControlId, testPushFrame(t, protocol.MessageType_PUSH_HINT, &protocol.PushHint{
		Seq: 1, Topic: PushTopicTls, Version: 5, Kind: uint32(protocol.MessageType_TLS_HINT), Hint: hint,
	}), connect.Peer{TransportType: connect.TransportTypeH1})
	testSocketAwait(t, reads, "the hint's read")

	// the generation's end takes its api back: the next pass is offline
	fixture.clock.awaitTimer(t, fixture.settings.CertHintMinInterval)
	cancel()
	ended := func() chan struct{} {
		component.stateLock.Lock()
		defer component.stateLock.Unlock()
		return component.generationEnded
	}()
	<-ended
	if err := component.CertManager().Sync(t.Context()); !errors.Is(err, ErrTlsCertsOffline) {
		t.Errorf("a pass after the generation ended: %v", err)
	}
	component.Close()
	if source != nil {
		t.Errorf("a closed component is still the certificate source")
	}
}

func TestSidecarWithNoTlsComponentRefuses(t *testing.T) {
	sidecar := newTestSidecar(t)
	if _, err := sidecar.EnsureTlsCertificate(t.Context()); !errors.Is(err, ErrTlsComponentAbsent) {
		t.Errorf("ensure: %v", err)
	}
	if certificates := sidecar.TlsCertificates(); len(certificates) != 0 {
		t.Errorf("certificates %v", certificates)
	}
	if _, err := sidecar.TlsSignLabelReclaim(t.Context(), "abcdefghij.sidecar.example", NewId()); !errors.Is(err, ErrTlsComponentAbsent) {
		t.Errorf("reclaim: %v", err)
	}
	if _, err := NewTlsComponent(t.Context(), nil); !errors.Is(err, errInvalidSettings) {
		t.Errorf("a component with no args: %v", err)
	}
}

func TestSidecarApiTlsRoutes(t *testing.T) {
	const serviceToken = "synthetic-certs-service-token"
	certId := NewId()
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			switch request.Method + " " + request.URL.Path {
			case "POST /tls/cert-order":
				return syntheticResponse(request, 200, `{"cert_id":"`+certId.String()+`","state":"queued","retry_after_ms":250}`, nil), nil
			case "GET /tls/cert-order/" + certId.String():
				return syntheticResponse(request, 200, `{"state":"ordering","retry_after_ms":500}`, nil), nil
			case "GET /tls/certs":
				return syntheticResponse(request, 200, `{"certs":[{"cert_id":"`+certId.String()+`","state":"custom_issued"}]}`, nil), nil
			case "POST /tls/cert-revoke":
				return syntheticResponse(request, 200, `{}`, nil), nil
			}
			return syntheticResponse(request, 404, `{}`, nil), nil
		},
	}
	api := newTestSidecarApi(t, transport)
	settings := validSidecarSettings()

	order, err := api.TlsCertOrder(t.Context(), serviceToken, &TlsCertOrderArgs{Csr: []byte("csr"), Attestation: []byte("attestation"), Replaces: "aki.serial"})
	if err != nil || order.CertId != certId || order.State != TlsCertStateQueued || order.RetryAfterMs != 250 {
		t.Fatalf("order %+v, %v", order, err)
	}
	status, err := api.TlsCertOrderStatus(t.Context(), serviceToken, certId)
	if err != nil || status.State != TlsCertStateOrdering || status.RetryAfterMs != 500 {
		t.Fatalf("status %+v, %v", status, err)
	}
	certs, err := api.TlsCerts(t.Context())
	if err != nil || len(certs.Certs) != 1 || certs.Certs[0].State != TlsCertStateCustomIssued {
		t.Fatalf("certs %+v, %v", certs, err)
	}
	if err := api.TlsCertRevoke(t.Context(), &TlsCertRevokeArgs{CertId: certId, KeyCompromise: true}); err != nil {
		t.Fatal(err)
	}

	transport.stateLock.Lock()
	requests := transport.requests
	bodies := transport.bodies
	transport.stateLock.Unlock()
	if len(requests) != 4 {
		t.Fatalf("%d requests", len(requests))
	}
	// the order routes carry the service token and never the client's; the other two the client's
	wantBearers := []string{serviceToken, serviceToken, testByJwt, testByJwt}
	for index, request := range requests {
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer "+wantBearers[index] {
			t.Errorf("request %d (%s %s) carries another token", index, request.Method, request.URL.Path)
		}
		if request.URL.Scheme+"://"+request.URL.Host != settings.ApiUrl {
			t.Errorf("request %d went to another origin", index)
		}
	}
	sent := &TlsCertOrderArgs{}
	if err := json.Unmarshal(bodies[0], sent); err != nil || string(sent.Csr) != "csr" || string(sent.Attestation) != "attestation" || sent.Replaces != "aki.serial" {
		t.Errorf("the order's body %s", bodies[0])
	}
	revoked := &TlsCertRevokeArgs{}
	if err := json.Unmarshal(bodies[3], revoked); err != nil || revoked.CertId != certId || !revoked.KeyCompromise {
		t.Errorf("the revocation's body %s", bodies[3])
	}

	// refused before sending: no token, no CSR, no id
	for _, refuse := range []func() error{
		func() error {
			_, err := api.TlsCertOrder(t.Context(), "", &TlsCertOrderArgs{Csr: []byte("csr"), Attestation: []byte("attestation")})
			return err
		},
		func() error {
			_, err := api.TlsCertOrder(t.Context(), serviceToken, &TlsCertOrderArgs{Attestation: []byte("attestation")})
			return err
		},
		func() error {
			_, err := api.TlsCertOrderStatus(t.Context(), serviceToken, Id{})
			return err
		},
		func() error {
			return api.TlsCertRevoke(t.Context(), &TlsCertRevokeArgs{})
		},
	} {
		if err := refuse(); !errors.Is(err, ErrSidecarApiArgs) {
			t.Errorf("a call that cannot be one: %v", err)
		}
	}
	// a refusal is the route's error, with its status
	missing, err := api.TlsCertOrderStatus(t.Context(), serviceToken, NewId())
	if apiErr := asSidecarApiError(t, err); missing != nil || apiErr.Status != 404 || apiErr.Route != tlsCertOrderStatusRoute {
		t.Errorf("a missing order: %v", err)
	}
}

func TestSidecarApiTlsRoutesRefuseAnAnswerThatIsNotTheRoutes(t *testing.T) {
	transport := &scriptedApiTransport{
		answer: func(request *http.Request, body []byte) (*http.Response, error) {
			switch request.Method + " " + request.URL.Path {
			case "POST /tls/cert-order":
				return syntheticResponse(request, 200, `{"state":"queued"}`, nil), nil
			case "GET /tls/certs":
				return syntheticResponse(request, 200, `{"certs":[{"state":"issued"}]}`, nil), nil
			}
			return syntheticResponse(request, 200, `{}`, nil), nil
		},
	}
	api := newTestSidecarApi(t, transport)
	if _, err := api.TlsCertOrder(t.Context(), "token", &TlsCertOrderArgs{Csr: []byte("csr"), Attestation: []byte("attestation")}); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("an order's answer with no row: %v", err)
	}
	if _, err := api.TlsCertOrderStatus(t.Context(), "token", NewId()); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("a status with no state: %v", err)
	}
	if _, err := api.TlsCerts(t.Context()); !errors.Is(err, ErrSidecarApiReply) {
		t.Errorf("a row with no id: %v", err)
	}
}

// A base Sidecar on a real keychain, its tls leg on clock, enrolled in testNetworkId with an identity.
func newTlsListenTestSidecar(t *testing.T, clock Clock) *Sidecar {
	t.Helper()
	sidecar, _ := newTlsTestSidecar(t, clock)
	sidecar.identity = &SidecarIdentity{
		NetworkId: testNetworkId,
		SidecarId: tlsCertTestId("tls listen test sidecar"),
		ClientId:  tlsCertTestId("tls listen test client"),
	}
	return sidecar
}

// The watch the Sidecar's status reports, nil for none.
func tlsListenTestAttachedWatch(sidecar *Sidecar) sidecarCtWatch {
	sidecar.tlsCt.stateLock.Lock()
	defer sidecar.tlsCt.stateLock.Unlock()
	return sidecar.tlsCt.watch
}

// D-TLS-8 by host (TLS-M8-01): a host that stays up runs the watch on a CT client of its own, which its component
// attaches to the Sidecar's status until it closes; a foreground host's args carry no watch and no client, the same
// manager otherwise, and its component attaches none.
func TestTlsForegroundComponentArgsRunNoCtWatch(t *testing.T) {
	sidecar := newTlsListenTestSidecar(t, newTlsTestClock())

	stayingUp, err := sidecar.TlsComponentArgs()
	if err != nil {
		t.Fatal(err)
	}
	if stayingUp.CtWatch == nil || len(stayingUp.CtWatch.Sources) != 2 || stayingUp.SetCtWatch == nil || stayingUp.CloseCtSources == nil {
		t.Fatalf("a host that stays up has no watch: %+v", stayingUp)
	}
	component, err := NewTlsComponent(t.Context(), stayingUp)
	if err != nil {
		t.Fatal(err)
	}
	if tlsListenTestAttachedWatch(sidecar) == nil {
		t.Error("the watch is not in the status")
	}
	component.Close()
	if tlsListenTestAttachedWatch(sidecar) != nil {
		t.Error("a closed component's watch is still in the status")
	}

	foreground, err := sidecar.TlsForegroundComponentArgs()
	if err != nil {
		t.Fatal(err)
	}
	if foreground.CtWatch != nil || foreground.SetCtWatch != nil || foreground.CloseCtSources != nil {
		t.Fatalf("a foreground host has a watch: %+v", foreground)
	}
	if foreground.Manager == nil || foreground.Manager.SidecarId != stayingUp.Manager.SidecarId ||
		foreground.Manager.NetworkId != stayingUp.Manager.NetworkId || foreground.SetSource == nil || foreground.sidecar != sidecar {
		t.Errorf("a foreground host's manager differs: %+v", foreground.Manager)
	}
	component, err = NewTlsComponent(t.Context(), foreground)
	if err != nil {
		t.Fatal(err)
	}
	defer component.Close()
	if tlsListenTestAttachedWatch(sidecar) != nil {
		t.Error("a foreground host's component attached a watch")
	}
	if status := component.CtWatchStatus(); status.Degraded || !status.PassTime.IsZero() || len(status.Alarms) != 0 {
		t.Errorf("a foreground host's component reports a watch: %+v", status)
	}

	// a Sidecar not yet enrolled makes neither
	unenrolled, _ := newTlsTestSidecar(t, newTlsTestClock())
	if _, err := unenrolled.TlsForegroundComponentArgs(); err == nil {
		t.Error("args with no identity")
	}
}

// A registration a test hands visitor streams to, with an address and the grant end it registered under, zero for
// none.
type testTlsListenRegistration struct {
	*tlsFrontTestListener
	grantExpireTime time.Time
}

var _ tlsListenRegistration = (*testTlsListenRegistration)(nil)

// See tlsListenRegistration.
func (self *testTlsListenRegistration) Addr() net.Addr {
	return &SocketAddr{}
}

// See tlsListenRegistration.
func (self *testTlsListenRegistration) GrantExpires() time.Time {
	return self.grantExpireTime
}

// Whether the registration was closed.
func (self *testTlsListenRegistration) isClosed() bool {
	select {
	case <-self.closed:
		return true
	default:
		return false
	}
}

// The edge's open of a visitor's stream for serverName, under a ticket from edgeNetworkId whose grant ends at
// grantExpire: the ticket and TlsEdgeOpen's bytes.
func tlsListenTestOpen(t *testing.T, edgeNetworkId Id, serverName string, grantExpire time.Time) (*protocol.SocketTicket, []byte) {
	t.Helper()
	visitor := tlsFrontTestVisitor()
	expireMillis := uint64(grantExpire.UnixMilli())
	metadata, err := proto.Marshal(&protocol.TlsEdgeOpen{
		ClientIp:         visitor.Addr().AsSlice(),
		ClientPort:       uint32(visitor.Port()),
		ServerName:       serverName,
		ConnectionId:     NewId().Bytes(),
		ExpireTimeMillis: expireMillis,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.SocketTicket{DialerNetworkId: edgeNetworkId.Bytes(), GrantExpireTimeMillis: expireMillis}, metadata
}

// Hands registration a visitor's stream for serverName as the edge opens one, and answers the visitor's end.
func tlsListenTestVisit(t *testing.T, registration *testTlsListenRegistration, serverName string, grantExpire time.Time) net.Conn {
	t.Helper()
	ticket, metadata := tlsListenTestOpen(t, registration.edgeNetworkId, serverName, grantExpire)
	listenerEnd, visitorEnd := newSocketStreamPipe(256 * 1024)
	registration.conns <- newSocketConn(listenerEnd, &SocketAddr{}, &SocketAddr{}, ticket, metadata)
	return newSocketConn(visitorEnd, &SocketAddr{}, &SocketAddr{}, nil, nil)
}

// A visitor's HTTP client whose every connection is a fresh stream from dial, handshaken for serverName, that follows
// no redirect.
func tlsListenTestClient(t *testing.T, serverName string, dial func() net.Conn) *http.Client {
	t.Helper()
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			conn := tls.Client(dial(), &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
			if err := conn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// An app's own HTTP server on a listener: it counts the connections it accepts, records each request and answers
// "app".
type testTlsAppServer struct {
	listener net.Listener
	requests chan *tlsFrontTestRequest

	stateLock   sync.Mutex
	acceptCount int
}

// See net.Listener: the listener's Accept, counted.
func (self *testTlsAppServer) Accept() (net.Conn, error) {
	conn, err := self.listener.Accept()
	if err == nil {
		self.stateLock.Lock()
		self.acceptCount += 1
		self.stateLock.Unlock()
	}
	return conn, err
}

// See net.Listener.
func (self *testTlsAppServer) Close() error {
	return self.listener.Close()
}

// See net.Listener.
func (self *testTlsAppServer) Addr() net.Addr {
	return self.listener.Addr()
}

// How many connections the server has accepted.
func (self *testTlsAppServer) accepted() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.acceptCount
}

// Serves listener until the test ends.
func serveTestTlsApp(t *testing.T, listener net.Listener) *testTlsAppServer {
	t.Helper()
	app := &testTlsAppServer{listener: listener, requests: make(chan *tlsFrontTestRequest, 16)}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.requests <- &tlsFrontTestRequest{method: r.Method, host: r.Host, path: r.URL.RequestURI(), header: r.Header.Clone()}
		io.WriteString(w, "app")
	})}
	served := make(chan struct{})
	go func() {
		defer close(served)
		server.Serve(app)
	}()
	t.Cleanup(func() {
		server.Close()
		<-served
	})
	return app
}

// A request the visitor sends to target on the endpoint.
func tlsListenTestRequest(t *testing.T, serverName string, target string) *http.Request {
	t.Helper()
	request, err := http.NewRequest("GET", "https://"+serverName+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// A listener on a test registration for tls/443/app under policy, its front on clock, its certificate self-signed
// for the fixture's server name, and every time it is untracked sent on untracked.
func newTlsListenTestListener(t *testing.T, clock Clock, registration tlsListenRegistration, policy TlsFrontPolicy, untracked chan *TlsListener) *TlsListener {
	t.Helper()
	key, err := newTlsDeviceKey(clock.Now(), TlsKeyRotationNone)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := newTlsSelfSignedCertificate(key, []string{tlsFrontTestServerName}, clock.Now(), DefaultSidecarTlsSettings())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := newTlsListener(t.Context(), &TlsFrontArgs{
		Target: &TlsFrontTarget{
			Name:         tlsFrontTestName,
			ServerNames:  []string{tlsFrontTestServerName},
			AppMode:      "http",
			LocalAddress: tlsListenerTargetAddress,
		},
		NetworkId: NewId(),
		SidecarId: NewId(),
		Policy:    policy,
		Certificate: func(serverName string) (*tls.Certificate, error) {
			return certificate, nil
		},
		Secrets:   newTlsFrontTestSecrets(),
		IssuerUrl: tlsFrontTestIssuer,
		// the notice is its own tests'
		Limits: func(ctx context.Context) (*QuotaLimits, error) {
			return &QuotaLimits{Tier: "pro"}, nil
		},
		Clock: clock,
		Log:   NewNoopLogger(),
	}, registration, func(listener *TlsListener) {
		if untracked != nil {
			untracked <- listener
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

// FI-11 through an app listener: a visitor its public grant admits reaches the app's own server as plain HTTP/1.1,
// its Host kept and its address nowhere; the registration takes no probe; and under members with no session the front
// answers the visitor itself, so Accept is handed nothing.
func TestTlsListenerHandsAcceptOnlyWhatAnAudienceCheckPassed(t *testing.T) {
	clock := newTlsFrontTestClock()
	registration := &testTlsListenRegistration{tlsFrontTestListener: newTlsFrontTestListener(NewId())}
	policy := newTlsFrontTestPolicy()
	policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_PUBLIC, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	listener := newTlsListenTestListener(t, clock, registration, policy, nil)
	app := serveTestTlsApp(t, listener)
	grantExpire := clock.Now().Add(24 * time.Hour)
	visit := func() net.Conn {
		return tlsListenTestVisit(t, registration, tlsFrontTestServerName, grantExpire)
	}

	response, body := tlsFrontTestDo(t, tlsListenTestClient(t, tlsFrontTestServerName, visit), tlsListenTestRequest(t, tlsFrontTestServerName, "/hello?x=1"))
	if response.StatusCode != http.StatusOK || body != "app" {
		t.Fatalf("the visitor got %d %q", response.StatusCode, body)
	}
	request := testSocketAwait(t, app.requests, "the app's request")
	if request.method != "GET" || request.host != tlsFrontTestServerName || request.path != "/hello?x=1" {
		t.Errorf("the app saw %+v", request)
	}
	for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Real-Ip"} {
		if request.header.Get(header) != "" {
			t.Errorf("the app was told the visitor's address in %s", header)
		}
	}
	if app.accepted() != 1 {
		t.Errorf("%d connections accepted for one visitor", app.accepted())
	}
	func() {
		registration.stateLock.Lock()
		defer registration.stateLock.Unlock()
		if len(registration.servingChanges) != 0 {
			t.Errorf("a probe moved serving: %v", registration.servingChanges)
		}
	}()
	if listener.Addr() == nil {
		t.Error("no address")
	}

	policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	response, _ = tlsFrontTestDo(t, tlsListenTestClient(t, tlsFrontTestServerName, visit), tlsFrontTestNavigation(t, "GET", "/private"))
	if response.StatusCode == http.StatusOK {
		t.Errorf("a members endpoint answered a visitor with no session")
	}
	if app.accepted() != 1 {
		t.Errorf("Accept was handed a connection before an audience check passed: %d", app.accepted())
	}
	select {
	case request := <-app.requests:
		t.Errorf("the app saw a refused request %+v", request)
	default:
	}
}

// A listener ends with its registration, however the registration ends: its Accepts answer net.ErrClosed and it
// leaves its component's once. Its own Close unlistens: the registration closes, and a second Close does nothing.
func TestTlsListenerEndsWithItsRegistration(t *testing.T) {
	clock := newTlsFrontTestClock()
	policy := newTlsFrontTestPolicy()
	policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_PUBLIC, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	untracked := make(chan *TlsListener, 4)

	// the registration ends from outside, as the registrar's revoked answer ends it
	registration := &testTlsListenRegistration{tlsFrontTestListener: newTlsFrontTestListener(NewId())}
	listener := newTlsListenTestListener(t, clock, registration, policy, untracked)
	accepted := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		accepted <- err
	}()
	registration.tlsFrontTestListener.Close()
	if err := testSocketAwait(t, accepted, "the Accept's end"); !errors.Is(err, net.ErrClosed) {
		t.Errorf("an Accept on an ended registration: %v", err)
	}
	if testSocketAwait(t, untracked, "the untrack") != listener {
		t.Error("another listener untracked")
	}
	if _, err := listener.AcceptContext(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("an Accept after the end: %v", err)
	}

	// its own Close
	registration = &testTlsListenRegistration{tlsFrontTestListener: newTlsFrontTestListener(NewId())}
	listener = newTlsListenTestListener(t, clock, registration, policy, untracked)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if !registration.isClosed() {
		t.Error("Close left the registration")
	}
	if testSocketAwait(t, untracked, "the untrack") != listener {
		t.Error("another listener untracked")
	}
	if err := listener.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
	select {
	case <-untracked:
		t.Error("untracked twice")
	default:
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := listener.AcceptContext(ctx); !errors.Is(err, net.ErrClosed) {
		t.Errorf("an Accept after Close: %v", err)
	}
}

// What a component's listen registered, in order.
type testTlsListenRegistrations struct {
	stateLock sync.Mutex
	addresses []string
	settings  []*SocketListenSettings
	// answered in place of a registration, when set
	err error
	// the registration handed out for each call
	registrations []*testTlsListenRegistration
	edgeNetworkId Id
	// the grant end each registration comes to, zero for none
	grantExpireTime time.Time
}

// See tlsListenParts.Register.
func (self *testTlsListenRegistrations) register(ctx context.Context, address string, settings *SocketListenSettings) (tlsListenRegistration, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.addresses = append(self.addresses, address)
	copied := *settings
	self.settings = append(self.settings, &copied)
	if self.err != nil {
		return nil, self.err
	}
	registration := &testTlsListenRegistration{tlsFrontTestListener: newTlsFrontTestListener(self.edgeNetworkId), grantExpireTime: self.grantExpireTime}
	self.registrations = append(self.registrations, registration)
	return registration, nil
}

// How many registrations were asked for.
func (self *testTlsListenRegistrations) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.addresses)
}

// A component over fixture's keys and store, as a Sidecar makes one, and the parts its listens run on, registering
// through registrations under a public grant.
func newTlsListenTestComponent(t *testing.T, fixture *tlsCertFixture, registrations *testTlsListenRegistrations) (*TlsComponent, *tlsListenParts) {
	t.Helper()
	component, err := NewTlsComponent(t.Context(), &TlsComponentArgs{
		Manager: &TlsCertManagerArgs{
			NetworkId: fixture.networkId,
			SidecarId: fixture.sidecarId,
			Settings:  fixture.settings,
			Keys:      fixture.keys,
			Sign:      testTlsSign(fixture.identity, fixture.sidecarId[:]),
			ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
				return "service token for " + resource, nil
			},
			Names: fixture.names,
			Store: fixture.store,
			Clock: fixture.clock,
			Log:   NewNoopLogger(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(component.Close)
	policy := newTlsFrontTestPolicy()
	policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_PUBLIC, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	return component, &tlsListenParts{
		NetworkId: fixture.networkId,
		SidecarId: fixture.sidecarId,
		Register:  registrations.register,
		Policy:    policy,
		Secrets:   newTlsFrontTestSecrets(),
		IssuerUrl: tlsFrontTestIssuer,
		Clock:     fixture.clock,
		Log:       NewNoopLogger(),
	}
}

// ListenTls's order: a name it cannot serve is refused before anything is ordered or registered, and with no
// certificate to be had nothing registers; a Sidecar with no tls component refuses.
func TestTlsComponentListenRefusesBeforeOrderingOrRegistering(t *testing.T) {
	// no api attached: an order would answer offline
	fixture := newTlsCertFixture(t)
	registrations := &testTlsListenRegistrations{edgeNetworkId: NewId()}
	component, parts := newTlsListenTestComponent(t, fixture, registrations)
	for _, address := range []string{"db/primary", "smtp/25/mx", "tls/443/blog.team", "tls/443/mta-sts", "tls/80/www", "tls/443", "not a name"} {
		if _, err := component.listen(t.Context(), address, nil, parts); !errors.Is(err, ErrTlsListenInvalid) {
			t.Errorf("%s: %v", address, err)
		}
	}
	if _, err := component.listen(t.Context(), "tls/443/app", nil, parts); !errors.Is(err, ErrTlsCertsOffline) {
		t.Errorf("a listen with no certificate to be had: %v", err)
	}
	if registrations.count() != 0 || fixture.api.orderCount() != 0 || component.listening() {
		t.Errorf("%d registrations and %d orders for refused listens", registrations.count(), fixture.api.orderCount())
	}

	// a network with no name yet: nothing ordered either
	fixture.stateLock.Lock()
	fixture.namesErr = errors.New("the zone is not there to read")
	fixture.stateLock.Unlock()
	if _, err := component.listen(t.Context(), "tls/443/app", nil, parts); err == nil {
		t.Error("a listen with no names")
	}
	if registrations.count() != 0 {
		t.Error("a listen with no names registered")
	}

	if _, err := newTestSidecar(t).ListenTls(t.Context(), "tls/443/app", nil); !errors.Is(err, ErrTlsComponentAbsent) {
		t.Errorf("a Sidecar with no tls component: %v", err)
	}
}

// ListenTls's way: the name registers as protocol tls, app mode http with h2 and http/1.1, the caller's weight and
// §9.5's default max_streams; the
// front serves the network's names on the device's issued certificate, never the self-signed leaf, and hands Accept
// the visitor's request; the gate's pending answer comes back as itself with nothing kept; and the component's Close
// ends its listeners.
func TestTlsComponentListenServesTheNetworksNamesOnItsIssuedCertificate(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.ensureIssued()
	registrations := &testTlsListenRegistrations{edgeNetworkId: NewId()}
	component, parts := newTlsListenTestComponent(t, fixture, registrations)

	listener, err := component.listen(t.Context(), "tls/443/app", &TlsListenSettings{Weight: 250}, parts)
	if err != nil {
		t.Fatal(err)
	}
	if registrations.count() != 1 || registrations.addresses[0] != "tls/443/app" {
		t.Fatalf("registered %v", registrations.addresses)
	}
	settings := registrations.settings[0]
	if settings.Protocol != "tls" || settings.AppMode != "http" || !slices.Equal(settings.Alpn, []string{"h2", "http/1.1"}) ||
		settings.Weight != 250 || settings.MaxStreams != 0 || settings.Decision != nil {
		t.Errorf("the registration's settings %+v", settings)
	}
	if !component.listening() {
		t.Error("the component does not count its listener")
	}

	serverName := "app." + tlsCertTestLabel + "." + tlsCertTestRoot
	registration := registrations.registrations[0]
	grantExpire := fixture.clock.Now().Add(24 * time.Hour)
	visit := func() net.Conn {
		return tlsListenTestVisit(t, registration, serverName, grantExpire)
	}
	conn := tls.Client(visit(), &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	if err := conn.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	issued, err := component.CertManager().PublishCertificate([]string{serverName})
	if err != nil {
		t.Fatal(err)
	}
	if presented := conn.ConnectionState().PeerCertificates; len(presented) == 0 || !slices.Equal(presented[0].Raw, issued.Leaf.Raw) {
		t.Error("the front presented another certificate than the issued one")
	}
	conn.Close()

	app := serveTestTlsApp(t, listener)
	response, body := tlsFrontTestDo(t, tlsListenTestClient(t, serverName, visit), tlsListenTestRequest(t, serverName, "/"))
	if response.StatusCode != http.StatusOK || body != "app" {
		t.Fatalf("the visitor got %d %q", response.StatusCode, body)
	}
	if request := testSocketAwait(t, app.requests, "the app's request"); request.host != serverName {
		t.Errorf("the app saw host %q", request.host)
	}

	// the gate's pending answer reaches the caller as itself
	approvalId := NewId()
	registrations.err = &ApprovalPendingError{ApprovalId: approvalId}
	_, err = component.listen(t.Context(), "tls/443/shop", nil, parts)
	var pending *ApprovalPendingError
	if !errors.As(err, &pending) || pending.ApprovalId != approvalId {
		t.Errorf("a pending listen: %v", err)
	}
	registrations.err = nil

	second, err := component.listen(t.Context(), "tls/8443/app", nil, parts)
	if err != nil {
		t.Fatal(err)
	}
	component.Close()
	if _, err := second.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("an Accept after the component closed: %v", err)
	}
	if !registrations.registrations[1].isClosed() || component.listening() {
		t.Error("the component's Close left a listener")
	}
}

// One call that reached the lease service, with the registrar's wait count as the call arrived.
type testTlsLeaseCall struct {
	args  *SocketRegistrationsArgs
	waits uint64
}

// The sockets service as §9.5's lease: each call that reaches it holds each entry it carries for 45 s on its clock,
// answering ok with the fixture's keys and urnetwork-edge. A suspended app's calls reach no service: each is held,
// whatever its context, until the test fails it. A frozen app sees its call fail only once it runs again, so the
// registrar reads the failure's time after the clock's jump and never in the middle of it, where the test clock stops
// at each timer on its way: a failure read there has its retry due, or fired, before the jump ends, and the app would
// fail a second time while suspended and wait a doubled backoff.
type testTlsLeaseService struct {
	clock         Clock
	registrar     *socketRegistrar
	urnetworkEdge Id
	calls         chan *testTlsLeaseCall
	// the registrar's wait count at each call a suspended app made, as the call is held
	held chan uint64
	// each value fails one held call
	fail chan struct{}
	// closed at the test's end, which fails every call still held
	done <-chan struct{}

	stateLock sync.Mutex
	suspended bool
	// each name's lease end
	leases map[string]time.Time
}

// See socketRegistrationsFunction.
func (self *testTlsLeaseService) registrations(ctx context.Context, args *SocketRegistrationsArgs) (*SocketRegistrationsResult, error) {
	waits := self.registrar.waitCount.Value()
	now := self.clock.Now()
	suspended := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.suspended {
			return true
		}
		for _, registration := range args.Registrations {
			self.leases[registration.Name] = now.Add(45 * time.Second)
		}
		return false
	}()
	if suspended {
		self.held <- waits
		select {
		case <-self.fail:
		case <-self.done:
		}
		return nil, errors.New("a suspended app's call reaches no service")
	}
	self.calls <- &testTlsLeaseCall{args: args, waits: waits}
	statuses := make([]SocketRegistrationStatus, len(args.Registrations))
	for i := range statuses {
		statuses[i] = SocketRegistrationStatusOk
	}
	urnetworkEdge := connect.Id(self.urnetworkEdge)
	return &SocketRegistrationsResult{
		Statuses:         statuses,
		SetVersion:       args.SetVersion,
		ServerTimeMillis: uint64(now.UnixMilli()),
		TicketKeys: []*SocketTicketKey{{
			KeyId:            testAdmissionKeyId,
			PublicKey:        testAdmissionKey.Public().(ed25519.PublicKey),
			ExpireTimeMillis: uint64(testSocketNow.Add(24 * time.Hour).UnixMilli()),
		}},
		UrnetworkEdge: &urnetworkEdge,
	}, nil
}

// Sets whether the app is suspended.
func (self *testTlsLeaseService) setSuspended(suspended bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.suspended = suspended
}

// Whether name holds a lease at the service now.
func (self *testTlsLeaseService) leased(name string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	until, ok := self.leases[name]
	return ok && self.clock.Now().Before(until)
}

// Waits until registrar's loop has gone to wait more than count times: whatever it does next waits on a timer it has
// armed.
func awaitTlsListenRegistrarWait(t *testing.T, registrar *socketRegistrar, count uint64) {
	t.Helper()
	deadline := time.After(testSocketAwaitTimeout)
	for {
		current, changed := registrar.waitCount.Get()
		if count < current {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatal("the registrar never went to wait")
		}
	}
}

// One visitor's request through the listen fixture's admission, as the edge splices it: an edge ticket admitted on
// listener's generation, the TLS handshake on the front, and a GET whose answer must be the app's.
func tlsListenTestVisitThroughAdmission(t *testing.T, fixture *testListenFixture, listener *SocketListener, urnetworkEdge Id) {
	t.Helper()
	grantExpire := fixture.clock.Now().Add(time.Hour)
	_, metadata := tlsListenTestOpen(t, urnetworkEdge, tlsFrontTestServerName, grantExpire)
	edgeTicket := fixture.ticket(t, listener, func(ticket *protocol.SocketTicket) {
		ticket.DialerNetworkId = urnetworkEdge.Bytes()
		ticket.GrantExpireTimeMillis = uint64(grantExpire.UnixMilli())
	})
	listenerEnd, visitorEnd := newSocketStreamPipe(256 * 1024)
	request := &socketAdmissionRequest{ticketBytes: edgeTicket, sourceId: fixture.dialerId, edge: true}
	if err := listener.acceptStream(context.Background(), fixture.generation, request, func() socketStream { return listenerEnd }, metadata); err != nil {
		t.Fatalf("the edge's open: %v", err)
	}
	conn := tls.Client(newSocketConn(visitorEnd, &SocketAddr{}, &SocketAddr{}, nil, nil), &tls.Config{
		ServerName:         tlsFrontTestServerName,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true,
	})
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /resumed HTTP/1.1\r\nHost: "+tlsFrontTestServerName+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "app" {
		t.Fatalf("the visitor got %d %q %v", response.StatusCode, body, err)
	}
}

// §13.17's app listener through suspension, over the real registrar and admission (TLS-M8-01's foreground listen,
// background lapse and resume): an app listens and is served; suspended, its heartbeat's call reaches no service and
// hangs while its clock jumps two hours, so its 45 s lease lapses at the service, and nothing here closes the
// listener, its registration or its entry; the call fails once, after the jump, and on resume the registrar's next
// try sends the whole set, which registers the same listen again, and a visitor reaches Accept as before.
func TestTlsListenerLapsesByLeaseAndRegistersAgainOnResume(t *testing.T) {
	fixture := newTestListenFixture(t)
	fixture.grantStandingListens(t, tlsFrontTestName)
	registrar := fixture.component.registrar
	service := &testTlsLeaseService{
		clock:         fixture.clock,
		registrar:     registrar,
		urnetworkEdge: fixture.service.urnetworkEdge,
		calls:         make(chan *testTlsLeaseCall, 64),
		held:          make(chan uint64, 64),
		fail:          make(chan struct{}, 64),
		done:          t.Context().Done(),
		leases:        map[string]time.Time{},
	}
	registrar.attach(t.Context(), service.registrations, fixture.generation.identity.IdentityPublicKey)

	// in the foreground
	target := &TlsFrontTarget{Name: tlsFrontTestName, ServerNames: []string{tlsFrontTestServerName}, AppMode: "http", LocalAddress: tlsListenerTargetAddress}
	socketListener := fixture.listen(t, tlsFrontTestName, TlsFrontListenSettings(target, false))
	first := testSocketAwait(t, service.calls, "the listen's registration")
	if len(first.args.Registrations) != 1 || first.args.Registrations[0].Name != tlsFrontTestName ||
		Id(*first.args.Registrations[0].ListenId) != socketListener.listenId {
		t.Fatalf("the registration %+v", first.args.Registrations)
	}
	policy := newTlsFrontTestPolicy()
	policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_PUBLIC, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	listener := newTlsListenTestListener(t, newTlsFrontTestClock(), socketListener, policy, nil)
	serveTestTlsApp(t, listener)
	tlsListenTestVisitThroughAdmission(t, fixture, socketListener, fixture.service.urnetworkEdge)
	if !service.leased(tlsFrontTestName) {
		t.Fatal("a foreground listen holds no lease")
	}
	// the heartbeat is armed
	awaitTlsListenRegistrarWait(t, registrar, first.waits)

	// suspended for two hours: the heartbeat's call reaches nothing and hangs through the jump, and the lease lapses
	service.setSuspended(true)
	fixture.clock.advance(2 * time.Hour)
	waits := testSocketAwait(t, service.held, "a suspended app's heartbeat")
	// the call fails where the jump left the clock, so the one retry is armed from there
	service.fail <- struct{}{}
	awaitTlsListenRegistrarWait(t, registrar, waits)
	select {
	case <-service.held:
		t.Fatal("the suspended app called a second time before its retry was due")
	default:
	}
	if service.leased(tlsFrontTestName) {
		t.Error("the lease outlived the suspension")
	}
	select {
	case <-listener.closed:
		t.Fatal("the listener closed while the app was suspended")
	default:
	}
	func() {
		socketListener.stateLock.Lock()
		defer socketListener.stateLock.Unlock()
		if socketListener.closing || !socketListener.held {
			t.Errorf("the registration ended locally: closing %v, held %v", socketListener.closing, socketListener.held)
		}
	}()
	select {
	case call := <-service.calls:
		t.Fatalf("a call reached the service while suspended: %+v", call.args)
	default:
	}

	// resumed: the retry, at most RetryInterval and its jitter later, registers the same listen again
	service.setSuspended(false)
	settings := DefaultSidecarSocketSettings()
	fixture.clock.advance(time.Duration(float64(settings.RetryInterval) * (1 + settings.Jitter)))
	again := testSocketAwait(t, service.calls, "the registration on resume")
	found := slices.ContainsFunc(again.args.Registrations, func(registration *SocketRegistration) bool {
		return registration.Name == tlsFrontTestName && registration.ListenId != nil && Id(*registration.ListenId) == socketListener.listenId &&
			registration.AppMode == "http" && registration.Protocol == "tls"
	})
	if !found {
		t.Fatalf("the resumed call %+v", again.args.Registrations)
	}
	if !service.leased(tlsFrontTestName) {
		t.Error("the resumed registration holds no lease")
	}
	tlsListenTestVisitThroughAdmission(t, fixture, socketListener, fixture.service.urnetworkEdge)
}

// A device orders only active, grant-bound mappings. Pending names remain available for ACME on the correct front;
// reassigning a host removes it from the previous listener even if its certificate did not change.
func TestTlsDeviceZoneRoutesCustomCertificatesByOwner(t *testing.T) {
	zone := &DnsZone{Root: "operator.example.", Label: "network", Alias: "alias"}
	zone.CustomHosts = []DnsCustomHost{
		{Host: "shop.customer.example", Owner: "shop.network.operator.example.", State: DnsCustomHostStateActive},
		{Host: "other.customer.example", Owner: "other.network.operator.example.", State: DnsCustomHostStateActive},
		{Host: "pending.customer.example", Owner: "shop.network.operator.example.", State: DnsCustomHostStatePending},
		{Host: "foreign.customer.example", Owner: "shop.foreign.operator.example.", State: DnsCustomHostStateActive},
		{Host: "wrong.operator.example", Owner: "shop.network.operator.example.", State: DnsCustomHostStateActive},
	}
	names := tlsDeviceZoneNames(zone, "", func(owner string) bool { return owner == "shop" })
	if tlsCustomHostReady(zone, "shop.customer.example", "shop") {
		t.Fatal("an active mapping whose interfaces are pending was ready for ALPN")
	}
	zone.CustomHosts[0].Ready = true
	if !tlsCustomHostReady(zone, "shop.customer.example", "shop") || tlsCustomHostReady(zone, "shop.customer.example", "other") {
		t.Fatal("ALPN readiness did not identify the mapped owner")
	}
	if names.Root != "operator.example" || !slices.Equal(names.CustomHosts, []string{"shop.customer.example"}) {
		t.Fatalf("the device's names: %+v", names)
	}
	scoped := tlsDeviceZoneNames(zone, "team", nil)
	if got, err := tlsPublishServerNames("www.team", scoped); err != nil || !slices.Equal(got, []string{"www.team.network.operator.example"}) {
		t.Fatalf("the scope's host: %v, %v", got, err)
	}
	if _, err := tlsPublishServerNames("www.other", scoped); err == nil {
		t.Fatal("a device served a different scope")
	}
	fixture := newTlsCertFixture(t)
	manager := fixture.manager
	manager.setCustomOwners(names.CustomHostOwners)
	shop := &tlsFrontOwnerCertificates{manager: manager, owner: "shop"}
	other := &tlsFrontOwnerCertificates{manager: manager, owner: "other"}
	if entries := shop.CustomCertificates(); len(entries) != 1 || entries[0].Name != "shop.customer.example" || entries[0].Certificate != nil || len(other.CustomCertificates()) != 0 {
		t.Fatalf("the mapped owner's pending entry: %+v", entries)
	}
	changed := shop.CustomChanged()
	manager.setCustomOwners(map[string]string{"shop.customer.example": "other"})
	select {
	case <-changed:
	default:
		t.Fatal("the registration was not woken by reassignment")
	}
	if len(shop.CustomCertificates()) != 0 || len(other.CustomCertificates()) != 1 {
		t.Fatal("the old endpoint retained the mapping")
	}
}
