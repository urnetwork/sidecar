//go:build !sidecar_http && !ios_extension && !js

package sidecar

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// §13.9's system publish on the receiver (TLS-M8-02, §22.5's row: mta-sts served only as a receiver's system
// publish): the composition registers tls/443/mta-sts only through the receiver's own path, serves mta-sts under the
// network's names on the issued certificate, hands each request to the mail component with no interstitial and no
// port, and ends with its registration; the front takes a handler for the system publish alone, and refuses another
// name taking its path.

// A handler standing in for the mail component's MTA-STS policy: it records each request's path, host and headers.
type testTlsPolicyHandler struct {
	requests chan *http.Request
}

func newTestTlsPolicyHandler() *testTlsPolicyHandler {
	return &testTlsPolicyHandler{requests: make(chan *http.Request, 16)}
}

// See http.Handler: the policy, and a cookie and an Alt-Svc h3 the front must take off.
func (self *testTlsPolicyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	self.requests <- r
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Add("Set-Cookie", tlsSessionCookieName+"=forged")
	w.Header().Set("Alt-Svc", `h3=":443"`)
	w.Write([]byte("version: STSv1\nmode: enforce\n"))
}

// The composition's order: no handler is refused before anything is ordered or registered; with the network's
// certificate the name registers as tls/443/mta-sts, http, h2 and http/1.1, through the parts' register alone.
func TestTlsSystemPublishRegistersOnlyItsOwnName(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.ensureIssued()
	registrations := &testTlsListenRegistrations{edgeNetworkId: NewId()}
	component, parts := newTlsListenTestComponent(t, fixture, registrations)
	if _, err := component.serveSystemPublish(t.Context(), nil, nil, parts); !errors.Is(err, ErrTlsListenInvalid) {
		t.Fatalf("no handler: %v", err)
	}
	if registrations.count() != 0 {
		t.Fatal("a refused publish registered")
	}
	publish, err := component.serveSystemPublish(t.Context(), newTestTlsPolicyHandler(), &TlsSystemPublishSettings{Weight: 50}, parts)
	if err != nil {
		t.Fatal(err)
	}
	defer publish.Close()
	if registrations.count() != 1 || registrations.addresses[0] != "tls/443/mta-sts" {
		t.Fatalf("registered %v", registrations.addresses)
	}
	settings := registrations.settings[0]
	if settings.Protocol != "tls" || settings.AppMode != "http" || !slices.Equal(settings.Alpn, []string{"h2", "http/1.1"}) ||
		settings.Weight != 50 || settings.Decision != nil {
		t.Errorf("the registration's settings %+v", settings)
	}
	if _, err := newTestSidecar(t).ServeTlsSystemPublish(t.Context(), newTestTlsPolicyHandler(), nil); !errors.Is(err, ErrTlsComponentAbsent) {
		t.Errorf("a Sidecar with no tls component: %v", err)
	}
}

// Serving: a sending MTA's request for the policy, on a Community network whose public endpoints show the notice,
// reaches the mail component and no interstitial, on the issued certificate for mta-sts.<net>.<root>; the request
// loses the front's cookies and forwarded headers, the answer its Alt-Svc h3 and the front's cookies; and the publish
// ends with its registration.
func TestTlsSystemPublishHandsTheRequestToTheMailComponent(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.ensureIssued()
	registrations := &testTlsListenRegistrations{edgeNetworkId: NewId()}
	component, parts := newTlsListenTestComponent(t, fixture, registrations)
	handler := newTestTlsPolicyHandler()
	publish, err := component.serveSystemPublish(t.Context(), handler, nil, parts)
	if err != nil {
		t.Fatal(err)
	}
	serverName := "mta-sts." + tlsCertTestLabel + "." + tlsCertTestRoot
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

	request := tlsListenTestRequest(t, serverName, "/.well-known/mta-sts.txt")
	request.Header.Set(tlsHttpHeaderFetchSite, tlsFetchSiteNone)
	request.Header.Set(tlsHttpHeaderFetchMode, tlsFetchModeNavigate)
	request.Header.Set(tlsHttpHeaderFetchDest, tlsFetchDestDocument)
	request.Header.Set("Forwarded", "for=192.0.2.1")
	request.Header.Set("X-Forwarded-For", "192.0.2.1")
	request.AddCookie(&http.Cookie{Name: tlsSessionCookieName, Value: "visitor"})
	response, body := tlsFrontTestDo(t, tlsListenTestClient(t, serverName, visit), request)
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(body, "version: STSv1") {
		t.Fatalf("the sending MTA got %d %q", response.StatusCode, body)
	}
	if response.Header.Get("Alt-Svc") != "" || len(response.Header.Values("Set-Cookie")) != 0 {
		t.Errorf("the answer kept %v and %v", response.Header.Values("Alt-Svc"), response.Header.Values("Set-Cookie"))
	}
	seen := testSocketAwait(t, handler.requests, "the policy request")
	if seen.URL.Path != "/.well-known/mta-sts.txt" || seen.Host != serverName {
		t.Errorf("the component saw %s on %s", seen.URL.Path, seen.Host)
	}
	if seen.Header.Get("Forwarded") != "" || seen.Header.Get("X-Forwarded-For") != "" || seen.Header.Get("Cookie") != "" {
		t.Errorf("the component saw %v", seen.Header)
	}

	registration.Close()
	if _, err := publish.front.listener.AcceptSocket(context.Background()); err == nil {
		t.Error("the registration still accepts after it closed")
	}
	if err := publish.Close(); err != nil {
		t.Errorf("a second close: %v", err)
	}
}

// The front's target takes a handler for the system publish alone: a handler on another name, the system publish with
// a port, raw, a visitor address or no handler, and another name claiming to be the system publish are refused.
func TestTlsFrontTakesAHandlerForTheSystemPublishAlone(t *testing.T) {
	handler := newTestTlsPolicyHandler()
	valid := func() *TlsFrontTarget {
		return &TlsFrontTarget{
			Name:          tlsSystemPublishName,
			ServerNames:   []string{"mta-sts.example-label.sidecar.example"},
			AppMode:       "http",
			SystemPublish: true,
			Handler:       handler,
		}
	}
	if _, err := newTlsFrontTarget(valid()); err != nil {
		t.Fatalf("the system publish's target: %v", err)
	}
	for _, c := range []struct {
		name   string
		mutate func(target *TlsFrontTarget)
	}{
		{name: "a handler on another name", mutate: func(target *TlsFrontTarget) {
			target.Name = "tls/443/app"
			target.SystemPublish = false
		}},
		{name: "another name as the system publish", mutate: func(target *TlsFrontTarget) {
			target.Name = "tls/443/app"
		}},
		{name: "mta-sts on another port", mutate: func(target *TlsFrontTarget) {
			target.Name = "tls/8443/mta-sts"
		}},
		{name: "the system publish with no handler", mutate: func(target *TlsFrontTarget) {
			target.Handler = nil
			target.LocalAddress = "127.0.0.1:8080"
		}},
		{name: "the system publish with a port", mutate: func(target *TlsFrontTarget) {
			target.LocalAddress = "127.0.0.1:8080"
		}},
		{name: "the system publish raw", mutate: func(target *TlsFrontTarget) {
			target.AppMode = "raw"
		}},
		{name: "the system publish with a Forwarded header", mutate: func(target *TlsFrontTarget) {
			target.Forwarded = true
		}},
		{name: "the system publish with PROXY", mutate: func(target *TlsFrontTarget) {
			target.ProxyProtocol = true
		}},
		{name: "mta-sts as an ordinary endpoint", mutate: func(target *TlsFrontTarget) {
			target.SystemPublish = false
			target.Handler = nil
			target.LocalAddress = "127.0.0.1:8080"
		}},
	} {
		target := valid()
		c.mutate(target)
		if _, err := newTlsFrontTarget(target); !errors.Is(err, errInvalidSettings) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// an ordinary endpoint still needs its port
	if _, err := newTlsFrontTarget(&TlsFrontTarget{Name: "tls/443/app", ServerNames: []string{"app.example-label.sidecar.example"}}); !errors.Is(err, errInvalidSettings) {
		t.Errorf("an endpoint with no port: %v", err)
	}
}

// The handler is reached only past the audience check's pass: with no grant in this device's config, the receiver's
// smtp/25/mx listen grant revoked, the handshake fails and the component hears nothing.
func TestTlsSystemPublishEndsWithTheReceiversGrant(t *testing.T) {
	fixture := newAttachedTlsCertFixture(t)
	fixture.ensureIssued()
	registrations := &testTlsListenRegistrations{edgeNetworkId: NewId()}
	component, parts := newTlsListenTestComponent(t, fixture, registrations)
	policy := newTlsFrontTestPolicy()
	parts.Policy = policy
	handler := newTestTlsPolicyHandler()
	publish, err := component.serveSystemPublish(t.Context(), handler, nil, parts)
	if err != nil {
		t.Fatal(err)
	}
	defer publish.Close()
	serverName := "mta-sts." + tlsCertTestLabel + "." + tlsCertTestRoot
	registration := registrations.registrations[0]
	grantExpire := fixture.clock.Now().Add(24 * time.Hour)
	// no grant: the policy holds none
	conn := tls.Client(tlsListenTestVisit(t, registration, serverName, grantExpire), &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	if err := conn.HandshakeContext(t.Context()); err == nil {
		t.Fatal("a handshake with no receiver's grant")
	}
	conn.Close()
	// the grant stands: the policy is served
	policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_PUBLIC, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	visit := func() net.Conn {
		return tlsListenTestVisit(t, registration, serverName, grantExpire)
	}
	response, _ := tlsFrontTestDo(t, tlsListenTestClient(t, serverName, visit), tlsListenTestRequest(t, serverName, "/.well-known/mta-sts.txt"))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("with the grant: %d", response.StatusCode)
	}
	testSocketAwait(t, handler.requests, "the policy request")
}
