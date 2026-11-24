//go:build !sidecar_http && !ios_extension && !js

// certs' calls renew a token certs answered 401 (tls_component.go's file comment), over dns_certs_401_refresh_test.go's
// renewal world: the certificate manager's order and status read on the api the tls component lends it for a
// generation, and an ordering desktop's custom routes as Sidecar.TlsCustomOrdererDeps builds them, each under the
// Sidecar's own certs token, which its keeper keeps and drops.

package sidecar

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// A renewal world whose keeper is a tls test Sidecar on a cert fixture's clock, with api's certs routes behind certs'
// guard over the fixture's test CA: an order is issued at once while issueAtOnce holds, else when a test issues it, a
// status read answers the row, and the custom routes answer an empty work list and a claim. GET /tls/certs under the
// client's own token answers the rows with no guard, unrecorded. Safe for concurrent use.
type tlsCertsRenewWorld struct {
	world   *dnsCertsRenewWorld
	fixture *tlsCertFixture

	stateLock   sync.Mutex
	issueAtOnce bool
}

// A world issuing each order at once when issueAtOnce.
func newTlsCertsRenewWorld(t *testing.T, issueAtOnce bool) *tlsCertsRenewWorld {
	t.Helper()
	fixture := newTlsCertFixture(t)
	// the world's component makes its own manager over the fixture's parts
	fixture.manager.Close()
	self := &tlsCertsRenewWorld{fixture: fixture, issueAtOnce: issueAtOnce}
	self.world = newDnsCertsRenewWorld(t, newTlsListenTestSidecar(t, fixture.clock), fixture.networkId)
	func() {
		self.world.stateLock.Lock()
		defer self.world.stateLock.Unlock()
		self.world.serveApi = self.serveApi
	}()
	return self
}

// The certs audience the manager and the desktop ask their tokens for: the fixture's.
func (self *tlsCertsRenewWorld) resource() string {
	return self.fixture.settings.CertsResource
}

// Whether an order is issued as it is placed.
func (self *tlsCertsRenewWorld) issuesAtOnce() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.issueAtOnce
}

// api.example: GET /tls/certs under the client's own token, and certs' routes behind its guard.
func (self *tlsCertsRenewWorld) serveApi(request *http.Request, body []byte) *http.Response {
	if request.Method == http.MethodGet && request.URL.Path == "/tls/certs" && !request.URL.Query().Has("work") {
		rows, err := self.fixture.api.TlsCerts(request.Context())
		if err != nil {
			return syntheticResponse(request, http.StatusServiceUnavailable, `{}`, nil)
		}
		return syntheticResponse(request, http.StatusOK, string(mustJson(rows)), nil)
	}
	return self.world.guarded(request, body, self.resource(), self.serveCerts)
}

// certs' routes past its guard.
func (self *tlsCertsRenewWorld) serveCerts(request *http.Request, body []byte) *http.Response {
	ctx := request.Context()
	switch route := request.Method + " " + request.URL.Path; {
	case route == "POST /tls/cert-order":
		args := &TlsCertOrderArgs{}
		if err := json.Unmarshal(body, args); err != nil {
			return syntheticResponse(request, http.StatusBadRequest, `{}`, nil)
		}
		result, err := self.fixture.api.TlsCertOrder(ctx, "", args)
		if err != nil {
			return syntheticResponse(request, http.StatusBadRequest, `{}`, nil)
		}
		if self.issuesAtOnce() {
			self.fixture.api.issue(result.CertId, tlsCertTestLifetime)
		}
		return syntheticResponse(request, http.StatusOK, string(mustJson(result)), nil)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/tls/cert-order/"):
		certId, err := ParseId(strings.TrimPrefix(request.URL.Path, "/tls/cert-order/"))
		if err != nil {
			return syntheticResponse(request, http.StatusNotFound, `{}`, nil)
		}
		status, err := self.fixture.api.TlsCertOrderStatus(ctx, "", certId)
		if err != nil {
			return syntheticResponse(request, http.StatusNotFound, `{}`, nil)
		}
		return syntheticResponse(request, http.StatusOK, string(mustJson(status)), nil)
	case route == "GET /tls/certs":
		return syntheticResponse(request, http.StatusOK, `{"certs":[],"accounts":[]}`, nil)
	case route == "POST /tls/custom-claim":
		args := &TlsCustomClaimArgs{}
		if err := json.Unmarshal(body, args); err != nil {
			return syntheticResponse(request, http.StatusBadRequest, `{}`, nil)
		}
		return syntheticResponse(request, http.StatusOK, string(mustJson(&TlsCustomClaimResult{ClaimSeq: 1, LeaseMs: 120_000, Record: &TlsCertRecord{CertId: args.CertId}})), nil)
	}
	return syntheticResponse(request, http.StatusNotFound, `{}`, nil)
}

// The tls component a host makes from the world's Sidecar (TlsForegroundComponentArgs), its manager on the fixture's
// keys, names, store and settings but under the Sidecar's own certs token and its keeper's ForgetServiceToken, attached
// to a generation on the Sidecar's api, with its loop parked on its resync timer after the attachment's pass.
func (self *tlsCertsRenewWorld) attachedComponent(t *testing.T) *TlsComponent {
	t.Helper()
	args, err := self.world.sidecar.TlsForegroundComponentArgs()
	if err != nil {
		t.Fatal(err)
	}
	fixture := self.fixture
	args.Manager.NetworkId = fixture.networkId
	args.Manager.SidecarId = fixture.sidecarId
	args.Manager.Settings = fixture.settings
	args.Manager.Keys = fixture.keys
	args.Manager.Sign = testTlsSign(fixture.identity, fixture.sidecarId[:])
	args.Manager.Names = fixture.names
	args.Manager.Store = fixture.store
	args.Manager.Clock = fixture.clock
	args.Manager.Log = NewNoopLogger()
	component, err := NewTlsComponent(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(component.Close)
	env := &SidecarEnv{
		Ctx:        t.Context(),
		SidecarApi: self.world.sidecar.sidecarApi,
		Identity:   &SidecarIdentity{NetworkId: fixture.networkId, SidecarId: fixture.sidecarId},
		Log:        NewNoopLogger(),
	}
	if err := component.Attach(env); err != nil {
		t.Fatal(err)
	}
	fixture.settleLoop()
	return component
}

// What EnsureTlsCertificate answered.
type tlsCertsRenewOutcome struct {
	certificate *tls.Certificate
	err         error
}

// The manager's EnsureTlsCertificate on its own goroutine, answered on the channel.
func tlsCertsRenewEnsure(ctx context.Context, manager *TlsCertManager) chan *tlsCertsRenewOutcome {
	done := make(chan *tlsCertsRenewOutcome, 1)
	go func() {
		certificate, err := manager.EnsureTlsCertificate(ctx)
		done <- &tlsCertsRenewOutcome{certificate: certificate, err: err}
	}()
	return done
}

// done's outcome.
func tlsCertsRenewAwait(t *testing.T, done chan *tlsCertsRenewOutcome) *tlsCertsRenewOutcome {
	t.Helper()
	select {
	case outcome := <-done:
		return outcome
	case <-time.After(30 * time.Second):
		// a guard against a broken test, never the proof
		t.Fatal("EnsureTlsCertificate did not end")
		return nil
	}
}

// The routes of requests, in order, a status read's id left out.
func tlsCertsRenewRoutes(requests []*dnsCertsRenewRequest) []string {
	routes := []string{}
	for _, request := range requests {
		route := request.route
		if strings.HasPrefix(route, "GET /tls/cert-order/") {
			route = "GET /tls/cert-order/<id>"
		}
		routes = append(routes, route)
	}
	return routes
}

// The manager's order under a certs token the keeper keeps, which certs no longer authenticates, is dropped at certs'
// 401 and goes once more at once with its same body under a token minted after it, and the status read that follows
// presents that token, which the keeper kept: the network's certificate is installed after one more exchange, one
// order having reached certs' rows. The code before ended EnsureTlsCertificate with the 401 and dropped nothing.
func TestTlsCertManagerRenewsATokenCertsNoLongerAuthenticates(t *testing.T) {
	world := newTlsCertsRenewWorld(t, true)
	component := world.attachedComponent(t)
	// the keeper keeps a certs token, as an earlier call left it
	if _, err := world.world.sidecar.certsServiceToken(t.Context(), world.resource(), nil); err != nil {
		t.Fatal(err)
	}
	world.world.expireTokens()

	start := world.world.requestCount()
	outcome := tlsCertsRenewAwait(t, tlsCertsRenewEnsure(t.Context(), component.CertManager()))
	if outcome.err != nil || outcome.certificate == nil {
		t.Fatalf("an order under a token certs no longer authenticates: %v", outcome.err)
	}
	requests := world.world.requestsSince(start)
	routes := tlsCertsRenewRoutes(requests)
	statuses := dnsCertsRenewStatuses(requests)
	wantRoutes := []string{tlsCertOrderRoute, tlsCertOrderRoute, tlsCertOrderStatusRoute}
	if len(routes) != 3 || strings.Join(routes, ", ") != strings.Join(wantRoutes, ", ") || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusOK || statuses[2] != http.StatusOK {
		t.Fatalf("certs answered %v %v", routes, statuses)
	}
	if requests[0].token == requests[1].token || len(requests[0].body) == 0 || !bytes.Equal(requests[0].body, requests[1].body) {
		t.Errorf("the order did not go again with its same body under a new token")
	}
	if requests[2].token != requests[1].token {
		t.Errorf("the status read did not present the renewed token")
	}
	if count := world.world.exchanges(); count != 2 {
		t.Errorf("%d exchanges in all", count)
	}
	if count := world.fixture.api.orderCount(); count != 1 {
		t.Errorf("%d orders reached certs' rows", count)
	}
}

// The status read of an order certs has queued renews its token as the order does: the order and its first read land
// under the token minted for them; once certs no longer authenticates it, the next read, a poll interval on, meets
// certs' 401 and goes once more under a new token, which reads the issued chain, and the certificate is installed.
func TestTlsCertManagerRenewsTheStatusReadsToken(t *testing.T) {
	world := newTlsCertsRenewWorld(t, false)
	fixture := world.fixture
	component := world.attachedComponent(t)

	start := world.world.requestCount()
	done := tlsCertsRenewEnsure(t.Context(), component.CertManager())
	// the order is placed and its first status read answers queued: the poll parks on its timer
	fixture.clock.awaitTimer(t, fixture.settings.CertOrderPollInterval)
	world.world.expireTokens()
	fixture.api.issue(fixture.api.lastRow().CertId, tlsCertTestLifetime)
	fixture.clock.advance(fixture.settings.CertOrderPollInterval)
	outcome := tlsCertsRenewAwait(t, done)
	if outcome.err != nil || outcome.certificate == nil {
		t.Fatalf("a status read under a token certs no longer authenticates: %v", outcome.err)
	}
	requests := world.world.requestsSince(start)
	routes := tlsCertsRenewRoutes(requests)
	statuses := dnsCertsRenewStatuses(requests)
	wantRoutes := []string{tlsCertOrderRoute, tlsCertOrderStatusRoute, tlsCertOrderStatusRoute, tlsCertOrderStatusRoute}
	wantStatuses := []int{http.StatusOK, http.StatusOK, http.StatusUnauthorized, http.StatusOK}
	if strings.Join(routes, ", ") != strings.Join(wantRoutes, ", ") || len(statuses) != len(wantStatuses) {
		t.Fatalf("certs answered %v %v", routes, statuses)
	}
	for index, status := range wantStatuses {
		if statuses[index] != status {
			t.Fatalf("certs answered %v %v", routes, statuses)
		}
	}
	if requests[1].token != requests[0].token || requests[2].token != requests[0].token || requests[3].token == requests[0].token {
		t.Errorf("the reads did not present the order's token until certs refused it, then a new one")
	}
	if count := world.world.exchanges(); count != 2 {
		t.Errorf("%d exchanges in all", count)
	}
}

// certs' 401 to the token the manager's order minted after its first is a refusal for good: rev/ voids the subject.
// EnsureTlsCertificate ends with that 401 after exactly two orders, the second under a new token, and one more
// exchange, no order reaching certs' rows.
func TestTlsCertManagerEndsAnOrderWhoseRenewedTokenCertsRefuses(t *testing.T) {
	world := newTlsCertsRenewWorld(t, true)
	component := world.attachedComponent(t)
	if _, err := world.world.sidecar.certsServiceToken(t.Context(), world.resource(), nil); err != nil {
		t.Fatal(err)
	}
	world.world.void()

	start := world.world.requestCount()
	exchangesBefore := world.world.exchanges()
	outcome := tlsCertsRenewAwait(t, tlsCertsRenewEnsure(t.Context(), component.CertManager()))
	var apiErr *SidecarApiError
	if !errors.As(outcome.err, &apiErr) || apiErr.Status != http.StatusUnauthorized || apiErr.Route != tlsCertOrderRoute {
		t.Errorf("an order whose renewed token certs refuses ended with %v", outcome.err)
	}
	requests := world.world.requestsSince(start)
	routes := tlsCertsRenewRoutes(requests)
	statuses := dnsCertsRenewStatuses(requests)
	if len(routes) != 2 || routes[0] != tlsCertOrderRoute || routes[1] != tlsCertOrderRoute || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusUnauthorized {
		t.Fatalf("certs answered %v %v", routes, statuses)
	}
	if requests[0].token == requests[1].token {
		t.Errorf("the order went again under the token certs refused")
	}
	if exchanges := world.world.exchanges() - exchangesBefore; exchanges != 1 {
		t.Errorf("the order asked the exchange %d times", exchanges)
	}
	if count := world.fixture.api.orderCount(); count != 0 {
		t.Errorf("%d orders reached certs' rows", count)
	}
}

// A read of the desktop's work list.
func tlsCertsRenewWork(api TlsCustomApi) error {
	_, err := api.Work(context.Background())
	return err
}

// A claim of a row's account lock.
func tlsCertsRenewClaim(api TlsCustomApi) error {
	_, err := api.Claim(context.Background(), &TlsCustomClaimArgs{Domain: "customer.example", Purpose: TlsCustomPurposeOrder, CertId: tlsCertTestId("renew claim"), KeySeq: 1})
	return err
}

// An ordering desktop's custom routes, as Sidecar.TlsCustomOrdererDeps builds them over the keeper, drop a kept token
// certs no longer authenticates at its 401 and go once more at once under a token minted after it: the work list's read
// lands after one more exchange, and the next read presents the new token, which the keeper kept; a claim lands too,
// sending its same body again. The code before ended each call with the 401, which the orderer read as an answer.
func TestTlsCustomApiRenewsATokenCertsNoLongerAuthenticates(t *testing.T) {
	world := newTlsCertsRenewWorld(t, true)
	api := world.world.sidecar.tlsCustomApi(world.resource())
	if err := tlsCertsRenewWork(api); err != nil {
		t.Fatalf("the first read: %v", err)
	}
	world.world.expireTokens()

	start := world.world.requestCount()
	if err := tlsCertsRenewWork(api); err != nil {
		t.Fatalf("a read under a token certs no longer authenticates: %v", err)
	}
	requests := world.world.requestsSince(start)
	if statuses := dnsCertsRenewStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusOK {
		t.Fatalf("certs answered the read %v", statuses)
	}
	if requests[0].token == requests[1].token {
		t.Errorf("the read went again under the token certs refused")
	}
	renewed := requests[1].token
	start = world.world.requestCount()
	if err := tlsCertsRenewWork(api); err != nil {
		t.Fatalf("the read after the renewal: %v", err)
	}
	if requests := world.world.requestsSince(start); len(requests) != 1 || requests[0].token != renewed {
		t.Errorf("the read after the renewal went %d times, under the renewed token: %t", len(requests), len(requests) == 1 && requests[0].token == renewed)
	}
	if count := world.world.exchanges(); count != 2 {
		t.Errorf("the keeper did not keep the renewed token: %d exchanges", count)
	}

	world.world.expireTokens()
	start = world.world.requestCount()
	if err := tlsCertsRenewClaim(api); err != nil {
		t.Fatalf("a claim under a token certs no longer authenticates: %v", err)
	}
	requests = world.world.requestsSince(start)
	if statuses := dnsCertsRenewStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusOK {
		t.Fatalf("certs answered the claim %v", statuses)
	}
	if requests[0].token == requests[1].token || len(requests[0].body) == 0 || !bytes.Equal(requests[0].body, requests[1].body) {
		t.Errorf("the claim did not go again with its same body under a new token")
	}
	if count := world.world.exchanges(); count != 3 {
		t.Errorf("%d exchanges in all", count)
	}
}

// certs' 401 to the token a custom route's call minted after its first is a refusal for good: rev/ voids the subject.
// A read and a claim each end with that 401 after exactly two requests and one more exchange, an answer to the orderer
// (tlsCustomUnanswered) and no token refusal (tlsCustomTokenRefusedForGood), as certs' 401 was before.
func TestTlsCustomApiEndsACallWhoseRenewedTokenCertsRefuses(t *testing.T) {
	world := newTlsCertsRenewWorld(t, true)
	api := world.world.sidecar.tlsCustomApi(world.resource())
	if err := tlsCertsRenewWork(api); err != nil {
		t.Fatalf("the first read: %v", err)
	}
	world.world.void()
	for _, call := range []struct {
		name string
		do   func(api TlsCustomApi) error
	}{
		{name: "a read", do: tlsCertsRenewWork},
		{name: "a claim", do: tlsCertsRenewClaim},
	} {
		start := world.world.requestCount()
		exchangesBefore := world.world.exchanges()
		err := call.do(api)
		var apiErr *SidecarApiError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized || tlsCustomUnanswered(err) || tlsCustomTokenRefusedForGood(err) {
			t.Errorf("%s ended with %v", call.name, err)
		}
		requests := world.world.requestsSince(start)
		if statuses := dnsCertsRenewStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusUnauthorized {
			t.Errorf("certs answered %s %v", call.name, statuses)
			continue
		}
		if requests[0].token == requests[1].token {
			t.Errorf("%s went again under the token certs refused", call.name)
		}
		if exchanges := world.world.exchanges() - exchangesBefore; exchanges != 1 {
			t.Errorf("%s asked the exchange %d times", call.name, exchanges)
		}
	}
}

// The token a custom route's call asks for after certs' 401 is read by why it could not be had, as every other is: the
// exchange's invalid_grant ends the claim at once, a call that never went for want of its token, refused for good
// (tlsCustomTokenRefusedForGood), nothing more reaching certs.
func TestTlsCustomApiReadsTheRenewalsTokenFailureByWhy(t *testing.T) {
	world := newTlsCertsRenewWorld(t, true)
	api := world.world.sidecar.tlsCustomApi(world.resource())
	if err := tlsCertsRenewWork(api); err != nil {
		t.Fatalf("the first read: %v", err)
	}
	world.world.expireTokens()
	world.world.refuseExchange(http.StatusBadRequest, `{"error":"invalid_grant"}`)
	start := world.world.requestCount()
	exchangesBefore := world.world.exchanges()
	err := tlsCertsRenewClaim(api)
	var apiErr *SidecarApiError
	if !errors.Is(err, errTlsCustomNoServiceToken) || !errors.As(err, &apiErr) || apiErr.Code != "invalid_grant" || !tlsCustomTokenRefusedForGood(err) || tlsCustomUnanswered(err) {
		t.Errorf("a claim whose renewal met invalid_grant ended with %v", err)
	}
	if statuses := dnsCertsRenewStatuses(world.world.requestsSince(start)); len(statuses) != 1 || statuses[0] != http.StatusUnauthorized {
		t.Errorf("certs answered the claim %v", statuses)
	}
	if exchanges := world.world.exchanges() - exchangesBefore; exchanges != 1 {
		t.Errorf("the claim asked the exchange %d times", exchanges)
	}
}
