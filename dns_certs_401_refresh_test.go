//go:build !ios_extension

// dns's client and certs' calls renew a token their service answered 401 (dns_client.go's and tls_component.go's file
// comments): the token keeper's contract has a caller drop a token a service refused and ask once more, as evs's and
// gkm's clients do on their 401 (owner decision 411). Each test runs its client as the Sidecar builds it, so over the
// keeper itself, whose ServiceToken keeps a token for its audience and whose ForgetServiceToken drops one, with a
// scripted api exchange and fake services behind the one transport SidecarApi carries them all on. The dns tests here
// run on every leg the client builds on; certs' are tls_certs_401_refresh_test.go's, on the legs certs' calls build on.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// What the scripted api answers an exchange in place of a token: a status and a body.
type dnsCertsRenewRefusal struct {
	status int
	body   string
}

// One request a service took behind its guard: its method and path, the token it bore, its body and the status it
// answered.
type dnsCertsRenewRequest struct {
	route  string
	token  string
	body   []byte
	status int
}

// A Sidecar's token keeper over a scripted api exchange and fake services behind one transport. api mints a new token
// at each exchange for the audience asked, which the keeper keeps for it, unless a test queued a refusal for it. Each
// service's guard answers 401 to a token api did not mint for its audience, to one a test marked as no longer
// authenticating there, past its life by the service's clock or signed under a key the service retired, and to every
// token once rev/ voids the subject, before the route does anything, as dnsservice's and certs' guards do. Past its
// guard dns serves GET /dns/zone and POST /dns/records, and api.example's routes are a test's to serve. Safe for
// concurrent use.
type dnsCertsRenewWorld struct {
	t         *testing.T
	sidecar   *Sidecar
	networkId Id

	stateLock sync.Mutex
	// api's answers to the next exchanges in place of a token, one each
	refusals []*dnsCertsRenewRefusal
	// how many exchanges api took, refused ones included
	exchangeCount int
	// the audience each token api minted names
	tokenResources map[string]string
	// the tokens no service authenticates any more
	expiredTokens map[string]bool
	// whether rev/ voids the subject, so every service refuses every token
	voided      bool
	zoneVersion uint64
	requests    []*dnsCertsRenewRequest
	// api.example's routes, nil for none
	serveApi func(request *http.Request, body []byte) *http.Response
}

// A world whose keeper is sidecar's, made with validSidecarSettings' urls and the test's clock, for networkId: its api
// carries the world's transport, a client token and a proof signer, and it runs client generation 1.
func newDnsCertsRenewWorld(t *testing.T, sidecar *Sidecar, networkId Id) *dnsCertsRenewWorld {
	t.Helper()
	world := &dnsCertsRenewWorld{
		t:              t,
		sidecar:        sidecar,
		networkId:      networkId,
		tokenResources: map[string]string{},
		expiredTokens:  map[string]bool{},
		zoneVersion:    1,
	}
	api, err := newSidecarApi(sidecar.settings, world, testApiClock)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt(testByJwt)
	installTestDpopSigner(t, api)
	sidecar.sidecarApi = api
	evsTestMoveTokenSidecar(t, sidecar, SidecarStateOffline)
	return world
}

// api's exchange at auth.example, dns's routes at dns.example and api's own at api.example.
func (self *dnsCertsRenewWorld) RoundTrip(request *http.Request) (*http.Response, error) {
	body := []byte{}
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	switch request.URL.Host {
	case "auth.example":
		return self.exchange(request, body)
	case "dns.example":
		return self.guarded(request, body, "https://dns.example", self.serveDns), nil
	case "api.example":
		serveApi := func() func(request *http.Request, body []byte) *http.Response {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.serveApi
		}()
		if serveApi != nil {
			return serveApi(request, body), nil
		}
	}
	self.t.Errorf("a request to %s", request.URL.Host)
	return nil, errors.New("synthetic: no such host")
}

// api's token exchange: the next refusal queued, else a new token for the audience asked.
func (self *dnsCertsRenewWorld) exchange(request *http.Request, body []byte) (*http.Response, error) {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.exchangeCount += 1
	if 0 < len(self.refusals) {
		refusal := self.refusals[0]
		self.refusals = self.refusals[1:]
		return syntheticResponse(request, refusal.status, refusal.body, nil), nil
	}
	token := fmt.Sprintf("synthetic-dns-certs-renew-token-%d", self.exchangeCount)
	self.tokenResources[token] = form.Get("resource")
	return syntheticResponse(request, http.StatusOK, fmt.Sprintf(`{"access_token":%q,"expires_in":900}`, token), nil), nil
}

// A service's guard for audience resource on the token alone, as dnsservice's and certs' answer a token they refuse,
// then serve; the request and the status answered are recorded.
func (self *dnsCertsRenewWorld) guarded(request *http.Request, body []byte, resource string, serve func(request *http.Request, body []byte) *http.Response) *http.Response {
	token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	authenticated := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		minted, ok := self.tokenResources[token]
		return ok && minted == resource && !self.voided && !self.expiredTokens[token]
	}()
	var response *http.Response
	if authenticated {
		response = serve(request, body)
	} else {
		response = syntheticResponse(request, http.StatusUnauthorized, "unauthorized\n", http.Header{"Content-Type": {"text/plain; charset=utf-8"}})
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requests = append(self.requests, &dnsCertsRenewRequest{
		route:  request.Method + " " + request.URL.Path,
		token:  token,
		body:   body,
		status: response.StatusCode,
	})
	return response
}

// dns's routes past its guard: the zone at its version, and a write that moves it.
func (self *dnsCertsRenewWorld) serveDns(request *http.Request, body []byte) *http.Response {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch request.Method + " " + request.URL.Path {
	case "GET " + DnsZonePath:
		return syntheticResponse(request, http.StatusOK, string(mustJson(testDnsClientZone(self.networkId, self.zoneVersion))), nil)
	case "POST " + DnsRecordsPath:
		if err := json.Unmarshal(body, &DnsRecordsRequest{}); err != nil {
			return syntheticResponse(request, http.StatusBadRequest, `{"code":"invalid"}`, nil)
		}
		self.zoneVersion += 1
		return syntheticResponse(request, http.StatusOK, string(mustJson(&DnsRecordsAnswer{Version: self.zoneVersion})), nil)
	}
	return syntheticResponse(request, http.StatusNotFound, `{"code":"invalid"}`, nil)
}

// Every token api minted so far no longer authenticates at any service: the service's clock passed its life, or its
// key retired.
func (self *dnsCertsRenewWorld) expireTokens() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for token := range self.tokenResources {
		self.expiredTokens[token] = true
	}
}

// rev/ voids the subject: every service refuses every token from now on.
func (self *dnsCertsRenewWorld) void() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.voided = true
}

// api answers the next exchange status with body in place of a token.
func (self *dnsCertsRenewWorld) refuseExchange(status int, body string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refusals = append(self.refusals, &dnsCertsRenewRefusal{status: status, body: body})
}

// How many exchanges api took.
func (self *dnsCertsRenewWorld) exchanges() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.exchangeCount
}

// How many requests the services took behind their guards.
func (self *dnsCertsRenewWorld) requestCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.requests)
}

// The requests the services took after the first start.
func (self *dnsCertsRenewWorld) requestsSince(start int) []*dnsCertsRenewRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*dnsCertsRenewRequest{}, self.requests[start:]...)
}

// The statuses of requests, in order.
func dnsCertsRenewStatuses(requests []*dnsCertsRenewRequest) []int {
	statuses := []int{}
	for _, request := range requests {
		statuses = append(statuses, request.status)
	}
	return statuses
}

// A world whose dns client is the Sidecar's own (Sidecar.Dns), as ur daemon's and the sdk's are, on a clock that
// reports each wait armed.
func newDnsRenewWorld(t *testing.T) (*dnsCertsRenewWorld, *gkmTestClock, *DnsClient) {
	t.Helper()
	clock := newGkmTestClock()
	settings := validSidecarSettings()
	settings.Clock = clock
	sidecar := newSidecarBase(nil, settings)
	networkId := NewId()
	sidecar.networkId = &networkId
	world := newDnsCertsRenewWorld(t, sidecar, networkId)
	client, err := sidecar.Dns()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return world, clock, client
}

// A read of the zone from dns now, as tlsCertNames reads it, the cache aside.
func dnsRenewRead(client *DnsClient) error {
	_, err := client.fetchZone(context.Background())
	return err
}

// A write of one RRset under a standing grant.
func dnsRenewWrite(client *DnsClient) error {
	_, err := client.SetRecord(context.Background(), &DnsRecordUpsert{Name: "shop.lbl0000001.root.example.", Type: "A", Ttl: 60, Values: []string{"192.0.2.44"}}, nil)
	return err
}

// A token the keeper keeps, which dns no longer authenticates (past its life by dns's clock, which runs ahead of this
// device's, or signed under a key dns retired), is dropped at dns's 401, and the call goes once more at once under a
// token minted after it: a read lands after one more exchange, and the next call presents the new token, which the
// keeper kept, asking the exchange nothing; a write lands too, sending its same body again. No wait is armed. The code
// before ended each call with the 401 and dropped nothing, so every call met the kept token again until the keeper's
// cache let it go.
func TestDnsClientRenewsATokenDnsNoLongerAuthenticates(t *testing.T) {
	world, clock, client := newDnsRenewWorld(t)
	if err := dnsRenewRead(client); err != nil {
		t.Fatalf("the first read: %v", err)
	}
	if count := world.exchanges(); count != 1 {
		t.Fatalf("the first read took %d exchanges", count)
	}
	world.expireTokens()

	start := world.requestCount()
	if err := dnsRenewRead(client); err != nil {
		t.Fatalf("a read under a token dns no longer authenticates: %v", err)
	}
	requests := world.requestsSince(start)
	if statuses := dnsCertsRenewStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusOK {
		t.Fatalf("dns answered the read %v", statuses)
	}
	if requests[0].token == requests[1].token {
		t.Errorf("the read went again under the token dns refused")
	}
	if count := world.exchanges(); count != 2 {
		t.Errorf("the read's renewal took %d exchanges in all", count)
	}
	renewed := requests[1].token

	start = world.requestCount()
	if err := dnsRenewRead(client); err != nil {
		t.Fatalf("the read after the renewal: %v", err)
	}
	if requests := world.requestsSince(start); len(requests) != 1 || requests[0].token != renewed {
		t.Errorf("the read after the renewal went %d times, under the renewed token: %t", len(requests), len(requests) == 1 && requests[0].token == renewed)
	}
	if count := world.exchanges(); count != 2 {
		t.Errorf("the keeper did not keep the renewed token: %d exchanges", count)
	}

	world.expireTokens()
	start = world.requestCount()
	if err := dnsRenewWrite(client); err != nil {
		t.Fatalf("a write under a token dns no longer authenticates: %v", err)
	}
	requests = world.requestsSince(start)
	if statuses := dnsCertsRenewStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusOK {
		t.Fatalf("dns answered the write %v", statuses)
	}
	if requests[0].token == requests[1].token || len(requests[0].body) == 0 || !bytes.Equal(requests[0].body, requests[1].body) {
		t.Errorf("the write did not go again with its same body under a new token")
	}
	if count := world.exchanges(); count != 3 {
		t.Errorf("%d exchanges in all", count)
	}
	if 0 < len(clock.armed) {
		t.Error("a renewal waited on the clock")
	}
}

// dns's 401 to the token the call minted after its first is a refusal for good: rev/ voids the subject. A read and a
// write each end with that 401, a *DnsApiError, after exactly two requests, the second under a new token, and one more
// exchange, with no wait. Each call renews once: the write presents the token the read's renewal left kept, and renews
// it again.
func TestDnsClientEndsACallWhoseRenewedTokenDnsRefuses(t *testing.T) {
	world, clock, client := newDnsRenewWorld(t)
	if err := dnsRenewRead(client); err != nil {
		t.Fatalf("the first read: %v", err)
	}
	world.void()
	for _, call := range []struct {
		name string
		do   func(client *DnsClient) error
	}{
		{name: "a read", do: dnsRenewRead},
		{name: "a write", do: dnsRenewWrite},
	} {
		start := world.requestCount()
		exchangesBefore := world.exchanges()
		err := call.do(client)
		var apiError *DnsApiError
		if !errors.As(err, &apiError) || apiError.Status != http.StatusUnauthorized {
			t.Errorf("%s ended with %v, not dns's 401", call.name, err)
		}
		requests := world.requestsSince(start)
		if statuses := dnsCertsRenewStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusUnauthorized {
			t.Errorf("dns answered %s %v", call.name, statuses)
			continue
		}
		if requests[0].token == requests[1].token {
			t.Errorf("%s went again under the token dns refused", call.name)
		}
		if exchanges := world.exchanges() - exchangesBefore; exchanges != 1 {
			t.Errorf("%s asked the exchange %d times", call.name, exchanges)
		}
	}
	if 0 < len(clock.armed) {
		t.Error("a renewal waited on the clock")
	}
}

// The token a call asks for after dns's 401 is read by why it could not be had, as every other is: the exchange's
// invalid_grant, api's gate holding the device's revocation too, ends the call at once with that refusal, nothing more
// reaching dns; api's 503 goes again ExchangeRetryWait later, and the call lands under the token minted then.
func TestDnsClientReadsTheRenewalsTokenFailureByWhy(t *testing.T) {
	world, clock, client := newDnsRenewWorld(t)
	if err := dnsRenewRead(client); err != nil {
		t.Fatalf("the first read: %v", err)
	}
	world.expireTokens()
	world.refuseExchange(http.StatusBadRequest, `{"error":"invalid_grant"}`)
	start := world.requestCount()
	exchangesBefore := world.exchanges()
	err := dnsRenewWrite(client)
	var apiError *SidecarApiError
	var dnsError *DnsApiError
	if !errors.As(err, &apiError) || apiError.Code != "invalid_grant" || errors.As(err, &dnsError) || !sidecarServiceTokenRefusalOf(err).final {
		t.Errorf("a write whose renewal met invalid_grant ended with %v", err)
	}
	if statuses := dnsCertsRenewStatuses(world.requestsSince(start)); len(statuses) != 1 || statuses[0] != http.StatusUnauthorized {
		t.Errorf("dns answered the write %v", statuses)
	}
	if exchanges := world.exchanges() - exchangesBefore; exchanges != 1 {
		t.Errorf("the write asked the exchange %d times", exchanges)
	}
	if 0 < len(clock.armed) {
		t.Error("invalid_grant waited on the clock")
	}

	// api's 503 refuses nothing: the renewal's exchange goes again an ExchangeRetryWait later
	if err := dnsRenewRead(client); err != nil {
		t.Fatalf("a read once api grants again: %v", err)
	}
	world.expireTokens()
	world.refuseExchange(http.StatusServiceUnavailable, `{}`)
	start = world.requestCount()
	exchangesBefore = world.exchanges()
	done := make(chan error, 1)
	go func() {
		done <- dnsRenewRead(client)
	}()
	select {
	case wait := <-clock.armed:
		if wait != DefaultDnsClientSettings().ExchangeRetryWait {
			t.Errorf("the renewal's exchange waits %s after api's 503", wait)
		}
		clock.Advance(wait)
	case err := <-done:
		t.Fatalf("the read ended before its renewal's exchange went again: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("a read whose renewal met api's 503 once: %v", err)
	}
	requests := world.requestsSince(start)
	if statuses := dnsCertsRenewStatuses(requests); len(statuses) != 2 || statuses[0] != http.StatusUnauthorized || statuses[1] != http.StatusOK || requests[0].token == requests[1].token {
		t.Errorf("dns answered the read %v", statuses)
	}
	if exchanges := world.exchanges() - exchangesBefore; exchanges != 2 {
		t.Errorf("the read asked the exchange %d times", exchanges)
	}
}
