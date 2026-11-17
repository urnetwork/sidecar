//go:build !sidecar_http && !js

// The /socket/* routes present a sockets service token from the exchange (QD-1029), never the client token: the
// exchange's request, the token kept for the client under ServiceTokenCacheTimeout and its expires_in and renewed on
// that schedule, a new client's exchange, and a 401 that drops the token at once.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A transport in front of next that answers the token exchange itself, a new sockets token each time, and hands every
// other request to next.
type testSocketsExchangeTransport struct {
	next http.RoundTripper
	// the token exchange's expires_in, in seconds
	expiresIn int

	stateLock sync.Mutex
	// each exchange's form, in order
	exchanges []url.Values
}

func (self *testSocketsExchangeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Path != "/oauth/token" {
		return self.next.RoundTrip(request)
	}
	if err := request.ParseForm(); err != nil {
		return syntheticResponse(request, 400, `{"error":"invalid_request"}`, nil), nil
	}
	exchangeCount := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.exchanges = append(self.exchanges, request.PostForm)
		return len(self.exchanges)
	}()
	body := `{"access_token":"` + testSocketsToken(exchangeCount) + `","issued_token_type":"urn:ietf:params:oauth:token-type:access_token",` +
		`"token_type":"Bearer","expires_in":` + strconv.Itoa(self.expiresIn) + `}`
	return syntheticResponse(request, 200, body, nil), nil
}

// The exchanges so far.
func (self *testSocketsExchangeTransport) exchangeForms() []url.Values {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]url.Values{}, self.exchanges...)
}

// The sockets token the exchange answers the nth time, from 1.
func testSocketsToken(n int) string {
	return "synthetic-sockets-token-" + strconv.Itoa(n)
}

// A SidecarApi on next whose exchange answers sockets tokens of 15 minutes, with a ClientKey's signer installed.
func newTestSocketsApi(t *testing.T, next http.RoundTripper) (*SidecarApi, *testSocketsExchangeTransport) {
	t.Helper()
	transport := &testSocketsExchangeTransport{next: next, expiresIn: 15 * 60}
	api := newTestSidecarApi(t, transport)
	installTestDpopSigner(t, api)
	return api, transport
}

// A sockets service answering every list with no names and recording each bearer it is given; status answers the
// nth call, from 1, when it is set.
type testSocketsListService struct {
	stateLock sync.Mutex
	bearers   []string
	status    func(n int) int
}

func (self *testSocketsListService) RoundTrip(request *http.Request) (*http.Response, error) {
	n := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.bearers = append(self.bearers, request.Header.Get("Authorization"))
		return len(self.bearers)
	}()
	if self.status != nil {
		if status := self.status(n); status != 200 {
			return syntheticResponse(request, status, `{}`, nil), nil
		}
	}
	return syntheticResponse(request, 200, `{"names":[]}`, nil), nil
}

func (self *testSocketsListService) presented() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.bearers...)
}

// The first call exchanges the client token for a sockets token, resource SocketsUrl and no scope, with the ClientKey's
// proof, and presents it, never the client token; later calls present the kept token until ServiceTokenCacheTimeout,
// when the next call exchanges again: the exchange's schedule.
func TestSocketRoutesPresentASocketsServiceToken(t *testing.T) {
	service := &testSocketsListService{}
	api, exchange := newTestSocketsApi(t, service)
	ctx := context.Background()
	for range 2 {
		if _, err := api.SocketList(ctx, ""); err != nil {
			t.Fatal(err)
		}
	}
	forms := exchange.exchangeForms()
	if len(forms) != 1 {
		t.Fatalf("%d exchanges for two calls", len(forms))
	}
	form := forms[0]
	if form.Get("resource") != "https://sockets.example" || form.Get("scope") != "" || form.Get("subject_token") != testByJwt ||
		form.Get("grant_type") != sidecarExchangeGrantType || form.Get("subject_token_type") != sidecarExchangeSubjectTokenType {
		t.Errorf("the exchange's form %v", form)
	}
	presented := service.presented()
	if len(presented) != 2 || presented[0] != "Bearer "+testSocketsToken(1) || presented[1] != "Bearer "+testSocketsToken(1) {
		t.Fatalf("presented %q", presented)
	}
	for _, bearer := range presented {
		if strings.Contains(bearer, testByJwt) {
			t.Fatal("a sockets call presented the client token")
		}
	}

	// the exchange's schedule: kept under ServiceTokenCacheTimeout, then exchanged again
	keepFor := api.settings.TokenRefreshSettings.ServiceTokenCacheTimeout
	api.now = func() time.Time { return testApiClock().Add(keepFor - time.Second) }
	if _, err := api.SocketList(ctx, ""); err != nil {
		t.Fatal(err)
	}
	api.now = func() time.Time { return testApiClock().Add(keepFor) }
	if _, err := api.SocketList(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if forms := exchange.exchangeForms(); len(forms) != 2 {
		t.Fatalf("%d exchanges across the cache timeout", len(forms))
	}
	presented = service.presented()
	if presented[2] != "Bearer "+testSocketsToken(1) || presented[3] != "Bearer "+testSocketsToken(2) {
		t.Fatalf("presented %q", presented)
	}
}

// A token whose expires_in is shorter than ServiceTokenCacheTimeout is kept no longer than that; a new client's calls
// never present a token another client's exchange got; and a 401 drops the token at once, so the next call exchanges
// again.
func TestSocketRoutesRenewTheSocketsToken(t *testing.T) {
	service := &testSocketsListService{status: func(n int) int {
		if n == 3 {
			return 401
		}
		return 200
	}}
	api, exchange := newTestSocketsApi(t, service)
	exchange.expiresIn = 60
	ctx := context.Background()
	if _, err := api.SocketList(ctx, ""); err != nil {
		t.Fatal(err)
	}
	api.now = func() time.Time { return testApiClock().Add(time.Minute) }
	if _, err := api.SocketList(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if forms := exchange.exchangeForms(); len(forms) != 2 {
		t.Fatalf("%d exchanges past a 60 s expires_in", len(forms))
	}

	_, err := api.SocketList(ctx, "")
	var apiErr *SidecarApiError
	if !errors.As(err, &apiErr) || apiErr.Status != 401 {
		t.Fatalf("a refused token: %v", err)
	}
	if _, err := api.SocketList(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if forms := exchange.exchangeForms(); len(forms) != 3 {
		t.Fatalf("%d exchanges after a 401", len(forms))
	}

	// another client's token in the api: its own exchange, never the kept token
	api.SetByJwt(testClientTokenOf(testRegistrarNetworkId, NewId()))
	if _, err := api.SocketList(ctx, ""); err != nil {
		t.Fatal(err)
	}
	forms := exchange.exchangeForms()
	presented := service.presented()
	if len(forms) != 4 || presented[len(presented)-1] != "Bearer "+testSocketsToken(4) {
		t.Fatalf("a new client's call: %d exchanges, presented %q", len(forms), presented[len(presented)-1])
	}
}

// An exchange that cannot run, with no ClientKey's signer, sends nothing to sockets: the call fails before it, and no
// client token goes in its place.
func TestSocketRoutesSendNothingWithoutASocketsToken(t *testing.T) {
	service := &testSocketsListService{}
	transport := &testSocketsExchangeTransport{next: service, expiresIn: 15 * 60}
	api := newTestSidecarApi(t, transport)
	if _, err := api.SocketList(context.Background(), ""); !errors.Is(err, ErrSidecarApiNoDpopSigner) {
		t.Fatalf("no signer: %v", err)
	}
	if presented := service.presented(); len(presented) != 0 {
		t.Fatalf("sockets was called with %q", presented)
	}
}
