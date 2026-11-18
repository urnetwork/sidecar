//go:build !sidecar_http

// The token exchange answered in front of a test's sockets service (QD-1029), for the tests of the /socket/* routes,
// the registrar's and the component's among them, on every leg those build on.

package sidecar

import (
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
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
