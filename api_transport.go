// What stands between a SidecarApi request and the network, on every leg (§5.4). In the page Worker
// net/http hands a request's url to fetch as it stands (net/http/roundtrip_js.go), and fetch resolves
// a relative url against the Worker's own origin, so a service url left empty would carry the bearer
// token to the page's host. Only the native transport refuses such a url itself, so the refusal
// cannot be left to the dial. settings_validate.go refuses a bad service url first, with a clearer
// error; this stays the last check, since a route builds its url by joining strings.

package sidecar

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
)

// A request's url that a token must not follow. The error never repeats the url, which may hold
// anything (I-13).
var errServiceUrl = errors.New("service url refused")

// Whether parsed is the least a token may follow: one of schemes, a host, and no credentials of its
// own. An empty, relative or scheme-relative url names no scheme, so it never passes.
func isAbsoluteServiceUrl(parsed *url.URL, schemes ...string) bool {
	return slices.Contains(schemes, parsed.Scheme) && parsed.Hostname() != "" && parsed.User == nil
}

// Refuses a request with no absolute http or https url before transport sees it. Safe for concurrent
// use, as http.RoundTripper requires.
type absoluteUrlTransport struct {
	transport http.RoundTripper
}

// Closes a refused request's body, as http.RoundTripper requires.
func (self *absoluteUrlTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL == nil || !isAbsoluteServiceUrl(request.URL, "http", "https") {
		if request.Body != nil {
			request.Body.Close()
		}
		return nil, fmt.Errorf("%w: a request with no absolute url", errServiceUrl)
	}
	return self.transport.RoundTrip(request)
}
