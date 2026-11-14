// The page Worker's reading of the api's clock (§7.4, QD-757, QD-776). A Worker calls api cross-origin with
// fetch, and a browser shows a cross-origin script only the response headers that are CORS-safelisted or
// that the answer's Access-Control-Expose-Headers names. Date is not safelisted, so a Worker reads the
// api's clock, and signs its DPoP proof's iat by it, only where the lb exposes Date, which QD-776 has it
// do. Here the api of api_clock_test.go stands behind the lb's CORS headers and a fetch's rule for them,
// both in this process: a Worker 10 min fast or slow renews, exchanges and mints under the api's 60 s
// window with the lb's list, and stays refused, in one request, with the list as it was before. Runs on
// every leg, the sidecar_http leg in a Worker's shape among them (legs_test.go), since it opens nothing.

package sidecar

import (
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

// The key origin the Worker here runs at, and another page's.
const (
	testPageKeyOrigin   = "https://sidecar.example"
	testPageOtherOrigin = "https://other.example"
)

// The lb's Access-Control-Expose-Headers list (warp's addCorsHeaders, §18.15), which the pagestack fixture
// answers with too (api_clock_page_source_test.go holds the two equal), and the list as it was before
// QD-776 added Date.
const (
	testLbCorsExposeHeaders           = "Content-Length,Content-Range,Accept,Mcp-Session-Id,MCP-Protocol-Version,Last-Event-ID,ETag,Retry-After,Date"
	testLbCorsExposeHeadersBeforeDate = "Content-Length,Content-Range,Accept,Mcp-Session-Id,MCP-Protocol-Version,Last-Event-ID,ETag,Retry-After"
)

// The response headers a browser shows any cross-origin script (the Fetch standard's CORS-safelisted
// response header names).
var testCorsSafelistedResponseHeaders = []string{"Cache-Control", "Content-Language", "Content-Length", "Content-Type", "Expires", "Last-Modified", "Pragma"}

var errPageFetchCors = errors.New("fetch: the answer does not allow this origin")

// The lb in front of a service whose cors_origins are origins, as warp's addCorsHeaders renders it: every
// answer, a refusal too, carries the expose list, and Access-Control-Allow-Origin for a request from a
// listed origin alone.
type lbCorsTransport struct {
	transport     http.RoundTripper
	origins       []string
	exposeHeaders string
}

func (self *lbCorsTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := self.transport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if origin := request.Header.Get("Origin"); slices.Contains(self.origins, origin) {
		response.Header.Set("Access-Control-Allow-Origin", origin)
		response.Header.Set("Vary", "Origin")
	}
	response.Header.Set("Access-Control-Expose-Headers", self.exposeHeaders)
	return response, nil
}

// What a browser's fetch gives a script at origin of a cross-origin answer, sent without credentials as
// the Worker's requests are (its token goes in Authorization): no answer at all unless it allows the
// origin, and of its headers only the safelisted ones and those its Access-Control-Expose-Headers names,
// by any case, or all of them for "*". A preflight is not modeled: what the Worker may send is the lb's
// other lists' matter.
type pageFetchTransport struct {
	transport http.RoundTripper
	origin    string
}

func (self *pageFetchTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	request = request.Clone(request.Context())
	request.Header.Set("Origin", self.origin)
	response, err := self.transport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if allowed := response.Header.Get("Access-Control-Allow-Origin"); allowed != self.origin && allowed != "*" {
		response.Body.Close()
		return nil, errPageFetchCors
	}
	shown := append([]string{}, testCorsSafelistedResponseHeaders...)
	all := false
	for _, exposed := range response.Header.Values("Access-Control-Expose-Headers") {
		for _, name := range strings.Split(exposed, ",") {
			name = strings.TrimSpace(name)
			if name == "*" {
				all = true
			} else if name != "" {
				shown = append(shown, http.CanonicalHeaderKey(name))
			}
		}
	}
	if !all {
		header := http.Header{}
		for name, values := range response.Header {
			if slices.Contains(shown, http.CanonicalHeaderKey(name)) {
				header[name] = values
			}
		}
		response.Header = header
	}
	return response, nil
}

// An api on its own clock, the lb's CORS for the key origin with exposeHeaders in front of it, and a page
// Worker at the key origin whose clock runs deviceOffset from the api's. The world's transport still
// counts what reaches the api.
func newTestPageWorkerWorld(t *testing.T, deviceOffset time.Duration, exposeHeaders string) *testApiClockWorld {
	t.Helper()
	world := newTestApiClockWorld(t, deviceOffset)
	world.api.setTransport(&pageFetchTransport{
		origin: testPageKeyOrigin,
		transport: &lbCorsTransport{
			transport:     world.transport,
			origins:       []string{testPageKeyOrigin},
			exposeHeaders: exposeHeaders,
		},
	})
	return world
}

// With Date exposed, a Worker 10 min fast or slow that has heard nothing from api renews at GET
// /auth/refresh, exchanges at POST /oauth/token and mints at POST /network/auth-client under the api's
// 60 s window: its first proof, on the browser's clock, is refused, the refusal's Date reaches it through
// fetch, and the second, at the api's time, is taken. From then on each route takes one request.
func TestSkewedPageWorkerRenewsExchangesAndMintsWithDateExposed(t *testing.T) {
	for _, deviceOffset := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		if deviceOffset.Abs() <= testApiClockIatWindow {
			t.Fatalf("a clock %s off fits the api's window of %s, so this proves nothing", deviceOffset, testApiClockIatWindow)
		}
		for i := range 3 {
			world := newTestPageWorkerWorld(t, deviceOffset, testLbCorsExposeHeaders)
			proofCall := world.proofCalls()[i]
			if err := proofCall.call(); err != nil {
				t.Errorf("device %s, %s: %v", deviceOffset, proofCall.name, err)
				continue
			}
			proofs := world.seenProofs()
			if world.transport.requestCount() != 2 || len(proofs) != 2 {
				t.Errorf("device %s, %s: %d requests, %d proofs", deviceOffset, proofCall.name, world.transport.requestCount(), len(proofs))
				continue
			}
			if proofs[0].Iat != world.deviceNow().Unix() || proofs[1].Iat != world.apiNow.Unix() {
				t.Errorf("device %s, %s: iat %d then %d", deviceOffset, proofCall.name, proofs[0].Iat, proofs[1].Iat)
			}
			if proofs[0].Jti == proofs[1].Jti {
				t.Errorf("device %s, %s: the second request repeated the first's jti", deviceOffset, proofCall.name)
			}
			if offset := world.api.currentApiClockOffset(); offset != -deviceOffset {
				t.Errorf("device %s, %s: offset %s", deviceOffset, proofCall.name, offset)
			}
			for j, nextCall := range world.proofCalls() {
				world.advance(7 * time.Second)
				before := world.transport.requestCount()
				if err := nextCall.call(); err != nil {
					t.Errorf("device %s, %s then %s: %v", deviceOffset, proofCall.name, nextCall.name, err)
				}
				if sent := world.transport.requestCount() - before; sent != 1 {
					t.Errorf("device %s, %s then %s: %d requests", deviceOffset, proofCall.name, nextCall.name, sent)
				}
				proofs := world.seenProofs()
				if len(proofs) != 3+j {
					t.Fatalf("device %s, %s then %s: %d proofs", deviceOffset, proofCall.name, nextCall.name, len(proofs))
				}
				if iat := proofs[2+j].Iat; iat != world.apiNow.Unix() {
					t.Errorf("device %s, %s then %s: iat %d, the api's clock reads %d", deviceOffset, proofCall.name, nextCall.name, iat, world.apiNow.Unix())
				}
			}
		}
	}
}

// The api sends its Date either way; what the lb exposes decides. With the list as it was before QD-776
// the same Worker reads no clock and stays refused at each route, in one request, never sent again on a
// guess: the window stands, and the one word in the lb's list is what lets the Worker meet it.
func TestSkewedPageWorkerStaysRefusedWithDateNotExposed(t *testing.T) {
	for _, deviceOffset := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		for i := range 3 {
			world := newTestPageWorkerWorld(t, deviceOffset, testLbCorsExposeHeadersBeforeDate)
			proofCall := world.proofCalls()[i]
			err := proofCall.call()
			apiErr := &SidecarApiError{}
			if !errors.As(err, &apiErr) || !isSidecarApiProofRefusal(apiErr) {
				t.Errorf("device %s, %s: err %v", deviceOffset, proofCall.name, err)
			}
			if count := world.transport.requestCount(); count != 1 {
				t.Errorf("device %s, %s: %d requests", deviceOffset, proofCall.name, count)
			}
			if offset := world.api.currentApiClockOffset(); offset != 0 {
				t.Errorf("device %s, %s: offset %s", deviceOffset, proofCall.name, offset)
			}
		}
	}
}

// A Worker with a true clock is untouched by the list either way: one request a route.
func TestUnskewedPageWorkerNeedsNoSecondRequest(t *testing.T) {
	for _, exposeHeaders := range []string{testLbCorsExposeHeaders, testLbCorsExposeHeadersBeforeDate} {
		world := newTestPageWorkerWorld(t, 0, exposeHeaders)
		for i, proofCall := range world.proofCalls() {
			if err := proofCall.call(); err != nil {
				t.Errorf("%s: %v", proofCall.name, err)
			}
			if count := world.transport.requestCount(); count != i+1 {
				t.Errorf("%s: %d requests", proofCall.name, count)
			}
		}
	}
}

// The fetch model's own rule, so the two tests above rest on it: a page sees an answer only where it
// allows the page's origin, and of its headers the safelisted ones and the exposed ones, named by any
// case, and nothing else, Date included.
func TestPageFetchShowsOnlySafelistedAndExposedHeaders(t *testing.T) {
	date := testApiNow.Format(http.TimeFormat)
	fetch := func(origin string, exposeHeaders string) (*http.Response, *http.Request, error) {
		api := &scriptedApiTransport{
			answer: func(request *http.Request, body []byte) (*http.Response, error) {
				header := http.Header{}
				header.Set("Date", date)
				header.Set("ETag", `"synthetic"`)
				header.Set("Retry-After", "7")
				header.Set("X-Synthetic", "hidden")
				return syntheticResponse(request, 200, `{}`, header), nil
			},
		}
		transport := &pageFetchTransport{
			origin:    origin,
			transport: &lbCorsTransport{transport: api, origins: []string{testPageKeyOrigin}, exposeHeaders: exposeHeaders},
		}
		request := newSyntheticRequest(t, "https://api.example/sidecar/bind")
		response, err := transport.RoundTrip(request)
		if request.Header.Get("Origin") != "" {
			t.Errorf("the caller's request was given an Origin")
		}
		if api.requestCount() != 1 {
			t.Fatalf("%d requests reached the api", api.requestCount())
		}
		sent, _ := api.onlyRequest(t)
		return response, sent, err
	}

	response, sent, err := fetch(testPageKeyOrigin, testLbCorsExposeHeaders)
	if err != nil {
		t.Fatal(err)
	}
	if origin := sent.Header.Get("Origin"); origin != testPageKeyOrigin {
		t.Errorf("the request's Origin: %q", origin)
	}
	for name, want := range map[string]string{
		"Date": date, "ETag": `"synthetic"`, "Retry-After": "7", "Content-Type": "application/json",
		"X-Synthetic": "", "Access-Control-Allow-Origin": "", "Vary": "",
	} {
		if got := response.Header.Get(name); got != want {
			t.Errorf("with the lb's list, %s reads %q, want %q", name, got, want)
		}
	}
	if body, err := io.ReadAll(response.Body); err != nil || string(body) != `{}` {
		t.Errorf("the body: %q, %v", body, err)
	}

	response, _, err = fetch(testPageKeyOrigin, testLbCorsExposeHeadersBeforeDate)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Date") != "" || response.Header.Get("Retry-After") != "7" || response.Header.Get("Content-Type") != "application/json" {
		t.Errorf("with the list before Date: %v", response.Header)
	}

	// a name in another case, between spaces, exposes its header, and "*" exposes them all
	response, _, err = fetch(testPageKeyOrigin, "etag , date")
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Date") != date || response.Header.Get("ETag") == "" || response.Header.Get("Retry-After") != "" {
		t.Errorf("with a lower-case list: %v", response.Header)
	}
	response, _, err = fetch(testPageKeyOrigin, "*")
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Date") != date || response.Header.Get("X-Synthetic") != "hidden" {
		t.Errorf("with *: %v", response.Header)
	}
	if response, _, err = fetch(testPageKeyOrigin, ""); err != nil || response.Header.Get("Date") != "" || response.Header.Get("Content-Type") == "" {
		t.Errorf("with no list: %v", err)
	}

	// an origin the lb does not list is given no answer, whatever the list exposes
	if response, _, err := fetch(testPageOtherOrigin, testLbCorsExposeHeaders); !errors.Is(err, errPageFetchCors) || response != nil {
		t.Errorf("another origin: %v", err)
	}
}
