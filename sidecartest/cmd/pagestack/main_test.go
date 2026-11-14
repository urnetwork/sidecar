// pagestack's own rules: the key origin serves its four files and nothing else, each answer with its CSP and no
// X-Frame-Options; api, auth, evs and gkm answer CORS for the key origin alone, with the lb's lists; the proxy tunnels
// the fixture names at the TLS port and refuses every other host before dialing anything; and the listeners bind only
// 127.0.0.1 above port 50000.

package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// A handler over a staged key origin and a pages directory in t's temp, with an api, evs and gkm that answer 299, 298
// and 297.
func testPagestackHandler(t *testing.T) *pagestackHandler {
	t.Helper()
	settings := defaultPagestackSettings()
	settings.keyOrigin, settings.pages = t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(settings.keyOrigin, "v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"index.html", "loader.js", "worker.js", "sidecar.wasm"} {
		if err := os.WriteFile(filepath.Join(settings.keyOrigin, "v1", name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(settings.keyOrigin, "secret.txt"), []byte("not served"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(settings.pages, "fixture-page.html"), []byte("page"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &pagestackHandler{
		settings:   settings,
		api:        http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(299) }),
		evs:        http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(298) }),
		gkm:        http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(297) }),
		pageOrigin: "https://ur.sidecartest.example:58443",
		keyOrigin:  "https://sidecar.sidecartest.example:58443",
		csp:        "default-src 'none'; frame-ancestors https://ur.sidecartest.example:58443",
	}
}

// The handler's answer to a request.
func testPagestackServe(handler http.Handler, method string, host string, path string, header map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://"+host+path, nil)
	request.Host = host
	for key, value := range header {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestKeyOriginServesOnlyItsFilesWithItsCsp(t *testing.T) {
	handler := testPagestackHandler(t)
	host := "sidecar.sidecartest.example:58443"
	for path, want := range map[string]string{"/v1/": "index.html", "/v1/loader.js": "loader.js", "/v1/sidecar.wasm": "sidecar.wasm"} {
		answer := testPagestackServe(handler, http.MethodGet, host, path, nil)
		if answer.Code != http.StatusOK || answer.Body.String() != want || answer.Header().Get("Content-Security-Policy") != handler.csp ||
			answer.Header().Get("X-Frame-Options") != "" {
			t.Errorf("%s: %d %q, headers %v", path, answer.Code, answer.Body.String(), answer.Header())
		}
	}
	if answer := testPagestackServe(handler, http.MethodGet, host, "/v1/sidecar.wasm", nil); answer.Header().Get("Content-Type") != "application/wasm" {
		t.Errorf("the wasm's type: %q", answer.Header().Get("Content-Type"))
	}
	for _, path := range []string{"/secret.txt", "/v1/../secret.txt", "/v2/", "/v1/other.js"} {
		answer := testPagestackServe(handler, http.MethodGet, host, path, nil)
		if answer.Code != http.StatusNotFound || answer.Header().Get("Content-Security-Policy") != handler.csp {
			t.Errorf("%s: %d, csp %q", path, answer.Code, answer.Header().Get("Content-Security-Policy"))
		}
	}
	if answer := testPagestackServe(handler, http.MethodPost, host, "/v1/", nil); answer.Code != http.StatusNotFound {
		t.Errorf("a POST: %d", answer.Code)
	}
	if answer := testPagestackServe(handler, http.MethodGet, "elsewhere.example:58443", "/v1/", nil); answer.Code != http.StatusMisdirectedRequest {
		t.Errorf("another host: %d", answer.Code)
	}
}

func TestServicesAnswerCorsForTheKeyOriginAlone(t *testing.T) {
	handler := testPagestackHandler(t)
	for host, code := range map[string]int{
		"api.sidecartest.example:58443": 299, "auth.sidecartest.example:58443": 299,
		"evs.sidecartest.example:58443": 298, "gkm.sidecartest.example:58443": 297,
	} {
		preflight := testPagestackServe(handler, http.MethodOptions, host, "/v1/anything", map[string]string{"Origin": handler.keyOrigin})
		header := preflight.Header()
		if preflight.Code != http.StatusNoContent || header.Get("Access-Control-Allow-Origin") != handler.keyOrigin || header.Get("Vary") != "Origin" ||
			header.Get("Access-Control-Max-Age") != "1728000" || header.Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("%s: the key origin's preflight: %d, %v", host, preflight.Code, header)
		}
		for _, name := range []string{"Authorization", "DPoP", "If-Match", "If-None-Match", "Range", "Content-Type"} {
			if !slices.Contains(strings.Split(header.Get("Access-Control-Allow-Headers"), ","), name) {
				t.Errorf("%s: %s is not among the allowed headers", host, name)
			}
		}
		// Date among them: the Worker signs its DPoP proof's iat by the api's clock (QD-776)
		for _, name := range []string{"ETag", "Retry-After", "Content-Range", "Date"} {
			if !slices.Contains(strings.Split(header.Get("Access-Control-Expose-Headers"), ","), name) {
				t.Errorf("%s: %s is not among the exposed headers", host, name)
			}
		}
		if answer := testPagestackServe(handler, http.MethodGet, host, "/v1/anything", map[string]string{"Origin": handler.keyOrigin}); answer.Code != code ||
			answer.Header().Get("Access-Control-Allow-Origin") != handler.keyOrigin {
			t.Errorf("%s: the key origin's request: %d, %v", host, answer.Code, answer.Header())
		}
		for _, origin := range []string{handler.pageOrigin, "https://other.sidecartest.example:58443", "https://localhost:58443", "null", ""} {
			answer := testPagestackServe(handler, http.MethodGet, host, "/v1/anything", map[string]string{"Origin": origin})
			if answer.Code != code || answer.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("%s, origin %q: %d, %v", host, origin, answer.Code, answer.Header())
			}
			// a preflight of another origin reaches the service, which no browser takes as an allow
			if preflight := testPagestackServe(handler, http.MethodOptions, host, "/v1/anything", map[string]string{"Origin": origin}); preflight.Code != code ||
				preflight.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("%s, origin %q's preflight: %d, %v", host, origin, preflight.Code, preflight.Header())
			}
		}
	}
}

// The fixture's api gives the key origin its clock (§7.4, QD-776): each answer of api's and the issuer's origins, a
// refusal too, carries a Date on the api's clock, and the answer to the key origin lists Date among the headers a
// browser shows its Worker. Another origin's answer lists nothing, and a browser shows that page none of it.
func TestApiAnswersGiveTheKeyOriginTheirDate(t *testing.T) {
	stack := testPagestack(t)
	window := sidecartest.DefaultFakeApiSettings().DpopIatWindow
	for _, name := range []string{"api", "auth"} {
		host := strings.TrimPrefix(stack.origin(name), "https://")
		// no token: the fixture's api refuses it, and the refusal is what a Worker with a wrong clock reads first
		answer := testPagestackServe(stack.handler, http.MethodGet, host, "/auth/refresh", map[string]string{"Origin": stack.handler.keyOrigin})
		if answer.Code < 400 {
			t.Errorf("%s: a request with no token answered %d", name, answer.Code)
		}
		if !slices.Contains(strings.Split(answer.Header().Get("Access-Control-Expose-Headers"), ","), "Date") {
			t.Errorf("%s: Date is not among the exposed headers %q", name, answer.Header().Get("Access-Control-Expose-Headers"))
		}
		date, err := http.ParseTime(answer.Header().Get("Date"))
		if err != nil {
			t.Errorf("%s: Date %q: %v", name, answer.Header().Get("Date"), err)
			continue
		}
		if offset := stack.world.Clock().Now().Sub(date); offset < -window || window < offset {
			t.Errorf("%s: Date is %s from the api's clock, outside a proof's window of %s", name, offset, window)
		}
		other := testPagestackServe(stack.handler, http.MethodGet, host, "/auth/refresh", map[string]string{"Origin": stack.handler.pageOrigin})
		if other.Header().Get("Access-Control-Allow-Origin") != "" || other.Header().Get("Access-Control-Expose-Headers") != "" {
			t.Errorf("%s: the page origin's answer carries CORS headers %v", name, other.Header())
		}
	}
}

func TestHarnessAddressAnswersOnlyItsOwnRoutes(t *testing.T) {
	handler := testPagestackHandler(t)
	if answer := testPagestackServe(handler, http.MethodGet, "127.0.0.1:58443", "/healthz", nil); answer.Code != http.StatusOK {
		t.Errorf("/healthz: %d", answer.Code)
	}
	// a handler with no fixture has no ids to give
	if answer := testPagestackServe(handler, http.MethodGet, "127.0.0.1:58443", "/fixture.json", nil); answer.Code != http.StatusNotFound {
		t.Errorf("/fixture.json with no fixture: %d", answer.Code)
	}
	for _, path := range []string{"/", "/v1/", "/fixture-page.html"} {
		if answer := testPagestackServe(handler, http.MethodGet, "127.0.0.1:58443", path, nil); answer.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, answer.Code)
		}
	}
	if answer := testPagestackServe(handler, http.MethodPost, "127.0.0.1:58443", "/healthz", nil); answer.Code != http.StatusMethodNotAllowed {
		t.Errorf("a POST: %d", answer.Code)
	}
}

func TestProxyTunnelsOnlyTheFixtureNames(t *testing.T) {
	// the target answers each tunnel with a line, so a tunnel that reached it shows
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			connection, err := target.Accept()
			if err != nil {
				return
			}
			io.WriteString(connection, "reached\n")
			connection.Close()
		}
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	settings := defaultPagestackSettings()
	proxy := &pagestackProxy{target: target.Addr().String(), port: "58443", names: []string{"ur.sidecartest.example", "localhost"}, settings: settings}
	go proxy.serve(t.Context(), listener)
	connect := func(request string) string {
		connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		io.WriteString(connection, request)
		reader := bufio.NewReader(connection)
		status, _ := reader.ReadString('\n')
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		rest, _ := io.ReadAll(reader)
		return strings.TrimSpace(strings.TrimSpace(status) + " " + strings.TrimSpace(string(rest)))
	}
	cases := map[string]string{
		"CONNECT ur.sidecartest.example:58443 HTTP/1.1\r\nHost: ur.sidecartest.example:58443\r\n\r\n": "HTTP/1.1 200 Connection Established reached",
		"CONNECT UR.sidecartest.example:58443 HTTP/1.1\r\nHost: UR.sidecartest.example:58443\r\n\r\n": "HTTP/1.1 200 Connection Established reached",
		"CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n":                   "HTTP/1.1 403 Forbidden",
		"CONNECT ur.sidecartest.example:443 HTTP/1.1\r\nHost: ur.sidecartest.example:443\r\n\r\n":     "HTTP/1.1 403 Forbidden",
		"GET http://ur.sidecartest.example:58443/ HTTP/1.1\r\nHost: ur.sidecartest.example\r\n\r\n":   "HTTP/1.1 403 Forbidden",
	}
	for request, want := range cases {
		if got := connect(request); got != want {
			t.Errorf("%q: %q, want %q", strings.SplitN(request, "\r\n", 2)[0], got, want)
		}
	}
}

func TestListenersBindOnlyLoopbackAboveFiftyThousand(t *testing.T) {
	for _, address := range []string{"0.0.0.0:58443", "127.0.0.1:8443", "127.0.0.1:50000", "[::1]:58443", "192.0.2.1:58443"} {
		if _, err := loopbackPort(address); err == nil {
			t.Errorf("%s was taken", address)
		}
	}
	if port, err := loopbackPort("127.0.0.1:58443"); err != nil || port != 58443 {
		t.Errorf("the default: %d, %v", port, err)
	}
}

func TestRunRefusesADomainOutsideExampleAndMissingDirectories(t *testing.T) {
	valid := func() *pagestackSettings {
		settings := defaultPagestackSettings()
		settings.keyOrigin, settings.pages = t.TempDir(), t.TempDir()
		return settings
	}
	if err := checkPagestackSettings(valid()); err != nil {
		t.Fatalf("the defaults over two directories: %v", err)
	}
	notDirectory := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDirectory, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(settings *pagestackSettings){
		// the test data rule keeps real names out of this file, so a reserved one other than .example stands for them
		"another reserved domain": func(settings *pagestackSettings) { settings.domain = "sidecartest.test" },
		"a domain past .example":  func(settings *pagestackSettings) { settings.domain = "sidecartest.example.com" },
		"no key origin":           func(settings *pagestackSettings) { settings.keyOrigin = "" },
		"a missing pages":         func(settings *pagestackSettings) { settings.pages = filepath.Join(t.TempDir(), "absent") },
		"a file for pages":        func(settings *pagestackSettings) { settings.pages = notDirectory },
		"a public listener":       func(settings *pagestackSettings) { settings.listen = "0.0.0.0:58443" },
		"a low proxy port":        func(settings *pagestackSettings) { settings.proxy = "127.0.0.1:8080" },
	}
	for name, edit := range cases {
		settings := valid()
		edit(settings)
		if err := checkPagestackSettings(settings); err == nil {
			t.Errorf("%s was taken", name)
		}
	}
}
