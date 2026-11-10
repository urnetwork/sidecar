// pagestack's own rules: the key origin serves its four files and nothing else, each answer with its CSP and no
// X-Frame-Options; the api answers CORS for the key origin alone; the proxy tunnels the fixture names at the TLS port
// and refuses every other host before dialing anything; and the listeners bind only 127.0.0.1 above port 50000.

package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A handler over a staged key origin and a pages directory in t's temp, with an api that answers 299.
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

func TestApiAnswersCorsForTheKeyOriginAlone(t *testing.T) {
	handler := testPagestackHandler(t)
	host := "api.sidecartest.example:58443"
	preflight := testPagestackServe(handler, http.MethodOptions, host, "/auth/refresh", map[string]string{"Origin": handler.keyOrigin})
	if preflight.Code != http.StatusNoContent || preflight.Header().Get("Access-Control-Allow-Origin") != handler.keyOrigin ||
		!strings.Contains(preflight.Header().Get("Access-Control-Allow-Headers"), "DPoP") {
		t.Errorf("the key origin's preflight: %d, %v", preflight.Code, preflight.Header())
	}
	for _, origin := range []string{handler.pageOrigin, "https://other.sidecartest.example:58443", ""} {
		answer := testPagestackServe(handler, http.MethodGet, host, "/auth/refresh", map[string]string{"Origin": origin})
		if answer.Code != 299 || answer.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("origin %q: %d, %v", origin, answer.Code, answer.Header())
		}
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
