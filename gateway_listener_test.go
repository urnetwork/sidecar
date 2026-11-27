//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension && !windows

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// DESIGN-COMPUTE §8.4's listener and §8.7's local security (GW-M12-01): the Host check before anything, browsers
// refused and no CORS header ever, the body and concurrency bounds, loopback alone whatever is asked, the unit's
// listeners taken for their addresses alone, and a daemon that holds a grant never idling out.

// A port both loopback addresses have free now, from a range no system hands out on its own.
func testGatewayPort(t *testing.T) int {
	t.Helper()
	settings := DefaultGatewaySettings()
	settings.PortFirst, settings.PortLast = 30000, 31999
	port, err := ChooseGatewayPort(settings, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// Writes the instance's gateway state under directory: port, held or not.
func writeTestGatewayState(t *testing.T, directory string, port int, hold bool) {
	t.Helper()
	if err := WriteGatewayState(directory, &GatewayState{Version: gatewayStateVersion, Port: port, Hold: hold}); err != nil {
		t.Fatal(err)
	}
}

// A request to the guard with host and headers, answered by a handler that counts what reaches it.
func serveTestGatewayGuard(guard *gatewayGuard, method string, host string, headers map[string]string, body io.Reader) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://placeholder.invalid/v1/models", body)
	request.Host = host
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	guard.ServeHTTP(recorder, request)
	return recorder
}

// A handler that counts its calls and answers 200, setting CORS headers a guard must drop.
type testGatewayCountingHandler struct {
	stateLock sync.Mutex
	count     int
}

func (self *testGatewayCountingHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	self.stateLock.Lock()
	self.count += 1
	self.stateLock.Unlock()
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("access-control-allow-headers", "authorization")
	writer.WriteHeader(http.StatusOK)
	io.WriteString(writer, "{}")
}

func (self *testGatewayCountingHandler) calls() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.count
}

// No CORS header in an answer.
func checkTestGatewayNoCors(t *testing.T, what string, header http.Header) {
	t.Helper()
	for name := range header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-") {
			t.Errorf("%s: the answer carries %s", what, name)
		}
	}
}

// Each of the three Host forms reaches the handler at the port; every other Host, a rebinding page's name among them,
// is 421 before the handler or anything that reads a token.
func TestHostCheckMatrix(t *testing.T) {
	port := 31234
	handler := &testGatewayCountingHandler{}
	guard := newGatewayGuard(DefaultGatewaySettings(), port, handler)
	portText := strconv.Itoa(port)
	allowed := []string{"127.0.0.1:" + portText, "localhost:" + portText, "LocalHost:" + portText, "[::1]:" + portText}
	for _, host := range allowed {
		recorder := serveTestGatewayGuard(guard, http.MethodGet, host, nil, nil)
		if recorder.Code != http.StatusOK {
			t.Errorf("%q: %d", host, recorder.Code)
		}
	}
	refused := []string{"", "127.0.0.1", "localhost", "[::1]", "127.0.0.1:" + strconv.Itoa(port+1), "rebind.example:" + portText,
		"rebind.example", "127.0.0.2:" + portText, "0.0.0.0:" + portText, "[::ffff:127.0.0.1]:" + portText,
		"localhost.:" + portText, "127.0.0.1:" + portText + ".rebind.example"}
	for _, host := range refused {
		recorder := serveTestGatewayGuard(guard, http.MethodGet, host, map[string]string{"Authorization": "Bearer ur_gw_synthetic"}, nil)
		if recorder.Code != http.StatusMisdirectedRequest {
			t.Errorf("%q: %d, not 421", host, recorder.Code)
		}
	}
	if handler.calls() != len(allowed) {
		t.Errorf("the handler ran %d times for %d allowed hosts", handler.calls(), len(allowed))
	}
}

// A request with an Origin, of any value, or a Sec-Fetch-Site other than none is refused 403; none passes; and no
// answer, refused or served, carries a CORS header, whatever the handler set.
func TestBrowserRequestsRefused(t *testing.T) {
	port := 31235
	handler := &testGatewayCountingHandler{}
	guard := newGatewayGuard(DefaultGatewaySettings(), port, handler)
	host := "127.0.0.1:" + strconv.Itoa(port)
	refused := []map[string]string{
		{"Origin": "http://rebind.example"},
		{"Origin": "null"},
		{"Origin": ""},
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
		{"Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Site": "None, cross-site"},
		{"Sec-Fetch-Site": "none", "Origin": "http://127.0.0.1:" + strconv.Itoa(port)},
	}
	for _, headers := range refused {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
			request := httptest.NewRequest(method, "http://placeholder.invalid/v1/responses", nil)
			request.Host = host
			for name, value := range headers {
				request.Header[http.CanonicalHeaderKey(name)] = []string{value}
			}
			recorder := httptest.NewRecorder()
			guard.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Errorf("%s %v: %d, not 403", method, headers, recorder.Code)
			}
			checkTestGatewayNoCors(t, fmt.Sprintf("%s %v", method, headers), recorder.Header())
		}
	}
	if handler.calls() != 0 {
		t.Fatalf("a browser's request reached the handler %d times", handler.calls())
	}
	for _, headers := range []map[string]string{nil, {"Sec-Fetch-Site": "none"}, {"Sec-Fetch-Site": "NONE"}} {
		recorder := serveTestGatewayGuard(guard, http.MethodGet, host, headers, nil)
		if recorder.Code != http.StatusOK {
			t.Errorf("%v: %d", headers, recorder.Code)
		}
		checkTestGatewayNoCors(t, fmt.Sprintf("served %v", headers), recorder.Header())
	}
}

// The listener asks for 127.0.0.1:<port> and [::1]:<port> and nothing else, whatever the daemon's own --listen says,
// and a unit's listener bound anywhere else is closed, never served.
func TestNonLoopbackNeverBound(t *testing.T) {
	port := testGatewayPort(t)
	directory := t.TempDir()
	writeTestGatewayState(t, directory, port, true)
	asked := []string{}
	askedLock := sync.Mutex{}
	listen := func(network string, address string) (net.Listener, error) {
		askedLock.Lock()
		asked = append(asked, network+" "+address)
		askedLock.Unlock()
		return net.Listen(network, address)
	}
	elsewhere := []net.Listener{}
	for _, address := range []string{"127.0.0.1:0", net.JoinHostPort("0.0.0.0", "0")} {
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		elsewhere = append(elsewhere, listener)
	}
	server := NewGatewayServer(&GatewayServerArgs{StateDirectory: directory, Listen: listen, Inherited: elsewhere})
	t.Cleanup(server.Close)
	status := server.Start()
	if !status.Serving {
		t.Fatalf("not serving: %+v", status)
	}
	want := []string{"tcp4 127.0.0.1:" + strconv.Itoa(port), "tcp6 [::1]:" + strconv.Itoa(port)}
	askedLock.Lock()
	got := slices.Clone(asked)
	askedLock.Unlock()
	if !slices.Equal(got, want) {
		t.Errorf("bound %v, want %v", got, want)
	}
	if status.RefusedInherited != len(elsewhere) {
		t.Errorf("%d of the unit's listeners refused, want %d", status.RefusedInherited, len(elsewhere))
	}
	for _, address := range status.Addresses {
		if address.Inherited {
			t.Errorf("%s was served from a listener bound elsewhere", address.Address)
		}
	}
	for _, listener := range elsewhere {
		if _, err := listener.Accept(); err == nil {
			t.Errorf("a listener bound elsewhere still accepts")
		}
	}
}

// A declared body past RequestByteCount is 413 before the handler; a chunked one fails its read at the bound; 32
// requests held at a barrier take every slot, the 33rd is 429 at once, and once one ends another is served.
func TestBodyAndConcurrencyCaps(t *testing.T) {
	settings := DefaultGatewaySettings()
	settings.RequestByteCount = 1024
	port := 31236
	host := "127.0.0.1:" + strconv.Itoa(port)
	entered := make(chan struct{}, 64)
	release := make(chan struct{})
	readErrs := make(chan error, 64)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/hold" {
			entered <- struct{}{}
			<-release
			writer.WriteHeader(http.StatusOK)
			return
		}
		_, err := io.ReadAll(request.Body)
		readErrs <- err
		writer.WriteHeader(http.StatusOK)
	})
	guard := newGatewayGuard(settings, port, handler)

	declared := httptest.NewRequest(http.MethodPost, "http://placeholder.invalid/v1/responses", bytes.NewReader(make([]byte, 1025)))
	declared.Host = host
	recorder := httptest.NewRecorder()
	guard.ServeHTTP(recorder, declared)
	if recorder.Code != http.StatusRequestEntityTooLarge || len(readErrs) != 0 {
		t.Fatalf("a declared 1025-byte body: %d, %d reads", recorder.Code, len(readErrs))
	}
	chunked := httptest.NewRequest(http.MethodPost, "http://placeholder.invalid/v1/responses", io.MultiReader(bytes.NewReader(make([]byte, 1025))))
	chunked.Host = host
	chunked.ContentLength = -1
	guard.ServeHTTP(httptest.NewRecorder(), chunked)
	var maxBytes *http.MaxBytesError
	if err := <-readErrs; !errors.As(err, &maxBytes) {
		t.Fatalf("a chunked body past the bound read: %v", err)
	}
	exact := httptest.NewRequest(http.MethodPost, "http://placeholder.invalid/v1/responses", bytes.NewReader(make([]byte, 1024)))
	exact.Host = host
	guard.ServeHTTP(httptest.NewRecorder(), exact)
	if err := <-readErrs; err != nil {
		t.Fatalf("a body at the bound: %v", err)
	}

	held := sync.WaitGroup{}
	for i := 0; i < settings.ConcurrentRequestCount; i += 1 {
		held.Add(1)
		go func() {
			defer held.Done()
			request := httptest.NewRequest(http.MethodGet, "http://placeholder.invalid/hold", nil)
			request.Host = host
			guard.ServeHTTP(httptest.NewRecorder(), request)
		}()
	}
	for i := 0; i < settings.ConcurrentRequestCount; i += 1 {
		<-entered
	}
	refused := serveTestGatewayGuard(guard, http.MethodGet, host, nil, nil)
	if refused.Code != http.StatusTooManyRequests || refused.Header().Get("Retry-After") != "1" {
		t.Errorf("the 33rd request: %d, Retry-After %q", refused.Code, refused.Header().Get("Retry-After"))
	}
	close(release)
	held.Wait()
	after := httptest.NewRequest(http.MethodPost, "http://placeholder.invalid/v1/responses", strings.NewReader("{}"))
	after.Host = host
	recorder = httptest.NewRecorder()
	guard.ServeHTTP(recorder, after)
	if recorder.Code != http.StatusOK {
		t.Errorf("after the held requests ended: %d", recorder.Code)
	}
	if err := <-readErrs; err != nil {
		t.Errorf("after the held requests ended: %v", err)
	}
}

// Through the real sockets: an absolute-form request naming another host is 421, as its Host is that host.
func TestHostCheckOnTheSocket(t *testing.T) {
	port := testGatewayPort(t)
	directory := t.TempDir()
	writeTestGatewayState(t, directory, port, true)
	server := NewGatewayServer(&GatewayServerArgs{StateDirectory: directory})
	t.Cleanup(server.Close)
	if status := server.Start(); !status.Serving {
		t.Fatalf("not serving: %+v", status)
	}
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET http://rebind.example:%d/v1/ur/listener HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", port, port)
	answer, _ := io.ReadAll(conn)
	if !strings.HasPrefix(string(answer), "HTTP/1.1 421") {
		t.Errorf("an absolute-form request to another host: %q", strings.SplitN(string(answer), "\r\n", 2)[0])
	}
}

// The port is held while the state holds, let go once no grant stands, and held again after.
func TestGatewayServesWhileHeld(t *testing.T) {
	port := testGatewayPort(t)
	directory := t.TempDir()
	server := NewGatewayServer(&GatewayServerArgs{StateDirectory: directory})
	t.Cleanup(server.Close)
	if status := server.Start(); status.Serving || status.Reason == "" {
		t.Fatalf("with no state: %+v", status)
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	writeTestGatewayState(t, directory, port, true)
	if status := server.Reload(); !status.Serving {
		t.Fatalf("held: %+v", status)
	}
	if _, err := net.Listen("tcp4", address); err == nil || !gatewayAddressInUse(err) {
		t.Fatalf("the held port bound again: %v", err)
	}
	writeTestGatewayState(t, directory, port, false)
	if status := server.Reload(); status.Serving {
		t.Fatalf("no grant: %+v", status)
	}
	released, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatalf("the port was not let go: %v", err)
	}
	released.Close()
	writeTestGatewayState(t, directory, port, true)
	if status := server.Reload(); !status.Serving {
		t.Fatalf("held again: %+v", status)
	}
}

// A listener the daemon's unit handed over on the port is served as the unit's; letting go of the port while no grant
// stands closes the server's listener and keeps the unit's socket, which serves again once a grant stands.
func TestInheritedSocketKeptAcrossReload(t *testing.T) {
	port := testGatewayPort(t)
	directory := t.TempDir()
	writeTestGatewayState(t, directory, port, true)
	unit, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	server := NewGatewayServer(&GatewayServerArgs{StateDirectory: directory, Inherited: []net.Listener{unit}})
	t.Cleanup(server.Close)
	check := func(what string) {
		t.Helper()
		status := server.Reload()
		if !status.Serving || !status.Addresses[0].Inherited {
			t.Fatalf("%s: %+v", what, status)
		}
		key, err := server.ListenerKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := ProveGatewayListener(context.Background(), DefaultGatewaySettings(), key, status.Addresses[0].Address, nil); err != nil {
			t.Fatalf("%s: the unit's socket did not answer: %v", what, err)
		}
	}
	check("first")
	writeTestGatewayState(t, directory, port, false)
	if status := server.Reload(); status.Serving {
		t.Fatalf("no grant: %+v", status)
	}
	writeTestGatewayState(t, directory, port, true)
	check("again")
}

// An auto-spawned daemon whose gateway holds a grant never idles out; once none stands it may; and a state that does
// not read keeps it up, the direction that keeps the port.
func TestDaemonStaysUpWhileGrantStands(t *testing.T) {
	port := testGatewayPort(t)
	directory := t.TempDir()
	writeTestGatewayState(t, directory, port, true)
	server := NewGatewayServer(&GatewayServerArgs{StateDirectory: directory})
	t.Cleanup(server.Close)
	server.Start()
	clock := newTokenTestClock()
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.AutoSpawned = true
		settings.Clock = clock
		settings.Busy = server.Active
	})
	clock.Advance(time.Hour)
	if started.daemon.ShouldIdleExit() {
		t.Fatal("a daemon holding a grant idles out")
	}
	writeTestGatewayState(t, directory, port, false)
	server.Reload()
	if !started.daemon.ShouldIdleExit() {
		t.Fatal("a daemon holding no grant stays up")
	}
	if err := os.WriteFile(GatewayStatePath(directory), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.Reload()
	if started.daemon.ShouldIdleExit() {
		t.Fatal("a state that does not read let the daemon idle out")
	}
	server.Close()
	if !started.daemon.ShouldIdleExit() {
		t.Fatal("a closed gateway keeps the daemon up")
	}
}

// The state file round-trips, refuses what it cannot serve, and is private.
func TestGatewayStateFile(t *testing.T) {
	directory := t.TempDir()
	settings := DefaultGatewaySettings()
	state, err := ReadGatewayState(directory, settings.StateFileByteCount)
	if err != nil || state.Holds() || state.Port != 0 {
		t.Fatalf("no file: %+v %v", state, err)
	}
	writeTestGatewayState(t, directory, 31237, true)
	state, err = ReadGatewayState(directory, settings.StateFileByteCount)
	if err != nil || !state.Holds() || state.Port != 31237 {
		t.Fatalf("written: %+v %v", state, err)
	}
	info, err := os.Stat(GatewayStatePath(directory))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the file's mode: %v %v", info, err)
	}
	for _, bad := range []*GatewayState{
		{Version: 2, Port: 1},
		{Version: gatewayStateVersion, Port: 70000},
		{Version: gatewayStateVersion, Port: 0, Hold: true},
	} {
		if err := WriteGatewayState(directory, bad); err == nil {
			t.Errorf("%+v written", bad)
		}
	}
	for _, content := range []string{"{}", `{"version":1,"port":1,"extra":true}`, strings.Repeat(" ", 5000)} {
		if err := os.WriteFile(GatewayStatePath(directory), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadGatewayState(directory, settings.StateFileByteCount); !errors.Is(err, ErrGatewayState) {
			t.Errorf("%.20q read: %v", content, err)
		}
	}
}
