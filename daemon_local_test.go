//go:build !js && !ios && !android && !sdk_mobile_bind && !windows

package sidecar

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"
)

// D-TRUST-8, I-17 and owner decisions 84 and 130 at the one helper every local service listens through.

// A self-signed certificate for a listener's TLS, on a synthetic name.
func testLocalTlsConfig(t *testing.T) *tls.Config {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "device.example"},
		DNSNames:     []string{"device.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}}}
}

// A connection whose local address a test chooses, so the per-connection rule is tested without a LAN address.
type testAddressedConn struct {
	net.Conn
	local net.Addr
}

func (self *testAddressedConn) LocalAddr() net.Addr {
	return self.local
}

// Each address the listener binds, as IPs.
func testListenerIps(listener *DaemonLocalListener) []string {
	ips := []string{}
	for _, address := range listener.Addrs() {
		ips = append(ips, address.(*net.TCPAddr).IP.String())
	}
	slices.Sort(ips)
	return ips
}

// §22.5's §5 row: git's http, submission and IMAP serve plaintext only on 127.0.0.1 and ::1. With no certificate a
// service stays on loopback, and an address beyond it, the wildcard included, is refused before anything binds; with
// one, a connection arriving off loopback is a TLS server, and plaintext there fails its handshake. git's ssh and a
// forward carry no plaintext rule of this helper's.
func TestPlaintextOnlyOnLoopback(t *testing.T) {
	tlsConfig := testLocalTlsConfig(t)
	for _, service := range []DaemonLocalService{DaemonLocalGitHttp, DaemonLocalSubmission, DaemonLocalImap} {
		for _, listen := range [][]string{{"192.0.2.10"}, {"0.0.0.0"}, {"::"}, {"127.0.0.1", "198.51.100.7"}} {
			if _, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: service, Listen: listen}); !errors.Is(err, ErrDaemonLocalPlaintext) {
				t.Errorf("%s with no certificate on %v: %v", service, listen, err)
			}
		}

		listener, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: service})
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range testListenerIps(listener) {
			if ip != "127.0.0.1" && ip != "::1" {
				t.Errorf("%s with no certificate bound %s", service, ip)
			}
		}
		if listener.LanExposed() {
			t.Errorf("%s on loopback reads LAN-exposed", service)
		}
		listener.Close()

		withTls, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: service, Tls: tlsConfig})
		if err != nil {
			t.Fatal(err)
		}
		// off loopback: a TLS server, which a TLS client completes and plaintext does not
		serverEnd, clientEnd := net.Pipe()
		served := withTls.serveAs(&testAddressedConn{Conn: serverEnd, local: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 17002}})
		if served == nil || !served.Tls || served.Loopback {
			t.Fatalf("%s off loopback: %+v", service, served)
		}
		handshaken := make(chan error, 1)
		go func() {
			handshaken <- served.Conn.(*tls.Conn).Handshake()
		}()
		client := tls.Client(clientEnd, &tls.Config{InsecureSkipVerify: true})
		if err := client.Handshake(); err != nil {
			t.Fatalf("%s's tls off loopback: %v", service, err)
		}
		if err := <-handshaken; err != nil {
			t.Fatal(err)
		}
		client.Close()
		served.Close()

		serverEnd, clientEnd = net.Pipe()
		served = withTls.serveAs(&testAddressedConn{Conn: serverEnd, local: &net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 17002}})
		go func() {
			handshaken <- served.Conn.(*tls.Conn).Handshake()
		}()
		go func() {
			clientEnd.Write([]byte("EHLO plaintext.example\r\n"))
			io.Copy(io.Discard, clientEnd)
		}()
		if err := <-handshaken; err == nil {
			t.Errorf("%s took plaintext off loopback", service)
		}
		served.Close()
		clientEnd.Close()

		// on loopback the same listener speaks plaintext
		serverEnd, clientEnd = net.Pipe()
		served = withTls.serveAs(&testAddressedConn{Conn: serverEnd, local: &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 17002}})
		if served == nil || served.Tls || !served.Loopback {
			t.Errorf("%s on loopback: %+v", service, served)
		}
		served.Close()
		clientEnd.Close()
		withTls.Close()
	}

	// ssh is encrypted everywhere and a forward is disclosed instead, so neither is narrowed
	for _, service := range []DaemonLocalService{DaemonLocalGitSsh, DaemonLocalForward} {
		listener, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: service})
		if err != nil {
			t.Fatal(err)
		}
		serverEnd, clientEnd := net.Pipe()
		served := listener.serveAs(&testAddressedConn{Conn: serverEnd, local: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 17001}})
		if served == nil || served.Tls || served.Loopback {
			t.Errorf("%s off loopback: %+v", service, served)
		}
		served.Close()
		clientEnd.Close()
		listener.Close()
	}
}

// --listen narrows: a service binds every interface unless it names addresses, and then binds those alone.
func TestListenNarrows(t *testing.T) {
	tlsConfig := testLocalTlsConfig(t)
	wide, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: DaemonLocalImap, Tls: tlsConfig})
	if err != nil {
		t.Fatal(err)
	}
	defer wide.Close()
	if ips := testListenerIps(wide); len(ips) != 1 || !net.ParseIP(ips[0]).IsUnspecified() {
		t.Errorf("the default binds %v, not every interface", ips)
	}
	if !wide.LanExposed() {
		t.Error("every interface does not read LAN-exposed")
	}

	narrow, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: DaemonLocalImap, Tls: tlsConfig, Listen: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer narrow.Close()
	if ips := testListenerIps(narrow); !slices.Equal(ips, []string{"127.0.0.1"}) {
		t.Errorf("--listen 127.0.0.1 binds %v", ips)
	}
	if narrow.LanExposed() {
		t.Error("a loopback-only listener reads LAN-exposed")
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := narrow.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	dialed, err := net.Dial("tcp", narrow.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer dialed.Close()
	select {
	case conn := <-accepted:
		local := conn.(*DaemonLocalConn)
		if !local.Loopback || local.Tls {
			t.Errorf("a loopback connection: %+v", local)
		}
		conn.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("no connection accepted")
	}

	if _, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: DaemonLocalImap, Listen: []string{"localhost"}}); !errors.Is(err, ErrDaemonLocalArgs) {
		t.Errorf("a name in --listen: %v", err)
	}
	// the port follows --port's first port, each service at its place
	first, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: DaemonLocalGitHttp, Listen: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	firstPort := first.Port()
	first.Close()
	if firstPort+3 <= 65535 {
		imap, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: DaemonLocalImap, FirstPort: firstPort, Listen: []string{"127.0.0.1"}})
		if err == nil {
			if imap.Port() != firstPort+3 {
				t.Errorf("IMAP at %d, not three past %d", imap.Port(), firstPort)
			}
			imap.Close()
		} else if !errors.Is(err, ErrDaemonLocalPortTaken) {
			t.Fatal(err)
		}
	}
}

// A forward is marked LAN-exposed when the LAN can reach it, and ur status lists it so while it is open.
func TestForwardLabeledLanExposed(t *testing.T) {
	started := startTestDaemon(t, nil)
	wide, err := started.daemon.LocalListen(&DaemonLocalListenArgs{Service: DaemonLocalForward})
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := started.daemon.LocalListen(&DaemonLocalListenArgs{Service: DaemonLocalForward, Listen: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !wide.LanExposed() || narrow.LanExposed() {
		t.Errorf("wide %v, narrow %v", wide.LanExposed(), narrow.LanExposed())
	}
	statuses := started.daemon.LocalListeners()
	exposed := 0
	for _, status := range statuses {
		if status.Service != DaemonLocalForward {
			t.Errorf("status %+v", status)
		}
		if status.LanExposed {
			exposed += 1
		}
	}
	if len(statuses) != 2 || exposed != 1 {
		t.Fatalf("statuses %+v", statuses)
	}
	wide.Close()
	if statuses := started.daemon.LocalListeners(); len(statuses) != 1 || statuses[0].LanExposed {
		t.Errorf("after the wide forward closed: %+v", statuses)
	}
	narrow.Close()
	if statuses := started.daemon.LocalListeners(); len(statuses) != 0 {
		t.Errorf("after both closed: %+v", statuses)
	}

	// the daemon's own --listen applies when a service names none
	narrowed := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.Listen = []string{"127.0.0.1"}
	})
	forward, err := narrowed.daemon.LocalListen(&DaemonLocalListenArgs{Service: DaemonLocalForward})
	if err != nil {
		t.Fatal(err)
	}
	if forward.LanExposed() {
		t.Error("the daemon's --listen did not narrow a forward")
	}
	forward.Close()
}

// HTTP targets check Host, so a page that rebinds a name to loopback reaches nothing, and every caller authenticates,
// loopback included (I-17).
func TestLocalHttpChecksHostAndCaller(t *testing.T) {
	listener, err := DaemonLocalListen(&DaemonLocalListenArgs{Service: DaemonLocalGitHttp, Listen: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	reached := 0
	handler := listener.HttpHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		reached += 1
	}), []string{"device.example"}, func(request *http.Request) bool {
		user, pass, ok := request.BasicAuth()
		return ok && user == "synthetic-user" && pass == "synthetic-pass"
	})
	serve := func(host string, authenticated bool) int {
		request := httptest.NewRequest("GET", "/repo/info/refs", nil)
		request.Host = host
		if authenticated {
			request.SetBasicAuth("synthetic-user", "synthetic-pass")
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}
	port := listener.Addr().(*net.TCPAddr).Port
	for _, host := range []string{"127.0.0.1", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), "localhost", "[::1]", "device.example"} {
		if code := serve(host, true); code != http.StatusOK {
			t.Errorf("Host %s answered %d", host, code)
		}
	}
	for _, host := range []string{"rebound.example", "192.0.2.10", ""} {
		if code := serve(host, true); code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q answered %d", host, code)
		}
	}
	if code := serve("127.0.0.1", false); code != http.StatusUnauthorized {
		t.Errorf("an unauthenticated loopback caller answered %d", code)
	}
	if reached != 5 {
		t.Errorf("the handler ran %d times", reached)
	}
	refusing := listener.HttpHandler(http.NotFoundHandler(), nil, nil)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/", nil)
	request.Host = "127.0.0.1"
	refusing.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("no authenticator answered %d", recorder.Code)
	}
}
