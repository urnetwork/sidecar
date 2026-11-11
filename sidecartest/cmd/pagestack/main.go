// pagestack: T2's fakes over HTTPS on loopback, for SDK-M4-09's browser harness (§22.9's Browsers row,
// mmm/sidecar.ur.io/test/playwright). Every name it answers is a fixture hostname under -domain, an .example domain no
// real host answers, and every browser reaches it through its own proxy, so no browser run resolves or reaches a real
// domain (CODESTYLE's test data rule).
//
//	pagestack -listen 127.0.0.1:58443 -proxy 127.0.0.1:58080 -key-origin <staged dir> -pages <dir>
//
// By Host, on the TLS listener:
//
//	ur.<domain>, other.<domain>, localhost   -pages, the fixture page: at the listed page origin, at another origin
//	                                         and at localhost, which the key origin never lists
//	sidecar.<domain>                          -key-origin's /v1/ only, as mmm's server block serves the key origin
//	                                         (SDK-M4-06): every answer, a 404 too, with its CSP exactly, frame-ancestors
//	                                         the listed page origin, and no X-Frame-Options
//	api.<domain>, auth.<domain>               sidecartest's FakeApi, api's and the issuer's origins, with CORS for the
//	                                         key origin alone, DPoP among its headers (SDK-M4-06's warp lists)
//	127.0.0.1                                 /healthz, which a harness polls before it starts
//
// The proxy takes CONNECT to those names at the TLS port and nothing else, so a browser's request for any other host,
// its own updates included, is refused here and never leaves the machine.
//
// TLS is a certificate made at start for those names, which the harness tells the browser to accept; nothing of it is
// a secret. The fakes run on the Net's fake clock, moved with real time, so the tokens it mints and the DPoP proofs a
// browser makes read as now.
//
// It prints "pagestack ready <page url>" once both listeners are up, and ends at SIGINT or SIGTERM. The listeners bind
// 127.0.0.1 above port 50000 only, as the brief bounds what a test starts.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The ports a pagestack may bind: above 50000, as every container and server a test starts.
const pagestackMinPort = 50001

// What the key origin's /v1/ serves, by its path, with each file's type (SDK-M4-06's server block).
var pagestackKeyOriginFiles = map[string]string{
	"/v1/":             "text/html; charset=utf-8",
	"/v1/index.html":   "text/html; charset=utf-8",
	"/v1/loader.js":    "text/javascript; charset=utf-8",
	"/v1/worker.js":    "text/javascript; charset=utf-8",
	"/v1/sidecar.wasm": "application/wasm",
}

// What a run takes, its flags' defaults from defaultPagestackSettings.
type pagestackSettings struct {
	listen    string
	proxy     string
	keyOrigin string
	pages     string
	domain    string
	// How often the fake clock catches up with real time: 200 ms, well inside a DPoP proof's 60 s window.
	clockInterval time.Duration
	// How long a proxied tunnel may sit idle before it closes: 5 min, past any one spec.
	tunnelIdleTimeout time.Duration
	// How long the TLS listener waits for a request's headers, and the proxy for a CONNECT: 30 s.
	readHeaderTimeout time.Duration
	// How long the proxy waits to reach the TLS listener: 10 s.
	dialTimeout time.Duration
	// How long a stop waits for requests in flight: 5 s.
	shutdownTimeout time.Duration
	// How long the certificate made at start is good for: a day, past any run.
	certificateLifetime time.Duration
	// How long before now it is good from: an hour, for a browser's clock a little behind.
	certificateBackdate time.Duration
}

// The defaults: the ports the harness uses, above 50000, and the fixture domain.
func defaultPagestackSettings() *pagestackSettings {
	return &pagestackSettings{
		listen:              "127.0.0.1:58443",
		proxy:               "127.0.0.1:58080",
		domain:              "sidecartest.example",
		clockInterval:       200 * time.Millisecond,
		tunnelIdleTimeout:   5 * time.Minute,
		readHeaderTimeout:   30 * time.Second,
		dialTimeout:         10 * time.Second,
		shutdownTimeout:     5 * time.Second,
		certificateLifetime: 24 * time.Hour,
		certificateBackdate: time.Hour,
	}
}

func main() {
	settings := defaultPagestackSettings()
	flag.StringVar(&settings.listen, "listen", settings.listen, "the TLS listener, 127.0.0.1 above port 50000")
	flag.StringVar(&settings.proxy, "proxy", settings.proxy, "the CONNECT proxy browsers reach the fixture names through")
	flag.StringVar(&settings.keyOrigin, "key-origin", "", "the staged key origin, a directory holding v1/")
	flag.StringVar(&settings.pages, "pages", "", "the fixture pages, a directory")
	flag.StringVar(&settings.domain, "domain", settings.domain, "the fixture domain, under .example")
	flag.DurationVar(&settings.clockInterval, "clock-interval", settings.clockInterval, "how often the fake clock follows real time")
	flag.DurationVar(&settings.tunnelIdleTimeout, "tunnel-idle-timeout", settings.tunnelIdleTimeout, "how long a proxied tunnel may sit idle")
	flag.Parse()
	if err := run(settings); err != nil {
		log.Fatalf("pagestack: %v", err)
	}
}

// Checks that address is 127.0.0.1 above pagestackMinPort, and answers its port.
func loopbackPort(address string) (int, error) {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return 0, err
	}
	if addrPort.Addr() != netip.MustParseAddr("127.0.0.1") || int(addrPort.Port()) < pagestackMinPort {
		return 0, fmt.Errorf("%s is not 127.0.0.1 above port %d", address, pagestackMinPort-1)
	}
	return int(addrPort.Port()), nil
}

func run(settings *pagestackSettings) error {
	port, err := loopbackPort(settings.listen)
	if err != nil {
		return err
	}
	if _, err := loopbackPort(settings.proxy); err != nil {
		return err
	}
	if !strings.HasSuffix(settings.domain, ".example") {
		return fmt.Errorf("the domain %s is not under .example", settings.domain)
	}
	for _, directory := range []string{settings.keyOrigin, settings.pages} {
		if info, err := os.Stat(directory); err != nil || !info.IsDir() {
			return fmt.Errorf("%q is not a directory", directory)
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	origin := func(name string) string {
		return fmt.Sprintf("https://%s.%s:%d", name, settings.domain, port)
	}
	netSettings := sidecartest.DefaultNetSettings()
	netSettings.ClockStart = time.Now()
	world := sidecartest.NewNet(ctx, netSettings)
	defer world.Close()
	apiSettings := sidecartest.DefaultFakeApiSettings()
	apiSettings.Origin = origin("api")
	apiSettings.AuthOrigin = origin("auth")
	apiSettings.ServiceDomain = settings.domain
	api, err := world.AddApi(apiSettings)
	if err != nil {
		return err
	}
	// the fakes' clock follows real time, since a browser's tokens and proofs carry it
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(settings.clockInterval):
			}
			if now := time.Now(); world.Clock().Now().Before(now) {
				world.Clock().AdvanceTo(now)
			}
		}
	}()

	names := []string{}
	for _, name := range []string{"ur", "other", "sidecar", "api", "auth"} {
		names = append(names, name+"."+settings.domain)
	}
	certificate, err := pagestackCertificate(append(copiedNames(names), "localhost"), settings)
	if err != nil {
		return err
	}
	handler := &pagestackHandler{
		settings:   settings,
		api:        api,
		pageOrigin: origin("ur"),
		keyOrigin:  origin("sidecar"),
		csp: fmt.Sprintf("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' %s %s; frame-ancestors %s",
			origin("api"), origin("auth"), origin("ur")),
	}
	listener, err := tls.Listen("tcp", settings.listen, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: settings.readHeaderTimeout}
	proxyListener, err := net.Listen("tcp", settings.proxy)
	if err != nil {
		listener.Close()
		return err
	}
	proxy := &pagestackProxy{
		target:   settings.listen,
		port:     strconv.Itoa(port),
		names:    append(copiedNames(names), "localhost"),
		settings: settings,
	}
	go server.Serve(listener)
	go proxy.serve(ctx, proxyListener)
	fmt.Printf("pagestack ready %s/fixture-page.html\n", origin("ur"))
	<-ctx.Done()
	proxyListener.Close()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), settings.shutdownTimeout)
	defer shutdownCancel()
	return server.Shutdown(shutdownCtx)
}

// A copy of names, so appending to it never writes into names.
func copiedNames(names []string) []string {
	return append([]string(nil), names...)
}

// A self-signed certificate for names, made now and good for the settings' lifetime.
func pagestackCertificate(names []string, settings *pagestackSettings) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "pagestack"},
		NotBefore:             now.Add(-settings.certificateBackdate),
		NotAfter:              now.Add(settings.certificateLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// Routes each request by its Host (the file's comment).
type pagestackHandler struct {
	settings   *pagestackSettings
	api        http.Handler
	pageOrigin string
	keyOrigin  string
	csp        string
}

func (self *pagestackHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	host := request.Host
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		host = hostOnly
	}
	host = strings.ToLower(host)
	domain := self.settings.domain
	switch host {
	case "ur." + domain, "other." + domain, "localhost":
		self.servePage(writer, request)
	case "sidecar." + domain:
		self.serveKeyOrigin(writer, request)
	case "api." + domain, "auth." + domain:
		self.serveApi(writer, request)
	case "127.0.0.1":
		if request.URL.Path == "/healthz" {
			writer.WriteHeader(http.StatusOK)
			io.WriteString(writer, "ok\n")
			return
		}
		http.NotFound(writer, request)
	default:
		http.Error(writer, "no such fixture host", http.StatusMisdirectedRequest)
	}
}

// A fixture page file, by its base name only.
func (self *pagestackHandler) servePage(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(writer, "method", http.StatusMethodNotAllowed)
		return
	}
	name := path.Base(path.Clean(request.URL.Path))
	if name == "/" || name == "." || strings.HasPrefix(name, ".") {
		name = "fixture-page.html"
	}
	contentType := map[string]string{".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8"}[path.Ext(name)]
	if contentType == "" {
		http.NotFound(writer, request)
		return
	}
	content, err := os.ReadFile(filepath.Join(self.settings.pages, name))
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Write(content)
}

// The key origin's four files and nothing else, each answer with its CSP.
func (self *pagestackHandler) serveKeyOrigin(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Security-Policy", self.csp)
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Cache-Control", "no-store")
	contentType, ok := pagestackKeyOriginFiles[request.URL.Path]
	if !ok || (request.Method != http.MethodGet && request.Method != http.MethodHead) {
		http.NotFound(writer, request)
		return
	}
	name := strings.TrimPrefix(request.URL.Path, "/")
	if strings.HasSuffix(name, "/") {
		name += "index.html"
	}
	content, err := os.ReadFile(filepath.Join(self.settings.keyOrigin, filepath.FromSlash(name)))
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", contentType)
	writer.Write(content)
}

// The fake api, with CORS for the key origin alone, as the lb's lists give it (SDK-M4-06).
func (self *pagestackHandler) serveApi(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Origin") == self.keyOrigin {
		header := writer.Header()
		header.Set("Access-Control-Allow-Origin", self.keyOrigin)
		header.Set("Vary", "Origin")
		header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, DPoP, If-Match, If-None-Match")
		header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		header.Set("Access-Control-Expose-Headers", "ETag, Retry-After")
		header.Set("Access-Control-Max-Age", "600")
		if request.Method == http.MethodOptions {
			writer.WriteHeader(http.StatusNoContent)
			return
		}
	}
	self.api.ServeHTTP(writer, request)
}

// The CONNECT proxy browsers reach the fixture names through: to those names at the TLS port it tunnels to the TLS
// listener, and refuses everything else.
type pagestackProxy struct {
	target   string
	port     string
	names    []string
	settings *pagestackSettings
}

// Accepts on listener until ctx ends or it closes.
func (self *pagestackProxy) serve(ctx context.Context, listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			continue
		}
		go self.tunnel(connection)
	}
}

// Reads one CONNECT and tunnels it, or refuses.
func (self *pagestackProxy) tunnel(connection net.Conn) {
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(self.settings.readHeaderTimeout))
	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	refuse := func() {
		io.WriteString(connection, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}
	if request.Method != http.MethodConnect {
		refuse()
		return
	}
	host, port, err := net.SplitHostPort(request.Host)
	if err != nil || port != self.port {
		refuse()
		return
	}
	allowed := false
	for _, name := range self.names {
		if strings.EqualFold(host, name) {
			allowed = true
		}
	}
	if !allowed {
		refuse()
		return
	}
	upstream, err := net.DialTimeout("tcp", self.target, self.settings.dialTimeout)
	if err != nil {
		io.WriteString(connection, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	connection.SetDeadline(time.Time{})
	// the bytes the reader took past the CONNECT are the tunnel's first
	if buffered := reader.Buffered(); 0 < buffered {
		head, _ := reader.Peek(buffered)
		if _, err := upstream.Write(head); err != nil {
			return
		}
	}
	idle := &pagestackIdle{timeout: self.settings.tunnelIdleTimeout, connections: []net.Conn{connection, upstream}}
	done := sync.WaitGroup{}
	done.Add(2)
	go func() {
		defer done.Done()
		io.Copy(idle.writer(upstream), connection)
		upstream.Close()
	}()
	go func() {
		defer done.Done()
		io.Copy(idle.writer(connection), upstream)
		connection.Close()
	}()
	done.Wait()
}

// Extends both ends' deadlines at each write, so a tunnel idle past timeout closes.
type pagestackIdle struct {
	timeout     time.Duration
	connections []net.Conn
}

// A writer to connection that extends the deadlines.
func (self *pagestackIdle) writer(connection net.Conn) io.Writer {
	self.extend()
	return pagestackIdleWriter{idle: self, connection: connection}
}

// Moves both deadlines to timeout from now.
func (self *pagestackIdle) extend() {
	deadline := time.Now().Add(self.timeout)
	for _, connection := range self.connections {
		connection.SetDeadline(deadline)
	}
}

type pagestackIdleWriter struct {
	idle       *pagestackIdle
	connection net.Conn
}

func (self pagestackIdleWriter) Write(p []byte) (int, error) {
	self.idle.extend()
	return self.connection.Write(p)
}
