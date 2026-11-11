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
//	api.<domain>, auth.<domain>               sidecartest's FakeApi, api's and the issuer's origins
//	evs.<domain>, gkm.<domain>                evsservice's and gkmservice's engines on the Net's host, over the
//	                                         fixture network's state (fixture.go), whose owner's vault holds a record
//	127.0.0.1                                 /healthz, which a harness polls before it starts, and /fixture.json, the
//	                                         fixture's ids, which a harness reads; no browser is proxied here
//
// Every service answers CORS for the key origin alone, with the lb's lists (warp's cors_origins block, SDK-M4-06), and
// the key origin's CSP names exactly api, auth, evs and gkm in its connect-src, as production's does.
//
// The proxy takes CONNECT to those names at the TLS port and nothing else, so a browser's request for any other host,
// its own updates included, is refused here and never leaves the machine.
//
// TLS is a certificate made at start for those names, which the harness tells the browser to accept; nothing of it is
// a secret. The fakes run on the Net's fake clock, moved with real time, so the tokens it mints and the DPoP proofs a
// browser makes read as now.
//
// It prints "pagestack ready <page url>" once both listeners are up and the fixture's record is committed, and ends
// at SIGINT or SIGTERM. The listeners bind 127.0.0.1 above port 50000 only, as the brief bounds what a test starts.
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
	"encoding/json"
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

	"github.com/urnetwork/sidecar"
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

// The fixture names under the domain: the page's two origins, the key origin, and the services the key origin's
// connect-src lists, in its order.
var (
	pagestackPageNames    = []string{"ur", "other"}
	pagestackServiceNames = []string{"api", "auth", "evs", "gkm"}
)

// The lb's CORS lists for a service whose cors_origins name an origin (warp's addCorsHeaders): what the page Worker
// sends and reads cross-origin, a DPoP proof, If-Match and If-None-Match, Range, ETag and Retry-After among them.
const (
	pagestackCorsAllowMethods  = "GET, POST, PUT, DELETE, OPTIONS"
	pagestackCorsAllowHeaders  = "DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,X-Client-Version,X-UR-ClientInfo,X-UR-Intended-Network-Id,Authorization,Accept,Mcp-Session-Id,MCP-Protocol-Version,Last-Event-ID,DPoP,If-Match,If-None-Match"
	pagestackCorsExposeHeaders = "Content-Length,Content-Range,Accept,Mcp-Session-Id,MCP-Protocol-Version,Last-Event-ID,ETag,Retry-After"
)

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
	// How long a browser may keep a preflight's answer: 20 days, the lb's Access-Control-Max-Age.
	corsMaxAge time.Duration
	// How long a fixture device's service token lasts: 15 min, the exchange's (§7.8).
	serviceTokenLifetime time.Duration
	// How long a fixture device's ReaderKey is good for: the most a ReaderKey may run (D-KEYS-25), past any run.
	readerKeyLifetime time.Duration
	// The fixture network's quota balance, in bytes: 1 TiB, so no fixture write meets a limit.
	fixtureBalanceByteCount int64
}

// The defaults: the ports the harness uses, above 50000, and the fixture domain.
func defaultPagestackSettings() *pagestackSettings {
	return &pagestackSettings{
		listen:                  "127.0.0.1:58443",
		proxy:                   "127.0.0.1:58080",
		domain:                  "sidecartest.example",
		clockInterval:           200 * time.Millisecond,
		tunnelIdleTimeout:       5 * time.Minute,
		readHeaderTimeout:       30 * time.Second,
		dialTimeout:             10 * time.Second,
		shutdownTimeout:         5 * time.Second,
		certificateLifetime:     24 * time.Hour,
		certificateBackdate:     time.Hour,
		corsMaxAge:              20 * 24 * time.Hour,
		serviceTokenLifetime:    15 * time.Minute,
		readerKeyLifetime:       sidecar.GkmReaderKeyLifetime,
		fixtureBalanceByteCount: 1024 * 1024 * 1024 * 1024,
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

// Checks the settings a run binds and reads: loopback ports above 50000, an .example domain, and both directories.
func checkPagestackSettings(settings *pagestackSettings) error {
	if _, err := loopbackPort(settings.listen); err != nil {
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
	return nil
}

func run(settings *pagestackSettings) error {
	if err := checkPagestackSettings(settings); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	listener, err := net.Listen("tcp", settings.listen)
	if err != nil {
		return err
	}
	proxyListener, err := net.Listen("tcp", settings.proxy)
	if err != nil {
		listener.Close()
		return err
	}
	stack, err := newPagestack(ctx, settings, listener, proxyListener)
	if err != nil {
		return err
	}
	fmt.Printf("pagestack ready %s\n", stack.pageUrl())
	<-ctx.Done()
	return stack.close()
}

// One running stack (the file's comment): the Net and its fakes, the fixture network, the TLS listener's server and
// the proxy.
type pagestack struct {
	settings    *pagestackSettings
	port        int
	cancel      context.CancelFunc
	world       *sidecartest.Net
	fixture     *pagestackFixture
	certificate tls.Certificate
	handler     *pagestackHandler
	server      *http.Server
	proxy       *pagestackProxy

	proxyListener net.Listener
	serving       sync.WaitGroup
	closeOnce     sync.Once
	closeErr      error
}

// Starts a stack serving TLS on listener and its proxy on proxyListener, which it owns from here and closes, on a
// failure too. It answers once the fixture's record is committed.
func newPagestack(ctx context.Context, settings *pagestackSettings, listener net.Listener, proxyListener net.Listener) (stack *pagestack, returnErr error) {
	stackCtx, cancel := context.WithCancel(ctx)
	stack = &pagestack{settings: settings, cancel: cancel, proxyListener: proxyListener}
	defer func() {
		if returnErr != nil {
			listener.Close()
			stack.close()
		}
	}()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("the listener at %s is not TCP", listener.Addr())
	}
	stack.port = address.Port

	netSettings := sidecartest.DefaultNetSettings()
	netSettings.ClockStart = time.Now()
	stack.world = sidecartest.NewNet(stackCtx, netSettings)
	apiSettings := sidecartest.DefaultFakeApiSettings()
	apiSettings.Origin = stack.origin("api")
	apiSettings.AuthOrigin = stack.origin("auth")
	apiSettings.ServiceDomain = settings.domain
	api, err := stack.world.AddApi(apiSettings)
	if err != nil {
		return nil, err
	}
	// the fakes' clock follows real time, since a browser's tokens and proofs carry it
	stack.serving.Add(1)
	go func() {
		defer stack.serving.Done()
		for {
			select {
			case <-stackCtx.Done():
				return
			case <-time.After(settings.clockInterval):
			}
			if now := time.Now(); stack.world.Clock().Now().Before(now) {
				stack.world.Clock().AdvanceTo(now)
			}
		}
	}()
	stack.fixture, err = newPagestackFixture(stackCtx, stack.world, settings)
	if err != nil {
		return nil, fmt.Errorf("the fixture network: %w", err)
	}

	names := stack.names()
	stack.certificate, err = pagestackCertificate(names, settings)
	if err != nil {
		return nil, err
	}
	connectOrigins := []string{}
	for _, name := range pagestackServiceNames {
		connectOrigins = append(connectOrigins, stack.origin(name))
	}
	stack.handler = &pagestackHandler{
		settings:   settings,
		api:        api,
		evs:        stack.fixture.evs.Handler(),
		gkm:        stack.fixture.gkm.Handler(),
		fixture:    stack.fixture,
		pageOrigin: stack.origin("ur"),
		keyOrigin:  stack.origin("sidecar"),
		csp: fmt.Sprintf("default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' %s; frame-ancestors %s",
			strings.Join(connectOrigins, " "), stack.origin("ur")),
	}
	stack.server = &http.Server{Handler: stack.handler, ReadHeaderTimeout: settings.readHeaderTimeout}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{stack.certificate}, MinVersion: tls.VersionTLS12})
	stack.proxy = &pagestackProxy{
		target:   listener.Addr().String(),
		port:     strconv.Itoa(stack.port),
		names:    names,
		settings: settings,
	}
	stack.serving.Add(2)
	go func() {
		defer stack.serving.Done()
		stack.server.Serve(tlsListener)
	}()
	go func() {
		defer stack.serving.Done()
		stack.proxy.serve(stackCtx, proxyListener)
	}()
	return stack, nil
}

// The origin of a fixture name at the TLS port.
func (self *pagestack) origin(name string) string {
	return fmt.Sprintf("https://%s.%s:%d", name, self.settings.domain, self.port)
}

// The fixture page at the listed page origin.
func (self *pagestack) pageUrl() string {
	return self.origin("ur") + "/fixture-page.html"
}

// Every name the certificate holds and the proxy tunnels: each fixture name under the domain, and localhost.
func (self *pagestack) names() []string {
	names := []string{}
	for _, name := range append(append(append([]string{}, pagestackPageNames...), "sidecar"), pagestackServiceNames...) {
		names = append(names, name+"."+self.settings.domain)
	}
	return append(names, "localhost")
}

// Stops the listeners, waits for requests in flight up to the settings' bound, and ends the fixture and the Net.
// Safe to call again.
func (self *pagestack) close() error {
	self.closeOnce.Do(func() {
		if self.proxyListener != nil {
			self.proxyListener.Close()
		}
		if self.server != nil {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), self.settings.shutdownTimeout)
			self.closeErr = self.server.Shutdown(shutdownCtx)
			shutdownCancel()
		}
		self.cancel()
		self.serving.Wait()
		if self.fixture != nil {
			self.fixture.close()
		}
		if self.world != nil {
			self.world.Close()
		}
	})
	return self.closeErr
}

// A self-signed certificate for names and 127.0.0.1, made now and good for the settings' lifetime.
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
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// Routes each request by its Host (the file's comment).
type pagestackHandler struct {
	settings   *pagestackSettings
	api        http.Handler
	evs        http.Handler
	gkm        http.Handler
	fixture    *pagestackFixture
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
		self.serveService(writer, request, self.api)
	case "evs." + domain:
		self.serveService(writer, request, self.evs)
	case "gkm." + domain:
		self.serveService(writer, request, self.gkm)
	case "127.0.0.1":
		self.serveHarness(writer, request)
	default:
		http.Error(writer, "no such fixture host", http.StatusMisdirectedRequest)
	}
}

// What the harness itself reads: /healthz, and the fixture's ids.
func (self *pagestackHandler) serveHarness(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method", http.StatusMethodNotAllowed)
		return
	}
	switch request.URL.Path {
	case "/healthz":
		writer.WriteHeader(http.StatusOK)
		io.WriteString(writer, "ok\n")
	case "/fixture.json":
		if self.fixture == nil {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(writer).Encode(self.fixture.view())
	default:
		http.NotFound(writer, request)
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

// A service, with CORS for the key origin alone, as the lb's cors_origins give it to api, auth, evs and gkm
// (SDK-M4-06): a preflight from the key origin answers 204 with the lb's lists, and an answer to it carries its
// origin; any other origin, or none, gets no CORS header, so a browser refuses that page the answer.
func (self *pagestackHandler) serveService(writer http.ResponseWriter, request *http.Request, service http.Handler) {
	if request.Header.Get("Origin") == self.keyOrigin {
		header := writer.Header()
		header.Set("Access-Control-Allow-Origin", self.keyOrigin)
		header.Set("Vary", "Origin")
		header.Set("Access-Control-Allow-Methods", pagestackCorsAllowMethods)
		header.Set("Access-Control-Allow-Headers", pagestackCorsAllowHeaders)
		header.Set("Access-Control-Expose-Headers", pagestackCorsExposeHeaders)
		if request.Method == http.MethodOptions {
			header.Set("Access-Control-Max-Age", strconv.FormatInt(int64(self.settings.corsMaxAge/time.Second), 10))
			writer.WriteHeader(http.StatusNoContent)
			return
		}
	}
	service.ServeHTTP(writer, request)
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
