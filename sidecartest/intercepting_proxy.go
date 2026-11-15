// CC4's TLS-intercepting fixture proxy (TEST-M4-02; §22.7's CC4, R-TEST-3, D-TEST-5, I-3; §18.9, §2.4's sandbox
// row): "a TLS-intercepting fixture proxy with its own CA, which ur status reports". It stands in for a cloud
// sandbox's proxy, which adds secrets at its edge and so reads what the agent sends over HTTPS: an HTTP CONNECT proxy
// that terminates the client's TLS with a leaf its own CA signs for the CONNECT's host, re-originates TLS to the real
// target, relays both ways, and hands every decrypted byte, each direction of each flow, to a PrivacyCapture as a
// source under PrivacyClassInterceptingProxy.
//
// The proxy sits inside TB1 by design (§2.4), so what a test asserts of it is about content, not tokens: a canary
// sealed in Required mode stays out of its capture while a plaintext body it relays is caught, and a bearer token it
// sees is declared, listed by BearerTokens as §2.4's row lets it see, rather than hidden from the capture. ur status's
// interception report names its CA, an issuer outside the host table's pins.
//
// Its CA is made per proxy and lives only in memory, and a test names only .example hosts. A proxy serves in-process
// connections (Dial, Serve), which every leg runs, and listens on loopback for a client that dials a proxy by
// address (Listen), as ur's HTTPS_PROXY does. InterceptingOrigin is the real target for a fixture: an in-process HTTPS
// origin with a CA of its own. Safe for concurrent use.

package sidecartest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// What the proxy decrypted, each direction of each flow (§22.7's CC4).
var PrivacyClassInterceptingProxy = RegisterPrivacyClass("CC4/intercepting-proxy")

var errInterceptingProxy = errors.New("intercepting proxy")

type InterceptingProxySettings struct {
	// Dials the target a CONNECT names: net.Dialer's when nil. A fixture maps its .example hosts to its origins here.
	Dial func(ctx context.Context, network string, address string) (net.Conn, error)
	// What the proxy's own TLS to a target trusts: the system's roots when nil.
	TargetRoots *x509.CertPool
	// The CA's common name, which ur status prints as the intercepted chain's issuer.
	CaName string
	// How long the CA and each leaf are valid from an hour before the proxy starts.
	CertificateLifetime time.Duration
	// Where Listen listens: a loopback port the kernel picks.
	ListenAddress string
	// The most a CONNECT request with its headers may hold.
	RequestByteCount int
	// The most of one direction of one flow the capture holds. A flow that would pass it is cut, so no byte crosses
	// the proxy uncaptured.
	CaptureByteCount int
	// How long a flow's CONNECT and its two handshakes may take, in real time: a guard that ends a stuck flow.
	HandshakeTimeout time.Duration
	// The size of one relay read.
	ReadByteCount int
}

func DefaultInterceptingProxySettings() *InterceptingProxySettings {
	return &InterceptingProxySettings{
		CaName:              "synthetic intercepting proxy",
		CertificateLifetime: 24 * time.Hour,
		ListenAddress:       "127.0.0.1:0",
		RequestByteCount:    16 * 1024,
		CaptureByteCount:    16 * 1024 * 1024,
		HandshakeTimeout:    10 * time.Second,
		ReadByteCount:       32 * 1024,
	}
}

// One CONNECT the proxy intercepted.
type InterceptedFlow struct {
	// From 1, in arrival order.
	Index int
	// host:port, as the CONNECT named it.
	Target string
	// What the client sent the target, decrypted.
	ToTarget []byte
	// What the target answered, decrypted.
	FromTarget []byte
	// Why the flow ended early, if it did: a handshake failed, a capture's bound was reached.
	Failure string
}

type InterceptingProxy struct {
	capture  *PrivacyCapture
	settings *InterceptingProxySettings
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	notAfter time.Time
	// when its certificates start being valid
	notBefore time.Time

	stateLock sync.Mutex
	leaves    map[string]*tls.Certificate
	flows     []*InterceptedFlow
	conns     map[net.Conn]bool
	listener  net.Listener
	closed    bool

	waitGroup sync.WaitGroup
}

// A proxy with a fresh CA, its decrypted bytes a source of capture's. settings nil takes the defaults.
func NewInterceptingProxy(capture *PrivacyCapture, settings *InterceptingProxySettings) (*InterceptingProxy, error) {
	if settings == nil {
		settings = DefaultInterceptingProxySettings()
	}
	notBefore := time.Now().Add(-time.Hour)
	ca, caKey, err := newFixtureCa(settings.CaName, notBefore, notBefore.Add(settings.CertificateLifetime))
	if err != nil {
		return nil, err
	}
	self := &InterceptingProxy{
		capture:   capture,
		settings:  settings,
		ca:        ca,
		caKey:     caKey,
		notBefore: notBefore,
		notAfter:  notBefore.Add(settings.CertificateLifetime),
		leaves:    map[string]*tls.Certificate{},
		conns:     map[net.Conn]bool{},
	}
	if capture != nil {
		capture.AddSource(self.privacyItems)
	}
	return self, nil
}

// The proxy's CA, which a sandbox installs among its system's roots.
func (self *InterceptingProxy) Certificate() *x509.Certificate {
	return self.ca
}

// Listens on loopback for clients that dial the proxy by address, and returns its http:// URL, as HTTPS_PROXY names
// it. Once only.
func (self *InterceptingProxy) Listen() (string, error) {
	listener, err := net.Listen("tcp", self.settings.ListenAddress)
	if err != nil {
		return "", err
	}
	accepted := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed || self.listener != nil {
			return false
		}
		self.listener = listener
		// counted under the lock, so a Close that has begun waiting never misses it
		self.waitGroup.Add(1)
		return true
	}()
	if !accepted {
		listener.Close()
		return "", fmt.Errorf("%w: closed, or listening already", errInterceptingProxy)
	}
	go func() {
		defer self.waitGroup.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			self.Serve(conn)
		}
	}()
	return "http://" + listener.Addr().String(), nil
}

// An in-process connection to the proxy, which serves its other end: what a client whose dial the test controls
// takes in place of a TCP connection to the proxy's address.
func (self *InterceptingProxy) Dial(ctx context.Context) (net.Conn, error) {
	client, server := NewMxPipe(interceptingPipeAddr("client"), interceptingPipeAddr("proxy"))
	if !self.Serve(server) {
		client.Close()
		return nil, fmt.Errorf("%w: closed", errInterceptingProxy)
	}
	return client, nil
}

// Serves conn as one client of the proxy, on a goroutine of its own, and closes it when done; false, with conn
// closed, once the proxy is closed.
func (self *InterceptingProxy) Serve(conn net.Conn) bool {
	accepted := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.conns[conn] = true
		self.waitGroup.Add(1)
		return true
	}()
	if !accepted {
		conn.Close()
		return false
	}
	go func() {
		defer self.waitGroup.Done()
		defer func() {
			conn.Close()
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.conns, conn)
		}()
		self.serveConnect(conn)
	}()
	return true
}

// Every flow so far, in order.
func (self *InterceptingProxy) Flows() []*InterceptedFlow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	flows := make([]*InterceptedFlow, 0, len(self.flows))
	for _, flow := range self.flows {
		kept := *flow
		kept.ToTarget = bytes.Clone(flow.ToTarget)
		kept.FromTarget = bytes.Clone(flow.FromTarget)
		flows = append(flows, &kept)
	}
	return flows
}

// Every bearer token a client sent through the proxy, in order, each once: what §2.4's sandbox row says such a proxy
// may see, declared here and kept in the capture, never hidden from it.
func (self *InterceptingProxy) BearerTokens() []string {
	tokens := []string{}
	for _, flow := range self.Flows() {
		for _, line := range strings.Split(string(flow.ToTarget), "\r\n") {
			name, value, ok := strings.Cut(line, ":")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), "Authorization") {
				continue
			}
			scheme, token, ok := strings.Cut(strings.TrimSpace(value), " ")
			token = strings.TrimSpace(token)
			if ok && strings.EqualFold(scheme, "Bearer") && token != "" && !slices.Contains(tokens, token) {
				tokens = append(tokens, token)
			}
		}
	}
	return tokens
}

// Closes the listener and every connection, and waits for every flow to end. Idempotent.
func (self *InterceptingProxy) Close() {
	var listener net.Listener
	var conns []net.Conn
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return
		}
		self.closed = true
		listener = self.listener
		for conn := range self.conns {
			conns = append(conns, conn)
		}
	}()
	if listener != nil {
		listener.Close()
	}
	for _, conn := range conns {
		conn.Close()
	}
	self.waitGroup.Wait()
}

// The capture's items: each direction of each flow, as decrypted.
func (self *InterceptingProxy) privacyItems() []*PrivacyItem {
	items := []*PrivacyItem{}
	for _, flow := range self.Flows() {
		items = append(items,
			&PrivacyItem{Class: PrivacyClassInterceptingProxy, Name: fmt.Sprintf("intercepting proxy flow %d to %s, as the client sent it", flow.Index, flow.Target), Body: flow.ToTarget},
			&PrivacyItem{Class: PrivacyClassInterceptingProxy, Name: fmt.Sprintf("intercepting proxy flow %d from %s, as the target answered", flow.Index, flow.Target), Body: flow.FromTarget},
		)
	}
	return items
}

// One client: its CONNECT, the two handshakes, then the relay, every decrypted byte kept.
func (self *InterceptingProxy) serveConnect(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(self.settings.HandshakeTimeout))
	reader := bufio.NewReader(io.LimitReader(conn, int64(self.settings.RequestByteCount)))
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	if request.Method != http.MethodConnect {
		io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	target := request.RequestURI
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	flow := func() *InterceptedFlow {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		flow := &InterceptedFlow{Index: len(self.flows) + 1, Target: target}
		self.flows = append(self.flows, flow)
		return flow
	}()
	fail := func(failure string) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if flow.Failure == "" {
			flow.Failure = failure
		}
	}

	dial := self.settings.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	handshakeCtx, cancel := context.WithTimeout(context.Background(), self.settings.HandshakeTimeout)
	defer cancel()
	upstream, err := dial(handshakeCtx, "tcp", target)
	if err != nil {
		fail("the target did not answer: " + err.Error())
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	// what the client pipelined behind its CONNECT is the start of its handshake
	clientSide := tls.Server(&interceptingBufferedConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(interceptingBuffered(reader)), conn)}, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return self.leaf(host)
		},
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := clientSide.HandshakeContext(handshakeCtx); err != nil {
		fail("the client refused the proxy's certificate: " + err.Error())
		return
	}
	targetSide := tls.Client(upstream, &tls.Config{
		ServerName: host,
		RootCAs:    self.settings.TargetRoots,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	upstream.SetDeadline(time.Now().Add(self.settings.HandshakeTimeout))
	if err := targetSide.HandshakeContext(handshakeCtx); err != nil {
		fail("the target's handshake failed: " + err.Error())
		return
	}
	conn.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	var relays sync.WaitGroup
	relay := func(from net.Conn, to net.Conn, toTarget bool) {
		defer relays.Done()
		// either side ending ends the flow
		defer from.Close()
		defer to.Close()
		buffer := make([]byte, self.settings.ReadByteCount)
		for {
			n, err := from.Read(buffer)
			if 0 < n {
				if !self.keep(flow, toTarget, buffer[:n]) {
					fail(fmt.Sprintf("a direction passed the capture's %d bytes, so the flow was cut", self.settings.CaptureByteCount))
					return
				}
				if _, err := to.Write(buffer[:n]); err != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	relays.Add(2)
	go relay(clientSide, targetSide, true)
	go relay(targetSide, clientSide, false)
	relays.Wait()
}

// Keeps data in flow's direction, or false when that would pass the capture's bound.
func (self *InterceptingProxy) keep(flow *InterceptedFlow, toTarget bool, data []byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kept := &flow.FromTarget
	if toTarget {
		kept = &flow.ToTarget
	}
	if self.settings.CaptureByteCount < len(*kept)+len(data) {
		return false
	}
	*kept = append(*kept, data...)
	return true
}

// host's leaf, signed by the proxy's CA, made once.
func (self *InterceptingProxy) leaf(host string) (*tls.Certificate, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if leaf, ok := self.leaves[host]; ok {
		return leaf, nil
	}
	leaf, err := newFixtureLeaf(host, self.ca, self.caKey, self.notBefore, self.notAfter)
	if err != nil {
		return nil, err
	}
	self.leaves[host] = leaf
	return leaf, nil
}

// What a bufio.Reader holds unread.
func interceptingBuffered(reader *bufio.Reader) []byte {
	buffered, _ := reader.Peek(reader.Buffered())
	return bytes.Clone(buffered)
}

// A connection whose reads start with what was read ahead of it.
type interceptingBufferedConn struct {
	net.Conn
	reader io.Reader
}

func (self *interceptingBufferedConn) Read(buffer []byte) (int, error) {
	return self.reader.Read(buffer)
}

// The address an in-process end reads as: a name, never a host's address.
type interceptingPipeAddr string

func (self interceptingPipeAddr) Network() string { return "pipe" }
func (self interceptingPipeAddr) String() string  { return string(self) }

// A self-signed CA with its key, ECDSA P-256, valid from notBefore to notAfter.
func newFixtureCa(name string, notBefore time.Time, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return certificate, key, nil
}

// A leaf for host, ECDSA P-256, signed by ca, with the chain a server presents.
func newFixtureLeaf(host string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, notBefore time.Time, notAfter time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

type InterceptingOriginSettings struct {
	// The CA's common name: the issuer an un-intercepted chain ends at.
	CaName string
	// How long the CA and each leaf are valid from an hour before the origin starts.
	CertificateLifetime time.Duration
	// The answer to every request, which the proxy captures as the target's.
	Answer []byte
	// The most a request may hold, its body included.
	RequestByteCount int64
}

func DefaultInterceptingOriginSettings() *InterceptingOriginSettings {
	return &InterceptingOriginSettings{
		CaName:              "synthetic real issuer",
		CertificateLifetime: 24 * time.Hour,
		Answer:              []byte("ok"),
		RequestByteCount:    4 * 1024 * 1024,
	}
}

// A fixture's real target: an in-process HTTPS origin for the hosts it serves, with a CA of its own, answering every
// request with its settings' Answer and keeping each body it took.
type InterceptingOrigin struct {
	settings *InterceptingOriginSettings
	hosts    []string
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	notAfter time.Time
	// when its certificates start being valid
	notBefore time.Time

	stateLock sync.Mutex
	leaves    map[string]*tls.Certificate
	bodies    [][]byte
	conns     map[net.Conn]bool
	closed    bool

	waitGroup sync.WaitGroup
}

// An origin serving hosts. settings nil takes the defaults.
func NewInterceptingOrigin(settings *InterceptingOriginSettings, hosts ...string) (*InterceptingOrigin, error) {
	if settings == nil {
		settings = DefaultInterceptingOriginSettings()
	}
	notBefore := time.Now().Add(-time.Hour)
	ca, caKey, err := newFixtureCa(settings.CaName, notBefore, notBefore.Add(settings.CertificateLifetime))
	if err != nil {
		return nil, err
	}
	return &InterceptingOrigin{
		settings:  settings,
		hosts:     slices.Clone(hosts),
		ca:        ca,
		caKey:     caKey,
		notBefore: notBefore,
		notAfter:  notBefore.Add(settings.CertificateLifetime),
		leaves:    map[string]*tls.Certificate{},
		conns:     map[net.Conn]bool{},
	}, nil
}

// The roots a client of the origin trusts: its CA alone.
func (self *InterceptingOrigin) Roots() *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(self.ca)
	return roots
}

// The origin's CA.
func (self *InterceptingOrigin) Certificate() *x509.Certificate {
	return self.ca
}

// Every request body the origin took, in order.
func (self *InterceptingOrigin) Bodies() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	bodies := [][]byte{}
	for _, body := range self.bodies {
		bodies = append(bodies, bytes.Clone(body))
	}
	return bodies
}

// A proxy's Dial: an in-process connection to the origin for a host it serves, port 443.
func (self *InterceptingOrigin) Dial(ctx context.Context, network string, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" || !slices.Contains(self.hosts, host) {
		return nil, fmt.Errorf("%w: the origin serves no %s", errInterceptingProxy, address)
	}
	client, server := NewMxPipe(interceptingPipeAddr("proxy"), interceptingPipeAddr(address))
	accepted := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.conns[server] = true
		self.waitGroup.Add(1)
		return true
	}()
	if !accepted {
		client.Close()
		server.Close()
		return nil, fmt.Errorf("%w: the origin is closed", errInterceptingProxy)
	}
	go func() {
		defer self.waitGroup.Done()
		defer func() {
			server.Close()
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.conns, server)
		}()
		self.serve(server)
	}()
	return client, nil
}

// One connection: TLS under the host's leaf, then requests, each answered, until the client ends it.
func (self *InterceptingOrigin) serve(conn net.Conn) {
	server := tls.Server(conn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if !slices.Contains(self.hosts, hello.ServerName) {
				return nil, fmt.Errorf("%w: the origin serves no %q", errInterceptingProxy, hello.ServerName)
			}
			return self.leaf(hello.ServerName)
		},
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	reader := bufio.NewReader(server)
	for {
		request, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, self.settings.RequestByteCount))
		if err != nil {
			return
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.bodies = append(self.bodies, body)
		}()
		answer := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n", len(self.settings.Answer))
		if _, err := io.WriteString(server, answer); err != nil {
			return
		}
		if _, err := server.Write(self.settings.Answer); err != nil {
			return
		}
	}
}

func (self *InterceptingOrigin) leaf(host string) (*tls.Certificate, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if leaf, ok := self.leaves[host]; ok {
		return leaf, nil
	}
	leaf, err := newFixtureLeaf(host, self.ca, self.caKey, self.notBefore, self.notAfter)
	if err != nil {
		return nil, err
	}
	self.leaves[host] = leaf
	return leaf, nil
}

// Ends every connection and waits for them. Idempotent.
func (self *InterceptingOrigin) Close() {
	var conns []net.Conn
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		for conn := range self.conns {
			conns = append(conns, conn)
		}
	}()
	for _, conn := range conns {
		conn.Close()
	}
	self.waitGroup.Wait()
}

// An HTTPS request through proxy, as an agent in a sandbox sends one: a CONNECT over conn, TLS to host trusting
// roots (the sandbox's, which hold the proxy's CA), then method and path with the bearer token, if any, and body.
// Returns the status and the answer's body. conn is the client's connection to the proxy, which this closes.
func InterceptingProxyRequest(ctx context.Context, conn net.Conn, roots *x509.CertPool, host string, method string, path string, bearer string, body []byte) (int, []byte, error) {
	defer conn.Close()
	// an in-process connection keeps no deadline of its own, so ctx's end closes it
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host); err != nil {
		return 0, nil, err
	}
	reader := bufio.NewReader(conn)
	connected, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return 0, nil, err
	}
	if connected.StatusCode != http.StatusOK {
		return connected.StatusCode, nil, fmt.Errorf("%w: CONNECT answered %d", errInterceptingProxy, connected.StatusCode)
	}
	client := tls.Client(&interceptingBufferedConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(interceptingBuffered(reader)), conn)}, &tls.Config{
		ServerName: host,
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := client.HandshakeContext(ctx); err != nil {
		return 0, nil, err
	}
	request := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n", method, path, host, len(body))
	if bearer != "" {
		request += "Authorization: Bearer " + bearer + "\r\n"
	}
	if _, err := io.WriteString(client, request+"\r\n"); err != nil {
		return 0, nil, err
	}
	if _, err := client.Write(body); err != nil {
		return 0, nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: method})
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(response.Body)
	return response.StatusCode, answer, err
}
