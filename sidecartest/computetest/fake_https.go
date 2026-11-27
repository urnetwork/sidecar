// The loopback HTTPS server computetest's network fakes share (FakeCalendarServer, FakeParallel, FakeBase): one
// listener on 127.0.0.1 that serves named hosts, each a synthetic .example name, under a test certificate authority
// whose keys come from the fake's seed. A client reaches a host through the fake's dialer (DialContext), which maps
// each name it serves, on any port, to the listener, so a URL keeps the name and port 443 a real one would have and a
// client's own checks of scheme and port run as they would; the authority's pool (RootCAs) is the only one that
// trusts these certificates, and no production build trusts it.
//
// Each request carries its connection's number (fakeConnectionId), counted from 1 in the order the listener accepted
// them, so a fake can record which requests shared a connection. HTTP/1.1 only, so a dropped answer closes its
// connection.
//
// Safe for concurrent use.

package computetest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// A dial or a request named a host the fake does not serve.
	ErrFakeHostUnserved = errors.New("computetest: the fake serves no such host")
)

// The connection number a request came on, from its context.
type fakeConnectionIdKey struct{}

// The connection number of a request's connection, or 0 for a request the shared server did not accept.
func fakeConnectionId(ctx context.Context) uint64 {
	connectionId, _ := ctx.Value(fakeConnectionIdKey{}).(uint64)
	return connectionId
}

// A test certificate authority: an ECDSA P-256 key drawn from the seed, a self-signed root, and leaves for named
// hosts issued as they are asked for and kept.
type fakeTlsAuthority struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	leafKey  *ecdsa.PrivateKey
	rootPool *x509.CertPool

	stateLock  sync.Mutex
	hostLeaves map[string]*tls.Certificate
}

// A P-256 key from seed and label: the first scalar of the label's stream that P-256 takes.
func fakeP256Key(seed string, label string) (*ecdsa.PrivateKey, error) {
	stream := newFakeStream(seed, "p256 "+label)
	scalar := make([]byte, 32)
	for range 64 {
		if _, err := io.ReadFull(stream, scalar); err != nil {
			return nil, err
		}
		if key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("computetest: no P-256 scalar in the stream for %q", label)
}

// Valid from 2000 to 2100, so a client checking against a fake clock or real time accepts it alike.
func newFakeTlsAuthority(seed string) (*fakeTlsAuthority, error) {
	rootKey, err := fakeP256Key(seed, "tls root")
	if err != nil {
		return nil, err
	}
	leafKey, err := fakeP256Key(seed, "tls leaf")
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "computetest test authority " + seed},
		NotBefore:             time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(newFakeStream(seed, "tls root signature"), template, template, rootKey.Public(), rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)
	return &fakeTlsAuthority{
		root:       root,
		rootKey:    rootKey,
		leafKey:    leafKey,
		rootPool:   rootPool,
		hostLeaves: map[string]*tls.Certificate{},
	}, nil
}

// A leaf for host, issued once and kept.
func (self *fakeTlsAuthority) leaf(host string) (*tls.Certificate, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if leaf, ok := self.hostLeaves[host]; ok {
		return leaf, nil
	}
	serialHash := sha256.Sum256([]byte("computetest tls leaf " + host))
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetUint64(binary.BigEndian.Uint64(serialHash[:8]) >> 1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(newFakeStream(host, "tls leaf signature"), template, self.root, self.leafKey.Public(), self.rootKey)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der, self.root.Raw}, PrivateKey: self.leafKey}
	self.hostLeaves[host] = leaf
	return leaf, nil
}

// One listener serving the hosts registered on it, each by its handler.
type fakeHttpsServer struct {
	authority *fakeTlsAuthority
	server    *httptest.Server

	connectionCount atomic.Uint64

	stateLock    sync.Mutex
	hostHandlers map[string]http.Handler
}

// Started at once; Close ends it.
func newFakeHttpsServer(seed string) (*fakeHttpsServer, error) {
	authority, err := newFakeTlsAuthority(seed)
	if err != nil {
		return nil, err
	}
	self := &fakeHttpsServer{
		authority:    authority,
		hostHandlers: map[string]http.Handler{},
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(self.serveHttp))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		return context.WithValue(ctx, fakeConnectionIdKey{}, self.connectionCount.Add(1))
	}
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := strings.ToLower(hello.ServerName)
			if self.handler(host) == nil {
				return nil, fmt.Errorf("%w: %q", ErrFakeHostUnserved, host)
			}
			return authority.leaf(host)
		},
	}
	server.StartTLS()
	self.server = server
	return self, nil
}

// Serves host by handler from now on, replacing any handler it had.
func (self *fakeHttpsServer) handle(host string, handler http.Handler) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.hostHandlers[strings.ToLower(host)] = handler
}

func (self *fakeHttpsServer) handler(host string) http.Handler {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.hostHandlers[strings.ToLower(host)]
}

// The hosts served, sorted.
func (self *fakeHttpsServer) hosts() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hosts := make([]string, 0, len(self.hostHandlers))
	for host := range self.hostHandlers {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	return hosts
}

func (self *fakeHttpsServer) serveHttp(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	handler := self.handler(host)
	if handler == nil {
		http.Error(w, fmt.Sprintf("%v: %q", ErrFakeHostUnserved, host), http.StatusMisdirectedRequest)
		return
	}
	handler.ServeHTTP(w, r)
}

// Dials the listener for a host it serves, on any port; any other address fails with ErrFakeHostUnserved, so a client
// built on it reaches nothing else.
func (self *fakeHttpsServer) dialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if self.handler(host) == nil {
		return nil, fmt.Errorf("%w: %q", ErrFakeHostUnserved, host)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", self.server.Listener.Addr().String())
}

// A client that reaches the hosts served and trusts the test authority alone, with no cookie jar, following no
// redirect: what it receives is what the fake answered.
func (self *fakeHttpsServer) httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:       self.dialContext,
			TLSClientConfig:   &tls.Config{RootCAs: self.authority.rootPool, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (self *fakeHttpsServer) close() {
	self.server.Close()
}
