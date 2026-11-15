package sidecartest

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// How long one request through the proxy may take before it fails: a guard, never the proof.
const interceptingTestTimeout = 10 * time.Second

// The sandbox's fixture: an origin serving the cloud agent's hosts, a proxy in front of it whose decrypted bytes are
// capture's, and the roots the sandbox's system trusts, its proxy's CA installed among them.
type interceptingSandbox struct {
	origin *InterceptingOrigin
	proxy  *InterceptingProxy
	roots  *x509.CertPool
}

func newInterceptingSandbox(t testing.TB, capture *PrivacyCapture, settings *InterceptingProxySettings) *interceptingSandbox {
	t.Helper()
	origin, err := NewInterceptingOrigin(nil, "api.cloudagent.example", "evs.cloudagent.example")
	if err != nil {
		t.Fatal(err)
	}
	if settings == nil {
		settings = DefaultInterceptingProxySettings()
	}
	settings.Dial = origin.Dial
	settings.TargetRoots = origin.Roots()
	proxy, err := NewInterceptingProxy(capture, settings)
	if err != nil {
		origin.Close()
		t.Fatal(err)
	}
	roots := origin.Roots()
	roots.AddCert(proxy.Certificate())
	return &interceptingSandbox{origin: origin, proxy: proxy, roots: roots}
}

func (self *interceptingSandbox) close() {
	self.proxy.Close()
	self.origin.Close()
}

// One request through the proxy, in process, failing t if it does not complete with 200.
func (self *interceptingSandbox) request(t testing.TB, host string, method string, path string, bearer string, body []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), interceptingTestTimeout)
	defer cancel()
	conn, err := self.proxy.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	status, answer, err := InterceptingProxyRequest(ctx, conn, self.roots, host, method, path, bearer, body)
	if err != nil || status != http.StatusOK || string(answer) != "ok" {
		t.Fatalf("%s https://%s%s through the proxy: %d %q %v", method, host, path, status, answer, err)
	}
}

// Content as Required mode carries it: sealed under a key the proxy never holds.
func interceptingSeal(t *testing.T, content []byte) []byte {
	t.Helper()
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	rand.Read(key)
	rand.Read(nonce)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return append(nonce, aead.Seal(nil, nonce, content, nil)...)
}

// A cloud agent's flow through the proxy: its sealed content and its status call cross it, the target takes what the
// agent sent, no canary is in the proxy's capture while the capture holds the decrypted flows, the bearer token is
// declared as seen and still in the capture, and a plaintext body planted in the same flow is caught there.
func TestInterceptingProxyCapturesWhatItDecrypts(t *testing.T) {
	capture := NewPrivacyCapture()
	sandbox := newInterceptingSandbox(t, capture, nil)
	defer sandbox.close()
	token := "synthetic-cloud-bearer-token-0001"

	sealed := interceptingSeal(t, capture.Canary("file contents"))
	sandbox.request(t, "evs.cloudagent.example", http.MethodPost, "/evs/seg", token, sealed)
	sandbox.request(t, "api.cloudagent.example", http.MethodGet, "/sidecar/status", token, nil)

	if findings := capture.Scan(); len(findings) != 0 {
		t.Fatalf("Required-mode content reached the proxy's capture: %v", findings)
	}
	if capture.ItemCount(PrivacyClassInterceptingProxy) != 4 {
		t.Fatalf("the capture holds %d proxy items, so a clean scan proves nothing", capture.ItemCount(PrivacyClassInterceptingProxy))
	}
	bodies := sandbox.origin.Bodies()
	if len(bodies) != 2 || !bytes.Equal(bodies[0], sealed) {
		t.Fatalf("the origin took %d bodies", len(bodies))
	}
	if tokens := sandbox.proxy.BearerTokens(); len(tokens) != 1 || tokens[0] != token {
		t.Fatalf("declared tokens: %v", tokens)
	}
	flows := sandbox.proxy.Flows()
	if len(flows) != 2 || flows[0].Target != "evs.cloudagent.example:443" || !bytes.Contains(flows[0].ToTarget, []byte(token)) || !bytes.Contains(flows[0].FromTarget, []byte("200 OK")) {
		t.Fatalf("the token is hidden from the capture, or the flow is not what crossed: %+v", flows)
	}

	planted := capture.CanaryText("plaintext body")
	sandbox.request(t, "api.cloudagent.example", http.MethodPost, "/sidecar/notes", token, []byte("note="+planted))
	caught := false
	for _, finding := range capture.Scan() {
		if finding.Needle == "plaintext body" && finding.Class == PrivacyClassInterceptingProxy {
			caught = true
		} else {
			t.Errorf("an unexpected finding: %v", finding)
		}
	}
	if !caught {
		t.Fatal("a plaintext body crossed the proxy and its capture did not catch it")
	}
}

// The proxy terminates TLS with its own CA: a client that trusts only the target's issuer refuses its leaf, and the
// flow says why, having carried nothing.
func TestInterceptingProxyTerminatesTlsWithItsOwnCa(t *testing.T) {
	sandbox := newInterceptingSandbox(t, NewPrivacyCapture(), nil)
	defer sandbox.close()
	ctx, cancel := context.WithTimeout(context.Background(), interceptingTestTimeout)
	defer cancel()
	conn, err := sandbox.proxy.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = InterceptingProxyRequest(ctx, conn, sandbox.origin.Roots(), "api.cloudagent.example", http.MethodGet, "/", "", nil)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("a client that trusts only the target's issuer took the proxy's leaf: %v", err)
	}
	sandbox.proxy.Close()
	flows := sandbox.proxy.Flows()
	if len(flows) != 1 || flows[0].Failure == "" || 0 < len(flows[0].ToTarget) || 0 < len(sandbox.origin.Bodies()) {
		t.Fatalf("flows: %+v", flows)
	}
	if sandbox.proxy.Certificate().Subject.CommonName != "synthetic intercepting proxy" || !sandbox.proxy.Certificate().IsCA {
		t.Fatalf("the proxy's CA: %v", sandbox.proxy.Certificate().Subject)
	}
}

// What is no CONNECT is refused, and a flow whose direction would pass the capture's bound is cut, so no byte crosses
// the proxy uncaptured.
func TestInterceptingProxyRefusesWhatItCannotCapture(t *testing.T) {
	settings := DefaultInterceptingProxySettings()
	settings.CaptureByteCount = 512
	sandbox := newInterceptingSandbox(t, NewPrivacyCapture(), settings)
	defer sandbox.close()
	ctx, cancel := context.WithTimeout(context.Background(), interceptingTestTimeout)
	defer cancel()

	conn, err := sandbox.proxy.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(interceptingTestTimeout))
	if _, err := conn.Write([]byte("GET http://api.cloudagent.example/ HTTP/1.1\r\nHost: api.cloudagent.example\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, 64)
	n, _ := conn.Read(answer)
	conn.Close()
	if !strings.HasPrefix(string(answer[:n]), "HTTP/1.1 405") {
		t.Fatalf("a plain GET was answered %q", answer[:n])
	}

	conn, err = sandbox.proxy.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := InterceptingProxyRequest(ctx, conn, sandbox.roots, "api.cloudagent.example", http.MethodPost, "/big", "", bytes.Repeat([]byte("x"), 4096)); err == nil {
		t.Fatal("a flow past the capture's bound completed")
	}
	sandbox.proxy.Close()
	flows := sandbox.proxy.Flows()
	if len(flows) != 1 || !strings.Contains(flows[0].Failure, "cut") || settings.CaptureByteCount < len(flows[0].ToTarget) {
		t.Fatalf("flows: %+v", flows)
	}
	for _, body := range sandbox.origin.Bodies() {
		if 4096 <= len(body) {
			t.Fatal("the origin took a body the capture never held whole")
		}
	}
}

// A client that dials the proxy by address, as ur's HTTPS_PROXY does, reaches it on loopback.
func TestInterceptingProxyListensForAClientThatDialsByAddress(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("not run: js/wasm has no loopback listener")
	}
	sandbox := newInterceptingSandbox(t, NewPrivacyCapture(), nil)
	defer sandbox.close()
	url, err := sandbox.proxy.Listen()
	if err != nil {
		t.Fatal(err)
	}
	address, ok := strings.CutPrefix(url, "http://")
	if !ok {
		t.Fatalf("the proxy's url %q", url)
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), interceptingTestTimeout)
	defer cancel()
	status, answer, err := InterceptingProxyRequest(ctx, conn, sandbox.roots, "api.cloudagent.example", http.MethodGet, "/sidecar/status", "", nil)
	if err != nil || status != http.StatusOK || string(answer) != "ok" {
		t.Fatalf("%d %q %v", status, answer, err)
	}
}

// The proxy's leak for TestEachCaptureClassNamesItsLeak: a plaintext body through it, on net's capture.
func leakThroughInterceptingProxy(t *testing.T, net *Net, canary string) {
	sandbox := newInterceptingSandbox(t, net.Capture(), nil)
	defer sandbox.close()
	sandbox.request(t, "api.cloudagent.example", http.MethodPost, "/sidecar/notes", "", []byte(canary))
}
