package main

// ur status's host report on fixtures: a list of .example hosts, a tls server on the loopback that certifies each by
// a fixture CA, the probe's dial mapped to that server, and for rung 2 a fake CONNECT proxy that maps the same way.
// No test reads the embedded table's hosts or leaves the loopback.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// A fixture CA and its key.
type testHostCa struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

// A CA named name, valid for the test's hour.
func newTestHostCa(t *testing.T, name string) *testHostCa {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testHostCa{certificate: certificate, key: key}
}

// The base64 SHA-256 of the CA's SPKI, as the host table pins an issuer.
func (self *testHostCa) spkiDigest() string {
	digest := sha256.Sum256(self.certificate.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(digest[:])
}

// A leaf for host, with the CA's certificate after it.
func (self *testHostCa) issue(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, self.certificate, &key.PublicKey, self.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, self.certificate.Raw}, PrivateKey: key}
}

// The hosts of one test: a tls server certifying each host by the CA it was given, the hosts the probe's dial
// reaches, and every dial it was asked for.
type testHostWorld struct {
	t        *testing.T
	listener net.Listener
	roots    *x509.CertPool

	stateLock    sync.Mutex
	certificates map[string]*tls.Certificate
	reachable    map[string]bool
	dials        map[string]int
}

// Starts the server; roots is what the probe trusts, as a system's store would.
func newTestHostWorld(t *testing.T, roots ...*testHostCa) *testHostWorld {
	t.Helper()
	pool := x509.NewCertPool()
	for _, ca := range roots {
		pool.AddCert(ca.certificate)
	}
	self := &testHostWorld{
		t:            t,
		roots:        pool,
		certificates: map[string]*tls.Certificate{},
		reachable:    map[string]bool{},
		dials:        map[string]int{},
	}
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			certificate, ok := self.certificates[hello.ServerName]
			if !ok {
				return nil, errors.New("no such host")
			}
			return certificate, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	self.listener = listener
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(urTestTimeout))
				conn.(*tls.Conn).Handshake()
				// the probe closes once its handshake is done; wait for that
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-done
	})
	return self
}

// Certifies host by ca and lets the probe's dial reach it.
func (self *testHostWorld) serve(host string, ca *testHostCa) {
	certificate := ca.issue(self.t, host)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.certificates[host] = &certificate
	self.reachable[host] = true
}

// How many dials host had.
func (self *testHostWorld) dialCount(host string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.dials[host]
}

// A prober whose dials reach the server for a served host and refuse every other, trusting the world's roots.
func (self *testHostWorld) prober() *urHostProber {
	return &urHostProber{
		connectSettings: func() *connect.ConnectSettings {
			settings := connect.DefaultConnectSettings()
			settings.DialContextSettings = &connect.DialContextSettings{
				DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
					host, _, err := net.SplitHostPort(address)
					if err != nil {
						return nil, err
					}
					reachable := func() bool {
						self.stateLock.Lock()
						defer self.stateLock.Unlock()
						self.dials[host] += 1
						return self.reachable[host]
					}()
					if !reachable {
						return nil, errors.New("synthetic: no route")
					}
					return (&net.Dialer{}).DialContext(ctx, "tcp4", self.listener.Addr().String())
				},
			}
			return settings
		},
		roots: self.roots,
	}
}

// A prober whose every dial refuses, for tests that must reach no host.
func newRefusingTestHostProber() *urHostProber {
	return &urHostProber{
		connectSettings: func() *connect.ConnectSettings {
			settings := connect.DefaultConnectSettings()
			settings.DialContextSettings = &connect.DialContextSettings{
				DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
					return nil, errors.New("no host is dialed in this test")
				},
			}
			return settings
		},
		roots: x509.NewCertPool(),
	}
}

// A list naming the fixture hosts, each of the four required, the platform, and one optional, pinning pins for
// every host when given.
func testHostList(t *testing.T, pins ...string) *sidecar.SidecarHostList {
	t.Helper()
	pinned := ""
	if 0 < len(pins) {
		pinned = `, "issuer_spki_sha256": ["` + strings.Join(pins, `", "`) + `"]`
	}
	entry := func(host string, service string, requirement string) string {
		serviceField := ""
		if service != "" {
			serviceField = fmt.Sprintf(`, "service": %q`, service)
		}
		return fmt.Sprintf(`{"host": %q, "tcp": 443, "need": "fixture"%s, "requirement": %q%s}`, host, serviceField, requirement, pinned)
	}
	data := `{"version": 1, "hosts": [` + strings.Join([]string{
		entry("api.statustest.example", "api", "required"),
		entry("auth.statustest.example", "auth", "required"),
		entry("evs.statustest.example", "evs", "required"),
		entry("gkm.statustest.example", "gkm", "required"),
		entry("connect.statustest.example", "platform", "streams"),
		entry("statustest.example", "", "optional"),
	}, ", ") + `]}`
	list, err := sidecar.ParseSidecarHostList([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// A cli whose status probes world's hosts for list, its daemon answering at socketPath.
func newTestStatusCli(t *testing.T, socketPath string, world *testHostWorld, list *sidecar.SidecarHostList) (*urCli, *strings.Builder) {
	t.Helper()
	cli, stdout, _ := newTestUrCli(socketPath)
	cli.hostList = func() (*sidecar.SidecarHostList, error) { return list, nil }
	cli.hostProber = world.prober()
	output := &strings.Builder{}
	cli.stdout = io.MultiWriter(stdout, output)
	return cli, output
}

// ur status probes every entry of the table once, alongside the daemon's state, and prints each.
func TestStatusProbesEveryEntry(t *testing.T) {
	realCa := newTestHostCa(t, "synthetic real issuer")
	world := newTestHostWorld(t, realCa)
	list := testHostList(t, realCa.spkiDigest())
	for _, entry := range list.Hosts {
		world.serve(entry.Host, realCa)
	}
	target := &testUrDaemonTarget{statusValue: sidecar.SidecarStatus{State: sidecar.SidecarStateOnline, Generation: 1}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, output := newTestStatusCli(t, daemon.socketPath, world, list)

	if code := cli.main(context.Background(), []string{"ur", "status"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, output.String())
	}
	text := output.String()
	if !strings.Contains(text, "online") || !strings.Contains(text, "rung 1, wss direct: everything") {
		t.Errorf("status:\n%s", text)
	}
	for _, entry := range list.Hosts {
		if count := world.dialCount(entry.Host); count != 1 {
			t.Errorf("%s dialed %d times", entry.Host, count)
		}
		if !strings.Contains(text, entry.Address()) {
			t.Errorf("status names no %s:\n%s", entry.Host, text)
		}
	}
	if strings.Count(text, "chain pinned") != len(list.Hosts) || strings.Contains(text, "interception") {
		t.Errorf("status:\n%s", text)
	}
}

// A chain ending at an issuer the table does not pin is reported as interception, whether or not the system trusts
// it, and blocks nothing: the status exits ok.
func TestStatusReportsInterception(t *testing.T) {
	realCa := newTestHostCa(t, "synthetic real issuer")
	interceptingCa := newTestHostCa(t, "synthetic intercepting proxy")
	unknownCa := newTestHostCa(t, "synthetic unknown issuer")
	// the system trusts the interceptor, as a cloud sandbox that installs its proxy's CA does
	world := newTestHostWorld(t, realCa, interceptingCa)
	list := testHostList(t, realCa.spkiDigest())
	for _, entry := range list.Hosts {
		world.serve(entry.Host, realCa)
	}
	world.serve("api.statustest.example", interceptingCa)
	world.serve("evs.statustest.example", unknownCa)
	target := &testUrDaemonTarget{statusValue: sidecar.SidecarStatus{State: sidecar.SidecarStateOnline, Generation: 1}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, output := newTestStatusCli(t, daemon.socketPath, world, list)

	if code := cli.main(context.Background(), []string{"ur", "status"}); code != urExitOk {
		t.Fatalf("interception blocked the status: exit %d: %s", code, output.String())
	}
	text := output.String()
	lineOf := func(host string) string {
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, host+":443") {
				return line
			}
		}
		return ""
	}
	if line := lineOf("api.statustest.example"); !strings.Contains(line, "chain intercepted") || strings.Contains(line, "not trusted") ||
		!strings.Contains(line, "synthetic intercepting proxy") {
		t.Errorf("the intercepted host: %q", line)
	}
	if line := lineOf("evs.statustest.example"); !strings.Contains(line, "chain intercepted") || !strings.Contains(line, "not trusted by this system") {
		t.Errorf("the untrusted host: %q", line)
	}
	if line := lineOf("auth.statustest.example"); !strings.Contains(line, "chain pinned") {
		t.Errorf("a pinned host: %q", line)
	}
	if !strings.Contains(text, "warning:    interception") || !strings.Contains(text, "never Required-mode traffic or repo content") ||
		!strings.Contains(text, "Nothing was blocked") {
		t.Errorf("no interception warning:\n%s", text)
	}
	// still rung 1: an intercepted chain is reached, and reported, not refused
	if !strings.Contains(text, "rung 1") {
		t.Errorf("status:\n%s", text)
	}
}

// With no issuer pinned for a host, which is every host until the release supplies them, its chain reads unpinned
// and nothing claims interception or its absence.
func TestStatusSaysUnpinnedWithoutIssuers(t *testing.T) {
	realCa := newTestHostCa(t, "synthetic real issuer")
	world := newTestHostWorld(t, realCa)
	list := testHostList(t)
	for _, entry := range list.Hosts {
		world.serve(entry.Host, realCa)
	}
	cli, output := newTestStatusCli(t, "", world, list)
	printUrHostReport(cli, cli.reportHosts(context.Background(), list))
	text := output.String()
	if strings.Count(text, "chain unpinned") != len(list.Hosts) || strings.Contains(text, "interception") || strings.Contains(text, "chain pinned") {
		t.Errorf("status:\n%s", text)
	}
}

// With the platform host out of reach and the required ones reached, the report is rung 3, and says what rung 3
// lacks: no streams, sockets or mail send.
func TestRungThreeHasNoStreams(t *testing.T) {
	realCa := newTestHostCa(t, "synthetic real issuer")
	world := newTestHostWorld(t, realCa)
	list := testHostList(t, realCa.spkiDigest())
	for _, entry := range list.Hosts {
		if entry.Requirement != sidecar.SidecarHostStreams {
			world.serve(entry.Host, realCa)
		}
	}
	cli, output := newTestStatusCli(t, "", world, list)
	report := cli.reportHosts(context.Background(), list)
	if report.Rung != urHostRungHttpsOnly {
		t.Fatalf("rung %d", report.Rung)
	}
	printUrHostReport(cli, report)
	text := output.String()
	if !strings.Contains(text, "rung 3, HTTPS only: evs, records and the long-poll; no streams, sockets or mail send") ||
		strings.Contains(text, "everything") {
		t.Errorf("status:\n%s", text)
	}
	if !strings.Contains(text, "connect.statustest.example:443") || !strings.Contains(text, "not reached") {
		t.Errorf("the platform host's line:\n%s", text)
	}
}

// A required host out of reach leaves no rung, whatever else is reached.
func TestNoRungWithoutARequiredHost(t *testing.T) {
	realCa := newTestHostCa(t, "synthetic real issuer")
	world := newTestHostWorld(t, realCa)
	list := testHostList(t, realCa.spkiDigest())
	for _, entry := range list.Hosts {
		if entry.Host != "gkm.statustest.example" {
			world.serve(entry.Host, realCa)
		}
	}
	cli, output := newTestStatusCli(t, "", world, list)
	report := cli.reportHosts(context.Background(), list)
	printUrHostReport(cli, report)
	if report.Rung != urHostRungNone || !strings.Contains(output.String(), "none: a required host is out of reach") {
		t.Errorf("rung %d:\n%s", report.Rung, output.String())
	}
}

// A fake CONNECT proxy on the loopback that tunnels a target the world serves to its server and refuses the rest
// with 502, recording each target.
type testStatusProxy struct {
	listener net.Listener
	world    *testHostWorld

	stateLock sync.Mutex
	targets   []string
}

func newTestStatusProxy(t *testing.T, world *testHostWorld) *testStatusProxy {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	self := &testStatusProxy{listener: listener, world: world}
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(urTestTimeout))
				reader := bufio.NewReader(conn)
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				host, _, _ := net.SplitHostPort(request.RequestURI)
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.targets = append(self.targets, request.Method+" "+request.RequestURI)
				}()
				world.stateLock.Lock()
				reachable := world.reachable[host]
				world.stateLock.Unlock()
				if request.Method != http.MethodConnect || !reachable {
					io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					return
				}
				backend, err := net.Dial("tcp4", world.listener.Addr().String())
				if err != nil {
					return
				}
				defer backend.Close()
				io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() {
					io.Copy(backend, reader)
					backend.Close()
				}()
				io.Copy(conn, backend)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		waitGroup.Wait()
	})
	return self
}

// What the proxy was asked for.
func (self *testStatusProxy) requests() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.targets...)
}

// With HTTPS_PROXY set, every probe crosses the proxy as a CONNECT naming its host, and the report is rung 2.
func TestStatusProbesThroughHttpsProxy(t *testing.T) {
	realCa := newTestHostCa(t, "synthetic real issuer")
	world := newTestHostWorld(t, realCa)
	list := testHostList(t, realCa.spkiDigest())
	for _, entry := range list.Hosts {
		world.serve(entry.Host, realCa)
	}
	connectProxy := newTestStatusProxy(t, world)
	cli, output := newTestStatusCli(t, "", world, list)
	// the proxy's own dial is real: no mapping, only HTTPS_PROXY
	cli.hostProber = &urHostProber{connectSettings: connect.DefaultConnectSettings, roots: world.roots}
	cli.getenv = func(name string) string {
		if name == "HTTPS_PROXY" {
			return "http://" + connectProxy.listener.Addr().String()
		}
		return ""
	}

	report := cli.reportHosts(context.Background(), list)
	printUrHostReport(cli, report)
	if !report.Proxied || report.Rung != urHostRungProxied {
		t.Fatalf("proxied %v, rung %d:\n%s", report.Proxied, report.Rung, output.String())
	}
	if !strings.Contains(output.String(), "rung 2, wss through HTTPS_PROXY: everything") {
		t.Errorf("status:\n%s", output.String())
	}
	requests := connectProxy.requests()
	for _, entry := range list.Hosts {
		want := "CONNECT " + entry.Address()
		count := 0
		for _, request := range requests {
			if request == want {
				count += 1
			}
		}
		if count != 1 {
			t.Errorf("the proxy read %q %d times: %v", want, count, requests)
		}
	}
}

// An HTTPS_PROXY ur cannot use probes nothing, rather than going around it, and says why without its value.
func TestStatusProbesNothingPastAnUnusableProxy(t *testing.T) {
	realCa := newTestHostCa(t, "synthetic real issuer")
	world := newTestHostWorld(t, realCa)
	list := testHostList(t, realCa.spkiDigest())
	for _, entry := range list.Hosts {
		world.serve(entry.Host, realCa)
	}
	cli, output := newTestStatusCli(t, "", world, list)
	cli.getenv = func(name string) string {
		if name == "HTTPS_PROXY" {
			return "https://synthetic-user:synthetic-password@proxy.statustest.example:3128"
		}
		return ""
	}
	printUrHostReport(cli, cli.reportHosts(context.Background(), list))
	text := output.String()
	if !strings.Contains(text, "not probed") || strings.Contains(text, "synthetic-password") {
		t.Errorf("status:\n%s", text)
	}
	for _, entry := range list.Hosts {
		if count := world.dialCount(entry.Host); count != 0 {
			t.Errorf("%s dialed %d times past a refused proxy", entry.Host, count)
		}
	}
}

// A daemon that does not answer still leaves the host report, and the status fails.
func TestStatusProbesWhenNoDaemonAnswers(t *testing.T) {
	realCa := newTestHostCa(t, "synthetic real issuer")
	world := newTestHostWorld(t, realCa)
	list := testHostList(t, realCa.spkiDigest())
	cli, output := newTestStatusCli(t, shortTestDirectory(t)+"/none", world, list)
	if code := cli.main(context.Background(), []string{"ur", "status"}); code != urExitFailed {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(output.String(), "hosts:") || !strings.Contains(output.String(), "none: a required host is out of reach") {
		t.Errorf("status:\n%s", output.String())
	}
}
