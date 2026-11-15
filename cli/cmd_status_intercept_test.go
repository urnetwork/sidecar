package main

// ur status through a TLS-intercepting proxy, sidecartest's InterceptingProxy standing in for a cloud sandbox's
// (TEST-M4-02; §22.7's CC4, §18.9, §2.4's sandbox row): the proxy terminates each probe's TLS with its own CA, which
// the sandbox's system trusts and the host table does not pin, so ur status names the interception and blocks nothing;
// the same world reached with no proxy reads pinned and names none.

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/sidecartest"
)

// With HTTPS_PROXY naming the intercepting proxy, every host's chain ends at the proxy's CA: ur status reads each
// intercepted and names the proxy's issuer, warns once that nothing was blocked, stays on rung 2, and each probe
// crossed the proxy carrying nothing after its handshake. With no proxy, no report.
func TestStatusNamesTheInterceptingProxy(t *testing.T) {
	realCa := newTestHostCa(t, "synthetic real issuer")
	world := newTestHostWorld(t, realCa)
	list := testHostList(t, realCa.spkiDigest())
	for _, entry := range list.Hosts {
		world.serve(entry.Host, realCa)
	}

	capture := sidecartest.NewPrivacyCapture()
	settings := sidecartest.DefaultInterceptingProxySettings()
	// the proxy reaches the real hosts as the world's server, trusting their real issuer
	settings.Dial = func(ctx context.Context, network string, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		world.stateLock.Lock()
		reachable := world.reachable[host]
		world.stateLock.Unlock()
		if !reachable {
			return nil, errors.New("synthetic: no route")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp4", world.listener.Addr().String())
	}
	settings.TargetRoots = world.roots
	proxy, err := sidecartest.NewInterceptingProxy(capture, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyUrl, err := proxy.Listen()
	if err != nil {
		t.Fatal(err)
	}

	// the sandbox installed its proxy's CA beside the real issuer
	roots := x509.NewCertPool()
	roots.AddCert(realCa.certificate)
	roots.AddCert(proxy.Certificate())
	cli, output := newTestStatusCli(t, "", world, list)
	cli.hostProber = &urHostProber{connectSettings: connect.DefaultConnectSettings, roots: roots}
	cli.getenv = func(name string) string {
		if name == "HTTPS_PROXY" {
			return proxyUrl
		}
		return ""
	}
	report := cli.reportHosts(context.Background(), list)
	printUrHostReport(cli, report)
	text := output.String()
	if !report.Proxied || report.Rung != urHostRungProxied {
		t.Fatalf("proxied %t, rung %d:\n%s", report.Proxied, report.Rung, text)
	}
	for _, entry := range list.Hosts {
		line := ""
		for _, candidate := range strings.Split(text, "\n") {
			if strings.Contains(candidate, entry.Address()) {
				line = candidate
			}
		}
		if !strings.Contains(line, "chain intercepted") || strings.Contains(line, "not trusted") || !strings.Contains(line, "synthetic intercepting proxy") {
			t.Errorf("%s: %q", entry.Host, line)
		}
	}
	if strings.Count(text, "warning:    interception") != 1 || !strings.Contains(text, "never Required-mode traffic or repo content") || !strings.Contains(text, "Nothing was blocked") {
		t.Errorf("no interception warning:\n%s", text)
	}
	flows := proxy.Flows()
	if len(flows) != len(list.Hosts) {
		t.Fatalf("the proxy saw %d flows for %d hosts: %+v", len(flows), len(list.Hosts), flows)
	}
	for _, flow := range flows {
		if 0 < len(flow.ToTarget) {
			t.Errorf("a probe sent %d bytes after its handshake to %s", len(flow.ToTarget), flow.Target)
		}
	}
	if findings := capture.Scan(); len(findings) != 0 {
		t.Errorf("findings: %v", findings)
	}

	// the same world with no proxy: every chain pinned, and no report of interception
	direct, directOutput := newTestStatusCli(t, "", world, list)
	direct.hostProber = world.prober()
	printUrHostReport(direct, direct.reportHosts(context.Background(), list))
	directText := directOutput.String()
	if strings.Contains(directText, "interception") || strings.Count(directText, "chain pinned") != len(list.Hosts) {
		t.Errorf("with no proxy:\n%s", directText)
	}
}
