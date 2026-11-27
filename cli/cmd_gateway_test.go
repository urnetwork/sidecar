package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A port both loopback addresses have free now, from a range no system hands out on its own.
func testUrGatewayPort(t *testing.T) int {
	t.Helper()
	settings := sidecar.DefaultGatewaySettings()
	settings.PortFirst, settings.PortLast = 30000, 31999
	port, err := sidecar.ChooseGatewayPort(settings, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// A control daemon with ur's methods over target and a gateway over its state directory, whose state holds port while
// hold; the gateway is started, and closed at the test's end.
func startTestGatewayDaemon(t *testing.T, target urDaemonTarget, port int, hold bool, holder func(address string) string) (*testUrDaemon, *sidecar.GatewayServer, string) {
	t.Helper()
	directory := shortTestDirectory(t)
	if 0 < port {
		if err := sidecar.WriteGatewayState(directory, &sidecar.GatewayState{Version: 1, Port: port, Hold: hold}); err != nil {
			t.Fatal(err)
		}
	}
	gateway := sidecar.NewGatewayServer(&sidecar.GatewayServerArgs{StateDirectory: directory, Holder: holder})
	t.Cleanup(gateway.Close)
	daemon := startTestUrDaemon(t, directory, func(daemon *sidecar.Daemon) {
		if err := registerUrDaemonMethods(daemon, "test", target, osKeyStoreKeyFile, func() []sidecar.SidecarHostCredentialStore { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := startUrDaemonGateway(daemon, gateway, sidecar.NewNoopLogger()); err != nil {
			t.Fatal(err)
		}
	})
	return daemon, gateway, directory
}

// ur status names the gateway's port and that this daemon holds it; where another process holds an address it names
// that process, as the OS shows it, and says ur gateway token refuses; with no port it says nothing of the gateway.
func TestStatusNamesGatewayPortAndHolder(t *testing.T) {
	port := testUrGatewayPort(t)
	daemon, _, _ := startTestGatewayDaemon(t, &testUrDaemonTarget{}, port, true, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	cli.main(context.Background(), []string{"ur", "status"})
	if want := "gateway:    port " + strconv.Itoa(port) + ", held by this daemon on 127.0.0.1:" + strconv.Itoa(port); !strings.Contains(stdout.String(), want) {
		t.Errorf("the served port: %q", stdout.String())
	}

	taken := testUrGatewayPort(t)
	foreign, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(taken)))
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	daemon, _, _ = startTestGatewayDaemon(t, &testUrDaemonTarget{}, taken, true, func(address string) string { return "pid 77 (synthetic), uid 501" })
	cli, stdout, _ = newTestUrCli(daemon.socketPath)
	cli.main(context.Background(), []string{"ur", "status"})
	if want := "127.0.0.1:" + strconv.Itoa(taken) + " is held by another process, pid 77 (synthetic), uid 501: ur gateway token refuses"; !strings.Contains(stdout.String(), want) {
		t.Errorf("a taken port: %q", stdout.String())
	}

	daemon, _, _ = startTestGatewayDaemon(t, &testUrDaemonTarget{}, 0, false, nil)
	cli, stdout, _ = newTestUrCli(daemon.socketPath)
	cli.main(context.Background(), []string{"ur", "status"})
	if strings.Contains(stdout.String(), "gateway:") {
		t.Errorf("no gateway installed: %q", stdout.String())
	}
}
