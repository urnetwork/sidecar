package main

// tls.edge_login.sign in ur (QD-827): ur daemon registers the root's method over a target that hosts Sidecars, a
// Confirm method acting on a network; a hook session and an unconfirmed control call are refused it at a running
// daemon, their flag set or not (D-CORE-13); and ur native-host's list never holds it.

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestDaemonRegistersTheEdgeLoginMethod(t *testing.T) {
	if methods := urTlsEdgeLoginMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target that hosts no Sidecars serves the edge-login method")
	}
	network := &urDaemonNetwork{}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		network.daemon = daemon
		for _, method := range urTlsEdgeLoginMethods(network) {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	methods := urDaemonMethods("default", network, osKeyStoreKeyFile, nil)
	index := slices.IndexFunc(methods, func(method *sidecar.DaemonMethod) bool {
		return method.Name == sidecar.DaemonMethodTlsEdgeLoginSign
	})
	if index < 0 {
		t.Fatal("ur daemon registers no edge-login method")
	}
	if !methods[index].Confirm || !methods[index].Network {
		t.Errorf("%s: Confirm %t, Network %t", methods[index].Name, methods[index].Confirm, methods[index].Network)
	}
	if slices.Contains(nativeHostRelayedMethods, sidecar.DaemonMethodTlsEdgeLoginSign) {
		t.Error("ur native-host relays the edge-login method")
	}

	cli, _, _ := newTestUrCli(daemon.socketPath)
	params := &sidecar.DaemonTlsEdgeLoginSignParams{Origin: "https://app.abcdefghij.ur.example", Nonce: make([]byte, 32)}
	for _, c := range []struct {
		mode      string
		confirmed bool
	}{
		{mode: sidecar.DaemonModeHook, confirmed: false},
		{mode: sidecar.DaemonModeHook, confirmed: true},
		{mode: sidecar.DaemonModeControl, confirmed: false},
	} {
		hello := cli.hello(c.mode)
		if c.mode == sidecar.DaemonModeHook {
			hello.Harness = "claude-code"
		}
		client, err := cli.connectDaemon(context.Background(), hello, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.mode, err)
		}
		var rpcError *sidecar.DaemonRpcError
		err = client.Call(context.Background(), sidecar.DaemonMethodTlsEdgeLoginSign, params, c.confirmed, nil)
		if !errors.As(err, &rpcError) || rpcError.Code != sidecar.DaemonRpcConfirmationRequired {
			t.Errorf("from %s, confirmed %t: %v", c.mode, c.confirmed, err)
		}
		client.Close()
	}
}
