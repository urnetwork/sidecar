// ur daemon serves a remote-mode app's request methods (MCP-M8-01; §16.6's host table, D-SDK-9): the list a read on its
// call's network, the decision a Confirm method on it, neither relayed by ur native-host, and every method of the
// daemon registered once, so they register beside ur approve's and the devices methods on one daemon.

package main

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestDaemonServesTheAppRequestMethods(t *testing.T) {
	network := &urDaemonNetwork{}
	started := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		network.daemon = daemon
		if err := registerUrDaemonMethods(daemon, "default", network, osKeyStoreKeyFile, func() []sidecar.SidecarHostCredentialStore { return nil }); err != nil {
			t.Fatal(err)
		}
	})
	methods := urDaemonMethods("default", &urDaemonNetwork{daemon: started.daemon}, osKeyStoreKeyFile, nil)
	counts := map[string]int{}
	for _, method := range methods {
		counts[method.Name] += 1
	}
	for name, count := range counts {
		if count != 1 {
			t.Errorf("%s is served %d times", name, count)
		}
	}
	for _, want := range []struct {
		name    string
		confirm bool
	}{
		{name: sidecar.DaemonMethodApprovalsAppRequests, confirm: false},
		{name: sidecar.DaemonMethodApprovalsAppRequest, confirm: true},
	} {
		index := slices.IndexFunc(methods, func(method *sidecar.DaemonMethod) bool { return method.Name == want.name })
		if index < 0 {
			t.Errorf("ur daemon serves no %s", want.name)
			continue
		}
		if methods[index].Confirm != want.confirm || !methods[index].Network {
			t.Errorf("%s: Confirm %t, Network %t", want.name, methods[index].Confirm, methods[index].Network)
		}
		if slices.Contains(nativeHostRelayedMethods, want.name) {
			t.Errorf("ur native-host relays %s", want.name)
		}
	}
	// a target that hosts no Sidecars serves none
	if len(urApprovalsAppMethods(&testUrDaemonTarget{})) != 0 {
		t.Error("a target with no Sidecars serves the app request methods")
	}
}
