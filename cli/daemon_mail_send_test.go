// ur daemon serves a remote-mode app's send methods (QD-853, owner decision 288): mail.check_send, mail.send_result and
// mail.send, each on its call's network, none a Confirm one, none relayed by ur native-host, registered once beside
// every other method of the daemon; a target that hosts no Sidecars serves none.

package main

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestDaemonServesTheMailSendMethods(t *testing.T) {
	network := &urDaemonNetwork{}
	started := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		network.daemon = daemon
		if err := registerUrDaemonMethods(daemon, "default", network, osKeyStoreKeyFile, func() []sidecar.SidecarHostCredentialStore { return nil }); err != nil {
			t.Fatal(err)
		}
	})
	methods := urDaemonMethods("default", &urDaemonNetwork{daemon: started.daemon}, osKeyStoreKeyFile, nil)
	for _, name := range []string{sidecar.DaemonMethodMailCheckSend, sidecar.DaemonMethodMailSendResult, sidecar.DaemonMethodMailSend} {
		served := 0
		for _, method := range methods {
			if method.Name != name {
				continue
			}
			served += 1
			if method.Confirm || !method.Network {
				t.Errorf("%s: Confirm %t, Network %t", name, method.Confirm, method.Network)
			}
		}
		if served != 1 {
			t.Errorf("%s is served %d times", name, served)
		}
		if slices.Contains(nativeHostRelayedMethods, name) {
			t.Errorf("ur native-host relays %s", name)
		}
	}
	if len(urMailSendMethods(&testUrDaemonTarget{})) != 0 {
		t.Error("a target with no Sidecars serves the send methods")
	}
}
