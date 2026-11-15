// The daemon's tls.edge_login.sign (QD-827; §13.7, §18.5, D-CORE-13): a remote-mode app's Sidecar.SignEdgeLogin has ur
// daemon's Sidecar of the network sign the device's members-device statement (the root's tls_edge_login_daemon.go).
// It registers here beside the daemon's tls methods as a Confirm method, so ur daemon signs only for a control call
// confirmed in an app's UI or on /dev/tty, and ur native-host, which relays no Confirm method, never carries one. No ur
// command sends it: the person confirms a login in the app whose page asked.

package main

import (
	"github.com/urnetwork/sidecar"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urTlsEdgeLoginMethods)
}

// The root's edge-login method, over a target that hosts Sidecars.
func urTlsEdgeLoginMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if _, ok := target.(*urDaemonNetwork); !ok {
		return nil
	}
	return sidecar.DaemonTlsEdgeLoginMethods()
}
