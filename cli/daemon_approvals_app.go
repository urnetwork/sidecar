// The daemon's request methods for a remote-mode desktop app (MCP-M8-01; §16.6's host table, D-SDK-9): the root's
// approvals.app.requests and approvals.app.request (daemon_approvals_app.go), on which the app's SidecarApprovals lists
// and decides §16.8's requests as the table's remote-mode row, never this sidecar's own. ur approve keeps its own
// methods (cmd_approve_request.go), and ur native-host relays neither.

package main

import (
	"github.com/urnetwork/sidecar"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urApprovalsAppMethods)
}

// The root's app request methods, over a target that hosts Sidecars.
func urApprovalsAppMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	if _, ok := target.(*urDaemonNetwork); !ok {
		return nil
	}
	return sidecar.DaemonApprovalsAppMethods()
}
