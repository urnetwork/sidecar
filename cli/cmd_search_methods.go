// The root's search control methods on the daemon (§16.10's wire row; §5.8; SEARCH-M10-29): search, search.agents and
// search.status, each on its call's network (sidecar.DaemonSearchMethods), which `ur search`, `ur agents` and `ur search
// status` (SEARCH-M10-30) call with the MCP tools' arguments; and search.sync, `ur search sync`'s
// (sidecar.DaemonSearchSyncMethods).

package main

import (
	"github.com/urnetwork/sidecar"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urSearchMethods)
}

// The root's search methods, when target's daemon hosts Sidecars: each finds its network's engine per call.
func urSearchMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	devices, ok := target.(urDevicesTarget)
	if !ok || devices.devicesDaemon() == nil {
		return nil
	}
	return append(sidecar.DaemonSearchMethods(nil), sidecar.DaemonSearchSyncMethods()...)
}
