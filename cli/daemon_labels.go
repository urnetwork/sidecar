// The daemon's part in each network's label (§12.5's label row, §5.8's project row, §11.11's names row; sidecar's
// dns_label_refresh.go and daemon_labels.go): every Sidecar it starts, the one a further enrollment takes among them,
// gets the core's label refresh, which reads the network's label and alias from api's GET /sidecar/label into the
// network's own label table at each client generation, under the user root its settings name; and the daemon resolves
// the <net> of `.ur`, a call's network argument, a git session and a socket address through those tables, each
// network's speaking for itself, under the same root (DaemonSettings.LabelRoot). So a daemon hosting several networks
// picks each by its label, and ur acl push in a project whose `.ur` names one plans on that one.
//
// The root is SidecarSettings.UserRoot, which the service urls' fill sets from §18.9's host table, the one copy of
// production's root in code (QD-1407). A daemon whose settings name none, as one that runs no Sidecar, reads no label
// and resolves no <net> by name, a network id or the only network still naming one.

package main

import (
	"errors"

	"github.com/urnetwork/sidecar"
)

// Adds running's label refresh, on settings, nil taking the defaults, which the Sidecar closes with it. One that does
// not add leaves the network's table to what its zone writes, from M5.
func startUrNetworkLabels(running *sidecar.Sidecar, settings *sidecar.NetworkLabelRefreshSettings, log sidecar.Logger) {
	if _, err := running.AddComponent(running.NewNetworkLabelRefreshComponent(settings)); err != nil && !errors.Is(err, sidecar.ErrSidecarClosed) {
		log.Warningf("[ur]a network's label is not read from api: %s", err)
	}
}
