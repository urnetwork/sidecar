// The daemon's part in each network's DNS (§12.5's label row; sidecar's dns_component.go): every Sidecar it starts, the
// one a further enrollment takes among them, gets the core's dns component, which attaches the network's label table
// and its zone hints to the network's DnsClient from its first client generation on. So the table in the network's
// dns/ directory holds the row the network's own zone wrote, and its retiring aliases, which a writer's network: label
// read takes (ur acl push, cmd_acl.go), and a DNS_ZONE_CHANGED hint or the hourly resync refetches the zone.
//
// Beside it each gets D-TRUST-9's zone watch (sidecar's dns_watch_component.go), which a host that stays up runs: a
// pass about every 6 h asks two public DoH resolvers about this device's published names and mail hosts and alarms on
// records it did not request. The daemon is that host for the desktop and the CLI (§18.4), so it runs the watch for
// every network it hosts, on the settings urDaemonNetwork holds.

package main

import (
	"errors"

	"github.com/urnetwork/sidecar"
)

// Adds running's dns component and its zone watch, on watchSettings, nil taking the defaults, both of which the
// Sidecar closes with it. A dns component that does not add leaves the network's label table to open at its first
// read, its zone refetched only when read; a watch that does not add leaves the zone unwatched.
func startUrDns(running *sidecar.Sidecar, watchSettings *sidecar.DnsWatchComponentSettings, log sidecar.Logger) {
	if _, err := running.AddComponent(running.NewDnsComponent()); err != nil && !errors.Is(err, sidecar.ErrSidecarClosed) {
		log.Warningf("[ur]a network's zone feeds no label table: %s", err)
	}
	watch := running.NewDnsWatchComponent(watchSettings)
	if _, err := running.AddComponent(watch); err != nil {
		watch.Close()
		if !errors.Is(err, sidecar.ErrSidecarClosed) {
			log.Warningf("[ur]a network's zone is not watched: %s", err)
		}
	}
}
