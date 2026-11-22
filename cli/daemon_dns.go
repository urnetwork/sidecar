// The daemon's part in each network's DNS (§12.5's label row; sidecar's dns_component.go): every Sidecar it starts, the
// one a further enrollment takes among them, gets the core's dns component, which attaches the network's label table
// and its zone hints to the network's DnsClient from its first client generation on. So the table in the network's
// dns/ directory holds the row the network's own zone wrote, and its retiring aliases, which a writer's network: label
// read takes (ur acl push, cmd_acl.go), and a DNS_ZONE_CHANGED hint or the hourly resync refetches the zone.

package main

import (
	"errors"

	"github.com/urnetwork/sidecar"
)

// Adds running's dns component, which the Sidecar closes with it. One that does not add leaves the network's label
// table to open at its first read, its zone refetched only when read.
func startUrDns(running *sidecar.Sidecar, log sidecar.Logger) {
	if _, err := running.AddComponent(running.NewDnsComponent()); err != nil && !errors.Is(err, sidecar.ErrSidecarClosed) {
		log.Warningf("[ur]a network's zone feeds no label table: %s", err)
	}
}
