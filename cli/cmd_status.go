// ur status (§5.4, §18.5): each network's state, its reason and the bound client generation, a failed network among
// them (CORE-M6-01), which store wraps U, any store on this host holding a network credential (D-TRUST-3), and each
// local listener the LAN can reach, marked LAN-exposed (§22.5, D-TRUST-8); --stats adds SidecarStats' counters, which
// carry no requester, repo or query label (I-13). The daemon's reply never holds a token, a key or the pass, which its
// reply walk refuses (daemon_rpc.go). Then §18.9's host probes, the rung and any interception (cmd_status_hosts.go).

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "status",
		usage:   "  ur status [--stats]",
		summary: "the sidecar's state, its reason and its generation",
		run:     runUrStatus,
	})
}

func runUrStatus(ctx context.Context, cli *urCli, options docopt.Opts) error {
	stats, _ := options.Bool("--stats")
	reply := &urStatusReply{}
	callErr := cli.callDaemon(ctx, urMethodStatus, &urStatusParams{Stats: stats}, false, reply)
	if callErr == nil {
		printUrStatus(cli, reply)
		for _, section := range urStatusSections {
			section(ctx, cli)
		}
	}
	// §18.9's probes run whether or not a daemon answered, since a host out of reach is often why none did
	list, err := cli.hostList()
	if err != nil {
		fmt.Fprintf(cli.stdout, "hosts:      not probed: %s\n", err)
	} else {
		printUrHostReport(cli, cli.reportHosts(ctx, list))
	}
	return callErr
}

// The reply, as a person reads it.
func printUrStatus(cli *urCli, reply *urStatusReply) {
	out := cli.stdout
	fmt.Fprintf(out, "instance:   %s\n", reply.Instance)
	if reply.NoSidecar != "" {
		fmt.Fprintf(out, "sidecar:    none: %s\n", reply.NoSidecar)
	} else {
		state := reply.State
		if reply.Reason != "" {
			state += " (" + reply.Reason + ")"
		}
		fmt.Fprintf(out, "state:      %s\n", state)
		fmt.Fprintf(out, "generation: %d\n", reply.Generation)
	}
	for _, network := range reply.Networks {
		state := network.State
		if network.Reason != "" {
			state += " (" + network.Reason + ")"
		}
		fmt.Fprintf(out, "network:    %s  %s, generation %d\n", network.NetworkId, state, network.Generation)
	}
	for _, listener := range reply.LocalListeners {
		exposure := "loopback only"
		if listener.LanExposed {
			exposure = "LAN-exposed"
		}
		fmt.Fprintf(out, "listening:  %s on %s (%s)\n", listener.Service, strings.Join(listener.Addresses, ", "), exposure)
	}
	if 0 < reply.Sockets || 0 < reply.LiveShares {
		// a share is served only while this daemon runs (§9.9), so the person learns why it stays up
		fmt.Fprintf(out, "sockets:    %d held, %d live shares; the daemon stays up while any is\n", reply.Sockets, reply.LiveShares)
	}
	keyStore := reply.KeyStore
	if keyStore == string(osKeyStoreKeyFile) {
		keyStore += " (warning: a 0600 key file wraps the unlock key, which any process of this user can read)"
	}
	fmt.Fprintf(out, "key store:  %s\n", keyStore)
	if 0 < len(reply.CredentialStores) {
		fmt.Fprintf(out, "warning:    a URnetwork %s on this host holds a network credential; enrollment is refused until it is gone\n",
			strings.Join(reply.CredentialStores, " and "))
	}
	if reply.Stats != nil {
		printUrStats(cli, reply.Stats)
	}
}

// --stats' counters.
func printUrStats(cli *urCli, stats *sidecar.SidecarStats) {
	out := cli.stdout
	fmt.Fprintf(out, "generations started: %d\n", stats.GenerationCount)
	fmt.Fprintf(out, "core hints:          %d\n", stats.CoreHintCount)
	for _, component := range stats.Components {
		fmt.Fprintf(out, "component %s: queued %d, ran %d, dropped %d (%d bytes), panics %d\n", component.Name,
			component.QueuedCount, component.RanCount, component.DroppedCount, component.DroppedByteCount, component.PanicCount)
	}
	subprotocol := stats.Subprotocol
	fmt.Fprintf(out, "subprotocol: queued %d, dispatched %d, refused %d by identity, %d by policy, %d at a full queue, replies %d sent, %d dropped\n",
		subprotocol.QueuedCount, subprotocol.DispatchedCount, subprotocol.IdentityRefusedCount, subprotocol.InboundRefusedCount,
		subprotocol.QueueFullCount, subprotocol.ReplySentCount, subprotocol.ReplyDroppedCount)
}
