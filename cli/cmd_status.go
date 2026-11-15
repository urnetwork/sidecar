// ur status (§5.4, §18.5): each network's state, its reason and the bound client generation, a failed network among
// them (CORE-M6-01), which store wraps U, any store on this host holding a network credential (D-TRUST-3), and each
// local listener the LAN can reach, marked LAN-exposed (§22.5, D-TRUST-8); --stats adds SidecarStats' counters, which
// carry no requester, repo or query label (I-13). Each path a mirror journalled as ignored under a repo's prefix rules,
// and not yet repaired, is listed with its version, kind and signer (DESIGN-DETAILS 16.2.5, 16.2.8): the device's own
// plaintext, shown to its person and in no log. The daemon's reply never holds a token, a key or the pass, which its
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
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urStatusPrefixMethods)
	urStatusSections = append(urStatusSections, printUrStatusPrefix)
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
		printUrNetworkConfig(cli, &network)
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

// A network's config follower, under its network line: the log position it stands at, what it waits for, or why it
// refused, which is why nothing on the network is admitted.
func printUrNetworkConfig(cli *urCli, network *urNetworkStatus) {
	switch {
	case network.Config == "":
		fmt.Fprintf(cli.stdout, "  config:   not followed, so nothing on the network is admitted\n")
	case network.Config == string(sidecar.SidecarConfigFollowerStanding):
		fmt.Fprintf(cli.stdout, "  config:   followed, at position %d\n", network.ConfigPin)
	case network.ConfigReason != "":
		fmt.Fprintf(cli.stdout, "  config:   %s: %s\n", network.Config, network.ConfigReason)
	default:
		fmt.Fprintf(cli.stdout, "  config:   %s\n", network.Config)
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

// The control method `ur status` reads the prefix rules' journal by (DESIGN-DETAILS 16.2.5, 16.2.8; EVS1-M6-05).
const urMethodStatusPrefix = "status.prefix"

// status.prefix's reply: a line per journalled path, each hosted network's.
type urStatusPrefixReply struct {
	Lines []string `json:"lines,omitempty"`
}

// The journal's lines: every ignored event a mirror journalled and no repair has settled, oldest first. A path is this
// device's own plaintext, which `ur status` shows its user and no log takes (I-13).
func urStatusPrefixLines(units []*sidecar.EvsPrefixIgnored) []string {
	lines := []string{}
	for _, unit := range units {
		path := unit.Path
		if !unit.Named {
			path = "a path this device's mirror holds no name for"
		}
		lines = append(lines, fmt.Sprintf("prefix:     repo %s ref %s %s: version %d (%s) ignored, signed by %s; waits for its repair",
			unit.RepoId, unit.RefId, path, unit.Version, unit.Kind, unit.SignerSidecarId))
	}
	return lines
}

// The journal method over target, when it hosts Sidecars: each hosted network's evs client's journal, a network with
// no evs client passed over.
func urStatusPrefixMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	hosting, ok := target.(urStatusCoverageTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name: urMethodStatusPrefix,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			reply := &urStatusPrefixReply{}
			if urDaemonEvsClient == nil {
				return reply, nil
			}
			for _, network := range hosting.hosted() {
				client, err := urDaemonEvsClient(network.Sidecar)
				if err != nil {
					continue
				}
				units, err := client.PrefixIgnored(nil)
				if err != nil {
					reply.Lines = append(reply.Lines, fmt.Sprintf("prefix:     network %s: the journal does not read: %s", network.NetworkId, err))
					continue
				}
				reply.Lines = append(reply.Lines, urStatusPrefixLines(units)...)
			}
			return reply, nil
		},
	}}
}

// The journal's lines, after status's own; nothing for a daemon that does not answer, or holds nothing.
func printUrStatusPrefix(ctx context.Context, cli *urCli) {
	reply := &urStatusPrefixReply{}
	if err := cli.callDaemon(ctx, urMethodStatusPrefix, struct{}{}, false, reply); err != nil {
		return
	}
	for _, line := range reply.Lines {
		fmt.Fprintf(cli.stdout, "%s\n", line)
	}
}
