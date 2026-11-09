// ur logout (§5.6, CORE-M2-07): signs this device's SidecarRevoke{removed} for one network and posts it, removes its
// client and wipes that network's state, in that order, leaving the instance's other networks running (CORE-M6-01).
// The network is --network, else the project's .ur, else the only one (§5.8). While the sign-out cannot land, as when
// api is out of reach, nothing is removed or wiped, and the next ur logout posts the same signed bytes.

package main

import (
	"context"

	"github.com/docopt/docopt-go"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "logout",
		usage:   "  ur logout [--network=<name>]",
		summary: "sign this device out of a network, remove its client and wipe its network state",
		run:     runUrLogout,
	})
}

func runUrLogout(ctx context.Context, cli *urCli, options docopt.Opts) error {
	network, _ := options.String("--network")
	confirmed, err := confirmOnTty(cli, "sign this device out, remove its client and delete its keys for the network?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	if err := cli.callDaemon(ctx, urMethodLogout, &urNetworkParams{Network: network}, true, nil); err != nil {
		return err
	}
	cli.printf("logged out\n")
	return nil
}
