// ur logout (§5.6): at M1 it removes the sidecar's client and wipes this network's state; CORE-M2-07 adds the
// SidecarRevoke{removed} it signs first.

package main

import (
	"context"

	"github.com/docopt/docopt-go"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "logout",
		usage:   "  ur logout",
		summary: "remove this device's client and wipe its network state",
		run:     runUrLogout,
	})
}

func runUrLogout(ctx context.Context, cli *urCli, options docopt.Opts) error {
	confirmed, err := confirmOnTty(cli, "remove this device's client and delete its keys for the network?")
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing changed\n")
		return nil
	}
	if err := cli.callDaemon(ctx, urMethodLogout, nil, true, nil); err != nil {
		return err
	}
	cli.printf("logged out\n")
	return nil
}
