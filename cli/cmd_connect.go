// ur connect --token (§5.6, R-CORE-9): enrolls the instance's sidecar from a §7 auth key, which the daemon spends in
// D-CORE-7's order (Sidecar.Enroll). The key is single use: once the enrollment spends it, it admits nothing, so the
// argv that carried it holds no live credential (S1). --ephemeral needs an ephemeral daemon, which a connect that
// finds none spawns, and --replace takes restored state as this machine's (plan-CORE-cli-ui-missing #4).

package main

import (
	"context"

	"github.com/docopt/docopt-go"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "connect",
		usage:   "  ur connect --token=<key> [--ephemeral] [--replace]",
		summary: "enroll this device's sidecar with an auth key",
		run:     runUrConnect,
	})
}

func runUrConnect(ctx context.Context, cli *urCli, options docopt.Opts) error {
	authKey, _ := options.String("--token")
	ephemeral, _ := options.Bool("--ephemeral")
	replace, _ := options.Bool("--replace")
	// no client declares provider egress until `ur proxy` or a public exit exists to set it (§20.8)
	return enrollThroughDaemon(ctx, cli, &urEnrollParams{
		AuthKey:   authKey,
		Ephemeral: ephemeral,
		Replace:   replace,
	})
}

// Hands an auth key to the daemon to enroll with, spawning an ephemeral daemon for an ephemeral enrollment.
func enrollThroughDaemon(ctx context.Context, cli *urCli, params *urEnrollParams) error {
	spawnArgs := []string{}
	if params.Ephemeral {
		spawnArgs = append(spawnArgs, "--ephemeral")
	}
	reply := &urEnrollReply{}
	if err := cli.callDaemon(ctx, urMethodEnroll, params, false, reply, spawnArgs...); err != nil {
		return err
	}
	cli.printf("enrolled: generation %d\n", reply.Generation)
	return nil
}
