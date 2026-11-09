// ur login (§5.6, §7.8, D-TEAM-7): TEAM-M1-08's ur-cli mints a single-use, user-owned auth key of at most 5 min in
// this process, never through the daemon or MCP; ur drops the OAuth token at once, hands the key to the daemon over
// the control socket, and then offers to register a presence key through §16's hook. Until ur-cli lands, ur login
// refuses (C-14). --recover is CORE-M2-06's code-only recovery, refused until it lands.

package main

import (
	"context"
	"errors"

	"github.com/docopt/docopt-go"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "login",
		usage:   "  ur login [--invite=<link>] [--replace]\n  ur login --recover",
		summary: "log in with URnetwork and enroll this device's sidecar",
		run:     runUrLogin,
	})
}

func runUrLogin(ctx context.Context, cli *urCli, options docopt.Opts) error {
	if recover, _ := options.Bool("--recover"); recover {
		return errors.New("code-only recovery is not built yet")
	}
	if cli.login == nil {
		return errors.New("ur login needs ur-cli, which is not built yet: use ur connect --token")
	}
	invite, _ := options.String("--invite")
	replace, _ := options.Bool("--replace")
	authKey, drop, err := cli.login(ctx, cli, invite)
	// the OAuth token goes before anything else runs: only the single-use key outlives it
	if drop != nil {
		drop()
	}
	if err != nil {
		return err
	}
	if err := enrollThroughDaemon(ctx, cli, &urEnrollParams{AuthKey: authKey, Replace: replace}); err != nil {
		return err
	}
	if cli.offerPresenceKey != nil {
		return cli.offerPresenceKey(ctx, cli)
	}
	return nil
}
