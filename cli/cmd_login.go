// ur login (§5.6, §7.8, D-TEAM-7): TEAM-M1-08's ur-cli mints a single-use, user-owned auth key of at most 5 min in
// this process, never through the daemon or MCP; ur drops the OAuth token at once, hands the key to the daemon over
// the control socket, and then offers to register a presence key through §16's hook. ur-cli is urcli_login.go's
// (C-14). --device gets the same key by RFC 8628's device grant, for a host with no browser (cmd_login_device.go).
// --recover is CORE-M2-06's code-only recovery (cmd_login_recover.go). Into a further network, the daemon enrolls one
// more Sidecar beside the others (CORE-M6-01); --network re-enrolls a network it holds by name. On a paired daemon
// (CORE-M8-02) ur login unpairs: the top-level client it enrolls is the next generation, and the child goes.

package main

import (
	"context"
	"errors"

	"github.com/docopt/docopt-go"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "login",
		usage:   "  ur login [--invite=<link>] [--replace] [--network=<name>] [--device]\n  ur login --recover",
		summary: "log in with URnetwork and enroll this device's sidecar",
		run:     runUrLogin,
	})
}

func runUrLogin(ctx context.Context, cli *urCli, options docopt.Opts) error {
	if recover, _ := options.Bool("--recover"); recover {
		return runUrLoginRecover(ctx, cli, options)
	}
	login := cli.login
	if device, _ := options.Bool("--device"); device {
		login = cli.loginDevice
	}
	if login == nil {
		return errors.New("ur login needs ur-cli, which is not built yet: use ur connect --token")
	}
	invite, _ := options.String("--invite")
	replace, _ := options.Bool("--replace")
	network, _ := options.String("--network")
	authKey, drop, err := login(ctx, cli, invite)
	// the OAuth token goes before anything else runs: only the single-use key outlives it
	if drop != nil {
		drop()
	}
	if err != nil {
		return err
	}
	if err := enrollThroughDaemon(ctx, cli, &urEnrollParams{AuthKey: authKey, Replace: replace, Network: network}); err != nil {
		return err
	}
	if cli.offerPresenceKey != nil {
		return cli.offerPresenceKey(ctx, cli)
	}
	return nil
}
