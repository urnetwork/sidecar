// ur git-hook <name> (DESIGN-DETAILS 8.2.8; EVS1-M2-36): each mount's pre-receive and proc-receive hook files exec
// this, git-receive-pack having been started by the daemon with UR_GIT_SESSION and UR_INSTANCE set. It dials the
// instance's daemon in its git-hook mode, names the session, and relays the hook's stdin, stdout and stderr, exiting
// with the code the daemon sends (sidecar.EvsGitHookRelay). With no daemon, or no session, it exits 1, which refuses
// the push: a hook never fails open. The session id names a session and grants nothing, and git's environment holds
// no credential.

package main

import (
	"context"
	"fmt"
	"io"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "git-hook",
		usage:   "  ur git-hook <name>",
		summary: "run a mount's git hook in the daemon: each mount's pre-receive and proc-receive exec it",
		run:     runUrGitHook,
	})
}

// Relays one hook to the daemon.
func runUrGitHook(ctx context.Context, cli *urCli, options docopt.Opts) error {
	name, _ := options.String("<name>")
	code := sidecar.EvsGitHookRelay(ctx, &sidecar.EvsGitHookRelayArgs{
		Hook: name,
		Dial: func(ctx context.Context) (io.ReadWriteCloser, error) {
			socketPath, err := cli.socketPath(cli.instance)
			if err != nil {
				return nil, err
			}
			hello := cli.hello(sidecar.DaemonModeGitHook)
			hello.Service = name
			client, err := cli.dialDaemon(ctx, socketPath, hello)
			if err != nil {
				return nil, err
			}
			return &urDaemonStream{ReadWriter: client.Stream(), client: client}, nil
		},
		Getenv: cli.getenv,
		Stdin:  cli.stdin,
		Stdout: cli.stdout,
		Stderr: cli.stderr,
	})
	if code != 0 {
		return &urExitError{code: code, err: fmt.Errorf("the %s hook exited %d", name, code)}
	}
	return nil
}
