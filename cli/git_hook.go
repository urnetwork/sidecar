// ur git-hook <name> (DESIGN-DETAILS 8.2.8; EVS1-M2-36): each mount's pre-receive and proc-receive hook files exec
// this, git-receive-pack having been started by the daemon with UR_GIT_SESSION and UR_INSTANCE set. It dials the
// instance's daemon in its git-hook mode, names the session, and relays the hook's stdin, stdout and stderr, exiting
// with the code the daemon sends (sidecar.EvsGitHookRelay). With no daemon, or no session, it exits 1, which refuses
// the push: a hook never fails open. The session id names a session and grants nothing, and git's environment holds
// no credential.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

// The daemon's git-hook mode (DESIGN-DETAILS 8.2.8): the header names a receive session, and the hosted network whose
// mounts opened it serves the hook (sidecar.EvsMounts.ServeGitHook), the header handed on ahead of the stream. A
// session no network holds, or a daemon that builds no evs client, exits the hook 1, which refuses the push.
func urDaemonGitHookMode(daemon *sidecar.Daemon) sidecar.DaemonModeHandler {
	return func(ctx context.Context, hello *sidecar.DaemonHello, stream io.ReadWriter) error {
		reader := bufio.NewReader(stream)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return err
		}
		header := &sidecar.EvsGitHookHeader{}
		if err := json.Unmarshal(line, header); err != nil {
			return err
		}
		replayed := &urReplayedStream{reader: io.MultiReader(bytes.NewReader(line), reader), writer: stream}
		if urDaemonEvsClient != nil {
			for _, network := range daemon.Sidecars() {
				client, err := urDaemonEvsClient(network.Sidecar)
				if err != nil {
					continue
				}
				mounts, err := client.Mounts()
				if err != nil || !mounts.HasReceiveSession(header.Session) {
					continue
				}
				return mounts.ServeGitHook(ctx, hello.Service, replayed)
			}
		}
		return sidecar.RefuseEvsGitHook(stream, "ur: no network of this daemon holds the push's receive session")
	}
}

// A stream whose reads begin with bytes already read off it.
type urReplayedStream struct {
	reader io.Reader
	writer io.Writer
}

// Reads the replayed bytes, then the stream's.
func (self *urReplayedStream) Read(p []byte) (int, error) {
	return self.reader.Read(p)
}

// Writes to the stream.
func (self *urReplayedStream) Write(p []byte) (int, error) {
	return self.writer.Write(p)
}
