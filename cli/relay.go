// The relay (§5.8): `ur mcp`, and bare ur on a pipe, carry a harness's stdio to the instance's daemon, where MCP runs
// (§16), after §5.8's hello. If no daemon answers, it spawns `ur daemon` detached, once, and dials until it answers
// (commands.go's connectDaemon). It never logs to stdout, which carries only the daemon's bytes: what it has to say
// goes to stderr. A daemon of another version is refused, never relayed through.

package main

import (
	"context"
	"io"

	"github.com/urnetwork/sidecar"
)

// Pipes stdin to the daemon's session of hello's mode and the session to stdout, until either side ends.
func relayToDaemon(ctx context.Context, cli *urCli, hello *sidecar.DaemonHello, spawnArgs []string) error {
	client, err := cli.connectDaemon(ctx, hello, spawnArgs)
	if err != nil {
		return err
	}
	defer client.Close()
	stream := client.Stream()
	ended := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, cli.stdin)
		ended <- err
	}()
	go func() {
		_, err := io.Copy(cli.stdout, stream)
		ended <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-ended:
		// the harness closed stdin, or the daemon ended the session: either ends the relay
		return err
	}
}
