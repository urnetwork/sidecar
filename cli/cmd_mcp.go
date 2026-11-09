// ur mcp (§5.8, §16): relays a harness's stdio to the daemon's MCP, after §5.8's hello naming the harness and
// agent. Bare ur on a pipe runs this too (owner decision 57). The daemon's MCP server is §16's, registered as its
// mcp mode; a daemon without one refuses the hello, and the relay says so on stderr.

package main

import (
	"context"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "mcp",
		usage:   "  ur mcp [--agent=<name>] [--harness=<name>]",
		summary: "relay MCP over stdio to the daemon (what bare ur does on a pipe)",
		run:     runUrMcp,
	})
}

func runUrMcp(ctx context.Context, cli *urCli, options docopt.Opts) error {
	hello := cli.hello(sidecar.DaemonModeMcp)
	hello.Agent, _ = options.String("--agent")
	hello.Harness, _ = options.String("--harness")
	return relayToDaemon(ctx, cli, hello, nil)
}
