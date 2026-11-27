// `ur status`'s context lines (DESIGN-COMPUTE §24.8's coverage row, Q-CTXH-14; CTXH-M13-01): each harness whose model
// calls the gateway did not see within its index's window, by hosted network, with the command that sets it to the
// gateway, since such a harness keeps its own provider and its runs keep only what their transcripts show
// (context_partial). The daemon answers from each network's gateway recorder as it stands, building none, so a
// network whose gateway has recorded nothing prints nothing. The lines name a harness and a run id, never a prompt.

package main

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar"
)

// The control method `ur status` reads the context lines by.
const urMethodStatusContext = "status.context"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urStatusContextMethods)
	urStatusSections = append(urStatusSections, printUrStatusContext)
}

// status.context's reply: each hosted network's lines.
type urStatusContextReply struct {
	Lines []string `json:"lines,omitempty"`
}

// The lines of one network's harnesses not set to the gateway.
func urStatusContextLines(networkId sidecar.Id, partials []*sidecar.SessionGatewayPartial) []string {
	lines := []string{}
	for _, partial := range partials {
		lines = append(lines, fmt.Sprintf("context:    network %s: %s calls its own provider, so its runs keep only what their transcripts show "+
			"(context_partial, run %s); `ur install-harness %s --gateway` sets it to the gateway",
			networkId, partial.Harness, partial.RunId, partial.Harness))
	}
	return lines
}

// The context method over target, when it hosts Sidecars.
func urStatusContextMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	hosting, ok := target.(urStatusCoverageTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name: urMethodStatusContext,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			reply := &urStatusContextReply{}
			for _, network := range hosting.hosted() {
				if network.Sidecar == nil {
					continue
				}
				reply.Lines = append(reply.Lines, urStatusContextLines(network.NetworkId, network.Sidecar.SessionGatewayContextPartial())...)
			}
			return reply, nil
		},
	}}
}

// The context lines, after status's own; nothing for a daemon that does not answer, since status said why.
func printUrStatusContext(ctx context.Context, cli *urCli) {
	reply := &urStatusContextReply{}
	if err := cli.callDaemon(ctx, urMethodStatusContext, struct{}{}, false, reply); err != nil {
		return
	}
	printUrStatusContextReply(cli, reply)
}

// The reply's lines as the daemon gave them.
func printUrStatusContextReply(cli *urCli, reply *urStatusContextReply) {
	for _, line := range reply.Lines {
		fmt.Fprintf(cli.stdout, "%s\n", line)
	}
}
