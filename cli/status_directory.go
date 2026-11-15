// `ur status`'s directory lines (§16.11's revoke and readers rows; RECORD-M6-20; plan-RECORD-small-readings#13): for
// each hosted team network, this device's revocations still waiting for the directory's erasure runner, each with its
// age, and on a directory admin's device each erasure request waiting past 24 h and the oldest waiting
// (sidecar.DirectoryClient.ErasureStatusLines). A personal network, or a team whose directory does not exist yet,
// prints nothing. The lines carry ids and ages only (I-13).

package main

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar"
)

// The control method `ur status` reads the directory's lines by.
const urMethodStatusDirectory = "status.directory"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urStatusDirectoryMethods)
	urStatusSections = append(urStatusSections, printUrStatusDirectory)
}

// One hosted network's directory lines.
type urNetworkDirectoryLines struct {
	NetworkId sidecar.Id `json:"network_id"`
	Lines     []string   `json:"lines,omitempty"`
}

// status.directory's reply: each hosted network with a line to show.
type urStatusDirectoryReply struct {
	Networks []*urNetworkDirectoryLines `json:"networks,omitempty"`
}

// The directory method over target, when it hosts Sidecars.
func urStatusDirectoryMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	hosting, ok := target.(urStatusCoverageTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodStatusDirectory,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				return urStatusDirectoryOf(hosting.hosted(), urDirectoryErasureLines), nil
			},
		},
	}
}

// A hosted Sidecar's directory lines: its team directory's, none outside a team network.
func urDirectoryErasureLines(running *sidecar.Sidecar) []string {
	if running == nil {
		return nil
	}
	client := running.Directory()
	if client == nil {
		return nil
	}
	return client.ErasureStatusLines(nil)
}

// Each hosted network's lines through lines, a network with none left out.
func urStatusDirectoryOf(hosted []sidecar.DaemonNetwork, lines func(running *sidecar.Sidecar) []string) *urStatusDirectoryReply {
	reply := &urStatusDirectoryReply{}
	for _, network := range hosted {
		networkLines := lines(network.Sidecar)
		if len(networkLines) == 0 {
			continue
		}
		reply.Networks = append(reply.Networks, &urNetworkDirectoryLines{NetworkId: network.NetworkId, Lines: networkLines})
	}
	return reply
}

// The directory lines, after status's own: a daemon that does not answer the method says so in one line.
func printUrStatusDirectory(ctx context.Context, cli *urCli) {
	reply := &urStatusDirectoryReply{}
	if err := cli.callDaemon(ctx, urMethodStatusDirectory, struct{}{}, false, reply); err != nil {
		fmt.Fprintf(cli.stdout, "directory:  not read: %s\n", err)
		return
	}
	printUrDirectoryReply(cli, reply)
}

// Each network's lines as the daemon gave them.
func printUrDirectoryReply(cli *urCli, reply *urStatusDirectoryReply) {
	for _, network := range reply.Networks {
		for _, line := range network.Lines {
			fmt.Fprintf(cli.stdout, "%s\n", line)
		}
	}
}
