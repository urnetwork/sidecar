// `ur status`'s coverage lines (§11.13's status row, D-EVS-17; EVSB-M2-19): for each hosted network, each repo this
// device keeps a full mirror of with its coverage, full or partial and why, each record-class repo and config no
// indexer designated for mirror keeps, a network no indexer mirrors, and each indexer with its services and the
// newest sign of it this device holds (sidecar.EvsMirrorStatusLines). The lines carry ids and counts only (I-13).
//
// The daemon answers them from its evs clients' mirrors, which its composition builds once it builds an evs client
// for each network: urDaemonCoverage is that seam. No host builds one yet (CORE's), so until it does the daemon
// answers that it keeps no mirror and `ur status` says so in one line, never a coverage it cannot read.

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
)

// The control method `ur status` reads coverage by.
const urMethodStatusCoverage = "status.coverage"

// A hosted Sidecar's coverage lines, which the daemon's composition assigns once it builds an evs client and the
// mirrors on it; nil until then.
var urDaemonCoverage func(ctx context.Context, running *sidecar.Sidecar) ([]string, error)

// What the daemon answers while it builds no evs client.
var errUrNoMirrors = errors.New("this daemon builds no evs client for its networks yet, so it keeps no mirror")

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urStatusCoverageMethods)
	urStatusSections = append(urStatusSections, printUrStatusCoverage)
}

// What prints after status's own lines, each section on what the daemon answers it.
var urStatusSections []func(ctx context.Context, cli *urCli)

// One hosted network's coverage lines, or why it has none.
type urNetworkCoverage struct {
	NetworkId sidecar.Id `json:"network_id"`
	Lines     []string   `json:"lines,omitempty"`
	// Why the network has no lines.
	Unknown string `json:"unknown,omitempty"`
}

type urStatusCoverageReply struct {
	Networks []*urNetworkCoverage `json:"networks,omitempty"`
}

// What the coverage method acts on: a target hosting Sidecars.
type urStatusCoverageTarget interface {
	hosted() []sidecar.DaemonNetwork
}

// The coverage method over target, when it hosts Sidecars.
func urStatusCoverageMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	hosting, ok := target.(urStatusCoverageTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodStatusCoverage,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				return urStatusCoverageOf(ctx, hosting.hosted(), urDaemonCoverage), nil
			},
		},
	}
}

// Each hosted network's lines through coverage, a network whose coverage fails naming why.
func urStatusCoverageOf(ctx context.Context, hosted []sidecar.DaemonNetwork,
	coverage func(ctx context.Context, running *sidecar.Sidecar) ([]string, error)) *urStatusCoverageReply {
	reply := &urStatusCoverageReply{}
	for _, network := range hosted {
		networkCoverage := &urNetworkCoverage{NetworkId: network.NetworkId}
		switch {
		case coverage == nil:
			networkCoverage.Unknown = errUrNoMirrors.Error()
		default:
			lines, err := coverage(ctx, network.Sidecar)
			if err != nil {
				networkCoverage.Unknown = err.Error()
			} else {
				networkCoverage.Lines = lines
			}
		}
		reply.Networks = append(reply.Networks, networkCoverage)
	}
	return reply
}

// The coverage lines, after status's own: a daemon that does not answer the method prints nothing more, since status
// already said why it did not answer.
func printUrStatusCoverage(ctx context.Context, cli *urCli) {
	reply := &urStatusCoverageReply{}
	if err := cli.callDaemon(ctx, urMethodStatusCoverage, struct{}{}, false, reply); err != nil {
		fmt.Fprintf(cli.stdout, "coverage:   not read: %s\n", err)
		return
	}
	printUrCoverageReply(cli, reply)
}

func printUrCoverageReply(cli *urCli, reply *urStatusCoverageReply) {
	for _, network := range reply.Networks {
		if network.Unknown != "" {
			fmt.Fprintf(cli.stdout, "coverage:   network %s unknown: %s\n", network.NetworkId, network.Unknown)
			continue
		}
		for _, line := range network.Lines {
			fmt.Fprintf(cli.stdout, "%s\n", line)
		}
	}
}
