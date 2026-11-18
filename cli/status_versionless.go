// `ur status`'s versionless lines (§11.7's cli row; R-EVS-26, I-13; EVS2-M10-23): for each repo the daemon reports, its
// versionless files' bytes, its search index's bytes apart from content, and the versioned paths whose history holds
// most of its storage (sidecar.EvsStorageStatusLines), with ids, counts and the person's own path names only.
//
// The daemon answers them from its evs clients, which its composition builds once it builds an evs client for each
// network: urDaemonVersionless is that seam, as urDaemonCoverage is coverage's. No host builds one yet (CORE's), so until
// it does the daemon answers that it keeps no evs client and `ur status` says so in one line.

package main

import (
	"context"
	"errors"

	"github.com/urnetwork/sidecar"
)

// The control method `ur status` reads the versionless lines by.
const urMethodStatusVersionless = "status.versionless"

// A hosted Sidecar's versionless lines, which the daemon's composition assigns once it builds an evs client; nil until
// then.
var urDaemonVersionless func(ctx context.Context, running *sidecar.Sidecar) ([]string, error)

// What the daemon answers while it builds no evs client.
var errUrNoVersionlessSource = errors.New("this daemon builds no evs client for its networks yet")

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urStatusVersionlessMethods)
	urStatusSections = append(urStatusSections, printUrStatusVersionless)
}

// status.versionless's reply: each hosted network's lines, as coverage's.
type urStatusVersionlessReply struct {
	Networks []*urNetworkCoverage `json:"networks,omitempty"`
}

// The method over target, when it hosts Sidecars.
func urStatusVersionlessMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	hosting, ok := target.(urStatusCoverageTarget)
	if !ok {
		return nil
	}
	return []*sidecar.DaemonMethod{{
		Name: urMethodStatusVersionless,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			reply := &urStatusVersionlessReply{}
			for _, network := range hosting.hosted() {
				entry := &urNetworkCoverage{NetworkId: network.NetworkId}
				switch {
				case urDaemonVersionless == nil:
					entry.Unknown = errUrNoVersionlessSource.Error()
				default:
					lines, err := urDaemonVersionless(ctx, network.Sidecar)
					if err != nil {
						entry.Unknown = err.Error()
					}
					entry.Lines = lines
				}
				reply.Networks = append(reply.Networks, entry)
			}
			return reply, nil
		},
	}}
}

// Prints each network's versionless lines, or why it has none; a daemon without the method prints nothing.
func printUrStatusVersionless(ctx context.Context, cli *urCli) {
	reply := &urStatusVersionlessReply{}
	if err := cli.callDaemon(ctx, urMethodStatusVersionless, struct{}{}, false, reply); err != nil {
		return
	}
	for _, network := range reply.Networks {
		if network.Unknown != "" {
			cli.printf("versionless %s: %s\n", network.NetworkId, network.Unknown)
			continue
		}
		for _, line := range network.Lines {
			cli.printf("versionless %s: %s\n", network.NetworkId, line)
		}
	}
}
