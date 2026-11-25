// ur status's lines for §17.7.1's own-services notice (Disclosure and opt-out; owner decision 778): a network whose
// discovery publishes this computer's own services shows the notice in ur status until its person has seen it, which
// ur bridge devices and ur bridge discovery mark. A network whose bridge the daemon has not built runs no discovery, so
// publishes nothing and shows nothing.

package main

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar"
)

// The control method ur status reads the notices by.
const urMethodStatusDiscovery = "status.discovery"

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urStatusDiscoveryMethods)
	urStatusSections = append(urStatusSections, printUrStatusDiscovery)
}

// status.discovery's reply: each network's notice its person has not seen, by network id.
type urStatusDiscoveryReply struct {
	Notices []*urStatusDiscoveryNotice `json:"notices,omitempty"`
}

// One network's notice.
type urStatusDiscoveryNotice struct {
	NetworkId sidecar.Id `json:"network_id"`
	Notice    string     `json:"notice"`
}

// The notices' method over a target that hosts its networks' bridges.
func urStatusDiscoveryMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	network, ok := target.(*urDaemonNetwork)
	if !ok || network.bridges == nil {
		return nil
	}
	bridges := network.bridges
	return []*sidecar.DaemonMethod{{
		Name: urMethodStatusDiscovery,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			return urStatusDiscoveryOf(bridges), nil
		},
	}}
}

// Each built network's pending notice, by network id.
func urStatusDiscoveryOf(bridges *urBridgeDaemon) *urStatusDiscoveryReply {
	networks := func() []*urBridgeNetwork {
		bridges.stateLock.Lock()
		defer bridges.stateLock.Unlock()
		networks := []*urBridgeNetwork{}
		for _, network := range bridges.networks {
			networks = append(networks, network)
		}
		return networks
	}()
	slices.SortFunc(networks, func(a *urBridgeNetwork, b *urBridgeNetwork) int {
		return bytes.Compare(a.networkId.Bytes(), b.networkId.Bytes())
	})
	reply := &urStatusDiscoveryReply{}
	for _, network := range networks {
		if network.discovery == nil {
			continue
		}
		if notice := network.discovery.component.PendingNotice(); notice != "" {
			reply.Notices = append(reply.Notices, &urStatusDiscoveryNotice{NetworkId: network.networkId, Notice: notice})
		}
	}
	return reply
}

// The notices, after status's own lines. A daemon that does not answer the method prints nothing.
func printUrStatusDiscovery(ctx context.Context, cli *urCli) {
	reply := &urStatusDiscoveryReply{}
	if err := cli.callDaemon(ctx, urMethodStatusDiscovery, struct{}{}, false, reply); err != nil {
		return
	}
	for _, notice := range reply.Notices {
		fmt.Fprintf(cli.stdout, "notice:     network %s: %s (ur bridge devices lists what it publishes, and marks this seen)\n",
			notice.NetworkId, notice.Notice)
	}
}
