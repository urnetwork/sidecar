// The production bridge filer, address book and per-forward grant checks for one enrolled network.
package main

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar"
)

// The filer's args over a network's standing follower and its client. ur daemon's follower runs no general config
// writer, only the one a person's confirmed save takes (ConfigClient.ConfirmedWriter), which `ur bridge block` saves its
// head through (QD-1205); a share's accept and activation keep to a general one.
func urBridgeFilerArgs(running *sidecar.Sidecar, follower *sidecar.SidecarConfigFollower, client *sidecar.ConfigClient, grants *sidecar.AclGrantFiler) *sidecar.BridgeFilerArgs {
	return &sidecar.BridgeFilerArgs{
		Sidecar: running, Config: client, Heads: follower.Heads(), Grants: grants, AclLocal: follower.AclLocal,
		HeadWriter: func() sidecar.BridgeHeadWriter {
			if writer := client.Writer(); writer != nil {
				return writer
			}
			return nil
		},
		ConfirmedHeadWriter: func() sidecar.BridgeHeadWriter {
			if writer := client.ConfirmedWriter(); writer != nil {
				return writer
			}
			return nil
		},
	}
}

// Both control and MCP reach this network's own signer and verified log. The effect lookups retire with the wire.
func newUrBridgeFilingNetwork(wire *urBridgeWire, running *sidecar.Sidecar, follower *sidecar.SidecarConfigFollower, client *sidecar.ConfigClient) (*urBridgeNetwork, error) {
	identity := running.Identity()
	engine := follower.AclEngine()
	acl := follower.AclFollower()
	if identity == nil || engine == nil || acl == nil {
		wire.close()
		return nil, errUrBridgeUnwired
	}
	grants := sidecar.NewAclGrantFiler(running, engine)
	filer, err := sidecar.NewBridgeFiler(urBridgeFilerArgs(running, follower, client, grants))
	if err != nil {
		wire.close()
		return nil, err
	}
	network := wire.network()
	network.config = &urBridgeConfig{
		SidecarId: identity.SidecarId, Filer: filer, Rules: filer.ListRules,
		Resolve: filer.ResolvePeer, grantsChanged: acl.GrantsChanged,
		ForwardRoute: func(ctx context.Context, request *sidecar.BridgeForwardRequest, grantId []byte) (*sidecar.DaemonBridgeForwardRoute, error) {
			if follower.Client() != client || client.Fork() != nil {
				return &sidecar.DaemonBridgeForwardRoute{}, nil
			}
			return filer.ForwardRoute(ctx, request, grantId)
		},
		Names: func() []*sidecar.DaemonBridgeName {
			compiled := wire.component.Compiled()
			if compiled == nil || compiled.State == nil {
				return nil
			}
			var names []*sidecar.DaemonBridgeName
			for label, raw := range compiled.State.GetNames() {
				var address [4]byte
				binary.BigEndian.PutUint32(address[:], raw)
				names = append(names, &sidecar.DaemonBridgeName{Name: label, Address: netip.AddrFrom4(address).String()})
			}
			slices.SortFunc(names, func(a, b *sidecar.DaemonBridgeName) int { return strings.Compare(a.Name, b.Name) })
			return names
		},
	}
	removeForward := running.RegisterEffectLookup(sidecar.SidecarActionForward, grants.Lookup)
	removeRules := filer.Register()
	gate, removeGate, err := running.InstallApprovalGateIfAbsent(&sidecar.ApprovalGateSources{
		Grants: engine,
		States: func() (sidecar.ApprovalStates, error) {
			if follower.Client() != client || client.Fork() != nil {
				return nil, sidecar.ErrApprovalNoState
			}
			return sidecar.NewConfigApprovalStates(client.State(), false, follower.AclLocal())
		},
	})
	if err == nil && gate != nil {
		_, err = gate.Reconcile(wire.host.ctx)
	}
	if err != nil {
		if removeGate != nil {
			removeGate()
		}
		removeRules()
		removeForward()
		wire.close()
		return nil, err
	}
	if gate != nil {
		go gate.Inbox().Run(wire.host.ctx)
	}
	// §17.7.1's discovery beside the bridge, its shares filing through this network's filer (owner decision 778); a
	// network whose discovery does not build keeps its bridge, and discovery's methods answer that none runs
	discovery, err := newUrBridgeDiscovery(wire, running, follower.AclLocal, filer)
	if err != nil && wire.args.Log != nil {
		wire.args.Log.Warningf("[discovery]%s discovery did not start: %v", wire.args.NetworkId, err)
	}
	network.discovery = discovery
	network.close = func() {
		if discovery != nil {
			discovery.close()
		}
		if removeGate != nil {
			removeGate()
		}
		removeRules()
		removeForward()
		wire.close()
	}
	return network, nil
}
