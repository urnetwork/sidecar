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
	filer, err := sidecar.NewBridgeFiler(&sidecar.BridgeFilerArgs{
		Sidecar: running, Config: client, Heads: follower.Heads(), Grants: grants, AclLocal: follower.AclLocal,
		HeadWriter: func() sidecar.BridgeHeadWriter {
			if writer := client.Writer(); writer != nil {
				return writer
			}
			return nil
		},
	})
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
	network.close = func() {
		if removeGate != nil {
			removeGate()
		}
		removeRules()
		removeForward()
		wire.close()
	}
	return network, nil
}
