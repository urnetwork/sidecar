//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon reads addresses, grants and rules from the same verified revision used to file bridge changes.
package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The advertised routes and maps in the verified ledger.
func (self *BridgeFiler) ListRules(ctx context.Context) ([]*BridgeLedgerRule, error) {
	view, err := self.view(ctx)
	if err != nil {
		return nil, err
	}
	return slices.Concat(view.ledger.Rules(bridge.SignedType_SIGNED_BRIDGE_ROUTE), view.ledger.Rules(bridge.SignedType_SIGNED_BRIDGE_MAP)), nil
}

// Resolves an overlay address or a private sidecar label from the verified head and ledger.
func (self *BridgeFiler) ResolvePeer(ctx context.Context, name string) (Id, error) {
	view, err := self.view(ctx)
	if err != nil {
		return Id{}, err
	}
	if addr, err := netip.ParseAddr(name); err == nil && addr.Is4() {
		octets := addr.As4()
		address := binary.BigEndian.Uint32(octets[:])
		for _, row := range view.ledger.Addresses() {
			if block := view.block.GetIpv4Prefix(); block != nil && block.GetAddress()|row.HostBits == address {
				return row.SidecarId, nil
			}
			if block := view.block.GetPreviousPrefix(); block != nil && self.clock.Now().UnixMilli() < view.block.GetDrainUntil() &&
				block.GetAddress()|row.HostBits == address {
				return row.SidecarId, nil
			}
		}
	} else if view.head != nil {
		names, err := view.head.Names()
		if err != nil {
			return Id{}, err
		}
		var rows []*bridge.SidecarRow
		for _, id := range view.state.SidecarIds() {
			rows = append(rows, view.state.SidecarRow(id))
		}
		labels, err := ConfigNames(names, rows, nil)
		if err != nil {
			return Id{}, err
		}
		for id, label := range labels {
			if strings.EqualFold(strings.TrimSuffix(name, "."), label) {
				return id, nil
			}
		}
	}
	return Id{}, fmt.Errorf("%w: no target for %q", ErrBridgeFileRefused, name)
}

// Resolves the target and the grant that authorized the listener. A different grant cannot keep a withdrawn
// listener open; a forward filed under a standing rule may use a matching standing rule.
func (self *BridgeFiler) ForwardRoute(ctx context.Context, request *BridgeForwardRequest, grantId []byte) (*DaemonBridgeForwardRoute, error) {
	view, err := self.view(ctx)
	if err != nil {
		return nil, err
	}
	route := &DaemonBridgeForwardRoute{}
	if request == nil || request.Port == 0 {
		return route, nil
	}
	block, row := view.block.GetIpv4Prefix(), view.ledger.Address(request.Target)
	if block == nil || row == nil {
		return route, nil
	}
	route.Address = bridgeAddressOf(block.GetAddress() | row.HostBits)
	acl, err := view.state.Acl()
	if err != nil {
		return nil, err
	}
	var policy *AclLocalPolicy
	if self.args.AclLocal != nil {
		policy = self.args.AclLocal()
	}
	if policy == nil && !acl.HasDocument() {
		policy = aclImplicitLocalPolicy()
	}
	now := self.clock.Now()
	protocol := request.Protocol
	if protocol == 0 {
		protocol = bridgeProtocolTcp
	}
	for _, rule := range acl.DialRules(AclSidecarSubject(view.self), AclSidecarSubject(request.Target), now) {
		if !bytes.Equal(rule.GrantId, grantId) {
			continue
		}
		local := policy.Rule(rule.RuleId)
		if len(grantId) != 0 && rule.PortsLimited {
			actions := view.state.grantActionsAtHead(view.head)
			local = view.state.grantPortRule(actions[string(grantId)], request.Target, self.repoKeyAt())
		}
		if !aclLocalPortsMatch(rule.PortsLimited, local, protocol, request.Port) {
			continue
		}
		route.Live = true
		if rule.ExpiresMs == 0 {
			route.ExpiresAt = time.Time{}
			break
		}
		if end := time.UnixMilli(rule.ExpiresMs); route.ExpiresAt.Before(end) {
			route.ExpiresAt = end
		}
	}
	return route, nil
}
