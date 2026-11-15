//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's share methods (BRIDGE-M6-03; §17.9, §17.11; I-8, I-13): what `ur bridge invite` and
// `ur bridge accept-invite` call, each over one network's backend, whose acts are BridgeFiler's (bridge_share_invite.go).
//
//	bridge.invite         seals the targets and posts the invite; answers the share's id and the code, once
//	bridge.accept_invite  accepts an invite by its code; answers the aliases in force, or the refusal's figures
//
// Both are DaemonMethod{Confirm: true}: the daemon runs them only from control with the ur's confirmation, never from
// mcp or hook (D-CORE-9), and the filer holds them to a person's confirmation and an admin's device again. A backend
// that offers no share acts answers ErrDaemonBridgeUnwired.
//
// The code is the one secret a reply carries: it reaches the person's terminal alone, and no log names it (I-13).
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The share's control methods.
const (
	DaemonMethodBridgeInvite       = "bridge.invite"
	DaemonMethodBridgeAcceptInvite = "bridge.accept_invite"
)

// The share acts a backend offers beside DaemonBridgeBackend's filings: BridgeFiler's own.
type DaemonBridgeShareBackend interface {
	Invite(ctx context.Context, origin *BridgeFileOrigin, request *BridgeShareInviteRequest) (*BridgeShareInvite, error)
	AcceptInvite(ctx context.Context, origin *BridgeFileOrigin, code []byte) (*BridgeShareAccepted, error)
}

var _ DaemonBridgeShareBackend = (*BridgeFiler)(nil)

// One target of bridge.invite.
type DaemonBridgeShareTargetParams struct {
	// The host as a person names it: a sidecar id, a private name or an overlay address.
	Host string `json:"host"`
	// What the host reaches for the other network: an IPv4 prefix.
	Prefix string `json:"prefix"`
	// "" for every protocol, or tcp or udp with ports.
	Protocol  string `json:"protocol,omitempty"`
	FirstPort uint32 `json:"first_port,omitempty"`
	LastPort  uint32 `json:"last_port,omitempty"`
}

// bridge.invite's params.
type DaemonBridgeInviteParams struct {
	Network string                           `json:"network,omitempty"`
	Targets []*DaemonBridgeShareTargetParams `json:"targets"`
}

// bridge.invite's answer. Code is shown to the person once and kept nowhere.
type DaemonBridgeInviteReply struct {
	ShareId    Id         `json:"share_id"`
	Code       string     `json:"code"`
	UseCount   int        `json:"use_count,omitempty"`
	ExpireTime *time.Time `json:"expire_time,omitempty"`
}

// bridge.accept_invite's params.
type DaemonBridgeAcceptInviteParams struct {
	Network string `json:"network,omitempty"`
	Code    string `json:"code"`
}

// One alias of an accepted share: the target's index and its block in this network's upper half.
type DaemonBridgeShareAlias struct {
	Index    uint32 `json:"index"`
	HostBits uint32 `json:"host_bits"`
	Length   uint32 `json:"length"`
}

// bridge.accept_invite's answer: the share active with its aliases, or refused with the room there was.
type DaemonBridgeAcceptInviteReply struct {
	ShareId          *Id                       `json:"share_id,omitempty"`
	SharingNetworkId *Id                       `json:"sharing_network_id,omitempty"`
	Status           string                    `json:"status"`
	Aliases          []*DaemonBridgeShareAlias `json:"aliases,omitempty"`
	// A refusal's figures: the target that did not fit and its length, the addresses free, and the largest free block.
	RefusedIndex      uint32 `json:"refused_index,omitempty"`
	RefusedLength     uint32 `json:"refused_length,omitempty"`
	FreeAddressCount  uint32 `json:"free_address_count,omitempty"`
	LargestFreeLength uint32 `json:"largest_free_length,omitempty"`
}

// An invite's code as a person carries it: base64url of its 32 bytes, unpadded.
func FormatBridgeShareCode(code []byte) string {
	return base64.RawURLEncoding.EncodeToString(code)
}

// The code a person typed, or ErrDaemonBridgeParams for text that is none. The error never quotes the text.
func ParseBridgeShareCode(text string) ([]byte, error) {
	code, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(code) != bridgeShareCodeByteCount {
		return nil, fmt.Errorf("%w: an invite's code is %d characters of base64url", ErrDaemonBridgeParams, base64.RawURLEncoding.EncodedLen(bridgeShareCodeByteCount))
	}
	return code, nil
}

// The share methods, registered beside Methods' on a network's daemon target.
func (self *DaemonBridges) ShareMethods() []*DaemonMethod {
	return []*DaemonMethod{
		{
			Name:    DaemonMethodBridgeInvite,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeInviteParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				return self.Invite(ctx, call.NetworkId, call.Sidecar, daemonBridgeOrigin(call), params)
			},
		},
		{
			Name:    DaemonMethodBridgeAcceptInvite,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeAcceptInviteParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				return self.AcceptInvite(ctx, call.NetworkId, call.Sidecar, daemonBridgeOrigin(call), params)
			},
		},
	}
}

// The network's backend and its share acts, for a person's confirmed call alone.
func (self *DaemonBridges) shareBackend(ctx context.Context, networkId Id, running *Sidecar, origin *BridgeFileOrigin) (DaemonBridgeBackend, DaemonBridgeShareBackend, error) {
	if origin == nil || origin.Act != SidecarActConfirmed {
		return nil, nil, fmt.Errorf("%w: a share takes a person's confirmation", ErrBridgeFileRefused)
	}
	backend, err := self.backend(ctx, networkId, running)
	if err != nil {
		return nil, nil, err
	}
	shares, ok := backend.(DaemonBridgeShareBackend)
	if !ok {
		return nil, nil, ErrDaemonBridgeUnwired
	}
	return backend, shares, nil
}

// Invites another network to the targets. The daemon runs it only for a person's confirmed control call.
func (self *DaemonBridges) Invite(ctx context.Context, networkId Id, running *Sidecar, origin *BridgeFileOrigin, params *DaemonBridgeInviteParams) (*DaemonBridgeInviteReply, error) {
	backend, shares, err := self.shareBackend(ctx, networkId, running, origin)
	if err != nil {
		return nil, err
	}
	if len(params.Targets) == 0 {
		return nil, fmt.Errorf("%w: an invite names at least one target", ErrDaemonBridgeParams)
	}
	request := &BridgeShareInviteRequest{}
	for index, target := range params.Targets {
		if target == nil {
			return nil, fmt.Errorf("%w: target %d is empty", ErrDaemonBridgeParams, index)
		}
		host, err := backend.ResolveSidecar(ctx, target.Host)
		if err != nil {
			return nil, err
		}
		prefix, err := netip.ParsePrefix(target.Prefix)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("%w: target %d's prefix is no ipv4 prefix", ErrDaemonBridgeParams, index)
		}
		entry := &BridgeShareTargetRequest{Host: host, Prefix: prefix.Masked()}
		switch target.Protocol {
		case "":
			if target.FirstPort != 0 || target.LastPort != 0 {
				return nil, fmt.Errorf("%w: target %d names ports and no protocol", ErrDaemonBridgeParams, index)
			}
		case daemonBridgeProtocolTcp, daemonBridgeProtocolUdp:
			entry.Protocol = bridgeProtocolTcp
			if target.Protocol == daemonBridgeProtocolUdp {
				entry.Protocol = bridgeProtocolUdp
			}
			last := max(target.FirstPort, target.LastPort)
			if target.FirstPort == 0 || 65535 < last {
				return nil, fmt.Errorf("%w: target %d's ports", ErrDaemonBridgeParams, index)
			}
			entry.Ports = []*bridge.BridgePortRange{{First: target.FirstPort, Last: last}}
		default:
			return nil, fmt.Errorf("%w: target %d's protocol is tcp or udp", ErrDaemonBridgeParams, index)
		}
		request.Targets = append(request.Targets, entry)
	}
	invite, err := shares.Invite(ctx, origin, request)
	if err != nil {
		return nil, err
	}
	reply := &DaemonBridgeInviteReply{ShareId: invite.ShareId, Code: FormatBridgeShareCode(invite.Code), UseCount: invite.UseCount}
	if !invite.ExpireTime.IsZero() {
		expireTime := invite.ExpireTime
		reply.ExpireTime = &expireTime
	}
	return reply, nil
}

// Accepts an invite by its code. A refusal for size or room is an answer, with its figures, not an error: the
// sharing network was told, and the person reads why. The daemon runs it only for a person's confirmed control call.
func (self *DaemonBridges) AcceptInvite(ctx context.Context, networkId Id, running *Sidecar, origin *BridgeFileOrigin, params *DaemonBridgeAcceptInviteParams) (*DaemonBridgeAcceptInviteReply, error) {
	_, shares, err := self.shareBackend(ctx, networkId, running, origin)
	if err != nil {
		return nil, err
	}
	code, err := ParseBridgeShareCode(params.Code)
	if err != nil {
		return nil, err
	}
	accepted, err := shares.AcceptInvite(ctx, origin, code)
	if refusal := (*BridgeShareRefusal)(nil); errors.As(err, &refusal) {
		status := BridgeShareAcceptStatusRefusedNoSpace
		if errors.Is(refusal.Reason, ErrBridgeShareTooLarge) {
			status = BridgeShareAcceptStatusRefusedTooLarge
		}
		return &DaemonBridgeAcceptInviteReply{
			Status: string(status), RefusedIndex: refusal.Shortfall.GetIndex(), RefusedLength: refusal.Shortfall.GetLength(),
			FreeAddressCount: refusal.Shortfall.GetFreeAddressCount(), LargestFreeLength: refusal.Shortfall.GetLargestFreeLength(),
		}, nil
	}
	if err != nil {
		return nil, err
	}
	shareId, sharingNetworkId := accepted.ShareId, accepted.SharingNetworkId
	reply := &DaemonBridgeAcceptInviteReply{ShareId: &shareId, SharingNetworkId: &sharingNetworkId, Status: string(accepted.Status)}
	for _, alias := range accepted.Aliases {
		reply.Aliases = append(reply.Aliases, &DaemonBridgeShareAlias{Index: alias.GetIndex(), HostBits: alias.GetAliasHostBits(), Length: alias.GetLength()})
	}
	return reply, nil
}
