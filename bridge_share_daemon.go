//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's share methods (BRIDGE-M6-03; §17.9, §17.11; DESIGN-DETAILS 12.2.7; QD-831; I-8, I-13): what
// `ur bridge invite`, `ur bridge accept-invite` and `ur bridge activate` call, each over one network's backend, whose
// acts are BridgeFiler's (bridge_share_invite.go).
//
//	bridge.invite         seals the targets and posts the invite; answers the share's id and the code, once
//	bridge.accept_invite  accepts an invite by its code; answers the aliases in force, or the refusal's figures
//	bridge.activate       the sharing network's approving admin's two calls on one share. Without a preview digest it
//	                      answers the share as PreviewShare opens it (Y's network, each target with its alias, the
//	                      ShareKey's fingerprint, both tables' hashes) and the preview's digest, and files nothing.
//	                      With the digest the person confirmed, it opens the share again, refuses it unless it still
//	                      digests to what was shown, and runs ActivateShare on that preview, which refuses a row that
//	                      changed after its own fetch; it answers the filing, or the approval it waits on
//
// All three are DaemonMethod{Confirm: true}: the daemon runs them only from control with the ur's confirmation, never
// from mcp or hook (D-CORE-9), and the filer holds them to a person's confirmation and an admin's device again. A
// backend that offers no share acts answers ErrDaemonBridgeUnwired. bridge.activate's first call carries the
// confirmation too, since the filer opens a share only for a confirmed origin: ur sends it only with a terminal to ask
// on, shows its answer on that terminal, and sends the second call only on the person's yes, carrying the digest of
// exactly what was shown. The activation stays apart from the invite: another admin may approve.
//
// The code is the one secret a reply carries: it reaches the person's terminal alone, and no log names it (I-13). A
// preview carries no key: the ShareKey reaches ur as its fingerprint.
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The share's control methods.
const (
	DaemonMethodBridgeInvite       = "bridge.invite"
	DaemonMethodBridgeAcceptInvite = "bridge.accept_invite"
	DaemonMethodBridgeActivate     = "bridge.activate"
)

// The format values of what ur shows of a share: the preview digest's domain, and the hex digits of each group of a
// ShareKey's fingerprint.
const (
	bridgeSharePreviewDigestDomain       = "urnetwork-sidecar-v1/bridge-share-preview"
	bridgeShareKeyFingerprintGroupDigits = 4
)

// The share acts a backend offers beside DaemonBridgeBackend's filings: BridgeFiler's own.
type DaemonBridgeShareBackend interface {
	Invite(ctx context.Context, origin *BridgeFileOrigin, request *BridgeShareInviteRequest) (*BridgeShareInvite, error)
	AcceptInvite(ctx context.Context, origin *BridgeFileOrigin, code []byte) (*BridgeShareAccepted, error)
	PreviewShare(ctx context.Context, origin *BridgeFileOrigin, shareId Id) (*BridgeSharePreview, error)
	ActivateShare(ctx context.Context, origin *BridgeFileOrigin, preview *BridgeSharePreview, lifetime time.Duration) (*BridgeFiling, error)
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
	// The ShareKey's fingerprint (FormatBridgeShareKeyFingerprint) for an active share: what the sharing network's
	// approving admin is shown before activating, for the two admins to compare.
	ShareKeyFingerprint string `json:"share_key_fingerprint,omitempty"`
	// A refusal's figures: the target that did not fit and its length, the addresses free, and the largest free block.
	RefusedIndex      uint32 `json:"refused_index,omitempty"`
	RefusedLength     uint32 `json:"refused_length,omitempty"`
	FreeAddressCount  uint32 `json:"free_address_count,omitempty"`
	LargestFreeLength uint32 `json:"largest_free_length,omitempty"`
}

// bridge.activate's params. Without PreviewDigest the call answers the share's preview and files nothing; with it, the
// call activates the share as that preview showed it.
type DaemonBridgeActivateParams struct {
	Network string `json:"network,omitempty"`
	ShareId Id     `json:"share_id"`
	// The preview's digest the person confirmed, hex, as DaemonBridgeSharePreview.PreviewDigest answered it.
	PreviewDigest string `json:"preview_digest,omitempty"`
}

// One target of a share as its approving admin is shown it, with the alias the accepting network gave it.
type DaemonBridgeShareTarget struct {
	Index uint32 `json:"index"`
	// The host of this network that serves the target.
	HostSidecarId Id `json:"host_sidecar_id"`
	// What the host reaches for the other network: an IPv4 prefix.
	Prefix string `json:"prefix"`
	// "" for every protocol, or tcp or udp with its port ranges, each "<port>" or "<first>-<last>".
	Protocol string   `json:"protocol,omitempty"`
	Ports    []string `json:"ports,omitempty"`
	// Its block in the accepting network's upper half; nil until that network accepted.
	Alias *DaemonBridgeShareAlias `json:"alias,omitempty"`
}

// bridge.activate's answer to a call with no preview digest: the share as its approving admin is shown it before
// approving (DESIGN-DETAILS 12.2.7's activate row), as PreviewShare opened it, and the digest a confirmed call sends
// back. A confirmed call with the digest answers DaemonBridgeFilingReply instead.
type DaemonBridgeSharePreview struct {
	ShareId Id `json:"share_id"`
	// Y, the network that accepted the invite; nil while the invite is open.
	AcceptingNetworkId *Id `json:"accepting_network_id,omitempty"`
	// network_bridge_share.accept_status: "" while the invite is open, active, or a refusal's.
	Status  string                     `json:"status"`
	Targets []*DaemonBridgeShareTarget `json:"targets"`
	// The ShareKey's fingerprint (FormatBridgeShareKeyFingerprint); empty unless the share is active.
	ShareKeyFingerprint string `json:"share_key_fingerprint,omitempty"`
	// Each table's SHA-256 as the row stores it, hex, and its version: what the activation pins. The alias table's
	// are empty while the invite is open.
	TargetTableSha256  string `json:"target_table_sha256"`
	TargetTableVersion uint64 `json:"target_table_version"`
	AliasTableSha256   string `json:"alias_table_sha256,omitempty"`
	AliasTableVersion  uint64 `json:"alias_table_version,omitempty"`
	// A refusal's figures, as bridge.accept_invite answers them.
	RefusedIndex      uint32 `json:"refused_index,omitempty"`
	RefusedLength     uint32 `json:"refused_length,omitempty"`
	FreeAddressCount  uint32 `json:"free_address_count,omitempty"`
	LargestFreeLength uint32 `json:"largest_free_length,omitempty"`
	// What the confirmed call sends back, hex: the SHA-256 of everything the activation is held to.
	PreviewDigest string `json:"preview_digest"`
}

// An invite's code as a person carries it: base64url of its 32 bytes, unpadded.
func FormatBridgeShareCode(code []byte) string {
	return base64.RawURLEncoding.EncodeToString(code)
}

// A ShareKey's fingerprint as ur shows it on both sides of a share: the SHA-256 of its public key in lowercase hex, in
// groups of four digits, which the two networks' admins can read to each other.
func FormatBridgeShareKeyFingerprint(sharePublicKey []byte) string {
	sum := sha256.Sum256(sharePublicKey)
	digits := hex.EncodeToString(sum[:])
	groups := make([]string, 0, len(digits)/bridgeShareKeyFingerprintGroupDigits)
	for start := 0; start < len(digits); start += bridgeShareKeyFingerprintGroupDigits {
		groups = append(groups, digits[start:start+bridgeShareKeyFingerprintGroupDigits])
	}
	return strings.Join(groups, " ")
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
		{
			Name:    DaemonMethodBridgeActivate,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeActivateParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				if params.PreviewDigest == "" {
					return self.PreviewShare(ctx, call.NetworkId, call.Sidecar, daemonBridgeOrigin(call), params)
				}
				return self.ActivateShare(ctx, call.NetworkId, call.Sidecar, daemonBridgeOrigin(call), params)
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
	if len(accepted.SharePublicKey) != 0 {
		reply.ShareKeyFingerprint = FormatBridgeShareKeyFingerprint(accepted.SharePublicKey)
	}
	return reply, nil
}

// The share as PreviewShare opens it for the network's share acts, held to the share asked for.
func (self *DaemonBridges) openShare(ctx context.Context, shares DaemonBridgeShareBackend, origin *BridgeFileOrigin, shareId Id) (*BridgeSharePreview, error) {
	if shareId == (Id{}) {
		return nil, fmt.Errorf("%w: an activation names its share", ErrDaemonBridgeParams)
	}
	preview, err := shares.PreviewShare(ctx, origin, shareId)
	if err != nil {
		return nil, err
	}
	if preview == nil || preview.ShareId != shareId {
		return nil, fmt.Errorf("%w: the preview is another share's", ErrBridgeFileRefused)
	}
	return preview, nil
}

// Shows a share this device invited to the network's approving admin (DESIGN-DETAILS 12.2.7's activate row): Y's
// network, each target with its alias, the ShareKey's fingerprint, both tables' hashes, and the digest the
// confirmation sends back. Files nothing. The daemon runs it only for a person's confirmed control call.
func (self *DaemonBridges) PreviewShare(ctx context.Context, networkId Id, running *Sidecar, origin *BridgeFileOrigin, params *DaemonBridgeActivateParams) (*DaemonBridgeSharePreview, error) {
	_, shares, err := self.shareBackend(ctx, networkId, running, origin)
	if err != nil {
		return nil, err
	}
	preview, err := self.openShare(ctx, shares, origin, params.ShareId)
	if err != nil {
		return nil, err
	}
	return daemonBridgeSharePreviewOf(preview)
}

// Activates a share as the preview the person confirmed showed it. The share is opened again and must digest to what
// was shown, or it is refused and nothing is filed; ActivateShare then holds its own fetch to that preview, files the
// share's grant through §5.4's gate and writes its pin file. A filing that waits for a person's decision answers the
// approval's id, and the same call again once it lands files nothing twice (ActivateShare keeps the grant's id). The
// daemon runs it only for a person's confirmed control call.
func (self *DaemonBridges) ActivateShare(ctx context.Context, networkId Id, running *Sidecar, origin *BridgeFileOrigin, params *DaemonBridgeActivateParams) (*DaemonBridgeFilingReply, error) {
	_, shares, err := self.shareBackend(ctx, networkId, running, origin)
	if err != nil {
		return nil, err
	}
	shown, err := hex.DecodeString(params.PreviewDigest)
	if err != nil || len(shown) != sha256.Size {
		return nil, fmt.Errorf("%w: an activation sends back the digest of the preview the person confirmed", ErrDaemonBridgeParams)
	}
	preview, err := self.openShare(ctx, shares, origin, params.ShareId)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(bridgeSharePreviewDigest(preview), shown) {
		return nil, fmt.Errorf("%w: %w: the share changed after it was shown: ur bridge activate shows it as it is now", ErrBridgeFileRefused, ErrBridgeShareTableMismatch)
	}
	// 0 is the grant's rule's lifetime
	return daemonBridgeFilingReply(shares.ActivateShare(ctx, origin, preview, 0))
}

// A preview's digest: SHA-256 over the domain, a 0x00, the share's id and Y's, then the status, each table's hash and
// version and the ShareKey, each variable field after its length as a u64be. Everything ActivateShare holds a preview
// to is in it, and the target table's hash besides, so a confirmation sends back exactly what the person saw.
func bridgeSharePreviewDigest(preview *BridgeSharePreview) []byte {
	hash := sha256.New()
	hash.Write([]byte(bridgeSharePreviewDigestDomain))
	hash.Write([]byte{0x00})
	hash.Write(preview.ShareId.Bytes())
	hash.Write(preview.AcceptingNetworkId.Bytes())
	writeUint64 := func(value uint64) {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value)
		hash.Write(encoded[:])
	}
	writeField := func(field []byte) {
		writeUint64(uint64(len(field)))
		hash.Write(field)
	}
	writeField([]byte(preview.Status))
	writeField(preview.TargetTableSha256)
	writeUint64(preview.TargetTableVersion)
	writeField(preview.AliasTableSha256)
	writeUint64(preview.AliasTableVersion)
	writeField(preview.SharePublicKey)
	return hash.Sum(nil)
}

// The preview as bridge.activate answers it (DaemonBridgeSharePreview). The filer checked both tables' form as it
// opened them; a target that does not read refuses the preview rather than showing less than the share holds.
func daemonBridgeSharePreviewOf(preview *BridgeSharePreview) (*DaemonBridgeSharePreview, error) {
	shown := &DaemonBridgeSharePreview{
		ShareId: preview.ShareId, Status: string(preview.Status), Targets: []*DaemonBridgeShareTarget{},
		TargetTableSha256: hex.EncodeToString(preview.TargetTableSha256), TargetTableVersion: preview.TargetTableVersion,
		AliasTableSha256: hex.EncodeToString(preview.AliasTableSha256), AliasTableVersion: preview.AliasTableVersion,
		PreviewDigest: hex.EncodeToString(bridgeSharePreviewDigest(preview)),
	}
	if preview.AcceptingNetworkId != (Id{}) {
		acceptingNetworkId := preview.AcceptingNetworkId
		shown.AcceptingNetworkId = &acceptingNetworkId
	}
	if len(preview.SharePublicKey) != 0 {
		shown.ShareKeyFingerprint = FormatBridgeShareKeyFingerprint(preview.SharePublicKey)
	}
	indexAliases := map[uint32]*bridge.BridgeShareAlias{}
	for _, alias := range preview.Aliases {
		indexAliases[alias.GetIndex()] = alias
	}
	for _, target := range preview.Targets {
		host, err := IdFromBytes(target.GetHostSidecarId())
		if err != nil {
			return nil, fmt.Errorf("%w: %w: target %d names no host", ErrBridgeFileRefused, ErrBridgeShareTableInvalid, target.GetIndex())
		}
		prefix, err := bridgePrefixOf(target.GetPrefix())
		if err != nil {
			return nil, fmt.Errorf("%w: %w: target %d's prefix", ErrBridgeFileRefused, ErrBridgeShareTableInvalid, target.GetIndex())
		}
		shownTarget := &DaemonBridgeShareTarget{Index: target.GetIndex(), HostSidecarId: host, Prefix: prefix.String()}
		switch target.GetProtocol() {
		case 0:
		case bridgeProtocolTcp:
			shownTarget.Protocol = daemonBridgeProtocolTcp
		case bridgeProtocolUdp:
			shownTarget.Protocol = daemonBridgeProtocolUdp
		default:
			return nil, fmt.Errorf("%w: %w: target %d's protocol", ErrBridgeFileRefused, ErrBridgeShareTableInvalid, target.GetIndex())
		}
		for _, ports := range target.GetPorts() {
			text := strconv.FormatUint(uint64(ports.GetFirst()), 10)
			if ports.GetFirst() != ports.GetLast() {
				text += "-" + strconv.FormatUint(uint64(ports.GetLast()), 10)
			}
			shownTarget.Ports = append(shownTarget.Ports, text)
		}
		if alias := indexAliases[target.GetIndex()]; alias != nil {
			shownTarget.Alias = &DaemonBridgeShareAlias{Index: alias.GetIndex(), HostBits: alias.GetAliasHostBits(), Length: alias.GetLength()}
		}
		shown.Targets = append(shown.Targets, shownTarget)
	}
	if shortfall := preview.Shortfall; shortfall != nil {
		shown.RefusedIndex, shown.RefusedLength = shortfall.GetIndex(), shortfall.GetLength()
		shown.FreeAddressCount, shown.LargestFreeLength = shortfall.GetFreeAddressCount(), shortfall.GetLargestFreeLength()
	}
	return shown, nil
}
