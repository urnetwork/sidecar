// What a host of the sharing network reads of a share's row (BRIDGE-M6-03; §17.9's share pins; DESIGN-DETAILS 12.2.7;
// QD-077, QD-670; I-2): the row as api answers it, its tables opened under K and held to each other, and to the pins
// the network's approving admin wrote in its grant file (BridgeShareGrant). A row at another hash or version than the
// pins is ErrBridgeShareTableMismatch, which a compile ignores with bridge_alarm share_table_mismatch: the server holds
// the row, so what it serves is trusted for nothing the pins do not fix.
//
// On every leg: the compile opens the tables in a VPN component as on a daemon (DESIGN-DETAILS 12.2.1), with no I/O,
// no clock and no random source. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// A share's row is not what the share's grant file pins: another hash or version of a table, another accepting
	// network, or another ShareKey. The row is ignored (bridge_alarm share_table_mismatch).
	ErrBridgeShareTableMismatch = errors.New("bridge share table is not the one pinned")
	// A target table or alias table no accept takes: indexes that are not dense from 0, an id, a key, a prefix or ports
	// out of form, or an alias table that is not its target table's.
	ErrBridgeShareTableInvalid = errors.New("bridge share table refused")
)

// network_bridge_share.accept_status (§17.9's status row). Format values.
type BridgeShareAcceptStatus string

const (
	BridgeShareAcceptStatusActive          BridgeShareAcceptStatus = "active"
	BridgeShareAcceptStatusRefusedTooLarge BridgeShareAcceptStatus = "refused_too_large"
	BridgeShareAcceptStatusRefusedNoSpace  BridgeShareAcceptStatus = "refused_no_space"
)

// One share's row as api answers it. Every table is ciphertext under K.
type BridgeShareRow struct {
	ShareId Id
	// X, the network whose targets are shared, and Y, the zero id before a claim binds one.
	SharingNetworkId   Id
	AcceptingNetworkId Id
	// X's sealed BridgeShareTargets and its version.
	TargetTable        []byte
	TargetTableVersion uint64
	// Y's side, a marshalled BridgeShareAccept of seals, and its version; nil before Y completes.
	AliasTable        []byte
	AliasTableVersion uint64
	// Empty before Y completes.
	AcceptStatus BridgeShareAcceptStatus
}

// The target table an invite seals and an accept opens, held to its form: indexes dense from 0, each host a
// sidecar_id with its Ed25519 identity key (QD-077), a masked IPv4 prefix, a protocol of 0, 6 or 17, and ports only
// under 6 or 17, each range in order. A length is not judged here: the preflight refuses a wide one as too large. At
// most listMaxCount port ranges a target, the ledger's BodyListMaxCount.
func CheckBridgeShareTargets(targets *bridge.BridgeShareTargets, settings *BridgeLedgerSettings) error {
	read := bridgeLedgerSettingsOrDefault(settings)
	if targets == nil || len(targets.GetTargets()) == 0 {
		return fmt.Errorf("%w: no target", ErrBridgeShareTableInvalid)
	}
	for i, target := range targets.GetTargets() {
		switch {
		case target == nil || target.GetIndex() != uint32(i):
			return fmt.Errorf("%w: target %d is out of its index", ErrBridgeShareTableInvalid, i)
		case len(target.GetHostSidecarId()) != len(Id{}):
			return fmt.Errorf("%w: target %d names no host", ErrBridgeShareTableInvalid, i)
		case len(target.GetHostIdentityPublicKey()) != ed25519.PublicKeySize:
			return fmt.Errorf("%w: target %d carries no host identity key", ErrBridgeShareTableInvalid, i)
		}
		prefix, err := bridgePrefixOf(target.GetPrefix())
		if err != nil {
			return fmt.Errorf("%w: target %d: %w", ErrBridgeShareTableInvalid, i, err)
		}
		if prefix.length == 0 {
			return fmt.Errorf("%w: target %d is every address", ErrBridgeShareTableInvalid, i)
		}
		switch target.GetProtocol() {
		case 0:
			if len(target.GetPorts()) != 0 {
				return fmt.Errorf("%w: target %d names ports of no protocol", ErrBridgeShareTableInvalid, i)
			}
		case aclIpProtocolTcp, aclIpProtocolUdp:
		default:
			return fmt.Errorf("%w: target %d names a protocol with no ports", ErrBridgeShareTableInvalid, i)
		}
		if read.BodyListMaxCount < len(target.GetPorts()) {
			return fmt.Errorf("%w: target %d names %d port ranges", ErrBridgeShareTableInvalid, i, len(target.GetPorts()))
		}
		for _, ports := range target.GetPorts() {
			if ports == nil || ports.GetFirst() == 0 || ports.GetLast() < ports.GetFirst() || 65535 < ports.GetLast() {
				return fmt.Errorf("%w: target %d names a port range out of form", ErrBridgeShareTableInvalid, i)
			}
		}
	}
	return nil
}

// The alias table an accept seals, held to its target table: one alias a target, by index, each of its target's
// length, aligned, inside the upper /17, a /32 at neither a .0 nor a .255, and no two overlapping.
func CheckBridgeShareAliases(aliases *bridge.BridgeShareAliases, targets *bridge.BridgeShareTargets) error {
	if aliases == nil || targets == nil || len(aliases.GetAliases()) != len(targets.GetTargets()) {
		return fmt.Errorf("%w: an alias table that is not one alias a target", ErrBridgeShareTableInvalid)
	}
	type held struct{ first, last uint32 }
	holds := make([]held, 0, len(aliases.GetAliases()))
	for i, alias := range aliases.GetAliases() {
		target := targets.GetTargets()[i]
		length := alias.GetLength()
		if alias == nil || alias.GetIndex() != uint32(i) || length != target.GetPrefix().GetLength() || length < 17 || 32 < length {
			return fmt.Errorf("%w: alias %d does not match its target", ErrBridgeShareTableInvalid, i)
		}
		first, size := alias.GetAliasHostBits(), uint32(1)<<(32-length)
		last := first + size - 1
		switch {
		case first < bridgeUpperHostBits || 0xffff < last || first%size != 0:
			return fmt.Errorf("%w: alias %d is no aligned block of the upper /17", ErrBridgeShareTableInvalid, i)
		case length == 32 && (first&0xff == 0x00 || first&0xff == 0xff):
			return fmt.Errorf("%w: alias %d is a /32 at a .0 or a .255", ErrBridgeShareTableInvalid, i)
		case slices.ContainsFunc(holds, func(other held) bool { return first <= other.last && other.first <= last }):
			return fmt.Errorf("%w: alias %d overlaps another", ErrBridgeShareTableInvalid, i)
		}
		holds = append(holds, held{first: first, last: last})
	}
	return nil
}

// A share's tables, opened under K and held to each other.
type BridgeShareOpened struct {
	ShareId            Id
	SharingNetworkId   Id
	AcceptingNetworkId Id
	Targets            *bridge.BridgeShareTargets
	// One alias a target, by index; nil for a share that was refused or has not completed.
	Aliases *bridge.BridgeShareAliases
	// Y's ShareKey, Ed25519; nil with no aliases.
	SharePublicKey []byte
	// A refusal's figures, nil for an active share.
	Shortfall *bridge.BridgeShareShortfall
	// SHA-256 of each side as the row stores it, and its version: what X's approving admin pins.
	TargetTableSha256  []byte
	TargetTableVersion uint64
	AliasTableSha256   []byte
	AliasTableVersion  uint64
	AcceptStatus       BridgeShareAcceptStatus
}

// Opens a share's row under seal, K for the row's sharing network: the target table, and, once the accepting network
// completed, its side. ErrBridgeShareSeal for anything that does not open, and ErrBridgeShareTableInvalid for tables
// out of form or an alias table that is not its target table's. The row's sharing network must be the seal's.
func OpenBridgeShareRow(seal *BridgeShareSeal, row *BridgeShareRow, settings *BridgeLedgerSettings) (*BridgeShareOpened, error) {
	if seal == nil || row == nil || row.ShareId == (Id{}) {
		return nil, fmt.Errorf("%w: no row", ErrBridgeShareTableInvalid)
	}
	if row.SharingNetworkId != seal.SharingNetworkId() {
		return nil, fmt.Errorf("%w: a row of another sharing network", ErrBridgeShareSeal)
	}
	opened := &BridgeShareOpened{
		ShareId: row.ShareId, SharingNetworkId: row.SharingNetworkId, AcceptingNetworkId: row.AcceptingNetworkId,
		Targets:           &bridge.BridgeShareTargets{},
		TargetTableSha256: BridgeShareTableSha256(row.TargetTable), TargetTableVersion: row.TargetTableVersion,
		AcceptStatus: row.AcceptStatus,
	}
	if err := seal.Open(BridgeShareLabelTargets, Id{}, row.TargetTableVersion, row.TargetTable, opened.Targets); err != nil {
		return nil, err
	}
	if err := CheckBridgeShareTargets(opened.Targets, settings); err != nil {
		return nil, err
	}
	if len(row.AliasTable) == 0 {
		if row.AcceptStatus != "" {
			return nil, fmt.Errorf("%w: a status with no accepting side", ErrBridgeShareTableInvalid)
		}
		return opened, nil
	}
	if row.AcceptingNetworkId == (Id{}) || row.AcceptingNetworkId == row.SharingNetworkId {
		return nil, fmt.Errorf("%w: an accepting side of no other network", ErrBridgeShareTableInvalid)
	}
	opened.AliasTableSha256, opened.AliasTableVersion = BridgeShareTableSha256(row.AliasTable), row.AliasTableVersion
	accept := &bridge.BridgeShareAccept{}
	if err := proto.Unmarshal(row.AliasTable, accept); err != nil || bridgeLedgerUnknownFields(accept) {
		return nil, fmt.Errorf("%w: the accepting side is no BridgeShareAccept", ErrBridgeShareSeal)
	}
	switch row.AcceptStatus {
	case BridgeShareAcceptStatusActive:
		if len(accept.GetAliases()) == 0 || len(accept.GetShareKey()) == 0 || len(accept.GetShortfall()) != 0 {
			return nil, fmt.Errorf("%w: an active accept without its aliases and key", ErrBridgeShareTableInvalid)
		}
		opened.Aliases = &bridge.BridgeShareAliases{}
		if err := seal.Open(BridgeShareLabelAliases, row.AcceptingNetworkId, row.AliasTableVersion, accept.GetAliases(), opened.Aliases); err != nil {
			return nil, err
		}
		if err := CheckBridgeShareAliases(opened.Aliases, opened.Targets); err != nil {
			return nil, err
		}
		keyBody := &bridge.BridgeShareKeyBody{}
		if err := seal.Open(BridgeShareLabelShareKey, row.AcceptingNetworkId, row.AliasTableVersion, accept.GetShareKey(), keyBody); err != nil {
			return nil, err
		}
		if len(keyBody.GetSharePublicKey()) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: a ShareKey of %d bytes", ErrBridgeShareTableInvalid, len(keyBody.GetSharePublicKey()))
		}
		opened.SharePublicKey = keyBody.GetSharePublicKey()
	case BridgeShareAcceptStatusRefusedNoSpace, BridgeShareAcceptStatusRefusedTooLarge:
		// a refusal carries its figures alone: which target, how wide, and the room there was
		if len(accept.GetAliases()) != 0 || len(accept.GetShareKey()) != 0 || len(accept.GetShortfall()) == 0 {
			return nil, fmt.Errorf("%w: a refusal without its shortfall alone", ErrBridgeShareTableInvalid)
		}
		opened.Shortfall = &bridge.BridgeShareShortfall{}
		if err := seal.Open(BridgeShareLabelShortfall, row.AcceptingNetworkId, row.AliasTableVersion, accept.GetShortfall(), opened.Shortfall); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: an accepting side with no status", ErrBridgeShareTableInvalid)
	}
	return opened, nil
}

// Holds a share's row to its grant file's pins and opens it (the file's comment): the file's share, the sharing
// network K was written for, the accepting network, each table's hash and version, and the ShareKey. A share that is
// not active compiles nothing, so it is a mismatch too.
func OpenBridgeShareTables(grant *bridge.BridgeShareGrant, sharingNetworkId Id, row *BridgeShareRow, settings *BridgeShareSettings, ledgerSettings *BridgeLedgerSettings) (*BridgeShareOpened, error) {
	if err := CheckBridgeShareGrant(grant); err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("%w: no row", ErrBridgeShareTableMismatch)
	}
	switch {
	case !bytes.Equal(grant.GetShareId(), row.ShareId.Bytes()) || row.SharingNetworkId != sharingNetworkId:
		return nil, fmt.Errorf("%w: another share's row", ErrBridgeShareTableMismatch)
	case !bytes.Equal(grant.GetAcceptingNetworkId(), row.AcceptingNetworkId.Bytes()):
		return nil, fmt.Errorf("%w: another accepting network", ErrBridgeShareTableMismatch)
	case grant.GetTargetTableVersion() != row.TargetTableVersion || !bytes.Equal(grant.GetTargetTableSha256(), BridgeShareTableSha256(row.TargetTable)):
		return nil, fmt.Errorf("%w: the target table", ErrBridgeShareTableMismatch)
	case grant.GetAliasTableVersion() != row.AliasTableVersion || !bytes.Equal(grant.GetAliasTableSha256(), BridgeShareTableSha256(row.AliasTable)):
		return nil, fmt.Errorf("%w: the alias table", ErrBridgeShareTableMismatch)
	case row.AcceptStatus != BridgeShareAcceptStatusActive:
		return nil, fmt.Errorf("%w: a share that is not active", ErrBridgeShareTableMismatch)
	}
	seal, err := NewBridgeShareSealOfKey(grant.GetTableKey(), sharingNetworkId, settings)
	if err != nil {
		return nil, err
	}
	opened, err := OpenBridgeShareRow(seal, row, ledgerSettings)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(opened.SharePublicKey, grant.GetSharePublicKey()) {
		return nil, fmt.Errorf("%w: another ShareKey", ErrBridgeShareTableMismatch)
	}
	return opened, nil
}

// A grant file held to its form: ids of 16 bytes, a grant id and hashes of 32, K, an Ed25519 ShareKey and versions
// from 1.
func CheckBridgeShareGrant(grant *bridge.BridgeShareGrant) error {
	switch {
	case grant == nil || bridgeLedgerUnknownFields(grant):
		return fmt.Errorf("%w: no grant file this build reads", ErrBridgeShareTableInvalid)
	case len(grant.GetShareId()) != len(Id{}) || len(grant.GetAcceptingNetworkId()) != len(Id{}):
		return fmt.Errorf("%w: a grant file's ids", ErrBridgeShareTableInvalid)
	case len(grant.GetGrantId()) != sha256.Size || len(grant.GetTargetTableSha256()) != sha256.Size || len(grant.GetAliasTableSha256()) != sha256.Size:
		return fmt.Errorf("%w: a grant file's grant or hashes", ErrBridgeShareTableInvalid)
	case len(grant.GetTableKey()) != bridgeShareKeyByteCount || len(grant.GetSharePublicKey()) != ed25519.PublicKeySize:
		return fmt.Errorf("%w: a grant file's keys", ErrBridgeShareTableInvalid)
	case grant.GetTargetTableVersion() == 0 || grant.GetAliasTableVersion() == 0:
		return fmt.Errorf("%w: a grant file's versions", ErrBridgeShareTableInvalid)
	}
	return nil
}

// bridge/share-grant/<share_id hex>, the path of a share's grant file in the sharing network's head.
func ConfigHeadBridgeShareGrantPath(shareId Id) string {
	return ConfigHeadBridgeShareGrantPrefix + fmt.Sprintf("%x", shareId.Bytes())
}

// The grant files a head holds, by share id in path order. A file that is no BridgeShareGrant of its path's share is
// left out: it pins nothing.
func ReadBridgeShareGrants(head *ConfigHead) []*bridge.BridgeShareGrant {
	if head == nil {
		return nil
	}
	grants := []*bridge.BridgeShareGrant{}
	paths := head.Paths()
	slices.Sort(paths)
	for _, path := range paths {
		if len(path) != len(ConfigHeadBridgeShareGrantPrefix)+configHeadShareIdHexLength || path[:len(ConfigHeadBridgeShareGrantPrefix)] != ConfigHeadBridgeShareGrantPrefix {
			continue
		}
		grant := &bridge.BridgeShareGrant{}
		if err := proto.Unmarshal(head.File(path), grant); err != nil || CheckBridgeShareGrant(grant) != nil {
			continue
		}
		shareId, err := IdFromBytes(grant.GetShareId())
		if err != nil || ConfigHeadBridgeShareGrantPath(shareId) != path {
			continue
		}
		grants = append(grants, grant)
	}
	return grants
}
