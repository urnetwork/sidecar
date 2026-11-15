// The bridge compile's shares (§17.9; DESIGN-DETAILS 12.2.7's "what each side compiles"; BRIDGE-M6-03, BRIDGE-M6-05):
// what the sharing network's hosts serve and what the accepting network's senders route, each from the signed config
// of the compiling sidecar's own network.
//
//	X, a host    a share compiles from its grant file (bridge/share-grant/<share_id hex>) only while the file's grant
//	             is live at t and the state lets network:Y reach this host, and only from the share's row
//	             (BridgeCompileLocal.ShareTables) when its tables hash to the file's pins and open under the file's K: a
//	             row at another hash or version is ignored with bridge_alarm share_table_mismatch, and a share with no
//	             row waits for one. The rules carry the targets this host hosts, each with its alias's host bits and
//	             length (BridgeRules.shares), and the state the share's pinned ShareKey (BridgeState.share_keys)
//	Y, a sender  an alias in force is an entry of the sender's table, its prefix the alias's host bits in each block,
//	             when the state lets this sidecar reach network:X (§8.11's dial on the sharing network): a link to the
//	             target's host naming the share and X, pinned to the host identity key the alias carries (QD-077), at the
//	             client the host's binding names once it verifies under that key; until then the entry waits for the
//	             binding and rejects
//
// Equal inputs give equal rows: the grant files run in path order, the aliases in the ledger's, and nothing ranges over a
// Go map. On every leg: the forwarding role compiles with the same code (DESIGN-DETAILS 12.2.1).

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"slices"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The shares this host serves at t, by share id, and their pinned ShareKeys (the file's X row).
func (self *bridgeCompiler) hostedShares() ([]*bridge.BridgeRuleShare, []*bridge.BridgeShareKey) {
	shares := []*bridge.BridgeRuleShare{}
	keys := []*bridge.BridgeShareKey{}
	head := self.view.Head()
	if head == nil || self.selfDenied {
		return shares, keys
	}
	networkId := self.state.NetworkId()
	selfKey := self.state.IdentityKey(self.self)
	for _, grant := range ReadBridgeShareGrants(head) {
		shareId, err := IdFromBytes(grant.GetShareId())
		acceptingNetworkId, networkErr := IdFromBytes(grant.GetAcceptingNetworkId())
		if err != nil || networkErr != nil || acceptingNetworkId == networkId {
			continue
		}
		// the file counts only while its grant is live, and only where the state lets the accepting network reach this
		// host: X's half of §8.11's share
		rule := self.acl.grantRule(grant.GetGrantId())
		if rule == nil || !rule.activeAt(self.t) {
			continue
		}
		if !self.acl.contractReach(&AclSubject{Kind: AclSubjectRemote, Id: acceptingNetworkId}, &self.selfSubject, false, self.t).Allowed {
			continue
		}
		row := self.shareRow(shareId)
		if row == nil {
			self.wait(BridgeCompileWait{Kind: BridgeCompileWaitShareTable, ShareId: shareId})
			continue
		}
		opened, err := OpenBridgeShareTables(grant, networkId, row, self.local.ShareSettings, self.ledgerSettings)
		if err != nil {
			self.alarm(SidecarBridgeAlarmShareTableMismatch, 0, Id{},
				"share "+hex.EncodeToString(shareId.Bytes())+": its tables are not the ones its grant file pins; it compiles nothing")
			continue
		}
		share := &bridge.BridgeRuleShare{
			ShareId:            shareId.Bytes(),
			AcceptingNetworkId: acceptingNetworkId.Bytes(),
			SharePublicKey:     bytes.Clone(grant.GetSharePublicKey()),
			GrantId:            bytes.Clone(grant.GetGrantId()),
			Expires:            rule.expiresMs,
		}
		for i, target := range opened.Targets.GetTargets() {
			if !bytes.Equal(target.GetHostSidecarId(), self.self.Bytes()) {
				continue
			}
			if !bytes.Equal(target.GetHostIdentityPublicKey(), selfKey) {
				// the accepting network's routers pin the key the table sealed, which is no longer this host's
				self.alarm(SidecarBridgeAlarmShareTableMismatch, 0, self.self,
					"share "+hex.EncodeToString(shareId.Bytes())+": a target names this host under another identity key")
				continue
			}
			alias := opened.Aliases.GetAliases()[i]
			share.Targets = append(share.Targets, &bridge.BridgeRuleShareTarget{
				Index:         target.GetIndex(),
				AliasHostBits: alias.GetAliasHostBits(),
				Length:        alias.GetLength(),
				Target:        bridgeCompileClonePrefix(target.GetPrefix()),
				Protocol:      target.GetProtocol(),
				Ports:         bridgeCompileClonePorts(target.GetPorts()),
			})
		}
		if len(share.Targets) == 0 {
			continue
		}
		shares = append(shares, share)
		keys = append(keys, &bridge.BridgeShareKey{ShareId: shareId.Bytes(), PublicKey: bytes.Clone(grant.GetSharePublicKey())})
	}
	return shares, keys
}

// The share's row among the local tables, nil for none.
func (self *bridgeCompiler) shareRow(shareId Id) *BridgeShareRow {
	for _, row := range self.local.ShareTables {
		if row != nil && row.ShareId == shareId {
			return row
		}
	}
	return nil
}

// A prefix's copy, nil for none.
func bridgeCompileClonePrefix(prefix *bridge.BridgeIpv4Prefix) *bridge.BridgeIpv4Prefix {
	if prefix == nil {
		return nil
	}
	return &bridge.BridgeIpv4Prefix{Address: prefix.GetAddress(), Length: prefix.GetLength()}
}

// Port ranges' copies.
func bridgeCompileClonePorts(ports []*bridge.BridgePortRange) []*bridge.BridgePortRange {
	cloned := make([]*bridge.BridgePortRange, 0, len(ports))
	for _, portRange := range ports {
		cloned = append(cloned, &bridge.BridgePortRange{First: portRange.GetFirst(), Last: portRange.GetLast()})
	}
	return cloned
}

// The share links of S's table (the file's Y row): an entry of each alias in force S may use, in each block, with a
// link to its target's host.
func (self *bridgeCompiler) shareEntries(find func(prefix bridgePrefix) *bridgeCompileEntry, add func(entry *bridgeCompileEntry)) {
	if self.selfDenied || len(self.blocks) == 0 {
		return
	}
	networkId := self.state.NetworkId()
	for _, alias := range self.ledger.Aliases() {
		body := alias.Body
		shareId, shareErr := IdFromBytes(body.GetShareId())
		hostId, hostErr := IdFromBytes(body.GetHost())
		sharingNetworkId, networkErr := IdFromBytes(body.GetSharingNetworkId())
		hostKey := body.GetHostIdentityPublicKey()
		if shareErr != nil || hostErr != nil || networkErr != nil || sharingNetworkId == networkId || len(hostKey) != ed25519.PublicKeySize {
			// an alias that names no host of another network under a key a link can check routes nothing
			continue
		}
		// Y's half of §8.11's share: S reaches the sharing network
		if !self.acl.contractReach(&self.selfSubject, &AclSubject{Kind: AclSubjectRemote, Id: sharingNetworkId}, false, self.t).Allowed {
			continue
		}
		first, _, err := bridgeUpperRangeOf(body.GetAliasPrefix())
		if err != nil {
			continue
		}
		link := self.shareLink(shareId, hostId, sharingNetworkId, hostKey)
		for _, block := range self.blocks {
			prefix := bridgePrefix{address: bridgeCompileInBlock(block, first), length: body.GetAliasPrefix().GetLength()}
			entry := find(prefix)
			switch {
			case entry != nil && entry.kind != bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK:
				self.alarm(SidecarBridgeAlarmBlockConflict, alias.At, alias.Signer, "a share's alias is the block's own entry")
				continue
			case !self.linkEntryFits(prefix):
				self.alarm(SidecarBridgeAlarmBlockConflict, alias.At, alias.Signer, "a share's alias covers the block's services")
				continue
			case entry == nil:
				entry = &bridgeCompileEntry{prefix: prefix, kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK}
				add(entry)
			}
			if link != nil && !slices.ContainsFunc(entry.links, func(held *bridge.BridgeRuleLink) bool {
				return bytes.Equal(held.GetTargetClientId(), link.GetTargetClientId())
			}) {
				entry.links = append(entry.links, link)
			}
		}
	}
}

// A share link to a host of the sharing network, at the client its current binding names once the binding verifies
// under the key the alias pinned; nil, and a wait, for one with none.
func (self *bridgeCompiler) shareLink(shareId Id, hostId Id, sharingNetworkId Id, hostKey []byte) *bridge.BridgeRuleLink {
	binding := self.bindings.Current(hostId)
	if binding == nil || binding.SidecarId != hostId || !bytes.Equal(binding.IdentityPublicKey, hostKey) {
		wait := BridgeCompileWait{Kind: BridgeCompileWaitShareBinding, SidecarId: hostId, NetworkId: sharingNetworkId}
		copy(wait.IdentityPublicKey[:], hostKey)
		self.wait(wait)
		return nil
	}
	return &bridge.BridgeRuleLink{
		TargetClientId:          binding.ClientId.Bytes(),
		TargetSidecarId:         hostId.Bytes(),
		TargetIdentityPublicKey: bytes.Clone(hostKey),
		Weight:                  1,
		ShareId:                 shareId.Bytes(),
		TargetNetworkId:         sharingNetworkId.Bytes(),
	}
}
