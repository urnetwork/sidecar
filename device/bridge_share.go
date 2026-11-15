// §17.9's shares at a host, the sharing network X's side (BRIDGE-M6-04, BRIDGE-M6-05; C18, D-BRIDGE-14, D-BRIDGE-15,
// D-BRIDGE-17; DESIGN-DETAILS 12.2.7, 12.2.8; I-5, I-10): the share branch of VerifyPrincipal, the FriendsAndFamily row
// of §17.6's table, the ratchet, and the switch connect reads.
//
//	admit    a FriendsAndFamily contract's delegation is a share signer's: its ShareCert verifies under the share's pinned
//	         ShareKey (BridgeRules.shares[].share_public_key) with signer_id the share, its not_after_ms ahead and at
//	         most ShareCertSettings.Lifetime and Skew away, and its generation at least the share's ratchet; then the
//	         delegation under the cert's signer key, naming this host, the contract's window client and its sealed
//	         session key, and C13's sealed network, which must be the share's accepting network and not this one. A
//	         generation above the ratchet is committed to the posture's store (BridgeShareRatchet) before the principal
//	         is answered, so a contract is admitted only once the raise is durable, and a ShareCert below a committed
//	         generation is refused, after a restart too. A share link skips the sealed-subject clause: the host checks
//	         that a current reader of the accepting network's config signed, never which (§17.12). The principal's
//	         not_after is the earlier of the delegation's and the cert's
//	row      FriendsAndFamily at a host: C18 on, the principal's verified share live (its grant neither revoked nor
//	         expired) and its network the share's; a destination whose low 16 bits lie in an alias of one of the
//	         share's targets this host hosts maps to that target, keeping the bits past the alias's length; the target's
//	         protocol and ports admit the flow; then rule 0, rule 1's maps and remaps, rule 2, rule 3 by the share's grant
//	         alone, rule 5 and rule 6 decide where it leads, each a Map; anything else denies: never rule 4, an exit, a
//	         daemon listener, unmapped loopback or another host's address (owner decision 11)
//	tag      (share_id, 0x53 || u32be(target index)): X's host cannot list the accepting network's subjects, so a share's
//	         flows to one target end together; the disposition ends them when the share, the target or what the target
//	         leads through goes (bridge_disposition.go)
//	switch   FriendsAndFamilyEgress is true only on the host profile while it enforces a state holding a share, never on
//	         an sdk provider (§17.9's isolation row)
//
// The aliases match by host bits because the accepting network's block is not in the rules and need not be: its
// senders keep an alias's host bits when its block cycles (§17.4), so nothing the sharing network pinned changes.
//
// The sender's side, the accepting network Y's, is a share link: an entry of the alias's prefix whose link names the
// share and the sharing network, which BridgeLinkManager builds FriendsAndFamily with the aliases as C18's source half
// (bridge_link.go), signs with the share's signer through the sidecar role, and re-signs when that signer changes
// (Bridge.ResignShares).
//
// Safe for concurrent use: the published state is immutable, the ratchet the posture's.

package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A share flow's rule id begins with this byte, the target's index following (DESIGN-DETAILS 12.2.2). An identifier.
const BridgeRuleShareTarget byte = 0x53

// A share target's rule id: BridgeRuleShareTarget, then the target's index, most significant byte first.
func bridgeShareRuleId(index uint32) [5]byte {
	ruleId := [5]byte{BridgeRuleShareTarget}
	binary.BigEndian.PutUint32(ruleId[1:], index)
	return ruleId
}

// The tag of a share target's flows: BridgeRuleTag with the share_id as its subject (DESIGN-DETAILS 12.2.2).
func BridgeShareRuleTag(shareId connect.Id, index uint32) uint64 {
	ruleId := bridgeShareRuleId(index)
	return BridgeRuleTag(shareId, ruleId[:])
}

// What a host keeps of each share's newest verified ShareCert (§17.9's admit row): the posture, which keeps it in its
// store. Implementations are safe for concurrent use.
type BridgeShareRatchet interface {
	// The generation of the newest ShareCert kept for a share, and false for none.
	ShareCertGeneration(shareId []byte) (uint64, bool)
	// Keeps a ShareCert its caller verified under the share's pinned ShareKey, committed to the store before it
	// returns. A generation below the newest kept is refused; an equal one changes nothing.
	RaiseShareCert(shareId []byte, generation uint64, signedCert []byte) error
}

var _ BridgeShareRatchet = (*Posture)(nil)

// Holds a ratchet in an atomic pointer, which needs one concrete type.
type bridgeShareRatchetBox struct {
	ratchet BridgeShareRatchet
}

// Where a host keeps its shares' ratchets: the bridge's posture (NewBridge sets it). A policy with none admits no share
// principal, which fails closed.
func (self *BridgeEgressPolicy) SetShareRatchet(ratchet BridgeShareRatchet) {
	if ratchet == nil {
		self.shareRatchet.Store(nil)
		return
	}
	self.shareRatchet.Store(&bridgeShareRatchetBox{ratchet: ratchet})
}

// The ratchet, nil for none.
func (self *BridgeEgressPolicy) ratchet() BridgeShareRatchet {
	box := self.shareRatchet.Load()
	if box == nil {
		return nil
	}
	return box.ratchet
}

// One target of a share this host hosts, as the policy reads it.
type bridgePolicyShareTarget struct {
	index uint32
	// the alias's host bits in the accepting network's block, first and last
	aliasFirst uint32
	aliasLast  uint32
	// T_i, masked to the alias's length
	target   netip.Prefix
	protocol uint32
	ports    []bridgePolicyPortRange
	ruleTag  uint64
}

// A share this host serves, its grant's revocation applied.
type bridgePolicyShare struct {
	shareId            connect.Id
	acceptingNetworkId connect.Id
	publicKey          []byte
	// the share's grant as a reach row, for its revocation, its expiry and the reach events it admits under
	grant   bridgePolicyReach
	targets []*bridgePolicyShareTarget
}

// Whether the share admits a new flow at now: its grant neither revoked between states nor expired.
func (self *bridgePolicyShare) admits(now time.Time) bool {
	return !self.grant.revoked && (self.grant.expires.IsZero() || now.Before(self.grant.expires))
}

// The target whose alias holds hostBits, nil for none.
func (self *bridgePolicyShare) targetOf(hostBits uint32) *bridgePolicyShareTarget {
	for _, target := range self.targets {
		if target.aliasFirst <= hostBits && hostBits <= target.aliasLast {
			return target
		}
	}
	return nil
}

// Whether the target's protocol and ports admit a flow: every protocol, or the flow's with no ports or one of them. ICMP
// has no port, so a target naming ports never admits it.
func (self *bridgePolicyShareTarget) admits(protocolNumber uint32, port uint16) bool {
	if self.protocol == 0 {
		return true
	}
	if self.protocol != protocolNumber {
		return false
	}
	if len(self.ports) == 0 {
		return true
	}
	if protocolNumber == bridgeProtocolIcmp {
		return false
	}
	for _, portRange := range self.ports {
		if portRange.first <= port && port <= portRange.last {
			return true
		}
	}
	return false
}

// Indexes the shares the rules carry, the overlay's grant revocations applied. ParseBridgeRules has held each to its
// form.
func newBridgePolicyShares(rules *bridge.BridgeRules, overlay *bridgePolicyOverlay) map[connect.Id]*bridgePolicyShare {
	shares := map[connect.Id]*bridgePolicyShare{}
	for _, ruleShare := range rules.GetShares() {
		share := &bridgePolicyShare{
			shareId:            connect.Id(ruleShare.GetShareId()),
			acceptingNetworkId: connect.Id(ruleShare.GetAcceptingNetworkId()),
			publicKey:          bytes.Clone(ruleShare.GetSharePublicKey()),
			grant: bridgePolicyReach{
				grantId: ruleShare.GetGrantId(),
				expires: bridgePolicyTime(ruleShare.GetExpires()),
				revoked: overlay.revokedGrantIds[string(ruleShare.GetGrantId())],
			},
		}
		for _, ruleTarget := range ruleShare.GetTargets() {
			target, _ := bridgeRulePrefix(ruleTarget.GetTarget())
			size := uint32(1) << (32 - ruleTarget.GetLength())
			share.targets = append(share.targets, &bridgePolicyShareTarget{
				index:      ruleTarget.GetIndex(),
				aliasFirst: ruleTarget.GetAliasHostBits(),
				aliasLast:  ruleTarget.GetAliasHostBits() + size - 1,
				target:     target,
				protocol:   ruleTarget.GetProtocol(),
				ports:      bridgePolicyPorts(ruleTarget.GetPorts()),
				ruleTag:    BridgeShareRuleTag(share.shareId, ruleTarget.GetIndex()),
			})
		}
		shares[share.shareId] = share
	}
	return shares
}

// The FriendsAndFamily row at a host (the file's row). Inline, with no lock and no allocation: a share's flow reaches
// only where its share's targets lead.
func (self *bridgePolicyState) resolveShare(
	settings *BridgeSettings,
	flow *connect.EgressFlow,
	protocolNumber uint32,
	now time.Time,
	reach *BridgeReachEvent,
) connect.EgressDecision {
	deny := connect.EgressDecision{Verdict: connect.EgressVerdictDeny, PolicyGeneration: self.generation}
	principal := flow.Principal
	if principal == nil || principal.ShareId == (connect.Id{}) || !flow.Sealed || !now.Before(principal.NotAfter) {
		return deny
	}
	if !self.posture.Enforcing() || self.rulesRefused {
		return deny
	}
	share := self.shareById[principal.ShareId]
	if share == nil || !share.admits(now) || principal.Network != share.acceptingNetworkId || principal.Network == self.networkId {
		return deny
	}
	addr := flow.To.Addr().Unmap()
	if !addr.Is4() {
		return deny
	}
	port := flow.To.Port()
	if protocolNumber == bridgeProtocolIcmp {
		port = 0
	}
	hostBits := bridgeAddrUint32(addr) & 0xffff
	target := share.targetOf(hostBits)
	if target == nil || !target.admits(protocolNumber, port) {
		return deny
	}
	// T_i, keeping the destination's bits past the alias's length
	mapped := bridgeRuleAddr(bridgeAddrUint32(target.target.Addr()) | (hostBits - target.aliasFirst))
	idle := settings.PinIdleTimeout
	if protocolNumber == bridgeProtocolTcp {
		idle = settings.PinTcpIdleTimeout
	}
	admit := func(to netip.AddrPort, kind BridgeReachKind) connect.EgressDecision {
		// the share's grant admitted it, from the subject the delegation names: a peer the record names by its id
		peer := bridgePolicySubject{sidecarId: principal.Subject}
		self.reachEvent(reach, kind, &share.grant, &peer, flow, to.Port())
		return connect.EgressDecision{
			Verdict:          connect.EgressVerdictMap,
			Target:           to,
			RuleTag:          target.ruleTag,
			PolicyGeneration: self.generation,
			IdleTimeout:      idle,
		}
	}
	// rule 0
	if self.daemonListener(mapped, port) {
		return deny
	}
	// rule 1, by the share's grant
	if policyMap := self.matchMap(mapped, port, protocolNumber, now); policyMap != nil {
		mapTarget, ok := policyMap.mapTarget(mapped, port)
		if !ok || self.inBlock(mapTarget.Addr()) || self.daemonListener(mapTarget.Addr(), mapTarget.Port()) {
			return deny
		}
		return admit(mapTarget, BridgeReachKindForward)
	}
	// rule 6's remap, hosted here
	if served, remapped := self.matchExposed(mapped, now); served != nil {
		if self.daemonListener(remapped, port) {
			return deny
		}
		return admit(netip.AddrPortFrom(remapped, port), BridgeReachKindRoute)
	}
	hosted := self.hosted(mapped, now)
	// rule 2: never another host's address
	if !hosted && self.inBlock(mapped) {
		return deny
	}
	// rule 3, by the share's grant alone
	if hosted {
		if self.daemonListener(bridgeHostedTarget, port) {
			return deny
		}
		return admit(netip.AddrPortFrom(bridgeHostedTarget, port), BridgeReachKindForward)
	}
	// rule 5: no unmapped loopback, link-local, multicast or unspecified
	if bridgeRuleFiveAddress(mapped) {
		return deny
	}
	// rule 6
	if self.matchServed(mapped, now) != nil {
		return admit(netip.AddrPortFrom(mapped, port), BridgeReachKindRoute)
	}
	// never rule 4, an exit or a LAN with no route
	return deny
}

// The share branch of VerifyPrincipal (the file's admit row): the principal of a FriendsAndFamily contract from another
// network, or nil. The one write is the ratchet's commit, once a share and a rise, in this contract's sequence before
// its first flow dials, never a packet's (QD-671).
func (self *BridgeEgressPolicy) verifySharePrincipal(
	sourceId connect.Id,
	sessionKey []byte,
	sealedNetwork connect.Id,
	delegationBytes []byte,
) *connect.BridgePrincipal {
	state := self.state.Load()
	if !state.posture.Enforcing() || state.rulesRefused || len(delegationBytes) == 0 || len(state.shareById) == 0 {
		return nil
	}
	// a share link comes from another network: C13's sealed network is the accepting one, never this one
	if sealedNetwork == (connect.Id{}) || sealedNetwork == state.networkId || state.hostSidecarId == (connect.Id{}) {
		return nil
	}
	ratchet := self.ratchet()
	if ratchet == nil {
		return nil
	}
	now := self.clock.Now()
	self.principalVerifiedCount.Add(1)
	admission, err := bridge.VerifyWindowDelegationAdmission(delegationBytes, &bridge.WindowDelegationCheck{
		NetworkId:             sealedNetwork[:],
		WindowClientId:        sourceId[:],
		WindowClientPublicKey: sessionKey,
		TargetSidecarId:       state.hostSidecarId[:],
		NowMs:                 now.UnixMilli(),
		// a share link names no subject of this network: only a share signer's delegation verifies here
		IdentityKey: func(sidecarId []byte) ([]byte, bool) {
			return nil, false
		},
		Share: func(shareId []byte) (*bridge.WindowDelegationShare, bool) {
			if len(shareId) != len(connect.Id{}) {
				return nil, false
			}
			share := state.shareById[connect.Id(shareId)]
			if share == nil || !share.admits(now) || share.acceptingNetworkId != sealedNetwork {
				return nil, false
			}
			generation, _ := ratchet.ShareCertGeneration(shareId)
			return &bridge.WindowDelegationShare{
				SharePublicKey: share.publicKey,
				Generation:     generation,
				CertSettings:   self.settings.ShareCert,
			}, true
		},
		Settings: self.settings.WindowDelegation,
	})
	if err != nil || admission.ShareCert == nil {
		return nil
	}
	delegation, cert := admission.Delegation, admission.ShareCert
	shareId := connect.Id(delegation.GetShareId())
	// committed before the contract is admitted: a kill between leaves the ratchet raised or the contract refused
	testHookBarrier("bridge_principal.share_ratchet.before", shareId.String())
	err = ratchet.RaiseShareCert(shareId[:], cert.GetConfigGeneration(), admission.ShareCertSigned)
	testHookBarrier("bridge_principal.share_ratchet.after", shareId.String())
	if err != nil {
		self.shareRatchetRefusedCount.Add(1)
		return nil
	}
	return &connect.BridgePrincipal{
		Subject:  connect.Id(delegation.GetSubjectSidecarId()),
		Network:  sealedNetwork,
		ShareId:  shareId,
		NotAfter: time.UnixMilli(min(delegation.GetNotAfterMs(), cert.GetNotAfterMs())),
	}
}

// §18.6's ResignShares, or in process from the sidecar role's compile (BridgeComponent.ResignShares): the shares'
// signers changed, so each live window client of their share links is signed again, for its later contracts (§17.9's
// sign row). Links of other shares and of this network are untouched. Off the packet path.
func (self *Bridge) ResignShares(shareIds []connect.Id) error {
	_, err := self.links.resignShares(shareIds)
	return err
}

// The tags of the shares' flows this state admits under at a time, and their atoms (bridge_disposition.go): a share
// target's tag rests on the share, its grant and the target, and on every map, hosted address and served route the
// target leads through, so its flows end when any of them goes.
func (self *bridgePolicyState) shareAdmission(admission bridgeAdmission, at time.Time) {
	for _, share := range self.shareById {
		if !share.admits(at) {
			continue
		}
		shareAtom := fmt.Sprintf("share:%x:%x:%x:%s", share.shareId[:], share.acceptingNetworkId[:], share.publicKey,
			share.grant.atom("share_grant"))
		for _, target := range share.targets {
			atoms := []string{shareAtom, bridgeShareTargetAtom(target)}
			for _, policyMap := range self.maps {
				if self.mapKept(policyMap, at) && target.target.Overlaps(policyMap.match) {
					atoms = append(atoms, bridgeMapAtom(policyMap))
				}
			}
			for _, addr := range self.hostedAddrs {
				if target.target.Contains(addr) && !self.lapsedInPreviousBlock(addr, at) {
					atoms = append(atoms, "hosted:"+addr.String())
				}
			}
			for _, served := range self.served {
				if served.exit || !served.admits(at) {
					continue
				}
				if target.target.Overlaps(served.prefix) {
					atoms = append(atoms, bridgeServedAtom(served))
				}
				if served.exposed.IsValid() && target.target.Overlaps(served.exposed) && !self.lapsedInPreviousBlock(served.exposed.Addr(), at) {
					atoms = append(atoms, bridgeServedAtom(served), bridgeRemapAtom(served))
				}
			}
			admission.add(target.ruleTag, atoms...)
		}
	}
}
