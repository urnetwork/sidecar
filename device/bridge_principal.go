// §17.9's verify row (D-BRIDGE-17, I-3, I-4): BridgeEgressPolicy.VerifyPrincipal, which connect calls once per contract
// a source presents, in its first flow's sequence before that flow dials, and whose answer it keeps on the contract's
// flows (C5). A host admits a native flow only from a window client a customer key vouches for: the delegation's
// signature by the subject's identity key, pinned in the state and neither revoked nor suspended at it, or by the key
// of the subject's forwarding Delegation live at the state (owner decision 197; DESIGN-DETAILS 4.2.2), and every value
// the delegation names held to what the host established itself (bridge.VerifyWindowDelegation). C13's seals are the
// operator's statements, so they serve only as consistency checks: the sealed network must be this one and the
// delegation's, and the sealed subject, a client id, must be one the delegation's subject binds in the compiled rules
// (plan-BRIDGE-subject-resolution), else the contract is refused and alarms.
//
// Any failure answers nil, which the hook's "no verified principal" row denies; nothing falls back to a seal. A peer
// with no verified session key reads as no session, as on a client without ExposeVerifiedPeerClientKey, so a host must
// turn that on (BRIDGE-M4-17). The principal lapses at the delegation's not_after_ms, and ResolveEgress rechecks its
// subject against the published state on every flow, one lookup, so a revocation between the two denies.
//
// Which key admitted a principal is kept with it (bridgeForwardPrincipals): the per-flow recheck denies one a
// forwarding key admitted while the overlay holds a DelegationRevoke of that Delegation or a supersession of its
// sidecar, or once the state no longer lists it, and its flows carry their own tags (BridgeForwardRuleTag), so those
// end and the flows the same subject's identity key admitted go on (DESIGN-DETAILS 4.2.5).
//
// A share link's delegation, FriendsAndFamily under a ShareSigner, is refused until shares land (BRIDGE-M6-05), and an
// sdk provider verifies none until C16 (§17.6's sdk exit NAT).

package device

import (
	"crypto/sha256"
	"runtime"
	"sync"
	"time"
	"weak"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// connect.EgressHook: the contract's principal, or nil. See the file's comment.
func (self *BridgeEgressPolicy) VerifyPrincipal(source connect.TransferPath, peer connect.Peer) *connect.BridgePrincipal {
	if self.profile != BridgePolicyProfileHost || peer.ProvideMode != protocol.ProvideMode_Network {
		return nil
	}
	sessionKey, ok := peer.VerifiedClientPublicKey()
	if !ok {
		return nil
	}
	return self.verifyPrincipal(source.SourceId, sessionKey[:], peer.SourceNetwork, peer.SourceSubject, peer.WindowDelegation)
}

// VerifyPrincipal's checks over what it reads of the contract: its source, the session's verified key, C13's sealed
// network and subject, and the delegation as sealed.
func (self *BridgeEgressPolicy) verifyPrincipal(
	sourceId connect.Id,
	sessionKey []byte,
	sealedNetwork connect.Id,
	sealedSubject connect.Id,
	delegationBytes []byte,
) *connect.BridgePrincipal {
	state := self.state.Load()
	if !state.posture.Enforcing() || state.rulesRefused || len(delegationBytes) == 0 {
		return nil
	}
	// a same-network link: the sealed network is this one, and the delegation must name it too
	if state.networkId == (connect.Id{}) || sealedNetwork != state.networkId {
		return nil
	}
	self.principalVerifiedCount.Add(1)
	admission, err := bridge.VerifyWindowDelegationAdmission(delegationBytes, &bridge.WindowDelegationCheck{
		NetworkId:             sealedNetwork[:],
		WindowClientId:        sourceId[:],
		WindowClientPublicKey: sessionKey,
		TargetSidecarId:       state.hostSidecarId[:],
		NowMs:                 self.clock.Now().UnixMilli(),
		IdentityKey: func(sidecarId []byte) ([]byte, bool) {
			if len(sidecarId) != len(connect.Id{}) {
				return nil, false
			}
			subject := state.subjectBySidecarId[connect.Id(sidecarId)]
			if subject == nil || !subject.admitted || !subject.hasIdentity {
				return nil, false
			}
			return subject.identityKey, true
		},
		ForwardingKey: func(delegationId []byte) ([]byte, []byte, bool) {
			if len(delegationId) != sha256.Size {
				return nil, nil, false
			}
			subject := state.subjectByForwardDelegationId[[sha256.Size]byte(delegationId)]
			if subject == nil || !subject.forwardAdmitted() {
				return nil, nil, false
			}
			return subject.sidecarId[:], subject.forwardKey, true
		},
		Settings: self.settings.WindowDelegation,
	})
	if err != nil {
		return nil
	}
	delegation := admission.Delegation
	subject := state.subjectBySidecarId[connect.Id(delegation.GetSubjectSidecarId())]
	if subject == nil || state.subjectByClientId[sealedSubject] != subject {
		// the operator sealed a subject the customer's delegation does not bind
		self.principalMismatchCount.Add(1)
		return nil
	}
	principal := &connect.BridgePrincipal{
		Subject:  subject.sidecarId,
		Network:  state.networkId,
		NotAfter: time.UnixMilli(delegation.GetNotAfterMs()),
	}
	if len(admission.ForwardDelegationId) == sha256.Size {
		self.forwardPrincipals.add(principal, [sha256.Size]byte(admission.ForwardDelegationId))
	}
	return principal
}

// Which forwarding Delegation's key admitted a principal, for the principals a forwarding key admitted and no other:
// connect's BridgePrincipal has no field for it, and the NAT hands the hook back the pointer the hook answered with, so
// the pointer is the key. Each entry is held weakly and leaves when its principal is collected, which is after the NAT
// drops the contract's answer, so an entry is never lost while a flow can still present its principal, and one the
// table does not hold was admitted by the identity key. Safe for concurrent use; a read takes no lock.
type bridgeForwardPrincipals struct {
	// weak.Pointer[connect.BridgePrincipal] -> [sha256.Size]byte
	delegationIds sync.Map
}

// Records that the forwarding Delegation's key admitted principal, until principal is collected.
func (self *bridgeForwardPrincipals) add(principal *connect.BridgePrincipal, delegationId [sha256.Size]byte) {
	key := weak.Make(principal)
	self.delegationIds.Store(key, delegationId)
	runtime.AddCleanup(principal, func(key weak.Pointer[connect.BridgePrincipal]) {
		self.delegationIds.Delete(key)
	}, key)
}

// The forwarding Delegation whose key admitted principal, and false for one the identity key admitted.
func (self *bridgeForwardPrincipals) delegationId(principal *connect.BridgePrincipal) ([sha256.Size]byte, bool) {
	if principal == nil {
		return [sha256.Size]byte{}, false
	}
	value, ok := self.delegationIds.Load(weak.Make(principal))
	if !ok {
		return [sha256.Size]byte{}, false
	}
	return value.([sha256.Size]byte), true
}
