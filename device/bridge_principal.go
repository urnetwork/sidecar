// §17.9's verify row (D-BRIDGE-17, I-3, I-4): BridgeEgressPolicy.VerifyPrincipal, which connect calls once per contract
// a source presents, in its first flow's sequence before that flow dials, and whose answer it keeps on the contract's
// flows (C5). A host admits a native flow only from a window client a customer key vouches for: the delegation's
// signature by the subject's identity key, pinned in the state and neither revoked nor suspended at it, and every value
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
// A share link's delegation, FriendsAndFamily under a ShareSigner, is refused until shares land (BRIDGE-M6-05), and an
// sdk provider verifies none until C16 (§17.6's sdk exit NAT).

package device

import (
	"time"

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
	delegation, err := bridge.VerifyWindowDelegation(delegationBytes, &bridge.WindowDelegationCheck{
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
	})
	if err != nil {
		return nil
	}
	subject := state.subjectBySidecarId[connect.Id(delegation.GetSubjectSidecarId())]
	if subject == nil || state.subjectByClientId[sealedSubject] != subject {
		// the operator sealed a subject the customer's delegation does not bind
		self.principalMismatchCount.Add(1)
		return nil
	}
	return &connect.BridgePrincipal{
		Subject:  subject.sidecarId,
		Network:  state.networkId,
		NotAfter: time.UnixMilli(delegation.GetNotAfterMs()),
	}
}
