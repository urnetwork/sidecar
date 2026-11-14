//go:build !sidecar_http && !ios_extension

// §8.11's cross-network share as the contract gate reads it (D-ACL-10, R-ACL-1, R-ACL-6, I-5; §6.10.1 item 4). A
// non-companion contract from a subject a of network Y to a sidecar b of network X is covered by a share when both of
// its halves hold, each read from its own network's verified state, so neither network's groups reach the other:
//
//	Y's half   reach(a, network:X) in Y's state: a dial or route rule of Y's whose src holds a and whose targets
//	           name X (Y grants its subjects dial on network:X)
//	X's half   reach(network:Y, b) in X's state: a dial or route rule of X's whose src names network:Y and that
//	           reaches b (X grants network:Y a resource, with an admin's approval, owner decision 74)
//
// Access is their intersection. Y's half is the one this gate enforces for Y (Y's routers check it too); X's provider
// checks X's half again per flow against the verified source network and the share (§17.9), and verifies only that a
// current reader of Y's config signed, never Y's per-subject grant (CC-05, disclosed): a Y reader that Y's policy
// denies reaches X's granted targets only on a contract the operator mints, still within X's grant.
//
// A covered pair is answered class data with Reason share, before the Public rule's egress and declared refusals,
// which a share is not: its contract is FriendsAndFamily toward a marked sidecar, never Public. CreateContract settles
// it so only when the relationship is Public and the destination client is a sidecar's own (model.AclShareBetween),
// never for an sdk device client, which advertises FriendsAndFamily whenever it provides Public, and it is never
// normalized to Network.
//
// What leaves a pair uncovered, so the Public rule decides it: a companion (a share's reply rides its forward
// contract's companion, which the Public rule passes), an end the facts cannot tell, a destination that is no bound
// sidecar, a destination network with no head row, or one with no loaded state, which is asked to load, a hard-denied
// end at either state, and either half missing. Rows name a remote network only by its id: network:* names none,
// since no state tells this gate which networks a share binds, and a share's requested grant cannot fold yet, since
// a GrantActivate folds only for a sidecar subject (question acl-m6-03-share-grant-subject); standing document grants
// naming network:<net> are what cover a pair until it is answered.
//
// Reads two maps and two states and allocates nothing, as the rest of Decide.

package sidecar

import (
	"time"
)

// The share half of Decide for a non-companion between two networks, sourceState being the source network's: a share
// verdict and true when both halves hold, false to leave the pair to the Public rule.
func (self *AclContractGate) decideShare(request *AclContractRequest, sourceState *AclState, heads map[Id]uint64, nowMs int64) (AclContractVerdict, bool) {
	source, destination := &request.Source, &request.Destination
	if request.Companion || !destination.Known || destination.SidecarId == (Id{}) || !destination.SidecarHeld {
		return AclContractVerdict{}, false
	}
	sourceNetworkId, destinationNetworkId := source.NetworkId, destination.NetworkId
	if destinationNetworkId == (Id{}) || destinationNetworkId == sourceNetworkId {
		return AclContractVerdict{}, false
	}
	if _, found := heads[destinationNetworkId]; !found {
		// a network with no config repo holds no projection, so no grant of its
		return AclContractVerdict{}, false
	}
	snapshot, status := self.states.State(destinationNetworkId)
	if status != AclGateLoaded || snapshot == nil || snapshot.Acl == nil {
		self.states.Changed(destinationNetworkId)
		return AclContractVerdict{}, false
	}
	sourceSubject, sourceKnown := source.subject()
	destinationSubject, destinationKnown := destination.subject()
	if !sourceKnown || !destinationKnown {
		return AclContractVerdict{}, false
	}
	return sourceState.shareCovers(sourceNetworkId, &sourceSubject, snapshot.Acl, destinationNetworkId, &destinationSubject, nowMs)
}

// Both halves of a share from source of sourceNetworkId, whose state this is, to destination of destinationNetworkId,
// whose state destinationState is.
func (self *AclState) shareCovers(
	sourceNetworkId Id,
	source *AclSubject,
	destinationState *AclState,
	destinationNetworkId Id,
	destination *AclSubject,
	nowMs int64,
) (AclContractVerdict, bool) {
	outbound := self.contractReach(source, &AclSubject{Kind: AclSubjectRemote, Id: destinationNetworkId}, false, nowMs)
	if !outbound.Allowed {
		return AclContractVerdict{}, false
	}
	inbound := destinationState.contractReach(&AclSubject{Kind: AclSubjectRemote, Id: sourceNetworkId}, destination, false, nowMs)
	if !inbound.Allowed {
		return AclContractVerdict{}, false
	}
	return AclContractVerdict{
		Outcome:       AclContractAllow,
		Class:         AclContractClassData,
		Reason:        AclContractReasonShare,
		NetworkId:     sourceNetworkId,
		Decision:      outbound,
		ShareDecision: inbound,
	}, true
}

// Whether a share covered the contract (§8.11): a verdict CreateContract settles as FriendsAndFamily toward a marked
// sidecar, its Decision Y's half and its ShareDecision X's.
func (self AclContractVerdict) Shared() bool {
	return self.Outcome == AclContractAllow && self.Reason == AclContractReasonShare
}

// §8.11's share between subjects of two networks, each half on its own network's state: what the gate's share half
// answers, for a caller that holds both states itself (a test, a bridge compile's check). Hard denies at either state
// refuse it.
func AclShareReach(sourceState *AclState, sourceNetworkId Id, source AclSubject, destinationState *AclState, destinationNetworkId Id, destination AclSubject, now time.Time) (outbound AclDecision, inbound AclDecision) {
	nowMs := now.UnixMilli()
	outbound = sourceState.contractReach(&source, &AclSubject{Kind: AclSubjectRemote, Id: destinationNetworkId}, false, nowMs)
	if !outbound.Allowed {
		return outbound, AclDecision{}
	}
	inbound = destinationState.contractReach(&AclSubject{Kind: AclSubjectRemote, Id: sourceNetworkId}, &destination, false, nowMs)
	return outbound, inbound
}
