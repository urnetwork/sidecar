// The keys of gkm's objects that a delivery or a generation names (§10.6), which client, gkm and evs build
// alike, so they live here rather than in gkmservice: evs reads gen/<g> for its gate and cannot import it.
// The encoding is QD-442's, as testdata/gkm/wrap_paths.json pins it: <g> is 20 decimal digits, zero-padded;
// group_id, member_id, sidecar_id and network_id are 32 lowercase hex characters, a delegation_id 64; c8, k8 and b8
// are 16, the hex of a digest's first 8 bytes; s: and d: are literal. Every key here has a fixed length for its
// kind, so none prefixes another (§11.8's keys row). Keys carry opaque ids only (I-13).
//
// A Welcome pointer is keyed by its group and epoch, never by the KeyPackageRef its Add used, so two Adds through
// one last-resort KeyPackage keep two pointers, and a group's owner marker is the first object of the group
// (DESIGN-DETAILS 6.2.2).
//
// A forwarding Delegation's reader key, which its row names by digest alone, is gkm's object keyed by its network
// and the Delegation's id, gkm/dkey/<network_id>/<delegation_id> (DESIGN-DETAILS 4.2.2; QD-763): the route's path
// id and the object's last element take one form, built here. The network is the token's at the upload and the read,
// never a request's, and gkm's reconciler sweeps one network's objects by its prefix (QD-675), as a network's shred
// or a hold finds them.
//
// On every leg, with no connect import. Package-level functions are safe for concurrent use.

package sidecar

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// The digits of a generation in a key, as proj/ writes positions (§7.9).
const gkmGenerationDigitCount = 20

// A key's id: 32 lowercase hex characters, no dashes.
func gkmPathId(id Id) string {
	return hex.EncodeToString(id[:])
}

// g in 20 digits.
func gkmPathGeneration(generation uint64) string {
	digits := strconv.FormatUint(generation, 10)
	return strings.Repeat("0", gkmGenerationDigitCount-len(digits)) + digits
}

// The 16 hex characters of a 32-byte digest's first 8 bytes, or an error for anything else.
func gkmPathPrefix(digest []byte) (string, error) {
	if len(digest) != gkmDigestByteCount {
		return "", fmt.Errorf("%w: a digest of %d bytes", ErrGkmMalformed, len(digest))
	}
	return hex.EncodeToString(digest[:gkmDigestPrefixByteCount]), nil
}

// gkm/<group_id>/gen/<g>, where generation g exists and nowhere else (D-KEYS-15).
func GkmGenerationPath(groupId Id, generation uint64) string {
	return "gkm/" + gkmPathId(groupId) + "/gen/" + gkmPathGeneration(generation)
}

// A delivery's wrap/ path in its group: gkm/<group_id>/wrap/<g>/<c8>/<recipient>/<k8>, the recipient s:<sidecar_id>
// for a ReaderWrap or d:<delegation_id> for a DelegationWrap, and k8 from the key digest it seals to, so each
// (recipient, key) has its own object (D-KEYS-24).
func GkmWrapPath(groupId Id, generation uint64, commitment []byte, wrapType GkmWrapType, recipient []byte, recipientKeySha256 []byte) (string, error) {
	c8, err := gkmPathPrefix(commitment)
	if err != nil {
		return "", err
	}
	k8, err := gkmPathPrefix(recipientKeySha256)
	if err != nil {
		return "", err
	}
	if wrapType.recipientByteCount() == 0 || len(recipient) != wrapType.recipientByteCount() {
		return "", fmt.Errorf("%w: a recipient of %d bytes for wrap type %d", ErrGkmMalformed, len(recipient), wrapType)
	}
	recipientPrefix := "s:"
	if wrapType == GkmWrapTypeDelegation {
		recipientPrefix = "d:"
	}
	return "gkm/" + gkmPathId(groupId) + "/wrap/" + gkmPathGeneration(generation) + "/" + c8 + "/" +
		recipientPrefix + hex.EncodeToString(recipient) + "/" + k8, nil
}

// The wrap/ path of a delivery as its body names it, in groupId, the group of the route it came by, which
// gkm holds a body to (§10.6's wrap checks).
func GkmDeliveryPath(groupId Id, delivery *GkmDelivery) (string, error) {
	if delivery == nil || delivery.Body == nil {
		return "", fmt.Errorf("%w: no delivery", ErrGkmMalformed)
	}
	body := delivery.Body
	return GkmWrapPath(groupId, body.GetGeneration(), body.GetCommitment(), delivery.Type, body.GetRecipient(), body.GetRecipientKeySha256())
}

// A RecoveryWrap's path: gkm/recovery/<member_id>/<group_id>/<g>/<c8>/<b8>, b8 naming the binding whose key it
// is sealed to (§10.6), so a rebind's wraps take paths of their own (§10.8).
func GkmRecoveryWrapPath(memberId Id, groupId Id, generation uint64, commitment []byte, bindingKeySha256 []byte) (string, error) {
	c8, err := gkmPathPrefix(commitment)
	if err != nil {
		return "", err
	}
	b8, err := gkmPathPrefix(bindingKeySha256)
	if err != nil {
		return "", err
	}
	return "gkm/recovery/" + gkmPathId(memberId) + "/" + gkmPathId(groupId) + "/" + gkmPathGeneration(generation) + "/" +
		c8 + "/" + b8, nil
}

// gkm/welcome/<sidecar_id>/: a sidecar's Welcome pointers, by LIST.
func GkmWelcomePointerPrefix(sidecarId Id) string {
	return "gkm/welcome/" + gkmPathId(sidecarId) + "/"
}

// gkm/welcome/<sidecar_id>/<group_id>/<n>: the pointer to the Welcome that joins the sidecar to the group at epoch
// n, n in 20 digits as every epoch number: one Welcome, one key, whatever KeyPackage it used.
func GkmWelcomePointerPath(sidecarId Id, groupId Id, epoch uint64) string {
	return GkmWelcomePointerPrefix(sidecarId) + gkmPathId(groupId) + "/" + gkmPathGeneration(epoch)
}

// gkm/<group_id>/owner: the group's owner marker, a GkmGroupOwner naming the one repo the group belongs to, which
// gkm writes first at a creation or a re-form and resolves every group route through.
func GkmGroupOwnerPath(groupId Id) string {
	return "gkm/" + gkmPathId(groupId) + "/owner"
}

// A delegation_id as a path or key names it: 64 lowercase hex characters (QD-442), or an error for an id of another
// size.
func GkmDelegationPathId(delegationId []byte) (string, error) {
	if len(delegationId) != gkmDelegationIdByteCount {
		return "", fmt.Errorf("%w: a delegation id of %d bytes", ErrGkmMalformed, len(delegationId))
	}
	return hex.EncodeToString(delegationId), nil
}

// gkm/dkey/<network_id>/: a network's forwarding Delegations' reader key objects, by LIST (QD-763).
func GkmDelegationKeyNetworkPrefix(networkId Id) string {
	return "gkm/dkey/" + gkmPathId(networkId) + "/"
}

// gkm/dkey/<network_id>/<delegation_id>: a forwarding Delegation's reader key, its 1,216 B X-Wing public key as the
// Delegation's statement names it, on the first cluster beside the per-sidecar objects (DESIGN-DETAILS 4.2.2), under
// the network whose log holds the Delegation (QD-763). An error for a delegation id of another size, or for the zero
// network, which no token names.
func GkmDelegationKeyPath(networkId Id, delegationId []byte) (string, error) {
	if networkId == (Id{}) {
		return "", fmt.Errorf("%w: a delegation key names no network", ErrGkmMalformed)
	}
	pathId, err := GkmDelegationPathId(delegationId)
	if err != nil {
		return "", err
	}
	return GkmDelegationKeyNetworkPrefix(networkId) + pathId, nil
}
