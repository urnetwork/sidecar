// Every barrier gkmservice calls (§22.4, §22.8): the names a fault schedule holds, listed once here so a schedule
// and the code agree. KEYS-M2-12 names them all, and each route's task calls its own around the conditional write
// that is its linearization point.
//
// A name is gkm.<step>.before or gkm.<step>.after. A key says which instance is held, an opaque id or a pair of
// them joined by a colon, never a path or a name (I-13): a group's step is keyed by the group's id in
// sidecar.EvsKeyId's form, or <group>:<n> for one epoch or generation, and a KeyPackage claim by <target>:<ref>.
//
// Each hook may block for as long as a schedule holds it, so none is called with a state lock held.

package gkmservice

import (
	"encoding/hex"
	"strconv"

	"github.com/urnetwork/sidecar"
)

const (
	// Around POST /gkm/groups's If-None-Match creates: GroupForm, epoch/0, gen/1 (KEYS-M2-14), keyed by the group.
	BarrierGroupCreateBefore = "gkm.group_create.before"
	BarrierGroupCreateAfter  = "gkm.group_create.after"
	// Around the owner marker's If-None-Match, the first write of a creation or a re-form (DESIGN-DETAILS 6.2.2),
	// keyed by the group.
	BarrierGroupOwnerBefore = "gkm.group_owner.before"
	BarrierGroupOwnerAfter  = "gkm.group_owner.after"
	// Around epoch/<n>'s If-None-Match, one commit per epoch (KEYS-M2-14), keyed by <group>:<n>.
	BarrierEpochPutBefore = "gkm.epoch_put.before"
	BarrierEpochPutAfter  = "gkm.epoch_put.after"
	// Around gen/<g>'s If-None-Match, the claim that is the only place a generation exists (KEYS-M2-15), keyed by
	// <group>:<g>.
	BarrierGenClaimBefore = "gkm.gen_claim.before"
	BarrierGenClaimAfter  = "gkm.gen_claim.after"
	// Around a wrap/ or recovery/ object's If-None-Match (KEYS-M2-15), keyed by <group>:<g>.
	BarrierWrapPutBefore = "gkm.wrap_put.before"
	BarrierWrapPutAfter  = "gkm.wrap_put.after"
	// Around a KeyPackage claim's If-None-Match on <ref>.claim (KEYS-M2-13), keyed by <target>:<ref>.
	BarrierKeyPackageClaimBefore = "gkm.kp_claim.before"
	BarrierKeyPackageClaimAfter  = "gkm.kp_claim.after"
	// Around welcome/<n>'s write (KEYS-M2-14), keyed by <group>:<n>.
	BarrierWelcomePutBefore = "gkm.welcome_put.before"
	BarrierWelcomePutAfter  = "gkm.welcome_put.after"
	// Around group-info's If-Match, the pointer's rewrite (KEYS-M2-14), keyed by the group.
	BarrierPointerPutBefore = "gkm.pointer_put.before"
	BarrierPointerPutAfter  = "gkm.pointer_put.after"
	// Around an ack's {gka_} write (KEYS-M2-14), keyed by the group.
	BarrierAckWriteBefore = "gkm.ack_write.before"
	BarrierAckWriteAfter  = "gkm.ack_write.after"
	// Around a forwarding Delegation's reader key object's If-None-Match, dkey/<delegation_id> (KEYS-M8-01), keyed by
	// the delegation_id in 64 hex characters.
	BarrierDelegationKeyPutBefore = "gkm.dkey_put.before"
	BarrierDelegationKeyPutAfter  = "gkm.dkey_put.after"
)

// A group's barrier key.
func gkmBarrierGroupKey(groupId sidecar.Id) string {
	return sidecar.EvsKeyId(groupId)
}

// One epoch's or generation's barrier key: <group>:<n>.
func gkmBarrierNumberKey(groupId sidecar.Id, number uint64) string {
	return sidecar.EvsKeyId(groupId) + ":" + strconv.FormatUint(number, 10)
}

// A KeyPackage claim's barrier key: <target>:<ref>.
func gkmBarrierClaimKey(targetSidecarId sidecar.Id, ref []byte) string {
	return sidecar.EvsKeyId(targetSidecarId) + ":" + hex.EncodeToString(ref)
}
