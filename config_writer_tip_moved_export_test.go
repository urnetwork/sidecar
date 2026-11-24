//go:build !sidecar_http && !ios_extension

// The bridge the tip-moved writer tests reach a confirmed ACL save and the writer's plan barrier through: a plan
// PlanAclSave made, pinned to the exact config ref position its head was read at, as aclPlanAtRef pins one once the
// person confirmed its preview (EXACT_HEAD, QD-1213), so AclSave hands the writer that position as the head the save
// requires; and the barrier's name, which a schedule under sidecar_testhooks holds. Tests only.

package sidecar

// The barrier a writer's plan passes between its head read and its tip check (configWriterBarrierPlanTip).
const ConfigWriterBarrierPlanTip = configWriterBarrierPlanTip

// plan, saved only on the ref at tip.
func AclSavePlanAtRef(plan *AclSavePlan, tip *ConfigHeadTip) *AclSavePlan {
	plan.ref = tip
	return plan
}
