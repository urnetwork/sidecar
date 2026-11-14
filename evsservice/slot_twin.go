// The rules of DESIGN-DETAILS 14.2 that the slot twins break, one at a time, as details/EvsSlot.tla's Twin constant
// does (14.3): each twin test shows its rule carries the property the model's twin config loses. Only the
// sidecar_testhooks build can switch one on (slot_twin_testhooks.go); a release build breaks none
// (slot_twin_off.go), and make check fails a release leg built with that tag.

package evsservice

// One rule a twin breaks.
type evsSlotTwin int

const (
	// Breaks nothing.
	evsSlotTwinNone evsSlotTwin = iota
	// Step 6 takes another statement's object of equal bytes as it stands (EvsSlotTwin-TakesForeign).
	evsSlotTwinTakesForeign
	// A takeover of a statement in the attempt's own path epoch (EvsSlotTwin-TakesLive).
	evsSlotTwinTakesLive
	// A takeover that does not look for the statement in the head (EvsSlotTwin-TakesCommitted).
	evsSlotTwinTakesCommitted
	// A takeover that does not wait out the settle age (EvsSlotTwin-TakesUnsettled).
	evsSlotTwinTakesUnsettled
	// Evacuation deletes a dead record's slot whatever its origin (EvsSlotTwin-NoOriginAtDelete).
	evsSlotTwinNoOriginAtDelete
	// Evacuation's DELETE names no LastModified (EvsSlotTwin-UnconditionalDelete).
	evsSlotTwinUnconditionalDelete
	// Evacuation deletes an unsettled slot (EvsSlotTwin-NoSettle).
	evsSlotTwinNoSettle
)
