// §11.7's on row at evs's 5h (EVS2-M10-16): a version written with versioning on that names its path's own kind-5
// segment by a kind-1 locator adopts it, a push that carries no format-2 value otherwise, and the citation rule
// judges it all the same; another path's kind-5 segment, a staged one, and one named by two new versions stay refused.

package evsservice

import (
	"crypto/sha256"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A kind-1 locator of id.
func checkTestKind1Locator(id [32]byte) *protocol.EvsLocator {
	return &protocol.EvsLocator{
		Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: id[:],
		Offset: sidecar.EvsKind5SegmentHeaderByteCount, Length: uint32(sidecar.EvsRecordByteCount(100)),
	}
}

func TestCheckAdoptsThePathsOwnKind5SegmentAsKind1(t *testing.T) {
	fixture := newCheckFixture(t)
	x, y := checkTestPath("x"), checkTestPath("y")
	segmentId := sha256.Sum256([]byte("adopted"))

	// k of x is versionless, its record in an uploaded kind-5 segment
	k := fixture.plan()
	kEntry := fixture.versionedEntry(k, 1, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(segmentId, false))

	// k+1 of x, versioning on, names it as kind 1: nothing in the push is format 2's, and it passes under the rule
	adopt := fixture.plan()
	adopt.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 1, EntryVersion: fixture.versionedEntry(adopt, 2, protocol.EvsVersioning_EVS_VERSIONING_KEPT, checkTestKind1Locator(segmentId))}}
	view := fixture.viewFormat2(adopt, nil)
	if view.NeedsFormat2 {
		t.Fatal("an adoption carries no format-2 value")
	}
	checkTestNewest(view, x, kEntry, 1)
	if !evsViewAdoptsKind5(view) {
		t.Fatal("the adoption is not seen")
	}
	requireCheckPass(t, "a version adopting its path's kind-5 segment", CheckPush(view))

	// over a versioned base that names another segment it is format 1's unknown segment
	view = fixture.viewFormat2(adopt, nil)
	checkTestNewest(view, x, fixture.versionedEntry(k, 1, protocol.EvsVersioning_EVS_VERSIONING_KEPT, checkTestKind1Locator(sha256.Sum256([]byte("another")))), 1)
	requireCheckRefusal(t, "a kind-1 locator naming no segment read", CheckPush(view), EvsCheckReasonSegmentUnknown)

	// another path's kind-5 segment is never adopted: y's version names x's, x written beside it
	other := fixture.plan()
	other.Changes = []*sidecar.EvsPlannedChange{
		{TokenPath: x, BaseEntryVersion: 1, EntryVersion: fixture.versionedEntry(other, 2, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(segmentId, false))},
		{TokenPath: y, EntryVersion: fixture.versionedEntry(other, 1, protocol.EvsVersioning_EVS_VERSIONING_KEPT, checkTestKind1Locator(segmentId))},
	}
	view = fixture.viewFormat2(other, nil)
	checkTestNewest(view, x, kEntry, 1)
	requireCheckRefusal(t, "another path's kind-5 segment as kind 1", CheckPush(view), EvsCheckReasonSegmentUnknown)

	// a staged segment is cited only by its introducing version: the next version adopts nothing
	stagedPlan := fixture.plan()
	_, staged := checkTestStaged(t, stagedPlan, "s")
	stagedEntry := fixture.versionedEntry(stagedPlan, 1, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(staged.Id, true))
	over := fixture.plan()
	over.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 1, EntryVersion: fixture.versionedEntry(over, 2, protocol.EvsVersioning_EVS_VERSIONING_KEPT, checkTestKind1Locator(staged.Id))}}
	view = fixture.viewFormat2(over, nil)
	checkTestNewest(view, x, stagedEntry, 1)
	requireCheckRefusal(t, "a staged segment adopted as kind 1", CheckPush(view), EvsCheckReasonSegmentUnknown)
}
