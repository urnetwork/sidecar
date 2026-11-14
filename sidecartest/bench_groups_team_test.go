package sidecartest

// §22.8's groups row at Team scale (KEYS-M6-03; owner decisions 144, 182; §20.4's 5,000 Team admissions): the
// harness's rotation rows at 5,000 wrapped holders in every run, by a leaf, whose leaf_wrap serves the tree, and by
// a wrapped rotator, which wraps to the tree's 1,000 leaves as well. The group itself is measured at the table's
// first column here; its 1,000-leaf column is TestGroupsBenchAtFullScale's, behind -groups-bench-full.

import (
	"testing"

	"github.com/urnetwork/sidecar"
)

// A config or directory rotation at Team scale: each wrapped reader costs one staged ReaderWrap of about 1.3 KB
// (§10.9's Directory group row), a leaf's rotation stages 5,000 of them and a wrapped rotator's 6,000, in requests
// of at most RotateBatchSize.
func TestGroupsBenchAtTeamScale(t *testing.T) {
	settings := &GroupsBenchSettings{
		LeafCounts:         []int{10},
		WrappedHolderCount: groupsBenchFullHolderCount,
		RotationLeafCount:  groupsBenchConfigTreeLeafCount,
	}
	report := runGroupsBench(t, settings)
	wrap := report.Row(GroupsBenchReaderWrap, 0)
	// §10.9's ~1.3 KB a wrapped reader, within a tenth
	if wrap.ByteCount < 1_300-130 || 1_300+130 < wrap.ByteCount {
		t.Errorf("a staged ReaderWrap is %d B, outside §10.9's ~1.3 KB", wrap.ByteCount)
	}
	byLeaf := report.Row(GroupsBenchRotationByLeaf, groupsBenchFullHolderCount)
	byWrapped := report.Row(GroupsBenchRotationByWrapped, groupsBenchFullHolderCount+groupsBenchConfigTreeLeafCount)
	if byLeaf == nil || byWrapped == nil {
		t.Fatalf("no rotation rows at Team scale")
	}
	if byLeaf.ByteCount != int64(groupsBenchFullHolderCount)*wrap.ByteCount {
		t.Errorf("a leaf's rotation stages %d B for %d wrapped holders of %d B each", byLeaf.ByteCount, groupsBenchFullHolderCount, wrap.ByteCount)
	}
	// a wrapped rotator pays the tree's leaves on top
	if extra := byWrapped.ByteCount - byLeaf.ByteCount; extra != int64(groupsBenchConfigTreeLeafCount)*wrap.ByteCount {
		t.Errorf("a wrapped rotator stages %d B more than a leaf for the tree's %d leaves", extra, groupsBenchConfigTreeLeafCount)
	}
	if byLeaf.Duration <= 0 || byWrapped.Duration <= 0 {
		t.Errorf("a rotation row with no time: %s, %s", byLeaf.Duration, byWrapped.Duration)
	}
	batchSize := sidecar.DefaultGkmSettings().RotateBatchSize
	t.Logf("Team scale: a leaf's rotation stages %d wraps, %d B, in %d requests, %s on this machine; a wrapped rotator's %d wraps, %d B, in %d requests, %s",
		byLeaf.Count, byLeaf.ByteCount, (byLeaf.Count+batchSize-1)/batchSize, byLeaf.Duration,
		byWrapped.Count, byWrapped.ByteCount, (byWrapped.Count+batchSize-1)/batchSize, byWrapped.Duration)
}
