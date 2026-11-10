package sidecartest

// §22.8's groups row (KEYS-M2-31): the harness at reduced scale in every run, and at full scale, 10, 100 and 1,000
// leaves with 5,000 wrapped holders under the ios32 surrogate's memory limit, behind -groups-bench-full. The size
// assertions against §10.6's table are the root's mls_sizes_test.go.

import (
	"flag"
	"testing"
)

var groupsBenchFull = flag.Bool("groups-bench-full", false, "run §22.8's groups row at full scale: 10, 100 and 1,000 leaves, 5,000 wrapped holders, 32 MiB")

// Every row a groups run names, per group and per object.
var groupsBenchGroupRows = []string{
	GroupsBenchAddOnlyCommit, GroupsBenchWelcome, GroupsBenchGroupInfoBlank, GroupsBenchGroupInfoPaths, GroupsBenchSealedGroupInfo,
	GroupsBenchPathCommitBlank, GroupsBenchPathCommitFull, GroupsBenchWelcomeJoin, GroupsBenchWelcomeJoinPeak, GroupsBenchPathCommitPeak,
	GroupsBenchResync, GroupsBenchResyncPeak,
}

var groupsBenchObjectRows = []string{
	GroupsBenchKeyPackage, GroupsBenchReaderKey, GroupsBenchReaderWrap, GroupsBenchReaderWrapLate, GroupsBenchRecoveryWrap,
	GroupsBenchGenRotate, GroupsBenchGenRotateNoLeafWrap, GroupsBenchGenRotateDropKey, GroupsBenchGenWrap, GroupsBenchGroupOwner, GroupsBenchWelcomePointer,
}

// Runs the harness and holds its report to its shape: every row measured at every leaf count, and the relations
// the design's sizes rest on.
func runGroupsBench(t *testing.T, settings *GroupsBenchSettings) *GroupsBenchReport {
	t.Helper()
	report, err := RunGroupsBench(settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("§22.8 groups, %v leaves, %d wrapped holders:\n%s", settings.LeafCounts, settings.WrappedHolderCount, report.Table())
	for _, name := range groupsBenchObjectRows {
		if row := report.Row(name, 0); row == nil || row.ByteCount <= 0 {
			t.Errorf("no measurement of %s", name)
		}
	}
	for _, leafCount := range settings.LeafCounts {
		for _, name := range groupsBenchGroupRows {
			if row := report.Row(name, leafCount); row == nil || row.ByteCount <= 0 && row.Duration <= 0 {
				t.Fatalf("no measurement of %s at %d leaves", name, leafCount)
			}
		}
		blank, full := report.Row(GroupsBenchPathCommitBlank, leafCount), report.Row(GroupsBenchPathCommitFull, leafCount)
		if blank.ByteCount <= full.ByteCount {
			t.Errorf("%d leaves: a path over blank parents is %d B, over a full copath %d B", leafCount, blank.ByteCount, full.ByteCount)
		}
		groupInfoBlank, groupInfoPaths := report.Row(GroupsBenchGroupInfoBlank, leafCount), report.Row(GroupsBenchGroupInfoPaths, leafCount)
		if groupInfoPaths.ByteCount <= groupInfoBlank.ByteCount {
			t.Errorf("%d leaves: the tree did not grow with its parents: %d B then %d B", leafCount, groupInfoBlank.ByteCount, groupInfoPaths.ByteCount)
		}
		// K_groupinfo's seal adds a nonce and a tag, nothing else
		sealed := report.Row(GroupsBenchSealedGroupInfo, leafCount)
		if overhead := sealed.ByteCount - groupInfoPaths.ByteCount; overhead <= 0 || 64 < overhead {
			t.Errorf("%d leaves: the GroupInfo's seal adds %d B", leafCount, overhead)
		}
		// a resync is one path commit from one GroupInfo, whatever the device missed
		if resync := report.Row(GroupsBenchResync, leafCount); blank.ByteCount < resync.ByteCount {
			t.Errorf("%d leaves: a resync of %d B, past a path over blank parents", leafCount, resync.ByteCount)
		}
	}
	byLeaf := report.Row(GroupsBenchRotationByLeaf, settings.WrappedHolderCount)
	byWrapped := report.Row(GroupsBenchRotationByWrapped, settings.WrappedHolderCount+settings.RotationLeafCount)
	if byLeaf == nil || byWrapped == nil || byWrapped.ByteCount <= byLeaf.ByteCount {
		t.Errorf("the config rotation's rows: %+v %+v", byLeaf, byWrapped)
	}
	return report
}

// The reduced run every test run takes: 10 leaves and one tree above the 16-leaf bound.
func TestGroupsBenchAtReducedScale(t *testing.T) {
	runGroupsBench(t, ReducedGroupsBenchSettings())
}

// §22.8's row: 10, 100 and 1,000 leaves, a config rotation re-wrapping to 5,000 holders, and each group's join,
// path commit and resync under the ios32 surrogate's 32 MiB of headroom. It emits the table and holds the 100- and
// 1,000-leaf columns to §10.6's ranges, each figure within a tenth. The heap peaks are reported against the 32 MiB
// and fail nothing here: the bound is the ios32 cell's own run of this harness (§22.9), and this leg's pointers are
// not that cell's.
func TestGroupsBenchAtFullScale(t *testing.T) {
	if !*groupsBenchFull {
		t.Skip("full scale runs with -groups-bench-full")
	}
	settings := DefaultGroupsBenchSettings()
	report := runGroupsBench(t, settings)
	hold := func(name string, leafCount int, low int64, high int64) {
		row := report.Row(name, leafCount)
		if row.ByteCount < low-low/10 || high+high/10 < row.ByteCount {
			t.Errorf("%s at %d leaves: %d B, outside §10.6's %d to %d", name, leafCount, row.ByteCount, low, high)
		}
	}
	// the tree, parents blank to full, in a GroupInfo that adds 1.6 KB; a commit with a path, every parent full to
	// blank
	hold(GroupsBenchGroupInfoBlank, 100, 158_000+1_600, 282_000+1_600)
	hold(GroupsBenchGroupInfoPaths, 100, 158_000+1_600, 282_000+1_600)
	hold(GroupsBenchPathCommitFull, 100, 18_000, 126_000)
	hold(GroupsBenchPathCommitBlank, 100, 18_000, 126_000)
	hold(GroupsBenchGroupInfoBlank, 1000, 1_580_000+1_600, 2_830_000+1_600)
	hold(GroupsBenchGroupInfoPaths, 1000, 1_580_000+1_600, 2_830_000+1_600)
	hold(GroupsBenchPathCommitFull, 1000, 26_000, 1_180_000)
	hold(GroupsBenchPathCommitBlank, 1000, 26_000, 1_180_000)
	// a device a week behind a full group comes back from one GroupInfo by one commit with a path
	hold(GroupsBenchResync, 1000, 26_000, 1_180_000)
	for _, leafCount := range settings.LeafCounts {
		for _, name := range []string{GroupsBenchWelcomeJoinPeak, GroupsBenchPathCommitPeak, GroupsBenchResyncPeak} {
			if peak := report.Row(name, leafCount); settings.MemoryLimitByteCount < peak.ByteCount {
				t.Logf("%s at %d leaves: %d B on this leg, past the ios32 surrogate's %d", name, leafCount, peak.ByteCount, settings.MemoryLimitByteCount)
			}
		}
	}
}
