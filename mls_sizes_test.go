//go:build !sidecar_http

// §10.6's size table held to what the real subset and the real ladder produce (KEYS-M2-31; D-KEYS-10, D-KEYS-14):
// the 10-leaf column and the per-object rows, measured by sidecartest's groups harness at reduced scale, within the
// table's ranges. The 100- and 1,000-leaf columns are the harness's full run (sidecartest, -groups-bench-full).

package sidecar_test

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// One row of §10.6's table as a range of bytes.
type mlsSizeRange struct {
	name  string
	count int
	low   int64
	high  int64
}

// TestMlsSizesHoldSection106sTable: the table's 10-leaf column and its per-object rows. The table's figures are
// rounded estimates from RFC 9420's structures, so each is taken within a tenth, a range at both of its ends; a
// figure the table gives as approximate, its GenRotate rows, within three tenths, since a GenRotate's size moves
// with its optional fields (a leaf_wrap, a drop key).
func TestMlsSizesHoldSection106sTable(t *testing.T) {
	report, err := sidecartest.RunGroupsBench(sidecartest.ReducedGroupsBenchSettings())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("measured:\n%s", report.Table())
	between := func(name string, count int, low int64, high int64) mlsSizeRange {
		return mlsSizeRange{name: name, count: count, low: low - low/10, high: high + high/10}
	}
	ranges := []mlsSizeRange{
		// tree 16-27 KB, parents blank to full, in a GroupInfo that adds 1.6 KB
		between(sidecartest.GroupsBenchGroupInfoBlank, 10, 16_000+1_600, 27_000+1_600),
		between(sidecartest.GroupsBenchGroupInfoPaths, 10, 16_000+1_600, 27_000+1_600),
		// under 50 KB at 16 leaves or fewer, inside each epoch object
		{name: sidecartest.GroupsBenchSealedGroupInfo, count: 10, low: 16_000, high: 50_000},
		// a commit with a path: 11-17 KB, every parent full to blank
		between(sidecartest.GroupsBenchPathCommitFull, 10, 11_000, 17_000),
		between(sidecartest.GroupsBenchPathCommitBlank, 10, 11_000, 17_000),
		// a resync is a commit with a path
		between(sidecartest.GroupsBenchResync, 10, 11_000, 17_000),
		// GenWrap, LeafWrap and GenLink: 72 B exactly
		{name: sidecartest.GroupsBenchGenWrap, low: 72, high: 72},
	}
	within := func(name string, count int, byteCount int64, tenths int64) {
		ranges = append(ranges, mlsSizeRange{name: name, count: count, low: byteCount - byteCount*tenths/10, high: byteCount + byteCount*tenths/10})
	}
	within(sidecartest.GroupsBenchKeyPackage, 0, 2_850, 1)
	// 0.2 KB plus 2.85 KB a joiner, and 0.4 KB plus 1.2 KB a joiner, with 9 joiners
	within(sidecartest.GroupsBenchAddOnlyCommit, 10, 200+9*2_850, 1)
	within(sidecartest.GroupsBenchWelcome, 10, 400+9*1_200, 1)
	within(sidecartest.GroupsBenchReaderKey, 0, 1_340, 1)
	within(sidecartest.GroupsBenchReaderWrap, 0, 1_370, 1)
	within(sidecartest.GroupsBenchReaderWrapLate, 0, 1_420, 1)
	within(sidecartest.GroupsBenchRecoveryWrap, 0, 1_170, 1)
	within(sidecartest.GroupsBenchGenRotate, 0, 500, 3)
	within(sidecartest.GroupsBenchGenRotateDropKey, 0, 1_700, 3)
	for _, sizeRange := range ranges {
		row := report.Row(sizeRange.name, sizeRange.count)
		if row == nil {
			t.Errorf("%s: not measured", sizeRange.name)
			continue
		}
		if row.ByteCount < sizeRange.low || sizeRange.high < row.ByteCount {
			t.Errorf("%s at %d leaves: %d B, outside §10.6's %d to %d", sizeRange.name, sizeRange.count, row.ByteCount, sizeRange.low, sizeRange.high)
		}
	}
	// a path over a full copath is the low end and one over blank parents the high end
	if full, blank := report.Row(sidecartest.GroupsBenchPathCommitFull, 10), report.Row(sidecartest.GroupsBenchPathCommitBlank, 10); full != nil && blank != nil && blank.ByteCount <= full.ByteCount {
		t.Errorf("a path over blank parents of %d B, over a full copath %d B", blank.ByteCount, full.ByteCount)
	}
	// DESIGN-DETAILS 6.2.2's two objects: small, and the same whatever the group
	for _, name := range []string{sidecartest.GroupsBenchGroupOwner, sidecartest.GroupsBenchWelcomePointer} {
		if row := report.Row(name, 0); row == nil || row.ByteCount <= 0 || 96 < row.ByteCount {
			t.Errorf("%s: %+v", name, row)
		}
	}
}
