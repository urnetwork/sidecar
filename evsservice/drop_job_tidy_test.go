package evsservice

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// Owner decision 570 (QD-1021; §11.13's table row, §2.8's evs-28): an ended job's snap-0 stays past the 30 d its other
// files get, as its list files do, so `sidecarctl evs drop-reindex` can still read which drops the job covered. A job
// run to done leaves snap-0, a later round's snap, cand, mark and del; with a list file, a held file and a dry run's
// ask and res beside them, one second short of the retention every file stands, and at it only snap-0 and the list
// file do, each with the bytes it had, again a retention later.
func TestDropJobTidyKeepsSnapZeroAndTheListFilesPastTheRetention(t *testing.T) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	fixture.appendDrop("drop-1", world.clock.Now())
	fixture.marker.marks = []DropScanId{fixture.b}
	fixture.ripen()
	if result := fixture.run(); !result.Ended || result.Moved[DropStateDone] != 1 {
		t.Fatalf("the run: %+v", result)
	}
	jobId := fixture.resolver.requests[0].JobId
	previewId := testId("preview-1")
	files := fixture.files(jobId)
	previewFiles := fixture.files(previewId)

	// what resolve's stand-in and this job's one round do not write: the listed index, a hold's ids and a dry run
	drop := fixture.entry("drop-1")
	listFiles, err := EncodeDropListFiles(world.repoId, jobId, []*dropListInput{{
		drop: &DropListDrop{DropId: drop.DropId, RefId: drop.RefId, Version: drop.Version, PushId: drop.PushId},
		rows: []*dropHit{{entrySha256: [32]byte{7}}},
	}}, DefaultDropSettings())
	if err != nil || len(listFiles) != 1 {
		t.Fatalf("%d list files: %v", len(listFiles), err)
	}
	if err := files.Put(world.ctx, DropFileList, 0, listFiles[0]); err != nil {
		t.Fatal(err)
	}
	held, err := EncodeDropIdFile(DropFileHeld, world.repoId, jobId, 0, []DropScanId{fixture.a})
	if err != nil {
		t.Fatal(err)
	}
	if err := files.Put(world.ctx, DropFileHeld, 0, held); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []DropFileKind{DropFileAsk, DropFileRes} {
		message, err := EncodeDropMessageFile(kind, world.repoId, previewId, []byte("a dry run's message"))
		if err != nil {
			t.Fatal(err)
		}
		if err := previewFiles.Put(world.ctx, kind, 0, message); err != nil {
			t.Fatal(err)
		}
	}

	segmentCluster, err := world.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	// every dropscan/ key of the repo, with its bytes as the fake store dumps them
	dropscan := func() map[string][]byte {
		t.Helper()
		prefix := segmentCluster.ClusterId() + "/" + dropscanKeyPrefix + sidecar.EvsKeyId(world.repoId) + "/"
		found := map[string][]byte{}
		for name, dumped := range world.host.Blobs.Dump() {
			if strings.HasPrefix(name, prefix) {
				found[name] = dumped
			}
		}
		return found
	}
	name := func(id sidecar.Id, kind DropFileKind, sequence uint32) string {
		return segmentCluster.ClusterId() + "/" + DropFileKey(world.repoId, id, kind, sequence)
	}
	before := dropscan()
	for _, want := range []string{
		name(jobId, DropFileSnap, 0), name(jobId, DropFileSnap, 1), name(jobId, DropFileCand, 0), name(jobId, DropFileMark, 0),
		name(jobId, DropFileDel, 0), name(jobId, DropFileList, 0), name(jobId, DropFileHeld, 0),
		name(previewId, DropFileAsk, 0), name(previewId, DropFileRes, 0),
	} {
		if _, ok := before[want]; !ok {
			t.Fatalf("the ended job left no %s, so this shows nothing of it; it left %v", want, slices.Sorted(maps.Keys(before)))
		}
	}

	// a second short of the retention, counted from the newest file: nothing goes
	world.clock.Advance(fixture.job.settings.EndedRetention - time.Second)
	fixture.run()
	if after := dropscan(); len(after) != len(before) {
		t.Fatalf("short of the retention %d of %d files stand", len(after), len(before))
	}

	// at it: every file but snap-0 and the list file goes, the dry run's too
	world.clock.Advance(time.Second)
	fixture.run()
	wantKept := []string{name(jobId, DropFileList, 0), name(jobId, DropFileSnap, 0)}
	slices.Sort(wantKept)
	kept := dropscan()
	if got := slices.Sorted(maps.Keys(kept)); !slices.Equal(got, wantKept) {
		t.Fatalf("past the retention %v stand, want %v", got, wantKept)
	}
	for _, keptName := range wantKept {
		if string(kept[keptName]) != string(before[keptName]) {
			t.Fatalf("%s changed", keptName)
		}
	}
	snap, err := files.Read(world.ctx, DropFileSnap, 0)
	if err != nil || snap == nil || len(snap.Covered) != 1 || snap.Covered[0].DropId != drop.DropId || snap.Covered[0].RefId != drop.RefId ||
		snap.Covered[0].Version != drop.Version || snap.Covered[0].PushId != drop.PushId {
		t.Fatalf("snap-0 past the retention: %+v, %v", snap, err)
	}
	if round, err := files.Read(world.ctx, DropFileSnap, 1); err != nil || round != nil {
		t.Fatalf("a later round's snap past the retention: %+v, %v", round, err)
	}

	// and for the repo's life: another retention on, both stand
	world.clock.Advance(fixture.job.settings.EndedRetention)
	fixture.run()
	if got := slices.Sorted(maps.Keys(dropscan())); !slices.Equal(got, wantKept) {
		t.Fatalf("two retentions on %v stand, want %v", got, wantKept)
	}
}

// Nothing is deleted while the segment cluster has not passed the settle cases, the retention passed or not.
func TestDropJobTidyDeletesNothingOnAnUnsettledSegmentCluster(t *testing.T) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	fixture.appendDrop("drop-1", world.clock.Now())
	fixture.ripen()
	if result := fixture.run(); !result.Ended {
		t.Fatalf("the run: %+v", result)
	}
	segmentCluster, err := world.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	before := len(world.host.Blobs.Dump())
	world.host.Blobs.SetSettlePassed(segmentCluster.ClusterId(), false)
	world.clock.Advance(2 * fixture.job.settings.EndedRetention)
	fixture.run()
	if after := len(world.host.Blobs.Dump()); after != before {
		t.Fatalf("an unsettled cluster holds %d objects, held %d", after, before)
	}
}
