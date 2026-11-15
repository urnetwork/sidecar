package fault

// FS-96 on T2 (EVSB-M10-04, EVSB-M10-06; DESIGN-DETAILS 10.6): the drop job's interactions. A git-mode ref's history
// segments stay through a drop in its repo (G11); the stored count falls by each deleted seg/ object's stored size as
// deletes land, slots reporting nothing; observe deletes nothing and records its delete set, verify agreeing with mark;
// and a job's resolve run again writes equal list files, as a re-seeded job's does. The DROP's index rewrites, mirrors,
// a re-seed from a stale mirror and a drive's heal are other tasks' and T3's.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// A git-mode ref's history segments, named by its pushes' new-objects lists and by no entry version, stay through a
// drop whose listed version names one of them by its bytes: only what the listed version alone names goes.
func TestFs96GitHistorySegmentsStayThroughADrop(t *testing.T) {
	world := newFsDropWorld(t)
	refA, refG := fsDropId16("ref a"), fsDropId16("ref g")
	h1, h2, x1 := fsDropSegment("h1"), fsDropSegment("h2"), fsDropSegment("x1")
	world.storeSegment(h1, 1000)
	world.storeSegment(h2, 1000)
	world.commit(refG, protocol.EvsRefMode_EVS_REF_GIT, &fsDropPush{
		changes: []*fsDropChange{{path: fsDropPath("g"), spec: &fsDropEntry{version: 1, inline: true}}},
		newObjects: []*sidecar.EvsNewObject{
			{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: h1[:], PaddedSize: 4096, UploadDay: 1},
			{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: h2[:], PaddedSize: 4096, UploadDay: 1},
		},
	})
	x := fsDropPath("x")
	listed := world.write(refA, x, 0, &fsDropEntry{segments: [][32]byte{h1, x1}})
	dropId := fsDropId16("drop x")
	world.drop(refA, dropId, []*protocol.EvsDropPath{fsDropPathOf(2, 1, nil, fsDropSource(1, x))}, [][][]byte{{listed}})
	world.ripen(50 * time.Hour)
	if result := world.runToEnd(world.job("a"), 8); !result.Ended || world.dropState(dropId) != evsservice.DropStateDone {
		t.Fatalf("the job: %+v", result)
	}
	if !world.stored(h1) || !world.stored(h2) || world.stored(x1) {
		t.Fatalf("h1 %t, h2 %t, x1 %t", world.stored(h1), world.stored(h2), world.stored(x1))
	}
}

// The stored count falls by each deleted seg/ object's stored size, a deleted slot reporting nothing.
func TestFs96StoredBytesFallByEachDeletedSegmentAndSlotsReportNothing(t *testing.T) {
	world := newFsDropWorld(t)
	refA := fsDropId16("ref a")
	x := fsDropPath("x")
	slot := fsDropId16("slot k")
	first := world.write(refA, x, 0, &fsDropEntry{segments: [][32]byte{fsDropSegment("a"), fsDropSegment("b")}, slots: []sidecar.Id{slot}})
	second := world.write(refA, x, 1, &fsDropEntry{segments: [][32]byte{fsDropSegment("c")}})
	dropId := fsDropId16("drop x")
	world.drop(refA, dropId, []*protocol.EvsDropPath{fsDropPathOf(3, 1, nil, fsDropSource(1, x))}, [][][]byte{{first, second}})
	world.ripen(50 * time.Hour)
	world.runToEnd(world.job("a"), 8)
	if world.slotStored(slot) {
		t.Fatal("the listed versions' slot stayed")
	}
	if delta := world.host.Quota.StoredDelta(connect.Id(world.networkId)); delta != -3000 {
		t.Fatalf("stored delta %d, want three segments' 3000 and nothing for the slot", delta)
	}
}

// §19.11's observe (D-TEST-18): executing ends after verify, which agrees with mark, with every id of D recorded as
// observed and nothing deleted; once drop turns on, the observed drop runs again and deletes.
func TestFs96ObserveDeletesNothingAndRecordsItsDeleteSet(t *testing.T) {
	history := newFs90History(t)
	world := history.world
	world.format2.mode = sidecar.Format2Observe
	world.runToEnd(world.job("a"), 8)
	if state := world.dropState(history.dropId); state != evsservice.DropStateObserved {
		t.Fatalf("drop state %d under observe", state)
	}
	if !world.stored(history.d1) || !world.stored(history.d2) {
		t.Fatal("observe deleted")
	}
	answers, err := evsservice.NewDropFiles(world.segment, world.repoId, world.onlyJobId(), world.dropSettings).Answers(world.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 2 || answers[evsservice.DropSegmentId(history.d1)] != evsservice.DropOutcomeObserved ||
		answers[evsservice.DropSegmentId(history.d2)] != evsservice.DropOutcomeObserved {
		t.Fatalf("observe recorded %v, want d1 and d2 observed", answers)
	}
	world.format2.mode = sidecar.Format2On
	world.ripen(time.Hour)
	world.runToEnd(world.job("a"), 8)
	history.requireDone(t)
}

// The one job id whose files the segment cluster holds.
func (self *fsDropWorld) onlyJobId() sidecar.Id {
	self.t.Helper()
	jobIds := map[sidecar.Id]bool{}
	prefix := "dropscan/" + sidecar.EvsKeyId(self.repoId) + "/"
	for key := range self.host.Blobs.Dump() {
		_, objectKey, _ := strings.Cut(key, "/")
		rest, ok := strings.CutPrefix(objectKey, prefix)
		if !ok {
			continue
		}
		jobText, _, _ := strings.Cut(rest, "/")
		jobId, err := sidecar.ParseId(jobText)
		if err != nil {
			self.t.Fatal(err)
		}
		jobIds[jobId] = true
	}
	if len(jobIds) != 1 {
		self.t.Fatalf("%d jobs' files", len(jobIds))
	}
	for jobId := range jobIds {
		return jobId
	}
	return sidecar.Id{}
}

// A job's resolve run again over its covered drops, as a re-seeded job's is, writes its list files byte for byte again.
func TestFs96ResolveRunAgainWritesEqualListFiles(t *testing.T) {
	history := newFs90History(t)
	world := history.world
	world.runToEnd(world.job("a"), 8)
	history.requireDone(t)
	before := map[string][]byte{}
	var jobPrefix string
	for key, value := range world.host.Blobs.Dump() {
		if strings.Contains(key, "/list-") {
			before[key] = value
			jobPrefix = key[:strings.LastIndex(key, "/")]
		}
	}
	if len(before) != 1 {
		t.Fatalf("%d list files", len(before))
	}
	jobId, err := sidecar.ParseId(jobPrefix[strings.LastIndex(jobPrefix, "/")+1:])
	if err != nil {
		t.Fatal(err)
	}
	snap, err := evsservice.NewDropFiles(world.segment, world.repoId, jobId, world.dropSettings).Read(world.ctx, evsservice.DropFileSnap, 0)
	if err != nil || snap == nil {
		t.Fatalf("snap-0: %v", err)
	}
	resolver, err := evsservice.NewDropResolve(world.host.ServiceHost(), &evsservice.DropResolveDeps{Settings: world.dropSettings, EvsSettings: world.settings})
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.Resolve(world.ctx, &evsservice.DropResolveRequest{
		Cluster: world.cluster, SegmentCluster: world.segment, RepoId: world.repoId, JobId: jobId, Drops: snap.Covered,
	})
	if err != nil || len(result.Mismatch) != 0 {
		t.Fatalf("resolve again: %+v, %v", result, err)
	}
	for key, value := range world.host.Blobs.Dump() {
		if strings.Contains(key, "/list-") && !bytes.Equal(before[key], value) {
			t.Fatalf("%s rewritten with other bytes", key)
		}
	}
}
