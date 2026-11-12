package evsservice

// EVS2-M10-06's candidates and their hand-off through the push route (FS-65's clauses to the point of PurgeSink;
// DESIGN-DETAILS 10.2.6): a versionless overwrite's record lists what it replaced less what it names, window bit 4 is
// set, and the sink is handed the list once the commit is certain, with each replaced version step 4 read; a refused
// push hands nothing; a 5a retry of the committed push id hands the record's list, its replaced versions read back;
// a rename across two parts lists none of the target's ids at the seal, each part's record carrying its replaced ids
// whole with replaced set, and the sink gets the seal's list alone; FS-71's limit: a staged push is refused at the
// storage limit and one that only removes versionless files passes it.

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A sink recording what it is handed.
type recordingPurgeSink struct {
	stateLock sync.Mutex
	commits   []*PurgeCommit
}

func (self *recordingPurgeSink) Certain(commit *PurgeCommit) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.commits = append(self.commits, commit)
}

func (self *recordingPurgeSink) all() []*PurgeCommit {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.commits)
}

// The format2 gate open to the fixture's network with format 2's own rules, and a recording purge sink.
func (self *pushFixture) openFormat2Checked() *recordingPurgeSink {
	self.t.Helper()
	self.openFormat2()
	self.engine.deps.Format2Rules = nil
	sink := &recordingPurgeSink{}
	self.engine.deps.Purge = sink
	return sink
}

// A versionless version of path at version on base, its one kind-5 locator a versionless upload of plan's push with
// its receipt, which the returned body carries.
func (self *pushFixture) versionlessWrite(plan *sidecar.EvsPushPlan, path sidecar.EvsTokenPath, base uint64, version uint64, label string) ([32]byte, *protocol.EvsUploadReceipt) {
	self.t.Helper()
	segmentId := sha256.Sum256([]byte("purge test segment " + label))
	uploadTime := self.clock.Now().Add(-time.Minute)
	receipt, err := IssueUploadReceipt(self.check.receiptKeys, self.check.repoId, segmentId, 4096, uploadTime, self.check.signerId, true, self.clock.Now())
	if err != nil {
		self.t.Fatal(err)
	}
	plan.NewObjects = append(plan.NewObjects, &sidecar.EvsNewObject{
		Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: segmentId[:], PaddedSize: 4096,
		UploadDay: uint32(uploadTime.UnixMilli() / evsUploadDayMs),
	})
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: path, BaseEntryVersion: base,
		EntryVersion: self.check.versionedEntry(plan, version, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(segmentId, false)),
	})
	return segmentId, receipt
}

// The window entry of the head at version.
func (self *pushFixture) windowEntryAt(version uint64) *sidecar.EvsWindowEntry {
	self.t.Helper()
	head := self.head()
	entry := windowEntryAt(head.Head, version)
	if entry == nil {
		self.t.Fatalf("no window entry at %d", version)
	}
	return entry
}

// The purge list of the record at place, nil for none.
func (self *pushFixture) recordList(place *protocol.EvsPlace) *protocol.EvsPurgeList {
	self.t.Helper()
	recordBytes, err := self.engine.readRecordBytesAt(self.ctx, self.cluster, self.check.repoId, self.check.refId, place)
	if err != nil {
		self.t.Fatal(err)
	}
	_, tail, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
	if err != nil {
		self.t.Fatal(err)
	}
	list, err := tail.PurgeListValue()
	if err != nil {
		self.t.Fatal(err)
	}
	return list
}

func TestPushPurgeHandsACertainCommitsListOnce(t *testing.T) {
	fixture := newPushFixture(t, nil)
	sink := fixture.openFormat2Checked()
	token := fixture.token(fixture.check.signerId)
	x := checkTestPath("x")

	first := fixture.plan()
	firstSegment, firstReceipt := fixture.versionlessWrite(first, x, 0, 1, "v1")
	body := fixture.bodyFormat2(first)
	body.Receipts = []*protocol.EvsUploadReceipt{firstReceipt}
	fixture.requireCommitted(fixture.post(token, body), 1)
	fixture.awaitStepEights()
	if commits := sink.all(); len(commits) != 0 {
		t.Fatalf("a creation handed %d lists", len(commits))
	}
	if fixture.windowEntryAt(1).ReplacesVersionless() {
		t.Error("a creation set window bit 4")
	}

	second := fixture.plan()
	_, secondReceipt := fixture.versionlessWrite(second, x, 1, 2, "v2")
	secondBody := fixture.bodyFormat2(second)
	secondBody.Receipts = []*protocol.EvsUploadReceipt{secondReceipt}
	fixture.requireCommitted(fixture.post(token, secondBody), 2)
	fixture.awaitStepEights()
	entry := fixture.windowEntryAt(2)
	if !entry.ReplacesVersionless() {
		t.Fatal("a versionless overwrite left window bit 4 unset")
	}
	list := fixture.recordList(entry.Place)
	if len(list.GetCandidates()) != 1 || len(list.GetCandidates()[0].GetSegmentIds()) != 1 ||
		[32]byte(list.GetCandidates()[0].GetSegmentIds()[0]) != firstSegment || list.GetCandidates()[0].GetReplacedVersion() != 1 || list.GetReplaced() {
		t.Fatalf("the record's list: %v", list)
	}
	commits := sink.all()
	if len(commits) != 1 || commits[0].Version != 2 || len(commits[0].Replaced) != 1 || commits[0].Replaced[0].Version.GetVersion() != 1 ||
		len(commits[0].List.GetCandidates()) != 1 {
		t.Fatalf("handed %v", commits)
	}

	// a refused push hands nothing: a write on a stale base
	stale := fixture.plan()
	_, staleReceipt := fixture.versionlessWrite(stale, x, 1, 2, "stale")
	staleBody := fixture.bodyFormat2(stale)
	staleBody.Receipts = []*protocol.EvsUploadReceipt{staleReceipt}
	requireRefusal(t, fixture.post(token, staleBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	fixture.awaitStepEights()
	if after := sink.all(); len(after) != 1 {
		t.Fatalf("a refused push handed a list: %d", len(after))
	}

	// a 5a retry of the committed push id: 200 at its version, and the record's list handed, its replaced version
	// read back for the purge's times
	fixture.requireCommitted(fixture.post(token, secondBody), 2)
	fixture.awaitStepEights()
	after := sink.all()
	if len(after) != 2 || after[1].Version != 2 || len(after[1].List.GetCandidates()) != 1 || len(after[1].Replaced) != 1 ||
		after[1].Replaced[0].Version.GetVersion() != 1 || after[1].Replaced[0].Version.GetTimeMs() != commits[0].Replaced[0].Version.GetTimeMs() {
		t.Fatalf("the retry handed %v", after)
	}
}

// A rename of a versionless file whose removal and target fall in two parts: each part's record lists what its
// versions replaced, whole, with replaced set; the seal lists none of the target's ids; the sink gets the seal's list
// alone (DESIGN-DETAILS 10.2.6). A part's list is never handed.
func TestPushPurgeOfARenameAcrossPartsListsAtTheSeal(t *testing.T) {
	fixture := newPushFixture(t, nil)
	sink := fixture.openFormat2Checked()
	token := fixture.token(fixture.check.signerId)

	// x and y sorting first and last among 1,102 paths, so a push in parts holds them in its first and last parts
	paths := []sidecar.EvsTokenPath{}
	for i := 0; i < 1102; i += 1 {
		paths = append(paths, checkTestPath(fmt.Sprintf("pad-%05d", i)))
	}
	slices.SortFunc(paths, sidecar.EvsTokenPath.Compare)
	x, y, padding := paths[0], paths[len(paths)-1], paths[1:len(paths)-1]
	create := fixture.plan()
	segment, receipt := fixture.versionlessWrite(create, x, 0, 1, "x")
	otherSegment, otherReceipt := fixture.versionlessWrite(create, checkTestPath("w"), 0, 1, "w")
	body := fixture.bodyFormat2(create)
	body.Receipts = []*protocol.EvsUploadReceipt{receipt, otherReceipt}
	fixture.requireCommitted(fixture.post(token, body), 1)

	rename := fixture.plan()
	rename.Changes = append(rename.Changes, &sidecar.EvsPlannedChange{TokenPath: x, BaseEntryVersion: 1})
	rename.Changes = append(rename.Changes, &sidecar.EvsPlannedChange{TokenPath: checkTestPath("w"), BaseEntryVersion: 1})
	rename.Changes = append(rename.Changes, &sidecar.EvsPlannedChange{
		TokenPath:    y,
		EntryVersion: fixture.check.versionedEntry(rename, 2, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(segment, false)),
	})
	for _, path := range padding {
		rename.Changes = append(rename.Changes, fixture.check.change(rename, path, 0, 2))
	}
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.check.signingKey, fixture.check.signerId)).BuildFormat2(rename)
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Parts) < 2 {
		t.Fatalf("the rename went in %d parts", len(built.Parts))
	}
	places := make([]*protocol.EvsPlace, len(built.Parts))
	pushId := sidecar.Id(built.Statement.Push.GetPushId())
	for i := range built.Parts {
		places[i] = fixture.requirePlace(fixture.call(token, http.MethodPost, "/push/"+sidecar.EvsKeyId(pushId)+"/"+strconv.Itoa(i+1),
			&protocol.EvsPartRequest{Statement: built.Statement.Bytes, Part: built.Parts[i]}))
	}
	// each part's record: its replaced versions' ids whole, replaced set
	firstList := fixture.recordList(places[0])
	if firstList == nil || !firstList.GetReplaced() || firstList.GetMarked() {
		t.Fatalf("part 1's list: %v", firstList)
	}
	listed := map[[32]byte]bool{}
	for _, candidate := range firstList.GetCandidates() {
		for _, id := range candidate.GetSegmentIds() {
			listed[[32]byte(id)] = true
		}
	}
	if !listed[segment] {
		t.Fatal("part 1's list left out the renamed file's segment, which a part does not subtract")
	}
	fixture.requireCommitted(fixture.post(token, &protocol.EvsPushRequest{Statement: built.Statement.Bytes, PartPlaces: places}), 2)
	fixture.awaitStepEights()
	sealList := fixture.recordList(fixture.windowEntryAt(2).Place)
	if sealList == nil || sealList.GetReplaced() || sealList.GetMarked() {
		t.Fatalf("the seal's list: %v", sealList)
	}
	for _, candidate := range sealList.GetCandidates() {
		for _, id := range candidate.GetSegmentIds() {
			if [32]byte(id) == segment {
				t.Fatal("the seal listed a segment the rename's target names")
			}
		}
	}
	if len(sealList.GetCandidates()) != 1 || [32]byte(sealList.GetCandidates()[0].GetSegmentIds()[0]) != otherSegment {
		t.Fatalf("the seal's list: %v", sealList)
	}
	if !fixture.windowEntryAt(2).ReplacesVersionless() {
		t.Error("the seal left window bit 4 unset")
	}
	commits := sink.all()
	if len(commits) != 1 || commits[0].List.GetReplaced() || len(commits[0].List.GetCandidates()) != 1 {
		t.Fatalf("handed %v", commits)
	}
}

// FS-71's limit cases: at the storage limit a push staging a segment is refused as new payload, and one that only
// removes versionless files adds none and passes.
func TestPushPurgeAtTheStorageLimit(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	token := fixture.token(fixture.check.signerId)
	x := checkTestPath("x")
	first := fixture.plan()
	_, receipt := fixture.versionlessWrite(first, x, 0, 1, "v1")
	body := fixture.bodyFormat2(first)
	body.Receipts = []*protocol.EvsUploadReceipt{receipt}
	fixture.requireCommitted(fixture.post(token, body), 1)

	fixture.check.quota.atLimit(connect.Id(fixture.check.networkId))
	staged := fixture.plan()
	segment, stagedSegment := checkTestStaged(t, staged, "s")
	staged.NewObjects = []*sidecar.EvsNewObject{stagedSegment.NewObject()}
	staged.Changes = []*sidecar.EvsPlannedChange{{
		TokenPath:    checkTestPath("y"),
		EntryVersion: fixture.check.versionedEntry(staged, 2, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(stagedSegment.Id, true)),
	}}
	stagedBody := fixture.bodyFormat2(staged)
	stagedBody.Staged = sidecar.EvsEncodeStaged([][]byte{segment})
	requireRefusal(t, fixture.post(token, stagedBody), http.StatusPaymentRequired, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT)

	removal := fixture.plan()
	removal.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 1}}
	fixture.requireCommitted(fixture.post(token, fixture.body(removal)), 2)
}
