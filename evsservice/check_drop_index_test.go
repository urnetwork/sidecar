package evsservice

// QD-1078's DROP index rewrites on evs (§11.14's drop row, §11.7's boundary and refused rows, §11.8's 5d and 5h;
// question evs2-m10-21-drop-index-rewrites, option 1), each refusal with a passing twin: beside its written lineages a
// DROP rewrites standing index files of versioning 2 in place, padded to the replaced length, and commits with them,
// the replaced versions going to the purge; a creation, a removal or a directory delta beside the lineages, a write of
// no index file, a rewrite of a file that is no index file or of another version than its newest, and one past Padmé
// of the chain it replaces each answer 409 DROP_BOUNDARY, recorded, naming the path; a rewrite of an index file that
// stands only on another ref, as `ur/index`'s do, is a creation on the DROP's own ref and refused so; a DROP whose
// rewrites name an index_epoch below the head's gets 409 INDEX_EPOCH, final, one above it recorded, and its twin
// naming the head's commits, while a DROP writing no index file passes 5d whatever it names; and the fold takes each
// rewrite as an ordinary write, setting no drop mark and raising no alarm, where a DROP's other unnamed write still
// alarms.

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The index files the tests rewrite: a writer's head and a bucket shard, under the index root of the fixture's ref.
func dropIndexTestPaths() (sidecar.EvsTokenPath, sidecar.EvsTokenPath) {
	return checkTestPath(".ur-index", "head"), checkTestPath(".ur-index", "shard")
}

// The payload bytes of the records the tests' index files hold, and so the length a rewrite pads to.
const dropIndexTestBodyByteCount = 100

// A write of an index file at version on base by plan's push: versioning 2, one staged record of bodyByteCount
// payload bytes. The staged bytes it carries.
func dropIndexTestRewrite(t *testing.T, fixture *checkFixture, plan *sidecar.EvsPushPlan, path sidecar.EvsTokenPath, base uint64, version uint64, label string, bodyByteCount uint64) []byte {
	t.Helper()
	segment, staged := checkTestStaged(t, plan, label)
	plan.NewObjects = append(plan.NewObjects, staged.NewObject())
	locator := checkTestKind5Locator(staged.Id, true)
	locator.Length = uint32(sidecar.EvsRecordByteCount(bodyByteCount))
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: path, BaseEntryVersion: base,
		EntryVersion: fixture.versionedEntry(plan, version, protocol.EvsVersioning_EVS_VERSIONING_INDEX, locator),
	})
	return segment
}

// A one-part DROP's view as dropTestView builds it, a written boundary over x at version 2, with the changes add
// appends to its plan and the staged bytes they carry.
func dropIndexTestView(t *testing.T, fixture *checkFixture, add func(plan *sidecar.EvsPushPlan) [][]byte) *PushView {
	t.Helper()
	x := checkTestPath("x")
	plan := fixture.plan()
	plan.BaseVersion = 2
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
	base := fixture.fileEntry(plan, 2, nil)
	baseHash := sha256.Sum256(base)
	history := &protocol.EvsDropHistory{
		DropId: testId("index view drop").Bytes(), Action: 1, NotBeforeMs: plan.TimeMs + sidecar.DefaultEvsFormatSettings().DropWindowMs(),
		Paths: []*protocol.EvsDropPath{{Lineage: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: x.Components()}}, ThroughVersion: 3, Boundary: 1}},
	}
	lists, err := sidecar.EvsBuildDropLists(history.GetPaths(), [][][]byte{{baseHash[:]}})
	if err != nil {
		t.Fatal(err)
	}
	plan.DropLists = lists
	marshal := proto.MarshalOptions{Deterministic: true}
	if plan.DropBody, err = marshal.Marshal(history); err != nil {
		t.Fatal(err)
	}
	plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 2, EntryVersion: fixture.fileEntry(plan, 3, nil)}}
	staged := add(plan)
	view := fixture.viewFormat2(plan, staged)
	view.Head = checkTestHead(view, 2)
	view.Rights |= sidecar.AclEvsAdmin
	view.Paths[x.KeyString()] = &PathRead{Newest: &EvsNewest{Exists: true, Version: 2, CommitVersion: 2, IndexVersion: &protocol.EvsIndexVersion{EntryVersion: base, CommitVersion: 2}}}
	view.Drop = &PushDropReads{ListSlices: [][]byte{lists}, Removed: map[int]*DropRemovedRead{}, CancelMargin: time.Minute}
	return view
}

// An index file standing in view at version 1, committed by an earlier push: versioning, one kind-5 record of
// dropIndexTestBodyByteCount payload bytes that push uploaded.
func dropIndexTestStanding(fixture *checkFixture, view *PushView, path sidecar.EvsTokenPath, versioning protocol.EvsVersioning) {
	fixture.t.Helper()
	earlier := fixture.plan()
	locator := checkTestKind5Locator(sha256.Sum256([]byte("standing "+path.KeyString())), false)
	locator.Length = uint32(sidecar.EvsRecordByteCount(dropIndexTestBodyByteCount))
	if versioning == protocol.EvsVersioning_EVS_VERSIONING_KEPT {
		locator = &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: bytes.Repeat([]byte{1}, dropIndexTestBodyByteCount)}
	}
	checkTestNewest(view, path, fixture.versionedEntry(earlier, 1, versioning, locator), 1)
}

// The boundary rule's index row over views: a rewrite padded to the replaced length, one up to its Padmé step, a
// shorter one, as a CLOSURE's may be, and a head and a shard together pass, and 5d holds the DROP to the head's
// index_epoch; each other change no written lineage names is DROP_BOUNDARY naming its path, and a standing version
// step 4 gave no bytes of refuses 503.
func TestCheckDropBoundaryTakesIndexRewrites(t *testing.T) {
	fixture := newCheckFixture(t)
	head, shard := dropIndexTestPaths()
	rewrite := func(path sidecar.EvsTokenPath, bodyByteCount uint64) func(plan *sidecar.EvsPushPlan) [][]byte {
		return func(plan *sidecar.EvsPushPlan) [][]byte {
			return [][]byte{dropIndexTestRewrite(t, fixture, plan, path, 1, 2, path.KeyString(), bodyByteCount)}
		}
	}
	padmeBodyByteCount := uint64(0)
	for sidecar.EvsRecordByteCount(padmeBodyByteCount+1) <= sidecar.EvsPadme(sidecar.EvsRecordByteCount(dropIndexTestBodyByteCount)) {
		padmeBodyByteCount += 1
	}
	if padmeBodyByteCount <= dropIndexTestBodyByteCount {
		t.Fatalf("no Padmé step above a record of %d bytes", dropIndexTestBodyByteCount)
	}
	standingIndex := func(view *PushView) {
		dropIndexTestStanding(fixture, view, head, protocol.EvsVersioning_EVS_VERSIONING_INDEX)
	}
	for _, c := range []struct {
		name  string
		add   func(plan *sidecar.EvsPushPlan) [][]byte
		stand func(view *PushView)
		// the refusal, 0 to pass, and the path a DROP_BOUNDARY names, nil for head
		reason EvsCheckReason
		named  sidecar.EvsTokenPath
	}{
		{name: "a rewrite padded to the replaced length", add: rewrite(head, dropIndexTestBodyByteCount), stand: standingIndex},
		{name: "a rewrite up to the replaced length's Padmé step", add: rewrite(head, padmeBodyByteCount), stand: standingIndex},
		{name: "a shorter rewrite", add: rewrite(head, dropIndexTestBodyByteCount/2), stand: standingIndex},
		{name: "a head and a shard", stand: func(view *PushView) {
			standingIndex(view)
			dropIndexTestStanding(fixture, view, shard, protocol.EvsVersioning_EVS_VERSIONING_INDEX)
		}, add: func(plan *sidecar.EvsPushPlan) [][]byte {
			return append(rewrite(head, dropIndexTestBodyByteCount)(plan), rewrite(shard, dropIndexTestBodyByteCount)(plan)...)
		}},
		{name: "a rewrite past the Padmé step", add: rewrite(head, padmeBodyByteCount+1), stand: standingIndex, reason: EvsCheckReasonDropBoundary},
		{name: "a creation", reason: EvsCheckReasonDropBoundary, add: func(plan *sidecar.EvsPushPlan) [][]byte {
			return [][]byte{dropIndexTestRewrite(t, fixture, plan, head, 0, 3, "creation", dropIndexTestBodyByteCount)}
		}},
		{name: "a removal", stand: standingIndex, reason: EvsCheckReasonDropBoundary, add: func(plan *sidecar.EvsPushPlan) [][]byte {
			plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: head, BaseEntryVersion: 1})
			return nil
		}},
		{name: "a directory delta", reason: EvsCheckReasonDropBoundary, named: head[:1], stand: func(view *PushView) {
			view.Paths[head[:1].KeyString()] = &PathRead{Newest: &EvsNewest{Exists: true, Directory: true, Version: 1, CommitVersion: 1}}
		}, add: func(plan *sidecar.EvsPushPlan) [][]byte {
			rows := []*protocol.EvsName{{Token: head[1][:], Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: []byte("sealed head")}}
			plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: head[:1], BaseEntryVersion: 1, EntryVersion: fixture.directoryEntry(plan, 2, rows, nil)})
			return nil
		}},
		{name: "a write of no index file", stand: standingIndex, reason: EvsCheckReasonDropBoundary, add: func(plan *sidecar.EvsPushPlan) [][]byte {
			plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: head, BaseEntryVersion: 1, EntryVersion: fixture.fileEntry(plan, 2, nil)})
			return nil
		}},
		{name: "a versionless write", stand: standingIndex, reason: EvsCheckReasonDropBoundary, add: func(plan *sidecar.EvsPushPlan) [][]byte {
			segment, staged := checkTestStaged(t, plan, "versionless")
			plan.NewObjects = append(plan.NewObjects, staged.NewObject())
			plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: head, BaseEntryVersion: 1,
				EntryVersion: fixture.versionedEntry(plan, 2, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(staged.Id, true))})
			return [][]byte{segment}
		}},
		{name: "a rewrite of a file that is no index file", add: rewrite(head, dropIndexTestBodyByteCount), reason: EvsCheckReasonDropBoundary, stand: func(view *PushView) {
			dropIndexTestStanding(fixture, view, head, protocol.EvsVersioning_EVS_VERSIONING_KEPT)
		}},
		{name: "a rewrite of another version than the newest", stand: standingIndex, reason: EvsCheckReasonDropBoundary, add: func(plan *sidecar.EvsPushPlan) [][]byte {
			return [][]byte{dropIndexTestRewrite(t, fixture, plan, head, 2, 3, "another version", dropIndexTestBodyByteCount)}
		}},
		{name: "a standing version step 4 gave no bytes of", add: rewrite(head, dropIndexTestBodyByteCount), reason: EvsCheckReasonUnchecked, stand: func(view *PushView) {
			view.Paths[head.KeyString()] = &PathRead{Newest: &EvsNewest{Exists: true, Version: 1, CommitVersion: 1}}
		}},
	} {
		view := dropIndexTestView(t, fixture, c.add)
		if c.stand != nil {
			c.stand(view)
		}
		refusal := CheckDropBoundary(view)
		if c.reason == 0 {
			requireCheckPass(t, c.name, refusal)
			continue
		}
		requireCheckRefusal(t, c.name, refusal, c.reason)
		named := c.named
		if named == nil {
			named = head
		}
		if c.reason == EvsCheckReasonDropBoundary && refusal != nil && (len(refusal.Paths) != 1 || !refusal.Paths[0].Equal(named)) {
			t.Errorf("%s: names %v", c.name, refusal.Paths)
		}
	}

	// 5d holds a DROP carrying index rewrites to the head's index_epoch, as any push writing an index file, and a DROP
	// writing none to nothing
	for _, at := range []struct {
		name   string
		epoch  uint64
		reason EvsCheckReason
	}{
		{name: "at the head's epoch", epoch: 5},
		{name: "below it", epoch: 4, reason: EvsCheckReasonIndexEpochBelow},
		{name: "above it", epoch: 6, reason: EvsCheckReasonIndexEpochAbove},
	} {
		view := dropIndexTestView(t, fixture, func(plan *sidecar.EvsPushPlan) [][]byte {
			plan.IndexEpoch = at.epoch
			return rewrite(head, dropIndexTestBodyByteCount)(plan)
		})
		view.Head.IndexEpoch = 5
		refusal := CheckIndexEpoch(view)
		if at.reason == 0 {
			requireCheckPass(t, "a DROP's rewrites "+at.name, refusal)
		} else {
			requireCheckRefusal(t, "a DROP's rewrites "+at.name, refusal, at.reason)
		}
		bare := dropIndexTestView(t, fixture, func(plan *sidecar.EvsPushPlan) [][]byte {
			plan.IndexEpoch = at.epoch
			return nil
		})
		bare.Head.IndexEpoch = 5
		requireCheckPass(t, "a DROP of no index file naming an epoch "+at.name, CheckIndexEpoch(bare))
	}
}

// The drop fixture with two index files standing beside x, a writer's head and a bucket shard, each created as one
// staged record of versioning 2 in one push at the head's index_epoch.
type dropIndexTestFixture struct {
	*dropTestFixture
	indexHead  sidecar.EvsTokenPath
	indexShard sidecar.EvsTokenPath
	// the path version both index files stand at
	indexVersion uint64
	seq          int
}

func newDropIndexTestFixture(t *testing.T, versions int) *dropIndexTestFixture {
	fixture := &dropIndexTestFixture{dropTestFixture: newDropTestFixture(t, versions)}
	fixture.indexHead, fixture.indexShard = dropIndexTestPaths()
	plan := fixture.plan()
	version := plan.BaseVersion + 1
	staged := [][]byte{
		dropIndexTestRewrite(t, fixture.check, plan, fixture.indexHead, 0, version, "head 0", dropIndexTestBodyByteCount),
		dropIndexTestRewrite(t, fixture.check, plan, fixture.indexShard, 0, version, "shard 0", dropIndexTestBodyByteCount),
	}
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), fixture.bodyStaged(plan, staged)), version)
	fixture.awaitStepEights()
	fixture.indexVersion = version
	return fixture
}

// A drop of x at its written boundary that rewrites both index files in place, padded to their length, naming epoch.
func (self *dropIndexTestFixture) dropWithRewrites(epoch uint64) (*sidecar.EvsPushPlan, *protocol.EvsDropHistory, [][]byte) {
	self.t.Helper()
	self.seq += 1
	plan, history := self.dropPlan(false, self.listedBelow(self.newest+1))
	plan.IndexEpoch = epoch
	staged := [][]byte{}
	for _, path := range []sidecar.EvsTokenPath{self.indexHead, self.indexShard} {
		label := path.KeyString() + " rewrite " + string(rune('a'+self.seq))
		staged = append(staged, dropIndexTestRewrite(self.t, self.check, plan, path, self.indexVersion, self.indexVersion+1, label, dropIndexTestBodyByteCount))
	}
	return plan, history, staged
}

// plan with its staged bytes posted under the admin token.
func (self *dropIndexTestFixture) postStaged(plan *sidecar.EvsPushPlan, staged [][]byte) *httptest.ResponseRecorder {
	return self.post(self.adminToken(), self.bodyStaged(plan, staged))
}

// A DROP with its rewrites committed at version: x's kept head then its newest, the index files one version on.
func (self *dropIndexTestFixture) commitRewrites(plan *sidecar.EvsPushPlan, staged [][]byte, version uint64) {
	self.t.Helper()
	self.requireCommitted(self.postStaged(plan, staged), version)
	self.awaitStepEights()
	for _, change := range plan.Changes {
		if change.TokenPath.Equal(self.x) {
			self.newest += 1
			digest := sha256.Sum256(change.EntryVersion)
			self.hashes[self.newest] = digest[:]
		}
	}
	self.indexVersion += 1
}

// The version path's newest stands at, and the ref version that committed it, as a read answers.
func (self *dropIndexTestFixture) newestOf(path sidecar.EvsTokenPath) (uint64, uint64) {
	self.t.Helper()
	reply := self.readPath(self.token(self.check.signerId), 0, true, path)
	version := reply.paths[0].GetVersion()
	if version == nil {
		self.t.Fatalf("no version of a path: %v", reply.paths[0])
	}
	entry, err := parseEvsEntryVersion(version.GetEntryVersion())
	if err != nil {
		self.t.Fatal(err)
	}
	return entry.GetVersion(), version.GetCommitVersion()
}

// A DROP with its index rewrites commits: window bits 5 and 4, its table entry pending, x's kept head and both index
// files at the DROP's own version, which no backfill waits for, and the versions they replaced in the purge's hands.
func TestPushDropCommitsWithItsIndexRewrites(t *testing.T) {
	fixture := newDropIndexTestFixture(t, 2)
	plan, history, staged := fixture.dropWithRewrites(0)
	fixture.commitRewrites(plan, staged, 4)
	entry := fixture.windowEntryAt(4)
	if !entry.Drop() || !entry.ReplacesVersionless() {
		t.Fatalf("the DROP's window entry: drop %v, replaces versionless %v", entry.Drop(), entry.ReplacesVersionless())
	}
	if dropped := fixture.table().Drop(sidecar.Id(history.GetDropId())); dropped == nil || dropped.State != DropStatePending || dropped.Version != 4 {
		t.Fatalf("the table holds %+v", dropped)
	}
	for _, path := range []sidecar.EvsTokenPath{fixture.x, fixture.indexHead, fixture.indexShard} {
		if _, committedAt := fixture.newestOf(path); committedAt != 4 {
			t.Fatalf("a path the DROP wrote stands from version %d", committedAt)
		}
	}
	if version, _ := fixture.newestOf(fixture.indexHead); version != fixture.indexVersion {
		t.Fatalf("the head's index file stands at %d, want %d", version, fixture.indexVersion)
	}
	sink := fixture.engine.deps.Purge.(*recordingPurgeSink)
	handed := 0
	for _, commit := range sink.all() {
		if commit.Version == 4 {
			handed += 1
			if len(commit.Replaced) != 2 || len(commit.List.GetCandidates()) != 2 {
				t.Fatalf("the DROP's purge: %d replaced, list %v", len(commit.Replaced), commit.List)
			}
		}
	}
	if handed != 1 {
		t.Fatalf("the DROP's list handed %d times", handed)
	}

	// a second drop rewrites them again at their new version
	again, _, againStaged := fixture.dropWithRewrites(0)
	fixture.commitRewrites(again, againStaged, 5)
}

// Each change beside the lineages that is no index rewrite is 409 DROP_BOUNDARY, recorded, the head unmoved: a
// creation, a removal, a write of no index file, a rewrite past Padmé of the chain it replaces, and a rewrite of an
// index file that stands on another ref alone, whose base names that ref's version 5g refuses 409 PATH_CONFLICT,
// final; the DROP with its rewrites alone then commits.
func TestPushDropRefusesWhatIsNoIndexRewrite(t *testing.T) {
	fixture := newDropIndexTestFixture(t, 2)
	writer := fixture.token(fixture.check.signerId)
	// an index file standing on another ref alone, as the companion index's on ur/index
	elsewhere := checkTestPath(".ur-index", "elsewhere")
	otherRefId := testId("check index ref")
	other := fixture.plan()
	other.RefId, other.BaseVersion, other.BaseChain = otherRefId, 0, sidecar.EvsChainStart(fixture.check.repoId, otherRefId)
	otherStaged := dropIndexTestRewrite(t, fixture.check, other, elsewhere, 0, 1, "elsewhere", dropIndexTestBodyByteCount)
	fixture.requireCommitted(fixture.post(writer, fixture.bodyStaged(other, [][]byte{otherStaged})), 1)
	fixture.awaitStepEights()
	padmeBodyByteCount := uint64(dropIndexTestBodyByteCount)
	for sidecar.EvsRecordByteCount(padmeBodyByteCount+1) <= sidecar.EvsPadme(sidecar.EvsRecordByteCount(dropIndexTestBodyByteCount)) {
		padmeBodyByteCount += 1
	}

	for _, c := range []struct {
		name   string
		status int
		code   protocol.EvsRefusalCode
		// what the drop carries beside x's kept head
		build func(plan *sidecar.EvsPushPlan) [][]byte
	}{
		{name: "a creation under the index root", status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY, build: func(plan *sidecar.EvsPushPlan) [][]byte {
			return [][]byte{dropIndexTestRewrite(t, fixture.check, plan, checkTestPath(".ur-index", "new"), 0, plan.BaseVersion+1, "new", dropIndexTestBodyByteCount)}
		}},
		{name: "a removal of an index file", status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY, build: func(plan *sidecar.EvsPushPlan) [][]byte {
			plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: fixture.indexShard, BaseEntryVersion: fixture.indexVersion})
			return nil
		}},
		{name: "a write of no index file", status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY, build: func(plan *sidecar.EvsPushPlan) [][]byte {
			plan.Changes = append(plan.Changes, fixture.check.change(plan, checkTestPath("y"), 0, plan.BaseVersion+1))
			return nil
		}},
		{name: "a rewrite past Padmé of the chain it replaces", status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY, build: func(plan *sidecar.EvsPushPlan) [][]byte {
			return [][]byte{dropIndexTestRewrite(t, fixture.check, plan, fixture.indexShard, fixture.indexVersion, fixture.indexVersion+1, "unpadded", padmeBodyByteCount+1)}
		}},
		{name: "a rewrite of an index file on another ref, as a creation", status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY, build: func(plan *sidecar.EvsPushPlan) [][]byte {
			return [][]byte{dropIndexTestRewrite(t, fixture.check, plan, elsewhere, 0, plan.BaseVersion+1, "elsewhere here", dropIndexTestBodyByteCount)}
		}},
		{name: "a rewrite of an index file on another ref, at its version there", status: http.StatusConflict, code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, build: func(plan *sidecar.EvsPushPlan) [][]byte {
			return [][]byte{dropIndexTestRewrite(t, fixture.check, plan, elsewhere, 1, 2, "elsewhere there", dropIndexTestBodyByteCount)}
		}},
	} {
		plan, _ := fixture.dropPlan(false, fixture.listedBelow(fixture.newest+1))
		staged := c.build(plan)
		before := fixture.head()
		recorder := fixture.postStaged(plan, staged)
		requireRefusal(t, recorder, c.status, c.code)
		after := fixture.head()
		if after.Version() != before.Version() {
			t.Fatalf("%s: the head moved to %d", c.name, after.Version())
		}
		recorded := after.Etag != before.Etag
		if recorded != (c.code == protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY) {
			t.Errorf("%s: recorded %v", c.name, recorded)
		}
		if paths := refusalOf(t, recorder).GetPaths(); len(paths) != 1 {
			t.Errorf("%s: names %d paths", c.name, len(paths))
		}
		fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	}
	plan, _, staged := fixture.dropWithRewrites(0)
	fixture.commitRewrites(plan, staged, 4)
}

// 5d over a DROP's rewrites, after a CUT moved the ref's index_epoch: below the head's, 409 INDEX_EPOCH, final; above
// it, recorded; the twin naming the head's commits; and a DROP writing no index file commits whatever epoch it names.
func TestPushDropIndexRewritesNameTheHeadsIndexEpoch(t *testing.T) {
	fixture := newDropIndexTestFixture(t, 2)
	cut := fixture.plan()
	cut.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
	cutStaged := cutTestIndexFile(t, fixture.check, cut, checkTestPath(".ur-index", "x"), 0, cut.BaseVersion+1, "erasure set")
	fixture.requireCommitted(fixture.post(fixture.adminToken(), fixture.bodyStaged(cut, [][]byte{cutStaged})), 4)
	fixture.awaitStepEights()
	if epoch := fixture.head().Head.GetIndexEpoch(); epoch != 4 {
		t.Fatalf("the CUT left index_epoch %d", epoch)
	}

	stale, _, staleStaged := fixture.dropWithRewrites(0)
	before := fixture.head()
	requireRefusal(t, fixture.postStaged(stale, staleStaged), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH)
	if after := fixture.head(); after.Etag != before.Etag {
		t.Error("a DROP naming an epoch below the head's was recorded: it is final")
	}

	ahead, _, aheadStaged := fixture.dropWithRewrites(5)
	requireRefusal(t, fixture.postStaged(ahead, aheadStaged), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH)
	if after := fixture.head(); after.Etag == before.Etag || after.Version() != 4 {
		t.Error("a DROP naming an epoch above the head's was not recorded")
	}
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)

	twin, _, twinStaged := fixture.dropWithRewrites(4)
	fixture.commitRewrites(twin, twinStaged, 5)
	if epoch := fixture.head().Head.GetIndexEpoch(); epoch != 4 {
		t.Fatalf("a DROP moved index_epoch to %d", epoch)
	}

	// a DROP writing no index file is held to no epoch
	bare, _ := fixture.dropPlan(false, fixture.listedBelow(fixture.newest+1))
	fixture.commitDrop(bare, 6)
}

// The fold of a DROP takes each index rewrite as an ordinary write: the index file's entry holds the rewritten
// version with no drop mark, x's holds the kept head with its mark, and nothing alarms; a DROP's versioned write that
// no written lineage names still alarms once.
func TestFormat2DropIndexRewriteFoldsAsAWrite(t *testing.T) {
	world, lines := newFormat2World(t)
	x, index, y := worldPath("x"), worldPath(".ur-index", "shard"), worldPath("y")
	indexChange := func(base uint64, version uint64, label string) *format2Change {
		return &format2Change{
			worldChange: &worldChange{path: index, base: base, version: version},
			versioning:  uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX),
			stagedIds:   [][]byte{format2Id(label + " staged")},
		}
	}
	world.pushFormat2(&format2Push{changes: []*format2Change{versioned(&worldChange{path: x, version: 1}), indexChange(0, 1, "index 1")}})
	dropId := testId("index drop")
	push := format2DropPush(dropId, x, 1, 1)
	push.changes = append(push.changes, indexChange(1, 2, "index 2"))
	dropped := world.pushFormat2(push)
	world.fold(dropped)
	if entry := world.entryOf(x).Entry; !hasDropMark(entry, dropId, 2) {
		t.Fatalf("x after the drop: %v", entry)
	}
	entry := world.entryOf(index).Entry
	if entry.GetDropMark() != nil || len(entry.GetVersions()) == 0 {
		t.Fatalf("the index file after the drop: %v", entry)
	}
	if newest := foldedEntryVersion(t, entry.GetVersions()[0]); newest.GetVersion() != 2 || newest.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX) {
		t.Fatalf("the index file's newest folded version: %v", newest)
	}
	world.requireNewest(index)
	if count := lines.count("fold_drop"); count != 0 {
		t.Fatalf("an index rewrite alarmed:\n%s", lines)
	}

	other := format2DropPush(testId("other drop"), x, 1, 2)
	other.changes = append(other.changes, versioned(&worldChange{path: y, version: ExpectedEntryVersion(0, world.head.Version(), 0)}))
	world.fold(world.pushFormat2(other))
	if count := lines.count("fold_drop"); count != 1 {
		t.Fatalf("%d alarms for a DROP's versioned write no lineage names:\n%s", count, lines)
	}
}
