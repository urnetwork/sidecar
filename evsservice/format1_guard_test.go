// EVS2-M2-01's tests of what format-1 code does with format 2 (§11.6's kinds and format rows, D-PHASE-9, FS-72): the
// fixed refusal table holding format 2's codes, so a rolled-back instance answers a head's recorded format-2
// refusal with recorded: true; a format-2 construct in a push refused 409 FORMAT_UNSUPPORTED {needs_format: 2},
// recorded, which a format-2 instance in the gate then answers too; a fold keeping an entry's drop mark and a
// marker's carried ids; and a format-2 repo/ under a format-1 instance taking no push, fold, page-out or copy
// write. A format-1 instance is EvsSettings.InstanceFormat 1, as the rolled-back binary is.

package evsservice

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Format 2's refusal codes as the task lists them, and whether §11.8's refuse row records each: DROP_KIND is final,
// a repo's kind never changing, so no head ever holds it.
var format2RefusalCodes = []struct {
	code     protocol.EvsRefusalCode
	recorded bool
}{
	{protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING, true},
	{protocol.EvsRefusalCode_EVS_REFUSAL_DROPPED, true},
	{protocol.EvsRefusalCode_EVS_REFUSAL_DROP_KIND, false},
	{protocol.EvsRefusalCode_EVS_REFUSAL_DROP_PATH, true},
	{protocol.EvsRefusalCode_EVS_REFUSAL_DROP_CONSENT, true},
	{protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY, true},
	{protocol.EvsRefusalCode_EVS_REFUSAL_DROP_LIST, true},
	{protocol.EvsRefusalCode_EVS_REFUSAL_DROP_STATE, true},
	{protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH, true},
}

// A format-1 instance, as a rolled-back binary is, on the push fixture.
func newFormat1PushFixture(t *testing.T) *pushFixture {
	return newPushFixture(t, func(settings *EvsSettings) {
		settings.InstanceFormat = sidecar.EvsRepoFormat1
	})
}

// The fixed table holds every format-2 code with its status, and a recorded one round-trips a head's refusal
// record: a format-1 instance after a rollback answers a push id a format-2 instance refused with that code and
// recorded: true, never as an unknown code, and commits nothing for it.
func TestFormat2RefusalCodesAnswerRecordedAtAFormat1Instance(t *testing.T) {
	fixture := newFormat1PushFixture(t)
	first := fixture.plan()
	fixture.create(first, "first")
	fixture.requireCommitted(fixture.push(first), 1)

	token := fixture.token(fixture.check.signerId)
	untilMs := fixture.clock.Now().Add(evsPushTimeBound).UnixMilli()
	bodies := map[protocol.EvsRefusalCode]*protocol.EvsPushRequest{}
	refusals := []*sidecar.EvsRefusal{}
	for i, c := range format2RefusalCodes {
		status, ok := sidecar.EvsRefusalStatus(c.code)
		if !ok || status != http.StatusConflict {
			t.Errorf("%s: status %d in the table, %t", c.code, status, ok)
		}
		if sidecar.EvsRefusalRecordable(c.code) != c.recorded {
			t.Errorf("%s: recordable %t", c.code, !c.recorded)
		}
		if !c.recorded {
			if _, err := sidecar.NewEvsRefusal(testId("push"), [32]byte{}, c.code, untilMs); !errors.Is(err, sidecar.ErrEvsRefusalInvalid) {
				t.Errorf("%s: a final code made a record: %v", c.code, err)
			}
			continue
		}
		plan := fixture.plan()
		fixture.create(plan, "refused", string(rune('a'+i)))
		built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.check.signingKey, fixture.check.signerId)).Build(plan)
		if err != nil {
			t.Fatal(err)
		}
		bodies[c.code] = &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload}
		refusal, err := sidecar.NewEvsRefusal(plan.PushId, built.Statement.Sha256, c.code, untilMs)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := sidecar.DecodeEvsRefusal(refusal.Encode())
		if err != nil || decoded.Code != c.code || !decoded.RecordsPush(plan.PushId) || !decoded.RecordsStatement(built.Statement.Sha256) {
			t.Fatalf("%s: a record read back as %v: %v", c.code, decoded, err)
		}
		refusals = append(refusals, refusal)
	}
	// the head as a format-2 instance left it: one record a code, by a write that commits nothing
	refused, err := sidecar.EncodeEvsRefusals(refusals)
	if err != nil {
		t.Fatal(err)
	}
	prior := fixture.head()
	next := CloneEvsHead(prior.Head)
	next.Refused = refused
	next.Fence += 1
	if _, err := fixture.engine.heads.Commit(fixture.ctx, fixture.cluster, fixture.check.repoId, fixture.check.refId, prior, next); err != nil {
		t.Fatal(err)
	}
	for code, body := range bodies {
		recorder := fixture.post(token, body)
		requireRefusal(t, recorder, http.StatusConflict, code)
		if reply := refusalOf(t, recorder); !reply.GetRecorded() || reply.GetNeedsFormat() != 0 {
			t.Errorf("%s: answered %v", code, reply)
		}
	}
	if head := fixture.head(); head.Version() != 1 || !bytes.Equal(head.Head.GetRefused(), refused) {
		t.Fatalf("the head moved under recorded refusals: version %d", head.Version())
	}
}

// FS-72's M2 case and its rolling one (plan-EVS1-format-unsupported#5): a format-1 instance refuses a push carrying
// a format-2 value 409 FORMAT_UNSUPPORTED {needs_format: 2}, recorded, whatever the gate says, and writes nothing
// of it; the same process run as format 2, its network in the gate, then meets the retry and answers the recorded
// refusal rather than committing it.
func TestFormat1InstanceRefusesFormat2PushesRecorded(t *testing.T) {
	fixture := newFormat1PushFixture(t)
	fixture.openFormat2()
	token := fixture.token(fixture.check.signerId)
	_, etag := fixture.repo()
	plan := fixture.plan()
	fixture.createVersionless(plan, "a")
	body := fixture.bodyFormat2(plan)
	recorder := fixture.post(token, body)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED)
	if reply := refusalOf(t, recorder); reply.GetNeedsFormat() != sidecar.EvsRepoFormat2 || reply.GetRecorded() {
		t.Fatalf("the recording attempt answered %v", reply)
	}
	head := fixture.head()
	if head.Version() != 0 || len(head.Head.GetRefused()) != sidecar.EvsRefusalByteCount {
		t.Fatalf("the refusal was not recorded: %v", head.Head)
	}
	if object, after := fixture.repo(); object.GetFormat() != sidecar.EvsRepoFormat1 || after != etag {
		t.Fatal("a format-1 instance raised a repo")
	}
	// staged bytes beside a format-1 statement are format 2's too
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	staged := fixture.plan()
	fixture.create(staged, "b")
	stagedBody := fixture.body(staged)
	stagedBody.Staged = []byte("staged segments")
	requireRefusal(t, fixture.post(token, stagedBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED)

	// the binary rolls forward: the settings are the engine's own, read on each request
	fixture.settings.InstanceFormat = sidecar.EvsRepoFormat2
	again := fixture.post(token, body)
	requireRefusal(t, again, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED)
	if !refusalOf(t, again).GetRecorded() {
		t.Fatal("a format-2 instance in the gate answered the retry without recorded: true")
	}
	if fixture.head().Version() != 0 {
		t.Fatal("a push a format-1 instance refused committed after the roll forward")
	}
	if object, _ := fixture.repo(); object.GetFormat() != sidecar.EvsRepoFormat1 {
		t.Fatal("a recorded push id raised the repo")
	}
}

// Every object the fixture's clusters hold: every byte a write would change.
func (self *pushFixture) storedObjects() map[string][]byte {
	objects := map[string][]byte{}
	for key, object := range self.host.Blobs.Dump() {
		objects[key] = bytes.Clone(object)
	}
	return objects
}

func requireSameObjects(t *testing.T, what string, before map[string][]byte, after map[string][]byte) {
	t.Helper()
	for key, object := range after {
		if held, ok := before[key]; !ok || !bytes.Equal(held, object) {
			t.Errorf("%s: wrote %s", what, key)
		}
	}
	for key := range before {
		if _, ok := after[key]; !ok {
			t.Errorf("%s: deleted %s", what, key)
		}
	}
}

// FS-72's "writing nothing": on repo/'s format 2 a format-1 instance answers every push 503 with Retry-After before
// any check, a format-1 push included, refusing nothing, and its path-epoch copy issues no write, so its stored
// bytes stay as they were. The same repo under a format-2 instance takes the copy.
func TestFormat1InstanceWritesNothingToAFormat2Repo(t *testing.T) {
	fixture := newFormat1PushFixture(t)
	fixture.committedEpochTwo()
	fixture.awaitStepEights()
	raised := fixture.fullRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE, sidecar.EvsRepoFormat2)
	fixture.writeRepo(raised)
	fixture.engine.repos.Forget(fixture.check.repoId)
	before := fixture.storedObjects()
	token := fixture.token(fixture.check.signerId)

	plain := fixture.plan()
	fixture.create(plain, "plain")
	versionless := fixture.plan()
	fixture.createVersionless(versionless, "versionless")
	for name, body := range map[string]*protocol.EvsPushRequest{"a format-1 push": fixture.body(plain), "a format-2 push": fixture.bodyFormat2(versionless)} {
		// the format row's 503 comes before the kinds row's 409, so nothing is recorded in a head this instance
		// must not write
		recorder := fixture.post(token, body)
		if recorder.Code != http.StatusServiceUnavailable || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE {
			t.Errorf("%s: answered %d %s", name, recorder.Code, refusalOf(t, recorder).GetCode())
		}
		if recorder.Header().Get("Retry-After") == "" {
			t.Errorf("%s: a 503 without Retry-After", name)
		}
	}
	copySettings := *fixture.settings
	if _, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), &EvsEpochCopyDeps{Settings: &copySettings}, fixture.copyArgs(2)); !errors.Is(err, ErrEvsFoldRepoFormat) {
		t.Errorf("a copy of a format-2 repo: %v", err)
	}
	requireSameObjects(t, "a format-1 instance on a format-2 repo", before, fixture.storedObjects())
	if stored, _ := fixture.repo(); !proto.Equal(stored, raised) {
		t.Errorf("repo/ changed: %v", stored)
	}

	// a format-2 instance writes it: the copy drains the source
	result, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2))
	if err != nil || result.MovedCount == 0 || !result.SourcesDropped {
		t.Fatalf("a format-2 instance's copy: %+v %v", result, err)
	}
}

// The same for the fold and the page-out's write: a format-1 folder on a format-2 repo issues no entry write, where
// a format-2 folder folds it.
func TestFormat1FoldWritesNothingToAFormat2Repo(t *testing.T) {
	world := newEvsWorld(t)
	world.settings.InstanceFormat = sidecar.EvsRepoFormat1
	world.push(&worldChange{path: worldPath("x"), version: 1})
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat2, NetworkId: testId("network-a").Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	object, err := world.cluster.Head(world.ctx, RepoKey(world.repoId))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.cluster.PutIfMatch(world.paidCtx, RepoKey(world.repoId), object.Etag, repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	request := &EvsFoldRequest{Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Rank: sidecar.WriteP2RankFold}
	if _, err := world.folder.Fold(world.ctx, request); !errors.Is(err, ErrEvsFoldRepoFormat) {
		t.Fatalf("a format-1 fold of a format-2 repo: %v", err)
	}
	if err := world.folder.recheckRepo(world.ctx, world.foldCluster, world.repoId); !errors.Is(err, ErrEvsFoldRepoFormat) {
		t.Fatalf("a format-1 page-out's recheck of a format-2 repo: %v", err)
	}
	if !world.entryOf(worldPath("x")).Absent() {
		t.Fatal("a format-1 fold wrote a format-2 repo's entry")
	}
	world.settings.InstanceFormat = sidecar.EvsRepoFormat2
	if result, err := world.folder.Fold(world.ctx, request); err != nil || result.EntryWriteCount != 1 {
		t.Fatalf("a format-2 fold of a format-2 repo: %+v %v", result, err)
	}
}

// §11.13's skip row with the format rule, as every P2 write rereads it: active or deleted, and of a format the
// instance writes.
func TestCheckRepoWritableByStateAndFormat(t *testing.T) {
	for _, c := range []struct {
		state          protocol.EvsRepoState
		format         uint32
		instanceFormat uint32
		want           error
	}{
		{protocol.EvsRepoState_EVS_REPO_ACTIVE, 1, 1, nil},
		{protocol.EvsRepoState_EVS_REPO_DELETED, 1, 1, nil},
		{protocol.EvsRepoState_EVS_REPO_ACTIVE, 1, 2, nil},
		{protocol.EvsRepoState_EVS_REPO_ACTIVE, 2, 2, nil},
		{protocol.EvsRepoState_EVS_REPO_DELETED, 2, 2, nil},
		{protocol.EvsRepoState_EVS_REPO_ACTIVE, 2, 1, ErrEvsFoldRepoFormat},
		{protocol.EvsRepoState_EVS_REPO_DELETED, 2, 1, ErrEvsFoldRepoFormat},
		{protocol.EvsRepoState_EVS_REPO_ACTIVE, 3, 2, ErrEvsFoldRepoFormat},
		{protocol.EvsRepoState_EVS_REPO_KEYING, 1, 1, ErrEvsFoldRepoState},
		{protocol.EvsRepoState_EVS_REPO_SHREDDING, 2, 1, ErrEvsFoldRepoState},
		{protocol.EvsRepoState_EVS_REPO_SHREDDED, 1, 2, ErrEvsFoldRepoState},
	} {
		err := checkRepoWritable(&EvsRepoRead{Object: &protocol.EvsRepoObject{State: c.state, Format: c.format}}, c.instanceFormat)
		if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s format %d at an instance of format %d: %v, want %v", c.state, c.format, c.instanceFormat, err, c.want)
		}
	}
}

// A file's entry version at version, written by pushId.
func format1GuardEntryVersion(t *testing.T, pushId sidecar.Id, version uint64, base uint64) []byte {
	t.Helper()
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
		Version: version, PushId: pushId.Bytes(), BaseVersion: base, Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096,
		SealedFields: []byte("sealed fields"),
		Chain:        []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return entryBytes
}

// A write of a file's version at commitVersion, a creation when base is 0.
func format1GuardWrite(t *testing.T, label string, commitVersion uint64, version uint64, base uint64) *foldEvent {
	t.Helper()
	pushId := testId(label)
	entryBytes := format1GuardEntryVersion(t, pushId, version, base)
	entryVersion, err := parseEvsEntryVersion(entryBytes)
	if err != nil {
		t.Fatal(err)
	}
	return &foldEvent{
		kind: foldEventWrite, commitVersion: commitVersion, pushId: pushId,
		change: &EvsCommittedChange{BaseEntryVersion: base, EntryVersion: entryBytes}, entryVersion: entryVersion,
	}
}

// A format-1 fold over an entry holding format 2's kept fields (reserved_numbers.yml's kept): the drop mark stays
// byte for byte through a write, a removal, a creation over the marker and a directory's delta; a newer marker over
// an older one inherits the ids it carried; a prefix's removal over a marker changes nothing; and a write that
// cannot keep a marker's ids on a standing entry alarms, the content they name staying
// (plan-EVS2-marker-carried-ids's interim).
func TestFormat1FoldKeepsTheDropMarkAndCarriedIds(t *testing.T) {
	dropMark := &protocol.EvsDropMark{DropId: testId("drop").Bytes(), ThroughVersion: 7}
	segmentId, slotId := bytes.Repeat([]byte{5}, 32), testId("slot").Bytes()
	carrying := func() *protocol.EvsRemovalMarker {
		return &protocol.EvsRemovalMarker{
			PushId: testId("removal").Bytes(), RemovalVersion: 3, PathVersion: 3,
			SegmentIds: [][]byte{bytes.Clone(segmentId)}, SlotIds: [][]byte{bytes.Clone(slotId)},
		}
	}
	lines := []string{}
	log := &capturingLogger{lines: &lines}
	alarms := func() int {
		count := 0
		for _, line := range lines {
			if strings.Contains(line, "alarm fold_carried_ids") {
				count += 1
			}
		}
		return count
	}
	first := format1GuardWrite(t, "push 1", 1, 1, 0)
	standing := &protocol.EvsIndexEntry{
		Versions: []*protocol.EvsIndexVersion{{PushId: first.pushId.Bytes(), CommitVersion: 1, EntryVersion: first.change.EntryVersion}},
		DropMark: proto.Clone(dropMark).(*protocol.EvsDropMark),
	}

	// a write over a standing entry
	written := mergeFoldEvents(standing, []*foldEvent{format1GuardWrite(t, "push 2", 2, 2, 1)}, log)
	if !written.changed || len(written.entry.GetVersions()) != 2 || !proto.Equal(written.entry.GetDropMark(), dropMark) {
		t.Errorf("a write: %v", written.entry)
	}
	// a removal of it
	removed := mergeFoldEvents(standing, []*foldEvent{{kind: foldEventRemoval, commitVersion: 2, pushId: testId("push 2"), change: &EvsCommittedChange{BaseEntryVersion: 1}}}, log)
	if !removed.removed || removed.entry.GetMarker() == nil || !proto.Equal(removed.entry.GetDropMark(), dropMark) {
		t.Errorf("a removal: %v", removed.entry)
	}
	if alarms() != 0 {
		t.Errorf("a fold that dropped no ids alarmed: %v", lines)
	}

	marked := &protocol.EvsIndexEntry{Marker: carrying(), DropMark: proto.Clone(dropMark).(*protocol.EvsDropMark)}
	// a newer marker over the older one
	again := mergeFoldEvents(marked, []*foldEvent{{kind: foldEventRemoval, commitVersion: 5, pushId: testId("push 5"), change: &EvsCommittedChange{BaseEntryVersion: 4}}}, log)
	if marker := again.entry.GetMarker(); marker.GetRemovalVersion() != 5 || len(marker.GetSegmentIds()) != 1 || !bytes.Equal(marker.GetSegmentIds()[0], segmentId) ||
		len(marker.GetSlotIds()) != 1 || !bytes.Equal(marker.GetSlotIds()[0], slotId) || !proto.Equal(again.entry.GetDropMark(), dropMark) {
		t.Errorf("a newer marker: %v", again.entry)
	}
	// a prefix's removal over a path already removed
	covered := mergeFoldEvents(marked, []*foldEvent{{kind: foldEventPrefixRemoval, commitVersion: 5, pushId: testId("push 5")}}, log)
	if covered.changed || !proto.Equal(covered.entry, marked) {
		t.Errorf("a prefix's removal over a marker: %v", covered.entry)
	}
	if alarms() != 0 {
		t.Errorf("a fold that kept the ids alarmed: %v", lines)
	}
	// a creation over the marker: the mark stays, and the ids, which a standing entry cannot hold, alarm
	created := mergeFoldEvents(marked, []*foldEvent{format1GuardWrite(t, "push 6", 6, 4, 0)}, log)
	if !created.replaced || created.entry.GetMarker() != nil || !proto.Equal(created.entry.GetDropMark(), dropMark) {
		t.Errorf("a creation over a marker: %v", created.entry)
	}
	if alarms() != 1 {
		t.Errorf("a creation over a marker carrying ids: %d alarms in %v", alarms(), lines)
	}
	// a directory's delta over the marker
	directoryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
		Version: 4, PushId: testId("push 7").Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY), Names: &protocol.EvsNameTable{},
	})
	if err != nil {
		t.Fatal(err)
	}
	directoryVersion, err := parseEvsEntryVersion(directoryBytes)
	if err != nil {
		t.Fatal(err)
	}
	table := mergeFoldEvents(marked, []*foldEvent{{
		kind: foldEventWrite, commitVersion: 7, pushId: testId("push 7"), change: &EvsCommittedChange{EntryVersion: directoryBytes}, entryVersion: directoryVersion,
	}}, log)
	if table.entry.GetNames() == nil || !proto.Equal(table.entry.GetDropMark(), dropMark) || alarms() != 2 {
		t.Errorf("a directory's delta over a marker: %v, %d alarms", table.entry, alarms())
	}
	// held was never changed
	if !proto.Equal(marked.GetMarker(), carrying()) || len(standing.GetVersions()) != 1 {
		t.Error("a merge changed the entry it read")
	}
}

// The same through a real fold on the store: an entry a format-2 writer left with a drop mark keeps it, byte for
// byte, when a format-1 fold writes the path's next version over it, and a marker carrying ids that no later
// version touches is read by format-1 code without refusal and left as it is.
func TestFormat1FoldOnTheStoreLeavesFormat2sKeptBytes(t *testing.T) {
	world := newEvsWorld(t)
	world.settings.InstanceFormat = sidecar.EvsRepoFormat1
	file, gone := worldPath("x"), worldPath("y")
	world.push(&worldChange{path: file, version: 1}, &worldChange{path: gone, version: 1})
	world.push(&worldChange{path: gone, base: 1})
	world.fold(2)

	dropMark := &protocol.EvsDropMark{DropId: testId("drop").Bytes(), ThroughVersion: 1}
	fileRead := world.entryOf(file)
	marked := proto.Clone(fileRead.Entry).(*protocol.EvsIndexEntry)
	marked.DropMark = dropMark
	if _, err := PutEntry(world.paidCtx, world.cluster, world.repoId, world.refId, 1, file, fileRead, marked, EvsEntryStateValue{}); err != nil {
		t.Fatal(err)
	}
	goneRead := world.entryOf(gone)
	carrying := proto.Clone(goneRead.Entry).(*protocol.EvsIndexEntry)
	carrying.Marker.SegmentIds = [][]byte{bytes.Repeat([]byte{5}, 32)}
	carrying.Marker.SlotIds = [][]byte{testId("slot").Bytes()}
	carrying.DropMark = dropMark
	if _, err := PutEntry(world.paidCtx, world.cluster, world.repoId, world.refId, 1, gone, goneRead, carrying, EvsEntryStateValue{}); err != nil {
		t.Fatal(err)
	}
	goneEtag := world.entryOf(gone).Etag

	world.push(&worldChange{path: file, base: 1, version: 2})
	world.fold(3)
	folded := world.entryOf(file).Entry
	if len(folded.GetVersions()) != 2 || folded.GetVersions()[0].GetCommitVersion() != 3 {
		t.Fatalf("the fold's entry: %v", folded)
	}
	wantMark, _ := proto.MarshalOptions{Deterministic: true}.Marshal(dropMark)
	gotMark, _ := proto.MarshalOptions{Deterministic: true}.Marshal(folded.GetDropMark())
	if !bytes.Equal(gotMark, wantMark) {
		t.Fatalf("the drop mark after a format-1 fold: %v", folded.GetDropMark())
	}
	kept := world.entryOf(gone)
	if kept.Etag != goneEtag || !proto.Equal(kept.Entry, carrying) {
		t.Fatalf("the marker carrying ids after a format-1 fold: %v", kept.Entry)
	}
	world.requireNewest(file)
	world.requireNewest(gone)
}
