// EVS1-M2-14's tests on T2's fakes, through the engine's guard: the head summary, the statements after a pin and
// `behind` past the window, a path's version with its statement and Merkle proof, FS-10's server side (a path a
// push in parts under changes_root left alone answered by adjacent-leaf proofs with no change list), a removal, a
// directory's table and deltas, an older version by number, an overlay's base, FS-62's stale-cache cases (a cached
// head never served below a reader's pin, and not on fresh), R-EVS-8's round count with a cached head, a
// deposit-only principal refused, GET .../refs and GET .../log. A reader paused across an evacuation (pidx/) is
// EVSB-M2-10's and is left to the review phase.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A read reply's frames as they arrived.
type readTestReply struct {
	head       *protocol.EvsHeadSummary
	statements []*protocol.EvsReadStatement
	behind     uint64
	paths      []*protocol.EvsReadPathReply
	objects    []*protocol.EvsReadObject
	ended      bool
}

// POST .../read, its frames decoded; a status other than 200 fails the test.
func (self *pushFixture) read(token string, request *protocol.EvsReadRequest) *readTestReply {
	self.t.Helper()
	recorder := self.call(token, http.MethodPost, "/read", request)
	if recorder.Code != http.StatusOK {
		self.t.Fatalf("read: status %d (%s)", recorder.Code, refusalOf(self.t, recorder).GetCode())
	}
	return decodeReadFrames(self.t, recorder.Body.Bytes())
}

// The frames of a read reply's bytes.
func decodeReadFrames(t *testing.T, body []byte) *readTestReply {
	t.Helper()
	frames := sidecar.NewEvsReadFrames(bytes.NewReader(body))
	reply := &readTestReply{}
	for {
		frame, err := frames.Next()
		if err == io.EOF {
			reply.ended = true
			break
		}
		if err != nil {
			t.Fatalf("frames: %v", err)
		}
		if frame.GetHead() != nil {
			reply.head = frame.GetHead()
		}
		if frame.GetStatement() != nil {
			reply.statements = append(reply.statements, frame.GetStatement())
		}
		if frame.GetBehind() != 0 {
			reply.behind = frame.GetBehind()
		}
		if frame.GetPath() != nil {
			reply.paths = append(reply.paths, frame.GetPath())
		}
		if frame.GetObject() != nil {
			reply.objects = append(reply.objects, frame.GetObject())
		}
	}
	return reply
}

// A read of one path at the newest version.
func (self *pushFixture) readPath(token string, pin uint64, fresh bool, path sidecar.EvsTokenPath) *readTestReply {
	return self.read(token, &protocol.EvsReadRequest{
		RefId: self.check.refId.Bytes(), PinVersion: pin, Fresh: fresh,
		Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{TokenPath: path.Components()}}}},
	})
}

// The statement bytes a reply holds for version: among those after the pin, or the one sent beside pathReply.
func readTestStatement(t *testing.T, reply *readTestReply, pathReply *protocol.EvsReadPathReply, version uint64) *sidecar.EvsStatement {
	t.Helper()
	var statementBytes []byte
	for _, statement := range reply.statements {
		if statement.GetVersion() == version {
			statementBytes = statement.GetStatement()
		}
	}
	if statementBytes == nil {
		statementBytes = pathReply.GetStatement()
	}
	if statementBytes == nil {
		t.Fatalf("no statement for version %d", version)
	}
	statement, err := sidecar.ParseEvsStatement(statementBytes)
	if err != nil {
		t.Fatal(err)
	}
	return statement
}

// Checks a version as §11.9's reader does: its entry hashes to its statement's change of the path, inline or by
// its proof.
func requireVersionProven(t *testing.T, reply *readTestReply, pathReply *protocol.EvsReadPathReply, path sidecar.EvsTokenPath) *sidecar.EvsStatement {
	t.Helper()
	version := pathReply.GetVersion()
	if version == nil || version.GetElided() {
		t.Fatalf("path %v: no version", pathReply)
	}
	statement := readTestStatement(t, reply, pathReply, version.GetCommitVersion())
	push := statement.Push
	digest := sha256.Sum256(version.GetEntryVersion())
	var change *protocol.EvsChange
	if len(push.GetChangesRoot()) == 0 {
		if len(pathReply.GetProof()) != 0 {
			t.Fatal("a proof beside an inline list")
		}
		for _, listed := range statement.Changes {
			if listed.TokenPath.Equal(path) {
				change = listed.Change
			}
		}
	} else {
		proven, provenPath, err := sidecar.EvsVerifyChangeInclusion(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), pathReply.GetProof())
		if err != nil || !provenPath.Equal(path) {
			t.Fatalf("proof: %v %v", err, provenPath)
		}
		change = proven
	}
	if change == nil || !bytes.Equal(change.GetEntrySha256(), digest[:]) {
		t.Fatalf("the version does not hash to its statement's change")
	}
	return statement
}

func TestReadServesTheHeadStatementsAndAVersion(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId, "r")
	// an unwritten ref: version 0, C_0, every path absent
	path := checkTestPath("a")
	reply := fixture.readPath(token, 0, false, path)
	chain := sidecar.EvsChainStart(fixture.check.repoId, fixture.check.refId)
	if reply.head.GetVersion() != 0 || !bytes.Equal(reply.head.GetChain(), chain[:]) || len(reply.paths) != 1 || reply.paths[0].GetVersion() != nil || !reply.ended {
		t.Fatalf("absent ref: %v %v", reply.head, reply.paths)
	}

	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "b")
	head := fixture.head()
	reply = fixture.readPath(token, 0, false, path)
	if reply.head.GetVersion() != 2 || !bytes.Equal(reply.head.GetChain(), head.Head.GetChain()) || !bytes.Equal(reply.head.GetPushId(), head.Head.GetPushId()) {
		t.Fatalf("head %v", reply.head)
	}
	if reply.head.GetRefMode() != protocol.EvsRefMode_EVS_REF_FILE || reply.head.GetPathEpoch().GetCurrent() != 1 || reply.head.GetPushSequence() == 0 {
		t.Fatalf("head fill %v", reply.head)
	}
	if len(reply.statements) != 2 || reply.statements[0].GetVersion() != 1 || reply.statements[1].GetVersion() != 2 || reply.behind != 0 {
		t.Fatalf("statements %v behind %d", reply.statements, reply.behind)
	}
	pathReply := reply.paths[0]
	if !bytes.Equal(bytes.Join(pathReply.GetTokenPath(), nil), path.Bytes()) {
		t.Fatal("a reply for another path")
	}
	if pathReply.GetVersion().GetCommitVersion() != 1 || len(pathReply.GetStatement()) != 0 {
		t.Fatalf("version %v with statement %d", pathReply.GetVersion(), len(pathReply.GetStatement()))
	}
	statement := requireVersionProven(t, reply, pathReply, path)
	if !bytes.Equal(statement.Push.GetPushId(), pathReply.GetVersion().GetPushId()) {
		t.Fatal("a version its statement did not write")
	}
	// inline lists need no absence proofs
	if len(pathReply.GetAbsences()) != 0 {
		t.Fatalf("absences %v for inline statements", pathReply.GetAbsences())
	}

	// pinned at 2: no statements after the pin, so the version's statement rides beside the path
	reply = fixture.readPath(token, 2, false, path)
	if len(reply.statements) != 0 || len(reply.paths[0].GetStatement()) == 0 {
		t.Fatalf("pinned read: %d statements, statement of %d bytes", len(reply.statements), len(reply.paths[0].GetStatement()))
	}
	requireVersionProven(t, reply, reply.paths[0], path)
}

// FS-10's server side: a path a push in parts under changes_root left alone is answered by adjacent-leaf proofs,
// never the change list, and a path it changed by its inclusion proof.
func TestReadProvesAbsenceAgainstAPartedChangeList(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "zzz")
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "aaa")
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 2500))
	if len(built.Statement.Push.GetChangesRoot()) == 0 || len(built.Parts) < 3 {
		t.Fatalf("a parted push with %d parts and a root of %d bytes", len(built.Parts), len(built.Statement.Push.GetChangesRoot()))
	}
	places := fixture.postParts(token, built)
	fixture.requireCommitted(fixture.seal(token, built, places), 3)
	fixture.awaitStepEights()
	push := built.Statement.Push

	for _, label := range []string{"zzz", "aaa"} {
		path := checkTestPath(label)
		reply := fixture.readPath(token, 0, false, path)
		pathReply := reply.paths[0]
		requireVersionProven(t, reply, pathReply, path)
		absences := pathReply.GetAbsences()
		if len(absences) != 1 || absences[0].GetVersion() != 3 {
			t.Fatalf("%s: absences %v, want one for version 3", label, absences)
		}
		if err := sidecar.EvsVerifyChangeAbsence(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), path, absences[0]); err != nil {
			t.Fatalf("%s: absence proof: %v", label, err)
		}
		if len(reply.statements) != 3 {
			t.Fatalf("%d statements", len(reply.statements))
		}
	}
	// a path in the middle of the parted list, by its inclusion proof, part level last
	for _, label := range []string{"file-00000", "file-01200", "file-02499"} {
		path := checkTestPath(label)
		reply := fixture.readPath(token, 0, false, path)
		pathReply := reply.paths[0]
		if pathReply.GetVersion().GetCommitVersion() != 3 || len(pathReply.GetProof()) != 2 {
			t.Fatalf("%s: version %v with %d proofs", label, pathReply.GetVersion(), len(pathReply.GetProof()))
		}
		requireVersionProven(t, reply, pathReply, path)
		if len(pathReply.GetAbsences()) != 0 {
			t.Fatalf("%s: absences after its own version", label)
		}
	}
	// a reader pinned at 2 and behind nothing: the proofs speak for version 3 alone
	reply := fixture.readPath(token, 2, false, checkTestPath("zzz"))
	if len(reply.statements) != 1 || len(reply.paths[0].GetAbsences()) != 1 || len(reply.paths[0].GetStatement()) == 0 {
		t.Fatalf("pinned at 2: %d statements, %d absences, statement %d", len(reply.statements), len(reply.paths[0].GetAbsences()), len(reply.paths[0].GetStatement()))
	}
}

// A removed path answers its removal's push id, version and path version, from the window, and from its marker
// once folded.
func TestReadAnswersARemoval(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
	remove := fixture.plan()
	remove.Changes = append(remove.Changes, fixture.check.change(remove, checkTestPath("a"), 1, 0))
	fixture.requireCommitted(fixture.push(remove), 2)
	fixture.awaitStepEights()
	reply := fixture.readPath(token, 0, false, checkTestPath("a"))
	removal := reply.paths[0].GetRemoval()
	if removal == nil || removal.GetRemovalVersion() != 2 || removal.GetPathVersion() != 2 || !bytes.Equal(removal.GetPushId(), remove.PushId.Bytes()) {
		t.Fatalf("removal %v", removal)
	}
	if reply.paths[0].GetVersion() != nil {
		t.Fatal("a version beside a removal")
	}
}

// A directory answers its folded table, names_through and the deltas after it, each a version its push wrote.
func TestReadAnswersADirectory(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	directory := checkTestPath("d")
	row := func(label string) *protocol.EvsName {
		token := checkTestPath(label)[0]
		return &protocol.EvsName{Token: token[:], SealedName: []byte("sealed " + label)}
	}
	first := fixture.plan()
	first.Changes = append(first.Changes, &sidecar.EvsPlannedChange{TokenPath: directory, EntryVersion: fixture.check.directoryEntry(first, 1, []*protocol.EvsName{row("x")}, nil)})
	fixture.requireCommitted(fixture.push(first), 1)
	fixture.awaitStepEights()
	second := fixture.plan()
	second.Changes = append(second.Changes, &sidecar.EvsPlannedChange{TokenPath: directory, BaseEntryVersion: 1, EntryVersion: fixture.check.directoryEntry(second, 2, []*protocol.EvsName{row("y")}, nil)})
	fixture.requireCommitted(fixture.push(second), 2)
	fixture.awaitStepEights()
	reply := fixture.readPath(token, 0, false, directory)
	pathReply := reply.paths[0]
	requireVersionProven(t, reply, pathReply, directory)
	if pathReply.GetVersion().GetCommitVersion() != 2 || len(pathReply.GetDeltas()) != 2 || pathReply.GetNamesThrough() != 0 {
		t.Fatalf("directory %v", pathReply)
	}
	for i, delta := range pathReply.GetDeltas() {
		if delta.GetCommitVersion() != uint64(i+1) || len(delta.GetEntryVersion()) == 0 {
			t.Fatalf("delta %d: %v", i, delta)
		}
	}
}

// An older version by number comes from the window with its own statement and proof.
func TestReadAnswersAnOlderVersionByNumber(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	path := checkTestPath("a")
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
	write := fixture.plan()
	write.Changes = append(write.Changes, fixture.check.change(write, path, 1, 2))
	fixture.requireCommitted(fixture.push(write), 2)
	fixture.awaitStepEights()
	reply := fixture.read(token, &protocol.EvsReadRequest{
		RefId: fixture.check.refId.Bytes(), PinVersion: 2,
		Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{TokenPath: path.Components()}}, Version: 1}},
	})
	pathReply := reply.paths[0]
	if pathReply.GetVersion().GetCommitVersion() != 1 {
		t.Fatalf("older version %v", pathReply.GetVersion())
	}
	requireVersionProven(t, reply, pathReply, path)
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(pathReply.GetVersion().GetEntryVersion(), entry); err != nil || entry.GetVersion() != 1 {
		t.Fatalf("entry %v %v", entry, err)
	}
}

// FS-62's cache cases: a cached head is never served below a reader's pin, nor on fresh, and a pin the window no
// longer reaches answers behind.
func TestReadCacheNeverServesBelowAPinOrOnFresh(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
	// a second engine on the same store with no Redis commits version 2, which the first engine's cache never learns
	otherHost := *fixture.host.ServiceHost()
	otherHost.Redis = nil
	other, err := NewEvsEngine(fixture.ctx, &otherHost, fixture.settings, &EvsEngineDeps{
		AuthState: fixture.auth,
		Uploads:   &EvsUploadDeps{Keys: fixture.check.receiptKeys, Quota: fixture.check.quota.gate},
		GateViews: &pushTestGateViews{check: fixture.check},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	plan := fixture.plan()
	fixture.create(plan, "b")
	bodyBytes, _ := proto.Marshal(fixture.body(plan))
	request := httptest.NewRequestWithContext(fixture.ctx, http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(fixture.check.repoId)+"/push", bytes.NewReader(bodyBytes))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	other.Handler().ServeHTTP(recorder, request)
	fixture.requireCommitted(recorder, 2)

	path := checkTestPath("a")
	// pin 1: the cached head at version 1 is served, below the cluster's 2 but not below the pin
	gets := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	if reply := fixture.readPath(token, 1, false, path); reply.head.GetVersion() != 1 {
		t.Fatalf("pin 1 served version %d", reply.head.GetVersion())
	}
	if got := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - gets; got != 1 {
		t.Errorf("%d GETs with a cached head, want the entry's alone", got)
	}
	// pin 2: the cache is below the pin, so the cluster's head is served
	if reply := fixture.readPath(token, 2, false, path); reply.head.GetVersion() != 2 {
		t.Fatalf("pin 2 served version %d", reply.head.GetVersion())
	}
	// fresh: the cluster's
	if reply := fixture.readPath(token, 0, true, path); reply.head.GetVersion() != 2 {
		t.Fatalf("fresh served version %d", reply.head.GetVersion())
	}
	// a cached head over 10 min old is not served
	fixture.clock.Advance(11 * time.Minute)
	if reply := fixture.readPath(token, 0, false, path); reply.head.GetVersion() != 2 {
		t.Fatalf("after 10 min served version %d", reply.head.GetVersion())
	}
}

// A deposit-only principal is refused on every read route (FS-23).
func TestReadRefusesADepositOnlyPrincipal(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.auth.grant(fixture.check.otherId, fixture.check.repoId, sidecar.AclEvsDeposit)
	token := fixture.token(fixture.check.otherId, "deposit")
	requireRefusal(t, fixture.call(token, http.MethodPost, "/read", &protocol.EvsReadRequest{RefId: fixture.check.refId.Bytes()}), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	requireRefusal(t, fixture.call(token, http.MethodGet, "/refs", nil), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	requireRefusal(t, fixture.call(token, http.MethodGet, "/log?ref="+sidecar.EvsKeyId(fixture.check.refId)+"&since=1", nil), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	// the streams form is M6's
	requireRefusal(t, fixture.call(fixture.token(fixture.check.signerId, "r"), http.MethodPost, "/read",
		&protocol.EvsReadRequest{RefId: fixture.check.refId.Bytes(), Refs: []*protocol.EvsReadRef{{RefId: fixture.check.refId.Bytes()}}}),
		http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
}

// GET .../refs lists each committed ref's head, the repo's format and push sequence, and no placeholder.
func TestRefsListsCommittedHeads(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
	// a refusal on another ref leaves a placeholder head
	stale := fixture.plan()
	stale.RefId = testId("other ref")
	stale.BaseVersion, stale.BaseChain = 0, sidecar.EvsChainStart(fixture.check.repoId, stale.RefId)
	stale.TimeMs = fixture.clock.Now().Add(-11 * time.Minute).UnixMilli()
	fixture.create(stale, "stale")
	requireRefusal(t, fixture.push(stale), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE)
	recorder := fixture.call(token, http.MethodGet, "/refs", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("refs: %d", recorder.Code)
	}
	reply := &protocol.EvsRefsReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		t.Fatal(err)
	}
	if reply.GetFormat() != 1 || reply.GetPushSequence() == 0 || len(reply.GetRefs()) != 1 {
		t.Fatalf("refs %v", reply)
	}
	ref := reply.GetRefs()[0]
	if !bytes.Equal(ref.GetRefId(), fixture.check.refId.Bytes()) || ref.GetVersion() != 1 || ref.GetPushSequence() == 0 {
		t.Fatalf("ref %v", ref)
	}
}

// GET .../log pages statements from since, at most LogReplyStatementCount an answer, next_version 0 at the head.
func TestLogPagesStatements(t *testing.T) {
	fixture := newPushFixture(t, func(settings *EvsSettings) { settings.LogReplyStatementCount = 2 })
	token := fixture.token(fixture.check.signerId, "r")
	for _, label := range []string{"a", "b", "c"} {
		fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, label)
	}
	page := func(since uint64) *protocol.EvsLogReply {
		recorder := fixture.call(token, http.MethodGet, "/log?ref="+sidecar.EvsKeyId(fixture.check.refId)+"&since="+strconv.FormatUint(since, 10), nil)
		if recorder.Code != http.StatusOK {
			t.Fatalf("log: %d", recorder.Code)
		}
		reply := &protocol.EvsLogReply{}
		if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	first := page(1)
	if len(first.GetStatements()) != 2 || first.GetStatements()[0].GetVersion() != 1 || first.GetNextVersion() != 3 {
		t.Fatalf("page 1: %v", first)
	}
	second := page(3)
	if len(second.GetStatements()) != 1 || second.GetStatements()[0].GetVersion() != 3 || second.GetNextVersion() != 0 {
		t.Fatalf("page 2: %v", second)
	}
	// each statement is the push's, in order
	chain := sidecar.EvsChainStart(fixture.check.repoId, fixture.check.refId)
	for _, statement := range append(first.GetStatements(), second.GetStatements()...) {
		parsed, err := sidecar.ParseEvsStatement(statement.GetStatement())
		if err != nil {
			t.Fatal(err)
		}
		chain = sidecar.EvsChainNext(chain, sidecar.Id(parsed.Push.GetPushId()), parsed.Sha256)
	}
	if !bytes.Equal(chain[:], fixture.head().Head.GetChain()) {
		t.Fatal("the log's statements do not chain to the head")
	}
	if empty := page(4); len(empty.GetStatements()) != 0 || empty.GetNextVersion() != 0 {
		t.Fatalf("past the head: %v", empty)
	}
	requireRefusal(t, fixture.call(token, http.MethodGet, "/log?ref="+sidecar.EvsKeyId(fixture.check.refId)+"&since=0", nil), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
}

// The objects a read names: a slot whole, a push record by its version, and a missing one marked so.
func TestReadStreamsObjects(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	slotId, slotObject, slotBody := checkTestSlot(t, "slot a")
	plan := fixture.plan()
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("a"), EntryVersion: fixture.check.fileEntry(plan, 1, nil, slotId),
	})
	plan.NewObjects = append(plan.NewObjects, slotObject)
	plan.SlotBodies = append(plan.SlotBodies, slotBody)
	fixture.requireCommitted(fixture.push(plan), 1)
	fixture.awaitStepEights()
	reply := fixture.read(token, &protocol.EvsReadRequest{
		RefId:   fixture.check.refId.Bytes(),
		SlotIds: [][]byte{slotId.Bytes(), testId("no slot").Bytes()},
		Pushes:  []*protocol.EvsReadPush{{PushId: plan.PushId.Bytes(), Version: 1}, {PushId: testId("no push").Bytes(), Version: 1}},
		Ranges:  []*protocol.EvsReadRange{{SegmentId: bytes.Repeat([]byte{9}, 32), Offset: 0, Length: 16}},
	})
	if len(reply.objects) != 5 {
		t.Fatalf("%d objects", len(reply.objects))
	}
	if slot := reply.objects[0]; slot.GetKind() != protocol.EvsReadObjectKind_EVS_READ_OBJECT_SLOT || !bytes.Equal(slot.GetBody(), slotBody) {
		t.Fatalf("slot %v", slot)
	}
	if !reply.objects[1].GetMissing() {
		t.Fatal("an unknown slot not missing")
	}
	record := reply.objects[2]
	if record.GetKind() != protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD || record.GetMissing() {
		t.Fatalf("record %v", record)
	}
	parsed, err := sidecar.ParseEvsBatchRecord(record.GetBody())
	if err != nil || parsed.PushId != plan.PushId {
		t.Fatalf("record bytes: %v", err)
	}
	if !reply.objects[3].GetMissing() || !reply.objects[4].GetMissing() {
		t.Fatal("an unknown push or segment not missing")
	}
}
