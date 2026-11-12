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
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
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
		Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: path.Components()}}}},
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
		Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: path.Components()}}, Version: 1}},
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

// §11.12's refused row on the read routes (QD-665): while repo/ is deleted the read, GET .../refs and GET .../log
// answer 409 REPO_DELETED, and while it is shredding or shredded 409 SHREDDING, reading nothing past repo/; keying
// and active are served, and a repo active again reads as before.
func TestReadRoutesRefuseADeletedOrShreddingRepo(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId, "r")
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "a")
	routes := []struct {
		method string
		path   string
		body   proto.Message
	}{
		{method: http.MethodPost, path: "/read", body: &protocol.EvsReadRequest{RefId: fixture.check.refId.Bytes(), Fresh: true}},
		{method: http.MethodGet, path: "/refs"},
		{method: http.MethodGet, path: "/log?ref=" + sidecar.EvsKeyId(fixture.check.refId) + "&since=1"},
	}
	states := []struct {
		state protocol.EvsRepoState
		// the refusal, or none for a state that is served
		code protocol.EvsRefusalCode
	}{
		{state: protocol.EvsRepoState_EVS_REPO_ACTIVE},
		{state: protocol.EvsRepoState_EVS_REPO_DELETED, code: protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED},
		{state: protocol.EvsRepoState_EVS_REPO_SHREDDING, code: protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING},
		{state: protocol.EvsRepoState_EVS_REPO_SHREDDED, code: protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING},
		{state: protocol.EvsRepoState_EVS_REPO_KEYING},
		{state: protocol.EvsRepoState_EVS_REPO_ACTIVE},
	}
	for _, c := range states {
		fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, c.state)
		gets := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
		lists := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpList)
		for _, route := range routes {
			recorder := fixture.call(token, route.method, route.path, route.body)
			switch {
			case c.code == protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED && recorder.Code != http.StatusOK:
				t.Errorf("%s %s with repo/ %s: %d (%s), want 200", route.method, route.path, c.state, recorder.Code, refusalOf(t, recorder).GetCode())
			case c.code != protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED && (recorder.Code != http.StatusConflict || refusalOf(t, recorder).GetCode() != c.code):
				t.Errorf("%s %s with repo/ %s: %d, want 409 %s", route.method, route.path, c.state, recorder.Code, c.code)
			}
		}
		if c.code == protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
			continue
		}
		// repo/ from the cluster once, the cache serving the next two, and no head, entry or LIST
		if got := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - gets; got != 1 {
			t.Errorf("with repo/ %s the refusals read %d objects, want repo/ alone", c.state, got)
		}
		if got := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpList) - lists; got != 0 {
			t.Errorf("with repo/ %s the refusals listed %d times", c.state, got)
		}
	}
	reply := fixture.readPath(token, 0, true, checkTestPath("a"))
	if reply.head.GetVersion() != 1 || len(reply.paths) != 1 || reply.paths[0].GetVersion() == nil {
		t.Fatalf("the active repo's read after the refusals: head %v paths %v", reply.head, reply.paths)
	}
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

// A read of paths, each named by its token path in each epoch its map gives, newest epoch first.
func (self *pushFixture) readNamed(token string, pin uint64, paths ...map[uint64]sidecar.EvsTokenPath) *readTestReply {
	self.t.Helper()
	return self.read(token, self.namedRequest(pin, 0, 0, paths...))
}

// The read request for paths named by epoch, at version with commitVersion when version is not 0.
func (self *pushFixture) namedRequest(pin uint64, version uint64, commitVersion uint64, paths ...map[uint64]sidecar.EvsTokenPath) *protocol.EvsReadRequest {
	request := &protocol.EvsReadRequest{RefId: self.check.refId.Bytes(), PinVersion: pin}
	for _, named := range paths {
		readPath := &protocol.EvsReadPath{Version: version, CommitVersion: commitVersion}
		for _, epoch := range slices.Sorted(maps.Keys(named)) {
			readPath.TokenPaths = append([]*protocol.EvsSourcePath{{Epoch: epoch, TokenPath: named[epoch].Components()}}, readPath.TokenPaths...)
		}
		request.Paths = append(request.Paths, readPath)
	}
	return request
}

// A one-part push at generation 2 under commitment on the head as it stands, in its current epoch, creating each label
// below directory, so many that its list goes under changes_root: its version.
func (self *pushFixture) commitRooted(commitment []byte, directory string, labels ...string) uint64 {
	self.t.Helper()
	plan := self.planOnHead(2, commitment)
	for _, label := range labels {
		plan.Changes = append(plan.Changes, self.check.change(plan, epochPath(plan.PathEpoch, directory, label), 0, plan.BaseVersion+1))
	}
	if built := self.built(plan); len(built.Statement.Push.GetChangesRoot()) == 0 || len(built.Parts) != 0 {
		self.t.Fatal("a push whose list is inline or in parts")
	}
	version := self.requireCommitted(self.push(plan), plan.BaseVersion+1).GetVersion()
	self.awaitStepEights()
	return version
}

// Thirty labels from prefix.
func readTestLabels(prefix string) []string {
	labels := []string{}
	for i := 0; i < 30; i += 1 {
		labels = append(labels, fmt.Sprintf("%s-%02d", prefix, i))
	}
	return labels
}

// A PATH_EPOCH to epoch 2 on the head as it stands, its map moving each of moves, committed at its next version.
func (self *pushFixture) cutOverToEpochTwo(commitment []byte, moves ...*protocol.EvsPathMove) uint64 {
	self.t.Helper()
	source := self.head()
	parts, mapSha256 := self.mapPartsAt(2, source.Version(), source.Head.GetChain(), moves)
	self.uploadParts(parts, mapSha256)
	version := self.requireCommitted(self.push(self.pathEpochPlanAt(2, 2, commitment, mapSha256, source.Version(), source.Head.GetChain())), source.Version()+1).GetVersion()
	self.awaitStepEights()
	return version
}

// Asserts the reply's absence proofs: each for a version want names, of that version's token path or a prefix
// holding it, verifying against its statement's root, and one at least for each version want names.
func requireAbsences(t *testing.T, reply *readTestReply, pathReply *protocol.EvsReadPathReply, want map[uint64]sidecar.EvsTokenPath) {
	t.Helper()
	seen := map[uint64]bool{}
	for _, absence := range pathReply.GetAbsences() {
		tokenPath, ok := want[absence.GetVersion()]
		absentPath, err := sidecar.ParseEvsTokenPath(absence.GetTokenPath())
		if !ok || err != nil || !tokenPath.HasPrefix(absentPath) {
			t.Fatalf("an absence for version %d of another path", absence.GetVersion())
		}
		push := readTestStatement(t, reply, pathReply, absence.GetVersion()).Push
		if err := sidecar.EvsVerifyChangeAbsence(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), absentPath, absence); err != nil {
			t.Fatalf("version %d's absence: %v", absence.GetVersion(), err)
		}
		seen[absence.GetVersion()] = true
	}
	for version := range want {
		if !seen[version] {
			t.Fatalf("no absence for version %d among %d", version, len(pathReply.GetAbsences()))
		}
	}
}

// DESIGN-DETAILS 9.2.4: a version written before a cut-over by a push under changes_root is served with its proof by
// the leaf place its fold recorded, unmoved from the source a reader names and once the copy moved it; each later
// statement under changes_root answers adjacent-leaf proofs under the path's token path in its own epoch, and
// nothing for an epoch the request does not name.
func TestReadServesAVersionOfAnOlderEpochByItsLeafPlace(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	commitment := fixture.crossRemove(false)
	written := fixture.commitRooted(commitment, "dir", readTestLabels("r")...)
	untouched := fixture.commitRooted(commitment, "dir", readTestLabels("q")...)
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "dir", "r-07"))
	later := fixture.commitRooted(commitment, "dir", readTestLabels("s")...)
	oldPath, newPath := epochPath(1, "dir", "r-07"), epochPath(2, "dir", "r-07")

	reply := fixture.readNamed(token, written, map[uint64]sidecar.EvsTokenPath{2: newPath, 1: oldPath})
	pathReply := reply.paths[0]
	if pathReply.GetEntryEpoch() != 1 || pathReply.GetVersion().GetCommitVersion() != written || pathReply.GetVersion().GetLeafIndex() == 0 ||
		!bytes.Equal(bytes.Join(pathReply.GetTokenPath(), nil), newPath.Bytes()) {
		t.Fatalf("unmoved: entry epoch %d, version %v", pathReply.GetEntryEpoch(), pathReply.GetVersion())
	}
	requireVersionProven(t, reply, pathReply, oldPath)
	requireAbsences(t, reply, pathReply, map[uint64]sidecar.EvsTokenPath{untouched: oldPath, later: newPath})

	if _, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2)); err != nil {
		t.Fatal(err)
	}
	if fixture.entryAt(2, "epoch 2", "dir", "r-07").Absent() {
		t.Fatal("the copy did not move the path")
	}
	reply = fixture.readNamed(token, written, map[uint64]sidecar.EvsTokenPath{2: newPath})
	pathReply = reply.paths[0]
	if pathReply.GetEntryEpoch() != 0 || pathReply.GetVersion().GetCommitVersion() != written {
		t.Fatalf("moved: entry epoch %d, version %v", pathReply.GetEntryEpoch(), pathReply.GetVersion())
	}
	requireVersionProven(t, reply, pathReply, oldPath)
	requireAbsences(t, reply, pathReply, map[uint64]sidecar.EvsTokenPath{later: newPath})
}

// DESIGN-DETAILS 9.2.4: a request naming no token path in the head's current epoch gets stale_epoch for that path,
// nothing read for it, beside the paths it names well; one naming an epoch twice, or none, is 400.
func TestReadAnswersStaleEpoch(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	commitment := fixture.crossRemove(false)
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))
	reply := fixture.readNamed(token, 0, map[uint64]sidecar.EvsTokenPath{1: checkTestPath("a")},
		map[uint64]sidecar.EvsTokenPath{2: epochPath(2, "a"), 1: checkTestPath("a")})
	stale, fresh := reply.paths[0], reply.paths[1]
	if !stale.GetStaleEpoch() || stale.GetVersion() != nil || len(stale.GetStatement()) != 0 || stale.GetRemoval() != nil ||
		!bytes.Equal(bytes.Join(stale.GetTokenPath(), nil), checkTestPath("a").Bytes()) {
		t.Fatalf("stale: %v", stale)
	}
	if fresh.GetStaleEpoch() || fresh.GetVersion() == nil || reply.head.GetPathEpoch().GetCurrent() != 2 {
		t.Fatalf("fresh: %v at epoch %d", fresh, reply.head.GetPathEpoch().GetCurrent())
	}
	for _, paths := range [][]*protocol.EvsSourcePath{
		{{Epoch: 2, TokenPath: epochPath(2, "a").Components()}, {Epoch: 2, TokenPath: checkTestPath("a").Components()}},
		{{TokenPath: checkTestPath("a").Components()}},
	} {
		request := &protocol.EvsReadRequest{RefId: fixture.check.refId.Bytes(), Paths: []*protocol.EvsReadPath{{TokenPaths: paths}}}
		requireRefusal(t, fixture.call(token, http.MethodPost, "/read", request), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	}
}

// DESIGN-DETAILS 9.2.4: a directory's table served from the source a reader names says so in entry_epoch, its delta
// at names_through, an inline push's, found by the request's token path in that epoch; once the copy carried it, a
// reader naming only the current epoch is served it in the same round by the leaf place its fold recorded, an inline
// list's (QD-633), naming no token path of the older epoch; and an entry folded with no place is answered with the
// statement alone, which the reader asks again from.
func TestReadServesATableFromItsSourceWithItsEntryEpoch(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	commitment := fixture.crossRemove(false)
	row := func(label string) *protocol.EvsName {
		return &protocol.EvsName{Token: checkTestPath("d", label).Last().Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: []byte("sealed " + label)}
	}
	plan := fixture.planAtTwo(commitment)
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("d"), EntryVersion: fixture.check.directoryEntry(plan, 3, []*protocol.EvsName{row("x"), row("y")}, nil),
	})
	created := fixture.requireCommitted(fixture.push(plan), 3).GetVersion()
	fixture.awaitStepEights()
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "d"))

	oldPath, newPath := checkTestPath("d"), epochPath(2, "d")
	reply := fixture.readNamed(token, 0, map[uint64]sidecar.EvsTokenPath{2: newPath, 1: oldPath})
	pathReply := reply.paths[0]
	if pathReply.GetEntryEpoch() != 1 || pathReply.GetNamesThrough() != created || len(pathReply.GetNames().GetNames()) != 2 {
		t.Fatalf("the source's table: entry epoch %d, %v", pathReply.GetEntryEpoch(), pathReply)
	}
	requireVersionProven(t, reply, pathReply, oldPath)

	if _, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2)); err != nil {
		t.Fatal(err)
	}
	reply = fixture.readNamed(token, 0, map[uint64]sidecar.EvsTokenPath{2: newPath})
	pathReply = reply.paths[0]
	if pathReply.GetEntryEpoch() != 0 || pathReply.GetNamesThrough() != created || len(pathReply.GetNames().GetNames()) != 2 ||
		pathReply.GetVersion().GetLeafIndex() == 0 {
		t.Fatalf("the carried table by its place: %v", pathReply)
	}
	requireVersionProven(t, reply, pathReply, oldPath)

	// an entry folded before places were recorded for an inline list: the statement alone, as before QD-633
	carried := fixture.entryAt(2, "epoch 2", "d")
	unplaced := proto.Clone(carried.Entry).(*protocol.EvsIndexEntry)
	unplaced.NamesLeafPart, unplaced.NamesLeafIndex = 0, 0
	for _, version := range unplaced.GetVersions() {
		version.LeafPart, version.LeafIndex = 0, 0
	}
	if _, err := PutEntry(fixture.ctx, fixture.cluster, fixture.check.repoId, fixture.check.refId, 2, epochPath(2, "d"), carried, unplaced, carried.State); err != nil {
		t.Fatal(err)
	}
	reply = fixture.readNamed(token, 0, map[uint64]sidecar.EvsTokenPath{2: newPath})
	pathReply = reply.paths[0]
	statement, err := sidecar.ParseEvsStatement(pathReply.GetStatement())
	if err != nil || pathReply.GetVersion() != nil || pathReply.GetNames() != nil || statement.Push.GetPathEpoch() != 1 ||
		!bytes.Equal(statement.Push.GetPushId(), plan.PushId.Bytes()) {
		t.Fatalf("the statement alone: %v %v", pathReply, err)
	}
}

// DESIGN-DETAILS 9.2.4 and QD-633: after a cut-over and its copy, a file's version and a removal's marker that inline
// pushes wrote in epoch 1 are each served in one round to a reader naming only the current epoch, found in their
// statements by the leaf places their folds recorded, with no token path of epoch 1 named, and each verifies under the
// path's own token path in epoch 1 as the reader computes it.
func TestReadServesAnInlinePushsVersionAndRemovalByTheirPlaces(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	commitment := fixture.crossRemove(false)
	// a removal of b, an inline push of epoch 1
	created := fixture.planAtTwo(commitment)
	fixture.create(created, "b")
	createdVersion := fixture.requireCommitted(fixture.push(created), 3).GetVersion()
	removal := fixture.planAtTwo(commitment)
	removal.Changes = append(removal.Changes, fixture.check.change(removal, checkTestPath("b"), createdVersion, 0))
	removedAt := fixture.requireCommitted(fixture.push(removal), 4).GetVersion()
	fixture.awaitStepEights()
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"), pathEpochTestMoveAt(2, []uint64{1}, "b"))
	if _, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2)); err != nil {
		t.Fatal(err)
	}
	// a, written by crossRemove's inline pushes of epoch 1
	reply := fixture.readNamed(token, 0, map[uint64]sidecar.EvsTokenPath{2: epochPath(2, "a")})
	pathReply := reply.paths[0]
	if pathReply.GetVersion() == nil || pathReply.GetVersion().GetLeafIndex() == 0 {
		t.Fatalf("a's version by its place: %v", pathReply)
	}
	requireVersionProven(t, reply, pathReply, checkTestPath("a"))
	reply = fixture.readNamed(token, 0, map[uint64]sidecar.EvsTokenPath{2: epochPath(2, "b")})
	pathReply = reply.paths[0]
	if removal := pathReply.GetRemoval(); removal == nil || removal.GetRemovalVersion() != removedAt || removal.GetLeafIndex() == 0 {
		t.Fatalf("b's removal by its place: %v", pathReply)
	}
}

// DESIGN-DETAILS 9.2.4's history: an older version no entry and no window holds is read from the push commit_version
// names, by the request's token path in that push's epoch, or answered with that statement alone when the request
// names none there; an elided version an inline list wrote is restored by its elided bytes.
func TestReadAnswersAnOlderVersionByItsCommitVersion(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	commitment := fixture.crossRemove(false)
	for version := uint64(3); version <= 6; version += 1 {
		plan := fixture.planAtTwo(commitment)
		fixture.write(plan, version-1, "a")
		fixture.requireCommitted(fixture.push(plan), version)
	}
	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))
	if _, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2)); err != nil {
		t.Fatal(err)
	}
	oldPath, newPath := checkTestPath("a"), epochPath(2, "a")
	if versions := fixture.entryAt(2, "epoch 2", "a").Entry.GetVersions(); len(versions) != 4 || !versions[2].GetElided() {
		t.Fatalf("the carried entry holds %d versions", len(versions))
	}

	alone := fixture.read(token, fixture.namedRequest(0, 1, 1, map[uint64]sidecar.EvsTokenPath{2: newPath})).paths[0]
	statement, err := sidecar.ParseEvsStatement(alone.GetStatement())
	if err != nil || alone.GetVersion() != nil || statement.Push.GetPathEpoch() != 1 {
		t.Fatalf("version 1 naming epoch 2 alone: %v %v", alone, err)
	}
	reply := fixture.read(token, fixture.namedRequest(0, 1, 1, map[uint64]sidecar.EvsTokenPath{2: newPath, 1: oldPath}))
	if pathReply := reply.paths[0]; pathReply.GetVersion().GetCommitVersion() != 1 {
		t.Fatalf("version 1 naming epoch 1: %v", pathReply)
	}
	requireVersionProven(t, reply, reply.paths[0], oldPath)

	reply = fixture.read(token, fixture.namedRequest(0, 4, 0, map[uint64]sidecar.EvsTokenPath{2: newPath}))
	pathReply := reply.paths[0]
	entry := &protocol.EvsEntryVersion{}
	if pathReply.GetVersion().GetElided() || proto.Unmarshal(pathReply.GetVersion().GetEntryVersion(), entry) != nil || entry.GetVersion() != 4 {
		t.Fatalf("the elided version 4: %v", pathReply.GetVersion())
	}
	requireVersionProven(t, reply, pathReply, oldPath)
}
