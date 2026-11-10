// EVS1-M2-13's tests on T2's fakes, through the engine's guard: a push in parts sealed in file mode and under a
// git-mode lease; uncommitted parts invisible to a read; a part's refusal unrecorded; FS-113's seal with a part
// missing, posted again and sealed again; FS-5's lease cases on a warm head cache (a lease after another push's
// refusal fence, 429 during another's lease, a lease below the tip, a one-part push refused 429 while a lease
// stands); an expired lease's seal failing TIP once another push took the tip; and a kill between parts exposing
// nothing. §22.5's 2,000-file merge taking a push every 3 s is left to the review phase.

package evsservice

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A plan creating count paths on the fixture's ref, in mode, which the builder splits into parts past 1,024 entry
// writes.
func (self *pushFixture) partsPlan(mode protocol.EvsRefMode, count int) *sidecar.EvsPushPlan {
	plan := self.plan()
	plan.RefMode = mode
	for i := 0; i < count; i += 1 {
		self.create(plan, fmt.Sprintf("file-%05d", i))
	}
	return plan
}

// plan built and signed by the fixture's writer, in parts.
func (self *pushFixture) built(plan *sidecar.EvsPushPlan) *sidecar.EvsBuiltPush {
	self.t.Helper()
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(self.check.signingKey, self.check.signerId)).Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	return built
}

// One request of method at path under token, with body's bytes.
func (self *pushFixture) call(token string, method string, path string, body proto.Message) *httptest.ResponseRecorder {
	self.t.Helper()
	var reader io.Reader
	if body != nil {
		bodyBytes, err := proto.Marshal(body)
		if err != nil {
			self.t.Fatal(err)
		}
		reader = bytes.NewReader(bodyBytes)
	}
	request := httptest.NewRequestWithContext(self.ctx, method, "/evs/v1/repos/"+sidecar.EvsKeyId(self.check.repoId)+path, reader)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// POST .../push/<P>/<k> of part index of built.
func (self *pushFixture) postPart(token string, built *sidecar.EvsBuiltPush, index int) *httptest.ResponseRecorder {
	pushId := sidecar.Id(built.Statement.Push.GetPushId())
	return self.call(token, http.MethodPost, "/push/"+sidecar.EvsKeyId(pushId)+"/"+strconv.Itoa(index+1),
		&protocol.EvsPartRequest{Statement: built.Statement.Bytes, Part: built.Parts[index]})
}

// The place a part's 200 answers.
func (self *pushFixture) requirePlace(recorder *httptest.ResponseRecorder) *protocol.EvsPlace {
	self.t.Helper()
	if recorder.Code != http.StatusOK {
		self.t.Fatalf("status %d (%s), want 200", recorder.Code, refusalOf(self.t, recorder).GetCode())
	}
	reply := &protocol.EvsPushReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		self.t.Fatal(err)
	}
	if reply.GetPlace() == nil {
		self.t.Fatal("a part answered no place")
	}
	return reply.GetPlace()
}

// Every part of built posted, their places in part order.
func (self *pushFixture) postParts(token string, built *sidecar.EvsBuiltPush) []*protocol.EvsPlace {
	self.t.Helper()
	places := make([]*protocol.EvsPlace, len(built.Parts))
	for i := range built.Parts {
		places[i] = self.requirePlace(self.postPart(token, built, i))
	}
	return places
}

// POST .../push with built's statement and places: the seal.
func (self *pushFixture) seal(token string, built *sidecar.EvsBuiltPush, places []*protocol.EvsPlace) *httptest.ResponseRecorder {
	return self.post(token, &protocol.EvsPushRequest{Statement: built.Statement.Bytes, PartPlaces: places})
}

// POST .../push/<P>/lease.
func (self *pushFixture) lease(token string, pushId sidecar.Id, baseVersion uint64, duration time.Duration) *httptest.ResponseRecorder {
	return self.call(token, http.MethodPost, "/push/"+sidecar.EvsKeyId(pushId)+"/lease",
		&protocol.EvsLeaseRequest{RefId: self.check.refId.Bytes(), BaseVersion: baseVersion, Ms: uint32(duration.Milliseconds())})
}

// A one-part push committed on the fixture's ref in mode, creating label.
func (self *pushFixture) commitOne(mode protocol.EvsRefMode, label string) uint64 {
	self.t.Helper()
	plan := self.plan()
	plan.RefMode = mode
	self.create(plan, label)
	reply := self.requireCommitted(self.push(plan), plan.BaseVersion+1)
	self.awaitStepEights()
	return reply.GetVersion()
}

// A push past 1,024 entry writes goes in parts: each part answers its place, the seal commits at the next version,
// and the record at the head's place is the seal naming every part.
func TestPartsSealCommitInFileMode(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	if len(built.Parts) < 2 {
		t.Fatalf("%d parts, want at least 2", len(built.Parts))
	}
	places := fixture.postParts(token, built)
	if !fixture.head().Absent() {
		t.Fatal("a part wrote the head")
	}
	fixture.requireCommitted(fixture.seal(token, built, places), 1)
	fixture.awaitStepEights()
	head := fixture.head()
	window, err := EvsHeadWindow(head.Head)
	if err != nil || len(window) != 1 {
		t.Fatalf("window %v %v", window, err)
	}
	record, err := fixture.engine.readRecordAt(fixture.ctx, fixture.cluster, fixture.check.repoId, fixture.check.refId, window[0].Place)
	if err != nil {
		t.Fatal(err)
	}
	if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
		t.Fatalf("record type %d, want a seal", record.Type)
	}
	_, parts, err := sidecar.ParseEvsSealRecordBody(record.Body)
	if err != nil || len(parts) != len(places) {
		t.Fatalf("seal parts %d %v", len(parts), err)
	}
	for i, part := range parts {
		if !sameEvsPlace(part.Place, places[i]) {
			t.Errorf("part %d at another place", i+1)
		}
	}
	// a retry of the seal answers the same version
	fixture.requireCommitted(fixture.seal(token, built, places), 1)
}

// Git mode: the lease first, then the parts, then the seal, which clears the lease.
func TestPartsSealCommitUnderAGitLease(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_GIT, "first")
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_GIT, 1100))
	pushId := sidecar.Id(built.Statement.Push.GetPushId())
	if recorder := fixture.lease(token, pushId, 1, 60*time.Second); recorder.Code != http.StatusOK {
		t.Fatalf("lease: %d %s", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	head := fixture.head()
	if lease := head.Head.GetLease(); !bytes.Equal(lease.GetPushId(), pushId.Bytes()) || head.Version() != 1 {
		t.Fatalf("lease %v at version %d", lease, head.Version())
	}
	// its own lease again: 200, nothing written
	etag := head.Etag
	if recorder := fixture.lease(token, pushId, 1, 60*time.Second); recorder.Code != http.StatusOK {
		t.Fatalf("own lease again: %d", recorder.Code)
	}
	if fixture.head().Etag != etag {
		t.Fatal("an own lease wrote the head again")
	}
	places := fixture.postParts(token, built)
	fixture.requireCommitted(fixture.seal(token, built, places), 2)
	fixture.awaitStepEights()
	head = fixture.head()
	if head.Version() != 2 || head.Head.GetLease() != nil {
		t.Fatalf("after the seal: version %d lease %v", head.Version(), head.Head.GetLease())
	}
}

// A lease on a ref with no head takes a placeholder head at version 0, which reads treat as absent and the seal
// replaces by its first commit.
func TestLeaseOnARefWithNoHead(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_GIT, 1100))
	pushId := sidecar.Id(built.Statement.Push.GetPushId())
	if recorder := fixture.lease(token, pushId, 0, time.Minute); recorder.Code != http.StatusOK {
		t.Fatalf("lease: %d %s", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	head := fixture.head()
	if head.Absent() || head.Version() != 0 || !bytes.Equal(head.Head.GetLease().GetPushId(), pushId.Bytes()) {
		t.Fatalf("placeholder %v", head.Head)
	}
	if reply := fixture.read(token, &protocol.EvsReadRequest{RefId: fixture.check.refId.Bytes()}); reply.head.GetVersion() != 0 || reply.head.GetRefMode() != 0 {
		t.Fatalf("a placeholder read as %v", reply.head)
	}
	// another push's one-part push to the ref waits on the lease
	one := fixture.plan()
	one.RefMode = protocol.EvsRefMode_EVS_REF_GIT
	fixture.create(one, "one")
	requireRefusal(t, fixture.push(one), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_WAIT)
	places := fixture.postParts(token, built)
	fixture.requireCommitted(fixture.seal(token, built, places), 1)
	if head := fixture.head(); head.Version() != 1 || head.Head.GetLease() != nil || head.Head.GetRefMode() != uint32(protocol.EvsRefMode_EVS_REF_GIT) {
		t.Fatalf("after the seal: %v", head.Head)
	}
}

// Parts not sealed are invisible: the head stands and a read answers the path absent.
func TestPartsUnsealedAreInvisible(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "first")
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	// a kill between parts: the first part lands, the rest never post
	fixture.requirePlace(fixture.postPart(token, built, 0))
	if fixture.head().Version() != 1 {
		t.Fatal("a part moved the head")
	}
	reply := fixture.read(token, &protocol.EvsReadRequest{
		RefId: fixture.check.refId.Bytes(),
		Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: checkTestPath("file-00000").Components()}}}},
	})
	if reply.head.GetVersion() != 1 || len(reply.paths) != 1 || reply.paths[0].GetVersion() != nil || reply.paths[0].GetRemoval() != nil {
		t.Fatalf("an unsealed part's path read %v at version %d", reply.paths[0], reply.head.GetVersion())
	}
}

// A part's refusal is answered as is and recorded nowhere: a stale part leaves no placeholder head.
func TestPartRefusalIsNotRecorded(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	plan := fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100)
	plan.TimeMs = fixture.clock.Now().Add(-31 * time.Minute).UnixMilli()
	built := fixture.built(plan)
	recorder := fixture.postPart(token, built, 0)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE)
	if refusalOf(t, recorder).GetRecorded() {
		t.Fatal("a part's refusal answered recorded")
	}
	if !fixture.head().Absent() {
		t.Fatal("a part's refusal wrote a head")
	}
	// another push's part, numbered off its path
	fresh := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	pushId := sidecar.Id(fresh.Statement.Push.GetPushId())
	requireRefusal(t, fixture.call(token, http.MethodPost, "/push/"+sidecar.EvsKeyId(pushId)+"/2",
		&protocol.EvsPartRequest{Statement: fresh.Statement.Bytes, Part: fresh.Parts[0]}), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
}

// FS-113's seal: a part missing answers 409 PARTS_MISSING, recording and refusing nothing; the part posted again and
// the push sealed again commits.
func TestSealWithAPartMissing(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	places := fixture.postParts(token, built)
	missing := append([]*protocol.EvsPlace{}, places...)
	missing[1] = &protocol.EvsPlace{Minute: places[1].GetMinute() + 1, Instance: places[1].GetInstance(), Seq: 7, Offset: 0, Length: places[1].GetLength()}
	recorder := fixture.seal(token, built, missing)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING)
	if !fixture.head().Absent() {
		t.Fatal("PARTS_MISSING wrote the head")
	}
	// a place holding another push's record is a part missing too
	other := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	otherPlaces := fixture.postParts(token, other)
	swapped := append([]*protocol.EvsPlace{}, places...)
	swapped[1] = otherPlaces[1]
	requireRefusal(t, fixture.seal(token, built, swapped), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING)
	// the part again, then the seal
	places[1] = fixture.requirePlace(fixture.postPart(token, built, 1))
	fixture.requireCommitted(fixture.seal(token, built, places), 1)
}

// FS-5's lease cases on a warm head cache.
func TestLeaseCases(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_GIT, "first")

	// a lease below the tip: 409 non-fast-forward
	lower := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_GIT, 1100))
	requireRefusal(t, fixture.lease(token, sidecar.Id(lower.Statement.Push.GetPushId()), 0, time.Minute),
		http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD)

	// another push's refusal fence moved the head's ETag past the cache's: the lease rereads and lands
	stale := fixture.plan()
	stale.RefMode = protocol.EvsRefMode_EVS_REF_GIT
	stale.TimeMs = fixture.clock.Now().Add(-11 * time.Minute).UnixMilli()
	fixture.create(stale, "stale")
	requireRefusal(t, fixture.push(stale), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE)
	fenced := fixture.head()
	if fenced.Head.GetFence() == 0 {
		t.Fatal("no refusal fence")
	}
	first := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_GIT, 1100))
	firstId := sidecar.Id(first.Statement.Push.GetPushId())
	if recorder := fixture.lease(token, firstId, 1, time.Minute); recorder.Code != http.StatusOK {
		t.Fatalf("lease after a refusal fence: %d %s", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	if lease := fixture.head().Head.GetLease(); !bytes.Equal(lease.GetPushId(), firstId.Bytes()) {
		t.Fatalf("lease %v", lease)
	}

	// another push's lease while the first stands: 429 with the remaining time; a one-part push 429 too
	second := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_GIT, 1100))
	recorder := fixture.lease(token, sidecar.Id(second.Statement.Push.GetPushId()), 1, time.Minute)
	requireRefusal(t, recorder, http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_WAIT)
	if after := refusalOf(t, recorder).GetRetryAfterMs(); after == 0 || 60000 < after {
		t.Fatalf("retry_after_ms %d", after)
	}
	one := fixture.plan()
	one.RefMode = protocol.EvsRefMode_EVS_REF_GIT
	fixture.create(one, "one")
	requireRefusal(t, fixture.push(one), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_WAIT)

	// once the lease expires, the second takes one
	fixture.clock.Advance(61 * time.Second)
	if recorder := fixture.lease(token, sidecar.Id(second.Statement.Push.GetPushId()), 1, time.Minute); recorder.Code != http.StatusOK {
		t.Fatalf("lease after expiry: %d %s", recorder.Code, refusalOf(t, recorder).GetCode())
	}

	// a lease on a file-mode ref: 409 REF_MODE
	file := newPushFixture(t, nil)
	file.commitOne(protocol.EvsRefMode_EVS_REF_FILE, "first")
	requireRefusal(t, file.lease(file.token(file.check.signerId), testId("file lease"), 1, time.Minute), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE)

	// a lease past 120 s: 400
	requireRefusal(t, fixture.lease(token, testId("long lease"), 1, 121*time.Second), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
}

// An expired lease's seal fails TIP: another push took the tip meanwhile, and the seal answers 409 non-fast-forward,
// its parts left to evacuation.
func TestSealAfterAnExpiredLeaseFailsTip(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_GIT, "first")
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_GIT, 1100))
	pushId := sidecar.Id(built.Statement.Push.GetPushId())
	if recorder := fixture.lease(token, pushId, 1, time.Second); recorder.Code != http.StatusOK {
		t.Fatalf("lease: %d", recorder.Code)
	}
	places := fixture.postParts(token, built)
	fixture.clock.Advance(2 * time.Second)
	// the lease lapsed: a one-part push takes the tip
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_GIT, "second")
	requireRefusal(t, fixture.seal(token, built, places), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD)
	if fixture.head().Version() != 2 {
		t.Fatal("the seal moved the head")
	}
}

// A seal within its lease on the tip commits even when the cached head is stale by the lease's own write.
func TestSealReadsTheClusterHead(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	fixture.commitOne(protocol.EvsRefMode_EVS_REF_GIT, "first")
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_GIT, 1100))
	pushId := sidecar.Id(built.Statement.Push.GetPushId())
	if recorder := fixture.lease(token, pushId, 1, time.Minute); recorder.Code != http.StatusOK {
		t.Fatalf("lease: %d", recorder.Code)
	}
	places := fixture.postParts(token, built)
	puts := fixture.host.Blobs.RequestCount("meta-1", "put")
	fixture.requireCommitted(fixture.seal(token, built, places), 2)
	if got := fixture.host.Blobs.RequestCount("meta-1", "put") - puts; got != 2 {
		t.Errorf("%d PUTs for the seal, want its batch's and its head's", got)
	}
}
