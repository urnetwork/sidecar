package gkmservice

// A creation's readers race it (§11.8's place and resolve rows): each reader's sync of a new repo asks gkm as its
// RepoCreate lands, ahead of the creator's PUT, so gkm caches place/'s 404 moments before the placement. It may not
// refuse the creation's own writes, on this process or another that served only a reader. Before the fix, KF1's POST
// /gkm/groups answered the readers' 404, and a group write on the other process 403.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The group world before evs places its repo: newGkmGroupWorld's repo, admin and token, with neither place/ nor repo/
// written yet.
func newGkmUnplacedGroupWorld(t *testing.T) *gkmGroupWorld {
	fixture := newGkmFixture(t)
	fixture.auth.advanceLog(10, 1)
	world := &gkmGroupWorld{
		t:        t,
		fixture:  fixture,
		repoId:   testId("repo-g"),
		groupId:  testId("group-g"),
		memberId: testId("member-a"),
	}
	world.admin = fixture.newSidecar("sc-admin", memberDeviceFacts(world.memberId))
	fixture.auth.grant(world.admin.sidecarId, world.repoId, sidecar.AclEvsAdmin)
	world.adminToken = fixture.token(world.admin.sidecarId, repoScope(world.repoId, "admin"))
	return world
}

// Another gkm process over the fixture's stores and state, sharing none of the fixture engine's caches: an lb host
// beside it.
func (self *gkmFixture) otherEngine() *GkmEngine {
	self.t.Helper()
	engine, err := NewGkmEngine(self.ctx, self.host.ServiceHost(), self.settings, self.deps)
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(engine.Close)
	return engine
}

// One request through engine's handler, as serve sends one through the fixture engine's.
func (self *gkmFixture) serveOn(engine *GkmEngine, method string, path string, token string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(self.ctx, method, path, bytes.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// The status of one delivery posted alone to engine: the request's own when it is refused whole, else the item's.
func (self *gkmGroupWorld) postWrapOn(engine *GkmEngine, token string, generation uint64, c8 string, delivery []byte) int {
	self.t.Helper()
	path := "/gkm/groups/" + sidecar.EvsKeyId(self.groupId) + "/wraps/" + strconv.FormatUint(generation, 10) + "/" + c8
	recorder := self.fixture.serveOn(engine, http.MethodPost, path, token, self.fixture.marshal(&protocol.GkmWrapBatch{Deliveries: [][]byte{delivery}}))
	if recorder.Code != http.StatusOK {
		return recorder.Code
	}
	reply := &protocol.GkmWrapBatchReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil || len(reply.GetResults()) != 1 {
		self.t.Fatalf("a batch of one answered %v", err)
	}
	return int(reply.GetResults()[0].GetStatus())
}

// Readers sync the new repo as its RepoCreate lands, the creator's own device among them, on this process and on
// another, before evs places it: each meets the 404, which a read within its 5 s still meets. Then the creator's KF1,
// sent right after the placement, takes its group on this process, its first delivery lands on the other, which had
// cached the 404 and seen none of the creation, and every read after the creation finds the group, the clock unmoved.
func TestGkmCreationIsNotRefusedByThePlaceNotFoundItsReadersCached(t *testing.T) {
	world := newGkmUnplacedGroupWorld(t)
	fixture := world.fixture
	other := fixture.otherEngine()
	reader := world.newReader("sc-reader")
	readerToken := fixture.token(reader.sidecarId, repoScope(world.repoId, "r"))
	formsPath := "/gkm/repos/" + sidecar.EvsKeyId(world.repoId) + "/forms"
	start := fixture.clock.Now()
	for _, c := range []struct {
		name   string
		engine *GkmEngine
		token  string
	}{
		{name: "the reader's sync", engine: fixture.engine, token: readerToken},
		{name: "the creator's own sync", engine: fixture.engine, token: world.adminToken},
		{name: "the reader's sync on another process", engine: other, token: readerToken},
	} {
		if recorder := fixture.serveOn(c.engine, http.MethodGet, formsPath, c.token, nil); recorder.Code != http.StatusNotFound {
			t.Fatalf("%s before the placement: %d", c.name, recorder.Code)
		}
	}
	fixture.placeRepo(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_KEYING)
	if recorder := fixture.serve(http.MethodGet, formsPath, readerToken, nil); recorder.Code != http.StatusNotFound {
		t.Errorf("a read within the 404's 5 s: %d", recorder.Code)
	}
	if recorder := world.postCreate(world.createRequest(world.groupId)); recorder.Code != http.StatusOK {
		t.Fatalf("KF1's POST /gkm/groups right after the placement: %d", recorder.Code)
	}
	staged := world.readerWrap(world.admin, world.key1, reader.sidecarId, reader.xwingPublicKey, sidecar.GkmDeliveryStaged, nil, fixture.clock.Now())
	if status := world.postWrapOn(other, world.adminToken, 1, gkmTestC8(world.key1), staged); status != http.StatusCreated {
		t.Fatalf("the creation's first delivery on the process that cached the 404: %d", status)
	}
	if recorder := fixture.serve(http.MethodGet, formsPath, readerToken, nil); recorder.Code != http.StatusOK {
		t.Errorf("the reader's sync after the creation: %d", recorder.Code)
	}
	if !fixture.clock.Now().Equal(start) {
		t.Error("the clock moved")
	}
}

// A write to a repo place/ does not name is refused 404 as before, read each time; a read keeps its 404.
func TestGkmWriteToAnUnplacedRepoStillAnswersNotFound(t *testing.T) {
	world := newGkmUnplacedGroupWorld(t)
	fixture := world.fixture
	for i := range 2 {
		if recorder := world.postCreate(world.createRequest(world.groupId)); recorder.Code != http.StatusNotFound {
			t.Fatalf("KF1's POST %d before any placement: %d", i, recorder.Code)
		}
	}
	if fixture.object("meta-1", GkmFormKey(world.repoId, 1)) != nil || fixture.object("meta-2", GkmFormKey(world.repoId, 1)) != nil {
		t.Error("a refused creation filed a form")
	}
}
