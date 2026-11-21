package evsservice

// A creation's readers race it on evs as on gkm (§11.8's place and resolve rows): a reader's request for the new repo
// ahead of the creator's PUT caches place/'s 404 on the process that serves it, and the creation's next write landing
// there, its activation, must not be refused by it. Before the fix the activation answered 404 NOT_FOUND for the rest
// of the 404's 5 s.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Another evs process over the fixture's stores and state, sharing none of the fixture engine's caches: an lb host
// beside it.
func (self *evsFixture) otherEngine() *EvsEngine {
	self.t.Helper()
	engine, err := NewEvsEngine(self.ctx, self.host.ServiceHost(), DefaultEvsSettings(), &EvsEngineDeps{
		AuthState:  self.auth,
		ServiceLog: self.serviceLog,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(engine.Close)
	return engine
}

// One request through engine's handler, as serve sends one through the fixture engine's.
func (self *evsFixture) serveOn(engine *EvsEngine, method string, path string, token string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(self.ctx, method, path, bytes.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// A reader's GET of the new repo on another process, before the creator's PUT on the fixture's, caches the 404 there;
// a read there within its 5 s still meets it, the creator's activation there right after the PUT and KF1 is taken,
// and a read after it finds the repo, the clock unmoved.
func TestPlaceActivationOnAProcessThatCachedAReadersNotFoundIsTaken(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId, admin, reader := testId("repo"), testId("sidecar-a"), testId("sidecar-r")
	fixture.projectRepo(repoId, admin)
	fixture.auth.grant(reader, repoId, sidecar.AclEvsRead)
	other := fixture.otherEngine()
	readerToken := fixture.token(reader, repoScope(repoId, "r"))
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId)
	start := fixture.clock.Now()
	requireRefusal(t, fixture.serveOn(other, http.MethodGet, path, readerToken, nil), http.StatusNotFound, protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
	if status := fixture.putRepo(repoId, admin); status != http.StatusOK {
		t.Fatalf("the creator's PUT: %d", status)
	}
	fixture.formGroup(repoId, testId("group"), true)
	requireRefusal(t, fixture.serveOn(other, http.MethodGet, path, readerToken, nil), http.StatusNotFound, protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
	if recorder := fixture.serveOn(other, http.MethodPost, path+"/activate", fixture.token(admin, repoScope(repoId, "admin")), nil); recorder.Code != http.StatusOK {
		t.Fatalf("the activation on the process that cached the 404: %d", recorder.Code)
	}
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("repo/ %v", object.GetState())
	}
	if recorder := fixture.serveOn(other, http.MethodGet, path, readerToken, nil); recorder.Code != http.StatusOK {
		t.Errorf("a read after the activation: %d", recorder.Code)
	}
	if !fixture.clock.Now().Equal(start) {
		t.Error("the clock moved")
	}
}
