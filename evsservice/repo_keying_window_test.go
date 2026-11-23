package evsservice

// A push right after a repo/ transition that ran on another evs process (§11.8's step 4 and refuse rows, §11.12's
// activate and restore rows). Each process keeps repo/ in its own cache, and the creator's activation, or a restore,
// runs on one of them, whose own entry it drops: another process that read repo/ keying, or deleted, moments before
// answered a push from that read, 409 REPO_KEYING or REPO_DELETED, recorded, so the push id stood refused for its
// life, and answered the activation itself 404 after a reader's read between place/ and repo/. A single process never
// met it, its own transition clearing its cache. Now a keying repo/, or a 404, is cached only RepoKeyingCacheTtl, 0 by
// default, and a push refuses on a keying or deleted state only from a repo/ read from the cluster, whatever that
// setting is. The push and activation cases run two engines on one store, the clock unmoved; the cache's own cases
// read one RepoCache against the store.

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A second engine over the fixture's host, as otherEngine is (read_staged_test.go), its settings a copy of the
// fixture's as adjust leaves them.
func (self *pushFixture) otherEngineWith(adjust func(settings *EvsSettings)) *EvsEngine {
	self.t.Helper()
	settings := *self.settings
	adjust(&settings)
	engine, err := NewEvsEngine(self.ctx, self.host.ServiceHost(), &settings, &EvsEngineDeps{
		AuthState: self.auth,
		Uploads:   self.engine.deps.Uploads,
		GateViews: &pushTestGateViews{check: self.check},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(engine.Close)
	return engine
}

// One request on /evs/v1/repos/<the fixture's repo> plus suffix through engine's handler.
func (self *pushFixture) requestOn(engine *EvsEngine, method string, suffix string, token string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequestWithContext(self.ctx, method, "/evs/v1/repos/"+sidecar.EvsKeyId(self.check.repoId)+suffix, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// One POST .../push of body under token through engine's handler.
func (self *pushFixture) postOn(engine *EvsEngine, token string, body *protocol.EvsPushRequest) *httptest.ResponseRecorder {
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.requestOn(engine, http.MethodPost, "/push", token, bodyBytes)
}

// repo/'s state as GET /evs/v1/repos/<id> on engine answers it: keying or active, or the refusal's code.
func (self *pushFixture) repoStateOn(engine *EvsEngine) (protocol.EvsRepoState, protocol.EvsRefusalCode) {
	self.t.Helper()
	recorder := self.requestOn(engine, http.MethodGet, "", self.token(self.check.signerId, "r"), nil)
	if recorder.Code != http.StatusOK {
		return protocol.EvsRepoState_EVS_REPO_STATE_UNSPECIFIED, refusalOf(self.t, recorder).GetCode()
	}
	object := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), object); err != nil {
		self.t.Fatal(err)
	}
	return object.GetState(), protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED
}

// The creator's activation through engine: gkm's GroupForm naming the fixture's group, whose gen/1 the fixture
// stored, as KF1 leaves it, then POST .../activate under an admin token.
func (self *pushFixture) activateOn(engine *EvsEngine) {
	self.t.Helper()
	body, err := proto.Marshal(&protocol.GroupForm{RepoId: self.check.repoId.Bytes(), GroupId: self.check.groupId.Bytes(), Generation: 1})
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := proto.Marshal(&bridge.Signed{Type: uint32(bridge.SignedType_SIGNED_GROUP_FORM), Body: body, SignerId: self.check.signerId.Bytes()})
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, gkmservice.GkmFormKey(self.check.repoId, 1), signed, nil); err != nil {
		self.t.Fatal(err)
	}
	self.auth.grant(self.check.signerId, self.check.repoId, sidecar.AclEvsAdmin)
	if recorder := self.requestOn(engine, http.MethodPost, "/activate", self.token(self.check.signerId, "admin"), nil); recorder.Code != http.StatusOK {
		self.t.Fatalf("the activation: %d", recorder.Code)
	}
}

// At the defaults: a reader's read of the keying repo on the other process, and a push there to another ref while it
// is keying, refused and recorded; the creator's activation runs on the fixture's process; a push right after it on
// the other process lands, and the early push's refusal stands recorded. Before the fix the other process judged that
// push against the keying repo/ it had read, 409 REPO_KEYING, recorded.
func TestPushRightAfterActivationOnAnotherProcessLands(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_KEYING)
	other := fixture.otherEngine()
	start := fixture.clock.Now()
	token := fixture.token(fixture.check.signerId)
	if state, code := fixture.repoStateOn(other); state != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("a reader's read while keying: %s %s", state, code)
	}

	// on a ref of its own, so its refusal fence holds back no recording on the fixture's ref
	early := fixture.plan()
	early.RefId = testId("early ref")
	early.BaseChain = sidecar.EvsChainStart(fixture.check.repoId, early.RefId)
	fixture.create(early, "early")
	earlyBody := fixture.body(early)
	requireRefusal(t, fixture.postOn(other, token, earlyBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_KEYING)

	fixture.activateOn(fixture.engine)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.postOn(other, token, fixture.body(plan)), 1)

	again := fixture.postOn(other, token, earlyBody)
	requireRefusal(t, again, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_KEYING)
	if !refusalOf(t, again).GetRecorded() {
		t.Error("the keying push's retry answered without recorded: true")
	}
	if !fixture.clock.Now().Equal(start) {
		t.Error("the clock moved")
	}
}

// With RepoKeyingCacheTtl at its most, RepoCacheTtl, the other process holds the keying repo/ it read past the
// activation, and its reads still answer keying from it; a push there right after the activation lands all the same,
// its refusal on the cached state sending step 4 to the cluster, whose repo/ then replaces the entry.
func TestPushRightAfterActivationOnAProcessHoldingAKeyingEntryLands(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_KEYING)
	other := fixture.otherEngineWith(func(settings *EvsSettings) {
		settings.RepoKeyingCacheTtl = settings.RepoCacheTtl
	})
	start := fixture.clock.Now()
	if state, code := fixture.repoStateOn(other); state != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("the other process's read while keying: %s %s", state, code)
	}

	fixture.activateOn(fixture.engine)
	if state, code := fixture.repoStateOn(other); state != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("the other process's read within its keying ttl: %s %s", state, code)
	}
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.postOn(other, fixture.token(fixture.check.signerId), fixture.body(plan)), 1)
	if state, code := fixture.repoStateOn(other); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("the other process's read after the push's: %s %s", state, code)
	}
	if !fixture.clock.Now().Equal(start) {
		t.Error("the clock moved")
	}
}

// A repo that really is keying is still refused, 409 REPO_KEYING, recorded, and only on a repo/ read from the
// cluster: on a process holding the keying repo/ in its cache, a push whose cluster read of repo/ fails answers 503
// and records nothing; once repo/ reads, the push is refused and recorded, and its retry answers recorded: true.
func TestPushToAKeyingRepoIsRefusedOnlyOnAClusterRead(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_KEYING)
	other := fixture.otherEngineWith(func(settings *EvsSettings) {
		settings.RepoKeyingCacheTtl = settings.RepoCacheTtl
	})
	token := fixture.token(fixture.check.signerId)
	if state, code := fixture.repoStateOn(other); state != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("the other process's read while keying: %s %s", state, code)
	}
	fired, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpGet, KeyPrefix: RepoKey(fixture.check.repoId), Result: sidecartest.FailBeforeApply,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	recorder := fixture.postOn(other, token, body)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	select {
	case <-fired:
	default:
		t.Fatal("the push read no repo/ from the cluster")
	}
	if head := fixture.head(); !head.Absent() {
		t.Fatalf("a push refused nothing and wrote the head: %v", head.Head)
	}

	requireRefusal(t, fixture.postOn(other, token, body), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_KEYING)
	again := fixture.postOn(other, token, body)
	requireRefusal(t, again, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_KEYING)
	if !refusalOf(t, again).GetRecorded() {
		t.Error("the keying push's retry answered without recorded: true")
	}
}

// A push in parts right after the activation, on the process holding the keying repo/ it read: each part, judged by
// steps 4 and 5 there, is taken, and the seal commits. Before the fix each part was refused 409 REPO_KEYING from the
// cached repo/, and a seal, whose step 4 read repo/ from the cache too, refused and recorded.
func TestPartsAndSealRightAfterActivationOnAProcessHoldingAKeyingEntryLand(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_KEYING)
	other := fixture.otherEngineWith(func(settings *EvsSettings) {
		settings.RepoKeyingCacheTtl = settings.RepoCacheTtl
	})
	if state, code := fixture.repoStateOn(other); state != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("the other process's read while keying: %s %s", state, code)
	}
	fixture.activateOn(fixture.engine)

	token := fixture.token(fixture.check.signerId)
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	if len(built.Parts) < 2 {
		t.Fatalf("%d parts, want at least 2", len(built.Parts))
	}
	first := fixture.engine
	fixture.engine = other
	defer func() { fixture.engine = first }()
	places := fixture.postParts(token, built)
	fixture.requireCommitted(fixture.seal(token, built, places), 1)
}

// The same window at a restore: the other process reads repo/ deleted, which it keeps RepoCacheTtl, and answers its
// reads REPO_DELETED from it past the restore on the fixture's process; a push there right after the restore lands.
// Before the fix the push was refused from the cached deleted repo/, 409 REPO_DELETED, recorded.
func TestPushRightAfterARestoreOnAnotherProcessLands(t *testing.T) {
	fixture := newPushFixture(t, nil)
	other := fixture.otherEngine()
	start := fixture.clock.Now()
	admin := fixture.token(fixture.check.signerId, "admin")
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: start, SignerSidecarId: fixture.check.signerId}
	facts := &EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_GENERAL, NetworkId: fixture.check.networkId, Deletion: deletion}
	fixture.auth.setRepo(fixture.check.repoId, facts)
	if recorder := fixture.requestOn(fixture.engine, http.MethodDelete, "", admin, nil); recorder.Code != http.StatusOK {
		t.Fatalf("the deletion: %d", recorder.Code)
	}
	if _, code := fixture.repoStateOn(other); code != protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED {
		t.Fatalf("the other process's read while deleted: %s", code)
	}

	restored := *deletion
	restored.Restored = true
	fixture.auth.setRepo(fixture.check.repoId, &EvsRepoFacts{Kind: facts.Kind, NetworkId: facts.NetworkId, Deletion: &restored})
	if recorder := fixture.requestOn(fixture.engine, http.MethodPost, "/restore", admin, nil); recorder.Code != http.StatusOK {
		t.Fatalf("the restore: %d", recorder.Code)
	}
	if _, code := fixture.repoStateOn(other); code != protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED {
		t.Fatalf("the other process's read within its ttl: %s", code)
	}
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.postOn(other, fixture.token(fixture.check.signerId), fixture.body(plan)), 1)
	if !fixture.clock.Now().Equal(start) {
		t.Error("the clock moved")
	}
}

// The repo/ 404 of a creation, as place_race_test.go has the place/ one: a reader's read on another process between
// the creator's place/ and repo/ writes finds the repo placed and its repo/ absent, 404; the creator's activation
// landing there right after its PUT and KF1 is taken. Before the fix that process kept the 404 RepoCacheTtl and
// answered the activation 404 NOT_FOUND.
func TestActivationOnAProcessThatReadARepoNotFoundIsTaken(t *testing.T) {
	fixture := newEvsFixture(t)
	repoId, admin, reader := testId("repo"), testId("sidecar-a"), testId("sidecar-r")
	fixture.projectRepo(repoId, admin)
	fixture.auth.grant(reader, repoId, sidecar.AclEvsRead)
	other := fixture.otherEngine()
	readerToken := fixture.token(reader, repoScope(repoId, "r"))
	path := "/evs/v1/repos/" + sidecar.EvsKeyId(repoId)
	start := fixture.clock.Now()
	fixture.standPlacement(repoId, "meta-1", admin)
	requireRefusal(t, fixture.serveOn(other, http.MethodGet, path, readerToken, nil), http.StatusNotFound, protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
	if status := fixture.putRepo(repoId, admin); status != http.StatusOK {
		t.Fatalf("the creator's PUT: %d", status)
	}
	fixture.formGroup(repoId, testId("group"), true)
	if recorder := fixture.serveOn(other, http.MethodPost, path+"/activate", fixture.token(admin, repoScope(repoId, "admin")), nil); recorder.Code != http.StatusOK {
		t.Fatalf("the activation on the process that read the 404: %d", recorder.Code)
	}
	if object := fixture.repoObject(repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("repo/ %v", object.GetState())
	}
	if !fixture.clock.Now().Equal(start) {
		t.Error("the clock moved")
	}
}

// repo/'s cache at the defaults keeps neither a 404 nor a keying repo/: a placed repo with no repo/, then keying, then
// active, each seen by the next read with the clock unmoved, each read a GET whose answer is not marked cached; an
// active repo/ is kept RepoCacheTtl, its answers marked cached, through a deletion it has not seen.
func TestRepoCacheKeepsNoKeyingRepoOrNotFoundByDefault(t *testing.T) {
	fixture := newPushFixture(t, nil)
	repoId := testId("repo-k")
	repos := NewRepoCache(fixture.clock, DefaultEvsSettings())
	world := newRepoCacheWorld(t, fixture, repos, repoId)

	world.requireNotFound("placed, repo/ unwritten", 1)
	world.requireNotFound("again", 1)
	world.put(protocol.EvsRepoState_EVS_REPO_KEYING)
	world.requireState("written keying", protocol.EvsRepoState_EVS_REPO_KEYING, false, 1)
	world.requireState("keying again", protocol.EvsRepoState_EVS_REPO_KEYING, false, 1)
	world.put(protocol.EvsRepoState_EVS_REPO_ACTIVE)
	world.requireState("activated", protocol.EvsRepoState_EVS_REPO_ACTIVE, false, 1)
	world.requireState("active again", protocol.EvsRepoState_EVS_REPO_ACTIVE, true, 0)
	world.put(protocol.EvsRepoState_EVS_REPO_DELETED)
	world.requireState("deleted, within RepoCacheTtl", protocol.EvsRepoState_EVS_REPO_ACTIVE, true, 0)
	fixture.clock.Advance(DefaultEvsSettings().RepoCacheTtl)
	world.requireState("deleted, past RepoCacheTtl", protocol.EvsRepoState_EVS_REPO_DELETED, false, 1)
}

// With RepoKeyingCacheTtl set, a 404 and a keying repo/ are each kept that long and no longer, and ReadFresh replaces
// a kept answer at once.
func TestRepoCacheKeepsAKeyingRepoOrNotFoundOnlyItsKeyingTtl(t *testing.T) {
	fixture := newPushFixture(t, nil)
	repoId := testId("repo-t")
	settings := DefaultEvsSettings()
	settings.RepoKeyingCacheTtl = 2 * time.Second
	repos := NewRepoCache(fixture.clock, settings)
	world := newRepoCacheWorld(t, fixture, repos, repoId)

	world.requireNotFound("placed, repo/ unwritten", 1)
	world.put(protocol.EvsRepoState_EVS_REPO_KEYING)
	world.requireNotFound("written keying, within the keying ttl", 0)
	fixture.clock.Advance(settings.RepoKeyingCacheTtl)
	world.requireState("written keying, past the keying ttl", protocol.EvsRepoState_EVS_REPO_KEYING, false, 1)
	world.put(protocol.EvsRepoState_EVS_REPO_ACTIVE)
	world.requireState("activated, within the keying ttl", protocol.EvsRepoState_EVS_REPO_KEYING, true, 0)
	fresh, err := repos.ReadFresh(fixture.ctx, fixture.cluster, repoId)
	if err != nil || fresh.Object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE || fresh.Cached {
		t.Fatalf("a fresh read: %v %v", fresh, err)
	}
	world.requireState("after a fresh read", protocol.EvsRepoState_EVS_REPO_ACTIVE, true, 0)
}

// The setting's default and bound: 0, and at most RepoCacheTtl.
func TestEvsSettingsHoldTheKeyingTtlUnderRepoCacheTtl(t *testing.T) {
	settings := DefaultEvsSettings()
	if settings.RepoKeyingCacheTtl != 0 {
		t.Fatalf("RepoKeyingCacheTtl %s by default", settings.RepoKeyingCacheTtl)
	}
	settings.RepoKeyingCacheTtl = settings.RepoCacheTtl
	if err := settings.Validate(); err != nil {
		t.Errorf("a keying ttl of RepoCacheTtl: %v", err)
	}
	settings.RepoKeyingCacheTtl = settings.RepoCacheTtl + time.Millisecond
	if err := settings.Validate(); !errors.Is(err, ErrEvsSettings) {
		t.Errorf("a keying ttl past RepoCacheTtl: %v", err)
	}
	settings = DefaultEvsSettings()
	settings.RepoCacheTtl = 0
	if err := settings.Validate(); err != nil {
		t.Errorf("no repo/ cache: %v", err)
	}
}

// One repo's repo/ written by hand on the push fixture's cluster and read through repos, counting the GETs.
type repoCacheWorld struct {
	t       *testing.T
	fixture *pushFixture
	repos   *RepoCache
	repoId  sidecar.Id
}

func newRepoCacheWorld(t *testing.T, fixture *pushFixture, repos *RepoCache, repoId sidecar.Id) *repoCacheWorld {
	return &repoCacheWorld{t: t, fixture: fixture, repos: repos, repoId: repoId}
}

// repo/ in state, written over by If-Match, as evs's transitions write it.
func (self *repoCacheWorld) put(state protocol.EvsRepoState) {
	self.t.Helper()
	object := &protocol.EvsRepoObject{RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: state, Format: 1}
	if state == protocol.EvsRepoState_EVS_REPO_DELETED {
		object.DeletionId = testId("deletion").Bytes()
		object.StateMs = self.fixture.clock.Now().UnixMilli()
		object.StateSigner = self.fixture.check.signerId.Bytes()
	}
	objectBytes, err := sidecar.MarshalEvsRepoObject(object)
	if err != nil {
		self.t.Fatal(err)
	}
	cluster := self.fixture.cluster
	info, err := cluster.Head(self.fixture.ctx, RepoKey(self.repoId))
	if err == nil {
		_, err = cluster.PutIfMatch(self.fixture.ctx, RepoKey(self.repoId), info.Etag, objectBytes, nil)
	} else {
		_, err = cluster.PutIfNoneMatch(self.fixture.ctx, RepoKey(self.repoId), objectBytes, nil)
	}
	if err != nil {
		self.t.Fatal(err)
	}
}

// One read, with the GETs it issued.
func (self *repoCacheWorld) read() (*EvsRepoRead, int, error) {
	before := self.fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	read, err := self.repos.Read(self.fixture.ctx, self.fixture.cluster, self.repoId)
	return read, self.fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - before, err
}

// A read answers 404 with getCount GETs.
func (self *repoCacheWorld) requireNotFound(what string, getCount int) {
	self.t.Helper()
	read, gets, err := self.read()
	if !errors.Is(err, sidecar.ErrEvsRepoNotFound) || gets != getCount {
		self.t.Fatalf("%s: %v %v, %d GETs", what, read, err, gets)
	}
}

// A read answers state, marked cached or not, with getCount GETs.
func (self *repoCacheWorld) requireState(what string, state protocol.EvsRepoState, cached bool, getCount int) {
	self.t.Helper()
	read, gets, err := self.read()
	if err != nil || read.Object.GetState() != state || read.Cached != cached || gets != getCount {
		self.t.Fatalf("%s: %v %v, %d GETs", what, read, err, gets)
	}
}
