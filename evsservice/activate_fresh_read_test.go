package evsservice

// §11.12's activate row reads repo/ from the cluster. Each evs process keeps repo/ in its own cache, an active or later
// state RepoCacheTtl and, with RepoKeyingCacheTtl set, a keying one or a 404 that long, and a transition drops only
// its own process's entry. An activation landing on another process that had read repo/ moments before answered that
// read: 200 for a repo the cluster shows deleted, REPO_DELETED for one restored or gone on to shredding, 404 for one
// created since, and, from a keying entry, paid P1, or was refused it, for a CAS the cluster's active repo/ never
// issues. Each case runs two engines on one store, the clock unmoved: the transitions on the fixture's process, the
// read and the activation on the other.

import (
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Another evs process over the fixture's stores and state, as otherEngine is, on the default settings as adjust
// leaves them.
func (self *evsFixture) otherEngineWith(adjust func(settings *EvsSettings)) *EvsEngine {
	self.t.Helper()
	settings := DefaultEvsSettings()
	adjust(settings)
	engine, err := NewEvsEngine(self.ctx, self.host.ServiceHost(), settings, &EvsEngineDeps{
		AuthState:  self.auth,
		ServiceLog: self.serviceLog,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(engine.Close)
	return engine
}

// One projected repo, its creator holding admin and a reader r, served by the fixture's process and another.
type activateFreshWorld struct {
	t       *testing.T
	fixture *evsFixture
	other   *EvsEngine
	repoId  sidecar.Id
	admin   sidecar.Id
	reader  sidecar.Id
}

// The world on a new fixture, the other process's settings the defaults as adjust leaves them, or the defaults for
// nil.
func newActivateFreshWorld(t *testing.T, adjust func(settings *EvsSettings)) *activateFreshWorld {
	fixture := newEvsFixture(t)
	world := &activateFreshWorld{t: t, fixture: fixture, repoId: testId("repo"), admin: testId("sidecar-a"), reader: testId("sidecar-r")}
	fixture.projectRepo(world.repoId, world.admin)
	fixture.auth.grant(world.reader, world.repoId, sidecar.AclEvsRead)
	if adjust == nil {
		world.other = fixture.otherEngine()
	} else {
		world.other = fixture.otherEngineWith(adjust)
	}
	return world
}

// /evs/v1/repos/<the repo>.
func (self *activateFreshWorld) path() string {
	return "/evs/v1/repos/" + sidecar.EvsKeyId(self.repoId)
}

// repo/'s state as the reader's GET on engine answers it: keying or active, or the refusal's code.
func (self *activateFreshWorld) readOn(engine *EvsEngine) (protocol.EvsRepoState, protocol.EvsRefusalCode) {
	self.t.Helper()
	recorder := self.fixture.serveOn(engine, http.MethodGet, self.path(), self.fixture.token(self.reader, repoScope(self.repoId, "r")), nil)
	if recorder.Code != http.StatusOK {
		return protocol.EvsRepoState_EVS_REPO_STATE_UNSPECIFIED, refusalOf(self.t, recorder).GetCode()
	}
	object := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), object); err != nil {
		self.t.Fatal(err)
	}
	return object.GetState(), protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED
}

// The creator's POST .../activate on engine: its status, and its refusal's code for any answer but a 200.
func (self *activateFreshWorld) activateOn(engine *EvsEngine) (int, protocol.EvsRefusalCode) {
	self.t.Helper()
	recorder := self.fixture.serveOn(engine, http.MethodPost, self.path()+"/activate", self.fixture.token(self.admin, repoScope(self.repoId, "admin")), nil)
	if recorder.Code == http.StatusOK {
		return recorder.Code, protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED
	}
	return recorder.Code, refusalOf(self.t, recorder).GetCode()
}

// The cluster the repo is placed on.
func (self *activateFreshWorld) clusterId() string {
	self.t.Helper()
	place := self.fixture.placement(self.repoId)
	if place == nil {
		self.t.Fatal("the repo is not placed")
	}
	return place.ClusterId
}

// repo/'s ETag on its cluster, which only a write changes.
func (self *activateFreshWorld) repoEtag() string {
	self.t.Helper()
	info, err := self.fixture.rawCluster(self.clusterId()).Head(self.fixture.ctx, RepoKey(self.repoId))
	if err != nil {
		self.t.Fatal(err)
	}
	return info.Etag
}

// A DELETE on the fixture's process under deletion, made the projection's newest RepoDelete first: with ?now=1 for a
// RepoDelete{now}.
func (self *activateFreshWorld) deleteOnFixture(deletion *EvsRepoDeletionFacts) {
	self.t.Helper()
	self.fixture.projectDeletion(self.repoId, deletion)
	suffix := ""
	if deletion.Now {
		suffix = "?now=1"
	}
	if status := self.fixture.lifecycle(http.MethodDelete, self.repoId, suffix, self.admin); status != http.StatusOK {
		self.t.Fatalf("the delete: %d", status)
	}
}

// A restore of deletion on the fixture's process, a RepoRestore of it projected first.
func (self *activateFreshWorld) restoreOnFixture(deletion *EvsRepoDeletionFacts) {
	self.t.Helper()
	restored := *deletion
	restored.Restored = true
	self.fixture.projectDeletion(self.repoId, &restored)
	if status := self.fixture.lifecycle(http.MethodPost, self.repoId, "/restore", self.admin); status != http.StatusOK {
		self.t.Fatalf("the restore: %d", status)
	}
}

// A transition on the fixture's process after the other process read repo/, which it keeps RepoCacheTtl, its reads
// answering from that read past the transition: an activation there answers the cluster's state, writing nothing, and
// leaves that state in its cache, where the reader's next read finds it. Before the fix the activation answered the
// cached state: 200 for the repo deleted, and REPO_DELETED for the repo restored or gone on to shredding.
func TestActivationAnswersTheClustersStatePastAnotherProcesssTransition(t *testing.T) {
	type activateFreshCase struct {
		name string
		// run on the fixture's process before the other process reads repo/, and after it
		before     func(world *activateFreshWorld, first *EvsRepoDeletionFacts)
		transition func(world *activateFreshWorld, first *EvsRepoDeletionFacts)
		// what the other process's reads answer from its cache, before the transition and after it
		cachedState protocol.EvsRepoState
		cachedCode  protocol.EvsRefusalCode
		// the activation's answer there: a 200, or a 409 with code
		status int
		code   protocol.EvsRefusalCode
	}
	cases := []*activateFreshCase{
		{
			name:   "deleted while the other process holds it active",
			before: func(world *activateFreshWorld, first *EvsRepoDeletionFacts) {},
			transition: func(world *activateFreshWorld, first *EvsRepoDeletionFacts) {
				world.deleteOnFixture(first)
			},
			cachedState: protocol.EvsRepoState_EVS_REPO_ACTIVE,
			status:      http.StatusConflict,
			code:        protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED,
		},
		{
			name: "restored while the other process holds it deleted",
			before: func(world *activateFreshWorld, first *EvsRepoDeletionFacts) {
				world.deleteOnFixture(first)
			},
			transition: func(world *activateFreshWorld, first *EvsRepoDeletionFacts) {
				world.restoreOnFixture(first)
			},
			cachedCode: protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED,
			status:     http.StatusOK,
		},
		{
			name: "shredding while the other process holds it deleted",
			before: func(world *activateFreshWorld, first *EvsRepoDeletionFacts) {
				world.deleteOnFixture(first)
			},
			transition: func(world *activateFreshWorld, first *EvsRepoDeletionFacts) {
				world.deleteOnFixture(&EvsRepoDeletionFacts{
					DeletionId: testId("deletion 2"), Now: true, Time: world.fixture.clock.Now(), SignerSidecarId: world.admin,
				})
			},
			cachedCode: protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED,
			status:     http.StatusConflict,
			code:       protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING,
		},
	}
	for _, c := range cases {
		world := newActivateFreshWorld(t, nil)
		fixture := world.fixture
		fixture.activeRepo(world.repoId, world.admin)
		start := fixture.clock.Now()
		first := &EvsRepoDeletionFacts{DeletionId: testId("deletion 1"), Time: start, SignerSidecarId: world.admin}
		c.before(world, first)
		if state, code := world.readOn(world.other); state != c.cachedState || code != c.cachedCode {
			t.Fatalf("%s: the other process's read: %s %s", c.name, state, code)
		}
		c.transition(world, first)
		if state, code := world.readOn(world.other); state != c.cachedState || code != c.cachedCode {
			t.Fatalf("%s: the other process's read within RepoCacheTtl: %s %s", c.name, state, code)
		}

		etag := world.repoEtag()
		status, code := world.activateOn(world.other)
		if status != c.status || code != c.code {
			t.Errorf("%s: the activation on the other process: %d %s, want %d %s", c.name, status, code, c.status, c.code)
		}
		if world.repoEtag() != etag {
			t.Errorf("%s: the activation wrote repo/", c.name)
		}
		wantState := protocol.EvsRepoState_EVS_REPO_STATE_UNSPECIFIED
		if c.status == http.StatusOK {
			wantState = protocol.EvsRepoState_EVS_REPO_ACTIVE
		}
		if state, code := world.readOn(world.other); state != wantState || code != c.code {
			t.Errorf("%s: the other process's read after the activation: %s %s", c.name, state, code)
		}
		if !fixture.clock.Now().Equal(start) {
			t.Errorf("%s: the clock moved", c.name)
		}
	}
}

// With RepoKeyingCacheTtl at its most, RepoCacheTtl, the other process keeps the 404 a reader's read found between the
// creator's place/ and repo/ writes, and its reads answer 404 from it past the creator's PUT; the creator's activation
// there right after the PUT and KF1 is taken all the same. Before the fix it answered 404 NOT_FOUND from that read.
func TestActivationOnAProcessHoldingANotFoundForItsKeyingTtlIsTaken(t *testing.T) {
	world := newActivateFreshWorld(t, func(settings *EvsSettings) {
		settings.RepoKeyingCacheTtl = settings.RepoCacheTtl
	})
	fixture := world.fixture
	start := fixture.clock.Now()
	fixture.standPlacement(world.repoId, "meta-1", world.admin)
	if _, code := world.readOn(world.other); code != protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND {
		t.Fatalf("the reader's read between place/ and repo/: %s", code)
	}
	if status := fixture.putRepo(world.repoId, world.admin); status != http.StatusOK {
		t.Fatalf("the creator's PUT: %d", status)
	}
	fixture.formGroup(world.repoId, testId("group"), true)
	if _, code := world.readOn(world.other); code != protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND {
		t.Fatalf("the reader's read within the keying ttl: %s", code)
	}

	if status, code := world.activateOn(world.other); status != http.StatusOK {
		t.Fatalf("the activation on the process holding the 404: %d %s", status, code)
	}
	if object := fixture.repoObject(world.repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("repo/ %v", object.GetState())
	}
	if state, code := world.readOn(world.other); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("the reader's read after the activation: %s %s", state, code)
	}
	if !fixture.clock.Now().Equal(start) {
		t.Error("the clock moved")
	}
}

// With RepoKeyingCacheTtl at RepoCacheTtl, the other process keeps the keying repo/ the reader's read found, past the
// creator's activation on the fixture's process; the creator's retry of the activation there, its first answer lost,
// answers 200, pays no P1 and writes nothing, with the network's P1 on the repo's cluster open and with it refused.
// Before the fix the retry was admitted on the cached keying state: with P1 open it paid P1 for a CAS it never issued,
// and with P1 refused it answered 429 RESOURCE_EXHAUSTED for a repo the cluster shows active, which the row answers
// 200.
func TestActivationRetryOnAProcessHoldingAKeyingEntryPaysNothing(t *testing.T) {
	for _, refused := range []bool{false, true} {
		world := newActivateFreshWorld(t, func(settings *EvsSettings) {
			settings.RepoKeyingCacheTtl = settings.RepoCacheTtl
		})
		fixture := world.fixture
		start := fixture.clock.Now()
		if status := fixture.putRepo(world.repoId, world.admin); status != http.StatusOK {
			t.Fatalf("P1 refused %t: the creator's PUT: %d", refused, status)
		}
		if state, code := world.readOn(world.other); state != protocol.EvsRepoState_EVS_REPO_KEYING {
			t.Fatalf("P1 refused %t: the reader's read while keying: %s %s", refused, state, code)
		}
		fixture.formGroup(world.repoId, testId("group"), true)
		if status, code := world.activateOn(fixture.engine); status != http.StatusOK {
			t.Fatalf("P1 refused %t: the activation on the fixture's process: %d %s", refused, status, code)
		}
		if state, code := world.readOn(world.other); state != protocol.EvsRepoState_EVS_REPO_KEYING {
			t.Fatalf("P1 refused %t: the reader's read within the keying ttl: %s %s", refused, state, code)
		}

		clusterId := world.clusterId()
		fixture.host.Budget.RefuseP1(clusterId, fixture.networkId, refused)
		p1ByteCount, _ := fixture.host.Budget.P1ByteCount(clusterId)
		etag := world.repoEtag()
		if status, code := world.activateOn(world.other); status != http.StatusOK {
			t.Errorf("P1 refused %t: the retry on the process holding the keying entry: %d %s", refused, status, code)
		}
		if paid, _ := fixture.host.Budget.P1ByteCount(clusterId); paid != p1ByteCount {
			t.Errorf("P1 refused %t: the retry paid %d P1 bytes", refused, paid-p1ByteCount)
		}
		if world.repoEtag() != etag {
			t.Errorf("P1 refused %t: the retry wrote repo/", refused)
		}
		if state, code := world.readOn(world.other); state != protocol.EvsRepoState_EVS_REPO_ACTIVE {
			t.Errorf("P1 refused %t: the reader's read after the retry: %s %s", refused, state, code)
		}
		if !fixture.clock.Now().Equal(start) {
			t.Errorf("P1 refused %t: the clock moved", refused)
		}
	}
}
