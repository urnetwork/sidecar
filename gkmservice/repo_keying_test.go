package gkmservice

// repo/ as a creation moves it on (§10.6's checks row): gkm reads it keying at KF1's writes moments before the
// activation, and judged against that read a LATE delivery right after the activation would be refused 409 as keying
// for up to RepoCacheTtl ("a keying repo takes only its creation's deliveries"), which its deliverer drops until the
// next ask, a LateAskInterval later. A keying repo/, or none yet, is cached only RepoKeyingCacheTtl, 0 by default.

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// repo/ written over in state, by If-Match, as evs's activation writes it, the clock unmoved: no cache lapses.
func (self *gkmFixture) moveRepoNow(repoId sidecar.Id, clusterId string, state protocol.EvsRepoState) {
	self.t.Helper()
	cluster := self.cluster(clusterId)
	held, info, err := readGkmObject(self.ctx, cluster, GkmEvsRepoKey(repoId), self.settings.RepoObjectMaxByteCount)
	if err != nil {
		self.t.Fatal(err)
	}
	object := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(held, object); err != nil {
		self.t.Fatal(err)
	}
	object.State = state
	if _, err := cluster.PutIfMatch(self.ctx, GkmEvsRepoKey(repoId), info.Etag, self.marshal(object), nil); err != nil {
		self.t.Fatal(err)
	}
}

// The creation's last write reads repo/ keying just before evs activates the repo; a LATE delivery to a holder the
// creation's STAGED set did not hold, judged right after the activation with no time passing, is taken. Before the fix
// gkm judged it against the keying repo/ it had cached and answered 409.
func TestGkmLateDeliveryRightAfterTheActivationIsTaken(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	if recorder := world.postCreate(world.createRequest(world.groupId)); recorder.Code != http.StatusOK {
		t.Fatalf("a creation: %d", recorder.Code)
	}
	first := world.newReader("sc-first")
	now := fixture.clock.Now()
	staged := world.readerWrap(world.admin, world.key1, first.sidecarId, first.xwingPublicKey, sidecar.GkmDeliveryStaged, nil, now)
	if status := world.postWrap(world.adminToken, 1, gkmTestC8(world.key1), staged); status != http.StatusCreated {
		t.Fatalf("the creation's delivery while keying: %d", status)
	}
	fixture.moveRepoNow(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	joiner := world.newReader("sc-joiner")
	late := world.readerWrap(world.admin, world.key1, joiner.sidecarId, joiner.xwingPublicKey, sidecar.GkmDeliveryLate, fakeGkmPin(10), now)
	if status := world.postWrap(world.adminToken, 1, gkmTestC8(world.key1), late); status != http.StatusCreated {
		t.Fatalf("a LATE delivery right after the activation: %d", status)
	}
	if !fixture.clock.Now().Equal(now) {
		t.Error("the clock moved")
	}
}

// RepoKeyingCacheTtl bounds that window where a deployment sets it: a LATE delivery inside it meets the keying repo/
// gkm cached, 409, and the same delivery once it lapses is taken.
func TestGkmRepoKeyingCacheTtlBoundsTheLateDeliveryWindow(t *testing.T) {
	world := newGkmGroupWorld(t)
	fixture := world.fixture
	fixture.settings.RepoKeyingCacheTtl = 2 * time.Second
	fixture.start()
	if recorder := world.postCreate(world.createRequest(world.groupId)); recorder.Code != http.StatusOK {
		t.Fatalf("a creation: %d", recorder.Code)
	}
	now := fixture.clock.Now()
	fixture.moveRepoNow(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	joiner := world.newReader("sc-joiner")
	late := world.readerWrap(world.admin, world.key1, joiner.sidecarId, joiner.xwingPublicKey, sidecar.GkmDeliveryLate, fakeGkmPin(10), now)
	if status := world.postWrap(world.adminToken, 1, gkmTestC8(world.key1), late); status != http.StatusConflict {
		t.Errorf("a LATE delivery inside the keying ttl: %d", status)
	}
	fixture.clock.Advance(fixture.settings.RepoKeyingCacheTtl)
	if status := world.postWrap(world.adminToken, 1, gkmTestC8(world.key1), late); status != http.StatusCreated {
		t.Errorf("the same delivery once it lapsed: %d", status)
	}
}

// repo/'s cache keeps an answer its creation moves on from within moments only RepoKeyingCacheTtl, 0 by default: no
// repo/ yet, then keying, then active, each seen by the next read, while an active repo/ is kept RepoCacheTtl (the
// other half is TestGkmRepoAndFormCachesHoldAnAnswerAtMostTheirTtl's). With the ttl set, a keying answer is kept that
// long and no longer.
func TestGkmRepoCacheKeepsAKeyingRepoOnlyItsKeyingTtl(t *testing.T) {
	fixture := newGkmFixture(t)
	repoId := testId("repo-k")
	cluster := fixture.cluster("meta-1")
	repoObject := func(state protocol.EvsRepoState) []byte {
		return fixture.marshal(&protocol.EvsRepoObject{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: state, Format: 1})
	}
	if _, err := fixture.engine.repos.read(fixture.ctx, cluster, repoId); !errors.Is(err, errGkmRepoNotFound) {
		t.Fatalf("placed, repo/ unwritten: %v", err)
	}
	fixture.put("meta-1", GkmEvsRepoKey(repoId), repoObject(protocol.EvsRepoState_EVS_REPO_KEYING))
	if object, err := fixture.engine.repos.read(fixture.ctx, cluster, repoId); err != nil || object.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("repo/ just written: %v %v", object, err)
	}
	fixture.moveRepoNow(repoId, "meta-1", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	if object, _ := fixture.engine.repos.read(fixture.ctx, cluster, repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("the activation, read at once: %v", object.GetState())
	}
	fixture.moveRepoNow(repoId, "meta-1", protocol.EvsRepoState_EVS_REPO_DELETED)
	if object, _ := fixture.engine.repos.read(fixture.ctx, cluster, repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("an active repo/ within RepoCacheTtl: %v", object.GetState())
	}

	kept := newGkmFixtureWith(t, func(settings *GkmServiceSettings, deps *GkmEngineDeps) {
		settings.RepoKeyingCacheTtl = 2 * time.Second
	})
	keptCluster := kept.cluster("meta-1")
	kept.put("meta-1", GkmEvsRepoKey(repoId), repoObject(protocol.EvsRepoState_EVS_REPO_KEYING))
	if object, err := kept.engine.repos.read(kept.ctx, keptCluster, repoId); err != nil || object.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Fatalf("keying: %v %v", object, err)
	}
	kept.moveRepoNow(repoId, "meta-1", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	if object, _ := kept.engine.repos.read(kept.ctx, keptCluster, repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING {
		t.Errorf("keying within its ttl: %v", object.GetState())
	}
	kept.clock.Advance(kept.settings.RepoKeyingCacheTtl)
	if object, _ := kept.engine.repos.read(kept.ctx, keptCluster, repoId); object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("keying past its ttl: %v", object.GetState())
	}
}

// The two fields' defaults and bounds: a keying repo/ cached 0 by default and never past RepoCacheTtl, and repo/'s
// format bound the root's 4 KiB, positive.
func TestGkmServiceSettingsHoldTheKeyingTtlAndTheRepoBound(t *testing.T) {
	settings := DefaultGkmServiceSettings()
	if settings.RepoKeyingCacheTtl != 0 || settings.RepoObjectMaxByteCount != sidecar.EvsRepoObjectMaxByteCount {
		t.Fatalf("defaults %s %d", settings.RepoKeyingCacheTtl, settings.RepoObjectMaxByteCount)
	}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	settings.RepoKeyingCacheTtl = settings.RepoCacheTtl + time.Second
	if err := settings.Validate(); !errors.Is(err, ErrGkmSettings) {
		t.Errorf("a keying ttl past RepoCacheTtl: %v", err)
	}
	settings = DefaultGkmServiceSettings()
	settings.RepoObjectMaxByteCount = 0
	if err := settings.Validate(); !errors.Is(err, ErrGkmSettings) {
		t.Errorf("no repo/ bound: %v", err)
	}
	// a repo/ past the bound is a fault, never a state
	fixture := newGkmFixtureWith(t, func(settings *GkmServiceSettings, deps *GkmEngineDeps) {
		settings.RepoObjectMaxByteCount = 8
	})
	repoId := testId("repo-b")
	fixture.placeRepo(repoId, "meta-1", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	if _, err := fixture.engine.repos.read(fixture.ctx, fixture.cluster("meta-1"), repoId); !errors.Is(err, errGkmStoreFault) {
		t.Errorf("a repo/ past an 8-byte bound: %v", err)
	}
}
