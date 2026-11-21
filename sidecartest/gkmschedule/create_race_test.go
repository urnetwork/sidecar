package gkmschedule

// A creation raced by its readers, on T2's KeyDelivery world with gkm's caches as production runs them (§11.8's place
// and resolve rows, §10.6's checks row), where NewFsKeysWorld's own engine caches nothing so that a schedule sees each
// write at once. Every reader's sync of a new repo, the creator's own among them, asks gkm as its RepoCreate lands
// and ahead of the creator's PUT: here on two gkm processes, one read answered by the store before the placement and
// held on its way back across it. The creator's KF1 right after the placement never fails, its deliveries landing on
// either process, and each reader then holds generation 1. And a LATE delivery right after the config repo's
// activation lands with no time passing. Before the fix KF1's POST /gkm/groups answered the readers' 404, and the LATE
// delivery 409 as keying, which its deliverer dropped.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// gkm's caches as production runs them: place/'s 404 for 5 s, repo/, the forms and group-info 5 s, a keying repo/ not
// at all.
func createRaceProductionCaches(settings *gkmservice.GkmServiceSettings) {
	defaults := gkmservice.DefaultGkmServiceSettings()
	settings.Place = defaults.Place
	settings.RepoCacheTtl = defaults.RepoCacheTtl
	settings.RepoKeyingCacheTtl = defaults.RepoKeyingCacheTtl
	settings.FormCacheTtl = defaults.FormCacheTtl
	settings.GroupInfoCacheTtl = defaults.GroupInfoCacheTtl
}

// One read of one key on the world's store, armed by arm: it answers from the store, then holds that answer until let
// go, as a network that delays a read's answer past writes issued after it. Every other read passes.
type createRaceHold struct {
	stateLock sync.Mutex
	key       string
	held      chan struct{}
	release   chan struct{}
}

// Arms the next read of key, and the channel closed once it is held.
func (self *createRaceHold) arm(key string) <-chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.key, self.held, self.release = key, make(chan struct{}), make(chan struct{})
	return self.held
}

// Lets the held read answer.
func (self *createRaceHold) let() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.release != nil {
		close(self.release)
		self.release = nil
	}
}

// Holds a read of key that the arm names, once.
func (self *createRaceHold) wait(key string) {
	release := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.key == "" || key != self.key {
			return nil
		}
		self.key = ""
		close(self.held)
		return self.release
	}()
	if release != nil {
		<-release
	}
}

// The services' store, each cluster's reads passing the hold.
type createRaceBlobs struct {
	sidecar.BlobStore
	hold *createRaceHold
}

func (self *createRaceBlobs) Cluster(clusterId string) (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.Cluster(clusterId)
	if err != nil {
		return nil, err
	}
	return &createRaceCluster{BlobCluster: cluster, hold: self.hold}, nil
}

func (self *createRaceBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.FirstCluster()
	if err != nil {
		return nil, err
	}
	return &createRaceCluster{BlobCluster: cluster, hold: self.hold}, nil
}

type createRaceCluster struct {
	sidecar.BlobCluster
	hold *createRaceHold
}

func (self *createRaceCluster) Get(ctx context.Context, key string) (*sidecar.BlobObject, error) {
	object, err := self.BlobCluster.Get(ctx, key)
	self.hold.wait(key)
	return object, err
}

// Another gkm process over the world's stores and state, sharing none of the world engine's caches: an lb host beside
// it.
func (self *FsKeysWorld) anotherEngine() *gkmservice.GkmEngine {
	self.t.Helper()
	engine, err := gkmservice.NewGkmEngine(self.Ctx, self.serviceHost(), self.engineSettings, &gkmservice.GkmEngineDeps{AuthState: &fsKeysWorldState{world: self}})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(engine.Close)
	return engine
}

// Serves the device's requests that route picks, every one for nil, on engine in place of the world's: what an lb that
// sends them to another process does. The count of requests it served.
func createRaceRoute(device *FsKeysDevice, engine *gkmservice.GkmEngine, route func(request *http.Request) bool) *atomic.Int64 {
	served := &atomic.Int64{}
	device.Transport.Respond = func(request *http.Request) *http.Response {
		if route != nil && !route(request) {
			return nil
		}
		served.Add(1)
		recorder := httptest.NewRecorder()
		engine.Handler().ServeHTTP(recorder, request)
		return recorder.Result()
	}
	return served
}

// Whether a request is a wraps batch, POST /gkm/groups/<id>/wraps/<g>/<c8>.
func createRaceWrapBatch(request *http.Request) bool {
	return request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/wraps/")
}

// Three readers and the creator sync the new repo as its RepoCreate lands, before evs places it: reader-c on a second
// gkm process, its read answered 404 by the store and held across the placement and the whole creation, the rest on
// the world's, which caches their 404. The creator's KF1 right after the placement takes its group on the world's
// process and stages its deliveries on the second; each held or cached 404 answers only the read it was made for, and
// every reader then holds generation 1, the clock unmoved throughout.
func TestReadersRacingACreateNeverFailIt(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil)
	hold := &createRaceHold{}
	world := NewFsKeysWorldOn(t, protocol.RepoKind_REPO_KIND_GENERAL, clock, host, func(serviceHost *sidecar.ServiceHost) {
		serviceHost.Blobs = &createRaceBlobs{BlobStore: serviceHost.Blobs, hold: hold}
	})
	ctx, cancel := context.WithTimeout(world.Ctx, 30*time.Second)
	defer cancel()
	world.Ctx = ctx
	t.Cleanup(hold.let)
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) {
		settings.DraftMls = false
		createRaceProductionCaches(settings)
	})
	other := world.anotherEngine()
	creator := world.AddMember("creator", false)
	readerA, readerB, readerC := world.AddMember("reader-a", false), world.AddMember("reader-b", false), world.AddMember("reader-c", false)
	world.Grant(true, creator)
	world.Grant(false, readerA, readerB, readerC)
	world.Creator(creator)
	world.Advance()
	world.Publish()
	start := world.Clock.Now()
	createRaceRoute(readerC, other, nil)
	stagedOnOther := createRaceRoute(creator, other, createRaceWrapBatch)

	held := hold.arm(sidecar.EvsPlaceKey(world.RepoId))
	heldErrs := make(chan error, 1)
	go func() { heldErrs <- readerC.Client.SyncRepo(ctx, world.RepoId) }()
	select {
	case <-held:
	case <-ctx.Done():
		t.Fatal("reader-c's read of place/ never reached the store")
	}
	for _, device := range []*FsKeysDevice{readerA, readerB, creator} {
		if err := device.Client.SyncRepo(ctx, world.RepoId); !sidecar.IsGkmStatus(err, http.StatusNotFound) {
			t.Fatalf("%s's sync before the placement: %v", device.Label, err)
		}
	}
	world.Place(creator)
	key, err := creator.Client.CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{
		NetworkId: sidecar.Id(world.NetworkId), RepoId: world.RepoId, Kind: world.Kind,
	})
	if err != nil {
		t.Fatalf("KF1 right after the placement: %v", err)
	}
	world.GroupId = key.GroupId()
	if stagedOnOther.Load() == 0 {
		t.Fatal("no delivery was staged on the second process")
	}
	hold.let()
	if err := <-heldErrs; !sidecar.IsGkmStatus(err, http.StatusNotFound) {
		t.Errorf("reader-c's held read: %v", err)
	}
	world.Activate()
	for _, reader := range []*FsKeysDevice{readerA, readerB, readerC} {
		if !world.WrapRecipients(1)[reader.SidecarId()] {
			t.Errorf("KF1 staged no delivery to %s", reader.Label)
		}
		got, err := reader.Client.CurrentRepoKey(ctx, world.RepoId)
		if err != nil || !bytes.Equal(got.Commitment(), key.Commitment()) {
			t.Errorf("%s's key after the creation: %v", reader.Label, err)
		}
	}
	if !world.Clock.Now().Equal(start) {
		t.Error("the clock moved")
	}
}

// The config repo's KF1 reads repo/ keying moments before its activation; a member device admitted after gen/1's
// claim asks for its first wrap, and the config writer's LATE delivery answering it, right after the activation with
// no time passing, lands and opens for the joiner. RepoKeyingCacheTtl, 0 by default, is the bound.
func TestLateDeliveryRightAfterTheConfigRepoActivatesLands(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	ctx, cancel := context.WithTimeout(world.Ctx, 30*time.Second)
	defer cancel()
	world.Ctx = ctx
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) {
		settings.DraftMls = false
		createRaceProductionCaches(settings)
	})
	writer := world.AddMember("writer", false)
	world.ConfigWriters(writer)
	world.Advance()
	world.Publish()
	first := world.CreateConfig(writer)
	start := world.Clock.Now()
	joiner := world.AddMember("joiner", false)
	world.Advance()
	joiner.PublishReaderKey()
	if _, err := joiner.Client.CurrentRepoKey(ctx, world.ConfigRepoId); err == nil {
		t.Fatal("the joiner held the config before any delivery to it")
	}
	if err := writer.Client.DeliverLate(ctx, world.ConfigRepoId, fsKeysRecipient(joiner.SidecarId())); err != nil {
		t.Fatalf("the writer's late delivery: %v", err)
	}
	if !world.WrapRecipientsIn(world.ConfigGroupId, 1)[joiner.SidecarId()] {
		t.Fatal("no delivery to the joiner stands: gkm refused the one right after the activation")
	}
	got, err := joiner.Client.CurrentRepoKey(ctx, world.ConfigRepoId)
	if err != nil || !bytes.Equal(got.Commitment(), first.Commitment()) || got.Generation() != 1 {
		t.Fatalf("the joiner's config key: %v", err)
	}
	if !world.Clock.Now().Equal(start) {
		t.Error("the clock moved")
	}
}
