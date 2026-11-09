//go:build !sidecar_http

// FS-62's {acl_}e case on AclGateDirectSource, T2 on sidecartest's fake Blobs and op-counted Redis, with FakeApi as
// api's sequencer and the test as api's one script (TEAM-M2-14's, not built): the cache serves only while it records
// {acl_}v's current value and holds every position needed; lost, stale with an older {acl_}v or short of a position,
// proj/ serves; and through AclGateCache a miss touches no store, api's INCR loads the tip from {acl_}e by its event,
// and with the hash lost the next event loads from proj/.

package sidecar_test

import (
	"context"
	"io"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The first cluster as a gate's source reads it, its reads counted apart from api's.
type aclGateCountingBlobs struct {
	sidecar.BlobStore
	reads *atomic.Int64
}

func (self aclGateCountingBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.FirstCluster()
	if err != nil {
		return nil, err
	}
	return aclGateCountingCluster{BlobCluster: cluster, reads: self.reads}, nil
}

type aclGateCountingCluster struct {
	sidecar.BlobCluster
	reads *atomic.Int64
}

func (self aclGateCountingCluster) Get(ctx context.Context, key string) (*sidecar.BlobObject, error) {
	self.reads.Add(1)
	return self.BlobCluster.Get(ctx, key)
}

func (self aclGateCountingCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	self.reads.Add(1)
	return self.BlobCluster.List(ctx, keyPrefix, startAfter, limit)
}

// One network's log on a fake cluster, api's read cache beside it in a fake Redis.
type aclGateWorld struct {
	t       *testing.T
	ctx     context.Context
	cluster sidecar.BlobCluster
	redis   *sidecartest.FakeRedis
	world   *sidecartest.ConfigLogSuiteWorld
	api     *sidecartest.FakeApi
	tip     *bridge.AuthPin
	// the gate source's reads of the store, and the store it reads through
	sourceReads atomic.Int64
	sourceBlobs sidecar.BlobStore
}

func newAclGateWorld(t *testing.T) *aclGateWorld {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, sidecartest.NewFaultQueue(), nil, sidecartest.DefaultFakeBlobsSettings())
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	world := sidecartest.NewConfigLogSuiteWorld(ctx, cluster)
	api := sidecartest.NewFakeApi(ctx, world.Clock(), sidecartest.NewFaultQueue(), nil, cluster, nil)
	if err := world.Start(api); err != nil {
		t.Fatal(err)
	}
	redis := sidecartest.NewFakeRedis(ctx, clock, sidecartest.NewFaultQueue(), nil, sidecartest.DefaultFakeRedisSettings())
	t.Cleanup(redis.Close)
	self := &aclGateWorld{t: t, ctx: ctx, cluster: cluster, redis: redis, world: world, api: api, tip: &bridge.AuthPin{Version: 1}}
	self.sourceBlobs = aclGateCountingBlobs{BlobStore: blobs, reads: &self.sourceReads}
	self.writeCache(1)
	return self
}

// The entry the store holds at n.
func (self *aclGateWorld) entry(n uint64) []byte {
	self.t.Helper()
	object, err := self.cluster.Get(self.ctx, sidecar.ConfigEntryKey(self.world.NetworkId(), n))
	if err != nil {
		self.t.Fatal(err)
	}
	defer object.Body.Close()
	entryBytes, err := io.ReadAll(object.Body)
	if err != nil {
		self.t.Fatal(err)
	}
	return entryBytes
}

// What api's one script does after appending entry n, the hash written before the INCR whose event reaches gates, as
// the script's atomic run shows them: {acl_}e gains the entry and the tip and records the value {acl_}v is raised to.
// Base 1 is the newest base throughout.
func (self *aclGateWorld) writeCache(n uint64) {
	self.t.Helper()
	networkId := self.world.NetworkId()
	current, _, err := self.redis.Get(self.ctx, sidecar.AclVersionKey(networkId))
	if err != nil {
		self.t.Fatal(err)
	}
	version, _ := strconv.ParseInt(string(current), 10, 64)
	if err := self.redis.HashSet(self.ctx, sidecar.AclEntryCacheKey(networkId), map[string][]byte{
		sidecar.AclEntryCacheField(n):     self.entry(n),
		sidecar.AclEntryCacheFieldBase:    []byte("1"),
		sidecar.AclEntryCacheFieldTip:     []byte(strconv.FormatUint(n, 10)),
		sidecar.AclEntryCacheFieldVersion: []byte(strconv.FormatInt(version+1, 10)),
	}); err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.redis.Increment(self.ctx, sidecar.AclVersionKey(networkId), 48*time.Hour); err != nil {
		self.t.Fatal(err)
	}
}

// Appends one member admit through api; cached, the script runs after it, else only {acl_}v moves, as when the hash
// was lost or its write never landed.
func (self *aclGateWorld) appendAdmit(cached bool) {
	self.t.Helper()
	pin, err := self.world.PostMemberAdmit(self.api)
	if err != nil {
		self.t.Fatal(err)
	}
	self.tip = pin
	if cached {
		self.writeCache(pin.GetVersion())
	} else if _, err := self.redis.Increment(self.ctx, sidecar.AclVersionKey(self.world.NetworkId()), 48*time.Hour); err != nil {
		self.t.Fatal(err)
	}
}

// The entries from after+1 to the tip as the store holds them.
func (self *aclGateWorld) storedRun(after uint64) [][]byte {
	run := [][]byte{}
	for n := after + 1; n <= self.tip.GetVersion(); n += 1 {
		run = append(run, self.entry(n))
	}
	return run
}

func aclGateRunsEqual(a [][]byte, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if string(a[i]) != string(b[i]) {
			return false
		}
	}
	return true
}

// The cache serves while it matches {acl_}v and holds every position; lost, stale or short of a position, proj/ does,
// and each read gives the store's run.
func TestAclGateDirectSourceReadsTheCacheOnlyWhenItServes(t *testing.T) {
	world := newAclGateWorld(t)
	source := sidecar.NewAclGateDirectSource(world.redis, world.sourceBlobs, nil)
	networkId := world.world.NetworkId()
	for range 3 {
		world.appendAdmit(true)
	}
	after := &bridge.AuthPin{Version: 1}
	want := world.storedRun(1)
	read := func(name string, fromStore bool) {
		t.Helper()
		before := world.sourceReads.Load()
		run, err := source.Entries(world.ctx, networkId, after)
		if err != nil || !aclGateRunsEqual(run, want) {
			t.Fatalf("%s: %v, %d entries", name, err, len(run))
		}
		if readStore := world.sourceReads.Load() != before; readStore != fromStore {
			t.Errorf("%s: read the store %v", name, readStore)
		}
	}
	read("a current cache", false)

	// stale: {acl_}v moved past what the hash records
	world.appendAdmit(false)
	want = world.storedRun(1)
	read("a stale cache", true)

	// current again, then lost
	world.writeCache(world.tip.GetVersion())
	read("the cache current again", false)
	world.redis.LoseKeys(sidecar.AclEntryCacheKey(networkId))
	read("a lost cache", true)

	// a hash missing a position the reader needs
	world.writeCache(world.tip.GetVersion())
	if err := world.redis.HashDelete(world.ctx, sidecar.AclEntryCacheKey(networkId), []string{sidecar.AclEntryCacheField(2)}); err != nil {
		t.Fatal(err)
	}
	read("a cache short of a position", true)

	// a cold start reads proj/ from position 1, and the genesis from 0
	run, err := source.Entries(world.ctx, networkId, nil)
	if err != nil || !aclGateRunsEqual(run, world.storedRun(0)) {
		t.Fatalf("a cold start: %v", err)
	}
	if genesis, err := source.Genesis(world.ctx, networkId); err != nil || string(genesis) != string(world.world.SignedGenesis()) {
		t.Errorf("the genesis: %v", err)
	}
}

// Through the cache: a network it was never told of costs no Redis op and no store read; api's INCR reaches it as a
// key event on the shared subscriber and loads the tip from {acl_}e with no store read; with the hash lost, the next
// event loads from proj/.
func TestAclGateCacheOverTheDirectSource(t *testing.T) {
	world := newAclGateWorld(t)
	networkId := world.world.NetworkId()
	settings := sidecar.DefaultAclGateSettings()
	settings.Log = sidecar.NewNoopLogger()
	loads := make(chan *bridge.AuthPin, 64)
	settings.OnLoad = func(loadedNetworkId sidecar.Id, pin *bridge.AuthPin, err error) {
		if err != nil {
			t.Errorf("a load failed: %v", err)
		}
		loads <- pin
	}
	cache := sidecar.NewAclGateCache(world.ctx, sidecar.NewAclGateDirectSource(world.redis, world.sourceBlobs, settings),
		sidecartest.NewFakeClock(sidecartest.DefaultClockStart()), settings)
	defer cache.Close()
	remove, err := cache.Watch(world.redis)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	opsBefore, readsBefore := world.redis.OpCounts(), world.sourceReads.Load()
	if snapshot, status := cache.State(sidecar.NewId()); snapshot != nil || status != sidecar.AclGateUnknown {
		t.Fatalf("a miss: %d", status)
	}
	if ops := world.redis.OpCounts(); len(ops) != len(opsBefore) || world.sourceReads.Load() != readsBefore {
		t.Errorf("a miss touched a store: %v %v", opsBefore, ops)
	}

	nextLoad := func() *bridge.AuthPin {
		t.Helper()
		select {
		case pin := <-loads:
			return pin
		case <-time.After(30 * time.Second):
			t.Fatal("no load finished")
		}
		return nil
	}
	held := func() uint64 {
		snapshot, status := cache.State(networkId)
		if status != sidecar.AclGateLoaded {
			t.Fatalf("status %d", status)
		}
		return snapshot.Pin.GetVersion()
	}
	cache.Changed(networkId)
	if pin := nextLoad(); pin.GetVersion() != 1 || held() != 1 {
		t.Fatalf("the cold start's pin %d", pin.GetVersion())
	}
	for range 2 {
		readsBefore = world.sourceReads.Load()
		world.appendAdmit(true)
		if pin := nextLoad(); pin.GetVersion() != world.tip.GetVersion() || held() != world.tip.GetVersion() {
			t.Fatalf("the event's load %d, the tip %d", pin.GetVersion(), world.tip.GetVersion())
		}
		if reads := world.sourceReads.Load() - readsBefore; reads != 0 {
			t.Errorf("an event's load read the store %d times with {acl_}e current", reads)
		}
	}
	world.redis.LoseKeys(sidecar.AclEntryCacheKey(networkId))
	readsBefore = world.sourceReads.Load()
	world.appendAdmit(false)
	if pin := nextLoad(); pin.GetVersion() != world.tip.GetVersion() || world.sourceReads.Load() == readsBefore {
		t.Fatalf("the load with the hash lost: %d, %d reads", pin.GetVersion(), world.sourceReads.Load()-readsBefore)
	}
}
