package evsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"math/rand/v2"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A head store over one fake host's meta-1, its Redis twins registered.
type headFixture struct {
	t       *testing.T
	ctx     context.Context
	clock   *sidecartest.FakeClock
	host    *sidecartest.FakeHost
	cluster sidecar.BlobCluster
	heads   *HeadStore
	repoId  sidecar.Id
	refId   sidecar.Id
}

func newHeadFixture(t *testing.T) *headFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	heads := NewHeadStore(clock, host.ClockCheck, host.Redis, DefaultEvsSettings(), sidecar.NewNoopLogger())
	return &headFixture{t: t, ctx: ctx, clock: clock, host: host, cluster: cluster, heads: heads, repoId: testId("repo"), refId: testId("ref")}
}

// A head at version with a window of entryCount entries, a chain and pins.
func testHead(version uint64, entryCount int) *protocol.EvsHead {
	window := []byte{}
	for i := 0; i < entryCount; i += 1 {
		entry := &sidecar.EvsWindowEntry{
			PushId: testId("push"),
			Place:  &protocol.EvsPlace{Minute: 1, Instance: 2, Seq: uint32(i), Offset: 32, Length: 200},
		}
		window = append(window, entry.Encode()...)
	}
	chain := sha256.Sum256([]byte{byte(version)})
	head := &protocol.EvsHead{
		Version: version, PushId: testId("push").Bytes(),
		RefKind: uint32(protocol.EvsRefKind_EVS_REF_SHARED), RefMode: uint32(protocol.EvsRefMode_EVS_REF_FILE),
		Auth:    &bridge.AuthPin{Version: 10, Chain: bytes.Repeat([]byte{1}, 32)},
		GroupId: testId("group").Bytes(), Generation: 2, GenerationCommitment: bytes.Repeat([]byte{2}, 32),
		PathEpoch: &protocol.EvsPathEpoch{Current: 1},
		Window:    window,
	}
	if 0 < version {
		head.Chain = chain[:]
	}
	if 0 < entryCount {
		head.WindowBaseChain = bytes.Repeat([]byte{3}, 32)
	}
	return head
}

func TestHeadCommitCreatesThenMovesByIfMatchOnly(t *testing.T) {
	fixture := newHeadFixture(t)
	absent, err := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if err != nil || !absent.Absent() {
		t.Fatalf("a ref with no head: %v %v", absent, err)
	}
	first, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, absent, testHead(1, 1))
	if err != nil {
		t.Fatal(err)
	}
	if first.Head.GetWrittenMs() != fixture.clock.Now().UnixMilli() {
		t.Error("written_ms is not the writer's clock")
	}
	// a second create of the same ref fails If-None-Match
	if _, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, absent, testHead(1, 1)); !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("a second create: %v", err)
	}
	second, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, first, testHead(2, 2))
	if err != nil {
		t.Fatal(err)
	}
	// the first ETag is stale now, and can never apply again
	if _, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, first, testHead(3, 3)); !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("a stale If-Match: %v", err)
	}
	read, err := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if err != nil || read.Etag != second.Etag || read.Version() != 2 {
		t.Errorf("read %v %v", read, err)
	}
}

func TestHeadCommitRefusesAWriteThatBreaksTheHeadsRules(t *testing.T) {
	fixture := newHeadFixture(t)
	absent, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	prior, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, absent, testHead(5, 5))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(head *protocol.EvsHead){
		"raises nothing":     func(head *protocol.EvsHead) {},
		"version falls":      func(head *protocol.EvsHead) { head.Version = 4; head.Window = head.Window[:4*64]; head.Fence = 9 },
		"fence falls":        func(head *protocol.EvsHead) { head.Version = 6; head.Fence = 0; prior.Head.Fence = 1 },
		"auth pin falls":     func(head *protocol.EvsHead) { head.Version = 6; head.Auth.Version = 9 },
		"auth chain differs": func(head *protocol.EvsHead) { head.Version = 6; head.Auth.Chain = bytes.Repeat([]byte{7}, 32) },
		"generation falls":   func(head *protocol.EvsHead) { head.Version = 6; head.Generation = 1 },
		"commitment differs": func(head *protocol.EvsHead) {
			head.Version = 6
			head.GenerationCommitment = bytes.Repeat([]byte{8}, 32)
		},
		"index epoch falls": func(head *protocol.EvsHead) { head.Version = 6; prior.Head.IndexEpoch = 2 },
		"path epoch falls": func(head *protocol.EvsHead) {
			head.Version = 6
			head.PathEpoch.Current = 0
			prior.Head.PathEpoch.Current = 1
		},
		"256 window entries":    func(head *protocol.EvsHead) { head.Version = 300; head.Window = testHead(300, 256).Window },
		"9 refusal records":     func(head *protocol.EvsHead) { head.Version = 6; head.Refused = make([]byte, 9*16) },
		"folded past version":   func(head *protocol.EvsHead) { head.Version = 6; head.FoldedThrough = 7 },
		"a window past version": func(head *protocol.EvsHead) { head.Version = 3; head.Fence = 1; head.Window = testHead(3, 4).Window },
	}
	for name, adjust := range cases {
		priorHead := proto.Clone(prior.Head).(*protocol.EvsHead)
		next := CloneEvsHead(prior.Head)
		adjust(next)
		_, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, prior, next)
		if !errors.Is(err, ErrEvsHeadRule) {
			t.Errorf("%s: %v", name, err)
		}
		prior.Head = priorHead
	}
	// nothing was written
	read, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if read.Etag != prior.Etag {
		t.Error("a refused write moved the head")
	}
}

// D-EVS-13: every write raises the version or the fence, so an ETag never repeats, whatever the writes.
func TestHeadEtagNeverRepeats(t *testing.T) {
	fixture := newHeadFixture(t)
	random := rand.New(rand.NewPCG(1, 2))
	stored, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	seen := map[string]bool{}
	next := testHead(0, 0)
	for i := 0; i < 400; i += 1 {
		switch {
		case stored.Absent():
		case random.IntN(3) == 0:
			next = CloneEvsHead(stored.Head)
			next.Fence += 1
		default:
			next = CloneEvsHead(stored.Head)
			next.Version += 1
			chain := sha256.Sum256(next.GetChain())
			next.Chain = chain[:]
			next.PushId = testId("push").Bytes()
			// the window rolls at its bound, as a page-out would leave it
			entryCount := min(int(next.Version), 127)
			next.Window = testHead(next.Version, entryCount).Window
			next.WindowBaseChain = bytes.Repeat([]byte{3}, 32)
		}
		// a refusal record now and then, which a later write's clock lapses
		if random.IntN(5) == 0 && !stored.Absent() {
			refusal, err := sidecar.NewEvsRefusal(testId("refused"), [32]byte{}, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE, fixture.clock.Now().Add(time.Second).UnixMilli())
			if err != nil {
				t.Fatal(err)
			}
			refusals, _ := sidecar.DecodeEvsRefusals(next.GetRefused())
			if len(refusals) < sidecar.EvsHeadMaxRefusalCount {
				next.Refused = append(bytes.Clone(next.GetRefused()), refusal.Encode()...)
			}
		}
		fixture.clock.Advance(time.Duration(random.IntN(3)) * time.Second)
		written, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, stored, next)
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if seen[written.Etag] {
			t.Fatalf("write %d repeated an ETag", i)
		}
		seen[written.Etag] = true
		stored = written
	}
}

func TestHeadCommitDropsLapsedRefusalsOnlyOnASureClock(t *testing.T) {
	fixture := newHeadFixture(t)
	absent, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	head := testHead(1, 1)
	lapsing, _ := sidecar.NewEvsRefusal(testId("refused-1"), [32]byte{1}, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE, fixture.clock.Now().Add(time.Second).UnixMilli())
	lasting, _ := sidecar.NewEvsRefusal(testId("refused-2"), [32]byte{2}, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE, fixture.clock.Now().Add(time.Hour).UnixMilli())
	head.Refused = append(lapsing.Encode(), lasting.Encode()...)
	stored, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, absent, head)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(2 * time.Second)
	// an unsure clock drops none
	fixture.host.ClockCheck.SetUnknown()
	fence := CloneEvsHead(stored.Head)
	fence.Fence += 1
	stored, err = fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, stored, fence)
	if err != nil {
		t.Fatal(err)
	}
	if refusals, _ := sidecar.DecodeEvsRefusals(stored.Head.GetRefused()); len(refusals) != 2 {
		t.Errorf("an unsure clock kept %d records", len(refusals))
	}
	fixture.host.ClockCheck.SetOffset(0)
	fence = CloneEvsHead(stored.Head)
	fence.Fence += 1
	stored, err = fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, stored, fence)
	if err != nil {
		t.Fatal(err)
	}
	refusals, _ := sidecar.DecodeEvsRefusals(stored.Head.GetRefused())
	if len(refusals) != 1 || !refusals[0].RecordsPush(testId("refused-2")) {
		t.Errorf("a sure clock kept %d records", len(refusals))
	}
}

func TestHeadRaiseFenceSetsFenceMsAndMovesNoVersion(t *testing.T) {
	fixture := newHeadFixture(t)
	absent, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	stored, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, absent, testHead(3, 3))
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(time.Minute)
	fenced, err := fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if err != nil {
		t.Fatal(err)
	}
	if fenced.Version() != 3 || fenced.Head.GetFence() != stored.Head.GetFence()+1 || fenced.Head.GetFenceMs() != fixture.clock.Now().UnixMilli() {
		t.Errorf("fenced %v", fenced.Head)
	}
	// a commit planned on the head before the fence can never land
	next := CloneEvsHead(stored.Head)
	next.Version = 4
	if _, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, stored, next); !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("a commit on the pre-fence ETag: %v", err)
	}
	// an unsure clock raises nothing
	fixture.host.ClockCheck.SetUnknown()
	if _, err := fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId); !errors.Is(err, ErrEvsClockUnsure) {
		t.Errorf("an unsure clock: %v", err)
	}
}

func TestHeadRaiseFenceRetriesALostRaceAndResolvesALostResponse(t *testing.T) {
	fixture := newHeadFixture(t)
	absent, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if _, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, absent, testHead(3, 3)); err != nil {
		t.Fatal(err)
	}
	faults := fixture.host.Blobs.Faults()
	// one 412, as a commit landing between its read and its CAS would give
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: sidecartest.Precondition}); err != nil {
		t.Fatal(err)
	}
	fenced, err := fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if err != nil || fenced.Head.GetFence() != 1 {
		t.Fatalf("after a 412: %v %v", fenced, err)
	}
	// a lost response: the reread finds the fence landed, and raises no second one
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	fenced, err = fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if err != nil || fenced.Head.GetFence() != 2 {
		t.Fatalf("after a lost response: %v %v", fenced, err)
	}
	// a send that never landed is sent again
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	fenced, err = fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if err != nil || fenced.Head.GetFence() != 3 {
		t.Fatalf("after a lost send: %v %v", fenced, err)
	}
	// FenceRetryCount 412s in a row: busy
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: sidecartest.Precondition, Repeat: 8}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId); !errors.Is(err, ErrEvsHeadBusy) {
		t.Errorf("nine 412s: %v", err)
	}
}

// §11.8's size row: ~8.9 KiB at 127 entries and 8 refusal records, 17 KiB at 255.
func TestHeadSizeAt127And255Entries(t *testing.T) {
	fixture := newHeadFixture(t)
	for _, bound := range []struct {
		entryCount int
		byteCount  int
	}{{127, 9 * 1024}, {255, 17 * 1024}} {
		refId := testId("ref-" + string(rune('a'+bound.entryCount%26)))
		head := testHead(1000, bound.entryCount)
		head.SealedRefName = make([]byte, 64)
		head.OwnerSidecarId = testId("owner").Bytes()
		head.Lease = &protocol.EvsSealLease{PushId: testId("lease").Bytes(), UntilMs: 1 << 50}
		head.FoldedThrough = 900
		head.FenceMs, head.RefusedMs = 1<<50, 1<<50
		head.Collect = &protocol.EvsCollect{Done: 800, Through: 850, UntilMs: 1 << 50}
		head.PathEpoch = &protocol.EvsPathEpoch{Current: 4, DueGeneration: 5, DueByMs: 1 << 50, BlockUntilMs: 1 << 50,
			Sources: []*protocol.EvsEpochSource{{Epoch: 3, MapSha256: make([]byte, 32)}, {Epoch: 2, MapSha256: make([]byte, 32)}, {Epoch: 1, MapSha256: make([]byte, 32)}}}
		for i := 0; i < sidecar.EvsHeadMaxRefusalCount; i += 1 {
			refusal, _ := sidecar.NewEvsRefusal(testId("refused"), [32]byte{}, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE, fixture.clock.Now().Add(time.Hour).UnixMilli())
			head.Refused = append(head.Refused, refusal.Encode()...)
		}
		absent, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, refId)
		written, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, refId, absent, head)
		if err != nil {
			t.Fatalf("%d entries: %v", bound.entryCount, err)
		}
		if bound.byteCount < len(written.Bytes) {
			t.Errorf("%d entries: %d bytes, past %d", bound.entryCount, len(written.Bytes), bound.byteCount)
		}
	}
}

// FS-62: a cached head is served only within 10 min of its own cache time, though another ref of the repo kept
// writing, only at or above the version asked, and never to a fresh read.
func TestHeadCacheServesWithinTenMinutesOfItsOwnCacheTime(t *testing.T) {
	fixture := newHeadFixture(t)
	otherRefId := testId("ref-other")
	absent, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	stored, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, absent, testHead(4, 4))
	if err != nil {
		t.Fatal(err)
	}
	fixture.heads.CacheCommit(fixture.ctx, fixture.repoId, fixture.refId, stored, 1001)
	getsBefore := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	cached, err := fixture.heads.ReadCached(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, 4, false)
	if err != nil || !cached.Cached || cached.Etag != stored.Etag || cached.PushSequence != 1001 {
		t.Fatalf("cached %v %v", cached, err)
	}
	if fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) != getsBefore {
		t.Error("a cache hit read the cluster")
	}
	// a pin above the cached version, and a fresh read, go to the cluster
	if read, _ := fixture.heads.ReadCached(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, 5, false); read.Cached {
		t.Error("served below the pin")
	}
	if read, _ := fixture.heads.ReadCached(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, 0, true); read.Cached {
		t.Error("served to a fresh read")
	}
	// another ref keeps writing, extending the hash's ttl, while this ref's entry ages past 10 min
	otherAbsent, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, otherRefId)
	other, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, otherRefId, otherAbsent, testHead(1, 1))
	if err != nil {
		t.Fatal(err)
	}
	for minute := 1; minute <= 10; minute += 1 {
		fixture.clock.Advance(time.Minute)
		next := CloneEvsHead(other.Head)
		next.Version += 1
		next.Window = testHead(next.Version, int(next.Version)).Window
		next.WindowBaseChain = bytes.Repeat([]byte{3}, 32)
		other, err = fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, otherRefId, other, next)
		if err != nil {
			t.Fatal(err)
		}
		fixture.heads.CacheCommit(fixture.ctx, fixture.repoId, otherRefId, other, uint64(1001+minute))
	}
	read, err := fixture.heads.ReadCached(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, 0, false)
	if err != nil || read.Cached {
		t.Errorf("a head cached 10 min ago served: %v %v", read, err)
	}
	if read, _ := fixture.heads.ReadCached(fixture.ctx, fixture.cluster, fixture.repoId, otherRefId, 0, false); !read.Cached {
		t.Error("the other ref's fresh entry was not served")
	}
}

func TestHeadCacheIsWrittenOnlyIfTheVersionRises(t *testing.T) {
	fixture := newHeadFixture(t)
	absent, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	v9, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, absent, testHead(9, 9))
	if err != nil {
		t.Fatal(err)
	}
	v10, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, v9, testHead(10, 10))
	if err != nil {
		t.Fatal(err)
	}
	fixture.heads.CacheCommit(fixture.ctx, fixture.repoId, fixture.refId, v10, 2)
	// a late writer of the older commit lowers nothing, though 9 < 10 only as numbers, not as strings of one length
	fixture.heads.CacheCommit(fixture.ctx, fixture.repoId, fixture.refId, v9, 1)
	cached, ok := fixture.heads.Cache().Read(fixture.ctx, fixture.repoId, fixture.refId, 0)
	if !ok || cached.Version() != 10 || cached.PushSequence != 2 {
		t.Errorf("cached %v", cached)
	}
	sequences, err := fixture.heads.Cache().PushSequences(fixture.ctx, fixture.repoId)
	if err != nil || sequences[fixture.refId] != 2 {
		t.Errorf("sequences %v %v", sequences, err)
	}
}

// FS-62: a push holding a stale cached ETag fails its commit, and costs one cluster read.
func TestHeadCacheStaleEtagCostsOneClusterRead(t *testing.T) {
	fixture := newHeadFixture(t)
	absent, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	v1, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, absent, testHead(1, 1))
	if err != nil {
		t.Fatal(err)
	}
	fixture.heads.CacheCommit(fixture.ctx, fixture.repoId, fixture.refId, v1, 1)
	// another process commits v2 and loses its cache write
	if _, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, v1, testHead(2, 2)); err != nil {
		t.Fatal(err)
	}
	cached, _ := fixture.heads.ReadCached(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, 1, false)
	if !cached.Cached {
		t.Fatal("not cached")
	}
	getsBefore := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	if _, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, cached, testHead(2, 2)); !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Fatalf("a stale cached ETag: %v", err)
	}
	reread, err := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if err != nil || reread.Version() != 2 {
		t.Fatal(err)
	}
	if _, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, reread, testHead(3, 3)); err != nil {
		t.Fatal(err)
	}
	if got := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - getsBefore; got != 1 {
		t.Errorf("%d cluster reads for one stale ETag", got)
	}
}

// FS-62: {evsh_} lost: every read falls to the cluster, and nothing fails.
func TestHeadCacheLostFallsToTheCluster(t *testing.T) {
	fixture := newHeadFixture(t)
	absent, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	stored, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, absent, testHead(1, 1))
	if err != nil {
		t.Fatal(err)
	}
	fixture.heads.CacheCommit(fixture.ctx, fixture.repoId, fixture.refId, stored, 1)
	fixture.host.Redis.LoseEverything()
	read, err := fixture.heads.ReadCached(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, 0, false)
	if err != nil || read.Cached || read.Etag != stored.Etag {
		t.Errorf("after the loss: %v %v", read, err)
	}
	// Redis down: the cache write is dropped and the read falls through
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpRedis, Result: sidecartest.FailBeforeApply, Repeat: -1}); err != nil {
		t.Fatal(err)
	}
	fixture.heads.CacheCommit(fixture.ctx, fixture.repoId, fixture.refId, stored, 2)
	if read, err := fixture.heads.ReadCached(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, 0, false); err != nil || read.Cached {
		t.Errorf("with Redis down: %v %v", read, err)
	}
}

func TestParseEvsHeadRefusesABrokenHead(t *testing.T) {
	good, err := proto.Marshal(testHead(2, 2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEvsHead(good); err != nil {
		t.Fatal(err)
	}
	for name, head := range map[string]*protocol.EvsHead{
		"a version with no push": {Version: 1, Chain: make([]byte, 32)},
		"a ragged window":        {Version: 2, PushId: make([]byte, 16), Chain: make([]byte, 32), Window: make([]byte, 65), WindowBaseChain: make([]byte, 32)},
		"ragged refusals":        {Version: 2, PushId: make([]byte, 16), Chain: make([]byte, 32), Refused: make([]byte, 17)},
		"a window with no base":  {Version: 2, PushId: make([]byte, 16), Chain: make([]byte, 32), Window: make([]byte, 64)},
	} {
		headBytes, _ := proto.Marshal(head)
		if _, err := ParseEvsHead(headBytes); !errors.Is(err, ErrEvsHeadInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseEvsHead(make([]byte, EvsHeadMaxByteCount+1)); !errors.Is(err, ErrEvsHeadInvalid) {
		t.Errorf("past the bound: %v", err)
	}
}

// DESIGN-DETAILS 2.2.3's fence rule: a ref with no head is fenced by creating a placeholder head, If-None-Match, at
// version 0 with no window, kind or mode, fence 1 and fence_ms its writer's clock.
func TestHeadRaiseFenceCreatesAPlaceholderOnARefWithNoHead(t *testing.T) {
	fixture := newHeadFixture(t)
	fixture.clock.Advance(25 * time.Hour)
	puts := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpPut)
	fenced, err := fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if err != nil {
		t.Fatal(err)
	}
	nowMs := fixture.clock.Now().UnixMilli()
	head := fenced.Head
	if fenced.Absent() || head.GetVersion() != 0 || head.GetFence() != 1 || head.GetFenceMs() != nowMs || head.GetWrittenMs() != nowMs {
		t.Fatalf("placeholder %v", head)
	}
	if len(head.GetWindow()) != 0 || head.GetRefKind() != 0 || head.GetRefMode() != 0 || len(head.GetPushId()) != 0 || len(head.GetRefused()) != 0 {
		t.Fatalf("a fence's placeholder carries more than its fence: %v", head)
	}
	if len(fenced.Bytes) > evsFencePlaceholderByteCount {
		t.Errorf("a placeholder of %d bytes, priced as %d", len(fenced.Bytes), evsFencePlaceholderByteCount)
	}
	if got := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpPut) - puts; got != 1 {
		t.Errorf("%d PUTs for one fence", got)
	}
	stored, err := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if err != nil || stored.Etag != fenced.Etag || !proto.Equal(stored.Head, head) {
		t.Fatalf("the stored placeholder: %v, %v", stored, err)
	}

	// a creating attempt that held the absent head can no longer create it
	if _, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, &EvsStoredHead{}, testHead(1, 1)); !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Errorf("a create on the absent head after the fence: %v", err)
	}
	// and the ref's first commit replaces the placeholder by If-Match, keeping its fence count
	first := testHead(1, 1)
	first.Fence = head.GetFence()
	committed, err := fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, fenced, first)
	if err != nil || committed.Version() != 1 || committed.Head.GetFence() != 1 {
		t.Fatalf("the first commit on a fenced placeholder: %v, %v", committed, err)
	}

	// a second fence of the same ref is the overwrite any fence is
	fixture.clock.Advance(time.Minute)
	again, err := fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if err != nil || again.Version() != 1 || again.Head.GetFence() != 2 {
		t.Fatalf("a fence over the committed head: %v, %v", again, err)
	}
}

// A lost response on the placeholder's creation is found by the reread, and one that never landed goes again.
func TestHeadRaiseFenceResolvesALostPlaceholderCreation(t *testing.T) {
	fixture := newHeadFixture(t)
	faults := fixture.host.Blobs.Faults()
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	fenced, err := fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if err != nil || fenced.Version() != 0 || fenced.Head.GetFence() != 1 {
		t.Fatalf("a creation whose answer was lost: %v, %v", fenced, err)
	}

	other := testId("other ref")
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	fenced, err = fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, other)
	if err != nil || fenced.Version() != 0 || fenced.Head.GetFence() != 1 {
		t.Fatalf("a creation that never landed: %v, %v", fenced, err)
	}
}

// A head write stalled at the store holds the key: the placeholder's creation fails ErrBlobHeld, which is the
// caller's to wait out, and nothing is written.
func TestHeadRaiseFenceOnAHeldKeyWritesNothing(t *testing.T) {
	fixture := newHeadFixture(t)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: sidecartest.Held}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId); !errors.Is(err, sidecar.ErrBlobHeld) {
		t.Fatalf("a fence on a held key: %v", err)
	}
	if stored, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId); !stored.Absent() {
		t.Fatal("a held creation wrote a head")
	}
}

// An unsure clock creates no placeholder either.
func TestHeadRaiseFenceCreatesNothingOnAnUnsureClock(t *testing.T) {
	fixture := newHeadFixture(t)
	fixture.host.ClockCheck.SetUnknown()
	if _, err := fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId); !errors.Is(err, ErrEvsClockUnsure) {
		t.Fatalf("an unsure clock: %v", err)
	}
	if stored, _ := fixture.heads.ReadCluster(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId); !stored.Absent() {
		t.Fatal("an unsure clock wrote a head")
	}
}
