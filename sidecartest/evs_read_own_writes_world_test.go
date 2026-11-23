// A device's reads right after its own push on T2 while evs's head cache has not reached that push (sidecar's
// evs_read.go, its own pushes row): sidecar.EvsClient devices against an evsservice.EvsEngine over FakeHost's stores.
// evs caches a commit's head in {evsh_} only in step 8, after it answered the push (§11.9's cache row); here the put
// of one commit is lost (evs_write_stale_cache_world_test.go's loseNextHeadCachePut), so the head before it is served
// to every request that is not fresh and asks no more than its version.
//
//	read     the writer's ReadHead of its own path reads the version its push made, its request asked again fresh
//	list     its List of the directory its push created a name in lists that name
//	other    another device's reads stay on the cached head, as before, with no fresh request
//	consume  an ingester's CONSUME right after its own, naming a deposit the first removed, leaves it out and commits in
//	         one push, where its push was refused PATH_CONFLICT and rebuilt
//	erase    an eraser's ERASE right after its own is built on that ERASE's head, its request asked again fresh

package sidecartest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// read: the writer's second write's head is lost from the cache, which holds its first's; the writer's ReadHead of the
// path reads the second, at the head the second made. Before the fix it read the first's content.
func TestEvsReadHeadOwnPushOnAStaleHeadCacheWorld(t *testing.T) {
	world := newEpochWorld(t)
	writer := world.device("w", nil)
	path := "notes/own.txt"
	_, second := staleCacheWrites(t, world, writer, path)
	reads := world.logReads(writer, nil)
	content, info, err := writer.read(path)
	world.setIntercept(nil)
	if err != nil || string(content) != "two" || info.Version != second.PathVersions[0] || info.HeadVersion != second.Version {
		t.Fatalf("the read right after the push: %q %+v %v, not version %d at head %d", content, info, err, second.PathVersions[0], second.Version)
	}
	if fresh := reads.take(); !staleCacheReadAgainFresh(fresh) {
		t.Errorf("the read's requests, fresh: %v", fresh)
	}
}

// list: the writer's second write creates a name in the directory its first did, its head lost from the cache; the
// writer's List of the directory lists both names. Before the fix it listed the first alone.
func TestEvsListOwnPushOnAStaleHeadCacheWorld(t *testing.T) {
	world := newEpochWorld(t)
	writer := world.device("w", nil)
	first, err := writer.write("d/a.txt", []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	lost := world.loseNextHeadCachePut()
	second, err := writer.write("d/b.txt", []byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-lost:
	default:
		t.Fatal("the second commit's head reached the cache")
	}
	refId := world.mainRefId(writer)
	if cached := world.cachedHeadVersion(refId); cached != first.Version {
		t.Fatalf("the cache holds version %d, not %d", cached, first.Version)
	}
	reads := world.logReads(writer, nil)
	names, err := writer.list("d")
	world.setIntercept(nil)
	if err != nil || !slices.Equal(names, []string{"a.txt", "b.txt"}) {
		t.Fatalf("the listing right after the push at %d: %v %v", second.Version, names, err)
	}
	if fresh := reads.take(); !staleCacheReadAgainFresh(fresh) {
		t.Errorf("the listing's requests, fresh: %v", fresh)
	}
}

// other: a device that read the path at the writer's first write reads it at that head again after the writer's
// second, whose head the cache lost, with no fresh request: its reads are held to its own pushes, of which it has
// none, as before the fix. The writer's own read is held to its push.
func TestEvsReadsOfAnotherDeviceOnAStaleHeadCacheWorld(t *testing.T) {
	world := newEpochWorld(t)
	writer := world.device("w", nil)
	other := world.device("v", nil)
	path := "notes/own.txt"
	if _, err := writer.write(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if content, _, err := other.read(path); err != nil || string(content) != "one" {
		t.Fatalf("the other device's first read: %q %v", content, err)
	}
	lost := world.loseNextHeadCachePut()
	if _, err := writer.write(path, []byte("two")); err != nil {
		t.Fatal(err)
	}
	<-lost
	reads := world.logReads(other, nil)
	content, _, err := other.read(path)
	if err != nil || string(content) != "one" {
		t.Fatalf("the other device's read: %q %v, not the cached head's", content, err)
	}
	if names, err := other.list("notes"); err != nil || !slices.Equal(names, []string{"own.txt"}) {
		t.Fatalf("the other device's listing: %v %v", names, err)
	}
	if fresh := reads.take(); len(fresh) == 0 || slices.Contains(fresh, true) {
		t.Errorf("the other device's requests, fresh: %v", fresh)
	}
	reads = world.logReads(writer, nil)
	content, _, err = writer.read(path)
	world.setIntercept(nil)
	if err != nil || string(content) != "two" {
		t.Fatalf("the writer's read: %q %v", content, err)
	}
	if fresh := reads.take(); !staleCacheReadAgainFresh(fresh) {
		t.Errorf("the writer's requests, fresh: %v", fresh)
	}
}

// Loses step 8's next put into the repo's {evsh_} key in host's Redis, as epochWorld.loseNextHeadCachePut does: the
// channel closes once a put was lost.
func loseNextHeadCachePutOf(t *testing.T, host *FakeHost, repoId sidecar.Id) <-chan struct{} {
	t.Helper()
	lost, err := host.Redis.Faults().Add(&FaultPlan{
		Op: FaultOpRedis, KeyPrefix: evsservice.HeadCacheKey(repoId), WritesOnly: true, Result: FailBeforeApply,
	})
	if err != nil {
		t.Fatal(err)
	}
	return lost
}

// The version host's {evsh_} holds for a ref, 0 for none, read past the faults, as epochWorld.cachedHeadVersion reads
// it.
func cachedHeadVersionOf(t *testing.T, world *depositWorld, refId sidecar.Id) uint64 {
	t.Helper()
	encoded, found, err := world.host.Redis.HashGet(InspectContext(world.ctx), evsservice.HeadCacheKey(world.repoId), sidecar.EvsKeyId(refId))
	if err != nil {
		t.Fatal(err)
	}
	if !found || len(encoded) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(encoded[:8])
}

// consume: the owner ingests three deposits and consumes the first, that CONSUME's head lost from the cache; its next
// CONSUME names the first and the second, as an ingester whose batch still lists one it consumed does. Its plan reads
// the first as gone and leaves it out, and the CONSUME commits the second's removal in one push. Before the fix the plan
// read the head before the first CONSUME, both deposits standing, and evs refused the push PATH_CONFLICT on the first,
// which the rebuild loop then planned again: two pushes.
func TestEvsConsumeAfterOwnConsumeOnAStaleHeadCacheWorld(t *testing.T) {
	world := newDepositWorld(t)
	depositor := world.device(world.depositor, true, NewFakeStore().Root()).Repo(world.repoId)
	owner := world.device(world.owner, false, NewFakeStore().Root()).Repo(world.repoId)
	deposits := []*sidecar.EvsDepositResult{}
	for i := range 3 {
		body := []byte(fmt.Sprintf("deposit %d", i))
		deposited, err := depositor.Deposit(world.ctx, &sidecar.EvsDepositArgs{Body: bytes.NewReader(body), Size: int64(len(body))})
		if err != nil {
			t.Fatal(err)
		}
		deposits = append(deposits, deposited)
	}
	if standing := world.standing(owner); len(standing) != 3 {
		t.Fatalf("%d deposits standing", len(standing))
	}
	refId := sidecar.EvsDepositRefId(world.repoId, world.depositor.SidecarId)
	lost := loseNextHeadCachePutOf(t, world.host, world.repoId)
	first, err := owner.Consume(world.ctx, &sidecar.EvsConsumeArgs{DepositRefId: refId, EntryIds: []sidecar.EvsToken{deposits[0].EntryId}, ConsumedThrough: deposits[0].Version})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-lost:
	default:
		t.Fatal("the CONSUME's head reached the cache")
	}
	if cached := cachedHeadVersionOf(t, world, refId); cached != deposits[2].Version || first.Version != deposits[2].Version+1 {
		t.Fatalf("the cache holds version %d, the CONSUME committed at %d", cached, first.Version)
	}
	var stateLock sync.Mutex
	pushes := 0
	world.afterServe = func(request *http.Request) error {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push") {
			stateLock.Lock()
			pushes += 1
			stateLock.Unlock()
		}
		return nil
	}
	second, err := owner.Consume(world.ctx, &sidecar.EvsConsumeArgs{
		DepositRefId: refId, EntryIds: []sidecar.EvsToken{deposits[0].EntryId, deposits[1].EntryId}, ConsumedThrough: deposits[1].Version,
	})
	world.afterServe = nil
	if err != nil || second.Version != first.Version+1 {
		t.Fatalf("the second CONSUME: %+v %v, not at %d", second, err, first.Version+1)
	}
	if pushes != 1 {
		t.Errorf("%d pushes: the CONSUME's plan held a deposit its own last CONSUME removed", pushes)
	}
	if standing := world.standing(owner); len(standing) != 1 || standing[0] != deposits[2].EntryId {
		t.Errorf("deposits standing after both CONSUMEs: %v", standing)
	}
}

// Waits out every step 8 the engine started: POST .../slots/delete's, which the world's transport does not wait for.
func (self *epochWorld) waitStepEights() {
	for {
		started, finished, changed := self.engine.StepEights()
		if started == finished {
			return
		}
		<-changed
	}
}

// erase: three versionless files of a record repo, each its key in a slot of its own, erased one ERASE each; the
// second ERASE's head is lost from the cache, which holds the first's. The third ERASE's build reads the erasure
// ref's head through the cache and again fresh, and commits after the second. Before the fix its build was served the
// first ERASE's head and based on it, as file mode's base window lets commit: no request went fresh.
func TestEvsEraseAfterOwnEraseOnAStaleHeadCacheWorld(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	w := world.format2Device("w")
	paths := []string{"notes/a.bin", "notes/b.bin", "notes/c.bin"}
	keys := [][]*sidecar.EvsErasedKey{}
	for i, path := range paths {
		if _, err := w.writeSetting(path, versionlessContent(fmt.Sprintf("draft %d", i), 40*1024), sidecar.EvsVersioningOff); err != nil {
			t.Fatalf("the write of %s: %v", path, err)
		}
		pathKeys, err := w.repo.SlotKeysOf(world.ctx, nil, []string{path})
		if err != nil || len(pathKeys) != 1 {
			t.Fatalf("the slot keys of %s: %v %v", path, pathKeys, err)
		}
		keys = append(keys, pathKeys)
	}
	erase := func(index int) *sidecar.EvsEraseResult {
		t.Helper()
		erased, err := w.repo.Erase(world.ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: keys[index], Complete: true, Note: []byte(paths[index])})
		if err != nil {
			t.Fatalf("the ERASE of %s: %v", paths[index], err)
		}
		world.waitStepEights()
		return erased
	}
	if first := erase(0); first.Version != 1 {
		t.Fatalf("the first ERASE committed at %d", first.Version)
	}
	lost := world.loseNextHeadCachePut()
	second := erase(1)
	select {
	case <-lost:
	default:
		t.Fatal("the second ERASE's head reached the cache")
	}
	erasureRefId := sidecar.EvsErasureRefId(world.repoId)
	if cached, head := world.cachedHeadVersion(erasureRefId), world.head(erasureRefId).GetVersion(); cached != 1 || head != second.Version {
		t.Fatalf("the cache holds version %d, the erasure ref's head %d", cached, head)
	}
	reads := world.logReads(w, nil)
	third := erase(2)
	world.setIntercept(nil)
	if third.Version != second.Version+1 {
		t.Errorf("the third ERASE committed at %d, after %d", third.Version, second.Version)
	}
	if fresh := reads.take(); !staleCacheReadAgainFresh(fresh) {
		t.Errorf("the third ERASE's build's requests, fresh: %v", fresh)
	}
	if erasures, err := world.format2Device("v").repo.Erasures(world.ctx); err != nil || len(erasures) != 3 {
		t.Fatalf("the erasures read back: %v %v", erasures, err)
	}
}
