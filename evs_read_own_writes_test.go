// A device's plain reads right after its own push while evs's head cache has not reached it (evs_read.go's own pushes
// row; the evs-write-update-stale-cache finding's reads): step 8 caches a commit's head only after evs answered the
// push (§11.9's cache row), so ReadHead and List, which go through the cache, were served the head before the
// device's own push. The device did not read what it had just written, and mail_store.go, which takes a path's
// IfVersion from ReadHead, was refused as moved again and again while the cache lagged. A request served a head below
// the version this device's own push committed at is now asked once more, fresh. Another device's reads are held only
// to its own pushes, and a cluster behind this device's push is read as it stands after one fresh request.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
)

// Requires a read's requests to be the cache's and then one fresh one: the first served from the cache, not fresh, and
// the next and only fresh one right after it.
func evsTestRequireCachedThenFresh(t *testing.T, when string, reads []evsTestCacheRead) {
	t.Helper()
	fresh := 0
	for _, read := range reads {
		if read.fresh {
			fresh += 1
		}
	}
	if len(reads) < 2 || !reads[0].cached || reads[0].fresh || !reads[1].fresh || fresh != 1 {
		t.Errorf("%s: requests %+v, not the cache's and then one fresh one", when, reads)
	}
}

// How many of reads were fresh.
func evsTestFreshCount(reads []evsTestCacheRead) int {
	fresh := 0
	for _, read := range reads {
		if read.fresh {
			fresh += 1
		}
	}
	return fresh
}

// Another sidecar of the world, as otherWriter makes, whose requests go through writer's head cache.
func (self *evsTestWriter) otherWriterThrough(t *testing.T, label string, cache *evsTestStaleCache) *evsTestWriter {
	t.Helper()
	other := self.otherWriter(t, label)
	other.test.client.args.Transport = &evsTestTransport{handler: cache}
	other.test.client.http.transport = wrapSidecarApiTransport(other.test.client.args.Transport)
	return other
}

// The writer's ReadHead right after its own push, while the cache holds the head before that push, reads the version
// the push made, its content and its head; before the fix it read the content the push replaced. The cache served the
// read's request, which was asked again, fresh.
func TestEvsReadHeadRightAfterOwnPushReadsItsVersion(t *testing.T) {
	writer, cache := newEvsTestWriterCached(t)
	writer.seed(t)
	path := "notes/own.txt"
	if _, err := writer.write(t, path, []byte("zero")); err != nil {
		t.Fatal(err)
	}
	// evs caches the head the next write is planned on, and nothing after it: step 8 has not run for that write's
	// commit when the writer reads
	cache.cache(t, writer.world)
	written, err := writer.write(t, path, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	reads := cache.readCount()
	out := &bytes.Buffer{}
	info, err := writer.repo.ReadHead(context.Background(), &EvsReadArgs{Path: path}, out)
	if err != nil || out.String() != "one" || info.Version != written.PathVersion || info.HeadVersion != written.Version {
		t.Fatalf("the read right after the push: %q %+v %v, not version %d at head %d", out.String(), info, err, written.PathVersion, written.Version)
	}
	evsTestRequireCachedThenFresh(t, "the read", cache.readsSince(reads))
	// History reads through the same rounds: newest first, the push's version on top
	history, err := writer.repo.History(context.Background(), &EvsReadArgs{Path: path})
	if err != nil || len(history.Versions) == 0 || history.Versions[0].Version != written.PathVersion {
		t.Errorf("the history: %+v %v", history, err)
	}
	if alarms := writer.test.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// The writer's List right after its own push created a name lists that name with the rest, at the push's head; before
// the fix it listed the directory as it stood before the push.
func TestEvsListRightAfterOwnPushListsItsCreation(t *testing.T) {
	writer, cache := newEvsTestWriterCached(t)
	writer.seed(t)
	if _, err := writer.write(t, "d/a.txt", []byte("a")); err != nil {
		t.Fatal(err)
	}
	cache.cache(t, writer.world)
	written, err := writer.write(t, "d/b.txt", []byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	reads := cache.readCount()
	listing, err := writer.repo.List(context.Background(), &EvsReadArgs{Path: "d"})
	if err != nil || evsTestListedNames(listing) != "a.txt,b.txt" || listing.HeadVersion != written.Version {
		t.Fatalf("the listing right after the push: %+v %v", listing, err)
	}
	evsTestRequireCachedThenFresh(t, "the listing", cache.readsSince(reads))
	if alarms := writer.test.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// mail_store.go's read-modify-write right after its own write: the read gives the version the store's own push made,
// and the write held to it lands at once, one push and no conflict. Before the fix the read was served the head before
// the store's own creation, found the path absent, and a write held to that was refused as moved, as every write
// after it was until the cache caught up.
func TestMailStoreWriteRightAfterItsOwnLandsAtOnce(t *testing.T) {
	writer, cache := newEvsTestWriterCached(t)
	writer.seed(t)
	ctx := context.Background()
	store := newMailEvsStore(writer.repo, nil, nil)
	path := "f/flags"
	writer.server.know(path)
	if _, _, err := store.Read(ctx, path, 1024); !errors.Is(err, ErrEvsPathAbsent) {
		t.Fatalf("the path before its creation: %v", err)
	}
	cache.cache(t, writer.world)
	created, err := store.Write(ctx, []*mailStoreWrite{{Path: path, Content: []byte("one")}})
	if err != nil {
		t.Fatal(err)
	}
	for round, content := range []string{"two", "three"} {
		reads := cache.readCount()
		read, version, err := store.Read(ctx, path, 1024)
		if err != nil || string(read) != []string{"one", "two"}[round] || version != created[0]+uint64(round) {
			t.Fatalf("round %d: the store's read after its own write: %q at %d, %v", round, read, version, err)
		}
		if round == 0 {
			evsTestRequireCachedThenFresh(t, "the first read", cache.readsSince(reads))
		}
		posted := writer.server.postCount()
		written, err := store.Write(ctx, []*mailStoreWrite{{Path: path, Content: []byte(content), IfVersion: version}})
		if err != nil || len(written) != 1 || written[0] != version+1 {
			t.Fatalf("round %d: the write held to the version read: %v %v", round, written, err)
		}
		if got := writer.server.postCount() - posted; got != 1 {
			t.Errorf("round %d: %d pushes", round, got)
		}
	}
	if read, version, err := store.Read(ctx, path, 1024); err != nil || string(read) != "three" || version != created[0]+2 {
		t.Errorf("the path reads %q at %d: %v", read, version, err)
	}
}

// Another device's reads are not held to the writer's pushes: right after the writer's push, the other device's
// ReadHead and List are served the cached head, as before, with no fresh request, while the writer's own read is held
// to its push.
func TestEvsReadsOfAnotherDeviceStayOnTheCache(t *testing.T) {
	writer, cache := newEvsTestWriterCached(t)
	writer.seed(t)
	ctx := context.Background()
	other := writer.otherWriterThrough(t, "other device", cache)
	path := "notes/own.txt"
	if _, err := writer.write(t, path, []byte("zero")); err != nil {
		t.Fatal(err)
	}
	// the other device holds a pin at the head before the writer's next push
	if _, err := other.repo.ReadHead(ctx, &EvsReadArgs{Path: path}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	cache.cache(t, writer.world)
	if _, err := writer.write(t, path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	reads := cache.readCount()
	out := &bytes.Buffer{}
	if _, err := other.repo.ReadHead(ctx, &EvsReadArgs{Path: path}, out); err != nil || out.String() != "zero" {
		t.Fatalf("the other device's read: %q %v, not the cached head's", out.String(), err)
	}
	if listing, err := other.repo.List(ctx, &EvsReadArgs{Path: "notes"}); err != nil || evsTestListedNames(listing) != "own.txt" {
		t.Fatalf("the other device's listing: %+v %v", listing, err)
	}
	served := cache.readsSince(reads)
	if len(served) == 0 || evsTestFreshCount(served) != 0 || slices.ContainsFunc(served, func(read evsTestCacheRead) bool { return !read.cached }) {
		t.Errorf("the other device's requests %+v, not the cache's alone", served)
	}
	reads = cache.readCount()
	out.Reset()
	if _, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: path}, out); err != nil || out.String() != "one" {
		t.Fatalf("the writer's read: %q %v", out.String(), err)
	}
	evsTestRequireCachedThenFresh(t, "the writer's read", cache.readsSince(reads))
	if alarms := append(writer.test.alarms(), other.test.alarms()...); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// A device whose push evs's cluster no longer holds, as a site loss leaves it before its reseed: its read asks fresh
// once and reads what the cluster holds, and its reads after that go as any other's, with no fresh request, the fresh
// one having found the cluster behind the push. Its next push, which the cluster commits below the version it lost,
// holds its reads again: one right after it, while the cache holds the head before it, is asked again, fresh, and
// reads that push.
func TestEvsReadFreshOnceWhileEvsStaysBehindItsPush(t *testing.T) {
	writer, cache := newEvsTestWriterCached(t)
	writer.seed(t)
	ctx := context.Background()
	head, _ := writer.world.head()
	writer.test.client.epochs.noteCommitted(writer.world.repoId, writer.world.refId, head+8)
	reads := cache.readCount()
	out := &bytes.Buffer{}
	if _, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt"}, out); err != nil || out.String() != "seed" {
		t.Fatalf("the read: %q %v", out.String(), err)
	}
	if served := cache.readsSince(reads); evsTestFreshCount(served) != 1 || served[0].fresh {
		t.Errorf("the read's requests %+v, not one and then one fresh", served)
	}
	reads = cache.readCount()
	if _, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if listing, err := writer.repo.List(ctx, &EvsReadArgs{Path: ""}); err != nil || evsTestListedNames(listing) != "seed.txt" {
		t.Fatalf("the root's listing: %+v %v", listing, err)
	}
	if served := cache.readsSince(reads); evsTestFreshCount(served) != 0 {
		t.Errorf("the reads after it: requests %+v", served)
	}
	cache.cache(t, writer.world)
	written, err := writer.write(t, "seed.txt", []byte("seed again"))
	if err != nil || written.Version != head+1 {
		t.Fatalf("the next push: %+v %v", written, err)
	}
	reads = cache.readCount()
	out.Reset()
	info, err := writer.repo.ReadHead(ctx, &EvsReadArgs{Path: "seed.txt"}, out)
	if err != nil || out.String() != "seed again" || info.HeadVersion != head+1 {
		t.Fatalf("the read right after the next push: %q %+v %v", out.String(), info, err)
	}
	evsTestRequireCachedThenFresh(t, "the read right after the next push", cache.readsSince(reads))
}

// What a device's reads of a ref are held to: the version its newest push committed at; a fresh read sent before a
// commit was noted says nothing of it; one sent after that finds evs's cluster behind the push holds reads to what it
// found instead, raised by later fresh reads and by this device's pushes the cluster commits below the lost one, and
// never lowered by them; a fresh read at or past the push, a push past it and a reseed each end that; and each ref is
// its own.
func TestEvsOwnFloorFollowsCommitsFreshReadsAndReseeds(t *testing.T) {
	epochs := newEvsClientEpochs()
	repoId, refId, otherRefId := evsTestId("floor repo"), evsTestId("floor ref"), evsTestId("floor other ref")
	steps := []struct {
		name  string
		step  func()
		floor uint64
	}{
		{name: "nothing pushed", step: func() {}, floor: 0},
		{name: "a push at 5", step: func() { epochs.noteCommitted(repoId, refId, 5) }, floor: 5},
		{name: "a push at 6, then a fresh read sent before it was noted finds 5", step: func() {
			epochs.noteCommitted(repoId, refId, 6)
			epochs.noteFreshHead(repoId, refId, 5, 5)
		}, floor: 6},
		{name: "a fresh read sent after it finds 4", step: func() { epochs.noteFreshHead(repoId, refId, 6, 4) }, floor: 4},
		{name: "a later fresh read finds 3", step: func() { epochs.noteFreshHead(repoId, refId, 6, 3) }, floor: 4},
		{name: "a late answer at 3", step: func() { epochs.noteCommitted(repoId, refId, 3) }, floor: 4},
		{name: "a push the cluster commits at 5", step: func() { epochs.noteCommitted(repoId, refId, 5) }, floor: 5},
		{name: "a fresh read finds 6", step: func() { epochs.noteFreshHead(repoId, refId, 6, 6) }, floor: 6},
		{name: "a fresh read finds 2 again", step: func() { epochs.noteFreshHead(repoId, refId, 6, 2) }, floor: 2},
		{name: "a push at 7", step: func() { epochs.noteCommitted(repoId, refId, 7) }, floor: 7},
		{name: "a fresh read finds 1", step: func() { epochs.noteFreshHead(repoId, refId, 7, 1) }, floor: 1},
		{name: "a reseed at 3", step: func() { epochs.forgetAbove(repoId, refId, 3) }, floor: 3},
	}
	for _, step := range steps {
		step.step()
		if floor := epochs.ownFloor(repoId, refId); floor != step.floor {
			t.Errorf("%s: held to %d, not %d", step.name, floor, step.floor)
		}
	}
	if committed := epochs.committedVersion(repoId, refId); committed != 3 {
		t.Errorf("committed %d after the reseed", committed)
	}
	if floor := epochs.ownFloor(repoId, otherRefId); floor != 0 {
		t.Errorf("another ref held to %d", floor)
	}
}
