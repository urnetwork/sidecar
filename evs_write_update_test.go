// A writer's own writes of one path back to back while evs's head cache has not reached the first (the e2e-churn-load
// finding, its case in server/sidecare2e/churn_load_test.go; evs_plan.go's own-push paragraph): step 8 caches a
// commit's head only after evs answered the push (§11.9's cache row), so the writer's next plan, made on a read that
// is not fresh, is served the head before its own push. Planned on it, the second write stated its path's base below
// the version its own first write made, and evs's 5g refused it 409 PATH_CONFLICT, which went back to the caller; or
// it read a path its first write created as absent, removed one as absent, or found the version it was held to
// missing. The plan now reads again fresh when the head it was served is below a version this device's own push
// committed at, and each write lands. A write another writer's push beats still answers 409, the other's content
// standing, and a fresh read is never read again.

package sidecar

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// evs's head cache as a writer meets it just after its own push: once cache is called, a read that is not fresh and
// asks at most the cached head's version is served from a fork of the world as it stood then (evsTestForkWorld), as
// {evsh_} serves the head it cached before a commit whose step 8 has not run. A fresh read, a read asking past the
// cached head, and every other request go on to evs's stand-in.
type evsTestStaleCache struct {
	server http.Handler

	stateLock sync.Mutex
	cached    *evsTestWorld
	reads     []evsTestCacheRead
}

// One read the cache saw: whether it was fresh, and whether the cache served it.
type evsTestCacheRead struct {
	fresh  bool
	cached bool
}

// Caches world's head as it stands now, and serves it from now on.
func (self *evsTestStaleCache) cache(t *testing.T, world *evsTestWorld) {
	fork := evsTestForkWorld(t, world)
	func() {
		// the head's fields beside the history, which a fork leaves as a new world's: a git-mode ref's among them
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		fork.mode, fork.currentEpoch, fork.sourceEpochs = world.mode, world.currentEpoch, slices.Clone(world.sourceEpochs)
		fork.sealedRefName, fork.base, fork.deleted, fork.immutable = world.sealedRefName, world.base, world.deleted, world.immutable
		fork.indexEpoch, fork.owned = world.indexEpoch, world.owned
	}()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cached = fork
}

// How many reads the cache has seen.
func (self *evsTestStaleCache) readCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.reads)
}

// The reads the cache saw from the start'th on, in order.
func (self *evsTestStaleCache) readsSince(start int) []evsTestCacheRead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.reads[start:])
}

func (self *evsTestStaleCache) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/read") {
		self.server.ServeHTTP(writer, request)
		return
	}
	body, err := io.ReadAll(request.Body)
	read := &protocol.EvsReadRequest{}
	if err != nil || proto.Unmarshal(body, read) != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	cached := func() *evsTestWorld {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		var served *evsTestWorld
		if self.cached != nil && !read.GetFresh() {
			// at least the version asked, never to a fresh read (§11.9's cache row)
			if version, _ := self.cached.head(); read.GetPinVersion() <= version {
				served = self.cached
			}
		}
		self.reads = append(self.reads, evsTestCacheRead{fresh: read.GetFresh(), cached: served != nil})
		return served
	}()
	if cached != nil {
		cached.ServeHTTP(writer, request)
		return
	}
	self.server.ServeHTTP(writer, request)
}

// A writer whose client reaches evs through a head cache the test fills, and the cache.
func newEvsTestWriterCached(t *testing.T) (*evsTestWriter, *evsTestStaleCache) {
	var cache *evsTestStaleCache
	writer := newEvsTestWriterThrough(t, func(server http.Handler) http.Handler {
		cache = &evsTestStaleCache{server: server}
		return cache
	})
	return writer, cache
}

// The e2e finding: two writes of one path by one writer back to back, the second planned on a cache that has not yet
// seen the first. Whether the path stood before the first or the first created it, the second write lands on the
// version the first made, sent once, where evs answered it 409 PATH_CONFLICT; a removal after a creation removes what
// the creation made, where the plan found the path absent; and a write held to the version the first write answered
// (QD-721) bears out, where the planner refused it as moved. The cache served the plan's first read, and the plan
// read again fresh.
func TestEvsWriteBackToBackOnAStaleCacheLands(t *testing.T) {
	cases := []struct {
		name string
		// the path stands before the first write
		stands bool
		// the second write removes the path, or is held to the version the first answered
		remove bool
		held   bool
	}{
		{name: "an update after an update", stands: true},
		{name: "an update after a creation"},
		{name: "a removal after a creation", remove: true},
		{name: "an update held to the first's version", stands: true, held: true},
	}
	for _, c := range cases {
		writer, cache := newEvsTestWriterCached(t)
		writer.seed(t)
		path := "notes/own.txt"
		if c.stands {
			if _, err := writer.write(t, path, []byte("zero")); err != nil {
				t.Fatal(err)
			}
		}
		// evs caches the head the first write is planned on, and nothing after it: step 8 has not run for the first
		// write's commit when the second write reads
		cache.cache(t, writer.world)
		first, err := writer.write(t, path, []byte("one"))
		if err != nil {
			t.Fatalf("%s: the first write: %v", c.name, err)
		}
		posted := writer.server.postCount()
		reads := cache.readCount()
		var pathVersion uint64
		switch {
		case c.remove:
			var second *EvsWriteResult
			if second, err = writer.write(t, path, nil); err == nil {
				pathVersion = second.PathVersion
			}
		case c.held:
			var second *EvsWritePathsResult
			if second, err = writer.writeHeld(path, first.PathVersion, "two"); err == nil {
				pathVersion = second.PathVersions[0]
			}
		default:
			var second *EvsWriteResult
			if second, err = writer.write(t, path, []byte("two")); err == nil {
				pathVersion = second.PathVersion
			}
		}
		if err != nil {
			t.Errorf("%s: the second write, planned on the cache: %v", c.name, err)
			continue
		}
		// one push, none refused
		if got := writer.server.postCount() - posted; got != 1 {
			t.Errorf("%s: %d posts", c.name, got)
		}
		served := cache.readsSince(reads)
		if len(served) == 0 || !served[0].cached || !slices.ContainsFunc(served, func(read evsTestCacheRead) bool { return read.fresh }) {
			t.Errorf("%s: the plan's reads %+v, not the cache's and then a fresh one", c.name, served)
		}
		read, info, err := writer.read(t, path)
		switch {
		case c.remove:
			// a removal answers the version it removed past
			if !errors.Is(err, ErrEvsPathAbsent) || pathVersion != first.PathVersion+1 {
				t.Errorf("%s: the path reads %q at %d after its removal: %v", c.name, read, pathVersion, err)
			}
		case err != nil || string(read) != "two" || info.Version != first.PathVersion+1 || pathVersion != info.Version:
			t.Errorf("%s: the path reads %q: %+v %v", c.name, read, info, err)
		}
		if alarms := writer.test.alarms(); len(alarms) != 0 {
			t.Errorf("%s: alarms %v", c.name, alarms)
		}
	}
}

// A write another writer's push beats is a real conflict and still answers 409 naming its path (§11.7's writers row):
// whether its plan was served a head that held the writer's own last push or the cache's from before it, which the
// plan read again fresh, the push it sent is refused and goes back, nothing is sent again, and the other writer's
// content stands.
func TestEvsWriteBeatenByAnotherWriterStillAnswers409(t *testing.T) {
	for _, stale := range []bool{false, true} {
		writer, cache := newEvsTestWriterCached(t)
		writer.seed(t)
		other := writer.otherWriter(t, "racing writer")
		path := "shared/a.txt"
		if _, err := writer.write(t, path, []byte("zero")); err != nil {
			t.Fatal(err)
		}
		if stale {
			cache.cache(t, writer.world)
		}
		if _, err := writer.write(t, path, []byte("one")); err != nil {
			t.Fatal(err)
		}
		// the other writer's push lands between the writer's plan and its push
		writer.server.raceNextPush(func() {
			if _, err := other.write(t, path, []byte("theirs")); err != nil {
				t.Error(err)
			}
		})
		posted := writer.server.postCount()
		reads := cache.readCount()
		_, err := writer.write(t, path, []byte("mine"))
		evsTestRequirePathConflict(t, err, path)
		// the refused push and the other writer's
		if got := writer.server.postCount() - posted; got != 2 {
			t.Errorf("stale %t: %d posts", stale, got)
		}
		served := cache.readsSince(reads)
		if fresh := slices.ContainsFunc(served, func(read evsTestCacheRead) bool { return read.fresh }); len(served) == 0 || served[0].cached != stale || fresh != stale {
			t.Errorf("stale %t: the plan's reads %+v", stale, served)
		}
		if read, _, err := writer.read(t, path); err != nil || string(read) != "theirs" {
			t.Errorf("stale %t: the path reads %q: %v", stale, read, err)
		}
	}
}

// A plan whose fresh read is below this device's own push too, as a cluster that lost the push to a site loss is
// before its reseed, reads fresh once and plans on what it holds: the write lands, and no read is made again past
// the one fresh read.
func TestEvsWritePlanReadsFreshOnceWhenEvsStaysBehind(t *testing.T) {
	writer, cache := newEvsTestWriterCached(t)
	writer.seed(t)
	head, _ := writer.world.head()
	writer.test.client.epochs.noteCommitted(writer.world.repoId, writer.world.refId, head+8)
	reads := cache.readCount()
	posted := writer.server.postCount()
	// an update, which reads no root's table fresh
	written, err := writer.write(t, "seed.txt", []byte("seed again"))
	if err != nil {
		t.Fatal(err)
	}
	fresh := 0
	for _, read := range cache.readsSince(reads) {
		if read.fresh {
			fresh += 1
		}
	}
	if fresh != 1 {
		t.Errorf("%d fresh reads", fresh)
	}
	if got := writer.server.postCount() - posted; got != 1 || written.Version != head+1 {
		t.Errorf("%d posts, committed at %d", got, written.Version)
	}
	if read, _, err := writer.read(t, "seed.txt"); err != nil || string(read) != "seed again" {
		t.Errorf("seed.txt reads %q: %v", read, err)
	}
}
