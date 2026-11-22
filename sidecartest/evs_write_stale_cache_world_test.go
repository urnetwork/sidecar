// A writer's own writes of one path back to back on T2 while evs's head cache has not reached the first (the
// e2e-churn-load finding; sidecar's evs_plan.go, its own-push paragraph): sidecar.EvsClient devices against an
// evsservice.EvsEngine over FakeHost's stores, on the path-epoch world (evs_epoch_world_test.go). evs caches a commit's
// head in {evsh_} only in step 8, after it answered the push (§11.9's cache row); here the put of one commit is lost,
// as the e2e's came 48 ms late, so the head before that commit is served to every read that is not fresh and asks no
// more than its version, until the next commit's put.
//
//	own      the writer's next write of the path, planned on that head, reads again fresh and lands at the version
//	         after its own, sent once, where evs answered it 409 PATH_CONFLICT
//	other    a write another writer's push beats after that plan still answers 409 naming its path, sent once, the
//	         other's content standing

package sidecartest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// Loses step 8's next put of a head into the repo's {evsh_} key, as a Redis that does not answer loses it: the cache
// keeps the head before that commit. The channel closes once a put was lost.
func (self *epochWorld) loseNextHeadCachePut() <-chan struct{} {
	self.t.Helper()
	lost, err := self.host.Redis.Faults().Add(&FaultPlan{
		Op: FaultOpRedis, KeyPrefix: evsservice.HeadCacheKey(self.repoId), WritesOnly: true, Result: FailBeforeApply,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return lost
}

// The version {evsh_} holds for refId, 0 for none, read past the faults: an entry's first eight bytes
// (evsservice/head_cache.go's header).
func (self *epochWorld) cachedHeadVersion(refId sidecar.Id) uint64 {
	self.t.Helper()
	encoded, found, err := self.host.Redis.HashGet(InspectContext(self.ctx), evsservice.HeadCacheKey(self.repoId), sidecar.EvsKeyId(refId))
	if err != nil {
		self.t.Fatal(err)
	}
	if !found || len(encoded) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(encoded[:8])
}

// Whether each read a device sent was fresh, in order.
type staleCacheReads struct {
	stateLock sync.Mutex
	fresh     []bool
}

// Logs whether each read device sends from now on is fresh, and runs then, when given, before every device's requests.
func (self *epochWorld) logReads(device *epochDevice, then func(device *epochDevice, request *http.Request) error) *staleCacheReads {
	reads := &staleCacheReads{}
	self.setIntercept(func(sender *epochDevice, request *http.Request) error {
		if sender == device && request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/read") {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return err
			}
			request.Body.Close()
			request.Body = io.NopCloser(bytes.NewReader(body))
			read := &protocol.EvsReadRequest{}
			if err := proto.Unmarshal(body, read); err != nil {
				return err
			}
			reads.stateLock.Lock()
			reads.fresh = append(reads.fresh, read.GetFresh())
			reads.stateLock.Unlock()
		}
		if then != nil {
			return then(sender, request)
		}
		return nil
	})
	return reads
}

// The reads logged so far.
func (self *staleCacheReads) take() []bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fresh := self.fresh
	self.fresh = nil
	return fresh
}

// The writer's first and second writes, the second commit's head lost from the cache, which then holds the first's.
func staleCacheWrites(t *testing.T, world *epochWorld, writer *epochDevice, path string) (*sidecar.EvsWritePathsResult, *sidecar.EvsWritePathsResult) {
	t.Helper()
	first, err := writer.write(path, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	lost := world.loseNextHeadCachePut()
	second, err := writer.write(path, []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-lost:
	default:
		t.Fatal("the second commit's head reached the cache")
	}
	refId := world.mainRefId(writer)
	if cached, head := world.cachedHeadVersion(refId), world.head(refId).GetVersion(); cached != first.Version || head != second.Version {
		t.Fatalf("the cache holds version %d, the head %d", cached, head)
	}
	return first, second
}

// Whether a plan's reads went to evs's cache first and then once fresh.
func staleCacheReadAgainFresh(fresh []bool) bool {
	freshCount := 0
	for _, each := range fresh {
		if each {
			freshCount += 1
		}
	}
	return 2 <= len(fresh) && !fresh[0] && freshCount == 1
}

// path's newest content on a reader of its own, read fresh.
func staleCacheRead(t *testing.T, world *epochWorld, path string) []byte {
	t.Helper()
	reader := world.device("r", nil)
	out := &bytes.Buffer{}
	if _, err := reader.repo.ReadHead(world.ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true}, out); err != nil {
		t.Fatalf("the read of %s: %v", path, err)
	}
	return out.Bytes()
}

// own: the third write of the writer's own path, planned while the cache holds the head of its first, lands on its
// second's version, one push, its history every version in order. Before the fix evs answered it 409 PATH_CONFLICT,
// as the e2e's writer was answered.
func TestEvsWriteOwnPathBackToBackOnAStaleHeadCacheWorld(t *testing.T) {
	world := newEpochWorld(t)
	writer := world.device("w", nil)
	path := "notes/own.txt"
	_, second := staleCacheWrites(t, world, writer, path)
	pushes := 0
	reads := world.logReads(writer, func(device *epochDevice, request *http.Request) error {
		if device == writer && epochIsPush(request) {
			pushes += 1
		}
		return nil
	})
	third, err := writer.write(path, []byte("three"))
	world.setIntercept(nil)
	if err != nil {
		t.Fatalf("a write planned on the cached head: %v", err)
	}
	if third.Version != second.Version+1 || third.PathVersions[0] != second.PathVersions[0]+1 || pushes != 1 {
		t.Errorf("committed at %d, path version %d, after %d and %d, in %d pushes", third.Version, third.PathVersions[0], second.Version, second.PathVersions[0], pushes)
	}
	if fresh := reads.take(); !staleCacheReadAgainFresh(fresh) {
		t.Errorf("the plan's reads, fresh: %v", fresh)
	}
	if content := staleCacheRead(t, world, path); string(content) != "three" {
		t.Errorf("%s reads %q", path, content)
	}
	history, err := writer.repo.History(world.ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true})
	if err != nil || len(history.Versions) != 3 {
		t.Fatalf("the history: %v", err)
	}
	for i, version := range history.Versions {
		// newest first
		if want := third.PathVersions[0] - uint64(i); version.Version != want {
			t.Errorf("history %d: version %d, not %d", i, version.Version, want)
		}
	}
}

// other: a write whose push another writer's beats, after its plan read the head again fresh past the cache, is a real
// conflict and answers 409 naming its path, sent once, and the other writer's content stands.
func TestEvsWriteBeatenOnAStaleHeadCacheStillAnswers409World(t *testing.T) {
	world := newEpochWorld(t)
	writer := world.device("w", nil)
	other := world.device("v", nil)
	path := "notes/shared.txt"
	staleCacheWrites(t, world, writer, path)
	// the other writer has read past the cached head, so its own plan is not served it
	if _, err := other.repo.ReadHead(world.ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	pushes := 0
	var once sync.Once
	var raceErr error
	reads := world.logReads(writer, func(device *epochDevice, request *http.Request) error {
		if device != writer || !epochIsPush(request) {
			return nil
		}
		pushes += 1
		once.Do(func() {
			// the other writer's push lands after the writer planned and before its push
			if _, err := other.write(path, []byte("theirs")); err != nil {
				raceErr = fmt.Errorf("the other writer's write: %w", err)
			}
		})
		return nil
	})
	_, err := writer.write(path, []byte("mine"))
	world.setIntercept(nil)
	if raceErr != nil {
		t.Fatal(raceErr)
	}
	var conflict *sidecar.EvsPathConflictError
	if !errors.As(err, &conflict) || !sidecar.IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT) || len(conflict.Paths) != 1 || conflict.Paths[0] != path {
		t.Fatalf("a push another writer's beat: %v, want 409 PATH_CONFLICT naming its path", err)
	}
	if pushes != 1 {
		t.Errorf("%d pushes: a conflict is never planned again", pushes)
	}
	if fresh := reads.take(); !staleCacheReadAgainFresh(fresh) {
		t.Errorf("the plan's reads, fresh: %v", fresh)
	}
	if content := staleCacheRead(t, world, path); string(content) != "theirs" {
		t.Errorf("%s reads %q", path, content)
	}
}
