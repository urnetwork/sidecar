//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// A device's git updates of one ref back to back while evs's head cache has not reached the first (evs_plan.go's own
// pushes paragraph; the stale cache of evs_write_update_test.go): the next update, built on the version the device's
// own push committed at, was planned on the head before that push, took it for a head other than its base and ended
// ErrEvsGitTipMoved, as a second `git push` right after a first would have been refused. Its plan reads again fresh
// and the update commits on its base, sent once; replay on another device holds it.

package sidecar

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A publisher, as newEvsTestPublisher makes one, whose device reaches evs through a head cache the test fills.
func newEvsTestPublisherCached(t *testing.T) (*evsTestPublisher, *evsTestStaleCache) {
	t.Helper()
	writer, cache := newEvsTestWriterCached(t)
	writer.world.mode = protocol.EvsRefMode_EVS_REF_GIT
	writer.world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: writer.world.signer.sidecarId.Bytes()}}
	mount := newEvsTestMount(t)
	mount.repo.RepoId = writer.world.repoId
	publisher := &evsTestPublisher{
		t: t, writer: writer, mount: mount, state: &evsTestSourceState{refs: map[Id]*EvsGitSourceRef{}},
		refs: map[string]*evsTestPublishedRef{}, email: evsTestId("world client").String() + evsCommitterDomain,
	}
	return publisher, cache
}

// The update after a device's own committed one, planned while the cache holds the head before it, commits at the
// version after it, one push, where the publish ended ErrEvsGitTipMoved; the cache served the plan's first read and
// the plan read again fresh.
func TestEvsLocalPublishBackToBackOnAStaleCacheCommits(t *testing.T) {
	publisher, cache := newEvsTestPublisherCached(t)
	c1 := publisher.commit(map[string]string{"a.txt": "a\n"})
	if _, err := publisher.publish("main", &c1); err != nil {
		t.Fatal(err)
	}
	// evs caches the head the second update is built on, and nothing after it
	cache.cache(t, publisher.writer.world)
	c2 := publisher.commit(map[string]string{"a.txt": "a two\n"}, c1)
	second, err := publisher.publish("main", &c2)
	if err != nil {
		t.Fatal(err)
	}
	c3 := publisher.commit(map[string]string{"a.txt": "a three\n"}, c2)
	posted := publisher.posted()
	reads := cache.readCount()
	third, err := publisher.publish("main", &c3)
	if err != nil {
		t.Fatalf("an update after its own on a stale cache: %v", err)
	}
	if third.Version != second.Version+1 || publisher.posted() != posted+1 {
		t.Errorf("committed at %d after %d, %d posts", third.Version, second.Version, publisher.posted()-posted)
	}
	served := cache.readsSince(reads)
	if len(served) == 0 || !served[0].cached || !slices.ContainsFunc(served, func(read evsTestCacheRead) bool { return read.fresh }) {
		t.Errorf("the plan's reads %+v, not the cache's and then a fresh one", served)
	}
	if _, exported := publisher.export("main"); len(exported.Refs) != 1 || exported.Refs[0].Tip != c3 {
		t.Errorf("replay exports %+v, not main at %s", exported.Refs, c3)
	}
}
