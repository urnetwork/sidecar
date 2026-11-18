//go:build sidecar_testhooks && !ios_extension

package sidecar

// QD-1025's race: a cache drop waits for the round running on a ref it drops and runs nothing of itself before that
// round ends, so the round neither reads a half-dropped cache nor stores, after the drop, files and a manifest that the
// reset forgets while the cache keeps them, which the next round would then count as held.

import (
	"context"
	"slices"
	"testing"
)

// The round holds inside its fetch until the drop finds it running and waits at search.sync.drop.waiting, which checks
// that nothing of the drop ran yet and lets the round go on; at the round's last barrier the drop has not returned.
// After both, the cache holds nothing of the ref, and the next round fetches every file again and a search finds both
// documents.
func TestADropWaitsForTheRunningRound(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/harbor.md", "Harbor lights\nthe evening boat"))
	synced := world.sync
	repoId, refId := synced.repoId, synced.refId
	synced.head.push(t, evsTestId("writer"), testEngineDocument(t, "doc", 2, 1, "notes/quay.md", "Quay\nthe harbor wall"))
	inFetch := make(chan struct{})
	release := make(chan struct{})
	synced.source.beforeFetch[synced.source.fetchCalls] = func() {
		close(inFetch)
		<-release
	}
	key := searchSyncBarrierKey(repoId, refId)
	waited := make(chan struct{})
	dropReturned := make(chan struct{})
	SetTestHooks(&TestHooks{Barrier: func(name string, barrierKey string) {
		if barrierKey != key {
			return
		}
		switch name {
		case "search.sync.drop.waiting":
			// the drop found the round running and did nothing yet: the cache still holds what the last round kept
			if held, err := synced.cache.cache.Ref(repoId, refId); err != nil || held == nil || len(held.Files) == 0 {
				t.Errorf("the drop began before the round it waits for ended: %+v, %v", held, err)
			}
			close(waited)
			close(release)
		case "search.sync.retired":
			select {
			case <-dropReturned:
				t.Error("the drop returned while a round ran on a ref it drops")
			default:
			}
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })
	roundErr := make(chan error, 1)
	go func() {
		roundErr <- synced.sync.RunRound(context.Background(), repoId, refId, false)
	}()
	<-inFetch
	dropErr := make(chan error, 1)
	go func() {
		err := world.engine.DropCache(nil)
		close(dropReturned)
		dropErr <- err
	}()
	if err := <-roundErr; err != nil {
		t.Fatal(err)
	}
	if err := <-dropErr; err != nil {
		t.Fatal(err)
	}
	SetTestHooks(nil)
	select {
	case <-waited:
	default:
		t.Fatal("the drop never waited for the round")
	}
	if held, err := synced.cache.cache.Ref(repoId, refId); err != nil || held != nil {
		t.Fatalf("the drop left what the round stored: %+v, %v", held, err)
	}
	fetched := len(synced.source.fetched())
	synced.round(t)
	if len(synced.source.fetched()) == fetched {
		t.Fatal("the round after the drop fetched nothing")
	}
	if hits, _ := world.all(t, &SearchRequest{Text: "harbor"}); !slices.Equal(testHitPaths(hits), []string{"notes/harbor.md", "notes/quay.md"}) {
		t.Fatalf("after the drop and a round, hits %v", testHitPaths(hits))
	}
}
