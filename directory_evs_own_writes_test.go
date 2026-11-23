//go:build !sidecar_http

// The team directory's cards read right after this device's own card write, on T2 while evs's head cache has not
// reached that write (directory_evs.go's cards row; evs_read.go's own pushes row): the record world's engine loses
// step 8's put of the write's head, so the head before it is served to every request that is not fresh. The cards
// read made its own request for the head, apart from the reads' rounds, so it was served the cached head and gave no
// change past the version its copy held; a write held to the card's version, which only that read gives a copy, was
// refused as moved until the cache caught up.

package sidecar_test

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The writer's ReadCards from the version it held, right after its own card write whose head the cache lost, reads
// that card at the write's head, and a rewrite held to the version read lands. Before the fix the read gave the
// cached head and no file.
func TestDirectoryEvsCardsReadOwnPutOnAStaleHeadCache(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 1)
	ctx := t.Context()
	cards := directory.binding(t, directory.client(directory.writers[0]), nil)
	notices := directoryEvsNoticePaths(t, 2)
	write := func(path string, ifVersion uint64, content string) *sidecar.DirectoryCardWrite {
		return &sidecar.DirectoryCardWrite{PushId: sidecar.NewId(), Path: path, IfVersion: ifVersion, Content: []byte(content), AuthPin: directory.world.Pin()}
	}
	if _, err := cards.PutCard(ctx, directory.directoryId, write(notices[0], 0, "a")); err != nil {
		t.Fatal(err)
	}
	held, err := cards.ReadCards(ctx, directory.directoryId, 0)
	if err != nil || len(held.Files) != 1 {
		t.Fatalf("the first read: %+v %v", held, err)
	}
	lost, err := directory.world.host.Redis.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpRedis, KeyPrefix: evsservice.HeadCacheKey(directory.directoryId), WritesOnly: true, Result: sidecartest.FailBeforeApply,
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := cards.PutCard(ctx, directory.directoryId, write(notices[1], 0, "b"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-lost:
	default:
		t.Fatal("the card write's head reached the cache")
	}
	changes, err := cards.ReadCards(ctx, directory.directoryId, held.HeadVersion)
	if err != nil || changes.HeadVersion != held.HeadVersion+1 || len(changes.Files) != 1 {
		t.Fatalf("the read right after the write: %+v %v, not one file at head %d", changes, err, held.HeadVersion+1)
	}
	if file := changes.Files[0]; file.Path != notices[1] || file.Version != created || string(file.Content) != "b" || file.PushVersion != changes.HeadVersion {
		t.Fatalf("the file read: %+v", file)
	}
	if rewritten, err := cards.PutCard(ctx, directory.directoryId, write(notices[1], changes.Files[0].Version, "c")); err != nil || rewritten != created+1 {
		t.Fatalf("a rewrite held to the version read: %d %v", rewritten, err)
	}
}
