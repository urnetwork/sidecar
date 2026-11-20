//go:build !sidecar_http

// HoldSet.CoveringAtDelete, the bound held at a DELETE (owner decision 629), on FakeBlobs and a fake clock: a cover
// carries the time its read began, a fresh one is acted on with no read, an aged one is read again once through the
// cache, and a read that comes back already past the bound is unknown with ErrHoldReadStale.

package sidecar_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A cover carries the time before its read's LIST, a cached answer its read's time, not the time it was asked.
func TestHoldCoverCarriesItsReadTime(t *testing.T) {
	ctx := context.Background()
	clock, _, holds := newTestHoldSet()
	readTime := clock.Now()
	cover, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil || !cover.ReadTime.Equal(readTime) {
		t.Fatalf("the first read: %+v %v", cover, err)
	}
	clock.Advance(3 * time.Second)
	cover, err = holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil || !cover.ReadTime.Equal(readTime) {
		t.Fatalf("a cached answer carries %s, want its read's %s", cover.ReadTime, readTime)
	}
	if unknown, _ := holds.Covering(ctx, sidecar.Id{}, testHoldRepoId1); !unknown.Unknown || !unknown.ReadTime.IsZero() {
		t.Fatalf("a repo of no known network: %+v", unknown)
	}
}

// A cover younger than the bound is acted on as it is, with no read: a DELETE after a quick HEAD deletes on the read
// it had, though a hold placed since is not in it yet.
func TestHoldSetCoveringAtDeleteKeepsAFreshCover(t *testing.T) {
	ctx := context.Background()
	clock, blobs, holds := newTestHoldSet()
	cover, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil || cover.Covered() {
		t.Fatalf("no hold: %+v %v", cover, err)
	}
	clock.Advance(time.Second)
	if err := sidecartest.PlaceHold(ctx, blobs, testPreserveHold(testHoldNetworkId, testHoldCaseId1, clock.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(5*time.Second - time.Second - time.Millisecond)
	if !holds.Fresh(cover) {
		t.Fatal("a cover under 5 s old reads as aged")
	}
	atDelete, err := holds.CoveringAtDelete(ctx, cover, testHoldNetworkId, testHoldRepoId1)
	if err != nil || atDelete != cover {
		t.Fatalf("a fresh cover was not kept: %+v %v", atDelete, err)
	}
	if got := testListCount(blobs); got != 1 {
		t.Fatalf("%d LISTs, want the one read", got)
	}
}

// A cover whose read reached the bound while its caller waited is read again, through the cache, and the new read
// shows a hold placed meanwhile; a second aged cover then takes the cache's new read with no LIST of its own.
func TestHoldSetCoveringAtDeleteRereadsAnAgedCoverOnce(t *testing.T) {
	ctx := context.Background()
	clock, blobs, holds := newTestHoldSet()
	first, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId1)
	if err != nil || first.Covered() {
		t.Fatalf("no hold: %+v %v", first, err)
	}
	second, err := holds.Covering(ctx, testHoldNetworkId, testHoldRepoId2)
	if err != nil || second.Covered() {
		t.Fatalf("no hold: %+v %v", second, err)
	}
	// a stall: the hold is acknowledged within it, and the caller comes back 5 s on
	clock.Advance(500 * time.Millisecond)
	if err := sidecartest.PlaceHold(ctx, blobs, testPreserveHold(testHoldNetworkId, testHoldCaseId1, clock.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(5*time.Second - 500*time.Millisecond)
	if holds.Fresh(first) {
		t.Fatal("a cover 5 s old reads as fresh")
	}
	atDelete, err := holds.CoveringAtDelete(ctx, first, testHoldNetworkId, testHoldRepoId1)
	if err != nil || !atDelete.Covered() || len(atDelete.Holds) != 1 || !atDelete.ReadTime.Equal(clock.Now()) {
		t.Fatalf("the read at the DELETE: %+v %v", atDelete, err)
	}
	if got := testListCount(blobs); got != 2 {
		t.Fatalf("%d LISTs, want one more", got)
	}
	atDelete, err = holds.CoveringAtDelete(ctx, second, testHoldNetworkId, testHoldRepoId2)
	if err != nil || !atDelete.Covered() {
		t.Fatalf("the second DELETE's read: %+v %v", atDelete, err)
	}
	if got := testListCount(blobs); got != 2 {
		t.Fatalf("%d LISTs: the second aged cover read again", got)
	}
	// a nil cover reads now, through the cache
	if atDelete, err := holds.CoveringAtDelete(ctx, nil, testHoldNetworkId, testHoldRepoId1); err != nil || !atDelete.Covered() {
		t.Fatalf("a nil cover: %+v %v", atDelete, err)
	}
	if got := testListCount(blobs); got != 2 {
		t.Fatalf("%d LISTs after a nil cover's read", got)
	}
}

// A LIST that comes back after the bound has passed since it began answers a read already too old to delete on:
// unknown, with ErrHoldReadStale, whatever it found.
func TestHoldSetCoveringAtDeleteRefusesAReadSlowerThanItsBound(t *testing.T) {
	ctx := context.Background()
	clock, blobs, holds := newTestHoldSet()
	if _, err := blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpList, KeyPrefix: "hold/", Result: sidecartest.Delay, Delay: sidecartest.DelayInNetwork,
	}); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		cover *sidecar.HoldCover
		err   error
	}
	answers := make(chan answer, 1)
	go func() {
		cover, err := holds.CoveringAtDelete(ctx, nil, testHoldNetworkId, testHoldRepoId1)
		answers <- answer{cover: cover, err: err}
	}()
	// the parked LIST's client timeout is the one timer
	if err := clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(6 * time.Second)
	if delivered := blobs.DeliverDelayed("meta-1", "hold/"); delivered != 1 {
		t.Fatalf("%d parked LISTs", delivered)
	}
	got := <-answers
	if !errors.Is(got.err, sidecar.ErrHoldReadStale) || !got.cover.Unknown || !got.cover.Covered() {
		t.Fatalf("a read slower than its bound: %+v %v", got.cover, got.err)
	}
}

// A HoldSet whose reread interval is not positive rereads on every call, and no read of it is young enough to delete
// on: every doubt keeps data.
func TestHoldSetWithNoRereadIntervalLeavesNoReadToDeleteOn(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	settings := sidecar.DefaultHoldSetSettings()
	settings.RereadInterval = 0
	holds := sidecar.NewHoldSet(blobs, clock, settings)
	cover, err := holds.CoveringAtDelete(ctx, nil, testHoldNetworkId, testHoldRepoId1)
	if !errors.Is(err, sidecar.ErrHoldReadStale) || !cover.Covered() {
		t.Fatalf("%+v %v", cover, err)
	}
}
