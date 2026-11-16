//go:build !ios_extension

package sidecar

// CORE-M10-04: executed drops on a device (D-CORE-19, FI-27). Applying one deletes from the sealed mirror what only
// listed versions name and keeps what a live version names too, a chunk the kept head re-cites among them, and keeps
// what Live cannot answer for; nothing applies before the window passes on this device's clock, nor for a cancelled or
// refused drop, and a device offline at the drop applies it when it syncs, a second time deleting nothing more; the
// index cache's part ends the repo's searches, drops its retained buckets, the replaced index files and the local
// layer's listed entries; a registered holder, as §16.7's restore points are, deletes its decrypted copy of a listed
// version and keeps one a revert shares; and history_drop's plumbing carries each state, a held drop reading done.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A segment's body and the id it is kept under, its SHA-256.
func testDropSegment(label string) ([]byte, []byte) {
	body := evsTestMirrorBody("segment "+label, 600)
	id := sha256.Sum256(body)
	return body, id[:]
}

// A Live over the sets the test names: an object in live is live, one in failing fails, anything else is not.
func testDropLive(live [][]byte, failing [][]byte, failure error) func(ctx context.Context, object SidecarDropObject) (bool, error) {
	return func(ctx context.Context, object SidecarDropObject) (bool, error) {
		for _, id := range failing {
			if bytes.Equal(id, object.Id) {
				return false, failure
			}
		}
		for _, id := range live {
			if bytes.Equal(id, object.Id) {
				return true, nil
			}
		}
		return false, nil
	}
}

// Whether the mirror holds key.
func testDropHeld(t *testing.T, mirror *EvsMirrorStore, key EvsMirrorKey) bool {
	t.Helper()
	held, err := mirror.Has(key)
	if err != nil {
		t.Fatal(err)
	}
	return held
}

// §11.7's rule row (FI-27): an executed drop deletes from the sealed mirror the segments and slot copies only listed
// versions name, and keeps every one a live version also names (the kept head's re-cited chunk, a slot a copy on
// another ref shares) and every one Live could not answer for, whose error it answers; the head's own segment is not
// touched; inline records stay, counted, for the mirror's statement-only rule.
func TestDropKeepsSharedChunks(t *testing.T) {
	world := newSearchTestSidecar(t, nil)
	ctx := t.Context()
	repoId := evsTestId("drop repo")
	mirror := evsTestMirror(t, newEvsTestStore(t), repoId)
	onlyBody, onlyId := testDropSegment("only listed")
	sharedBody, sharedId := testDropSegment("re-cited by the head")
	headBody, headId := testDropSegment("the head's own")
	failingBody, failingId := testDropSegment("live unanswered")
	for _, segment := range []struct {
		body []byte
		id   []byte
	}{{onlyBody, onlyId}, {sharedBody, sharedId}, {headBody, headId}, {failingBody, failingId}} {
		if err := mirror.Put(EvsMirrorSegmentKey(segment.id), bytes.NewReader(segment.body)); err != nil {
			t.Fatal(err)
		}
	}
	onlySlot, sharedSlot := evsTestId("slot only listed"), evsTestId("slot shared")
	for _, slotId := range []Id{onlySlot, sharedSlot} {
		if err := mirror.Put(EvsMirrorSlotKey(slotId.Bytes()), bytes.NewReader(evsTestMirrorBody("slot "+slotId.String(), 200))); err != nil {
			t.Fatal(err)
		}
	}
	liveFailure := errors.New("the live versions could not be read")
	drop := &SidecarExecutedDrop{
		RepoId: repoId, RefId: evsTestId("drop ref"), DropId: evsTestId("drop"),
		NotBefore: world.clock.Now().Add(-time.Hour),
		Versions: []*SidecarDroppedVersion{
			{Path: "notes/a.md", Version: 1, SegmentIds: [][]byte{onlyId, sharedId}, SlotIds: []Id{onlySlot, sharedSlot}},
			{Path: "notes/a.md", Version: 2, SegmentIds: [][]byte{failingId, sharedId},
				InlineRecords: []SidecarDroppedInline{{PushId: evsTestId("push"), Part: 0, Index: 3}, {PushId: evsTestId("push"), Part: 0, Index: 4}}},
		},
		Mirror: mirror,
		Live:   testDropLive([][]byte{sharedId, sharedSlot.Bytes()}, [][]byte{failingId}, liveFailure),
	}
	applied, err := world.sidecar.ApplyExecutedDrop(ctx, drop)
	if !errors.Is(err, liveFailure) {
		t.Fatalf("the unanswered liveness: %v", err)
	}
	if testDropHeld(t, mirror, EvsMirrorSegmentKey(onlyId)) || testDropHeld(t, mirror, EvsMirrorSlotKey(onlySlot.Bytes())) {
		t.Error("a copy only listed versions name stays")
	}
	for _, key := range []EvsMirrorKey{EvsMirrorSegmentKey(sharedId), EvsMirrorSegmentKey(headId), EvsMirrorSegmentKey(failingId), EvsMirrorSlotKey(sharedSlot.Bytes())} {
		if !testDropHeld(t, mirror, key) {
			t.Errorf("a %s a live version names, or Live could not judge, went", key.Family)
		}
	}
	if applied.SegmentCount != 1 || applied.SlotCount != 1 || applied.KeptCount != 3 || applied.InlineCount != 2 {
		t.Errorf("applied %+v", applied)
	}

	// a drop with no liveness check deletes nothing at all
	drop.Live = nil
	if _, err := world.sidecar.ApplyExecutedDrop(ctx, drop); !errors.Is(err, ErrSidecarDropArgs) {
		t.Errorf("a drop with no Live: %v", err)
	}
	if !testDropHeld(t, mirror, EvsMirrorSegmentKey(sharedId)) {
		t.Error("a drop with no Live deleted")
	}
	drop.Live = testDropLive(nil, nil, nil)
	drop.Mirror = evsTestMirror(t, newEvsTestStore(t), evsTestId("another repo"))
	if _, err := world.sidecar.ApplyExecutedDrop(ctx, drop); !errors.Is(err, ErrSidecarDropArgs) {
		t.Errorf("another repo's mirror: %v", err)
	}
}

// A drop holder that keeps sealed copies of plaintext in file class restore, under restore/<run_id>/ of the network's
// store as §16.7's restore points do, each named by its bytes' SHA-256, and deletes those an executed drop drops.
type testRestoreDropHolder struct {
	store SidecarStore

	stateLock sync.Mutex
	applied   int
	failure   error
}

func newTestRestoreDropHolder(t *testing.T, network SidecarStore, runId Id) *testRestoreDropHolder {
	t.Helper()
	store, err := network.Directory("restore/"+hex.EncodeToString(runId[:]), "restore")
	if err != nil {
		t.Fatal(err)
	}
	return &testRestoreDropHolder{store: store}
}

// Keeps a sealed copy of content, as a point's base walk does.
func (self *testRestoreDropHolder) keep(t *testing.T, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	name := "base/" + hex.EncodeToString(sum[:])
	writer, err := self.store.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	return name
}

// The copies held, by name.
func (self *testRestoreDropHolder) names(t *testing.T) []string {
	t.Helper()
	entries, err := self.store.List("")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}

func (self *testRestoreDropHolder) ApplyExecutedDrop(ctx context.Context, drop *SidecarExecutedDrop) error {
	self.stateLock.Lock()
	self.applied += 1
	failure := self.failure
	self.stateLock.Unlock()
	if failure != nil {
		return failure
	}
	entries, err := self.store.List("base/")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		sum, err := hex.DecodeString(strings.TrimPrefix(entry.Name, "base/"))
		if err != nil || len(sum) != sha256.Size {
			continue
		}
		dropped, err := drop.DroppedContent(ctx, [sha256.Size]byte(sum))
		if err != nil {
			return err
		}
		if dropped {
			if err := self.store.Remove(entry.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// The times it was reached.
func (self *testRestoreDropHolder) appliedCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.applied
}

// §16.7's never row with D-CORE-19: a restore point's decrypted copy of a listed version goes with the drop, through
// the holder the root reaches since it cannot import mcp/; a copy whose bytes a live version shares, a revert to them,
// stays, as does a copy of no listed version. A holder's error is answered while the rest applies, and a removed holder
// is not reached again.
func TestDropDeletesRestorePointCopy(t *testing.T) {
	world := newSearchTestSidecar(t, nil)
	ctx := t.Context()
	network := world.instance.Store(&world.networkId)
	holder := newTestRestoreDropHolder(t, network, evsTestId("run"))
	remove, err := world.sidecar.AddDropHolder(holder)
	if err != nil {
		t.Fatal(err)
	}
	dropped := []byte("the first draft, which the drop lists\n")
	reverted := []byte("the second draft, listed, and the head reverts to it\n")
	unlisted := []byte("a file no listed version holds\n")
	droppedName := holder.keep(t, dropped)
	revertedName := holder.keep(t, reverted)
	unlistedName := holder.keep(t, unlisted)
	revertedSum := sha256.Sum256(reverted)
	drop := &SidecarExecutedDrop{
		RepoId: evsTestId("restore repo"), RefId: evsTestId("restore ref"), DropId: evsTestId("drop"),
		NotBefore: world.clock.Now(),
		Versions: []*SidecarDroppedVersion{
			{Path: "src/main.go", Version: 1, ContentSha256: sha256.Sum256(dropped)},
			{Path: "src/main.go", Version: 2, ContentSha256: revertedSum},
		},
		Live: testDropLive([][]byte{revertedSum[:]}, nil, nil),
	}
	if _, err := world.sidecar.ApplyExecutedDrop(ctx, drop); err != nil {
		t.Fatal(err)
	}
	names := holder.names(t)
	if slices.Contains(names, droppedName) || !slices.Contains(names, revertedName) || !slices.Contains(names, unlistedName) {
		t.Fatalf("the restore point after the drop: %v", names)
	}

	failure := errors.New("the restore point is busy")
	holder.stateLock.Lock()
	holder.failure = failure
	holder.stateLock.Unlock()
	if _, err := world.sidecar.ApplyExecutedDrop(ctx, drop); !errors.Is(err, failure) {
		t.Errorf("a holder's error: %v", err)
	}
	remove()
	before := holder.appliedCount()
	if _, err := world.sidecar.ApplyExecutedDrop(ctx, drop); err != nil {
		t.Fatal(err)
	}
	if holder.appliedCount() != before {
		t.Error("a removed holder was reached")
	}
	if _, err := world.sidecar.AddDropHolder(nil); !errors.Is(err, ErrSidecarDropArgs) {
		t.Errorf("no holder: %v", err)
	}
}

// §11.7's states row with D-CORE-19: nothing applies before the window passes on this device's clock, nor for a drop a
// cancel names or evs reports refused; a device offline at the drop applies it when it syncs, days later: the mirror's
// copies, the index file versions the DROP's rewrites replaced with their derived data, the repo's retained buckets and
// the local layer's entries of listed versions go, its sealed copy written again, and the repo's searches end; a
// second application at the next sync deletes nothing more and fails nothing.
func TestOfflineDropAppliesAtSync(t *testing.T) {
	world := newSearchTestSidecar(t, nil)
	ctx := t.Context()
	repoId, refId := evsTestId("offline repo"), evsTestId("offline ref")
	cache, err := world.sidecar.SearchCache()
	if err != nil {
		t.Fatal(err)
	}
	ended := []Id{}
	endedLock := sync.Mutex{}
	refKey := testSearchRefKey("offline")
	layer, err := NewSearchLocalLayer(&SearchLocalLayerArgs{RepoId: repoId, RefId: refId, RefKey: refKey})
	if err != nil {
		t.Fatal(err)
	}
	layerKey := SearchCacheKey{RepoId: repoId, RefId: refId, Path: SearchCacheRefPath}
	removeHooks, err := cache.AddDeleteHooks(&SearchDeleteHooks{
		EndRepo: func(endedRepoId Id) {
			endedLock.Lock()
			defer endedLock.Unlock()
			ended = append(ended, endedRepoId)
		},
		LocalLayer: func(askedRepoId Id, askedRefId Id) (*SearchLocalLayer, SearchCacheKey) {
			if askedRepoId == repoId && askedRefId == refId {
				return layer, layerKey
			}
			return nil, SearchCacheKey{}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer removeHooks()
	normalizer := testSearchNormalizer(t)
	listedDocuments, ok := indexExtractFile([]byte("notes/old.md"), []byte("# Old\nthe listed draft\n"), DefaultIndexFormatSettings())
	if !ok {
		t.Fatal("no text")
	}
	if err := layer.Index(normalizer, &SearchLocalVersion{RefId: refId, Path: []byte("notes/old.md"), Version: 2, TimeMs: 1800000000000, Documents: listedDocuments}); err != nil {
		t.Fatal(err)
	}
	listedKey, err := indexDocKey(refKey, refId, []byte("notes/old.md"), 0)
	if err != nil {
		t.Fatal(err)
	}
	replacedKey := SearchCacheKey{RepoId: repoId, RefId: refId, Path: ".ur-index/i1/b/20080/w/aa/1", Version: 3}
	replaced := newTestSearchRecord(t, replacedKey, SearchCachePartition{StartDay: 20080}, testSearchPlaintext("the replaced head", 1200))
	if err := cache.PutRecord(ctx, replaced.record); err != nil {
		t.Fatal(err)
	}
	if err := cache.PutDerived(ctx, &SearchCacheDerived{Key: replacedKey, Part: SearchCachePartBlockIndex, Plaintext: testSearchPlaintext("blocks", 500)}); err != nil {
		t.Fatal(err)
	}
	if err := layer.Save(ctx, cache, layerKey); err != nil {
		t.Fatal(err)
	}
	if err := cache.RetainBucket(repoId, refId, 20073, 7, world.clock.Now()); err != nil {
		t.Fatal(err)
	}
	mirror := evsTestMirror(t, newEvsTestStore(t), repoId)
	segmentBody, segmentId := testDropSegment("listed")
	if err := mirror.Put(EvsMirrorSegmentKey(segmentId), bytes.NewReader(segmentBody)); err != nil {
		t.Fatal(err)
	}
	drop := &SidecarExecutedDrop{
		RepoId: repoId, RefId: refId, DropId: evsTestId("drop"),
		NotBefore: world.clock.Now().Add(7 * 24 * time.Hour),
		Versions: []*SidecarDroppedVersion{
			{Path: "notes/old.md", Version: 2, SegmentIds: [][]byte{segmentId}, IndexRefId: refId, DocKeys: [][indexIdByteCount]byte{listedKey}},
		},
		IndexReplaced: []SearchCacheKey{replacedKey},
		Mirror:        mirror,
		Live:          testDropLive(nil, nil, nil),
	}
	held := func() bool {
		held, err := cache.Ref(repoId, refId)
		if err != nil {
			t.Fatal(err)
		}
		return testDropHeld(t, mirror, EvsMirrorSegmentKey(segmentId)) && held != nil && len(held.Files) == 1 && len(held.Retained) == 1
	}
	if _, err := world.sidecar.ApplyExecutedDrop(ctx, drop); !errors.Is(err, ErrSidecarDropNotExecuted) || !held() {
		t.Fatalf("a drop inside its window: %v", err)
	}
	world.clock.advance(9 * 24 * time.Hour)
	for _, void := range []func(drop *SidecarExecutedDrop){
		func(drop *SidecarExecutedDrop) { drop.Cancelled = true },
		func(drop *SidecarExecutedDrop) { drop.Refused = true },
	} {
		voided := *drop
		void(&voided)
		if _, err := world.sidecar.ApplyExecutedDrop(ctx, &voided); !errors.Is(err, ErrSidecarDropNotExecuted) || !held() {
			t.Fatalf("a cancelled or refused drop: %v", err)
		}
	}

	// the device was offline at the drop; it syncs now
	applied, err := world.sidecar.ApplyExecutedDrop(ctx, drop)
	if err != nil {
		t.Fatal(err)
	}
	if applied.SegmentCount != 1 || applied.CacheFileCount != 1 {
		t.Fatalf("applied %+v", applied)
	}
	if testDropHeld(t, mirror, EvsMirrorSegmentKey(segmentId)) {
		t.Error("the mirror keeps the listed segment")
	}
	if _, err := cache.OpenRecord(replacedKey); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("the replaced index file stays: %v", err)
	}
	if _, err := cache.OpenDerived(replacedKey, SearchCachePartBlockIndex); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("the replaced index file's derived data stays: %v", err)
	}
	refHeld, err := cache.Ref(repoId, refId)
	if err != nil || refHeld == nil || len(refHeld.Retained) != 0 {
		t.Errorf("the retained buckets stay: %+v, %v", refHeld, err)
	}
	if _, _, ok := layer.newest(listedKey); ok {
		t.Error("the local layer keeps a listed version's entry")
	}
	sealed, err := NewSearchLocalLayer(&SearchLocalLayerArgs{RepoId: repoId, RefId: refId, RefKey: refKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := sealed.Load(cache, layerKey); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := sealed.newest(listedKey); ok {
		t.Error("the sealed local layer keeps a listed version's entry")
	}
	endedLock.Lock()
	endedRepos := slices.Clone(ended)
	endedLock.Unlock()
	if len(endedRepos) < 2 || endedRepos[0] != repoId {
		t.Errorf("the repo's searches ended %v", endedRepos)
	}

	again, err := world.sidecar.ApplyExecutedDrop(ctx, drop)
	if err != nil || *again != (SidecarDropApplied{}) {
		t.Errorf("the next sync's application: %+v, %v", again, err)
	}
}

// history_drop's plumbing (§11.7's states row, §18.5's Drops listing): each state's event names the repo, ref and drop;
// pending its window's end; invalid its signer, which it must; any other state, or none of a drop, raises nothing. The
// client's raise reaches its sink. evs's report maps to the states a device shows, a held drop, reported done, and
// observe mode's reading done.
func TestHistoryDropEventPlumbing(t *testing.T) {
	world := newSearchTestSidecar(t, nil)
	repoId, refId, dropId, signerId := evsTestId("drop repo"), evsTestId("drop ref"), evsTestId("drop"), evsTestId("signer")
	notBefore := world.clock.Now().Add(7 * 24 * time.Hour)
	if err := world.sidecar.raiseHistoryDrop(&SidecarHistoryDrop{RepoId: repoId, RefId: refId, DropId: dropId, State: SidecarDropPending, Path: "notes/a.md", NotBefore: notBefore}); err != nil {
		t.Fatal(err)
	}
	if err := world.sidecar.raiseHistoryDrop(&SidecarHistoryDrop{RepoId: repoId, RefId: refId, DropId: dropId, State: SidecarDropInvalid, SignerSidecarId: &signerId}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []*SidecarHistoryDrop{
		{RepoId: repoId, RefId: refId, DropId: dropId, State: SidecarDropInvalid},
		{RepoId: repoId, RefId: refId, DropId: dropId, State: SidecarDropPending},
		{RepoId: repoId, RefId: refId, DropId: dropId, State: "held"},
		{RepoId: repoId, RefId: refId, State: SidecarDropDone},
		nil,
	} {
		if err := world.sidecar.raiseHistoryDrop(bad); !errors.Is(err, ErrSidecarDropArgs) {
			t.Errorf("a malformed history_drop %+v: %v", bad, err)
		}
	}
	events := world.raised()
	if len(events) != 2 {
		t.Fatalf("%d events", len(events))
	}
	pending, invalid := events[0], events[1]
	if pending.Kind != SidecarEventHistoryDrop || *pending.RepoId != repoId || *pending.RefId != refId || *pending.DropId != dropId ||
		pending.DropState != SidecarDropPending || !pending.NotBefore.Equal(notBefore) || pending.Path != "notes/a.md" || pending.SidecarId != nil {
		t.Errorf("pending %+v", pending)
	}
	if invalid.DropState != SidecarDropInvalid || invalid.SidecarId == nil || *invalid.SidecarId != signerId {
		t.Errorf("invalid %+v", invalid)
	}

	client := newEvsTestClient(t, http.NotFoundHandler(), newEvsTestStore(t))
	if err := client.client.raiseHistoryDrop(&SidecarHistoryDrop{RepoId: repoId, RefId: refId, DropId: dropId, State: SidecarDropDone}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range *client.events {
		found = found || (event.Kind == SidecarEventHistoryDrop && event.DropState == SidecarDropDone && *event.DropId == dropId)
	}
	if !found {
		t.Error("the client's history_drop did not reach its sink")
	}

	for state, want := range map[protocol.EvsDropState]SidecarDropState{
		protocol.EvsDropState_EVS_DROP_PENDING:   SidecarDropPending,
		protocol.EvsDropState_EVS_DROP_CANCELLED: SidecarDropCancelled,
		protocol.EvsDropState_EVS_DROP_EXECUTING: SidecarDropExecuting,
		protocol.EvsDropState_EVS_DROP_DONE:      SidecarDropDone,
		protocol.EvsDropState_EVS_DROP_OBSERVED:  SidecarDropDone,
		protocol.EvsDropState_EVS_DROP_REFUSED:   SidecarDropRefused,
	} {
		if got, ok := SidecarDropStateOf(state); !ok || got != want {
			t.Errorf("%s reads %q", state, got)
		}
	}
	if _, ok := SidecarDropStateOf(protocol.EvsDropState_EVS_DROP_STATE_UNSPECIFIED); ok {
		t.Error("an unspecified state reads as one")
	}
}
