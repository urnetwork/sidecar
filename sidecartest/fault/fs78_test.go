//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-78 on T2 (§11.14's erase, bound, holds and limit rows; §11.12's closure, rekey, versionless and bytes rows;
// §11.13's wait row; D-EVS-26, D-EVS-48, FI-5, FI-19; SEARCH-M10-37): an admin's erasure of one document at the exact
// storage limit and spent, the eraser at evs_closure_bytes_floor, on the search world under a slot-keyed repo's keys
// (search_erase_testhooks.go), the index's own eraser cutting and rewriting.
//
//	limit     the CUT and the first ERASE, of the document's own keys, commit at once at the limit; the document is
//	          masked from the CUT on a desktop, a phone and a daemon whose cache held it; CLOSURE pushes rewrite every
//	          index file holding it in place, each at its replaced length, each upload at most 1,088 KiB, then ERASEs
//	          destroy the old keys; its postings open to key holders until their part's ERASE and never after; the old
//	          ciphertext goes PurgeAfter after its CLOSURE and the staged bytes with their batch; the erasure completes
//	          within the next 00:00 UTC and two turns, the bound §11.13's wait row gives a one-document message
//	companion a companion push built before the CUT is refused 409 INDEX_EPOCH, and its rebuild, which waits at the limit,
//	          commits without the document once under it
//	windows   a note edited across three windows and rolled into all has every all file holding any of its versions
//	          rewritten, the versions a hold kept included
//	hold      under a hold the keys go at once and the ciphertext stays, unreadable
//	forged    a CLOSURE creating a path, or growing a file past its replaced length, is refused
//	after     the document stays gone through later pushes and a merge (FI-5), and FI-19's sweep finds no stored
//	          version a reader's keys open holding it
//
// Not here, each named for what it waits on: the mailbox and the vault themselves (the world is a file-mode ref's index
// under a slot-keyed repo's keys, as a group inbox keeps it; the mailbox case at the later of M10-out and M7-out, the
// record-class index on ur/index with RECORD-M10-01 and MAIL-M10-02's callers); a reader dropping its local overlay,
// vocabulary entries, a retained bucket and journaled companion entries on the ERASE's hint (CORE-M10-04's
// SearchCache.ApplyErase and the host's SearchDeleteHooks, not wired; the world's devices hear no hint and mask by the
// set at their next round); an iOS-only eraser fetching only the files holding the document (the eraser finds all's
// shards by reading every doc table, not a/m's days: SEARCH-M10-17's draft); a shard whose canonical rebuild in blocks
// of 64 outgrows its replaced length, which TestRewriteWithoutTheProbeKeepsThePartition and
// TestRewriteWithoutOnRandomShards hold to the replaced partition and pad_generation; an ephemeral sidecar's cache on
// a "search more" past MemoryBudgetByteCount (FS-109's heap harness); FI-13c's stored bytes after the nightly pass
// (evs's usage, T3); and the deletion of a file in a CLOSURE, which the eraser's seam cannot express.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// evs_closure_bytes_floor (§20.4): 4 MiB a UTC day, which no §21 rule lowers.
const fs78ClosureBytesFloor = int64(4 * 1024 * 1024)

// Puts the world at the exact storage limit and spent: every push adding payload refused, a CUT aside, which is
// maintenance; each eraser's closure allowance at the floor.
func (self *fsEraseWorld) atTheLimit() {
	self.index.SetStorageLimit(func(shape sidecar.SearchTestPushShape) bool {
		return !shape.Cut && (0 < shape.FileCount || shape.Content)
	})
	self.erasure.SetClosureAllowance(fs78ClosureBytesFloor)
}

// Takes the world under the limit.
func (self *fsEraseWorld) underTheLimit() {
	self.index.SetStorageLimit(nil)
	self.erasure.SetClosureAllowance(0)
}

// Runs erasureId's rewrite to its end at the limit: each wait moves the clock to its next try and runs the rewrite
// again, on a fresh eraser of signer after the restartAfter'th wait (0 never), as its device starting again; onWait,
// nil for none, runs at each wait before the clock moves. The waits it met, in order.
func (self *fsEraseWorld) rewriteAtTheLimit(t *testing.T, signer sidecar.Id, erasureId sidecar.Id, restartAfter int, events *[]sidecar.SidecarErasure, onWait func(waiting sidecar.SidecarErasure)) []sidecar.SidecarErasure {
	t.Helper()
	ctx := t.Context()
	eraser := self.eraser(t, signer, events)
	waits := []sidecar.SidecarErasure{}
	for range 64 {
		result, err := eraser.Rewrite(ctx, &sidecar.IndexRewriteArgs{ErasureId: erasureId, Complete: true, Note: []byte("note")})
		if err != nil {
			t.Fatal(err)
		}
		if result.Erasure == nil {
			t.Fatal("a rewrite with no state")
		}
		if result.Erasure.State != sidecar.SidecarErasureWaiting {
			if !self.erasure.Complete(erasureId) {
				t.Fatalf("the rewrite ended %s with no complete ERASE", result.Erasure.State)
			}
			return waits
		}
		waits = append(waits, *result.Erasure)
		if onWait != nil {
			onWait(*result.Erasure)
		}
		if wait := result.Erasure.NextTry.Sub(self.clock.Now()); 0 < wait {
			self.clock.Advance(wait)
		}
		if len(waits) == restartAfter {
			eraser = self.eraser(t, signer, events)
		}
	}
	t.Fatal("the rewrite never finished")
	return nil
}

// Checks, at each part of a rewrite, that the versions its CLOSURE replaced still open to key holders until its ERASE
// commits and never after: what the hooks saw, as errors.
type fs78Parts struct {
	erasure   *sidecar.SearchTestErasure
	stateLock sync.Mutex
	// the files the newest CLOSURE replaced, as path and version
	replaced []sidecar.SearchTestRewritten
	// the parts watched to their ERASE
	partCount int
	errs      []error
}

// Watches hooks' closed and erased barriers.
func newFs78Parts(hooks *fsEraseHooks, erasure *sidecar.SearchTestErasure) *fs78Parts {
	parts := &fs78Parts{erasure: erasure}
	hooks.onBarrier = func(name string) {
		switch name {
		case "evs.index.erase.closed":
			parts.closed()
		case "evs.index.erase.erased":
			parts.erased()
		}
	}
	return parts
}

// A CLOSURE committed: the versions it replaced still open.
func (self *fs78Parts) closed() {
	closures := self.erasure.Closures()
	newest := closures[len(closures)-1].RefVersion
	replaced := []sidecar.SearchTestRewritten{}
	for _, rewritten := range self.erasure.Rewritten() {
		if rewritten.CommitVersion == newest {
			replaced = append(replaced, rewritten)
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.replaced = replaced
	for _, file := range replaced {
		if !self.erasure.Openable(file.Path, file.Version-1) {
			self.errs = append(self.errs, fmt.Errorf("%s@%d no longer opens before its part's ERASE", file.Path, file.Version-1))
		}
	}
}

// An ERASE committed: none of the versions its part's CLOSURE replaced opens.
func (self *fs78Parts) erased() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, file := range self.replaced {
		if self.erasure.Openable(file.Path, file.Version-1) {
			self.errs = append(self.errs, fmt.Errorf("%s@%d still opens after its part's ERASE", file.Path, file.Version-1))
		}
	}
	if 0 < len(self.replaced) {
		self.partCount += 1
	}
	self.replaced = nil
}

// What the watch saw go wrong, and an error where it watched no part to its ERASE.
func (self *fs78Parts) err() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.partCount == 0 {
		return errors.Join(append(self.errs, errors.New("no CLOSURE and ERASE part was watched"))...)
	}
	return errors.Join(self.errs...)
}

// A device of host that synced the world now: a daemon or a phone whose cache holds the world's files.
func (self *fsEraseWorld) syncedDevice(t *testing.T, host string) *sidecar.SearchTestDevice {
	t.Helper()
	device, err := self.device(t.Context(), searchHostNamed(host), nil, nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { self.done(device) })
	if err := device.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	return device
}

// FS-78's limit clause, the row's base case on T2: see the file header's limit, companion and after rows.
func TestFs78(t *testing.T) {
	world := newFsEraseWorld(t, "fs78 limit", nil)
	ctx := t.Context()
	hooks := newFsEraseHooks(t)
	now := world.clock.Now()
	// the email: in its writer's head, and in the bucket's shards beside other mail once a merge absorbs the seals
	email := fsIndexDocument("mail/kestrel.eml", 1, "kestrel", now)
	world.fillSeals(t, searchId("writer s"), "seal", 160, now)
	world.push(t, searchId("writer w"), email)
	if merged, err := world.index.Merge(ctx, searchId("merger"), 0); err != nil || merged == 0 {
		t.Fatalf("the merge: %d, %v", merged, err)
	}
	world.push(t, searchId("writer w"), fsIndexDocument("mail/osprey.eml", 1, "osprey", now))
	erased := []*fsErased{fsErasedOf(t, world.searchWorld, email.Path, 1)}
	queries := []string{"kestrel"}
	daemon := world.syncedDevice(t, "desktop")
	phone := world.syncedDevice(t, "ios32")
	for _, device := range []*sidecar.SearchTestDevice{daemon, phone} {
		if hits := world.searchOn(t, device, "kestrel"); len(hits) != 1 {
			t.Fatalf("before the erasure a device found %v", hits)
		}
	}
	companion, err := world.index.PlanPush(ctx, searchId("writer a"), now, []*sidecar.SearchTestDocument{email})
	if err != nil {
		t.Fatal(err)
	}

	// at the limit and spent: the CUT and the first ERASE land at once
	world.atTheLimit()
	start := world.clock.Now()
	erasureId := searchId("fs78 erasure")
	cutVersion := world.cut(t, world.eraser(t, sidecar.Id{}, nil), erasureId, erased)
	if err := world.erasure.EraseOwnKeys(ctx, world.index.AdminId(), erasureId, []string{email.Path}, false); err != nil {
		t.Fatal(err)
	}
	if world.erasure.ContentOpens(email.Path) {
		t.Fatal("the email's body opens after its first ERASE")
	}
	if !world.clock.Now().Equal(start) {
		t.Fatal("the CUT or the first ERASE waited at the limit")
	}
	for _, device := range []*sidecar.SearchTestDevice{daemon, phone} {
		if hits := world.searchOn(t, device, "kestrel"); 0 < len(hits) {
			t.Fatalf("from the CUT a device whose cache held the email found %v", hits)
		}
	}
	world.checkSearch(t, "kestrel")

	// the companion push built before the CUT: 409 INDEX_EPOCH, its rebuild waiting at the limit
	if _, err := companion.Commit(ctx); !errors.Is(err, sidecar.ErrSearchTestIndexEpoch) {
		t.Fatalf("a companion push built before the CUT: %v", err)
	}
	if err := world.index.PushDocuments(ctx, searchId("writer a"), world.clock.Now(), []*sidecar.SearchTestDocument{email, fsIndexDocument("mail/plover.eml", 1, "plover", now)}); err == nil {
		t.Fatal("a rebuilt companion push adding payload committed at the limit")
	}

	// the rewrite, each part's replaced versions opening until its ERASE
	parts := newFs78Parts(hooks, world.erasure)
	waits := world.rewriteAtTheLimit(t, sidecar.Id{}, erasureId, 0, nil, nil)
	hooks.onBarrier = nil
	if err := parts.err(); err != nil {
		t.Fatal(err)
	}
	erases := world.erasure.Erases()
	last := erases[len(erases)-1].At
	bound := start.UTC().Truncate(24 * time.Hour).Add(24*time.Hour + 2*sidecar.DefaultIndexEraseSettings().PacingTurn)
	if last.After(bound) || 1 < len(waits) {
		t.Fatalf("a one-document erasure's last ERASE at %v after %d waits, past the next 00:00 UTC and two turns, %v", last, len(waits), bound)
	}
	rewritten := world.erasure.Rewritten()
	if len(rewritten) < 2 {
		t.Fatalf("the CLOSUREs rewrote %d files, the email standing in its writer's head and the bucket's shards", len(rewritten))
	}
	for _, file := range rewritten {
		if file.ByteCount != file.ReplacedByteCount || 1088*1024 < file.ByteCount {
			t.Fatalf("%s@%d rewrote %d B in place of %d B", file.Path, file.Version, file.ByteCount, file.ReplacedByteCount)
		}
	}
	if err := fsEraseFence(world.erasure, cutVersion, erased); err != nil {
		t.Fatal(err)
	}
	if err := fsEraseSweep(world.erasure, erased, false); err != nil {
		t.Fatal(err)
	}

	// the old ciphertext goes a minute after its CLOSURE, the staged bytes with their batch
	world.clock.Advance(61 * time.Second)
	holding, err := world.erasure.Holding(fsCutDocuments(erased))
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range holding {
		if version.Stored {
			t.Fatalf("%s@%d's ciphertext stays a minute past its CLOSURE", version.Path, version.Version)
		}
	}
	world.clock.Advance(26 * time.Hour)
	if holding, err = world.erasure.Holding(fsCutDocuments(erased)); err != nil {
		t.Fatal(err)
	}
	for _, version := range holding {
		if version.Stored || version.Staged {
			t.Fatalf("%s@%d stays past its batch's 26 h", version.Path, version.Version)
		}
	}

	// under the limit the rebuilt companion push commits, without the email; the email never returns (FI-5)
	world.underTheLimit()
	plover := fsIndexDocument("mail/plover.eml", 1, "plover", world.clock.Now())
	if err := world.index.PushDocuments(ctx, searchId("writer a"), world.clock.Now(), []*sidecar.SearchTestDocument{email, plover}); err != nil {
		t.Fatal(err)
	}
	if err := world.record(world.clock.Now(), plover); err != nil {
		t.Fatal(err)
	}
	world.fillSeals(t, searchId("writer s"), "later", 40, world.clock.Now())
	if _, err := world.index.Merge(ctx, searchId("merger"), 0); err != nil {
		t.Fatal(err)
	}
	if err := fsEraseFence(world.erasure, cutVersion, erased); err != nil {
		t.Fatal(err)
	}
	for _, device := range []*sidecar.SearchTestDevice{daemon, phone} {
		if hits := world.searchOn(t, device, "kestrel"); 0 < len(hits) {
			t.Fatalf("after the erasure a device found %v", hits)
		}
	}
	world.fsEraseFreshDevice(t, world.erasure, erased, queries)
	world.checkSearch(t, "plover")
	world.checkSearch(t, "osprey")
}

// FS-78's windows clause: a note edited in three windows, each version rolled into all in turn under a hold placed
// after the first roll-up, has every all file holding any of its versions rewritten and every key of theirs
// destroyed, the held versions' included.
func TestFs78ANoteEditedAcrossWindowsHasEveryAllFileRewritten(t *testing.T) {
	world := newFsEraseWorld(t, "fs78 windows", nil)
	ctx := t.Context()
	a := searchId("writer a")
	note := "notes/heron.md"
	for version := uint64(1); version <= 3; version += 1 {
		document := fsIndexDocument(note, version, fmt.Sprintf("heron%d", version), world.clock.Now())
		world.push(t, a, document)
		world.push(t, a, fsIndexDocument(fmt.Sprintf("notes/filler-%d.md", version), 1, fmt.Sprintf("filler%d", version), world.clock.Now()))
		world.clock.Advance(31 * 24 * time.Hour)
	}
	// every bucket expires; each roll-up takes the oldest, and the hold keeps all as the first left it
	world.clock.Advance(100 * 24 * time.Hour)
	held := false
	for range 8 {
		result, err := world.index.RollUpResult(ctx, searchId("indexer"))
		if err != nil {
			t.Fatal(err)
		}
		if result.Version == 0 {
			break
		}
		if !held {
			world.erasure.SetHold(true)
			held = true
		}
	}
	if days, err := world.index.BucketStartDays(ctx); err != nil || 0 < len(days) {
		t.Fatalf("buckets %v stand after the roll-ups, %v", days, err)
	}
	erased := []*fsErased{fsErasedOf(t, world.searchWorld, note, 3)}
	before, err := world.erasure.Holding(fsCutDocuments(erased))
	if err != nil {
		t.Fatal(err)
	}
	allVersions := 0
	for _, version := range before {
		if fs75IsAll(version.Path) && (version.Live || version.Held) {
			allVersions += 1
		}
	}
	if allVersions < 2 {
		t.Fatalf("all's files held the note's versions %d times, live or held: %+v", allVersions, before)
	}
	b := world.eraser(t, sidecar.Id{}, nil)
	erasureId := searchId("fs78 windows erasure")
	world.cut(t, b, erasureId, erased)
	fsRewriteAll(t, b, erasureId, true)
	if err := fsEraseSweep(world.erasure, erased, true); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 3; version += 1 {
		world.checkSearch(t, fmt.Sprintf("heron%d", version))
	}
	world.checkSearch(t, "filler2")
}

// FS-78's hold clause: under a hold the erasure's keys go at once, its first ERASE's and every pair's, and the
// ciphertext the hold keeps stays, unreadable.
func TestFs78UnderAHoldTheKeysGoAtOnceAndTheCiphertextStays(t *testing.T) {
	world := newFsEraseWorld(t, "fs78 hold", nil)
	ctx := t.Context()
	email := fsIndexDocument("mail/kestrel.eml", 1, "kestrel", world.clock.Now())
	world.push(t, searchId("writer w"), email)
	world.erasure.SetHold(true)
	erased := []*fsErased{fsErasedOf(t, world.searchWorld, email.Path, 1)}
	b := world.eraser(t, sidecar.Id{}, nil)
	erasureId := searchId("fs78 hold erasure")
	world.cut(t, b, erasureId, erased)
	if err := world.erasure.EraseOwnKeys(ctx, world.index.AdminId(), erasureId, []string{email.Path}, false); err != nil {
		t.Fatal(err)
	}
	if world.erasure.ContentOpens(email.Path) {
		t.Fatal("under a hold the email's own keys stayed")
	}
	fsRewriteAll(t, b, erasureId, true)
	world.clock.Advance(27 * time.Hour)
	holding, err := world.erasure.Holding(fsCutDocuments(erased))
	if err != nil {
		t.Fatal(err)
	}
	kept := 0
	for _, version := range holding {
		if version.Held {
			kept += 1
			if !version.Stored || !version.Destroyed {
				t.Fatalf("under the hold %s@%d: stored %t, key destroyed %t", version.Path, version.Version, version.Stored, version.Destroyed)
			}
		}
	}
	if kept == 0 {
		t.Fatal("the hold kept no version holding the email")
	}
	if err := fsEraseSweep(world.erasure, erased, true); err != nil {
		t.Fatal(err)
	}
	world.checkSearch(t, "kestrel")
}

// FS-78's forged clause: a CLOSURE that creates a path, or grows a file past its replaced length, is refused, and
// one at the replaced length of the same files commits.
func TestFs78AClosureCreatingOrGrowingAFileIsRefused(t *testing.T) {
	world := newFsEraseWorld(t, "fs78 forged", nil)
	ctx := context.Background()
	email := fsIndexDocument("mail/kestrel.eml", 1, "kestrel", world.clock.Now())
	world.push(t, searchId("writer w"), email)
	files, err := world.index.WriterFiles(ctx, searchId("writer w"), 0)
	if err != nil || files.Head == "" {
		t.Fatalf("the writer's files: %+v, %v", files, err)
	}
	admin, erasureId := world.index.AdminId(), searchId("fs78 forged erasure")
	if err := world.erasure.ForgeClosure(ctx, admin, erasureId, []string{files.Head}, 1); err == nil {
		t.Fatal("a CLOSURE growing a file past its replaced length committed")
	}
	if err := world.erasure.ForgeClosure(ctx, admin, erasureId, []string{files.Head + "-created"}, 0); err == nil {
		t.Fatal("a CLOSURE creating a path committed")
	}
	if 0 < len(world.erasure.Closures()) {
		t.Fatal("a refused CLOSURE was recorded")
	}
	if err := world.erasure.ForgeClosure(ctx, admin, erasureId, []string{files.Head}, 0); err != nil {
		t.Fatalf("a CLOSURE at the replaced length: %v", err)
	}
}
