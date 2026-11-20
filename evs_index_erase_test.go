//go:build !ios_extension

package sidecar

// SEARCH-M10-17 (§11.14's erase, bound, holds and limit rows; §11.12's closure, rekey, versionless and reconcile rows;
// §11.13's wait row; FS-78's and FS-112's mechanics at unit level on the fake; DESIGN-DETAILS 15.2.3 to 15.2.7 and
// 15.2.10 with full entries only, QD-1036): clean takes listed entries out at the replaced length, a large entry emptied
// included; the list holds every file holding a listed document; CLOSUREs and ERASEs take them out and destroy every key
// any version of a rewritten path named, so no openable stored version holds a listed entry; pairs stay within the
// eraser's allowance and the finish estimate holds across 00:00 UTC on a fake clock; a crash between a CLOSURE and its
// ERASE resumes with the orphan's ERASE; another device resumes after 25 h and commits a missing CUT; a held version's
// path is rewritten and a removed one's key destroyed; nothing says complete where the history did not walk whole; a
// reproducer rebuilds a slot's CLOSURE and alarms a forged one; and a run card is folded again into the eraser's head.
// On a full cluster (QD-1118), against the stand-in evs behind the limit gate as QD-1088's and QD-1099's DROP tests
// run: evs's 507 CLUSTER_FULL is the index's quota refusal with its Retry-After; a CLOSURE refused it at its upload
// waits until then, and a re-entry refused it at its push waits ReentryRetryInterval, as at the storage limit, each
// raising waiting and going on once there is room; a 507 naming no wait keeps the waits a refusal naming none has.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One version of an index path over the fake ref's history.
type testEraseVersion struct {
	file      *indexFileVersion
	plaintext []byte
	// The ref version it stopped standing at, 0 while it stands, and that push's signed time.
	endedAt uint64
	endedMs int64
	removed bool
	slotId  Id
}

// A (path, entry version) pair.
type testErasePathVersion struct {
	path    string
	version uint64
}

// An erasure's record on the fake.
type testEraseClosure struct {
	erasureId Id
	closed    *indexEraseClosed
}

type testEraseErase struct {
	erasureId Id
	erased    *indexEraseErased
	// A completion ERASE the fake took (QD-1132): it destroyed nothing.
	completion bool
	// The caller's bytes it carried.
	note []byte
}

// One fake evs behind every eraser's handle on a ref (§11.12's rows as the fake models them): every write but a CLOSURE
// reuses its path's slot, a CLOSURE draws a fresh one, and a creation after a removal starts a new life in a new slot;
// a CLOSURE replaces only the newest version of a path, never creates, removes or grows one, and its payload must name
// every slot its replaced versions named; an ERASE destroys what it names, and one naming only keys already gone is
// done (NOTHING_TO_ERASE); a hold keeps every replaced and removed version readable; at the storage limit an eraser's
// CLOSURE bytes stay within its allowance a UTC day, a 429 naming it, and each upload past stagedMax takes a pacing
// turn on the world's clock. Safe for concurrent use.
type testEraseEvs struct {
	ref   *testIndexRef
	world *testHeadWorld

	stateLock sync.Mutex
	// A general repo's versions name no slot.
	slotKeyed bool
	hold      bool
	// Retained also reports versions evs no longer serves, unreadable.
	reportCollected bool
	// Retained answers incomplete.
	retainedIncomplete bool
	closureSlots       map[testErasePathVersion]Id
	destroyed          map[Id]bool
	closures           []*testEraseClosure
	erases             []*testEraseErase
	// The eraser's allowance a UTC day at the limit, 0 below it, and its pacing turn.
	allowance     int64
	allowanceDay  int64
	allowanceUsed int64
	pacingTurn    time.Duration
	stagedMax     int
	// Refusals the next CLOSUREs and ERASEs answer.
	closureRefusals []error
	eraseRefusals   []error
	// Takes no completion ERASE, answering it NOTHING_TO_ERASE as evsservice does until question
	// erasure-completion-erase-evs-cannot-read-complete is answered.
	refusesCompletions bool
	// The world's time at each committed ERASE.
	eraseTimes []time.Time
}

// One eraser's handle on the fake evs: indexEraseStore, and its indexRefStore, which reads a held version a hold keeps.
type testEraseStore struct {
	evs    *testEraseEvs
	handle *testIndexStore
}

func testNewEraseEvs(world *testHeadWorld) *testEraseEvs {
	return &testEraseEvs{
		ref: world.ref, world: world, slotKeyed: true, closureSlots: map[testErasePathVersion]Id{}, destroyed: map[Id]bool{},
		stagedMax: 16 * 1024,
	}
}

// A handle signing as signer.
func (self *testEraseEvs) as(signer Id) *testEraseStore {
	return &testEraseStore{evs: self, handle: self.ref.store(signer)}
}

func (self *testEraseStore) Head(ctx context.Context) (*indexRefHead, error) {
	return self.handle.Head(ctx)
}

func (self *testEraseStore) List(ctx context.Context, refVersion uint64) (*indexListing, error) {
	return self.handle.List(ctx, refVersion)
}

func (self *testEraseStore) History(ctx context.Context, path string, refVersion uint64) ([]*indexFileVersion, error) {
	return self.handle.History(ctx, path, refVersion)
}

func (self *testEraseStore) Commit(ctx context.Context, push *indexPush) (*indexCommitted, error) {
	return self.handle.Commit(ctx, push)
}

func (self *testEraseStore) Read(ctx context.Context, file *indexFileVersion) ([]byte, error) {
	plaintext, err := self.handle.Read(ctx, file)
	if !errors.Is(err, errIndexCollected) {
		return plaintext, err
	}
	self.evs.stateLock.Lock()
	hold := self.evs.hold
	self.evs.stateLock.Unlock()
	if !hold {
		return nil, err
	}
	for _, version := range self.evs.versions()[file.path] {
		if version.file.version == file.version {
			return bytes.Clone(version.plaintext), nil
		}
	}
	return nil, err
}

// Every index path's versions over the ref's history, oldest first, each with the slot it was sealed under.
func (self *testEraseEvs) versions() map[string][]*testEraseVersion {
	self.ref.stateLock.Lock()
	states := slices.Clone(self.ref.states)
	self.ref.stateLock.Unlock()
	self.stateLock.Lock()
	closureSlots := map[testErasePathVersion]Id{}
	for key, slotId := range self.closureSlots {
		closureSlots[key] = slotId
	}
	self.stateLock.Unlock()
	paths := map[string][]*testEraseVersion{}
	newest := func(state *testIndexState, path string) *testIndexFile {
		files := state.files[path]
		if len(files) == 0 {
			return nil
		}
		return files[len(files)-1]
	}
	for index := 1; index < len(states); index += 1 {
		previous, current := states[index-1], states[index]
		seen := map[string]bool{}
		for path := range current.files {
			seen[path] = true
		}
		for path := range previous.files {
			seen[path] = true
		}
		for path := range seen {
			before, after := newest(previous, path), newest(current, path)
			versions := paths[path]
			if after != nil && (before == nil || before.version.version != after.version.version) {
				if before != nil && 0 < len(versions) {
					versions[len(versions)-1].endedAt = uint64(index)
					versions[len(versions)-1].endedMs = current.head.signedTimeMs
				}
				file := *after.version
				versions = append(versions, &testEraseVersion{file: &file, plaintext: after.plaintext})
			}
			if after == nil && before != nil && 0 < len(versions) {
				versions[len(versions)-1].endedAt = uint64(index)
				versions[len(versions)-1].endedMs = current.head.signedTimeMs
				versions[len(versions)-1].removed = true
			}
			paths[path] = versions
		}
	}
	for path, versions := range paths {
		life := 0
		for index, version := range versions {
			slotId, closed := closureSlots[testErasePathVersion{path: path, version: version.file.version}]
			switch {
			case closed:
			case index == 0 || versions[index-1].removed:
				life += 1
				slotId = evsTestId(fmt.Sprintf("slot %s life %d", path, life))
			default:
				slotId = versions[index-1].slotId
			}
			version.slotId = slotId
		}
	}
	return paths
}

// See indexEraseStore: every slot any version of each path named.
func (self *testEraseStore) KeysOf(ctx context.Context, paths []string) ([]*EvsErasedKey, error) {
	self.evs.stateLock.Lock()
	slotKeyed := self.evs.slotKeyed
	self.evs.stateLock.Unlock()
	if !slotKeyed {
		return nil, nil
	}
	versions := self.evs.versions()
	keys := []*EvsErasedKey{}
	named := map[Id]bool{}
	for _, path := range paths {
		for _, version := range versions[path] {
			if !named[version.slotId] {
				named[version.slotId] = true
				keys = append(keys, &EvsErasedKey{SlotId: version.slotId})
			}
		}
	}
	return keys, nil
}

// See indexEraseStore.
func (self *testEraseStore) Retained(ctx context.Context) (*indexRetained, error) {
	self.evs.stateLock.Lock()
	hold, reportCollected, incomplete := self.evs.hold, self.evs.reportCollected, self.evs.retainedIncomplete
	self.evs.stateLock.Unlock()
	retained := &indexRetained{complete: !incomplete}
	if !hold && !reportCollected {
		return retained, nil
	}
	for _, versions := range self.evs.versions() {
		for _, version := range versions {
			if version.endedAt == 0 {
				continue
			}
			file := *version.file
			retained.versions = append(retained.versions, &indexRetainedVersion{
				file: &file, readable: hold, replacedVersion: version.endedAt, replacedMs: version.endedMs,
			})
		}
	}
	return retained, nil
}

// See indexEraseStore.
func (self *testEraseStore) Progress(ctx context.Context, erasureId Id) (*indexEraseProgress, error) {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	progress := &indexEraseProgress{}
	for _, closure := range self.evs.closures {
		if closure.erasureId == erasureId {
			progress.closures = append(progress.closures, closure.closed)
		}
	}
	for _, erase := range self.evs.erases {
		if erase.erasureId == erasureId {
			progress.erases = append(progress.erases, erase.erased)
		}
	}
	return progress, nil
}

// The UTC day of t.
func testUtcDay(t time.Time) int64 {
	return t.UTC().Unix() / (24 * 60 * 60)
}

// See indexEraseStore.
func (self *testEraseStore) Closure(ctx context.Context, closure *indexClosurePush) (*indexCommitted, error) {
	evs := self.evs
	now := evs.world.at
	byteCount := int64(0)
	for _, file := range closure.files {
		byteCount += int64(len(file.plaintext))
	}
	versions := evs.versions()
	err := func() error {
		evs.stateLock.Lock()
		defer evs.stateLock.Unlock()
		if 0 < len(evs.closureRefusals) {
			refusal := evs.closureRefusals[0]
			evs.closureRefusals = evs.closureRefusals[1:]
			return refusal
		}
		if 0 < evs.allowance {
			if day := testUtcDay(now); day != evs.allowanceDay {
				evs.allowanceDay, evs.allowanceUsed = day, 0
			}
			if evs.allowance < evs.allowanceUsed+byteCount {
				return &indexRefusal{
					kind: indexRefusalRetry, retryAfter: indexNextUtcMidnight(now).Sub(now),
					quota: &QuotaRefusal{LimitKey: "evs_closure_bytes_per_day", Limit: evs.allowance, Used: evs.allowanceUsed},
				}
			}
		}
		named := map[Id]bool{}
		for _, key := range closure.erased {
			named[key.SlotId] = true
		}
		for _, file := range closure.files {
			standing := versions[file.path]
			if file.replaces == 0 || len(standing) == 0 || standing[len(standing)-1].endedAt != 0 {
				return fmt.Errorf("test erase store: a CLOSURE that creates a path")
			}
			replaced := standing[len(standing)-1]
			if replaced.file.version != file.replaces {
				return &indexRefusal{kind: indexRefusalConflict, paths: []string{file.path}}
			}
			if replaced.file.byteCount < len(file.plaintext) {
				return fmt.Errorf("test erase store: a CLOSURE that grows a file")
			}
			for _, version := range standing {
				if evs.slotKeyed && !named[version.slotId] {
					return fmt.Errorf("test erase store: a CLOSURE that leaves a replaced version's slot off its list")
				}
			}
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}
	committed, err := self.handle.Commit(ctx, &indexPush{
		pushId: closure.pushId, kind: indexPushClosure, baseVersion: closure.baseVersion, signedTimeMs: closure.signedTimeMs,
		files: closure.files,
	})
	if err != nil {
		return nil, err
	}
	evs.stateLock.Lock()
	defer evs.stateLock.Unlock()
	for _, file := range committed.files {
		key := testErasePathVersion{path: file.path, version: file.version}
		evs.closureSlots[key] = evsTestId(fmt.Sprintf("closure slot %s %d", file.path, file.version))
	}
	evs.closures = append(evs.closures, &testEraseClosure{
		erasureId: closure.erasureId, closed: &indexEraseClosed{version: committed.version, keys: closure.erased},
	})
	if 0 < evs.allowance {
		evs.allowanceUsed += byteCount
	}
	for _, file := range closure.files {
		if evs.stagedMax < len(file.plaintext) && 0 < evs.pacingTurn {
			// a ?closure=1 upload waits its turn of the network's pacing
			evs.world.at = evs.world.at.Add(evs.pacingTurn)
		}
	}
	return committed, nil
}

// See indexEraseStore.
func (self *testEraseStore) Erase(ctx context.Context, erase *indexErasePush) error {
	evs := self.evs
	evs.stateLock.Lock()
	defer evs.stateLock.Unlock()
	if 0 < len(evs.eraseRefusals) {
		refusal := evs.eraseRefusals[0]
		evs.eraseRefusals = evs.eraseRefusals[1:]
		return refusal
	}
	if !evs.slotKeyed || len(erase.keys) == 0 {
		return fmt.Errorf("test erase store: an ERASE of no key")
	}
	live := false
	for _, key := range erase.keys {
		live = live || !evs.destroyed[key.SlotId]
	}
	if !live && !(erase.completion && evs.takesCompletionWithLock(erase)) {
		// NOTHING_TO_ERASE: done, and nothing commits
		return nil
	}
	for _, key := range erase.keys {
		evs.destroyed[key.SlotId] = true
	}
	evs.erases = append(evs.erases, &testEraseErase{
		erasureId:  erase.erasureId,
		erased:     &indexEraseErased{keys: erase.keys, complete: erase.complete, timeMs: evs.world.at.UnixMilli()},
		completion: !live,
		note:       bytes.Clone(erase.note),
	})
	evs.eraseTimes = append(evs.eraseTimes, evs.world.at)
	return nil
}

// Whether the fake takes erase, naming only keys gone, as a completion ERASE (QD-1132): it says complete; an earlier
// ERASE of its erasure named each key it names, and the newest ERASE naming each is no completion, which is what evs
// can see of it (question erasure-completion-erase-evs-cannot-read-complete's option 1); and the erasure's newest ERASE
// does not say complete already, which only a reader of the note can. The lock held.
func (self *testEraseEvs) takesCompletionWithLock(erase *indexErasePush) bool {
	if self.refusesCompletions || !erase.complete || len(erase.keys) == 0 {
		return false
	}
	ownKeys := map[EvsErasedKey]bool{}
	newestCompletion := map[EvsErasedKey]bool{}
	complete := false
	for _, committed := range self.erases {
		for _, key := range committed.erased.keys {
			newestCompletion[*key] = committed.completion
			if committed.erasureId == erase.erasureId {
				ownKeys[*key] = true
			}
		}
		if committed.erasureId == erase.erasureId {
			complete = committed.erased.complete
		}
	}
	if complete {
		return false
	}
	for _, key := range erase.keys {
		if !ownKeys[*key] || newestCompletion[*key] {
			return false
		}
	}
	return true
}

// FS-78's sweep: no stored version under a key a reader can obtain holds an entry listed takes. Stored versions are the
// live ones, and every one a hold keeps.
func (self *testEraseEvs) sweep(t testing.TB, listed indexEraseListed) {
	t.Helper()
	self.stateLock.Lock()
	hold := self.hold
	destroyed := map[Id]bool{}
	for slotId := range self.destroyed {
		destroyed[slotId] = true
	}
	self.stateLock.Unlock()
	for path, versions := range self.versions() {
		parsed, ok := indexParsePath(path, false)
		if !ok || !indexPathHoldsDocuments(parsed.kind) {
			continue
		}
		for _, version := range versions {
			if version.endedAt != 0 && !hold || destroyed[version.slotId] {
				continue
			}
			holds, err := indexHolds(parsed, version.plaintext, listed, DefaultIndexFormatSettings())
			if err != nil {
				t.Fatal(err)
			}
			if holds {
				t.Fatalf("an openable stored version of %s at %d holds a listed entry", path, version.file.version)
			}
		}
	}
}

// An erasure's world: the head world's ref and writers, and the fake evs behind its erasers.
type testEraseWorld struct {
	*testHeadWorld
	evs *testEraseEvs
	// The erasure events the erasers raised, in order.
	events []*SidecarErasure
}

func testNewEraseWorld() *testEraseWorld {
	world := testNewHeadWorld()
	return &testEraseWorld{testHeadWorld: world, evs: testNewEraseEvs(world)}
}

// An eraser of the world's ref, signing as signer through its handle on the fake evs, with settings (nil for the
// defaults).
func (self *testEraseWorld) eraserAs(t testing.TB, signer Id, settings *IndexEraseSettings) *IndexEraser {
	t.Helper()
	return self.eraserJudging(t, signer, settings, nil)
}

// eraserAs whose CUTs read which erasures are complete through complete, nil for none: a CUT drops a complete one
// from the set (§11.14's cut row).
func (self *testEraseWorld) eraserJudging(t testing.TB, signer Id, settings *IndexEraseSettings, complete func(ctx context.Context, erasureIds []Id) (map[Id]bool, error)) *IndexEraser {
	t.Helper()
	store := self.evs.as(signer)
	eraser, err := indexNewEraser(&indexEraserArgs{
		store:      store,
		eraseStore: store,
		repoId:     evsTestId("view repo"),
		refId:      evsTestId("view ref"),
		repoKind:   protocol.RepoKind_REPO_KIND_GENERAL,
		isAdmin:    self.isAdmin,
		format:     self.settings,
		settings:   settings,
		eraser:     signer,
		tables:     testHeadTables,
		complete:   complete,
		events: func(erasure *SidecarErasure) {
			self.events = append(self.events, erasure)
		},
		clock: &testIndexWorldClock{world: self.testHeadWorld},
		log:   NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return eraser
}

// The world's eraser, its CUTs reading an erasure complete while its newest ERASE on the fake says so.
func (self *testEraseWorld) completingEraser(t testing.TB) *IndexEraser {
	t.Helper()
	return self.eraserJudging(t, evsTestId("eraser"), nil, func(ctx context.Context, erasureIds []Id) (map[Id]bool, error) {
		self.evs.stateLock.Lock()
		defer self.evs.stateLock.Unlock()
		return recordEraseCompleteByNewest(self.evs.erases, func(erase *testEraseErase) (Id, bool) {
			return erase.erasureId, erase.erased.complete
		}), nil
	})
}

func (self *testEraseWorld) eraser(t testing.TB, settings *IndexEraseSettings) *IndexEraser {
	t.Helper()
	return self.eraserAs(t, evsTestId("eraser"), settings)
}

// The states the erasers raised, in order.
func (self *testEraseWorld) states() []string {
	states := []string{}
	for _, event := range self.events {
		states = append(states, event.State)
	}
	return states
}

// What the set at the head lists, L(k) over every erasure.
func (self *testEraseWorld) listed(t testing.TB) indexEraseListed {
	t.Helper()
	return indexEraseListed(indexErasureSetListed(self.view(t, evsTestId("reader")).erasureSet))
}

// Rewrites erasure label to its end, failing on any error or a wait.
func (self *testEraseWorld) rewrite(t testing.TB, eraser *IndexEraser, label string, complete bool) *IndexRewriteResult {
	t.Helper()
	result, err := eraser.Rewrite(context.Background(), &IndexRewriteArgs{ErasureId: evsTestId(label), Complete: complete, Note: []byte("note")})
	if err != nil {
		t.Fatal(err)
	}
	if result.Erasure == nil || result.Erasure.State == SidecarErasureWaiting {
		t.Fatalf("a rewrite that did not finish: %+v", result.Erasure)
	}
	return result
}

// Every live slot, large entry and shard path holding an entry listed takes.
func (self *testEraseWorld) holding(t testing.TB, listed indexEraseListed) []string {
	t.Helper()
	view := self.view(t, evsTestId("reader"))
	paths := []string{}
	for path, file := range indexEraseLiveFiles(view) {
		plaintext, err := view.store.Read(context.Background(), file.file)
		if err != nil {
			t.Fatal(err)
		}
		holds, err := indexHolds(file.path, plaintext, listed, view.settings)
		if err != nil {
			t.Fatal(err)
		}
		if holds {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	return paths
}

// A large entry's key set: enough keys at a wide step, two VByte bytes a gap, that its entry passes
// SlotEntryMaxByteCount.
func testLargeKeys(index int, count int) indexKeySet {
	return testIndexKeys(0x100000+index*0x10000, count, 200)
}

// clean of a slot (DESIGN-DETAILS 15.2.5): the listed entry and every entry at or below its listed version go, an entry
// above it and every other key stay in key order, the header's count and body_length set, and the file keeps the
// replaced version's exact length with zero bytes after its body; clean again changes nothing.
func TestIndexCleanTakesListedEntriesAtTheReplacedLength(t *testing.T) {
	settings := DefaultIndexFormatSettings()
	slot := &indexSlot{header: testSlotHeader(indexFileSlot)}
	for index := range 4 {
		keys := testHeadKeys(index, 0)
		slot.entries = append(slot.entries, &indexEntry{kind: indexEntryFull, key: testIndexId("doc", index), version: uint64(index + 1), timeSeconds: 1800000000, row: testFileRow(keys), keys: keys})
	}
	slot.entries = append(slot.entries, &indexEntry{kind: indexEntryTombstone, key: testIndexId("gone", 0), version: 2, timeSeconds: 1800000000})
	file, err := indexEncodeSlot(slot, false, settings)
	if err != nil {
		t.Fatal(err)
	}
	listed := indexEraseListed{testIndexId("doc", 1): 2, testIndexId("doc", 3): 3, testIndexId("gone", 0): 2}
	path := indexPath{kind: indexPathSlot}
	cleaned, taken, err := indexClean(path, file, listed, settings)
	if err != nil {
		t.Fatal(err)
	}
	if !taken || len(cleaned) != len(file) {
		t.Fatalf("clean took %v at %d B of %d", taken, len(cleaned), len(file))
	}
	decoded, err := testDecodeSlotFile(cleaned, settings)
	if err != nil {
		t.Fatal(err)
	}
	keys := [][indexIdByteCount]byte{}
	for _, entry := range decoded.entries {
		keys = append(keys, entry.key)
	}
	want := [][indexIdByteCount]byte{testIndexId("doc", 0), testIndexId("doc", 2), testIndexId("doc", 3)}
	slices.SortFunc(want, compareIndexKeys)
	if !slices.Equal(keys, want) || decoded.header.Count != 3 || decoded.padByteCount == 0 {
		t.Fatalf("the entries left %x, count %d, pad %d", keys, decoded.header.Count, decoded.padByteCount)
	}
	for _, entry := range decoded.entries {
		if entry.key == testIndexId("doc", 3) && entry.version != 4 {
			t.Fatal("an entry above its listed version did not stay")
		}
	}
	again, taken, err := indexClean(path, cleaned, listed, settings)
	if err != nil || taken || !bytes.Equal(again, cleaned) {
		t.Fatalf("clean again: taken %v, err %v", taken, err)
	}
}

// Decodes a slot or large entry under its true hash.
func testDecodeSlotFile(file []byte, settings *IndexFormatSettings) (*indexSlot, error) {
	sum := sha256.Sum256(file)
	return indexDecodeSlot(file, sum[:], false, settings)
}

// A large entry's one entry listed: no entry left, all pad, at the replaced length, which a decoder takes as a large
// entry an erasure emptied; an empty large entry without a pad is refused both ways, so only a rewrite makes one.
func TestIndexCleanEmptiesALargeEntry(t *testing.T) {
	settings := DefaultIndexFormatSettings()
	keys := testLargeKeys(0, 6000)
	large := &indexSlot{header: testSlotHeader(indexFileLargeEntry), entries: []*indexEntry{
		{kind: indexEntryFull, key: testIndexId("big", 0), version: 3, timeSeconds: 1800000000, row: testFileRow(keys), keys: keys},
	}}
	file, err := indexEncodeSlot(large, false, settings)
	if err != nil {
		t.Fatal(err)
	}
	cleaned, taken, err := indexClean(indexPath{kind: indexPathLargeEntry}, file, indexEraseListed{testIndexId("big", 0): 3}, settings)
	if err != nil {
		t.Fatal(err)
	}
	if !taken || len(cleaned) != len(file) {
		t.Fatalf("clean took %v at %d B of %d", taken, len(cleaned), len(file))
	}
	decoded, err := testDecodeSlotFile(cleaned, settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.entries) != 0 || decoded.header.Count != 0 || decoded.padByteCount == 0 {
		t.Fatalf("an emptied large entry holds %d entries and %d B of pad", len(decoded.entries), decoded.padByteCount)
	}
	empty := &indexSlot{header: testSlotHeader(indexFileLargeEntry)}
	if _, err := indexEncodeSlot(empty, false, settings); !isIndexMalformed(err) {
		t.Fatalf("an empty large entry with no pad encoded: %v", err)
	}
	empty.padByteCount = 1
	padded, err := indexEncodeSlot(empty, false, settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testDecodeSlotFile(padded[:len(padded)-1], settings); !isIndexMalformed(err) {
		t.Fatalf("an empty large entry with no pad decoded: %v", err)
	}
}

// A shard's clean is rewriteWithout's, the replaced length and pad generation kept; a shard holding nothing listed is
// its replaced bytes; a rewrite past the replaced length is refused, never padded short.
func TestIndexCleanShardAtTheReplacedLength(t *testing.T) {
	documents := testShardDocuments(5, "shard", 20, indexDocFile)
	shard := &indexShard{header: testShardHeader(indexFileBucketShard), documents: documents}
	file := testBuildShard(t, shard, false, testPadKey(t, 2))
	path := indexPath{kind: indexPathBucketShard}
	listed := indexEraseListed{documents[3].key: documents[3].version}
	cleaned, taken, err := indexClean(path, file, listed, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := testDecodeShard(cleaned, false)
	if err != nil {
		t.Fatal(err)
	}
	if !taken || len(cleaned) != len(file) || decoded.header.PadGeneration != 2 || len(decoded.documents) != 19 {
		t.Fatalf("the rewrite: taken %v, %d B of %d, generation %d, %d documents", taken, len(cleaned), len(file), decoded.header.PadGeneration, len(decoded.documents))
	}
	if slices.ContainsFunc(decoded.documents, func(document *indexShardDocument) bool { return document.key == documents[3].key }) {
		t.Fatal("the listed document survived")
	}
	unchanged, taken, err := indexClean(path, file, indexEraseListed{testIndexId("elsewhere", 0): 9}, DefaultIndexFormatSettings())
	if err != nil || taken || !bytes.Equal(unchanged, file) {
		t.Fatalf("a shard holding nothing listed: taken %v, err %v", taken, err)
	}
	original, err := testDecodeShard(file, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := indexNewShardBuilder(false).rewriteWithout(original, func(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool {
		return false
	}, len(file)/2); !isIndexMalformed(err) {
		t.Fatalf("a rewrite past its replaced length: %v", err)
	}
}

// A world with one listed document d0 at version 1 in every kind of file: writer a's sealed slots, one absorbed by a
// merge into the bucket's shard, writer b's head, and a large entry of b's; d0 at version 2 in a's head stays.
func testEraseWorldWithCopies(t testing.TB) *testEraseWorld {
	t.Helper()
	world := testNewEraseWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("d", 0, 1, testHeadKeys(0, 0)))
	world.fillUntilSealed(t, a, "fill", 0)
	world.merge(t, evsTestId("merger"))
	world.push(t, b, testLive("d", 0, 1, testHeadKeys(0, 0)), testLive("big", 0, 1, testLargeKeys(0, 6000)))
	world.push(t, a, testLive("d", 0, 2, testHeadKeys(0, 1)))
	return world
}

// §11.14's erase row: the list holds every file holding a listed version, an absorbed slot, the bucket's shard, another
// writer's head and a large entry included, and the version above the list stays where it is; the CLOSUREs rewrite each
// at its replaced length without the listed versions; the ERASEs destroy every key any version of each rewritten path
// named; the last ERASE says complete; and no stored version under a live key holds a listed entry (FS-78's sweep). The
// erasure event goes fenced, rewriting, done.
func TestIndexRewriteClosesEveryFileAndErasesItsKeys(t *testing.T) {
	world := testEraseWorldWithCopies(t)
	eraser := world.eraser(t, nil)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("d", 0), Version: 1}, &IndexCutDocument{Key: testIndexId("big", 0), Version: 1})
	listed := world.listed(t)
	before := world.holding(t, listed)
	if len(before) < 4 {
		t.Fatalf("the world holds the listed versions in %d files", len(before))
	}
	byteCounts := map[string]int{}
	for path, file := range indexEraseLiveFiles(world.view(t, evsTestId("reader"))) {
		byteCounts[path] = file.file.byteCount
	}
	result := world.rewrite(t, eraser, "erasure", true)
	if !result.Completed || result.Unproven || result.FileCount != len(before) || result.Erasure.State != SidecarErasureDone {
		t.Fatalf("the rewrite: %+v, %d files held", result, len(before))
	}
	if held := world.holding(t, listed); len(held) != 0 {
		t.Fatalf("files still holding a listed version: %v", held)
	}
	view := world.view(t, evsTestId("reader"))
	for _, path := range before {
		if live := indexEraseLiveFiles(view)[path]; live == nil || live.file.byteCount != byteCounts[path] {
			t.Fatalf("%s rewritten at another length", path)
		}
	}
	entries := world.entries(t, "d", 0)
	if !slices.ContainsFunc(entries, func(entry *indexBucketEntry) bool { return entry.version == 2 && entry.kind == indexEntryFull }) {
		t.Fatal("the version above the list did not stay")
	}
	world.evs.sweep(t, listed)
	if !slices.Equal(world.states(), []string{SidecarErasureFenced, SidecarErasureRewriting, SidecarErasureDone}) {
		t.Fatalf("the erasure's states %v", world.states())
	}
	last := world.evs.erases[len(world.evs.erases)-1]
	if !last.erased.complete {
		t.Fatal("the last ERASE did not say complete")
	}
	// called again once done: nothing more is sent
	closures := len(world.evs.closures)
	again := world.rewrite(t, eraser, "erasure", true)
	if again.Erasure.State != SidecarErasureDone || again.PairCount != 0 || len(world.evs.closures) != closures {
		t.Fatalf("a rewrite after done: %+v", again)
	}
}

// A rewrite of an erasure the set does not list is refused: its CUT comes first.
func TestIndexRewriteRefusesBeforeTheCut(t *testing.T) {
	world := testEraseWorldWithCopies(t)
	if _, err := world.eraser(t, nil).Rewrite(context.Background(), &IndexRewriteArgs{ErasureId: evsTestId("erasure")}); !errors.Is(err, ErrIndexEraseNotCut) {
		t.Fatalf("a rewrite before the CUT: %v", err)
	}
}

// A writer's push that rewrites a listed file between the list and the CLOSURE makes the CLOSURE's 409: the eraser lists
// again and rewrites the new version (§11.14's erase row).
func TestIndexRewriteListsAgainOnAConflict(t *testing.T) {
	world := testEraseWorldWithCopies(t)
	eraser := world.eraser(t, nil)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("d", 0), Version: 1})
	b := evsTestId("writer b")
	raced := false
	world.ref.beforeCommit = func(push *indexPush) {
		if raced || push.kind != indexPushClosure {
			return
		}
		raced = true
		// b writes its head again, as its next push in the bucket does
		plan, view := world.plan(t, b, true, testLive("other", 0, 1, testHeadKeys(9, 0)))
		if _, err := world.ref.store(b).Commit(context.Background(), &indexPush{
			pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: world.at.UnixMilli(),
			files: plan.files(), removals: plan.removals(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	result := world.rewrite(t, eraser, "erasure", true)
	world.ref.beforeCommit = nil
	if !raced || result.Attempts < 2 || !result.Completed {
		t.Fatalf("the raced rewrite: raced %v, %+v", raced, result)
	}
	if held := world.holding(t, world.listed(t)); len(held) != 0 {
		t.Fatalf("files still holding a listed version: %v", held)
	}
	world.evs.sweep(t, world.listed(t))
}

// A crash between a CLOSURE and its ERASE: the resume's first step erases the keys that CLOSURE listed, then the pairs
// go on at the head, and the erasure completes (§11.12's reconcile row).
func TestIndexRewriteResumesAnOrphanedClosure(t *testing.T) {
	world := testEraseWorldWithCopies(t)
	settings := DefaultIndexEraseSettings()
	settings.PairByteCount = 1
	eraser := world.eraser(t, settings)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("d", 0), Version: 1})
	crash := errors.New("the device stopped")
	world.evs.eraseRefusals = []error{crash}
	if _, err := eraser.Rewrite(context.Background(), &IndexRewriteArgs{ErasureId: evsTestId("erasure"), Complete: true}); !errors.Is(err, crash) {
		t.Fatalf("the crashed rewrite: %v", err)
	}
	if len(world.evs.closures) != 1 || len(world.evs.erases) != 0 {
		t.Fatalf("%d CLOSUREs and %d ERASEs before the resume", len(world.evs.closures), len(world.evs.erases))
	}
	orphan := world.evs.closures[0].closed.keys
	resumed, err := world.eraser(t, settings).Resume(context.Background(), &IndexResumeArgs{ErasureId: evsTestId("erasure"), Role: IndexResumeEraser, Complete: true})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Cut != nil || resumed.Rewrite == nil || !resumed.Rewrite.Completed {
		t.Fatalf("the resume: %+v", resumed)
	}
	first := world.evs.erases[0].erased.keys
	if !slices.EqualFunc(first, orphan, func(a *EvsErasedKey, b *EvsErasedKey) bool { return *a == *b }) {
		t.Fatal("the resume's first ERASE is not the orphaned CLOSURE's keys")
	}
	world.evs.sweep(t, world.listed(t))
}

// Another device of the eraser's member resumes only 25 h after the CUT or the last ERASE, whichever is later; then it
// finishes the erasure in its own allowance (§11.12's reconcile row).
func TestIndexResumeByAnotherDeviceAfter25Hours(t *testing.T) {
	world := testEraseWorldWithCopies(t)
	world.admins = append(world.admins, evsTestId("eraser 2"))
	testCut(t, world.eraser(t, nil), "erasure", &IndexCutDocument{Key: testIndexId("d", 0), Version: 1})
	cutAt := world.at
	other := world.eraserAs(t, evsTestId("eraser 2"), nil)
	early, err := other.Resume(context.Background(), &IndexResumeArgs{ErasureId: evsTestId("erasure"), Role: IndexResumeMember, Complete: true})
	if err != nil {
		t.Fatal(err)
	}
	if early.Rewrite != nil || !early.NotBefore.Equal(cutAt.Add(25*time.Hour)) || len(world.evs.closures) != 0 {
		t.Fatalf("a resume before 25 h: %+v", early)
	}
	world.at = cutAt.Add(25 * time.Hour)
	late, err := other.Resume(context.Background(), &IndexResumeArgs{ErasureId: evsTestId("erasure"), Role: IndexResumeMember, Complete: true})
	if err != nil {
		t.Fatal(err)
	}
	if late.Rewrite == nil || !late.Rewrite.Completed {
		t.Fatalf("a resume after 25 h: %+v", late)
	}
	world.evs.sweep(t, world.listed(t))
}

// A crash that left the CUT missing after the erasure's first ERASE (a record erasure ERASEs its bodies first,
// QD-781): a resume given the erasure's documents commits the CUT itself, then rewrites; one without them cannot, and
// says so; and an erasure that committed nothing never began, so no other device takes it up.
func TestIndexResumeCommitsAMissingCut(t *testing.T) {
	world := testEraseWorldWithCopies(t)
	documents := []*IndexCutDocument{{Key: testIndexId("d", 0), Version: 1}}
	if _, err := world.eraser(t, nil).Resume(context.Background(), &IndexResumeArgs{ErasureId: evsTestId("erasure"), Role: IndexResumeAny, Documents: documents}); !errors.Is(err, ErrIndexErasureNotBegun) {
		t.Fatalf("another device's resume of an erasure that never began: %v", err)
	}
	// the erasure's first ERASE, of the entry's own keys, lands before the crash
	body := world.evs.as(evsTestId("eraser"))
	if err := body.Erase(context.Background(), &indexErasePush{erasureId: evsTestId("erasure"), keys: []*EvsErasedKey{{SlotId: evsTestId("entry body slot")}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := world.eraser(t, nil).Resume(context.Background(), &IndexResumeArgs{ErasureId: evsTestId("erasure"), Role: IndexResumeAny}); !errors.Is(err, ErrIndexEraseNotCut) {
		t.Fatalf("a resume with no CUT and no documents: %v", err)
	}
	resumed, err := world.eraser(t, nil).Resume(context.Background(), &IndexResumeArgs{ErasureId: evsTestId("erasure"), Role: IndexResumeAny, Documents: documents, Complete: true})
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Cut == nil || !resumed.Cut.Pushed || !resumed.Rewrite.Completed {
		t.Fatalf("the resume: %+v", resumed)
	}
	world.evs.sweep(t, world.listed(t))
}

// A hold keeps an absorbed slot's version after its writer reused the slot, and a large entry its writer removed once
// absorbed: the reused slot's path is rewritten with its live bytes under a fresh key and its old key destroyed, the
// removed path's key destroyed with no CLOSURE, and no version the hold keeps opens a listed entry (§11.14's erase row's
// history; FS-112's held version).
func TestIndexRewriteTakesHeldVersions(t *testing.T) {
	world := testNewEraseWorld()
	world.evs.hold = true
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 0, 1, testHeadKeys(0, 0)), testLive("big", 0, 1, testLargeKeys(0, 6000)))
	world.fillUntilSealed(t, a, "fill", 0)
	world.merge(t, evsTestId("merger"))
	// a reuses its absorbed slot and removes its absorbed large entry at its next pushes
	next := world.fillUntilSealed(t, a, "more", 0)
	world.fillUntilSealed(t, a, "more", next)
	eraser := world.eraser(t, nil)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("d", 0), Version: 1}, &IndexCutDocument{Key: testIndexId("big", 0), Version: 1})
	listed := world.listed(t)
	result := world.rewrite(t, eraser, "erasure", true)
	if !result.Completed {
		t.Fatalf("the rewrite: %+v", result)
	}
	world.evs.sweep(t, listed)
}

// A version evs no longer serves cannot be read: one replaced within StagedRetention counts as holding, so its live
// path is rewritten; past it, it is left (§11.12's bytes row's 26 h).
func TestIndexRewriteTakesAnUnreadableRecentVersion(t *testing.T) {
	world := testNewEraseWorld()
	world.evs.reportCollected = true
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 0, 1, testHeadKeys(0, 0)))
	world.push(t, a, testLive("e", 0, 1, testHeadKeys(1, 0)))
	eraser := world.eraser(t, nil)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("unheld", 0), Version: 1})
	recent := world.rewrite(t, eraser, "erasure", true)
	if recent.FileCount == 0 {
		t.Fatal("a recently replaced version that does not read left its path alone")
	}

	late := testNewEraseWorld()
	late.evs.reportCollected = true
	late.push(t, a, testLive("d", 0, 1, testHeadKeys(0, 0)))
	late.push(t, a, testLive("e", 0, 1, testHeadKeys(1, 0)))
	late.at = late.at.Add(27 * time.Hour)
	lateEraser := late.eraser(t, nil)
	testCut(t, lateEraser, "erasure", &IndexCutDocument{Key: testIndexId("unheld", 0), Version: 1})
	if result := late.rewrite(t, lateEraser, "erasure", true); result.FileCount != 0 {
		t.Fatalf("a version replaced past StagedRetention rewrote %d files", result.FileCount)
	}
}

// Nothing says complete where the store could not walk the whole history (EvsRepo's removed paths), and a general
// repo's CLOSUREs are followed by no ERASE, its keys riding segments the purge deletes, complete left to the caller.
func TestIndexRewriteLeavesCompleteUnproven(t *testing.T) {
	world := testEraseWorldWithCopies(t)
	world.evs.retainedIncomplete = true
	eraser := world.eraser(t, nil)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("d", 0), Version: 1})
	result := world.rewrite(t, eraser, "erasure", true)
	if result.Completed || !result.Unproven || result.FileCount == 0 || result.Erasure.State != SidecarErasureRewriting {
		t.Fatalf("an unproven rewrite: %+v", result)
	}
	for _, erased := range world.evs.erases {
		if erased.erased.complete {
			t.Fatal("an unproven rewrite said complete")
		}
	}

	general := testEraseWorldWithCopies(t)
	general.evs.slotKeyed = false
	generalEraser := general.eraser(t, nil)
	testCut(t, generalEraser, "erasure", &IndexCutDocument{Key: testIndexId("d", 0), Version: 1})
	generalResult := general.rewrite(t, generalEraser, "erasure", true)
	if generalResult.Completed || generalResult.FileCount == 0 || len(general.evs.erases) != 0 {
		t.Fatalf("a general repo's rewrite: %+v, %d ERASEs", generalResult, len(general.evs.erases))
	}
	if held := general.holding(t, general.listed(t)); len(held) != 0 {
		t.Fatalf("files still holding a listed version: %v", held)
	}
}

// FS-112's mechanics: at the storage limit, with an allowance that takes two of five large entries a UTC day and the
// run starting 10 min before 00:00 UTC, the pairs stay within the allowance, the first refusal's event names the objects
// and bytes left, its next try at 00:00 UTC and a finish that the last ERASE meets within one pacing turn on the fake
// clock, the eraser restarting at each next try; and the finish never passes §11.13's bound.
func TestIndexRewriteWaitsOnTheAllowanceAcrossMidnight(t *testing.T) {
	world := testNewEraseWorld()
	a := evsTestId("writer a")
	pending := []*indexPendingDocument{}
	for index := range 5 {
		pending = append(pending, testLive("big", index, 1, testLargeKeys(index, 6000)))
	}
	world.push(t, a, pending...)
	world.at = testDayTime(20342, -10*time.Minute)
	settings := DefaultIndexEraseSettings()
	settings.ClosureUploadMaxByteCount = 8 * 1024
	turn := 250 * time.Millisecond
	world.evs.pacingTurn = turn
	view := world.view(t, evsTestId("reader"))
	largeByteCount := 0
	for _, file := range indexEraseLiveFiles(view) {
		if file.path.kind == indexPathLargeEntry {
			largeByteCount = max(largeByteCount, file.file.byteCount)
		}
	}
	world.evs.allowance = int64(2*largeByteCount + largeByteCount/2)
	eraser := world.eraser(t, settings)
	documents := []*IndexCutDocument{}
	for index := range 5 {
		documents = append(documents, &IndexCutDocument{Key: testIndexId("big", index), Version: 1})
	}
	testCut(t, eraser, "erasure", documents...)
	var firstWait *SidecarErasure
	var objects []*indexRekeyObject
	for range 16 {
		result, err := eraser.Rewrite(context.Background(), &IndexRewriteArgs{ErasureId: evsTestId("erasure"), Complete: true})
		if err != nil {
			t.Fatal(err)
		}
		if result.Erasure.State != SidecarErasureWaiting {
			if !result.Completed {
				t.Fatalf("the rewrite ended %+v", result)
			}
			break
		}
		if firstWait == nil {
			firstWait = result.Erasure
			for _, file := range indexEraseLiveFiles(world.view(t, evsTestId("reader"))) {
				if file.path.kind == indexPathLargeEntry {
					if holds, _ := indexHolds(file.path, testMustRead(t, world, file.file), world.listed(t), world.settings); holds {
						objects = append(objects, indexNewRekeyObject(file.file.path, file.file.byteCount, settings))
					}
				}
			}
		}
		if !result.Erasure.NextTry.After(world.at) {
			t.Fatalf("a next try %s not after now %s", result.Erasure.NextTry, world.at)
		}
		world.at = result.Erasure.NextTry
	}
	if firstWait == nil {
		t.Fatal("the allowance never refused")
	}
	if firstWait.ObjectsLeft != int64(len(objects)) || firstWait.BytesLeft != indexRekeyByteCount(objects) {
		t.Fatalf("the first wait names %d objects and %d B, the files %d and %d B", firstWait.ObjectsLeft, firstWait.BytesLeft, len(objects), indexRekeyByteCount(objects))
	}
	lastErase := world.evs.eraseTimes[len(world.evs.eraseTimes)-1]
	if gap := lastErase.Sub(firstWait.Finish); gap < -turn || turn < gap {
		t.Fatalf("the last ERASE at %s, the finish %s", lastErase, firstWait.Finish)
	}
	bound := indexRekeyDayBound(objects, world.evs.allowance, settings)
	days, _ := indexRekeyDays(objects, world.evs.allowance)
	if bound < days {
		t.Fatalf("the finish's %d days past the bound's %d", days, bound)
	}
	world.evs.sweep(t, world.listed(t))
}

// The plaintext of a live file, failing on any error.
func testMustRead(t testing.TB, world *testEraseWorld, file *indexFileVersion) []byte {
	t.Helper()
	plaintext, err := world.evs.as(evsTestId("reader")).Read(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

// §11.13's finish, unit by unit: the days from the next 00:00 UTC that whole objects take within an allowance, staged
// records taking no pacing turn, within the bound; a one-object erasure after the next 00:00 within its turns; nothing
// left, no finish.
func TestIndexEraseFinish(t *testing.T) {
	settings := DefaultIndexEraseSettings()
	now := time.Date(2026, 11, 18, 23, 50, 0, 0, time.UTC)
	midnight := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	one := []*indexRekeyObject{indexNewRekeyObject("a", 1024*1024, settings), indexNewRekeyObject("b", 1000, settings)}
	if finish := indexEraseFinish(now, one, 4*1024*1024, settings); !finish.Equal(midnight.Add(settings.PacingTurn)) {
		t.Fatalf("one message's finish %s", finish)
	}
	objects := []*indexRekeyObject{}
	for index := range 9 {
		objects = append(objects, indexNewRekeyObject(fmt.Sprintf("shard %d", index), 1000*1024, settings))
	}
	days, uploads := indexRekeyDays(objects, 4*1024*1024)
	if days != 3 || uploads != 1 {
		t.Fatalf("nine shards at the floor: %d days, %d uploads the last", days, uploads)
	}
	if bound := indexRekeyDayBound(objects, 4*1024*1024, settings); bound < days {
		t.Fatalf("the bound %d below %d days", bound, days)
	}
	if finish := indexEraseFinish(now, objects, 4*1024*1024, settings); !finish.Equal(midnight.Add(2*24*time.Hour + settings.PacingTurn)) {
		t.Fatalf("nine shards' finish %s", finish)
	}
	if finish := indexEraseFinish(now, nil, 4*1024*1024, settings); !finish.IsZero() {
		t.Fatalf("nothing left finishes at %s", finish)
	}
}

// A reproducer holding the CLOSURE's inputs rebuilds its slot rewrite and fetches nothing; a CLOSURE that left a
// listed entry in a slot it rewrote is fetched and alarms index_mismatch naming its signer (DESIGN-DETAILS 15.2.5).
func TestIndexReproduceASlotClosure(t *testing.T) {
	for _, forged := range []bool{false, true} {
		world := testNewEraseWorld()
		a := evsTestId("writer a")
		world.push(t, a, testLive("d", 0, 1, testHeadKeys(0, 0)), testLive("e", 0, 1, testHeadKeys(1, 0)))
		eraser := world.eraser(t, nil)
		testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("d", 0), Version: 1})
		base := testHeldBase(t, world.ref)
		var sent *indexPush
		world.ref.beforeCommit = func(push *indexPush) {
			if push.kind != indexPushClosure {
				return
			}
			if forged {
				// the replaced bytes, the listed entry left in
				for _, file := range push.files {
					for _, held := range base.listing.files {
						if held.path == file.path {
							plaintext, _, _ := base.held(context.Background(), held)
							file.plaintext = plaintext
						}
					}
				}
			}
			sent = push
		}
		world.rewrite(t, eraser, "erasure", true)
		world.ref.beforeCommit = nil
		if sent == nil {
			t.Fatal("no CLOSURE")
		}
		committed := world.ref.committed[sent.pushId]
		push := testReproducePush(sent, committed, evsTestId("eraser"), 2)
		push.closure, push.erasureId = true, evsTestId("erasure")
		outcome, err := world.reproducer(t, nil, nil).Reproduce(context.Background(), push, base)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case !forged && (len(outcome.matched) != len(sent.files) || len(outcome.fetch) != 0 || len(outcome.events) != 0):
			t.Fatalf("an honest CLOSURE reproduced: %d matched, %d fetched, %d events", len(outcome.matched), len(outcome.fetch), len(outcome.events))
		case forged && (len(outcome.events) == 0 || outcome.events[0].Kind != SidecarEventIndexMismatch || *outcome.events[0].SidecarId != evsTestId("eraser")):
			t.Fatalf("a forged CLOSURE reproduced: %d events", len(outcome.events))
		}
	}
}

// DESIGN-DETAILS 15.2.10's step 5: a run card the CUT listed through its epoch is folded again at its stream's head,
// without the erased entry, and entered full in the eraser's own head at E * 2^32 + c; a re-entry asked again finds it
// standing above the list and enters nothing; a quota refusal waits ReentryRetryInterval, holding back nothing.
func TestIndexReenterFoldsACardAgain(t *testing.T) {
	ref := testNewIndexRef()
	at := testDayTime(20341, 0)
	clock := &testIndexReenterClock{at: at}
	refKey := bytes.Repeat([]byte{0x2c}, 32)
	runId := evsTestId("run")
	stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "a")
	stream.add(t, testRecordEntry(t, "context", RecordKindContext, runId, 1, &protocol.ContextBody{Harness: "claude-code", Title: "Rotate the keys"}))
	erased := stream.add(t, testRecordEntry(t, "change", RecordKindChange, runId, 2, nil))
	stream.add(t, testRecordEntry(t, "tool", RecordKindToolCall, runId, 3, nil))
	cardKey, err := indexDocKey(refKey, stream.refId, indexRunCardName(runId), 0)
	if err != nil {
		t.Fatal(err)
	}
	evs := testNewEraseEvs(&testHeadWorld{ref: ref, at: at, settings: DefaultIndexFormatSettings()})
	store := evs.as(evsTestId("eraser"))
	eraser, err := indexNewEraser(&indexEraserArgs{
		store: store, eraseStore: store, repoId: evsTestId("vault"), refId: evsTestId("index ref"),
		repoKind: protocol.RepoKind_REPO_KIND_VAULT, companion: true, isAdmin: testIndexEraserAdmin,
		format: DefaultIndexFormatSettings(), eraser: evsTestId("eraser"), refKey: refKey, tables: testHeadTables, clock: clock,
		log: NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cut, err := eraser.Cut(context.Background(), &IndexCutArgs{ErasureId: evsTestId("erasure"), Documents: []*IndexCutDocument{{Key: cardKey, ThroughEpoch: true}}})
	if err != nil {
		t.Fatal(err)
	}
	erasures := []*RecordStreamErasure{{ErasureId: evsTestId("erasure"), Keys: []*RecordSlotKey{&erased.slotKeys[0]}}}
	card := &IndexReenterCard{Key: cardKey, Stream: stream, RunId: runId, Head: func(ctx context.Context) (uint64, error) { return stream.readTo, nil }}
	args := &IndexReenterArgs{ErasureId: evsTestId("erasure"), Cards: []*IndexReenterCard{card}, Erasures: erasures}
	result, err := eraser.Reenter(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	if result.EnteredCount != 1 || result.PushCount != 1 || result.Waiting {
		t.Fatalf("the re-entry: %+v", result)
	}
	view := testLoadViewCompanion(t, store)
	documents, err := view.bucketDocuments(context.Background(), view.writeRoot().newestBucket())
	if err != nil {
		t.Fatal(err)
	}
	entries := documents.of(cardKey)
	want, err := indexRunCardVersion(cut.Version, stream.readTo, DefaultIndexFormatSettings().CardVersionBitCount)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].version != want || entries[0].writer != evsTestId("eraser") || !entries[0].head {
		t.Fatalf("the card's entries %+v, want version %d in the eraser's head", entries, want)
	}
	if !view.erased(cardKey, cut.Set.Erasures[0].Docs[0].Version) || view.erased(cardKey, want) {
		t.Fatal("the re-entered version is not above the list")
	}
	again, err := eraser.Reenter(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	if again.EnteredCount != 0 || again.SkippedCount != 1 {
		t.Fatalf("a re-entry asked again: %+v", again)
	}

	// another run's card, not yet standing: a quota refusal of its push waits, tried again in ReentryRetryInterval
	otherRunId := evsTestId("other run")
	stream.add(t, testRecordEntry(t, "other context", RecordKindContext, otherRunId, 4, &protocol.ContextBody{Harness: "claude-code", Title: "Ship it"}))
	otherKey, err := indexDocKey(refKey, stream.refId, indexRunCardName(otherRunId), 0)
	if err != nil {
		t.Fatal(err)
	}
	ref.refuseNext(&indexRefusal{kind: indexRefusalQuota}, false)
	waiting, err := eraser.Reenter(context.Background(), &IndexReenterArgs{
		ErasureId: evsTestId("erasure"), Erasures: erasures,
		Cards: []*IndexReenterCard{{Key: otherKey, Stream: stream, RunId: otherRunId, Head: card.Head}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !waiting.Waiting || !waiting.NextTry.Equal(at.Add(10*time.Minute)) || waiting.EnteredCount != 0 {
		t.Fatalf("a re-entry a quota refused: %+v", waiting)
	}
}

// A clock at a fixed time.
type testIndexReenterClock struct {
	at time.Time
}

func (self *testIndexReenterClock) Now() time.Time {
	return self.at
}

func (self *testIndexReenterClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.at
	return fired
}

func (self *testIndexReenterClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// A companion view of store, the eraser counting.
func testLoadViewCompanion(t testing.TB, store indexRefStore) *indexView {
	t.Helper()
	view, err := indexLoadView(context.Background(), &indexViewArgs{
		store: store, repoId: evsTestId("vault"), refId: evsTestId("index ref"), repoKind: protocol.RepoKind_REPO_KIND_VAULT,
		companion: true, isAdmin: testIndexEraserAdmin, settings: DefaultIndexFormatSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// A document a roll-up moved into all: the all shard holding it is on the list and rewritten (I-EVS-11), and the
// bucket the roll-up removed, which a hold keeps, has the keys of its files holding the document destroyed with no
// CLOSURE, so no version the hold keeps opens it (§11.14's erase row: a bucket a roll-up removed).
func TestIndexRewriteTakesAnAllShardAndARolledBucket(t *testing.T) {
	headWorld, a := testRollupWorld(t)
	world := &testEraseWorld{testHeadWorld: headWorld, evs: testNewEraseEvs(headWorld)}
	world.evs.hold = true
	before := world.view(t, a).writeRoot().newestBucket()
	world.at = testDayTime(before.window.endDay()+before.window.days, time.Hour)
	world.rollUp(t, evsTestId("runner"))
	rows, root := world.allRows(t)
	if rows[testIndexId("u", 1)] == nil || len(root.allShards) == 0 {
		t.Fatal("the roll-up left u1 out of all")
	}
	eraser := world.eraser(t, nil)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("u", 1), Version: 1})
	listed := world.listed(t)
	held := world.holding(t, listed)
	if len(held) != 1 || !slices.Contains(held, root.paths.allShard(root.allShards[0].path.shardNumber)) {
		t.Fatalf("the live files holding u1: %v", held)
	}
	result := world.rewrite(t, eraser, "erasure", true)
	if !result.Completed || result.FileCount != 1 || result.KeyCount <= 1 {
		t.Fatalf("the rewrite: %+v", result)
	}
	if rows, _ := world.allRows(t); rows[testIndexId("u", 1)] != nil || rows[testIndexId("u", 2)] == nil {
		t.Fatal("the all shard's rewrite kept u1 or lost u2")
	}
	world.evs.sweep(t, listed)
}

// QD-1118's mapping: evs's 507 CLUSTER_FULL is the index's quota refusal, its retry delay the wait, 0 where it names
// none, its text naming the full cluster rather than a quota, and the eraser reads that wait from it and no allowance;
// the storage limit's own QuotaRefusal stays the quota refusal it was, its record and wait with it; and a 507 that is
// no evs refusal, with no CLUSTER_FULL code, passes as it is.
func TestIndexRefusalOfEvsTakesAFullClusterAsTheLimit(t *testing.T) {
	for _, wait := range []time.Duration{7 * time.Minute, 0} {
		full := &EvsError{Status: http.StatusInsufficientStorage, Code: protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL, RetryAfter: wait}
		refusal, ok := indexRefusalOf(indexRefusalOfEvs(full))
		if !ok || refusal.kind != indexRefusalQuota || refusal.retryAfter != wait || refusal.quota != nil || !refusal.clusterFull ||
			refusal.Error() != "index push refused: storage cluster full" {
			t.Fatalf("a 507 waiting %s: the index's refusal %+v", wait, refusal)
		}
		allowance, ok := indexEraseAllowanceOf(indexEraseRefusalOfEvs(full))
		if !ok || allowance.retryAfter != wait || allowance.limit != 0 || allowance.used != 0 {
			t.Fatalf("a 507 waiting %s: the eraser's allowance %+v", wait, allowance)
		}
	}
	storage := &EvsError{Status: http.StatusForbidden, Code: protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT, Quota: &protocol.EvsQuotaRefusal{
		LimitKey: "evs_storage_bytes", Limit: 9000, Used: 12000, RetryAfterMs: 1000,
	}}
	refusal, ok := indexRefusalOf(indexEraseRefusalOfEvs(storage))
	if !ok || refusal.kind != indexRefusalQuota || refusal.clusterFull || refusal.quota == nil || refusal.quota.LimitKey != "evs_storage_bytes" ||
		refusal.Error() != "index push refused: quota" {
		t.Fatalf("the storage limit's refusal: %+v", refusal)
	}
	if allowance, ok := indexEraseAllowanceOf(refusal); !ok || allowance.retryAfter != time.Second {
		t.Fatalf("the storage limit's wait: %+v", allowance)
	}
	bare := error(&EvsError{Status: http.StatusInsufficientStorage})
	if indexRefusalOfEvs(bare) != bare || indexEraseRefusalOfEvs(bare) != bare {
		t.Fatal("a 507 that is no evs refusal was read as one")
	}
}

// An eraser of the stand-in's main ref, signing as its writer, every version counting, K_ref refKey (nil where it
// re-enters nothing), each erasure event it raises appended to events.
func testIndexLimitEraser(t *testing.T, writer *evsTestWriter, refKey []byte, events *[]*SidecarErasure) *IndexEraser {
	t.Helper()
	store := newIndexEvsStore(writer.repo, nil, false)
	eraser, err := indexNewEraser(&indexEraserArgs{
		store: store, eraseStore: store, repoId: writer.world.repoId, refId: writer.world.refId,
		repoKind: protocol.RepoKind_REPO_KIND_GENERAL, isAdmin: func(*indexFileVersion) bool { return true },
		format: DefaultIndexFormatSettings(), eraser: writer.world.signer.sidecarId, refKey: refKey, tables: testHeadTables,
		events: func(erasure *SidecarErasure) { *events = append(*events, erasure) },
		clock:  writer.test.clock, log: NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return eraser
}

// Every live slot, large entry and shard of the stand-in's main index holding an entry listed takes, in path order,
// as rekey objects.
func testIndexLimitHolding(t testing.TB, writer *evsTestWriter, listed indexEraseListed) []*indexRekeyObject {
	t.Helper()
	view := testDropLimitView(t, writer)
	objects := []*indexRekeyObject{}
	for path, file := range indexEraseLiveFiles(view) {
		plaintext, err := view.store.Read(context.Background(), file.file)
		if err != nil {
			t.Fatal(err)
		}
		holds, err := indexHolds(file.path, plaintext, listed, view.settings)
		if err != nil {
			t.Fatal(err)
		}
		if holds {
			objects = append(objects, indexNewRekeyObject(path, file.file.byteCount, DefaultIndexEraseSettings()))
		}
	}
	slices.SortFunc(objects, func(a *indexRekeyObject, b *indexRekeyObject) int {
		return strings.Compare(a.path, b.path)
	})
	return objects
}

// The states events raised, in order.
func testIndexErasureStates(events []*SidecarErasure) []string {
	states := []string{}
	for _, event := range events {
		states = append(states, event.State)
	}
	return states
}

// On a full cluster an erasure's CLOSURE of a bucket shard, an upload, is refused 507 there: the erasure waits as at
// the storage limit, its next try the 507's Retry-After, or now where it names none, with the objects and bytes the
// list holds and the floor's finish, since a 507 names no allowance; nothing is committed and the events go fenced
// (the CUT), rewriting, waiting. At its next try, with room, the pair commits and the shard no longer holds the listed
// version.
func testIndexRewriteOnAFullCluster(t *testing.T, noWait bool) {
	writer, capture, gate, key := testDropLimitShardWorld(t)
	if noWait {
		testIndexNoWaitBehind(capture, gate)
	}
	// the repo's erasure ref, which no ERASE has made yet, reads as a ref with no version, as at evs
	writer.world.autoRefs = true
	events := []*SidecarErasure{}
	eraser := testIndexLimitEraser(t, writer, nil, &events)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: key, Version: 1})
	listed := indexEraseListed(indexErasureSetListed(testDropLimitView(t, writer).erasureSet))
	objects := testIndexLimitHolding(t, writer, listed)
	if !slices.ContainsFunc(objects, func(object *indexRekeyObject) bool { return !object.staged }) {
		t.Fatal("no file holding the listed version is an upload")
	}
	settings := DefaultIndexEraseSettings()

	gate.set(evsTestDropLimitClusterFull)
	now := writer.test.clock.Now()
	wait := testIndexClusterFullWait(noWait)
	result, err := eraser.Rewrite(context.Background(), &IndexRewriteArgs{ErasureId: evsTestId("erasure")})
	if err != nil {
		t.Fatalf("a rewrite on a full cluster: %v", err)
	}
	waiting := result.Erasure
	if waiting == nil || waiting.State != SidecarErasureWaiting || !waiting.NextTry.Equal(now.Add(wait)) || result.PairCount != 0 {
		t.Fatalf("the rewrite on a full cluster: %+v, the erasure %+v", result, waiting)
	}
	if waiting.ObjectsLeft != int64(len(objects)) || waiting.BytesLeft != indexRekeyByteCount(objects) ||
		!waiting.Finish.Equal(indexEraseFinish(now, objects, settings.PairByteCount, settings)) {
		t.Fatalf("the wait names %d objects, %d B and a finish at %s", waiting.ObjectsLeft, waiting.BytesLeft, waiting.Finish)
	}
	// the CUT's, the pair's, and the wait's, the last the rewrite's own state
	if states := testIndexErasureStates(events); !slices.Equal(states, []string{SidecarErasureFenced, SidecarErasureRewriting, SidecarErasureWaiting}) ||
		*events[len(events)-1] != *waiting {
		t.Fatalf("the events %v", states)
	}
	// the pair's upload refused, and no push sent
	if uploads, pushes := gate.refused(); uploads != 1 || pushes != 0 {
		t.Fatalf("%d uploads and %d pushes refused", uploads, pushes)
	}
	if closures, err := writer.repo.ReadClosures(context.Background(), nil, 0); err != nil || len(closures) != 0 {
		t.Fatalf("%d CLOSUREs on a full cluster: %v", len(closures), err)
	}
	if held := testIndexLimitHolding(t, writer, listed); len(held) != len(objects) {
		t.Fatalf("%d files hold the listed version after a refused pair, %d before", len(held), len(objects))
	}

	// the next try, with room
	gate.set(evsTestDropLimitNone)
	writer.test.clock.advance(wait)
	result, err = eraser.Rewrite(context.Background(), &IndexRewriteArgs{ErasureId: evsTestId("erasure")})
	if err != nil || result.PairCount != 1 || result.FileCount != len(objects) || result.Erasure == nil || result.Erasure.State != SidecarErasureRewriting {
		t.Fatalf("the rewrite once there is room: %+v, %v", result, err)
	}
	closures, err := writer.repo.ReadClosures(context.Background(), nil, 0)
	if err != nil || len(closures) != 1 || closures[0].ErasureId != evsTestId("erasure") {
		t.Fatalf("%d CLOSUREs once there is room: %v", len(closures), err)
	}
	if held := testIndexLimitHolding(t, writer, listed); len(held) != 0 {
		t.Fatalf("files still holding the listed version: %d", len(held))
	}
}

// QD-1118: a CLOSURE's upload on a full cluster waits its 507's Retry-After, then goes on.
func TestIndexRewriteOnAFullClusterWaitsItsRetryAfter(t *testing.T) {
	testIndexRewriteOnAFullCluster(t, false)
}

// A 507 naming no wait keeps a refusal naming none's: the next try is now, the caller's next turn.
func TestIndexRewriteOnAFullClusterWithoutRetryAfterKeepsTheDefaultWait(t *testing.T) {
	testIndexRewriteOnAFullCluster(t, true)
}

// On a full cluster a run card's re-entry push, which adds payload, is refused 507 at its push and waits as at the
// storage limit, whatever wait the 507 names: tried again in ReentryRetryInterval, the event waiting with the card
// left. At its next try, with room, the card is entered in the eraser's head above the list.
func testIndexReenterOnAFullCluster(t *testing.T, noWait bool) {
	writer, gate := testIndexLimitWorld(t, noWait)
	testDropLimitIndexPush(t, writer, testLive("doc", 0, 1, testHeadKeys(0, 0)))
	refKey := testIndexDropEvsRefKey(t, writer)
	runId := evsTestId("run")
	stream := testNewRecordStream(protocol.RepoKind_REPO_KIND_VAULT, "a")
	stream.add(t, testRecordEntry(t, "context", RecordKindContext, runId, 1, &protocol.ContextBody{Harness: "claude-code", Title: "Rotate the keys"}))
	erased := stream.add(t, testRecordEntry(t, "change", RecordKindChange, runId, 2, nil))
	stream.add(t, testRecordEntry(t, "tool", RecordKindToolCall, runId, 3, nil))
	cardKey, err := indexDocKey(refKey, stream.refId, indexRunCardName(runId), 0)
	if err != nil {
		t.Fatal(err)
	}
	events := []*SidecarErasure{}
	eraser := testIndexLimitEraser(t, writer, refKey, &events)
	cut := testCut(t, eraser, "erasure", &IndexCutDocument{Key: cardKey, ThroughEpoch: true})
	args := &IndexReenterArgs{
		ErasureId: evsTestId("erasure"),
		Cards: []*IndexReenterCard{{
			Key: cardKey, Stream: stream, RunId: runId, Head: func(ctx context.Context) (uint64, error) { return stream.readTo, nil },
		}},
		Erasures: []*RecordStreamErasure{{ErasureId: evsTestId("erasure"), Keys: []*RecordSlotKey{&erased.slotKeys[0]}}},
	}
	interval := DefaultIndexEraseSettings().ReentryRetryInterval

	gate.set(evsTestDropLimitClusterFull)
	now := writer.test.clock.Now()
	result, err := eraser.Reenter(context.Background(), args)
	if err != nil || !result.Waiting || !result.NextTry.Equal(now.Add(interval)) || result.EnteredCount != 0 || result.PushCount != 0 {
		t.Fatalf("the re-entry on a full cluster: %+v, %v", result, err)
	}
	if uploads, pushes := gate.refused(); uploads != 0 || pushes != 1 {
		t.Fatalf("%d uploads and %d pushes refused", uploads, pushes)
	}
	// the CUT's, and the wait's with the card left
	states := testIndexErasureStates(events)
	if !slices.Equal(states, []string{SidecarErasureFenced, SidecarErasureWaiting}) || events[1].ObjectsLeft != 1 || !events[1].NextTry.Equal(result.NextTry) {
		t.Fatalf("the events %v", states)
	}

	// the next try, with room
	gate.set(evsTestDropLimitNone)
	writer.test.clock.advance(interval)
	result, err = eraser.Reenter(context.Background(), args)
	if err != nil || result.Waiting || result.EnteredCount != 1 || result.PushCount != 1 {
		t.Fatalf("the re-entry once there is room: %+v, %v", result, err)
	}
	view := testDropLimitView(t, writer)
	documents, err := view.bucketDocuments(context.Background(), view.writeRoot().newestBucket())
	if err != nil {
		t.Fatal(err)
	}
	want, err := indexRunCardVersion(cut.Version, stream.readTo, DefaultIndexFormatSettings().CardVersionBitCount)
	if err != nil {
		t.Fatal(err)
	}
	entries := documents.of(cardKey)
	if len(entries) != 1 || entries[0].version != want || entries[0].writer != writer.world.signer.sidecarId || !entries[0].head {
		t.Fatalf("the card's entries %+v, want version %d in the eraser's head", entries, want)
	}
}

// QD-1118: a re-entry on a full cluster waits as at the storage limit.
func TestIndexReenterOnAFullClusterWaitsAsAtTheLimit(t *testing.T) {
	testIndexReenterOnAFullCluster(t, false)
}

// A 507 naming no wait keeps the re-entry's own: ReentryRetryInterval.
func TestIndexReenterOnAFullClusterWithoutRetryAfterKeepsTheDefaultWait(t *testing.T) {
	testIndexReenterOnAFullCluster(t, true)
}

// QD-1132: an erasure whose CUT lists documents no index file holds (the index off when they were written, a run card
// never built) finds no file to rewrite, so no pair's ERASE is left to say complete. A rewrite whose history did not
// walk whole sends nothing; one asked no Completion leaves the erasure rewriting for its caller to end; one asked it
// sends a completion ERASE naming the key the erasure's first ERASE destroyed, saying complete with the caller's note,
// and the erasure reads done and is sent nothing more. The next CUT, another erasure's, drops it from the set.
func TestIndexRewriteEndsAnErasureWithNothingToRewriteByACompletion(t *testing.T) {
	ctx := context.Background()
	world := testEraseWorldWithCopies(t)
	eraser := world.completingEraser(t)
	erasureId := evsTestId("erasure")
	// the caller's first ERASE took the entry's own key before the CUT, as a record erasure's does (QD-781)
	entryKey := &EvsErasedKey{SlotId: evsTestId("entry slot")}
	if err := world.evs.as(evsTestId("eraser")).Erase(ctx, &indexErasePush{erasureId: erasureId, keys: []*EvsErasedKey{entryKey}}); err != nil {
		t.Fatal(err)
	}
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("never indexed", 0), Version: 1},
		&IndexCutDocument{Key: testIndexId("card never built", 0), ThroughEpoch: true})
	rewrite := func(completion bool) *IndexRewriteResult {
		t.Helper()
		result, err := eraser.Rewrite(ctx, &IndexRewriteArgs{ErasureId: erasureId, Complete: true, Note: []byte("note"), Completion: completion})
		if err != nil || result.Erasure == nil {
			t.Fatalf("the rewrite: %+v, %v", result, err)
		}
		return result
	}
	world.evs.retainedIncomplete = true
	if unproven := rewrite(true); unproven.Completed || !unproven.Unproven || unproven.Erasure.State != SidecarErasureRewriting || len(world.evs.erases) != 1 {
		t.Fatalf("an unproven rewrite: %+v, %d ERASEs", unproven, len(world.evs.erases))
	}
	world.evs.retainedIncomplete = false
	if left := rewrite(false); left.Completed || left.PairCount != 0 || left.Erasure.State != SidecarErasureRewriting || len(world.evs.erases) != 1 {
		t.Fatalf("a rewrite asked no completion: %+v, %d ERASEs", left, len(world.evs.erases))
	}
	result := rewrite(true)
	if !result.Completed || result.PairCount != 0 || result.Erasure.State != SidecarErasureDone || len(world.evs.erases) != 2 {
		t.Fatalf("the completion: %+v, %d ERASEs", result, len(world.evs.erases))
	}
	completion := world.evs.erases[1]
	if !completion.completion || !completion.erased.complete || completion.erasureId != erasureId || len(completion.erased.keys) != 1 ||
		*completion.erased.keys[0] != *entryKey || string(completion.note) != "note" {
		t.Fatalf("the completion ERASE: %+v", completion)
	}
	if again := rewrite(true); again.Erasure.State != SidecarErasureDone || len(world.evs.erases) != 2 {
		t.Fatalf("a rewrite after done: %+v, %d ERASEs", again, len(world.evs.erases))
	}
	testCut(t, eraser, "later", &IndexCutDocument{Key: testIndexId("d", 0), Version: 1})
	set := testErasureSetOf(t, world.view(t, evsTestId("reader")))
	if indexErasureOf(set, erasureId) != nil || indexErasureOf(set, evsTestId("later")) == nil {
		t.Fatal("the next CUT kept the completed erasure, or listed nothing of its own")
	}
}

// QD-1132: a crash between the last CLOSURE and its ERASE leaves nothing else to rewrite. The resume lists first, finds
// nothing else, and its ERASE of the orphaned CLOSURE's keys says complete with the caller's note, so the erasure
// ends by that ERASE, with no completion ERASE after it, and no stored version a key still opens holds a listed one.
func TestIndexResumeEndsAnErasureWithItsOrphanedClosuresErase(t *testing.T) {
	ctx := context.Background()
	world := testEraseWorldWithCopies(t)
	eraser := world.eraser(t, nil)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("d", 0), Version: 1})
	crash := errors.New("the device stopped")
	world.evs.eraseRefusals = []error{crash}
	if _, err := eraser.Rewrite(ctx, &IndexRewriteArgs{ErasureId: evsTestId("erasure"), Complete: true}); !errors.Is(err, crash) {
		t.Fatalf("the crashed rewrite: %v", err)
	}
	if len(world.evs.closures) != 1 || len(world.evs.erases) != 0 {
		t.Fatalf("%d CLOSUREs and %d ERASEs before the resume: one pair should hold every file", len(world.evs.closures), len(world.evs.erases))
	}
	orphan := world.evs.closures[0].closed.keys
	resumed, err := world.eraser(t, nil).Resume(ctx, &IndexResumeArgs{
		ErasureId: evsTestId("erasure"), Role: IndexResumeEraser, Complete: true, Note: []byte("note"), Completion: true,
	})
	if err != nil || resumed.Rewrite == nil || !resumed.Rewrite.Completed || resumed.Rewrite.PairCount != 0 ||
		resumed.Rewrite.Erasure.State != SidecarErasureDone {
		t.Fatalf("the resume: %+v, %v", resumed, err)
	}
	if len(world.evs.erases) != 1 {
		t.Fatalf("%d ERASEs after the resume", len(world.evs.erases))
	}
	erase := world.evs.erases[0]
	if !erase.erased.complete || erase.completion || string(erase.note) != "note" ||
		!slices.EqualFunc(erase.erased.keys, orphan, func(a *EvsErasedKey, b *EvsErasedKey) bool { return *a == *b }) {
		t.Fatalf("the orphaned CLOSURE's ERASE: %+v", erase)
	}
	world.evs.sweep(t, world.listed(t))
}

// QD-1132's question: evs cannot read an ERASE's note, and until the question is answered it refuses a completion
// as NOTHING_TO_ERASE, as any ERASE whose keys are gone. The rewrite reads evs's state back after it, finds the
// erasure incomplete, and leaves it rewriting: nothing reads done that evs does not show complete.
func TestIndexRewriteLeavesAnErasureRewritingWhereEvsTakesNoCompletion(t *testing.T) {
	ctx := context.Background()
	world := testEraseWorldWithCopies(t)
	world.evs.refusesCompletions = true
	eraser := world.eraser(t, nil)
	erasureId := evsTestId("erasure")
	if err := world.evs.as(evsTestId("eraser")).Erase(ctx, &indexErasePush{erasureId: erasureId, keys: []*EvsErasedKey{{SlotId: evsTestId("entry slot")}}}); err != nil {
		t.Fatal(err)
	}
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("never indexed", 0), Version: 1})
	result, err := eraser.Rewrite(ctx, &IndexRewriteArgs{ErasureId: erasureId, Complete: true, Completion: true})
	if err != nil || result.Completed || result.Erasure == nil || result.Erasure.State != SidecarErasureRewriting {
		t.Fatalf("the rewrite: %+v, %v", result, err)
	}
	if len(world.evs.erases) != 1 || world.evs.erases[0].erased.complete {
		t.Fatalf("%d ERASEs committed", len(world.evs.erases))
	}
}
