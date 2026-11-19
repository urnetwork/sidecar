//go:build sidecar_testhooks && !ios_extension && !js

// Erasure on a search world, for FS-78's, FS-111's and FS-112's schedules (SEARCH-M10-37): the world's store as an
// eraser's seam to evs (indexEraseStore), so an erasure's CUT, its CLOSURE and ERASE pairs, its waits at the storage
// limit and its resume run through the index's own eraser (SEARCH-M10-16, SEARCH-M10-17) on the world's store and
// clock, beside the writers, merges, roll-ups, builds and backfills the world already runs; and FI-19's sweep over every
// version the world's index files ever had.
//
//	keys      a slot-keyed world (record-class repos and group inboxes, §11.14's keys row) keeps each index path's key in
//	          one slot that only that path's versions name, reused by each next version until a CLOSURE draws a fresh
//	          one in a new slot, a creation after a removal starting a new life in a new slot; a general world's
//	          versions name no slot, each riding its segment, which the purge deletes. Each document's own keys, the
//	          mail's or the entry's that its erasure's first ERASE takes, are one slot a content path, standing for the
//	          caller's (§15.7's message, §16.8's entry)
//	closure   a CLOSURE replaces only each path's standing version, never past its length, never creates or removes
//	          one, names no index_epoch and lists every slot any version of its paths named (§11.12's rekey row); a
//	          409 names a path another push changed. At the storage limit (SetClosureAllowance) an eraser's closure
//	          bytes stay within its own allowance a UTC day, a 429 naming the allowance, what it used and the next
//	          00:00 UTC, an upload past ClosureUploadMaxByteCount is a quota refusal, and each ?closure=1 upload (a
//	          file past StagedMaxByteCount) waits one PacingTurn on the world's clock (§20.7's pacing, one eraser
//	          asking)
//	erase     an ERASE destroys the slots it names, under a hold too; one naming only slots already gone is done and
//	          commits nothing (NOTHING_TO_ERASE)
//	history   every version an index path had beside its standing one is retained, and served only while a hold keeps
//	          it and its key stands (Retained, Read)
//	purge     a replaced or removed version's ciphertext goes PurgeAfter after the push that replaced it, unless a hold
//	          keeps it: one that stood at the hold's placement or was not yet purged then; a staged version's bytes stay
//	          in their batch StagedRetention after the push that wrote it, under its path's slot in a slot-keyed world
//	          (§11.12's bytes row)
//	sweep     FI-19: a stored version holding a listed document at or below its listed version, which a current
//	          reader's keys open (its slot live in a slot-keyed world; any stored copy in a general one), is a breach
//	          once its erasure completes (Holding)
//
// Stands in for evs's eraser routes: the real ones run on the evs world (fs111.go) and on T3 through server's evshost.
// Only the sidecar_testhooks build has it, which no release leg is (§22.4). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// What a world's erasure model holds to (QD-702): evs's values, as §11.12 and §11.13 give them.
type SearchTestErasureSettings struct {
	// Each index path keeps its key in a slot of its own (record-class repos, group inboxes); false keys each version
	// by its segment, as a general repo's file-mode index.
	SlotKeyed bool
	// From the push that replaced or removed a version to the purge's delete of its ciphertext: 60 s, FI-16's in-flight
	// allowance.
	PurgeAfter time.Duration
	// How long a staged version's bytes stay in their batch after the push that wrote it: 26 h (§11.12's bytes row).
	StagedRetention time.Duration
	// The largest version written as a staged record rather than a ?closure=1 upload: 16 KiB, a slot's record.
	StagedMaxByteCount int
	// The largest ?closure=1 upload: 1,088 KiB (§11.12's rekey row).
	ClosureUploadMaxByteCount int64
	// The turn of §20.7's pacing each ?closure=1 upload waits at the limit, one eraser asking: 250 ms.
	PacingTurn time.Duration
}

// evs's values for a slot-keyed repo, a fresh value each call.
func DefaultSearchTestErasureSettings() *SearchTestErasureSettings {
	return &SearchTestErasureSettings{
		SlotKeyed:                 true,
		PurgeAfter:                60 * time.Second,
		StagedRetention:           26 * time.Hour,
		StagedMaxByteCount:        16 * 1024,
		ClosureUploadMaxByteCount: 1088 * 1024,
		PacingTurn:                250 * time.Millisecond,
	}
}

// A world's erasure model: see the file header.
type SearchTestErasure struct {
	world    *SearchTestWorld
	settings *SearchTestErasureSettings

	stateLock sync.Mutex
	// the slot each CLOSURE drew, by the version it wrote
	closureSlots map[searchTestPathVersion]Id
	destroyed    map[Id]bool
	closures     []*searchTestErasureClosure
	erases       []*searchTestErasureErase
	// an eraser's closure allowance a UTC day at the limit, 0 below it; what each eraser used on its day
	allowance    int64
	usedByteDays map[Id]*searchTestErasureUsed
	// what the CLOSUREs took: bytes, ?closure=1 uploads and staged records
	closureByteCount int64
	uploadCount      int
	stagedCount      int
	// the hold, while one stands: the ref version and time it was placed at
	holdVersion uint64
	holdAt      time.Time
	held        bool
	// refusals the next CLOSUREs answer, before anything else
	closureRefusals []error
}

// One (path, version) pair.
type searchTestPathVersion struct {
	path    string
	version uint64
}

// One committed CLOSURE.
type searchTestErasureClosure struct {
	erasureId Id
	signer    Id
	closed    *indexEraseClosed
	at        time.Time
}

// One committed ERASE.
type searchTestErasureErase struct {
	erasureId Id
	signer    Id
	erased    *indexEraseErased
	at        time.Time
}

// What an eraser spent of its allowance on one UTC day.
type searchTestErasureUsed struct {
	day       int64
	byteCount int64
}

// The world's erasure model under settings, nil taking the defaults. A world has one: call it once.
func (self *SearchTestWorld) NewErasure(settings *SearchTestErasureSettings) *SearchTestErasure {
	if settings == nil {
		settings = DefaultSearchTestErasureSettings()
	}
	return &SearchTestErasure{
		world: self, settings: settings, closureSlots: map[searchTestPathVersion]Id{}, destroyed: map[Id]bool{},
		usedByteDays: map[Id]*searchTestErasureUsed{},
	}
}

// The doc_key path's chunk takes, as every reader of the repo derives it.
func (self *SearchTestWorld) DocKeyOf(path string, chunk uint32) ([indexIdByteCount]byte, error) {
	return indexDocKey(self.refKey, self.refId, []byte(path), chunk)
}

// --- the history, keys and purge ---

// One version of an index path over the ref's history.
type searchTestHistoryVersion struct {
	file      *indexFileVersion
	plaintext []byte
	// The ref version and signed time of the push that replaced or removed it; 0 while it stands.
	endedAt uint64
	endedMs int64
	removed bool
	// Its key's slot in a slot-keyed world, zero in a general one.
	slotId Id
	// A CLOSURE wrote it.
	closure bool
}

// Every index path's versions over the ref's history, oldest first, each with its slot.
func (self *SearchTestErasure) history() map[string][]*searchTestHistoryVersion {
	ref := self.world.ref
	ref.stateLock.Lock()
	states := slices.Clone(ref.states)
	ref.stateLock.Unlock()
	self.stateLock.Lock()
	closureSlots := map[searchTestPathVersion]Id{}
	for key, slotId := range self.closureSlots {
		closureSlots[key] = slotId
	}
	self.stateLock.Unlock()

	paths := map[string][]*searchTestHistoryVersion{}
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
			before, after := previous.files[path], current.files[path]
			versions := paths[path]
			ended := func(removed bool) {
				if 0 < len(versions) {
					last := versions[len(versions)-1]
					last.endedAt, last.endedMs, last.removed = current.head.version, current.head.signedTimeMs, removed
				}
			}
			switch {
			case after != nil && (before == nil || before.version.version != after.version.version):
				if before != nil {
					ended(false)
				}
				file := *after.version
				versions = append(versions, &searchTestHistoryVersion{file: &file, plaintext: after.plaintext})
			case after == nil && before != nil:
				ended(true)
			}
			paths[path] = versions
		}
	}
	for path, versions := range paths {
		life := 0
		for index, version := range versions {
			slotId, closed := closureSlots[searchTestPathVersion{path: path, version: version.file.version}]
			switch {
			case closed:
				version.closure = true
			case index == 0 || versions[index-1].removed:
				life += 1
				slotId = self.lifeSlot(path, life)
			default:
				slotId = versions[index-1].slotId
			}
			if self.settings.SlotKeyed {
				version.slotId = slotId
			} else {
				version.slotId = Id{}
			}
		}
	}
	return paths
}

// The slot of path's life'th life.
func (self *SearchTestErasure) lifeSlot(path string, life int) Id {
	digest := sha256.Sum256(fmt.Appendf(nil, "search test slot %s %s %d", self.world.repoId, path, life))
	return Id(digest[:16])
}

// Whether a hold keeps version: it stood at the hold's placement, or was replaced and not yet purged then. The state
// lock held.
func (self *SearchTestErasure) heldWithLock(version *searchTestHistoryVersion) bool {
	if !self.held || self.holdVersion < version.file.commitVersion {
		return false
	}
	return version.endedAt == 0 || self.holdVersion < version.endedAt ||
		self.holdAt.Before(time.UnixMilli(version.endedMs).Add(self.settings.PurgeAfter))
}

// What is left of a version now: its ciphertext stored (standing, held, or not yet purged), its staged bytes in their
// batch, and whether its key is destroyed. The state lock held.
func (self *SearchTestErasure) storedWithLock(version *searchTestHistoryVersion, now time.Time) (stored bool, staged bool, destroyed bool) {
	held := self.heldWithLock(version)
	stored = version.endedAt == 0 || held || now.Before(time.UnixMilli(version.endedMs).Add(self.settings.PurgeAfter))
	staged = version.file.byteCount <= self.settings.StagedMaxByteCount &&
		now.Before(time.UnixMilli(version.file.signedTimeMs).Add(self.settings.StagedRetention))
	destroyed = self.settings.SlotKeyed && self.destroyed[version.slotId]
	return stored, staged, destroyed
}

// --- documents' own keys ---

// The slot of path's own keys: the message's or the entry's, which its erasure's first ERASE takes.
func (self *SearchTestErasure) ContentKey(path string) *EvsErasedKey {
	digest := sha256.Sum256(fmt.Appendf(nil, "search test content key %s %s", self.world.repoId, path))
	return &EvsErasedKey{SlotId: Id(digest[:16])}
}

// Whether path's body still opens: its own keys stand.
func (self *SearchTestErasure) ContentOpens(path string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return !self.destroyed[self.ContentKey(path).SlotId]
}

// The first ERASE of an erasure, of paths' own keys, by signer, as its caller (mail, the record) commits it at once,
// which re-keys nothing and waits for no allowance (§11.12's closure row); complete where it ends the erasure.
func (self *SearchTestErasure) EraseOwnKeys(ctx context.Context, signer Id, erasureId Id, paths []string, complete bool) error {
	keys := []*EvsErasedKey{}
	for _, path := range paths {
		keys = append(keys, self.ContentKey(path))
	}
	return self.store(signer).Erase(ctx, &indexErasePush{erasureId: erasureId, keys: keys, complete: complete})
}

// --- the faults and the limit ---

// Puts the network at the storage limit, or spent, with each eraser's closure allowance a UTC day (§20.4's
// evs_closure_bytes_per_day, never under evs_closure_bytes_floor); 0 takes it below the limit, where none applies.
func (self *SearchTestErasure) SetClosureAllowance(byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.allowance = byteCount
}

// Places a hold on the repo now, or lifts it: a hold keeps what existed at its placement, and pauses no ERASE.
func (self *SearchTestErasure) SetHold(on bool) {
	ref := self.world.ref
	ref.stateLock.Lock()
	version := ref.states[len(ref.states)-1].head.version
	ref.stateLock.Unlock()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.held, self.holdVersion, self.holdAt = on, version, self.world.clock.Now()
}

// The next CLOSUREs answer refusals, in order, before anything else.
func (self *SearchTestErasure) RefuseClosures(refusals ...error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closureRefusals = append(self.closureRefusals, refusals...)
}

// A 409 for a path another push changed, as a CLOSURE refusal.
func SearchTestClosureConflict() error {
	return &indexRefusal{kind: indexRefusalConflict}
}

// What the CLOSUREs took: closure bytes, ?closure=1 uploads and staged records.
func (self *SearchTestErasure) ClosureCounts() (int64, int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closureByteCount, self.uploadCount, self.stagedCount
}

// One committed ERASE as a schedule reads it.
type SearchTestErase struct {
	ErasureId Id
	Signer    Id
	KeyCount  int
	Complete  bool
	At        time.Time
}

// Every committed ERASE, in order.
func (self *SearchTestErasure) Erases() []SearchTestErase {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	erases := []SearchTestErase{}
	for _, erase := range self.erases {
		erases = append(erases, SearchTestErase{
			ErasureId: erase.erasureId, Signer: erase.signer, KeyCount: len(erase.erased.keys), Complete: erase.erased.complete,
			At: erase.at,
		})
	}
	return erases
}

// One committed CLOSURE as a schedule reads it.
type SearchTestClosure struct {
	ErasureId  Id
	Signer     Id
	RefVersion uint64
	KeyCount   int
	At         time.Time
}

// Every committed CLOSURE, in order.
func (self *SearchTestErasure) Closures() []SearchTestClosure {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	closures := []SearchTestClosure{}
	for _, closure := range self.closures {
		closures = append(closures, SearchTestClosure{
			ErasureId: closure.erasureId, Signer: closure.signer, RefVersion: closure.closed.version,
			KeyCount: len(closure.closed.keys), At: closure.at,
		})
	}
	return closures
}

// Whether an ERASE of erasureId said complete.
func (self *SearchTestErasure) Complete(erasureId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, erase := range self.erases {
		if erase.erasureId == erasureId && erase.erased.complete {
			return true
		}
	}
	return false
}

// --- the sweep ---

// One stored version of an index file holding a listed document.
type SearchTestHolding struct {
	Path    string
	Version uint64
	// It stands at the head; a hold keeps it; its ciphertext or its staged bytes are still stored.
	Live   bool
	Held   bool
	Stored bool
	Staged bool
	// Its key is destroyed, so no reader opens it.
	Destroyed bool
	// A CLOSURE wrote it, and the ref version that committed it.
	Closure       bool
	CommitVersion uint64
}

// Whether a current reader's keys open it: stored, or staged, under a key no ERASE destroyed.
func (self SearchTestHolding) Openable() bool {
	return (self.Stored || self.Staged) && !self.Destroyed
}

// Every version the world's index files ever had that holds one of documents at or below its version, an entry, row
// or posting of it, with what is left of it now: FI-19's sweep reads the openable ones.
func (self *SearchTestErasure) Holding(documents []*IndexCutDocument) ([]SearchTestHolding, error) {
	listed := indexEraseListed{}
	for _, document := range documents {
		listed[document.Key] = max(listed[document.Key], document.Version)
	}
	now := self.world.clock.Now()
	holding := []SearchTestHolding{}
	for path, versions := range self.history() {
		parsed, ok := indexParsePath(path, false)
		if !ok || !indexPathHoldsDocuments(parsed.kind) {
			continue
		}
		for _, version := range versions {
			holds, err := indexHolds(parsed, version.plaintext, listed, self.world.format)
			if err != nil {
				return nil, fmt.Errorf("search test erasure: %s at %d: %w", path, version.file.version, err)
			}
			if !holds {
				continue
			}
			self.stateLock.Lock()
			stored, staged, destroyed := self.storedWithLock(version, now)
			held := self.heldWithLock(version)
			self.stateLock.Unlock()
			holding = append(holding, SearchTestHolding{
				Path: path, Version: version.file.version, Live: version.endedAt == 0, Held: held, Stored: stored,
				Staged: staged, Destroyed: destroyed, Closure: version.closure, CommitVersion: version.file.commitVersion,
			})
		}
	}
	slices.SortFunc(holding, func(a SearchTestHolding, b SearchTestHolding) int {
		if a.Path != b.Path {
			return bytes.Compare([]byte(a.Path), []byte(b.Path))
		}
		return int(a.Version) - int(b.Version)
	})
	return holding, nil
}

// Whether the version of path the world's index had at version still has openable ciphertext: a current reader's keys
// open it, as FS-78's "openable to key holders until its part's ERASE" reads it.
func (self *SearchTestErasure) Openable(path string, version uint64) bool {
	now := self.world.clock.Now()
	for _, held := range self.history()[path] {
		if held.file.version != version {
			continue
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		stored, staged, destroyed := self.storedWithLock(held, now)
		return (stored || staged) && !destroyed
	}
	return false
}

// --- the eraser's seam ---

// An eraser's handle on the world: the index's reads through the world's store, a held version served beside the
// head's, and evs's eraser routes.
type searchTestEraseStore struct {
	erasure *SearchTestErasure
	handle  *searchTestStore
	signer  Id
}

// signer's handle.
func (self *SearchTestErasure) store(signer Id) *searchTestEraseStore {
	return &searchTestEraseStore{erasure: self, handle: self.world.ref.store(signer), signer: signer}
}

var _ indexEraseStore = (*searchTestEraseStore)(nil)

// See indexRefStore.
func (self *searchTestEraseStore) Head(ctx context.Context) (*indexRefHead, error) {
	return self.handle.Head(ctx)
}

// See indexRefStore.
func (self *searchTestEraseStore) List(ctx context.Context, refVersion uint64) (*indexListing, error) {
	return self.handle.List(ctx, refVersion)
}

// See indexRefStore.
func (self *searchTestEraseStore) History(ctx context.Context, path string, refVersion uint64) ([]*indexFileVersion, error) {
	return self.handle.History(ctx, path, refVersion)
}

// See indexRefStore.
func (self *searchTestEraseStore) Commit(ctx context.Context, push *indexPush) (*indexCommitted, error) {
	return self.handle.Commit(ctx, push)
}

// See indexRefStore: the head's version, or one a hold keeps whose key still stands; a held version whose key an ERASE
// destroyed no longer opens, so it reads as collected.
func (self *searchTestEraseStore) Read(ctx context.Context, file *indexFileVersion) ([]byte, error) {
	plaintext, err := self.handle.Read(ctx, file)
	if !errors.Is(err, errIndexCollected) {
		return plaintext, err
	}
	for _, version := range self.erasure.history()[file.path] {
		if version.file.version != file.version {
			continue
		}
		self.erasure.stateLock.Lock()
		held := self.erasure.heldWithLock(version)
		destroyed := self.erasure.settings.SlotKeyed && self.erasure.destroyed[version.slotId]
		self.erasure.stateLock.Unlock()
		if held && !destroyed {
			return bytes.Clone(version.plaintext), nil
		}
	}
	return nil, err
}

// See indexEraseStore: every slot any version of each path named, each once; none in a general world.
func (self *searchTestEraseStore) KeysOf(ctx context.Context, paths []string) ([]*EvsErasedKey, error) {
	if !self.erasure.settings.SlotKeyed {
		return []*EvsErasedKey{}, nil
	}
	history := self.erasure.history()
	keys := []*EvsErasedKey{}
	named := map[Id]bool{}
	for _, path := range paths {
		for _, version := range history[path] {
			if !named[version.slotId] {
				named[version.slotId] = true
				keys = append(keys, &EvsErasedKey{SlotId: version.slotId})
			}
		}
	}
	return keys, nil
}

// See indexEraseStore: every version beside each standing one, removed paths' included, served while held.
func (self *searchTestEraseStore) Retained(ctx context.Context) (*indexRetained, error) {
	retained := &indexRetained{complete: true}
	history := self.erasure.history()
	self.erasure.stateLock.Lock()
	defer self.erasure.stateLock.Unlock()
	for _, versions := range history {
		for _, version := range versions {
			if version.endedAt == 0 {
				continue
			}
			file := *version.file
			retained.versions = append(retained.versions, &indexRetainedVersion{
				file: &file, readable: self.erasure.heldWithLock(version), replacedVersion: version.endedAt,
				replacedMs: version.endedMs,
			})
		}
	}
	slices.SortFunc(retained.versions, func(a *indexRetainedVersion, b *indexRetainedVersion) int {
		if a.file.path != b.file.path {
			return bytes.Compare([]byte(a.file.path), []byte(b.file.path))
		}
		return int(a.file.version) - int(b.file.version)
	})
	return retained, nil
}

// See indexEraseStore.
func (self *searchTestEraseStore) Progress(ctx context.Context, erasureId Id) (*indexEraseProgress, error) {
	self.erasure.stateLock.Lock()
	defer self.erasure.stateLock.Unlock()
	progress := &indexEraseProgress{}
	for _, closure := range self.erasure.closures {
		if closure.erasureId == erasureId {
			progress.closures = append(progress.closures, closure.closed)
		}
	}
	for _, erase := range self.erasure.erases {
		if erase.erasureId == erasureId {
			progress.erases = append(progress.erases, erase.erased)
		}
	}
	return progress, nil
}

// See indexEraseStore and the file header's closure row.
func (self *searchTestEraseStore) Closure(ctx context.Context, closure *indexClosurePush) (*indexCommitted, error) {
	erasure := self.erasure
	settings := erasure.settings
	now := erasure.world.clock.Now()
	byteCount := int64(0)
	uploads, staged := 0, 0
	for _, file := range closure.files {
		byteCount += int64(len(file.plaintext))
		if settings.StagedMaxByteCount < len(file.plaintext) {
			uploads += 1
		} else {
			staged += 1
		}
	}
	history := erasure.history()
	limited := false
	err := func() error {
		erasure.stateLock.Lock()
		defer erasure.stateLock.Unlock()
		if 0 < len(erasure.closureRefusals) {
			refusal := erasure.closureRefusals[0]
			erasure.closureRefusals = erasure.closureRefusals[1:]
			return refusal
		}
		named := map[Id]bool{}
		for _, key := range closure.erased {
			named[key.SlotId] = true
		}
		for _, file := range closure.files {
			versions := history[file.path]
			if file.replaces == 0 || len(versions) == 0 || versions[len(versions)-1].endedAt != 0 {
				return errors.New("search test erasure: a CLOSURE that creates a path")
			}
			replaced := versions[len(versions)-1]
			if replaced.file.version != file.replaces {
				return &indexRefusal{kind: indexRefusalConflict, paths: []string{file.path}}
			}
			if replaced.file.byteCount < len(file.plaintext) || EvsPadme(uint64(replaced.file.byteCount)) < uint64(len(file.plaintext)) {
				return errors.New("search test erasure: a CLOSURE that grows a file past its replaced length")
			}
			if settings.StagedMaxByteCount < len(file.plaintext) && settings.ClosureUploadMaxByteCount < int64(len(file.plaintext)) {
				return &indexRefusal{kind: indexRefusalQuota, quota: &QuotaRefusal{LimitKey: "closure_upload_bytes", Limit: settings.ClosureUploadMaxByteCount}}
			}
			for _, version := range versions {
				if settings.SlotKeyed && !named[version.slotId] {
					return errors.New("search test erasure: a CLOSURE that leaves a replaced version's slot off its list")
				}
			}
		}
		if 0 < erasure.allowance {
			limited = true
			used := erasure.usedByteDays[self.signer]
			if used == nil || used.day != indexUtcDay(now) {
				used = &searchTestErasureUsed{day: indexUtcDay(now)}
				erasure.usedByteDays[self.signer] = used
			}
			if erasure.allowance < used.byteCount+byteCount {
				return &indexRefusal{
					kind: indexRefusalRetry, retryAfter: indexNextUtcMidnight(now).Sub(now),
					quota: &QuotaRefusal{LimitKey: "evs_closure_bytes_per_day", Limit: erasure.allowance, Used: used.byteCount},
				}
			}
		}
		return nil
	}()
	if err != nil {
		return nil, err
	}
	committed, err := func() (*indexCommitted, error) {
		ref := erasure.world.ref
		ref.stateLock.Lock()
		defer ref.stateLock.Unlock()
		return ref.commitClosureWithLock(self.signer, closure)
	}()
	if err != nil {
		return nil, err
	}
	func() {
		erasure.stateLock.Lock()
		defer erasure.stateLock.Unlock()
		for _, file := range committed.files {
			digest := sha256.Sum256(fmt.Appendf(nil, "search test closure slot %s %s %d", erasure.world.repoId, file.path, file.version))
			erasure.closureSlots[searchTestPathVersion{path: file.path, version: file.version}] = Id(digest[:16])
		}
		erasure.closures = append(erasure.closures, &searchTestErasureClosure{
			erasureId: closure.erasureId, signer: self.signer, at: now,
			closed: &indexEraseClosed{version: committed.version, keys: slices.Clone(closure.erased)},
		})
		erasure.closureByteCount += byteCount
		erasure.uploadCount += uploads
		erasure.stagedCount += staged
		if limited {
			erasure.usedByteDays[self.signer].byteCount += byteCount
		}
	}()
	if limited && 0 < uploads && 0 < settings.PacingTurn {
		// each ?closure=1 upload waits its turn of the network's pacing, the lock released
		erasure.world.clock.Advance(time.Duration(uploads) * settings.PacingTurn)
	}
	return committed, nil
}

// See indexEraseStore and the file header's erase row.
func (self *searchTestEraseStore) Erase(ctx context.Context, erase *indexErasePush) error {
	erasure := self.erasure
	if len(erase.keys) == 0 {
		return errors.New("search test erasure: an ERASE of no key")
	}
	erasure.stateLock.Lock()
	defer erasure.stateLock.Unlock()
	live := false
	for _, key := range erase.keys {
		live = live || !erasure.destroyed[key.SlotId]
	}
	if !live {
		// NOTHING_TO_ERASE: done, and nothing commits
		return nil
	}
	for _, key := range erase.keys {
		erasure.destroyed[key.SlotId] = true
	}
	now := erasure.world.clock.Now()
	erasure.erases = append(erasure.erases, &searchTestErasureErase{
		erasureId: erase.erasureId, signer: self.signer, at: now,
		erased: &indexEraseErased{keys: slices.Clone(erase.keys), complete: erase.complete, timeMs: now.UnixMilli()},
	})
	return nil
}

// Commits closure by signer at the head: each file replacing the version it names, at the next ref version, no
// index_epoch named or moved. The checks are the caller's (Closure). The lock held.
func (self *searchTestRef) commitClosureWithLock(signer Id, closure *indexClosurePush) (*indexCommitted, error) {
	head := self.states[len(self.states)-1]
	conflicts := []string{}
	for _, file := range closure.files {
		if current := head.files[file.path]; current == nil || current.version.version != file.replaces {
			conflicts = append(conflicts, file.path)
		}
	}
	if 0 < len(conflicts) {
		slices.Sort(conflicts)
		return nil, &indexRefusal{kind: indexRefusalConflict, paths: conflicts}
	}
	next := self.nextStateWithLock(head, closure.pushId, closure.signedTimeMs, signer)
	committed := &indexCommitted{version: next.head.version}
	for _, file := range closure.files {
		stored := &searchTestStored{
			version: &indexFileVersion{
				path: file.path, version: file.replaces + 1, commitVersion: next.head.version,
				contentSha256: sha256.Sum256(file.plaintext), byteCount: len(file.plaintext), signerSidecarId: signer,
				signedTimeMs: closure.signedTimeMs,
			},
			plaintext: bytes.Clone(file.plaintext),
		}
		next.files[file.path] = stored
		written := *stored.version
		committed.files = append(committed.files, &written)
	}
	self.states = append(self.states, next)
	return committed, nil
}

// --- erasers ---

// What an eraser of the world's ref is made of.
type SearchTestEraserArgs struct {
	// The device erasing; zero is the world's admin. Another device of the admin's member is named by AddAdmin.
	Signer Id
	// Nil takes DefaultIndexEraseSettings.
	Settings *IndexEraseSettings
	// §5.4's erasure event, at each change of a rewrite's state; nil raises none.
	Events func(erasure *SidecarErasure)
}

// An eraser of the world's ref through the erasure model, on the world's clock: a fresh one each call, as a device
// starting holds none of its memory.
func (self *SearchTestErasure) NewEraser(args *SearchTestEraserArgs) (*IndexEraser, error) {
	if args == nil {
		args = &SearchTestEraserArgs{}
	}
	signer := args.Signer
	if signer == (Id{}) {
		signer = self.world.AdminId()
	}
	store := self.store(signer)
	return indexNewEraser(&indexEraserArgs{
		store: store, eraseStore: store, repoId: self.world.repoId, refId: self.world.refId, repoKind: self.world.kind,
		isAdmin: self.world.isAdmin, format: self.world.format, settings: args.Settings, eraser: signer,
		complete: func(ctx context.Context, erasureIds []Id) (map[Id]bool, error) {
			complete := map[Id]bool{}
			for _, erasureId := range erasureIds {
				complete[erasureId] = self.Complete(erasureId)
			}
			return complete, nil
		},
		refKey: self.world.refKey, tables: indexLinkedTables(), mayMerge: func() bool { return true },
		padKey: func(ctx context.Context) (*indexPadKey, error) { return self.world.padKey, nil },
		events: args.Events, clock: self.world.clock, log: NewNoopLogger(),
	})
}

// A CLOSURE of paths' standing versions, each written back as it stands with grow zero bytes after it, by signer, sent
// through the erasure model as a forger's would be: what FS-78 holds evs's CLOSURE checks to, a file grown past its
// replaced length, and a creation through a path that does not stand. Its error is the refusal.
func (self *SearchTestErasure) ForgeClosure(ctx context.Context, signer Id, erasureId Id, paths []string, grow int) error {
	ref := self.world.ref
	ref.stateLock.Lock()
	head := ref.states[len(ref.states)-1]
	files := []*indexPushFile{}
	for _, path := range paths {
		stored := head.files[path]
		if stored == nil {
			files = append(files, &indexPushFile{path: path, plaintext: []byte("a created file")})
			continue
		}
		plaintext := slices.Concat(stored.plaintext, make([]byte, grow))
		files = append(files, &indexPushFile{path: path, plaintext: plaintext, replaces: stored.version.version})
	}
	base := head.head.version
	ref.stateLock.Unlock()
	store := self.store(signer)
	keys, err := store.KeysOf(ctx, paths)
	if err != nil {
		return err
	}
	_, err = store.Closure(ctx, &indexClosurePush{
		pushId: NewId(), erasureId: erasureId, baseVersion: base, signedTimeMs: self.world.clock.Now().UnixMilli(),
		files: files, erased: keys,
	})
	return err
}

// The paths the planned push writes and removes, in order: where FS-111 finds a push that opens its writer's head in
// an absorbed slot.
func (self *SearchTestPlannedPush) Paths() []string {
	paths := []string{}
	for _, file := range self.push.files {
		paths = append(paths, file.path)
	}
	for _, removal := range self.push.removals {
		paths = append(paths, removal.path)
	}
	return paths
}

// The index_epoch the planned push names.
func (self *SearchTestPlannedPush) IndexEpoch() uint64 {
	return self.push.indexEpoch
}

// The head's index_epoch: the version of the last CUT, 0 before any.
func (self *SearchTestWorld) IndexEpoch(ctx context.Context) (uint64, error) {
	head, err := self.ref.store(Id{}).Head(ctx)
	if err != nil {
		return 0, err
	}
	return head.indexEpoch, nil
}

// writer's push of documents planned at the head now by a builder that never read the erasure set, and committed at
// the head's index_epoch, which evs's step 5d takes, since evs reads no sealed file: FS-111's twin, the bug the epoch
// guard exists to stop and FI-19's fence must catch. The ref version it committed at.
func (self *SearchTestWorld) ForgePushIgnoringTheSet(ctx context.Context, writer Id, at time.Time, documents []*SearchTestDocument) (uint64, error) {
	pending := []*indexPendingDocument{}
	for _, document := range documents {
		prepared, err := self.prepare(document)
		if err != nil {
			return 0, err
		}
		pending = append(pending, &indexPendingDocument{
			kind: indexEntryFull, key: prepared.key, version: document.Version, keys: prepared.keys, row: prepared.row,
		})
	}
	view, err := self.view(ctx, writer)
	if err != nil {
		return 0, err
	}
	// the forger's view holds no set
	view.erasureSet = nil
	plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: writer, signedTimeMs: at.UnixMilli(), tables: indexLinkedTables(),
		pending: pending, mayMerge: true,
	})
	if err != nil {
		return 0, err
	}
	committed, err := self.ref.store(writer).Commit(ctx, &indexPush{
		pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: at.UnixMilli(),
		files: plan.files(), removals: plan.removals(),
	})
	if err != nil {
		return 0, err
	}
	return committed.version, nil
}

// One file version a CLOSURE wrote, beside the version it replaced.
type SearchTestRewritten struct {
	Path              string
	Version           uint64
	ByteCount         int
	ReplacedByteCount int
	// The ref version the CLOSURE committed at.
	CommitVersion uint64
}

// Every file version a CLOSURE wrote, in path and version order: what FS-78 holds to the replaced lengths.
func (self *SearchTestErasure) Rewritten() []SearchTestRewritten {
	rewritten := []SearchTestRewritten{}
	for path, versions := range self.history() {
		for index, version := range versions {
			if !version.closure || index == 0 {
				continue
			}
			rewritten = append(rewritten, SearchTestRewritten{
				Path: path, Version: version.file.version, ByteCount: version.file.byteCount,
				ReplacedByteCount: versions[index-1].file.byteCount, CommitVersion: version.file.commitVersion,
			})
		}
	}
	slices.SortFunc(rewritten, func(a SearchTestRewritten, b SearchTestRewritten) int {
		if a.Path != b.Path {
			return bytes.Compare([]byte(a.Path), []byte(b.Path))
		}
		return int(a.Version) - int(b.Version)
	})
	return rewritten
}

// Counts byteCount of signer's closure allowance as spent today, as its earlier CLOSUREs of the UTC day would have:
// FS-112's eraser whose allowance is spent when a one-document erasure begins.
func (self *SearchTestErasure) SpendClosureAllowance(signer Id, byteCount int64) {
	if signer == (Id{}) {
		signer = self.world.AdminId()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	day := indexUtcDay(self.world.clock.Now())
	used := self.usedByteDays[signer]
	if used == nil || used.day != day {
		used = &searchTestErasureUsed{day: day}
		self.usedByteDays[signer] = used
	}
	used.byteCount += byteCount
}

// The chunk documents an in-ref writer extracts from content at path: a 5 MiB message is five.
func (self *SearchTestWorld) ChunkCount(path string, content []byte) (int, error) {
	extraction, err := self.extract(path, 1, content)
	if err != nil {
		return 0, err
	}
	return int(extraction.count), nil
}

// writer's companion push of chunks of content at path and version, extracted as the in-ref writer extracts them,
// each a full entry of its chunk's doc_key planned into writer's head at the head now, merged into the bucket's shards
// in the push past DirectBytes: a copy of chunks a writer already indexed, as a late companion push or a backfill
// writes one into the bucket of its signed time (§11.13's wait row). A push the planner would merge first is refused.
// The ref version it committed at.
func (self *SearchTestWorld) PushChunks(ctx context.Context, writer Id, at time.Time, path string, version uint64, content []byte, chunks []uint32) (uint64, error) {
	extraction, err := self.extract(path, version, content)
	if err != nil {
		return 0, err
	}
	pending := []*indexPendingDocument{}
	for _, document := range extraction.full {
		if !slices.Contains(chunks, document.chunk) {
			continue
		}
		key, err := self.DocKeyOf(path, document.chunk)
		if err != nil {
			return 0, err
		}
		pending = append(pending, &indexPendingDocument{kind: indexEntryFull, key: key, version: version, keys: document.keys, row: document.row})
	}
	if len(pending) != len(chunks) {
		return 0, fmt.Errorf("search test world: %d of %d chunks extracted", len(pending), len(chunks))
	}
	view, err := self.view(ctx, writer)
	if err != nil {
		return 0, err
	}
	plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: writer, signedTimeMs: at.UnixMilli(), tables: indexLinkedTables(),
		pending: pending, mayMerge: true,
	})
	if err != nil {
		return 0, err
	}
	if plan.mergeFirst {
		return 0, errors.New("search test world: a chunk copy whose writer must merge first")
	}
	files, removals := plan.files(), plan.removals()
	if plan.mergeInPush {
		if files, removals, err = indexMergeHeadPlan(ctx, view, view.writeRoot(), plan, self.padKey, indexLinkedTables()); err != nil {
			return 0, err
		}
	}
	committed, err := self.ref.store(writer).Commit(ctx, &indexPush{
		pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: at.UnixMilli(),
		files: files, removals: removals,
	})
	if err != nil {
		return 0, err
	}
	return committed.version, nil
}
