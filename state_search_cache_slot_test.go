package sidecar

// QD-845: a slot-keyed repo's kept index record (record-class repos and group inboxes) reopens after its round from
// the slot's 72 B block, kept exactly as the slot object carried it, the slot key's generation and the segment's,
// with RK asked of gkm at each, both when they differ; a record without them is refused; an ERASE's hint drops at once
// every kept record whose (slot_id, key_index) it names and ends every read of one, after which nothing reopens it; no
// plaintext key is ever stored; and a slot-keyed record kept before the cache kept its block reads as lacking it and
// is unmarked for the next round to fetch again. General repos' records are as before (state_search_cache_test.go).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A slot object of a slot-keyed repo, as evs stores one, with the keys a test wrapped into it.
type testSearchSlot struct {
	repoId Id
	slotId Id
	object *protocol.EvsSlotObject
	keys   map[uint16]*EvsObjectKey
}

func newTestSearchSlot(repoId Id, label string) *testSearchSlot {
	return &testSearchSlot{repoId: repoId, slotId: evsTestId("slot " + label), object: &protocol.EvsSlotObject{}, keys: map[uint16]*EvsObjectKey{}}
}

// Draws the key at keyIndex and wraps it into the slot under fek of generation, as a push that writes the slot does.
func (self *testSearchSlot) addKey(t *testing.T, keyIndex uint16, generation uint64) {
	t.Helper()
	fekKey, err := NewEvsFekKey(evsTestRepoKey(self.repoId, generation))
	if err != nil {
		t.Fatal(err)
	}
	objectKey := NewEvsObjectKey()
	wrapped, err := EvsWrapObjectKey(fekKey, objectKey)
	if err != nil {
		t.Fatal(err)
	}
	self.keys[keyIndex] = objectKey
	self.object.Keys = append(self.object.Keys, &protocol.EvsSlotKey{KeyIndex: uint32(keyIndex), Generation: generation, Wrapped: wrapped})
	slices.SortFunc(self.object.Keys, func(a *protocol.EvsSlotKey, b *protocol.EvsSlotKey) int {
		return int(a.GetKeyIndex()) - int(b.GetKeyIndex())
	})
}

// The slot object as a read of evs answers it: its stored bytes, decoded.
func (self *testSearchSlot) stored(t *testing.T) *protocol.EvsSlotObject {
	t.Helper()
	objectBytes, err := EvsEncodeSlotObject(self.object)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := EvsDecodeSlotObject(objectBytes)
	if err != nil {
		t.Fatal(err)
	}
	return slot
}

// The block the slot carries at keyIndex.
func (self *testSearchSlot) block(t *testing.T, keyIndex uint16) []byte {
	t.Helper()
	slotKey, ok := EvsSlotKeyAt(self.object, uint32(keyIndex))
	if !ok {
		t.Fatalf("the slot holds no key %d", keyIndex)
	}
	return slotKey.GetWrapped()
}

// An index file's record of a slot-keyed repo, sealed as evs seals one: its header names the slot key at keyIndex and
// that key's generation, which its frames' AAD carries, and is sealed under manifest of segmentGeneration, its
// segment's; its body under the slot key. Not yet given its slot key (SetSlotKey).
func (self *testSearchSlot) bareRecord(t *testing.T, key SearchCacheKey, partition SearchCachePartition, plaintext []byte, keyIndex uint16, segmentGeneration uint64) *testSearchRecord {
	t.Helper()
	slotKey, ok := EvsSlotKeyAt(self.object, uint32(keyIndex))
	if !ok {
		t.Fatalf("the slot holds no key %d", keyIndex)
	}
	manifestKey, err := NewEvsManifestKey(evsTestRepoKey(key.RepoId, segmentGeneration))
	if err != nil {
		t.Fatal(err)
	}
	fileId := NewId()
	header := evsTestHeader(key.Path, protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, len(plaintext))
	header.KeyRefKind = protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT
	header.SlotId = self.slotId
	header.KeyIndex = keyIndex
	header.Generation = slotKey.GetGeneration()
	sealed, opened := evsTestWriteRecord(t, manifestKey, self.keys[keyIndex], fileId, header, plaintext)
	return &testSearchRecord{
		plaintext: plaintext,
		record: &SearchCacheRecord{
			Key:           key,
			RefVersion:    9,
			ContentSha256: sha256.Sum256(plaintext),
			Partition:     partition,
			SealedHeader:  sealed[:EvsRecordHeaderByteCount],
			SealedFrames:  sealed[EvsRecordHeaderByteCount:],
			Header:        &opened,
			ObjectKey:     self.keys[keyIndex],
			FileId:        fileId,
		},
	}
}

// bareRecord as the fetch offers it to the cache: with its slot key taken from the slot object while the fetch holds
// it.
func (self *testSearchSlot) record(t *testing.T, key SearchCacheKey, partition SearchCachePartition, plaintext []byte, keyIndex uint16, segmentGeneration uint64) *testSearchRecord {
	t.Helper()
	kept := self.bareRecord(t, key, partition, plaintext, keyIndex, segmentGeneration)
	if err := kept.record.SetSlotKey(self.stored(t), segmentGeneration); err != nil {
		t.Fatal(err)
	}
	return kept
}

// A gkm that answers evsTestRepoKey's generations and lists which were asked, refusing those in missing.
type testSearchAskGkm struct {
	gkmRefusingClient
	missing []uint64

	stateLock sync.Mutex
	asked     []uint64
}

func (self *testSearchAskGkm) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asked = append(self.asked, generation)
	if slices.Contains(self.missing, generation) {
		return nil, ErrGkmKeyMissing
	}
	return evsTestRepoKey(repoId, generation), nil
}

// The generations asked since the last call.
func (self *testSearchAskGkm) take() []uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	asked := self.asked
	self.asked = nil
	return asked
}

// The plaintext of every file in a cache's store, by name.
func testSearchStorePlaintexts(t *testing.T, cache *SearchCache) map[string][]byte {
	t.Helper()
	entries, err := cache.store.List("")
	if err != nil {
		t.Fatal(err)
	}
	plaintexts := map[string][]byte{}
	for _, entry := range entries {
		reader, err := cache.store.Open(entry.Name)
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		plaintexts[entry.Name] = content
	}
	return plaintexts
}

// Whether content holds secret raw or in an encoding a store or a log might give it.
func testSearchHoldsSecret(content []byte, secret []byte) bool {
	for _, encoding := range []string{string(secret), hex.EncodeToString(secret), strings.ToUpper(hex.EncodeToString(secret)),
		base64.StdEncoding.EncodeToString(secret), base64.RawStdEncoding.EncodeToString(secret),
		base64.URLEncoding.EncodeToString(secret), base64.RawURLEncoding.EncodeToString(secret)} {
		if bytes.Contains(content, []byte(encoding)) {
			return true
		}
	}
	return false
}

// QD-845: a slot-keyed record kept in one round reopens in a later one, a new cache over the same store standing for a
// restart, from its cache key and gkm alone. Where the slot key and the segment share a generation gkm is asked for it
// once; where the slot key's generation is older than the segment's it is asked for both, fek of the slot key's
// unwrapping the block and manifest of the segment's opening the header. The block kept is the slot object's own. One
// key for both generations, the two swapped, and a generation gkm no longer reaches open nothing and drop nothing.
func TestSlotKeyedRecordReopensInALaterRound(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	repoId, refId := NewId(), NewId()
	slot := newTestSearchSlot(repoId, "inbox")
	slot.addKey(t, 0, 2)
	slot.addKey(t, 5, 1)
	// key 0 and its segment at generation 2; key 5 at generation 1, older than its segment's 3
	same := SearchCacheKey{RepoId: repoId, RefId: refId, Path: ".ur-index/i1/b/20070/s/0", Version: 4}
	older := SearchCacheKey{RepoId: repoId, RefId: refId, Path: ".ur-index/i1/b/20070/s/1", Version: 2}
	keptSame := slot.record(t, same, SearchCachePartition{StartDay: 20070}, testSearchPlaintext("same", 3000), 0, 2)
	keptOlder := slot.record(t, older, SearchCachePartition{StartDay: 20070}, testSearchPlaintext("older", 5*EvsRecordFrameByteCount/2), 5, 3)
	general := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/a/0", Version: 1}
	keptGeneral := newTestSearchRecordAt(t, general, SearchCachePartition{All: true}, testSearchPlaintext("general", 4000), 2)
	for _, kept := range []*testSearchRecord{keptSame, keptOlder, keptGeneral} {
		if err := world.cache.PutRecord(t.Context(), kept.record); err != nil {
			t.Fatal(err)
		}
	}
	world.cache.Close()

	later, err := NewSearchCache(t.Context(), world.instance.Store(&world.networkId), world.settings, world.clock, NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(later.Close)
	ref, err := later.Ref(repoId, refId)
	if err != nil || ref == nil || len(ref.Files) != 2 {
		t.Fatalf("held %+v, %v", ref, err)
	}
	for _, file := range ref.Files {
		keyIndex := uint16(0)
		if file.Key == older {
			keyIndex = 5
		}
		if !file.KeysKept || !file.SlotKeyed || file.SlotId != slot.slotId || file.KeyIndex != keyIndex {
			t.Errorf("%s is held as %+v", file.Key.Path, file)
		}
	}

	gkm := &testSearchAskGkm{}
	for _, check := range []struct {
		kept             *testSearchRecord
		keyIndex         uint16
		generation       uint64
		headerGeneration uint64
		asked            []uint64
	}{
		{keptSame, 0, 2, 2, []uint64{2}},
		{keptOlder, 5, 1, 3, []uint64{1, 3}},
	} {
		key := check.kept.record.Key
		frames, err := later.OpenRecord(key)
		if err != nil {
			t.Fatal(err)
		}
		if frames.Generation() != check.generation || frames.HeaderGeneration() != check.headerGeneration {
			t.Errorf("%s kept generations %d and %d", key.Path, frames.Generation(), frames.HeaderGeneration())
		}
		if !bytes.Equal(frames.WrappedObjectKey(), slot.block(t, check.keyIndex)) {
			t.Errorf("%s: the block kept is not the slot object's", key.Path)
		}
		if slotKey, ok := frames.SlotKey(); !ok || slotKey.SlotId != slot.slotId || slotKey.KeyIndex != check.keyIndex {
			t.Errorf("%s names slot key %+v", key.Path, slotKey)
		}
		read, err := later.OpenRecordRead(t.Context(), key, gkm)
		if err != nil {
			t.Fatalf("%s: %v", key.Path, err)
		}
		if asked := gkm.take(); !slices.Equal(asked, check.asked) {
			t.Errorf("%s: gkm was asked for %v, not %v", key.Path, asked, check.asked)
		}
		whole, err := testReadThrough(t, read)
		if err != nil || !bytes.Equal(whole, check.kept.plaintext) {
			t.Errorf("%s reopened reads back otherwise: %v", key.Path, err)
		}
		// Close clears the key the read unwrapped
		objectKey := read.objectKey
		read.Close()
		if read.objectKey != nil || !bytes.Equal(objectKey.key, make([]byte, len(objectKey.key))) {
			t.Errorf("%s: a closed read kept its object key", key.Path)
		}
	}

	// a general repo's record keeps one generation, asked once, and names no slot
	frames, err := later.OpenRecord(general)
	if err != nil {
		t.Fatal(err)
	}
	if frames.Generation() != 2 || frames.HeaderGeneration() != 2 {
		t.Errorf("a general record kept generations %d and %d", frames.Generation(), frames.HeaderGeneration())
	}
	if slotKey, ok := frames.SlotKey(); ok {
		t.Errorf("a general record names slot key %+v", slotKey)
	}
	read, err := later.OpenRecordRead(t.Context(), general, gkm)
	if err != nil {
		t.Fatal(err)
	}
	if whole, err := testReadThrough(t, read); err != nil || !bytes.Equal(whole, keptGeneral.plaintext) {
		t.Errorf("the general record reopened reads back otherwise: %v", err)
	}
	read.Close()
	if asked := gkm.take(); !slices.Equal(asked, []uint64{2}) {
		t.Errorf("a general record: gkm was asked for %v", asked)
	}

	// the two keys of a record whose generations differ are not one another's, and neither alone opens it
	frames, err = later.OpenRecord(older)
	if err != nil {
		t.Fatal(err)
	}
	slotRepoKey, segmentRepoKey := evsTestRepoKey(repoId, 1), evsTestRepoKey(repoId, 3)
	for label, open := range map[string]func() (*SearchCacheRecordRead, error){
		"the slot key's generation alone": func() (*SearchCacheRecordRead, error) { return frames.OpenRead(slotRepoKey) },
		"the segment's generation alone":  func() (*SearchCacheRecordRead, error) { return frames.OpenRead(segmentRepoKey) },
		"the two swapped":                 func() (*SearchCacheRecordRead, error) { return frames.OpenReadKeys(segmentRepoKey, slotRepoKey) },
		"no header key":                   func() (*SearchCacheRecordRead, error) { return frames.OpenReadKeys(slotRepoKey, nil) },
		"another repo's keys": func() (*SearchCacheRecordRead, error) {
			return frames.OpenReadKeys(evsTestRepoKey(NewId(), 1), evsTestRepoKey(NewId(), 3))
		},
		"a forked slot generation": func() (*SearchCacheRecordRead, error) {
			forked := &EvsRepoKey{repoId: repoId, generation: 1, repoKey: evsTestBytes("RK forked", evsKeyByteCount)}
			return frames.OpenReadKeys(forked, segmentRepoKey)
		},
		"a forked segment generation": func() (*SearchCacheRecordRead, error) {
			forked := &EvsRepoKey{repoId: repoId, generation: 3, repoKey: evsTestBytes("RK forked", evsKeyByteCount)}
			return frames.OpenReadKeys(slotRepoKey, forked)
		},
	} {
		if read, err := open(); !errors.Is(err, ErrSearchCacheKey) || read != nil {
			t.Errorf("%s: %v", label, err)
		}
	}
	// a generation this sidecar no longer reaches is gkm's refusal, for either of the two
	for _, missing := range []uint64{1, 3} {
		if _, err := later.OpenRecordRead(t.Context(), older, &testSearchAskGkm{missing: []uint64{missing}}); !errors.Is(err, ErrGkmKeyMissing) {
			t.Errorf("generation %d missing: %v", missing, err)
		}
	}
	if ref, err := later.Ref(repoId, refId); err != nil || ref == nil || len(ref.Files) != 2 {
		t.Fatalf("a refused key dropped a record: %+v, %v", ref, err)
	}
	read, err = frames.OpenReadKeys(slotRepoKey, segmentRepoKey)
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	if frame, err := read.ReadFrame(2, nil); err != nil || !bytes.Equal(frame, keptOlder.plaintext[2*EvsRecordFrameByteCount:]) {
		t.Errorf("the last frame under the two keys: %v", err)
	}
}

// QD-845's block is the one the slot object carries at the key the record names. A slot-keyed record without it, with
// a short one, without its slot key's generation or with another than its header's, or without its segment's
// generation is refused, as a container-keyed record is without its block or file id or with a slot key's generations;
// nothing reaches the medium. SetSlotKey takes nothing from a slot whose key an ERASE dropped, a key of another
// generation than the header's, a record slot row or a deposit's key, nor for a container-keyed record.
func TestSlotKeyedRecordNeedsItsSlotKey(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/b/20060/0", Version: 1}
	partition := SearchCachePartition{StartDay: 20060}
	plaintext := testSearchPlaintext("slot", 3000)
	for label, change := range map[string]func(record *SearchCacheRecord){
		"no block": func(record *SearchCacheRecord) { record.WrappedObjectKey = nil },
		"a short one": func(record *SearchCacheRecord) {
			record.WrappedObjectKey = record.WrappedObjectKey[:EvsWrappedKeyByteCount-1]
		},
		"no file id":                 func(record *SearchCacheRecord) { record.FileId = Id{} },
		"a slot key's generation":    func(record *SearchCacheRecord) { record.SlotKeyGeneration = 1 },
		"another segment generation": func(record *SearchCacheRecord) { record.SegmentGeneration = 2 },
		"a key ref kind evs has none": func(record *SearchCacheRecord) {
			header := *record.Header
			header.KeyRefKind = 7
			record.Header = &header
		},
	} {
		refused := newTestSearchRecord(t, key, partition, plaintext)
		change(refused.record)
		if err := world.cache.PutRecord(t.Context(), refused.record); !errors.Is(err, ErrSearchCacheArgs) {
			t.Errorf("a container-keyed record, %s: %v", label, err)
		}
	}

	slot := newTestSearchSlot(key.RepoId, "record")
	slot.addKey(t, 3, 1)
	for label, change := range map[string]func(record *SearchCacheRecord){
		"no block": func(record *SearchCacheRecord) { record.WrappedObjectKey = nil },
		"a short one": func(record *SearchCacheRecord) {
			record.WrappedObjectKey = record.WrappedObjectKey[:EvsWrappedKeyByteCount-1]
		},
		"a record slot row's width": func(record *SearchCacheRecord) {
			record.WrappedObjectKey = make([]byte, EvsRecordSlotRowWrappedByteCount)
		},
		"no file id":                  func(record *SearchCacheRecord) { record.FileId = Id{} },
		"no slot key generation":      func(record *SearchCacheRecord) { record.SlotKeyGeneration = 0 },
		"another slot key generation": func(record *SearchCacheRecord) { record.SlotKeyGeneration = 2 },
		"no segment generation":       func(record *SearchCacheRecord) { record.SegmentGeneration = 0 },
		"nothing of its slot, as before 845": func(record *SearchCacheRecord) {
			record.WrappedObjectKey, record.SlotKeyGeneration, record.SegmentGeneration = nil, 0, 0
		},
	} {
		refused := slot.record(t, key, partition, plaintext, 3, 2)
		change(refused.record)
		if err := world.cache.PutRecord(t.Context(), refused.record); !errors.Is(err, ErrSearchCacheArgs) {
			t.Errorf("a slot-keyed record, %s: %v", label, err)
		}
	}
	if paths := world.searchPaths(t); len(paths) != 0 {
		t.Fatalf("refused records left %v", paths)
	}

	bare := slot.bareRecord(t, key, partition, plaintext, 3, 2)
	stored := slot.stored(t)
	erased, removedCount, err := func() (*protocol.EvsSlotObject, int, error) {
		objectBytes, err := EvsEncodeSlotObject(slot.object)
		if err != nil {
			return nil, 0, err
		}
		rewritten, removedCount, err := EvsSlotWithoutKeys(objectBytes, []uint32{3})
		if err != nil {
			return nil, 0, err
		}
		decoded, err := EvsDecodeSlotObject(rewritten)
		return decoded, removedCount, err
	}()
	if err != nil || removedCount != 1 {
		t.Fatalf("the slot after its ERASE: %d removed, %v", removedCount, err)
	}
	anotherGeneration := &protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 3, Generation: 2, Wrapped: stored.Keys[0].Wrapped}}}
	row := &protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 3, Generation: 1, Wrapped: make([]byte, EvsRecordSlotRowWrappedByteCount)}}}
	deposit := &protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 3, Generation: 1, Wrapped: make([]byte, EvsDepositWrappedKeyByteCount)}}}
	for label, refused := range map[string]*protocol.EvsSlotObject{
		"a slot whose key an ERASE dropped": erased,
		"a key of another generation":       anotherGeneration,
		"a record slot row":                 row,
		"a deposit's key":                   deposit,
		"no slot":                           nil,
	} {
		if err := bare.record.SetSlotKey(refused, 2); !errors.Is(err, ErrSearchCacheArgs) {
			t.Errorf("%s: %v", label, err)
		}
		if bare.record.WrappedObjectKey != nil || bare.record.SlotKeyGeneration != 0 || bare.record.SegmentGeneration != 0 {
			t.Fatalf("%s: a refused slot gave the record a key", label)
		}
	}
	if err := bare.record.SetSlotKey(stored, 0); !errors.Is(err, ErrSearchCacheArgs) {
		t.Errorf("no segment generation: %v", err)
	}
	container := newTestSearchRecord(t, key, partition, plaintext)
	if err := container.record.SetSlotKey(stored, 1); !errors.Is(err, ErrSearchCacheArgs) {
		t.Errorf("a container-keyed record took a slot key: %v", err)
	}

	// with its slot's key it is kept
	if err := bare.record.SetSlotKey(stored, 2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bare.record.WrappedObjectKey, slot.block(t, 3)) || bare.record.SlotKeyGeneration != 1 || bare.record.SegmentGeneration != 2 {
		t.Fatalf("the record took generations %d and %d", bare.record.SlotKeyGeneration, bare.record.SegmentGeneration)
	}
	if err := world.cache.PutRecord(t.Context(), bare.record); err != nil {
		t.Fatal(err)
	}
	if whole, err := testReadKeptRecord(t, world.cache, bare.record); err != nil || !bytes.Equal(whole, plaintext) {
		t.Errorf("the round's own read: %v", err)
	}
}

// QD-845: an ERASE's hint deletes at once every kept record whose (slot_id, key_index) names a slot key the ERASE
// destroys: each version of a path that shares the key, on every ref of the repo, loaded or not, with its derived
// data, and ends every open read of one, its unwrapped key cleared. Then nothing reopens it: not a read through gkm,
// not a record opened before the hint, and no file of the store holds its block. A record of another key of the same
// slot, of another slot, of another repo and a general repo's stay and read.
func TestEraseHintDropsSlotKeyedRecords(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	repoId, refId, otherRefId := NewId(), NewId(), NewId()
	slot := newTestSearchSlot(repoId, "erased")
	slot.addKey(t, 0, 1)
	slot.addKey(t, 1, 1)
	otherSlot := newTestSearchSlot(repoId, "kept")
	otherSlot.addKey(t, 0, 1)
	otherRepoId := NewId()
	// another repo's slot of the same id and index: an ERASE names keys of its own repo alone
	otherRepoSlot := newTestSearchSlot(otherRepoId, "erased")
	otherRepoSlot.addKey(t, 0, 1)
	partition := SearchCachePartition{StartDay: 20080}
	path := ".ur-index/i1/b/20080/s/0"
	// the path's two versions share its slot key (§11.14's keys row), the newer in a segment of a later generation
	erasedOld := slot.record(t, SearchCacheKey{RepoId: repoId, RefId: refId, Path: path, Version: 1}, partition, testSearchPlaintext("old", 2*EvsRecordFrameByteCount), 0, 1)
	erasedNew := slot.record(t, SearchCacheKey{RepoId: repoId, RefId: refId, Path: path, Version: 2}, partition, testSearchPlaintext("new", 2*EvsRecordFrameByteCount), 0, 2)
	erasedOnOtherRef := slot.record(t, SearchCacheKey{RepoId: repoId, RefId: otherRefId, Path: path, Version: 1}, partition, testSearchPlaintext("other ref", 900), 0, 1)
	sameSlot := slot.record(t, SearchCacheKey{RepoId: repoId, RefId: refId, Path: ".ur-index/i1/b/20080/s/1", Version: 1}, partition, testSearchPlaintext("same slot", 800), 1, 1)
	anotherSlot := otherSlot.record(t, SearchCacheKey{RepoId: repoId, RefId: refId, Path: ".ur-index/i1/b/20080/s/2", Version: 1}, partition, testSearchPlaintext("another slot", 700), 0, 1)
	anotherRepo := otherRepoSlot.record(t, SearchCacheKey{RepoId: otherRepoId, RefId: refId, Path: path, Version: 1}, partition, testSearchPlaintext("another repo", 600), 0, 1)
	general := newTestSearchRecord(t, SearchCacheKey{RepoId: NewId(), RefId: refId, Path: ".ur-index/i1/a/0", Version: 1}, SearchCachePartition{All: true}, testSearchPlaintext("general", 500))
	erased := []*testSearchRecord{erasedOld, erasedNew, erasedOnOtherRef}
	stays := []*testSearchRecord{sameSlot, anotherSlot, anotherRepo, general}
	for _, kept := range slices.Concat(erased, stays) {
		if err := world.cache.PutRecord(t.Context(), kept.record); err != nil {
			t.Fatal(err)
		}
	}
	derived := &SearchCacheDerived{Key: erasedNew.record.Key, Part: SearchCachePartBlockIndex, Plaintext: testSearchPlaintext("blocks", 3000)}
	if err := world.cache.PutDerived(t.Context(), derived); err != nil {
		t.Fatal(err)
	}
	world.cache.Close()

	// the hint arrives in a later round, before the other ref's holdings were read
	cache, err := NewSearchCache(t.Context(), world.instance.Store(&world.networkId), world.settings, world.clock, NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cache.Close)
	gkm := &evsTestReadGkm{newest: 2}
	openRead, err := cache.OpenRecordRead(t.Context(), erasedNew.record.Key, gkm)
	if err != nil {
		t.Fatal(err)
	}
	defer openRead.Close()
	if _, err := openRead.ReadFrame(0, nil); err != nil {
		t.Fatal(err)
	}
	openKey := openRead.objectKey
	stayingRead, err := cache.OpenRecordRead(t.Context(), sameSlot.record.Key, gkm)
	if err != nil {
		t.Fatal(err)
	}
	defer stayingRead.Close()
	openedBefore, err := cache.OpenRecord(erasedOld.record.Key)
	if err != nil {
		t.Fatal(err)
	}

	// a hint naming nothing held, and one of another repo, drop nothing
	for label, hint := range map[string]func() ([]SearchCacheKey, error){
		"no keys": func() ([]SearchCacheKey, error) { return cache.DropErasedSlotKeys(repoId, nil) },
		"another index of the slot": func() ([]SearchCacheKey, error) {
			return cache.DropErasedSlotKeys(repoId, []*EvsErasedKey{{SlotId: slot.slotId, KeyIndex: 7}})
		},
		"a repo the cache holds nothing of": func() ([]SearchCacheKey, error) {
			return cache.DropErasedSlotKeys(NewId(), []*EvsErasedKey{{SlotId: slot.slotId, KeyIndex: 0}})
		},
	} {
		if dropped, err := hint(); err != nil || len(dropped) != 0 {
			t.Fatalf("%s: dropped %v, %v", label, dropped, err)
		}
	}
	if _, err := cache.DropErasedSlotKeys(Id{}, []*EvsErasedKey{{SlotId: slot.slotId}}); !errors.Is(err, ErrSearchCacheArgs) {
		t.Errorf("an erasure of no repo: %v", err)
	}
	if _, err := cache.DropErasedSlotKeys(repoId, []*EvsErasedKey{{}}); !errors.Is(err, ErrSearchCacheArgs) {
		t.Errorf("an erased key of no slot: %v", err)
	}

	dropped, err := cache.DropErasedSlotKeys(repoId, []*EvsErasedKey{{SlotId: slot.slotId, KeyIndex: 0}, {SlotId: evsTestId("slot never held"), KeyIndex: 0}})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) != len(erased) {
		t.Fatalf("the hint dropped %v", dropped)
	}
	for _, kept := range erased {
		key := kept.record.Key
		if !slices.Contains(dropped, key) {
			t.Errorf("%s@%d on ref %s was not dropped", key.Path, key.Version, key.RefId)
		}
		if _, err := cache.OpenRecordRead(t.Context(), key, gkm); !errors.Is(err, ErrSidecarStoreAbsent) {
			t.Errorf("%s@%d reopens after its ERASE: %v", key.Path, key.Version, err)
		}
		if _, err := cache.OpenRecord(key); !errors.Is(err, ErrSidecarStoreAbsent) {
			t.Errorf("%s@%d is held after its ERASE: %v", key.Path, key.Version, err)
		}
	}
	// the read open across the hint ended, its key cleared
	if _, err := openRead.ReadFrame(1, nil); !errors.Is(err, ErrSearchCacheReadEnded) {
		t.Errorf("a frame after the hint: %v", err)
	}
	if openRead.objectKey != nil || !bytes.Equal(openKey.key, make([]byte, len(openKey.key))) {
		t.Error("the hint left a read's object key")
	}
	// a record opened before the hint, holding its meta in memory, opens no read after it
	if read, err := openedBefore.OpenReadKeys(evsTestRepoKey(repoId, 1), evsTestRepoKey(repoId, 1)); !errors.Is(err, ErrSidecarStoreAbsent) || read != nil {
		t.Errorf("a record opened before the hint: %v", err)
	}
	if _, err := cache.OpenDerived(derived.Key, derived.Part); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("an erased record's derived data: %v", err)
	}
	// no file of the store holds the destroyed key's block, nor anything under the erased path
	block := slot.block(t, 0)
	for name, content := range testSearchStorePlaintexts(t, cache) {
		if testSearchHoldsSecret(content, block) {
			t.Errorf("%s holds the destroyed key's block", name)
		}
		for _, kept := range erased {
			if strings.HasPrefix(name, searchCacheRefName(kept.record.Key.RepoId, kept.record.Key.RefId)+"/p"+hex.EncodeToString([]byte(path))+"/") {
				t.Errorf("%s stays of an erased record", name)
			}
		}
	}

	// what the ERASE did not name stays and reads, the read open across the hint too
	if whole, err := testReadThrough(t, stayingRead); err != nil || !bytes.Equal(whole, sameSlot.plaintext) {
		t.Errorf("a read of another key of the slot, across the hint: %v", err)
	}
	for _, kept := range stays {
		read, err := cache.OpenRecordRead(t.Context(), kept.record.Key, gkm)
		if err != nil {
			t.Fatalf("%s: %v", kept.record.Key.Path, err)
		}
		whole, err := testReadThrough(t, read)
		read.Close()
		if err != nil || !bytes.Equal(whole, kept.plaintext) {
			t.Errorf("%s reads back otherwise after the hint: %v", kept.record.Key.Path, err)
		}
	}
	// the same hint again finds nothing, and a restart finds the records gone
	if dropped, err := cache.DropErasedSlotKeys(repoId, []*EvsErasedKey{{SlotId: slot.slotId, KeyIndex: 0}}); err != nil || len(dropped) != 0 {
		t.Errorf("the hint again dropped %v, %v", dropped, err)
	}
	cache.Close()
	restarted, err := NewSearchCache(t.Context(), world.instance.Store(&world.networkId), world.settings, world.clock, NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	for _, kept := range erased {
		if _, err := restarted.OpenRecordRead(t.Context(), kept.record.Key, gkm); !errors.Is(err, ErrSidecarStoreAbsent) {
			t.Errorf("%s@%d reopens after a restart: %v", kept.record.Key.Path, kept.record.Key.Version, err)
		}
	}
	if ref, err := restarted.Ref(repoId, otherRefId); err != nil || (ref != nil && len(ref.Files) != 0) {
		t.Errorf("the other ref holds %+v, %v", ref, err)
	}
}

// QD-845: the cache keeps a slot-keyed record's key only as the slot's wrapped block. No byte on the medium, no sealed
// file's plaintext and no file of an in-memory cache holds the slot key, fek of its generation, manifest of the
// segment's or either RK, raw or encoded; the block is in the record's meta alone; and a read writes nothing.
func TestNoPlaintextSlotKeyKept(t *testing.T) {
	for _, cacheByteCount := range []int64{1 << 30, 0} {
		world := newTestSearchCacheWorld(t, cacheByteCount)
		cache := world.cache
		key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/b/20090/s/0", Version: 1}
		slot := newTestSearchSlot(key.RepoId, "private")
		slot.addKey(t, 2, 1)
		kept := slot.record(t, key, SearchCachePartition{StartDay: 20090}, testSearchPlaintext("private slot", 2*EvsRecordFrameByteCount), 2, 3)
		if err := cache.PutRecord(t.Context(), kept.record); err != nil {
			t.Fatal(err)
		}
		slotRepoKey, segmentRepoKey := evsTestRepoKey(key.RepoId, 1), evsTestRepoKey(key.RepoId, 3)
		fekKey, err := NewEvsFekKey(slotRepoKey)
		if err != nil {
			t.Fatal(err)
		}
		manifestKey, err := NewEvsManifestKey(segmentRepoKey)
		if err != nil {
			t.Fatal(err)
		}
		// taken before a read, whose Close clears the key it unwrapped but never the fetch's
		secrets := map[string][]byte{
			"slot key": bytes.Clone(kept.record.ObjectKey.key), "fek of the slot key's generation": fekKey.key,
			"manifest of the segment's generation": manifestKey.key, "RK of the slot key's generation": slotRepoKey.repoKey,
			"RK of the segment's generation": segmentRepoKey.repoKey,
		}
		scan := func(where string, content []byte) {
			for name, secret := range secrets {
				if testSearchHoldsSecret(content, secret) {
					t.Errorf("cache of %d bytes: %s holds the %s", cacheByteCount, where, name)
				}
			}
		}

		before := backendSnapshot(t, world.backend)
		read, err := cache.OpenRecordRead(t.Context(), key, &testSearchAskGkm{})
		if err != nil {
			t.Fatal(err)
		}
		if whole, err := testReadThrough(t, read); err != nil || !bytes.Equal(whole, kept.plaintext) {
			t.Fatalf("cache of %d bytes: the record reopened reads back otherwise: %v", cacheByteCount, err)
		}
		read.Close()
		frames, err := cache.OpenRecord(key)
		if err != nil {
			t.Fatal(err)
		}
		_, refused := frames.OpenRead(slotRepoKey)
		if refused == nil {
			t.Fatal("the slot key's generation alone opened the record")
		}
		scan("a refused key's error", []byte(refused.Error()))
		after := backendSnapshot(t, world.backend)
		if len(after) != len(before) {
			t.Errorf("a read wrote %d files", len(after)-len(before))
		}
		for path, content := range before {
			if !bytes.Equal(after[path], content) {
				t.Errorf("a read rewrote %s", path)
			}
		}

		block := base64.StdEncoding.EncodeToString(slot.block(t, 2))
		blocks := 0
		for name, content := range testSearchStorePlaintexts(t, cache) {
			scan(name, content)
			if bytes.Contains(content, []byte(block)) {
				if !strings.HasSuffix(name, "/record/m") {
					t.Errorf("cache of %d bytes: %s keeps the wrapped block", cacheByteCount, name)
				}
				blocks += 1
			}
		}
		if blocks != 1 {
			t.Errorf("cache of %d bytes: %d files keep the wrapped block", cacheByteCount, blocks)
		}
		for path, raw := range after {
			scan(path, raw)
			// the block is not a key, and still it rests only inside the store's seal
			if testSearchHoldsSecret(raw, slot.block(t, 2)) {
				t.Errorf("cache of %d bytes: %s holds the wrapped block outside the store's seal", cacheByteCount, path)
			}
		}
	}
}

// QD-845: a slot-keyed record the cache kept before it kept its slot's block, marked as keeping its keys with nothing
// that opens it, reads as lacking them. It stays held and reads to a reader holding its keys, as the round that
// fetched it did; a reader through gkm is answered ErrSearchCacheKeysLacking, and that read unmarks its holdings
// entry, so the next sync round fetches it again (search_fetch.go). It names no slot, so an ERASE's hint passes it
// over: it holds no block to drop. The copy the next round keeps replaces it, reopens, and drops at its ERASE.
func TestSlotKeyedRecordKeptBeforeItsBlockIsFetchedAgain(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	cache := world.cache
	key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/b/20100/s/0", Version: 1}
	slot := newTestSearchSlot(key.RepoId, "earlier")
	slot.addKey(t, 4, 1)
	kept := slot.record(t, key, SearchCachePartition{StartDay: 20100}, testSearchPlaintext("earlier", EvsRecordFrameByteCount+10), 4, 2)
	if err := cache.PutRecord(t.Context(), kept.record); err != nil {
		t.Fatal(err)
	}
	// the earlier meta: the slot-keyed mark and the file id alone, its holdings entry marked as keeping its keys
	base := searchCachePartName(key, searchCachePartRecord)
	meta, err := cache.readMeta(base)
	if err != nil {
		t.Fatal(err)
	}
	meta.WrappedKey, meta.Generation, meta.SegmentGeneration, meta.SlotId, meta.KeyIndex = nil, 0, 0, "", 0
	encoded, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.writeSmall(base+"/"+searchCacheMetaName, encoded, true); err != nil {
		t.Fatal(err)
	}
	func() {
		cache.operationLock.Lock()
		defer cache.operationLock.Unlock()
		ref, err := cache.loadRefWithLock(key.RepoId, key.RefId)
		if err != nil {
			t.Fatal(err)
		}
		cache.stateLock.Lock()
		ref.Files[0].SlotKeyed, ref.Files[0].SlotId, ref.Files[0].KeyIndex = false, Id{}, 0
		cache.stateLock.Unlock()
		if err := cache.storeRefWithLock(ref); err != nil {
			t.Fatal(err)
		}
	}()
	if ref, err := cache.Ref(key.RepoId, key.RefId); err != nil || ref == nil || len(ref.Files) != 1 || !ref.Files[0].KeysKept {
		t.Fatalf("the earlier record is held as %+v, %v", ref, err)
	}

	gkm := &testSearchAskGkm{}
	if _, err := cache.OpenRecordRead(t.Context(), key, gkm); !errors.Is(err, ErrSearchCacheKeysLacking) {
		t.Errorf("a read through gkm: %v", err)
	}
	if asked := gkm.take(); len(asked) != 0 {
		t.Errorf("gkm was asked for %v for a record that keeps no block", asked)
	}
	ref, err := cache.Ref(key.RepoId, key.RefId)
	if err != nil || ref == nil || len(ref.Files) != 1 || ref.Files[0].KeysKept {
		t.Fatalf("after the read it is held as %+v, %v", ref, err)
	}
	frames, err := cache.OpenRecord(key)
	if err != nil {
		t.Fatal(err)
	}
	if slotKey, ok := frames.SlotKey(); ok {
		t.Errorf("the earlier record names slot key %+v", slotKey)
	}
	if _, err := frames.OpenReadKeys(evsTestRepoKey(key.RepoId, 1), evsTestRepoKey(key.RepoId, 2)); !errors.Is(err, ErrSearchCacheKeysLacking) {
		t.Errorf("a read under its repo's keys: %v", err)
	}
	if whole, err := testReadKeptRecord(t, cache, kept.record); err != nil || !bytes.Equal(whole, kept.plaintext) {
		t.Errorf("the round's own read: %v", err)
	}
	erasedKey := []*EvsErasedKey{{SlotId: slot.slotId, KeyIndex: 4}}
	if dropped, err := cache.DropErasedSlotKeys(key.RepoId, erasedKey); err != nil || len(dropped) != 0 {
		t.Errorf("the hint dropped %v of a record that names no slot, %v", dropped, err)
	}

	// fetched again, it is kept with its slot's block, reopens, and drops at its ERASE
	if err := cache.PutRecord(t.Context(), kept.record); err != nil {
		t.Fatal(err)
	}
	if ref, err := cache.Ref(key.RepoId, key.RefId); err != nil || ref == nil || len(ref.Files) != 1 || !ref.Files[0].KeysKept || !ref.Files[0].SlotKeyed {
		t.Fatalf("fetched again, held %+v, %v", ref, err)
	}
	read, err := cache.OpenRecordRead(t.Context(), key, gkm)
	if err != nil {
		t.Fatal(err)
	}
	whole, err := testReadThrough(t, read)
	read.Close()
	if err != nil || !bytes.Equal(whole, kept.plaintext) {
		t.Errorf("fetched again, it reads %v", err)
	}
	if dropped, err := cache.DropErasedSlotKeys(key.RepoId, erasedKey); err != nil || !slices.Equal(dropped, []SearchCacheKey{key}) {
		t.Errorf("the hint dropped %v, %v", dropped, err)
	}
	if _, err := cache.OpenRecordRead(t.Context(), key, gkm); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("it reopens after its ERASE: %v", err)
	}
}

// QD-845: what the cache keeps beside a slot-keyed record must be the slot key its sealed header names, since an
// ERASE's hint finds the record by it. A meta naming another key index, or another slot, than the header a reader
// opens drops the file: ErrSearchCacheRefetch, and nothing of it stays.
func TestSlotKeyedRecordNamingAnotherSlotKeyIsDropped(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	cache := world.cache
	for index, change := range []func(meta *searchCacheMetaWire){
		func(meta *searchCacheMetaWire) { meta.KeyIndex = 9 },
		func(meta *searchCacheMetaWire) { meta.SlotId = hex.EncodeToString(evsTestId("another slot").Bytes()) },
		func(meta *searchCacheMetaWire) {
			meta.SlotKeyed, meta.SegmentGeneration, meta.SlotId, meta.KeyIndex = false, 0, "", 0
		},
		func(meta *searchCacheMetaWire) { meta.SlotKeyed = false },
	} {
		key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/b/20110/s/0", Version: uint64(index + 1)}
		slot := newTestSearchSlot(key.RepoId, "named")
		slot.addKey(t, 6, 1)
		kept := slot.record(t, key, SearchCachePartition{StartDay: 20110}, testSearchPlaintext("named", 2000), 6, 1)
		if err := cache.PutRecord(t.Context(), kept.record); err != nil {
			t.Fatal(err)
		}
		base := searchCachePartName(key, searchCachePartRecord)
		meta, err := cache.readMeta(base)
		if err != nil {
			t.Fatal(err)
		}
		change(meta)
		encoded, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		if err := cache.writeSmall(base+"/"+searchCacheMetaName, encoded, true); err != nil {
			t.Fatal(err)
		}
		if _, err := cache.OpenRecordRead(t.Context(), key, &testSearchAskGkm{}); !errors.Is(err, ErrSearchCacheRefetch) {
			t.Errorf("changed meta %d: %v", index, err)
		}
		if ref, err := cache.Ref(key.RepoId, key.RefId); err != nil || (ref != nil && len(ref.Files) != 0) {
			t.Errorf("changed meta %d: held %+v, %v", index, ref, err)
		}
		for name := range testSearchStorePlaintexts(t, cache) {
			if strings.HasPrefix(name, searchCacheRefName(key.RepoId, key.RefId)+"/p") {
				t.Errorf("changed meta %d: %s stays", index, name)
			}
		}
	}
}
