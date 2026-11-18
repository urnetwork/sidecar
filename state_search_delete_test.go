//go:build !ios_extension

package sidecar

// CORE-M10-04: §5.9's delete row. An ERASE's or a CLOSURE's hint leaves no decrypted copy of an erased document on a
// current reader's device (§22.5's §11 row): the replaced versions and the records of destroyed slot keys go with their
// derived data and open reads, the retained buckets go, the local layer, the journal and the vocabulary lose the
// document and their sealed copies are written again, and its key is masked whole until a set lists it, which then
// masks at its listed version (DESIGN-DETAILS 15.2.10). A CUT masks what it lists at once, through IndexEraser's seam.
// A lost read deletes every file of the repo, or of one index ref. A record log's ERASE masks every copy's entry
// document and the run cards and hands the journal its again units. Too many masks mask everything. Each ends the
// repo's searches and remote cursors.

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A cache with a host's search parts over one repo registered through its delete hooks: an index ref's local layer and
// vocabulary, the repo's journal, and what the hooks were asked.
type testDeleteWorld struct {
	cacheWorld *testSearchCacheWorld
	cache      *SearchCache
	repoId     Id
	refId      Id
	refKey     []byte
	normalizer *indexNormalizer
	layer      *SearchLocalLayer
	layerKey   SearchCacheKey
	vocabulary *SearchVocabulary
	vocabKey   SearchCacheKey
	journal    *IndexJournal

	stateLock sync.Mutex
	ended     []Id
	forgot    []string
	again     []*SearchEraseAgain
}

func newTestDeleteWorld(t *testing.T, repoId Id, refId Id) *testDeleteWorld {
	t.Helper()
	cacheWorld := newTestSearchCacheWorld(t, 64*1024*1024)
	world := &testDeleteWorld{
		cacheWorld: cacheWorld,
		cache:      cacheWorld.cache,
		repoId:     repoId,
		refId:      refId,
		refKey:     testSearchRefKey("delete"),
		normalizer: testSearchNormalizer(t),
		vocabulary: NewSearchVocabulary(nil),
		layerKey:   SearchCacheKey{RepoId: repoId, RefId: refId, Path: SearchCacheRefPath},
		vocabKey:   SearchCacheKey{RepoId: repoId, RefId: refId, Path: SearchCacheRefPath, Version: 1},
	}
	layer, err := NewSearchLocalLayer(&SearchLocalLayerArgs{RepoId: repoId, RefId: refId, RefKey: world.refKey})
	if err != nil {
		t.Fatal(err)
	}
	world.layer = layer
	journal, err := newIndexJournal(cacheWorld.instance.Store(&cacheWorld.networkId), repoId, cacheWorld.settings, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	world.journal = journal
	if err := world.cache.SetRefVersion(repoId, refId, 9); err != nil {
		t.Fatal(err)
	}
	remove, err := world.cache.AddDeleteHooks(&SearchDeleteHooks{
		EndRepo: func(endedRepoId Id) {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			world.ended = append(world.ended, endedRepoId)
		},
		Journal: func(askedRepoId Id) *IndexJournal {
			if askedRepoId == world.repoId {
				return world.journal
			}
			return nil
		},
		LocalLayer: func(askedRepoId Id, askedRefId Id) (*SearchLocalLayer, SearchCacheKey) {
			if askedRepoId == world.repoId && askedRefId == world.refId {
				return world.layer, world.layerKey
			}
			return nil, SearchCacheKey{}
		},
		Vocabulary: func(askedRepoId Id, askedRefId Id) (*SearchVocabulary, SearchCacheKey, *indexNormalizer) {
			if askedRepoId == world.repoId && askedRefId == world.refId {
				return world.vocabulary, world.vocabKey, world.normalizer
			}
			return nil, SearchCacheKey{}, nil
		},
		Again: func(ctx context.Context, againRepoId Id, units []*SearchEraseAgain) error {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			world.again = append(world.again, units...)
			return nil
		},
		Forget: func(forgotRepoId Id, forgotRefId *Id) {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			name := forgotRepoId.String()
			if forgotRefId != nil {
				name += "/" + forgotRefId.String()
			}
			world.forgot = append(world.forgot, name)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)
	return world
}

// The repos the hooks ended, in order.
func (self *testDeleteWorld) endedRepos() []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.ended)
}

// A document's chunk-0 doc key under the world's ref.
func (self *testDeleteWorld) docKey(t *testing.T, path string) [indexIdByteCount]byte {
	t.Helper()
	key, err := indexDocKey(self.refKey, self.refId, []byte(path), 0)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A file's documents as extraction gives them.
func (self *testDeleteWorld) documents(t *testing.T, path string, content string, version uint64) []*IndexDocument {
	t.Helper()
	documents, ok := indexExtractFile([]byte(path), []byte(content), DefaultIndexFormatSettings())
	if !ok {
		t.Fatalf("%s is no text", path)
	}
	for _, document := range documents {
		document.Version = version
	}
	return documents
}

// Indexes a file version into the local layer and the vocabulary, sealing both, and journals it: what a desktop holds
// of a document it wrote.
func (self *testDeleteWorld) hold(t *testing.T, path string, content string, version uint64) []*IndexDocument {
	t.Helper()
	documents := self.documents(t, path, content, version)
	if err := self.layer.Index(self.normalizer, &SearchLocalVersion{RefId: self.refId, Path: []byte(path), Version: version, TimeMs: 1800000000000, Documents: documents}); err != nil {
		t.Fatal(err)
	}
	for _, document := range documents {
		if err := self.vocabulary.AddDocument(self.normalizer, document); err != nil {
			t.Fatal(err)
		}
	}
	unit := &indexJournalUnit{refId: self.refId, version: version, signedTimeMs: 1800000000000, stripped: true}
	for chunk := range documents {
		key, err := indexDocKey(self.refKey, self.refId, []byte(path), uint32(chunk))
		if err != nil {
			t.Fatal(err)
		}
		unit.documents = append(unit.documents, &indexJournalDocument{key: key, name: path, chunk: uint32(chunk), version: version})
	}
	if err := self.journal.Committed(unit); err != nil {
		t.Fatal(err)
	}
	if err := self.layer.Save(t.Context(), self.cache, self.layerKey); err != nil {
		t.Fatal(err)
	}
	if err := self.vocabulary.Save(t.Context(), self.cache, self.vocabKey); err != nil {
		t.Fatal(err)
	}
	return documents
}

// The doc keys every journal unit holds.
func (self *testDeleteWorld) journaled(t *testing.T) map[[indexIdByteCount]byte]bool {
	t.Helper()
	units, err := self.journal.units()
	if err != nil {
		t.Fatal(err)
	}
	keys := map[[indexIdByteCount]byte]bool{}
	for _, unit := range units {
		for _, document := range unit.documents {
			keys[document.key] = true
		}
	}
	return keys
}

// The sealed local layer as a restart reads it back.
func (self *testDeleteWorld) sealedLayer(t *testing.T) *SearchLocalLayer {
	t.Helper()
	layer, err := NewSearchLocalLayer(&SearchLocalLayerArgs{RepoId: self.repoId, RefId: self.refId, RefKey: self.refKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := layer.Load(self.cache, self.layerKey); err != nil {
		t.Fatal(err)
	}
	return layer
}

// A version table of the world's ref holding records, probed as a snapshot of that run.
func (self *testDeleteWorld) table(t *testing.T, records ...SearchVersionRecord) (*SearchVersionTable, []SearchVersionRunId) {
	t.Helper()
	table, err := NewSearchVersionTable(self.cache, self.repoId, self.refId, ".ur-index/i1")
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(records, func(a SearchVersionRecord, b SearchVersionRecord) int { return compareSearchVersionRecords(&a, &b) })
	runId, err := table.Merge(t.Context(), SearchVersionSlot{Kind: SearchVersionShards, StartDay: 20080}, []SearchVersionSource{SearchVersionRecordsSource(records)})
	if err != nil {
		t.Fatal(err)
	}
	return table, []SearchVersionRunId{runId}
}

// Probes one key, failing on an error.
func testDeleteProbe(t *testing.T, table *SearchVersionTable, runIds []SearchVersionRunId, key [indexIdByteCount]byte) SearchVersionProbe {
	t.Helper()
	probe, err := table.Probe(runIds, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return probe
}

// Whether any file of the cache's store holds word once its seal is opened, in any case.
func testDeleteStoreHolds(t *testing.T, cache *SearchCache, word string) bool {
	t.Helper()
	for _, content := range testSearchStorePlaintexts(t, cache) {
		if bytes.Contains(bytes.ToLower(content), []byte(word)) {
			return true
		}
	}
	return false
}

// §22.5's §11 row: after an ERASE's and a CLOSURE's hints a current reader's device holds no decrypted copy of the
// erased document: the record of the destroyed slot key and the CLOSURE's replaced version are gone with their derived
// data and the open read of one has ended, the retained buckets are gone, the local layer, the journal and the
// vocabulary hold nothing of it in memory or in their sealed copies, no file of the cache opens to its words, and its
// key is masked whole. Another document, and a record of another slot key, stay. The repo's searches end before and
// after.
func TestEraseLeavesNoDecryptedCopy(t *testing.T) {
	repoId, refId := evsTestId("erase repo"), evsTestId("erase ref")
	world := newTestDeleteWorld(t, repoId, refId)
	ctx := t.Context()
	erased := world.hold(t, "notes/secret.md", "# Zanzibarite\nthe zanzibarite plan and its shared words\n", 3)
	world.hold(t, "notes/plan.md", "# Plan\nshared words that stay\n", 2)
	erasedKey, keptKey := world.docKey(t, "notes/secret.md"), world.docKey(t, "notes/plan.md")
	if !testDeleteStoreHolds(t, world.cache, "zanzibarite") {
		t.Fatal("the cache's derived data does not hold the document before the erasure")
	}

	slotA, slotB := newTestSearchSlot(repoId, "a"), newTestSearchSlot(repoId, "b")
	slotA.addKey(t, 0, 1)
	slotA.addKey(t, 1, 1)
	slotB.addKey(t, 0, 1)
	partition := SearchCachePartition{StartDay: 20080}
	destroyed := slotA.record(t, SearchCacheKey{RepoId: repoId, RefId: refId, Path: ".ur-index/i1/b/20080/s/0", Version: 1}, partition, testSearchPlaintext("shard", 2*EvsRecordFrameByteCount), 0, 1)
	replaced := slotA.record(t, SearchCacheKey{RepoId: repoId, RefId: refId, Path: ".ur-index/i1/b/20080/w/aa/1", Version: 4}, partition, testSearchPlaintext("slot", 900), 1, 1)
	staying := slotB.record(t, SearchCacheKey{RepoId: repoId, RefId: refId, Path: ".ur-index/i1/b/20080/s/1", Version: 1}, partition, testSearchPlaintext("other shard", 700), 0, 1)
	for _, kept := range []*testSearchRecord{destroyed, replaced, staying} {
		if err := world.cache.PutRecord(ctx, kept.record); err != nil {
			t.Fatal(err)
		}
	}
	if err := world.cache.PutDerived(ctx, &SearchCacheDerived{Key: replaced.record.Key, Part: SearchCachePartBlockIndex, Plaintext: testSearchPlaintext("blocks", 3000)}); err != nil {
		t.Fatal(err)
	}
	if err := world.cache.RetainBucket(repoId, refId, 20073, 7, world.cacheWorld.clock.Now()); err != nil {
		t.Fatal(err)
	}
	read, err := world.cache.OpenRecordRead(ctx, destroyed.record.Key, &evsTestReadGkm{newest: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	replacedRead, err := world.cache.OpenRecordRead(ctx, replaced.record.Key, &evsTestReadGkm{newest: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer replacedRead.Close()
	table, runIds := world.table(t,
		SearchVersionRecord{Key: erasedKey, Version: 3, File: SearchVersionFile{Path: ".ur-index/i1/b/20080/s/0", Version: 1}},
		SearchVersionRecord{Key: keptKey, Version: 2, File: SearchVersionFile{Path: ".ur-index/i1/b/20080/s/1", Version: 1}})

	err = world.cache.ApplyErase(ctx, &SearchErase{
		RepoId:    repoId,
		ErasureId: evsTestId("erasure"),
		Keys:      []*EvsErasedKey{{SlotId: slotA.slotId, KeyIndex: 0}},
		Documents: []*SearchErasedDocuments{{RefId: refId, Keys: [][indexIdByteCount]byte{erasedKey}}},
		Texts:     []*SearchErasedText{{RefId: refId, Document: erased[0]}},
		Replaced:  []SearchCacheKey{replaced.record.Key},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, gone := range []SearchCacheKey{destroyed.record.Key, replaced.record.Key} {
		if _, err := world.cache.OpenRecord(gone); !errors.Is(err, ErrSidecarStoreAbsent) {
			t.Errorf("a record the erasure reached is still held: %v", err)
		}
	}
	if _, err := world.cache.OpenDerived(replaced.record.Key, SearchCachePartBlockIndex); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("the replaced version's derived data stays: %v", err)
	}
	if _, err := read.ReadFrame(0, nil); !errors.Is(err, ErrSearchCacheReadEnded) {
		t.Errorf("the open read of the destroyed key's record goes on: %v", err)
	}
	if _, err := replacedRead.ReadFrame(0, nil); !errors.Is(err, ErrSearchCacheReadEnded) || replacedRead.objectKey != nil {
		t.Errorf("the open read of the replaced version goes on: %v", err)
	}
	if _, err := world.cache.OpenRecord(staying.record.Key); err != nil {
		t.Errorf("another slot key's record went: %v", err)
	}
	held, err := world.cache.Ref(repoId, refId)
	if err != nil || held == nil || len(held.Retained) != 0 {
		t.Fatalf("the retained buckets stay: %+v, %v", held, err)
	}
	if journaled := world.journaled(t); journaled[erasedKey] || !journaled[keptKey] {
		t.Errorf("the journal after the erasure: %v", journaled)
	}
	if _, _, ok := world.layer.newest(erasedKey); ok {
		t.Error("the local layer holds the erased document")
	}
	sealed := world.sealedLayer(t)
	if _, _, ok := sealed.newest(erasedKey); ok {
		t.Error("the sealed local layer holds the erased document")
	}
	if _, _, ok := sealed.newest(keptKey); !ok {
		t.Error("the sealed local layer lost the kept document")
	}
	if world.vocabulary.Count("zanzibarite") != 0 || world.vocabulary.Count("shared") != 1 {
		t.Errorf("the vocabulary: zanzibarite %d, shared %d", world.vocabulary.Count("zanzibarite"), world.vocabulary.Count("shared"))
	}
	if testDeleteStoreHolds(t, world.cache, "zanzibarite") {
		t.Error("a file of the cache opens to the erased document's words")
	}
	if probe := testDeleteProbe(t, table, runIds, erasedKey); probe.ErasedThrough != SearchVersionErasedAll || probe.Current(3) {
		t.Errorf("the erased key's probe: %+v", probe)
	}
	if probe := testDeleteProbe(t, table, runIds, keptKey); !probe.Current(2) {
		t.Errorf("the kept key's probe: %+v", probe)
	}
	if ended := world.endedRepos(); len(ended) != 2 || ended[0] != repoId || ended[1] != repoId {
		t.Errorf("the repo's searches ended %v", ended)
	}
	for _, malformed := range []*SearchErase{
		{RepoId: repoId},
		{RepoId: repoId, ErasureId: evsTestId("erasure"), Keys: []*EvsErasedKey{{}}},
		{RepoId: repoId, ErasureId: evsTestId("erasure"), Replaced: []SearchCacheKey{{RepoId: evsTestId("another repo"), RefId: refId, Path: "x", Version: 1}}},
		{RepoId: repoId, ErasureId: evsTestId("erasure"), Documents: []*SearchErasedDocuments{{RefId: refId, Keys: [][indexIdByteCount]byte{{}}}}},
	} {
		if err := world.cache.ApplyErase(ctx, malformed); !errors.Is(err, ErrSearchCacheArgs) {
			t.Errorf("a malformed hint %+v: %v", malformed, err)
		}
	}
	if ended := world.endedRepos(); len(ended) != 2 {
		t.Errorf("a malformed hint ended searches: %v", ended)
	}
}

// FS-78's clause at the cache: an ERASE's text leaves the vocabulary, a word only the erased document held going with
// it and a shared one counting one less, in memory and in the sealed copy that replaces the last; another ref's
// vocabulary is not asked.
func TestEraseRemovesVocabularyWords(t *testing.T) {
	repoId, refId := evsTestId("vocabulary repo"), evsTestId("vocabulary ref")
	world := newTestDeleteWorld(t, repoId, refId)
	ctx := t.Context()
	erased := world.hold(t, "mail/1.eml", "Subject: quixotry\n\nthe quixotry and common words\n", 1)
	world.hold(t, "mail/2.eml", "Subject: hello\n\ncommon words again\n", 1)
	if world.vocabulary.Count("quixotry") != 1 || world.vocabulary.Count("common") != 2 {
		t.Fatalf("before: quixotry %d, common %d", world.vocabulary.Count("quixotry"), world.vocabulary.Count("common"))
	}
	texts := []*SearchErasedText{}
	for _, document := range erased {
		texts = append(texts, &SearchErasedText{RefId: refId, Document: document})
	}
	// a text of another ref, whose vocabulary this host does not keep, asks nothing of this one
	texts = append(texts, &SearchErasedText{RefId: evsTestId("another ref"), Document: erased[0]})
	err := world.cache.ApplyErase(ctx, &SearchErase{RepoId: repoId, ErasureId: evsTestId("erasure"), Texts: texts})
	if err != nil {
		t.Fatal(err)
	}
	if world.vocabulary.Count("quixotry") != 0 || world.vocabulary.Count("common") != 1 || world.vocabulary.Count("again") != 1 {
		t.Fatalf("after: quixotry %d, common %d", world.vocabulary.Count("quixotry"), world.vocabulary.Count("common"))
	}
	loaded, err := LoadSearchVocabulary(world.cache, world.vocabKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.encode(), world.vocabulary.encode()) || loaded.Count("quixotry") != 0 {
		t.Fatal("the sealed vocabulary is not the one erased")
	}
}

// DESIGN-DETAILS 15.2.10's masks: an ERASE's key is masked whole until an erasure set this device holds lists it, and
// then at and below its listed version, so a version above shows; a CUT masks what it lists at once, before any swap;
// a newer set that dropped the erasure lifts its mask, a stale one lifts nothing; a set's run in the table wins over
// the ERASE's mask too; and the masks outlive a restart.
func TestEraseMaskGivesWayToSetListing(t *testing.T) {
	repoId, refId := evsTestId("mask repo"), evsTestId("mask ref")
	world := newTestDeleteWorld(t, repoId, refId)
	ctx := t.Context()
	edited, cutOnly, older := testIndexId("edited", 1), testIndexId("cut only", 1), testIndexId("older", 1)
	table, runIds := world.table(t,
		SearchVersionRecord{Key: edited, Version: 6, File: SearchVersionFile{Path: "b/20080/s/0", Version: 1}},
		SearchVersionRecord{Key: cutOnly, Version: 3, File: SearchVersionFile{Path: "b/20080/s/0", Version: 1}},
		SearchVersionRecord{Key: older, Version: 4, File: SearchVersionFile{Path: "b/20080/s/0", Version: 1}})
	err := world.cache.ApplyErase(ctx, &SearchErase{RepoId: repoId, ErasureId: evsTestId("erasure"),
		Documents: []*SearchErasedDocuments{{RefId: refId, Keys: [][indexIdByteCount]byte{edited}}}})
	if err != nil {
		t.Fatal(err)
	}
	if probe := testDeleteProbe(t, table, runIds, edited); probe.ErasedThrough != SearchVersionErasedAll || probe.Current(6) {
		t.Fatalf("the ERASE's key before any set: %+v", probe)
	}
	set := &protocol.IndexErasureSet{Erasures: []*protocol.IndexErasure{{
		ErasureId: evsTestId("erasure").Bytes(), Epoch: 10,
		Docs: []*protocol.IndexErased{{DocKey: edited[:], Version: 5}, {DocKey: cutOnly[:], Version: 3}},
	}}}
	if err := world.cache.ApplyCut(ctx, repoId, refId, set); err != nil {
		t.Fatal(err)
	}
	if probe := testDeleteProbe(t, table, runIds, edited); probe.ErasedThrough != 5 || !probe.Current(6) {
		t.Fatalf("an edit above the listed version: %+v", probe)
	}
	if probe := testDeleteProbe(t, table, runIds, cutOnly); probe.ErasedThrough != 3 || probe.Current(3) {
		t.Fatalf("a CUT's document at once: %+v", probe)
	}
	// an ERASE of a key a CUT lists already keeps the listing
	if err := world.cache.ApplyErase(ctx, &SearchErase{RepoId: repoId, ErasureId: evsTestId("erasure"),
		Documents: []*SearchErasedDocuments{{RefId: refId, Keys: [][indexIdByteCount]byte{cutOnly}}}}); err != nil {
		t.Fatal(err)
	}
	if probe := testDeleteProbe(t, table, runIds, cutOnly); probe.ErasedThrough != 3 {
		t.Fatalf("an ERASE after the CUT: %+v", probe)
	}
	// a stale set, below the erasure's epoch, lists neither: nothing lifts
	if err := world.cache.ApplyCut(ctx, repoId, refId, &protocol.IndexErasureSet{ListedSince: 4}); err != nil {
		t.Fatal(err)
	}
	if probe := testDeleteProbe(t, table, runIds, cutOnly); probe.ErasedThrough != 3 {
		t.Fatalf("a stale set lifted a mask: %+v", probe)
	}
	// the masks are sealed with the ref's holdings: a restart reads them back
	world.cache.Close()
	restarted, err := NewSearchCache(ctx, world.cacheWorld.instance.Store(&world.cacheWorld.networkId), world.cacheWorld.settings, world.cacheWorld.clock, NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	restartedTable, err := NewSearchVersionTable(restarted, repoId, refId, ".ur-index/i1")
	if err != nil {
		t.Fatal(err)
	}
	if probe := testDeleteProbe(t, restartedTable, runIds, edited); probe.ErasedThrough != 5 {
		t.Fatalf("after a restart: %+v", probe)
	}
	// a newer set, whose listed_since passed the erasure's epoch, dropped it: the masks it listed go
	if err := restarted.ApplyCut(ctx, repoId, refId, &protocol.IndexErasureSet{ListedSince: 11}); err != nil {
		t.Fatal(err)
	}
	if probe := testDeleteProbe(t, restartedTable, runIds, cutOnly); probe.ErasedThrough != 0 || !probe.Current(3) {
		t.Fatalf("a mask the newer set dropped: %+v", probe)
	}
	if held, err := restarted.Ref(repoId, refId); err != nil || held == nil || len(held.Erased) != 0 {
		t.Fatalf("masks left: %+v, %v", held, err)
	}
	// a set's run in the table wins over an ERASE's mask: the listing masks at its version
	if err := restarted.ApplyErase(ctx, &SearchErase{RepoId: repoId, ErasureId: evsTestId("second erasure"),
		Documents: []*SearchErasedDocuments{{RefId: refId, Keys: [][indexIdByteCount]byte{older}}}}); err != nil {
		t.Fatal(err)
	}
	listedRun, err := restartedTable.Merge(ctx, SearchVersionSlot{Kind: SearchVersionErased}, []SearchVersionSource{SearchVersionRecordsSource{{Key: older, Version: 2}}})
	if err != nil {
		t.Fatal(err)
	}
	if probe := testDeleteProbe(t, restartedTable, append(slices.Clone(runIds), listedRun), older); probe.ErasedThrough != 2 || !probe.Current(4) {
		t.Fatalf("a set's run beside the ERASE's mask: %+v", probe)
	}
	if probe := testDeleteProbe(t, restartedTable, runIds, older); probe.ErasedThrough != SearchVersionErasedAll {
		t.Fatalf("the ERASE's mask with no set: %+v", probe)
	}
}

// SEARCH-M10-16's seam joined: a CUT's eraser takes ApplyCut as its applyCut, so the CUT's own device masks what it
// lists at once, its journaled and local-layer entries at or below the listed version gone, a newer version staying,
// and the repo's searches ended.
func TestCutAppliesAtOnceThroughTheEraser(t *testing.T) {
	headWorld := testNewHeadWorld()
	writer := evsTestId("writer a")
	headWorld.push(t, writer, testLive("d", 1, 1, testHeadKeys(1, 0)))
	repoId, refId := evsTestId("view repo"), evsTestId("view ref")
	world := newTestDeleteWorld(t, repoId, refId)
	ctx := t.Context()
	world.hold(t, "notes/cut.md", "# Cut\nwords a cut lists\n", 2)
	world.hold(t, "notes/later.md", "# Later\nwords of a later version\n", 7)
	cutKey, laterKey := world.docKey(t, "notes/cut.md"), world.docKey(t, "notes/later.md")
	table, runIds := world.table(t,
		SearchVersionRecord{Key: cutKey, Version: 2, File: SearchVersionFile{Path: ".ur-index/b/20080/s/0", Version: 1}},
		SearchVersionRecord{Key: laterKey, Version: 7, File: SearchVersionFile{Path: ".ur-index/b/20080/s/0", Version: 1}})
	eraser, err := indexNewEraser(&indexEraserArgs{
		store:    headWorld.ref.store(evsTestId("eraser")),
		repoId:   repoId,
		refId:    refId,
		repoKind: protocol.RepoKind_REPO_KIND_GENERAL,
		isAdmin:  testIndexEraserAdmin,
		format:   DefaultIndexFormatSettings(),
		eraser:   evsTestId("eraser"),
		applyCut: world.cache.ApplyCut,
		clock:    &testIndexWorldClock{world: headWorld},
		log:      NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	result := testCut(t, eraser, "erasure", &IndexCutDocument{Key: cutKey, Version: 2}, &IndexCutDocument{Key: laterKey, Version: 3})
	if !result.Pushed {
		t.Fatalf("the CUT: %+v", result)
	}
	if probe := testDeleteProbe(t, table, runIds, cutKey); probe.ErasedThrough != 2 || probe.Current(2) {
		t.Errorf("the listed document: %+v", probe)
	}
	if probe := testDeleteProbe(t, table, runIds, laterKey); !probe.Current(7) {
		t.Errorf("a version above its listing: %+v", probe)
	}
	if journaled := world.journaled(t); journaled[cutKey] || !journaled[laterKey] {
		t.Errorf("the journal after the CUT: %v", journaled)
	}
	if _, _, ok := world.sealedLayer(t).newest(cutKey); ok {
		t.Error("the sealed local layer holds the listed document")
	}
	if _, _, ok := world.layer.newest(laterKey); !ok {
		t.Error("the local layer lost a version above its listing")
	}
	if ended := world.endedRepos(); len(ended) < 2 || ended[0] != repoId {
		t.Errorf("the repo's searches ended %v", ended)
	}
	if err := world.cache.ApplyCut(ctx, repoId, refId, nil); !errors.Is(err, ErrSearchCacheArgs) {
		t.Errorf("a CUT of no set: %v", err)
	}
}

// Every name the cache's store holds under a repo.
func testDeleteNamesOf(t *testing.T, cache *SearchCache, repoId Id) []string {
	t.Helper()
	entries, err := cache.store.List(hex.EncodeToString(repoId[:]) + "/")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}

// §5.9's delete row: a repo this sidecar no longer reads loses every file of the cache, on every ref, with its derived
// data, masks and retained buckets, and its journal's units, and the host forgets it; another repo keeps all of its
// own. An index turned off on one ref loses that ref's files alone.
func TestLostReadDeletesRepoFiles(t *testing.T) {
	repoId, refId := evsTestId("lost repo"), evsTestId("lost ref")
	world := newTestDeleteWorld(t, repoId, refId)
	ctx := t.Context()
	world.hold(t, "notes/a.md", "# A\nwords\n", 1)
	otherRefId, otherRepoId := evsTestId("lost other ref"), evsTestId("kept repo")
	put := func(key SearchCacheKey, label string) {
		record := newTestSearchRecord(t, key, SearchCachePartition{StartDay: 20080}, testSearchPlaintext(label, 1500))
		if err := world.cache.PutRecord(ctx, record.record); err != nil {
			t.Fatal(err)
		}
		if err := world.cache.PutDerived(ctx, &SearchCacheDerived{Key: key, Part: SearchCachePartDocCounts, Plaintext: testSearchPlaintext(label+" counts", 400)}); err != nil {
			t.Fatal(err)
		}
	}
	put(SearchCacheKey{RepoId: repoId, RefId: refId, Path: ".ur-index/i1/b/20080/s/0", Version: 1}, "lost a")
	put(SearchCacheKey{RepoId: repoId, RefId: otherRefId, Path: ".ur-index/i1/b/20080/s/0", Version: 1}, "lost b")
	put(SearchCacheKey{RepoId: otherRepoId, RefId: refId, Path: ".ur-index/i1/b/20080/s/0", Version: 1}, "kept")
	put(SearchCacheKey{RepoId: otherRepoId, RefId: otherRefId, Path: ".ur-index/i1/b/20080/s/0", Version: 1}, "kept off")
	if err := world.cache.RetainBucket(repoId, otherRefId, 20073, 7, world.cacheWorld.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := world.cache.ApplyErase(ctx, &SearchErase{RepoId: repoId, ErasureId: evsTestId("erasure"),
		Documents: []*SearchErasedDocuments{{RefId: otherRefId, Keys: [][indexIdByteCount]byte{testIndexId("masked", 1)}}}}); err != nil {
		t.Fatal(err)
	}
	if len(world.journaled(t)) == 0 || len(testDeleteNamesOf(t, world.cache, repoId)) == 0 {
		t.Fatal("nothing held before the lost read")
	}
	keptBefore := testDeleteNamesOf(t, world.cache, otherRepoId)
	lostRead, err := world.cache.OpenRecordRead(ctx, SearchCacheKey{RepoId: repoId, RefId: otherRefId, Path: ".ur-index/i1/b/20080/s/0", Version: 1}, &evsTestReadGkm{newest: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer lostRead.Close()
	keptRead, err := world.cache.OpenRecordRead(ctx, SearchCacheKey{RepoId: otherRepoId, RefId: refId, Path: ".ur-index/i1/b/20080/s/0", Version: 1}, &evsTestReadGkm{newest: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer keptRead.Close()

	if err := world.cache.ApplyLostRead(ctx, repoId, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := lostRead.ReadFrame(0, nil); !errors.Is(err, ErrSearchCacheReadEnded) {
		t.Errorf("a read of the lost repo goes on: %v", err)
	}
	if _, err := keptRead.ReadFrame(0, nil); err != nil {
		t.Errorf("a read of another repo ended: %v", err)
	}
	if names := testDeleteNamesOf(t, world.cache, repoId); len(names) != 0 {
		t.Errorf("the lost repo's files stay: %v", names)
	}
	for _, lostRefId := range []Id{refId, otherRefId} {
		if held, err := world.cache.Ref(repoId, lostRefId); err != nil || held != nil {
			t.Errorf("the lost repo's ref is still held: %+v, %v", held, err)
		}
	}
	if len(world.journaled(t)) != 0 {
		t.Error("the lost repo's journal keeps units")
	}
	if names := testDeleteNamesOf(t, world.cache, otherRepoId); !slices.Equal(names, keptBefore) {
		t.Errorf("another repo's files changed: %v", names)
	}

	// the index turned off on one ref of the other repo
	if err := world.cache.ApplyLostRead(ctx, otherRepoId, &otherRefId); err != nil {
		t.Fatal(err)
	}
	for _, name := range testDeleteNamesOf(t, world.cache, otherRepoId) {
		if strings.HasPrefix(name, hex.EncodeToString(otherRepoId[:])+"/"+hex.EncodeToString(otherRefId[:])) {
			t.Errorf("the ref whose index is off keeps %s", name)
		}
	}
	if held, err := world.cache.Ref(otherRepoId, refId); err != nil || held == nil || len(held.Files) != 1 {
		t.Errorf("the other ref of that repo: %+v, %v", held, err)
	}
	world.stateLock.Lock()
	forgot := slices.Clone(world.forgot)
	world.stateLock.Unlock()
	if !slices.Equal(forgot, []string{repoId.String(), otherRepoId.String() + "/" + otherRefId.String()}) {
		t.Errorf("the host forgot %v", forgot)
	}
	if err := world.cache.ApplyLostRead(ctx, Id{}, nil); !errors.Is(err, ErrSearchCacheArgs) {
		t.Errorf("a lost read of no repo: %v", err)
	}
}

// DESIGN-DETAILS 15.2.10 and 15.7's note: a record log's ERASE masks the entry document of every copy of an entry it
// names, by key or by its note's entry_id, and the run card of each stream holding a copy of a source entry, drops
// their journal units, and hands the journal an again unit for each such run and stream.
func TestEraseRecordMasksCardsAndCopies(t *testing.T) {
	logId, indexRefId := evsTestId("record log"), evsTestId("record ur/index")
	world := newTestDeleteWorld(t, logId, indexRefId)
	ctx := t.Context()
	runId := evsTestId("run")
	streamA, streamB := evsTestId("stream sidecar a"), evsTestId("stream sidecar b")
	refA, refB := evsTestId("ref a"), evsTestId("ref b")
	note := testRecordEntry(t, "note", RecordKindNote, Id{}, 1, &protocol.CoordinationBody{Text: "two copies"})
	tool := testRecordEntry(t, "tool", RecordKindToolCall, runId, 2, &protocol.ToolCallBody{ToolName: "Edit"})
	noteKeyA := RecordSlotKey{SlotId: evsTestId("slot note a")}
	entries := []*RecordReadEntry{
		testRecordReadEntry(note, RecordEntryErased,
			&RecordEntryCopy{StreamSidecarId: streamA, Version: 1, Path: "e/0/0/1", SlotId: noteKeyA.SlotId},
			&RecordEntryCopy{StreamSidecarId: streamB, Version: 4, Path: "e/0/0/4", SlotId: evsTestId("slot note b")}),
		testRecordReadEntry(tool, RecordEntryErased,
			&RecordEntryCopy{StreamSidecarId: streamA, Version: 2, Path: "e/0/0/2", SlotId: evsTestId("slot tool a")},
			&RecordEntryCopy{StreamSidecarId: streamB, Version: 5, Path: "e/0/0/5", SlotId: evsTestId("slot tool b")}),
	}
	streams := []*RecordReadStream{{StreamSidecarId: streamA, RefId: refA}, {StreamSidecarId: streamB, RefId: refB}}
	erasureId := evsTestId("erasure")
	erase := testRecordErase(t, erasureId, false, 1, []RecordSlotKey{noteKeyA}, tool.entryId)
	key := func(refId Id, name []byte) [indexIdByteCount]byte {
		key, err := indexDocKey(world.refKey, refId, name, 0)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	noteCopyB, cardA := key(refB, []byte("e/0/0/4")), key(refA, indexRunCardName(runId))
	journaledUnit := &indexJournalUnit{refId: refB, version: 4, signedTimeMs: 1800000000000, stripped: true,
		documents: []*indexJournalDocument{{key: noteCopyB, name: "e/0/0/4", version: 4}}}
	if err := world.journal.Committed(journaledUnit); err != nil {
		t.Fatal(err)
	}
	table, runIds := world.table(t, SearchVersionRecord{Key: noteCopyB, Version: 4}, SearchVersionRecord{Key: cardA, Version: 1 << 32})

	err := world.cache.ApplyErase(ctx, &SearchErase{RepoId: logId, ErasureId: erasureId, Record: &SearchEraseRecord{
		IndexRefId: indexRefId, RefKey: world.refKey, Kind: protocol.RepoKind_REPO_KIND_VAULT, Erasure: erase, Entries: entries, Streams: streams,
	}})
	if err != nil {
		t.Fatal(err)
	}
	// a vault indexes a note as its own document and a tool call only as its run card's source (RECORD.md 7.1)
	for _, masked := range [][indexIdByteCount]byte{key(refA, []byte("e/0/0/1")), noteCopyB, cardA, key(refB, indexRunCardName(runId))} {
		if probe := testDeleteProbe(t, table, runIds, masked); probe.ErasedThrough != SearchVersionErasedAll {
			t.Errorf("a copy or card not masked: %x %+v", masked, probe)
		}
	}
	for _, unmasked := range [][indexIdByteCount]byte{key(refA, []byte("e/0/0/2")), key(refB, []byte("e/0/0/5"))} {
		if probe := testDeleteProbe(t, table, runIds, unmasked); probe.ErasedThrough != 0 {
			t.Errorf("a key that is no document of the log masked: %x %+v", unmasked, probe)
		}
	}
	if world.journaled(t)[noteCopyB] {
		t.Error("the journal keeps a copy's unit")
	}
	world.stateLock.Lock()
	again := slices.Clone(world.again)
	world.stateLock.Unlock()
	want := []*SearchEraseAgain{{RefId: refA, RunId: runId, ErasureId: erasureId}, {RefId: refB, RunId: runId, ErasureId: erasureId}}
	slices.SortFunc(want, func(a *SearchEraseAgain, b *SearchEraseAgain) int { return a.RefId.Cmp(b.RefId) })
	if len(again) != len(want) || *again[0] != *want[0] || *again[1] != *want[1] {
		t.Errorf("again units %+v, want %+v", again, want)
	}
}

// Past Search.EraseMaskCount a ref's masks overflow and every probe of it fails, so every candidate is masked, across a
// restart, until the ref is dropped.
func TestEraseMasksOverflowFailsClosed(t *testing.T) {
	repoId, refId := evsTestId("overflow repo"), evsTestId("overflow ref")
	world := newTestDeleteWorld(t, repoId, refId)
	world.cacheWorld.settings.EraseMaskCount = 2
	ctx := t.Context()
	table, runIds := world.table(t, SearchVersionRecord{Key: testIndexId("unrelated", 1), Version: 1})
	keys := [][indexIdByteCount]byte{testIndexId("masked", 1), testIndexId("masked", 2), testIndexId("masked", 3)}
	if err := world.cache.ApplyErase(ctx, &SearchErase{RepoId: repoId, ErasureId: evsTestId("erasure"),
		Documents: []*SearchErasedDocuments{{RefId: refId, Keys: keys}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := table.Probe(runIds, testIndexId("unrelated", 1), nil); !errors.Is(err, ErrSearchCacheMasksOverflow) {
		t.Fatalf("a probe of an overflowed ref: %v", err)
	}
	world.cache.Close()
	restarted, err := NewSearchCache(ctx, world.cacheWorld.instance.Store(&world.cacheWorld.networkId), world.cacheWorld.settings, world.cacheWorld.clock, NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	restartedTable, err := NewSearchVersionTable(restarted, repoId, refId, ".ur-index/i1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restartedTable.Probe(runIds, testIndexId("unrelated", 1), nil); !errors.Is(err, ErrSearchCacheMasksOverflow) {
		t.Fatalf("after a restart: %v", err)
	}
	if err := restarted.DropRef(repoId, refId); err != nil {
		t.Fatal(err)
	}
	if held, err := restarted.Ref(repoId, refId); err != nil || held != nil {
		t.Fatalf("the dropped ref: %+v, %v", held, err)
	}
}

// §5.4's erasure event: the repo and the erasure's state, what is left and when it tries next, in one of §5.4's states;
// any other state, or none of a repo or an erasure, is refused and raises nothing.
func TestErasureEventStates(t *testing.T) {
	world := newSearchTestSidecar(t, nil)
	repoId := evsTestId("erasure event repo")
	erasure := &SidecarErasure{ErasureId: evsTestId("erasure"), State: SidecarErasureWaiting, ObjectsLeft: 3, BytesLeft: 4096}
	if err := world.sidecar.raiseErasure(repoId, erasure); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		repoId  Id
		erasure *SidecarErasure
	}{
		{repoId: repoId, erasure: &SidecarErasure{ErasureId: evsTestId("erasure"), State: "paused"}},
		{repoId: Id{}, erasure: erasure},
		{repoId: repoId, erasure: &SidecarErasure{State: SidecarErasureDone}},
		{repoId: repoId, erasure: nil},
	} {
		if err := world.sidecar.raiseErasure(bad.repoId, bad.erasure); !errors.Is(err, ErrSearchCacheArgs) {
			t.Errorf("a malformed erasure event: %v", err)
		}
	}
	events := world.raised()
	if len(events) != 1 {
		t.Fatalf("%d events raised", len(events))
	}
	event := events[0]
	if event.Kind != SidecarEventErasure || event.RepoId == nil || *event.RepoId != repoId || event.Erasure == nil ||
		event.Erasure.State != SidecarErasureWaiting || event.Erasure.ObjectsLeft != 3 || event.Erasure == erasure {
		t.Fatalf("the event %+v", event)
	}
}
