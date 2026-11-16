//go:build !ios_extension

// §5.9's delete row for the index cache (CORE-M10-04; R-CORE-18, D-CORE-16, I-19, FI-19, FS-111; DESIGN-DETAILS 7.2.5,
// 7.2.7, 15.2.10 and 15.7's note): what an erasure, a CUT and a lost read delete of one network's search state, at once,
// before the call that asks it answers.
//
//	erase  ApplyErase, at an ERASE's or a CLOSURE's hint (§11.12's after row): every cached version a CLOSURE replaced,
//	       with its derived data; every kept record whose slot key the ERASE destroys, its wrapped block with it, and
//	       every open read of one (QD-845); the repo's retained buckets; the erased documents' local-layer entries and
//	       those this device journaled for its next companion push; their words in the vocabulary, decremented from the
//	       text the caller read before it deleted it; and their keys, masked whole in search until an erasure set this
//	       device holds lists them (DESIGN-DETAILS 15.2.10's masks). A record log's ERASE also masks the entry document
//	       of every copy of an erased entry, found by entry_id from the ERASE's note, and the run card of each stream
//	       holding a copy of a source entry (indexRecordEraseMaskKeys), drops their journal units, and hands the
//	       journal its again units (15.2.9)
//	cut    ApplyCut, at a CUT's hint or a synced erasure set: the documents it lists, their journaled and local-layer
//	       entries dropped and their versions at or below the listed one masked at once, until the sync engine's swap
//	       brings the set into the version table; a CUT's eraser takes it as IndexEraser's applyCut
//	lost   ApplyLostRead: every file of a repo this sidecar no longer reads (a removal, a generation not wrapped to it, a
//	       revoked EvsShare or grant) or that is deleted or shredded, or of one index ref whose index was turned off,
//	       derived data, masks and retained buckets with them, and what the host holds of it in memory
//	ends   each ends the repo's open searches with their snapshots (SearchSync.EndRepo) and its remote cursors
//	       (SearchRemoteServer.EndRepo) before it deletes and again before it answers, through the hooks the host
//	       registers (AddDeleteHooks), so the files an erasure replaced go at once and no page computed after it holds
//	       what it deleted (§16.10's pages row)
//
// Masks live in the ref's holdings record (SearchCacheRef.Erased), sealed and derived, so they go with the ref's files,
// and a probe of the ref's version table joins them (SearchVersionSnapshot.Probe). An ERASE's mask stays until a set
// this device applied lists the key; a CUT's until a set that raised listed_since past its erasure's epoch, a newer
// one, no longer lists it. A mask that would pass Search.EraseMaskCount, or does not decode, overflows the ref: its
// probes fail, so every candidate of it is masked, until the ref is dropped and synced again.
//
// Not here: files a newer ref version no longer names, but a retained bucket, which the sync engine's retire step
// deletes (SEARCH-M10-19, CORE-M10-01's RetainBucket); `ur search sync --evict`, which is DropRef, DropRepo and DropAll;
// a lock, which drops the decoded state and open cursors (state_search_cache.go). Nothing here creates, derives or
// unwraps a key, and nothing of a document is logged (I-13). Barriers search.cache.erase.applied, .cut.applied and
// .lost.applied, keyed by repo, at each call's linearization point: its masks stored and its files gone.
//
// On every leg but the forwarding one, which runs no search. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// More erasure masks were asked of a ref than Search.EraseMaskCount, or a kept one did not decode: every probe of
	// the ref fails, masking every candidate, until the ref is dropped and synced again.
	ErrSearchCacheMasksOverflow = errors.New("search cache: the ref's erasure masks overflowed; its candidates are masked")
)

// A host's search parts over its repos that a deletion reaches beside the cache's own files (§5.9's delete row;
// DESIGN-DETAILS 7.2.5, 7.2.7, 15.7's note), registered with AddDeleteHooks by the host that builds them. Each field is
// nil where the host keeps none of it, and each is called with no lock of the cache held, before the deletion answers.
type SearchDeleteHooks struct {
	// Ends every open search of the repo, releasing its snapshot (SearchSync.EndRepo), or every remote cursor serving
	// it (SearchRemoteServer.EndRepo).
	EndRepo func(repoId Id)
	// The repo's journal of this device's own committed documents not yet in a companion push (SEARCH-M10-14), nil for
	// none.
	Journal func(repoId Id) *IndexJournal
	// The local layer of an index ref (SEARCH-M10-25), with the key its sealed copy is kept at; nil for none.
	LocalLayer func(repoId Id, refId Id) (*SearchLocalLayer, SearchCacheKey)
	// The local vocabulary of an index ref (SEARCH-M10-25), the key its sealed copy is kept at, and the normalizer that
	// counted it; nil for none.
	Vocabulary func(repoId Id, refId Id) (*SearchVocabulary, SearchCacheKey, *indexNormalizer)
	// Appends a record log's again units (DESIGN-DETAILS 15.2.9) to the repo's journal: SEARCH-M10-14's.
	Again func(ctx context.Context, repoId Id, units []*SearchEraseAgain) error
	// Forgets what the host holds in memory of a repo whose files a lost read deleted, or with refId of one index ref of
	// it: its follows, local layers, vocabularies and, for the whole repo, its journal.
	Forget func(repoId Id, refId *Id)
}

// The hook sets a cache's deletions reach, in the order they were added.
type searchDeleteHookSet struct {
	stateLock sync.Mutex
	hooks     map[uint64]*SearchDeleteHooks
	nextId    uint64
}

// The cache's hook sets, made on first use.
func (self *SearchCache) deleteHookSet() *searchDeleteHookSet {
	if set, ok := self.deleteHooks.Load().(*searchDeleteHookSet); ok {
		return set
	}
	self.deleteHooks.CompareAndSwap(nil, &searchDeleteHookSet{hooks: map[uint64]*SearchDeleteHooks{}})
	return self.deleteHooks.Load().(*searchDeleteHookSet)
}

// Adds hooks, which every deletion from now on reaches; the answer removes them.
func (self *SearchCache) AddDeleteHooks(hooks *SearchDeleteHooks) (func(), error) {
	if hooks == nil {
		return nil, fmt.Errorf("%w: no hooks", ErrSearchCacheArgs)
	}
	set := self.deleteHookSet()
	set.stateLock.Lock()
	defer set.stateLock.Unlock()
	set.nextId += 1
	hooksId := set.nextId
	set.hooks[hooksId] = hooks
	var once sync.Once
	return func() {
		once.Do(func() {
			set.stateLock.Lock()
			defer set.stateLock.Unlock()
			delete(set.hooks, hooksId)
		})
	}, nil
}

// The hooks added, oldest first.
func (self *SearchCache) deleteHookList() []*SearchDeleteHooks {
	set := self.deleteHookSet()
	set.stateLock.Lock()
	defer set.stateLock.Unlock()
	hooksIds := make([]uint64, 0, len(set.hooks))
	for hooksId := range set.hooks {
		hooksIds = append(hooksIds, hooksId)
	}
	slices.Sort(hooksIds)
	list := make([]*SearchDeleteHooks, 0, len(hooksIds))
	for _, hooksId := range hooksIds {
		list = append(list, set.hooks[hooksId])
	}
	return list
}

// Ends the repo's open searches and remote cursors through every hook set (DESIGN-DETAILS 7.2.5, 7.2.7).
func (self *SearchCache) endRepo(repoId Id) {
	for _, hooks := range self.deleteHookList() {
		if hooks.EndRepo != nil {
			hooks.EndRepo(repoId)
		}
	}
}

// The journals of the repo the hooks hold, each once.
func (self *SearchCache) deleteJournals(repoId Id) []*IndexJournal {
	journals := []*IndexJournal{}
	for _, hooks := range self.deleteHookList() {
		if hooks.Journal == nil {
			continue
		}
		if journal := hooks.Journal(repoId); journal != nil && !slices.Contains(journals, journal) {
			journals = append(journals, journal)
		}
	}
	return journals
}

// A local layer the hooks hold, with where it is sealed.
type searchDeleteLayer struct {
	layer *SearchLocalLayer
	key   SearchCacheKey
}

// The local layers of an index ref the hooks hold, each once.
func (self *SearchCache) deleteLayers(repoId Id, refId Id) []searchDeleteLayer {
	layers := []searchDeleteLayer{}
	for _, hooks := range self.deleteHookList() {
		if hooks.LocalLayer == nil {
			continue
		}
		layer, key := hooks.LocalLayer(repoId, refId)
		if layer == nil || slices.ContainsFunc(layers, func(held searchDeleteLayer) bool { return held.layer == layer }) {
			continue
		}
		layers = append(layers, searchDeleteLayer{layer: layer, key: key})
	}
	return layers
}

// A vocabulary the hooks hold, with where it is sealed and what counted it.
type searchDeleteVocabulary struct {
	vocabulary *SearchVocabulary
	key        SearchCacheKey
	normalizer *indexNormalizer
}

// The vocabularies of an index ref the hooks hold, each once.
func (self *SearchCache) deleteVocabularies(repoId Id, refId Id) []searchDeleteVocabulary {
	vocabularies := []searchDeleteVocabulary{}
	for _, hooks := range self.deleteHookList() {
		if hooks.Vocabulary == nil {
			continue
		}
		vocabulary, key, normalizer := hooks.Vocabulary(repoId, refId)
		if vocabulary == nil || normalizer == nil ||
			slices.ContainsFunc(vocabularies, func(held searchDeleteVocabulary) bool { return held.vocabulary == vocabulary }) {
			continue
		}
		vocabularies = append(vocabularies, searchDeleteVocabulary{vocabulary: vocabulary, key: key, normalizer: normalizer})
	}
	return vocabularies
}

// Seals a derived part again after a deletion took something from it, so no kept copy holds what went: save writes
// it; where the ref is no longer followed, so it cannot be written, the kept copy goes instead.
func (self *SearchCache) resealDerived(key SearchCacheKey, part SearchCachePart, save func() error) error {
	err := save()
	if errors.Is(err, ErrSearchCacheUnnamed) {
		return self.RemoveDerived(key, part)
	}
	return err
}

// An ERASE's or a CLOSURE's hint, as the device that read it hands it to the cache (§11.12's after row): the erasure
// ref's reader for an ERASE, with what its keys covered; the sync engine's replay for a CLOSURE, with what it replaced.
type SearchErase struct {
	RepoId Id
	// The erasure, by the id its notes name.
	ErasureId Id
	// An ERASE's slot keys: each kept record of the repo naming one goes at once, its wrapped block with it, and every
	// open read of one ends (QD-845).
	Keys []*EvsErasedKey
	// The documents an ERASE names, by index ref: masked whole until an erasure set this device holds lists them, their
	// journaled and local-layer entries gone at once.
	Documents []*SearchErasedDocuments
	// The erased documents' text as this device held it, read before it was deleted: their words leave the index ref's
	// vocabulary.
	Texts []*SearchErasedText
	// A CLOSURE's replaced index file versions (§11.14's erase row): each copy this cache holds goes at once, with its
	// derived data.
	Replaced []SearchCacheKey
	// A record log's ERASE: what this device holds of the log, from which the copies' entry documents, the run cards and
	// the again units come (DESIGN-DETAILS 15.2.10, 15.7's note). Nil for any other repo.
	Record *SearchEraseRecord
}

// Documents of one index ref.
type SearchErasedDocuments struct {
	// A file-mode ref, whose .ur-index/ holds its documents, or the repo's ur/index.
	RefId Id
	// Their doc keys (§11.14's key row), one a chunk.
	Keys [][indexIdByteCount]byte
}

// One erased document's text, as extraction gave it, of an index ref.
type SearchErasedText struct {
	RefId    Id
	Document *IndexDocument
}

// What a record log's ERASE reaches in the index, as the log's reader holds it (DESIGN-DETAILS 15.2.10, 15.7's note).
type SearchEraseRecord struct {
	// The log's ur/index ref, which indexes its streams' entry documents and run cards.
	IndexRefId Id
	// K_ref, which the log's doc keys derive from (indexRefKey).
	RefKey []byte
	Kind   protocol.RepoKind
	// The ERASE as the reader read it, and the log's entries and streams it holds.
	Erasure *RecordStreamErasure
	Entries []*RecordReadEntry
	Streams []*RecordReadStream
}

// One again unit {R, run_id, erasure_id} (DESIGN-DETAILS 15.2.9): a run of stream R whose card this device folds again
// once the erasure's CUT is below the epoch its builds name.
type SearchEraseAgain struct {
	// Stream R's ref.
	RefId     Id
	RunId     Id
	ErasureId Id
}

// The well-formed part of erase: ErrSearchCacheArgs for a hint of no repo or erasure, or naming nothing well formed.
func (self *SearchErase) check() error {
	if self.RepoId == (Id{}) || self.ErasureId == (Id{}) {
		return fmt.Errorf("%w: an erasure hint of no repo or erasure", ErrSearchCacheArgs)
	}
	for _, key := range self.Keys {
		if key == nil || key.SlotId == (Id{}) {
			return fmt.Errorf("%w: an erased key of no slot", ErrSearchCacheArgs)
		}
	}
	for _, documents := range self.Documents {
		if documents == nil || documents.RefId == (Id{}) {
			return fmt.Errorf("%w: erased documents of no index ref", ErrSearchCacheArgs)
		}
		if slices.Contains(documents.Keys, [indexIdByteCount]byte{}) {
			return fmt.Errorf("%w: an erased document of no doc key", ErrSearchCacheArgs)
		}
	}
	for _, text := range self.Texts {
		if text == nil || text.RefId == (Id{}) || text.Document == nil {
			return fmt.Errorf("%w: an erased text of no index ref or document", ErrSearchCacheArgs)
		}
	}
	for _, key := range self.Replaced {
		if key.RepoId != self.RepoId || key.check() != nil {
			return fmt.Errorf("%w: a replaced version of another repo", ErrSearchCacheArgs)
		}
	}
	if record := self.Record; record != nil && (record.IndexRefId == (Id{}) || len(record.RefKey) == 0 || record.Erasure == nil) {
		return fmt.Errorf("%w: a record log's erasure without its index ref, K_ref or ERASE", ErrSearchCacheArgs)
	}
	return nil
}

// Applies an ERASE's or a CLOSURE's hint at once (§5.9's delete row): the replaced versions and the records of the
// destroyed slot keys go with their derived data and reads, the repo's retained buckets go (DESIGN-DETAILS 7.2.7),
// the named documents are masked whole in search, their journaled and local-layer entries go and the sealed copies
// that held them are written again, and their words leave the vocabulary. A record log's ERASE adds its copies'
// entry documents and its run cards, and hands the journal its again units. The repo's open searches and remote
// cursors end first, and again before it answers. Every step runs whatever an earlier one answered, and the answer
// joins their errors: a caller tries again, since each step is idempotent.
func (self *SearchCache) ApplyErase(ctx context.Context, erase *SearchErase) error {
	if erase == nil {
		return fmt.Errorf("%w: no erasure hint", ErrSearchCacheArgs)
	}
	if err := erase.check(); err != nil {
		return err
	}
	repoId := erase.RepoId
	self.endRepo(repoId)
	defer self.endRepo(repoId)
	errs := []error{}

	documents := map[Id][][indexIdByteCount]byte{}
	refIds := []Id{}
	addDocuments := func(refId Id, keys [][indexIdByteCount]byte) {
		if _, ok := documents[refId]; !ok {
			refIds = append(refIds, refId)
		}
		for _, key := range keys {
			if !slices.Contains(documents[refId], key) {
				documents[refId] = append(documents[refId], key)
			}
		}
	}
	for _, named := range erase.Documents {
		addDocuments(named.RefId, named.Keys)
	}
	againUnits := []*SearchEraseAgain{}
	if record := erase.Record; record != nil {
		keys, err := indexRecordEraseMaskKeys(record.RefKey, record.Kind, record.Erasure, record.Entries, record.Streams)
		if err != nil {
			errs = append(errs, err)
		} else {
			addDocuments(record.IndexRefId, keys)
		}
		againUnits = searchEraseAgainUnits(record, erase.ErasureId)
	}

	// the cache's own files and masks: the linearization point
	if 0 < len(erase.Keys) {
		if _, err := self.DropErasedSlotKeys(repoId, erase.Keys); err != nil {
			errs = append(errs, err)
		}
	}
	for _, key := range erase.Replaced {
		if err := self.Remove(key); err != nil {
			errs = append(errs, err)
		}
	}
	if err := self.DropRetained(repoId); err != nil {
		errs = append(errs, err)
	}
	for _, refId := range refIds {
		if err := self.maskErased(repoId, refId, documents[refId]); err != nil {
			errs = append(errs, err)
		}
	}
	testHookBarrier("search.cache.erase.applied", repoId.String())

	// what the host holds beside the files
	allKeys := [][indexIdByteCount]byte{}
	for _, refId := range refIds {
		allKeys = append(allKeys, documents[refId]...)
	}
	if 0 < len(allKeys) {
		for _, journal := range self.deleteJournals(repoId) {
			if err := journal.ApplyErase(allKeys); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for _, refId := range refIds {
		errs = append(errs, self.eraseLayers(ctx, repoId, refId, func(layer *SearchLocalLayer) bool {
			erased := false
			for _, key := range documents[refId] {
				erased = layer.Erase(key, searchErasedAll) || erased
			}
			return erased
		}))
	}
	errs = append(errs, self.eraseWords(ctx, repoId, erase.Texts))
	if 0 < len(againUnits) {
		for _, hooks := range self.deleteHookList() {
			if hooks.Again != nil {
				if err := hooks.Again(ctx, repoId, againUnits); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}

// Takes from each local layer of an index ref what erase says, sealing again each layer it took something from.
func (self *SearchCache) eraseLayers(ctx context.Context, repoId Id, refId Id, erase func(layer *SearchLocalLayer) bool) error {
	errs := []error{}
	for _, held := range self.deleteLayers(repoId, refId) {
		if !erase(held.layer) {
			continue
		}
		errs = append(errs, self.resealDerived(held.key, SearchCachePartLocalLayer, func() error {
			return held.layer.Save(ctx, self, held.key)
		}))
	}
	return errors.Join(errs...)
}

// Uncounts each erased document's words in its index ref's vocabularies, from the text the caller read before it
// deleted it, sealing again each vocabulary that changed, so a word no other document holds leaves every kept copy.
func (self *SearchCache) eraseWords(ctx context.Context, repoId Id, texts []*SearchErasedText) error {
	errs := []error{}
	byRef := map[Id][]*IndexDocument{}
	refIds := []Id{}
	for _, text := range texts {
		if _, ok := byRef[text.RefId]; !ok {
			refIds = append(refIds, text.RefId)
		}
		byRef[text.RefId] = append(byRef[text.RefId], text.Document)
	}
	for _, refId := range refIds {
		for _, held := range self.deleteVocabularies(repoId, refId) {
			for _, document := range byRef[refId] {
				if err := held.vocabulary.RemoveDocument(held.normalizer, document); err != nil {
					errs = append(errs, err)
				}
			}
			errs = append(errs, self.resealDerived(held.key, SearchCachePartVocabulary, func() error {
				return held.vocabulary.Save(ctx, self, held.key)
			}))
		}
	}
	return errors.Join(errs...)
}

// The again units of a record log's ERASE (DESIGN-DETAILS 15.2.9): one {R, run_id, erasure_id} for each run of a source
// entry the ERASE names, by a copy's key row or its note's entry_id, in each stream R holding a copy of it, sorted. A
// log with no run cards gives none.
func searchEraseAgainUnits(record *SearchEraseRecord, erasureId Id) []*SearchEraseAgain {
	if !indexRunCardLog(record.Kind) {
		return nil
	}
	sources := indexRunCardSources(record.Kind)
	streamRefIds := map[Id]Id{}
	for _, stream := range record.Streams {
		streamRefIds[stream.StreamSidecarId] = stream.RefId
	}
	named := map[Id]bool{}
	if body, ok := recordErasureNoteBody(record.Erasure); ok {
		for _, entryId := range body.GetEntryIds() {
			if len(entryId) == len(Id{}) {
				named[Id(entryId)] = true
			}
		}
	}
	keys := map[RecordSlotKey]bool{}
	for _, key := range record.Erasure.Keys {
		if key != nil {
			keys[*key] = true
		}
	}
	units := map[[2]Id]bool{}
	for _, entry := range record.Entries {
		if entry == nil || entry.Header == nil || !slices.Contains(sources, entry.Kind()) {
			continue
		}
		hit := named[entry.EntryId]
		for _, entryCopy := range entry.Copies {
			hit = hit || keys[RecordSlotKey{SlotId: entryCopy.SlotId, KeyIndex: entryCopy.KeyIndex}]
		}
		runId := entry.Header.Header.GetRunId()
		if !hit || len(runId) != len(Id{}) {
			continue
		}
		for _, entryCopy := range entry.Copies {
			if refId := streamRefIds[entryCopy.StreamSidecarId]; refId != (Id{}) {
				units[[2]Id{refId, Id(runId)}] = true
			}
		}
	}
	ordered := make([]*SearchEraseAgain, 0, len(units))
	for unit := range units {
		ordered = append(ordered, &SearchEraseAgain{RefId: unit[0], RunId: unit[1], ErasureId: erasureId})
	}
	slices.SortFunc(ordered, func(a *SearchEraseAgain, b *SearchEraseAgain) int {
		if c := a.RefId.Cmp(b.RefId); c != 0 {
			return c
		}
		return a.RunId.Cmp(b.RunId)
	})
	return ordered
}

// Applies an erasure set at once (§5.9's delete row, §11.14's cut row): at a CUT's hint, or when the sync engine stages
// a set, every document it lists has its journaled and local-layer entries at or below its listed version dropped and
// those versions masked in search, until a swap brings the set into the version table; an ERASE's mask of a key the
// set lists gives way to the listing (DESIGN-DETAILS 15.2.10's masks), and a CUT's mask of a key a newer set no longer
// lists, its erasure complete, goes. The repo's open searches and remote cursors end first, and again before it
// answers. A CUT's eraser takes it as IndexEraser's applyCut: the signature is that seam's.
func (self *SearchCache) ApplyCut(ctx context.Context, repoId Id, refId Id, erasureSet *protocol.IndexErasureSet) error {
	if repoId == (Id{}) || refId == (Id{}) || erasureSet == nil {
		return fmt.Errorf("%w: a CUT of no repo, ref or set", ErrSearchCacheArgs)
	}
	self.endRepo(repoId)
	defer self.endRepo(repoId)
	errs := []error{}
	listed := indexErasureSetListed(erasureSet)
	if err := self.maskCut(repoId, refId, erasureSet); err != nil {
		errs = append(errs, err)
	}
	testHookBarrier("search.cache.cut.applied", repoId.String())
	erased := func(key [indexIdByteCount]byte, version uint64) bool {
		through, ok := listed[key]
		return ok && version <= through
	}
	if 0 < len(listed) {
		for _, journal := range self.deleteJournals(repoId) {
			if err := journal.ApplyCut(erased); err != nil {
				errs = append(errs, err)
			}
		}
	}
	errs = append(errs, self.eraseLayers(ctx, repoId, refId, func(layer *SearchLocalLayer) bool {
		erasedAny := false
		for key, through := range listed {
			erasedAny = layer.Erase(key, through) || erasedAny
		}
		return erasedAny
	}))
	return errors.Join(errs...)
}

// Deletes what this device holds of a repo it no longer reads (§5.9's delete row): with refId nil every file of the repo,
// as at a removal, a generation not wrapped to this sidecar, a revoked EvsShare or grant, the repo's deletion or its
// shredding, and the journal's units for it; with refId one index ref's files, as when its index is turned off. Derived
// data, masks and retained buckets go with the files, and the hooks forget what the host holds in memory. The repo's
// open searches and remote cursors end first, and again before it answers.
func (self *SearchCache) ApplyLostRead(ctx context.Context, repoId Id, refId *Id) error {
	if repoId == (Id{}) || (refId != nil && *refId == (Id{})) {
		return fmt.Errorf("%w: a lost read of no repo", ErrSearchCacheArgs)
	}
	self.endRepo(repoId)
	defer self.endRepo(repoId)
	errs := []error{}
	for _, hooks := range self.deleteHookList() {
		if hooks.Forget != nil {
			hooks.Forget(repoId, refId)
		}
	}
	if refId == nil {
		for _, journal := range self.deleteJournals(repoId) {
			if err := journal.removeListed(func(*indexJournalDocument) bool { return true }); err != nil {
				errs = append(errs, err)
			}
		}
		if err := self.DropRepo(repoId); err != nil {
			errs = append(errs, err)
		}
	} else if err := self.DropRef(repoId, *refId); err != nil {
		errs = append(errs, err)
	}
	testHookBarrier("search.cache.lost.applied", repoId.String())
	return errors.Join(errs...)
}

// The order masks keep: by key.
func compareSearchCacheErased(a SearchCacheErased, b SearchCacheErased) int {
	return bytes.Compare(a.Key[:], b.Key[:])
}

// The mask of key in ref, sorted by key, and where it is or would go.
func searchErasedIndex(ref *SearchCacheRef, key [indexIdByteCount]byte) (int, bool) {
	return slices.BinarySearchFunc(ref.Erased, SearchCacheErased{Key: key}, compareSearchCacheErased)
}

// Inserts mask at index, or overflows the ref where that would pass the bound. Called with the state lock held.
func (self *SearchCache) insertErasedWithLock(ref *SearchCacheRef, index int, mask SearchCacheErased) {
	if self.settings.EraseMaskCount <= len(ref.Erased) {
		ref.ErasedOverflow = true
		return
	}
	ref.Erased = slices.Insert(ref.Erased, index, mask)
}

// Masks keys of an index ref whole for an ERASE: each gains an ERASE's mask unless a CUT this device applied lists it
// already, whose listing wins (DESIGN-DETAILS 15.2.10).
func (self *SearchCache) maskErased(repoId Id, refId Id, keys [][indexIdByteCount]byte) error {
	if len(keys) == 0 {
		return nil
	}
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	ref, err := self.loadRefWithLock(repoId, refId)
	if err != nil {
		return err
	}
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		changed := false
		for _, key := range keys {
			index, found := searchErasedIndex(ref, key)
			switch {
			case !found:
				overflowed, maskCount := ref.ErasedOverflow, len(ref.Erased)
				self.insertErasedWithLock(ref, index, SearchCacheErased{Key: key, Erase: true})
				changed = changed || overflowed != ref.ErasedOverflow || maskCount != len(ref.Erased)
			case ref.Erased[index].Through == 0 && !ref.Erased[index].Erase:
				ref.Erased[index].Erase = true
				changed = true
			}
		}
		return changed
	}()
	if !changed {
		return nil
	}
	return self.storeRefWithLock(ref)
}

// One document an erasure set lists: the highest version it is listed at, and the highest epoch of the erasures that
// list it.
type searchCutListing struct {
	through uint64
	epoch   uint64
}

// Masks what erasureSet lists in an index ref: each key at or below its listed version, an ERASE's mask of it giving
// way; and lifts the CUT's mask of a key the set no longer lists where the set dropped the erasure that listed it, a
// set whose listed_since passed that erasure's epoch, so a set older than the mask lifts nothing.
func (self *SearchCache) maskCut(repoId Id, refId Id, erasureSet *protocol.IndexErasureSet) error {
	listings := map[[indexIdByteCount]byte]searchCutListing{}
	for _, erasure := range erasureSet.GetErasures() {
		for _, erased := range erasure.GetDocs() {
			if len(erased.GetDocKey()) != indexIdByteCount || erased.GetVersion() == 0 {
				continue
			}
			key := [indexIdByteCount]byte(erased.GetDocKey())
			listing := listings[key]
			listing.through = max(listing.through, erased.GetVersion())
			listing.epoch = max(listing.epoch, erasure.GetEpoch())
			listings[key] = listing
		}
	}
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	ref, err := self.loadRefWithLock(repoId, refId)
	if err != nil {
		return err
	}
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		before := slices.Clone(ref.Erased)
		overflowed := ref.ErasedOverflow
		kept := make([]SearchCacheErased, 0, len(ref.Erased))
		for _, mask := range ref.Erased {
			if listing, ok := listings[mask.Key]; ok {
				mask.Erase = false
				mask.Through = max(mask.Through, listing.through)
				mask.Epoch = max(mask.Epoch, listing.epoch)
				delete(listings, mask.Key)
			} else if 0 < mask.Through && mask.Epoch < erasureSet.GetListedSince() {
				mask.Through, mask.Epoch = 0, 0
			}
			if mask.Erase || 0 < mask.Through {
				kept = append(kept, mask)
			}
		}
		ref.Erased = kept
		added := make([]SearchCacheErased, 0, len(listings))
		for key, listing := range listings {
			added = append(added, SearchCacheErased{Key: key, Through: listing.through, Epoch: listing.epoch})
		}
		slices.SortFunc(added, compareSearchCacheErased)
		for _, mask := range added {
			index, _ := searchErasedIndex(ref, mask.Key)
			self.insertErasedWithLock(ref, index, mask)
		}
		return overflowed != ref.ErasedOverflow || !slices.Equal(before, ref.Erased)
	}()
	if !changed {
		return nil
	}
	return self.storeRefWithLock(ref)
}

// The cache's own erasure mask of key in an index ref, which a probe of the ref's version table joins to its runs; the
// zero mask for none. ErrSearchCacheMasksOverflow for a ref whose masks overflowed, which masks every candidate.
func (self *SearchCache) erasedMask(repoId Id, refId Id, key [indexIdByteCount]byte) (SearchCacheErased, error) {
	ref, ok := func() (*SearchCacheRef, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ref, ok := self.refs[[2]Id{repoId, refId}]
		return ref, ok
	}()
	if !ok {
		var err error
		ref, err = func() (*SearchCacheRef, error) {
			self.operationLock.Lock()
			defer self.operationLock.Unlock()
			return self.loadRefWithLock(repoId, refId)
		}()
		if err != nil {
			return SearchCacheErased{}, err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if ref.ErasedOverflow {
		return SearchCacheErased{}, ErrSearchCacheMasksOverflow
	}
	if index, found := searchErasedIndex(ref, key); found {
		return ref.Erased[index], nil
	}
	return SearchCacheErased{}, nil
}

// SidecarErasure's states (§5.4's erasure event, §11.12's reconcile row, §18.5).
const (
	// Its CUTs committed, its documents masked and unpublishable, its own keys gone with the first ERASE.
	SidecarErasureFenced    = "fenced"
	SidecarErasureRewriting = "rewriting"
	// A 429 for its allowance or turn, or room for its CUT in a ref's full erasure set.
	SidecarErasureWaiting = "waiting"
	// Every key destroyed.
	SidecarErasureDone = "done"
	// No device that may finish it is running.
	SidecarErasureStalled = "stalled"
)

// The erasure event of an erasure in repoId (§5.4, §18.5): ErrSearchCacheArgs for one of no repo or erasure, or of a
// state §5.4 does not name.
func newSidecarErasureEvent(repoId Id, erasure *SidecarErasure) (SidecarEvent, error) {
	if repoId == (Id{}) || erasure == nil || erasure.ErasureId == (Id{}) {
		return SidecarEvent{}, fmt.Errorf("%w: an erasure event of no repo or erasure", ErrSearchCacheArgs)
	}
	switch erasure.State {
	case SidecarErasureFenced, SidecarErasureRewriting, SidecarErasureWaiting, SidecarErasureDone, SidecarErasureStalled:
	default:
		return SidecarEvent{}, fmt.Errorf("%w: an erasure state %q", ErrSearchCacheArgs, erasure.State)
	}
	copied := *erasure
	return SidecarEvent{Kind: SidecarEventErasure, RepoId: &repoId, Erasure: &copied}, nil
}

// Raises the erasure event of an erasure in repoId that this device runs or may finish, as its state changed.
func (self *Sidecar) raiseErasure(repoId Id, erasure *SidecarErasure) error {
	event, err := newSidecarErasureEvent(repoId, erasure)
	if err != nil {
		return err
	}
	self.emitEvent(event)
	return nil
}

// Raises the erasure event through the client's sink, for evs's erasers, which hold the client and not its Sidecar.
func (self *EvsClient) raiseErasure(repoId Id, erasure *SidecarErasure) error {
	event, err := newSidecarErasureEvent(repoId, erasure)
	if err != nil {
		return err
	}
	self.emit(event)
	return nil
}
