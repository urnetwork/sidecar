// Diff chains on the read side (§11.14's chains row; FS-107; SEARCH-M10-23). A diff resolves by its doc_key and base
// version in its bucket's shards, sealed slots and large entries, never a head, the base's chain likewise; copies of
// one version are one, and a self-contained copy answers first. A current diff whose chain does not resolve, runs past
// 15 diffs, or whose composed set's size is not its row's trigram count breaks the format: its signer is alarmed
// index_malformed, and the document reads not yet searchable, never no match. A query never fetches, so a base this
// device lacks is a coverage gap, not a read.
//
// A reader composes the chain's deltas and keeps the base where it lies: a slot's or large entry's key set, applied
// exactly, or a shard row, whose keys a query's trigram is tested against through the shard's own lists, so no shard is
// inverted to answer one document. Against a shard base the composed size is the row's count less what the chain
// removed plus what it added; the delta's fit to the base is checked by hosts that hold the text (§11.14's coverage
// row), not here.

package sidecar

import (
	"bytes"
	"cmp"
	"slices"
	"sort"
)

// What a bucket's diffs resolve in: its shards and the entries of its sealed slots and large entries.
type searchChainSources struct {
	shards []*indexShardReader
	// Each key's entries of sealed slots and large entries, absorbed or not, never a head's.
	entries map[[indexIdByteCount]byte][]*indexEntry
}

// The sources of one bucket.
func searchNewChainSources(shards []*indexShardReader, sealed []*indexSlot) *searchChainSources {
	sources := &searchChainSources{shards: shards, entries: map[[indexIdByteCount]byte][]*indexEntry{}}
	for _, slot := range sealed {
		for _, entry := range slot.entries {
			if entry.kind == indexEntryFull || entry.kind == indexEntryDiff {
				sources.entries[entry.key] = append(sources.entries[entry.key], entry)
			}
		}
	}
	return sources
}

// A diff resolved: its deltas composed over a self-contained base.
type searchResolvedChain struct {
	// A base in a slot or large entry: its key set.
	baseKeys indexKeySet
	// A base in a shard: the shard, its docid there and its row's trigram count.
	baseShard        *indexShardReader
	baseDocId        uint32
	baseTrigramCount int
	// The base's set less removed plus added is the diff's.
	delta     indexDelta
	diffCount int
	// The composed set, where the base's keys are at hand.
	keys indexKeySet
}

// The composed set's size.
func (self *searchResolvedChain) trigramCount() int {
	if self.baseShard == nil {
		return len(self.keys)
	}
	return self.baseTrigramCount - len(self.delta.removed) + len(self.delta.added)
}

// Whether the composed set holds key: in what the chain added, else in the base and not removed.
func (self *searchResolvedChain) holds(key uint32) (bool, error) {
	if self.baseShard == nil {
		_, found := slices.BinarySearch(self.keys, key)
		return found, nil
	}
	if _, added := slices.BinarySearch(self.delta.added, key); added {
		return true, nil
	}
	if _, removed := slices.BinarySearch(self.delta.removed, key); removed {
		return false, nil
	}
	location, found, err := self.baseShard.lookup(key)
	if err != nil || !found {
		return false, err
	}
	list, err := self.baseShard.list(location)
	if err != nil {
		return false, err
	}
	return list.contains(self.baseDocId), nil
}

// Finds docKey's row in a shard by binary search over its doc table, which is in doc_key order: its docid and version,
// or false.
func searchShardFind(reader *indexShardReader, docKey [indexIdByteCount]byte) (uint32, uint64, bool, error) {
	var findErr error
	count := reader.documentCount()
	docId := sort.Search(count, func(index int) bool {
		if findErr != nil {
			return true
		}
		document, err := reader.document(uint32(index))
		if err != nil {
			findErr = err
			return true
		}
		return 0 <= bytes.Compare(document.key[:], docKey[:])
	})
	if findErr != nil || count <= docId {
		return 0, 0, false, findErr
	}
	document, err := reader.document(uint32(docId))
	if err != nil || document.key != docKey {
		return 0, 0, false, err
	}
	return uint32(docId), document.version, true, nil
}

// Visits the shard's tombstone table in order, which opening the shard checked.
func (self *indexShardReader) walkTombstones(visit func(tombstone *indexShardTombstone)) error {
	position := self.layout.tombstonesStart
	for range self.layout.header.Tombstones {
		window, err := self.window(position, self.layout.dictionaryStart, indexTombstoneMaxByteCount)
		if err != nil {
			return err
		}
		decoder := indexDecoder{src: window}
		tombstone := decoder.tombstone(self.companion)
		if decoder.err != nil {
			return decoder.err
		}
		visit(tombstone)
		position += len(window) - decoder.remaining()
	}
	return nil
}

// Resolves diff in sources, or answers why it breaks the format.
func searchResolveChain(sources *searchChainSources, diff *indexEntry) (*searchResolvedChain, error) {
	if diff.kind != indexEntryDiff {
		return nil, indexMalformed("a chain from no diff")
	}
	deltas := []indexDelta{diff.delta}
	version := diff.baseVersion
	resolved := &searchResolvedChain{}
	for {
		if indexChainMaxDiffCount < len(deltas) {
			return nil, indexMalformed("a chain past 15 diffs")
		}
		copies := slices.Clone(sources.entries[diff.key])
		slices.SortStableFunc(copies, func(a *indexEntry, b *indexEntry) int {
			return cmp.Compare(a.kind, b.kind)
		})
		var next *indexEntry
		found := false
		for _, entry := range copies {
			if entry.version != version {
				continue
			}
			if entry.kind == indexEntryFull {
				resolved.baseKeys = entry.keys
				found = true
				break
			}
			if next == nil {
				next = entry
			}
		}
		if !found {
			for _, shard := range sources.shards {
				docId, shardVersion, ok, err := searchShardFind(shard, diff.key)
				if err != nil {
					return nil, err
				}
				if ok && shardVersion == version {
					resolved.baseShard, resolved.baseDocId = shard, docId
					resolved.baseTrigramCount = int(shard.layout.trigramCounts[docId])
					found = true
					break
				}
			}
		}
		if found {
			break
		}
		if next == nil {
			return nil, indexMalformed("a base no file holds")
		}
		deltas = append(deltas, next.delta)
		version = next.baseVersion
	}

	// Composed from the base up: the oldest diff first.
	composed := indexDelta{added: indexKeySet{}, removed: indexKeySet{}}
	for _, delta := range slices.Backward(deltas) {
		var err error
		if composed, err = indexComposeDelta(composed, delta); err != nil {
			return nil, err
		}
	}
	resolved.delta = composed
	resolved.diffCount = len(deltas)
	if resolved.baseShard == nil {
		keys, err := composed.applyTo(resolved.baseKeys)
		if err != nil {
			return nil, err
		}
		resolved.keys = keys
	}
	if resolved.trigramCount() < 0 || uint64(resolved.trigramCount()) != diff.row.trigramCount {
		return nil, indexMalformed("a composed set whose size is not its row's trigram count")
	}
	return resolved, nil
}
