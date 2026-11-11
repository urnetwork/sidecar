//go:build !ios_extension

// Diff chains on the read side (§11.14's chains row as DESIGN-DETAILS 1.2.9 rewrites it; FS-107; SEARCH-M10-23 and
// SEARCH-M10-45). A diff resolves in one step, by its doc_key and base version, from the full entry in another file of
// its own writer in its bucket, a slot that is not the head, absorbed or not, or a large entry; of two, the one in the
// file with the higher seq. No diff rests on a diff, on a head or on a shard, so nothing is composed. An unabsorbed
// diff whose base no such file holds, or whose composed set's size is not its row's trigram count, breaks the format:
// its signer is alarmed index_malformed, and the document reads not yet searchable, never no match, until a host with
// the text re-enters it. Under I1 an honest writer's slot is never in that state. A query never fetches.

package sidecar

import (
	"slices"
)

// What a bucket's diffs resolve in: each writer's files that are not its head, slots and large entries, absorbed or
// not.
type searchChainSources struct {
	writerFiles map[Id][]*searchSlotSource
}

// The sources of one bucket, from its slots and large entries as the device holds them.
func searchNewChainSources(slots []*searchSlotSource) *searchChainSources {
	sources := &searchChainSources{writerFiles: map[Id][]*searchSlotSource{}}
	for _, slot := range slots {
		if !slot.head {
			sources.writerFiles[slot.writer] = append(sources.writerFiles[slot.writer], slot)
		}
	}
	return sources
}

// A diff resolved: its base's key set and the composed set.
type searchResolvedChain struct {
	baseKeys indexKeySet
	delta    indexDelta
	// The composed set.
	keys indexKeySet
}

// The composed set's size.
func (self *searchResolvedChain) trigramCount() int {
	return len(self.keys)
}

// Whether the composed set holds key.
func (self *searchResolvedChain) holds(key uint32) (bool, error) {
	_, found := slices.BinarySearch(self.keys, key)
	return found, nil
}

// Resolves diff, which slot holds, in one step from its writer's other files in sources, or answers why it breaks the
// format.
func searchResolveChain(sources *searchChainSources, slot *searchSlotSource, diff *indexEntry) (*searchResolvedChain, error) {
	if diff.kind != indexEntryDiff {
		return nil, indexMalformed("a chain from no diff")
	}
	var baseFile *searchSlotSource
	var base *indexEntry
	for _, file := range sources.writerFiles[slot.writer] {
		if file == slot {
			continue
		}
		for _, entry := range file.slot.entries {
			if entry.key == diff.key && entry.version == diff.baseVersion && entry.kind == indexEntryFull && (baseFile == nil || baseFile.seq < file.seq) {
				baseFile, base = file, entry
			}
		}
	}
	if base == nil {
		return nil, indexMalformed("a diff whose base no file of its writer holds")
	}
	keys, err := diff.delta.applyTo(base.keys)
	if err != nil {
		return nil, err
	}
	if uint64(len(keys)) != diff.row.trigramCount {
		return nil, indexMalformed("a composed set whose size is not its row's trigram count")
	}
	return &searchResolvedChain{baseKeys: base.keys, delta: diff.delta, keys: keys}, nil
}
