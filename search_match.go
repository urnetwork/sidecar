//go:build !ios_extension

// Matching (§11.14's plan and reads rows; R-EVS-14; D-EVS-44; owner decision 584; FS-107; SEARCH-M10-23 and
// SEARCH-M10-45): one partition's candidates for a query. Per shard the query's trigrams are looked up rarest first, a
// term with an absent trigram matching nothing there and a group none of whose terms is present ending that shard;
// only the query's lists are decoded, read through the shard's frames, and intersected rarest first
// (search_intersect.go). Heads, sealed slots and unabsorbed large entries are scanned per document, a full entry's key
// set holding every trigram of a term in each group. Every entry is full or a tombstone, so each is matched as it
// stands and nothing resolves through another file; a file holding an entry of the reserved kind 2 never decodes, so
// it reaches no partition (its sync lists it bad, index_malformed naming its signer). A slot or large entry at or
// below its writer's watermark is not scanned: what it held is in the shards.
//
// A candidate is where a document's row sits and its n_d, nothing more: masking, confirmation and ranking read its row
// lazily in rank order (SEARCH-M10-24), so a partition's candidates cost a few words each, and past
// Search.TooBroadCandidateCount the partition answers too_broad with its count. A query never fetches: the partition
// holds what this device has.

package sidecar

import (
	"cmp"
	"slices"
)

// One shard of a partition, as the device holds it.
type searchShardSource struct {
	n      uint32
	reader *indexShardReader
}

// One slot or large entry of a bucket partition, as the device holds it.
type searchSlotSource struct {
	slot   *indexSlot
	writer Id
	seq    uint32
	// A slot or large entry at or below its writer's watermark, other than its head: what it held is in the shards, so
	// it holds no candidate.
	absorbed bool
	// Its file's path and its version's signer, which an alarm names.
	path   string
	signer Id
}

// One partition's files.
type searchPartitionSource struct {
	partition searchPartitionKind
	shards    []*searchShardSource
	// Bucket partitions: every writer's slots, heads included, and large entries.
	slots []*searchSlotSource
}

// A document a partition offers a query.
type searchCandidate struct {
	// A shard row: its shard and docid.
	shard *searchShardSource
	docId uint32
	// A slot's or large entry's full entry.
	slot  *searchSlotSource
	entry *indexEntry
	// n_d, the document's trigram count.
	trigramCount int
}

// One partition's answer to a query.
type searchPartitionResult struct {
	candidates []*searchCandidate
	// Every candidate the partition gave, kept or not.
	candidateCount int
	// Past the cap: the partition answers too_broad with candidateCount.
	tooBroad bool
	// The lists decoded, which a query's trigrams bound (§16.10's targets count postings).
	listCount int
}

// What one partition's match reads.
type searchMatchArgs struct {
	query  *SearchQuery
	source *searchPartitionSource
	// Search.TooBroadCandidateCount.
	maxCandidateCount int
}

// The partition's candidates for the query. An empty query offers every document, for filters to list; one of
// excluded terms alone offers none.
func searchMatch(args *searchMatchArgs) (*searchPartitionResult, error) {
	result := &searchPartitionResult{}
	query := args.query
	if query.matchesNothing() {
		return result, nil
	}
	add := func(candidate *searchCandidate) {
		result.candidateCount += 1
		if args.maxCandidateCount < result.candidateCount {
			result.tooBroad = true
			return
		}
		result.candidates = append(result.candidates, candidate)
	}

	for _, shard := range args.source.shards {
		docIds, err := searchMatchShard(query, shard.reader, result)
		if err != nil {
			return nil, err
		}
		for _, docId := range docIds {
			add(&searchCandidate{shard: shard, docId: docId, trigramCount: int(shard.reader.layout.trigramCounts[docId])})
		}
	}

	for _, slot := range args.source.slots {
		if slot.absorbed {
			continue
		}
		for _, entry := range slot.slot.entries {
			if entry.kind == indexEntryFull && (query.Empty() || searchQueryHoldsKeys(query, entry.keys)) {
				add(&searchCandidate{slot: slot, entry: entry, trigramCount: len(entry.keys)})
			}
		}
	}
	return result, nil
}

// Whether a key set holds a term of every group.
func searchQueryHoldsKeys(query *SearchQuery, keys indexKeySet) bool {
	for _, group := range query.Groups {
		if !slices.ContainsFunc(group, func(term *SearchTerm) bool {
			return !slices.ContainsFunc(term.trigrams, func(key uint32) bool {
				_, found := slices.BinarySearch(keys, key)
				return !found
			})
		}) {
			return false
		}
	}
	return true
}

// One shard's docids holding the query: each trigram looked up once, rarest first within a term, a term with an absent
// trigram matching nothing, and a group none of whose terms is present ending the shard. An empty query offers every
// document.
func searchMatchShard(query *SearchQuery, reader *indexShardReader, result *searchPartitionResult) ([]uint32, error) {
	documentCount := reader.documentCount()
	if query.Empty() {
		docIds := make([]uint32, documentCount)
		for index := range docIds {
			docIds[index] = uint32(index)
		}
		return docIds, nil
	}
	type lookedUp struct {
		location indexKeyLocation
		found    bool
		list     *indexPostingList
	}
	lookups := map[uint32]*lookedUp{}
	lookup := func(key uint32) (*lookedUp, error) {
		if found, ok := lookups[key]; ok {
			return found, nil
		}
		location, found, err := reader.lookup(key)
		if err != nil {
			return nil, err
		}
		lookups[key] = &lookedUp{location: location, found: found}
		return lookups[key], nil
	}
	list := func(entry *lookedUp) (*indexPostingList, error) {
		if entry.list == nil {
			decoded, err := reader.list(entry.location)
			if err != nil {
				return nil, err
			}
			entry.list = decoded
			result.listCount += 1
		}
		return entry.list, nil
	}

	// Each term's trigrams looked up, so a term with an absent one drops out before any list is read.
	type termPlan struct {
		entries []*lookedUp
		rarest  uint64
	}
	groups := [][]*termPlan{}
	for _, group := range query.Groups {
		terms := []*termPlan{}
		for _, term := range group {
			plan := &termPlan{}
			present := true
			for _, key := range term.trigrams {
				entry, err := lookup(key)
				if err != nil {
					return nil, err
				}
				if !entry.found {
					present = false
					break
				}
				plan.entries = append(plan.entries, entry)
			}
			if !present {
				continue
			}
			slices.SortFunc(plan.entries, func(a *lookedUp, b *lookedUp) int {
				return cmp.Compare(a.location.key.documentCount, b.location.key.documentCount)
			})
			plan.rarest = plan.entries[0].location.key.documentCount
			terms = append(terms, plan)
		}
		if len(terms) == 0 {
			return nil, nil
		}
		groups = append(groups, terms)
	}
	// The group whose likeliest term is rarest goes first, so the candidate set starts small.
	slices.SortStableFunc(groups, func(a []*termPlan, b []*termPlan) int {
		largest := func(terms []*termPlan) uint64 {
			total := uint64(0)
			for _, term := range terms {
				total += term.rarest
			}
			return total
		}
		return cmp.Compare(largest(a), largest(b))
	})

	var candidates *searchDocSet
	for _, terms := range groups {
		var groupSet *searchDocSet
		for _, term := range terms {
			var termSet *searchDocSet
			if candidates != nil {
				termSet = &searchDocSet{documentCount: documentCount, docIds: slices.Clone(candidates.all())}
			}
			for _, entry := range term.entries {
				decoded, err := list(entry)
				if err != nil {
					return nil, err
				}
				if termSet == nil {
					termSet = searchDocSetOf(decoded, documentCount)
				} else {
					termSet.intersect(decoded)
				}
				if termSet.count() == 0 {
					break
				}
			}
			if groupSet == nil {
				groupSet = termSet
			} else {
				groupSet.union(termSet)
			}
		}
		if candidates == nil {
			candidates = groupSet
		} else {
			candidates.intersectSet(groupSet)
		}
		if candidates.count() == 0 {
			return nil, nil
		}
	}
	return candidates.all(), nil
}
