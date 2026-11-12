//go:build !ios_extension

// Ranking (§11.14's rank and confirm rows; §16.10's rank, phase and pages rows; D-EVS-54; FI-18; SEARCH-M10-24): the
// order a phase's hits are given in, and the lazy walk that masks and checks candidates only as far as a page needs.
//
// A phase's candidates, from every partition it reads in every repo of the search, have their key, version and time
// read ahead (a shard row's from its doc table entry, a few bytes, a slot entry's as it stands), the time filters
// applied, and are walked newest first. Each walked candidate is masked through its repo's version table, then checked
// as far as this host can (search_confirm.go), so masking and confirmation run lazily in rank order, and a search's
// mask state is its pending candidates (FS-109). Within a phase the tiers are: 1 matches, verified and confirmed,
// newest first, or by path (header matches first) or by term density where the caller asks; 2 possible matches by
// trigram overlap J = |T(q)| / n_d, fewest distinct trigrams first, ties newest first; 3 near hits by J against the
// corrected query. Matches stream as the walk finds them, since every later one is older; possible matches wait for
// the walk to end, since any candidate may be one; near hits wait for the caller to settle them (search_typo.go).
// The walk stops once a page's worth is found (ConfirmPageHitCount, 50) or the page has checked
// Search.PageCandidateCount candidates, and the counts read "about n" while candidates remain unchecked.
//
// A partition past Search.TooBroadCandidateCount answers too_broad (search_match.go): its kept candidates are
// confirmed from their rows alone, header-confirmed hits are given and the rest only counted (§11.14's newest row).
// Phases follow one another, phase 1 before phase 2, so a returned page is never revised: every phase-2 hit is older
// than every phase-1 hit, and a document given in one phase is not given again.

package sidecar

import (
	"cmp"
	"context"
	"fmt"
	"slices"
)

// What ranking, confirmation, near hits, the local layer and the no-index scan hold to (QD-702). Wire caps shared with
// remote search take their defaults from SearchWireSettings, so each default stays in one place.
type SearchResultSettings struct {
	// A page's hits where the caller names no count: a walk checks candidates only until a page is full, so a page
	// waits on no more verification than it holds: 50 (§11.14's confirm row). Positive.
	ConfirmPageHitCount int
	// A hit's snippet around its first match: SearchWireSettings.SnippetMaxByteCount's 200 B (§16.10's result row;
	// DESIGN-DETAILS 11.2.9's Z4). At least 8, so a window holds a code point.
	SnippetMaxByteCount int
	// The original text a snippet's search normalizes a block at a time before it narrows to a window: 4 KiB, so a
	// 1 MiB body is normalized about twice. Past twice SnippetMaxByteCount.
	SnippetBlockByteCount int
	// A term with fewer exact hits than this is expanded to near hits: 3 (§11.14's typos row). Positive.
	NearHitExactCount int
	// A local vocabulary word is a near hit of a term at this trigram similarity or above: 0.3 (§11.14's typos row).
	// Within (0, 1].
	NearHitSimilarity float64
	// One-edit variants a phone tests a term: 4,096, past the ~1,100 of a 20-letter Latin word, so work stays bounded
	// on any script's alphabet. Positive.
	NearHitVariantMaxCount int
	// Runes of one script a phone's variants range over beyond the script's base letters: those of the term and the
	// display vocabulary, at most 256 (search_typo.go). Positive.
	NearHitAlphabetMaxCount int
	// A word longer than this, in normalized bytes, is kept in no vocabulary: 64 B, past any word a person types with
	// a typo, which keeps hashes, keys and URLs out. Positive.
	VocabularyWordMaxByteCount int
	// The local layer's entries in memory, past which a version is left uncovered and reported not yet searchable:
	// 32 MiB, a desktop's working set (§16.10's memory row) beside the 64 MiB of decoded index. Positive.
	LocalLayerByteCount int64
	// Documents a no-index scan reads a call before it returns a page with its position: 10,000, a few seconds of
	// linear verification on a desktop (§11.14's off row). Positive.
	ScanDocumentCount int
}

// The values the rows above give, the only source of their defaults but the wire's. A fresh value each call, sharing
// nothing mutable with any other.
func DefaultSearchResultSettings() *SearchResultSettings {
	return &SearchResultSettings{
		ConfirmPageHitCount:        50,
		SnippetMaxByteCount:        DefaultSearchWireSettings().SnippetMaxByteCount,
		SnippetBlockByteCount:      4 * 1024,
		NearHitExactCount:          3,
		NearHitSimilarity:          0.3,
		NearHitVariantMaxCount:     4096,
		NearHitAlphabetMaxCount:    256,
		VocabularyWordMaxByteCount: 64,
		LocalLayerByteCount:        32 * 1024 * 1024,
		ScanDocumentCount:          10000,
	}
}

// Refuses values no search can run on.
func (self *SearchResultSettings) check() error {
	switch {
	case self == nil:
		return fmt.Errorf("%w: no search result settings", errInvalidSettings)
	case self.ConfirmPageHitCount <= 0 || self.NearHitExactCount <= 0 || self.NearHitVariantMaxCount <= 0 ||
		self.NearHitAlphabetMaxCount <= 0 || self.VocabularyWordMaxByteCount <= 0 || self.LocalLayerByteCount <= 0 ||
		self.ScanDocumentCount <= 0:
		return fmt.Errorf("%w: search result counts are positive", errInvalidSettings)
	case self.SnippetMaxByteCount < 8 || self.SnippetBlockByteCount <= 2*self.SnippetMaxByteCount:
		return fmt.Errorf("%w: a snippet holds a code point and its block twice a snippet", errInvalidSettings)
	case !(0 < self.NearHitSimilarity && self.NearHitSimilarity <= 1):
		return fmt.Errorf("%w: a similarity threshold within (0, 1]", errInvalidSettings)
	}
	return nil
}

// The local layer's partition (§16.10's hit partition local): versions this host indexed from its own text past what
// the index covers (search_local_layer.go), searched in phase 1 beside the buckets.
const searchPartitionLocal = searchPartitionAll + 1

// Where a ranked candidate came from: one (repo, index root) of the search, with what masks and checks its rows.
type searchRankSource struct {
	repoId Id
	// The ref an in-ref index serves, whose every row it is; ur/index's rows name their own.
	refId     Id
	companion bool
	mask      *searchMask
	confirmer *searchConfirmer
}

// One partition's candidates, as SEARCH-M10-23's match gave them.
type searchRankInput struct {
	source    *searchRankSource
	partition searchPartitionKind
	// The plan step's place in the search's order, which breaks ties between partitions.
	step   int
	result *searchPartitionResult
}

// One candidate as ranking holds it until it is checked: where its row is, and its key, version and time, read ahead
// so the walk runs newest first. A few words each, so a phase's 20,000 a partition stay cheap.
type searchRankCandidate struct {
	source      *searchRankSource
	candidate   *searchCandidate
	key         [indexIdByteCount]byte
	version     uint64
	timeSeconds uint64
	step        int
	partition   searchPartitionKind
	headerOnly  bool
}

// The candidate's row: a shard row read from its doc table, or a slot entry's.
func (self *searchRankCandidate) row() (*indexRow, error) {
	if self.candidate.entry != nil {
		return self.candidate.entry.row, nil
	}
	document, err := self.candidate.shard.reader.document(self.candidate.docId)
	if err != nil {
		return nil, err
	}
	return document.row, nil
}

// A shard row's key, version and time, read from the start of its doc table entry without its row.
func searchShardHeader(reader *indexShardReader, docId uint32) ([indexIdByteCount]byte, uint64, uint64, error) {
	if len(reader.layout.documentStarts) <= int(docId) {
		return [indexIdByteCount]byte{}, 0, 0, indexMalformed("a docid out of range")
	}
	window, err := reader.window(int(reader.layout.documentStarts[docId]), reader.layout.tombstonesStart, indexIdByteCount+2*indexVByteMaxByteCount)
	if err != nil {
		return [indexIdByteCount]byte{}, 0, 0, err
	}
	decoder := indexDecoder{src: window}
	taken := decoder.take(indexIdByteCount)
	version := decoder.vbyte()
	timeSeconds := decoder.vbyte()
	if decoder.err != nil {
		return [indexIdByteCount]byte{}, 0, 0, decoder.err
	}
	return [indexIdByteCount]byte(taken), version, timeSeconds, nil
}

// The order tier 1 is given in.
type searchRankOrder int

const (
	// Newest first, the default.
	searchRankByTime searchRankOrder = iota + 1
	// File repos: matches in a header field or the path first, then by path (§16.10's sort path).
	searchRankByPath
	// Hosts with the text: by the query's matches a KiB of text (§11.14's rank row).
	searchRankByDensity
)

// One hit, which SEARCH-M10-26 maps onto §5.4's SearchHit.
type searchRankedHit struct {
	repoId      Id
	refId       Id
	key         [indexIdByteCount]byte
	version     uint64
	timeSeconds uint64
	partition   searchPartitionKind
	phase       int
	row         *indexRow
	// Verified, confirmed or possible; a near hit's state is that of its check against the corrected query.
	match      searchMatchState
	near       bool
	correction string
	snippet    string
	// J = |T(q)| / n_d against the query, or for a near hit the corrected one.
	overlap      float64
	trigramCount int
	inHeader     bool
	density      float64
	// Found by a scan of a ref with no index (search_no_index.go): no doc key, no partition, and "index off".
	scanned bool
}

// §16.10's counts for a phase so far.
type searchRankCounts struct {
	// Candidates the phase holds, those past the time filters among them.
	candidates int
	filtered   int
	// Checked and given or held: matches (verified and confirmed), possible, near.
	matches  int
	possible int
	near     int
	// Masked by newest-wins, a tombstone, an erasure or searchable_days (§16.10's masked).
	masked int
	// False candidates, by text or by a scoped field.
	rejected int
	// Not yet searchable: a table that does not cover a candidate, or a diff whose chain broke the format.
	unsearchable int
	// Left unchecked, so the count reads "about n".
	pending int
	// A partition answered too_broad; its candidates past the cap are counted here, not held.
	tooBroad          bool
	tooBroadUncounted int
}

// One page of a phase.
type searchRankPage struct {
	hits []*searchRankedHit
	// Every exact candidate is checked, so tier 2 is whole and the caller may settle near hits.
	exactDone bool
	// The phase has given everything: the next page begins the next phase.
	phaseDone bool
	counts    searchRankCounts
}

// Ranks one search's hits phase by phase. Not safe for concurrent use: one search walks it.
type searchRanker struct {
	settings *SearchResultSettings
	// Search.PageCandidateCount: candidates a page checks at most.
	pageCandidateCount int
	order              searchRankOrder
	// Tier 2 newest first rather than by J, as the app may switch it (§11.14's rank row).
	possibleNewestFirst bool
	// |T(q)|, the query's distinct trigrams.
	queryTrigramCount int

	phase   int
	pending []*searchRankCandidate
	next    int
	// Matches found and not yet given, in walk order or, past the walk, in tier 1's order.
	matches  []*searchRankedHit
	possible []*searchRankedHit
	// Near candidates once settled, walked after the exact ones, and their hits.
	nearPending      []*searchRankCandidate
	nearNext         int
	nearSettled      bool
	nearCorrection   string
	nearTrigramCount int
	nearHits         []*searchRankedHit
	sortedTiers      bool
	sortedNear       bool
	counts           searchRankCounts
	// Documents a phase has given or judged, by repo and key: copies of one version in two partitions are one, and a
	// document given in phase 1 is not given in phase 2. Bounded by the candidates checked.
	seen map[searchSeenKey]bool
}

// A document across the search.
type searchSeenKey struct {
	repoId Id
	key    [indexIdByteCount]byte
}

// What a ranker reads.
type searchRankerArgs struct {
	settings *SearchResultSettings
	search   *SidecarSearchSettings
	order    searchRankOrder
	// Tier 2 newest first rather than by J.
	possibleNewestFirst bool
	query               *SearchQuery
}

// A ranker for one search, before its first phase.
func newSearchRanker(args *searchRankerArgs) (*searchRanker, error) {
	if err := args.settings.check(); err != nil {
		return nil, err
	}
	if args.search == nil || args.search.PageCandidateCount <= 0 {
		return nil, fmt.Errorf("%w: a page checks a positive count of candidates", errInvalidSettings)
	}
	order := args.order
	if order == 0 {
		order = searchRankByTime
	}
	return &searchRanker{
		settings:            args.settings,
		pageCandidateCount:  args.search.PageCandidateCount,
		order:               order,
		possibleNewestFirst: args.possibleNewestFirst,
		queryTrigramCount:   len(args.query.trigrams()),
		seen:                map[searchSeenKey]bool{},
	}, nil
}

// The candidates of inputs read ahead and sorted newest first, those past the time filters left out. An exact
// phase's are counted; a near tier's add to its own count alone.
func (self *searchRanker) collect(inputs []*searchRankInput, exact bool) ([]*searchRankCandidate, error) {
	candidates := []*searchRankCandidate{}
	for _, input := range inputs {
		result := input.result
		if exact && result.tooBroad {
			self.counts.tooBroad = true
			self.counts.tooBroadUncounted += result.candidateCount - len(result.candidates)
		}
		if exact {
			self.counts.unsearchable += len(result.unresolved)
		}
		for _, candidate := range result.candidates {
			ranked := &searchRankCandidate{
				source:     input.source,
				candidate:  candidate,
				step:       input.step,
				partition:  input.partition,
				headerOnly: result.tooBroad,
			}
			if candidate.entry != nil {
				ranked.key, ranked.version, ranked.timeSeconds = candidate.entry.key, candidate.entry.version, candidate.entry.timeSeconds
			} else {
				key, version, timeSeconds, err := searchShardHeader(candidate.shard.reader, candidate.docId)
				if err != nil {
					return nil, err
				}
				ranked.key, ranked.version, ranked.timeSeconds = key, version, timeSeconds
			}
			if exact {
				self.counts.candidates += 1
			}
			if !input.source.confirmer.filters.timeHolds(ranked.timeSeconds) {
				if exact {
					self.counts.filtered += 1
				}
				continue
			}
			candidates = append(candidates, ranked)
		}
	}
	slices.SortStableFunc(candidates, func(a *searchRankCandidate, b *searchRankCandidate) int {
		return cmp.Or(
			cmp.Compare(b.timeSeconds, a.timeSeconds),
			cmp.Compare(a.step, b.step),
			compareIndexKeys(a.key, b.key),
			cmp.Compare(b.version, a.version),
		)
	})
	return candidates, nil
}

// Starts the next phase over its partitions' candidates. The phase before must be done.
func (self *searchRanker) beginPhase(inputs []*searchRankInput) error {
	if self.phase != 0 && !self.phaseDone() {
		return fmt.Errorf("%w: a phase begun before the last was given", ErrSearchCacheArgs)
	}
	self.phase += 1
	self.pending, self.next = nil, 0
	self.matches, self.possible = nil, nil
	self.nearPending, self.nearNext, self.nearSettled, self.nearHits = nil, 0, false, nil
	self.nearCorrection, self.nearTrigramCount = "", 0
	self.sortedTiers, self.sortedNear = false, false
	self.counts = searchRankCounts{}
	pending, err := self.collect(inputs, true)
	if err != nil {
		return err
	}
	self.pending = pending
	return nil
}

// Settles tier 3: the corrected query's candidates, matched by the caller against correction's query and confirmed by
// inputs' sources, or none. Called once a phase, once every exact candidate is checked or at any time before.
func (self *searchRanker) settleNear(inputs []*searchRankInput, correction string, correctedTrigramCount int) error {
	if self.nearSettled {
		return fmt.Errorf("%w: near hits settled twice in a phase", ErrSearchCacheArgs)
	}
	self.nearSettled = true
	self.nearCorrection = correction
	self.nearTrigramCount = correctedTrigramCount
	if len(inputs) == 0 {
		return nil
	}
	near, err := self.collect(inputs, false)
	if err != nil {
		return err
	}
	self.nearPending = near
	return nil
}

// Whether the phase has given everything it holds.
func (self *searchRanker) phaseDone() bool {
	return self.next == len(self.pending) && self.nearSettled && self.nearNext == len(self.nearPending) &&
		len(self.matches) == 0 && len(self.possible) == 0 && len(self.nearHits) == 0
}

// Masks and checks one candidate, adding what it is to its tier. near says it is a corrected query's.
func (self *searchRanker) check(ctx context.Context, candidate *searchRankCandidate, near bool) error {
	source := candidate.source
	row, err := candidate.row()
	if err != nil {
		return err
	}
	verdict, err := source.mask.judge(&searchMaskCandidate{
		key:         candidate.key,
		version:     candidate.version,
		timeSeconds: candidate.timeSeconds,
		row:         row,
		local:       candidate.partition == searchPartitionLocal,
	})
	if err != nil {
		return err
	}
	switch verdict {
	case searchMaskCurrent:
	case searchMaskOtherRef:
		return nil
	case searchMaskUnknown:
		self.counts.unsearchable += 1
		return nil
	default:
		self.counts.masked += 1
		return nil
	}
	seenKey := searchSeenKey{repoId: source.repoId, key: candidate.key}
	if self.seen[seenKey] {
		return nil
	}
	refId := source.refId
	if source.companion {
		if refId, err = IdFromBytes(row.refId); err != nil {
			return err
		}
	}
	confirmation, err := source.confirmer.confirm(ctx, &searchConfirmCandidate{
		refId:      refId,
		version:    candidate.version,
		row:        row,
		headerOnly: candidate.headerOnly,
	})
	if err != nil {
		return err
	}
	if confirmation.state == searchMatchRejected || candidate.headerOnly && confirmation.state == searchMatchPossible {
		// a false candidate for this query may still be a near hit of the corrected one, so it is not marked seen
		self.counts.rejected += 1
		return nil
	}
	self.seen[seenKey] = true
	trigramCount := self.queryTrigramCount
	if near {
		trigramCount = self.nearTrigramCount
	}
	hit := &searchRankedHit{
		repoId:       source.repoId,
		refId:        refId,
		key:          candidate.key,
		version:      candidate.version,
		timeSeconds:  candidate.timeSeconds,
		partition:    candidate.partition,
		phase:        self.phase,
		row:          row,
		match:        confirmation.state,
		near:         near,
		snippet:      confirmation.snippet,
		overlap:      float64(trigramCount) / float64(max(1, candidate.candidate.trigramCount)),
		trigramCount: candidate.candidate.trigramCount,
		inHeader:     confirmation.inHeader,
		density:      confirmation.density,
	}
	switch {
	case near:
		hit.correction = self.nearCorrection
		self.counts.near += 1
		self.nearHits = append(self.nearHits, hit)
	case confirmation.state == searchMatchPossible:
		self.counts.possible += 1
		self.possible = append(self.possible, hit)
	default:
		self.counts.matches += 1
		self.matches = append(self.matches, hit)
	}
	return nil
}

// Possible and near hits by J: fewest distinct trigrams first, ties newest first.
func searchCompareOverlap(a *searchRankedHit, b *searchRankedHit) int {
	return cmp.Or(
		cmp.Compare(a.trigramCount, b.trigramCount),
		cmp.Compare(b.timeSeconds, a.timeSeconds),
		compareIndexKeys(a.key, b.key),
	)
}

// Hits newest first, as the walk found them.
func searchCompareNewest(a *searchRankedHit, b *searchRankedHit) int {
	return cmp.Or(cmp.Compare(b.timeSeconds, a.timeSeconds), compareIndexKeys(a.key, b.key))
}

// Tier 1 in the order asked, once the walk has found every match: by path, header matches first, or by density.
func (self *searchRanker) sortMatches() {
	switch self.order {
	case searchRankByPath:
		slices.SortStableFunc(self.matches, func(a *searchRankedHit, b *searchRankedHit) int {
			if a.inHeader != b.inHeader {
				if a.inHeader {
					return -1
				}
				return 1
			}
			return cmp.Or(cmp.Compare(a.row.locator, b.row.locator), cmp.Compare(b.timeSeconds, a.timeSeconds))
		})
	case searchRankByDensity:
		slices.SortStableFunc(self.matches, func(a *searchRankedHit, b *searchRankedHit) int {
			return cmp.Or(cmp.Compare(b.density, a.density), cmp.Compare(b.timeSeconds, a.timeSeconds))
		})
	}
}

// Up to hitCount hits in rank order, ConfirmPageHitCount where it is not positive, checking candidates only until the
// page is full, at most Search.PageCandidateCount of them, and stopping when ctx is done (the caller's PageCpu and
// wait_ms); what is checked and not given stays for the next page.
func (self *searchRanker) page(ctx context.Context, hitCount int) (*searchRankPage, error) {
	page := &searchRankPage{}
	checked := 0
	give := func(from *[]*searchRankedHit) {
		for 0 < len(*from) && len(page.hits) < hitCount {
			page.hits = append(page.hits, (*from)[0])
			*from = (*from)[1:]
		}
	}
	mayCheck := func() bool {
		return checked < self.pageCandidateCount && ctx.Err() == nil
	}
	if hitCount <= 0 {
		hitCount = self.settings.ConfirmPageHitCount
	}
	for self.phase != 0 && len(page.hits) < hitCount {
		if self.next < len(self.pending) {
			// newest first streams; any other order needs every match found before it gives one
			if self.order == searchRankByTime {
				give(&self.matches)
				if len(page.hits) == hitCount {
					break
				}
			}
			if !mayCheck() {
				break
			}
			candidate := self.pending[self.next]
			self.next += 1
			checked += 1
			if err := self.check(ctx, candidate, false); err != nil {
				return nil, err
			}
			continue
		}
		if !self.sortedTiers {
			self.sortMatches()
			if self.possibleNewestFirst {
				slices.SortStableFunc(self.possible, searchCompareNewest)
			} else {
				slices.SortStableFunc(self.possible, searchCompareOverlap)
			}
			self.sortedTiers = true
		}
		give(&self.matches)
		give(&self.possible)
		if len(page.hits) == hitCount || 0 < len(self.matches) || 0 < len(self.possible) {
			break
		}
		if !self.nearSettled {
			break
		}
		if self.nearNext < len(self.nearPending) {
			if !mayCheck() {
				break
			}
			candidate := self.nearPending[self.nearNext]
			self.nearNext += 1
			checked += 1
			if err := self.check(ctx, candidate, true); err != nil {
				return nil, err
			}
			continue
		}
		if !self.sortedNear {
			slices.SortStableFunc(self.nearHits, searchCompareOverlap)
			self.sortedNear = true
		}
		give(&self.nearHits)
		break
	}
	page.exactDone = self.next == len(self.pending)
	page.phaseDone = self.phaseDone()
	page.counts = self.counts
	page.counts.pending = len(self.pending) - self.next + len(self.nearPending) - self.nearNext
	return page, nil
}
