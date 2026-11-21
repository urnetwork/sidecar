//go:build !sidecar_http && !ios_extension

// What a designated daemon serves remote searches from (SEARCH-M10-32; §11.14's serve and ranking rows; I-19, FI-24;
// DESIGN-DETAILS 7.2.2's rows 4 to 8, 7.2.5's candidate order and 7.7): its SearchEngine's snapshots, kept records,
// local layers and text views, through SEARCH-M10-26's searchCandidatesAfter and searchVerifyCandidate.
//
//	rows     for each ref a request names that rows 1 to 3 let through: REFUSED_INDEX_OFF where its index is off or it
//	         has no index root; REFUSED_FORMAT where the snapshot is a newer format or normalizer; REFUSED_ALL_ABSENT
//	         where no whole snapshot is held, or the scope is all and all is not usable; SERVED_INDEX where this host
//	         holds no text pin of the content ref (TextPin) or the snapshot holds a bad file; else SERVED_TEXT
//	order    the text-served refs' candidates newest first by (time, the repo's place, doc_key): every bucket matched
//	         at page 0, and an all shard matched only once the order can reach it, by its file's two times: a shard
//	         whose time_min_ms is above the watermark's time holds nothing after it, and the pass stops at a shard
//	         whose time_max_ms is older than the candidate after the page's K, so page 0 of a mailbox reads no all
//	         shard while its buckets fill the page
//	verify   against the text view as SEARCH-M10-24's confirmer reads it, which never fetches
//	tail     the index-served refs' hits, ranked as a phone ranks them, confirmed then possible
//
// Keys: a kept record opens only with RK_g already in this device's key store. A hosted server looks it up directly.
// For an engine supplied without a local key reader, the engine's GkmClient is asked on an ended context. A search
// never fetches an index or a key.
//
// Not safe for concurrent use: a view is one cursor's, used under its pageLock.

package sidecar

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The corpus over engine. textPin names the content refs this host holds the text of; nil serves every ref from the
// index.
type searchEngineRemoteCorpus struct {
	engine      *SearchEngine
	heldRepoKey func(Id, uint64) *EvsRepoKey
	textPin     func(repoId Id, refId Id) (SearchSyncPin, uint32, bool)
}

// The corpus over engine, the text pins textPin names.
func newSearchEngineRemoteCorpus(engine *SearchEngine, textPin func(repoId Id, refId Id) (SearchSyncPin, uint32, bool)) *searchEngineRemoteCorpus {
	return &searchEngineRemoteCorpus{engine: engine, textPin: textPin}
}

// The engine's GkmClient answering only from what this device already holds: every call that might reach gkm runs on
// an ended context, so it fails where a fetch would start. What a remote search opens records with.
type searchRemoteHeldKeys struct {
	inner       GkmClient
	heldRepoKey func(Id, uint64) *EvsRepoKey
}

// A context that has already ended.
func searchRemoteEndedContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// See GkmClient: what the key store holds, never a fetch.
func (self *searchRemoteHeldKeys) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	if self.heldRepoKey != nil {
		return nil, ErrGkmKeyMissing
	}
	return self.inner.CurrentRepoKey(searchRemoteEndedContext(), repoId)
}

// See GkmClient: what the key store holds, never a fetch.
func (self *searchRemoteHeldKeys) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	if self.heldRepoKey != nil {
		if key := self.heldRepoKey(repoId, generation); key != nil && key.RepoId() == repoId && key.Generation() == generation {
			return key, nil
		}
		return nil, ErrGkmKeyMissing
	}
	return self.inner.RepoKey(searchRemoteEndedContext(), repoId, generation)
}

// Refused: serving writes nothing.
func (self *searchRemoteHeldKeys) EnsureWritable(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return nil, ErrGkmUnavailable
}

// Refused: serving writes nothing.
func (self *searchRemoteHeldKeys) DropKey(ctx context.Context, repoId Id) (*GkmDropKey, error) {
	return nil, ErrGkmUnavailable
}

// Refused: serving writes nothing.
func (self *searchRemoteHeldKeys) CreateGroup(ctx context.Context, args *GkmCreateGroupArgs) (*EvsRepoKey, error) {
	return nil, ErrGkmUnavailable
}

// Refused: serving writes nothing.
func (self *searchRemoteHeldKeys) RotateRepo(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return nil, ErrGkmUnavailable
}

// Nothing: the engine's own client follows the log.
func (self *searchRemoteHeldKeys) AuthAdvanced(state GkmAuthView) {}

// Refused: serving drops nothing.
func (self *searchRemoteHeldKeys) ForgetRepo(ctx context.Context, repoId Id) error {
	return ErrGkmUnavailable
}

// The engine's request a remote query reads as: its text, its filters as §16.10 names them, and its inclusive time
// bounds. errSearchRemoteQuery for a filter this build cannot apply here, so the requester falls back rather than
// getting hits the filter would have kept out.
func searchRemoteEngineRequest(query *searchRemoteQuery) (*SearchRequest, error) {
	request := &SearchRequest{Text: query.text, Fuzzy: query.fuzzy}
	if 0 < query.sinceMs {
		request.Since = time.UnixMilli(query.sinceMs)
	}
	if 0 < query.untilMs {
		request.Until = time.UnixMilli(query.untilMs)
	}
	filters := query.filters
	if filters == nil {
		return request, nil
	}
	add := func(name string, value string) {
		request.Filters = append(request.Filters, SearchFieldFilter{Name: name, Value: value})
	}
	for _, agent := range filters.GetAgents() {
		add("agent", agent)
	}
	for _, named := range []struct {
		name string
		ids  [][]byte
	}{
		{name: "sidecar", ids: filters.GetSidecarIds()},
		{name: "member", ids: filters.GetMemberIds()},
		{name: "run", ids: filters.GetRunIds()},
	} {
		for _, idBytes := range named.ids {
			id, err := IdFromBytes(idBytes)
			if err != nil {
				return nil, fmt.Errorf("%w: a filter id", errSearchRemoteQuery)
			}
			add(named.name, id.String())
		}
	}
	for _, session := range filters.GetSessionIds() {
		add("session", session)
	}
	if prefix := filters.GetPathPrefix(); prefix != "" {
		add("path_prefix", prefix)
	}
	for _, field := range filters.GetFields() {
		name := ""
		for headerName, number := range searchQueryHeaderFields {
			if uint32(number) == field.GetField() {
				name = headerName
			}
		}
		if name == "" {
			return nil, fmt.Errorf("%w: a field filter past the header fields", errSearchRemoteQuery)
		}
		add(name, field.GetText())
	}
	if 0 < len(filters.GetKinds()) {
		return nil, fmt.Errorf("%w: a kind filter", errSearchRemoteQuery)
	}
	return request, nil
}

// One ref a view serves, opened as the engine opens a ref for a search.
type searchRemoteServedRef struct {
	opened *searchOpenedRef
	place  uint16
	text   bool
	// all's shards, by their files' times, each matched once the order can reach it
	allSteps []*searchRemoteAllStep
}

// One all shard of a text-served ref.
type searchRemoteAllStep struct {
	ref       *searchRemoteServedRef
	shard     uint32
	timeMinMs int64
	timeMaxMs int64
	input     *searchRankInput
}

// One cursor's view over the engine. See searchRemoteView.
type searchEngineRemoteView struct {
	corpus     *searchEngineRemoteCorpus
	query      *SearchQuery
	scopeAll   bool
	refs       []*searchRemoteServedRef
	places     map[*searchRankSource]uint16
	bucketHeld []*searchRankInput
	// whether the buckets were found too broad, which the first pass reports, and whether a pass has read all
	bucketsTooBroad bool
	firstPass       bool
	allRead         bool
	allNewestMs     int64
	tail            *searchRanker
	tailPhase       int
	tailCounts      searchRankCounts
}

// See searchRemoteCorpus.
func (self *searchEngineRemoteCorpus) Open(ctx context.Context, query *searchRemoteQuery, asks []searchRemoteRefAsk) (searchRemoteView, []searchRemoteRefRow, error) {
	engine := self.engine
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return nil, nil, err
	}
	parsed, err := searchParseQuery(query.text, normalizer)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errSearchRemoteQuery, err)
	}
	request, err := searchRemoteEngineRequest(query)
	if err != nil {
		return nil, nil, err
	}
	if parsed.Empty() && len(request.Filters) == 0 {
		return nil, nil, fmt.Errorf("%w: a query or a filter", errSearchRemoteQuery)
	}
	filters, err := searchRowFiltersOf(request, normalizer, engine.args.Members)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errSearchRemoteQuery, err)
	}
	scopeRepos, err := engine.args.Scope.Repos(ctx)
	if err != nil {
		return nil, nil, err
	}
	view := &searchEngineRemoteView{corpus: self, query: parsed, scopeAll: query.scopeAll, places: map[*searchRankSource]uint16{}, firstPass: true}
	rows := make([]searchRemoteRefRow, len(asks))
	keys := &searchRemoteHeldKeys{inner: engine.args.Gkm, heldRepoKey: self.heldRepoKey}
	for i, ask := range asks {
		row, served, err := view.openRef(ctx, ask, scopeRepos, request, filters, normalizer, keys)
		if err != nil {
			view.Close()
			return nil, nil, err
		}
		rows[i] = row
		if served != nil {
			view.refs = append(view.refs, served)
			view.places[served.opened.source] = ask.place
		}
	}
	// the buckets of the text-served refs, matched once for every page; their too-broad verdict is page 0's
	step := 0
	for _, served := range view.refs {
		if !served.text {
			continue
		}
		inputs, _, err := served.opened.phaseOne(ctx, parsed, &step)
		if err != nil {
			view.Close()
			return nil, nil, err
		}
		for _, input := range inputs {
			view.bucketsTooBroad = view.bucketsTooBroad || input.result.tooBroad
		}
		view.bucketHeld = append(view.bucketHeld, inputs...)
	}
	return view, rows, nil
}

// Eviction can remove a bucket or its wrapped keys after a swap. Check local holdings and key
// generations against the snapshot without reading postings or asking the network for a key.
func searchRemoteSnapshotHeld(ctx context.Context, cache *SearchCache, snapshot *SearchSyncSnapshot, held *SearchCacheRef, all bool, keys GkmClient) bool {
	pin := snapshot.Pin()
	if pin.Version == 0 || pin.Chain == ([sha256.Size]byte{}) || held == nil || held.RefVersion < pin.Version || held.ErasedOverflow {
		return false
	}
	// Ref returns a private copy. Sorting avoids a second holdings map or a linear lookup per file.
	compare := func(a, b SearchCacheFile) int {
		if c := cmp.Compare(a.Key.Path, b.Key.Path); c != 0 {
			return c
		}
		return cmp.Compare(a.Key.Version, b.Key.Version)
	}
	slices.SortFunc(held.Files, compare)
	generations := map[uint64]bool{}
	rootHeld := false
	companion := searchRootCompanion(snapshot.manifest.Root)
	for _, file := range snapshot.manifest.Files {
		if ctx.Err() != nil {
			return false
		}
		if file.Partition.All && !all {
			continue
		}
		parsed, known := indexParsePath(file.Path, companion)
		if !known {
			return false
		}
		if file.State != SearchManifestHeld {
			// Bad postings can contribute only index coverage. Settings and the erasure set govern
			// whether any result may be shown.
			if parsed.kind == indexPathSettings || parsed.kind == indexPathErasureSet {
				return false
			}
			continue
		}
		key := SearchCacheKey{RepoId: held.RepoId, RefId: held.RefId, Path: file.Path, Version: file.Version}
		index, found := slices.BinarySearchFunc(held.Files, SearchCacheFile{Key: key}, compare)
		if !found || held.Files[index].ContentSha256 != file.ContentSha256 || !held.Files[index].KeysKept {
			return false
		}
		meta, err := cache.readMeta(searchCachePartName(key, searchCachePartRecord))
		if err != nil || meta.keysState() != nil {
			return false
		}
		for _, generation := range []uint64{meta.Generation, meta.headerGeneration()} {
			if !generations[generation] {
				key, err := keys.RepoKey(ctx, held.RepoId, generation)
				if err != nil || key == nil {
					return false
				}
				generations[generation] = true
			}
		}
		switch parsed.kind {
		case indexPathSlot, indexPathLargeEntry, indexPathBucketShard, indexPathAllShard:
			rootHeld = true
		}
	}
	return rootHeld
}

// Opens one asked ref: its row, and the served ref where it serves. An error only for what the engine itself failed
// at; a ref it cannot serve is a refusal.
func (self *searchEngineRemoteView) openRef(ctx context.Context, ask searchRemoteRefAsk, scopeRepos []*SearchScopeRepo, request *SearchRequest,
	filters *searchRowFilters, normalizer *indexNormalizer, keys GkmClient) (searchRemoteRefRow, *searchRemoteServedRef, error) {
	engine := self.corpus.engine
	refuse := func(served protocol.SearchServed) (searchRemoteRefRow, *searchRemoteServedRef, error) {
		return searchRemoteRefRow{served: served}, nil, nil
	}
	var repo *SearchScopeRepo
	for _, candidate := range scopeRepos {
		if candidate != nil && candidate.RepoId == ask.repoId && candidate.Readable {
			repo = candidate
		}
	}
	if repo == nil {
		return refuse(protocol.SearchServed_REFUSED_ALL_ABSENT)
	}
	var ref *SearchScopeRef
	for _, candidate := range repo.Refs {
		if candidate == nil {
			continue
		}
		if len(ask.refId) == 0 && candidate.Default || len(ask.refId) != 0 && candidate.RefId == Id(ask.refId) {
			ref = candidate
		}
	}
	switch {
	case ref == nil:
		return refuse(protocol.SearchServed_REFUSED_INDEX_OFF)
	case ref.IndexOff:
		return refuse(protocol.SearchServed_REFUSED_INDEX_OFF)
	case ref.Unbuilt || (repo.valid != nil && !repo.valid()) || (ref.valid != nil && !ref.valid()):
		return refuse(protocol.SearchServed_REFUSED_ALL_ABSENT)
	}
	snapshot, err := engine.args.Sync.Snapshot(repo.RepoId, ref.RefId)
	if err != nil {
		if errors.Is(err, ErrSidecarStoreAbsent) || errors.Is(err, ErrSearchSyncUnfollowed) || errors.Is(err, ErrSearchSyncClosed) {
			return refuse(protocol.SearchServed_REFUSED_ALL_ABSENT)
		}
		return searchRemoteRefRow{}, nil, err
	}
	held, err := engine.args.Cache.Ref(repo.RepoId, ref.RefId)
	if err != nil {
		snapshot.Release()
		return searchRemoteRefRow{}, nil, err
	}
	retained := []SearchCacheRetained{}
	if held != nil {
		retained = held.Retained
	}
	holding := searchHoldingOfSnapshot(snapshot, repo.RepoId, ref.RefId, retained)
	planScope := searchPlanLatest
	if self.scopeAll {
		planScope = searchPlanAll
	}
	nowMs := engine.clock.Now().UnixMilli()
	plan := searchPlanRef(&searchPlanArgs{scope: planScope, since: request.Since, nowMs: nowMs, tables: indexLinkedTables()}, holding)
	switch {
	case plan.status == searchRefOff:
		snapshot.Release()
		return refuse(protocol.SearchServed_REFUSED_INDEX_OFF)
	case plan.status == searchRefUpdate:
		snapshot.Release()
		return refuse(protocol.SearchServed_REFUSED_FORMAT)
	case self.scopeAll && (!snapshot.AllUsable() || slices.ContainsFunc(holding.allShards, func(shard *searchHeldShard) bool { return !shard.held })):
		snapshot.Release()
		return refuse(protocol.SearchServed_REFUSED_ALL_ABSENT)
	case !searchRemoteSnapshotHeld(ctx, engine.args.Cache, snapshot, held, self.scopeAll, keys):
		snapshot.Release()
		return refuse(protocol.SearchServed_REFUSED_ALL_ABSENT)
	}
	if ask.recordServed != nil && !ask.recordServed() {
		snapshot.Release()
		return refuse(protocol.SearchServed_REFUSED_ALL_ABSENT)
	}
	companion := searchRootCompanion(snapshot.manifest.Root)
	opened := &searchOpenedRef{
		engine: engine, scoped: &searchScopedRef{repo: repo, ref: ref}, repoId: repo.RepoId, refId: ref.RefId, snap: snapshot, holding: holding, plan: plan,
		probe: searchProbeOf(snapshot.Versions()), keys: keys, searchableSinceSeconds: searchSearchableSinceSeconds(nowMs, repo.SearchableAge),
	}
	if engine.args.Local != nil {
		opened.local = engine.args.Local(repo.RepoId, ref.RefId)
	}
	var localNewest searchLocalNewestFunc
	if opened.local != nil {
		localNewest = opened.local.newest
	}
	if opened.probe == nil {
		opened.probe = func(key [indexIdByteCount]byte) (searchVersionRecord, error) { return searchVersionRecord{}, nil }
	}
	// §11.14's serve row: masks, newest wins and searchable_days, as a local search applies them
	mask, err := newSearchMask(&searchMaskArgs{
		probe: opened.probe, companion: companion, refId: ref.RefId, local: localNewest, searchableSinceSeconds: opened.searchableSinceSeconds,
	})
	if err != nil {
		snapshot.Release()
		return searchRemoteRefRow{}, nil, err
	}
	// row 7: the text of the content ref, else served from the index; a bad file serves from the index too, since the
	// local layer's cover of it is not known here
	row := searchRemoteRefRow{refId: ref.RefId, latestFromMs: snapshot.LatestFromMs()}
	text := false
	if pinner := self.corpus.textPin; pinner != nil && len(snapshot.Bad()) == 0 {
		if pin, uncovered, ok := pinner(repo.RepoId, ref.RefId); ok {
			text = true
			row.served = protocol.SearchServed_SERVED_TEXT
			row.refVersion, row.chain, row.refTimeMs, row.uncovered = pin.Version, pin.Chain[:], pin.TimeMs, uncovered
		}
	}
	if !text {
		row.served = protocol.SearchServed_SERVED_INDEX
		if !companion {
			pin := snapshot.Pin()
			row.refVersion, row.chain, row.refTimeMs = pin.Version, pin.Chain[:], pin.TimeMs
		}
	}
	confirmer := &searchConfirmer{
		query: self.query, filters: filters, normalizer: normalizer, registry: searchRegistryOf(repo.Kind),
		settings: engine.results, repoId: repo.RepoId, acceptRow: repo.acceptRow,
	}
	if text && engine.args.Text != nil {
		confirmer.text = engine.args.Text(repo.RepoId, ref.RefId)
	}
	if engine.args.Display != nil {
		confirmer.display = engine.args.Display(repo.RepoId, ref.RefId)
	}
	opened.source = &searchRankSource{repoId: repo.RepoId, refId: ref.RefId, companion: companion, mask: mask, confirmer: confirmer}
	served := &searchRemoteServedRef{opened: opened, place: ask.place, text: text}
	if text && self.scopeAll {
		files := map[string]*SearchManifestFile{}
		for _, file := range snapshot.Files() {
			files[file.Path] = file
		}
		paths := indexNewPaths(companion, indexRootNumber)
		for _, planStep := range plan.steps {
			if planStep.partition != searchPartitionAll || !planStep.held {
				continue
			}
			file := files[paths.allShard(planStep.shardNumber)]
			if file == nil {
				continue
			}
			served.allSteps = append(served.allSteps, &searchRemoteAllStep{ref: served, shard: planStep.shardNumber, timeMinMs: file.TimeMinMs, timeMaxMs: file.TimeMaxMs})
			self.allNewestMs = max(self.allNewestMs, file.TimeMaxMs)
		}
	}
	return row, served, nil
}

// See searchRemoteView. Every bucket was matched at Open; an all shard is matched once the order can reach it.
func (self *searchEngineRemoteView) CandidatesAfter(ctx context.Context, watermark searchWatermark, k int) ([]*searchRemoteCandidate, *searchRemoteCandidate, bool, error) {
	firstPass := self.firstPass
	self.firstPass = false
	inputs := slices.Clone(self.bucketHeld)
	allSteps := []*searchRemoteAllStep{}
	for _, served := range self.refs {
		for _, step := range served.allSteps {
			if step.input != nil {
				inputs = append(inputs, step.input)
			} else {
				allSteps = append(allSteps, step)
			}
		}
	}
	repoIndex := func(source *searchRankSource) uint16 { return self.places[source] }
	ordered, next, err := searchCandidatesAfter(inputs, repoIndex, watermark, k)
	if err != nil {
		return nil, nil, false, err
	}
	if firstPass && self.bucketsTooBroad {
		return self.candidatesOf(ctx, ordered, true), nil, true, nil
	}
	slices.SortFunc(allSteps, func(a *searchRemoteAllStep, b *searchRemoteAllStep) int { return cmp.Compare(b.timeMaxMs, a.timeMaxMs) })
	step := len(self.bucketHeld)
	for _, allStep := range allSteps {
		if watermark != (searchWatermark{}) && watermark.timeMs < allStep.timeMinMs {
			// every row of the shard is newer than the watermark: before it, accounted for
			continue
		}
		if next != nil && allStep.timeMaxMs < next.place.timeMs {
			// the shard's newest row is older than the candidate after K: nothing in it reaches this page
			break
		}
		source, err := allStep.ref.opened.allSource(ctx, allStep.shard)
		if err != nil {
			return nil, nil, false, err
		}
		if source == nil {
			continue
		}
		input, err := allStep.ref.opened.match(self.query, source, step)
		if err != nil {
			return nil, nil, false, err
		}
		step += 1
		allStep.input = input
		inputs = append(inputs, input)
		if !self.allRead {
			self.allRead = true
			if input.result.tooBroad {
				return self.candidatesOf(ctx, ordered, true), nil, true, nil
			}
		}
		if ordered, next, err = searchCandidatesAfter(inputs, repoIndex, watermark, k); err != nil {
			return nil, nil, false, err
		}
	}
	candidates := self.candidatesOf(ctx, ordered, false)
	var after *searchRemoteCandidate
	if next != nil {
		after = &searchRemoteCandidate{place: next.place, handle: next}
	}
	return candidates, after, false, nil
}

// The order's candidates as a page examines them; where header is set, each with the hit its display fields give, as a
// too-broad page returns.
func (self *searchEngineRemoteView) candidatesOf(ctx context.Context, ordered []*searchOrderedCandidate, header bool) []*searchRemoteCandidate {
	candidates := make([]*searchRemoteCandidate, 0, len(ordered))
	for _, item := range ordered {
		candidate := &searchRemoteCandidate{place: item.place, handle: item}
		if header && item.row != nil {
			confirmation, err := item.candidate.source.confirmer.confirm(ctx, &searchConfirmCandidate{
				refId: self.refIdOf(item), version: item.candidate.version, row: item.row, headerOnly: true,
			})
			if err == nil && confirmation.state == searchMatchConfirmed {
				candidate.header = searchRemoteHitOf(item.candidate, item.row, self.refIdOf(item), SearchConfirmed, "")
				candidate.headerConfirmed = true
			}
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

// The ref a candidate's document is on: its row's ref_id in ur/index, else the index's ref.
func (self *searchEngineRemoteView) refIdOf(item *searchOrderedCandidate) Id {
	source := item.candidate.source
	if source.companion && item.row != nil {
		if refId, err := IdFromBytes(item.row.refId); err == nil {
			return refId
		}
	}
	return source.refId
}

// See searchRemoteView.
func (self *searchEngineRemoteView) Verify(ctx context.Context, candidate *searchRemoteCandidate) (*protocol.SearchHit, bool, error) {
	item, ok := candidate.handle.(*searchOrderedCandidate)
	if !ok {
		return nil, false, nil
	}
	confirmation, err := searchVerifyCandidate(ctx, item)
	if err != nil {
		return nil, false, err
	}
	state := SearchPossible
	switch confirmation.state {
	case searchMatchRejected:
		return nil, false, nil
	case searchMatchVerified:
		state = SearchVerified
	case searchMatchConfirmed:
		state = SearchConfirmed
	}
	snippet := ""
	if state == SearchVerified {
		snippet = confirmation.snippet
	}
	return searchRemoteHitOf(item.candidate, item.row, self.refIdOf(item), state, snippet), true, nil
}

// See searchRemoteView: the index-served refs' buckets as a phase, then their all where the scope is all and it is
// usable, each ranked as a phone ranks it.
func (self *searchEngineRemoteView) Tail(ctx context.Context, k int) ([]*protocol.SearchHit, bool, error) {
	engine := self.corpus.engine
	indexRefs := []*searchRemoteServedRef{}
	for _, served := range self.refs {
		if !served.text {
			indexRefs = append(indexRefs, served)
		}
	}
	if len(indexRefs) == 0 {
		return nil, true, nil
	}
	if self.tail == nil {
		ranker, err := newSearchRanker(&searchRankerArgs{settings: engine.results, search: engine.args.Settings, query: self.query})
		if err != nil {
			return nil, false, err
		}
		self.tail = ranker
	}
	begin := func() (bool, error) {
		step := 0
		inputs := []*searchRankInput{}
		for _, served := range indexRefs {
			switch self.tailPhase {
			case 0:
				refInputs, _, err := served.opened.phaseOne(ctx, self.query, &step)
				if err != nil {
					return false, err
				}
				inputs = append(inputs, refInputs...)
			case 1:
				if !self.scopeAll {
					continue
				}
				refInputs, err := served.opened.phaseTwo(ctx, self.query, &step)
				if err != nil {
					return false, err
				}
				inputs = append(inputs, refInputs...)
			}
		}
		if self.tailPhase == 1 && len(inputs) == 0 {
			return false, nil
		}
		self.tailPhase += 1
		if err := self.tail.beginPhase(inputs); err != nil {
			return false, err
		}
		return true, self.tail.settleNear(nil, "", 0)
	}
	if self.tailPhase == 0 {
		if _, err := begin(); err != nil {
			return nil, false, err
		}
	}
	hits := []*protocol.SearchHit{}
	for len(hits) < k {
		page, err := self.tail.page(ctx, k-len(hits))
		if err != nil {
			return nil, false, err
		}
		for _, ranked := range page.hits {
			hits = append(hits, searchRemoteRankedHitOf(ranked))
		}
		if !page.phaseDone {
			if len(page.hits) == 0 {
				return hits, false, nil
			}
			continue
		}
		if 2 <= self.tailPhase {
			return hits, true, nil
		}
		began, err := begin()
		if err != nil {
			return nil, false, err
		}
		if !began {
			return hits, true, nil
		}
	}
	return hits, false, nil
}

// See searchRemoteView.
func (self *searchEngineRemoteView) AllNewestMs() int64 {
	return self.allNewestMs
}

// See searchRemoteView.
func (self *searchEngineRemoteView) Ended() bool {
	for _, served := range self.refs {
		scope := served.opened.scoped
		if (scope.repo.valid != nil && !scope.repo.valid()) || (scope.ref.valid != nil && !scope.ref.valid()) {
			return true
		}
		select {
		case <-served.opened.snap.Ended():
			return true
		default:
		}
	}
	return false
}

// See searchRemoteView.
func (self *searchEngineRemoteView) Close() {
	for _, served := range self.refs {
		served.opened.close()
	}
	self.refs = nil
}

// A candidate's hit as the reply carries it, in state with snippet. Its signer is the row's writer where the row
// carries one, else the slot's signer, else unknown (zeros), which groups under no agent.
func searchRemoteHitOf(candidate *searchRankCandidate, row *indexRow, refId Id, state SearchHitState, snippet string) *protocol.SearchHit {
	hit := &protocol.SearchHit{
		RepoId: candidate.source.repoId.Bytes(), RefId: refId.Bytes(), DocKey: candidate.key[:], Version: candidate.version,
		TimeMs: int64(candidate.timeSeconds) * 1000, State: uint32(state), Partition: searchRemotePartitionOf(candidate.partition),
		Snippet: snippet, Signer: make([]byte, len(Id{})),
	}
	if candidate.candidate != nil && candidate.candidate.slot != nil {
		hit.Signer = candidate.candidate.slot.signer.Bytes()
	}
	if row != nil {
		hit.DocKind = uint32(row.docKind)
		hit.Locator = row.locator
		for field := indexFieldSubject; field <= indexFieldTitle; field += 1 {
			if text := row.fields[field]; text != "" {
				hit.Fields = append(hit.Fields, &protocol.SearchField{Field: uint32(field), Text: text})
			}
		}
		if row.docKind.hasRegisteredFields() {
			if writer, err := ParseId(row.fields[searchFieldWriter]); err == nil {
				hit.Signer = writer.Bytes()
			}
		}
	}
	return hit
}

// A ranked tail hit as the reply carries it.
func searchRemoteRankedHitOf(ranked *searchRankedHit) *protocol.SearchHit {
	local := searchHitOf(ranked)
	hit := &protocol.SearchHit{
		RepoId: ranked.repoId.Bytes(), RefId: ranked.refId.Bytes(), DocKey: ranked.key[:], Version: ranked.version,
		TimeMs: int64(ranked.timeSeconds) * 1000, DocKind: uint32(local.DocKind), Locator: local.Path, State: uint32(local.State),
		Correction: local.Correction, Partition: searchRemotePartitionOf(ranked.partition), Snippet: local.Snippet,
		Signer: make([]byte, len(Id{})),
	}
	if local.Signer != (Id{}) {
		hit.Signer = local.Signer.Bytes()
	}
	for _, field := range local.Fields {
		hit.Fields = append(hit.Fields, &protocol.SearchField{Field: uint32(field.Field), Text: field.Text})
	}
	return hit
}

// search.proto's partition: 1 current, 2 previous, 3 older or retained, 4 all; the local layer's newest pushes read
// current.
func searchRemotePartitionOf(partition searchPartitionKind) uint32 {
	switch partition {
	case searchPartitionPrevious:
		return 2
	case searchPartitionOlder:
		return 3
	case searchPartitionAll:
		return 4
	}
	return 1
}
