//go:build !sidecar_http && !ios_extension

// Remote search, merging (SEARCH-M10-34; §11.14's merge row; R-SDK-14, D-EVS-60, D-SDK-22, FI-24, FS-83; DESIGN-DETAILS
// 7.2.6, QD-708, QD-709): one row per (repo, ref, doc_key) from the claims of the device's own search of its cache and of
// each leg, by the indexer whose session carried the page. A claim is what one source says of one document: its version,
// time, state and display data; a later page's claim from one source replaces that source's earlier one for the key.
// The merge is a function of the claims, not of their order of arrival, save for the last tie.
//
//	none        no row
//	folded      the device's own claim is the only one, its state is possible or near, and some leg's span holds it:
//	            state unmatched, By that leg's indexer
//	else        the strongest claim: class first, a match (verified or confirmed) before a possible match before a near
//	            hit; then the higher version; then verified before confirmed; then an indexer's claim before the
//	            device's; then the leg whose first page arrived first. State, version, fields and snippet are that
//	            claim's; By is its indexer's config device name, or empty for the device's own
//
//	span        a leg's span holds the device's claim of time t in repo R when the leg serves R from text and its row
//	            reported uncovered 0; t is above the checked_through_ms of the leg's last page of status OK or PARTIAL;
//	            t is at or below the request's until_ms, where one was sent; the index rides R's content ref and the
//	            device's index pin is at or below the leg's pinned version, or t is more than SkewGuard below the pinned
//	            version's time; and the leg is not void
//
// So a match always outranks a weaker claim at a higher version (QD-708): the device's own confirmed hit stays a match
// whatever an indexer says, and so does another indexer's verified hit. A document some indexer claims in any state is
// never folded. One indexer can add its own claims and fold the device's unclaimed possible matches inside its own span,
// into a row that names it, and can do nothing else to the list (M1 to M4).
//
// The pin check: a served row's (ref_version, chain) against the device's own chain at that version from its ring of
// replayed versions: equal passes; unequal raises §6.4's head_alarm fork naming the indexer and voids the leg for the
// repo; above the device's pin it waits, at most RemotePinWaitCount a ref, for a replay to reach it; below the ring it
// is not checked. No read is made for it.
//
// Opening a hit (searchRemoteSearch.checkOpened, SearchRemoteClient.CheckOpened): with the read's pin and the path's
// version e: a read answering dropped, or a document erased or masked here, takes the row away with no alarm; e equal
// to the claim's version checks the query in the chunk whose doc_key is the claim's, verified by this device as well
// where it holds, search_alarm{mismatch} where it does not and the claim said verified; e above the claim's version
// takes the device's own judgment of e, no alarm; e below it alarms mismatch only where the claim said verified and the
// read's pin is at or above the leg's pinned version, else nothing is decided. RemoteMismatchCount mismatches from one
// indexer within RemoteMismatchInterval void every claim and span of its legs and distrust it RemoteDistrustTimeout.
//
// Omission: search_alarm{omission} only where both sides judged the same version: the device's own confirmed claim in a
// repo a leg serves from text with uncovered 0, inside the leg's span by its first three lines, the index riding the
// content ref and the leg's pinned (version, chain) the device's own pin, no page having returned the document, and
// the confirming field not cut at its cap.
//
// Memory: at most RemoteClaimCount claims a search, past which the oldest pages' own possible claims go first. Nothing
// is written to storage, and nothing is logged with a query, hit or snippet (I-13). Not safe for concurrent use: one
// search's, under its step.

package sidecar

import (
	"cmp"
	"slices"
	"time"
)

// One document's key in the merge.
type searchRemoteMergeKey struct {
	repoId Id
	refId  Id
	docKey [16]byte
}

// The key of a hit.
func searchRemoteMergeKeyOf(hit *SearchHit) searchRemoteMergeKey {
	return searchRemoteMergeKey{repoId: hit.Repo, refId: hit.Ref, docKey: hit.DocKey}
}

// One leg's span over one repo it serves, and what its coverage row said.
type searchRemoteSpan struct {
	refId Id
	// the leg serves the repo from text, with no push uncovered
	text      bool
	uncovered uint32
	// the checked_through_ms of the leg's last page of status OK or PARTIAL, and whether one came
	checkedThroughMs int64
	checked          bool
	// the request's until_ms, 0 for none
	untilMs int64
	// the pin the cursor holds: its version, chain and signed time
	pinVersion uint64
	pinChain   []byte
	refTimeMs  int64
	// the pin check failed, or the leg was voided: its claims and span count for nothing
	void bool
}

// One source of claims: the device (leg nil) or a leg, with its indexer and the order its first page came in.
type searchRemoteSource struct {
	indexerId   Id
	indexerName string
	order       int
	spans       map[Id]*searchRemoteSpan
	// every claim and span void: the indexer passed RemoteMismatchCount mismatches
	void bool
}

// One claim of one source.
type searchRemoteClaim struct {
	source *searchRemoteSource
	hit    SearchHit
	// the merge's page count when it came, so the bound drops the oldest pages' first
	page int
}

// The device's own index of a ref: its pin, whether the index rides the content ref (not a companion), and the ring of
// versions it replayed.
type searchRemoteOwnIndex struct {
	pin       SearchSyncPin
	companion bool
	ring      []SearchSyncPinPair
}

// One search's merge.
type searchRemoteMerge struct {
	settings *SidecarSearchSettings
	// the device's own index of a ref, false where it holds none
	ownIndex func(repoId Id, refId Id) (searchRemoteOwnIndex, bool)
	// whether this device's ERASE, erasure-set masks or read checks hide a version of a document
	masked func(key searchRemoteMergeKey, version uint64) bool
	// Stock member-side joins and verified row policy, applied only to a claim received from an indexer.
	acceptRemote func(SearchHit) bool

	device  *searchRemoteSource
	claims  map[searchRemoteMergeKey]map[*searchRemoteSource]*searchRemoteClaim
	count   int
	page    int
	sources []*searchRemoteSource
	// pins waiting for a replay to reach them, a ref's at most RemotePinWaitCount
	waiting []*searchRemotePinWait
}

// A coverage pin above the device's own, waiting.
type searchRemotePinWait struct {
	source *searchRemoteSource
	repoId Id
	refId  Id
}

// A merge under settings' bounds, reading the device's own index of a ref and its masks.
func newSearchRemoteMerge(settings *SidecarSearchSettings, ownIndex func(repoId Id, refId Id) (searchRemoteOwnIndex, bool),
	masked func(key searchRemoteMergeKey, version uint64) bool) *searchRemoteMerge {
	device := &searchRemoteSource{order: -1, spans: map[Id]*searchRemoteSpan{}}
	return &searchRemoteMerge{
		settings: settings, ownIndex: ownIndex, masked: masked, device: device,
		claims: map[searchRemoteMergeKey]map[*searchRemoteSource]*searchRemoteClaim{},
	}
}

// A new leg's source, its first page the order-th to arrive.
func (self *searchRemoteMerge) newSource(indexerId Id, indexerName string, order int) *searchRemoteSource {
	source := &searchRemoteSource{indexerId: indexerId, indexerName: indexerName, order: order, spans: map[Id]*searchRemoteSpan{}}
	self.sources = append(self.sources, source)
	return source
}

// The class of a state: 0 a match, 1 a possible match, 2 a near hit; unmatched reads as the possible claim it folded.
func searchRemoteClass(state SearchHitState) int {
	switch state {
	case SearchVerified, SearchConfirmed:
		return 0
	case SearchNear:
		return 2
	}
	return 1
}

// Whether a is the stronger claim of one document: class, version, verified before confirmed, an indexer's before the
// device's, the earlier leg.
func searchRemoteStronger(a *searchRemoteClaim, b *searchRemoteClaim) bool {
	if classA, classB := searchRemoteClass(a.hit.State), searchRemoteClass(b.hit.State); classA != classB {
		return classA < classB
	}
	if a.hit.Version != b.hit.Version {
		return a.hit.Version > b.hit.Version
	}
	if verifiedA, verifiedB := a.hit.State == SearchVerified, b.hit.State == SearchVerified; verifiedA != verifiedB {
		return verifiedA
	}
	if a.source.order != b.source.order {
		// the device's order is -1: an indexer's claim first, then the leg whose first page came first
		if a.source.order < 0 || b.source.order < 0 {
			return b.source.order < 0
		}
		return a.source.order < b.source.order
	}
	return false
}

// Adds source's claims of a page (nil source: the device's own), each replacing that source's earlier claim of its key.
// A hit this device masks is no claim. Answers the keys whose claims changed.
func (self *searchRemoteMerge) add(source *searchRemoteSource, hits []SearchHit) []searchRemoteMergeKey {
	if source == nil {
		source = self.device
	}
	self.page += 1
	touched := []searchRemoteMergeKey{}
	for _, hit := range hits {
		key := searchRemoteMergeKeyOf(&hit)
		if self.masked != nil && self.masked(key, hit.Version) || source != self.device && self.acceptRemote != nil && !self.acceptRemote(hit) {
			continue
		}
		sources := self.claims[key]
		if sources == nil {
			sources = map[*searchRemoteSource]*searchRemoteClaim{}
			self.claims[key] = sources
		}
		if sources[source] == nil {
			self.count += 1
		}
		sources[source] = &searchRemoteClaim{source: source, hit: hit, page: self.page}
		touched = append(touched, key)
	}
	self.bound()
	return touched
}

// Keeps the claims within RemoteClaimCount: the oldest pages' own possible and near claims go first, then the oldest
// pages' own claims of any state.
func (self *searchRemoteMerge) bound() {
	if self.count <= self.settings.RemoteClaimCount {
		return
	}
	type owned struct {
		key   searchRemoteMergeKey
		claim *searchRemoteClaim
	}
	own := []owned{}
	for key, sources := range self.claims {
		if claim := sources[self.device]; claim != nil {
			own = append(own, owned{key: key, claim: claim})
		}
	}
	slices.SortFunc(own, func(a owned, b owned) int {
		return cmp.Or(cmp.Compare(searchRemoteClass(b.claim.hit.State), searchRemoteClass(a.claim.hit.State)), cmp.Compare(a.claim.page, b.claim.page))
	})
	for _, item := range own {
		if self.count <= self.settings.RemoteClaimCount {
			return
		}
		delete(self.claims[item.key], self.device)
		if len(self.claims[item.key]) == 0 {
			delete(self.claims, item.key)
		}
		self.count -= 1
	}
}

// Whether a leg's span holds the device's claim of time timeMs in repoId (the file header's five lines).
func (self *searchRemoteMerge) spanHolds(source *searchRemoteSource, repoId Id, refId Id, timeMs int64) bool {
	span := source.spans[repoId]
	if span == nil || span.refId != refId || source.void || span.void || !span.text || span.uncovered != 0 || !span.checked {
		return false
	}
	if timeMs <= span.checkedThroughMs {
		return false
	}
	if 0 < span.untilMs && span.untilMs < timeMs {
		return false
	}
	if own, ok := self.ownIndex(repoId, refId); ok && !own.companion && own.pin.Version <= span.pinVersion {
		return true
	}
	return timeMs < span.refTimeMs-self.settings.SkewGuard.Milliseconds()
}

// Recheck local masks before showing a retained claim. A CUT or verified read may postdate its page.
func (self *searchRemoteMerge) strongest(key searchRemoteMergeKey) (*searchRemoteClaim, bool) {
	var strongest *searchRemoteClaim
	indexerClaims := false
	for source, claim := range self.claims[key] {
		if source.void || source != self.device && source.spans[key.repoId] != nil && source.spans[key.repoId].void ||
			self.masked != nil && self.masked(key, claim.hit.Version) || source != self.device && self.acceptRemote != nil && !self.acceptRemote(claim.hit) {
			continue
		}
		indexerClaims = indexerClaims || source != self.device
		if strongest == nil || searchRemoteStronger(claim, strongest) {
			strongest = claim
		}
	}
	return strongest, indexerClaims
}

// The row of key, from its claims: nil for none.
func (self *searchRemoteMerge) row(key searchRemoteMergeKey) *SearchHit {
	strongest, indexerClaims := self.strongest(key)
	if strongest == nil {
		return nil
	}
	row := strongest.hit
	if strongest.source != self.device {
		row.By = strongest.source.indexerName
		return &row
	}
	row.By = ""
	if !indexerClaims && (row.State == SearchPossible || row.State == SearchNear) {
		for _, source := range self.sources {
			if self.spanHolds(source, key.repoId, key.refId, row.Time.UnixMilli()) {
				row.State = SearchUnmatched
				row.By = source.indexerName
				break
			}
		}
	}
	return &row
}

// The rows of keys, each once, ranked: matches, then possible, near and unmatched, newest first within.
func (self *searchRemoteMerge) rows(keys []searchRemoteMergeKey) []SearchHit {
	seen := map[searchRemoteMergeKey]bool{}
	rows := []SearchHit{}
	for _, key := range keys {
		if seen[key] {
			continue
		}
		seen[key] = true
		if row := self.row(key); row != nil {
			rows = append(rows, *row)
		}
	}
	slices.SortStableFunc(rows, func(a SearchHit, b SearchHit) int {
		rank := func(state SearchHitState) int {
			if state == SearchUnmatched {
				return 3
			}
			return searchRemoteClass(state)
		}
		return cmp.Or(cmp.Compare(rank(a.State), rank(b.State)), b.Time.Compare(a.Time))
	})
	return rows
}

// The keys a span change may refold: every key the device alone claims in repoId.
func (self *searchRemoteMerge) ownKeysOf(repoId Id) []searchRemoteMergeKey {
	keys := []searchRemoteMergeKey{}
	for key, sources := range self.claims {
		if key.repoId == repoId && sources[self.device] != nil && len(sources) == 1 {
			keys = append(keys, key)
		}
	}
	return keys
}

// Every key a source claims.
func (self *searchRemoteMerge) keysOf(source *searchRemoteSource) []searchRemoteMergeKey {
	keys := []searchRemoteMergeKey{}
	for key, sources := range self.claims {
		if sources[source] != nil {
			keys = append(keys, key)
		}
	}
	return keys
}

// Records a leg's page over the repos it serves: the span moves to the page's checked_through_ms where its status was OK
// or PARTIAL. Answers the keys whose rows the move may change.
func (self *searchRemoteMerge) moveSpan(source *searchRemoteSource, repoIds []Id, checkedThroughMs int64) []searchRemoteMergeKey {
	touched := []searchRemoteMergeKey{}
	for _, repoId := range repoIds {
		span := source.spans[repoId]
		if span == nil {
			continue
		}
		span.checkedThroughMs, span.checked = checkedThroughMs, true
		touched = append(touched, self.ownKeysOf(repoId)...)
	}
	return touched
}

// Voids source's claims and span over repoId: the pin check failed. Answers the keys whose rows change.
func (self *searchRemoteMerge) voidRepo(source *searchRemoteSource, repoId Id) []searchRemoteMergeKey {
	if span := source.spans[repoId]; span != nil {
		span.void = true
	}
	touched := self.ownKeysOf(repoId)
	for _, key := range self.keysOf(source) {
		if key.repoId == repoId {
			touched = append(touched, key)
		}
	}
	return touched
}

// Voids every claim and span of source. Answers the keys whose rows change.
func (self *searchRemoteMerge) voidSource(source *searchRemoteSource) []searchRemoteMergeKey {
	source.void = true
	touched := self.keysOf(source)
	for repoId := range source.spans {
		touched = append(touched, self.ownKeysOf(repoId)...)
	}
	return touched
}

// Removes key's row: its document was dropped, erased or masked here.
func (self *searchRemoteMerge) remove(key searchRemoteMergeKey) {
	self.count -= len(self.claims[key])
	delete(self.claims, key)
}

// The pin check of one served coverage row (the file header): pass, fail (a fork, the leg voided for the repo), or
// wait for a replay. Answers whether it forked.
func (self *searchRemoteMerge) checkPin(source *searchRemoteSource, repoId Id, refId Id) (forked bool, waiting bool) {
	span := source.spans[repoId]
	own, ok := self.ownIndex(repoId, refId)
	if span == nil || !ok || own.companion || span.pinVersion == 0 {
		return false, false
	}
	for _, pair := range own.ring {
		if pair.Version == span.pinVersion {
			return string(pair.Chain[:]) != string(span.pinChain), false
		}
	}
	if own.pin.Version < span.pinVersion {
		return false, true
	}
	return false, false
}

// Adds a pin to wait for, a ref's at most RemotePinWaitCount, the oldest going unchecked past it.
func (self *searchRemoteMerge) waitPin(source *searchRemoteSource, repoId Id, refId Id) {
	self.waiting = append(self.waiting, &searchRemotePinWait{source: source, repoId: repoId, refId: refId})
	count := 0
	for i := len(self.waiting) - 1; 0 <= i; i -= 1 {
		wait := self.waiting[i]
		if wait.repoId == repoId && wait.refId == refId {
			count += 1
			if self.settings.RemotePinWaitCount < count {
				self.waiting = slices.Delete(self.waiting, i, i+1)
			}
		}
	}
}

// Checks the waiting pins again, as replays reach them: those that fork, and those still waiting.
func (self *searchRemoteMerge) recheckPins() []*searchRemotePinWait {
	forked := []*searchRemotePinWait{}
	kept := self.waiting[:0]
	for _, wait := range self.waiting {
		isFork, stillWaiting := self.checkPin(wait.source, wait.repoId, wait.refId)
		switch {
		case isFork:
			forked = append(forked, wait)
		case stillWaiting:
			kept = append(kept, wait)
		}
	}
	self.waiting = kept
	return forked
}

// Omission's test (the file header): whether the device's own confirmed claim of key lies where source examined the
// same version and returned nothing.
func (self *searchRemoteMerge) omitted(source *searchRemoteSource, key searchRemoteMergeKey) bool {
	sources := self.claims[key]
	own := sources[self.device]
	if own == nil || own.hit.State != SearchConfirmed || len(sources) != 1 || own.hit.Cut || self.masked != nil && self.masked(key, own.hit.Version) {
		return false
	}
	span := source.spans[key.repoId]
	if span == nil || span.refId != key.refId || source.void || span.void || !span.text || span.uncovered != 0 || !span.checked {
		return false
	}
	timeMs := own.hit.Time.UnixMilli()
	if timeMs <= span.checkedThroughMs || 0 < span.untilMs && span.untilMs < timeMs {
		return false
	}
	ownIndex, ok := self.ownIndex(key.repoId, key.refId)
	return ok && !ownIndex.companion && ownIndex.pin.Version == span.pinVersion && string(ownIndex.pin.Chain[:]) == string(span.pinChain)
}

// The keys of the device's own confirmed claims no indexer returned that source examined at the same version: what
// raises omission once its leg is complete.
func (self *searchRemoteMerge) omissions(source *searchRemoteSource) []searchRemoteMergeKey {
	keys := []searchRemoteMergeKey{}
	for key := range self.claims {
		if self.omitted(source, key) {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(a searchRemoteMergeKey, b searchRemoteMergeKey) int {
		return cmp.Or(a.repoId.Cmp(b.repoId), a.refId.Cmp(b.refId), compareIndexKeys(a.docKey, b.docKey))
	})
	return keys
}

// An indexer's mismatches inside RemoteMismatchInterval with one more at now, and whether they reach
// RemoteMismatchCount.
func searchRemoteMismatch(mismatches []time.Time, now time.Time, settings *SidecarSearchSettings) ([]time.Time, bool) {
	since := now.Add(-settings.RemoteMismatchInterval)
	kept := []time.Time{}
	for _, at := range mismatches {
		if at.After(since) {
			kept = append(kept, at)
		}
	}
	kept = append(kept, now)
	return kept, settings.RemoteMismatchCount <= len(kept)
}

// One mismatch against indexerId in repoId: search_alarm{mismatch, indexer, repo}, and past RemoteMismatchCount within
// RemoteMismatchInterval, every claim and span of its legs in this client's open searches void, the indexer distrusted
// RemoteDistrustTimeout, and its repos back to the plan. caller, the search whose step raised it (nil for none), is
// voided at once, under the pageLock its step holds; every other search at its own next step. Answers the keys whose
// rows the voiding changed in caller.
func (self *SearchRemoteClient) mismatch(caller *searchRemoteSearch, indexerId Id, repoId Id) []searchRemoteMergeKey {
	self.raise(SidecarEvent{Kind: SidecarEventSearchAlarm, SearchAlarm: SidecarSearchAlarmMismatch, SidecarId: &indexerId, RepoId: &repoId})
	now := self.clock.Now()
	distrust := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		health := self.healthWithLock(indexerId)
		mismatches, reached := searchRemoteMismatch(health.mismatches, now, self.settings)
		health.mismatches = mismatches
		return reached
	}()
	if !distrust {
		return nil
	}
	if err := self.args.State.SetDistrustUntil(indexerId, now.Add(self.settings.RemoteDistrustTimeout)); err != nil {
		self.log.Warningf("[search]an indexer's distrust was not written: %s", err)
	}
	touched := []searchRemoteMergeKey{}
	for _, search := range self.openSearches() {
		if search == caller {
			touched = append(touched, search.distrust(indexerId)...)
		} else {
			search.queueDistrust(indexerId)
		}
	}
	return touched
}

// Keeps indexerId for this search's next step to void, from another search's step, which holds no lock of this one's.
func (self *searchRemoteSearch) queueDistrust(indexerId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pendingDistrust = append(self.pendingDistrust, indexerId)
}

// Voids what other searches' steps queued, at this search's step.
func (self *searchRemoteSearch) applyDistrust() []searchRemoteMergeKey {
	pending := func() []Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		pending := self.pendingDistrust
		self.pendingDistrust = nil
		return pending
	}()
	touched := []searchRemoteMergeKey{}
	for _, indexerId := range pending {
		touched = append(touched, self.distrust(indexerId)...)
	}
	return touched
}

// Voids every leg of indexerId in this search, its repos back to the plan, as the step that next runs takes them.
func (self *searchRemoteSearch) distrust(indexerId Id) []searchRemoteMergeKey {
	touched := []searchRemoteMergeKey{}
	for _, leg := range self.legs {
		if leg.indexerId != indexerId || leg.source == nil {
			continue
		}
		touched = append(touched, self.merge.voidSource(leg.source)...)
		if leg.state == searchRemoteLegWaiting || leg.state == searchRemoteLegIdle {
			self.endLeg(leg, SearchFallbackRefused, true)
		}
		for repoId := range leg.served {
			if repo := self.repos[repoId]; repo.servedBy == nil && repo.state == searchRemoteRepoServed {
				repo.state = searchRemoteRepoTodo
			}
		}
	}
	return touched
}

// Omission, once leg is done: search_alarm{omission, indexer, repo} for each of the device's own confirmed claims it
// examined at the same pin and did not return. The rows stay as the device's own.
func (self *searchRemoteSearch) raiseOmissions(leg *searchRemoteLeg) []searchRemoteMergeKey {
	if leg.source == nil {
		return nil
	}
	alarmed := map[Id]bool{}
	for _, key := range self.merge.omissions(leg.source) {
		if alarmed[key.repoId] {
			continue
		}
		alarmed[key.repoId] = true
		indexerId, repoId := leg.indexerId, key.repoId
		self.client.raise(SidecarEvent{Kind: SidecarEventSearchAlarm, SearchAlarm: SidecarSearchAlarmOmission, SidecarId: &indexerId, RepoId: &repoId})
	}
	return nil
}

// What the app's open path read of a hit (§3's F12 step 8): an ordinary read at the head, with the read's pin and the
// path's version there, and the version's documents extracted as the index's writer did (DESIGN-DETAILS section 11),
// each with its doc_key under the index's key.
type SearchOpened struct {
	// The read answered dropped (section 10), or the document is erased or masked on this device.
	Dropped bool
	Erased  bool
	// The path's version e at the read's pin, and the pin's version of the content ref.
	Version    uint64
	PinVersion uint64
	// The version's chunks, each with its doc_key. Nil where this device does not link the normalizer and extractor the
	// index's headers name: then no check is made and nothing is raised.
	Documents []SearchOpenedDocument
}

// One chunk of an opened version.
type SearchOpenedDocument struct {
	DocKey   [16]byte
	Document *IndexDocument
}

// Checks an opened hit of a remote search against the query (DESIGN-DETAILS 7.2.6's open check): the row it shows now,
// nil where it went. A stream that is no remote search, or a hit its merge holds no claim of, answers the hit unchanged.
func (self *SearchRemoteClient) CheckOpened(stream *SearchStream, hit SearchHit, opened *SearchOpened) (*SearchHit, error) {
	if stream == nil || opened == nil {
		return &hit, nil
	}
	search, ok := stream.source.(*searchRemoteSearch)
	if !ok {
		return &hit, nil
	}
	return search.checkOpened(hit, opened)
}

// The open check's four rows over the claim the row of hit shows (DESIGN-DETAILS 7.2.6).
func (self *searchRemoteSearch) checkOpened(hit SearchHit, opened *SearchOpened) (*SearchHit, error) {
	self.pageLock.Lock()
	defer self.pageLock.Unlock()
	self.applyDistrust()
	key := searchRemoteMergeKeyOf(&hit)
	if opened.Dropped || opened.Erased {
		self.merge.remove(key)
		return nil, nil
	}
	if self.isClosed() || self.scopeEnded() {
		return nil, ErrSearchCursorExpired
	}
	if self.merge.masked != nil && self.merge.masked(key, hit.Version) {
		return nil, nil
	}
	claim, _ := self.merge.strongest(key)
	if claim == nil {
		if len(self.merge.claims[key]) != 0 {
			return nil, nil
		}
		return &hit, nil
	}
	indexer := claim.source != self.merge.device
	switch {
	case opened.Version == claim.hit.Version:
		if opened.Documents == nil {
			break
		}
		holds, err := self.holdsQuery(key, opened)
		if err != nil {
			return nil, err
		}
		switch {
		case holds:
			// verified by this device as well
			own := claim.hit
			own.State, own.By = SearchVerified, ""
			self.merge.add(nil, []SearchHit{own})
		case indexer && claim.hit.State == SearchVerified:
			self.voidClaim(claim, key)
		}
	case claim.hit.Version < opened.Version:
		// the document changed since the claim: this device judges the version it read, with no alarm
		if opened.Documents == nil {
			break
		}
		holds, err := self.holdsQuery(key, opened)
		if err != nil {
			return nil, err
		}
		if !holds {
			self.merge.remove(key)
			return nil, nil
		}
		own := claim.hit
		own.Version, own.State, own.By = opened.Version, SearchVerified, ""
		self.merge.add(nil, []SearchHit{own})
	default:
		// a claim of a version the read does not reach: false only where it said verified and the read's pin is at or
		// above the version the leg pinned, so no such version existed in its text
		if span := claim.source.spans[key.repoId]; indexer && claim.hit.State == SearchVerified && span != nil && span.pinVersion <= opened.PinVersion {
			self.voidClaim(claim, key)
		}
	}
	return self.merge.row(key), nil
}

// Voids one indexer's claim of key: a mismatch against its indexer, which counts toward distrust.
func (self *searchRemoteSearch) voidClaim(claim *searchRemoteClaim, key searchRemoteMergeKey) {
	delete(self.merge.claims[key], claim.source)
	self.merge.count -= 1
	if len(self.merge.claims[key]) == 0 {
		delete(self.merge.claims, key)
	}
	self.client.mismatch(self, claim.source.indexerId, key.repoId)
}

// Whether the query holds in the opened chunk whose doc_key is key's, by the confirmer's own verification; false where
// no chunk has that doc_key.
func (self *searchRemoteSearch) holdsQuery(key searchRemoteMergeKey, opened *SearchOpened) (bool, error) {
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return false, err
	}
	for _, chunk := range opened.Documents {
		if chunk.DocKey != key.docKey || chunk.Document == nil {
			continue
		}
		confirmer := &searchConfirmer{query: self.parsed, normalizer: normalizer, settings: DefaultSearchResultSettings(), repoId: key.repoId}
		row := chunk.Document.row(0, false, key.refId)
		confirmation, err := confirmer.verify(chunk.Document, &searchRowTexts{normalizer: normalizer, row: row, padded: map[int]string{}})
		if err != nil {
			return false, err
		}
		return confirmation.state == searchMatchVerified, nil
	}
	return false, nil
}
