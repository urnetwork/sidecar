//go:build !sidecar_http && !ios_extension

package sidecar

// SEARCH-M10-34: merging and open checks, DESIGN-DETAILS 7.6's search_remote_merge_test.go list, each twin of
// RemoteMerge.tla on real code: the row by class then version (VersionFirst), no fold over an indexer's claim
// (FoldOverClaims), SkewGuard's bound, omission only at equal pins, the open check's rows, and three mismatches voiding
// an indexer.

import (
	"testing"
	"time"
)

// A merge over one ref whose own index rides the content ref at version ownVersion.
func testSearchRemoteMergeOf(ownVersion uint64, companion bool) *searchRemoteMerge {
	settings := DefaultSidecarSettings().Search
	own := searchRemoteOwnIndex{pin: SearchSyncPin{Version: ownVersion}, companion: companion}
	return newSearchRemoteMerge(settings, func(repoId Id, refId Id) (searchRemoteOwnIndex, bool) { return own, true }, nil)
}

// A claim's hit of document label in repoId at version and timeMs in state.
func testSearchRemoteClaimOf(repoId Id, label string, version uint64, timeMs int64, state SearchHitState) SearchHit {
	return SearchHit{Repo: repoId, Ref: repoId, DocKey: testSearchRemoteKey(label), Version: version, Time: time.UnixMilli(timeMs), State: state}
}

// A leg's source serving repoId from text, pinned at version with refTimeMs, its span checked through checkedMs.
func testSearchRemoteLegOf(merge *searchRemoteMerge, repoId Id, version uint64, refTimeMs int64, checkedMs int64, order int) *searchRemoteSource {
	source := merge.newSource(NewId(), "indexer", order)
	source.spans[repoId] = &searchRemoteSpan{text: true, pinVersion: version, pinChain: make([]byte, 32), refTimeMs: refTimeMs}
	merge.moveSpan(source, []Id{repoId}, checkedMs)
	return source
}

// RemoteMerge's states as a table: each combination of the device's claim and one indexer's, the row it shows.
func TestMergeTable(t *testing.T) {
	repoId := NewId()
	cases := []struct {
		label    string
		own      SearchHitState
		indexer  SearchHitState
		wantBy   bool
		wantRow  SearchHitState
		ownFirst bool
	}{
		{label: "own possible, indexer verified", own: SearchPossible, indexer: SearchVerified, wantBy: true, wantRow: SearchVerified},
		{label: "own confirmed, indexer possible", own: SearchConfirmed, indexer: SearchPossible, wantBy: false, wantRow: SearchConfirmed},
		{label: "own confirmed, indexer verified", own: SearchConfirmed, indexer: SearchVerified, wantBy: true, wantRow: SearchVerified},
		{label: "own near, indexer possible", own: SearchNear, indexer: SearchPossible, wantBy: true, wantRow: SearchPossible},
		{label: "own possible, indexer possible", own: SearchPossible, indexer: SearchPossible, wantBy: true, wantRow: SearchPossible},
		{label: "own possible alone", own: SearchPossible, wantRow: SearchUnmatched, wantBy: true},
		{label: "indexer alone", indexer: SearchConfirmed, wantBy: true, wantRow: SearchConfirmed},
	}
	for _, c := range cases {
		merge := testSearchRemoteMergeOf(5, false)
		source := testSearchRemoteLegOf(merge, repoId, 5, 10_000_000, 0, 0)
		if c.own != 0 {
			merge.add(nil, []SearchHit{testSearchRemoteClaimOf(repoId, "doc", 5, 1_000, c.own)})
		}
		if c.indexer != 0 {
			merge.add(source, []SearchHit{testSearchRemoteClaimOf(repoId, "doc", 5, 1_000, c.indexer)})
		}
		row := merge.row(searchRemoteMergeKey{repoId: repoId, refId: repoId, docKey: testSearchRemoteKey("doc")})
		if row == nil || row.State != c.wantRow || (row.By != "") != c.wantBy {
			t.Errorf("%s: %+v", c.label, row)
		}
	}
}

// RemoteMergeTwin-VersionFirst: an indexer's possible claim of a higher version leaves the device's confirmed row a
// match, and another indexer's verified one too.
func TestAMatchOutranksAHigherVersion(t *testing.T) {
	repoId := NewId()
	merge := testSearchRemoteMergeOf(5, false)
	first := testSearchRemoteLegOf(merge, repoId, 6, 0, 0, 0)
	second := testSearchRemoteLegOf(merge, repoId, 6, 0, 0, 1)
	key := searchRemoteMergeKey{repoId: repoId, refId: repoId, docKey: testSearchRemoteKey("note")}
	merge.add(nil, []SearchHit{testSearchRemoteClaimOf(repoId, "note", 5, 1_000, SearchConfirmed)})
	merge.add(first, []SearchHit{testSearchRemoteClaimOf(repoId, "note", 6, 1_000, SearchPossible)})
	if row := merge.row(key); row.State != SearchConfirmed || row.Version != 5 || row.By != "" {
		t.Errorf("a higher possible version demoted the device's confirmed row: %+v", row)
	}
	merge.add(first, []SearchHit{testSearchRemoteClaimOf(repoId, "note", 5, 1_000, SearchVerified)})
	merge.add(second, []SearchHit{testSearchRemoteClaimOf(repoId, "note", 7, 1_000, SearchPossible)})
	if row := merge.row(key); row.State != SearchVerified || row.By == "" {
		t.Errorf("another indexer demoted a verified row: %+v", row)
	}
}

// RemoteMergeTwin-FoldOverClaims: a document an indexer claims in any state is never folded, though a span holds the
// device's possible claim of it.
func TestAClaimedDocumentIsNeverFolded(t *testing.T) {
	repoId := NewId()
	merge := testSearchRemoteMergeOf(5, false)
	source := testSearchRemoteLegOf(merge, repoId, 5, 10_000_000, 0, 0)
	key := searchRemoteMergeKey{repoId: repoId, refId: repoId, docKey: testSearchRemoteKey("doc")}
	merge.add(nil, []SearchHit{testSearchRemoteClaimOf(repoId, "doc", 5, 1_000, SearchPossible)})
	if row := merge.row(key); row.State != SearchUnmatched {
		t.Fatalf("an unclaimed possible match inside the span: %+v", row)
	}
	merge.add(source, []SearchHit{testSearchRemoteClaimOf(repoId, "doc", 5, 1_000, SearchNear)})
	if row := merge.row(key); row.State == SearchUnmatched {
		t.Errorf("a claimed document folded: %+v", row)
	}
}

// QD-709's bound: with a companion index, or the device's pin above the leg's, a possible match folds only more than
// SkewGuard below the pinned version's time: 41 minutes below folds, 39 does not.
func TestTheFoldHoldsSkewGuard(t *testing.T) {
	repoId := NewId()
	refTimeMs := int64(100 * 60 * 1000)
	for _, c := range []struct {
		label     string
		companion bool
		ownPin    uint64
	}{
		{label: "a companion index", companion: true, ownPin: 5},
		{label: "the device ahead", companion: false, ownPin: 9},
	} {
		merge := testSearchRemoteMergeOf(c.ownPin, c.companion)
		testSearchRemoteLegOf(merge, repoId, 5, refTimeMs, 0, 0)
		merge.add(nil, []SearchHit{
			testSearchRemoteClaimOf(repoId, "inside", 1, refTimeMs-41*60*1000, SearchPossible),
			testSearchRemoteClaimOf(repoId, "skewed", 1, refTimeMs-39*60*1000, SearchPossible),
		})
		inside := merge.row(searchRemoteMergeKey{repoId: repoId, refId: repoId, docKey: testSearchRemoteKey("inside")})
		skewed := merge.row(searchRemoteMergeKey{repoId: repoId, refId: repoId, docKey: testSearchRemoteKey("skewed")})
		if inside.State != SearchUnmatched || skewed.State != SearchPossible {
			t.Errorf("%s: 41 minutes below %v, 39 minutes below %v", c.label, inside.State, skewed.State)
		}
	}
	// the device's pin at or below the leg's, the index riding the content ref: the span holds whatever the time
	merge := testSearchRemoteMergeOf(5, false)
	testSearchRemoteLegOf(merge, repoId, 5, refTimeMs, 0, 0)
	merge.add(nil, []SearchHit{testSearchRemoteClaimOf(repoId, "recent", 1, refTimeMs-60*1000, SearchPossible)})
	if row := merge.row(searchRemoteMergeKey{repoId: repoId, refId: repoId, docKey: testSearchRemoteKey("recent")}); row.State != SearchUnmatched {
		t.Errorf("at equal pins a recent possible match did not fold: %v", row.State)
	}
}

// Omission only where both judged one version: a confirmed own claim the leg passed over at an equal pin and chain;
// none when the pins differ, a field was cut, or the claim lies below the span.
func TestOmissionOnlyAtEqualPins(t *testing.T) {
	repoId := NewId()
	for _, c := range []struct {
		label     string
		ownPin    uint64
		cut       bool
		timeMs    int64
		omissions int
	}{
		{label: "equal pins", ownPin: 5, timeMs: 5_000, omissions: 1},
		{label: "the device ahead", ownPin: 6, timeMs: 5_000},
		{label: "the device behind", ownPin: 4, timeMs: 5_000},
		{label: "a cut field", ownPin: 5, cut: true, timeMs: 5_000},
		{label: "below the span", ownPin: 5, timeMs: 500},
	} {
		merge := testSearchRemoteMergeOf(c.ownPin, false)
		source := testSearchRemoteLegOf(merge, repoId, 5, 10_000, 1_000, 0)
		merge.ownIndex = func(Id, Id) (searchRemoteOwnIndex, bool) {
			return searchRemoteOwnIndex{pin: SearchSyncPin{Version: c.ownPin}}, true
		}
		hit := testSearchRemoteClaimOf(repoId, "title match", 5, c.timeMs, SearchConfirmed)
		hit.Cut = c.cut
		merge.add(nil, []SearchHit{hit})
		if got := len(merge.omissions(source)); got != c.omissions {
			t.Errorf("%s: %d omissions", c.label, got)
		}
	}
}

// The pin check: a coverage pin in the device's ring with another chain forks; above its pin waits; equal passes.
func TestThePinCheck(t *testing.T) {
	repoId := NewId()
	merge := testSearchRemoteMergeOf(7, false)
	ring := []SearchSyncPinPair{{Version: 6, Chain: [32]byte{6}}, {Version: 7, Chain: [32]byte{7}}}
	merge.ownIndex = func(Id, Id) (searchRemoteOwnIndex, bool) {
		return searchRemoteOwnIndex{pin: SearchSyncPin{Version: 7, Chain: [32]byte{7}}, ring: ring}, true
	}
	check := func(version uint64, chain byte) (bool, bool) {
		source := merge.newSource(NewId(), "indexer", 0)
		pinChain := make([]byte, 32)
		pinChain[0] = chain
		source.spans[repoId] = &searchRemoteSpan{text: true, pinVersion: version, pinChain: pinChain}
		return merge.checkPin(source, repoId, repoId)
	}
	if forked, waiting := check(6, 6); forked || waiting {
		t.Errorf("an equal chain: forked %v, waiting %v", forked, waiting)
	}
	if forked, _ := check(6, 9); !forked {
		t.Errorf("another chain at a version in the ring did not fork")
	}
	if _, waiting := check(9, 9); !waiting {
		t.Errorf("a version above the device's pin did not wait")
	}
	if forked, waiting := check(2, 9); forked || waiting {
		t.Errorf("below the ring: forked %v, waiting %v", forked, waiting)
	}
}

// 7.2.6's open check over a remote search served by Dana's NAS: a verified claim whose opened chunk does not hold the
// query alarms mismatch and goes; one whose chunk holds it is verified by the device as well; a dropped read takes the
// row with no alarm; a newer version is the device's own judgment, with no alarm.
func TestOpenCheckTable(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	docs := testSearchRemoteDocs("doc ", 900, 800, 700, 600)
	fixture.serve(t, team.danaNas).corpus.serveText(team.danaVault, 5, docs...)
	stream := fixture.search(t, team.danaVault)
	page := testSearchRemoteNext(t, stream)
	if len(page.hits) != 4 {
		t.Fatalf("hits %d", len(page.hits))
	}
	opened := func(hit SearchHit, version uint64, body string) *SearchOpened {
		document := &IndexDocument{Kind: IndexDocFile, Name: []byte(hit.Path), Version: version}
		document.Fields[indexFieldBody] = []byte(body)
		return &SearchOpened{Version: version, PinVersion: 5, Documents: []SearchOpenedDocument{{DocKey: hit.DocKey, Document: document}}}
	}
	if row, err := fixture.client.CheckOpened(stream, page.hits[0], opened(page.hits[0], 1, "the plan for the quarter")); err != nil || row == nil || row.State != SearchVerified {
		t.Errorf("a holding chunk: %+v, %v", row, err)
	}
	row, err := fixture.client.CheckOpened(stream, page.hits[1], opened(page.hits[1], 1, "nothing of the kind"))
	if err != nil || row != nil {
		t.Errorf("a verified claim the text disproves stayed: %+v, %v", row, err)
	}
	if alarms := fixture.alarms(SidecarEventSearchAlarm); len(alarms) != 1 || alarms[0].SearchAlarm != SidecarSearchAlarmMismatch {
		t.Errorf("alarms %v", alarms)
	}
	if row, err := fixture.client.CheckOpened(stream, page.hits[2], &SearchOpened{Dropped: true}); err != nil || row != nil {
		t.Errorf("a dropped read: %+v, %v", row, err)
	}
	if row, err := fixture.client.CheckOpened(stream, page.hits[3], opened(page.hits[3], 2, "a newer plan")); err != nil || row == nil || row.Version != 2 || row.By != "" {
		t.Errorf("a newer version: %+v, %v", row, err)
	}
	if alarms := fixture.alarms(SidecarEventSearchAlarm); len(alarms) != 1 {
		t.Errorf("%d alarms after the rows that raise none", len(alarms))
	}
}

// RemoteMismatchCount mismatches within RemoteMismatchInterval distrust the indexer RemoteDistrustTimeout: it is not
// asked, and search.state keeps the deadline.
func TestThreeMismatchesVoidTheIndexer(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	nas := team.danaNas.sidecarId
	for i := 0; i < fixture.settings.RemoteMismatchCount; i += 1 {
		fixture.client.mismatch(nil, nas, team.danaVault)
	}
	until, err := fixture.world.state.DistrustUntil(nas)
	if err != nil || until.IsZero() {
		t.Fatalf("no distrust: %v", err)
	}
	if fixture.client.usable(team.net.log.State(), nas, team.danaVault, map[Id]bool{}, fixture.clock.Now()) {
		t.Errorf("a distrusted indexer is usable")
	}
	if alarms := fixture.alarms(SidecarEventSearchAlarm); len(alarms) != fixture.settings.RemoteMismatchCount {
		t.Errorf("%d alarms", len(alarms))
	}
}
