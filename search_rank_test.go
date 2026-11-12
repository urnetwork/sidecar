// Confirmation and ranking (SEARCH-M10-24): verification against this host's text and confirmation from display
// fields, phrases a candidate assembles by chance, exclusions only where confirmed, field-scoped terms against the
// row, mail's i/ snippet, the rank tiers on a fixed set with the J formula and its ties, the lazy walk and its "about
// n", too_broad's header-confirmed hits, near hits after possible ones, phases that never revise a page, and the
// orders by path and density.

package sidecar

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A text source over contents by "path@version", for a repo of kind.
func testSearchTextSource(contents map[string][]byte, kind protocol.RepoKind) *SearchContentTextSource {
	return &SearchContentTextSource{
		Content: func(ctx context.Context, repoId Id, refId Id, path []byte, version uint64) ([]byte, bool, error) {
			content, ok := contents[fmt.Sprintf("%s@%d", path, version)]
			return content, ok, nil
		},
		Place: func(repoId Id) (protocol.RepoKind, bool) {
			return kind, false
		},
	}
}

// A display source over snippets by locator.
type testSearchDisplays map[string]*SearchDisplay

func (self testSearchDisplays) SearchDisplay(ctx context.Context, request *SearchTextRequest) (*SearchDisplay, bool, error) {
	display, ok := self[string(request.Name)]
	return display, ok, nil
}

// A version's entry as its writer builds it from content: extractor 1 for files or mail, chunk 0.
func testSearchEntryOfContent(t testing.TB, refKey []byte, refId Id, kind IndexDocKind, path string, content []byte, version uint64, time uint64) *indexEntry {
	t.Helper()
	var documents []*IndexDocument
	if kind == IndexDocMail {
		documents = indexExtractMail([]byte(path), content, DefaultIndexFormatSettings())
	} else {
		var ok bool
		if documents, ok = indexExtractFile([]byte(path), content, DefaultIndexFormatSettings()); !ok {
			t.Fatalf("%s is no text", path)
		}
	}
	prepared, err := documents[0].prepare(testSearchNormalizer(t), false, refId)
	if err != nil {
		t.Fatal(err)
	}
	key, err := indexDocKey(refKey, refId, []byte(path), 0)
	if err != nil {
		t.Fatal(err)
	}
	return &indexEntry{kind: indexEntryFull, key: key, version: version, timeSeconds: time, row: prepared.row, keys: prepared.keys}
}

// Ranks one partition of entries for query on a host with the text source and display source given, either nil.
func testRankEntries(t testing.TB, query string, text SearchTextSource, display SearchDisplaySource, entries ...*indexEntry) ([]*searchRankedHit, searchRankCounts) {
	t.Helper()
	run := newTestSearchRun(t, query)
	repoId, refId := evsTestId("rank repo"), evsTestId("rank ref")
	table := testVersionTableOf(testSearchRecords(entries...))
	source := run.source(repoId, refId, &searchMaskArgs{probe: table.probe, refId: refId}, text, display)
	return run.all(run.inputs(source, testSearchSlotPartition(searchPartitionCurrent, entries...)))
}

// The hits' locators, in order.
func testHitLocators(hits []*searchRankedHit) []string {
	locators := []string{}
	for _, hit := range hits {
		locators = append(locators, hit.row.locator)
	}
	return locators
}

// A host with the text verifies: a document holding the phrase is verified with a snippet around it; one whose
// trigrams assemble the phrase by chance is dropped; an excluded term the text holds drops its document. The same
// candidates on a host without the text are possible, the excluded term unconfirmed and so dropping nothing.
func TestSearchConfirmWithAndWithoutText(t *testing.T) {
	refKey, refId := testSearchRefKey("confirm"), evsTestId("rank ref")
	filler := strings.Repeat("Nothing to see in this line of the report. ", 30)
	contents := map[string][]byte{
		"notes/true.md@3":     []byte("# Fruit\n" + filler + "We picked a red apple at noon.\n" + filler),
		"notes/chance.md@4":   []byte("# Fruit\nThe red ant crawled onto an apple.\n"),
		"notes/excluded.md@5": []byte("# Fruit\nA red apple and a banana.\n"),
	}
	entries := []*indexEntry{}
	for index, name := range []string{"notes/true.md", "notes/chance.md", "notes/excluded.md"} {
		version := uint64(3 + index)
		entries = append(entries, testSearchEntryOfContent(t, refKey, refId, IndexDocFile, name, contents[fmt.Sprintf("%s@%d", name, version)], version, uint64(1800000000+index)))
	}

	hits, counts := testRankEntries(t, `"red apple" -banana`, testSearchTextSource(contents, protocol.RepoKind_REPO_KIND_GENERAL), nil, entries...)
	if locators := testHitLocators(hits); !slices.Equal(locators, []string{"notes/true.md"}) {
		t.Fatalf("verified %v", locators)
	}
	hit := hits[0]
	if hit.match != searchMatchVerified || !strings.Contains(hit.snippet, "red apple") || DefaultSearchResultSettings().SnippetMaxByteCount < len(hit.snippet) {
		t.Errorf("match %d, snippet %q", hit.match, hit.snippet)
	}
	if counts.rejected != 2 || counts.matches != 1 || counts.pending != 0 {
		t.Errorf("counts %+v", counts)
	}

	hits, counts = testRankEntries(t, `"red apple" -banana`, nil, nil, entries...)
	if len(hits) != 3 || counts.possible != 3 {
		t.Fatalf("without the text: %v, %+v", testHitLocators(hits), counts)
	}
	for _, hit := range hits {
		if hit.match != searchMatchPossible || hit.snippet != "" {
			t.Errorf("%s: match %d, snippet %q", hit.row.locator, hit.match, hit.snippet)
		}
	}
}

// Without the text, a term in a display field confirms by field, a term only in the body leaves a hit possible, an
// excluded term in a display field drops its hit, and a field-scoped term is judged on the row: held, absent from an
// uncut field and so false, or unknown where its field was cut at its cap. Mail's i/ snippet confirms too, and the hit
// carries it.
func TestSearchConfirmFromDisplayFields(t *testing.T) {
	refKey, refId := testSearchRefKey("display"), evsTestId("rank ref")
	month := MailYearMonth(202611)
	message := func(index int, subject string, body string) (string, []byte) {
		return MailMessagePath(month, evsTestId(fmt.Sprintf("message %d", index))),
			[]byte("From: Ann <ann@example.com>\r\nSubject: " + subject + "\r\n\r\n" + body + "\r\n")
	}
	pathA, mailA := message(1, "Invoice 42", "please pay the invoice")
	pathB, mailB := message(2, "Receipt", "the invoice is attached")
	pathC, mailC := message(3, strings.Repeat("long subject ", 20)+"invoice", "see the invoice")
	pathD, mailD := message(4, "Hello", "your invoice is ready")
	entries := []*indexEntry{
		testSearchEntryOfContent(t, refKey, refId, IndexDocMail, pathA, mailA, 1, 1800000400),
		testSearchEntryOfContent(t, refKey, refId, IndexDocMail, pathB, mailB, 1, 1800000300),
		testSearchEntryOfContent(t, refKey, refId, IndexDocMail, pathC, mailC, 1, 1800000200),
		testSearchEntryOfContent(t, refKey, refId, IndexDocMail, pathD, mailD, 1, 1800000100),
	}
	if entries[2].row.flags&indexRowCutFlag(indexFieldSubject) == 0 {
		t.Fatal("the long subject was not cut")
	}
	displays := testSearchDisplays{pathD: {Address: "me@example.com", Snippet: "your invoice is ready"}}

	hits, _ := testRankEntries(t, "subject:invoice", nil, displays, entries...)
	if locators := testHitLocators(hits); !slices.Equal(locators, []string{pathA, pathC}) || hits[0].match != searchMatchConfirmed || hits[1].match != searchMatchPossible {
		t.Fatalf("subject:invoice gave %v", testHitLocators(hits))
	}

	hits, counts := testRankEntries(t, "invoice", nil, displays, entries...)
	matches := map[string]searchMatchState{}
	for _, hit := range hits {
		matches[hit.row.locator] = hit.match
	}
	if matches[pathA] != searchMatchConfirmed || matches[pathB] != searchMatchPossible || matches[pathD] != searchMatchConfirmed {
		t.Errorf("invoice gave %v, %+v", matches, counts)
	}
	for _, hit := range hits {
		if hit.row.locator == pathD && hit.snippet != "your invoice is ready" {
			t.Errorf("the i/ snippet %q", hit.snippet)
		}
	}

	hits, _ = testRankEntries(t, "invoice -receipt", nil, displays, entries...)
	if slices.Contains(testHitLocators(hits), pathB) || len(hits) != 3 {
		t.Errorf("an excluded term in the subject left %v", testHitLocators(hits))
	}
	hits, _ = testRankEntries(t, "invoice -attached", nil, displays, entries...)
	if !slices.Contains(testHitLocators(hits), pathB) {
		t.Error("an excluded term only in the body dropped a hit this host cannot check")
	}
}

// The tiers on a fixed set, on a host without the text: matches confirmed by title newest first, then possible ones by
// J = |T(q)| / n_d, fewest distinct trigrams first, equal counts newest first.
func TestSearchRankTiersAndOverlap(t *testing.T) {
	refKey, refId := testSearchRefKey("tiers"), evsTestId("rank ref")
	entry := func(path string, title string, body string, time uint64) *indexEntry {
		return testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: path, title: title, body: body, version: 1, time: time})
	}
	entries := []*indexEntry{
		entry("x/a.md", "Budget review", "", 1800000300),
		entry("x/b.md", "The budget plan", "", 1800000500),
		entry("y/c.md", "", "the budget", 1800000100),
		entry("y/d.md", "", strings.Repeat("many different words fill this budget report ", 4)+"zebra quokka", 1800000900),
		entry("y/e.md", "", "the budget", 1800000200),
	}
	hits, counts := testRankEntries(t, "budget", nil, nil, entries...)
	want := []string{"x/b.md", "x/a.md", "y/e.md", "y/c.md", "y/d.md"}
	if locators := testHitLocators(hits); !slices.Equal(locators, want) {
		t.Fatalf("ranked %v, want %v", locators, want)
	}
	if counts.matches != 2 || counts.possible != 3 {
		t.Errorf("counts %+v", counts)
	}
	queryTrigrams := float64(len(indexTrigrams([]byte("budget"))))
	for _, hit := range hits {
		if want := queryTrigrams / float64(hit.row.trigramCount); math.Abs(hit.overlap-want) > 1e-12 || hit.trigramCount != int(hit.row.trigramCount) {
			t.Errorf("%s: J %v, want %v", hit.row.locator, hit.overlap, want)
		}
	}
	if hits[2].trigramCount != hits[3].trigramCount || hits[3].trigramCount >= hits[4].trigramCount {
		t.Errorf("the possible tier's counts %d %d %d", hits[2].trigramCount, hits[3].trigramCount, hits[4].trigramCount)
	}
}

// The walk is lazy: a page checks candidates only until it is full and reads "about n" while some wait; a page holds
// no more than Search.PageCandidateCount checks; the next page goes on where the last stopped, never repeating a hit.
func TestSearchRankWalksLazily(t *testing.T) {
	refKey, refId := testSearchRefKey("lazy"), evsTestId("rank ref")
	entries := []*indexEntry{}
	for index := range 120 {
		entries = append(entries, testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: fmt.Sprintf("d/%03d.md", index), title: "Budget note", version: 1, time: uint64(1800000000 + index)}))
	}
	run := newTestSearchRun(t, "budget")
	run.search.PageCandidateCount = 30
	repoId := evsTestId("rank repo")
	table := testVersionTableOf(testSearchRecords(entries...))
	source := run.source(repoId, refId, &searchMaskArgs{probe: table.probe, refId: refId}, nil, nil)
	ranker, err := newSearchRanker(&searchRankerArgs{settings: run.settings, search: run.search, query: run.query})
	if err != nil {
		t.Fatal(err)
	}
	if err := ranker.beginPhase(run.inputs(source, testSearchSlotPartition(searchPartitionCurrent, entries...))); err != nil {
		t.Fatal(err)
	}
	page, err := ranker.page(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.hits) != 20 || table.probes != 20 || page.counts.pending != 100 || page.exactDone {
		t.Fatalf("first page: %d hits, %d probes, %d pending", len(page.hits), table.probes, page.counts.pending)
	}
	if page.hits[0].row.locator != "d/119.md" {
		t.Errorf("the first hit is %s, not the newest", page.hits[0].row.locator)
	}
	given := map[string]bool{}
	for _, hit := range page.hits {
		given[hit.row.locator] = true
	}
	page, err = ranker.page(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.hits) != 30 || page.counts.pending != 70 {
		t.Errorf("a page past PageCandidateCount: %d hits, %d pending", len(page.hits), page.counts.pending)
	}
	for range 10 {
		for _, hit := range page.hits {
			if given[hit.row.locator] {
				t.Fatalf("%s given twice", hit.row.locator)
			}
			given[hit.row.locator] = true
		}
		if page.exactDone && !page.phaseDone {
			if err := ranker.settleNear(nil, "", 0); err != nil {
				t.Fatal(err)
			}
		}
		if page.phaseDone {
			break
		}
		if page, err = ranker.page(context.Background(), 50); err != nil {
			t.Fatal(err)
		}
	}
	if len(given) != 120 || !page.phaseDone {
		t.Errorf("%d hits given, phase done %v", len(given), page.phaseDone)
	}
}

// A too-broad partition's candidates are confirmed from their rows alone: header-confirmed hits are given, the rest
// counted, and no text is read for them.
func TestSearchRankTooBroadGivesHeaderConfirmedHits(t *testing.T) {
	refKey, refId := testSearchRefKey("broad"), evsTestId("rank ref")
	contents := map[string][]byte{}
	entries := []*indexEntry{}
	for index := range 6 {
		title := "Weekly notes"
		if index%2 == 0 {
			title = "Weekly budget"
		}
		path := fmt.Sprintf("w/%d.md", index)
		content := []byte("# " + title + "\nthe budget figures\n")
		contents[path+"@1"] = content
		entries = append(entries, testSearchEntryOfContent(t, refKey, refId, IndexDocFile, path, content, 1, uint64(1800000000+index)))
	}
	run := newTestSearchRun(t, "budget")
	repoId := evsTestId("rank repo")
	table := testVersionTableOf(testSearchRecords(entries...))
	reads := 0
	text := testSearchTextSource(contents, protocol.RepoKind_REPO_KIND_GENERAL)
	content := text.Content
	text.Content = func(ctx context.Context, repoId Id, refId Id, path []byte, version uint64) ([]byte, bool, error) {
		reads += 1
		return content(ctx, repoId, refId, path, version)
	}
	source := run.source(repoId, refId, &searchMaskArgs{probe: table.probe, refId: refId}, text, nil)
	inputs := run.inputs(source, testSearchSlotPartition(searchPartitionCurrent, entries...))
	inputs[0].result.tooBroad = true
	inputs[0].result.candidateCount = 25000
	hits, counts := run.all(inputs)
	if len(hits) != 3 || reads != 0 || !counts.tooBroad || counts.tooBroadUncounted != 25000-6 || counts.rejected != 3 {
		t.Fatalf("%d hits, %d text reads, %+v", len(hits), reads, counts)
	}
	for _, hit := range hits {
		if hit.match != searchMatchConfirmed || !strings.Contains(hit.row.fields[indexFieldTitle], "budget") {
			t.Errorf("%s: match %d", hit.row.locator, hit.match)
		}
	}
}

// Near hits come after the possible tier, ranked by J against the corrected query and carrying the correction; a
// document already given is not given again as a near hit; and the phase waits for near hits to be settled.
func TestSearchRankNearHitsComeLast(t *testing.T) {
	refKey, refId := testSearchRefKey("near"), evsTestId("rank ref")
	entry := func(path string, title string, body string, time uint64) *indexEntry {
		return testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: path, title: title, body: body, version: 1, time: time})
	}
	exact := entry("a.md", "Recieve notes", "", 1800000100)
	nearShort := entry("b.md", "", "receive", 1800000200)
	nearLong := entry("c.md", "", "please receive the long letter with many words", 1800000300)
	both := entry("d.md", "Recieve and receive", "", 1800000050)
	entries := []*indexEntry{exact, nearShort, nearLong, both}
	run := newTestSearchRun(t, "recieve")
	repoId := evsTestId("rank repo")
	table := testVersionTableOf(testSearchRecords(entries...))
	source := run.source(repoId, refId, &searchMaskArgs{probe: table.probe, refId: refId}, nil, nil)
	ranker, err := newSearchRanker(&searchRankerArgs{settings: run.settings, search: run.search, query: run.query})
	if err != nil {
		t.Fatal(err)
	}
	if err := ranker.beginPhase(run.inputs(source, testSearchSlotPartition(searchPartitionCurrent, entries...))); err != nil {
		t.Fatal(err)
	}
	page, err := ranker.page(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if locators := testHitLocators(page.hits); !slices.Equal(locators, []string{"a.md", "d.md"}) || !page.exactDone || page.phaseDone {
		t.Fatalf("exact hits %v, done %v %v", locators, page.exactDone, page.phaseDone)
	}

	corrected := newTestSearchRun(t, "receive")
	nearSource := corrected.source(repoId, refId, &searchMaskArgs{probe: table.probe, refId: refId}, nil, nil)
	if err := ranker.settleNear(corrected.inputs(nearSource, testSearchSlotPartition(searchPartitionCurrent, entries...)), "receive", len(corrected.query.trigrams())); err != nil {
		t.Fatal(err)
	}
	page, err = ranker.page(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if locators := testHitLocators(page.hits); !slices.Equal(locators, []string{"b.md", "c.md"}) || !page.phaseDone {
		t.Fatalf("near hits %v, phase done %v", locators, page.phaseDone)
	}
	for _, hit := range page.hits {
		if !hit.near || hit.correction != "receive" || hit.overlap != float64(len(corrected.query.trigrams()))/float64(hit.trigramCount) {
			t.Errorf("%s: near %v, correction %q, J %v", hit.row.locator, hit.near, hit.correction, hit.overlap)
		}
	}
	if err := ranker.settleNear(nil, "", 0); err == nil {
		t.Error("near hits settled twice")
	}
}

// Phase 2 never revises phase 1: a document phase 1 gave is not given again from all, and phase 2's hits follow.
func TestSearchRankPhasesNeverRepeat(t *testing.T) {
	refKey, refId := testSearchRefKey("phases"), evsTestId("rank ref")
	entry := func(path string, time uint64) *indexEntry {
		return testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: path, title: "Budget", version: 1, time: time})
	}
	recent := entry("recent.md", 1800000900)
	both := entry("both.md", 1800000500)
	old := entry("old.md", 1700000000)
	run := newTestSearchRun(t, "budget")
	repoId := evsTestId("rank repo")
	table := testVersionTableOf(testSearchRecords(recent, both, old))
	source := run.source(repoId, refId, &searchMaskArgs{probe: table.probe, refId: refId}, nil, nil)
	ranker, err := newSearchRanker(&searchRankerArgs{settings: run.settings, search: run.search, query: run.query})
	if err != nil {
		t.Fatal(err)
	}
	pages := func() []string {
		locators := []string{}
		for range 10 {
			page, err := ranker.page(context.Background(), 1)
			if err != nil {
				t.Fatal(err)
			}
			locators = append(locators, testHitLocators(page.hits)...)
			if page.exactDone && !page.phaseDone && !ranker.nearSettled {
				if err := ranker.settleNear(nil, "", 0); err != nil {
					t.Fatal(err)
				}
			}
			if page.phaseDone {
				return locators
			}
		}
		t.Fatal("a phase that never ends")
		return nil
	}
	if err := ranker.beginPhase(run.inputs(source, testSearchSlotPartition(searchPartitionCurrent, recent, both))); err != nil {
		t.Fatal(err)
	}
	if locators := pages(); !slices.Equal(locators, []string{"recent.md", "both.md"}) {
		t.Fatalf("phase 1 gave %v", locators)
	}
	if err := ranker.beginPhase(run.inputs(source, testSearchShardPartition(t, false, both, old))); err != nil {
		t.Fatal(err)
	}
	if locators := pages(); !slices.Equal(locators, []string{"old.md"}) {
		t.Fatalf("phase 2 gave %v", locators)
	}
	if ranker.phase != 2 {
		t.Errorf("phase %d", ranker.phase)
	}
}

// By path, matches in a header field or the path come first, then by path; by density, the text's matches a KiB.
func TestSearchRankByPathAndDensity(t *testing.T) {
	refKey, refId := testSearchRefKey("orders"), evsTestId("rank ref")
	contents := map[string][]byte{
		"b/budget.md@1": []byte("# Plans\nsome text\n"),
		"a/notes.md@1":  []byte("# Notes\na budget, a budget, a budget\n"),
		"c/long.md@1":   []byte("# Notes\nthe budget " + strings.Repeat("and many other words here ", 40) + "\n"),
	}
	entries := []*indexEntry{}
	for index, path := range []string{"b/budget.md", "a/notes.md", "c/long.md"} {
		entries = append(entries, testSearchEntryOfContent(t, refKey, refId, IndexDocFile, path, contents[path+"@1"], 1, uint64(1800000000+index)))
	}
	for _, c := range []struct {
		order searchRankOrder
		want  []string
	}{
		{order: searchRankByTime, want: []string{"c/long.md", "a/notes.md", "b/budget.md"}},
		{order: searchRankByPath, want: []string{"b/budget.md", "a/notes.md", "c/long.md"}},
		{order: searchRankByDensity, want: []string{"a/notes.md", "b/budget.md", "c/long.md"}},
	} {
		run := newTestSearchRun(t, "budget")
		run.order = c.order
		repoId := evsTestId("rank repo")
		table := testVersionTableOf(testSearchRecords(entries...))
		source := run.source(repoId, refId, &searchMaskArgs{probe: table.probe, refId: refId}, testSearchTextSource(contents, protocol.RepoKind_REPO_KIND_GENERAL), nil)
		hits, _ := run.all(run.inputs(source, testSearchSlotPartition(searchPartitionCurrent, entries...)))
		if locators := testHitLocators(hits); !slices.Equal(locators, c.want) {
			t.Errorf("order %d: %v, want %v", c.order, locators, c.want)
		}
	}
}

// §16.10's doc-table filters: times before any row is read, then path prefix, doc kind and fields on the row.
func TestSearchConfirmFilters(t *testing.T) {
	refKey, refId := testSearchRefKey("filters"), evsTestId("rank ref")
	entry := func(path string, title string, time uint64) *indexEntry {
		return testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: path, title: title, version: 1, time: time})
	}
	entries := []*indexEntry{
		entry("src/a.md", "Budget alpha", 1800000100),
		entry("src/b.md", "Budget beta", 1800000200),
		entry("doc/c.md", "Budget gamma", 1800000300),
		entry("src/d.md", "Budget delta", 1700000000),
	}
	run := newTestSearchRun(t, "budget")
	repoId := evsTestId("rank repo")
	table := testVersionTableOf(testSearchRecords(entries...))
	source := run.source(repoId, refId, &searchMaskArgs{probe: table.probe, refId: refId}, nil, nil)
	beta, ok, err := searchNewTerm(run.normalizer, "BETA")
	if err != nil || !ok {
		t.Fatal(err)
	}
	source.confirmer.filters = &searchRowFilters{
		sinceSeconds: 1750000000,
		pathPrefix:   "src/",
		docKinds:     []indexDocKind{indexDocFile},
		fields:       []*searchFieldFilter{{field: indexFieldTitle, term: beta}},
	}
	hits, counts := run.all(run.inputs(source, testSearchSlotPartition(searchPartitionCurrent, entries...)))
	if locators := testHitLocators(hits); !slices.Equal(locators, []string{"src/b.md"}) || counts.filtered != 1 || counts.rejected != 2 {
		t.Fatalf("filtered to %v, %+v", testHitLocators(hits), counts)
	}
	if !(&searchRowFilters{untilSeconds: 10}).timeHolds(10) || (&searchRowFilters{untilSeconds: 10}).timeHolds(11) {
		t.Error("until is inclusive")
	}
}

// m/ paths parse back to their month and id exactly as MailMessagePath spells them, and nothing else does.
func TestSearchMailMessagePaths(t *testing.T) {
	month := MailYearMonth(202611)
	messageId := evsTestId("a message")
	path := MailMessagePath(month, messageId)
	gotMonth, gotId, ok := searchMailMessageOf([]byte(path))
	if !ok || gotMonth != month || gotId != messageId {
		t.Fatalf("%s gave %v %v %v", path, gotMonth, gotId, ok)
	}
	parts := strings.Split(path, "/")
	for _, bad := range []string{"", "m/202611", "i/202611/" + parts[2] + "/" + parts[3], "m/202613/" + parts[2] + "/" + parts[3], "m/202611/zz/" + parts[3], path + "/x"} {
		if _, _, ok := searchMailMessageOf([]byte(bad)); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	if _, ok, err := (&SearchMailDisplay{}).SearchDisplay(context.Background(), &SearchTextRequest{Kind: IndexDocMail, Name: []byte(path)}); ok || err != nil {
		t.Error("a display with no view answered")
	}
}

// Settings no search can run on are refused, and the defaults pass with the wire's snippet cap.
func TestSearchResultSettingsCheck(t *testing.T) {
	if err := DefaultSearchResultSettings().check(); err != nil {
		t.Fatal(err)
	}
	if DefaultSearchResultSettings().SnippetMaxByteCount != DefaultSearchWireSettings().SnippetMaxByteCount {
		t.Error("the snippet cap is not the wire's")
	}
	for _, change := range []func(settings *SearchResultSettings){
		func(settings *SearchResultSettings) { settings.ConfirmPageHitCount = 0 },
		func(settings *SearchResultSettings) { settings.SnippetMaxByteCount = 4 },
		func(settings *SearchResultSettings) { settings.SnippetBlockByteCount = settings.SnippetMaxByteCount },
		func(settings *SearchResultSettings) { settings.NearHitSimilarity = 0 },
		func(settings *SearchResultSettings) { settings.NearHitSimilarity = 1.5 },
		func(settings *SearchResultSettings) { settings.LocalLayerByteCount = 0 },
	} {
		settings := DefaultSearchResultSettings()
		change(settings)
		if settings.check() == nil {
			t.Errorf("%+v passed", settings)
		}
	}
}
