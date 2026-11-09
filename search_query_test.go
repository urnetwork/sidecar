// The query grammar and the plan (SEARCH-M10-22): each form of §16.10's query row, the limits at 512 B and 16 terms,
// whole words of one and two bytes, CJK runs, and the plan's partitions, order, scopes and statuses.

package sidecar

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// A term as a test expects it: its field, field name, phrase mark and normalized text.
type testTerm struct {
	field      int
	fieldName  string
	phrase     bool
	normalized string
}

// The terms of a query's groups and exclusions, flattened for comparison.
func testTermsOf(terms []*SearchTerm) []testTerm {
	flattened := []testTerm{}
	for _, term := range terms {
		flattened = append(flattened, testTerm{field: term.Field, fieldName: term.FieldName, phrase: term.Phrase, normalized: term.normalized})
	}
	return flattened
}

func TestSearchQueryForms(t *testing.T) {
	cases := []struct {
		query    string
		groups   [][]testTerm
		excluded []testTerm
	}{
		{query: "rate limiter", groups: [][]testTerm{{{normalized: "rate"}}, {{normalized: "limiter"}}}},
		{query: `"Rate Limiter"`, groups: [][]testTerm{{{phrase: true, normalized: "rate limiter"}}}},
		{query: `say "rate limiter" now`, groups: [][]testTerm{{{normalized: "say"}}, {{phrase: true, normalized: "rate limiter"}}, {{normalized: "now"}}}},
		{query: "rate OR limit", groups: [][]testTerm{{{normalized: "rate"}, {normalized: "limit"}}}},
		{query: "a OR b OR c d", groups: [][]testTerm{{{normalized: "a"}, {normalized: "b"}, {normalized: "c"}}, {{normalized: "d"}}}},
		{query: "rate -draft", groups: [][]testTerm{{{normalized: "rate"}}}, excluded: []testTerm{{normalized: "draft"}}},
		{query: "from:Ann subject:Numbers", groups: [][]testTerm{{{field: indexFieldFrom, normalized: "ann"}}, {{field: indexFieldSubject, normalized: "numbers"}}}},
		{query: "TITLE:Plan to:bob", groups: [][]testTerm{{{field: indexFieldTitle, normalized: "plan"}}, {{field: indexFieldTo, normalized: "bob"}}}},
		{query: "agent:builder kind:claim", groups: [][]testTerm{{{fieldName: "agent", normalized: "builder"}}, {{fieldName: "kind", normalized: "claim"}}}},
		{query: "-from:spam ok", groups: [][]testTerm{{{normalized: "ok"}}}, excluded: []testTerm{{field: indexFieldFrom, normalized: "spam"}}},
		{query: "foo:bar", groups: [][]testTerm{{{normalized: "foo bar"}}}},
		{query: "Go!", groups: [][]testTerm{{{normalized: "go"}}}},
		{query: "É", groups: [][]testTerm{{{normalized: "e"}}}},
		{query: "e-mail", groups: [][]testTerm{{{normalized: "e mail"}}}},
		{query: "OR", groups: [][]testTerm{{{normalized: "or"}}}},
		{query: "a OR", groups: [][]testTerm{{{normalized: "a"}}, {{normalized: "or"}}}},
		{query: `"a OR b"`, groups: [][]testTerm{{{phrase: true, normalized: "a or b"}}}},
		{query: "東京tower", groups: [][]testTerm{{{normalized: "東京tower"}}}},
		// A term that normalizes to nothing is no term, and the OR after it still joins (SearchOracle's reading).
		{query: "a !!! OR b", groups: [][]testTerm{{{normalized: "a"}, {normalized: "b"}}}},
		{query: "a OR !!! b", groups: [][]testTerm{{{normalized: "a"}}, {{normalized: "b"}}}},
	}
	for _, c := range cases {
		parsed, err := ParseSearchQuery(c.query)
		if err != nil {
			t.Errorf("%q: %v", c.query, err)
			continue
		}
		groups := [][]testTerm{}
		for _, group := range parsed.Groups {
			groups = append(groups, testTermsOf(group))
		}
		if !slices.EqualFunc(groups, c.groups, slices.Equal[[]testTerm]) || !slices.Equal(testTermsOf(parsed.Excluded), c.excluded) {
			t.Errorf("%q: groups %v excluded %v, want %v and %v", c.query, groups, testTermsOf(parsed.Excluded), c.groups, c.excluded)
		}
	}
}

// An empty query lists with filters, and one whose every term normalizes to nothing is empty too, as SearchOracle reads
// it; one of excluded terms alone matches nothing.
func TestSearchQueryEmptyAndExcludedOnly(t *testing.T) {
	for _, query := range []string{"", "   ", "!!!", `""`, "- -- ---"} {
		parsed, err := ParseSearchQuery(query)
		if err != nil || !parsed.Empty() || parsed.matchesNothing() {
			t.Errorf("%q: empty %v, %v", query, parsed != nil && parsed.Empty(), err)
		}
	}
	parsed, err := ParseSearchQuery("-draft -wip")
	if err != nil || parsed.Empty() || !parsed.matchesNothing() {
		t.Errorf("excluded only: %+v, %v", parsed, err)
	}
}

// Terms of one and two normalized bytes match as whole words through their space-padded trigrams; longer ones as
// substrings through their own.
func TestSearchQueryShortWordsAreWholeWords(t *testing.T) {
	trigram := func(text string) uint32 {
		return indexTrigramAt([]byte(text), 2)
	}
	cases := []struct {
		query string
		want  indexKeySet
	}{
		{query: "a", want: indexKeySet{trigram(" a ")}},
		{query: "Go", want: indexSortedKeys(indexKeySet{trigram(" go"), trigram("go ")})},
		{query: "ж", want: indexTrigrams([]byte(" ж "))},
		{query: "abc", want: indexKeySet{trigram("abc")}},
		{query: "abcd", want: indexSortedKeys(indexKeySet{trigram("abc"), trigram("bcd")})},
	}
	for _, c := range cases {
		parsed, err := ParseSearchQuery(c.query)
		if err != nil {
			t.Fatal(err)
		}
		term := parsed.Groups[0][0]
		if !slices.Equal(term.trigrams, c.want) || term.wholeWord() != (len(term.normalized) <= 2) {
			t.Errorf("%q: trigrams %x, want %x", c.query, term.trigrams, c.want)
		}
	}
}

// A CJK run is one substring term: one character one exact list, two characters four, a four-byte character two.
func TestSearchQueryCjkRuns(t *testing.T) {
	cases := []struct {
		query string
		count int
	}{
		{query: "東", count: 1},
		{query: "東京", count: 4},
		{query: "東京都", count: 7},
		{query: "日本語の検索", count: 16},
		{query: "\U0002000b", count: 2},
		{query: "한국", count: 4},
	}
	for _, c := range cases {
		parsed, err := ParseSearchQuery(c.query)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.Groups) != 1 || len(parsed.Groups[0]) != 1 {
			t.Fatalf("%q: %d groups", c.query, len(parsed.Groups))
		}
		if got := len(parsed.Groups[0][0].trigrams); got != c.count {
			t.Errorf("%q: %d trigrams, want %d", c.query, got, c.count)
		}
	}
	one, _ := ParseSearchQuery("東")
	if want := []byte("東"); one.Groups[0][0].trigrams[0] != uint32(want[0])<<16|uint32(want[1])<<8|uint32(want[2]) {
		t.Errorf("one character's trigram %x is not its own bytes", one.Groups[0][0].trigrams[0])
	}
}

// §16.10's limits on the normalized query: 512 B and 16 terms pass, one more of either is refused, and no refusal
// repeats the query.
func TestSearchQueryLimits(t *testing.T) {
	if _, err := ParseSearchQuery(strings.Repeat("x", 512)); err != nil {
		t.Errorf("512 B: %v", err)
	}
	if _, err := ParseSearchQuery(strings.Repeat("x", 513)); !errors.Is(err, ErrSearchQueryTooLong) {
		t.Errorf("513 B: %v", err)
	}
	// Normalization decides: U+FDFA, 3 B typed, is 33 B after NFKC.
	if _, err := ParseSearchQuery(strings.Repeat("x", 479) + "\uFDFA"); err != nil {
		t.Errorf("482 B typed, 512 B normalized: %v", err)
	}
	if _, err := ParseSearchQuery(strings.Repeat("x", 480) + "\uFDFA"); !errors.Is(err, ErrSearchQueryTooLong) {
		t.Errorf("483 B typed, 513 B normalized: %v", err)
	}
	words := []string{}
	for index := range 16 {
		words = append(words, "w"+string(rune('a'+index)))
	}
	if _, err := ParseSearchQuery(strings.Join(words, " ")); err != nil {
		t.Errorf("16 terms: %v", err)
	}
	for _, seventeen := range []string{strings.Join(words, " ") + " zz", strings.Join(words, " OR ") + " -zz"} {
		_, err := ParseSearchQuery(seventeen)
		if !errors.Is(err, ErrSearchQueryTooLong) {
			t.Errorf("17 terms: %v", err)
			continue
		}
		if strings.Contains(err.Error(), "wa") || strings.Contains(err.Error(), "zz") {
			t.Errorf("a refusal repeats the query: %s", err)
		}
	}
	// Terms that normalize to nothing do not count.
	if _, err := ParseSearchQuery(strings.Join(words, " ") + " !!! ???"); err != nil {
		t.Errorf("16 terms and punctuation: %v", err)
	}
}

// A holding with two present buckets, an expired one, a retained one and three all shards, one not held.
func testSearchHolding() *searchIndexHolding {
	return &searchIndexHolding{
		repoId:            evsTestId("repo"),
		refId:             evsTestId("ref"),
		normalizer:        indexNormalizerId,
		unicodeVersion:    "17.0.0",
		textModuleVersion: "v0.43.0",
		windowDays:        30,
		buckets: []*searchHeldBucket{
			{window: indexBucketWindow{startDay: 20250, days: 30}, retained: true},
			{window: indexBucketWindow{startDay: 20310, days: 30}},
			{window: indexBucketWindow{startDay: 20340, days: 30}},
			{window: indexBucketWindow{startDay: 20370, days: 30}},
		},
		allShards: []*searchHeldShard{
			{n: 0, firstDay: 20100, lastDay: 20189, held: true},
			{n: 1, firstDay: 20190, lastDay: 20249, held: false},
			{n: 2, firstDay: 20250, lastDay: 20279, held: true},
		},
	}
}

// The tables a holding's tests read with: normalizer 1's.
var testSearchTables = indexTables{normVersion: "17.0.0", casesVersion: "17.0.0", unicodeVersion: "17.0.0", textModuleVersion: "v0.43.0"}

// A step as a test expects it.
type testStep struct {
	partition searchPartitionKind
	start     uint32
	retained  bool
	shard     uint32
	held      bool
}

// The steps of a ref's plan, flattened.
func testStepsOf(plan *searchRefPlan) []testStep {
	steps := []testStep{}
	for _, step := range plan.steps {
		steps = append(steps, testStep{partition: step.partition, start: step.window.startDay, retained: step.retained, shard: step.shardNumber, held: step.held})
	}
	return steps
}

// The plan's order: the current bucket, the previous one, expired then retained buckets newest first, then all's
// shards youngest first; scope latest stops before all, cached reads only the all shards held, and all every one.
func TestSearchPlanOrderAndScopes(t *testing.T) {
	now := testDayMs(20375, time.Hour)
	buckets := []testStep{
		{partition: searchPartitionCurrent, start: 20370},
		{partition: searchPartitionPrevious, start: 20340},
		{partition: searchPartitionOlder, start: 20310},
		{partition: searchPartitionOlder, start: 20250, retained: true},
	}
	cases := []struct {
		scope searchPlanScope
		want  []testStep
	}{
		{scope: searchPlanLatest, want: buckets},
		{scope: searchPlanCached, want: append(slices.Clone(buckets), testStep{partition: searchPartitionAll, shard: 2, held: true}, testStep{partition: searchPartitionAll, shard: 0, held: true})},
		{scope: searchPlanAll, want: append(slices.Clone(buckets), testStep{partition: searchPartitionAll, shard: 2, held: true}, testStep{partition: searchPartitionAll, shard: 1}, testStep{partition: searchPartitionAll, shard: 0, held: true})},
	}
	for _, c := range cases {
		plan := searchPlanFor(&searchPlanArgs{holdings: []*searchIndexHolding{testSearchHolding()}, scope: c.scope, nowMs: now, tables: testSearchTables})
		if len(plan.refs) != 1 || plan.refs[0].status != searchRefSearched || plan.refs[0].otherTables {
			t.Fatalf("scope %d: %+v", c.scope, plan.refs[0])
		}
		if got := testStepsOf(plan.refs[0]); !slices.Equal(got, c.want) {
			t.Errorf("scope %d: %v, want %v", c.scope, got, c.want)
		}
	}
}

// A since after all's newest time skips all, which is before the oldest bucket still present; one before it does not.
func TestSearchPlanSinceSkipsAll(t *testing.T) {
	now := testDayMs(20375, time.Hour)
	count := func(since time.Time) int {
		plan := searchPlanFor(&searchPlanArgs{holdings: []*searchIndexHolding{testSearchHolding()}, scope: searchPlanAll, since: since, nowMs: now, tables: testSearchTables})
		allSteps := 0
		for _, step := range plan.refs[0].steps {
			if step.partition == searchPartitionAll {
				allSteps += 1
			}
		}
		return allSteps
	}
	if got := count(testDayTime(20310, 0)); got != 0 {
		t.Errorf("since the oldest present bucket's start: %d all steps", got)
	}
	if got := count(testDayTime(20310, -time.Millisecond)); got != 3 {
		t.Errorf("since just before it: %d all steps", got)
	}
	if got := count(time.Time{}); got != 3 {
		t.Errorf("unbounded: %d all steps", got)
	}
	holding := testSearchHolding()
	holding.buckets = nil
	plan := searchPlanFor(&searchPlanArgs{holdings: []*searchIndexHolding{holding}, scope: searchPlanAll, since: testDayTime(20280, 0), nowMs: now, tables: testSearchTables})
	if len(plan.refs[0].steps) != 0 {
		t.Errorf("no bucket, since past all's last day: %v", testStepsOf(plan.refs[0]))
	}
}

// A newer format or normalizer reads update; an index off or unbuilt reads off; other tables are searched and said.
func TestSearchPlanStatuses(t *testing.T) {
	now := testDayMs(20375, 0)
	plan := func(mutate func(holding *searchIndexHolding), tables indexTables) *searchRefPlan {
		holding := testSearchHolding()
		mutate(holding)
		return searchPlanFor(&searchPlanArgs{holdings: []*searchIndexHolding{holding}, nowMs: now, tables: tables}).refs[0]
	}
	if got := plan(func(holding *searchIndexHolding) { holding.newerFormat = true }, testSearchTables); got.status != searchRefUpdate || len(got.steps) != 0 {
		t.Errorf("newer format: %+v", got)
	}
	if got := plan(func(holding *searchIndexHolding) { holding.normalizer = 2 }, testSearchTables); got.status != searchRefUpdate {
		t.Errorf("newer normalizer: %+v", got)
	}
	if got := plan(func(holding *searchIndexHolding) { holding.off = true }, testSearchTables); got.status != searchRefOff || len(got.steps) != 0 {
		t.Errorf("off: %+v", got)
	}
	if got := plan(func(holding *searchIndexHolding) {}, indexTables{normVersion: "18.0.0"}); got.status != searchRefUpdate {
		t.Errorf("a reader on other tables than normalizer 1's: %+v", got)
	}
	if got := plan(func(holding *searchIndexHolding) { holding.unicodeVersion = "16.0.0" }, testSearchTables); got.status != searchRefSearched || !got.otherTables || len(got.steps) == 0 {
		t.Errorf("an index on other tables: %+v", got)
	}
}

// A view's holding: its buckets, a/m's shards held, its slots' tables.
func TestSearchHoldingOfAView(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	holding := searchHoldingOf(world.view(t, a))
	if holding.off || len(holding.buckets) != 1 || holding.buckets[0].window.startDay != 20340 || holding.normalizer != indexNormalizerId || holding.windowDays != 30 {
		t.Errorf("holding %+v", holding)
	}
	plan := searchPlanFor(&searchPlanArgs{holdings: []*searchIndexHolding{holding}, nowMs: testDayMs(20341, 0), tables: testSearchTables})
	if got := testStepsOf(plan.refs[0]); !slices.Equal(got, []testStep{{partition: searchPartitionCurrent, start: 20340}}) {
		t.Errorf("steps %v", got)
	}
}
