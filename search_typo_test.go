// Near hits and the vocabulary (SEARCH-M10-25): vectors for one-edit generation per script and for the similarity
// score, a desktop's expansion against its vocabulary (best by similarity, ties by count, the threshold), a phone's
// variants probed as whole words in the index with its display vocabulary first, the terms never corrected, and the
// vocabulary's counts, its erasure leaving no word (FS-78's clause) and its sealed copy streamed back.

package sidecar

import (
	"bytes"
	"context"
	"math"
	"slices"
	"strings"
	"testing"
)

// The optimal string alignment distance of two rune strings: insertions, deletions, substitutions and transpositions
// of neighbors, an edit at most once a position. An independent check of what searchOneEditVariants makes.
func testEditDistance(a []rune, b []rune) int {
	rows := make([][]int, len(a)+1)
	for i := range rows {
		rows[i] = make([]int, len(b)+1)
		rows[i][0] = i
	}
	for j := range rows[0] {
		rows[0][j] = j
	}
	for i := 1; i <= len(a); i += 1 {
		for j := 1; j <= len(b); j += 1 {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			rows[i][j] = min(rows[i-1][j]+1, rows[i][j-1]+1, rows[i-1][j-1]+cost)
			if 1 < i && 1 < j && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				rows[i][j] = min(rows[i][j], rows[i-2][j-2]+1)
			}
		}
	}
	return rows[len(a)][len(b)]
}

// A term's normalized form.
func testNormalizedWord(t testing.TB, word string) string {
	t.Helper()
	term, ok, err := searchNewTerm(testSearchNormalizer(t), word)
	if err != nil || !ok {
		t.Fatalf("%q: %v", word, err)
	}
	return term.normalized
}

// One-edit variants, a vector a script: on a two-letter alphabet every variant in its order; on each script's
// alphabet the count a word with no equal neighbors gives, n deletions, n-1 transpositions, n(A-1) substitutions and
// (n+1)A-n insertions, every variant one edit from the word, none twice and never the word; a CJK word none.
func TestSearchOneEditVariantsPerScript(t *testing.T) {
	if got := searchOneEditVariants("ab", []rune{'a', 'b'}, 100); !slices.Equal(got, []string{"b", "a", "ba", "bb", "aa", "aab", "bab", "abb", "aba"}) {
		t.Fatalf("ab: %q", got)
	}
	args := &searchNearArgs{settings: DefaultSearchResultSettings()}
	for _, c := range []struct {
		word       string
		normalized string
		alphabet   int
	}{
		{word: "Cat", normalized: "cat", alphabet: 26},
		{word: "λόγος", normalized: "λογοσ", alphabet: 24},
		{word: "Кот", normalized: "кот", alphabet: 32},
		{word: "كتب", normalized: "كتب", alphabet: 36},
		{word: "שלום", normalized: "שלום", alphabet: 27},
		{word: "2024", normalized: "2024", alphabet: 10},
		{word: "नमस्ते", normalized: "नमस्ते", alphabet: 6},
	} {
		normalized := testNormalizedWord(t, c.word)
		if normalized != c.normalized {
			t.Errorf("%s normalizes to %q", c.word, normalized)
			continue
		}
		alphabet := args.alphabet(normalized)
		if len(alphabet) != c.alphabet {
			t.Errorf("%s: an alphabet of %d", c.word, len(alphabet))
			continue
		}
		runes := []rune(normalized)
		n, a := len(runes), len(alphabet)
		variants := searchOneEditVariants(normalized, alphabet, 100000)
		if want := n + (n - 1) + n*(a-1) + (n+1)*a - n; len(variants) != want {
			t.Errorf("%s: %d variants, want %d", c.word, len(variants), want)
		}
		seen := map[string]bool{}
		for _, variant := range variants {
			if seen[variant] || variant == normalized || testEditDistance(runes, []rune(variant)) != 1 {
				t.Errorf("%s: variant %q repeated, the word, or not one edit", c.word, variant)
			}
			seen[variant] = true
		}
		if capped := searchOneEditVariants(normalized, alphabet, 10); !slices.Equal(capped, variants[:10]) {
			t.Errorf("%s: the cap keeps %q", c.word, capped)
		}
	}
	for _, word := range []string{"東京", "ひらがな", "한국어"} {
		if searchCorrectable(&SearchTerm{normalized: testNormalizedWord(t, word)}) {
			t.Errorf("%s is correctable", word)
		}
	}
}

// The similarity score, vectors: both words padded with two spaces before and one after, shared trigrams over their
// union.
func TestSearchWordSimilarityVectors(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want float64
	}{
		{a: "receive", b: "recieve", want: 4.0 / 12},
		{a: "hello", b: "helo", want: 4.0 / 7},
		{a: "abc", b: "abc", want: 1},
		{a: "abc", b: "xyz", want: 0},
		{a: "a", b: "ab", want: 1.0 / 4},
	} {
		if got := searchWordSimilarity(c.a, c.b); math.Abs(got-c.want) > 1e-12 || math.Abs(searchWordSimilarity(c.b, c.a)-got) > 1e-12 {
			t.Errorf("%s, %s: %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// A desktop expands a term with too few exact hits against its vocabulary: the most similar word at the threshold or
// above, ties by document count, never the term itself; nothing below the threshold; a term with enough exact hits
// only on request; phrases, scoped terms and CJK never; the corrected query keeps every other term and the excluded
// ones.
func TestSearchNearHitsOnADesktop(t *testing.T) {
	normalizer := testSearchNormalizer(t)
	vocabularyOf := func(counts map[string]int) *SearchVocabulary {
		vocabulary := NewSearchVocabulary(nil)
		for word, count := range counts {
			for range count {
				if err := vocabulary.AddText(normalizer, []byte(word)); err != nil {
					t.Fatal(err)
				}
			}
		}
		return vocabulary
	}
	vocabulary := vocabularyOf(map[string]int{"abce": 2, "abcf": 9, "zzzz": 99, "stable": 3})
	nearIn := func(vocabulary *SearchVocabulary, query string, fuzzy bool, exact int) *searchNearResult {
		parsed, err := ParseSearchQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		result, err := searchNearHits(context.Background(), &searchNearArgs{
			query: parsed, normalizer: normalizer, settings: DefaultSearchResultSettings(), fuzzy: fuzzy,
			exactCount: func(term *SearchTerm) (int, error) { return exact, nil },
			vocabulary: func(visit func(word []byte, count uint32) bool) error {
				vocabulary.each(visit)
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	near := func(query string, fuzzy bool, exact int) *searchNearResult {
		return nearIn(vocabulary, query, fuzzy, exact)
	}
	// abce and abcf are equally similar to abcx, and abcf more documents hold; stable is its own and nothing near it
	result := near("abcx stable -zzzz", false, 0)
	if len(result.corrections) != 1 || result.corrections[0].word != "abcf" {
		t.Fatalf("corrections %+v", result.corrections)
	}
	if want := searchWordSimilarity("abcx", "abcf"); result.corrections[0].similarity != want || result.corrections[0].count != 9 {
		t.Errorf("abcx's correction %+v", result.corrections[0])
	}
	if result.query == nil || result.query.Groups[0][0].normalized != "abcf" || result.query.Groups[1][0].normalized != "stable" ||
		len(result.query.Excluded) != 1 || result.query.Excluded[0].normalized != "zzzz" {
		t.Errorf("the corrected query %+v", result.query)
	}
	// similarity first: abcxyw shares 5 of 9 trigrams with abcxyz, abcxqq 4 of 10, however many documents hold it
	if result := nearIn(vocabularyOf(map[string]int{"abcxyw": 1, "abcxqq": 99}), "abcxyz", false, 0); len(result.corrections) != 1 || result.corrections[0].word != "abcxyw" {
		t.Errorf("abcxyz gave %+v", result.corrections)
	}
	if result := near("abcx", false, 3); len(result.corrections) != 0 || result.query != nil {
		t.Error("a term with enough exact hits was corrected")
	}
	if result := near("abcx", true, 3); len(result.corrections) != 1 {
		t.Error("fuzzy did not correct a term with enough exact hits")
	}
	if result := near("qqqqqqq", false, 0); len(result.corrections) != 0 {
		t.Errorf("a word below the threshold was offered: %q", result.corrections[0].word)
	}
	for _, query := range []string{`"abcx abcy"`, "subject:abcx", "東京都"} {
		if result := near(query, true, 0); len(result.corrections) != 0 {
			t.Errorf("%s was corrected", query)
		}
	}
	if text := searchCorrectionText(&searchCorrection{word: strings.Repeat("é", 200)}, DefaultSearchWireSettings()); len(text) != 256 {
		t.Errorf("a correction cut to %d B", len(text))
	}
}

// A phone tests one-edit variants as whole words in the index it holds: a transposition finds the word documents
// hold, a word only inside a longer one does not count, and a variant its display vocabulary holds comes first
// whatever the counts.
func TestSearchNearHitsOnAPhone(t *testing.T) {
	refKey, refId := testSearchRefKey("phone"), evsTestId("phone ref")
	entries := []*indexEntry{}
	for index, body := range []string{"please receive this", "we receive mail", "a cat sat", "the cat ran", "one cat", "a bar", "categorical"} {
		entries = append(entries, testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: strings.Repeat("p", index+1), body: body, version: 1, time: 1}))
	}
	// a document the version table holds as erased: no correction may come from its words alone
	erased := testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: "erased.md", body: "the zebu grazed", version: 1, time: 1})
	records := testSearchRecords(append(slices.Clone(entries), erased)...)
	records[erased.key] = searchVersionRecord{found: true, version: 1, erasedThrough: searchErasedAll}
	table := testVersionTableOf(records)
	mask, err := newSearchMask(&searchMaskArgs{probe: table.probe, refId: refId})
	if err != nil {
		t.Fatal(err)
	}
	partitions := []*searchNearPartition{{source: testSearchSlotPartition(searchPartitionCurrent, append(slices.Clone(entries), erased)...), mask: mask}}
	normalizer := testSearchNormalizer(t)
	near := func(query string, display *SearchVocabulary) []*searchCorrection {
		parsed, err := ParseSearchQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		result, err := searchNearHits(context.Background(), &searchNearArgs{
			query: parsed, normalizer: normalizer, settings: DefaultSearchResultSettings(),
			partitions: partitions, display: display, maxCandidateCount: 20000,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result.corrections
	}
	if corrections := near("recieve", nil); len(corrections) != 1 || corrections[0].word != "receive" || corrections[0].count != 2 {
		t.Fatalf("recieve gave %+v", corrections)
	}
	if corrections := near("bat", nil); len(corrections) != 1 || corrections[0].word != "cat" || corrections[0].count != 3 {
		t.Fatalf("bat gave %+v", corrections)
	}
	display := NewSearchVocabulary(nil)
	if err := display.AddText(normalizer, []byte("Re: the bar tab")); err != nil {
		t.Fatal(err)
	}
	if corrections := near("bat", display); len(corrections) != 1 || corrections[0].word != "bar" || !corrections[0].displayed {
		t.Fatalf("bat with bar on display gave %+v", corrections)
	}
	if corrections := near("categorica", nil); len(corrections) != 1 || corrections[0].word != "categorical" {
		t.Fatalf("categorica gave %+v", corrections)
	}
	if corrections := near("zebo", nil); len(corrections) != 0 {
		t.Fatalf("a word only an erased document holds was offered: %+v", corrections)
	}
	// "cat" is a candidate of "categorical"'s document only as a substring: as a whole word it is in three documents
	count, current, err := (&searchNearArgs{partitions: partitions, maxCandidateCount: 20000}).candidateCount(&SearchQuery{Groups: [][]*SearchTerm{{{normalized: "cat", trigrams: indexTrigrams([]byte(" cat "))}}}}, true)
	if err != nil || count != 3 || !current {
		t.Errorf("cat as a whole word: %d, %v, %v", count, current, err)
	}
}

// The vocabulary counts documents a word: a word only an erased document held leaves with it, a shared one stays one
// lower, and the sealed copy that replaces the last holds no erased word (FS-78's clause). Words past the cap and CJK
// words are kept out, and the kept copy streams back a frame at a time in byte order.
func TestSearchVocabularyCountsAndErasure(t *testing.T) {
	normalizer := testSearchNormalizer(t)
	document := func(title string, body string) *IndexDocument {
		indexDocument := &IndexDocument{Kind: IndexDocFile, Name: []byte("notes/x.md")}
		indexDocument.Fields[indexFieldTitle] = []byte(title)
		indexDocument.Fields[indexFieldBody] = []byte(body)
		return indexDocument
	}
	erased := document("Secret", "the zanzibarite plan, shared words "+strings.Repeat("x", 80)+" 東京")
	kept := document("Plan", "shared words")
	vocabulary := NewSearchVocabulary(nil)
	for _, indexDocument := range []*IndexDocument{erased, kept} {
		if err := vocabulary.AddDocument(normalizer, indexDocument); err != nil {
			t.Fatal(err)
		}
	}
	if vocabulary.Count("zanzibarite") != 1 || vocabulary.Count("shared") != 2 || vocabulary.Count("notes") != 2 || vocabulary.Count(strings.Repeat("x", 80)) != 0 || vocabulary.Count("東京") != 0 {
		t.Fatalf("counts: zanzibarite %d, shared %d, notes %d", vocabulary.Count("zanzibarite"), vocabulary.Count("shared"), vocabulary.Count("notes"))
	}

	world := newTestSearchCacheWorld(t, 64*1024*1024)
	key := SearchCacheKey{RepoId: evsTestId("vocabulary repo"), RefId: evsTestId("vocabulary ref"), Path: SearchCacheRefPath}
	if err := world.cache.SetRefVersion(key.RepoId, key.RefId, 9); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := vocabulary.Save(ctx, world.cache, key); err != nil {
		t.Fatal(err)
	}
	if err := vocabulary.RemoveDocument(normalizer, erased); err != nil {
		t.Fatal(err)
	}
	if vocabulary.Count("zanzibarite") != 0 || vocabulary.Count("secret") != 0 || vocabulary.Count("shared") != 1 || vocabulary.Count("plan") != 1 {
		t.Fatalf("after the erasure: zanzibarite %d, secret %d, shared %d, plan %d", vocabulary.Count("zanzibarite"), vocabulary.Count("secret"), vocabulary.Count("shared"), vocabulary.Count("plan"))
	}
	if err := vocabulary.Save(ctx, world.cache, key); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSearchVocabulary(world.cache, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.encode(), vocabulary.encode()) || loaded.Count("zanzibarite") != 0 {
		t.Fatal("the kept vocabulary is not the one saved")
	}
	frames, err := world.cache.OpenDerived(key, SearchCachePartVocabulary)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := frames.ReadAll()
	if err != nil || bytes.Contains(plaintext, []byte("zanzibarite")) {
		t.Fatalf("the kept copy holds the erased word: %v", err)
	}
	streamed := []string{}
	if err := searchScanVocabulary(frames, DefaultSearchResultSettings(), func(word []byte, count uint32) bool {
		streamed = append(streamed, string(word))
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.IsSorted(streamed) || len(streamed) != vocabulary.Len() {
		t.Errorf("streamed %q", streamed)
	}
	if _, err := searchDecodeVocabulary([]byte{searchVocabularyFormat, 2, 1, 'b', 1, 1, 'a', 1}, nil); err == nil {
		t.Error("words out of order decoded")
	}
}
