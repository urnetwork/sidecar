//go:build !ios_extension

// Near hits (§11.14's typos row; §16.10's query row, its fuzzy; R-MAIL-17; D-EVS-54; SEARCH-M10-25): a correction for
// a term with fewer than NearHitExactCount exact hits, or for every term on request, never for a CJK term or a phrase.
//
// A desktop expands the term against its local vocabulary (search_vocabulary.go) by trigram similarity: both words
// padded with two spaces before and one after, their shared trigrams over their union, at NearHitSimilarity (0.3) or
// above, the most similar first and ties by document count. A phone, which holds no vocabulary of text, tests each
// one-edit variant of the term (a deletion, a transposition of neighbors, a substitution or an insertion, over the
// letters of the term's script) whose trigrams, padded with one space a side as a whole word sits in the index, all
// exist and share a document in the partitions it holds, preferring words of its display vocabulary (the subjects,
// senders and i/ snippets it holds), then those more documents share. The rule "documents missing up to 3 of a typo's
// trigrams" is not used: it gave hundreds of candidates for each true one (§11.14's typos row).
//
// One correction a term: the corrected query replaces each corrected term, and its hits are near hits, which say
// "showing results for <word>" and rank after the possible tier by J against the corrected query (search_rank.go).
// A phone's variants are probed in the index it holds and nothing is fetched; nothing here logs or keeps a term.

package sidecar

import (
	"context"
	"slices"
	"strings"
	"unicode"
)

// One term's correction.
type searchCorrection struct {
	term *SearchTerm
	// The correction, normalized, and the term it makes.
	word      string
	corrected *SearchTerm
	// A desktop's trigram similarity; 0 on a phone.
	similarity float64
	// The documents holding the word: its vocabulary count on a desktop, its candidates in the index on a phone.
	count int
	// A phone's variant its display vocabulary holds.
	displayed bool
}

// What near hits read.
type searchNearArgs struct {
	query      *SearchQuery
	normalizer *indexNormalizer
	settings   *SearchResultSettings
	// §16.10's fuzzy: every eligible term is expanded, however many exact hits it has.
	fuzzy bool
	// A term's exact hits; nil counts its candidates in partitions.
	exactCount func(term *SearchTerm) (int, error)
	// A desktop's local vocabulary, streamed in byte order; nil on a phone.
	vocabulary func(visit func(word []byte, count uint32) bool) error
	// The partitions this device holds, each with its repo's mask: a phone's variants are probed in them, and exact
	// hits counted where exactCount is nil.
	partitions []*searchNearPartition
	// A phone's display vocabulary, whose words its variants prefer; nil holds none.
	display *SearchVocabulary
	// Search.TooBroadCandidateCount, which bounds a probe as it bounds a search.
	maxCandidateCount int
}

// One partition a phone's variants are probed in, with the mask of its repo's index, so a variant only an erased,
// removed or superseded document holds is never offered: a correction is shown, and must not show what a mask hides.
type searchNearPartition struct {
	source *searchPartitionSource
	mask   *searchMask
}

// What near hits found.
type searchNearResult struct {
	corrections []*searchCorrection
	// The query with each corrected term replaced by its correction; nil when nothing was corrected.
	query *SearchQuery
}

// The trigram similarity of two normalized words: their trigrams, each word padded with two spaces before and one
// after, shared over their union.
func searchWordSimilarity(a string, b string) float64 {
	aKeys := indexTrigrams([]byte("  " + a + " "))
	bKeys := indexTrigrams([]byte("  " + b + " "))
	shared := searchSharedKeyCount(aKeys, bKeys)
	return float64(shared) / float64(len(aKeys)+len(bKeys)-shared)
}

// The keys two ascending key sets share.
func searchSharedKeyCount(a indexKeySet, b indexKeySet) int {
	shared := 0
	for aIndex, bIndex := 0, 0; aIndex < len(a) && bIndex < len(b); {
		switch {
		case a[aIndex] < b[bIndex]:
			aIndex += 1
		case b[bIndex] < a[aIndex]:
			bIndex += 1
		default:
			shared += 1
			aIndex += 1
			bIndex += 1
		}
	}
	return shared
}

// Whether a term may be corrected: one word, no field it confines itself to, and no CJK character.
func searchCorrectable(term *SearchTerm) bool {
	if term.Phrase || strings.Contains(term.normalized, " ") || term.Field != 0 || term.FieldName != "" {
		return false
	}
	for _, r := range term.normalized {
		if searchIsCjk(r) {
			return false
		}
	}
	return term.normalized != ""
}

// Corrections for the query's terms, and the corrected query.
func searchNearHits(ctx context.Context, args *searchNearArgs) (*searchNearResult, error) {
	if err := args.settings.check(); err != nil {
		return nil, err
	}
	result := &searchNearResult{}
	replaced := map[*SearchTerm]*SearchTerm{}
	for _, group := range args.query.Groups {
		for _, term := range group {
			if !searchCorrectable(term) || replaced[term] != nil {
				continue
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !args.fuzzy {
				count, err := args.termExactCount(term)
				if err != nil {
					return nil, err
				}
				if args.settings.NearHitExactCount <= count {
					continue
				}
			}
			var correction *searchCorrection
			var err error
			if args.vocabulary != nil {
				correction, err = args.expandByVocabulary(term)
			} else {
				correction, err = args.expandByVariants(ctx, term)
			}
			if err != nil {
				return nil, err
			}
			if correction == nil {
				continue
			}
			corrected, ok, err := searchNewTerm(args.normalizer, correction.word)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			correction.corrected = corrected
			replaced[term] = corrected
			result.corrections = append(result.corrections, correction)
		}
	}
	if len(result.corrections) == 0 {
		return result, nil
	}
	result.query = &SearchQuery{Excluded: args.query.Excluded}
	for _, group := range args.query.Groups {
		correctedGroup := []*SearchTerm{}
		for _, term := range group {
			if corrected, ok := replaced[term]; ok {
				term = corrected
			}
			correctedGroup = append(correctedGroup, term)
		}
		result.query.Groups = append(result.query.Groups, correctedGroup)
	}
	return result, nil
}

// A term's exact hits: exactCount's, else its candidates across the partitions.
func (self *searchNearArgs) termExactCount(term *SearchTerm) (int, error) {
	if self.exactCount != nil {
		return self.exactCount(term)
	}
	count, _, err := self.candidateCount(&SearchQuery{Groups: [][]*SearchTerm{{term}}}, false)
	return count, err
}

// The candidates a query has across the partitions, and whether one of them is current under its mask. A diff's
// currency is not judged here (newest answers nothing), since a probe only asks whether documents hold the trigrams.
func (self *searchNearArgs) candidateCount(query *SearchQuery, wantCurrent bool) (int, bool, error) {
	count := 0
	current := false
	for _, partition := range self.partitions {
		matched, err := searchMatch(&searchMatchArgs{
			query: query, source: partition.source, maxCandidateCount: self.maxCandidateCount,
			newest: func(key [indexIdByteCount]byte) (uint64, bool) { return 0, false },
		})
		if err != nil {
			return 0, false, err
		}
		count += matched.candidateCount
		for _, candidate := range matched.candidates {
			if current || !wantCurrent {
				break
			}
			if current, err = searchCandidateCurrent(partition.mask, partition.source.partition, candidate); err != nil {
				return 0, false, err
			}
		}
	}
	return count, current, nil
}

// Whether a match's candidate counts under mask, its row read as the ranker reads it.
func searchCandidateCurrent(mask *searchMask, partition searchPartitionKind, candidate *searchCandidate) (bool, error) {
	if mask == nil {
		return false, errSearchMaskNoTable
	}
	masked := &searchMaskCandidate{local: partition == searchPartitionLocal}
	if candidate.entry != nil {
		masked.key, masked.version, masked.timeSeconds, masked.row = candidate.entry.key, candidate.entry.version, candidate.entry.timeSeconds, candidate.entry.row
	} else {
		document, err := candidate.shard.reader.document(candidate.docId)
		if err != nil {
			return false, err
		}
		masked.key, masked.version, masked.timeSeconds, masked.row = document.key, document.version, document.timeSeconds, document.row
	}
	verdict, err := mask.judge(masked)
	return verdict == searchMaskCurrent, err
}

// A desktop's correction: the vocabulary word most similar to the term at the threshold or above, ties by document
// count, then byte order. Words whose trigram counts alone put them below the threshold are passed over unscored.
func (self *searchNearArgs) expandByVocabulary(term *SearchTerm) (*searchCorrection, error) {
	termKeys := indexTrigrams([]byte("  " + term.normalized + " "))
	var best *searchCorrection
	err := self.vocabulary(func(word []byte, count uint32) bool {
		if string(word) == term.normalized {
			return true
		}
		wordKeys := indexTrigrams([]byte("  " + string(word) + " "))
		if float64(min(len(termKeys), len(wordKeys)))/float64(max(len(termKeys), len(wordKeys))) < self.settings.NearHitSimilarity {
			return true
		}
		shared := searchSharedKeyCount(termKeys, wordKeys)
		similarity := float64(shared) / float64(len(termKeys)+len(wordKeys)-shared)
		if similarity < self.settings.NearHitSimilarity {
			return true
		}
		if best == nil || best.similarity < similarity || best.similarity == similarity && best.count < int(count) {
			best = &searchCorrection{term: term, word: string(word), similarity: similarity, count: int(count)}
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return best, nil
}

// A phone's correction: the one-edit variants of the term whose whole-word trigrams all exist and share a document in
// the partitions held, one such document counting under its mask, the display vocabulary's words first, then those
// more documents share, then the order they were made in.
func (self *searchNearArgs) expandByVariants(ctx context.Context, term *SearchTerm) (*searchCorrection, error) {
	if len(self.partitions) == 0 {
		return nil, nil
	}
	var best *searchCorrection
	for _, variant := range searchOneEditVariants(term.normalized, self.alphabet(term.normalized), self.settings.NearHitVariantMaxCount) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		probe := &SearchTerm{normalized: variant, trigrams: indexTrigrams([]byte(" " + variant + " "))}
		count, current, err := self.candidateCount(&SearchQuery{Groups: [][]*SearchTerm{{probe}}}, true)
		if err != nil {
			return nil, err
		}
		if !current {
			continue
		}
		displayed := self.display != nil && 0 < self.display.Count(variant)
		if best == nil || displayed && !best.displayed || displayed == best.displayed && best.count < count {
			best = &searchCorrection{term: term, word: variant, count: count, displayed: displayed}
		}
	}
	return best, nil
}

// The script a rune belongs to, as variants range over it: a decimal digit counts as its own script, "digit", and a
// rune of no script answers "".
func searchRuneScript(r rune) string {
	if unicode.IsDigit(r) {
		return "digit"
	}
	for _, name := range []string{"Latin", "Greek", "Cyrillic", "Arabic", "Hebrew"} {
		if unicode.Is(unicode.Scripts[name], r) {
			return name
		}
	}
	names := []string{}
	for name, table := range unicode.Scripts {
		if unicode.Is(table, r) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	if len(names) == 0 || names[0] == "Common" || names[0] == "Inherited" {
		return ""
	}
	return names[0]
}

// A script's base letters as normalizer 1 leaves them, case-folded and, for the five scripts whose marks it drops,
// bare: a to z, the Greek and Cyrillic small letters (final sigma folds to sigma), the Arabic and Hebrew letters, and
// the ten digits. Other scripts have none, and range over the letters the term and the display vocabulary hold.
func searchBaseAlphabet(script string) []rune {
	runes := func(ranges ...[2]rune) []rune {
		letters := []rune{}
		for _, span := range ranges {
			for r := span[0]; r <= span[1]; r += 1 {
				letters = append(letters, r)
			}
		}
		return letters
	}
	switch script {
	case "digit":
		return runes([2]rune{'0', '9'})
	case "Latin":
		return runes([2]rune{'a', 'z'})
	case "Greek":
		return runes([2]rune{'α', 'ρ'}, [2]rune{'σ', 'ω'})
	case "Cyrillic":
		return runes([2]rune{'а', 'я'})
	case "Arabic":
		return runes([2]rune{'ء', 'غ'}, [2]rune{'ف', 'ي'})
	case "Hebrew":
		return runes([2]rune{'א', 'ת'})
	}
	return nil
}

// The letters a term's variants range over: for each script the term holds, its base letters with the term's own and
// the display vocabulary's letters of that script, at most NearHitAlphabetMaxCount beyond the base, in rune order.
func (self *searchNearArgs) alphabet(term string) []rune {
	scripts := map[string]bool{}
	letters := map[rune]bool{}
	for _, r := range term {
		if script := searchRuneScript(r); script != "" {
			scripts[script] = true
			letters[r] = true
		}
	}
	for script := range scripts {
		for _, r := range searchBaseAlphabet(script) {
			letters[r] = true
		}
	}
	inScripts := func(r rune) bool {
		for script := range scripts {
			if script == "digit" && unicode.IsDigit(r) || script != "digit" && unicode.Is(unicode.Scripts[script], r) {
				return true
			}
		}
		return false
	}
	if self.display != nil {
		added := 0
		self.display.each(func(word []byte, count uint32) bool {
			for _, r := range string(word) {
				if letters[r] || !inScripts(r) {
					continue
				}
				letters[r] = true
				added += 1
				if self.settings.NearHitAlphabetMaxCount <= added {
					return false
				}
			}
			return true
		})
	}
	alphabet := []rune{}
	for r := range letters {
		alphabet = append(alphabet, r)
	}
	slices.Sort(alphabet)
	return alphabet
}

// The one-edit variants of a normalized word over alphabet, each once and never the word itself, in a fixed order:
// deletions, transpositions of neighbors, substitutions, then insertions, each by position from the start and letter
// by letter; at most maxCount.
func searchOneEditVariants(word string, alphabet []rune, maxCount int) []string {
	runes := []rune(word)
	seen := map[string]bool{word: true}
	variants := []string{}
	add := func(variant []rune) bool {
		text := string(variant)
		if !seen[text] {
			seen[text] = true
			variants = append(variants, text)
		}
		return len(variants) < maxCount
	}
	edit := func(prefix []rune, middle []rune, suffix []rune) []rune {
		return append(append(append([]rune{}, prefix...), middle...), suffix...)
	}
	if 1 < len(runes) {
		for index := range runes {
			if !add(edit(runes[:index], nil, runes[index+1:])) {
				return variants
			}
		}
	}
	for index := 0; index+1 < len(runes); index += 1 {
		if !add(edit(runes[:index], []rune{runes[index+1], runes[index]}, runes[index+2:])) {
			return variants
		}
	}
	for index := range runes {
		for _, letter := range alphabet {
			if !add(edit(runes[:index], []rune{letter}, runes[index+1:])) {
				return variants
			}
		}
	}
	for index := 0; index <= len(runes); index += 1 {
		for _, letter := range alphabet {
			if !add(edit(runes[:index], []rune{letter}, runes[index:])) {
				return variants
			}
		}
	}
	return variants
}

// "showing results for <word>": what a near hit says of its correction, the word cut to the wire's cap.
func searchCorrectionText(correction *searchCorrection, settings *SearchWireSettings) string {
	return indexCutUtf8(correction.word, settings.CorrectionMaxByteCount)
}
