//go:build !ios_extension

// Confirmation (§11.14's confirm row; §16.10's match and doc-table rows; owner decision 155; D-EVS-53, D-MCP-22;
// SEARCH-M10-24): what a trigram candidate is once this host has checked it as far as it can without a fetch.
//
// A host with the document's text (SearchTextSource: a desktop or indexer mirroring the ref, a mounted working tree,
// an indexer answering a remote search, a body already cached) verifies it: the text, extracted and normalized as the
// index's writer did, must hold every term and phrase, and a candidate it does not hold is dropped as false. A host
// without the text confirms a candidate whose display fields hold the query: the row's fields and locator, or for mail
// the i/ address and 200 B snippet it mirrors (SearchDisplaySource), and shows the rest as possible matches; it fetches
// no body to check them, and opening one confirms or rejects it. An excluded term drops a candidate only where this
// host confirms the term, by text or by a display field; a term it cannot check never drops anything.
//
// A field-scoped term is confirmed against the doc-table row (§11.14's fields row: one posting set covers every field):
// it holds where the row's field holds it, and is absent where the field does not and was not cut; a field the row cut
// at its cap reads unknown, which a host with the text settles from the document's own field. §16.10's doc-table
// filters are judged on the row before any term, and its time filters before the row is read (search_rank.go).
//
// The query is what a person or an agent asked: nothing here logs, keeps or repeats it, a snippet included, which
// lives only in the hit (I-13, R-CORE-18).

package sidecar

import (
	"bytes"
	"context"
	"slices"
	"strings"
)

// What a checked candidate is (§16.10's match row).
type searchMatchState int

const (
	// A false candidate: a term this host can check is absent, an excluded term it confirms is present, or a doc-table
	// filter fails.
	searchMatchRejected searchMatchState = iota + 1
	// A trigram candidate this host cannot check (§16.10's possible).
	searchMatchPossible
	// A display field, or mail's i/ address or snippet, holds the query (§16.10's confirmed by field).
	searchMatchConfirmed
	// This host's plaintext of the newest version holds every term and phrase (§16.10's confirmed by text; §11.14's
	// verified).
	searchMatchVerified
)

// What a host can say of one term.
type searchTermResult int

const (
	// Checked, and not there.
	searchTermAbsent searchTermResult = iota + 1
	// Not checkable here.
	searchTermUnknown
	// There.
	searchTermHolds
)

// Judges a query term by term: every group needs a term that holds, an excluded term that holds drops the candidate,
// and a group whose best term is unknown leaves it possible. A query of no group lists: what its filters pass holds.
func searchJudge(query *SearchQuery, check func(term *SearchTerm) (searchTermResult, error)) (searchMatchState, error) {
	unknown := false
	for _, group := range query.Groups {
		best := searchTermAbsent
		for _, term := range group {
			result, err := check(term)
			if err != nil {
				return 0, err
			}
			best = max(best, result)
			if best == searchTermHolds {
				break
			}
		}
		switch best {
		case searchTermAbsent:
			return searchMatchRejected, nil
		case searchTermUnknown:
			unknown = true
		}
	}
	for _, term := range query.Excluded {
		result, err := check(term)
		if err != nil {
			return 0, err
		}
		if result == searchTermHolds {
			return searchMatchRejected, nil
		}
	}
	if unknown {
		return searchMatchPossible, nil
	}
	return searchMatchConfirmed, nil
}

// A term of text normalized as the query grammar normalizes one, with its trigrams, or false for text that normalizes
// to nothing: a filter's text, or a correction.
func searchNewTerm(normalizer *indexNormalizer, text string) (*SearchTerm, bool, error) {
	normalized, err := normalizer.normalize([]byte(text))
	if err != nil {
		return nil, false, err
	}
	term := &SearchTerm{Text: text, normalized: strings.Trim(string(normalized), " ")}
	if term.normalized == "" {
		return nil, false, nil
	}
	term.trigrams = indexTrigrams([]byte(term.needle()))
	return term, true, nil
}

// §16.10's doc-table filters, which a confirmation applies to a row before any term. SEARCH-M10-26 maps §5.4's
// SearchFilters onto them; the times the ranker applies before it reads a row.
type searchRowFilters struct {
	// The entry's time, in seconds, inclusive; 0 leaves an end open.
	sinceSeconds uint64
	untilSeconds uint64
	// The locator starts with this (§16.10's path prefix).
	pathPrefix string
	// The row's doc kinds; empty passes every kind.
	docKinds []indexDocKind
	fields   []*searchFieldFilter
}

// One field a row must hold: field 1-4 by number, or a registered field by its class's name. It holds term, as a
// query term holds in a field, or where values is set it is one of them exactly (§16.10's kind[]).
type searchFieldFilter struct {
	field     int
	fieldName string
	term      *SearchTerm
	values    []string
}

// Whether an entry time passes the time filters.
func (self *searchRowFilters) timeHolds(timeSeconds uint64) bool {
	if self == nil {
		return true
	}
	return self.sinceSeconds <= timeSeconds && (self.untilSeconds == 0 || timeSeconds <= self.untilSeconds)
}

// One candidate a confirmer checks.
type searchConfirmCandidate struct {
	// The ref the document is on: its row's ref_id in ur/index, else the index's ref.
	refId   Id
	version uint64
	row     *indexRow
	// A too-broad partition's (§11.14's newest row): confirmed from its row alone, no text read.
	headerOnly bool
}

// What a confirmation found.
type searchConfirmation struct {
	state searchMatchState
	// A term held in a header field (1-4) or the locator, which sorting by path puts first (§16.10's rank row).
	inHeader bool
	// Around the first match in this host's text, or a mailbox's i/ snippet; at most SnippetMaxByteCount.
	snippet string
	// The query's matches a KiB of normalized text, for ranking by density on a host with the text.
	density float64
}

// Confirms one (repo, index root)'s candidates for one query. Not safe for concurrent use: its normalizer is one
// search's.
type searchConfirmer struct {
	query      *SearchQuery
	filters    *searchRowFilters
	normalizer *indexNormalizer
	// nil where this host holds no text, or no display fields beyond the row.
	text    SearchTextSource
	display SearchDisplaySource
	// The repo's class's registered fields: §16.8's for record logs, §16.11's for the directory; nil for files and
	// mail.
	registry *IndexFieldRegistry
	settings *SearchResultSettings
	repoId   Id
}

// A row's values as a confirmation reads them, normalized and padded once each.
type searchRowTexts struct {
	normalizer *indexNormalizer
	row        *indexRow
	padded     map[int]string
}

// The row's value at field, -1 being the locator, normalized and padded with one space a side as an index field is.
func (self *searchRowTexts) field(field int) (string, error) {
	if text, ok := self.padded[field]; ok {
		return text, nil
	}
	value := self.row.locator
	if 0 <= field {
		value = self.row.fields[field]
	}
	normalized, err := self.normalizer.normalize([]byte(value))
	if err != nil {
		return "", err
	}
	text := " " + string(normalized) + " "
	self.padded[field] = text
	return text, nil
}

// The registered or header field a scoped term names on this row's kind, or 0 where the kind holds no such field.
func (self *searchConfirmer) termField(term *SearchTerm, row *indexRow) int {
	if term.Field != 0 {
		return term.Field
	}
	if self.registry == nil || !row.docKind.hasRegisteredFields() {
		return 0
	}
	return self.registry.field(term.FieldName)
}

// Whether a scoped term holds in its row field: absent where the field does not hold it and lost nothing to its cap,
// unknown where it did.
func (self *searchConfirmer) rowFieldResult(term *SearchTerm, texts *searchRowTexts) (searchTermResult, error) {
	field := self.termField(term, texts.row)
	if field == 0 {
		return searchTermAbsent, nil
	}
	text, err := texts.field(field)
	if err != nil {
		return 0, err
	}
	if strings.Contains(text, term.needle()) {
		return searchTermHolds, nil
	}
	if texts.row.flags&indexRowCutFlag(field) != 0 {
		return searchTermUnknown, nil
	}
	return searchTermAbsent, nil
}

// Whether the row passes the doc-table filters other than time.
func (self *searchConfirmer) filtersHold(texts *searchRowTexts) (bool, error) {
	filters := self.filters
	if filters == nil {
		return true, nil
	}
	row := texts.row
	// a cut locator keeps its start, so a prefix it shows still holds; one that was not UTF-8 holds U+FFFD and fails
	if !strings.HasPrefix(row.locator, filters.pathPrefix) {
		return false, nil
	}
	if 0 < len(filters.docKinds) && !slices.Contains(filters.docKinds, row.docKind) {
		return false, nil
	}
	for _, filter := range filters.fields {
		term := &SearchTerm{Field: filter.field, FieldName: filter.fieldName}
		field := self.termField(term, row)
		if field == 0 {
			return false, nil
		}
		if 0 < len(filter.values) {
			if !slices.Contains(filter.values, row.fields[field]) {
				return false, nil
			}
			continue
		}
		if filter.term == nil {
			continue
		}
		text, err := texts.field(field)
		if err != nil {
			return false, err
		}
		if !strings.Contains(text, filter.term.needle()) {
			return false, nil
		}
	}
	return true, nil
}

// Checks one candidate: its filters, then its text where this host holds it, else its display fields.
func (self *searchConfirmer) confirm(ctx context.Context, candidate *searchConfirmCandidate) (*searchConfirmation, error) {
	texts := &searchRowTexts{normalizer: self.normalizer, row: candidate.row, padded: map[int]string{}}
	if holds, err := self.filtersHold(texts); err != nil || !holds {
		return &searchConfirmation{state: searchMatchRejected}, err
	}
	if len(self.query.Groups) == 0 && len(self.query.Excluded) == 0 {
		// an empty query lists what its filters pass, which the row confirms
		return &searchConfirmation{state: searchMatchConfirmed}, nil
	}
	request := &SearchTextRequest{
		RepoId:  self.repoId,
		RefId:   candidate.refId,
		Kind:    candidate.row.docKind,
		Name:    []byte(candidate.row.locator),
		Version: candidate.version,
	}
	if self.text != nil && !candidate.headerOnly && candidate.row.flags&indexRowInexact == 0 {
		documents, ok, err := self.text.SearchDocuments(ctx, request)
		if err != nil {
			return nil, err
		}
		if ok {
			for _, document := range documents {
				if uint64(document.Chunk) == candidate.row.chunk {
					return self.verify(document, texts)
				}
			}
		}
	}
	var display *SearchDisplay
	if self.display != nil && !candidate.headerOnly {
		found, ok, err := self.display.SearchDisplay(ctx, request)
		if err != nil {
			return nil, err
		}
		if ok {
			display = found
		}
	}
	return self.confirmByFields(texts, display)
}

// The display fields a row shows for an unscoped term: its locator and every field its kind holds.
func (self *searchConfirmer) displayFields(row *indexRow) []int {
	return append([]int{-1}, row.docKind.rowFields()...)
}

// Confirms from the row and what a display source holds: a term in some display field holds, a scoped one as its row
// field says, and the rest cannot be checked here.
func (self *searchConfirmer) confirmByFields(texts *searchRowTexts, display *SearchDisplay) (*searchConfirmation, error) {
	confirmation := &searchConfirmation{}
	displayTexts := []string{}
	if display != nil {
		for _, value := range []string{display.Address, display.Snippet} {
			if value == "" {
				continue
			}
			normalized, err := self.normalizer.normalize([]byte(value))
			if err != nil {
				return nil, err
			}
			displayTexts = append(displayTexts, " "+string(normalized)+" ")
		}
		confirmation.snippet = indexCutUtf8(indexRowText(display.Snippet), self.settings.SnippetMaxByteCount)
	}
	state, err := searchJudge(self.query, func(term *SearchTerm) (searchTermResult, error) {
		if term.Field != 0 || term.FieldName != "" {
			result, err := self.rowFieldResult(term, texts)
			if result == searchTermHolds {
				confirmation.inHeader = confirmation.inHeader || self.termField(term, texts.row) <= indexFieldTitle
			}
			return result, err
		}
		for _, field := range self.displayFields(texts.row) {
			text, err := texts.field(field)
			if err != nil {
				return 0, err
			}
			if strings.Contains(text, term.needle()) {
				confirmation.inHeader = confirmation.inHeader || field <= indexFieldTitle
				return searchTermHolds, nil
			}
		}
		for _, text := range displayTexts {
			if strings.Contains(text, term.needle()) {
				return searchTermHolds, nil
			}
		}
		return searchTermUnknown, nil
	})
	if err != nil {
		return nil, err
	}
	confirmation.state = state
	return confirmation, nil
}

// Verifies against this host's text of the version: the document's whole text as normalizer 1 writes it, fields
// padded and joined as the index's writer joined them, holds each unscoped term, and its row, or its own field where
// the row's was cut, each scoped one.
func (self *searchConfirmer) verify(document *IndexDocument, texts *searchRowTexts) (*searchConfirmation, error) {
	whole := &bytes.Buffer{}
	if err := self.normalizer.writeDocument(whole, document.textFields()); err != nil {
		return nil, err
	}
	confirmation := &searchConfirmation{}
	state, err := searchJudge(self.query, func(term *SearchTerm) (searchTermResult, error) {
		if term.Field == 0 && term.FieldName == "" {
			if bytes.Contains(whole.Bytes(), []byte(term.needle())) {
				return searchTermHolds, nil
			}
			return searchTermAbsent, nil
		}
		result, err := self.rowFieldResult(term, texts)
		if err != nil || result != searchTermUnknown {
			return result, err
		}
		field := self.termField(term, texts.row)
		text, err := self.documentField(document, field)
		if err != nil {
			return 0, err
		}
		if strings.Contains(text, term.needle()) {
			return searchTermHolds, nil
		}
		return searchTermAbsent, nil
	})
	if err != nil {
		return nil, err
	}
	confirmation.state = state
	if state != searchMatchConfirmed {
		return confirmation, nil
	}
	confirmation.state = searchMatchVerified
	matchCount := 0
	for _, group := range self.query.Groups {
		for _, term := range group {
			matchCount += bytes.Count(whole.Bytes(), []byte(term.needle()))
		}
	}
	confirmation.density = float64(matchCount) * 1024 / float64(max(1, whole.Len()))
	snippet, inHeader, err := self.snippetOf(document)
	if err != nil {
		return nil, err
	}
	confirmation.snippet = snippet
	confirmation.inHeader = inHeader
	return confirmation, nil
}

// A document's own field as the index's writer read it, normalized and padded: a header field cut at
// indexHeaderFieldByteCount, a file's title with its path.
func (self *searchConfirmer) documentField(document *IndexDocument, field int) (string, error) {
	for _, textField := range document.textFields() {
		if textField.number != field {
			continue
		}
		text := &bytes.Buffer{}
		if err := self.normalizer.writeField(text, textField); err != nil {
			return "", err
		}
		return text.String(), nil
	}
	return "", nil
}

// The snippet around the first match: the first field, in field order, whose normalized text holds a term of the
// query, and in it the first window of the original text that holds it, cut on a code point. Whether that field is a
// header's.
func (self *searchConfirmer) snippetOf(document *IndexDocument) (string, bool, error) {
	needles := []string{}
	for _, group := range self.query.Groups {
		for _, term := range group {
			if term.Field == 0 && term.FieldName == "" {
				needles = append(needles, term.needle())
			}
		}
	}
	for _, textField := range document.textFields() {
		original := document.Fields[textField.number]
		if textField.number == indexFieldTitle && document.Kind == IndexDocFile {
			original = append(append(append([]byte{}, original...), ' '), document.Name...)
		}
		text, err := self.normalizedPadded(original)
		if err != nil {
			return "", false, err
		}
		for _, needle := range needles {
			if !strings.Contains(text, needle) {
				continue
			}
			snippet, err := self.snippetIn(original, needle)
			return snippet, textField.number <= indexFieldTitle, err
		}
	}
	return "", false, nil
}

// text normalized and padded with one space a side.
func (self *searchConfirmer) normalizedPadded(text []byte) (string, error) {
	normalized, err := self.normalizer.normalize(text)
	if err != nil {
		return "", err
	}
	return " " + string(normalized) + " ", nil
}

// The first window of original, SnippetMaxByteCount long, whose normalized text holds needle: found a block of
// SnippetBlockByteCount at a time, blocks overlapping by a window, then a window at a time within the block, so a
// 1 MiB body is normalized about twice. A needle longer than a window answers its block's start.
func (self *searchConfirmer) snippetIn(original []byte, needle string) (string, error) {
	windowByteCount := self.settings.SnippetMaxByteCount
	if len(original) <= windowByteCount {
		return indexRowText(string(original)), nil
	}
	// windows of size bytes every step bytes, each start and end on a code point; size is at least a code point's
	// width and step at least 1 (SearchResultSettings.check)
	find := func(text []byte, size int, step int) (int, int, error) {
		for start := 0; ; {
			end := len(text)
			if start+size < len(text) {
				end = searchRuneStart(text, start+size)
			}
			normalized, err := self.normalizedPadded(text[start:end])
			if err != nil {
				return 0, 0, err
			}
			if strings.Contains(normalized, needle) {
				return start, end, nil
			}
			if end == len(text) {
				return -1, -1, nil
			}
			start = searchNextRuneStart(text, start+step)
		}
	}
	blockStart, blockEnd, err := find(original, self.settings.SnippetBlockByteCount, self.settings.SnippetBlockByteCount-windowByteCount)
	if err != nil {
		return "", err
	}
	if blockStart < 0 {
		return indexRowText(string(indexCutUtf8(original, windowByteCount))), nil
	}
	block := original[blockStart:blockEnd]
	windowStart, windowEnd, err := find(block, windowByteCount, max(1, windowByteCount/2))
	if err != nil {
		return "", err
	}
	if windowStart < 0 {
		return indexRowText(string(indexCutUtf8(block, windowByteCount))), nil
	}
	return indexRowText(string(indexCutUtf8(block[windowStart:windowEnd], windowByteCount))), nil
}

// The start of the code point at or before index in text, so a window never splits one.
func searchRuneStart(text []byte, index int) int {
	for 0 < index && index < len(text) && text[index]&0xC0 == 0x80 {
		index -= 1
	}
	return index
}

// The start of the first code point at or after index in text, or its length.
func searchNextRuneStart(text []byte, index int) int {
	for index < len(text) && text[index]&0xC0 == 0x80 {
		index += 1
	}
	return min(index, len(text))
}
