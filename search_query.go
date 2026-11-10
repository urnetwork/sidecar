//go:build !ios_extension

// The query grammar (§16.10's query row, §11.14's query row; D-EVS-55; SEARCH-M10-22). A query is at most 512 B and 16
// terms after the index's own normalization. Words and "quoted phrases" are required substring terms, ANDed; a OR b
// joins alternatives; -term excludes a hit only where this device confirms the term; field:text confines a term to
// one doc-table field; an empty query with filters lists; there is no regex in v1. A term of 1-2 normalized bytes
// matches as a whole word through its space-padded trigrams (" a "; " go" and "go "), since fields are padded and
// punctuation folds to spaces. A CJK run is one substring term, whose trigrams follow from UTF-8's disjoint lead and
// continuation bytes: one character is one exact list, two characters four lists.
//
// The readings SearchOracle takes (sidecartest/search_oracle.go) are this grammar's too, so the two agree: tokens split
// at whitespace outside quotes, a quote anywhere in a token making it a phrase; an unquoted OR between two terms joins
// them; a term is normalized by normalizer 1's steps 1-5 and trimmed of the spaces its edges' punctuation became, and
// one that normalizes to nothing is no term; a query left with no term is empty, and one with only excluded terms
// matches nothing; subject:, from:, to: and title: name fields 1-4, a registered field's name (§16.8, §16.11) names its
// field in each class that registers it, and any other name: is text.
//
// A query is what a person or an agent asked: it lives in memory only, and no error here repeats any of it (I-13,
// I-19).

package sidecar

import (
	"errors"
	"slices"
	"strings"
)

// §16.10's limits on a normalized query, facts of the grammar.
const (
	searchQueryMaxByteCount = 512
	searchQueryMaxTermCount = 16
)

// A normalized term this short matches as a whole word (D-EVS-55).
const searchWholeWordMaxByteCount = 2

// A query past 512 B or 16 terms after normalization: the search finds nothing for it (§16.10).
var ErrSearchQueryTooLong = errors.New("search query past 512 bytes or 16 terms")

// The doc-table fields every document holds, by the names a query gives them (§11.14's fields row).
var searchQueryHeaderFields = map[string]int{
	"subject": indexFieldSubject,
	"from":    indexFieldFrom,
	"to":      indexFieldTo,
	"title":   indexFieldTitle,
}

// A parsed query, normalized by this build's normalizer 1: every group must hold, a group holding when one of its
// alternatives does, and an excluded term drops a hit only where this device confirms it.
type SearchQuery struct {
	Groups   [][]*SearchTerm
	Excluded []*SearchTerm
}

// One term.
type SearchTerm struct {
	// As typed, NFC as the caller sent it: a word, or a phrase's inside.
	Text string
	// A "quoted phrase", one substring term spaces and all.
	Phrase bool
	// field:text with a field every document holds: 1 subject, 2 from, 3 to, 4 title. 0 for every field.
	Field int
	// field:text with a field a document class registers (§16.8, §16.11), which each class maps to its number.
	FieldName string
	// Normalized by steps 1-5 and trimmed, never empty.
	normalized string
	// Its trigrams: of the text, or of the text between two spaces for a whole word.
	trigrams indexKeySet
}

// Whether the term matches as a whole word: 1-2 normalized bytes.
func (self *SearchTerm) wholeWord() bool {
	return len(self.normalized) <= searchWholeWordMaxByteCount
}

// What a document's normalized text, or a row field's, must contain: the term, or the term between spaces.
func (self *SearchTerm) needle() string {
	if self.wholeWord() {
		return " " + self.normalized + " "
	}
	return self.normalized
}

// Whether the query has no term: with filters it lists, else it matches nothing.
func (self *SearchQuery) Empty() bool {
	return len(self.Groups) == 0 && len(self.Excluded) == 0
}

// Whether no document can match: a query of excluded terms alone.
func (self *SearchQuery) matchesNothing() bool {
	return len(self.Groups) == 0 && 0 < len(self.Excluded)
}

// The query's distinct trigrams, ascending: what a search may look up, whatever the index holds.
func (self *SearchQuery) trigrams() indexKeySet {
	keys := indexKeySet{}
	for _, group := range self.Groups {
		for _, term := range group {
			keys = append(keys, term.trigrams...)
		}
	}
	return indexSortedKeys(keys)
}

// Parses query by §16.10's grammar under this build's normalizer 1, which a build linking other tables does not have:
// it answers errIndexOtherNormalizer, and the search reads status update. Past 512 B normalized or 16 terms it answers
// ErrSearchQueryTooLong.
func ParseSearchQuery(query string) (*SearchQuery, error) {
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return nil, err
	}
	return searchParseQuery(query, normalizer)
}

// ParseSearchQuery on a normalizer the caller holds.
func searchParseQuery(query string, normalizer *indexNormalizer) (*SearchQuery, error) {
	normalized, err := normalizer.normalize([]byte(query))
	if err != nil {
		return nil, err
	}
	if searchQueryMaxByteCount < len(normalized) {
		return nil, ErrSearchQueryTooLong
	}

	type token struct {
		text   strings.Builder
		quoted bool
	}
	tokens := []*token{}
	var current *token
	quoting := false
	for _, r := range query {
		switch {
		case r == '"':
			if current == nil {
				current = &token{}
			}
			current.quoted = true
			quoting = !quoting
		case !quoting && (r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			if current != nil {
				tokens = append(tokens, current)
				current = nil
			}
		default:
			if current == nil {
				current = &token{}
			}
			current.text.WriteRune(r)
		}
	}
	if current != nil {
		tokens = append(tokens, current)
	}

	parsed := &SearchQuery{}
	termCount := 0
	joinNext := false
	for index, token := range tokens {
		text := token.text.String()
		if text == "OR" && !token.quoted && 0 < index && index < len(tokens)-1 && 0 < len(parsed.Groups) {
			joinNext = true
			continue
		}
		term := &SearchTerm{Phrase: token.quoted}
		excluded := false
		if strings.HasPrefix(text, "-") && 1 < len(text) {
			excluded = true
			text = text[1:]
		}
		if name, rest, ok := strings.Cut(text, ":"); ok && rest != "" {
			lowered := strings.ToLower(name)
			if number, ok := searchQueryHeaderFields[lowered]; ok {
				term.Field = number
				text = rest
			} else if searchRegisteredFieldName(lowered) {
				term.FieldName = lowered
				text = rest
			}
		}
		term.Text = text
		normalizedTerm, err := normalizer.normalize([]byte(text))
		if err != nil {
			return nil, err
		}
		term.normalized = strings.Trim(string(normalizedTerm), " ")
		if term.normalized == "" {
			joinNext = false
			continue
		}
		term.trigrams = indexTrigrams([]byte(term.needle()))
		termCount += 1
		switch {
		case excluded:
			parsed.Excluded = append(parsed.Excluded, term)
		case joinNext:
			parsed.Groups[len(parsed.Groups)-1] = append(parsed.Groups[len(parsed.Groups)-1], term)
		default:
			parsed.Groups = append(parsed.Groups, []*SearchTerm{term})
		}
		joinNext = false
	}
	if searchQueryMaxTermCount < termCount {
		return nil, ErrSearchQueryTooLong
	}
	return parsed, nil
}

// Whether name is a field some document class registers: §16.8's record entries and run cards, §16.11's directory.
func searchRegisteredFieldName(name string) bool {
	for _, registry := range []*IndexFieldRegistry{indexRecordFieldRegistry(), indexDirectoryFieldRegistry()} {
		for _, fieldName := range registry.FieldNames {
			if fieldName != "" && fieldName == name {
				return true
			}
		}
	}
	return false
}

// keys sorted and without repeats.
func indexSortedKeys(keys indexKeySet) indexKeySet {
	sorted := slices.Clone(keys)
	slices.Sort(sorted)
	return slices.Compact(sorted)
}
