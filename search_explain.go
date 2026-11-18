//go:build !ios_extension

// What `ur search --explain` shows of a query (§16.10's explain row; SEARCH-M10-30): each term as this build's
// normalizer 1 reads it, the field it is confined to, and the trigrams it looks up, each as its three normalized bytes.
// It runs on the person's own device, over the query the person typed, and nothing of it is logged (I-13). Package-level
// functions are safe for concurrent use.

package sidecar

// One term of a query as --explain shows it.
type SearchTermExplain struct {
	// As typed, NFC as sent.
	Text string
	// subject, from, to, title, a class's registered name, or "" for every field.
	Field string
	// A "quoted phrase", an excluded -term, and a term of 1-2 normalized bytes, which matches as a whole word.
	Phrase    bool
	Excluded  bool
	WholeWord bool
	// Normalized by steps 1-5.
	Normalized string
	// Each trigram the term looks up, its three normalized bytes, ascending by key.
	Trigrams []string
	// Which alternatives of a group of OR'd terms it is one of: groups are numbered from 1; 0 for an excluded term.
	Group int
}

// The query's terms as --explain shows them, ErrSearchQueryTooLong past §16.10's caps, as ParseSearchQuery answers.
func ExplainSearchQuery(query string) ([]*SearchTermExplain, error) {
	parsed, err := ParseSearchQuery(query)
	if err != nil {
		return nil, err
	}
	fieldNames := map[int]string{}
	for name, number := range searchQueryHeaderFields {
		fieldNames[number] = name
	}
	explain := func(term *SearchTerm, group int, excluded bool) *SearchTermExplain {
		field := fieldNames[term.Field]
		if term.FieldName != "" {
			field = term.FieldName
		}
		trigrams := make([]string, 0, len(term.trigrams))
		for _, key := range term.trigrams {
			trigrams = append(trigrams, string([]byte{byte(key >> 16), byte(key >> 8), byte(key)}))
		}
		return &SearchTermExplain{
			Text: term.Text, Field: field, Phrase: term.Phrase, Excluded: excluded, WholeWord: term.wholeWord(),
			Normalized: term.normalized, Trigrams: trigrams, Group: group,
		}
	}
	terms := []*SearchTermExplain{}
	for index, group := range parsed.Groups {
		for _, term := range group {
			terms = append(terms, explain(term, index+1, false))
		}
	}
	for _, term := range parsed.Excluded {
		terms = append(terms, explain(term, 0, true))
	}
	return terms, nil
}
