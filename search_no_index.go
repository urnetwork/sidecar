//go:build !ios_extension

// A ref with no index (§11.14's off row; §16.10's excluded and coverage rows; owner decision 156; SEARCH-M10-25): a
// repo-scoped search of a ref whose index is off or not built scans what this host holds of it instead. A host with
// the text scans every document at its newest version, exactly and linearly, extracted and normalized as an index
// would hold it, and verifies each as a candidate is verified (search_confirm.go). A phone or a browser, which holds no
// text, matches the names it holds and, for mail, the i/ fields it mirrors (from, to, subject, address, snippet), so a
// hit is confirmed by a field or not given at all: with no index there is no candidate to call possible. Either way
// the result says "index off", so a gap is reported, never hidden.
//
// The scan reads only this host's own store, through SearchScanSource, never a fetch. A call reads at most
// ScanDocumentCount documents and returns where it stopped, so a page of a large ref costs a bounded walk and the next
// page goes on from there; the source's order is fixed by the source, never by the query.

package sidecar

import (
	"context"
	"fmt"
)

// One document a scan visits: its newest version, and what this host holds of it.
type SearchScanDocument struct {
	// The ref it is on.
	RefId   Id
	Kind    IndexDocKind
	Name    []byte
	Version uint64
	// The version's signed time, ms.
	TimeMs int64
	// A host with the text: the version's documents, one a chunk, as SearchTextSource gives them.
	Documents []*IndexDocument
	// A phone or a browser: the names and mail's i/ fields it holds; nil where Documents is set.
	Display *SearchScanDisplay
}

// What a host without the text holds of a document: its name is the document's, and for mail its i/ entry's fields.
type SearchScanDisplay struct {
	Subject string
	From    string
	To      string
	// The i/ entry's address and snippet (§15.7).
	Address string
	Snippet string
}

// What a host holds of a ref with no index, in a fixed order. Implementations are safe for concurrent use.
type SearchScanSource interface {
	// Visits the ref's documents from this host's own store, each at its newest version, starting after position
	// after (0 starts at the first, whose position is 1) in the source's fixed order, until visit answers false or the
	// ref ends. Never a fetch.
	SearchScan(ctx context.Context, after uint64, visit func(position uint64, document *SearchScanDocument) (bool, error)) error
}

// What a scan reads.
type searchScanArgs struct {
	query      *SearchQuery
	filters    *searchRowFilters
	normalizer *indexNormalizer
	settings   *SearchResultSettings
	source     SearchScanSource
	repoId     Id
	// Where the last page stopped: 0 for the first.
	after uint64
	// The hits a page holds; ConfirmPageHitCount where it is not positive.
	hitCount int
}

// One page of a scan.
type searchScanResult struct {
	hits []*searchRankedHit
	// Where the next page goes on, and whether the ref has no document past it.
	position uint64
	done     bool
	scanned  int
	// Always true: the result says "index off" (§11.14's off row).
	indexOff bool
}

// One page of a no-index scan: verified hits where this host holds the text, hits a name or an i/ field confirms
// where it does not.
func searchNoIndexScan(ctx context.Context, args *searchScanArgs) (*searchScanResult, error) {
	if err := args.settings.check(); err != nil {
		return nil, err
	}
	if args.source == nil {
		return nil, fmt.Errorf("%w: a scan of no source", ErrSearchCacheArgs)
	}
	hitCount := args.hitCount
	if hitCount <= 0 {
		hitCount = args.settings.ConfirmPageHitCount
	}
	result := &searchScanResult{position: args.after, indexOff: true, done: true}
	confirmer := &searchConfirmer{query: args.query, filters: args.filters, normalizer: args.normalizer, settings: args.settings, repoId: args.repoId}
	err := args.source.SearchScan(ctx, args.after, func(position uint64, document *SearchScanDocument) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if len(result.hits) == hitCount || result.scanned == args.settings.ScanDocumentCount {
			result.done = false
			return false, nil
		}
		result.scanned += 1
		result.position = position
		hits, err := searchScanOne(ctx, confirmer, document)
		if err != nil {
			return false, err
		}
		result.hits = append(result.hits, hits...)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// One document's hits: each chunk the text verifies, or the one hit its display fields confirm.
func searchScanOne(ctx context.Context, confirmer *searchConfirmer, document *SearchScanDocument) ([]*searchRankedHit, error) {
	timeSeconds := indexEntrySeconds(document.TimeMs)
	if !confirmer.filters.timeHolds(timeSeconds) {
		return nil, nil
	}
	hit := func(row *indexRow, confirmation *searchConfirmation) *searchRankedHit {
		return &searchRankedHit{
			repoId:      confirmer.repoId,
			refId:       document.RefId,
			version:     document.Version,
			timeSeconds: timeSeconds,
			row:         row,
			match:       confirmation.state,
			snippet:     confirmation.snippet,
			inHeader:    confirmation.inHeader,
			density:     confirmation.density,
			scanned:     true,
		}
	}
	hits := []*searchRankedHit{}
	if document.Display == nil {
		for _, chunk := range document.Documents {
			row := chunk.row(0, false, document.RefId)
			if err := row.check(false); err != nil {
				return nil, err
			}
			texts := &searchRowTexts{normalizer: confirmer.normalizer, row: row, padded: map[int]string{}}
			if holds, err := confirmer.filtersHold(texts); err != nil || !holds {
				if err != nil {
					return nil, err
				}
				continue
			}
			confirmation, err := confirmer.verify(chunk, texts)
			if err != nil {
				return nil, err
			}
			if confirmation.state == searchMatchVerified {
				hits = append(hits, hit(row, confirmation))
			}
		}
		return hits, nil
	}
	row := &indexRow{docKind: document.Kind, locator: string(document.Name)}
	if document.Kind == IndexDocMail {
		row.fields[indexFieldSubject] = document.Display.Subject
		row.fields[indexFieldFrom] = document.Display.From
		row.fields[indexFieldTo] = document.Display.To
	}
	row.fit()
	texts := &searchRowTexts{normalizer: confirmer.normalizer, row: row, padded: map[int]string{}}
	if holds, err := confirmer.filtersHold(texts); err != nil || !holds {
		return nil, err
	}
	confirmation, err := confirmer.confirmByFields(texts, &SearchDisplay{Address: document.Display.Address, Snippet: document.Display.Snippet})
	if err != nil {
		return nil, err
	}
	if confirmation.state == searchMatchConfirmed {
		hits = append(hits, hit(row, confirmation))
	}
	return hits, nil
}
