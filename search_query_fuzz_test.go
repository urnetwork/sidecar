//go:build !js

// §22.6's search-arguments target for the query grammar and the plan (SEARCH-M10-22): any query parses or is refused
// without a panic, a refusal never repeats the query, the trigrams a query can look up stay bounded whatever it holds,
// parsing is a function of the query, and planning any parsed query over a fixed holding stays within its partitions.
// Not on js, where testing.F cannot open its corpus directory.

package sidecar

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// The most trigrams a query within §16.10's limits holds: every window of its 512 normalized bytes, and the padding a
// whole word adds for each of its 16 terms.
const testSearchQueryMaxTrigramCount = searchQueryMaxByteCount + 2*searchQueryMaxTermCount

func FuzzSearchQuery(f *testing.F) {
	for _, seed := range []string{
		"", "rate limiter", `"rate limiter" -draft`, "a OR b OR c", "from:Ann subject:Q3 title:plan", "agent:builder kind:claim",
		"東京 タワー", "\U0002000b", "-", `"`, `""""`, "OR OR OR", "x:y:z", strings.Repeat("w ", 20), strings.Repeat("ﷺ", 30),
		"\xff\xfe invalid", "é", "ß Σ ǅ", "a\x00b",
	} {
		f.Add(seed)
	}
	holding := testSearchHolding()
	f.Fuzz(func(t *testing.T, query string) {
		parsed, err := ParseSearchQuery(query)
		if err != nil {
			if !errors.Is(err, ErrSearchQueryTooLong) {
				t.Fatalf("a refusal other than the limits: %v", err)
			}
			if 3 < len(query) && strings.Contains(err.Error(), query) {
				t.Fatalf("a refusal repeats the query")
			}
			return
		}
		again, err := ParseSearchQuery(query)
		if err != nil || len(again.Groups) != len(parsed.Groups) || len(again.Excluded) != len(parsed.Excluded) {
			t.Fatalf("parsing twice differs: %v", err)
		}
		trigrams := parsed.trigrams()
		if testSearchQueryMaxTrigramCount < len(trigrams) || !slices.IsSorted(trigrams) {
			t.Fatalf("%d trigrams", len(trigrams))
		}
		terms := 0
		for _, group := range parsed.Groups {
			if len(group) == 0 {
				t.Fatal("an empty group")
			}
			for _, term := range group {
				terms += 1
				if term.normalized == "" || len(term.trigrams) == 0 || term.Field < 0 || indexFieldTitle < term.Field {
					t.Fatalf("a term %+v", term)
				}
			}
		}
		if searchQueryMaxTermCount < terms+len(parsed.Excluded) {
			t.Fatalf("%d terms", terms+len(parsed.Excluded))
		}
		plan := searchPlanFor(&searchPlanArgs{holdings: []*searchIndexHolding{holding}, scope: searchPlanAll, nowMs: testDayMs(20375, time.Hour), tables: testSearchTables})
		if len(plan.refs) != 1 || len(holding.buckets)+len(holding.allShards) < len(plan.refs[0].steps) {
			t.Fatalf("a plan of %d steps", len(plan.refs[0].steps))
		}
	})
}
