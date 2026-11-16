//go:build !sidecar_http && !ios_extension

package sidecar

// SEARCH-M10-34: §22.6's merge target against adversarial replies, with DESIGN-DETAILS 7.3's M1 to M4 as its oracle:
// whatever two indexers claim of a document beside the device, a row names an indexer only with that indexer's own
// claim or its fold; every claimed document has a row; a match any source claims shows as a match; and a fold happens
// only over the device's own possible or near claim alone, inside a span.

import (
	"testing"
	"time"
)

func FuzzSearchRemoteMerge(f *testing.F) {
	f.Add(uint8(3), uint8(1), uint8(0), uint8(5), uint8(6), uint8(0), int64(1000), int64(500), false)
	f.Add(uint8(2), uint8(3), uint8(4), uint8(5), uint8(5), uint8(5), int64(1000), int64(0), true)
	f.Add(uint8(0), uint8(1), uint8(1), uint8(1), uint8(9), uint8(2), int64(1), int64(2), false)
	f.Fuzz(func(t *testing.T, ownState uint8, firstState uint8, secondState uint8, ownVersion uint8, firstVersion uint8,
		secondVersion uint8, timeMs int64, checkedMs int64, companion bool) {
		repoId := Id{1}
		merge := testSearchRemoteMergeOf(uint64(ownVersion%8), companion)
		first := testSearchRemoteLegOf(merge, repoId, uint64(firstVersion%8), 10_000_000, checkedMs, 0)
		second := testSearchRemoteLegOf(merge, repoId, uint64(secondVersion%8), 10_000_000, checkedMs, 1)
		key := searchRemoteMergeKey{repoId: repoId, refId: repoId, docKey: testSearchRemoteKey("fuzz")}
		state := func(value uint8) SearchHitState { return SearchHitState(value % 5) }
		claims := map[*searchRemoteSource]SearchHit{}
		add := func(source *searchRemoteSource, value uint8, version uint8) {
			if state(value) == 0 {
				return
			}
			hit := SearchHit{Repo: repoId, Ref: repoId, DocKey: key.docKey, Version: uint64(version), Time: time.UnixMilli(timeMs), State: state(value)}
			merge.add(source, []SearchHit{hit})
			claims[source] = hit
		}
		add(nil, ownState, ownVersion)
		add(first, firstState, firstVersion)
		add(second, secondState, secondVersion)
		row := merge.row(key)
		// M2: a claimed document has a row
		if len(claims) != 0 && row == nil {
			t.Fatalf("no row for a claimed document")
		}
		if row == nil {
			return
		}
		match := false
		indexerClaims := false
		for source, hit := range claims {
			match = match || hit.State == SearchVerified || hit.State == SearchConfirmed
			indexerClaims = indexerClaims || source != nil
		}
		// M3: a match any source claims shows as a match
		if match && row.State != SearchVerified && row.State != SearchConfirmed {
			t.Fatalf("a match shows as %v", row.State)
		}
		// M4: a fold only over the device's own possible or near claim alone
		if row.State == SearchUnmatched {
			own, ok := claims[nil]
			if !ok || indexerClaims || (own.State != SearchPossible && own.State != SearchNear) {
				t.Fatalf("a fold over %v", claims)
			}
			return
		}
		// M1: a row naming an indexer carries that indexer's own claim
		if row.By != "" {
			found := false
			for source, hit := range claims {
				if source != nil && hit.State == row.State && hit.Version == row.Version {
					found = true
				}
			}
			if !found {
				t.Fatalf("a row by an indexer with no such claim: %+v", row)
			}
		}
	})
}
