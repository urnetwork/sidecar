//go:build !ios_extension

// What the search engine adds to §5.4's types (sidecar_search.go, CORE-M10-03's declarations, which this fills rather
// than redeclares): §16.10's breadth (QD-572), the exclusions and coverage a search and search_status name, the
// counts a page carries, and how a ranked hit becomes §5.4's SearchHit (SEARCH-M10-26).
//
// Breadth: repo when the request names repos, else network, every repo of this sidecar's network it reads; all, every
// network a daemon hosts, is the daemon's fan-out over one engine a network (owner decision 23), each hit naming its
// network. Nothing here holds a query: a hit carries its display fields and snippet, which live only in the page and
// its cursor (I-13, R-CORE-18).
//
// On every leg but ios_extension: root Id, no connect type.

package sidecar

import (
	"errors"
	"time"
)

var (
	// The call could not start within its wait: the session's searches at once (Search.SessionSearchCount), its rate
	// (Search.SessionSearchRate) or the daemon's (Search.DaemonSearchCount). Retryable (§16.10's limits row).
	ErrSearchBusy = errors.New("search: busy")
	// The cursor ended: idle past Search.CursorTimeout, dropped past Search.SessionCursorCount, or an erasure, a CUT, a
	// drop or a lost read in its scope (§16.10's pages row). No page of it is given again.
	ErrSearchCursorExpired = errors.New("search: cursor expired")
	// The cursor is none this session holds: forged, another session's, or malformed (§22.6's cursor target).
	ErrSearchCursorInvalid = errors.New("search: cursor invalid")
)

// §16.10's breadth (QD-572).
type SearchBreadth int

const (
	// The repos the request names.
	SearchBreadthRepo SearchBreadth = 1
	// Every repo of this sidecar's network it reads by §8.6's local evaluation, narrowed per agent: the default.
	SearchBreadthNetwork SearchBreadth = 2
	// Network breadth in every network the daemon hosts: the daemon's fan-out over each network's engine.
	SearchBreadthAll SearchBreadth = 3
)

// A request's breadth on one network's engine: repo when it names repos, else network.
func searchBreadthOf(request *SearchRequest) SearchBreadth {
	if 0 < len(request.Repos) {
		return SearchBreadthRepo
	}
	return SearchBreadthNetwork
}

// Why a repo or ref is not searched (§16.10's excluded row). search_status gives each; a secret repo, and a repo this
// sidecar cannot read, are never listed at all.
const (
	// config and mailcfg hold no index.
	SearchExcludedNoIndex = "no_index"
	// This sidecar only deposits to it.
	SearchExcludedDepositOnly = "deposit_only"
	// An owner-bound repo of this device's own member while the device is parked (owner decision 126).
	SearchExcludedConsentPending = "consent_pending"
	// Outside repo breadth, a ref whose index is off or not built (owner decision 156).
	SearchExcludedIndexOff = "index_off"
	SearchExcludedUnbuilt  = "unbuilt"
	// An owner-bound repo whose read receipt did not land: skipped (§16.10's owner-bound row).
	SearchExcludedReceipt = "receipt"
	// The index is in a newer format or normalizer than this build reads: status update.
	SearchExcludedUpdate = "update"
)

// One repo or ref a search left out, and why.
type SearchExclusion struct {
	RepoId Id
	// The ref, where one ref of the repo is left out; nil for the whole repo.
	RefId  *Id
	Reason string
}

// One ref's coverage in a search (§16.10's coverage row): a gap is reported, never hidden.
type SearchRepoCoverage struct {
	RepoId Id
	RefId  Id
	// The index ref's version the snapshot is whole at, and the newest version of the content ref up to which every
	// push is indexed; 0 where not known, which claims nothing.
	PinVersion     uint64
	IndexedThrough uint64
	// The start of the oldest bucket held: what the buckets alone cover from.
	LatestFrom time.Time
	// all's state: "current", "stale" (held, not usable), "absent", or "fetching" with AllSearched of AllTotal shards.
	All         string
	AllSearched int
	AllTotal    int
	// "searched", or one of the exclusion reasons for a ref outside the search.
	State string
}

// A record row's field 7, its writer's sidecar_id (§16.10's records doc table): a field number.
const searchFieldWriter = indexFieldFirstRegistered + 1

// all's states in coverage.
const (
	SearchAllCurrent  = "current"
	SearchAllStale    = "stale"
	SearchAllAbsent   = "absent"
	SearchAllFetching = "fetching"
)

// What a search's pages have found so far (§16.10's counts).
type SearchHitCounts struct {
	Confirmed int
	Possible  int
	Near      int
	Masked    int
	Repos     int
	Excluded  int
	// Candidates the page left unchecked: the counts read "about n".
	Pending int
}

// A ranked hit as §5.4's SearchHit: the row's locator as the path, its header fields as display fields, the match as
// the state, and the partition it came from.
func searchHitOf(hit *searchRankedHit) SearchHit {
	result := SearchHit{
		Repo:       hit.repoId,
		Ref:        hit.refId,
		Version:    hit.version,
		Time:       time.Unix(int64(hit.timeSeconds), 0).UTC(),
		Snippet:    hit.snippet,
		Correction: hit.correction,
		Partition:  SearchPartitionLatest,
	}
	if hit.partition == searchPartitionAll {
		result.Partition = SearchPartitionAll
	}
	result.PartitionName = searchPartitionName(hit.partition, hit.scanned)
	if !hit.scanned {
		result.DocKey = hit.key
	}
	if hit.row != nil {
		result.Path = hit.row.locator
		result.DocKind = int(hit.row.docKind)
		result.Tainted = hit.row.flags&indexRowTainted != 0
		result.Outside = hit.row.flags&indexRowOutside != 0
		result.Cut = hit.row.flags&indexRowInexact != 0
		for field := indexFieldSubject; field <= indexFieldLast; field += 1 {
			result.Cut = result.Cut || hit.row.flags&indexRowCutFlag(field) != 0
		}
		if hit.row.startedSeconds != 0 {
			result.Started = time.Unix(int64(hit.row.startedSeconds), 0).UTC()
		}
		if hit.row.expiresSeconds != 0 {
			result.Expires = time.Unix(int64(hit.row.expiresSeconds), 0).UTC()
		}
		for field := indexFieldSubject; field <= indexFieldTitle; field += 1 {
			if text := hit.row.fields[field]; text != "" {
				result.Fields = append(result.Fields, SearchField{Field: field, Text: text})
			}
		}
		if hit.row.docKind.hasRegisteredFields() {
			if writer, err := ParseId(hit.row.fields[searchFieldWriter]); err == nil {
				result.Signer = writer
			}
			for field := indexFieldFirstRegistered; field <= indexFieldLast; field += 1 {
				if field == searchFieldWriter {
					// the hit's Signer
					continue
				}
				if text := hit.row.fields[field]; text != "" {
					result.Fields = append(result.Fields, SearchField{Field: field, Text: text})
				}
			}
		}
	}
	switch {
	case hit.near:
		result.State = SearchNear
	case hit.match == searchMatchVerified:
		result.State = SearchVerified
	case hit.match == searchMatchConfirmed:
		result.State = SearchConfirmed
	default:
		result.State = SearchPossible
	}
	return result
}

// §16.10's name of the partition a hit came from: local, current, previous, older or all; "" for a scan of a ref with
// no index (§16.10's source content).
func searchPartitionName(partition searchPartitionKind, scanned bool) string {
	if scanned {
		return ""
	}
	switch partition {
	case searchPartitionLocal:
		return "local"
	case searchPartitionPrevious:
		return "previous"
	case searchPartitionOlder:
		return "older"
	case searchPartitionAll:
		return "all"
	}
	return "current"
}

// About the bytes a hit takes in an MCP page (§16.10's result row): its strings and a fixed share for the rest, so a
// page stops before Search.PageByteCount.
func searchHitByteCount(hit *SearchHit) int {
	byteCount := 256 + len(hit.Path) + len(hit.Snippet) + len(hit.Correction) + len(hit.By)
	for _, field := range hit.Fields {
		byteCount += 16 + len(field.Text)
	}
	return byteCount
}
