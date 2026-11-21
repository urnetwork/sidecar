//go:build !ios_extension

// Search's scope (§16.10's scope, excluded and owner-bound rows; D-ACL-14, FI-21; SEARCH-M10-26): which repos and refs
// one network's search reads, from what this sidecar reads by §8.6's local evaluation, never from the query.
//
//	repo      the repos the request names (Repos), on the default ref and each named ref that has an index; a ref
//	          whose index is off or not built is searched as §11.14's off row has it where a scan source is given,
//	          and coverage says so
//	network   every repo of the network this sidecar reads (RepoReaders), narrowed per agent by the scope source,
//	          the team directory included; a ref whose index is off or not built is left out, its reason given
//	excluded  secret repos, which nothing lists; config and mailcfg, which hold no index; repos this sidecar only
//	          deposits to; an owner-bound repo of this device's own member while the device is parked, as consent
//	          pending; a repo this sidecar cannot read is never listed, named in the request or not
//	receipts  an owner-bound repo read by a reader that is not its writer is searched only once its read receipts
//	          landed (search_receipts.go); one whose receipt did not land is skipped, coverage naming it
//	age       a repo's log's searchable_days (§16.8), as SearchableAge, masks its older documents from every search at
//	          query time, all included (§16.10's merge row), each mask taking it at the search's open
//	          (searchSearchableSinceSeconds); a document so masked stays in the index and readable by id, so a later
//	          rise finds it again with no rebuild (FS-76, FS-87; QD-1104)
//
// The scope source is the composition's: §8.6's evaluation over the installed AclState with this sidecar's refs
// (evs's EvsRepo and the agent's narrowing, §5.5, §8.4). The resolution here is a pure function of what it answers and
// the request. On every leg but ios_extension: root Id, no connect type.

package sidecar

import (
	"context"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One repo of the network as search's scope reads it.
type SearchScopeRepo struct {
	RepoId     Id
	Kind       protocol.RepoKind
	GroupInbox bool
	// This sidecar reads it: a repo it does not read is never listed.
	Readable bool
	// Whether this verified host view still stands when a page or hit reference is opened.
	valid func() bool
	// It may only deposit to it.
	DepositOnly bool
	// Owner-bound and its own member's while this device is parked (owner decision 126).
	ConsentPending bool
	// A read of it needs a read receipt first: owner-bound, and this sidecar not its writer (§16.10's owner-bound row,
	// AclEngine.ReadRequiresReceipt).
	ReceiptRequired bool
	// The refs it is followed on for search: its default ref first.
	Refs []*SearchScopeRef
	// Its log's searchable_days (§16.8) as an age, at the retention's day length: a document whose index time is
	// older than this at a search's open is masked from that search, all included. 0 or less masks none, as a
	// searchable_days of 0 does. The scope source's to give from the policy that governs the log.
	SearchableAge time.Duration
}

// The time before which a document's index time is past age at nowMs, in seconds, as searchMaskArgs reads it: rounded
// up, so a row a whole second short of the cut is masked and one at it is not. 0, which masks none, for an age of 0
// or less, or one reaching back to the epoch.
func searchSearchableSinceSeconds(nowMs int64, age time.Duration) uint64 {
	if age <= 0 {
		return 0
	}
	sinceMs := nowMs - age.Milliseconds()
	if sinceMs <= 0 {
		return 0
	}
	return uint64((sinceMs + 999) / 1000)
}

// One ref of a repo search follows.
type SearchScopeRef struct {
	RefId Id
	// The verified local name of this content ref.
	Name string
	// The repo's default ref.
	Default bool
	// The index rides the repo's ur/index (git-mode refs, record streams), whose rows carry their ref_id.
	Companion bool
	// The index is off, or not built yet (owner decision 156).
	IndexOff bool
	Unbuilt  bool
	// A previously verified local pin must still match when a result page or hit is used.
	valid func() bool
}

// What a search's scope is read from. Safe for concurrent use.
type SearchScopeSource interface {
	// Every repo of the network this sidecar holds a grant on, as §8.6 evaluates it now, narrowed to what the asking
	// agent may read.
	Repos(ctx context.Context) ([]*SearchScopeRepo, error)
}

// One ref a search reads.
type searchScopedRef struct {
	repo *SearchScopeRepo
	ref  *SearchScopeRef
	// Its place in the request's order, which breaks time ties (DESIGN-DETAILS 7.2.5's candidate order).
	index int
	// No index serves it: scanned by §11.14's off row where a scan source is given.
	scan bool
}

// The refs a request reads and what it leaves out, from repos as the scope source answered them.
func searchResolveScope(repos []*SearchScopeRepo, request *SearchRequest) ([]*searchScopedRef, []SearchExclusion) {
	breadth := searchBreadthOf(request)
	named := map[Id]int{}
	for index, repoId := range request.Repos {
		if _, ok := named[repoId]; !ok {
			named[repoId] = index
		}
	}
	ordered := slices.DeleteFunc(slices.Clone(repos), func(repo *SearchScopeRepo) bool { return repo == nil })
	slices.SortStableFunc(ordered, func(a *SearchScopeRepo, b *SearchScopeRepo) int {
		if breadth == SearchBreadthRepo {
			return named[a.RepoId] - named[b.RepoId]
		}
		return a.RepoId.Cmp(b.RepoId)
	})
	scoped := []*searchScopedRef{}
	excluded := []SearchExclusion{}
	for _, repo := range ordered {
		if request.allowRepo != nil && !request.allowRepo(repo.RepoId) {
			continue
		}
		if !repo.Readable && !repo.DepositOnly {
			// a repo this sidecar cannot read is never listed
			continue
		}
		if _, ok := named[repo.RepoId]; breadth == SearchBreadthRepo && !ok {
			continue
		}
		switch repo.Kind {
		case protocol.RepoKind_REPO_KIND_SECRET:
			// search_status omits it (16.6)
			continue
		case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_UNSPECIFIED:
			excluded = append(excluded, SearchExclusion{RepoId: repo.RepoId, Reason: SearchExcludedNoIndex})
			continue
		}
		switch {
		case !repo.Readable:
			excluded = append(excluded, SearchExclusion{RepoId: repo.RepoId, Reason: SearchExcludedDepositOnly})
			continue
		case repo.ConsentPending:
			excluded = append(excluded, SearchExclusion{RepoId: repo.RepoId, Reason: SearchExcludedConsentPending})
			continue
		}
		if len(repo.Refs) == 0 {
			excluded = append(excluded, SearchExclusion{RepoId: repo.RepoId, Reason: SearchExcludedUnbuilt})
			continue
		}
		selected := false
		for index, ref := range repo.Refs {
			if ref == nil || ref.Name == string(EvsIndexRefName) {
				continue
			}
			if breadth == SearchBreadthRepo {
				switch {
				case request.Ref == "":
					if !ref.Default && index != 0 {
						continue
					}
				case request.Ref == ref.Name, request.Ref == "id:"+ref.RefId.String():
				case ref.Default && ref.Name == "" && request.Ref == string(EvsMainRefName):
				default:
					continue
				}
			}
			selected = true
			if ref.IndexOff || ref.Unbuilt {
				reason := SearchExcludedUnbuilt
				if ref.IndexOff {
					reason = SearchExcludedIndexOff
				}
				if breadth != SearchBreadthRepo {
					refId := ref.RefId
					excluded = append(excluded, SearchExclusion{RepoId: repo.RepoId, RefId: &refId, Reason: reason})
					continue
				}
				scoped = append(scoped, &searchScopedRef{repo: repo, ref: ref, index: len(scoped), scan: true})
				continue
			}
			scoped = append(scoped, &searchScopedRef{repo: repo, ref: ref, index: len(scoped)})
		}
		if !selected && breadth == SearchBreadthRepo && request.Ref != "" {
			excluded = append(excluded, SearchExclusion{RepoId: repo.RepoId, Reason: SearchExcludedUnbuilt})
		}
	}
	return scoped, excluded
}
