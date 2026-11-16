//go:build !ios_extension

// Trust and taint (§16.10's Trust and taint block; §16.11's prose, identifiers, classes and stubs rows; R-MCP-14,
// D-MCP-16, D-MCP-29, I-7, I-9, FI-21, FS-80; SEARCH-M10-27): what a hit is to its reader, and what an untrusted one
// shows by default.
//
//	trust      per hit, from its row's tainted and outside bits and its writer: own (a device of the reader's member),
//	           member (another member's sidecar, or one a member sponsors), untrusted (the content came from outside the
//	           network or by a signed import, a tainted run wrote it, or its writer is none the reader's state names);
//	           a file's or a message's row keeps no writer, and every writer of a repo is a sidecar of the network, so
//	           such a hit is a member's, own being claimed only for a writer the reader can name
//	directory  the team directory's announcements, requests and decisions are untrusted whoever wrote them, since they
//	           reach every member's agents with no person reading them first; its coordination entries (ask, answer,
//	           check, note) keep the record rule (§16.11's prose row; owner decision 142)
//	remote     a hit an indexer served carries the trust it judged relative to its requester; this device keeps the
//	           lower of that and what it judges of the writer itself, so a served hit never reads above this device's
//	           own view
//	withhold   by default an untrusted hit returns as a stub: its doc key and kind, version, time, match, partition and
//	           trust, with no path, snippet, correction or name, and of its fields only its kind (field 6); a directory
//	           stub keeps its attested fields (ids, kinds and states: 7 as its signer, 8, 10, 11, 14 and 15) and, where
//	           the writing run was untainted and its writer a member's sidecar, its identifier fields (9 the agent
//	           label, 12 the project, 13 the branch); each counts as untrusted_withheld, and the run stays untainted
//	include    the caller taints the run, fsynced, before any untrusted text is read into a result (D-MCP-16):
//	           searchWithhold calls its taint before it keeps the first untrusted hit whole, and a failed taint fails
//	           the call with nothing returned
//	secrets    a hit whose path, field, snippet or correction holds the daemon's credentials or a token form returns as
//	           a stub, those fields left out, whatever its trust and whether or not include was asked, so no search
//	           result carries one (I-7); the MCP framework's matcher refuses a whole result besides
//
// A record row's writer is its field 7, which the index's writers copy from the entry's header; hosts with the text
// check it against the entry (SEARCH-M10-21's check), and elsewhere trust rests on it as the index does. Nothing here
// logs a hit (I-13). Safe for concurrent use: every function reads only its arguments.

package sidecar

import (
	"context"
	"errors"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// Untrusted text was asked for where nothing can taint the run first (D-MCP-16): nothing is returned. Constant text.
var ErrSearchToolInclude = errors.New("search: untrusted text is returned only once the run is tainted, which this caller cannot do")

// §16.10's trust of a hit relative to its reader (search.proto's SearchHit.trust).
type SearchTrust string

const (
	SearchTrustOwn       SearchTrust = "own"
	SearchTrustMember    SearchTrust = "member"
	SearchTrustUntrusted SearchTrust = "untrusted"
)

// A record or directory row's registered fields this file and grouping read, by §16.8's and §16.11's registries
// (evs_index_fields.go). Field 7, the writer or sidecar_id, is a hit's Signer and never one of its Fields.
const (
	// 6: a record's kind, a directory announcement's or entry's kind.
	searchFieldKind = indexFieldFirstRegistered
	// 8 and 9 in both registries.
	searchFieldAgentId    = indexFieldFirstRegistered + 2
	searchFieldAgentLabel = indexFieldFirstRegistered + 3
	// 10 in both.
	searchFieldRunId = indexFieldFirstRegistered + 4
	// A record's 13 and 14.
	searchFieldClaimExpires = indexFieldFirstRegistered + 7
	searchFieldClaimState   = indexFieldFirstRegistered + 8
	// The directory's 11 to 15.
	searchFieldMemberId = indexFieldFirstRegistered + 5
	searchFieldProject  = indexFieldFirstRegistered + 6
	searchFieldBranch   = indexFieldFirstRegistered + 7
	searchFieldRepoId   = indexFieldFirstRegistered + 8
	searchFieldState    = indexFieldFirstRegistered + 9
)

// The directory's stream entry kinds whose prose keeps the record rule's trust (§16.11's prose row); every other
// directory document's prose is untrusted whoever wrote it. Identifiers: RECORD.md's kind names.
var searchDirectoryCoordinationKinds = []string{"ask", "answer", "check", "note"}

// The directory's attested fields beside its signer, which a stub keeps (§16.11's classes row): kind, agent_id,
// run_id, member_id, repo_id and state.
var searchDirectoryAttestedFields = []int{searchFieldKind, searchFieldAgentId, searchFieldRunId, searchFieldMemberId, searchFieldRepoId, searchFieldState}

// The directory's identifier fields, which a stub keeps where they hold member trust (§16.11's identifiers row): the
// agent label, the project and the branch.
var searchDirectoryIdentifierFields = []int{searchFieldAgentLabel, searchFieldProject, searchFieldBranch}

// A trust's rank: untrusted, and an unjudged trust, below member below own.
func searchTrustRank(trust SearchTrust) int {
	switch trust {
	case SearchTrustOwn:
		return 2
	case SearchTrustMember:
		return 1
	}
	return 0
}

// The lower of a and b; an unjudged trust reads untrusted.
func searchTrustMin(a SearchTrust, b SearchTrust) SearchTrust {
	lower := a
	if searchTrustRank(b) < searchTrustRank(a) {
		lower = b
	}
	if searchTrustRank(lower) == 0 {
		return SearchTrustUntrusted
	}
	return lower
}

// Whether a hit of this trust shows its text by default.
func (self SearchTrust) shown() bool {
	return self == SearchTrustOwn || self == SearchTrustMember
}

// What a hit's trust is judged against: the reader's member, and §16.6's team views of the network's sidecars and
// repos, from the reader's newest verified config state. On an indexer serving a remote search, the requester's.
type SearchTrustReader struct {
	// The reader's member.
	MemberId Id
	// The member a sidecar belongs to, or the member who sponsors a tagged one; false for a sidecar the state does not
	// name. Nil names none, so every writer reads untrusted.
	MemberOf func(sidecarId Id) (Id, bool)
	// A repo's kind; nil reads every repo as a general one.
	RepoKind func(repoId Id) protocol.RepoKind
}

// Whether repoId is the team directory.
func (self *SearchTrustReader) directory(repoId Id) bool {
	return self != nil && self.RepoKind != nil && self.RepoKind(repoId) == protocol.RepoKind_REPO_KIND_DIRECTORY
}

// The member of a writer, false where the reader's state names none.
func (self *SearchTrustReader) memberOf(sidecarId Id) (Id, bool) {
	if self == nil || self.MemberOf == nil || sidecarId == (Id{}) {
		return Id{}, false
	}
	return self.MemberOf(sidecarId)
}

// The trust of what signer wrote: own, member, or untrusted for a writer the state does not name; no writer, as a
// file's or a message's row keeps none, reads member.
func (self *SearchTrustReader) writerTrust(signer Id) SearchTrust {
	if signer == (Id{}) {
		return SearchTrustMember
	}
	memberId, ok := self.memberOf(signer)
	switch {
	case !ok:
		return SearchTrustUntrusted
	case memberId == self.MemberId:
		return SearchTrustOwn
	}
	return SearchTrustMember
}

// The trust of hit for reader (see the file header); a nil reader reads every hit untrusted.
func searchTrustOf(hit *SearchHit, reader *SearchTrustReader) SearchTrust {
	if reader == nil {
		return SearchTrustUntrusted
	}
	if hit.By != "" {
		// an indexer's hit: its judgement for this requester, never above this device's own of the writer
		return searchTrustMin(hit.Trust, reader.writerTrust(hit.Signer))
	}
	if hit.Tainted || hit.Outside {
		return SearchTrustUntrusted
	}
	if reader.directory(hit.Repo) && !slices.Contains(searchDirectoryCoordinationKinds, searchHitField(hit, searchFieldKind)) {
		return SearchTrustUntrusted
	}
	return reader.writerTrust(hit.Signer)
}

// Judges each hit's trust in place, and answers the lowest, own for none.
func searchJudgeTrust(hits []SearchHit, reader *SearchTrustReader) SearchTrust {
	lowest := SearchTrustOwn
	for index := range hits {
		hits[index].Trust = searchTrustOf(&hits[index], reader)
		lowest = searchTrustMin(lowest, hits[index].Trust)
	}
	return lowest
}

// The text of a hit's field, "" for none.
func searchHitField(hit *SearchHit, field int) string {
	for _, held := range hit.Fields {
		if held.Field == field {
			return held.Text
		}
	}
	return ""
}

// Whether a directory hit's identifier fields keep member trust: the run that wrote it was untainted, nothing of it
// came from outside, and its writer is a member's sidecar (§16.11's identifiers row). A served hit carries no bits, so
// its identifiers are withheld.
func searchIdentifiersShown(hit *SearchHit, reader *SearchTrustReader) bool {
	if hit.Tainted || hit.Outside || hit.By != "" {
		return false
	}
	_, ok := reader.memberOf(hit.Signer)
	return ok
}

// An untrusted hit as its stub (§16.10's withhold row): what places the document without its text. A record keeps its
// kind; a directory hit its signer and attested fields, and its identifier fields where they hold member trust.
func searchStubOf(hit *SearchHit, reader *SearchTrustReader) SearchHit {
	stub := SearchHit{
		Repo: hit.Repo, Ref: hit.Ref, Version: hit.Version, Time: hit.Time, State: hit.State, Partition: hit.Partition,
		By: hit.By, DocKey: hit.DocKey, DocKind: hit.DocKind, Tainted: hit.Tainted, Outside: hit.Outside,
		Started: hit.Started, Expires: hit.Expires, PartitionName: hit.PartitionName, Trust: hit.Trust, Withheld: true,
	}
	kept := []int{searchFieldKind}
	if reader.directory(hit.Repo) {
		stub.Signer = hit.Signer
		kept = append(kept, searchDirectoryAttestedFields...)
		if searchIdentifiersShown(hit, reader) {
			kept = append(kept, searchDirectoryIdentifierFields...)
		}
	}
	for _, field := range hit.Fields {
		if slices.Contains(kept, field.Field) {
			stub.Fields = append(stub.Fields, field)
		}
	}
	return stub
}

// Whether any text of hit matches secret: its path, a field, its snippet or its correction.
func searchHitHoldsSecret(hit *SearchHit, secret func(text []byte) bool) bool {
	if secret([]byte(hit.Path)) || secret([]byte(hit.Snippet)) || secret([]byte(hit.Correction)) {
		return true
	}
	for _, field := range hit.Fields {
		if secret([]byte(field.Text)) {
			return true
		}
	}
	return false
}

// How hits are withheld for one call.
type searchWithholdArgs struct {
	reader *SearchTrustReader
	// Untrusted text is returned, the run tainted first.
	include bool
	// Taints the call's run, fsynced (D-MCP-16): called once, before the first untrusted hit is kept whole. Nil with
	// include refuses the call.
	taint func(ctx context.Context) error
	// The daemon's credentials and token forms; nil matches nothing.
	secret func(text []byte) bool
}

// The trust of what a hit shows as returned: a whole hit's own trust; a stub shows only attested fields, which the
// reader checks against its own state, and identifier fields where they hold member trust (§16.11's classes and
// identifiers rows), so it reads own where it names one of the reader's own sidecars and member otherwise, never
// untrusted, and returning one taints nothing.
func searchShownTrust(view *SearchHit, reader *SearchTrustReader) SearchTrust {
	if !view.Withheld {
		return searchTrustMin(view.Trust, view.Trust)
	}
	if view.Signer != (Id{}) && reader.writerTrust(view.Signer) == SearchTrustOwn {
		return SearchTrustOwn
	}
	return SearchTrustMember
}

// What withholding gave.
type searchWithheld struct {
	// Each hit as it is returned, whole or as its stub, in the order given.
	hits []SearchHit
	// The lowest trust of what they show (searchShownTrust), own for none: what the result's tags carry.
	trust SearchTrust
	// Untrusted hits returned as stubs (§16.10's untrusted_withheld).
	untrustedCount int
	// Hits whose text held a credential, returned as stubs whatever their trust (I-7).
	secretCount int
	// Untrusted text is among the hits: the run was tainted for it.
	untrusted bool
}

// The hits a call returns, each judged already (searchJudgeTrust): see the file header. ErrSearchToolInclude for
// include with no taint, and the taint's error, which returns nothing.
func searchWithhold(ctx context.Context, hits []SearchHit, args *searchWithholdArgs) (*searchWithheld, error) {
	if args.include && args.taint == nil {
		return nil, ErrSearchToolInclude
	}
	withheld := &searchWithheld{hits: make([]SearchHit, 0, len(hits)), trust: SearchTrustOwn}
	for index := range hits {
		hit := &hits[index]
		switch {
		case args.secret != nil && searchHitHoldsSecret(hit, args.secret):
			withheld.secretCount += 1
			stub := searchStubOf(hit, args.reader)
			stub.Fields = slices.DeleteFunc(stub.Fields, func(field SearchField) bool { return args.secret([]byte(field.Text)) })
			withheld.hits = append(withheld.hits, stub)
		case hit.Trust.shown():
			withheld.hits = append(withheld.hits, *hit)
		case !args.include:
			withheld.untrustedCount += 1
			withheld.hits = append(withheld.hits, searchStubOf(hit, args.reader))
		default:
			if !withheld.untrusted {
				// the taint is fsynced before the first untrusted text joins the result (D-MCP-16)
				testHookBarrier("search.trust.taint.before", hit.Repo.String())
				if err := args.taint(ctx); err != nil {
					return nil, err
				}
				testHookBarrier("search.trust.taint.after", hit.Repo.String())
				withheld.untrusted = true
			}
			withheld.hits = append(withheld.hits, *hit)
		}
	}
	for index := range withheld.hits {
		withheld.trust = searchTrustMin(withheld.trust, searchShownTrust(&withheld.hits[index], args.reader))
	}
	return withheld, nil
}
