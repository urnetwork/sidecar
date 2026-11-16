//go:build !sidecar_http && !ios_extension

// Who may ask whom for a remote search (SEARCH-M10-32, SEARCH-M10-33; §11.14's who, eligible and serve rows; R-EVS-25,
// D-EVS-58, FI-24, I-19; DESIGN-DETAILS 7.2.2): eligible_S(d, R, p), which each side evaluates in its own newest
// verified config state S, so a stale or forged view on one side reaches nothing the other refuses. The asker takes
// E1 to E7 (search_remote_order.go); the indexer takes all of it here, as the coverage row the reply carries for each
// repo a request names, the first of eight that holds:
//
//	1 REFUSED_NOT_READER     p is not in RepoReaders(R), whatever d reads, so the row tells p nothing about d; or R is
//	                         unknown, or of a kind E4 bars (secret, config, mailcfg, or one this build does not know);
//	                         or d is not in RepoReaders(R)
//	2 REFUSED_NOT_CONSENTED  R is owner-bound and E5's first line (d a consented device of R's owner) or third (p a
//	                         consented device of the owner, or the subject of a live EvsShare of R) fails
//	3 REFUSED_SCOPE          E5's second line (d's designation at member scope, or network in a network of one
//	                         member), or E6 (a team repo: network scope, or member scope and d and p devices of one
//	                         member), fails
//	4 REFUSED_INDEX_OFF      the ref's IndexSettings in force say off, or the ref has no index root
//	5 REFUSED_FORMAT         the index's format or normalizer is one d does not read
//	6 REFUSED_ALL_ABSENT     d holds no whole snapshot of the index; or the scope is all and d's all is not usable; or
//	                         a key the snapshot's files need is not in d's key store
//	7 SERVED_INDEX           d holds no text of the content ref, or its snapshot holds a bad file its local layer does
//	                         not cover
//	8 SERVED_TEXT
//
// Rows 1 to 3 are the config's, decided here; rows 4 to 8 are the index's, which the serving corpus answers for a repo
// rows 1 to 3 let through (search_remote_serve.go). E1 to E3 for the indexer and the requester are step 2's, decided
// before the body is read: a requester that is not an admitted, untagged, non-ephemeral member device, or an indexer
// that holds no designation naming search, is refused PERMISSION_DENIED before parsing. Both ends reach E1 to E6
// through ConfigState.SearchIndexersFor (TEAM-M10-02), the indexer passing the requester as searcher and finding its
// own id in the answer, so E1 and E2 are judged for it by the same code.
//
// Nothing here creates, derives or unwraps a key. Pure functions of the state they are given.

package sidecar

import (
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// Whether kind is one a remote search may name: owner-bound (vault, mailbox) or a team repo (general, which a group
// inbox is, record, team_record, the directory). Every other kind, those E4 bars and those this build does not know,
// answers none.
func searchRemoteKindOf(kind protocol.RepoKind) (ownerBound bool, ok bool) {
	switch kind {
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX:
		return true, true
	case protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_RECORD, protocol.RepoKind_REPO_KIND_TEAM_RECORD,
		protocol.RepoKind_REPO_KIND_DIRECTORY:
		return false, true
	}
	return false, false
}

// E3 for the requester requesterId in state: admitted and standing (not revoked, parked or past not_after), an
// untagged member device, not ephemeral, and named by no active Suspend. What step 2 asks before it reads a body.
func searchRemoteRequesterStands(state *ConfigState, requesterId Id) bool {
	if state == nil {
		return false
	}
	acl, err := state.Acl()
	if err != nil {
		return false
	}
	row, standing := state.standingSidecar(requesterId, state.timeMs)
	return standing && configRowMemberDevice(row) && !acl.Suspended(requesterId)
}

// Whether selfId holds a designation in state whose services, opened by services, name search, and stands (E1, E2):
// what step 2 asks of this device before it reads a body.
func searchRemoteServesSearch(state *ConfigState, selfId Id, services func(indexer ConfigIndexer) ([]protocol.IndexerService, bool)) bool {
	if state == nil || services == nil {
		return false
	}
	for _, indexer := range state.Indexers() {
		if indexer.SidecarId != selfId {
			continue
		}
		if offered, opened := services(indexer); opened && slices.Contains(offered, protocol.IndexerService_INDEXER_SERVICE_SEARCH) {
			row, standing := state.standingSidecar(selfId, state.timeMs)
			return standing && !row.GetEphemeral() && !configRowReadOnly(row)
		}
	}
	return false
}

// Rows 1 to 3 of the verdict for the repo repoId that requesterId named, in this device's state: the row that refuses
// it, or SERVED_TEXT with ok true where E1 to E6 let selfId answer it, rows 4 to 8 then being the index's to decide.
func searchRemoteConfigVerdict(state *ConfigState, selfId Id, requesterId Id, repoId Id,
	services func(indexer ConfigIndexer) ([]protocol.IndexerService, bool)) (protocol.SearchServed, bool) {
	if state == nil {
		return protocol.SearchServed_REFUSED_NOT_READER, false
	}
	acl, err := state.Acl()
	if err != nil {
		return protocol.SearchServed_REFUSED_NOT_READER, false
	}
	// row 1: the requester's read first, so the row says nothing of what this device reads
	readers := state.RepoReaders(repoId)
	repo := acl.Repo(repoId)
	if !slices.Contains(readers, requesterId) || repo == nil {
		return protocol.SearchServed_REFUSED_NOT_READER, false
	}
	ownerBound, known := searchRemoteKindOf(repo.GetKind())
	if !known || !slices.Contains(readers, selfId) {
		return protocol.SearchServed_REFUSED_NOT_READER, false
	}
	// row 2: an owner-bound repo only on a consented device of its owner, for its owner's device or a share's subject
	if ownerBound {
		ownerId, err := IdFromBytes(repo.GetOwnerMemberId())
		if err != nil || ownerId == (Id{}) || !acl.ConsentedFor(selfId, ownerId) {
			return protocol.SearchServed_REFUSED_NOT_CONSENTED, false
		}
		if !acl.ConsentedFor(requesterId, ownerId) && !state.evsShareSubject(acl, requesterId, repoId) {
			return protocol.SearchServed_REFUSED_NOT_CONSENTED, false
		}
	}
	// row 3: the scope lines, judged with E1 to E6 together by the function both ends call
	if !slices.Contains(state.SearchIndexersFor(requesterId, repoId, services), selfId) {
		return protocol.SearchServed_REFUSED_SCOPE, false
	}
	return protocol.SearchServed_SERVED_TEXT, true
}

// Whether a coverage row's served code serves its repo.
func searchRemoteServes(served protocol.SearchServed) bool {
	return served == protocol.SearchServed_SERVED_TEXT || served == protocol.SearchServed_SERVED_INDEX
}

// own(d, p) (DESIGN-DETAILS 7.2.1): d and p are untagged devices of one member, or the state holds one member (a
// personal network), where every indexer is own.
func searchRemoteOwn(state *ConfigState, indexerId Id, requesterId Id) bool {
	if state == nil {
		return false
	}
	if len(state.members) == 1 {
		return true
	}
	indexer, requester := state.Sidecar(indexerId), state.Sidecar(requesterId)
	if indexer == nil || requester == nil || indexer.Row == nil || requester.Row == nil {
		return false
	}
	indexerMember, indexerUntagged := configRowMember(indexer.Row)
	requesterMember, requesterUntagged := configRowMember(requester.Row)
	return indexerUntagged && requesterUntagged && indexerMember == requesterMember
}

// The notice member of an indexer that is not own (DESIGN-DETAILS 7.2.1): its member, or a tagged device's sponsor
// (§7.9's SponsorSet). False where the state names neither, when no notice can be answered for it.
func searchRemoteNoticeMember(state *ConfigState, indexerId Id) (Id, bool) {
	if state == nil {
		return Id{}, false
	}
	sidecar := state.Sidecar(indexerId)
	if sidecar == nil || sidecar.Row == nil {
		return Id{}, false
	}
	if memberId, untagged := configRowMember(sidecar.Row); untagged {
		return memberId, true
	}
	return state.Sponsor(indexerId)
}
