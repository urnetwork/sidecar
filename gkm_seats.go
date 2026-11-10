// Who sits in a group's tree (§8.12, §7.9's leaves row; owner decisions 114, 144, 182; D-KEYS-2), as gkm's client
// reads it from GkmAuthView:
//
//	config, directory   §7.9's leaves rule: the live member devices reading the repo, ranked by (live_since,
//	                    sidecar_id), the first GkmSeatCount leaf-entitled and the rest reading by wraps; a newly live
//	                    device ranks last, so one that stays live never loses entitlement, and when an entitled one
//	                    stops being live the first wrapped one by rank becomes entitled (the move row)
//	data                a member device keeps its leaf until a Remove; a free seat goes to the earliest-admitted
//	                    waiting member device that has a KeyPackage, by (admitted_at, sidecar_id); the 1,001st
//	                    waits keyless and is named in the writer's preview
//
// Seats live in the tree, not in the log: KeyHolders counts every member device reading a repo, seated or not, so
// which devices wait comes from the caller's tree and gkm's KeyPackage listing, and everything here is a pure
// function of them, the state and the time. The leaves rule is written over a repo's readers, so the team
// directory's group reuses it at M6 as it stands.
//
// A state that answers §7.9's rank itself (AclLeafRankView, which TEAM's ConfigState implements) is asked; one that
// does not, a fixture's, is ranked here from its rows, the same rule over the same fields.
//
// Pure, on every leg. Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"cmp"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §7.9's leaves rank of a repo at a state and time: every live member device reading it, by (live_since,
// sidecar_id).
func GkmLeafRank(view GkmAuthView, repoId Id, at time.Time) []Id {
	type ranked struct {
		sidecarId Id
		liveSince uint64
	}
	rankeds := []ranked{}
	for _, readerId := range view.RepoReadersAt(repoId, at) {
		row := view.SidecarRow(readerId)
		if !gkmRowMemberDevice(row) || !gkmRowStanding(row) {
			continue
		}
		rankeds = append(rankeds, ranked{sidecarId: readerId, liveSince: row.GetLiveSince()})
	}
	slices.SortFunc(rankeds, func(a ranked, b ranked) int {
		if c := cmp.Compare(a.liveSince, b.liveSince); c != 0 {
			return c
		}
		return a.sidecarId.Cmp(b.sidecarId)
	})
	order := make([]Id, 0, len(rankeds))
	for _, entry := range rankeds {
		order = append(order, entry.sidecarId)
	}
	return order
}

// Whether a device is leaf-entitled in a leaf-ranked group at a state and time: among the first GkmSeatCount of
// §7.9's rank.
func GkmLeafEntitled(view GkmAuthView, repoId Id, sidecarId Id, at time.Time) bool {
	if rankView, ok := view.(AclLeafRankView); ok {
		return rankView.LeafEntitled(sidecarId)
	}
	rank, ranked := gkmFindId(GkmLeafRank(view, repoId, at), sidecarId)
	return ranked && rank < GkmSeatCount
}

// The member devices that read a leaf-ranked repo past the first GkmSeatCount, by rank: they read by wraps, as
// agents do.
func GkmWrappedMembers(view GkmAuthView, repoId Id, at time.Time) []Id {
	order := GkmLeafRank(view, repoId, at)
	if len(order) <= GkmSeatCount {
		return []Id{}
	}
	return slices.Clone(order[GkmSeatCount:])
}

// One waiting device of a data repo, as a committer ranks it.
type gkmSeatCandidate struct {
	sidecarId  Id
	admittedAt uint64
}

// The member devices that take a data repo's free seats now (§8.12): of the candidates, each a reading member
// device outside the tree that has a KeyPackage gkm serves, the earliest-admitted first by (admitted_at,
// sidecar_id), up to freeSeatCount. The rest wait keyless.
func gkmFillSeats(view GkmAuthView, candidateIds []Id, freeSeatCount int) (seated []Id, waiting []Id) {
	candidates := []gkmSeatCandidate{}
	for _, candidateId := range candidateIds {
		var row *bridge.SidecarRow = view.SidecarRow(candidateId)
		if row == nil {
			continue
		}
		candidates = append(candidates, gkmSeatCandidate{sidecarId: candidateId, admittedAt: row.GetAdmittedAt()})
	}
	slices.SortFunc(candidates, func(a gkmSeatCandidate, b gkmSeatCandidate) int {
		if c := cmp.Compare(a.admittedAt, b.admittedAt); c != 0 {
			return c
		}
		return a.sidecarId.Cmp(b.sidecarId)
	})
	seated = []Id{}
	waiting = []Id{}
	for _, candidate := range candidates {
		if len(seated) < freeSeatCount {
			seated = append(seated, candidate.sidecarId)
		} else {
			waiting = append(waiting, candidate.sidecarId)
		}
	}
	return seated, waiting
}
