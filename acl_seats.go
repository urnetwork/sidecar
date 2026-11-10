// §8.12's seats in a data repo's group (owner decisions 114, 144, 182; D-ACL-17, D-KEYS-2):
//
//	data      member devices stay leaves of the data repos they read, at most 1,000 a repo; a reader without a seat
//	          waits keyless, and the writer's preview and the console name the repo; committers fill a free seat with
//	          the earliest-admitted waiting member device that has a KeyPackage (KF2), members checking only that it
//	          reads and the 1,000 bound; a seated device keeps its leaf until a Remove, and an external commit that
//	          adds a leaf needs a free seat
//
// Every repo but two is a data repo. The config group and a team directory's follow §7.9's leaves rule instead (the
// one exception, owner decision 182), which TEAM's ConfigState.LeafEntitled decides and KEYS commits, so nothing here
// plans their seats. Tagged, ephemeral, CI and cloud sidecars hold ReaderWraps and never take a seat (D-KEYS-11).
//
// Seats live in the group's tree, not in the log: §10.5's KeyHolders counts every member device reading a repo,
// seated or not, so its hash stays a function of the log (gkm_holders.go). So the leaves and which waiting devices have
// a KeyPackage come from the caller, a committer's MLS state and gkm's listing, and this stays a pure function of
// them, the state and the time. Earliest-admitted means by (admitted_at, sidecar_id), the position of the admitting
// entry and then the id, which one entry carrying several admissions needs.
//
// The writer's preview reads AclUnseated, which names each data repo whose reading member devices pass its 1,000
// seats, from the trees the writer holds where it holds them, else as the rule's steady state, the earliest-admitted
// 1,000 seated (§8.8's Saving).
//
// Pure: no clock, no I/O. On every leg, the sidecar_http page Worker's included: root Id, no connect type. Nothing
// here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"
)

// The most leaves a group's tree holds: MLS's 1,000 (D-KEYS-2), a protocol constant every member holds alike.
const aclRepoSeatCount = 1000

// Why AclDataSeats has no plan: the rows hold no such repo, or its group seats by §7.9's leaves rule instead.
var ErrAclNoDataSeats = errors.New("no data seats")

// What a committer of a data repo's group commits next, at a state and a time (§8.12, KF2).
type AclDataSeatPlan struct {
	// Leaves that keep their seats, sorted: member devices that still read the repo. A seated device is never
	// displaced, whoever waits.
	Seated []Id
	// Leaves due a Remove, sorted, each freeing its seat: no longer a reader, or no member device (§10.9's Remove row).
	Removes []AclNonReader
	// Waiting member devices that take a free seat now, earliest-admitted first, each with a KeyPackage. The free
	// seats count Removes as done, so they commit with or after the Removes, which MLS applies first in one commit.
	Adds []Id
	// Reading member devices left without a seat, earliest-admitted first: each waits keyless, with no free seat for
	// it or, while FreeSeats is above 0, no KeyPackage.
	Waiting []Id
	// Seats still free once the Removes and Adds commit.
	FreeSeats int
}

// One data repo's readers it cannot seat, for the writer's preview.
type AclUnseatedRepo struct {
	RepoId Id
	// How many member devices read it.
	ReaderCount int
	// The reading member devices past its seats, earliest-admitted first, which wait keyless.
	SidecarIds []Id
}

// Orders sidecars earliest-admitted first: by admitted_at, then by id.
func aclSeatOrder(a *aclSidecarState, b *aclSidecarState) int {
	if c := cmp.Compare(a.facts.Row.GetAdmittedAt(), b.facts.Row.GetAdmittedAt()); c != 0 {
		return c
	}
	return a.id.Cmp(b.id)
}

// The member devices of the state that pass a data repo's leaf check at nowMs, earliest-admitted first.
func (self *AclState) seatReaders(repoId Id, nowMs int64) []*aclSidecarState {
	readers := []*aclSidecarState{}
	for i := range self.sidecars {
		sidecar := &self.sidecars[i]
		if sidecar.class != AclSubjectClassMemberDevice {
			continue
		}
		if self.repoMemberDecision(sidecar, repoId, AclRepoMemberLeaf, nowMs).Allowed {
			readers = append(readers, sidecar)
		}
	}
	slices.SortFunc(readers, aclSeatOrder)
	return readers
}

// The data repo's index, or ErrAclNoDataSeats.
func (self *AclState) dataSeatRepo(repoId Id) (*aclRepoState, error) {
	repo := self.repos[repoId]
	if repo == nil {
		return nil, fmt.Errorf("%w: the rows hold no repo %s", ErrAclNoDataSeats, repoId)
	}
	if aclRepoKindLeafRanked(repo.kind) {
		return nil, fmt.Errorf("%w: %s's group seats by §7.9's leaves rule", ErrAclNoDataSeats, repo.kind)
	}
	return repo, nil
}

// §8.12's data seats of one repo's group at this state and now: which leaves keep their seats and which are due a
// Remove, and which waiting member devices take the free seats, earliest-admitted first among those with a KeyPackage.
// leaves are the sidecars the group's tree holds, from the committer's MLS state; keyPackageSidecarIds the member
// devices gkm lists a KeyPackage for. ErrAclNoDataSeats for a repo the rows do not hold, the config and a team's
// directory.
func AclDataSeats(state *AclState, repoId Id, leaves []Id, keyPackageSidecarIds map[Id]bool, now time.Time) (*AclDataSeatPlan, error) {
	if state == nil {
		return nil, fmt.Errorf("%w: no state", ErrAclNoDataSeats)
	}
	if _, err := state.dataSeatRepo(repoId); err != nil {
		return nil, err
	}
	nowMs := now.UnixMilli()
	plan := &AclDataSeatPlan{Seated: []Id{}, Removes: []AclNonReader{}, Adds: []Id{}, Waiting: []Id{}}
	seated := map[Id]bool{}
	leafIds := slices.Clone(leaves)
	slices.SortFunc(leafIds, Id.Cmp)
	for _, leafId := range slices.Compact(leafIds) {
		sidecar := state.sidecarState(leafId)
		if sidecar == nil {
			plan.Removes = append(plan.Removes, AclNonReader{SidecarId: leafId, Reason: AclReasonUnadmitted})
			continue
		}
		if decision := state.repoMemberDecision(sidecar, repoId, AclRepoMemberLeaf, nowMs); !decision.Allowed {
			plan.Removes = append(plan.Removes, AclNonReader{SidecarId: leafId, Reason: decision.Reason})
			continue
		}
		plan.Seated = append(plan.Seated, leafId)
		seated[leafId] = true
	}
	plan.FreeSeats = max(0, aclRepoSeatCount-len(plan.Seated))
	for _, reader := range state.seatReaders(repoId, nowMs) {
		if seated[reader.id] {
			continue
		}
		if 0 < plan.FreeSeats && keyPackageSidecarIds[reader.id] {
			plan.Adds = append(plan.Adds, reader.id)
			plan.FreeSeats -= 1
			continue
		}
		plan.Waiting = append(plan.Waiting, reader.id)
	}
	return plan, nil
}

// The data repos of the state whose reading member devices at now pass their 1,000 seats, sorted by repo, each with
// the readers it cannot seat, for the writer's preview of a new head (§8.8's Saving) and the console. leavesByRepo
// holds the trees the caller knows, a writer's own groups; a repo it holds none for is taken at the seating rule's
// steady state, its earliest-admitted 1,000 readers seated, so its count is exact and its names a prediction. Every
// free seat is taken as filled, earliest-admitted first, since a KeyPackage's absence passes.
func AclUnseated(state *AclState, leavesByRepo map[Id][]Id, now time.Time) []AclUnseatedRepo {
	unseatedRepos := []AclUnseatedRepo{}
	if state == nil {
		return unseatedRepos
	}
	nowMs := now.UnixMilli()
	// no repo passes its seats while the state holds no more member devices than that
	memberDeviceCount := 0
	for i := range state.sidecars {
		sidecar := &state.sidecars[i]
		if sidecar.class == AclSubjectClassMemberDevice && sidecar.hardDeny(nowMs) == 0 {
			memberDeviceCount += 1
		}
	}
	if memberDeviceCount <= aclRepoSeatCount {
		return unseatedRepos
	}
	repoIds := slices.SortedFunc(maps.Keys(state.repos), Id.Cmp)
	for _, repoId := range repoIds {
		repo := state.repos[repoId]
		if repo.deleted || aclRepoKindLeafRanked(repo.kind) {
			continue
		}
		readers := state.seatReaders(repoId, nowMs)
		if len(readers) <= aclRepoSeatCount {
			continue
		}
		seated := map[Id]bool{}
		if leaves, known := leavesByRepo[repoId]; known {
			for _, leafId := range leaves {
				sidecar := state.sidecarState(leafId)
				if sidecar != nil && state.repoMemberDecision(sidecar, repoId, AclRepoMemberLeaf, nowMs).Allowed {
					seated[leafId] = true
				}
			}
		} else {
			for _, reader := range readers[:aclRepoSeatCount] {
				seated[reader.id] = true
			}
		}
		freeSeats := max(0, aclRepoSeatCount-len(seated))
		unseated := AclUnseatedRepo{RepoId: repoId, ReaderCount: len(readers), SidecarIds: []Id{}}
		for _, reader := range readers {
			switch {
			case seated[reader.id]:
			case 0 < freeSeats:
				freeSeats -= 1
			default:
				unseated.SidecarIds = append(unseated.SidecarIds, reader.id)
			}
		}
		unseatedRepos = append(unseatedRepos, unseated)
	}
	return unseatedRepos
}
