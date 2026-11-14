// §16.11's one view of §7.9's and §8's state, so every rule of the team directory asks its question in one place
// (RECORD-M6-12): who stands to sign a card, an entry or a notice at a pin, who held a repo's admin right at a past
// position (D-MCP-35), who the directory's admins are, who may decide a request, whom a sidecar speaks for, and whose
// cards, notices and pending requests a removal masks. DirectoryAuthView stands in for ConfigState and AclState at a
// pin, as RecordAuthView does for the record, and NewDirectoryAuthView binds it to TEAM's ConfigState, whose acl part
// is ACL's AclState:
//
//	standing     admitted, not revoked or reaped (a reap revokes the row, a member's removal its devices), unexpired,
//	             not parked, suspended or read_only, and for a member device consented (§8.5): a parked-for-consent
//	             device writes nothing that counts (owner decision 126); read_only sidecars write nothing at all
//	repo admin   D-MCP-35's: a repo admin of the repo by its access log, standing and not read_only; an owner-bound
//	             repo's consented device of its owner; with no compromise cascade voiding what it signed there; a
//	             config, mailcfg or directory repo never, since §16.11 ignores their repo files; judged in the state at
//	             the position while this view's log retains it, else from the config head's positions, which the
//	             head keeps for the repo's life (§8.8): the repo's creation and deletion, a current admin's add, a
//	             device's consent and revocation, and a Suspend in force; a removed admin's earlier right is not told
//	             there and fails closed until question acl-m2-06-access-log-positions is answered
//	admins       the directory's creator and every config writer, each a consented member device, standing and not
//	             read_only (owner decision 8; §7.8's admin scope)
//	approvers    §16.11's Requests table: a general or record repo's admins; an owner-bound repo's owner's consented
//	             devices, never an admin; a worker's or a socket's reach by the requests rule the request's
//	             CanonicalAction names, autogroup:dst-owner resolved by ACL, a socket's listeners read as
//	             plan-ACL-small-readings #5, a sponsor gone resolving to autogroup:admin
//	masked       a sidecar whose row is revoked: a SidecarRevoke, a reap, or its member's MemberRevoke (§16.11's
//	             member and device rows); TEAM-M6-11's ConfigState.MaskedInDirectory replaces this reading
//	voided       what a sidecar signed at a position that a compromise cascade in this state reaches (§7.9's cascade,
//	             §7.10's since_n), however long after the signature the revocation came (RECORD-M6-15)
//	right ended  whether an entry after a repo item's push pin ended its signer's right more than 10 min before the
//	             push's time_ms, by the states this view's log still holds (§16.11's repo file row)
//	repos        each repo's kind, owner, creation position and liveness, as the access log holds them
//
// A view's answers never change, and a view is safe for concurrent use. On every leg, the sidecar_http page Worker's
// included: root Id, no connect type. Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// No authorization state is bound yet: nothing is judged, and every check refuses.
	ErrDirectoryAuthUnavailable = errors.New("directory auth unavailable")
	// The pin or position is above this state's: wait until the log reaches it.
	ErrDirectoryAuthAhead = errors.New("directory auth pin ahead of the state")
	// The pin is before what this state retains (§7.9's retain row): not judged, and held against no one.
	ErrDirectoryAuthNotRetained = errors.New("directory auth pin not retained")
	// The pin's chain value is not this chain's at its position: a fork (§5.4's head_alarm).
	ErrDirectoryAuthOffChain = errors.New("directory auth pin off the chain")
	// No one may decide the request at this state: an unknown or deleted repo, a repo kind that takes no request, a
	// reach request whose action does not parse or that no requests rule takes.
	ErrDirectoryAuthNoApprovers = errors.New("directory request has no eligible approvers")
)

// Whether a sidecar stands to write in the directory at a pin (§16.11's card row and writers row).
type DirectoryStanding int

const (
	// The pin could not be judged here: ahead of this state, before what it retains, off its chain, or nothing bound.
	DirectoryStandingUnjudged DirectoryStanding = iota
	// Admitted, and none of the below.
	DirectoryStandingStanding
	// The state holds no admission of it, or one naming neither a member nor tags.
	DirectoryStandingUnadmitted
	// Revoked or reaped, its row's revoked_at set, which a member's removal sets on each of its devices; the rows do
	// not tell a reap from a revocation.
	DirectoryStandingRevoked
	// Past its admission's not_after.
	DirectoryStandingExpired
	// Parked by §7.9's compromise cascade or a leaked bundle's DelegationRevoke.
	DirectoryStandingParked
	// An active Suspend names it (§8.8).
	DirectoryStandingSuspended
	// read_only (D-TEAM-24): it reads the directory and writes nothing there.
	DirectoryStandingReadOnly
	// A member device not consented for its member (§8.5): parked for consent, so nothing it writes counts.
	DirectoryStandingUnconsented
)

// The standing's name, for logs and tests.
func (self DirectoryStanding) String() string {
	switch self {
	case DirectoryStandingUnjudged:
		return "unjudged"
	case DirectoryStandingStanding:
		return "standing"
	case DirectoryStandingUnadmitted:
		return "unadmitted"
	case DirectoryStandingRevoked:
		return "revoked"
	case DirectoryStandingExpired:
		return "expired"
	case DirectoryStandingParked:
		return "parked"
	case DirectoryStandingSuspended:
		return "suspended"
	case DirectoryStandingReadOnly:
		return "read_only"
	case DirectoryStandingUnconsented:
		return "unconsented"
	}
	return fmt.Sprintf("standing(%d)", int(self))
}

// Who may decide one request, at the pin it was computed at (§16.11's Requests table). A decider is eligible when it
// is one of SidecarIds, judged again at its own push's pin, or an approval-capable device (consented, untagged, not
// ephemeral, not read_only, not suspended) of one of MemberIds or of a member whose role Autogroups names; an
// owner-bound repo's owner's devices alone, never an admin.
type DirectoryApprovers struct {
	// The target's kind.
	TargetKind DirectoryTargetKind
	// A repo target's id.
	RepoId Id
	// An owner-bound repo: its owner's consented devices decide, never an admin (owner decision 126).
	OwnerBound bool
	// A general or record repo's admins, each by its own right (D-MCP-35's), in id order.
	SidecarIds []Id
	// Members any of whose approval-capable devices decides, in id order: an owner-bound repo's owner, a worker's owner
	// or sponsor, a socket's listeners' one owner or sponsor, members a rule names.
	MemberIds []Id
	// Members by role, as ACL's autogroup bits (AclApprovers.Autogroups): autogroup:admin where no one owner or
	// sponsor stands, or where a rule names it.
	Autogroups uint32
	// Distinct approvals that decide it: 1, or a requests rule's two (§16.11's decide row).
	Count int
}

// Whether the set names an autogroup.
func (self *DirectoryApprovers) HasAutogroup(autogroup protocol.AclAutogroup) bool {
	return self.Autogroups&aclAutogroupBit(autogroup) != 0
}

// A repo as the access log holds it (§8.8's AclRepo), for the directory's repo items (RECORD-M6-15).
type DirectoryRepo struct {
	RepoId Id
	Kind   protocol.RepoKind
	// An owner-bound repo's owner; zero for any other kind.
	OwnerMemberId Id
	// The position of its RepoCreate, as the rows keep it: its earliest admin row's.
	CreatedAt uint64
	// Not deleted, or restored: §16.11's lifetime row ends its item at the deletion.
	Live bool
}

// One view of §7.9's and §8's state at its pin, through which every directory rule asks its question. Answers at
// another pin or position come from that state of the same log, never this one's tip, so a version is judged where it
// came in (I-4, I-EVS-14). Answers never change for one view, and a view is safe for concurrent use.
type DirectoryAuthView interface {
	// (n, A_n).
	Pin() *bridge.AuthPin
	// The view at an earlier pin on this chain: ErrDirectoryAuthAhead, ErrDirectoryAuthNotRetained or
	// ErrDirectoryAuthOffChain otherwise.
	At(pin *bridge.AuthPin) (DirectoryAuthView, error)
	// The network's directory: its live repo of kind directory by the access log, the one with the lowest RepoCreate
	// position should a second stand; false while none does.
	Directory() (Id, bool)
	// Whether the sidecar stands to sign and write in the directory at pin (§16.11's card row): DirectoryStandingUnjudged
	// with the reason when pin cannot be judged here.
	SignerStanding(sidecarId Id, pin *bridge.AuthPin) (DirectoryStanding, error)
	// D-MCP-35's right of a repo file's signer at a past position: see the file's header. ErrDirectoryAuthAhead for a
	// position above this state.
	RepoAdminRight(repoId Id, sidecarId Id, position uint64) (bool, error)
	// The directory's admins at pin, in id order: empty while the network has no directory.
	DirectoryAdmins(pin *bridge.AuthPin) ([]Id, error)
	// Who may decide request, filed by requesterSidecarId, at pin: ErrDirectoryAuthNoApprovers when no one may.
	EligibleApprovers(request *protocol.DirectoryRequest, requesterSidecarId Id, pin *bridge.AuthPin) (*DirectoryApprovers, error)
	// Whether deciderSidecarId may decide request at pin, its decision entry's push pin (§16.11's receipt row).
	Decides(request *protocol.DirectoryRequest, requesterSidecarId Id, deciderSidecarId Id, pin *bridge.AuthPin) (bool, error)
	// The member an untagged sidecar's admission names, while that member is one; false for a tagged sidecar, one
	// this state never admitted, or one whose member is gone.
	MemberOf(sidecarId Id) (Id, bool)
	// A tagged sidecar's live sponsor (§7.10, owner decision 83); false once it has none, when autogroup:admin stands in.
	SponsorOf(sidecarId Id) (Id, bool)
	// Whether readers mask the sidecar's cards, notices and pending requests at this state (§16.11's member and device
	// rows).
	Masked(sidecarId Id) bool
	// Whether a compromise cascade in this state voids what sidecarId signed at position: a compromise revocation of
	// it from a since_n at or before position (§7.10), however late that revocation came.
	SignatureVoided(sidecarId Id, position uint64) bool
	// Whether an entry after position after, timed before beforeMillis, ended D-MCP-35's right of sidecarId on repoId,
	// by the states this view's log still holds: §16.11's repo file row voids an item whose push's time_ms came more
	// than 10 min after such an entry. Positions this log no longer holds say nothing here.
	RepoAdminRightEnded(repoId Id, sidecarId Id, after uint64, beforeMillis int64) bool
	// The repo as this state's access log holds it, false for one it never held.
	Repo(repoId Id) (*DirectoryRepo, bool)
	// Every repo this state's access log holds, deleted ones included, in id order.
	Repos() []*DirectoryRepo
}

// The member §16.11's AnnounceWho.member_id names for a sidecar: its own member, or a tagged sidecar's live sponsor;
// false for a tagged sidecar whose sponsor is gone, whose items show autogroup:admin until a SponsorSet.
func DirectoryWhoMember(view DirectoryAuthView, sidecarId Id) (Id, bool) {
	if memberId, ok := view.MemberOf(sidecarId); ok {
		return memberId, true
	}
	return view.SponsorOf(sidecarId)
}

// The state a sidecar reads until TEAM's and ACL's states bind DirectoryAuthView: no pin, no directory and no right,
// and everyone masked, so every check that asks it refuses.
type DirectoryAuthUnavailable struct{}

// None.
func (self DirectoryAuthUnavailable) Pin() *bridge.AuthPin {
	return nil
}

// Ahead of every pin, so a caller waits rather than judges.
func (self DirectoryAuthUnavailable) At(pin *bridge.AuthPin) (DirectoryAuthView, error) {
	return nil, ErrDirectoryAuthUnavailable
}

// None.
func (self DirectoryAuthUnavailable) Directory() (Id, bool) {
	return Id{}, false
}

// Unjudged.
func (self DirectoryAuthUnavailable) SignerStanding(sidecarId Id, pin *bridge.AuthPin) (DirectoryStanding, error) {
	return DirectoryStandingUnjudged, ErrDirectoryAuthUnavailable
}

// Never.
func (self DirectoryAuthUnavailable) RepoAdminRight(repoId Id, sidecarId Id, position uint64) (bool, error) {
	return false, ErrDirectoryAuthUnavailable
}

// None.
func (self DirectoryAuthUnavailable) DirectoryAdmins(pin *bridge.AuthPin) ([]Id, error) {
	return nil, ErrDirectoryAuthUnavailable
}

// None.
func (self DirectoryAuthUnavailable) EligibleApprovers(request *protocol.DirectoryRequest, requesterSidecarId Id, pin *bridge.AuthPin) (*DirectoryApprovers, error) {
	return nil, ErrDirectoryAuthUnavailable
}

// Never.
func (self DirectoryAuthUnavailable) Decides(request *protocol.DirectoryRequest, requesterSidecarId Id, deciderSidecarId Id, pin *bridge.AuthPin) (bool, error) {
	return false, ErrDirectoryAuthUnavailable
}

// None.
func (self DirectoryAuthUnavailable) MemberOf(sidecarId Id) (Id, bool) {
	return Id{}, false
}

// None.
func (self DirectoryAuthUnavailable) SponsorOf(sidecarId Id) (Id, bool) {
	return Id{}, false
}

// Everyone, so nothing shows as current.
func (self DirectoryAuthUnavailable) Masked(sidecarId Id) bool {
	return true
}

// Everything, so no repo item stands.
func (self DirectoryAuthUnavailable) SignatureVoided(sidecarId Id, position uint64) bool {
	return true
}

// Ended, so no repo item stands.
func (self DirectoryAuthUnavailable) RepoAdminRightEnded(repoId Id, sidecarId Id, after uint64, beforeMillis int64) bool {
	return true
}

// None.
func (self DirectoryAuthUnavailable) Repo(repoId Id) (*DirectoryRepo, bool) {
	return nil, false
}

// None.
func (self DirectoryAuthUnavailable) Repos() []*DirectoryRepo {
	return []*DirectoryRepo{}
}

// DirectoryAuthView over TEAM's ConfigState and its acl part.
type configDirectoryAuth struct {
	state *ConfigState
}

// The directory's view of state, which must not change afterward.
func NewDirectoryAuthView(state *ConfigState) DirectoryAuthView {
	if state == nil {
		return DirectoryAuthUnavailable{}
	}
	return &configDirectoryAuth{state: state}
}

// A config error from StateAt as this view's.
func directoryAuthError(err error) error {
	switch {
	case errors.Is(err, ErrConfigPinAhead):
		return fmt.Errorf("%w: %w", ErrDirectoryAuthAhead, err)
	case errors.Is(err, ErrConfigPinNotRetained):
		return fmt.Errorf("%w: %w", ErrDirectoryAuthNotRetained, err)
	case errors.Is(err, ErrConfigPinOffChain):
		return fmt.Errorf("%w: %w", ErrDirectoryAuthOffChain, err)
	}
	return err
}

// The state's (n, A_n).
func (self *configDirectoryAuth) Pin() *bridge.AuthPin {
	return self.state.Pin()
}

// The state at pin, this one's own when pin is nil.
func (self *configDirectoryAuth) stateAt(pin *bridge.AuthPin) (*ConfigState, error) {
	if pin == nil {
		return self.state, nil
	}
	state, err := self.state.StateAt(pin)
	if err != nil {
		return nil, directoryAuthError(err)
	}
	return state, nil
}

// The view over StateAt's state at pin.
func (self *configDirectoryAuth) At(pin *bridge.AuthPin) (DirectoryAuthView, error) {
	if pin == nil {
		return nil, fmt.Errorf("%w: no pin", ErrDirectoryAuthOffChain)
	}
	state, err := self.stateAt(pin)
	if err != nil {
		return nil, err
	}
	return &configDirectoryAuth{state: state}, nil
}

// The acl part of a state, nil when its rows do not build, which a base refuses before any state holds them.
func directoryAcl(state *ConfigState) *AclState {
	acl, err := state.Acl()
	if err != nil {
		return nil
	}
	return acl
}

// A repo's access-log row, and whether the repo is live: not deleted, or restored.
func directoryRepoRow(acl *AclState, repoId Id) (*protocol.AclRepo, bool) {
	if acl == nil {
		return nil, false
	}
	repo := acl.Repo(repoId)
	if repo == nil {
		return nil, false
	}
	deletion := repo.GetDeletion()
	return repo, deletion == nil || deletion.GetDeletedAt() == 0 || deletion.GetRestoredAt() != 0
}

// The live directory of a state, by its RepoCreate's position, the lowest when two stand.
func directoryOfState(state *ConfigState) (*protocol.AclRepo, bool) {
	acl := directoryAcl(state)
	if acl == nil {
		return nil, false
	}
	var found *protocol.AclRepo
	createdAt := directoryRepoCreatedAt
	for _, repo := range acl.Rows().GetRepos() {
		if repo.GetKind() != protocol.RepoKind_REPO_KIND_DIRECTORY {
			continue
		}
		if _, live := directoryRepoRow(acl, Id(repo.GetRepoId())); !live {
			continue
		}
		if found == nil || createdAt(repo) < createdAt(found) ||
			(createdAt(repo) == createdAt(found) && bytes.Compare(repo.GetRepoId(), found.GetRepoId()) < 0) {
			found = repo
		}
	}
	return found, found != nil
}

// The state's live directory, by its RepoCreate's position.
func (self *configDirectoryAuth) Directory() (Id, bool) {
	repo, ok := directoryOfState(self.state)
	if !ok {
		return Id{}, false
	}
	return Id(repo.GetRepoId()), true
}

// A sidecar's standing in one state.
func directoryStandingIn(state *ConfigState, sidecarId Id) DirectoryStanding {
	sidecar := state.Sidecar(sidecarId)
	if sidecar == nil || sidecar.Row == nil || (sidecar.MemberId == Id{}) == (len(sidecar.TagIds) == 0) {
		return DirectoryStandingUnadmitted
	}
	row := sidecar.Row
	if row.GetRevokedAt() != 0 || (sidecar.MemberId != Id{} && state.Member(sidecar.MemberId) == nil) {
		return DirectoryStandingRevoked
	}
	if row.GetNotAfter() != 0 && row.GetNotAfter() <= state.TimeMs() {
		return DirectoryStandingExpired
	}
	if state.Parked(sidecarId) {
		return DirectoryStandingParked
	}
	acl := directoryAcl(state)
	if acl == nil {
		return DirectoryStandingUnadmitted
	}
	if acl.Suspended(sidecarId) {
		return DirectoryStandingSuspended
	}
	if configRowReadOnly(row) {
		return DirectoryStandingReadOnly
	}
	if configRowMemberDevice(row) && !acl.Consented(sidecarId) {
		return DirectoryStandingUnconsented
	}
	return DirectoryStandingStanding
}

// The standing in StateAt's state at pin.
func (self *configDirectoryAuth) SignerStanding(sidecarId Id, pin *bridge.AuthPin) (DirectoryStanding, error) {
	if pin == nil {
		return DirectoryStandingUnjudged, fmt.Errorf("%w: no pin", ErrDirectoryAuthOffChain)
	}
	state, err := self.stateAt(pin)
	if err != nil {
		return DirectoryStandingUnjudged, err
	}
	return directoryStandingIn(state, sidecarId), nil
}

// The kinds whose repo files §16.11 ignores, so no one holds the right there: config, mailcfg and the directory.
func directoryRepoFileIgnored(kind protocol.RepoKind) bool {
	switch kind {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_DIRECTORY:
		return true
	}
	return false
}

// The state at a position this view's log still holds, false when the position is before what it retains, where the
// head's positions answer instead.
func (self *configDirectoryAuth) stateAtPosition(position uint64) (*ConfigState, bool, error) {
	if self.state.n < position {
		return nil, false, fmt.Errorf("%w: position %d above %d", ErrDirectoryAuthAhead, position, self.state.n)
	}
	chain, ok := self.state.chainAt(position)
	if !ok {
		return nil, false, nil
	}
	state, err := self.state.StateAt(&bridge.AuthPin{Version: position, Chain: chain[:]})
	if errors.Is(err, ErrConfigPinNotRetained) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, directoryAuthError(err)
	}
	return state, true, nil
}

// Judged in the state at position while the log retains it, else from this state's positions; either way void where
// a cascade this state holds reaches position, which the state at position may predate.
func (self *configDirectoryAuth) RepoAdminRight(repoId Id, sidecarId Id, position uint64) (bool, error) {
	state, held, err := self.stateAtPosition(position)
	if err != nil {
		return false, err
	}
	if self.state.CascadeVoids(sidecarId.Bytes(), position) {
		return false, nil
	}
	if held {
		return directoryRepoAdminIn(state, repoId, sidecarId, position), nil
	}
	return directoryRepoAdminFromHead(self.state, repoId, sidecarId, position), nil
}

// The cascade's verdict in this state.
func (self *configDirectoryAuth) SignatureVoided(sidecarId Id, position uint64) bool {
	return self.state.CascadeVoids(sidecarId.Bytes(), position)
}

// Each held position after after, in order, until one timed at or past beforeMillis: the first at which the right
// no longer holds answers true. The scan ends at the bound, so for a push with a fresh pin it reads nothing.
func (self *configDirectoryAuth) RepoAdminRightEnded(repoId Id, sidecarId Id, after uint64, beforeMillis int64) bool {
	for position := max(after+1, self.state.chainsFrom); position <= self.state.n; position += 1 {
		state, held, err := self.stateAtPosition(position)
		if err != nil || !held {
			continue
		}
		if beforeMillis <= state.TimeMs() {
			return false
		}
		if !directoryRepoAdminIn(state, repoId, sidecarId, position) {
			return true
		}
	}
	return false
}

// A row as DirectoryRepo.
func directoryRepoOf(repo *protocol.AclRepo, live bool) *DirectoryRepo {
	return &DirectoryRepo{
		RepoId:        recordIdOf(repo.GetRepoId()),
		Kind:          repo.GetKind(),
		OwnerMemberId: recordIdOf(repo.GetOwnerMemberId()),
		CreatedAt:     directoryRepoCreatedAt(repo),
		Live:          live,
	}
}

// The access log's row.
func (self *configDirectoryAuth) Repo(repoId Id) (*DirectoryRepo, bool) {
	repo, live := directoryRepoRow(directoryAcl(self.state), repoId)
	if repo == nil {
		return nil, false
	}
	return directoryRepoOf(repo, live), true
}

// The access log's rows.
func (self *configDirectoryAuth) Repos() []*DirectoryRepo {
	acl := directoryAcl(self.state)
	repos := []*DirectoryRepo{}
	if acl == nil {
		return repos
	}
	for _, row := range acl.Rows().GetRepos() {
		repo, live := directoryRepoRow(acl, recordIdOf(row.GetRepoId()))
		if repo != nil {
			repos = append(repos, directoryRepoOf(repo, live))
		}
	}
	slices.SortFunc(repos, func(a *DirectoryRepo, b *DirectoryRepo) int { return a.RepoId.Cmp(b.RepoId) })
	return repos
}

// D-MCP-35's right judged in the state at position itself.
func directoryRepoAdminIn(state *ConfigState, repoId Id, sidecarId Id, position uint64) bool {
	acl := directoryAcl(state)
	repo, live := directoryRepoRow(acl, repoId)
	if repo == nil || !live || directoryRepoFileIgnored(repo.GetKind()) {
		return false
	}
	if state.CascadeVoids(sidecarId.Bytes(), position) {
		return false
	}
	switch standing := directoryStandingIn(state, sidecarId); {
	case aclRepoKindOwnerBound(repo.GetKind()):
		return standing == DirectoryStandingStanding && acl.ConsentedFor(sidecarId, Id(repo.GetOwnerMemberId()))
	default:
		return standing == DirectoryStandingStanding && acl.RepoAdminAt(repoId, sidecarId, position)
	}
}

// D-MCP-35's right at a position before what this state retains, from the head's positions: the repo created by then
// and not deleted then; the sidecar's row not revoked, parked, read_only or voided by a cascade there, no active Suspend of it
// from at or before it, and a member device consented by then; and an admin row added at or before it and not removed
// by then (RepoAdminAt), or, for an owner-bound repo, the device being its owner's. A removed admin's row stays in the
// rows with its removal's position until a base whose retention point passed the removal drops it (QD-743), so its
// right before the removal is told until then and refused after. A lifted Suspend and a consent replaced by a later one
// are gone from the head, so what they said of an earlier position is not told here: the first reads as never
// suspended, the second as consented later.
func directoryRepoAdminFromHead(head *ConfigState, repoId Id, sidecarId Id, position uint64) bool {
	acl := directoryAcl(head)
	if acl == nil {
		return false
	}
	repo := acl.Repo(repoId)
	if repo == nil || directoryRepoFileIgnored(repo.GetKind()) || position < directoryRepoCreatedAt(repo) {
		return false
	}
	if deletion := repo.GetDeletion(); deletion != nil && deletion.GetDeletedAt() != 0 && deletion.GetDeletedAt() <= position &&
		(deletion.GetRestoredAt() == 0 || position < deletion.GetRestoredAt()) {
		return false
	}
	row := head.SidecarRow(sidecarId)
	sidecar := acl.sidecarState(sidecarId)
	if row == nil || sidecar == nil || !sidecar.valid || configRowReadOnly(row) ||
		(row.GetRevokedAt() != 0 && row.GetRevokedAt() <= position) || (row.GetParkedAt() != 0 && row.GetParkedAt() <= position) ||
		head.CascadeVoids(sidecarId.Bytes(), position) {
		return false
	}
	for _, suspension := range acl.Rows().GetSuspensions() {
		if bytes.Equal(suspension.GetSubject(), sidecarId.Bytes()) && suspension.GetAt() <= position {
			return false
		}
	}
	memberDevice := !sidecar.tagged && !sidecar.ephemeral
	if memberDevice && (!sidecar.hasConsent || position < sidecar.consentedAt) {
		return false
	}
	if aclRepoKindOwnerBound(repo.GetKind()) {
		return memberDevice && sidecar.memberId == Id(repo.GetOwnerMemberId())
	}
	return acl.RepoAdminAt(repoId, sidecarId, position)
}

// The position of a repo's RepoCreate, which the rows keep as its creator's admin row: the earliest admin row's, a
// removed one's included while the rows keep it (QD-743), or never once no admin row is left.
func directoryRepoCreatedAt(repo *protocol.AclRepo) uint64 {
	createdAt := ^uint64(0)
	for _, admin := range repo.GetAdmins() {
		createdAt = min(createdAt, admin.GetAt())
	}
	return createdAt
}

// The admins of StateAt's state at pin, this state's own for a nil pin.
func (self *configDirectoryAuth) DirectoryAdmins(pin *bridge.AuthPin) ([]Id, error) {
	state, err := self.stateAt(pin)
	if err != nil {
		return nil, err
	}
	return directoryAdminsIn(state), nil
}

// The directory's admins in one state: its creator and every config writer, each a consented member device that
// stands and is not read_only.
func directoryAdminsIn(state *ConfigState) []Id {
	directory, ok := directoryOfState(state)
	if !ok {
		return []Id{}
	}
	admins := []Id{}
	for _, sidecarId := range state.SidecarIds() {
		creator := slices.ContainsFunc(directory.GetAdmins(), func(admin *protocol.AclRepoAdminRow) bool {
			return AclRepoAdminStands(admin) && bytes.Equal(admin.GetSidecarId(), sidecarId.Bytes())
		})
		if !creator && !state.IsConfigWriter(sidecarId) {
			continue
		}
		row := state.SidecarRow(sidecarId)
		if !configRowMemberDevice(row) || directoryStandingIn(state, sidecarId) != DirectoryStandingStanding {
			continue
		}
		admins = append(admins, sidecarId)
	}
	return admins
}

// §16.11's Requests table in StateAt's state at pin.
func (self *configDirectoryAuth) EligibleApprovers(request *protocol.DirectoryRequest, requesterSidecarId Id, pin *bridge.AuthPin) (*DirectoryApprovers, error) {
	state, err := self.stateAt(pin)
	if err != nil {
		return nil, err
	}
	return directoryApproversIn(state, request, requesterSidecarId)
}

// §16.11's Requests table in one state.
func directoryApproversIn(state *ConfigState, request *protocol.DirectoryRequest, requesterSidecarId Id) (*DirectoryApprovers, error) {
	targetKind, err := DirectoryRequestTargetKind(request.GetTarget())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDirectoryAuthNoApprovers, err)
	}
	acl := directoryAcl(state)
	if acl == nil {
		return nil, fmt.Errorf("%w: the state's acl does not build", ErrDirectoryAuthNoApprovers)
	}
	approvers := &DirectoryApprovers{TargetKind: targetKind, Count: 1}
	if targetKind == DirectoryTargetKindRepo {
		repoId := Id(request.GetTarget().GetRepoId())
		approvers.RepoId = repoId
		repo, live := directoryRepoRow(acl, repoId)
		if repo == nil || !live {
			return nil, fmt.Errorf("%w: a repo this state does not hold live", ErrDirectoryAuthNoApprovers)
		}
		switch kind := repo.GetKind(); {
		case aclRepoKindOwnerBound(kind):
			approvers.OwnerBound = true
			approvers.MemberIds = []Id{Id(repo.GetOwnerMemberId())}
		case aclRepoKindGeneral(kind):
			for _, admin := range repo.GetAdmins() {
				adminId := Id(admin.GetSidecarId())
				// a removed row, which the rows keep a while (QD-743), names no approver, and a re-added admin's
				// standing row names it once
				if AclRepoAdminStands(admin) && directoryRepoAdminIn(state, repoId, adminId, state.n) {
					approvers.SidecarIds = append(approvers.SidecarIds, adminId)
				}
			}
			slices.SortFunc(approvers.SidecarIds, Id.Cmp)
		default:
			return nil, fmt.Errorf("%w: a %s repo takes no request", ErrDirectoryAuthNoApprovers, kind)
		}
		return approvers, nil
	}
	// a worker's or a socket's reach: the requests rule its CanonicalAction names (§8.6's requests, D-ACL-23)
	action, err := ParseStoredCanonicalAction(request.GetApproval().GetCanonicalAction())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDirectoryAuthNoApprovers, err)
	}
	ask, err := ParseAclGrantAction(action.Action)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDirectoryAuthNoApprovers, err)
	}
	if ask.Subject != requesterSidecarId {
		return nil, fmt.Errorf("%w: a reach grant's subject is the requesting sidecar", ErrDirectoryAuthNoApprovers)
	}
	now := time.UnixMilli(state.TimeMs())
	match, err := MatchAclRequest(acl, ask, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDirectoryAuthNoApprovers, err)
	}
	resolved := acl.ResolveApprovers(match.Rule.GetApproverAtoms(), AclSidecarSubject(requesterSidecarId), ask.Dst, now)
	approvers.MemberIds = slices.Clone(resolved.MemberIds)
	approvers.Autogroups = resolved.Autogroups
	approvers.Count = max(1, int(match.Rule.GetApprovers()))
	if len(approvers.MemberIds) == 0 && approvers.Autogroups == 0 {
		return nil, fmt.Errorf("%w: the rule names no approver", ErrDirectoryAuthNoApprovers)
	}
	return approvers, nil
}

// The approvers at pin, and the decider among them there.
func (self *configDirectoryAuth) Decides(request *protocol.DirectoryRequest, requesterSidecarId Id, deciderSidecarId Id, pin *bridge.AuthPin) (bool, error) {
	state, err := self.stateAt(pin)
	if err != nil {
		return false, err
	}
	approvers, err := directoryApproversIn(state, request, requesterSidecarId)
	if err != nil {
		return false, err
	}
	if approvers.TargetKind == DirectoryTargetKindRepo && !approvers.OwnerBound {
		_, found := slices.BinarySearchFunc(approvers.SidecarIds, deciderSidecarId, Id.Cmp)
		return found, nil
	}
	acl := directoryAcl(state)
	row := state.SidecarRow(deciderSidecarId)
	if acl == nil || row == nil || !configRowMemberDevice(row) || !acl.ApprovalCapable(deciderSidecarId) {
		return false, nil
	}
	memberId := Id(row.GetMemberId())
	if approvers.OwnerBound {
		return slices.Contains(approvers.MemberIds, memberId) && acl.ConsentedFor(deciderSidecarId, memberId), nil
	}
	return acl.Approves(&AclApprovers{MemberIds: approvers.MemberIds, Autogroups: approvers.Autogroups}, memberId), nil
}

// The member the admission names, while a member.
func (self *configDirectoryAuth) MemberOf(sidecarId Id) (Id, bool) {
	sidecar := self.state.Sidecar(sidecarId)
	if sidecar == nil || len(sidecar.TagIds) != 0 || sidecar.MemberId == (Id{}) || self.state.Member(sidecar.MemberId) == nil {
		return Id{}, false
	}
	return sidecar.MemberId, true
}

// ConfigState's sponsor.
func (self *configDirectoryAuth) SponsorOf(sidecarId Id) (Id, bool) {
	return self.state.Sponsor(sidecarId)
}

// Whether its row is revoked at or before this state.
func (self *configDirectoryAuth) Masked(sidecarId Id) bool {
	row := self.state.SidecarRow(sidecarId)
	return row != nil && row.GetRevokedAt() != 0 && row.GetRevokedAt() <= self.state.n
}
