// §7.9's log and §8's evaluation as fixtures, for the team directory to read through sidecar.DirectoryAuthView where a
// test needs no real ConfigState: who is admitted under which member or sponsor and how each stands, the members whose
// role is Owner or Admin, the config writers, each repo's kind, owner and admin rows with their positions, the
// network's directory and its creator, and the approvers a reach target resolves to, which ACL's requests rules give
// the real view.
//
// Each position of a FakeDirectoryAuth is a state a test writes, and positions chain as FakeRecordAuth's do, so At
// sees a fork the way a reader would. A position below RetainFrom's is not retained: SignerStanding and the rest refuse
// it, and RepoAdminRight answers it from the newest position's admin rows and consent positions, as the real view
// answers from the config head, so a removed admin's earlier right fails closed there as it does in the real view. A
// view never changes once appended, and everything here is safe for concurrent use.

package sidecartest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One sidecar's admission at a position, as a test writes it.
type FakeDirectorySidecar struct {
	// An untagged admission's member; nil for a tagged one.
	MemberId *sidecar.Id
	// A tagged one's live sponsor; nil once it has none.
	SponsorId *sidecar.Id
	Ephemeral bool
	// What SignerStanding answers for it where RevokedAt and SuspendedAt say nothing; zero reads as standing.
	// DirectoryStandingUnconsented marks a member device never consented, and DirectoryStandingParked one a cascade
	// parked, whose signatures are void at every position.
	Standing sidecar.DirectoryStanding
	// A config writer: an AdminSet member's member device that is not read_only.
	ConfigWriter bool
	// The position its row was revoked at, 0 for none: revoked and masked from there.
	RevokedAt uint64
	// The position of a Suspend of it still in force, 0 for none: suspended from there.
	SuspendedAt uint64
	// The position a member device's consent first held, 0 for from the first position.
	ConsentedAt uint64
}

// One admin row of a repo: its sidecar and the position of the statement that added it.
type FakeDirectoryRepoAdmin struct {
	SidecarId sidecar.Id
	At        uint64
}

// One repo at a position.
type FakeDirectoryRepo struct {
	Kind protocol.RepoKind
	// An owner-bound repo's owner.
	OwnerMemberId *sidecar.Id
	Admins        []FakeDirectoryRepoAdmin
	Deleted       bool
}

// One position's state, as a test writes it. A nil map answers no.
type FakeDirectoryAuthFixture struct {
	Sidecars map[sidecar.Id]*FakeDirectorySidecar
	// Members whose role is Owner or Admin: autogroup:admin.
	AdminMemberIds []sidecar.Id
	Repos          map[sidecar.Id]*FakeDirectoryRepo
	// The network's directory, nil for none; its creator is its first admin row.
	DirectoryId *sidecar.Id
	// What a reach target resolves to by its requests rule, keyed by sidecar.DirectoryNoticeTarget's text.
	ReachApprovers map[string]*sidecar.DirectoryApprovers
}

// A deep copy, so a test changing its fixture later changes no appended view.
func (self *FakeDirectoryAuthFixture) clone() *FakeDirectoryAuthFixture {
	cloned := &FakeDirectoryAuthFixture{
		Sidecars:       map[sidecar.Id]*FakeDirectorySidecar{},
		Repos:          map[sidecar.Id]*FakeDirectoryRepo{},
		ReachApprovers: map[string]*sidecar.DirectoryApprovers{},
	}
	if self == nil {
		return cloned
	}
	cloneId := func(id *sidecar.Id) *sidecar.Id {
		if id == nil {
			return nil
		}
		copied := *id
		return &copied
	}
	for sidecarId, admission := range self.Sidecars {
		if admission == nil {
			continue
		}
		copied := *admission
		copied.MemberId = cloneId(admission.MemberId)
		copied.SponsorId = cloneId(admission.SponsorId)
		cloned.Sidecars[sidecarId] = &copied
	}
	cloned.AdminMemberIds = slices.Clone(self.AdminMemberIds)
	for repoId, repo := range self.Repos {
		if repo == nil {
			continue
		}
		cloned.Repos[repoId] = &FakeDirectoryRepo{
			Kind:          repo.Kind,
			OwnerMemberId: cloneId(repo.OwnerMemberId),
			Admins:        slices.Clone(repo.Admins),
			Deleted:       repo.Deleted,
		}
	}
	cloned.DirectoryId = cloneId(self.DirectoryId)
	for target, approvers := range self.ReachApprovers {
		if approvers == nil {
			continue
		}
		copied := *approvers
		copied.SidecarIds = slices.Clone(approvers.SidecarIds)
		copied.MemberIds = slices.Clone(approvers.MemberIds)
		cloned.ReachApprovers[target] = &copied
	}
	return cloned
}

// The log's positions, from 1. Safe for concurrent use.
type FakeDirectoryAuth struct {
	stateLock sync.Mutex
	views     []*fakeDirectoryAuthView
	// the first position a view still retains
	retainedFrom uint64
}

func NewFakeDirectoryAuth() *FakeDirectoryAuth {
	return &FakeDirectoryAuth{retainedFrom: 1}
}

// Appends the next position and returns its view. The fixture is copied.
func (self *FakeDirectoryAuth) Append(fixture *FakeDirectoryAuthFixture) sidecar.DirectoryAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	previous := make([]byte, sha256.Size)
	if len(self.views) > 0 {
		previous = self.views[len(self.views)-1].pin.GetChain()
	}
	version := uint64(len(self.views) + 1)
	chain := sha256.Sum256(binary.BigEndian.AppendUint64(append([]byte("fake directory auth"), previous...), version))
	view := &fakeDirectoryAuthView{
		auth:    self,
		pin:     &bridge.AuthPin{Version: version, Chain: chain[:]},
		fixture: fixture.clone(),
	}
	self.views = append(self.views, view)
	return view
}

// The newest position's view, nil before the first.
func (self *FakeDirectoryAuth) Tip() sidecar.DirectoryAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.views) == 0 {
		return nil
	}
	return self.views[len(self.views)-1]
}

// Drops what every view retains below version, as §7.9's retain row lets a reader.
func (self *FakeDirectoryAuth) RetainFrom(version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.retainedFrom = max(self.retainedFrom, version)
}

// One position. Its pin and fixture never change.
type fakeDirectoryAuthView struct {
	auth    *FakeDirectoryAuth
	pin     *bridge.AuthPin
	fixture *FakeDirectoryAuthFixture
}

func (self *fakeDirectoryAuthView) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: self.pin.GetVersion(), Chain: bytes.Clone(self.pin.GetChain())}
}

// The view at pin, with the real view's errors.
func (self *fakeDirectoryAuthView) viewAt(pin *bridge.AuthPin) (*fakeDirectoryAuthView, error) {
	if pin == nil {
		return nil, fmt.Errorf("%w: no pin", sidecar.ErrDirectoryAuthOffChain)
	}
	if self.pin.GetVersion() < pin.GetVersion() {
		return nil, sidecar.ErrDirectoryAuthAhead
	}
	self.auth.stateLock.Lock()
	defer self.auth.stateLock.Unlock()
	if pin.GetVersion() < self.auth.retainedFrom || pin.GetVersion() == 0 {
		return nil, sidecar.ErrDirectoryAuthNotRetained
	}
	view := self.auth.views[pin.GetVersion()-1]
	if !bytes.Equal(view.pin.GetChain(), pin.GetChain()) {
		return nil, sidecar.ErrDirectoryAuthOffChain
	}
	return view, nil
}

func (self *fakeDirectoryAuthView) At(pin *bridge.AuthPin) (sidecar.DirectoryAuthView, error) {
	view, err := self.viewAt(pin)
	if err != nil {
		return nil, err
	}
	return view, nil
}

// A live repo of the position.
func (self *fakeDirectoryAuthView) liveRepo(repoId sidecar.Id) (*FakeDirectoryRepo, bool) {
	repo := self.fixture.Repos[repoId]
	return repo, repo != nil && !repo.Deleted
}

func (self *fakeDirectoryAuthView) Directory() (sidecar.Id, bool) {
	if self.fixture.DirectoryId == nil {
		return sidecar.Id{}, false
	}
	if _, live := self.liveRepo(*self.fixture.DirectoryId); !live {
		return sidecar.Id{}, false
	}
	return *self.fixture.DirectoryId, true
}

// A sidecar's standing at a position of this view's fixture.
func (self *fakeDirectoryAuthView) standingAt(sidecarId sidecar.Id, position uint64) sidecar.DirectoryStanding {
	admission := self.fixture.Sidecars[sidecarId]
	_, memberDevice := self.memberDevice(sidecarId)
	switch {
	case admission == nil:
		return sidecar.DirectoryStandingUnadmitted
	case admission.RevokedAt != 0 && admission.RevokedAt <= position:
		return sidecar.DirectoryStandingRevoked
	case admission.Standing != sidecar.DirectoryStandingUnjudged:
		return admission.Standing
	case admission.SuspendedAt != 0 && admission.SuspendedAt <= position:
		return sidecar.DirectoryStandingSuspended
	case memberDevice && position < admission.ConsentedAt:
		return sidecar.DirectoryStandingUnconsented
	}
	return sidecar.DirectoryStandingStanding
}

// A sidecar's standing at this position.
func (self *fakeDirectoryAuthView) standing(sidecarId sidecar.Id) sidecar.DirectoryStanding {
	return self.standingAt(sidecarId, self.pin.GetVersion())
}

func (self *fakeDirectoryAuthView) SignerStanding(sidecarId sidecar.Id, pin *bridge.AuthPin) (sidecar.DirectoryStanding, error) {
	view, err := self.viewAt(pin)
	if err != nil {
		return sidecar.DirectoryStandingUnjudged, err
	}
	return view.standing(sidecarId), nil
}

// Whether a sidecar is a member device: untagged and not ephemeral.
func (self *fakeDirectoryAuthView) memberDevice(sidecarId sidecar.Id) (sidecar.Id, bool) {
	admission := self.fixture.Sidecars[sidecarId]
	if admission == nil || admission.MemberId == nil || admission.Ephemeral {
		return sidecar.Id{}, false
	}
	return *admission.MemberId, true
}

// The right judged at this position itself.
func (self *fakeDirectoryAuthView) repoAdminIn(repoId sidecar.Id, sidecarId sidecar.Id, position uint64) bool {
	repo, live := self.liveRepo(repoId)
	if !live || fakeDirectoryRepoFileIgnored(repo.Kind) || position < fakeDirectoryCreatedAt(repo) ||
		self.standingAt(sidecarId, position) != sidecar.DirectoryStandingStanding {
		return false
	}
	if fakeDirectoryOwnerBound(repo.Kind) {
		memberId, ok := self.memberDevice(sidecarId)
		return ok && repo.OwnerMemberId != nil && memberId == *repo.OwnerMemberId
	}
	return slices.ContainsFunc(repo.Admins, func(admin FakeDirectoryRepoAdmin) bool {
		return admin.SidecarId == sidecarId && admin.At <= position
	})
}

func (self *fakeDirectoryAuthView) RepoAdminRight(repoId sidecar.Id, sidecarId sidecar.Id, position uint64) (bool, error) {
	if self.pin.GetVersion() < position {
		return false, sidecar.ErrDirectoryAuthAhead
	}
	held, retained := func() (*fakeDirectoryAuthView, bool) {
		self.auth.stateLock.Lock()
		defer self.auth.stateLock.Unlock()
		if position == 0 || position < self.auth.retainedFrom {
			return nil, false
		}
		return self.auth.views[position-1], true
	}()
	if retained {
		return held.repoAdminIn(repoId, sidecarId, position), nil
	}
	// from this view's own positions, as the real view answers from the config head
	repo, ok := self.fixture.Repos[repoId]
	if !ok || repo == nil || fakeDirectoryRepoFileIgnored(repo.Kind) || repo.Deleted || position < fakeDirectoryCreatedAt(repo) {
		return false, nil
	}
	if self.standingAt(sidecarId, position) != sidecar.DirectoryStandingStanding {
		return false, nil
	}
	if fakeDirectoryOwnerBound(repo.Kind) {
		memberId, isMemberDevice := self.memberDevice(sidecarId)
		return isMemberDevice && repo.OwnerMemberId != nil && memberId == *repo.OwnerMemberId, nil
	}
	return slices.ContainsFunc(repo.Admins, func(admin FakeDirectoryRepoAdmin) bool {
		return admin.SidecarId == sidecarId && admin.At <= position
	}), nil
}

// The repo's creation position: its earliest admin row's.
func fakeDirectoryCreatedAt(repo *FakeDirectoryRepo) uint64 {
	createdAt := ^uint64(0)
	for _, admin := range repo.Admins {
		createdAt = min(createdAt, admin.At)
	}
	return createdAt
}

// The directory's admins at this position.
func (self *fakeDirectoryAuthView) admins() []sidecar.Id {
	directoryId, ok := self.Directory()
	if !ok {
		return []sidecar.Id{}
	}
	directory := self.fixture.Repos[directoryId]
	admins := []sidecar.Id{}
	for sidecarId, admission := range self.fixture.Sidecars {
		creator := slices.ContainsFunc(directory.Admins, func(admin FakeDirectoryRepoAdmin) bool { return admin.SidecarId == sidecarId })
		if !creator && !admission.ConfigWriter {
			continue
		}
		if _, ok := self.memberDevice(sidecarId); !ok || self.standing(sidecarId) != sidecar.DirectoryStandingStanding {
			continue
		}
		admins = append(admins, sidecarId)
	}
	slices.SortFunc(admins, sidecar.Id.Cmp)
	return admins
}

func (self *fakeDirectoryAuthView) DirectoryAdmins(pin *bridge.AuthPin) ([]sidecar.Id, error) {
	view := self
	if pin != nil {
		var err error
		if view, err = self.viewAt(pin); err != nil {
			return nil, err
		}
	}
	return view.admins(), nil
}

// §16.11's Requests table at this position.
func (self *fakeDirectoryAuthView) approvers(request *protocol.DirectoryRequest) (*sidecar.DirectoryApprovers, error) {
	targetKind, err := sidecar.DirectoryRequestTargetKind(request.GetTarget())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", sidecar.ErrDirectoryAuthNoApprovers, err)
	}
	if targetKind == sidecar.DirectoryTargetKindRepo {
		repoId := sidecar.Id(request.GetTarget().GetRepoId())
		repo, live := self.liveRepo(repoId)
		if !live {
			return nil, fmt.Errorf("%w: no live repo", sidecar.ErrDirectoryAuthNoApprovers)
		}
		approvers := &sidecar.DirectoryApprovers{TargetKind: targetKind, RepoId: repoId, Count: 1}
		switch {
		case fakeDirectoryOwnerBound(repo.Kind):
			approvers.OwnerBound = true
			approvers.MemberIds = []sidecar.Id{*repo.OwnerMemberId}
		case repo.Kind == protocol.RepoKind_REPO_KIND_GENERAL || repo.Kind == protocol.RepoKind_REPO_KIND_RECORD:
			for _, admin := range repo.Admins {
				if self.repoAdminIn(repoId, admin.SidecarId, self.pin.GetVersion()) {
					approvers.SidecarIds = append(approvers.SidecarIds, admin.SidecarId)
				}
			}
			slices.SortFunc(approvers.SidecarIds, sidecar.Id.Cmp)
		default:
			return nil, fmt.Errorf("%w: a %s repo takes no request", sidecar.ErrDirectoryAuthNoApprovers, repo.Kind)
		}
		return approvers, nil
	}
	target, err := sidecar.DirectoryNoticeTarget(request.GetTarget())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", sidecar.ErrDirectoryAuthNoApprovers, err)
	}
	approvers := self.fixture.ReachApprovers[target]
	if approvers == nil {
		return nil, fmt.Errorf("%w: no requests rule takes it", sidecar.ErrDirectoryAuthNoApprovers)
	}
	copied := *approvers
	copied.TargetKind = targetKind
	copied.MemberIds = slices.Clone(approvers.MemberIds)
	copied.SidecarIds = slices.Clone(approvers.SidecarIds)
	return &copied, nil
}

func (self *fakeDirectoryAuthView) EligibleApprovers(request *protocol.DirectoryRequest, requesterSidecarId sidecar.Id, pin *bridge.AuthPin) (*sidecar.DirectoryApprovers, error) {
	view, err := self.viewAt(pin)
	if err != nil {
		return nil, err
	}
	return view.approvers(request)
}

func (self *fakeDirectoryAuthView) Decides(request *protocol.DirectoryRequest, requesterSidecarId sidecar.Id, deciderSidecarId sidecar.Id, pin *bridge.AuthPin) (bool, error) {
	view, err := self.viewAt(pin)
	if err != nil {
		return false, err
	}
	approvers, err := view.approvers(request)
	if err != nil {
		return false, err
	}
	if approvers.TargetKind == sidecar.DirectoryTargetKindRepo && !approvers.OwnerBound {
		return slices.Contains(approvers.SidecarIds, deciderSidecarId), nil
	}
	memberId, ok := view.memberDevice(deciderSidecarId)
	if !ok || view.standing(deciderSidecarId) != sidecar.DirectoryStandingStanding {
		return false, nil
	}
	if slices.Contains(approvers.MemberIds, memberId) {
		return true, nil
	}
	return !approvers.OwnerBound && approvers.HasAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN) &&
		slices.Contains(view.fixture.AdminMemberIds, memberId), nil
}

func (self *fakeDirectoryAuthView) MemberOf(sidecarId sidecar.Id) (sidecar.Id, bool) {
	admission := self.fixture.Sidecars[sidecarId]
	if admission == nil || admission.MemberId == nil {
		return sidecar.Id{}, false
	}
	return *admission.MemberId, true
}

func (self *fakeDirectoryAuthView) SponsorOf(sidecarId sidecar.Id) (sidecar.Id, bool) {
	admission := self.fixture.Sidecars[sidecarId]
	if admission == nil || admission.MemberId != nil || admission.SponsorId == nil {
		return sidecar.Id{}, false
	}
	return *admission.SponsorId, true
}

func (self *fakeDirectoryAuthView) Masked(sidecarId sidecar.Id) bool {
	admission := self.fixture.Sidecars[sidecarId]
	return admission != nil && admission.RevokedAt != 0 && admission.RevokedAt <= self.pin.GetVersion()
}

// The kinds §16.11 ignores repo files of.
func fakeDirectoryRepoFileIgnored(kind protocol.RepoKind) bool {
	switch kind {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_DIRECTORY:
		return true
	}
	return false
}

// The owner-bound kinds (§8.5).
func fakeDirectoryOwnerBound(kind protocol.RepoKind) bool {
	switch kind {
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET:
		return true
	}
	return false
}
