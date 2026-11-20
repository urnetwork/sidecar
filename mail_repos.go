//go:build !ios_extension

// The repos mail lives in (R-MAIL-3, R-MAIL-5, D-MAIL-5, D-MAIL-6, D-ACL-13, I-5; MAIL-M7-05): which repo is a
// member's mailbox and which the network's mailcfg, their creation, and the RepoAdmin each of an owner's devices
// files for itself.
//
//	mailbox   one mailbox repo per member (kind mailbox, owner-bound, on its main file-mode ref), created by a
//	          consented device of that member that is not read_only, the only signer §8.8 takes a mailbox's
//	          RepoCreate from. Where the log holds more than one for a member, two devices having raced, every
//	          device takes the one created first in log order, the lowest id breaking a tie, so all agree
//	mailcfg   one mailcfg repo per network, created by a config writer (§8.8's RepoCreate row), its row naming no
//	          owner: the first such standing in log order. A Team scope's own mailcfg is the mailcfg whose row names
//	          the scope's member (§8.5's mailcfg row; QD-1093; MAIL-M8-09), never taken as the network's: a consented
//	          device of that member creates it, and the access log's fold owner-binds it to the creator's member, one
//	          per member, the first in log order, as a mailbox. Which of the two a RepoCreate makes is read from the
//	          log alone, not a field: a config writer's while no network mailcfg stands is the network's, and every
//	          other is its signer's member's scope's own, an AdminSet member's device's once the network's stands
//	          included (QD-1108). So each creation is refused here first where the log would read it as the other:
//	          a device that writes no config heads creates no network mailcfg, and a config writer no scope's while
//	          the network's does not stand (EnsureMailConfig, EnsureScopeMailConfig). A creation whose signer's
//	          standing, or the network mailcfg's, changed before it landed folds as the other and is answered
//	          ErrMailReposAbsent, never read as what was asked for. Two config writers racing to make the network's
//	          leave one network mailcfg, the first to land, and the other's member's scope's own, which is harmless
//	admins    ERASE and CLOSURE pushes take repo:<id>:admin (§11.8, §11.12), so each consented device of the owner
//	          that is not read_only files RepoAdmin{add} for itself once it holds the repo's key (§8.8), and any of
//	          them erases whether or not the device that created the mailbox survives. A read_only device, a parked
//	          one, an EvsShare subject, the audit reader and a deposit-only sidecar file nothing, and never erase
//	mail key  the network mail key is the admin mailbox's drop key (§15.8; D-KEYS-17): its repo is the mailbox the
//	          admin@ record names, which §14.8 seals reports to
//
// A creation resumes: a RepoCreate this device filed whose repo is not keyed yet is taken up again under its id
// (EvsCreateRepoArgs.ResumeRepoId), never filed twice, and a repo this process created is remembered until the
// state shows it.
//
// Group repos are mail_repos_group.go's. On every leg but the extension's. MailRepos is safe for concurrent use.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// Arguments out of shape. The error names no address.
	ErrMailReposInvalid = errors.New("mail repos: invalid")
	// No verified state of the access log yet, or nothing to file statements or create repos through: nothing is
	// read as present or absent.
	ErrMailReposNoState = errors.New("mail repos: no verified state")
	// This device is no consented device of the mailbox's owner, or is read_only: it creates no mailbox and files
	// no RepoAdmin.
	ErrMailReposNotConsented = errors.New("mail repos: not a consented device of the owner that may write")
	// No mailbox, or no mailcfg, stands for what was asked.
	ErrMailReposAbsent = errors.New("mail repos: no such repo")
	// The mailcfg asked for is not this device's to create: the network's is a config writer's, and a Team scope's
	// own is a device's that writes no config heads, or a config writer's once the network's stands, since the log
	// reads a config writer's as the network's while none stands (QD-1093, QD-1108).
	ErrMailReposConfigWriter = errors.New("mail repos: not this device's mailcfg to create")
)

// What MailRepos needs of evs, which *EvsClient is.
type mailReposEvs interface {
	CreateRepo(ctx context.Context, args *EvsCreateRepoArgs) (*EvsRepo, error)
	Repo(repoId Id) *EvsRepo
}

// What NewMailRepos builds on.
type MailReposArgs struct {
	// Creates repos and hands out their handles.
	Evs *EvsClient
	// The newest verified state of §8's access log, nil before one verifies.
	State func() *AclState
	// Files RepoAdmin and RepoGrant statements: the core's poster, as EvsClientArgs.FileStatement is.
	FileStatement EvsFileStatementFunction
	// Says whether this device holds a repo's key. Nil holds none.
	Gkm GkmClient
	// This sidecar.
	SidecarId Id
	// Nil logs nothing.
	Log Logger
}

// The repos mail lives in. See the file header. Safe for concurrent use.
type MailRepos struct {
	evs           mailReposEvs
	state         func() *AclState
	fileStatement EvsFileStatementFunction
	gkm           GkmClient
	sidecarId     Id
	log           Logger

	// held for one creation at a time, across its calls; never taken with stateLock held
	createToken chan struct{}

	stateLock sync.Mutex
	// repos this process created that the state may not show yet: each member's mailbox, the network's mailcfg, and
	// each member's scope's own
	createdMailboxIds     map[Id]Id
	createdMailConfig     *Id
	createdScopeConfigIds map[Id]Id
	// repos this process filed its own RepoAdmin for, which the state may not show yet
	adminFiledRepoIds map[Id]bool
}

// The mail repos of args.Evs's network.
func NewMailRepos(args *MailReposArgs) (*MailRepos, error) {
	if args == nil || args.Evs == nil {
		return nil, fmt.Errorf("%w: no evs client", ErrMailReposInvalid)
	}
	return newMailRepos(args.Evs, args), nil
}

// MailRepos over evs.
func newMailRepos(evs mailReposEvs, args *MailReposArgs) *MailRepos {
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &MailRepos{
		evs:                   evs,
		state:                 args.State,
		fileStatement:         args.FileStatement,
		gkm:                   args.Gkm,
		sidecarId:             args.SidecarId,
		log:                   log,
		createToken:           make(chan struct{}, 1),
		createdMailboxIds:     map[Id]Id{},
		createdScopeConfigIds: map[Id]Id{},
		adminFiledRepoIds:     map[Id]bool{},
	}
}

// The newest verified state, or ErrMailReposNoState.
func (self *MailRepos) verifiedState() (*AclState, error) {
	if self.state == nil {
		return nil, ErrMailReposNoState
	}
	state := self.state()
	if state == nil {
		return nil, ErrMailReposNoState
	}
	return state, nil
}

// Whether a repo row stands: not deleted, or deleted and restored, as the access log's fold reads it when it asks
// whether the network's mailcfg stands (aclNetworkMailcfgStands).
func mailRepoStands(repo *protocol.AclRepo) bool {
	return aclRepoRowStands(repo)
}

// The log position a repo was created at, as its rows tell it: its earliest standing admin row, the creator's, which a
// RepoCreate adds; 0 for a repo with none left. A removed admin's row, which the rows keep for a while (QD-743), counts
// as gone, as it did when a removal took the row out.
func mailRepoCreatedAt(repo *protocol.AclRepo) uint64 {
	createdAt := uint64(0)
	for _, admin := range repo.GetAdmins() {
		if !AclRepoAdminStands(admin) {
			continue
		}
		if at := admin.GetAt(); createdAt == 0 || at < createdAt {
			createdAt = at
		}
	}
	return createdAt
}

// The standing repo of kind that matches, the one created first in log order, then the lowest id: what every
// device agrees on from one state.
func mailRepoOfKind(state *AclState, kind protocol.RepoKind, matches func(repo *protocol.AclRepo) bool) (Id, *protocol.AclRepo, bool) {
	type candidate struct {
		repoId    Id
		repo      *protocol.AclRepo
		createdAt uint64
	}
	candidates := []candidate{}
	for _, repoId := range state.RepoIds() {
		repo := state.Repo(repoId)
		if repo == nil || repo.GetKind() != kind || !mailRepoStands(repo) || (matches != nil && !matches(repo)) {
			continue
		}
		candidates = append(candidates, candidate{repoId: repoId, repo: repo, createdAt: mailRepoCreatedAt(repo)})
	}
	if len(candidates) == 0 {
		return Id{}, nil, false
	}
	slices.SortFunc(candidates, func(a candidate, b candidate) int {
		// a repo with no admin row left sorts after those with one
		if (a.createdAt == 0) != (b.createdAt == 0) {
			if a.createdAt == 0 {
				return 1
			}
			return -1
		}
		if c := cmp.Compare(a.createdAt, b.createdAt); c != 0 {
			return c
		}
		return a.repoId.Cmp(b.repoId)
	})
	return candidates[0].repoId, candidates[0].repo, true
}

// A member's mailbox as the state holds it, false for none.
func (self *MailRepos) Mailbox(memberId Id) (Id, bool) {
	state, err := self.verifiedState()
	if err != nil {
		return Id{}, false
	}
	repoId, _, found := mailRepoOfKind(state, protocol.RepoKind_REPO_KIND_MAILBOX, func(repo *protocol.AclRepo) bool {
		return mailRepoOwnedBy(repo, memberId)
	})
	return repoId, found
}

// Whether a mailcfg row is the network's own: one that names no owner, as a Team scope's names its member.
func mailRepoNetworkConfig(repo *protocol.AclRepo) bool {
	return len(repo.GetOwnerMemberId()) == 0
}

// Whether a row names memberId as its owner.
func mailRepoOwnedBy(repo *protocol.AclRepo, memberId Id) bool {
	ownerMemberId, err := IdFromBytes(repo.GetOwnerMemberId())
	return err == nil && ownerMemberId == memberId
}

// Whether this device writes config heads at state, so the log reads a mailcfg it creates as the network's while none
// stands.
func (self *MailRepos) configWriter(state *AclState) bool {
	sidecar := state.sidecarState(self.sidecarId)
	return sidecar != nil && sidecar.configWriter
}

// Whether the network's mailcfg stands at state, so the log reads every mailcfg created now as its signer's member's
// scope's own, a config writer's included (QD-1108): the fold's own rule, on the same rows.
func mailNetworkConfigStands(state *AclState) bool {
	return aclNetworkMailcfgStands(state.Rows().GetRepos())
}

// Whether a mailcfg this process created folded as another than it asked for: the state holds its row, and the row is
// not what matches takes. Its signer's standing changed between the filing and its log position (the file header's
// mailcfg row).
func mailRepoFoldedAsAnother(state *AclState, remembered *Id, matches func(repo *protocol.AclRepo) bool) bool {
	if remembered == nil {
		return false
	}
	repo := state.Repo(*remembered)
	return repo != nil && !matches(repo)
}

// The network's mailcfg as the state holds it, false for none: never a Team scope's.
func (self *MailRepos) MailConfigRepo() (Id, bool) {
	state, err := self.verifiedState()
	if err != nil {
		return Id{}, false
	}
	repoId, _, found := mailRepoOfKind(state, protocol.RepoKind_REPO_KIND_MAILCFG, mailRepoNetworkConfig)
	return repoId, found
}

// A Team scope's own mailcfg as the state holds it (MAIL-M8-09; QD-1093): the mailcfg whose row names the scope's
// member, read only by that member's consented devices and the scope's receivers. Of several a member's devices made,
// the first in log order, the lowest id breaking a tie, so a later one never replaces it. False for none.
func (self *MailRepos) ScopeMailConfigRepo(memberId Id) (Id, bool) {
	state, err := self.verifiedState()
	if err != nil {
		return Id{}, false
	}
	return mailScopeConfigRepo(state, memberId)
}

// ScopeMailConfigRepo at state.
func mailScopeConfigRepo(state *AclState, memberId Id) (Id, bool) {
	if state == nil || memberId == (Id{}) {
		return Id{}, false
	}
	repoId, _, found := mailRepoOfKind(state, protocol.RepoKind_REPO_KIND_MAILCFG, func(repo *protocol.AclRepo) bool {
		return mailRepoOwnedBy(repo, memberId)
	})
	return repoId, found
}

// Whether this device holds repoId's key, so it reads and writes it.
func (self *MailRepos) holdsKey(ctx context.Context, repoId Id) (bool, error) {
	if self.gkm == nil {
		return false, nil
	}
	key, err := self.gkm.CurrentRepoKey(ctx, repoId)
	switch {
	case errors.Is(err, ErrGkmKeyMissing), errors.Is(err, ErrGkmUnavailable), errors.Is(err, ErrGkmAuthAhead):
		return false, nil
	case err != nil:
		return false, err
	}
	return key != nil, nil
}

// Whether this device created repo: its sidecar signed the earliest standing admin row, its own.
func (self *MailRepos) created(repo *protocol.AclRepo) bool {
	createdAt := mailRepoCreatedAt(repo)
	for _, admin := range repo.GetAdmins() {
		if !AclRepoAdminStands(admin) || admin.GetAt() != createdAt {
			continue
		}
		adminId, err := IdFromBytes(admin.GetSidecarId())
		return err == nil && adminId == self.sidecarId
	}
	return false
}

// Whether this device is a consented device of memberId that may write: not read_only, parked or suspended.
func (self *MailRepos) consentedWriter(state *AclState, memberId Id) bool {
	return state.ConsentedFor(self.sidecarId, memberId) && state.ApprovalCapable(self.sidecarId)
}

// The repo a creation of this process made, taken up again where the state does not show it yet; else a new one.
func (self *MailRepos) createOrResume(ctx context.Context, args *EvsCreateRepoArgs, remembered *Id, remember func(repoId Id)) (*EvsRepo, error) {
	if remembered != nil {
		keyed, err := self.holdsKey(ctx, *remembered)
		if err != nil {
			return nil, err
		}
		if keyed {
			return self.evs.Repo(*remembered), nil
		}
		resumed := *args
		resumed.ResumeRepoId = remembered
		args = &resumed
	}
	repo, err := self.evs.CreateRepo(ctx, args)
	if repo != nil {
		// filed, even where a later step failed: the next call resumes it
		remember(repo.RepoId())
	}
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// The member's mailbox, created when the log holds none (D-MAIL-6): by a consented device of that member that is
// not read_only, else ErrMailReposNotConsented. A mailbox this device created and did not finish keying is taken up
// again; another device's is answered as it stands, this device waiting for its seat in it.
func (self *MailRepos) EnsureMailbox(ctx context.Context, memberId Id) (*EvsRepo, error) {
	if memberId == (Id{}) {
		return nil, fmt.Errorf("%w: no member", ErrMailReposInvalid)
	}
	select {
	case self.createToken <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-self.createToken }()

	state, err := self.verifiedState()
	if err != nil {
		return nil, err
	}
	remembered := func() *Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if repoId, ok := self.createdMailboxIds[memberId]; ok {
			return &repoId
		}
		return nil
	}()
	repoId, repo, found := mailRepoOfKind(state, protocol.RepoKind_REPO_KIND_MAILBOX, func(repo *protocol.AclRepo) bool {
		ownerMemberId, err := IdFromBytes(repo.GetOwnerMemberId())
		return err == nil && ownerMemberId == memberId
	})
	if found {
		if !self.created(repo) || !self.consentedWriter(state, memberId) {
			return self.evs.Repo(repoId), nil
		}
		// this device's own: finished where a crash cut it short
		remembered = &repoId
	} else if !self.consentedWriter(state, memberId) {
		return nil, ErrMailReposNotConsented
	}
	return self.createOrResume(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_MAILBOX, OwnerMemberId: &memberId}, remembered, func(repoId Id) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.createdMailboxIds[memberId] = repoId
	})
}

// The network's mailcfg, created when the log holds none: its RepoCreate is a config writer's (§8.8), so a device
// that is none creates nothing, ErrMailReposConfigWriter, since the log would take its RepoCreate as its member's
// scope's own (QD-1093). One this device created and did not finish keying is taken up again; one that folded as a
// scope's own, this device a config writer no more when it landed, or another config writer's network mailcfg having
// landed first (QD-1108), is ErrMailReposAbsent where no network mailcfg stands, and the one that stands otherwise.
func (self *MailRepos) EnsureMailConfig(ctx context.Context) (*EvsRepo, error) {
	select {
	case self.createToken <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-self.createToken }()

	state, err := self.verifiedState()
	if err != nil {
		return nil, err
	}
	remembered := func() *Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.createdMailConfig
	}()
	repoId, repo, found := mailRepoOfKind(state, protocol.RepoKind_REPO_KIND_MAILCFG, mailRepoNetworkConfig)
	if found {
		if !self.created(repo) {
			return self.evs.Repo(repoId), nil
		}
		remembered = &repoId
	} else if mailRepoFoldedAsAnother(state, remembered, mailRepoNetworkConfig) {
		// forgotten, so the next call judges this device's standing anew
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.createdMailConfig = nil
		}()
		return nil, fmt.Errorf("%w: the mailcfg this device created is no network's", ErrMailReposAbsent)
	} else if remembered == nil && !self.configWriter(state) {
		return nil, ErrMailReposConfigWriter
	}
	return self.createOrResume(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_MAILCFG}, remembered, func(repoId Id) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.createdMailConfig = &repoId
	})
}

// The own mailcfg of the Team scope that is memberId's, created when the log holds none (MAIL-M8-09; QD-1093): by a
// consented device of that member that is not read_only, else ErrMailReposNotConsented. A config writer, an AdminSet
// member's device, creates it once the network's mailcfg stands (QD-1108), and while none stands is
// ErrMailReposConfigWriter, since the log would read its mailcfg as the network's. The access log's fold binds it to
// its creator's member, so its readers are that member's consented devices and the scope's receivers alone (§15.7).
// One this device created and did not finish keying is taken up again; another device's is answered as it stands,
// this device waiting for its seat in it; one that folded as the network's, this device a config writer and no network
// mailcfg standing by the time it landed, is ErrMailReposAbsent.
func (self *MailRepos) EnsureScopeMailConfig(ctx context.Context, memberId Id) (*EvsRepo, error) {
	if memberId == (Id{}) {
		return nil, fmt.Errorf("%w: no member", ErrMailReposInvalid)
	}
	select {
	case self.createToken <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-self.createToken }()

	state, err := self.verifiedState()
	if err != nil {
		return nil, err
	}
	remembered := func() *Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if repoId, ok := self.createdScopeConfigIds[memberId]; ok {
			return &repoId
		}
		return nil
	}()
	owned := func(repo *protocol.AclRepo) bool { return mailRepoOwnedBy(repo, memberId) }
	repoId, repo, found := mailRepoOfKind(state, protocol.RepoKind_REPO_KIND_MAILCFG, owned)
	switch {
	case found:
		if !self.created(repo) || !self.consentedWriter(state, memberId) {
			return self.evs.Repo(repoId), nil
		}
		// this device's own: finished where a crash cut it short
		remembered = &repoId
	case !self.consentedWriter(state, memberId):
		return nil, ErrMailReposNotConsented
	case mailRepoFoldedAsAnother(state, remembered, owned):
		// forgotten, so the next call judges this device's standing anew
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.createdScopeConfigIds, memberId)
		}()
		return nil, fmt.Errorf("%w: the mailcfg this device created is no scope's", ErrMailReposAbsent)
	case remembered == nil && self.configWriter(state) && !mailNetworkConfigStands(state):
		// the log would read it as the network's: an AdminSet member's scope waits for the network's to stand
		return nil, ErrMailReposConfigWriter
	}
	return self.createOrResume(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_MAILCFG, OwnerMemberId: &memberId}, remembered, func(repoId Id) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.createdScopeConfigIds[memberId] = repoId
	})
}

// Files RepoAdmin{add} for this device in a member's mailbox once it is seated (§8.8, §15.7), so erasure never
// waits on the device that created it. It answers whether a statement was filed: none for a device that is already
// an admin, holds no key of the repo yet, is no consented device of the owner or is read_only, and none for a repo
// that is no mailbox.
func (self *MailRepos) EnsureRepoAdmin(ctx context.Context, repoId Id) (bool, error) {
	state, err := self.verifiedState()
	if err != nil {
		return false, err
	}
	repo := state.Repo(repoId)
	if repo == nil || !mailRepoStands(repo) {
		return false, ErrMailReposAbsent
	}
	if repo.GetKind() != protocol.RepoKind_REPO_KIND_MAILBOX {
		// a group's admins are its creating device and those a repo admin or config writer adds (§15.7)
		return false, nil
	}
	ownerMemberId, err := IdFromBytes(repo.GetOwnerMemberId())
	if err != nil || !self.consentedWriter(state, ownerMemberId) {
		return false, nil
	}
	for _, admin := range repo.GetAdmins() {
		// a removed row of this device's, which the rows keep a while (QD-743), makes it no admin
		if adminId, err := IdFromBytes(admin.GetSidecarId()); err == nil && adminId == self.sidecarId && AclRepoAdminStands(admin) {
			return false, nil
		}
	}
	filed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.adminFiledRepoIds[repoId]
	}()
	if filed {
		return false, nil
	}
	keyed, err := self.holdsKey(ctx, repoId)
	if err != nil || !keyed {
		return false, err
	}
	if self.fileStatement == nil {
		return false, ErrMailReposNoState
	}
	admin := &protocol.RepoAdmin{RepoId: repoId.Bytes(), SidecarId: self.sidecarId.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD}
	if err := self.fileStatement(ctx, bridge.SignedType_SIGNED_REPO_ADMIN, admin); err != nil {
		return false, fmt.Errorf("mail repos: RepoAdmin: %w", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.adminFiledRepoIds[repoId] = true
	return true, nil
}

// The repo whose drop key is the network mail key (§15.8; D-KEYS-17): the mailbox the admin@ record of config's
// zone names, the owner's mailbox or a Team's admin group repo. ErrMailReposAbsent while no admin record a reader
// honors stands.
func (self *MailRepos) NetworkMailKeyRepo(ctx context.Context, config *MailConfig) (Id, error) {
	if config == nil {
		return Id{}, fmt.Errorf("%w: no mailcfg", ErrMailReposInvalid)
	}
	zone, _, err := config.zone()
	if err != nil {
		return Id{}, err
	}
	lookup, err := config.Resolve(ctx, MailRecipient{Kind: MailAddressKindAdmin, LocalPart: mailAdminLocalParts[0], Zone: zone})
	if err != nil {
		return Id{}, err
	}
	if !lookup.Known {
		return Id{}, ErrMailReposAbsent
	}
	return lookup.MailboxRepoId, nil
}
