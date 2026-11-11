//go:build !ios_extension

// RepoVersioning's lock, drops and their filing (ACL-M10-01; §8.8's RepoVersioning rows, §11.7, §11.13; D-ACL-25,
// D-PHASE-9; owner decisions 126, 160, 168, 173, 183):
//
//	lock     format 2 enforces the lock M2 folds into AclRepo.lock (D-PHASE-9). RepoLockAllowsVersioning refuses
//	         versioning 1, versionless, under it, never the search index's 2 (owner decision 168), and
//	         RepoLockAllowsDrop refuses drops, never their cancels, each judged at the state of the push's auth pin;
//	         RepoLocked is what evs's drop job reads at its start to void a drop still pending (§11.13)
//	drop     MayDrop is D-ACL-25: a repo admin's act; in an owner-bound repo only a consented, not-read-only device of
//	         its owner, so its admins neither drop nor cancel drops there (owner decisions 173, 183): one who tries is
//	         refused as unconsented, evs's 409 DROP_CONSENT. A reader judges a DROP's signer the same way at the
//	         DROP's own pin (DESIGN-DETAILS 10's H1). The config and mailcfg take no drop (evs's 409 DROP_KIND)
//	filing   AclRepoVersioningFiler signs RepoVersioning{repo_id, lock, rules} through CORE's act, from a person's
//	         confirmation alone, its rules sealed to the repo's own current generation when it is owner-bound, so
//	         only its readers learn its globs, and to the config's otherwise, which §17.8's rule bodies share; api
//	         and evs see only the lock (owner decision 126). The directory refuses every RepoVersioning (§8.8)
//	rules    AclRepoVersioningRules opens a statement's rules for TEAM-M10-01's ConfigState.VersioningFor, and
//	         AclRepoVersioningKeyRepo names the repo whose generation keys them
//
// The control class's remote search needs no gate change: receivers enforce SEARCH at Hello feature bit 0 and the
// contract gate never reads it (D-PROTO-21); acl_versioning_test.go shows the gate's verdict takes no feature input.
//
// On every leg but ios_extension, the sidecar_http page Worker's included, since every head reader judges a DROP's
// signer.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A versioning setting the lock refuses: versionless (§11.7). The search index's 2 stands (owner decision 168).
const aclLockedVersioning = ConfigVersioningVersionless

// A RepoVersioning this device will not file: the directory, a repo the state does not hold, rules that cover no path
// of the repo, or rules with no key to seal them under.
var ErrAclRepoVersioning = errors.New("acl: no RepoVersioning for this repo")

// Whether the newest RepoVersioning folded into the state locks the repo.
func (self *AclState) RepoLocked(repoId Id) bool {
	repo := self.repos[repoId]
	return repo != nil && repo.row.GetLock() == protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED
}

// Whether the lock lets a version of this setting be written: everything but versionless under a lock.
func (self *AclState) RepoLockAllowsVersioning(repoId Id, versioning uint32) bool {
	return versioning != aclLockedVersioning || !self.RepoLocked(repoId)
}

// Whether the lock lets a DROP push through: a cancel always, a drop only with no lock standing.
func (self *AclState) RepoLockAllowsDrop(repoId Id, cancel bool) bool {
	return cancel || !self.RepoLocked(repoId)
}

// D-ACL-25: whether the sidecar may sign a DROP push or its cancel on the repo at now. A repo admin may; in an
// owner-bound repo only one that is also a consented, not-read-only device of the owner, any other admin refused as
// unconsented (409 DROP_CONSENT). The config and mailcfg take no drop. The lock is RepoLockAllowsDrop's, beside this.
func (self *AclState) MayDrop(subjectId Id, repoId Id, now time.Time) AclDecision {
	nowMs := now.UnixMilli()
	sidecar := self.sidecarState(subjectId)
	if sidecar == nil {
		return aclDeny(AclReasonUnadmitted)
	}
	if deny := sidecar.hardDeny(nowMs); deny != 0 {
		return aclDeny(deny)
	}
	repo := self.repos[repoId]
	switch {
	case repo == nil:
		return aclDeny(AclReasonNoRepo)
	case repo.deleted:
		return aclDeny(AclReasonRepoDeleted)
	}
	switch repo.kind {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG:
		return aclDeny(AclReasonNoGrant)
	}
	if aclRepoKindOwnerBound(repo.kind) {
		if !repo.admins[sidecar.id] {
			return aclDeny(AclReasonNoGrant)
		}
		ownerDevice := sidecar.memberId == repo.ownerId && repo.consents[sidecar.id] && self.sidecarConsented(sidecar)
		if !ownerDevice || sidecar.readOnly {
			return aclDeny(AclReasonUnconsented)
		}
	}
	access := self.sidecarEvsAccess(sidecar, repoId, AclTokenAudienceEvs, nowMs)
	if !access.Rights.Has(AclEvsAdmin) {
		return aclDeny(AclReasonNoGrant)
	}
	return access.AclDecision
}

// The repo whose generation seals and opens a RepoVersioning's rules (§8.8's rules row): the repo itself when it is
// owner-bound, else the config. false for a repo the state does not hold.
func AclRepoVersioningKeyRepo(state *ConfigState, repoId Id) (Id, bool) {
	repo := state.Repo(repoId)
	if repo == nil {
		return Id{}, false
	}
	if aclRepoKindOwnerBound(repo.GetKind()) {
		return repoId, true
	}
	configRepoId, err := IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		return Id{}, false
	}
	return configRepoId, true
}

// A RepoVersioning's rules, opened with the generations repoKeyAt answers of the repo AclRepoVersioningKeyRepo names,
// and checked as every reader checks them; nil and no error for a statement with none. ErrConfigSealGenerationMissing
// while this device lacks the generation, which keeps the repo on the network's rules until it arrives.
func AclRepoVersioningRules(statement *protocol.RepoVersioning, repoKeyAt func(generation uint64) *EvsRepoKey) (*protocol.VersioningRules, error) {
	if len(statement.GetSealedRules()) == 0 {
		return nil, nil
	}
	rules := &protocol.VersioningRules{}
	context := NewConfigSealContext(bridge.SignedType_SIGNED_REPO_VERSIONING, statement.GetHeader())
	if _, err := OpenConfigBody(statement.GetSealedRules(), context, repoKeyAt, rules); err != nil {
		return nil, err
	}
	if err := CheckVersioningRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// The newest RepoVersioning of a repo among a config head's folded records and the entries after them that the
// state's log keeps, verified both: what a reader opens for VersioningFor. nil for none.
func AclNewestRepoVersioning(head *ConfigHead, state *ConfigState, repoId Id) (*protocol.RepoVersioning, error) {
	var newest *protocol.RepoVersioning
	take := func(body []byte) {
		signed := &bridge.Signed{}
		if proto.Unmarshal(body, signed) != nil || bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_REPO_VERSIONING {
			return
		}
		message, err := ParseConfigStatement(bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_REPO_VERSIONING, signed.GetBody())
		if err != nil {
			return
		}
		if statement := message.(*protocol.RepoVersioning); len(statement.GetRepoId()) == len(Id{}) && Id(statement.GetRepoId()) == repoId {
			newest = statement
		}
	}
	foldedThrough := uint64(0)
	if head != nil {
		records, err := head.RecordsIn(0, head.FoldedThrough())
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			if record.GetKind() == bridge.AuthEntryKindStatement {
				take(record.GetBody())
			}
		}
		foldedThrough = head.FoldedThrough()
	}
	if state != nil && state.history != nil {
		if view := state.history.view.Load(); view != nil {
			for n := max(view.from, foldedThrough+1); n <= state.n; n += 1 {
				if kept := state.keptEntryAt(n); kept != nil && kept.entry.GetKind() == bridge.AuthEntryKindStatement && kept.verdict.Accepted() {
					take(kept.entry.GetBody())
				}
			}
		}
	}
	return newest, nil
}

// One RepoVersioning to file.
type AclRepoVersioningRequest struct {
	RepoId Id
	// Locked or unlocked.
	Lock bool
	// The repo's own rules, replacing the network's VersioningRules for it (§7.9); nil files none.
	Rules *protocol.VersioningRules
}

// Files RepoVersioning statements for one Sidecar (ACL-M10-01's filer): a person's confirmation alone, rules sealed to
// the generation AclRepoVersioningKeyRepo names, whose key repoKey answers (the GkmClient's CurrentRepoKey). A nil
// repoKey files locks and refuses rules, which are never signed in the clear.
type AclRepoVersioningFiler struct {
	sidecar *Sidecar
	repoKey func(ctx context.Context, repoId Id) (*EvsRepoKey, error)
}

func NewAclRepoVersioningFiler(sidecar *Sidecar, repoKey func(ctx context.Context, repoId Id) (*EvsRepoKey, error)) *AclRepoVersioningFiler {
	return &AclRepoVersioningFiler{sidecar: sidecar, repoKey: repoKey}
}

// Signs and posts the request's RepoVersioning as the person confirmed it (origin, never MCP or a hook), answering
// once it lands. The repo's verifier at api and every reader judge the signer (§8.8's rule: a repo admin or a config
// writer, in an owner-bound repo a consented device of its owner).
func (self *AclRepoVersioningFiler) File(ctx context.Context, request *AclRepoVersioningRequest, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if origin != SidecarActConfirmed {
		return ErrSidecarActMode
	}
	state, err := self.sidecar.configState()
	if err != nil {
		return err
	}
	repo := state.Repo(request.RepoId)
	switch {
	case repo == nil:
		return fmt.Errorf("%w: the state holds no such repo", ErrAclRepoVersioning)
	case repo.GetKind() == protocol.RepoKind_REPO_KIND_DIRECTORY:
		return fmt.Errorf("%w: the directory takes no RepoVersioning (§8.8)", ErrAclRepoVersioning)
	}
	var repoKey *EvsRepoKey
	if request.Rules != nil {
		switch repo.GetKind() {
		case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG:
			return fmt.Errorf("%w: versioning rules cover no path of a %s repo", ErrAclRepoVersioning, repo.GetKind())
		}
		if err := CheckVersioningRules(request.Rules); err != nil {
			return err
		}
		keyRepoId, ok := AclRepoVersioningKeyRepo(state, request.RepoId)
		if !ok || self.repoKey == nil {
			return fmt.Errorf("%w: no key to seal its rules under", ErrAclRepoVersioning)
		}
		if repoKey, err = self.repoKey(ctx, keyRepoId); err != nil {
			return fmt.Errorf("%w: no key to seal its rules under: %w", ErrAclRepoVersioning, err)
		}
	}
	lock := protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_UNLOCKED
	if request.Lock {
		lock = protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED
	}
	act, err := self.sidecar.newAct(origin)
	if err != nil {
		return err
	}
	err = act.AddSealed(bridge.SignedType_SIGNED_REPO_VERSIONING, &protocol.RepoVersioning{RepoId: request.RepoId.Bytes(), Lock: lock},
		func(header *bridge.StatementHeader, statement proto.Message) error {
			if repoKey == nil {
				return nil
			}
			sealed, err := SealConfigBody(repoKey, NewConfigSealContext(bridge.SignedType_SIGNED_REPO_VERSIONING, header), request.Rules, nil)
			if err != nil {
				return err
			}
			statement.(*protocol.RepoVersioning).SealedRules = sealed
			return nil
		})
	if err != nil {
		return err
	}
	_, err = act.Run(ctx, check)
	return err
}

// Files a lock or an unlock of the repo's versioning, with no rules, as the person confirmed it (`ur evs lock`).
func (self *Sidecar) FileRepoLock(ctx context.Context, repoId Id, lock bool, origin SidecarActOrigin) error {
	return NewAclRepoVersioningFiler(self, nil).File(ctx, &AclRepoVersioningRequest{RepoId: repoId, Lock: lock}, origin, nil)
}

// The entry the state's log keeps at position n, nil when its window holds none there or holds an entry of another
// chain. The window is the log's immutable view, so this reads with no lock.
func (self *ConfigState) keptEntryAt(n uint64) *configKeptEntry {
	if self == nil || self.history == nil || n == 0 || self.n < n {
		return nil
	}
	view := self.history.view.Load()
	if view == nil || n < view.from || view.from+uint64(len(view.entries)) <= n {
		return nil
	}
	kept := view.entries[n-view.from]
	if kept == nil {
		return nil
	}
	if chain, ok := self.chainAt(n); !ok || chain != kept.chain {
		return nil
	}
	return kept
}
