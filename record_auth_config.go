//go:build !ios_extension

// Record authorization from one published config state and its folded ACL. Live reads sample the device clock once
// per view so expiring grants cannot outlive their expiry between config entries. Historical views use the time
// of the corresponding verified config entry.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The config and its immutable ACL at one point in time.
type configRecordAuth struct {
	state          *ConfigState
	acl            *AclState
	at             time.Time
	logsOnce       sync.Once
	logs           RecordLogIds
	memberVaultIds map[Id]Id
}

// The record's authorization against a published snapshot. An absent snapshot or unusable ACL grants nothing.
func NewRecordAuthView(state *ConfigState) RecordAuthView {
	return newConfigRecordAuth(state, RealClock{}.Now())
}

// Binds a verified state to its evaluation time.
func newConfigRecordAuth(state *ConfigState, at time.Time) RecordAuthView {
	if state == nil {
		return RecordAuthUnavailable{}
	}
	acl, err := state.Acl()
	if err != nil || acl == nil {
		return RecordAuthUnavailable{}
	}
	return &configRecordAuth{state: state, acl: acl, at: at}
}

// The config pin this snapshot verified.
func (self *configRecordAuth) Pin() *bridge.AuthPin {
	return self.state.Pin()
}

// The verified snapshot at the complete pin, including the chain value.
func (self *configRecordAuth) At(pin *bridge.AuthPin) (RecordAuthView, error) {
	state, err := self.state.StateAt(pin)
	switch {
	case errors.Is(err, ErrConfigPinAhead):
		return nil, fmt.Errorf("%w: %w", ErrRecordAuthAhead, err)
	case errors.Is(err, ErrConfigPinNotRetained):
		return nil, fmt.Errorf("%w: %w", ErrRecordAuthNotRetained, err)
	case errors.Is(err, ErrConfigPinOffChain):
		return nil, fmt.Errorf("%w: %w", ErrRecordAuthOffChain, err)
	case err != nil:
		return nil, err
	}
	return newConfigRecordAuth(state, time.UnixMilli(state.TimeMs())), nil
}

// A position resolves only to the chain the published state retained.
func (self *configRecordAuth) AtPosition(version uint64) (RecordAuthView, error) {
	if self.state.n < version {
		return nil, ErrRecordAuthAhead
	}
	chain, ok := self.state.chainAt(version)
	if !ok {
		return nil, ErrRecordAuthNotRetained
	}
	return self.At(&bridge.AuthPin{Version: version, Chain: chain[:]})
}

// The first later position at which neither writing nor depositing remained. An unjudgeable interval refuses.
func (self *configRecordAuth) RightEnded(repoId Id, sidecarId Id, after uint64) (int64, bool) {
	for position := after; position < self.state.n; {
		position++
		view, err := self.AtPosition(position)
		if err != nil {
			return 0, true
		}
		if !view.Writes(repoId, sidecarId) && !view.Deposits(repoId, sidecarId) {
			state, ok := view.(*configRecordAuth)
			if !ok {
				return 0, true
			}
			return state.state.TimeMs(), true
		}
	}
	return 0, false
}

// The admitted writer key, including its tombstone.
func (self *configRecordAuth) IdentityKey(sidecarId Id) []byte {
	return bytes.Clone(self.state.IdentityKey(sidecarId))
}

// The member of an admitted untagged device.
func (self *configRecordAuth) Member(sidecarId Id) (Id, bool) {
	return (&configDirectoryAuth{state: self.state}).MemberOf(sidecarId)
}

// A tagged sidecar's live sponsor.
func (self *configRecordAuth) Sponsor(sidecarId Id) (Id, bool) {
	return self.state.Sponsor(sidecarId)
}

// The owner's device consent and this live vault's own consent row.
func (self *configRecordAuth) Consented(repoId Id, sidecarId Id) bool {
	repo := self.acl.repos[repoId]
	return repo != nil && !repo.deleted && repo.kind == protocol.RepoKind_REPO_KIND_VAULT &&
		repo.consents[sidecarId] && self.acl.ConsentedFor(sidecarId, repo.ownerId)
}

// A live record log's EVS rights, checked by the same ACL as the service exchange.
func (self *configRecordAuth) rights(repoId Id, sidecarId Id) AclEvsRights {
	repo := self.acl.repos[repoId]
	if repo == nil || repo.deleted {
		return 0
	}
	switch repo.kind {
	case protocol.RepoKind_REPO_KIND_VAULT:
		rights := self.acl.EvsAccess(AclSidecarSubject(sidecarId), repoId, AclTokenAudienceEvs, self.at).Rights
		if rights.Has(AclEvsWrite) {
			// a vault's writer, its owner's consented device, writes its own stream, which lands in seq order: the
			// deposit its write implies (QD-1173) is none of the record's, so its chain gap alarms at once
			// (record_pins.go)
			rights &^= AclEvsDeposit
		}
		return rights
	case protocol.RepoKind_REPO_KIND_TEAM_RECORD, protocol.RepoKind_REPO_KIND_DIRECTORY, protocol.RepoKind_REPO_KIND_RECORD:
		return self.acl.EvsAccess(AclSidecarSubject(sidecarId), repoId, AclTokenAudienceEvs, self.at).Rights
	case protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET:
		// These venues take read receipts, but are not themselves record logs (§16.8).
		rights := self.acl.EvsAccess(AclSidecarSubject(sidecarId), repoId, AclTokenAudienceEvs, self.at).Rights
		if rights.Has(AclEvsRead|AclEvsDeposit) && !rights.Has(AclEvsWrite) {
			return AclEvsDeposit
		}
	}
	return 0
}

// Whether the subject may read the log.
func (self *configRecordAuth) Reads(repoId Id, sidecarId Id) bool {
	return self.rights(repoId, sidecarId).Has(AclEvsRead)
}

// Whether the subject may write its stream.
func (self *configRecordAuth) Writes(repoId Id, sidecarId Id) bool {
	return self.rights(repoId, sidecarId).Has(AclEvsWrite)
}

// Whether the subject administers the live log.
func (self *configRecordAuth) Admins(repoId Id, sidecarId Id) bool {
	return self.rights(repoId, sidecarId).Has(AclEvsAdmin)
}

// Whether the subject may deposit.
func (self *configRecordAuth) Deposits(repoId Id, sidecarId Id) bool {
	return self.rights(repoId, sidecarId).Has(AclEvsDeposit)
}

// Read-only credentials and a vault's nonwriting readers may deposit only observed reads.
func (self *configRecordAuth) ReceiptOnly(repoId Id, sidecarId Id) bool {
	rights := self.rights(repoId, sidecarId)
	if !rights.Has(AclEvsDeposit) || rights.Has(AclEvsWrite) {
		return false
	}
	switch self.acl.repos[repoId].kind {
	case protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET:
		return true
	case protocol.RepoKind_REPO_KIND_VAULT:
		return rights.Has(AclEvsRead)
	}
	return rights.Has(AclEvsRead) && configRowReadOnly(self.state.SidecarRow(sidecarId))
}

// A compromise span reaching a permanent revocation voids the writer from its start. A later compromise can extend a
// lost revocation backwards. A collateral park that ended before a revocation does not permanently void the writer.
func (self *configRecordAuth) CompromisedSince(sidecarId Id) (uint64, bool) {
	row := self.state.SidecarRow(sidecarId)
	revokedAt := row.GetRevokedAt()
	var since uint64
	if revokedAt != 0 {
		for _, span := range row.GetCascades() {
			if revokedAt <= span.GetUntil() && (since == 0 || span.GetFrom() < since) {
				since = span.GetFrom()
			}
		}
	}
	return since, since != 0
}

// Folds the live record logs once per snapshot. Repo ids break ties in the earliest retained creator rows.
func (self *configRecordAuth) loadLogs() {
	self.logsOnce.Do(func() {
		team := self.state.TeamSettings()
		self.logs = RecordLogIds{Team: team.Team, TeamCost: team.RecordCost}
		self.memberVaultIds = map[Id]Id{}
		earlier := func(repo *protocol.AclRepo, current Id) bool {
			return current == (Id{}) || directoryRepoCreatedAt(repo) < directoryRepoCreatedAt(self.acl.Repo(current))
		}
		for _, id := range self.acl.RepoIds() {
			repo, live := directoryRepoRow(self.acl, id)
			if !live {
				continue
			}
			switch repo.GetKind() {
			case protocol.RepoKind_REPO_KIND_VAULT:
				if owner, err := IdFromBytes(repo.GetOwnerMemberId()); err == nil && earlier(repo, self.memberVaultIds[owner]) {
					self.memberVaultIds[owner] = id
				}
			case protocol.RepoKind_REPO_KIND_DIRECTORY:
				if self.logs.DirectoryId == nil || earlier(repo, *self.logs.DirectoryId) {
					self.logs.DirectoryId = &id
				}
			case protocol.RepoKind_REPO_KIND_TEAM_RECORD:
				if self.logs.TeamRecordId == nil || earlier(repo, *self.logs.TeamRecordId) {
					self.logs.TeamRecordId = &id
				}
			case protocol.RepoKind_REPO_KIND_RECORD:
				self.logs.LedgerIds = append(self.logs.LedgerIds, id)
			}
		}
	})
}

// The team logs and ledger ids in the published config.
func (self *configRecordAuth) Logs() *RecordLogIds {
	self.loadLogs()
	logs := self.logs
	logs.LedgerIds = slices.Clone(logs.LedgerIds)
	if logs.TeamRecordId != nil {
		id := *logs.TeamRecordId
		logs.TeamRecordId = &id
	}
	if logs.DirectoryId != nil {
		id := *logs.DirectoryId
		logs.DirectoryId = &id
	}
	return &logs
}

// The member's live vault with the earliest creation.
func (self *configRecordAuth) Vault(memberId Id) (Id, bool) {
	self.loadLogs()
	id, ok := self.memberVaultIds[memberId]
	return id, ok
}

// The audit reader set that requires a second receipt in the team log.
func (self *configRecordAuth) AuditReaders(repoId Id, at time.Time) []Id {
	return self.acl.AuditReaders(repoId, at)
}
