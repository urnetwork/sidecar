//go:build !ios_extension

// RecordVault.Ensure (proposed; RECORD-M3-12; plan-RECORD-small-readings#3, QD-218; §11.12's kinds, §16.8's logs
// table): member M's vault is M's live vault repo whose RepoCreate has the lowest log position, and the first
// consented, not read_only device of M with an entry to write files that RepoCreate.
//
//	held      a vault the newest verified state names (RecordAuthView.Vault) is the answer, and nothing is filed
//	file      otherwise only a consented, not read_only device of its own member files (§8.5's consented(d, M), ACL's
//	          one predicate, through RecordVaultAuthority; §7.9's read_only): a tagged, ephemeral or parked sidecar,
//	          or one with no authority, is refused. It journals a fresh repo id, files RepoCreate{that id, vault}
//	          through the core's statement poster, then runs §11.12's creation from the route on (EvsClient.CreateRepo
//	          with ResumeRepoId: placement, KF1's group, activation)
//	race      then it waits for a state whose vault rule sees its RepoCreate, StateWait at a time, at most
//	          StateWaitCount times: its own repo is the vault, or an earlier one is, which takes everything, and then
//	          it files RepoDelete{now} for its own repo before anything is written there, so one vault is left. A
//	          state that names an earlier vault while not holding this device's RepoCreate answers the same, since
//	          this device's comes later in the log
//	restart   the journal names the repo it filed and how far it got: Ensure resumes the creation or the deletion
//	          from there, so a device killed between filing and deleting leaves no second live vault; a filing cut
//	          short is filed again only while the client's verified state does not hold the repo
//	waits     ErrRecordVaultWait when the state has not reached the RepoCreate within the waits: the journal keeps the
//	          step, and the next Ensure goes on from it
//
// A depositor never files a vault: it deposits to the one the rule names at its pin, and every such pin that holds a
// later RepoCreate holds the earlier one too, so no deposit reaches a vault that loses. On desktop and mobile legs.
// Safe for concurrent use: one Ensure at a time.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The vault journal's format values.
const (
	recordVaultJournalName    = "vault-create"
	recordVaultJournalVersion = 1
	recordVaultStepFiling     = "filing"
	recordVaultStepFiled      = "filed"
	recordVaultStepCreated    = "created"
	recordVaultStepDeleting   = "deleting"
)

var (
	// This sidecar may not file its member's vault: no member, a tagged or ephemeral sidecar, a read_only or parked
	// device, or no authority that says it is consented.
	ErrRecordVaultNotCreator = errors.New("record vault: this sidecar does not file its member's vault")
	// The vault's RepoCreate has not reached this device's verified state yet: Ensure goes on from its journal.
	ErrRecordVaultWait = errors.New("record vault: waiting for the vault's RepoCreate in the verified state")
)

// Who may file a member's vault: TEAM's and ACL's states, as their answer lands.
type RecordVaultAuthority interface {
	// Whether the sidecar is a consented device of the member (§8.5's consented(d, M)) that is not read_only (§7.9).
	VaultCreator(sidecarId Id, memberId Id) bool
}

// What Ensure waits by.
type RecordVaultSettings struct {
	// How long Ensure waits for a newer verified state between looks at the vault rule. Non-positive looks again at
	// once.
	StateWait time.Duration
	// How many waits before ErrRecordVaultWait: §8.9 brings a statement to every device within 5 s.
	StateWaitCount int
}

// One second at a time, for a minute.
func DefaultRecordVaultSettings() *RecordVaultSettings {
	return &RecordVaultSettings{
		StateWait:      time.Second,
		StateWaitCount: 60,
	}
}

// What a RecordVault runs on.
type RecordVaultArgs struct {
	SidecarId Id
	// The network's evs client, whose statement poster files RepoCreate and RepoDelete.
	Client *EvsClient
	// The newest verified state.
	Auth func() RecordAuthView
	// Nil: no vault is ever filed here.
	Authority RecordVaultAuthority
	// The record component's sealed directory.
	Store    SidecarStore
	Clock    Clock
	Settings *RecordVaultSettings
}

// A member's vault, made when it has none. See the file header.
type RecordVault struct {
	sidecarId Id
	client    *EvsClient
	auth      func() RecordAuthView
	authority RecordVaultAuthority
	store     SidecarStore
	clock     Clock
	settings  *RecordVaultSettings

	ensureLock sync.Mutex
}

// A vault maker on args.
func NewRecordVault(args *RecordVaultArgs) (*RecordVault, error) {
	if args == nil || args.Client == nil || args.Auth == nil || args.Store == nil {
		return nil, fmt.Errorf("%w: a record vault needs an evs client, a state and a store", ErrRecordDraftInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultRecordVaultSettings()
	}
	return &RecordVault{
		sidecarId: args.SidecarId,
		client:    args.Client,
		auth:      args.Auth,
		authority: args.Authority,
		store:     args.Store,
		clock:     clockOrReal(args.Clock),
		settings:  settings,
	}, nil
}

// The journal of the one vault this device filed and has not settled.
type recordVaultJournal struct {
	Version  int    `json:"version"`
	RepoId   Id     `json:"repo_id"`
	MemberId Id     `json:"member_id"`
	Step     string `json:"step"`
}

// The journal, nil for none.
func (self *RecordVault) readJournal() (*recordVaultJournal, error) {
	reader, err := self.store.Open(recordVaultJournalName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	journal := &recordVaultJournal{}
	if err := json.Unmarshal(content, journal); err != nil || journal.Version != recordVaultJournalVersion {
		return nil, fmt.Errorf("%w: the record vault journal", ErrSidecarStoreFailed)
	}
	return journal, nil
}

// Writes journal durably, nil removing it.
func (self *RecordVault) writeJournal(journal *recordVaultJournal) error {
	if journal == nil {
		return self.store.Remove(recordVaultJournalName)
	}
	journal.Version = recordVaultJournalVersion
	content, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(recordVaultJournalName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// This sidecar's member's vault, filed when it has none: see the file header.
func (self *RecordVault) Ensure(ctx context.Context) (Id, error) {
	self.ensureLock.Lock()
	defer self.ensureLock.Unlock()
	journal, err := self.readJournal()
	if err != nil {
		return Id{}, err
	}
	if journal == nil {
		auth := self.auth()
		memberId, ok := auth.Member(self.sidecarId)
		if !ok {
			return Id{}, fmt.Errorf("%w: no member", ErrRecordVaultNotCreator)
		}
		if vaultId, ok := auth.Vault(memberId); ok {
			return vaultId, nil
		}
		if self.authority == nil || !self.authority.VaultCreator(self.sidecarId, memberId) {
			return Id{}, ErrRecordVaultNotCreator
		}
		journal = &recordVaultJournal{RepoId: NewEvsRepoId(), MemberId: memberId, Step: recordVaultStepFiling}
		if err := self.writeJournal(journal); err != nil {
			return Id{}, err
		}
	}
	for {
		switch journal.Step {
		case recordVaultStepFiling:
			if !self.filed(journal.RepoId) {
				if self.client.args.FileStatement == nil {
					return Id{}, ErrEvsNoStatementPoster
				}
				create := &protocol.RepoCreate{RepoId: journal.RepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT}
				if err := self.client.args.FileStatement(ctx, bridge.SignedType_SIGNED_REPO_CREATE, create); err != nil {
					return Id{}, fmt.Errorf("record vault: RepoCreate: %w", err)
				}
			}
			journal.Step = recordVaultStepFiled
		case recordVaultStepFiled:
			memberId := journal.MemberId
			if _, err := self.client.CreateRepo(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: &memberId, ResumeRepoId: &journal.RepoId}); err != nil {
				return Id{}, err
			}
			journal.Step = recordVaultStepCreated
		case recordVaultStepCreated:
			vaultId, err := self.awaitVault(ctx, journal.MemberId)
			if err != nil {
				return Id{}, err
			}
			if vaultId == journal.RepoId {
				return vaultId, self.writeJournal(nil)
			}
			journal.Step = recordVaultStepDeleting
		case recordVaultStepDeleting:
			// an earlier vault won: this one was never written, and goes now
			if err := self.client.Repo(journal.RepoId).Delete(ctx, true); err != nil {
				return Id{}, fmt.Errorf("record vault: the losing vault's RepoDelete: %w", err)
			}
			if err := self.writeJournal(nil); err != nil {
				return Id{}, err
			}
			vaultId, ok := self.auth().Vault(journal.MemberId)
			if !ok {
				return Id{}, ErrRecordVaultWait
			}
			return vaultId, nil
		default:
			return Id{}, fmt.Errorf("%w: the record vault journal's step %q", ErrSidecarStoreFailed, journal.Step)
		}
		if err := self.writeJournal(journal); err != nil {
			return Id{}, err
		}
	}
}

// Whether the client's verified state holds repoId's RepoCreate.
func (self *RecordVault) filed(repoId Id) bool {
	if self.client.args.Config == nil {
		return false
	}
	state := self.client.args.Config()
	return state != nil && state.Repo(repoId) != nil
}

// The vault the rule names once a state sees one: see the file header's race row.
func (self *RecordVault) awaitVault(ctx context.Context, memberId Id) (Id, error) {
	for waits := 0; ; waits += 1 {
		if vaultId, ok := self.auth().Vault(memberId); ok {
			return vaultId, nil
		}
		if self.settings.StateWaitCount <= waits {
			return Id{}, ErrRecordVaultWait
		}
		select {
		case <-ctx.Done():
			return Id{}, ctx.Err()
		case <-self.clock.After(self.settings.StateWait):
		}
	}
}
