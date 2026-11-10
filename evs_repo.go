// EvsRepo (§11.20): one repo's calls, as EvsClient.Repo hands them out. The methods §11.20 names are all here, so
// §15, §16, §18 and TEAM's config tasks compile against them; each one this draft does not build yet answers
// ErrEvsNotBuilt naming the task that builds it, and does nothing.
//
//	CreateRepo                      EvsClient's (evs_client.go)
//	ReadHead, List, History         EVS1-M2-24 (evs_read.go, evs_list.go, evs_history.go)
//	Write                           EVS1-M2-25, EVS1-M2-26 (evs_plan.go, evs_write.go)
//	Deposit, Consume                EVS1-M2-29
//	Subscribe                       EVS1-M2-27 (evs_subscribe.go, evs_hint.go)
//	Erasures                        EVS1-M2-30
//	Import                          EVS1-M2-34
//	Export                          EVS1-M2-32 (evs_export.go)
//	Mount                           EVS1-M2-33 (evs_local_mount.go), on desktop legs only
//	Delete, Restore, Shred          here
//
// Paths are this device's own: raw names joined by /, never normalized, so NFC and NFD are two paths (§11.6). They
// are tokenized before anything leaves the device and never logged (I-13).
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The ref a read names when it names none: main, whose id any reader derives (§11.6).
var EvsMainRefName = []byte("main")

// One repo's calls.
type EvsRepo struct {
	client *EvsClient
	repoId Id
}

// The repo's id.
func (self *EvsRepo) RepoId() Id {
	return self.repoId
}

// The repo's client.
func (self *EvsRepo) Client() *EvsClient {
	return self.client
}

// What a read names.
type EvsReadArgs struct {
	// The ref's name bytes (plan-EVS1-ref-name-bytes): nil reads main. Head mode reads no other (§18.5).
	RefName []byte
	// The ref's id, for a ref whose name is not a named ref's: a deposit or the erasure ref. Overrides RefName.
	RefId *Id
	// The path: raw names joined by /. Empty is the root, which only List reads.
	Path string
	// 0 the newest committed version, else that older version of the path.
	Version uint64
	// Reads the cluster's head, not evs's cache (§11.9's fresh).
	Fresh bool
}

// One file version as a read shows it, verified against its signed statement (§11.9).
type EvsFileInfo struct {
	RefId Id
	Path  string
	// The path's version, and the ref version its push committed at.
	Version       uint64
	CommitVersion uint64
	PushId        Id
	// The push's signer, its client then, and its time_ms.
	SignerSidecarId Id
	ClientId        Id
	Time            time.Time
	Kind            protocol.EvsEntryKind
	// git's mode, the blob's oid and its plaintext size, from the entry's sealed fields.
	Mode   uint32
	GitOid EvsGitOid
	Size   uint64
	// The ref's head the read verified and pinned.
	HeadVersion uint64
}

// A directory's children as List shows them, each name checked against its token (§11.7's name row).
type EvsListing struct {
	RefId       Id
	Path        string
	HeadVersion uint64
	Entries     []*EvsListEntry
}

// One child.
type EvsListEntry struct {
	Name []byte
	Kind protocol.EvsEntryKind
	// The source path epoch a carried row keeps its token and AAD under, else 0 (§11.6).
	CarriedEpoch uint64
}

// One path's versions, newest first, as History walks them (§11.7's history row).
type EvsHistory struct {
	RefId       Id
	Path        string
	HeadVersion uint64
	Versions    []*EvsHistoryVersion
}

// One version of a path.
type EvsHistoryVersion struct {
	Version         uint64
	CommitVersion   uint64
	PushId          Id
	SignerSidecarId Id
	ClientId        Id
	Time            time.Time
	// The removal that ended the path at this version, if it is one.
	Removed bool
	// 0 kept; format 2's settings are refused before they get here.
	Versioning uint32
	// kept (format 1's only state); collected, drop_pending and dropped are format 2's (§11.9).
	State string
}

// What Write changes (EVS1-M2-25, EVS1-M2-26).
type EvsWriteArgs struct {
	RefName []byte
	Path    string
	// The new content, Size bytes; nil with Remove.
	Content io.Reader
	Size    int64
	Mode    uint32
	Remove  bool
	// "", "on" or "off" (§18.5): format 1 writes only versioning on.
	Versioning string
	// A whole checkpoint under a fresh key even where a diff would do: KEYS-M2-26's ur evs rekey.
	ForceCheckpoint bool
}

// What a committed Write did.
type EvsWriteResult struct {
	PushId Id
	// The ref version it committed at, and the path's new version.
	Version     uint64
	PathVersion uint64
}

// What Deposit appends to this sidecar's deposit ref (§11.12's deposits row; EVS1-M2-29).
type EvsDepositArgs struct {
	Body io.Reader
	Size int64
}

// A committed deposit.
type EvsDepositResult struct {
	EntryId EvsToken
	// The deposit ref's version it committed at, from the push's EvsDepositHead.
	Version uint64
}

// What Consume deletes from a deposit ref after ingest (EVS1-M2-29).
type EvsConsumeArgs struct {
	DepositRefId Id
	EntryIds     []EvsToken
	// The highest version at or below which the ingest left nothing unconsumed (EVS-FORMAT.md's consumed_through).
	ConsumedThrough uint64
}

// A committed CONSUME.
type EvsConsumeResult struct {
	PushId  Id
	Version uint64
}

// What Import brings in (§11.11's import row; EVS1-M2-34).
type EvsImportArgs struct {
	// A git repository's directory.
	Dir     string
	RefName []byte
}

// A committed import.
type EvsImportResult struct {
	PushIds []Id
}

// What Export writes (§11.12's export row).
type EvsExportArgs struct {
	// The new bare repository's directory, which must not hold one already.
	Dir string
	// The refs' name bytes; nil exports every ref but ur/index and ur/lfs.
	RefNames [][]byte
}

// What Export wrote: each ref's git name and tip.
type EvsExportResult struct {
	Refs []*EvsExportedRef
}

// One exported ref.
type EvsExportedRef struct {
	GitRef string
	Tip    EvsGitOid
	// The evs versions it rebuilt.
	Versions uint64
}

// What Mount serves (§11.11; cli/UI.md's ur mount add).
type EvsMountArgs struct {
	// The working directory the mount names: its bare repository sits in the daemon's state, not here.
	Dir string
	// The agent label committer.name carries; empty: the sidecar's id.
	AgentLabel string
}

// A mount's place on this device.
type EvsMountInfo struct {
	RepoId Id
	Dir    string
	// The plaintext bare repository the local git server runs on.
	BareDir string
}

// Deposits one entry to this sidecar's deposit ref. EVS1-M2-29 builds it.
func (self *EvsRepo) Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error) {
	return nil, fmt.Errorf("%w: Deposit is EVS1-M2-29's", ErrEvsNotBuilt)
}

// Commits a CONSUME of ingested deposits. EVS1-M2-29 builds it.
func (self *EvsRepo) Consume(ctx context.Context, args *EvsConsumeArgs) (*EvsConsumeResult, error) {
	return nil, fmt.Errorf("%w: Consume is EVS1-M2-29's", ErrEvsNotBuilt)
}

// The repo's erasures as this device sees them (§18.5). EVS1-M2-30 builds it.
func (self *EvsRepo) Erasures(ctx context.Context) ([]*SidecarErasure, error) {
	return nil, fmt.Errorf("%w: Erasures is EVS1-M2-30's", ErrEvsNotBuilt)
}

// Imports a git repository's history under a signed EvsImport. EVS1-M2-34 builds it.
func (self *EvsRepo) Import(ctx context.Context, args *EvsImportArgs) (*EvsImportResult, error) {
	return nil, fmt.Errorf("%w: Import is EVS1-M2-34's", ErrEvsNotBuilt)
}

// The newest re-pin of a ref past §11.9's catch-up budget, zero when nothing was skipped
// (g0-recheck-0-head-reader-read-paths#3).
func (self *EvsRepo) VerifiedSince(refId Id) time.Time {
	pin, ok, err := self.client.pins.Pin(self.repoId, refId)
	if err != nil || !ok {
		return time.Time{}
	}
	return pin.VerifiedSince
}

// §11.12's delete: files RepoDelete{repo_id, a new deletion_id, now}, then DELETE /evs/v1/repos/<id>, ?now=1 with
// now. Members get a hint and stop syncing; without now, Restore may bring it back within 7 days.
func (self *EvsRepo) Delete(ctx context.Context, now bool) error {
	if self.client.args.FileStatement == nil {
		return ErrEvsNoStatementPoster
	}
	deletion := &protocol.RepoDelete{RepoId: self.repoId.Bytes(), DeletionId: NewEvsRepoId().Bytes(), Now: now}
	if err := self.client.args.FileStatement(ctx, bridge.SignedType_SIGNED_REPO_DELETE, deletion); err != nil {
		return fmt.Errorf("evs: RepoDelete: %w", err)
	}
	path := "/evs/v1/repos/" + evsUrlId(self.repoId)
	if now {
		path += "?now=1"
	}
	return self.callLifecycle(ctx, &evsCall{
		route:  "DELETE /evs/v1/repos/{repo_id}",
		method: http.MethodDelete,
		path:   path,
		repoId: self.repoId,
		role:   evsScopeAdmin,
	})
}

// §11.12's restore: files RepoRestore of the deletion the newest verified config state holds for the repo, then
// POST /evs/v1/repos/<id>/restore. A repo past deleted answers 409 SHREDDING.
func (self *EvsRepo) Restore(ctx context.Context) error {
	if self.client.args.FileStatement == nil {
		return ErrEvsNoStatementPoster
	}
	if self.client.args.Config == nil {
		return ErrEvsNoConfig
	}
	state := self.client.args.Config()
	if state == nil {
		return ErrEvsNoConfig
	}
	deletion := state.Repo(self.repoId).GetDeletion()
	if len(deletion.GetDeletionId()) == 0 || deletion.GetNow() || deletion.GetRestoredAt() != 0 {
		return fmt.Errorf("%w: the repo has no restorable deletion", errInvalidSettings)
	}
	restore := &protocol.RepoRestore{RepoId: self.repoId.Bytes(), DeletionId: deletion.GetDeletionId()}
	if err := self.client.args.FileStatement(ctx, bridge.SignedType_SIGNED_REPO_RESTORE, restore); err != nil {
		return fmt.Errorf("evs: RepoRestore: %w", err)
	}
	return self.callLifecycle(ctx, &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/restore",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/restore",
		repoId: self.repoId,
		role:   evsScopeAdmin,
	})
}

// §11.12's shred: Delete with now, never restorable, then the repo's keys, MLS state and pins here go (§10.8:
// members drop its keys).
func (self *EvsRepo) Shred(ctx context.Context) error {
	if err := self.Delete(ctx, true); err != nil {
		return err
	}
	if err := self.client.args.Gkm.ForgetRepo(ctx, self.repoId); err != nil {
		return fmt.Errorf("evs: the repo's keys: %w", err)
	}
	return self.client.pins.Forget(self.repoId)
}

// One lifecycle route, which answers 200 with no body. STATEMENT_MISSING and GROUP_NOT_READY go again after
// ReadRetryWait, ReadRetryCount times, since the projection reaches evs within §8.9's 5 s and KF1's group within its
// own run; a 429 or 503 that refuses nothing goes again after its retry_after_ms.
func (self *EvsRepo) callLifecycle(ctx context.Context, call *evsCall) error {
	call.retry = true
	var err error
	for attempt := 0; attempt <= self.client.settings.ReadRetryCount; attempt += 1 {
		err = self.client.http.callMessage(ctx, call, nil)
		if !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING) &&
			!IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_GROUP_NOT_READY) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-self.client.clock.After(self.client.settings.ReadRetryWait):
		}
	}
	return err
}
