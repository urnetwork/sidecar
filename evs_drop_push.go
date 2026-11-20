//go:build !ios_extension

// Writing a drop (§11.7's action, boundary and cli rows, §11.20, §18.5's DropHistory; R-EVS-26, R-CTX-39, D-EVS-62,
// D-EVS-63, D-MCP-32, D-SDK-29, I-EVS-15, FI-27, FS-89, FS-95; DESIGN-DETAILS 10.2.4, 10.2.5 and 10.7's note;
// EVS2-M10-21): the DROP push, built from a completed dry run and the person's confirmation.
//
//	consent    DropHistory names a dry run DropHistoryPreview completed on this client, every list matching and every
//	           lineage linked (evs_drop_preview.go), confirmPath equal to the previewed path (EvsDropConfirmText), and
//	           with now the word now typed as well (EvsDropConfirmNow): the engine refuses otherwise, so no caller
//	           skips them. No MCP tool reaches it (D-MCP-32; §16.6's refused list): only the control path and the SDK
//	           call it. A dry run names one drop, and once its pushes commit it is forgotten
//	signer     a repo admin; in an owner-bound repo a consented device of its owner (D-ACL-25); for a drop no lock
//	           standing (§8.8). Checked here on the newest verified state before anything is sent, as evs's 5c and
//	           every reader check it again at the push's own auth pin
//	push       one DROP push per batch of the dry run, each cut at lineage boundaries within one DROP's bounds
//	           (evs_drop_preview.go): flag 256, drop_sha256 over its body, the body {a fresh drop_id, action 1, the
//	           batch's lineages with the dry run's map_parts, not_before_ms time_ms + 7 days or time_ms with now,
//	           preview_id}, then its lists as section 10, which the statement builder spreads over parts past 1 MiB
//	           (10.2.5). A written lineage's change writes through_version, the kept head (evs_drop_kept.go); a removed
//	           one writes nothing; a batch of removed lineages alone, like a cancel (evs_drop_cancel.go), is a push of
//	           no change
//	retry      a statement is retried as the same bytes, its drop_id with it; a rebuild under a new push id draws a
//	           new drop_id, time and slot ids. A path that moved since the dry run (a write, a removal, a new path
//	           epoch) fails the push, the planner or evs's 5g refusing it, and the command starts again with a new dry
//	           run (ErrEvsDropStale). A batch that committed is not sent again when the command is retried
//	index      EvsDropIndexHook lets §11.14's DROP rewrites ride the push: a 409 INDEX_EPOCH, or a 409 naming only the
//	           rewrites' own paths (another push wrote an index file they replace), rebuilds and signs again once under
//	           the same confirmation, then goes without them, left to the backfill (§11.14's drop and conflict rows).
//	           evs takes them beside the written lineages, each a rewrite of a standing index file within Padmé of the
//	           length it replaces, naming the head's index_epoch (QD-1078; evsservice/check_drop.go), but an evs from
//	           before that answer takes no change a written lineage does not name, so a push whose rewrites evs
//	           refuses 409 DROP_BOUNDARY goes again without them too; no hook is set until SEARCH's composition sets one
//	quota      a DROP carrying index rewrites that evs refuses for an upload, with a QuotaRefusal at the storage limit
//	           or while spent (QD-1088) or with 507 CLUSTER_FULL on a metadata cluster at §19.9's cohort limit, which
//	           takes only what the storage limit accepts (D-OPS-22; QD-1099), at the upload or at the push, goes again
//	           once without them, left to the backfill, whose rewrite waits there as builds do, since a DROP frees
//	           storage and its index must not block it (§11.14's drop and limit rows; owner decision 620). A kept head
//	           needing an upload is refused again then, and that refusal goes back to the person as it is, a 507's
//	           wait with it
//
// On every leg but ios_extension. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A drop the person did not confirm: the typed path is not the previewed one, or now came without the word now
	// typed, or the word without now.
	ErrEvsDropConfirm = errors.New("evs: a drop the person did not confirm")
	// A drop that names no dry run this client completed with every list matching.
	ErrEvsDropPreviewMissing = errors.New("evs: a drop names no completed dry run")
	// A path the drop covers moved since its dry run, or its ref's path epoch did: nothing was dropped by this push,
	// and the command starts again with a new dry run.
	ErrEvsDropStale = errors.New("evs: a path moved since the drop's dry run: run the drop again")
	// This device may not sign the DROP: not a repo admin, an owner-bound repo's other device, a locked repo for a
	// drop, or a repo kind that takes none (§11.7's refused row; D-ACL-25).
	ErrEvsDropRefused = errors.New("evs: this device may not sign the drop")
)

// The word a drop with now needs typed (§11.7's cli row).
const EvsDropConfirmNow = "now"

// What DropHistory is asked.
type EvsDropHistoryArgs struct {
	// The dry run the drop is built from: its preview id as DropHistoryPreview answered it.
	PreviewId []byte
	// The name the person typed, which must be the previewed path (EvsDropConfirmText).
	ConfirmPath string
	// Skips the 7-day window: not_before_ms is time_ms. ConfirmNow must then be EvsDropConfirmNow as typed, and must
	// be empty without it.
	Now        bool
	ConfirmNow string
}

// One committed DROP push of a drop.
type EvsDropPushResult struct {
	PushId Id
	// The ref version it committed at.
	Version uint64
	// The drop its body names, and its window's end.
	DropId    Id
	NotBefore time.Time
	PreviewId []byte
	// The paths of its lineages, as this device names them. Never logged (I-13).
	Paths []string
	// Whether §11.14's index rewrites rode the push; false leaves them to the backfill.
	IndexRewritten bool
}

// What a committed drop did: one push per batch of its dry run.
type EvsDropHistoryResult struct {
	Pushes []*EvsDropPushResult
}

// The text a drop's confirmation must equal: the paths the dry run was asked for, as the person named them, joined
// by a space; one path for a drop of one.
func EvsDropConfirmText(preview *EvsDropPreview) string {
	return strings.Join(preview.NamedPaths, " ")
}

// What §11.14's DROP rewrites are given: the drop's lineages, on the ref, and whether this is the rebuild a 409
// INDEX_EPOCH asked for, which reads the index's head again.
type EvsDropIndexArgs struct {
	RefName  []byte
	Lineages []*EvsDropLineage
	Rebuild  bool
}

// §11.14's rewrites of a DROP push: each index file holding a listed version written again without it, every write
// the index's reserved writer's (EvsWriteOptions.Reserved, EvsReservedIndex), and the head's index_epoch they name.
type EvsDropIndexRewrites struct {
	Writes     []*EvsPathWrite
	IndexEpoch uint64
}

// The seam §11.14's DROP rewrites come through (SEARCH's): called before each DROP push with a written or removed
// lineage, it answers the rewrites to plan in the same push, nil for none.
type EvsDropIndexHook func(ctx context.Context, repo *EvsRepo, args *EvsDropIndexArgs) (*EvsDropIndexRewrites, error)

// A DROP refused for its index rewrites alone: another push wrote an index file one of them replaces, while every
// lineage stands as its dry run found it, so the rewrites are built again under the same confirmation.
var errEvsDropRewritesMoved = errors.New("evs: an index file a DROP rewrites moved under it")

// Whether err is a conflict naming written paths, each one a path rewrites write.
func evsDropRewritesMoved(err error, rewrites *EvsDropIndexRewrites) bool {
	var conflict *EvsPathConflictError
	if !errors.As(err, &conflict) || len(conflict.Paths) == 0 {
		return false
	}
	rewritten := map[string]bool{}
	for _, write := range rewrites.Writes {
		rewritten[write.Path] = true
	}
	for _, path := range conflict.Paths {
		if !rewritten[path] {
			return false
		}
	}
	return true
}

// The drop engine's state on a client.
type evsDropClient struct {
	stateLock sync.Mutex
	// completed dry runs, oldest first
	previews  []*EvsDropPreview
	indexHook EvsDropIndexHook
	// the checked DROP bodies this device keeps (evs_drop_state.go), and the history_drop state raised last for each
	// drop (evs_drop_verify.go)
	bodies *evsDropBodies
	raised map[string]SidecarDropState
	// the Sidecar's ApplyExecutedDrop, which a composition sets (evs_drop_apply.go)
	applier func(ctx context.Context, drop *SidecarExecutedDrop) error
}

// The client's drop state, made on first use.
func (self *EvsClient) dropClient() *evsDropClient {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if drops, ok := self.drops.(*evsDropClient); ok {
		return drops
	}
	drops := &evsDropClient{}
	self.drops = drops
	return drops
}

// Sets the DROP index hook, nil for none (EvsDropIndexHook).
func (self *EvsClient) SetDropIndexHook(hook EvsDropIndexHook) {
	drops := self.dropClient()
	drops.stateLock.Lock()
	defer drops.stateLock.Unlock()
	drops.indexHook = hook
}

// Keeps a completed dry run for DropHistory to name, at most DropPreviewKeepCount, the oldest out first.
func (self *EvsClient) keepDropPreview(preview *EvsDropPreview) {
	drops := self.dropClient()
	drops.stateLock.Lock()
	defer drops.stateLock.Unlock()
	drops.previews = append(drops.previews, preview)
	if keep := max(1, self.settings.DropPreviewKeepCount); keep < len(drops.previews) {
		drops.previews = slices.Delete(drops.previews, 0, len(drops.previews)-keep)
	}
}

// The completed dry run of repoId whose first batch's preview id is previewId, nil for none.
func (self *EvsClient) dropPreview(repoId Id, previewId []byte) *EvsDropPreview {
	drops := self.dropClient()
	drops.stateLock.Lock()
	defer drops.stateLock.Unlock()
	for _, preview := range drops.previews {
		if preview.repoId == repoId && len(previewId) != 0 && bytes.Equal(preview.PreviewId, previewId) {
			return preview
		}
	}
	return nil
}

// Forgets a dry run whose drop committed.
func (self *EvsClient) forgetDropPreview(preview *EvsDropPreview) {
	drops := self.dropClient()
	drops.stateLock.Lock()
	defer drops.stateLock.Unlock()
	drops.previews = slices.DeleteFunc(drops.previews, func(kept *EvsDropPreview) bool {
		return kept == preview
	})
}

// Drops the history of the dry run's paths: see the file header.
func (self *EvsRepo) DropHistory(ctx context.Context, args *EvsDropHistoryArgs) (*EvsDropHistoryResult, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no drop", ErrEvsDropConfirm)
	}
	preview := self.client.dropPreview(self.repoId, args.PreviewId)
	if preview == nil {
		return nil, ErrEvsDropPreviewMissing
	}
	if args.ConfirmPath != EvsDropConfirmText(preview) {
		return nil, fmt.Errorf("%w: the typed path is not the previewed one", ErrEvsDropConfirm)
	}
	if args.Now != (args.ConfirmNow == EvsDropConfirmNow) || (!args.Now && args.ConfirmNow != "") {
		return nil, fmt.Errorf("%w: now needs the word %s typed", ErrEvsDropConfirm, EvsDropConfirmNow)
	}
	if err := self.dropSigner(false); err != nil {
		return nil, err
	}
	result := &EvsDropHistoryResult{}
	for _, batch := range preview.Batches {
		if batch.committed != nil {
			// a batch an earlier try of this command committed
			result.Pushes = append(result.Pushes, batch.committed)
			continue
		}
		pushed, err := self.dropPush(ctx, preview.RefName, batch, args.Now)
		if err != nil {
			return result, err
		}
		batch.committed = pushed
		result.Pushes = append(result.Pushes, pushed)
	}
	self.client.forgetDropPreview(preview)
	return result, nil
}

// Whether this device may sign a DROP on the repo, on its newest verified state: a repo admin; in an owner-bound repo
// a consented device of its owner; for a drop, no lock standing. A local check only: evs and every reader judge the
// statement at its own auth pin.
func (self *EvsRepo) dropSigner(cancel bool) error {
	state, err := self.client.verifier.config()
	if err != nil {
		return err
	}
	repo := state.Repo(self.repoId)
	signerId := self.client.args.Identity().SidecarId
	switch {
	case repo == nil:
		return fmt.Errorf("%w: a repo the state does not hold", ErrEvsDropRefused)
	case repo.GetKind() == protocol.RepoKind_REPO_KIND_CONFIG || repo.GetKind() == protocol.RepoKind_REPO_KIND_MAILCFG:
		return fmt.Errorf("%w: a config or mailcfg repo takes no drop", ErrEvsDropRefused)
	case !evsRepoAdmin(state, repo, signerId):
		return fmt.Errorf("%w: not a repo admin", ErrEvsDropRefused)
	case aclRepoKindOwnerBound(repo.GetKind()) && !evsDropOwnerDevice(state, repo, signerId):
		return fmt.Errorf("%w: an owner-bound repo's drop is its owner's consented device's", ErrEvsDropRefused)
	case !cancel && repo.GetLock() == protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED:
		return fmt.Errorf("%w: the repo is locked", ErrEvsDropRefused)
	}
	return nil
}

// Whether sidecarId is a consented device of an owner-bound repo's owner, as the repo's row lists them.
func evsDropOwnerDevice(state GkmAuthView, repo *protocol.AclRepo, sidecarId Id) bool {
	consented := slices.ContainsFunc(repo.GetConsentedSidecarIds(), func(consentedId []byte) bool {
		return bytes.Equal(consentedId, sidecarId.Bytes())
	})
	row := state.SidecarRow(sidecarId)
	return consented && row != nil && bytes.Equal(row.GetMemberId(), repo.GetOwnerMemberId())
}

// One batch's DROP push: see the file header's push, retry and index rows.
func (self *EvsRepo) dropPush(ctx context.Context, refName []byte, batch *EvsDropPreviewBatch, now bool) (*EvsDropPushResult, error) {
	spec, err := newEvsDropSpec(batch.Lineages, batch.PreviewId, now)
	if err != nil {
		return nil, err
	}
	writes, closeWrites, err := self.dropKeptWrites(ctx, refName, batch.Lineages)
	if err != nil {
		return nil, err
	}
	defer closeWrites()
	drops := self.client.dropClient()
	hook := func() EvsDropIndexHook {
		drops.stateLock.Lock()
		defer drops.stateLock.Unlock()
		return drops.indexHook
	}()
	rebuilt := false
	for {
		var rewrites *EvsDropIndexRewrites
		if hook != nil {
			if rewrites, err = hook(ctx, self, &EvsDropIndexArgs{RefName: refName, Lineages: batch.Lineages, Rebuild: rebuilt}); err != nil {
				return nil, err
			}
			if rewrites != nil {
				for _, write := range rewrites.Writes {
					if !evsIsIndexWrite(write) {
						return nil, fmt.Errorf("%w: a DROP's index rewrite that is not the index's own", ErrEvsWriteInvalid)
					}
				}
			}
		}
		rewritten := rewrites != nil && 0 < len(rewrites.Writes)
		pushId, version, err := self.dropSend(ctx, refName, spec, writes, rewrites)
		// evs refusing what the push uploads, at the upload or at the push: a QuotaRefusal at the storage limit or while
		// spent, or 507 CLUSTER_FULL on a metadata cluster at its cohort limit, which refuses what the storage limit
		// refuses (QD-1088, QD-1099)
		uploadRefused := IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT) ||
			IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT) ||
			IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL)
		switch {
		case err == nil:
			body := spec.bodyOf(pushId)
			if body == nil {
				return nil, fmt.Errorf("%w: a committed DROP whose body this device did not build", ErrEvsWriteInvalid)
			}
			dropId, _ := IdFromBytes(body.GetDropId())
			result := &EvsDropPushResult{
				PushId: pushId, Version: version, DropId: dropId, NotBefore: evsTime(body.GetNotBeforeMs()),
				PreviewId: bytes.Clone(batch.PreviewId), IndexRewritten: rewritten,
			}
			for _, lineage := range batch.Lineages {
				result.Paths = append(result.Paths, lineage.Path)
			}
			return result, nil
		case rewritten && !rebuilt && (IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH) || errors.Is(err, errEvsDropRewritesMoved)):
			// rebuilt and signed again once under the same confirmation (§11.14's drop row)
			rebuilt = true
		case rewritten && (IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH) ||
			IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY) || errors.Is(err, errEvsDropRewritesMoved) || uploadRefused):
			// without its rewrites, left to the backfill: at the storage limit, while spent or on a full cluster a
			// shard's rewrite is an upload evs refuses, which must not block a DROP (owner decision 620); the refusal
			// a DROP meets again without them, its kept head's own upload, goes back as it is, by the default
			hook = nil
		default:
			return nil, err
		}
	}
}

// Sends one DROP push of spec: its kept heads and rewrites through the write path, or a push of no change.
func (self *EvsRepo) dropSend(ctx context.Context, refName []byte, spec *evsDropSpec, writes []*EvsPathWrite, rewrites *EvsDropIndexRewrites) (Id, uint64, error) {
	all := slices.Clone(writes)
	extras := &evsPushExtras{flags: uint32(protocol.EvsPushFlag_EVS_PUSH_DROP), scope: evsScopeAdmin, drop: spec}
	if rewrites != nil && 0 < len(rewrites.Writes) {
		all = append(all, rewrites.Writes...)
		extras.indexEpoch = rewrites.IndexEpoch
	}
	if len(all) == 0 {
		return self.dropChangeless(ctx, refName, spec)
	}
	result, plan, err := self.writePathsPlanned(ctx, &EvsWritePathsArgs{RefName: refName, Writes: all}, extras)
	var conflict *EvsPathConflictError
	switch {
	case err != nil && rewrites != nil && evsDropRewritesMoved(evsWrittenConflict(err, all, plan), rewrites):
		// only an index file a rewrite replaces moved: the rewrites are built again, the lineages being as they were
		return Id{}, 0, fmt.Errorf("%w: %w", errEvsDropRewritesMoved, err)
	case errors.Is(err, ErrEvsPathMoved) || errors.As(err, &conflict) || IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH):
		return Id{}, 0, fmt.Errorf("%w: %w", ErrEvsDropStale, err)
	case err != nil:
		return Id{}, 0, err
	}
	return result.PushId, result.Version, nil
}

// A DROP push of no change, a cancel's or one of removed lineages alone, on the ref's newest head: the same sender as
// any push, on a plan of no path, as a pin push of no change is (evs_push.go's PinPush).
func (self *EvsRepo) dropChangeless(ctx context.Context, refName []byte, spec *evsDropSpec) (Id, uint64, error) {
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return Id{}, 0, err
	}
	repoKind, err := self.repoKind()
	if err != nil {
		return Id{}, 0, err
	}
	rebuilds := 0
	for {
		repoKey, err := self.client.args.Gkm.EnsureWritable(ctx, self.repoId)
		if err != nil {
			return Id{}, 0, err
		}
		plan, err := func() (*EvsWritePlan, error) {
			result, err := self.read(ctx, refId, []string{""}, 0, true)
			if err != nil {
				return nil, err
			}
			defer result.objects.close()
			head := result.head.Head
			switch {
			case result.head.Version == 0 || head.GetDeleted():
				return nil, fmt.Errorf("%w: a drop on a ref with no head", ErrEvsDropRefused)
			case head.GetRefMode() != protocol.EvsRefMode_EVS_REF_FILE:
				return nil, fmt.Errorf("%w: a drop goes only to a file-mode ref", ErrEvsGitRef)
			}
			plan := &EvsWritePlan{
				RepoId: self.repoId, RefId: refId, BaseVersion: result.head.Version, BaseChain: result.head.Chain,
				Head: head, PathEpoch: evsCurrentEpoch(head.GetPathEpoch()), Sources: evsSourceEpochs(head.GetPathEpoch()),
				Generation: repoKey.Generation(), keys: result.keys, floors: map[string]uint64{},
				slotKeyed: EvsRepoKindRecordClass(repoKind), refName: refName, repoKind: repoKind,
			}
			if err := plan.setRef(head, refName, self.client.args.Identity().SidecarId, false); err != nil {
				return nil, err
			}
			plan.Flags, plan.scope, plan.drop = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP), evsScopeAdmin, spec
			return plan, nil
		}()
		if err != nil {
			return Id{}, 0, err
		}
		sealed, err := self.client.sealWrite(ctx, plan, repoKey)
		if err != nil {
			return Id{}, 0, err
		}
		sealed.scope = plan.scope
		pushId, reply, err := self.sendSealed(ctx, sealed, &rebuilds)
		sealed.Close()
		switch {
		case err == nil:
			return pushId, reply.GetVersion(), nil
		case (evsNeedsRebuild(err) || errors.Is(err, errEvsPlanEpochMoved) || errors.Is(err, errEvsRetokenSealsAgain)) &&
			rebuilds < self.client.settings.PushRebuildCount:
			rebuilds += 1
		case IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH):
			return Id{}, 0, fmt.Errorf("%w: %w", ErrEvsDropStale, err)
		default:
			return Id{}, 0, err
		}
	}
}

// A DROP push's own part, which buildPush adds to each statement it builds (evs_push.go): the body, drawn afresh for
// the statement, and the lists, the same for every statement of one batch. Safe for concurrent use.
type evsDropSpec struct {
	format *EvsFormatSettings
	// a drop's lineages in body order, with their counts and listed_sha256, and their lists joined (section 10)
	paths     []*protocol.EvsDropPath
	lists     []byte
	previewId []byte
	now       bool
	// a cancel's target: its drop id and ref version; nil for a drop
	cancelsDropId  []byte
	cancelsVersion uint64

	stateLock sync.Mutex
	// each statement's body by its push id, which the committed one's result names
	pushIdBodies map[Id]*protocol.EvsDropHistory
}

// The spec of a drop of lineages, in body order, as one DROP push carries them.
func newEvsDropSpec(lineages []*EvsDropLineage, previewId []byte, now bool) (*evsDropSpec, error) {
	if len(lineages) == 0 {
		return nil, fmt.Errorf("%w: a drop of no path", ErrEvsDropPath)
	}
	paths := make([]*protocol.EvsDropPath, 0, len(lineages))
	listed := make([][][]byte, 0, len(lineages))
	for _, lineage := range lineages {
		paths = append(paths, proto.Clone(lineage.DropPath).(*protocol.EvsDropPath))
		listed = append(listed, lineage.Listed)
	}
	lists, err := EvsBuildDropLists(paths, listed)
	if err != nil {
		return nil, err
	}
	for i, path := range paths {
		if path.GetCount() != lineages[i].DropPath.GetCount() || !bytes.Equal(path.GetListedSha256(), lineages[i].DropPath.GetListedSha256()) {
			// the lists signed are the ones the dry run compared
			return nil, fmt.Errorf("%w: a lineage's list changed since its dry run", ErrEvsDropStale)
		}
	}
	return &evsDropSpec{
		format: DefaultEvsFormatSettings(), paths: paths, lists: lists, previewId: bytes.Clone(previewId), now: now,
		pushIdBodies: map[Id]*protocol.EvsDropHistory{},
	}, nil
}

// The spec of a cancel of the drop dropId committed at version.
func newEvsDropCancelSpec(dropId Id, version uint64) *evsDropSpec {
	return &evsDropSpec{
		format: DefaultEvsFormatSettings(), cancelsDropId: dropId.Bytes(), cancelsVersion: version,
		pushIdBodies: map[Id]*protocol.EvsDropHistory{},
	}
}

// Puts the DROP into push: a fresh drop_id and the body its time sets, the lists, and flag 256. A written lineage
// whose newest entry is not in the push's path epoch is one the ref moved past: ErrEvsDropStale.
func (self *evsDropSpec) fill(push *EvsPushPlan) error {
	dropId := make([]byte, 16)
	if _, err := cryptorand.Read(dropId); err != nil {
		return err
	}
	history := &protocol.EvsDropHistory{DropId: dropId}
	if self.cancelsDropId != nil {
		history.Action = evsDropActionCancel
		history.CancelsDropId, history.CancelsVersion = bytes.Clone(self.cancelsDropId), self.cancelsVersion
	} else {
		history.Action = evsDropActionDrop
		history.NotBeforeMs = push.TimeMs + self.format.DropWindowMs()
		if self.now {
			history.NotBeforeMs = push.TimeMs
		}
		history.PreviewId = bytes.Clone(self.previewId)
		for _, path := range self.paths {
			if path.GetBoundary() == evsDropBoundaryWritten && path.GetLineage()[0].GetEpoch() != push.PathEpoch {
				return fmt.Errorf("%w: a written lineage's newest epoch %d, the ref's %d", ErrEvsDropStale, path.GetLineage()[0].GetEpoch(), push.PathEpoch)
			}
			history.Paths = append(history.Paths, proto.Clone(path).(*protocol.EvsDropPath))
		}
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(history)
	if err != nil {
		return fmt.Errorf("evs: DROP body: %w", err)
	}
	push.DropBody = body
	if self.cancelsDropId == nil {
		push.DropLists = self.lists
	}
	push.Flags |= uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pushIdBodies[push.PushId] = history
	return nil
}

// Holds a built DROP statement to §11.6's checks over its body and lists, as evs and readers will.
func (self *evsDropSpec) check(statement *EvsStatement, push *EvsPushPlan) error {
	_, err := EvsCheckDropPayload(statement.Push, push.DropBody, [][]byte{push.DropLists})
	return err
}

// The body the statement of pushId carried, nil for none.
func (self *evsDropSpec) bodyOf(pushId Id) *protocol.EvsDropHistory {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pushIdBodies[pushId]
}
