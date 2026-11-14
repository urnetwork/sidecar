//go:build !ios_extension

// The push sender (§11.8's client steps and outcomes; D-EVS-5, D-EVS-20, D-EVS-22, D-EVS-23; EVS1-M2-26): a sealed
// write's push built under one push id, sent, and retried or rebuilt by what evs answers.
//
//	build    choose push_id P; render each entry version under P (evs_plan.go's planned paths, sealed); the new
//	         segments with the upload day their receipts give; sealed metadata under manifest_g with the §10 group
//	         head the writer pins, when the client knows one, and on a git-mode ref the plan's update (a rekey's REKEY
//	         shape, DESIGN-DETAILS 8.2.10), which a git-mode plan with none refuses; the statement on the head the plan read (v = b, C_b), its
//	         time fresh per statement, signed only by §5's identity key, naming sidecar_id and client_id (D-EVS-5)
//	send     a one-part push posts {statement, payload, receipts} once every upload answered 200; a push over 1 MiB or
//	         1,024 entry writes goes in parts (evs_push_parts.go), git mode taking its seal lease first
//	retry    one push id names one statement, retried one attempt at a time, the same bytes, until 200, 409 or 412:
//	         a 429 and a 503, an unknown outcome among them, and no answer at all, the lb's 502 or 504 among them
//	         (QD-758), go again after retry_after_ms (TIME_AHEAD's 429 included, unchanged), so a dropped answer's
//	         retry returns the original version (FS-1)
//	rebuild  a new push id, sealed afresh from a fresh read, never a second statement under one push id: 409
//	         SEGMENT_STALE, SEGMENT_GONE, SLOT_STALE, BASE_STALE and TIME_STALE, and 412 GATE_CLOSED (EnsureWritable
//	         again, so the next seal is to the next generation)
//	retoken  412 PATH_EPOCH, final for its statement, which can never commit since the epoch only rises: the floor
//	         of every path the push named falls to its epoch (E3), the sender reads a head whose current epoch is
//	         above it, and the plan is made again there with every sealed byte kept, segments and their receipts
//	         under RetokenReceiptMaxAge, slot ids and bodies, inline records, sealed fields, chains and each base,
//	         then sent under a new push id (DESIGN-DETAILS 9.2.5). A retoken counts against PushRebuildCount with
//	         rebuilds; a head whose generation is past the sealed one is a rebuild, as the gate would refuse it. A
//	         deposit or the erasure ref stays at epoch 1, so its 412 PATH_EPOCH goes back to the caller. A push
//	         planned on no head is never retokened, and lowers no floor: it is planned again, on the head now there or
//	         in the epoch its ref starts in read again, as evs's 409 for one that meets a head has it planned again
//	         (DESIGN-DETAILS 9.2.3, PathEpochTwin-StaleFirstPush)
//	return   any other refusal goes back to the caller as an *EvsError: a file-mode 409 with paths among them
//
// A part's own 409 PARTS_MISSING at the seal posts the parts again and seals P again (evs_push_parts.go).
//
// On every leg. A push attempt is one write's, not safe for concurrent use.

package sidecar

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The codes that ask for the push to be built again under a new push id (§11.8's outcomes; EVS1-M2-26's rebuild row).
// 412 PATH_EPOCH is the retoken's (sendSealed).
var evsRebuildCodes = map[protocol.EvsRefusalCode]bool{
	protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_STALE: true,
	protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_GONE:  true,
	protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE:    true,
	protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED:   true,
	protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE:    true,
	protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE:    true,
}

// Whether err asks for a rebuild under a new push id.
func evsNeedsRebuild(err error) bool {
	evsError, ok := EvsErrorOf(err)
	return ok && evsRebuildCodes[evsError.Code]
}

// A new random push id: 16 bytes that name one statement only (§11.8).
func NewEvsPushId() Id {
	pushId := Id{}
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(pushId[:])
	return pushId
}

// One push id's push, built and ready to send: its statement and payload or parts, and the receipts each request
// carries.
type evsPushAttempt struct {
	pushId Id
	built  *EvsBuiltPush
	// a one-part push's receipts: every new segment's
	receipts []*protocol.EvsUploadReceipt
	// a push in parts: each part's, for the segments its entry versions name
	partReceipts [][]*protocol.EvsUploadReceipt
	refMode      protocol.EvsRefMode
	baseVersion  uint64
	refId        Id
	// the token scope it posts under
	scope string
	// a git-mode push in parts: when it last took its seal lease, which renewLease takes again
	leaseLock sync.Mutex
	leaseAt   time.Time
}

// Builds sealed's push under pushId, its segments' receipts in hand.
func (self *EvsRepo) buildPush(ctx context.Context, sealed *EvsSealedWrite, pushId Id) (*evsPushAttempt, error) {
	plan := sealed.Plan
	repoKey := sealed.RepoKey
	state, err := self.client.verifier.config()
	if err != nil {
		return nil, err
	}
	authPin := state.Pin()
	if headAuth := plan.Head.GetAuth(); headAuth != nil && authPin.GetVersion() < headAuth.GetVersion() {
		return nil, fmt.Errorf("%w: this device's authorization state is behind the ref's head", ErrEvsNoConfig)
	}
	identity := self.client.args.Identity()
	timeMs := self.client.clock.Now().UnixMilli()
	pushPlan := &EvsPushPlan{
		RepoId: plan.RepoId, RefId: plan.RefId, RefKind: plan.RefKind, RefMode: plan.RefMode, OwnerSidecarId: plan.OwnerSidecarId,
		PushId: pushId, BaseVersion: plan.BaseVersion, BaseChain: plan.BaseChain, Generation: repoKey.Generation(),
		GroupId: repoKey.GroupId(), GenerationCommitment: repoKey.Commitment(), PathEpoch: plan.PathEpoch, Auth: authPin,
		SignerSidecarId: identity.SidecarId, ClientId: identity.ClientId, TimeMs: timeMs, SourcesStand: 0 < len(plan.Sources),
		Flags: plan.Flags, Erased: plan.Erased,
	}
	manifest, err := NewEvsManifestKey(repoKey)
	if err != nil {
		return nil, err
	}
	// the run's tainted bit rides a format-2 push's provenance (§16.6, EVS2-M10-15); format 1 ignores it
	metadata := &protocol.EvsSealedMetadata{Provenance: &protocol.EvsProvenance{Tainted: plan.Tainted}}
	// an ERASE's and a CLOSURE's note, sealed with the push's metadata (§11.12's push and rekey rows; QD-682)
	metadata.ErasureNote = plan.erasureNote
	if plan.RefMode == protocol.EvsRefMode_EVS_REF_GIT {
		// a git-mode push states its update (DESIGN-DETAILS 8.2.3): what readers check its changes against
		if plan.gitUpdate == nil {
			return nil, fmt.Errorf("%w: a git-mode push with no update", ErrEvsGitRef)
		}
		metadata.Git = plan.gitUpdate
		if extras := plan.gitExtras; extras != nil {
			metadata.Commits, metadata.SignedImport = extras.commits, extras.signedImport
			if extras.creating {
				// payload sections 15 and 16, which evs copies into the head, and their sealed copies (8.2.2)
				metadata.RefName, metadata.Base = extras.refName, extras.base
				if pushPlan.RefName, err = EvsSealRefName(manifest, plan.RefId, extras.refName); err != nil {
					return nil, err
				}
				pushPlan.Base = extras.base
			}
		}
		pushPlan.ReuseList = plan.reuse
	}
	if self.client.args.GroupHead != nil {
		if groupHead, ok := self.client.args.GroupHead(repoKey.GroupId()); ok {
			metadata.Group = groupHead
		}
	}
	if pushPlan.SealedMetadata, err = EvsSealMetadata(manifest, metadata); err != nil {
		return nil, err
	}
	segmentIdReceipts := map[string]*protocol.EvsUploadReceipt{}
	attempt := &evsPushAttempt{pushId: pushId, refMode: plan.RefMode, baseVersion: plan.BaseVersion, refId: plan.RefId, scope: plan.scope}
	if attempt.scope == "" {
		attempt.scope = evsScopeWrite
	}
	for _, segment := range sealed.Segments {
		if segment.Receipt == nil {
			return nil, fmt.Errorf("%w: a segment posted before its upload answered", ErrEvsWriteInvalid)
		}
		pushPlan.NewObjects = append(pushPlan.NewObjects, &EvsNewObject{
			Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: segment.Id[:], PaddedSize: segment.PaddedSize,
			UploadDay: evsUploadDay(segment.Receipt),
		})
		attempt.receipts = append(attempt.receipts, segment.Receipt)
		segmentIdReceipts[string(segment.Id[:])] = segment.Receipt
	}
	// a slot-keyed write's new slots, the same ones on every attempt of one seal
	for _, slot := range sealed.Slots {
		pushPlan.NewObjects = append(pushPlan.NewObjects, &EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, Id: slot.Id.Bytes()})
		pushPlan.SlotBodies = append(pushPlan.SlotBodies, slot.Body)
	}
	for _, path := range sealed.Paths {
		change, err := path.change(pushId, plan.BaseVersion, timeMs)
		if err != nil {
			return nil, err
		}
		pushPlan.Changes = append(pushPlan.Changes, change)
	}
	built, err := NewEvsStatementBuilder(self.client.args.Sign).Build(pushPlan)
	if err != nil {
		return nil, err
	}
	attempt.built = built
	partNamed := map[string]bool{}
	for _, partBytes := range built.Parts {
		checked, err := EvsCheckPart(built.Statement, partBytes)
		if err != nil {
			return nil, err
		}
		receipts := []*protocol.EvsUploadReceipt{}
		named := map[string]bool{}
		for _, change := range checked.Changes {
			for _, segmentId := range evsEntrySegmentIds(change.EntryVersion) {
				if receipt := segmentIdReceipts[segmentId]; receipt != nil && !named[segmentId] {
					named[segmentId] = true
					partNamed[segmentId] = true
					receipts = append(receipts, receipt)
				}
			}
		}
		attempt.partReceipts = append(attempt.partReceipts, receipts)
	}
	if 0 < len(attempt.partReceipts) {
		// a segment no entry names, a git-mode push's history segment, rides the first part's receipts, which the seal
		// joins with every part's for 5h's new-objects check
		for _, segment := range sealed.Segments {
			if !partNamed[string(segment.Id[:])] {
				attempt.partReceipts[0] = append(attempt.partReceipts[0], segment.Receipt)
			}
		}
	}
	return attempt, nil
}

// The segment ids an entry version's chain names.
func evsEntrySegmentIds(entryBytes []byte) []string {
	if entryBytes == nil {
		return nil
	}
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		return nil
	}
	segmentIds := []string{}
	for _, locator := range entry.GetChain() {
		if protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT {
			segmentIds = append(segmentIds, string(locator.GetId()))
		}
	}
	return segmentIds
}

// The change a sealed path makes under pushId: its entry version rendered for this push, or a removal.
func (self *EvsSealedPath) change(pushId Id, baseVersion uint64, timeMs int64) (*EvsPlannedChange, error) {
	planned := self.Planned
	change := &EvsPlannedChange{TokenPath: planned.TokenPath, BaseEntryVersion: planned.BaseEntryVersion, SourcePaths: planned.SourcePaths}
	if planned.Remove {
		return change, nil
	}
	entry := &protocol.EvsEntryVersion{
		Version: planned.Version, PushId: pushId.Bytes(), BaseVersion: baseVersion, PrevPushId: planned.PrevPushId,
		PrevCommitVersion: planned.PrevCommitVersion, TimeMs: timeMs, Kind: uint32(planned.Kind),
	}
	switch planned.Kind {
	case protocol.EvsEntryKind_EVS_ENTRY_FILE:
		entry.PaddedSize = self.PaddedSize
		entry.SealedFields = self.SealedFields
		entry.Chain = self.Chain
		for _, slotId := range self.SlotIds {
			entry.SlotIds = append(entry.SlotIds, slotId.Bytes())
		}
	case protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY:
		entry.Names = &protocol.EvsNameTable{Names: planned.Names, RemovedTokens: planned.RemovedTokens}
	default:
		return nil, fmt.Errorf("%w: entry kind %d", ErrEvsWriteInvalid, planned.Kind)
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		return nil, err
	}
	change.EntryVersion = entryBytes
	return change, nil
}

// Sends attempt until evs commits it, answering its version, or answers what ends it: an *EvsError a rebuild or the
// caller takes.
func (self *EvsRepo) sendPush(ctx context.Context, attempt *evsPushAttempt) (*protocol.EvsPushReply, error) {
	if 0 < len(attempt.built.Parts) {
		return self.sendParts(ctx, attempt)
	}
	request := &protocol.EvsPushRequest{
		Statement: attempt.built.Statement.Bytes, Payload: attempt.built.Payload, Receipts: attempt.receipts,
	}
	return self.postPushAs(ctx, attempt.pushId, request, attempt.scope)
}

// POST .../push, the same bytes until it answers anything but a 429, a 503 or nothing.
func (self *EvsRepo) postPush(ctx context.Context, pushId Id, request *protocol.EvsPushRequest) (*protocol.EvsPushReply, error) {
	return self.postPushAs(ctx, pushId, request, evsScopeWrite)
}

// postPush under the token scope scope: a deposit's deposit, or rw.
func (self *EvsRepo) postPushAs(ctx context.Context, pushId Id, request *protocol.EvsPushRequest, scope string) (*protocol.EvsPushReply, error) {
	call := &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/push",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/push",
		repoId: self.repoId,
		role:   scope,
		body:   request,
	}
	reply := &protocol.EvsPushReply{}
	err := self.client.retryRefusingNothing(ctx, func() error {
		reply = &protocol.EvsPushReply{}
		return self.client.http.callMessage(ctx, call, reply)
	})
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// Whether err is evs's refusal of a creation's version or base, which a fresh read of the removal standing there
// may answer (§11.7's versions row).
func evsCreationConflict(err error) bool {
	evsError, ok := EvsErrorOf(err)
	return ok && evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT
}

// Sends sealed under a new push id until evs commits it, answering that push id and its version: uploads, builds and
// posts it (above), and on 412 PATH_EPOCH re-tokenizes it and sends it again (the file header's retoken row).
// rebuilds counts the write's rebuilds and retokens against PushRebuildCount.
func (self *EvsRepo) sendSealed(ctx context.Context, sealed *EvsSealedWrite, rebuilds *int) (Id, *protocol.EvsPushReply, error) {
	return self.sendSealedNoting(ctx, sealed, rebuilds, nil, nil)
}

// sendSealed, noting each push id before anything is sent under it, nil for none: what a git publish judges a moved
// head by, since an attempt it sent may be in the history (DESIGN-DETAILS 8.2.5's 409 row).
func (self *EvsRepo) sendSealedNoting(ctx context.Context, sealed *EvsSealedWrite, rebuilds *int, note func(pushId Id), beforePost func(attempt *evsPushAttempt) error) (Id, *protocol.EvsPushReply, error) {
	for {
		pushId := NewEvsPushId()
		if note != nil {
			note(pushId)
		}
		if err := self.uploadSegments(ctx, sealed, pushId); err != nil {
			return pushId, nil, err
		}
		attempt, err := self.buildPush(ctx, sealed, pushId)
		if err != nil {
			return pushId, nil, err
		}
		if beforePost != nil {
			// the local tier journals the attempt here, durably, before its statement's first POST (8.2.8)
			if err := beforePost(attempt); err != nil {
				return pushId, nil, err
			}
		}
		reply, err := self.sendPush(ctx, attempt)
		if err == nil {
			self.client.epochs.noteCommitted(self.repoId, sealed.Plan.RefId, reply.GetVersion())
		}
		if !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH) {
			return pushId, reply, err
		}
		if evsEpochExempt(sealed.Plan.RefKind) || self.client.settings.PushRebuildCount <= *rebuilds {
			return pushId, nil, err
		}
		if sealed.Plan.firstPush {
			// planned on no head: planned again, on the head now there or under the epoch read again, and never
			// retokened, which would name the epoch a cut-over reached over a file another creator made in a lower one
			// (DESIGN-DETAILS 9.2.3, PathEpochTwin-StaleFirstPush)
			return pushId, nil, fmt.Errorf("%w: %w", errEvsPlanEpochMoved, err)
		}
		*rebuilds += 1
		if err := self.retoken(ctx, sealed); err != nil {
			return pushId, nil, err
		}
	}
}

// A test's hook on a retoken's floors once the refusal lowered them, nil outside tests: what DESIGN-DETAILS 9.6's
// 9.1 C test forgets the floors with, to show the creation that then lands.
var evsRetokenFloorsHook func(plan *EvsWritePlan)

// The retoken row of the file header, on a push sealed refused 412 PATH_EPOCH.
func (self *EvsRepo) retoken(ctx context.Context, sealed *EvsSealedWrite) error {
	plan := sealed.Plan
	plan.lowerFloors(plan.PathEpoch)
	if evsRetokenFloorsHook != nil {
		evsRetokenFloorsHook(plan)
	}
	head, err := self.readHeadPast(ctx, plan.RefId, plan.PathEpoch)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(plan.Paths, (*EvsPlannedPath).creates) {
		// a creation on a blocking ref whose pressure is immediate again waits, as the planner's does
		quiet, err := self.quiet(ctx, &evsRefEpoch{refId: plan.RefId, epoch: head.Head.GetPathEpoch(), version: head.Version,
			generation: head.Head.GetGeneration(), refKind: plan.RefKind})
		if err != nil {
			return err
		}
		if !quiet {
			return ErrEvsPathEpochDue
		}
	}
	if err := plan.Retoken(ctx, head); err != nil {
		return err
	}
	// evs adopts an upload under 24 h old, so a receipt past RetokenReceiptMaxAge is taken again by uploading the same
	// segment again
	now := self.client.clock.Now()
	for _, segment := range sealed.Segments {
		if segment.Receipt != nil && self.client.settings.RetokenReceiptMaxAge <= now.Sub(time.UnixMilli(segment.Receipt.GetUploadMs())) {
			segment.Receipt = nil
		}
	}
	return nil
}
