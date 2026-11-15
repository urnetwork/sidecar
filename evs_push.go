//go:build !ios_extension

// The push sender (§11.8's client steps and outcomes; D-EVS-5, D-EVS-20, D-EVS-22, D-EVS-23; EVS1-M2-26): a sealed
// write's push built under one push id, sent, and retried or rebuilt by what evs answers.
//
//	build    choose push_id P; render each entry version under P (evs_plan.go's planned paths, sealed); the new
//	         segments with the upload day their receipts give; sealed metadata under manifest_g with the §10 group
//	         head the writer pins, when the client knows one, a repair form's written_over (QD-833), and on a git-mode
//	         ref the plan's update (a rekey's REKEY shape, DESIGN-DETAILS 8.2.10), which a git-mode plan with none
//	         refuses; the statement on the head the plan read (v = b, C_b), its time fresh per statement, signed only by
//	         §5's identity key, naming sidecar_id and client_id (D-EVS-5)
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
//	follow   412 GATE_CLOSED on a push this device built to create or re-create a shared ref, planned on no head or
//	         on a deleted one (DESIGN-DETAILS 16.2.9, 8.2.5; QD-803): evs holds such a push's pin at or above the
//	         repo's newest rule set, so the device's log is behind it. The sender follows the log once through
//	         EvsClientArgs.ConfigFollow and keeps the refused statement's pin and generation for the ref. The rebuild
//	         above then builds a statement only where the installed pin, or the generation EnsureWritable returned,
//	         is above the kept ones; on the same pin and generation the build answers the kept refusal as an
//	         *EvsGateHeldError, which evsNeedsRebuild does not take, so no second statement is sent on them. One
//	         follow a refusal, never a loop, nothing in the background; each rebuild counts against PushRebuildCount.
//	         A push on a head that exists, a push to an owned ref and a deposit ask no follow. The kept refusal is
//	         its write's: a later write, or the same git update pushed again, builds its first statement afresh,
//	         since evs's gate also closes for reasons that pass with nothing changed on this device (FS-5's case)
//
// A part's own 409 PARTS_MISSING at the seal posts the parts again and seals P again (evs_push_parts.go).
//
// PinPush (EVS1-M6-05; DESIGN-DETAILS 16.2.9, 8.2.10) is a push of no change at this device's installed pin, which binds
// a ref to the rule sets at or below that pin: on a file-mode ref a statement with no change, sent through the same
// sender; on a git-mode branch the UPDATE of one tip, which only the local tier builds (evs_local_pin.go).
//
// On every leg. A push attempt is one write's, not safe for concurrent use.

package sidecar

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
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

// evs's 412 GATE_CLOSED for a push that creates or re-creates a shared ref, kept: the build's answer for the ref
// while this device's installed pin and writable generation are the refused statement's (the file header's follow
// row). It unwraps to evs's refusal, so a caller answers it as any closed gate, and no rebuild takes it.
type EvsGateHeldError struct {
	Refusal error
}

// The refusal, and that nothing newer stands to create the ref on.
func (self *EvsGateHeldError) Error() string {
	return fmt.Sprintf("evs: no newer authorization state or generation to create the ref on: %s", self.Refusal)
}

// evs's refusal, so EvsErrorOf and IsEvsRefusal find its code.
func (self *EvsGateHeldError) Unwrap() error {
	return self.Refusal
}

// Whether err asks for a rebuild under a new push id.
func evsNeedsRebuild(err error) bool {
	var held *EvsGateHeldError
	if errors.As(err, &held) {
		return false
	}
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
	// format 2: a one-part push's staged bytes, and each part's, for the staged segments its entry versions name;
	// the same bytes on every retry of the push id (evs_write_versionless.go)
	staged     []byte
	partStaged [][]byte
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
	if err := self.client.gateHeld(evsRefKey{repoId: plan.RepoId, refId: plan.RefId}, authPin.GetVersion(), repoKey.Generation()); err != nil {
		// the statement evs just refused, on the same pin and generation: not built again (the file header's follow row)
		return nil, err
	}
	identity := self.client.args.Identity()
	timeMs := self.client.clock.Now().UnixMilli()
	if plan.SignedTimeMs != 0 {
		// the index's entries name this time, and their buckets are chosen by it (§11.14's in-ref row)
		timeMs = plan.SignedTimeMs
	}
	pushPlan := &EvsPushPlan{
		RepoId: plan.RepoId, RefId: plan.RefId, RefKind: plan.RefKind, RefMode: plan.RefMode, OwnerSidecarId: plan.OwnerSidecarId,
		PushId: pushId, BaseVersion: plan.BaseVersion, BaseChain: plan.BaseChain, Generation: repoKey.Generation(),
		GroupId: repoKey.GroupId(), GenerationCommitment: repoKey.Commitment(), PathEpoch: plan.PathEpoch, Auth: authPin,
		SignerSidecarId: identity.SidecarId, ClientId: identity.ClientId, TimeMs: timeMs, SourcesStand: 0 < len(plan.Sources),
		Flags: plan.Flags, Erased: plan.Erased, IndexEpoch: plan.IndexEpoch,
	}
	manifest, err := NewEvsManifestKey(repoKey)
	if err != nil {
		return nil, err
	}
	// the run's tainted bit rides a format-2 push's provenance (§16.6, EVS2-M10-15); format 1 ignores it
	metadata := &protocol.EvsSealedMetadata{Provenance: &protocol.EvsProvenance{Tainted: plan.Tainted}}
	// an ERASE's and a CLOSURE's note, sealed with the push's metadata (§11.12's push and rekey rows; QD-682)
	metadata.ErasureNote = plan.erasureNote
	// a repair form's ignored pushes, for `ur evs log` alone, none on any other push (DESIGN-DETAILS 16.2.7; QD-833)
	metadata.WrittenOver = plan.writtenOver
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
	if plan.AgentId != nil {
		// the agent's subkey signs this push and its commits inside the sealed metadata, never a field evs reads (§11.5)
		message := EvsAgentProvenanceMessage(plan.RepoId, plan.RefId, pushId, timeMs, evsSealedCommitOids(metadata.Commits))
		if err := evsSignPushProvenance(metadata.Provenance, self.client.args.SignProvenance, *plan.AgentId, message); err != nil {
			return nil, err
		}
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
	format2 := sealed.format2()
	if format2 && sealed.kind5PushId != pushId && 0 < len(sealed.kind5) {
		return nil, fmt.Errorf("%w: versionless records sealed for another push", ErrEvsWriteInvalid)
	}
	idStaged, pathStaged := sealed.stagedOf()
	// the staged segments' items go in the changes' order, a part's contiguous run of it, so the parts' staged bytes
	// joined in part order are the items in order (evs_staged.go)
	stagedPaths := slices.Clone(sealed.Paths)
	slices.SortStableFunc(stagedPaths, func(a *EvsSealedPath, b *EvsSealedPath) int {
		return a.Planned.TokenPath.Compare(b.Planned.TokenPath)
	})
	allStaged := [][]byte{}
	for _, path := range stagedPaths {
		for _, segmentBytes := range pathStaged[path] {
			staged, err := EvsStagedSegmentOf(segmentBytes, plan.RepoId, pushId)
			if err != nil {
				return nil, err
			}
			pushPlan.NewObjects = append(pushPlan.NewObjects, staged.NewObject())
			allStaged = append(allStaged, segmentBytes)
		}
	}
	for _, path := range sealed.Paths {
		change, err := path.change(pushId, plan.BaseVersion, timeMs)
		if err != nil {
			return nil, err
		}
		change.StagedByteCount = evsStagedByteCount(pathStaged[path])
		pushPlan.Changes = append(pushPlan.Changes, change)
	}
	builder := NewEvsStatementBuilder(self.client.args.Sign)
	var built *EvsBuiltPush
	if format2 {
		built, err = builder.BuildFormat2(pushPlan)
	} else {
		built, err = builder.Build(pushPlan)
	}
	if err != nil {
		return nil, err
	}
	attempt.built = built
	if len(built.Parts) == 0 {
		attempt.staged = EvsEncodeStaged(allStaged)
	}
	partNamed := map[string]bool{}
	for _, partBytes := range built.Parts {
		var checked *EvsCheckedPart
		if format2 {
			checked, err = EvsCheckStoredPart(built.Statement, partBytes)
		} else {
			checked, err = EvsCheckPart(built.Statement, partBytes)
		}
		if err != nil {
			return nil, err
		}
		partSegments, err := evsChangesStaged(checked.Changes, idStaged)
		if err != nil {
			return nil, err
		}
		attempt.partStaged = append(attempt.partStaged, EvsEncodeStaged(partSegments))
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
		// format 2's setting (evs_plan_versionless.go); 0, every version kept, is format 1's absent field
		entry.Versioning = planned.Versioning
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
		Staged: attempt.staged,
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
	if *rebuilds == 0 {
		// a write's first build: a refusal kept for an earlier write of the ref is not this one's
		self.client.gateOpened(evsRefKey{repoId: self.repoId, refId: sealed.Plan.RefId})
	}
	for {
		pushId := NewEvsPushId()
		if note != nil {
			note(pushId)
		}
		// a versionless record's kind-5 segment names this push: sealed under it, and uploaded again for it
		if err := self.client.bindPush(sealed, pushId); err != nil {
			return pushId, nil, err
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
			self.client.gateOpened(evsRefKey{repoId: self.repoId, refId: sealed.Plan.RefId})
		}
		if IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED) && evsCreatesSharedRef(sealed.Plan) {
			self.client.followClosedGate(ctx, evsRefKey{repoId: self.repoId, refId: sealed.Plan.RefId},
				attempt.built.Statement.Push.GetAuth().GetVersion(), sealed.RepoKey.Generation(), err)
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

// Whether the plan's push creates or re-creates a shared ref: planned on no head, or on a deleted one. evs holds such
// a push's pin at or above the repo's newest rule set (QD-803).
func evsCreatesSharedRef(plan *EvsWritePlan) bool {
	return plan.RefKind == protocol.EvsRefKind_EVS_REF_SHARED && (plan.BaseVersion == 0 || plan.Head.GetDeleted())
}

// The file header's follow row: keeps the refused statement's pin and generation for the ref, then follows the
// authorization log once, on the caller's goroutine and within its ctx. A follow that fails leaves the state where it
// was, and the next build answers the kept refusal.
func (self *EvsClient) followClosedGate(ctx context.Context, key evsRefKey, pinVersion uint64, generation uint64, refusal error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.gateRefusals[key] = &evsGateRefusal{pinVersion: pinVersion, generation: generation, err: refusal}
	}()
	if self.args.ConfigFollow == nil {
		return
	}
	if err := self.args.ConfigFollow(ctx); err != nil {
		self.log.Infof("[evs]the follow after a closed gate on repo %s ref %s: %v", key.repoId, key.refId, err)
	}
}

// The kept refusal of a ref's creating push while neither the pin nor the generation a new statement would carry is
// above the refused one's, as an *EvsGateHeldError; nil, forgetting it, once either is.
func (self *EvsClient) gateHeld(key evsRefKey, pinVersion uint64, generation uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kept := self.gateRefusals[key]
	if kept == nil {
		return nil
	}
	if kept.pinVersion < pinVersion || kept.generation < generation {
		delete(self.gateRefusals, key)
		return nil
	}
	return &EvsGateHeldError{Refusal: kept.err}
}

// Forgets a ref's kept refusal: once a push to it committed, and at a later write's first build.
func (self *EvsClient) gateOpened(key evsRefKey) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.gateRefusals, key)
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

// Why a pin push sent nothing (DESIGN-DETAILS 16.2.9, 8.2.10; QD-802, QD-803): a ref a pin push cannot bind, which
// `ur evs rules show` lists apart.
type EvsPinPushSkip string

const (
	// A name with no head: a new ref is judged at its creating push's pin, which evs holds at or above the repo's
	// newest set (QD-803).
	EvsPinPushSkipNoHead EvsPinPushSkip = "no head"
	// A deleted ref: bound from the push that re-creates it, which evs holds as it holds a new ref's (QD-803).
	EvsPinPushSkipDeleted EvsPinPushSkip = "deleted"
	// A git-mode tag ref, which takes no second push and holds no file.
	EvsPinPushSkipTag EvsPinPushSkip = "tag"
	// A git-mode ref stopped on this device at a refused version, which its recovery binds: the DELETE and the
	// re-creating push carry the admin's pin.
	EvsPinPushSkipStopped EvsPinPushSkip = "stopped"
)

// What a pin push did: the push and the ref version it committed at, or why nothing was sent.
type EvsPinPushResult struct {
	PushId  Id
	Version uint64
	// Empty where the push went.
	Skipped EvsPinPushSkip
}

// The local tier's pin push of a git-mode ref, the mounts' (evs_local_pin.go): the UPDATE of one tip under the ref's
// publish lock. A leg with no local tier holds none.
type evsLocalPinPusher interface {
	pinPush(ctx context.Context, repoId Id, refId Id) (*EvsPinPushResult, error)
	// Whether the ref is stopped on this device's mount of the repo at a refused version, false where no mount holds
	// it.
	pinStopped(repoId Id, refId Id) bool
}

// A git-mode ref's pin push with no mount of its repo on this device: only a device that mounts the repo builds one,
// since the UPDATE of one tip is built on the version and chain its replay applied (8.2.10).
var ErrEvsPinPushNoMount = errors.New("evs: a git-mode ref's pin push needs a mount of its repo")

// The pin push of one shared ref (DESIGN-DETAILS 16.2.9, 8.2.10; QD-802, QD-803): a push of no change at this
// device's installed pin. A rule set binds a ref from the first push on it whose pin is at or above the set, so the
// set's filer sends one to every shared ref of the repo once its own log holds its statement, and retries a failed one
// from its journal (evs_prefix_repair.go). The push carries no change, so every reader's verdict allows it (16.2.4).
//
//	file mode  a statement with no change on the ref's head
//	git mode   the UPDATE of one tip, old_tip = new_tip, with no FORCE, commit, blob, tag, source or change, built on
//	           the version and chain replay applied under the ref's publish lock on a device that mounts the repo
//	           (evs_local_pin.go); it moves no local ref. A tag ref, a ref with no tip and a ref stopped on this device
//	           take none
//	nothing    a name with no head and a deleted ref: their next push creates the ref, and evs holds its pin at or
//	           above the repo's newest set (QD-803)
//
// A ref that is not shared, an owned ref, a deposit ref or the erasure ref, is ErrEvsWriteInvalid: the rules leave it
// outside. refName nil is main.
func (self *EvsRepo) PinPush(ctx context.Context, refName []byte) (*EvsPinPushResult, error) {
	if refName == nil {
		refName = EvsMainRefName
	}
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	return self.pinPushRef(ctx, refId, refName)
}

// PinPush of a ref by its id, refName its name where the caller holds it, nil where it does not: a pin push states no
// name, which only a creating push carries.
func (self *EvsRepo) pinPushRef(ctx context.Context, refId Id, refName []byte) (*EvsPinPushResult, error) {
	repoKind, err := self.repoKind()
	if err != nil {
		return nil, err
	}
	rebuilds := 0
	for {
		repoKey, err := self.client.args.Gkm.EnsureWritable(ctx, self.repoId)
		if err != nil {
			return nil, err
		}
		var skipped EvsPinPushSkip
		gitMode := false
		plan, err := func() (*EvsWritePlan, error) {
			result, err := self.read(ctx, refId, []string{""}, 0, true)
			if err != nil {
				return nil, err
			}
			defer result.objects.close()
			head := result.head.Head
			switch {
			case result.head.Version == 0:
				skipped = EvsPinPushSkipNoHead
				return nil, nil
			case head.GetDeleted():
				skipped = EvsPinPushSkipDeleted
				return nil, nil
			case head.GetRefKind() != protocol.EvsRefKind_EVS_REF_SHARED:
				return nil, fmt.Errorf("%w: a pin push goes to a shared ref", ErrEvsWriteInvalid)
			case head.GetRefMode() == protocol.EvsRefMode_EVS_REF_GIT:
				gitMode = true
				return nil, nil
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
			return plan, nil
		}()
		switch {
		case err != nil:
			return nil, err
		case skipped != "":
			return &EvsPinPushResult{Skipped: skipped}, nil
		case gitMode:
			pusher, _ := func() (evsLocalPinPusher, bool) {
				self.client.stateLock.Lock()
				defer self.client.stateLock.Unlock()
				pusher, ok := self.client.localTier.(evsLocalPinPusher)
				return pusher, ok
			}()
			if pusher == nil {
				return nil, ErrEvsPinPushNoMount
			}
			return pusher.pinPush(ctx, self.repoId, refId)
		}
		sealed, err := self.client.sealWrite(ctx, plan, repoKey)
		if err != nil {
			return nil, err
		}
		pushId, reply, err := self.sendSealed(ctx, sealed, &rebuilds)
		sealed.Close()
		switch {
		case err == nil:
			return &EvsPinPushResult{PushId: pushId, Version: reply.GetVersion()}, nil
		case (evsNeedsRebuild(err) || errors.Is(err, errEvsPlanEpochMoved) || errors.Is(err, errEvsRetokenSealsAgain)) &&
			rebuilds < self.client.settings.PushRebuildCount:
			rebuilds += 1
		default:
			return nil, err
		}
	}
}
