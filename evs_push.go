// The push sender (§11.8's client steps and outcomes; D-EVS-5, D-EVS-20, D-EVS-22, D-EVS-23; EVS1-M2-26): a sealed
// write's push built under one push id, sent, and retried or rebuilt by what evs answers.
//
//	build    choose push_id P; render each entry version under P (evs_plan.go's planned paths, sealed); the new
//	         segments with the upload day their receipts give; sealed metadata under manifest_g with the §10 group
//	         head the writer pins, when the client knows one; the statement on the head the plan read (v = b, C_b), its
//	         time fresh per statement, signed only by §5's identity key, naming sidecar_id and client_id (D-EVS-5)
//	send     a one-part push posts {statement, payload, receipts} once every upload answered 200; a push over 1 MiB or
//	         1,024 entry writes goes in parts (evs_push_parts.go), git mode taking its seal lease first
//	retry    one push id names one statement, retried one attempt at a time, the same bytes, until 200, 409 or 412:
//	         a 429 and a 503, an unknown outcome among them, and no answer at all go again after retry_after_ms
//	         (TIME_AHEAD's 429 included, unchanged), so a dropped answer's retry returns the original version (FS-1)
//	rebuild  a new push id, sealed afresh from a fresh read, never a second statement under one push id: 409
//	         SEGMENT_STALE, SEGMENT_GONE, SLOT_STALE, BASE_STALE and TIME_STALE, 412 PATH_EPOCH (re-tokenized by the
//	         fresh read) and GATE_CLOSED (EnsureWritable again, so the next seal is to the next generation)
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

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The codes that ask for the push to be built again under a new push id (§11.8's outcomes; EVS1-M2-26's rebuild row).
var evsRebuildCodes = map[protocol.EvsRefusalCode]bool{
	protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_STALE: true,
	protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_GONE:  true,
	protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE:    true,
	protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH:    true,
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
		SignerSidecarId: identity.SidecarId, ClientId: identity.ClientId, TimeMs: timeMs,
	}
	manifest, err := NewEvsManifestKey(repoKey)
	if err != nil {
		return nil, err
	}
	metadata := &protocol.EvsSealedMetadata{Provenance: &protocol.EvsProvenance{}}
	if self.client.args.GroupHead != nil {
		if groupHead, ok := self.client.args.GroupHead(repoKey.GroupId()); ok {
			metadata.Group = groupHead
		}
	}
	if pushPlan.SealedMetadata, err = EvsSealMetadata(manifest, metadata); err != nil {
		return nil, err
	}
	segmentIdReceipts := map[string]*protocol.EvsUploadReceipt{}
	attempt := &evsPushAttempt{pushId: pushId, refMode: plan.RefMode, baseVersion: plan.BaseVersion, refId: plan.RefId}
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
					receipts = append(receipts, receipt)
				}
			}
		}
		attempt.partReceipts = append(attempt.partReceipts, receipts)
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
	change := &EvsPlannedChange{TokenPath: planned.TokenPath, BaseEntryVersion: planned.BaseEntryVersion}
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
	return self.postPush(ctx, attempt.pushId, request)
}

// POST .../push, the same bytes until it answers anything but a 429, a 503 or nothing.
func (self *EvsRepo) postPush(ctx context.Context, pushId Id, request *protocol.EvsPushRequest) (*protocol.EvsPushReply, error) {
	call := &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/push",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/push",
		repoId: self.repoId,
		role:   evsScopeWrite,
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
