//go:build !ios_extension

// Erasure on the client (§11.12's erasure rows; owner decisions 61, 133; R-EVS-11, D-EVS-26, FI-5, FS-47; EVS1-M2-30):
// key destruction. An erasing device names every key of an entry's representations and destroys them by ERASE pushes
// on the repo's erasure ref, a derived chain first re-checkpointed without the entry by a CLOSURE push on its own ref
// (evs_closure.go), whose payload lists the old chain's keys for the ERASE that follows.
//
//	erase     an ERASE (flag 64, admin) on the erasure ref (EvsErasureRefId: shared semantics, file mode, creates only,
//	          path epoch 1 for life) through POST .../slots/delete: the erased list of (slot id, key index) in its
//	          payload, which erased_sha256 binds, and one creation under a random 16 B id, the erasure's note: its id,
//	          whether this ERASE completes it, and the caller's sealed note of what the keys covered, sealed as a file
//	          under the eraser's generation. evs commits it, then rewrites each named slot without its keys before its
//	          200; NOTHING_TO_ERASE, once recorded, means every named key is gone already, and counts done
//	first     an erasure's first ERASE carries at least the entry's own keys and an unconsumed deposit's slot, which
//	          re-key nothing, so at the storage limit the body goes at once and its derived chains follow in CLOSURE
//	          and ERASE pairs; that order is the caller's (§15.7, §16.8), which names the keys
//	read      ReadErasures walks the erasure ref's verified statements and, for each ERASE, reads its push record for
//	          the erased list and its note entry for the note
//	reconcile Erasures gives each erasure the committed ERASEs name, done once one of them completes it, else
//	          rewriting, and stalled 25 h after its last ERASE with none since; which device resumes it, its eraser's
//	          at its start or another of its member's after 25 h, is the caller's, from these states
//	after     on an ERASE's hint a reader deletes its cached object keys, slot copies and decrypted copies and refuses
//	          those keys: not built here, since those caches are §15.7's mail stores, §16.8's record caches and §5.9's
//	          index cache; ReadErasures gives them the keys to forget
//
// Erasure and deposit refs stay at path epoch 1 (evsEpochExempt), so an ERASE never meets 412 PATH_EPOCH. ERASE,
// CLOSURE and closure uploads take admin; a 429's retry_after_ms, which may run to the next 00:00 UTC for a closure's
// allowance, goes back to the caller as the refusal.
//
// On desktop and mobile legs. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What Erase destroys.
type EvsEraseArgs struct {
	// The erasure's id (§11.12): its CLOSUREs' and ERASEs' notes name it.
	ErasureId Id
	// Each key destroyed: a slot id and the key index in it.
	Keys []*EvsErasedKey
	// Whether this ERASE completes the erasure: every key of every representation gone.
	Complete bool
	// The caller's note of what the keys covered, its documents and each one whose last key goes, which Erase seals.
	Note []byte
}

// A committed ERASE.
type EvsEraseResult struct {
	PushId Id
	// The erasure ref's version it committed at, 0 when every named key was gone already (NOTHING_TO_ERASE).
	Version uint64
}

// One committed ERASE as ReadErasures reads it.
type EvsErasure struct {
	Version         uint64
	PushId          Id
	Time            time.Time
	EraserSidecarId Id
	ErasureId       Id
	Complete        bool
	Keys            []*EvsErasedKey
	Note            []byte
}

// An erasure note's opening: erasure id 16 B | complete u8 | the caller's note.
const evsErasureNoteHeaderByteCount = 17

// §11.12's reconcile row: an erasure with no ERASE for 25 h is another device's to finish.
const evsErasureStallAfter = 25 * time.Hour

// Destroys args.Keys by an ERASE: see the file header.
func (self *EvsRepo) Erase(ctx context.Context, args *EvsEraseArgs) (*EvsEraseResult, error) {
	if args == nil || len(args.Keys) == 0 {
		return nil, fmt.Errorf("%w: an ERASE of no key", ErrEvsWriteInvalid)
	}
	for _, key := range args.Keys {
		if EvsSlotMaxKeyCount <= key.KeyIndex {
			return nil, fmt.Errorf("%w: key index %d", ErrEvsWriteInvalid, key.KeyIndex)
		}
	}
	refId := EvsErasureRefId(self.repoId)
	note := append(append(args.ErasureId.Bytes(), 0), args.Note...)
	if args.Complete {
		note[16] = 1
	}
	for rebuild := 0; ; rebuild += 1 {
		repoKey, err := self.client.args.Gkm.EnsureWritable(ctx, self.repoId)
		if err != nil {
			return nil, err
		}
		head, err := self.readHeadAlone(ctx, refId, 0 < rebuild)
		if err != nil {
			return nil, err
		}
		plan, err := self.notePlan(ctx, refId, protocol.EvsRefKind_EVS_REF_ERASURE, head, repoKey, note)
		if err != nil {
			return nil, err
		}
		plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE)
		plan.Erased = args.Keys
		sealed, err := self.client.sealWrite(ctx, plan, repoKey)
		if err != nil {
			return nil, err
		}
		pushId := NewEvsPushId()
		attempt, err := self.buildPush(ctx, sealed, pushId)
		sealed.Close()
		if err != nil {
			return nil, err
		}
		reply, err := self.postErase(ctx, attempt)
		switch {
		case err == nil:
			return &EvsEraseResult{PushId: pushId, Version: reply.GetVersion()}, nil
		case IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE):
			return &EvsEraseResult{PushId: pushId}, nil
		case rebuild < self.client.settings.PushRebuildCount && evsNeedsRebuild(err):
		default:
			return nil, err
		}
	}
}

// A one-file plan on a ref that stays at epoch 1: the note as an inline checkpoint under a random id, created on head.
func (self *EvsRepo) notePlan(ctx context.Context, refId Id, refKind protocol.EvsRefKind, head *EvsVerifiedHead, repoKey *EvsRepoKey, note []byte) (*EvsWritePlan, error) {
	keys := newEvsReadKeys(self)
	plan := &EvsWritePlan{
		RepoId: self.repoId, RefId: refId, RefKind: refKind, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		BaseVersion: head.Version, BaseChain: head.Chain, Head: head.Head, PathEpoch: 1, Generation: repoKey.Generation(),
		keys: keys, floors: map[string]uint64{},
	}
	oid, err := EvsGitBlobOid(bytes.NewReader(note), int64(len(note)))
	if err != nil {
		return nil, err
	}
	noteId := NewEvsRandomToken()
	plan.Paths = []*EvsPlannedPath{{
		TokenPath: EvsTokenPath{noteId}, Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE, Version: head.Version + 1,
		Fields: &protocol.EvsSealedFields{FileId: NewEvsSlotId().Bytes(), Mode: EvsGitModeFile, GitOid: oid[:], OidKind: protocol.EvsOidKind_EVS_OID_SHA1, Size: uint64(len(note))},
		Chain:  []*EvsPlannedLink{{Record: &EvsPlannedRecord{Kind: protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, RecordId: NewEvsSlotId(), Oid: oid, Body: bytes.NewReader(note)}}},
		Inline: EvsPadme(EvsWrappedKeyByteCount+EvsRecordByteCount(uint64(len(note)))) <= EvsInlineMaxByteCount,
	}}
	return plan, nil
}

// POST .../slots/delete with the ERASE, admin, the same bytes until evs answers it.
func (self *EvsRepo) postErase(ctx context.Context, attempt *evsPushAttempt) (*protocol.EvsPushReply, error) {
	if 0 < len(attempt.built.Parts) {
		return nil, fmt.Errorf("%w: an ERASE past one part", ErrEvsWriteInvalid)
	}
	call := &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/slots/delete",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/slots/delete",
		repoId: self.repoId,
		role:   evsScopeAdmin,
		body:   &protocol.EvsPushRequest{Statement: attempt.built.Statement.Bytes, Payload: attempt.built.Payload, Receipts: attempt.receipts},
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

// The repo's committed ERASEs after afterVersion of its erasure ref, oldest first, each with its erased keys and its
// note opened: see the file header's read row.
func (self *EvsRepo) ReadErasures(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error) {
	refId := EvsErasureRefId(self.repoId)
	head, err := self.readHeadAlone(ctx, refId, true)
	if err != nil || head.Version == 0 {
		return nil, err
	}
	walked, err := self.client.verifier.Walk(ctx, self.repoId, refId, 0, EvsChainStart(self.repoId, refId), head.Version)
	if err != nil {
		return nil, err
	}
	erasures := []*EvsErasure{}
	for _, statement := range walked {
		push := statement.Statement.Push
		if statement.Version <= afterVersion || push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) == 0 {
			continue
		}
		erasure, err := self.readErasure(ctx, head, statement)
		if err != nil {
			return nil, err
		}
		erasures = append(erasures, erasure)
	}
	return erasures, nil
}

// One ERASE: its push record's erased list, checked against erased_sha256, and its note entry, read and opened.
func (self *EvsRepo) readErasure(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (*EvsErasure, error) {
	refId := head.RefId
	push := statement.Statement.Push
	pushId, _ := IdFromBytes(push.GetPushId())
	signerId, _ := IdFromBytes(push.GetSignerSidecarId())
	erasure := &EvsErasure{Version: statement.Version, PushId: pushId, Time: evsTime(push.GetTimeMs()), EraserSidecarId: signerId}
	checked, err := self.pushPayload(ctx, head, statement)
	if err != nil {
		return nil, err
	}
	erasure.Keys = checked.Erased
	if len(statement.Statement.Changes) != 1 {
		return nil, fmt.Errorf("%w: an ERASE of %d notes", ErrEvsEntryRefused, len(statement.Statement.Changes))
	}
	result, err := self.readPaths(ctx, refId, []*evsReadPath{{token: statement.Statement.Changes[0].TokenPath}}, false)
	if err != nil {
		return nil, err
	}
	defer result.objects.close()
	verified := result.replies[0]
	if verified.Entry == nil {
		return nil, fmt.Errorf("%w: an ERASE's note", ErrEvsPathAbsent)
	}
	content, _, _, err := self.reconstructContent(ctx, result, verified, nil)
	if err != nil {
		return nil, err
	}
	defer content.close()
	note, err := io.ReadAll(content.reader())
	if err != nil {
		return nil, err
	}
	if len(note) < evsErasureNoteHeaderByteCount || 1 < note[16] {
		return nil, fmt.Errorf("%w: an erasure note of %d bytes", ErrEvsEntryRefused, len(note))
	}
	erasure.ErasureId, _ = IdFromBytes(note[:16])
	erasure.Complete = note[16] == 1
	erasure.Note = note[evsErasureNoteHeaderByteCount:]
	return erasure, nil
}

// The repo's erasures as this device sees them from evs's state (§18.5, §11.12's reconcile row): one per erasure the
// committed ERASEs name, done once one completes it, stalled 25 h after its last ERASE with none since, else
// rewriting. Erasures with no committed ERASE yet, a crash before the first, are their devices' journals'.
func (self *EvsRepo) Erasures(ctx context.Context) ([]*SidecarErasure, error) {
	erasures, err := self.ReadErasures(ctx, 0)
	if err != nil {
		return nil, err
	}
	now := self.client.clock.Now()
	byId := map[Id]*SidecarErasure{}
	last := map[Id]time.Time{}
	order := []Id{}
	for _, erasure := range erasures {
		state := byId[erasure.ErasureId]
		if state == nil {
			state = &SidecarErasure{ErasureId: erasure.ErasureId, State: "rewriting"}
			byId[erasure.ErasureId] = state
			order = append(order, erasure.ErasureId)
		}
		if erasure.Complete {
			state.State = "done"
		}
		last[erasure.ErasureId] = erasure.Time
	}
	states := []*SidecarErasure{}
	for _, erasureId := range order {
		state := byId[erasureId]
		if state.State != "done" && last[erasureId].Add(evsErasureStallAfter).Before(now) {
			state.State = "stalled"
		}
		states = append(states, state)
	}
	return states, nil
}
