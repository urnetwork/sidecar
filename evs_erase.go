//go:build !ios_extension

// Erasure on the client (§11.12's erasure rows; owner decisions 61, 133; R-EVS-11, D-EVS-26, FI-5, FS-47; EVS1-M2-30):
// key destruction. An erasing device names every key of an entry's representations and destroys them by ERASE pushes
// on the repo's erasure ref, a derived chain first re-checkpointed without the entry by a CLOSURE push on its own ref
// (evs_closure.go), whose payload lists the old chain's keys for the ERASE that follows.
//
//	erase     an ERASE (flag 64, admin) on the erasure ref (EvsErasureRefId: shared semantics, file mode, creates only,
//	          path epoch 1 for life) through POST .../slots/delete: the erased list of (slot id, key index) in its
//	          payload, which erased_sha256 binds, and no change: it creates nothing on the erasure ref. evs commits
//	          it, then rewrites each named slot without its keys before its 200; NOTHING_TO_ERASE, once recorded,
//	          means every named key is gone already, and counts done
//	note      the erasure's note rides the push's sealed metadata, EvsSealedMetadata.erasure_note, sealed under the
//	          eraser's generation with the rest of it (QD-682; question evs1-m2-30-erasure-note-format; EVS-FORMAT.md's
//	          erasure notes): erasure id 16 B | complete u8, 1 when this ERASE ends the erasure | the caller's note
//	          of what the keys covered (RECORD's SealedNote, MAIL's documents). A CLOSURE's note is its erasure id
//	          alone (evs_closure.go)
//	first     an erasure's first ERASE carries at least the entry's own keys and an unconsumed deposit's slot, which
//	          re-key nothing, so at the storage limit the body goes at once and its derived chains follow in CLOSURE
//	          and ERASE pairs; that order is the caller's (§15.7, §16.8), which names the keys
//	read      ReadErasures walks the erasure ref's verified statements and, for each ERASE, reads its push record for
//	          the erased list and its sealed metadata, whose erasure note it opens; an ERASE that changes a path, or
//	          whose note is not one, refuses the read
//	reconcile Erasures gives each erasure the committed ERASEs' notes name, done once one of them completes it, else
//	          rewriting, and stalled 25 h after its last ERASE with none since; which device resumes it, its eraser's
//	          at its start or another of its member's after 25 h, is the caller's, from these states and from each
//	          content ref's CLOSUREs, whose notes name their erasure (EvsRepo.ReadClosures)
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
	"context"
	"fmt"
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

// An erasure note's layout (EVS-FORMAT.md's erasure notes; QD-682): the erasure's id, 16 B, which is all of a
// CLOSURE's note, and in an ERASE's the complete byte after it, then the caller's bytes.
const (
	evsErasureNoteIdByteCount     = 16
	evsErasureNoteHeaderByteCount = evsErasureNoteIdByteCount + 1
)

// An ERASE's note: erasure id 16 B | complete u8, 1 when this ERASE ends the erasure | the caller's note bytes.
func EvsEraseNote(erasureId Id, complete bool, callerNote []byte) []byte {
	note := make([]byte, 0, evsErasureNoteHeaderByteCount+len(callerNote))
	note = append(note, erasureId.Bytes()...)
	if complete {
		note = append(note, 1)
	} else {
		note = append(note, 0)
	}
	return append(note, callerNote...)
}

// An ERASE's note opened to its parts. ErrEvsEntryRefused for one short of its id and complete byte, or whose
// complete byte is neither 0 nor 1.
func ParseEvsEraseNote(note []byte) (erasureId Id, complete bool, callerNote []byte, err error) {
	if len(note) < evsErasureNoteHeaderByteCount || 1 < note[evsErasureNoteIdByteCount] {
		return Id{}, false, nil, fmt.Errorf("%w: an ERASE's erasure note of %d bytes", ErrEvsEntryRefused, len(note))
	}
	if erasureId, err = IdFromBytes(note[:evsErasureNoteIdByteCount]); err != nil {
		return Id{}, false, nil, fmt.Errorf("%w: an erasure note's id", ErrEvsEntryRefused)
	}
	return erasureId, note[evsErasureNoteIdByteCount] == 1, note[evsErasureNoteHeaderByteCount:], nil
}

// A CLOSURE's note: its erasure's id, 16 B, and no caller bytes.
func EvsClosureNote(erasureId Id) []byte {
	return erasureId.Bytes()
}

// A CLOSURE's note opened to its erasure's id. ErrEvsEntryRefused for anything but the id's 16 bytes.
func ParseEvsClosureNote(note []byte) (Id, error) {
	if len(note) != evsErasureNoteIdByteCount {
		return Id{}, fmt.Errorf("%w: a CLOSURE's erasure note of %d bytes", ErrEvsEntryRefused, len(note))
	}
	erasureId, err := IdFromBytes(note)
	if err != nil {
		return Id{}, fmt.Errorf("%w: an erasure note's id", ErrEvsEntryRefused)
	}
	return erasureId, nil
}

// Destroys args.Keys by an ERASE: see the file header.
func (self *EvsRepo) Erase(ctx context.Context, args *EvsEraseArgs) (*EvsEraseResult, error) {
	for rebuild := 0; ; rebuild += 1 {
		pushId := NewEvsPushId()
		attempt, err := self.buildErase(ctx, args, pushId, 0 < rebuild)
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

// One ERASE of args under pushId, built and signed on the erasure ref's verified head, fresh when asked, and not
// posted: what Erase sends, and what a caller that names its own push id keeps for its retries (record_evs.go).
func (self *EvsRepo) buildErase(ctx context.Context, args *EvsEraseArgs, pushId Id, fresh bool) (*evsPushAttempt, error) {
	if args == nil || len(args.Keys) == 0 {
		return nil, fmt.Errorf("%w: an ERASE of no key", ErrEvsWriteInvalid)
	}
	slotMaxKeyCount := DefaultEvsFormatSettings().SlotMaxKeyCount
	for _, key := range args.Keys {
		if slotMaxKeyCount <= int(key.KeyIndex) {
			return nil, fmt.Errorf("%w: key index %d", ErrEvsWriteInvalid, key.KeyIndex)
		}
	}
	refId := EvsErasureRefId(self.repoId)
	repoKey, err := self.client.args.Gkm.EnsureWritable(ctx, self.repoId)
	if err != nil {
		return nil, err
	}
	head, err := self.readHeadAlone(ctx, refId, fresh)
	if err != nil {
		return nil, err
	}
	// no change: the note rides the sealed metadata, and the erasure ref, which stays at epoch 1, gains no entry
	plan := &EvsWritePlan{
		RepoId: self.repoId, RefId: refId, RefKind: protocol.EvsRefKind_EVS_REF_ERASURE, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		BaseVersion: head.Version, BaseChain: head.Chain, Head: head.Head, PathEpoch: 1, Generation: repoKey.Generation(),
		keys: newEvsReadKeys(self), floors: map[string]uint64{},
		Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE), Erased: args.Keys,
		erasureNote: EvsEraseNote(args.ErasureId, args.Complete, args.Note),
	}
	sealed, err := self.client.sealWrite(ctx, plan, repoKey)
	if err != nil {
		return nil, err
	}
	defer sealed.Close()
	return self.buildPush(ctx, sealed, pushId)
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

// One ERASE: its push record's erased list, checked against erased_sha256, and its sealed metadata's erasure note,
// opened. An ERASE creates nothing, so one that changes a path is refused.
func (self *EvsRepo) readErasure(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (*EvsErasure, error) {
	push := statement.Statement.Push
	pushId, _ := IdFromBytes(push.GetPushId())
	signerId, _ := IdFromBytes(push.GetSignerSidecarId())
	erasure := &EvsErasure{Version: statement.Version, PushId: pushId, Time: evsTime(push.GetTimeMs()), EraserSidecarId: signerId}
	if len(statement.Statement.Changes) != 0 || push.GetChangeCount() != 0 {
		return nil, fmt.Errorf("%w: an ERASE that changes a path", ErrEvsEntryRefused)
	}
	checked, note, err := self.erasureNoteOf(ctx, head, statement)
	if err != nil {
		return nil, err
	}
	erasure.Keys = checked.Erased
	if erasure.ErasureId, erasure.Complete, erasure.Note, err = ParseEvsEraseNote(note); err != nil {
		return nil, err
	}
	return erasure, nil
}

// A committed ERASE's or CLOSURE's push payload, checked against its statement, and the erasure note its sealed
// metadata carries, opened under the generation the statement names; the note is empty when the metadata carries
// none, which its caller's parse refuses.
func (self *EvsRepo) erasureNoteOf(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (*EvsCheckedPayload, []byte, error) {
	checked, err := self.pushPayload(ctx, head, statement)
	if err != nil {
		return nil, nil, err
	}
	manifest, err := newEvsReadKeys(self).manifest(ctx, statement.Statement.Push.GetGeneration())
	if err != nil {
		return nil, nil, err
	}
	metadata, err := EvsOpenMetadata(manifest, checked.SealedMetadata)
	if err != nil {
		self.client.alarm(self.repoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
		return nil, nil, err
	}
	return checked, metadata.GetErasureNote(), nil
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
		if state.State != "done" && last[erasureId].Add(self.client.settings.ErasureStallAfter).Before(now) {
			state.State = "stalled"
		}
		states = append(states, state)
	}
	return states, nil
}
