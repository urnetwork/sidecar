//go:build !ios_extension

// EvsRepo.BuildStreamPush and PostStreamPush (proposed; RECORD-M3-12, D-EVS-10, R-EVS-11; C-14's EvsRepo.AppendStream):
// a push of creations on this sidecar's own stream in a record-class repo, the owned ref §11.8's refs table lets only
// its sidecar write and only by creating paths, introducing beside its entry files one slot object whose keys the
// caller chose and wrapped (RECORD.md section 5.2's slot rows, §16.8's storage row). Unlike Write, the caller names
// the push id and the slot id, so one push and every retry of it are one statement (I-EVS-3): BuildStreamPush seals,
// uploads and signs the push once, and PostStreamPush sends those bytes, which a caller keeps between attempts.
//
//	plan      EnsureWritable first, so nothing is sealed to a generation a non-reader holds (§8.12); then the write
//	          planner's plan of each file as a creation on the ref's verified head, with the directory deltas its
//	          paths need (evs_plan.go, evs_directory.go), in the head's path epoch, or the epoch a ref with no head
//	          starts in; a ref with no head is owned by this sidecar whatever its name, since the ref's name is
//	          ur/<sidecar_id as 32 lowercase hex>/record (plan-RECORD-stream-names#1) and the planner tells an owned
//	          ref only by Id.String()'s form (question record-m3-01-owned-ref-id-text)
//	creates   every file a creation: a path that stands, or a removal, is 409 PATH_CONFLICT before anything is
//	          sealed, as evs's creates-only rule would answer; a delta of a directory that already stands is refused
//	          here too, ErrEvsStreamDirectoryDelta, since evs's creates-only rule refuses every change on a base
//	          version, a delta's included, which §16.8's 2,048-entry directories need (question
//	          record-m3-12-stream-directory-rows): a stream takes its first push into each directory and no second
//	slots     each entry file is a record-class file, its chain under a fresh key in a new slot of its own
//	          (evs_upload.go), which an ERASE of a body row never touches; the caller's slot object follows them in
//	          the new-objects list, its keys from SlotKeys under fek_g of the generation EnsureWritable gave
//	pin       the push declares the newest verified config state's pin, as every push does (evs_push.go), and is
//	          refused while that state is below the caller's AuthPin or off its chain: the entries' policy_version
//	          must not pass the pin readers judge them at (RECORD.md section 5.5's right step)
//	parts     one part only, as §16.8's storage row has a stream push: a push past 1 MiB of payload or 1,024 entry
//	          writes is refused here
//	post      POST .../push at rw, the same bytes until evs answers anything but a 429, a 503 or nothing; every
//	          refusal, 412 GATE_CLOSED and 412 PATH_EPOCH among them, goes back to the caller as an *EvsError, never
//	          rebuilt here: a rebuilt push takes a new push id and new slot ids, which only the caller draws
//
// On desktop and mobile legs, beside Write. Safe for concurrent use, each build its own push.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// A stream push that would change a directory standing on its creates-only ref, which evs refuses: the push waits
	// on question record-m3-12-stream-directory-rows and sends nothing.
	ErrEvsStreamDirectoryDelta = errors.New("evs: a stream push extending a standing directory")
	// The newest verified config state is below the pin the push must declare, or off its chain: nothing was built.
	ErrEvsStreamPinBehind = errors.New("evs: the verified state is behind the stream push's pin")
)

// One entry file of a stream push: its plaintext path, raw names joined by /, and its bytes.
type EvsStreamFile struct {
	Path    string
	Content []byte
}

// What BuildStreamPush builds.
type EvsStreamPushArgs struct {
	// The stream's ref name bytes, this sidecar's own.
	RefName []byte
	// Drawn by the caller per statement: a rebuilt push takes another.
	PushId Id
	// The caller's slot object's id, drawn as PushId is.
	SlotId Id
	// The slot object's keys under fek, the generation the push seals to, in ascending key_index: at least one, at
	// most §11.8's 64, each of fek's generation.
	SlotKeys func(fek *EvsFekKey) ([]*protocol.EvsSlotKey, error)
	// Each a creation, in any order: the statement sorts its changes by token path.
	Files []*EvsStreamFile
	// The pin the push declares at least.
	AuthPin *bridge.AuthPin
}

// A stream push built under one push id, ready to post and to post again unchanged.
type EvsStreamPush struct {
	PushId    Id
	RefId     Id
	Statement []byte
	Payload   []byte
	Receipts  []*protocol.EvsUploadReceipt
	// The statement's time_ms, the push time readers take once it commits.
	TimeMs int64
}

// A committed stream push.
type EvsStreamCommit struct {
	Version uint64
	TimeMs  int64
}

// Seals, uploads and signs args' push: see the file header. Nothing is posted.
func (self *EvsRepo) BuildStreamPush(ctx context.Context, args *EvsStreamPushArgs) (*EvsStreamPush, error) {
	switch {
	case args == nil || len(args.RefName) == 0 || len(args.Files) == 0 || args.SlotKeys == nil || args.AuthPin == nil:
		return nil, fmt.Errorf("%w: a stream push needs its ref, files, slot keys and pin", ErrEvsWriteInvalid)
	case args.PushId == (Id{}) || args.SlotId == (Id{}):
		return nil, fmt.Errorf("%w: a stream push of no push or slot id", ErrEvsWriteInvalid)
	}
	sidecarId := self.client.args.Identity().SidecarId
	writes := make([]*EvsPathWrite, 0, len(args.Files))
	for _, file := range args.Files {
		if file == nil {
			return nil, fmt.Errorf("%w: a stream push's file is nil", ErrEvsWriteInvalid)
		}
		writes = append(writes, &EvsPathWrite{Path: file.Path, Content: bytes.NewReader(file.Content)})
	}
	refId, err := self.resolveRefId(ctx, args.RefName, nil)
	if err != nil {
		return nil, err
	}
	repoKey, err := self.client.args.Gkm.EnsureWritable(ctx, self.repoId)
	if err != nil {
		return nil, err
	}
	if self.client.epochs.noteWritable(self.repoId, repoKey.Generation()) {
		// a newer generation, which may be a removal this device rotated to: its refs' mappers tick
		self.client.NoteGeneration(self.repoId)
	}
	state, err := self.client.verifier.config()
	if err != nil {
		return nil, err
	}
	if state.Pin().GetVersion() < args.AuthPin.GetVersion() || !state.OnChain(args.AuthPin) {
		return nil, ErrEvsStreamPinBehind
	}
	plan, err := self.PlanWrite(ctx, &EvsPlanArgs{RefName: args.RefName, RefId: refId, Writes: writes, Generation: repoKey.Generation(), Fresh: true})
	if err != nil {
		return nil, err
	}
	if !plan.slotKeyed {
		return nil, fmt.Errorf("%w: a stream outside a record-class repo", ErrEvsWriteInvalid)
	}
	switch {
	case plan.firstPush && plan.RefKind == protocol.EvsRefKind_EVS_REF_SHARED && plan.OwnerSidecarId == nil:
		// a ref with no head takes this sidecar as its owner: its name's form is not Id.String()'s (file header)
		plan.RefKind = protocol.EvsRefKind_EVS_REF_OWNED
		plan.OwnerSidecarId = &sidecarId
	case plan.RefKind != protocol.EvsRefKind_EVS_REF_OWNED || plan.OwnerSidecarId == nil || *plan.OwnerSidecarId != sidecarId:
		return nil, fmt.Errorf("%w: a stream that is not this sidecar's owned ref", ErrEvsWriteInvalid)
	}
	conflicts := []EvsTokenPath{}
	directoryDelta := false
	for _, planned := range plan.Paths {
		switch {
		case planned.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY && !planned.Remove:
			directoryDelta = directoryDelta || planned.BaseEntryVersion != 0
		case planned.Remove || planned.BaseEntryVersion != 0:
			conflicts = append(conflicts, planned.TokenPath)
		}
	}
	if 0 < len(conflicts) {
		// evs's own answer to a creates-only ref's write (5c's change shape), given before anything is sealed
		return nil, &EvsError{Status: http.StatusConflict, Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, PushId: &args.PushId, Paths: conflicts}
	}
	if directoryDelta {
		return nil, fmt.Errorf("%w: question record-m3-12-stream-directory-rows", ErrEvsStreamDirectoryDelta)
	}
	sealed, err := self.client.sealWrite(ctx, plan, repoKey)
	if err != nil {
		return nil, err
	}
	defer sealed.Close()
	fek, err := NewEvsFekKey(repoKey)
	if err != nil {
		return nil, err
	}
	slotKeys, err := args.SlotKeys(fek)
	if err != nil {
		return nil, err
	}
	for _, slotKey := range slotKeys {
		if slotKey.GetGeneration() != repoKey.Generation() {
			return nil, fmt.Errorf("%w: a slot key of generation %d in a push sealed to %d", ErrEvsWriteInvalid, slotKey.GetGeneration(), repoKey.Generation())
		}
	}
	slotBytes, err := EvsEncodeSlotObject(&protocol.EvsSlotObject{Keys: slotKeys})
	if err != nil {
		return nil, err
	}
	for _, slot := range sealed.Slots {
		if slot.Id == args.SlotId {
			return nil, fmt.Errorf("%w: a slot id an entry's chain drew", ErrEvsWriteInvalid)
		}
	}
	sealed.Slots = append(sealed.Slots, &EvsSealedSlot{Id: args.SlotId, Body: slotBytes})
	if err := self.uploadSegments(ctx, sealed, args.PushId); err != nil {
		return nil, err
	}
	attempt, err := self.buildPush(ctx, sealed, args.PushId)
	if err != nil {
		return nil, err
	}
	if 0 < len(attempt.built.Parts) {
		return nil, fmt.Errorf("%w: a stream push past one part", ErrEvsWriteInvalid)
	}
	return &EvsStreamPush{
		PushId:    args.PushId,
		RefId:     refId,
		Statement: attempt.built.Statement.Bytes,
		Payload:   attempt.built.Payload,
		Receipts:  attempt.receipts,
		TimeMs:    attempt.built.Statement.Push.GetTimeMs(),
	}, nil
}

// Posts push, the same bytes until evs answers anything but a 429, a 503 or nothing, and answers its commit or evs's
// refusal as an *EvsError.
func (self *EvsRepo) PostStreamPush(ctx context.Context, push *EvsStreamPush) (*EvsStreamCommit, error) {
	if push == nil || len(push.Statement) == 0 {
		return nil, fmt.Errorf("%w: no stream push to post", ErrEvsWriteInvalid)
	}
	reply, err := self.postPush(ctx, push.PushId, &protocol.EvsPushRequest{Statement: push.Statement, Payload: push.Payload, Receipts: push.Receipts})
	if err != nil {
		return nil, err
	}
	self.client.epochs.noteCommitted(self.repoId, push.RefId, reply.GetVersion())
	return &EvsStreamCommit{Version: reply.GetVersion(), TimeMs: push.TimeMs}, nil
}

// BuildStreamPush, then PostStreamPush: one statement, sent until evs answers it. A caller that may retry after a
// crash keeps the built push and posts it again itself, as RecordStreams' binding does (record_evs.go).
func (self *EvsRepo) AppendStream(ctx context.Context, args *EvsStreamPushArgs) (*EvsStreamCommit, error) {
	push, err := self.BuildStreamPush(ctx, args)
	if err != nil {
		return nil, err
	}
	return self.PostStreamPush(ctx, push)
}
