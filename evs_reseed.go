//go:build !ios_extension

// A re-seed of one repo from this device's mirror (§11.13's re-seed row, §19.10's repos step, D-EVS-17; EVSB-M2-20;
// QD-725): after a site loss, while evs runs with reseed on, a repo admin's device sends evs back what its sealed
// mirror holds (evs_mirror_layout.go), through POST .../reseed, never re-signed:
//
//	order     the repo's erasure ref first, so evs holds every ERASE this device kept before any slot returns; then
//	          each other ref's history in version order; and last, after every ref's history, the slots
//	version   its new segments from seg/ through PUT .../segments, which takes re-seed uploads while reseed is on, then
//	          its statement and payload as the mirror's stmt/ and rec/ hold them, in one reseed call; a version evs
//	          already holds answers its version (§11.8's 5a) and the walk goes on
//	slot      each slot the mirror holds, under the statement of the last re-seeded version that names it, which is
//	          what evs takes a slot by; evs strips what its ERASEs cover (QD-096)
//	statement with SignReseed, for each ref re-seeded as far as the mirror holds it, a Signed EvsReseed over that
//	          head, which a reader whose pin lies above it accepts the shorter history under (§11.6)
//
// A ref stops at the first version the mirror cannot send or evs does not take, and says why: a version past it cannot
// chain. A push in parts stops its ref, since evs takes none yet (question evs-reseed-route-part-records), as does a
// PATH_EPOCH push whose map evs does not hold, whose parts this walk does not send. One ref's stop never ends the
// walk: the other refs and the slots go on, and the result names each.
//
// Nothing here reads evs: a head below this device's pin is what a re-seed mends, and the verifier refuses it until
// the EvsReseed is filed. The walk starts each ref at version 1 and lets 5a answer what evs already holds.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A version the mirror does not hold whole: its statement, its record or a segment it introduces.
	ErrEvsReseedMirrorPartial = errors.New("evs: the mirror does not hold the version whole")
	// A push in parts, which POST .../reseed does not take yet.
	ErrEvsReseedParts = errors.New("evs: a push in parts is not re-seeded yet")
	// evs answered a version another than the one the mirror holds the statement at.
	ErrEvsReseedVersion = errors.New("evs: a re-seeded push committed at another version")
)

// What a re-seed is asked.
type EvsReseedArgs struct {
	// The recovery's incident id, which each EvsReseed names (§19.10).
	IncidentId []byte
	// Sign and file an EvsReseed over each ref's re-seeded head: a repo admin's statement that the history evs now
	// serves is all that survived.
	SignReseed bool
}

// One ref of a re-seed.
type EvsReseedRef struct {
	RefId Id
	// The version the mirror holds the ref through.
	MirrorVersion uint64
	// The version evs holds the ref through after the walk, and its chain: 0 when not even version 1 went.
	Version uint64
	Chain   [32]byte
	// Why the walk stopped below MirrorVersion; nil when the ref went whole.
	Stopped error
	// The Signed EvsReseed filed over Version, and why none was when SignReseed asked for one.
	Filed     bool
	FileError error
}

// One slot evs did not take.
type EvsReseedSlot struct {
	SlotId Id
	// evs's refusal, or nil for a slot no version this walk re-seeded names.
	Refused error
}

// What a re-seed did.
type EvsReseedResult struct {
	Refs []*EvsReseedRef
	// Segments sent, and slots evs took or dropped as wholly erased.
	SegmentCount int
	SlotCount    int
	// Slots evs did not take.
	Slots []*EvsReseedSlot
}

// Whether every ref went as far as the mirror holds it and every slot was taken.
func (self *EvsReseedResult) Whole() bool {
	for _, ref := range self.Refs {
		if ref.Stopped != nil || ref.FileError != nil {
			return false
		}
	}
	return len(self.Slots) == 0
}

// One walk.
type evsReseedRun struct {
	repo   *EvsRepo
	store  *EvsMirrorStore
	result *EvsReseedResult
	// by slot id in hex, the statement of the last re-seeded version that names the slot
	slotStatements map[string][]byte
}

// Re-seeds the repo from this device's mirror. See the file header. An error is the mirror's or the context's; what
// evs refused is in the result.
func (self *EvsRepo) Reseed(ctx context.Context, args *EvsReseedArgs) (*EvsReseedResult, error) {
	if args == nil {
		args = &EvsReseedArgs{}
	}
	store, err := self.client.Mirror(self.repoId)
	if err != nil {
		return nil, err
	}
	refs, err := store.Refs()
	if err != nil {
		return nil, err
	}
	erasureRefId := EvsErasureRefId(self.repoId)
	slices.SortFunc(refs, func(a *EvsMirrorRef, b *EvsMirrorRef) int {
		// the erasure ref first, then by id
		if (a.RefId == erasureRefId) != (b.RefId == erasureRefId) {
			if a.RefId == erasureRefId {
				return -1
			}
			return 1
		}
		return a.RefId.Cmp(b.RefId)
	})
	run := &evsReseedRun{repo: self, store: store, result: &EvsReseedResult{}, slotStatements: map[string][]byte{}}
	for _, ref := range refs {
		refResult := &EvsReseedRef{RefId: ref.RefId, MirrorVersion: ref.Version, Chain: EvsChainStart(self.repoId, ref.RefId)}
		run.result.Refs = append(run.result.Refs, refResult)
		refResult.Stopped = run.reseedRef(ctx, refResult)
		if err := ctx.Err(); err != nil {
			return run.result, err
		}
	}
	if err := run.reseedSlots(ctx); err != nil {
		return run.result, err
	}
	if args.SignReseed {
		for _, refResult := range run.result.Refs {
			if refResult.Version == 0 {
				continue
			}
			refResult.FileError = run.fileReseed(ctx, refResult, args.IncidentId)
			refResult.Filed = refResult.FileError == nil
			if err := ctx.Err(); err != nil {
				return run.result, err
			}
		}
	}
	return run.result, nil
}

// What the mirror holds under key, ErrEvsReseedMirrorPartial when it holds nothing there.
func (self *evsReseedRun) held(key EvsMirrorKey) ([]byte, error) {
	reader, err := self.store.Open(key)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		name, _ := key.Name()
		return nil, fmt.Errorf("%w: no %s", ErrEvsReseedMirrorPartial, name)
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// One reseed call, the same bytes until evs answers anything but a 429, a 503 or nothing.
func (self *evsReseedRun) post(ctx context.Context, request *protocol.EvsReseedRequest) (*protocol.EvsPushReply, error) {
	repo := self.repo
	call := &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/reseed",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(repo.repoId) + "/reseed",
		repoId: repo.repoId,
		role:   evsScopeAdmin,
		body:   request,
	}
	reply := &protocol.EvsPushReply{}
	err := repo.client.retryRefusingNothing(ctx, func() error {
		reply = &protocol.EvsPushReply{}
		return repo.client.http.callMessage(ctx, call, reply)
	})
	if err != nil {
		return nil, err
	}
	return reply, nil
}

// The ref's versions from 1 through the mirror's, in order, raising ref's version and chain with each evs holds. The
// answer is why the walk stopped short, nil when it did not.
func (self *evsReseedRun) reseedRef(ctx context.Context, ref *EvsReseedRef) error {
	for version := uint64(1); version <= ref.MirrorVersion; version += 1 {
		if err := ctx.Err(); err != nil {
			return err
		}
		statementBytes, err := self.held(EvsMirrorStatementKey(ref.RefId, version))
		if err != nil {
			return err
		}
		statement, err := ParseEvsStatement(statementBytes)
		if err != nil {
			return err
		}
		push := statement.Push
		if !bytes.Equal(push.GetRepoId(), self.repo.repoId.Bytes()) || !bytes.Equal(push.GetRefId(), ref.RefId.Bytes()) {
			return fmt.Errorf("%w: a statement of another ref at version %d", ErrEvsMirrorRecordInvalid, version)
		}
		if 0 < push.GetPartCount() {
			return fmt.Errorf("%w: version %d", ErrEvsReseedParts, version)
		}
		pushId, err := IdFromBytes(push.GetPushId())
		if err != nil {
			return err
		}
		recordBytes, err := self.held(EvsMirrorRecordKey(pushId, 0))
		if err != nil {
			return err
		}
		checked, err := evsMirrorCheckRecords(statement, [][]byte{recordBytes})
		if err != nil {
			return err
		}
		record, err := ParseEvsBatchRecord(recordBytes)
		if err != nil {
			return err
		}
		_, payloadBytes, err := ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return err
		}
		for _, object := range checked.NewObjects {
			if object.Kind != protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT {
				continue
			}
			if err := self.sendSegment(ctx, object.Id, pushId); err != nil {
				return err
			}
		}
		reply, err := self.post(ctx, &protocol.EvsReseedRequest{Statement: statementBytes, Payload: payloadBytes})
		if err != nil {
			return err
		}
		if reply.GetVersion() != version {
			return fmt.Errorf("%w: %d, held at %d", ErrEvsReseedVersion, reply.GetVersion(), version)
		}
		ref.Version = version
		ref.Chain = EvsChainNext(ref.Chain, pushId, statement.Sha256)
		self.noteSlots(statementBytes, checked)
	}
	return nil
}

// One segment from the mirror's seg/ to evs, under the push that introduces it. evs answers a segment it already holds
// as it answers a new one.
func (self *evsReseedRun) sendSegment(ctx context.Context, segmentId []byte, pushId Id) error {
	body, err := self.held(EvsMirrorSegmentKey(segmentId))
	if err != nil {
		return err
	}
	repo := self.repo
	call := &evsCall{
		route:   "PUT /evs/v1/repos/{repo_id}/segments/{segment_id}",
		method:  http.MethodPut,
		path:    "/evs/v1/repos/" + evsUrlId(repo.repoId) + "/segments/" + hex.EncodeToString(segmentId) + "?push=" + evsUrlId(pushId),
		repoId:  repo.repoId,
		role:    evsScopeAdmin,
		rawBody: body,
	}
	receipt := &protocol.EvsUploadReceipt{}
	if err := repo.client.retryRefusingNothing(ctx, func() error { return repo.client.http.callMessage(ctx, call, receipt) }); err != nil {
		return err
	}
	self.result.SegmentCount += 1
	return nil
}

// The slots a re-seeded version names: those its new-objects section introduces and those its entry versions name.
func (self *evsReseedRun) noteSlots(statementBytes []byte, checked *EvsCheckedPayload) {
	for _, object := range checked.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
			self.slotStatements[hex.EncodeToString(object.Id)] = statementBytes
		}
	}
	for _, change := range checked.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			continue
		}
		for _, slotId := range entry.GetSlotIds() {
			self.slotStatements[hex.EncodeToString(slotId)] = statementBytes
		}
	}
}

// Every slot the mirror holds, after every ref's history. A slot no re-seeded version names is not sent, since evs
// takes none without one, and is reported; so is one evs refuses.
func (self *evsReseedRun) reseedSlots(ctx context.Context) error {
	keys, err := self.store.List(EvsMirrorSlots, nil)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		slotId, err := IdFromBytes(key.ObjectId)
		if err != nil {
			continue
		}
		statementBytes := self.slotStatements[hex.EncodeToString(key.ObjectId)]
		if statementBytes == nil {
			self.result.Slots = append(self.result.Slots, &EvsReseedSlot{SlotId: slotId})
			continue
		}
		slotBytes, err := self.held(key)
		if err != nil {
			return err
		}
		if _, err := self.post(ctx, &protocol.EvsReseedRequest{Statement: statementBytes, SlotId: slotId.Bytes(), Slot: slotBytes}); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			self.result.Slots = append(self.result.Slots, &EvsReseedSlot{SlotId: slotId, Refused: err})
			continue
		}
		self.result.SlotCount += 1
	}
	return nil
}

// Signs and files the EvsReseed over ref's re-seeded head.
func (self *evsReseedRun) fileReseed(ctx context.Context, ref *EvsReseedRef, incidentId []byte) error {
	client := self.repo.client
	signedBytes, err := SignEvsReseed(client.args.Sign, self.repo.repoId, ref.RefId, ref.Version, ref.Chain, incidentId)
	if err != nil {
		return err
	}
	reply, err := self.post(ctx, &protocol.EvsReseedRequest{Statement: signedBytes})
	if err != nil {
		return err
	}
	if reply.GetVersion() != ref.Version {
		return fmt.Errorf("%w: a reseed filed at %d, signed over %d", ErrEvsReseedVersion, reply.GetVersion(), ref.Version)
	}
	return nil
}
