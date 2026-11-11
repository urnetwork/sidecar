// A full mirror of one repo (§11.13's durability rows, D-EVS-17, R-EVS-17, owner decisions 90, 94, 150; EVSB-M2-19):
// every record and object a committed push names, held in the repo's sealed mirror (evs_mirror_layout.go) as the
// customer's own copy, since no operator copy of the file clusters exists and slots live only on the cluster and here
// (owner decision 90). A site loss is recovered from mirrors by §19.10's re-seed (evs_reseed.go).
//
// What a sync holds, per ref of the repo, through the head evs answers:
//
//	stmt   each version's Signed EvsPush, walked from the mirror's last version and chain to the head as a replaying
//	       reader walks them (EvsVerifier), so a mirror never holds a statement that does not chain
//	rec    the push's record, part 0, and for a push in parts its seal record and every part record, each held to
//	       its statement (§11.6's checks row)
//	seg    every segment a push's new-objects section names, its SHA-256 its id
//	slot   every slot a push's new-objects section names, as the wrapped bytes evs holds (fek-wrapped or
//	       drop-HPKE): the mirror never opens a slot
//	pmap   a PATH_EPOCH push's map parts, held to its path_map_sha256
//	keys   each generation a push names, asked of GkmClient, whose keychain holds the RK ladder (§10.5); the mirror
//	       keeps no key of its own
//
// ERASE first (§11.12's after row, §11.13's erasure row): the repo's erasure ref is synced before any other ref, and
// each ERASE the mirror takes removes the slot copies it covers before the next ref's objects are read, so no stale
// slot copy is held past the sync that saw its ERASE. evs strips the erased keys from its own slot (QD-096), and a
// removed copy is read again from evs at the end of the sync: the stripped slot replaces it, and a slot evs no longer
// holds because every key in it was erased counts as erased, not missing. The device that signs an ERASE keeps it
// (§19.10's 30-day window) by mirroring the erasure ref like any other.
//
// The mirror moves only forward: a head below the version it holds, or the same version on another chain, is evs's
// lie, alarmed and kept out (I-16). A ref is raised to the last version whose every named object is held; an object
// evs answers missing stays named in the mirror's state, which coverage reports (evs_mirror_coverage.go). A hash
// check (Check) rereads everything held, so a mirror that rotted on disk is reported partial.
//
// Bulk state stays on disk (QD-641): objects stream from evs's reply spills into the sealed store, and the state file
// names at most MissingNameCount missing objects, counting the rest. M10 adds a versionless path's newest-version rule
// and a drop's statement-only rule (EVS2-M10-13); format-2 batch records answer ErrEvsFormatUnsupported here until
// then. Safe for concurrent use: one sync or check runs at a time per mirror.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The mirror's own state beside its families, under mirror/<repo>/: a name no family's key gives, so a listing of the
// families never shows it, and Forget takes it with them.
const evsMirrorStateName = "state"

var (
	// A head evs answered below the version the mirror holds, or at it on another chain: the mirror keeps what it holds.
	ErrEvsMirrorHeadLower = errors.New("evs: a head below the mirror")
	// A record evs served that does not hold the statement the mirror verified.
	ErrEvsMirrorRecordInvalid = errors.New("evs: a mirrored record of another statement")
)

type EvsMirrorSettings struct {
	// §11.13's status row: a ref counts as mirrored while the mirror holds its head, or lacks only versions younger
	// than this. 1 h. Positive.
	HeadLag time.Duration
	// §11.13's status row: full coverage needs a hash check this recent. 7 days. Positive.
	CheckMaxAge time.Duration
	// §11.9's request bounds, as evs holds a read to them: push records, slots and map parts one read names, 64; the
	// segment ranges one read names, 64, and their bytes, 32 MiB. Positive.
	ReadObjectCount    int
	ReadRangeCount     int
	ReadRangeByteCount int64
	// The missing objects the state names, the rest only counted. 256. Positive.
	MissingNameCount int
}

func DefaultEvsMirrorSettings() *EvsMirrorSettings {
	return &EvsMirrorSettings{
		HeadLag:            1 * time.Hour,
		CheckMaxAge:        7 * 24 * time.Hour,
		ReadObjectCount:    EvsReadMaxPathCount,
		ReadRangeCount:     EvsReadMaxRangeCount,
		ReadRangeByteCount: EvsReadMaxRangeByteCount,
		MissingNameCount:   256,
	}
}

// One repo's full mirror on this device.
type EvsMirror struct {
	client   *EvsClient
	repoId   Id
	store    *EvsMirrorStore
	settings *EvsMirrorSettings

	// one sync or check at a time, so two never race a ref's raise or the state file
	runLock sync.Mutex
}

// The full mirror of repoId on this client's store. settings nil takes the defaults. Nothing is read or written until
// a sync.
func NewEvsMirror(client *EvsClient, repoId Id, settings *EvsMirrorSettings) (*EvsMirror, error) {
	if settings == nil {
		settings = DefaultEvsMirrorSettings()
	}
	switch {
	case settings.HeadLag <= 0 || settings.CheckMaxAge <= 0:
		return nil, fmt.Errorf("%w: a mirror's lag and check age are positive", errInvalidSettings)
	case settings.ReadObjectCount <= 0 || settings.ReadRangeCount <= 0 || settings.ReadRangeByteCount <= 0 || settings.MissingNameCount <= 0:
		return nil, fmt.Errorf("%w: a mirror's read bounds are positive", errInvalidSettings)
	}
	store, err := client.Mirror(repoId)
	if err != nil {
		return nil, err
	}
	return &EvsMirror{client: client, repoId: repoId, store: store, settings: settings}, nil
}

// The repo mirrored.
func (self *EvsMirror) RepoId() Id {
	return self.repoId
}

// The sealed objects the mirror holds.
func (self *EvsMirror) Store() *EvsMirrorStore {
	return self.store
}

// An object a push names that evs did not serve, as the state keeps it.
type EvsMirrorMissing struct {
	Family EvsMirrorFamily `json:"family"`
	// The object's key as its family names it (EvsMirrorKey.Name).
	Name string `json:"name"`
	// The ref and version whose push names it.
	RefId   Id     `json:"ref_id"`
	Version uint64 `json:"version"`
}

// One ref as the mirror's state keeps it, beside its refs/ record.
type EvsMirrorRefState struct {
	RefId Id `json:"ref_id"`
	// The newest head evs answered and the mirror verified, which the mirror may hold only part of.
	HeadVersion uint64 `json:"head_version"`
	// The time of the first version past what the mirror holds, the oldest it lacks; 0 when it holds the head.
	FirstMissingMs int64 `json:"first_missing_ms,omitempty"`
	// A head evs answered below the mirror, or forking from it, which the mirror kept out (I-16).
	Lower bool `json:"lower,omitempty"`
}

// What the mirror keeps beside its families: what the last sync and check found.
type evsMirrorState struct {
	SyncedMs  int64                `json:"synced_ms,omitempty"`
	CheckedMs int64                `json:"checked_ms,omitempty"`
	Refs      []*EvsMirrorRefState `json:"refs,omitempty"`
	// The objects pushes name that evs did not serve, at most MissingNameCount of them, and how many in all.
	Missing      []*EvsMirrorMissing `json:"missing,omitempty"`
	MissingCount int                 `json:"missing_count,omitempty"`
	// Slots an applied ERASE emptied, which evs holds no more and coverage does not count missing.
	ErasedSlotIds []string `json:"erased_slot_ids,omitempty"`
	// The erasure ref's newest version whose ERASE the mirror applied.
	ErasedThrough uint64 `json:"erased_through,omitempty"`
	// Slot copies an ERASE removed that a sync has not read again from evs.
	StaleSlotIds []string `json:"stale_slot_ids,omitempty"`
	// What the last hash check found wrong, by object name.
	CheckFailures []string `json:"check_failures,omitempty"`
	// Generations a push names whose key gkm did not give.
	KeyGenerationsMissing []uint64 `json:"key_generations_missing,omitempty"`
}

func (self *EvsMirror) loadState() (*evsMirrorState, error) {
	state := &evsMirrorState{}
	reader, err := self.store.store.Open(evsMirrorStateName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("%w: a mirror's state that does not parse", ErrSidecarStoreFailed)
	}
	return state, nil
}

func (self *EvsMirror) saveState(state *evsMirrorState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	writer, err := self.store.store.Create(evsMirrorStateName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// What one sync did.
type EvsMirrorSyncResult struct {
	// Versions newly held, over every ref.
	VersionCount int
	// Objects newly held: records, segments, slots and map parts.
	ObjectCount int
	// ERASEs applied, and the slot copies they removed.
	ErasureCount     int
	RemovedSlotCount int
	// Objects a push names that evs did not serve.
	MissingCount int
	// Refs whose head evs answered below the mirror, kept out.
	LowerRefIds []Id
}

// The missing objects this sync found, deduplicated by family and name.
type evsMirrorMissingSet struct {
	limit    int
	named    []*EvsMirrorMissing
	nameSet  map[string]bool
	count    int
	erasedOk map[string]bool
}

func (self *evsMirrorMissingSet) add(missing *EvsMirrorMissing) {
	key := string(missing.Family) + "/" + missing.Name
	if self.nameSet[key] {
		return
	}
	self.nameSet[key] = true
	self.count += 1
	if len(self.named) < self.limit {
		self.named = append(self.named, missing)
	}
}

// Brings the mirror to the head of every ref evs lists: the erasure ref and its ERASEs first, then every other ref,
// then the slots an ERASE emptied read again. A ref whose head evs answers below the mirror is alarmed and kept as it
// is. Answers what changed; an error leaves what was held and the state of the last whole sync.
func (self *EvsMirror) Sync(ctx context.Context) (*EvsMirrorSyncResult, error) {
	self.runLock.Lock()
	defer self.runLock.Unlock()
	state, err := self.loadState()
	if err != nil {
		return nil, err
	}
	heads, err := self.listHeads(ctx)
	if err != nil {
		return nil, err
	}
	result := &EvsMirrorSyncResult{}
	missing := &evsMirrorMissingSet{limit: self.settings.MissingNameCount, nameSet: map[string]bool{}, erasedOk: map[string]bool{}}
	erasedSlotIds := map[string]bool{}
	for _, slotId := range state.ErasedSlotIds {
		erasedSlotIds[slotId] = true
	}
	staleSlotIds := map[string]bool{}
	for _, slotId := range state.StaleSlotIds {
		staleSlotIds[slotId] = true
	}
	keyGenerations := map[uint64]bool{}
	run := &evsMirrorRun{
		mirror:         self,
		result:         result,
		missing:        missing,
		erasedSlotIds:  erasedSlotIds,
		staleSlotIds:   staleSlotIds,
		keyGenerations: keyGenerations,
		erasedThrough:  state.ErasedThrough,
	}
	refStates := []*EvsMirrorRefState{}
	for _, head := range heads {
		refState, err := run.syncRef(ctx, head)
		if err != nil {
			return nil, err
		}
		refStates = append(refStates, refState)
	}
	if err := run.rereadStaleSlots(ctx); err != nil {
		return nil, err
	}
	state.SyncedMs = self.client.clock.Now().UnixMilli()
	state.Refs = refStates
	state.Missing = missing.named
	state.MissingCount = missing.count
	state.ErasedThrough = run.erasedThrough
	state.ErasedSlotIds = evsMirrorSortedKeys(erasedSlotIds)
	state.StaleSlotIds = evsMirrorSortedKeys(staleSlotIds)
	state.KeyGenerationsMissing = nil
	for generation, held := range keyGenerations {
		if !held {
			state.KeyGenerationsMissing = append(state.KeyGenerationsMissing, generation)
		}
	}
	slices.Sort(state.KeyGenerationsMissing)
	result.MissingCount = missing.count
	if err := self.saveState(state); err != nil {
		return nil, err
	}
	return result, nil
}

func evsMirrorSortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key, ok := range set {
		if ok {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	return keys
}

// Every ref evs lists for the repo, the erasure ref first, then by ref id, so ERASEs apply before any other ref's
// slots are read.
func (self *EvsMirror) listHeads(ctx context.Context) ([]*protocol.EvsHeadSummary, error) {
	reply := &protocol.EvsRefsReply{}
	err := self.client.http.callMessage(ctx, &evsCall{
		route:  "GET /evs/v1/repos/{repo_id}/refs",
		method: http.MethodGet,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/refs",
		repoId: self.repoId,
		role:   evsScopeRead,
		retry:  true,
	}, reply)
	if err != nil {
		return nil, err
	}
	if reply.GetFormat() == 2 {
		return nil, fmt.Errorf("%w: a format-2 repo's mirror is M10's", ErrEvsFormatUnsupported)
	}
	erasureRefId := EvsErasureRefId(self.repoId)
	heads := []*protocol.EvsHeadSummary{}
	for _, head := range reply.GetRefs() {
		if _, err := IdFromBytes(head.GetRefId()); err != nil {
			return nil, fmt.Errorf("%w: a listed ref's id", ErrEvsReplyInvalid)
		}
		heads = append(heads, head)
	}
	rank := func(head *protocol.EvsHeadSummary) int {
		if bytes.Equal(head.GetRefId(), erasureRefId.Bytes()) {
			return 0
		}
		return 1
	}
	sort.SliceStable(heads, func(i int, j int) bool {
		if rank(heads[i]) != rank(heads[j]) {
			return rank(heads[i]) < rank(heads[j])
		}
		return bytes.Compare(heads[i].GetRefId(), heads[j].GetRefId()) < 0
	})
	return heads, nil
}

// One sync's work across refs.
type evsMirrorRun struct {
	mirror  *EvsMirror
	result  *EvsMirrorSyncResult
	missing *evsMirrorMissingSet
	// slot ids, hex, an applied ERASE emptied, and those whose copy it removed to be read again
	erasedSlotIds  map[string]bool
	staleSlotIds   map[string]bool
	keyGenerations map[uint64]bool
	erasedThrough  uint64
}

// One ref to its head: the statements past what the mirror holds, walked and verified, then each version's objects,
// the ref raised to the last version held whole.
func (self *evsMirrorRun) syncRef(ctx context.Context, summary *protocol.EvsHeadSummary) (*EvsMirrorRefState, error) {
	mirror := self.mirror
	client := mirror.client
	refId, _ := IdFromBytes(summary.GetRefId())
	refState := &EvsMirrorRefState{RefId: refId, HeadVersion: summary.GetVersion()}
	headChain, err := EvsChainFromBytes(summary.GetChain())
	if err != nil {
		return nil, fmt.Errorf("%w: a listed head's chain", ErrEvsReplyInvalid)
	}
	held, ok, err := mirror.store.Ref(refId)
	if err != nil {
		return nil, err
	}
	fromVersion, fromChain := uint64(0), EvsChainStart(mirror.repoId, refId)
	if ok {
		fromVersion, fromChain = held.Version, held.Chain
	}
	switch {
	case summary.GetVersion() < fromVersion, summary.GetVersion() == fromVersion && headChain != fromChain:
		client.verifier.alarmFork(mirror.repoId, refId, &EvsPin{RepoId: mirror.repoId, RefId: refId, Version: fromVersion, Chain: fromChain}, summary.GetVersion(), headChain)
		refState.Lower = true
		self.result.LowerRefIds = append(self.result.LowerRefIds, refId)
		return refState, nil
	case summary.GetVersion() == fromVersion:
		// the head held: only the time moves
		return refState, mirror.store.RaiseRef(&EvsMirrorRef{RefId: refId, Version: fromVersion, Chain: fromChain, MirroredAt: client.clock.Now()})
	}
	// this device's own pin holds the head too: a head below it is a fork the reader already alarms
	if err := client.verifier.checkPin(mirror.repoId, refId, summary.GetVersion(), headChain); err != nil {
		return nil, err
	}
	statements, err := client.readLog(ctx, mirror.repoId, refId, fromVersion+1, summary.GetVersion())
	if err != nil {
		return nil, err
	}
	walked, err := client.verifier.walk(mirror.repoId, refId, fromVersion, fromChain, statements, summary.GetVersion())
	if err != nil {
		return nil, err
	}
	if len(walked) == 0 || walked[len(walked)-1].Version != summary.GetVersion() || walked[len(walked)-1].Chain != headChain {
		return nil, fmt.Errorf("%w: the log does not chain to the head", ErrEvsChainBroken)
	}
	head := &EvsVerifiedHead{RepoId: mirror.repoId, RefId: refId, Head: summary, Version: summary.GetVersion(), Chain: headChain, Statements: walked, FromVersion: fromVersion}
	raised := false
	for _, statement := range walked {
		whole, err := self.mirrorVersion(ctx, head, statement)
		if err != nil {
			return nil, err
		}
		if !whole {
			if refState.FirstMissingMs == 0 {
				refState.FirstMissingMs = statement.Statement.Push.GetTimeMs()
			}
			continue
		}
		if refState.FirstMissingMs != 0 {
			// a version past a hole is held, and the ref stays below the hole
			continue
		}
		if err := mirror.store.RaiseRef(&EvsMirrorRef{RefId: refId, Version: statement.Version, Chain: statement.Chain, MirroredAt: client.clock.Now()}); err != nil {
			return nil, err
		}
		raised = true
	}
	if raised && refState.FirstMissingMs == 0 {
		if err := client.verifier.Pin(head); err != nil {
			return nil, err
		}
	}
	return refState, nil
}

// One version's statement and every object its push names, put into the mirror; false when evs did not serve one,
// which is named missing.
func (self *evsMirrorRun) mirrorVersion(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (bool, error) {
	mirror := self.mirror
	push := statement.Statement.Push
	refId := head.RefId
	if err := mirror.store.Put(EvsMirrorStatementKey(refId, statement.Version), bytes.NewReader(statement.Statement.Bytes)); err != nil {
		return false, err
	}
	self.result.VersionCount += 1
	self.noteGeneration(ctx, push.GetGeneration())
	checked, whole, err := self.mirrorRecords(ctx, head, statement)
	if err != nil || !whole {
		return whole, err
	}
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) != 0 && refId == EvsErasureRefId(mirror.repoId) {
		if err := self.applyErasure(statement, checked); err != nil {
			return false, err
		}
	}
	segments := []*EvsNewObject{}
	slotIds := [][]byte{}
	for _, object := range checked.NewObjects {
		switch object.Kind {
		case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT:
			segments = append(segments, object)
		case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT:
			slotIds = append(slotIds, object.Id)
		default:
			return false, fmt.Errorf("%w: new object kind %d", ErrEvsFormatUnsupported, object.Kind)
		}
	}
	segmentsWhole, err := self.mirrorSegments(ctx, head, statement, segments)
	if err != nil {
		return false, err
	}
	slotsWhole, err := self.mirrorSlots(ctx, head, statement, slotIds)
	if err != nil {
		return false, err
	}
	mapWhole := true
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 && 0 < len(push.GetPathMapSha256()) {
		mapWhole, err = self.mirrorMap(ctx, head, statement)
		if err != nil {
			return false, err
		}
	}
	return segmentsWhole && slotsWhole && mapWhole, nil
}

// Asks gkm for a generation's key, which its keychain keeps as the RK ladder; the mirror keeps no key itself.
func (self *evsMirrorRun) noteGeneration(ctx context.Context, generation uint64) {
	if generation == 0 {
		return
	}
	if _, asked := self.keyGenerations[generation]; asked {
		return
	}
	_, err := self.mirror.client.args.Gkm.RepoKey(ctx, self.mirror.repoId, generation)
	self.keyGenerations[generation] = err == nil
}

// The push's records, read from evs and held to the statement: part 0, and for a push in parts its seal and each part,
// then its payload checked whole. A record evs serves that holds another statement fails the sync; one it does not
// serve is named missing.
func (self *evsMirrorRun) mirrorRecords(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (*EvsCheckedPayload, bool, error) {
	mirror := self.mirror
	push := statement.Statement.Push
	pushId, err := IdFromBytes(push.GetPushId())
	if err != nil {
		return nil, false, fmt.Errorf("%w: a push id", ErrEvsReplyInvalid)
	}
	partCount := push.GetPartCount()
	records := make([][]byte, partCount+1)
	whole := true
	for start := uint32(0); start <= partCount; start += uint32(mirror.settings.ReadObjectCount) {
		end := min(partCount, start+uint32(mirror.settings.ReadObjectCount)-1)
		parts := []uint32{}
		for part := start; part <= end; part += 1 {
			key := EvsMirrorRecordKey(pushId, part)
			held, err := self.heldBytes(key)
			if err != nil {
				return nil, false, err
			}
			if held != nil {
				records[part] = held
				continue
			}
			parts = append(parts, part)
		}
		if len(parts) == 0 {
			continue
		}
		request := &protocol.EvsReadRequest{RefId: head.RefId.Bytes(), PinVersion: head.Version}
		for _, part := range parts {
			request.Pushes = append(request.Pushes, &protocol.EvsReadPush{PushId: pushId.Bytes(), Version: statement.Version, Part: part})
		}
		if err := func() error {
			_, objects, err := mirror.client.postRead(ctx, mirror.repoId, request)
			if err != nil {
				return err
			}
			defer objects.close()
			for key, spill := range objects.objects {
				if key.kind != protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD || key.id != hex.EncodeToString(pushId.Bytes()) || uint64(partCount) < key.number {
					continue
				}
				recordBytes, err := io.ReadAll(spill.reader())
				if err != nil {
					return err
				}
				records[key.number] = recordBytes
			}
			return nil
		}(); err != nil {
			return nil, false, err
		}
		for _, part := range parts {
			if records[part] == nil {
				name, _ := EvsMirrorRecordKey(pushId, part).Name()
				self.missing.add(&EvsMirrorMissing{Family: EvsMirrorRecords, Name: name, RefId: head.RefId, Version: statement.Version})
				whole = false
			}
		}
	}
	if !whole {
		return nil, false, nil
	}
	checked, err := evsMirrorCheckRecords(statement.Statement, records)
	if err != nil {
		return nil, false, err
	}
	for part, recordBytes := range records {
		if err := mirror.store.Put(EvsMirrorRecordKey(pushId, uint32(part)), bytes.NewReader(recordBytes)); err != nil {
			return nil, false, err
		}
		self.result.ObjectCount += 1
	}
	return checked, true, nil
}

// A push's records held to its statement: part 0 a push record holding the statement and its payload, or for a push
// in parts a seal record holding the statement and parts 1 to n each a part record of it, the parts' payload checked
// as its stored seal is.
func evsMirrorCheckRecords(statement *EvsStatement, records [][]byte) (*EvsCheckedPayload, error) {
	first, err := ParseEvsBatchRecord(records[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsMirrorRecordInvalid, err)
	}
	if len(records) == 1 {
		if first.Type != protocol.EvsBatchRecordType_EVS_BATCH_PUSH && first.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED {
			return nil, fmt.Errorf("%w: a one-part push's record of type %d", ErrEvsMirrorRecordInvalid, first.Type)
		}
		statementBytes, payload, err := ParseEvsPushRecordBody(first.Body)
		if err != nil || !bytes.Equal(statementBytes, statement.Bytes) {
			return nil, ErrEvsMirrorRecordInvalid
		}
		return EvsCheckPayload(statement, payload)
	}
	if first.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
		return nil, fmt.Errorf("%w: a sealed push's part 0 of type %d", ErrEvsMirrorRecordInvalid, first.Type)
	}
	statementBytes, _, err := ParseEvsSealRecordBody(first.Body)
	if err != nil || !bytes.Equal(statementBytes, statement.Bytes) {
		return nil, ErrEvsMirrorRecordInvalid
	}
	parts := make([][]byte, len(records)-1)
	for index, recordBytes := range records[1:] {
		record, err := ParseEvsBatchRecord(recordBytes)
		if err != nil || record.Type != protocol.EvsBatchRecordType_EVS_BATCH_PART {
			return nil, ErrEvsMirrorRecordInvalid
		}
		partStatement, partBytes, _, _, err := ParseEvsPartRecordBody(record.Body)
		if err != nil || !bytes.Equal(partStatement, statement.Bytes) {
			return nil, ErrEvsMirrorRecordInvalid
		}
		parts[index] = partBytes
	}
	checked, _, err := EvsCheckStoredSeal(statement, parts)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsMirrorRecordInvalid, err)
	}
	return checked, nil
}

// What the mirror holds under key, nil when it holds nothing there.
func (self *evsMirrorRun) heldBytes(key EvsMirrorKey) ([]byte, error) {
	reader, err := self.mirror.store.Open(key)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// The segments a push introduced that the mirror lacks, read whole by ranges in rounds within §11.9's bounds, each put
// under its SHA-256, which the store checks is its id.
func (self *evsMirrorRun) mirrorSegments(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement, segments []*EvsNewObject) (bool, error) {
	mirror := self.mirror
	needed := []*EvsNewObject{}
	for _, segment := range segments {
		held, err := mirror.store.Has(EvsMirrorSegmentKey(segment.Id))
		if err != nil {
			return false, err
		}
		if !held {
			needed = append(needed, segment)
		}
	}
	whole := true
	for 0 < len(needed) {
		round := []*EvsNewObject{}
		byteCount := int64(0)
		for len(needed) > 0 && len(round) < mirror.settings.ReadRangeCount {
			size := int64(needed[0].PaddedSize)
			if 0 < len(round) && mirror.settings.ReadRangeByteCount < byteCount+size {
				break
			}
			round = append(round, needed[0])
			byteCount += size
			needed = needed[1:]
		}
		request := &protocol.EvsReadRequest{RefId: head.RefId.Bytes(), PinVersion: head.Version}
		for _, segment := range round {
			request.Ranges = append(request.Ranges, &protocol.EvsReadRange{SegmentId: segment.Id, Offset: 0, Length: uint32(segment.PaddedSize)})
		}
		served := map[string]bool{}
		if err := func() error {
			_, objects, err := mirror.client.postRead(ctx, mirror.repoId, request)
			if err != nil {
				return err
			}
			defer objects.close()
			for key, spill := range objects.objects {
				if key.kind != protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT || key.offset != 0 {
					continue
				}
				segmentId, err := hex.DecodeString(key.id)
				if err != nil {
					continue
				}
				if err := mirror.store.Put(EvsMirrorSegmentKey(segmentId), spill.reader()); err != nil {
					// a segment whose bytes are not its id is evs's lie: it stays missing
					if errors.Is(err, ErrEvsMirrorObjectInvalid) {
						continue
					}
					return err
				}
				served[key.id] = true
				self.result.ObjectCount += 1
			}
			return nil
		}(); err != nil {
			return false, err
		}
		for _, segment := range round {
			if !served[hex.EncodeToString(segment.Id)] {
				name, _ := EvsMirrorSegmentKey(segment.Id).Name()
				self.missing.add(&EvsMirrorMissing{Family: EvsMirrorSegments, Name: name, RefId: head.RefId, Version: statement.Version})
				whole = false
			}
		}
	}
	return whole, nil
}

// The slots a push introduced that the mirror lacks, read in rounds and put as evs holds them. A slot an applied
// ERASE emptied that evs no longer holds is erased, not missing.
func (self *evsMirrorRun) mirrorSlots(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement, slotIds [][]byte) (bool, error) {
	mirror := self.mirror
	needed := [][]byte{}
	for _, slotId := range slotIds {
		// an emptied slot, or one an ERASE this sync took, which the sync's end reads again from evs
		if self.erasedSlotIds[hex.EncodeToString(slotId)] || self.staleSlotIds[hex.EncodeToString(slotId)] {
			continue
		}
		held, err := mirror.store.Has(EvsMirrorSlotKey(slotId))
		if err != nil {
			return false, err
		}
		if !held {
			needed = append(needed, slotId)
		}
	}
	served, err := self.readSlots(ctx, head.RefId, head.Version, needed)
	if err != nil {
		return false, err
	}
	whole := true
	for _, slotId := range needed {
		if !served[hex.EncodeToString(slotId)] {
			name, _ := EvsMirrorSlotKey(slotId).Name()
			self.missing.add(&EvsMirrorMissing{Family: EvsMirrorSlots, Name: name, RefId: head.RefId, Version: statement.Version})
			whole = false
		}
	}
	return whole, nil
}

// Reads slotIds from evs in rounds on refId's read and puts each served one, answering the hex ids served. A slot
// evs answers missing is left out.
func (self *evsMirrorRun) readSlots(ctx context.Context, refId Id, pinVersion uint64, slotIds [][]byte) (map[string]bool, error) {
	mirror := self.mirror
	served := map[string]bool{}
	for start := 0; start < len(slotIds); start += mirror.settings.ReadObjectCount {
		round := slotIds[start:min(len(slotIds), start+mirror.settings.ReadObjectCount)]
		request := &protocol.EvsReadRequest{RefId: refId.Bytes(), PinVersion: pinVersion}
		for _, slotId := range round {
			request.SlotIds = append(request.SlotIds, slotId)
		}
		if err := func() error {
			_, objects, err := mirror.client.postRead(ctx, mirror.repoId, request)
			if err != nil {
				return err
			}
			defer objects.close()
			for key, spill := range objects.objects {
				if key.kind != protocol.EvsReadObjectKind_EVS_READ_OBJECT_SLOT {
					continue
				}
				slotId, err := hex.DecodeString(key.id)
				if err != nil || len(slotId) != 16 {
					continue
				}
				if spill.Size() == 0 {
					continue
				}
				if err := mirror.store.Put(EvsMirrorSlotKey(slotId), spill.reader()); err != nil {
					return err
				}
				served[key.id] = true
				self.result.ObjectCount += 1
			}
			return nil
		}(); err != nil {
			return nil, err
		}
	}
	return served, nil
}

// A PATH_EPOCH push's map: part 1 read first for its part count, then the rest in rounds, each put as received and
// the whole held to the statement's path_map_sha256. A part evs does not serve is named missing.
func (self *evsMirrorRun) mirrorMap(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (bool, error) {
	mirror := self.mirror
	push := statement.Statement.Push
	mapSha256 := push.GetPathMapSha256()
	pathEpoch := push.GetPathEpoch()
	readParts := func(parts []uint32) (map[uint32][]byte, error) {
		request := &protocol.EvsReadRequest{RefId: head.RefId.Bytes(), PinVersion: head.Version}
		for _, part := range parts {
			request.Maps = append(request.Maps, &protocol.EvsReadMap{PathEpoch: pathEpoch, MapSha256: mapSha256, Part: part})
		}
		_, objects, err := mirror.client.postRead(ctx, mirror.repoId, request)
		if err != nil {
			return nil, err
		}
		defer objects.close()
		bodies := map[uint32][]byte{}
		for key, spill := range objects.objects {
			if key.kind != protocol.EvsReadObjectKind_EVS_READ_OBJECT_MAP_PART || key.id != hex.EncodeToString(mapSha256) {
				continue
			}
			body, err := io.ReadAll(spill.reader())
			if err != nil {
				return nil, err
			}
			bodies[uint32(key.number)] = body
		}
		return bodies, nil
	}
	missingPart := func(part uint32) {
		name, _ := EvsMirrorMapPartKey(head.RefId, pathEpoch, mapSha256, part).Name()
		self.missing.add(&EvsMirrorMissing{Family: EvsMirrorMapParts, Name: name, RefId: head.RefId, Version: statement.Version})
	}
	first, err := readParts([]uint32{1})
	if err != nil {
		return false, err
	}
	firstPart, ok := first[1]
	if !ok {
		missingPart(1)
		return false, nil
	}
	pathMap, err := evsMirrorParsePathMap(firstPart)
	if err != nil {
		return false, err
	}
	partCount := pathMap.GetParts()
	if partCount == 0 {
		return false, fmt.Errorf("%w: a path map of no parts", ErrEvsReplyInvalid)
	}
	bodies := map[uint32][]byte{1: firstPart}
	for start := uint32(2); start <= partCount; start += uint32(mirror.settings.ReadObjectCount) {
		parts := []uint32{}
		for part := start; part <= min(partCount, start+uint32(mirror.settings.ReadObjectCount)-1); part += 1 {
			parts = append(parts, part)
		}
		read, err := readParts(parts)
		if err != nil {
			return false, err
		}
		for part, body := range read {
			bodies[part] = body
		}
	}
	ordered := make([][]byte, partCount)
	whole := true
	for part := uint32(1); part <= partCount; part += 1 {
		body, ok := bodies[part]
		if !ok {
			missingPart(part)
			whole = false
			continue
		}
		ordered[part-1] = body
	}
	if !whole {
		return false, nil
	}
	if !bytes.Equal(EvsPathMapSha256(ordered), mapSha256) {
		return false, fmt.Errorf("%w: a path map that is not the one its statement names", ErrEvsReplyInvalid)
	}
	for part, body := range ordered {
		if err := mirror.store.Put(EvsMirrorMapPartKey(head.RefId, pathEpoch, mapSha256, uint32(part+1)), bytes.NewReader(body)); err != nil {
			return false, err
		}
		self.result.ObjectCount += 1
	}
	return true, nil
}

// An ERASE taken from the erasure ref (§11.12's after row): the slot copies of its erased keys removed, each to be
// read again from evs, which stripped them, by the end of this sync.
func (self *evsMirrorRun) applyErasure(statement *EvsVerifiedStatement, checked *EvsCheckedPayload) error {
	if statement.Version <= self.erasedThrough {
		return nil
	}
	for _, erased := range checked.Erased {
		slotId := erased.SlotId.Bytes()
		held, err := self.mirror.store.Has(EvsMirrorSlotKey(slotId))
		if err != nil {
			return err
		}
		if held {
			if err := self.mirror.store.Remove(EvsMirrorSlotKey(slotId)); err != nil {
				return err
			}
			self.result.RemovedSlotCount += 1
		}
		self.staleSlotIds[hex.EncodeToString(slotId)] = true
	}
	self.erasedThrough = statement.Version
	self.result.ErasureCount += 1
	return nil
}

// The slots an ERASE emptied, read again from evs on the erasure ref's read: a stripped slot replaces the copy; one
// evs no longer holds, every key in it erased, is erased.
func (self *evsMirrorRun) rereadStaleSlots(ctx context.Context) error {
	if len(self.staleSlotIds) == 0 {
		return nil
	}
	slotIds := [][]byte{}
	for slotIdHex := range self.staleSlotIds {
		slotId, err := hex.DecodeString(slotIdHex)
		if err == nil && len(slotId) == 16 {
			slotIds = append(slotIds, slotId)
		}
	}
	slices.SortFunc(slotIds, bytes.Compare)
	served, err := self.readSlots(ctx, EvsErasureRefId(self.mirror.repoId), 0, slotIds)
	if err != nil {
		return err
	}
	for _, slotId := range slotIds {
		slotIdHex := hex.EncodeToString(slotId)
		if !served[slotIdHex] {
			self.erasedSlotIds[slotIdHex] = true
		}
		delete(self.staleSlotIds, slotIdHex)
	}
	return nil
}

// A Signed EvsPathMap part's map, read without its signature, which the statement's path_map_sha256 binds.
func evsMirrorParsePathMap(part []byte) (*protocol.EvsPathMap, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(part, signed); err != nil {
		return nil, fmt.Errorf("%w: a path map part that does not parse", ErrEvsReplyInvalid)
	}
	pathMap := &protocol.EvsPathMap{}
	if err := proto.Unmarshal(signed.GetBody(), pathMap); err != nil {
		return nil, fmt.Errorf("%w: a path map part's body", ErrEvsReplyInvalid)
	}
	return pathMap, nil
}

// What one hash check found.
type EvsMirrorCheckResult struct {
	// Objects reread.
	ObjectCount int
	// What failed, by object name: a statement that does not chain, a record of another statement, a segment whose
	// bytes are not its id, a map that is not its statement's, a file whose seal fails.
	Failures []string
}

// Rereads everything the mirror holds (§11.13's status row's hash check): each ref's statements walked from C_0 to the
// version its refs/ record holds and held to that chain, each push's records held to its statement, each segment
// rehashed, each map rehashed against its statement. Records the check's time and failures, which coverage reads.
func (self *EvsMirror) Check(ctx context.Context) (*EvsMirrorCheckResult, error) {
	self.runLock.Lock()
	defer self.runLock.Unlock()
	state, err := self.loadState()
	if err != nil {
		return nil, err
	}
	result := &EvsMirrorCheckResult{}
	fail := func(name string, reason string) {
		result.Failures = append(result.Failures, name+": "+reason)
	}
	refs, err := self.store.Refs()
	if err != nil {
		return nil, err
	}
	checkedSegments := map[string]bool{}
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		statements := []*protocol.EvsReadStatement{}
		for version := uint64(1); version <= ref.Version; version += 1 {
			key := EvsMirrorStatementKey(ref.RefId, version)
			name, _ := key.Name()
			reader, err := self.store.Open(key)
			if errors.Is(err, ErrSidecarStoreAbsent) {
				fail(name, "absent")
				break
			}
			if err != nil {
				return nil, err
			}
			statementBytes, err := io.ReadAll(reader)
			reader.Close()
			result.ObjectCount += 1
			if err != nil {
				fail(name, err.Error())
				break
			}
			statements = append(statements, &protocol.EvsReadStatement{Version: version, Statement: statementBytes})
		}
		if len(statements) != int(ref.Version) {
			continue
		}
		walked, err := self.client.verifier.walk(self.repoId, ref.RefId, 0, EvsChainStart(self.repoId, ref.RefId), statements, ref.Version)
		refName := evsMirrorRefName(ref.RefId)
		if err != nil {
			fail(refName, err.Error())
			continue
		}
		if 0 < len(walked) && walked[len(walked)-1].Chain != ref.Chain {
			fail(refName, "the statements held do not chain to the version held")
			continue
		}
		for _, statement := range walked {
			push := statement.Statement.Push
			pushId, _ := IdFromBytes(push.GetPushId())
			records := [][]byte{}
			readable := true
			for part := uint32(0); part <= push.GetPartCount(); part += 1 {
				key := EvsMirrorRecordKey(pushId, part)
				name, _ := key.Name()
				recordBytes, err := self.readHeld(key)
				result.ObjectCount += 1
				if err != nil {
					fail(name, err.Error())
					readable = false
					break
				}
				records = append(records, recordBytes)
			}
			if !readable {
				continue
			}
			checked, err := evsMirrorCheckRecords(statement.Statement, records)
			if err != nil {
				name, _ := EvsMirrorRecordKey(pushId, 0).Name()
				fail(name, err.Error())
				continue
			}
			for _, object := range checked.NewObjects {
				if object.Kind != protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT || checkedSegments[hex.EncodeToString(object.Id)] {
					continue
				}
				checkedSegments[hex.EncodeToString(object.Id)] = true
				key := EvsMirrorSegmentKey(object.Id)
				name, _ := key.Name()
				segmentBytes, err := self.readHeld(key)
				result.ObjectCount += 1
				if err != nil {
					fail(name, err.Error())
					continue
				}
				if sum := sha256.Sum256(segmentBytes); !bytes.Equal(sum[:], object.Id) {
					fail(name, "its bytes are not its id")
				}
			}
			if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 && 0 < len(push.GetPathMapSha256()) {
				parts, err := self.store.List(EvsMirrorMapParts, &ref.RefId)
				if err != nil {
					return nil, err
				}
				ordered := [][]byte{}
				for _, key := range parts {
					if key.PathEpoch != push.GetPathEpoch() || !bytes.Equal(key.ObjectId, push.GetPathMapSha256()) {
						continue
					}
					body, err := self.readHeld(key)
					result.ObjectCount += 1
					if err != nil {
						name, _ := key.Name()
						fail(name, err.Error())
						continue
					}
					ordered = append(ordered, body)
				}
				if !bytes.Equal(EvsPathMapSha256(ordered), push.GetPathMapSha256()) {
					name, _ := EvsMirrorMapPartKey(ref.RefId, push.GetPathEpoch(), push.GetPathMapSha256(), 1).Name()
					fail(name, "the map held is not its statement's")
				}
			}
		}
	}
	slots, err := self.store.List(EvsMirrorSlots, nil)
	if err != nil {
		return nil, err
	}
	for _, key := range slots {
		name, _ := key.Name()
		if _, err := self.readHeld(key); err != nil {
			fail(name, err.Error())
		}
		result.ObjectCount += 1
	}
	state.CheckedMs = self.client.clock.Now().UnixMilli()
	state.CheckFailures = result.Failures
	if err := self.saveState(state); err != nil {
		return nil, err
	}
	return result, nil
}

// The whole of what the mirror holds under key, its seal checked to its end.
func (self *EvsMirror) readHeld(key EvsMirrorKey) ([]byte, error) {
	reader, err := self.store.Open(key)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
