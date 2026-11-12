//go:build !ios_extension

// RecordStreams over a network's EvsClient (RECORD-M3-12; D-EVS-10, D-EVS-11, R-EVS-11, D-MCP-6): the record's narrow
// surface of evs (record_seam.go) bound to real streams, deposit refs and the erasure ref, so the record's writer,
// reader, ingester, receipts and eraser reach evs with nothing of evs in their own code.
//
//	stream    a writer's stream is its owned ref ur/<sidecar_id as 32 lowercase hex>/record (plan-RECORD-stream-names#1,
//	          RecordStreamRefName), whose id is that name under K_ref, so a reader derives any writer's; a push is
//	          EvsRepo.BuildStreamPush and PostStreamPush (evs_stream_append.go), its entry files at the paths the caller
//	          names and its slot object the caller's rows; a push for another writer's stream is REF_MODE here, as evs
//	          answers another's owned ref, so no binding squats on a stream's id before its writer's first push
//	rows      a slot row is plaintext key || salt (RECORD.md section 5.2), which the row codec wraps under fek_g and
//	          opens; RECORD.md's 64 B rows have no slot format yet, since evs holds only 72 B wrapped 32 B keys
//	          (question record-m2-01-slot-row-salt), so the default codec refuses (RecordSlotRowsUnsettled): no push
//	          is built and no row slot opened until it is answered, and every other call works
//	journal   a built push, deposit or ERASE is kept in the store under its push id before its first post, so a retry
//	          of that push id, after a kill or an answer that never came, sends the same bytes and evs answers it as
//	          that statement (I-EVS-3); the same push id with other content is PUSH_ID_REUSED here, recorded, as evs
//	          would answer it. A record is kept JournalKeep, past what evs remembers of a push id, then dropped at the
//	          next journal write of its repo
//	pin       each push declares its evs client's newest verified pin, which must be at or above the caller's, or the
//	          build is refused with ErrEvsStreamPinBehind and nothing is sent: see RecordStreamPush.AuthPin
//	deposits  a deposit seals once under the caller's push id and deposit id, as EvsRepo.Deposit seals each attempt
//	          (evs_deposit.go), its batch one file; the head a 200 or a BASE_STALE carries is kept, so the caller's
//	          rebuilt deposit seals on it; every refusal goes back, since a rebuilt deposit takes new ids
//	consume   EvsRepo.Consume, whose own journal sends a CONSUME again after a kill: its push id is the client's, not
//	          the caller's, it consumes the deposits that stand, and one naming none that stands is PATH_CONFLICT
//	erase     an ERASE under the caller's push id through POST .../slots/delete (evs_erase.go's buildErase), its note
//	          the erasure id, whether it completes the erasure, and the caller's bytes, sealed with the push's
//	          metadata (QD-682), the ERASE creating nothing on the erasure ref; NOTHING_TO_ERASE is evs's recorded
//	          answer
//	read      a stream's statements walked and verified from its first; each push's payload read for its changes and
//	          new slots, each entry file rebuilt and checked against its sealed fields, and its path found from its
//	          tokens (below); the push's slot object is the one new slot that no entry's chain names. A version that
//	          creates no entry file, a BASE's, is left out, and so is an entry file a later BASE removed
//	counter   a token path's names are section 5.2's e/<n div 4,194,304>/<(n div 2,048) mod 2,048>/<n>: the level and
//	          leaf directories are found once each by trying their names under the push epoch's K_path, at most
//	          StreamLevelCount and 2,048 tries, and n by trying the leaf's 2,048 names from the one after the last
//	          found, so a push's consecutive counters cost one try each
//	hints     Subscribe leases the whole repo (EvsRepo.Subscribe) and listens to the client's verified changes, and this
//	          binding's own commits call the callbacks too, each with no lock held
//
// Every refusal of evs comes back as *RecordStreamRefusal with evs's code and whether evs recorded it; the slot-row
// refusal, a pin behind, an unreachable evs or a gkm failure come back as they are. On desktop and mobile legs. Safe
// for concurrent use.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The journal's own format values.
const (
	recordEvsJournalDirectory = "evs-journal/"
	recordEvsJournalVersion   = 1
	recordEvsJournalPush      = "push"
	recordEvsJournalDeposit   = "deposit"
	recordEvsJournalErase     = "erase"
	// a stream's ref name: ur/<sidecar_id as 32 lowercase hex>/record (plan-RECORD-stream-names#1)
	recordStreamRefNameRest = "/record"
	// the repo/ format whose streams this binding reads, format 1's (§11.6's format row); repo/'s own constant lives
	// off the sidecar_http leg
	evsRecordStreamsFormat = 1
	// the digests' labels
	recordEvsPushDigestLabel    = "urnetwork-sidecar-v1/record-stream-push\x00"
	recordEvsDepositDigestLabel = "urnetwork-sidecar-v1/record-stream-deposit\x00"
	recordEvsEraseDigestLabel   = "urnetwork-sidecar-v1/record-stream-erase\x00"
)

// RECORD.md's 64 B slot rows have no slot format evs takes yet (question record-m2-01-slot-row-salt): nothing was
// built, wrapped or opened.
var ErrRecordSlotRowUnsettled = errors.New("record slot rows wait on question record-m2-01-slot-row-salt")

// How a binding keeps slot rows in evs's slot objects: under fek_g of the push's generation, in ascending key_index,
// one slot key a row, so an ERASE of (slot, key_index) destroys exactly that row. Safe for concurrent use.
type RecordSlotRowCodec interface {
	// Whether rows can be wrapped: their widths and indexes, checked before anything is read or sent.
	Check(rows []*RecordSlotRow) error
	// The slot keys rows become under fek.
	Wrap(fek *EvsFekKey, rows []*RecordSlotRow) ([]*protocol.EvsSlotKey, error)
	// The rows a slot object's live keys hold, fekOf giving fek of a key's generation.
	Open(slot *protocol.EvsSlotObject, fekOf func(generation uint64) (*EvsFekKey, error)) ([]*RecordSlotRow, error)
}

// The codec while question record-m2-01-slot-row-salt is open: it wraps and opens nothing.
type RecordSlotRowsUnsettled struct{}

// Refuses.
func (self RecordSlotRowsUnsettled) Check(rows []*RecordSlotRow) error {
	return ErrRecordSlotRowUnsettled
}

// Refuses.
func (self RecordSlotRowsUnsettled) Wrap(fek *EvsFekKey, rows []*RecordSlotRow) ([]*protocol.EvsSlotKey, error) {
	return nil, ErrRecordSlotRowUnsettled
}

// Refuses.
func (self RecordSlotRowsUnsettled) Open(slot *protocol.EvsSlotObject, fekOf func(generation uint64) (*EvsFekKey, error)) ([]*RecordSlotRow, error) {
	return nil, ErrRecordSlotRowUnsettled
}

// What the binding runs by.
type RecordEvsStreamsSettings struct {
	// How long a built push, deposit or ERASE stays journaled, so a retry of its push id sends the same statement:
	// past evs's batch records, which hold a push id's outcome 25 to 26 h (§11.8's pb/ row), so a retry within
	// evs's memory always finds its bytes. Non-positive keeps none past its own call.
	JournalKeep time.Duration
	// The most level directories a stream's e/ holds, which a counter's search tries: §11.7's bound under e/ that
	// RECORD.md section 5.2 keeps a stream within, 3,584. A format value.
	StreamLevelCount int
}

// 48 h of journal, past evs's 26 h, and section 5.2's 3,584 level directories.
func DefaultRecordEvsStreamsSettings() *RecordEvsStreamsSettings {
	return &RecordEvsStreamsSettings{
		JournalKeep:      48 * time.Hour,
		StreamLevelCount: 3584,
	}
}

// What the binding runs on.
type RecordEvsStreamsArgs struct {
	Client *EvsClient
	// Where built pushes are journaled: the record component's sealed directory, or a directory under it.
	Store SidecarStore
	// Nil: RecordSlotRowsUnsettled.
	RowCodec RecordSlotRowCodec
	Settings *RecordEvsStreamsSettings
}

// RecordStreams over an EvsClient. See the file header.
type RecordEvsStreams struct {
	client   *EvsClient
	store    SidecarStore
	codec    RecordSlotRowCodec
	settings *RecordEvsStreamsSettings

	stateLock sync.Mutex
	// each repo's callbacks, by subscription
	repoIdSubscribers map[Id]map[uint64]func(repoId Id)
	subscriberCount   uint64
	// the leases and listeners each repo's first subscriber started, ended with its last
	repoIdHints map[Id]func()
}

// A binding on args.
func NewRecordEvsStreams(args *RecordEvsStreamsArgs) (*RecordEvsStreams, error) {
	if args == nil || args.Client == nil || args.Store == nil {
		return nil, fmt.Errorf("%w: record streams need an evs client and a store", ErrRecordDraftInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultRecordEvsStreamsSettings()
	}
	codec := args.RowCodec
	if codec == nil {
		codec = RecordSlotRowsUnsettled{}
	}
	return &RecordEvsStreams{
		client:            args.Client,
		store:             args.Store,
		codec:             codec,
		settings:          settings,
		repoIdSubscribers: map[Id]map[uint64]func(repoId Id){},
		repoIdHints:       map[Id]func(){},
	}, nil
}

// A writer's stream's ref name: ur/<sidecar_id as 32 lowercase hex>/record, in ASCII (plan-RECORD-stream-names#1),
// one function, since question record-m3-01-owned-ref-id-text asks whether the id takes Id.String()'s form instead.
func RecordStreamRefName(sidecarId Id) []byte {
	return []byte(evsOwnedRefPrefix + hex.EncodeToString(sidecarId[:]) + recordStreamRefNameRest)
}

// This sidecar.
func (self *RecordEvsStreams) sidecarId() Id {
	return self.client.args.Identity().SidecarId
}

// evs's refusal as the seam's, any other error as it is. Recorded is evs's own word on a retry, and a code a record
// holds on a first answer, since evs records such a refusal before it answers and says so only to a retry (§11.8's
// refuse row).
func recordEvsRefusal(err error) error {
	if evsError, ok := EvsErrorOf(err); ok && evsError.Code != protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
		return &RecordStreamRefusal{Code: evsError.Code, Recorded: evsError.Recorded || EvsRefusalRecordable(evsError.Code)}
	}
	return err
}

// One built push, deposit or ERASE, journaled under its push id.
type recordEvsJournal struct {
	Version   int      `json:"version"`
	Kind      string   `json:"kind"`
	PushId    Id       `json:"push_id"`
	Digest    []byte   `json:"digest"`
	RefId     Id       `json:"ref_id"`
	Statement []byte   `json:"statement"`
	Payload   []byte   `json:"payload"`
	Receipts  [][]byte `json:"receipts,omitempty"`
	TimeMs    int64    `json:"time_ms"`
}

// A repo's journal directory, and a push id's prefix in it: <repo>/<push>.<saved ms>, so a listing finds a push id's
// record and the records past JournalKeep.
func recordEvsJournalPrefix(repoId Id, pushId *Id) string {
	prefix := recordEvsJournalDirectory + hex.EncodeToString(repoId[:]) + "/"
	if pushId != nil {
		prefix += hex.EncodeToString(pushId[:]) + "."
	}
	return prefix
}

// The journaled record of pushId, nil for none.
func (self *RecordEvsStreams) readJournal(repoId Id, pushId Id) (*recordEvsJournal, error) {
	entries, err := self.store.List(recordEvsJournalPrefix(repoId, &pushId))
	if err != nil || len(entries) == 0 {
		return nil, err
	}
	reader, err := self.store.Open(entries[len(entries)-1].Name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	journal := &recordEvsJournal{}
	if err := json.Unmarshal(content, journal); err != nil || journal.Version != recordEvsJournalVersion || journal.PushId != pushId {
		return nil, fmt.Errorf("%w: a record evs journal of push %s", ErrSidecarStoreFailed, pushId)
	}
	return journal, nil
}

// Journals journal durably, then drops the repo's records past JournalKeep.
func (self *RecordEvsStreams) writeJournal(repoId Id, journal *recordEvsJournal) error {
	journal.Version = recordEvsJournalVersion
	content, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	nowMs := self.client.clock.Now().UnixMilli()
	directory := recordEvsJournalPrefix(repoId, nil)
	writer, err := self.store.Create(recordEvsJournalPrefix(repoId, &journal.PushId) + strconv.FormatInt(nowMs, 10))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	entries, err := self.store.List(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		dot := strings.LastIndexByte(entry.Name, '.')
		savedMs, parseErr := strconv.ParseInt(entry.Name[dot+1:], 10, 64)
		if dot < 0 || parseErr != nil || self.settings.JournalKeep <= time.Duration(nowMs-savedMs)*time.Millisecond {
			if err := self.store.Remove(entry.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// The journal's receipts as evs's messages.
func (self *recordEvsJournal) receipts() ([]*protocol.EvsUploadReceipt, error) {
	receipts := []*protocol.EvsUploadReceipt{}
	for _, receiptBytes := range self.Receipts {
		receipt := &protocol.EvsUploadReceipt{}
		if err := proto.Unmarshal(receiptBytes, receipt); err != nil {
			return nil, fmt.Errorf("%w: a journaled receipt", ErrSidecarStoreFailed)
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

// Receipts as the journal keeps them.
func recordEvsJournalReceipts(receipts []*protocol.EvsUploadReceipt) ([][]byte, error) {
	receiptBytes := [][]byte{}
	for _, receipt := range receipts {
		encoded, err := proto.Marshal(receipt)
		if err != nil {
			return nil, err
		}
		receiptBytes = append(receiptBytes, encoded)
	}
	return receiptBytes, nil
}

// Each argument's length and bytes into a digest: a value's place stays fixed whatever its bytes.
func recordEvsDigestWrite(digest io.Writer, values ...[]byte) {
	for _, value := range values {
		digest.Write(binary.BigEndian.AppendUint32(nil, uint32(len(value))))
		digest.Write(value)
	}
}

// What a push names, so a retry of its push id is told from another statement under it.
func recordEvsPushDigest(repoId Id, push *RecordStreamPush) []byte {
	digest := sha256.New()
	digest.Write([]byte(recordEvsPushDigestLabel))
	recordEvsDigestWrite(digest, repoId[:], push.WriterSidecarId[:], push.SlotId[:])
	for _, row := range push.SlotRows {
		rowSha256 := sha256.Sum256(row.Row)
		recordEvsDigestWrite(digest, binary.BigEndian.AppendUint32(nil, row.KeyIndex), rowSha256[:])
	}
	for _, entry := range push.Entries {
		entrySha256 := sha256.Sum256(entry.Entry)
		recordEvsDigestWrite(digest, []byte(entry.Path), entrySha256[:])
	}
	recordEvsDigestWrite(digest, binary.BigEndian.AppendUint64(nil, push.AuthPin.GetVersion()), push.AuthPin.GetChain())
	return digest.Sum(nil)
}

// Calls repoId's callbacks, with no lock held: a commit of this binding's is a hint (§11.10).
func (self *RecordEvsStreams) notify(repoId Id) {
	callbacks := func() []func(repoId Id) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		callbacks := []func(repoId Id){}
		for _, callback := range self.repoIdSubscribers[repoId] {
			callbacks = append(callbacks, callback)
		}
		return callbacks
	}()
	for _, callback := range callbacks {
		callback(repoId)
	}
}

// The routes a journaled push posts to, and the scope each takes.
const (
	recordEvsPushRoute           = "POST /evs/v1/repos/{repo_id}/push"
	recordEvsSlotsDeleteRoute    = "POST /evs/v1/repos/{repo_id}/slots/delete"
	recordEvsPushPathRest        = "/push"
	recordEvsSlotsDeletePathRest = "/slots/delete"
)

// Posts journal's bytes to route under scope until evs answers anything but a 503, a 429 WAIT or nothing at all,
// each such answer's retry_after waited, the read wait when it names none, at most PushRetryCount times and each at
// most PushRetryMaxWait: §11.8's retry row, but for a quota's 429, RESOURCE_EXHAUSTED, which goes back at once,
// since a receipt that cannot land refuses its read now (§16.8) and a stream push's wait is its writer's backoff.
func (self *RecordEvsStreams) post(ctx context.Context, repoId Id, route string, pathRest string, scope string, journal *recordEvsJournal) (*protocol.EvsPushReply, error) {
	receipts, err := journal.receipts()
	if err != nil {
		return nil, err
	}
	call := &evsCall{
		route:  route,
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(repoId) + pathRest,
		repoId: repoId,
		role:   scope,
		body:   &protocol.EvsPushRequest{Statement: journal.Statement, Payload: journal.Payload, Receipts: receipts},
	}
	settings := self.client.settings
	for attempt := 0; ; attempt += 1 {
		reply := &protocol.EvsPushReply{}
		err := self.client.http.callMessage(ctx, call, reply)
		if err == nil {
			return reply, nil
		}
		if ctx.Err() != nil || errors.Is(err, ErrEvsUnauthorized) || errors.Is(err, ErrEvsReplyInvalid) || settings.PushRetryCount <= attempt {
			return nil, err
		}
		wait := settings.ReadRetryWait
		if evsError, ok := EvsErrorOf(err); ok {
			if (!evsError.RefusesNothing() && !evsError.OutcomeUnknown) || evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED {
				return nil, err
			}
			if 0 < evsError.RetryAfter {
				wait = evsError.RetryAfter
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-self.client.clock.After(min(wait, settings.PushRetryMaxWait)):
		}
	}
}

// Commits push to this sidecar's own stream of repoId: see the file header's stream, rows, journal and pin rows.
func (self *RecordEvsStreams) Append(ctx context.Context, repoId Id, push *RecordStreamPush) (*RecordStreamCommit, error) {
	if push == nil || len(push.Entries) == 0 || push.AuthPin == nil {
		return nil, fmt.Errorf("%w: a stream push of no entry or pin", ErrRecordDraftInvalid)
	}
	if push.WriterSidecarId != self.sidecarId() {
		// another's owned ref, as evs answers it (§11.8's refs table)
		return nil, &RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE}
	}
	if err := self.codec.Check(push.SlotRows); err != nil {
		return nil, err
	}
	repo := self.client.Repo(repoId)
	digest := recordEvsPushDigest(repoId, push)
	journal, err := self.readJournal(repoId, push.PushId)
	if err != nil {
		return nil, err
	}
	if journal == nil {
		files := make([]*EvsStreamFile, 0, len(push.Entries))
		for _, entry := range push.Entries {
			files = append(files, &EvsStreamFile{Path: entry.Path, Content: entry.Entry})
		}
		built, err := repo.BuildStreamPush(ctx, &EvsStreamPushArgs{
			RefName:  RecordStreamRefName(push.WriterSidecarId),
			PushId:   push.PushId,
			SlotId:   push.SlotId,
			SlotKeys: func(fek *EvsFekKey) ([]*protocol.EvsSlotKey, error) { return self.codec.Wrap(fek, push.SlotRows) },
			Files:    files,
			AuthPin:  push.AuthPin,
		})
		if err != nil {
			return nil, recordEvsRefusal(err)
		}
		receipts, err := recordEvsJournalReceipts(built.Receipts)
		if err != nil {
			return nil, err
		}
		journal = &recordEvsJournal{
			Kind: recordEvsJournalPush, PushId: push.PushId, Digest: digest, RefId: built.RefId,
			Statement: built.Statement, Payload: built.Payload, Receipts: receipts, TimeMs: built.TimeMs,
		}
		if err := self.writeJournal(repoId, journal); err != nil {
			return nil, err
		}
	} else if journal.Kind != recordEvsJournalPush || !bytes.Equal(journal.Digest, digest) {
		return nil, &RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED, Recorded: true}
	}
	reply, err := self.post(ctx, repoId, recordEvsPushRoute, recordEvsPushPathRest, evsScopeWrite, journal)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	self.client.epochs.noteCommitted(repoId, journal.RefId, reply.GetVersion())
	self.notify(repoId)
	return &RecordStreamCommit{Version: reply.GetVersion(), TimeMillis: journal.TimeMs}, nil
}

// Every ref evs lists for the repo (GET .../refs), its word on each head: a caller that acts on one reads it verified.
func (self *RecordEvsStreams) listHeads(ctx context.Context, repoId Id) ([]*protocol.EvsHeadSummary, error) {
	reply := &protocol.EvsRefsReply{}
	err := self.client.http.callMessage(ctx, &evsCall{
		route:  "GET /evs/v1/repos/{repo_id}/refs",
		method: http.MethodGet,
		path:   "/evs/v1/repos/" + evsUrlId(repoId) + "/refs",
		repoId: repoId,
		role:   evsScopeRead,
		retry:  true,
	}, reply)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	if evsRecordStreamsFormat < reply.GetFormat() {
		return nil, fmt.Errorf("%w: a format-%d log's streams are M10's", ErrEvsFormatUnsupported, reply.GetFormat())
	}
	return reply.GetRefs(), nil
}

// The repo's streams, one a writer: each owned ref whose id is its owner's stream name's.
func (self *RecordEvsStreams) Streams(ctx context.Context, repoId Id) ([]*RecordStreamHead, error) {
	heads, err := self.listHeads(ctx, repoId)
	if err != nil {
		return nil, err
	}
	repo := self.client.Repo(repoId)
	streams := []*RecordStreamHead{}
	for _, head := range heads {
		if head.GetRefKind() != protocol.EvsRefKind_EVS_REF_OWNED {
			continue
		}
		ownerId, err := IdFromBytes(head.GetOwnerSidecarId())
		if err != nil {
			continue
		}
		refId, err := repo.resolveRefId(ctx, RecordStreamRefName(ownerId), nil)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(head.GetRefId(), refId[:]) {
			// another ref of the owner's, which no stream is
			continue
		}
		streams = append(streams, &RecordStreamHead{SidecarId: ownerId, Version: head.GetVersion(), RefId: refId})
	}
	slices.SortFunc(streams, func(a *RecordStreamHead, b *RecordStreamHead) int { return a.SidecarId.Cmp(b.SidecarId) })
	return streams, nil
}

// One push epoch's search of section 5.2's names: see the file header's counter row.
type recordStreamCounters struct {
	pathKey *EvsPathKey
	// e/'s token, then each level and leaf directory found, by token: a level's a, a leaf's n div 2,048
	root          EvsToken
	levelIndexes  map[EvsToken]uint64
	leafIndexes   map[EvsToken]uint64
	levelsTried   uint64
	leafLevelsHit map[EvsToken]bool
	next          uint64
}

// A search under pathKey.
func newRecordStreamCounters(pathKey *EvsPathKey) (*recordStreamCounters, error) {
	root, err := EvsPathToken(pathKey, EvsToken{}, []byte(strings.TrimSuffix(recordStreamPathPrefix, "/")))
	if err != nil {
		return nil, err
	}
	return &recordStreamCounters{
		pathKey:       pathKey,
		root:          root,
		levelIndexes:  map[EvsToken]uint64{},
		leafIndexes:   map[EvsToken]uint64{},
		leafLevelsHit: map[EvsToken]bool{},
	}, nil
}

// The counter n whose stream path is tokenPath, false for a token path no stream path names within levelCount
// level directories.
func (self *recordStreamCounters) counter(tokenPath EvsTokenPath, levelCount int) (uint64, bool, error) {
	if len(tokenPath) != 4 || tokenPath[0] != self.root {
		return 0, false, nil
	}
	name := func(n uint64) []byte {
		return []byte(strconv.FormatUint(n, 10))
	}
	level, ok := self.levelIndexes[tokenPath[1]]
	for !ok && self.levelsTried < uint64(levelCount) {
		token, err := EvsPathToken(self.pathKey, self.root, name(self.levelsTried))
		if err != nil {
			return 0, false, err
		}
		self.levelIndexes[token] = self.levelsTried
		self.levelsTried += 1
		level, ok = self.levelIndexes[tokenPath[1]]
	}
	if !ok {
		return 0, false, nil
	}
	leaf, ok := self.leafIndexes[tokenPath[2]]
	if !ok && !self.leafLevelsHit[tokenPath[1]] {
		self.leafLevelsHit[tokenPath[1]] = true
		for b := uint64(0); b < recordStreamLeafEntryCount; b += 1 {
			token, err := EvsPathToken(self.pathKey, tokenPath[1], name(b))
			if err != nil {
				return 0, false, err
			}
			self.leafIndexes[token] = level*recordStreamLeafEntryCount + b
		}
		leaf, ok = self.leafIndexes[tokenPath[2]]
	}
	if !ok {
		return 0, false, nil
	}
	tries := []uint64{}
	if self.next/recordStreamLeafEntryCount == leaf {
		tries = append(tries, self.next)
	}
	for i := uint64(0); i < recordStreamLeafEntryCount; i += 1 {
		tries = append(tries, leaf*recordStreamLeafEntryCount+i)
	}
	for _, n := range tries {
		if n == 0 {
			continue
		}
		token, err := EvsPathToken(self.pathKey, tokenPath[2], name(n))
		if err != nil {
			return 0, false, err
		}
		if token == tokenPath[3] {
			self.next = n + 1
			return n, true, nil
		}
	}
	return 0, false, nil
}

// A stream's committed pushes after afterVersion, oldest first: see the file header's read and counter rows.
func (self *RecordEvsStreams) ReadStream(ctx context.Context, repoId Id, writerSidecarId Id, afterVersion uint64) ([]*RecordStreamVersion, error) {
	repo := self.client.Repo(repoId)
	refId, err := repo.resolveRefId(ctx, RecordStreamRefName(writerSidecarId), nil)
	if err != nil {
		return nil, err
	}
	head, err := repo.readHeadAlone(ctx, refId, true)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	if head.Version <= afterVersion {
		return []*RecordStreamVersion{}, nil
	}
	walked, err := self.client.verifier.Walk(ctx, repoId, refId, 0, EvsChainStart(repoId, refId), head.Version)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	keys := newEvsReadKeys(repo)
	// the token paths a BASE removed, which a later read of their files finds gone
	removed := map[string]bool{}
	payloads := map[uint64]*EvsCheckedPayload{}
	for _, statement := range walked {
		if statement.Version <= afterVersion && statement.Statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_BASE) == 0 {
			continue
		}
		payload, err := repo.pushPayload(ctx, head, statement)
		if err != nil {
			return nil, recordEvsRefusal(err)
		}
		payloads[statement.Version] = payload
		if statement.Statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_BASE) != 0 {
			for _, change := range payload.Changes {
				if !change.WritesEntry() {
					removed[string(change.TokenPath.Bytes())] = true
				}
			}
		}
	}
	epochCounters := map[uint64]*recordStreamCounters{}
	versions := []*RecordStreamVersion{}
	for _, statement := range walked {
		push := statement.Statement.Push
		payload := payloads[statement.Version]
		if statement.Version <= afterVersion || payload == nil || push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_BASE) != 0 {
			continue
		}
		pushId, _ := IdFromBytes(push.GetPushId())
		version := &RecordStreamVersion{
			Version: statement.Version, PushId: pushId, TimeMillis: push.GetTimeMs(), Chain: bytes.Clone(statement.Chain[:]),
		}
		if push.GetAuth() != nil {
			version.AuthPin = &bridge.AuthPin{Version: push.GetAuth().GetVersion(), Chain: bytes.Clone(push.GetAuth().GetChain())}
		}
		counters := epochCounters[push.GetPathEpoch()]
		if counters == nil {
			pathKey, err := keys.path(ctx, push.GetPathEpoch())
			if err != nil {
				return nil, err
			}
			if counters, err = newRecordStreamCounters(pathKey); err != nil {
				return nil, err
			}
			epochCounters[push.GetPathEpoch()] = counters
		}
		named := map[Id]bool{}
		for _, change := range payload.Changes {
			if !change.WritesEntry() {
				continue
			}
			entry := &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
				return nil, fmt.Errorf("%w: a stream entry that does not parse", ErrEvsEntryRefused)
			}
			if entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
				continue
			}
			for _, slotId := range entry.GetSlotIds() {
				named[recordIdOf(slotId)] = true
			}
			n, ok, err := counters.counter(change.TokenPath, self.settings.StreamLevelCount)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, fmt.Errorf("%w: a stream file at no stream path", ErrEvsEntryRefused)
			}
			if removed[string(change.TokenPath.Bytes())] {
				continue
			}
			path, err := RecordStreamPath(n)
			if err != nil {
				return nil, err
			}
			content, err := func() ([]byte, error) {
				result := &evsReadResult{refId: refId, head: head, keys: keys, objects: newEvsReadObjects(self.client)}
				defer result.objects.close()
				verified := &EvsVerifiedPath{TokenPath: change.TokenPath, EntryBytes: change.EntryVersion, Entry: entry, Statement: statement.Statement, CommitVersion: statement.Version}
				spill, _, _, err := repo.reconstructContent(ctx, result, verified, nil)
				if err != nil {
					return nil, err
				}
				defer spill.close()
				return io.ReadAll(spill.reader())
			}()
			if err != nil {
				return nil, recordEvsRefusal(err)
			}
			version.Entries = append(version.Entries, &RecordStreamEntry{Path: path, Entry: content})
		}
		for _, object := range payload.NewObjects {
			if object.Kind != protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT || named[recordIdOf(object.Id)] {
				continue
			}
			version.SlotId = recordIdOf(object.Id)
		}
		// the push's order is its counters', which the statement's token order is not
		slices.SortFunc(version.Entries, func(a *RecordStreamEntry, b *RecordStreamEntry) int {
			n, _ := RecordStreamPathCounter(a.Path)
			m, _ := RecordStreamPathCounter(b.Path)
			return cmp.Compare(n, m)
		})
		if 0 < len(version.Entries) {
			versions = append(versions, version)
		}
	}
	return versions, nil
}

// A slot object's live rows, opened by the row codec. NOT_FOUND for a slot evs does not hold.
func (self *RecordEvsStreams) ReadSlot(ctx context.Context, repoId Id, slotId Id) (*RecordSlot, error) {
	repo := self.client.Repo(repoId)
	refId := EvsErasureRefId(repoId)
	_, objects, err := self.client.postRead(ctx, repoId, &protocol.EvsReadRequest{RefId: refId.Bytes(), SlotIds: [][]byte{slotId.Bytes()}})
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	defer objects.close()
	slotBytes, ok := objects.slot(slotId.Bytes())
	if !ok || len(slotBytes) == 0 {
		return nil, &RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND}
	}
	slot, err := EvsDecodeSlotObject(slotBytes)
	if err != nil {
		self.client.alarm(repoId, refId, SidecarEvsAlarmTamper, "", nil)
		return nil, err
	}
	// a row is a key: an owner-bound repo's reader that does not write it deposits its receipt first (§16.8)
	if err := self.client.preDecrypt(ctx, repoId, refId, [][]byte{slotId.Bytes()}); err != nil {
		return nil, err
	}
	keys := newEvsReadKeys(repo)
	rows, err := self.codec.Open(slot, func(generation uint64) (*EvsFekKey, error) { return keys.fek(ctx, generation) })
	if err != nil {
		return nil, err
	}
	return &RecordSlot{SlotId: slotId, Rows: rows}, nil
}

// What a deposit names, as recordEvsPushDigest a push.
func recordEvsDepositDigest(repoId Id, deposit *RecordStreamDeposit) []byte {
	digest := sha256.New()
	digest.Write([]byte(recordEvsDepositDigestLabel))
	batchSha256 := sha256.Sum256(deposit.Batch)
	recordEvsDigestWrite(digest, repoId[:], deposit.DepositorSidecarId[:], deposit.DepositId[:], batchSha256[:],
		binary.BigEndian.AppendUint64(nil, deposit.AuthPin.GetVersion()), deposit.AuthPin.GetChain())
	return digest.Sum(nil)
}

// Commits deposit to this sidecar's own deposit ref of repoId: see the file header's deposits row.
func (self *RecordEvsStreams) Deposit(ctx context.Context, repoId Id, deposit *RecordStreamDeposit) (*RecordStreamCommit, error) {
	if deposit == nil || deposit.AuthPin == nil || deposit.DepositId == (Id{}) {
		return nil, fmt.Errorf("%w: a deposit of no id or pin", ErrRecordDraftInvalid)
	}
	if deposit.DepositorSidecarId != self.sidecarId() {
		// another's deposit ref, as evs answers it (§11.8's refs table)
		return nil, &RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE}
	}
	repo := self.client.Repo(repoId)
	refId := EvsDepositRefId(repoId, deposit.DepositorSidecarId)
	digest := recordEvsDepositDigest(repoId, deposit)
	journal, err := self.readJournal(repoId, deposit.PushId)
	if err != nil {
		return nil, err
	}
	if journal == nil {
		state, err := self.client.verifier.config()
		if err != nil {
			return nil, err
		}
		if state.Pin().GetVersion() < deposit.AuthPin.GetVersion() || !state.OnChain(deposit.AuthPin) {
			return nil, ErrEvsStreamPinBehind
		}
		built, err := func() (*evsDepositPush, error) {
			body := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
			defer body.close()
			if _, err := body.Write(deposit.Batch); err != nil {
				return nil, err
			}
			oid, err := EvsGitBlobOid(body.reader(), body.Size())
			if err != nil {
				return nil, err
			}
			dropKey, err := repo.waitDropKey(ctx)
			if err != nil {
				return nil, err
			}
			head, err := repo.depositHead(refId)
			if err != nil {
				return nil, err
			}
			built, err := repo.sealDeposit(ctx, dropKey, refId, EvsToken(deposit.DepositId), body, oid, head, deposit.PushId)
			if err != nil {
				return nil, err
			}
			built.sealed.Close()
			return built, nil
		}()
		if err != nil {
			return nil, recordEvsRefusal(err)
		}
		receipts, err := recordEvsJournalReceipts(built.receipts)
		if err != nil {
			return nil, err
		}
		journal = &recordEvsJournal{
			Kind: recordEvsJournalDeposit, PushId: deposit.PushId, Digest: digest, RefId: refId,
			Statement: built.built.Statement.Bytes, Payload: built.built.Payload, Receipts: receipts,
			TimeMs: built.built.Statement.Push.GetTimeMs(),
		}
		if err := self.writeJournal(repoId, journal); err != nil {
			return nil, err
		}
	} else if journal.Kind != recordEvsJournalDeposit || !bytes.Equal(journal.Digest, digest) {
		return nil, &RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED, Recorded: true}
	}
	reply, err := self.post(ctx, repoId, recordEvsPushRoute, recordEvsPushPathRest, evsScopeDeposit, journal)
	if err != nil {
		if evsError, ok := EvsErrorOf(err); ok && evsError.DepositHead != nil {
			// the ref's head, which the caller's rebuilt deposit seals on
			if keepErr := repo.keepDepositHead(refId, evsError.DepositHead); keepErr != nil {
				return nil, keepErr
			}
		}
		return nil, recordEvsRefusal(err)
	}
	if err := repo.keepDepositHead(refId, reply.GetDepositHead()); err != nil {
		return nil, err
	}
	self.notify(repoId)
	return &RecordStreamCommit{Version: reply.GetVersion(), TimeMillis: journal.TimeMs}, nil
}

// The repo's deposit refs, one a depositor, as evs lists them.
func (self *RecordEvsStreams) DepositRefs(ctx context.Context, repoId Id) ([]*RecordStreamHead, error) {
	heads, err := self.listHeads(ctx, repoId)
	if err != nil {
		return nil, err
	}
	refs := []*RecordStreamHead{}
	for _, head := range heads {
		if head.GetRefKind() != protocol.EvsRefKind_EVS_REF_DEPOSIT {
			continue
		}
		depositorId, err := IdFromBytes(head.GetOwnerSidecarId())
		if err != nil || !bytes.Equal(head.GetRefId(), EvsDepositRefId(repoId, depositorId).Bytes()) {
			continue
		}
		refs = append(refs, &RecordStreamHead{SidecarId: depositorId, Version: head.GetVersion(), RefId: EvsDepositRefId(repoId, depositorId)})
	}
	slices.SortFunc(refs, func(a *RecordStreamHead, b *RecordStreamHead) int { return a.SidecarId.Cmp(b.SidecarId) })
	return refs, nil
}

// A deposit ref's standing deposits, each opened, in version order (EvsRepo.ReadDeposits).
func (self *RecordEvsStreams) ReadDeposits(ctx context.Context, repoId Id, depositorSidecarId Id) ([]*RecordStreamDepositVersion, error) {
	deposits := []*RecordStreamDepositVersion{}
	err := self.client.Repo(repoId).ReadDeposits(ctx, depositorSidecarId, 0, func(deposit *EvsDeposit, body io.Reader) error {
		batch, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		version := &RecordStreamDepositVersion{
			Version: deposit.Version, PushId: deposit.PushId, TimeMillis: deposit.Time.UnixMilli(), DepositId: Id(deposit.EntryId), Batch: batch,
			SlotId: deposit.SlotId,
		}
		if deposit.AuthPin != nil {
			version.AuthPin = &bridge.AuthPin{Version: deposit.AuthPin.GetVersion(), Chain: bytes.Clone(deposit.AuthPin.GetChain())}
		}
		deposits = append(deposits, version)
		return nil
	})
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	return deposits, nil
}

// A CONSUME of the deposits that stand: see the file header's consume row.
func (self *RecordEvsStreams) Consume(ctx context.Context, repoId Id, consume *RecordStreamConsume) (*RecordStreamCommit, error) {
	if consume == nil || len(consume.DepositIds) == 0 {
		return nil, fmt.Errorf("%w: a CONSUME of nothing", ErrRecordDraftInvalid)
	}
	entryIds := make([]EvsToken, 0, len(consume.DepositIds))
	for _, depositId := range consume.DepositIds {
		entryIds = append(entryIds, EvsToken(depositId))
	}
	result, err := self.client.Repo(repoId).Consume(ctx, &EvsConsumeArgs{DepositRefId: EvsDepositRefId(repoId, consume.DepositorSidecarId), EntryIds: entryIds})
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	if result.PushId == (Id{}) {
		// nothing stood: another ingester consumed them first
		return nil, &RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT}
	}
	self.notify(repoId)
	return &RecordStreamCommit{Version: result.Version, TimeMillis: self.client.clock.Now().UnixMilli()}, nil
}

// What an ERASE names, as recordEvsPushDigest a push.
func recordEvsEraseDigest(repoId Id, erase *RecordStreamErase) []byte {
	digest := sha256.New()
	digest.Write([]byte(recordEvsEraseDigestLabel))
	complete := []byte{0}
	if erase.Complete {
		complete[0] = 1
	}
	recordEvsDigestWrite(digest, repoId[:], erase.ErasureId[:], complete, erase.SealedNote)
	for _, key := range erase.Keys {
		recordEvsDigestWrite(digest, key.SlotId[:], binary.BigEndian.AppendUint32(nil, key.KeyIndex))
	}
	return digest.Sum(nil)
}

// Commits erase on the repo's erasure ref: see the file header's erase row.
func (self *RecordEvsStreams) Erase(ctx context.Context, repoId Id, erase *RecordStreamErase) (*RecordStreamCommit, error) {
	if erase == nil || len(erase.Keys) == 0 {
		return nil, fmt.Errorf("%w: an ERASE of no key", ErrRecordDraftInvalid)
	}
	repo := self.client.Repo(repoId)
	digest := recordEvsEraseDigest(repoId, erase)
	journal, err := self.readJournal(repoId, erase.PushId)
	if err != nil {
		return nil, err
	}
	if journal == nil {
		args := &EvsEraseArgs{ErasureId: erase.ErasureId, Complete: erase.Complete, Note: erase.SealedNote}
		for _, key := range erase.Keys {
			if EvsSlotMaxKeyCount <= key.KeyIndex {
				return nil, fmt.Errorf("%w: key index %d", ErrRecordDraftInvalid, key.KeyIndex)
			}
			args.Keys = append(args.Keys, &EvsErasedKey{SlotId: key.SlotId, KeyIndex: uint16(key.KeyIndex)})
		}
		attempt, err := repo.buildErase(ctx, args, erase.PushId, true)
		if err != nil {
			return nil, recordEvsRefusal(err)
		}
		if 0 < len(attempt.built.Parts) || 0 < len(attempt.receipts) {
			return nil, fmt.Errorf("%w: an ERASE whose note is past one part", ErrRecordDraftInvalid)
		}
		journal = &recordEvsJournal{
			Kind: recordEvsJournalErase, PushId: erase.PushId, Digest: digest, RefId: EvsErasureRefId(repoId),
			Statement: attempt.built.Statement.Bytes, Payload: attempt.built.Payload, TimeMs: attempt.built.Statement.Push.GetTimeMs(),
		}
		if err := self.writeJournal(repoId, journal); err != nil {
			return nil, err
		}
	} else if journal.Kind != recordEvsJournalErase || !bytes.Equal(journal.Digest, digest) {
		return nil, &RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED, Recorded: true}
	}
	reply, err := self.post(ctx, repoId, recordEvsSlotsDeleteRoute, recordEvsSlotsDeletePathRest, evsScopeAdmin, journal)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	self.notify(repoId)
	return &RecordStreamCommit{Version: reply.GetVersion(), TimeMillis: journal.TimeMs}, nil
}

// The repo's committed ERASEs after afterVersion, their notes opened (EvsRepo.ReadErasures).
func (self *RecordEvsStreams) ReadErasures(ctx context.Context, repoId Id, afterVersion uint64) ([]*RecordStreamErasure, error) {
	erasures, err := self.client.Repo(repoId).ReadErasures(ctx, afterVersion)
	if err != nil {
		return nil, recordEvsRefusal(err)
	}
	read := []*RecordStreamErasure{}
	for _, erasure := range erasures {
		recordErasure := &RecordStreamErasure{
			Version: erasure.Version, PushId: erasure.PushId, TimeMillis: erasure.Time.UnixMilli(), EraserSidecarId: erasure.EraserSidecarId,
			ErasureId: erasure.ErasureId, Complete: erasure.Complete, SealedNote: bytes.Clone(erasure.Note),
		}
		for _, key := range erasure.Keys {
			recordErasure.Keys = append(recordErasure.Keys, &RecordSlotKey{SlotId: key.SlotId, KeyIndex: uint32(key.KeyIndex)})
		}
		read = append(read, recordErasure)
	}
	return read, nil
}

// Calls callback, with no lock held, each time a ref of repoId moves: see the file header's hints row. The first
// subscriber of a repo leases it, in the background, and the last one's unsubscribe ends the lease and listener.
func (self *RecordEvsStreams) Subscribe(repoId Id, callback func(repoId Id)) func() {
	subscriberId, first := func() (uint64, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.subscriberCount += 1
		subscribers := self.repoIdSubscribers[repoId]
		if subscribers == nil {
			subscribers = map[uint64]func(repoId Id){}
			self.repoIdSubscribers[repoId] = subscribers
		}
		subscribers[self.subscriberCount] = callback
		return self.subscriberCount, len(subscribers) == 1
	}()
	if first {
		ctx, cancel := context.WithCancel(context.Background())
		removeListener := self.client.AddRepoChangeListener(&repoId, func(change *EvsRepoChange) {
			// on the subscriber's goroutine, which must not block: the callbacks run on their own
			go self.notify(repoId)
		})
		var subscription *EvsSubscription
		var subscriptionLock sync.Mutex
		go func() {
			leased, err := self.client.Repo(repoId).Subscribe(ctx, &EvsSubscribeArgs{})
			if err != nil {
				if self.client.log.V(1).Enabled() {
					self.client.log.Infof("[record]the lease of repo %s did not land: %v", repoId, err)
				}
				return
			}
			subscriptionLock.Lock()
			defer subscriptionLock.Unlock()
			if ctx.Err() != nil {
				leased.Close()
				return
			}
			subscription = leased
		}()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.repoIdHints[repoId] = func() {
				cancel()
				removeListener()
				subscriptionLock.Lock()
				defer subscriptionLock.Unlock()
				subscription.Close()
			}
		}()
	}
	return func() {
		end := func() func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			subscribers := self.repoIdSubscribers[repoId]
			if _, ok := subscribers[subscriberId]; !ok {
				return nil
			}
			delete(subscribers, subscriberId)
			if 0 < len(subscribers) {
				return nil
			}
			delete(self.repoIdSubscribers, repoId)
			end := self.repoIdHints[repoId]
			delete(self.repoIdHints, repoId)
			return end
		}()
		if end != nil {
			end()
		}
	}
}
