// A drop job's and a dry run's files, dropscan/<repo>/<id>/<kind>-<sequence> on the segment cluster (§11.8's dropscan/
// row; DESIGN-DETAILS 10.2.2, QD-562; EVSB-M10-03): each immutable, written If-None-Match, a 412 on equal bytes being
// success, and named as QD-562 spells it, the kind, a hyphen and a 10-digit decimal sequence from 0, so no name is a path
// prefix of another. <id> is the job's or dry run's 16-byte id. Integers big-endian:
//
//	every file  "URds" | format u8 = 1 | kind u8 | 2 zero bytes | repo_id 16 | job_id 16 | sequence u32 | row count u32;
//	            its rows; then SHA-256 of every byte before it
//	snap   1    sequence 0, one row per covered drop: drop_id 16 | ref_id 16 | version u64 | push_id 16 | place 20 |
//	            seen_ms i64 (84 B). Sequence r >= 1, round r's: a first row of horizon_ms i64 and 24 zero bytes, then one
//	            row per ref: ref_id 16 | its head's version at M_r u64 | at V_r u64 (32 B each)
//	cand   2    the candidates, ascending: id 32 (a slot's 16 B id zero-filled on the right) | kind u8 (1 segment, 2 slot)
//	list   3    the listed index, DESIGN-DETAILS 10.2.9's, which resolve writes (EVSB-M10-04) and this file does not parse
//	mark   4    a first row, the scan's cursor: ref_id 16 | version u64 | 9 zero bytes; then ids as cand's rows. A
//	            checkpoint writes the next sequence with the ids marked since the last; the marks are their union
//	del    5    id 32 | kind u8 | outcome u8 (1 deleted, 2 absent, 3 packed, 4 young, 5 replaced, 6 held, 7 observed):
//	            the ids answered since the last sequence; an id's newest row is its outcome
//	held   6    the ids a hold keeps, as cand's rows
//	ask    7    a dry run's request: its EvsDropPreviewRequest's bytes, the row count their length
//	res    8    a dry run's results: its EvsDropPreviewReply's bytes, the row count their length
//
// ask and res are this file's fill for QD-179's "a dry run's paths, lists and results go in dropscan/", which names
// the family and gives no layout: the request and the reply as their own protobuf bytes inside the common envelope, so
// GET .../drops/preview/<preview_id> answers the stored reply as it is.
//
// A mark file the job writes for verify's late marks repeats the newest mark file's cursor, so mark's resume reads the
// same position. snap, cand, mark, del, held, ask and res go 30 d after their job or dry run ends; list files stay for
// the repo's life.
//
// Package-level functions are safe for concurrent use.

package evsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The files' layout. Format values, not tunables.
const (
	dropFileMagic                     = "URds"
	dropFileFormat1              byte = 1
	dropFileHeaderByteCount           = 48
	dropFileTrailerByteCount          = sha256.Size
	dropFileSnapDropRowByteCount      = 84
	dropFileSnapRefRowByteCount       = 32
	dropFileIdRowByteCount            = 33
	dropFileDelRowByteCount           = 34
	dropFileSequenceDigitCount        = 10
)

// A dropscan/ file's kind (DESIGN-DETAILS 10.2.2's kind byte).
type DropFileKind uint8

const (
	DropFileSnap DropFileKind = 1
	DropFileCand DropFileKind = 2
	DropFileList DropFileKind = 3
	DropFileMark DropFileKind = 4
	DropFileDel  DropFileKind = 5
	DropFileHeld DropFileKind = 6
	DropFileAsk  DropFileKind = 7
	DropFileRes  DropFileKind = 8
)

// Its name in a key.
func (self DropFileKind) String() string {
	switch self {
	case DropFileSnap:
		return "snap"
	case DropFileCand:
		return "cand"
	case DropFileList:
		return "list"
	case DropFileMark:
		return "mark"
	case DropFileDel:
		return "del"
	case DropFileHeld:
		return "held"
	case DropFileAsk:
		return "ask"
	case DropFileRes:
		return "res"
	}
	return "unknown"
}

// A candidate's kind.
type DropIdKind uint8

const (
	DropIdSegment DropIdKind = 1
	DropIdSlot    DropIdKind = 2
)

// A del row's outcome.
type DropOutcome uint8

const (
	DropOutcomeDeleted  DropOutcome = 1
	DropOutcomeAbsent   DropOutcome = 2
	DropOutcomePacked   DropOutcome = 3
	DropOutcomeYoung    DropOutcome = 4
	DropOutcomeReplaced DropOutcome = 5
	DropOutcomeHeld     DropOutcome = 6
	DropOutcomeObserved DropOutcome = 7
)

// Whether the outcome answers the id for good, so a later round judges it no more: everything but young, which a
// later round takes once the horizon has passed its bound, and held, which the round after every covering hold ends
// deletes (owner decision 184).
func (self DropOutcome) Final() bool {
	switch self {
	case DropOutcomeDeleted, DropOutcomeAbsent, DropOutcomePacked, DropOutcomeReplaced, DropOutcomeObserved:
		return true
	}
	return false
}

// A dropscan/ file's bytes do not parse, or a name is not one.
var ErrDropFileInvalid = errors.New("evs drop file invalid")

// One candidate id: a segment's 32 B id, or a slot's 16 B id zero-filled on the right.
type DropScanId struct {
	Id   [32]byte
	Kind DropIdKind
}

// A segment's.
func DropSegmentId(segmentId [32]byte) DropScanId {
	return DropScanId{Id: segmentId, Kind: DropIdSegment}
}

// A slot's.
func DropSlotId(slotId sidecar.Id) DropScanId {
	scanId := DropScanId{Kind: DropIdSlot}
	copy(scanId.Id[:], slotId[:])
	return scanId
}

// The slot's id, for a slot's.
func (self DropScanId) SlotId() sidecar.Id {
	return sidecar.Id(self.Id[:16])
}

// Ascending by id, then kind: cand's order.
func CompareDropScanIds(a DropScanId, b DropScanId) int {
	if c := bytes.Compare(a.Id[:], b.Id[:]); c != 0 {
		return c
	}
	return int(a.Kind) - int(b.Kind)
}

// One del row.
type DropAnswer struct {
	DropScanId
	Outcome DropOutcome
}

// One covered drop, as snap-0 names it.
type DropCovered struct {
	DropId  sidecar.Id
	RefId   sidecar.Id
	Version uint64
	PushId  sidecar.Id
	Place   *protocol.EvsPlace
	SeenMs  int64
}

// One ref's snapshots in a round.
type DropRefSnapshot struct {
	RefId   sidecar.Id
	Marked  uint64
	Checked uint64
}

// A round's snapshot: its horizon, and each ref's version at M_r and at V_r.
type DropRoundSnapshot struct {
	Horizon time.Time
	Refs    []*DropRefSnapshot
}

// One parsed file.
type DropFile struct {
	Kind     DropFileKind
	RepoId   sidecar.Id
	JobId    sidecar.Id
	Sequence uint32
	// snap 0
	Covered []*DropCovered
	// snap r >= 1
	Round *DropRoundSnapshot
	// cand, held, and mark's ids
	Ids []DropScanId
	// mark's cursor
	CursorRefId   sidecar.Id
	CursorVersion uint64
	// del
	Answers []*DropAnswer
	// ask and res: the message's bytes
	Message []byte
}

// The key of a file: dropscan/<repo>/<id>/<kind>-<sequence>.
func DropFileKey(repoId sidecar.Id, jobId sidecar.Id, kind DropFileKind, sequence uint32) string {
	return DropscanKey(repoId, jobId, fmt.Sprintf("%s-%0*d", kind, dropFileSequenceDigitCount, sequence))
}

// The prefix every file of one kind of a job shares.
func dropFileKindPrefix(repoId sidecar.Id, jobId sidecar.Id, kind DropFileKind) string {
	return DropscanKey(repoId, jobId, kind.String()+"-")
}

// The prefix every file of a job shares.
func dropFileJobPrefix(repoId sidecar.Id, jobId sidecar.Id) string {
	return DropscanKey(repoId, jobId, "")
}

// The sequence a key of kind's prefix names, and whether it names one.
func dropFileSequence(prefix string, key string) (uint32, bool) {
	text, ok := strings.CutPrefix(key, prefix)
	if !ok || len(text) != dropFileSequenceDigitCount {
		return 0, false
	}
	sequence, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(sequence), true
}

// The common header.
func encodeDropFileHeader(kind DropFileKind, repoId sidecar.Id, jobId sidecar.Id, sequence uint32, rowCount int) []byte {
	encoded := make([]byte, 0, dropFileHeaderByteCount)
	encoded = append(encoded, dropFileMagic...)
	encoded = append(encoded, dropFileFormat1, byte(kind), 0, 0)
	encoded = append(encoded, repoId[:]...)
	encoded = append(encoded, jobId[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, sequence)
	return binary.BigEndian.AppendUint32(encoded, uint32(rowCount))
}

// The file's bytes: its header, rows and trailer.
func sealDropFile(encoded []byte) []byte {
	trailer := sha256.Sum256(encoded)
	return append(encoded, trailer[:]...)
}

// Appends an id row.
func appendDropIdRow(encoded []byte, scanId DropScanId) []byte {
	encoded = append(encoded, scanId.Id[:]...)
	return append(encoded, byte(scanId.Kind))
}

// snap-0: the covered drops.
func EncodeDropCoveredFile(repoId sidecar.Id, jobId sidecar.Id, covered []*DropCovered) []byte {
	encoded := encodeDropFileHeader(DropFileSnap, repoId, jobId, 0, len(covered))
	for _, drop := range covered {
		encoded = append(encoded, drop.DropId[:]...)
		encoded = append(encoded, drop.RefId[:]...)
		encoded = binary.BigEndian.AppendUint64(encoded, drop.Version)
		encoded = append(encoded, drop.PushId[:]...)
		encoded = append(encoded, sidecar.EvsPackPlace(drop.Place)...)
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(drop.SeenMs))
	}
	return sealDropFile(encoded)
}

// snap-r, r >= 1: a round's horizon and each ref's two versions, refs in id order.
func EncodeDropRoundFile(repoId sidecar.Id, jobId sidecar.Id, round uint32, snapshot *DropRoundSnapshot) []byte {
	refs := slices.Clone(snapshot.Refs)
	slices.SortFunc(refs, func(a *DropRefSnapshot, b *DropRefSnapshot) int {
		return bytes.Compare(a.RefId[:], b.RefId[:])
	})
	encoded := encodeDropFileHeader(DropFileSnap, repoId, jobId, round, 1+len(refs))
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(snapshot.Horizon.UnixMilli()))
	encoded = append(encoded, make([]byte, 24)...)
	for _, ref := range refs {
		encoded = append(encoded, ref.RefId[:]...)
		encoded = binary.BigEndian.AppendUint64(encoded, ref.Marked)
		encoded = binary.BigEndian.AppendUint64(encoded, ref.Checked)
	}
	return sealDropFile(encoded)
}

// A cand or held file of ids, sorted ascending.
func EncodeDropIdFile(kind DropFileKind, repoId sidecar.Id, jobId sidecar.Id, sequence uint32, scanIds []DropScanId) ([]byte, error) {
	if kind != DropFileCand && kind != DropFileHeld {
		return nil, fmt.Errorf("%w: ids in a %s file", ErrDropFileInvalid, kind)
	}
	sorted := slices.Clone(scanIds)
	slices.SortFunc(sorted, CompareDropScanIds)
	encoded := encodeDropFileHeader(kind, repoId, jobId, sequence, len(sorted))
	for _, scanId := range sorted {
		encoded = appendDropIdRow(encoded, scanId)
	}
	return sealDropFile(encoded), nil
}

// A mark checkpoint: its cursor, then the ids marked since the last.
func EncodeDropMarkFile(repoId sidecar.Id, jobId sidecar.Id, sequence uint32, cursorRefId sidecar.Id, cursorVersion uint64, scanIds []DropScanId) []byte {
	sorted := slices.Clone(scanIds)
	slices.SortFunc(sorted, CompareDropScanIds)
	encoded := encodeDropFileHeader(DropFileMark, repoId, jobId, sequence, 1+len(sorted))
	encoded = append(encoded, cursorRefId[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, cursorVersion)
	encoded = append(encoded, make([]byte, 9)...)
	for _, scanId := range sorted {
		encoded = appendDropIdRow(encoded, scanId)
	}
	return sealDropFile(encoded)
}

// A del file: the ids answered since the last, in the order answered.
func EncodeDropDelFile(repoId sidecar.Id, jobId sidecar.Id, sequence uint32, answers []*DropAnswer) []byte {
	encoded := encodeDropFileHeader(DropFileDel, repoId, jobId, sequence, len(answers))
	for _, answer := range answers {
		encoded = appendDropIdRow(encoded, answer.DropScanId)
		encoded = append(encoded, byte(answer.Outcome))
	}
	return sealDropFile(encoded)
}

// An ask or res file: one message's bytes.
func EncodeDropMessageFile(kind DropFileKind, repoId sidecar.Id, jobId sidecar.Id, message []byte) ([]byte, error) {
	if kind != DropFileAsk && kind != DropFileRes {
		return nil, fmt.Errorf("%w: a message in a %s file", ErrDropFileInvalid, kind)
	}
	encoded := encodeDropFileHeader(kind, repoId, jobId, 0, len(message))
	return sealDropFile(append(encoded, message...)), nil
}

// A file of any kind but list from its bytes, held to its key's repo, job, kind and sequence. ErrDropFileInvalid for
// bytes that break the layout.
func DecodeDropFile(encoded []byte, repoId sidecar.Id, jobId sidecar.Id, kind DropFileKind, sequence uint32) (*DropFile, error) {
	invalid := func(why string) error {
		return fmt.Errorf("%w: %s %d: %s", ErrDropFileInvalid, kind, sequence, why)
	}
	if len(encoded) < dropFileHeaderByteCount+dropFileTrailerByteCount {
		return nil, invalid("short")
	}
	body := encoded[:len(encoded)-dropFileTrailerByteCount]
	if trailer := sha256.Sum256(body); !bytes.Equal(trailer[:], encoded[len(body):]) {
		return nil, invalid("trailer")
	}
	if string(body[0:4]) != dropFileMagic || body[4] != dropFileFormat1 || body[6] != 0 || body[7] != 0 {
		return nil, invalid("header")
	}
	file := &DropFile{
		Kind:     DropFileKind(body[5]),
		RepoId:   sidecar.Id(body[8:24]),
		JobId:    sidecar.Id(body[24:40]),
		Sequence: binary.BigEndian.Uint32(body[40:44]),
	}
	rowCount := int(binary.BigEndian.Uint32(body[44:48]))
	if file.Kind != kind || file.RepoId != repoId || file.JobId != jobId || file.Sequence != sequence || kind == DropFileList {
		return nil, invalid("not the file its key names")
	}
	rows := body[dropFileHeaderByteCount:]
	idRows := func(rows []byte) ([]DropScanId, error) {
		if len(rows)%dropFileIdRowByteCount != 0 {
			return nil, invalid("rows")
		}
		scanIds := make([]DropScanId, 0, len(rows)/dropFileIdRowByteCount)
		for offset := 0; offset < len(rows); offset += dropFileIdRowByteCount {
			scanId := DropScanId{Id: [32]byte(rows[offset : offset+32]), Kind: DropIdKind(rows[offset+32])}
			if scanId.Kind != DropIdSegment && scanId.Kind != DropIdSlot {
				return nil, invalid("an id's kind")
			}
			scanIds = append(scanIds, scanId)
		}
		return scanIds, nil
	}
	switch kind {
	case DropFileSnap:
		if sequence == 0 {
			if len(rows) != rowCount*dropFileSnapDropRowByteCount {
				return nil, invalid("rows")
			}
			for offset := 0; offset < len(rows); offset += dropFileSnapDropRowByteCount {
				row := rows[offset : offset+dropFileSnapDropRowByteCount]
				place, err := sidecar.EvsUnpackPlace(row[56:76])
				if err != nil {
					return nil, invalid("place")
				}
				file.Covered = append(file.Covered, &DropCovered{
					DropId: sidecar.Id(row[0:16]), RefId: sidecar.Id(row[16:32]), Version: binary.BigEndian.Uint64(row[32:40]),
					PushId: sidecar.Id(row[40:56]), Place: place, SeenMs: int64(binary.BigEndian.Uint64(row[76:84])),
				})
			}
			break
		}
		if rowCount < 1 || len(rows) != rowCount*dropFileSnapRefRowByteCount || !bytes.Equal(rows[8:32], make([]byte, 24)) {
			return nil, invalid("rows")
		}
		file.Round = &DropRoundSnapshot{Horizon: time.UnixMilli(int64(binary.BigEndian.Uint64(rows[0:8])))}
		for offset := dropFileSnapRefRowByteCount; offset < len(rows); offset += dropFileSnapRefRowByteCount {
			row := rows[offset : offset+dropFileSnapRefRowByteCount]
			file.Round.Refs = append(file.Round.Refs, &DropRefSnapshot{
				RefId: sidecar.Id(row[0:16]), Marked: binary.BigEndian.Uint64(row[16:24]), Checked: binary.BigEndian.Uint64(row[24:32]),
			})
		}
	case DropFileCand, DropFileHeld:
		if len(rows) != rowCount*dropFileIdRowByteCount {
			return nil, invalid("rows")
		}
		scanIds, err := idRows(rows)
		if err != nil {
			return nil, err
		}
		file.Ids = scanIds
	case DropFileMark:
		if rowCount < 1 || len(rows) != rowCount*dropFileIdRowByteCount || !bytes.Equal(rows[24:33], make([]byte, 9)) {
			return nil, invalid("rows")
		}
		file.CursorRefId = sidecar.Id(rows[0:16])
		file.CursorVersion = binary.BigEndian.Uint64(rows[16:24])
		scanIds, err := idRows(rows[dropFileIdRowByteCount:])
		if err != nil {
			return nil, err
		}
		file.Ids = scanIds
	case DropFileDel:
		if len(rows) != rowCount*dropFileDelRowByteCount {
			return nil, invalid("rows")
		}
		for offset := 0; offset < len(rows); offset += dropFileDelRowByteCount {
			row := rows[offset : offset+dropFileDelRowByteCount]
			answer := &DropAnswer{
				DropScanId: DropScanId{Id: [32]byte(row[0:32]), Kind: DropIdKind(row[32])},
				Outcome:    DropOutcome(row[33]),
			}
			if (answer.Kind != DropIdSegment && answer.Kind != DropIdSlot) || answer.Outcome < DropOutcomeDeleted || DropOutcomeObserved < answer.Outcome {
				return nil, invalid("an answer")
			}
			file.Answers = append(file.Answers, answer)
		}
	case DropFileAsk, DropFileRes:
		if len(rows) != rowCount {
			return nil, invalid("message length")
		}
		file.Message = bytes.Clone(rows)
	default:
		return nil, invalid("kind")
	}
	return file, nil
}

// The job's or dry run's files on the segment cluster: writes each create-only and reads them back by kind.
type DropFiles struct {
	cluster  sidecar.BlobCluster
	repoId   sidecar.Id
	jobId    sidecar.Id
	settings *DropSettings
}

// The files of jobId in repoId on cluster, the segment cluster.
func NewDropFiles(cluster sidecar.BlobCluster, repoId sidecar.Id, jobId sidecar.Id, settings *DropSettings) *DropFiles {
	return &DropFiles{cluster: cluster, repoId: repoId, jobId: jobId, settings: settings}
}

// Writes a file's bytes at kind and sequence, If-None-Match: equal bytes already there are success, other bytes
// sidecar.ErrBlobImmutableMismatch (§11.8's immutable row).
func (self *DropFiles) Put(ctx context.Context, kind DropFileKind, sequence uint32, encoded []byte) error {
	_, err := sidecar.PutImmutable(ctx, self.cluster, DropFileKey(self.repoId, self.jobId, kind, sequence), encoded, nil)
	return err
}

// The sequences of kind's files, ascending.
func (self *DropFiles) Sequences(ctx context.Context, kind DropFileKind) ([]uint32, error) {
	prefix := dropFileKindPrefix(self.repoId, self.jobId, kind)
	sequences := []uint32{}
	startAfter := ""
	for {
		objects, more, err := self.cluster.List(ctx, prefix, startAfter, self.settings.ListLimit)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			if sequence, ok := dropFileSequence(prefix, object.Key); ok {
				sequences = append(sequences, sequence)
			}
		}
		if !more || len(objects) == 0 {
			return sequences, nil
		}
		startAfter = objects[len(objects)-1].Key
	}
}

// The most bytes a file of any kind but list holds under the settings: FileRowCount rows of the widest row and a
// cursor row, or a dry run's request, inside the envelope. A read bound, past which a file is not one this job wrote.
func (self *DropFiles) maxByteCount() int64 {
	rows := int64(self.settings.FileRowCount+1) * dropFileSnapDropRowByteCount
	return int64(dropFileHeaderByteCount+dropFileTrailerByteCount) + max(rows, self.settings.PreviewRequestByteCount)
}

// One file, nil when it does not exist.
func (self *DropFiles) Read(ctx context.Context, kind DropFileKind, sequence uint32) (*DropFile, error) {
	object, err := self.cluster.Get(ctx, DropFileKey(self.repoId, self.jobId, kind, sequence))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	encoded, err := readAllLimited(object, self.maxByteCount())
	if err != nil {
		return nil, err
	}
	return DecodeDropFile(encoded, self.repoId, self.jobId, kind, sequence)
}

// Every file of kind, in sequence order.
func (self *DropFiles) ReadAll(ctx context.Context, kind DropFileKind) ([]*DropFile, error) {
	sequences, err := self.Sequences(ctx, kind)
	if err != nil {
		return nil, err
	}
	files := make([]*DropFile, 0, len(sequences))
	for _, sequence := range sequences {
		file, err := self.Read(ctx, kind, sequence)
		if err != nil {
			return nil, err
		}
		if file == nil {
			return nil, fmt.Errorf("%w: %s %d listed and gone", ErrDropFileInvalid, kind, sequence)
		}
		files = append(files, file)
	}
	return files, nil
}

// The next sequence of kind: one past the highest written, 0 for none.
func (self *DropFiles) NextSequence(ctx context.Context, kind DropFileKind) (uint32, error) {
	sequences, err := self.Sequences(ctx, kind)
	if err != nil || len(sequences) == 0 {
		return 0, err
	}
	return sequences[len(sequences)-1] + 1, nil
}

// The candidates with each one's cand position, in cand order: what the delete cursor counts.
func (self *DropFiles) Candidates(ctx context.Context) ([]*DropCandidate, error) {
	files, err := self.ReadAll(ctx, DropFileCand)
	if err != nil {
		return nil, err
	}
	candidates := []*DropCandidate{}
	for _, file := range files {
		for row, scanId := range file.Ids {
			candidates = append(candidates, &DropCandidate{DropScanId: scanId, Cursor: DropCursor{Sequence: file.Sequence, Row: uint32(row)}})
		}
	}
	return candidates, nil
}

// The marks: the union of every mark file's ids, and the newest file's cursor.
func (self *DropFiles) Marks(ctx context.Context) (marks map[DropScanId]bool, cursorRefId sidecar.Id, cursorVersion uint64, err error) {
	files, err := self.ReadAll(ctx, DropFileMark)
	if err != nil {
		return nil, sidecar.Id{}, 0, err
	}
	marks = map[DropScanId]bool{}
	for _, file := range files {
		for _, scanId := range file.Ids {
			marks[scanId] = true
		}
		cursorRefId, cursorVersion = file.CursorRefId, file.CursorVersion
	}
	return marks, cursorRefId, cursorVersion, nil
}

// Each answered id's newest outcome.
func (self *DropFiles) Answers(ctx context.Context) (map[DropScanId]DropOutcome, error) {
	files, err := self.ReadAll(ctx, DropFileDel)
	if err != nil {
		return nil, err
	}
	answers := map[DropScanId]DropOutcome{}
	for _, file := range files {
		for _, answer := range file.Answers {
			answers[answer.DropScanId] = answer.Outcome
		}
	}
	return answers, nil
}

// One candidate and where cand holds it.
type DropCandidate struct {
	DropScanId
	Cursor DropCursor
}

// Whether a candidate at cursor lies before the cursor at: answered in this round.
func (self DropCursor) before(at DropCursor) bool {
	return self.Sequence < at.Sequence || (self.Sequence == at.Sequence && self.Row < at.Row)
}
