// RECORD.md section 10's verifiable log, on every leg: a tamper-evident log over the team record, held in the log's
// own checkpoint entries and summarized by signed checkpoints that witnesses cosign. No URnetwork server takes part
// and nothing here adds a server-visible value: a log_settings and a checkpoint are sealed entries like any other.
//
//	settings   a log admin's log_settings entry turns the log on, names its checkpointer, that device's log key and
//	           the witnesses, and governs batches from from_batch (On, Off)
//	monitor    every reader, at each sync (the reader's sync hook): batch k is the last + 1, starts at the tree's
//	           size, is signed by the checkpointer the governing settings name, its note's size and root match its
//	           leaves, each cosigned line verifies under a witness those settings name, versions only rise, and this
//	           reader's own derivation from the streams it holds gives the same leaves in the same places; a miss
//	           raises log_check and the batch is not taken
//	checkpoint the checkpointer, by section 10.2's steps (Checkpoint, Tick): read, batch, sign, journal, entry,
//	           witness, file
//
// Order across streams is section 10.1's batches, which the owner decided on record-md-log-order-across-streams
// (QD-203): batch by batch, streams by ref id within a batch, §16.8's order within a stream, a leaf already in the
// tree skipped. Witness calls run, a device's own HTTPS call to a host a log admin named in a signed log_settings,
// which the owner ruled no URnetwork carrier on record-md-witness-carrier (QD-242).
//
// A log never signs two roots at one size. Step 3 signs once a batch: the signed entry's bytes are written to this
// device's state before anything else happens to them, and every later step, in this process or the next, sends
// those bytes unchanged. A batch always adds a leaf, so sizes only rise. The log key is drawn here, kept in the
// record component's sealed state, shown to testHookSecret at its creation and read back nowhere else: no slot,
// export or packet holds it.
//
// V and D take no verifiable log, and an R log waits on its own question (record-md-record-repo-writers), so only
// the team record has one here. The states expired and lost are not told apart yet: a checkpoint leaf this reader
// holds no entry for counts as unbacked, raising nothing, since BASE is not on RecordStreams.
//
// Safe for concurrent use. Locks: a log's checkpointLock, then the reader's sync lock (through Sync), then stateLock,
// which is held across no I/O, barrier or call out. Barriers, keyed by the log: record.log.sign, .journal, .entry,
// .witness and .file, each .before and .after.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The log's format values (RECORD.md section 10.1's messages) and its state file's.
const (
	recordLogIntervalMinSeconds = 300
	recordLogIntervalMaxSeconds = 86400
	recordLogWitnessCount       = 8
	recordLogStateDirectory     = "log"
	recordLogStateVersion       = 1
	// a state file holds one pending checkpoint body and a few lines: bounded well past both
	recordLogStateByteCount = 64 * 1024 * 1024
)

var (
	// The log named takes no verifiable log: a vault, the directory, an R log, or a network with no team record.
	ErrRecordLogUnsupported = errors.New("record log has no verifiable log")
	// Turning the log on or off is a log admin's, on a device that writes the log.
	ErrRecordLogNotAdmin = errors.New("record log settings are a log admin's")
	// The act is a person's: it takes a command confirmed on /dev/tty or in an app's UI.
	ErrRecordLogUnconfirmed = errors.New("record log act takes a confirmed command")
	// The verifiable log is off: no log_settings governs the next batch, or the one that does turns it off.
	ErrRecordLogOff = errors.New("record log is off")
	// This device does not govern the next batch, so it signs none (section 10.2's step 1).
	ErrRecordLogNotCheckpointer = errors.New("record log is another device's to checkpoint")
	// The reader has not read every stream to its head, so no batch is cut now.
	ErrRecordLogBehind = errors.New("record log streams not read to their heads")
	// The settings asked for break section 10.1's bounds.
	ErrRecordLogSettings = errors.New("record log settings invalid")
	// No checkpoint this reader verified covers the entry.
	ErrRecordLogUncovered = errors.New("record log entry under no checkpoint")
	// The state file does not decode: nothing is signed on a guess.
	ErrRecordLogState = errors.New("record log state unreadable")
)

// One witness a log admin names.
type RecordLogWitnessArgs struct {
	Name string
	// Its submission prefix, https only.
	Url string
	// Its verifier key.
	Vkey string
}

// What turns a log on.
type RecordLogOnArgs struct {
	LogId Id
	// How often a batch is cut: zero for SidecarRecordSettings.CheckpointInterval, else 5 min to 24 h.
	Interval  time.Duration
	Witnesses []*RecordLogWitnessArgs
	// The person confirmed the command on /dev/tty or in an app's UI.
	Confirmed bool
}

// One witness as `ur record log status` names it.
type RecordLogWitnessStatus struct {
	Name string
	Url  string
	// The size this checkpointer last got it to cosign, 0 for none.
	Size uint64
	// Notes in a row it did not cosign.
	MissCount int
	// Why the last one failed: an http status with its meaning, or that it could not be reached. Empty after a
	// cosignature.
	Refusal string
	// The newest batch a cosignature of its is filed for in the log, 0 for none.
	CosignedBatch uint64
}

// A log as this device reads it.
type RecordLogStatus struct {
	LogId Id
	// A log_settings governs the next batch and turns the log on.
	On                    bool
	Origin                string
	CheckpointerSidecarId *Id
	// The governing log key, as a verifier key a recipient pins.
	LogKey          string
	IntervalSeconds uint32
	// This device is the checkpointer and holds the governing log key.
	ThisDevice bool
	Witnesses  []*RecordLogWitnessStatus
	// The newest batch verified, 0 for none, with the tree's size and root there.
	Batch uint64
	Size  uint64
	Root  []byte
	// Leaves the streams hold past the last batch, as of the last sync that read every stream.
	WaitingLeafCount int
	// Checkpoint leaves this reader holds no entry for: expired or lost.
	UnbackedLeafCount uint64
	// Why the checkpointer stopped at its last attempt, empty when it did not.
	Stopped string
	// Each finding the monitor raised, in order: what log_check alarmed about.
	Findings []string
}

// What a checkpoint attempt did.
type RecordLogCheckpointResult struct {
	// A batch was filed, or a journaled one sent again: its number, 0 for none.
	Batch uint64
	Size  uint64
	Note  []byte
	// The witnesses that cosigned this attempt's note.
	CosignedNames []string
}

// An entry's place in the tree under one verified checkpoint.
type RecordLogProof struct {
	LeafIndex uint64
	Batch     uint64
	// The signed note, with the lines of its cosigned rows appended (DisclosurePacket.checkpoints).
	Checkpoint []byte
	Size       uint64
	// RFC 9162 section 2.1.3's path at that size.
	InclusionPath [][]byte
}

// One verified log_settings.
type recordLogSettings struct {
	entryId        Id
	writerId       Id
	seq            uint64
	pushTimeMillis int64
	body           *protocol.LogSettingsBody
	checkpointerId Id
	logKey         *RecordLogVerifierKey
	witnesses      []*recordLogWitnessSetting
}

type recordLogWitnessSetting struct {
	name string
	url  string
	key  *RecordLogVerifierKey
}

// One checkpoint entry waiting to be judged, or judged.
type recordLogCandidate struct {
	entryId  Id
	writerId Id
	body     *protocol.LogCheckpointBody
	judged   bool
}

// One batch this reader verified.
type recordLogBatch struct {
	batch      uint64
	firstIndex uint64
	size       uint64
	root       [sha256.Size]byte
	note       []byte
	noteBody   []byte
	signerId   Id
	// the governing settings it was verified under
	settings *recordLogSettings
	// verified cosignature lines for this batch's note, as later entries filed them, by witness name
	cosignedNameLines map[string][]byte
}

type recordLogFrontierRow struct {
	version uint64
	chain   []byte
}

// One log as monitored. Every field but checkpointLock is RecordLog's stateLock's.
type recordLogView struct {
	logId Id
	// one Checkpoint, On or Off at a time
	checkpointLock sync.Mutex

	cursor     int
	entryIds   map[Id]bool
	settings   []*recordLogSettings
	candidates map[uint64][]*recordLogCandidate
	batches    []*recordLogBatch
	tree       *recordLogTree
	leafIndexs map[[sha256.Size]byte]uint64
	frontier   map[Id]*recordLogFrontierRow
	findings   []string
	findingSet map[string]bool
	unbacked   uint64
	// leaves the streams hold past the frontier, and those of them that are no checkpoint entry
	waitingLeafCount  int
	waitingOtherCount int
	stopped           string
	// this device holds a log key for the log: Tick only works then; unknown until the state file was read
	keyKnown bool
	keyHeld  bool
	// no tick before this, Unix milliseconds
	nextTickMillis int64
}

// The verifiable log of one network's record.
type RecordLog struct {
	record  *SidecarRecord
	witness RecordLogWitness

	stateLock sync.Mutex
	views     map[Id]*recordLogView
	stopWake  func() bool
}

func newRecordLog(record *SidecarRecord, witness RecordLogWitness) *RecordLog {
	if witness == nil {
		witness = NewRecordLogWitnessHttp(nil, nil)
	}
	return &RecordLog{record: record, witness: witness, views: map[Id]*recordLogView{}}
}

// Whether logId takes a verifiable log in this state: the team record alone, for now.
func recordLogVerifiable(auth RecordAuthView, logId Id) bool {
	teamRecordId, _ := recordTeamLogs(auth)
	return teamRecordId != nil && *teamRecordId == logId
}

// The log's view, made on first use.
func (self *RecordLog) view(logId Id) *recordLogView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	view, ok := self.views[logId]
	if !ok {
		view = &recordLogView{
			logId:      logId,
			entryIds:   map[Id]bool{},
			candidates: map[uint64][]*recordLogCandidate{},
			tree:       newRecordLogTree(),
			leafIndexs: map[[sha256.Size]byte]uint64{},
			frontier:   map[Id]*recordLogFrontierRow{},
			findingSet: map[string]bool{},
		}
		self.views[logId] = view
	}
	return view
}

// Holds a log_settings body to section 10.1's bounds: the writer's refusal and the reader's check.
func recordLogSettingsValidate(body *protocol.LogSettingsBody) error {
	checks := []error{
		recordBodyRule(strings.HasPrefix(body.GetOrigin(), recordLogOriginPrefix) && recordLogKeyNameValid(body.GetOrigin()), "log origin %q", body.GetOrigin()),
		recordBodyRule(recordBodyLength(body.GetCheckpointerSidecarId(), recordIdByteCount, false), "checkpointer_sidecar_id of %d bytes", len(body.GetCheckpointerSidecarId())),
		recordBodyRule(len(body.GetNotePublicKey()) == ed25519.PublicKeySize, "note_public_key of %d bytes", len(body.GetNotePublicKey())),
		recordBodyRule(body.GetIntervalSeconds() == 0 || (recordLogIntervalMinSeconds <= body.GetIntervalSeconds() && body.GetIntervalSeconds() <= recordLogIntervalMaxSeconds), "interval_seconds %d", body.GetIntervalSeconds()),
		recordBodyRule(len(body.GetWitnesses()) <= recordLogWitnessCount, "%d witnesses", len(body.GetWitnesses())),
		recordBodyRule(1 <= body.GetFromBatch(), "from_batch 0"),
	}
	names := map[string]bool{}
	for _, witness := range body.GetWitnesses() {
		key, err := ParseRecordLogVerifierKey(witness.GetVkey())
		checks = append(checks,
			recordBodyRule(err == nil && key.Name == witness.GetName(), "witness %q's verifier key", witness.GetName()),
			recordBodyRule(recordLogWitnessUrlValid(witness.GetUrl()), "witness %q's url is not https", witness.GetName()),
			recordBodyRule(!names[witness.GetName()], "witness %q named twice", witness.GetName()),
		)
		names[witness.GetName()] = true
	}
	return errors.Join(checks...)
}

// Holds a checkpoint body to section 10.1's shape. What it says of the tree is the monitor's to judge.
func recordLogCheckpointValidate(body *protocol.LogCheckpointBody) error {
	checks := []error{
		recordBodyRule(1 <= body.GetBatch(), "batch 0"),
		recordBodyRule(len(body.GetLeaves())%sha256.Size == 0, "leaves of %d bytes", len(body.GetLeaves())),
		recordBodyRule(0 < len(body.GetNote()) && len(body.GetNote()) <= recordLogNoteByteCount, "a note of %d bytes", len(body.GetNote())),
		recordBodyRule(len(body.GetCosigned()) <= recordLogWitnessCount*recordLogWitnessCount, "%d cosigned rows", len(body.GetCosigned())),
	}
	for i, row := range body.GetFrontier() {
		checks = append(checks,
			recordBodyRule(len(row.GetRefId()) == recordIdByteCount, "a frontier ref_id of %d bytes", len(row.GetRefId())),
			recordBodyRule(len(row.GetChain()) == sha256.Size, "a frontier chain of %d bytes", len(row.GetChain())),
			recordBodyRule(1 <= row.GetVersion(), "a frontier version 0"),
			recordBodyRule(i == 0 || bytes.Compare(body.GetFrontier()[i-1].GetRefId(), row.GetRefId()) < 0, "a frontier out of ref_id order"),
		)
	}
	for _, row := range body.GetCosigned() {
		checks = append(checks,
			recordBodyRule(1 <= row.GetBatch() && row.GetBatch() < body.GetBatch(), "a cosigned row of batch %d in batch %d", row.GetBatch(), body.GetBatch()),
			recordBodyRule(0 < len(row.GetLines()) && len(row.GetLines()) <= recordLogNoteByteCount, "cosigned lines of %d bytes", len(row.GetLines())),
		)
	}
	return errors.Join(checks...)
}

// The settings that govern batch among settings (section 10.2's who row): of those with from_batch at or below it,
// the highest from_batch, then section 5.5's newest: each writer's newest by seq, of those the latest push time, then
// the higher writer id. Nil for none.
func recordLogGoverning(settings []*recordLogSettings, batch uint64) *recordLogSettings {
	fromBatch := uint64(0)
	for _, entry := range settings {
		if entry.body.GetFromBatch() <= batch {
			fromBatch = max(fromBatch, entry.body.GetFromBatch())
		}
	}
	if fromBatch == 0 {
		return nil
	}
	writerNewest := map[Id]*recordLogSettings{}
	for _, entry := range settings {
		if entry.body.GetFromBatch() != fromBatch {
			continue
		}
		if newest, ok := writerNewest[entry.writerId]; !ok || newest.seq < entry.seq {
			writerNewest[entry.writerId] = entry
		}
	}
	var governing *recordLogSettings
	for _, entry := range writerNewest {
		if governing == nil || governing.pushTimeMillis < entry.pushTimeMillis ||
			(governing.pushTimeMillis == entry.pushTimeMillis && governing.writerId.Cmp(entry.writerId) < 0) {
			governing = entry
		}
	}
	return governing
}

// A finding, once: kept for status, and told whether it is new, so its alarm is raised once.
func (self *recordLogView) findWithLock(format string, args ...any) bool {
	finding := fmt.Sprintf(format, args...)
	if self.findingSet[finding] {
		return false
	}
	self.findingSet[finding] = true
	self.findings = append(self.findings, finding)
	return true
}

// The pushes of stream after version after, through version through.
func recordLogPushesBetween(stream *RecordReadStream, after uint64, through uint64) []*RecordReadPush {
	first := sort.Search(len(stream.Pushes), func(i int) bool { return after < stream.Pushes[i].Version })
	last := sort.Search(len(stream.Pushes), func(i int) bool { return through < stream.Pushes[i].Version })
	return stream.Pushes[first:last]
}

// What a batch running through frontier takes from the streams this reader holds, in section 10.1's order: streams
// as the frontier lists them, pushes by version, leaves in their push's order, one already in the tree or earlier in
// the batch skipped. pending says the reader has not read that far; mismatch names a frontier row whose chain value
// is not this reader's.
func (self *recordLogView) deriveWithLock(refStreams map[Id]*RecordReadStream, frontier []*protocol.LogFrontier) (leaves []RecordReadPushLeaf, pending bool, mismatch string) {
	taken := map[[sha256.Size]byte]bool{}
	for _, row := range frontier {
		refId := Id(row.GetRefId())
		stream, ok := refStreams[refId]
		if !ok || len(stream.Pushes) == 0 || stream.Pushes[len(stream.Pushes)-1].Version < row.GetVersion() {
			return nil, true, ""
		}
		after := uint64(0)
		if before, ok := self.frontier[refId]; ok {
			after = before.version
		}
		pushes := recordLogPushesBetween(stream, after, row.GetVersion())
		if len(pushes) == 0 || pushes[len(pushes)-1].Version != row.GetVersion() {
			return nil, false, fmt.Sprintf("version %d of ref %s is no push this reader holds", row.GetVersion(), refId)
		}
		if chain := pushes[len(pushes)-1].Chain; len(chain) != 0 && !bytes.Equal(chain, row.GetChain()) {
			return nil, false, fmt.Sprintf("the chain value at version %d of ref %s is not this reader's", row.GetVersion(), refId)
		}
		for _, push := range pushes {
			for _, leaf := range push.Leaves {
				if _, held := self.leafIndexs[leaf.Leaf]; held || taken[leaf.Leaf] {
					continue
				}
				taken[leaf.Leaf] = true
				leaves = append(leaves, leaf)
			}
		}
	}
	return leaves, false, ""
}

// The frontier a batch cut now runs through: each stream that moved past the last batch, by ref id, to its newest
// push, stopping at a push boundary once leafCount leaves are in. An error for a stream whose binding states no ref
// id or chain value, which no frontier can name.
func (self *recordLogView) cutWithLock(streams []*RecordReadStream, leafCount int) ([]*protocol.LogFrontier, error) {
	moved := []*RecordReadStream{}
	for _, stream := range streams {
		if len(stream.Pushes) == 0 {
			continue
		}
		if stream.RefId == (Id{}) {
			return nil, fmt.Errorf("%w: stream %s has no ref id", ErrRecordLogBehind, stream.StreamSidecarId)
		}
		moved = append(moved, stream)
	}
	slices.SortFunc(moved, func(a *RecordReadStream, b *RecordReadStream) int { return bytes.Compare(a.RefId[:], b.RefId[:]) })
	frontier := []*protocol.LogFrontier{}
	taken := map[[sha256.Size]byte]bool{}
	for _, stream := range moved {
		after := uint64(0)
		if before, ok := self.frontier[stream.RefId]; ok {
			after = before.version
		}
		var through *RecordReadPush
		full := false
		for _, push := range recordLogPushesBetween(stream, after, stream.Pushes[len(stream.Pushes)-1].Version) {
			fresh := 0
			for _, leaf := range push.Leaves {
				if _, held := self.leafIndexs[leaf.Leaf]; !held && !taken[leaf.Leaf] {
					fresh += 1
				}
			}
			if 0 < len(taken) && leafCount < len(taken)+fresh {
				full = true
				break
			}
			for _, leaf := range push.Leaves {
				if _, held := self.leafIndexs[leaf.Leaf]; !held {
					taken[leaf.Leaf] = true
				}
			}
			through = push
		}
		if through != nil {
			if len(through.Chain) != sha256.Size {
				return nil, fmt.Errorf("%w: stream %s has no chain value", ErrRecordLogBehind, stream.StreamSidecarId)
			}
			frontier = append(frontier, &protocol.LogFrontier{RefId: stream.RefId.Bytes(), Version: through.Version, Chain: bytes.Clone(through.Chain)})
		}
		if full {
			break
		}
	}
	return frontier, nil
}

// Judges candidate as batch len(batches) + 1 under governing: nil when it is that batch, pending when this reader
// has not read the streams it runs through, else why it is not.
func (self *recordLogView) judgeWithLock(candidate *recordLogCandidate, governing *recordLogSettings, refStreams map[Id]*RecordReadStream) (batch *recordLogBatch, leaves [][sha256.Size]byte, unbacked uint64, pending bool, reason string) {
	body := candidate.body
	number := uint64(len(self.batches)) + 1
	if body.GetBatch() != number {
		return nil, nil, 0, false, fmt.Sprintf("batch %d is not the last + 1", body.GetBatch())
	}
	if body.GetFirstIndex() != self.tree.size() {
		return nil, nil, 0, false, fmt.Sprintf("batch %d starts at %d, and the tree holds %d", number, body.GetFirstIndex(), self.tree.size())
	}
	if len(body.GetLeaves()) == 0 {
		return nil, nil, 0, false, fmt.Sprintf("batch %d adds no leaf", number)
	}
	batchSet := map[[sha256.Size]byte]bool{}
	for at := 0; at < len(body.GetLeaves()); at += sha256.Size {
		leaf := [sha256.Size]byte(body.GetLeaves()[at : at+sha256.Size])
		if _, held := self.leafIndexs[leaf]; held || batchSet[leaf] {
			return nil, nil, 0, false, fmt.Sprintf("batch %d repeats a leaf the tree holds", number)
		}
		batchSet[leaf] = true
		leaves = append(leaves, leaf)
	}
	for _, row := range body.GetFrontier() {
		if before, ok := self.frontier[Id(row.GetRefId())]; ok && row.GetVersion() <= before.version {
			return nil, nil, 0, false, fmt.Sprintf("batch %d winds ref %s back", number, Id(row.GetRefId()))
		}
	}
	note, err := ParseRecordLogNote(body.GetNote())
	if err != nil {
		return nil, nil, 0, false, fmt.Sprintf("batch %d's note does not parse", number)
	}
	size := self.tree.size() + uint64(len(leaves))
	grown := &recordLogTree{leaves: append(slices.Clone(self.tree.leaves), leaves...), nodes: self.tree.nodes}
	root := grown.root()
	if note.Origin != RecordLogOrigin(self.logId) || note.Size != size || note.Root != root {
		return nil, nil, 0, false, fmt.Sprintf("batch %d's note does not match its leaves", number)
	}
	if len(note.Signatures) != 1 {
		return nil, nil, 0, false, fmt.Sprintf("batch %d's note is not signed by the log key alone", number)
	}
	if _, err := note.SignedBy(governing.logKey); err != nil {
		return nil, nil, 0, false, fmt.Sprintf("batch %d's note is not signed by the governing log key", number)
	}
	derived, pending, mismatch := self.deriveWithLock(refStreams, body.GetFrontier())
	if pending {
		return nil, nil, 0, true, ""
	}
	if mismatch != "" {
		return nil, nil, 0, false, fmt.Sprintf("batch %d: %s", number, mismatch)
	}
	// every leaf this reader derives is in the batch, in the same order; a batch leaf it derives none for is an
	// entry it no longer holds, expired or lost
	at := 0
	for _, leaf := range derived {
		for at < len(leaves) && leaves[at] != leaf.Leaf {
			at += 1
			unbacked += 1
		}
		if at == len(leaves) {
			return nil, nil, 0, false, fmt.Sprintf("batch %d leaves out or misplaces an entry at or below its frontier", number)
		}
		at += 1
	}
	unbacked += uint64(len(leaves) - at)
	return &recordLogBatch{
		batch: number, firstIndex: body.GetFirstIndex(), size: size, root: root, note: bytes.Clone(body.GetNote()), noteBody: note.Body,
		signerId: candidate.writerId, settings: governing, cosignedNameLines: map[string][]byte{},
	}, leaves, unbacked, false, ""
}

// Files a checkpoint's cosigned rows under the batches they cosign: each line must verify, over that batch's note,
// under a witness the settings governing that batch name. False names what did not.
func (self *recordLogView) cosignedWithLock(body *protocol.LogCheckpointBody) (map[uint64]map[string][]byte, string) {
	filed := map[uint64]map[string][]byte{}
	for _, row := range body.GetCosigned() {
		if row.GetBatch() == 0 || uint64(len(self.batches)) < row.GetBatch() {
			return nil, fmt.Sprintf("batch %d cosigns batch %d, which this reader has not verified", body.GetBatch(), row.GetBatch())
		}
		cosigned := self.batches[row.GetBatch()-1]
		signatures, err := ParseRecordLogSignatureLines(row.GetLines())
		if err != nil || len(signatures) == 0 {
			return nil, fmt.Sprintf("batch %d's cosigned lines for batch %d do not parse", body.GetBatch(), row.GetBatch())
		}
		for _, signature := range signatures {
			index := slices.IndexFunc(cosigned.settings.witnesses, func(witness *recordLogWitnessSetting) bool { return witness.name == signature.Name })
			if index < 0 {
				return nil, fmt.Sprintf("batch %d carries a line of %s, which the settings governing batch %d do not name", body.GetBatch(), signature.Name, row.GetBatch())
			}
			if _, err := cosigned.settings.witnesses[index].key.Verify(cosigned.noteBody, signature); err != nil {
				return nil, fmt.Sprintf("batch %d carries a line of %s that does not verify over batch %d's note", body.GetBatch(), signature.Name, row.GetBatch())
			}
			if filed[row.GetBatch()] == nil {
				filed[row.GetBatch()] = map[string][]byte{}
			}
			filed[row.GetBatch()][signature.Name] = signature.line()
		}
	}
	return filed, ""
}

// One log_settings entry as read, judged outside the lock.
func (self *RecordLog) settingsOf(auth RecordAuthView, logId Id, entry *RecordReadEntry) (*recordLogSettings, string) {
	writerId := recordIdOf(entry.Header.Header.GetWriterSidecarId())
	body := &protocol.LogSettingsBody{}
	if err := proto.Unmarshal(entry.Body, body); err != nil {
		return nil, fmt.Sprintf("log_settings %s does not parse", entry.EntryId)
	}
	if err := recordLogSettingsValidate(body); err != nil || body.GetOrigin() != RecordLogOrigin(logId) {
		return nil, fmt.Sprintf("log_settings %s breaks its bounds or names another log", entry.EntryId)
	}
	if len(entry.Copies) == 0 || entry.Copies[0].AuthPin == nil {
		return nil, fmt.Sprintf("log_settings %s has no push pin", entry.EntryId)
	}
	pinView, err := auth.At(entry.Copies[0].AuthPin)
	if err != nil {
		// not judged at a pin this state cannot answer for, and so not taken: the closed reading
		return nil, fmt.Sprintf("log_settings %s is at a pin this state does not answer for", entry.EntryId)
	}
	if !pinView.Admins(logId, writerId) {
		return nil, fmt.Sprintf("log_settings %s is from no admin of the log", entry.EntryId)
	}
	logKey, err := NewRecordLogVerifierKey(body.GetOrigin(), RecordLogKeyTypeEd25519, body.GetNotePublicKey())
	if err != nil {
		return nil, fmt.Sprintf("log_settings %s names no log key", entry.EntryId)
	}
	settings := &recordLogSettings{
		entryId: entry.EntryId, writerId: writerId, seq: entry.Header.Header.GetSeq(), pushTimeMillis: entry.PushTimeMillis, body: body,
		checkpointerId: recordIdOf(body.GetCheckpointerSidecarId()), logKey: logKey,
	}
	for _, witness := range body.GetWitnesses() {
		key, err := ParseRecordLogVerifierKey(witness.GetVkey())
		if err != nil {
			return nil, fmt.Sprintf("log_settings %s names a witness with no key", entry.EntryId)
		}
		settings.witnesses = append(settings.witnesses, &recordLogWitnessSetting{name: witness.GetName(), url: witness.GetUrl(), key: key})
	}
	return settings, ""
}

// Section 10.2's monitor row, run at each sync of logId: takes the log_settings and checkpoint entries read since the
// last pass, then verifies batches in order as far as they go.
func (self *RecordLog) monitor(ctx context.Context, logId Id) {
	auth := self.record.writer.auth()
	if !recordLogVerifiable(auth, logId) {
		return
	}
	view := self.view(logId)
	reader := self.record.reader
	cursor := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return view.cursor
	}()
	entries, next := reader.EntriesOfKinds(logId, cursor, RecordKindLogSettings, RecordKindCheckpoint)
	streams, complete := reader.Streams(logId)
	refStreams := map[Id]*RecordReadStream{}
	for _, stream := range streams {
		if stream.RefId != (Id{}) {
			refStreams[stream.RefId] = stream
		}
	}
	type judgedSettings struct {
		settings *recordLogSettings
		finding  string
		writerId Id
	}
	newSettings := []*judgedSettings{}
	newCandidates := []*recordLogCandidate{}
	type alarm struct {
		signerId Id
	}
	alarms := []*alarm{}
	for _, entry := range entries {
		writerId := recordIdOf(entry.Header.Header.GetWriterSidecarId())
		if entry.State != RecordEntryLive || entry.Body == nil {
			// a forked, erased or invalid entry states nothing: the reader alarmed on it already
			continue
		}
		switch entry.Kind() {
		case RecordKindLogSettings:
			settings, finding := self.settingsOf(auth, logId, entry)
			newSettings = append(newSettings, &judgedSettings{settings: settings, finding: finding, writerId: writerId})
		case RecordKindCheckpoint:
			body := &protocol.LogCheckpointBody{}
			if err := proto.Unmarshal(entry.Body, body); err != nil || recordLogCheckpointValidate(body) != nil {
				newSettings = append(newSettings, &judgedSettings{finding: fmt.Sprintf("checkpoint %s breaks its shape", entry.EntryId), writerId: writerId})
				continue
			}
			newCandidates = append(newCandidates, &recordLogCandidate{entryId: entry.EntryId, writerId: writerId, body: body})
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		view.cursor = next
		for _, judged := range newSettings {
			if judged.settings == nil {
				if view.findWithLock("%s", judged.finding) {
					alarms = append(alarms, &alarm{signerId: judged.writerId})
				}
				continue
			}
			if !view.entryIds[judged.settings.entryId] {
				view.entryIds[judged.settings.entryId] = true
				view.settings = append(view.settings, judged.settings)
			}
		}
		for _, candidate := range newCandidates {
			if view.entryIds[candidate.entryId] {
				continue
			}
			view.entryIds[candidate.entryId] = true
			view.candidates[candidate.body.GetBatch()] = append(view.candidates[candidate.body.GetBatch()], candidate)
		}
		// batches already verified: a later entry for one is a copy, a fork, or another signer's
		for number, candidates := range view.candidates {
			if uint64(len(view.batches)) < number {
				continue
			}
			held := view.batches[number-1]
			for _, candidate := range candidates {
				if candidate.judged {
					continue
				}
				candidate.judged = true
				switch {
				case candidate.writerId != held.signerId:
					if view.findWithLock("batch %d has an entry from %s, which does not govern it", number, candidate.writerId) {
						alarms = append(alarms, &alarm{signerId: candidate.writerId})
					}
				case !bytes.Equal(candidate.body.GetNote(), held.note):
					if view.findWithLock("batch %d has a second entry with another note: a fork", number) {
						alarms = append(alarms, &alarm{signerId: candidate.writerId})
					}
				}
			}
		}
		for {
			number := uint64(len(view.batches)) + 1
			governing := recordLogGoverning(view.settings, number)
			accepted := false
			for _, candidate := range view.candidates[number] {
				if candidate.judged {
					continue
				}
				if governing == nil || governing.body.GetIntervalSeconds() == 0 || governing.checkpointerId != candidate.writerId {
					candidate.judged = true
					if view.findWithLock("batch %d has an entry from %s, which does not govern it", number, candidate.writerId) {
						alarms = append(alarms, &alarm{signerId: candidate.writerId})
					}
					continue
				}
				if accepted {
					// judged against the batch just taken, at the next pass's copy and fork check
					continue
				}
				batch, leaves, unbacked, pending, reason := view.judgeWithLock(candidate, governing, refStreams)
				if pending {
					continue
				}
				candidate.judged = true
				filed, cosignedReason := map[uint64]map[string][]byte{}, ""
				if reason == "" {
					filed, cosignedReason = view.cosignedWithLock(candidate.body)
					reason = cosignedReason
				}
				if reason != "" {
					if view.findWithLock("%s", reason) {
						alarms = append(alarms, &alarm{signerId: candidate.writerId})
					}
					continue
				}
				for _, leaf := range leaves {
					view.leafIndexs[leaf] = view.tree.size()
					view.tree.append(leaf)
				}
				for _, row := range candidate.body.GetFrontier() {
					view.frontier[Id(row.GetRefId())] = &recordLogFrontierRow{version: row.GetVersion(), chain: bytes.Clone(row.GetChain())}
				}
				view.batches = append(view.batches, batch)
				view.unbacked += unbacked
				for cosignedBatch, nameLines := range filed {
					for name, line := range nameLines {
						view.batches[cosignedBatch-1].cosignedNameLines[name] = line
					}
				}
				accepted = true
			}
			if !accepted {
				break
			}
		}
		// a batch past the next one from its governing signer, with the next one missing after a whole read
		next := uint64(len(view.batches)) + 1
		if complete {
			for number, candidates := range view.candidates {
				if number <= next {
					continue
				}
				governing := recordLogGoverning(view.settings, number)
				for _, candidate := range candidates {
					if governing != nil && governing.checkpointerId == candidate.writerId && len(view.candidates[next]) == 0 {
						if view.findWithLock("batch %d is in the log and batch %d is not", number, next) {
							alarms = append(alarms, &alarm{signerId: candidate.writerId})
						}
					}
				}
			}
			view.waitingLeafCount, view.waitingOtherCount = 0, 0
			if frontier, err := view.cutWithLock(streams, int(^uint(0)>>1)); err == nil {
				waiting, _, _ := view.deriveWithLock(refStreams, frontier)
				view.waitingLeafCount = len(waiting)
				for _, leaf := range waiting {
					if leaf.Kind != RecordKindCheckpoint {
						view.waitingOtherCount += 1
					}
				}
			}
		}
	}()
	for _, raised := range alarms {
		signerId := raised.signerId
		if self.record.writer.log.V(1).Enabled() {
			self.record.writer.log.Infof("[record]the verifiable log of %s raised a finding about %s", logId, signerId)
		}
		self.record.writer.raise(SidecarRecordAlarmLogCheck, logId, &signerId)
	}
}

// This device's state for one log, the record component's sealed file log/<log_id>: its log key, the batch it signed
// and has not finished, the cosignature lines waiting to ride the next entry, and what it knows of each witness.
type recordLogStateDocument struct {
	Version int `json:"version"`
	LogId   Id  `json:"log_id"`
	// the log key's seed, drawn once
	KeySeed []byte `json:"key_seed,omitempty"`
	// section 10.2's journal row: the batch signed and not yet filed whole
	Pending *recordLogPendingDocument `json:"pending,omitempty"`
	// lines got from witnesses, waiting for the next checkpoint entry's cosigned
	Cosigned             []*recordLogCosignedDocument `json:"cosigned,omitempty"`
	Witnesses            []*recordLogWitnessDocument  `json:"witnesses,omitempty"`
	LastCheckpointMillis int64                        `json:"last_checkpoint_millis,omitempty"`
}

type recordLogPendingDocument struct {
	Batch uint64 `json:"batch"`
	// the checkpoint entry's body as signed and marshaled once: what every retry appends
	Body []byte `json:"body"`
}

type recordLogCosignedDocument struct {
	Batch uint64 `json:"batch"`
	Lines []byte `json:"lines"`
}

type recordLogWitnessDocument struct {
	Name      string `json:"name"`
	Size      uint64 `json:"size"`
	MissCount int    `json:"miss_count"`
	Refusal   string `json:"refusal,omitempty"`
}

func recordLogStateName(logId Id) string {
	return recordLogStateDirectory + "/" + recordChainIdText(logId)
}

// Reads the log's state, a fresh one where the file is absent. A file that does not decode is ErrRecordLogState.
func (self *RecordLog) readState(logId Id) (*recordLogStateDocument, error) {
	state := &recordLogStateDocument{Version: recordLogStateVersion, LogId: logId}
	reader, err := self.record.writer.store.Open(recordLogStateName(logId))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, recordLogStateByteCount+1))
	if err != nil {
		return nil, err
	}
	if recordLogStateByteCount < len(content) {
		return nil, fmt.Errorf("%w: past its bound", ErrRecordLogState)
	}
	if err := recordChainDecode(content, state); err != nil || state.Version != recordLogStateVersion || state.LogId != logId ||
		(len(state.KeySeed) != 0 && len(state.KeySeed) != ed25519.SeedSize) {
		return nil, fmt.Errorf("%w: log %s", ErrRecordLogState, logId)
	}
	return state, nil
}

// Writes the log's state, durably.
func (self *RecordLog) writeState(state *recordLogStateDocument) error {
	content, err := json.Marshal(state)
	if err != nil {
		return err
	}
	writer, err := self.record.writer.store.Create(recordLogStateName(state.LogId))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// The witness's row in the state, made on first use.
func (self *recordLogStateDocument) witness(name string) *recordLogWitnessDocument {
	for _, witness := range self.Witnesses {
		if witness.Name == name {
			return witness
		}
	}
	witness := &recordLogWitnessDocument{Name: name}
	self.Witnesses = append(self.Witnesses, witness)
	return witness
}

// The log key the state holds, nil for none.
func (self *recordLogStateDocument) logKey() ed25519.PrivateKey {
	if len(self.KeySeed) != ed25519.SeedSize {
		return nil
	}
	return ed25519.NewKeyFromSeed(self.KeySeed)
}

// Notes whether this device holds a log key for the view's log.
func (self *RecordLog) noteKey(view *recordLogView, held bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	view.keyKnown = true
	view.keyHeld = held
}

// Notes why the checkpointer stopped, or that it did not.
func (self *RecordLog) noteStopped(view *recordLogView, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	view.stopped = ""
	if err != nil {
		view.stopped = err.Error()
	}
}

// What the view holds now for the next batch: its number, the settings governing it, and the tree's size.
func (self *RecordLog) nextBatch(view *recordLogView) (uint64, *recordLogSettings, uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	number := uint64(len(view.batches)) + 1
	return number, recordLogGoverning(view.settings, number), view.tree.size()
}

// Whether this sidecar may sign the log's settings: an admin of the log, on a device that writes its stream.
func (self *RecordLog) checkAdmin(logId Id, confirmed bool) error {
	auth := self.record.writer.auth()
	if !recordLogVerifiable(auth, logId) {
		return fmt.Errorf("%w: %s", ErrRecordLogUnsupported, logId)
	}
	sidecarId := self.record.writer.sidecarId
	if !auth.Admins(logId, sidecarId) || !auth.Writes(logId, sidecarId) || !auth.Reads(logId, sidecarId) {
		return ErrRecordLogNotAdmin
	}
	if !confirmed {
		return ErrRecordLogUnconfirmed
	}
	return nil
}

// Files a log_settings entry and waits for it to commit and be read back.
func (self *RecordLog) fileSettings(ctx context.Context, logId Id, body *protocol.LogSettingsBody) error {
	if err := recordLogSettingsValidate(body); err != nil {
		return fmt.Errorf("%w: %v", ErrRecordLogSettings, err)
	}
	refs, err := self.record.writer.Append(&RecordDraft{Kind: RecordKindLogSettings, Source: RecordSourceApprover, NoSession: true, Body: body})
	if err != nil {
		return err
	}
	if err := self.record.Land(ctx, refs); err != nil {
		return err
	}
	return self.record.reader.Sync(ctx, logId)
}

// Turns the log on, or changes its interval or witnesses: a log_settings naming this device as checkpointer, with
// its log key, drawn at the first call, governing from the first batch this device has not read (section 10.2's
// successor row). A log admin's confirmed command, on a device that writes the log.
func (self *RecordLog) On(ctx context.Context, args *RecordLogOnArgs) error {
	if args == nil {
		return fmt.Errorf("%w: no arguments", ErrRecordLogSettings)
	}
	if err := self.checkAdmin(args.LogId, args.Confirmed); err != nil {
		return err
	}
	view := self.view(args.LogId)
	view.checkpointLock.Lock()
	defer view.checkpointLock.Unlock()
	interval := args.Interval
	if interval == 0 {
		interval = self.record.writer.settings.CheckpointInterval
	}
	body := &protocol.LogSettingsBody{
		Origin:                RecordLogOrigin(args.LogId),
		CheckpointerSidecarId: self.record.writer.sidecarId.Bytes(),
		IntervalSeconds:       uint32(interval / time.Second),
	}
	if interval%time.Second != 0 || body.GetIntervalSeconds() == 0 {
		return fmt.Errorf("%w: an interval of %s", ErrRecordLogSettings, interval)
	}
	for _, witness := range args.Witnesses {
		body.Witnesses = append(body.Witnesses, &protocol.LogWitness{Name: witness.Name, Url: witness.Url, Vkey: witness.Vkey})
	}
	if err := self.record.reader.Sync(ctx, args.LogId); err != nil {
		return err
	}
	state, err := self.readState(args.LogId)
	if err != nil {
		return err
	}
	if state.logKey() == nil {
		seed := make([]byte, ed25519.SeedSize)
		random := self.record.writer.random
		if random == nil {
			random = rand.Reader
		}
		if _, err := io.ReadFull(random, seed); err != nil {
			return err
		}
		testHookSecret("record_log_key", seed)
		state.KeySeed = seed
		if err := self.writeState(state); err != nil {
			return err
		}
	}
	self.noteKey(view, true)
	body.NotePublicKey = state.logKey().Public().(ed25519.PublicKey)
	body.FromBatch, _, _ = self.nextBatch(view)
	return self.fileSettings(ctx, args.LogId, body)
}

// Turns the log off from the next batch: a log_settings with interval 0. A log admin's confirmed command.
func (self *RecordLog) Off(ctx context.Context, logId Id, confirmed bool) error {
	if err := self.checkAdmin(logId, confirmed); err != nil {
		return err
	}
	view := self.view(logId)
	view.checkpointLock.Lock()
	defer view.checkpointLock.Unlock()
	if err := self.record.reader.Sync(ctx, logId); err != nil {
		return err
	}
	number, governing, _ := self.nextBatch(view)
	if governing == nil || governing.body.GetIntervalSeconds() == 0 {
		return ErrRecordLogOff
	}
	return self.fileSettings(ctx, logId, &protocol.LogSettingsBody{
		Origin:                governing.body.GetOrigin(),
		CheckpointerSidecarId: governing.body.GetCheckpointerSidecarId(),
		NotePublicKey:         governing.body.GetNotePublicKey(),
		IntervalSeconds:       0,
		FromBatch:             number,
	})
}

// Whether the newest verified batch is number, signed by this device with note.
func (self *RecordLog) batchFiled(view *recordLogView, number uint64, note []byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return number <= uint64(len(view.batches)) && bytes.Equal(view.batches[number-1].note, note) &&
		view.batches[number-1].signerId == self.record.writer.sidecarId
}

// Section 10.2's steps for one batch, when one is due or force asks for it, and for a batch an earlier attempt
// signed and did not finish, always. Answers what it filed; a nil result with a nil error means nothing was due.
// ErrRecordLogNotCheckpointer, ErrRecordLogOff and ErrRecordLogBehind are step 1's stops, which Status names.
func (self *RecordLog) Checkpoint(ctx context.Context, logId Id, force bool) (*RecordLogCheckpointResult, error) {
	if !recordLogVerifiable(self.record.writer.auth(), logId) {
		return nil, fmt.Errorf("%w: %s", ErrRecordLogUnsupported, logId)
	}
	view := self.view(logId)
	view.checkpointLock.Lock()
	defer view.checkpointLock.Unlock()
	result, err := self.checkpoint(ctx, view, force)
	self.noteStopped(view, err)
	return result, err
}

func (self *RecordLog) checkpoint(ctx context.Context, view *recordLogView, force bool) (*RecordLogCheckpointResult, error) {
	logId := view.logId
	writer := self.record.writer
	reader := self.record.reader
	hookKey := recordChainIdText(logId)
	sidecarId := writer.sidecarId

	// 1 read
	if err := reader.Sync(ctx, logId); err != nil {
		return nil, err
	}
	state, err := self.readState(logId)
	if err != nil {
		return nil, err
	}
	logKey := state.logKey()
	self.noteKey(view, logKey != nil)
	number, governing, treeSize := self.nextBatch(view)
	governs := func(governing *recordLogSettings) bool {
		return governing != nil && governing.checkpointerId == sidecarId && logKey != nil &&
			bytes.Equal(governing.logKey.PublicKey, logKey.Public().(ed25519.PublicKey))
	}

	var body *protocol.LogCheckpointBody
	if state.Pending != nil {
		body = &protocol.LogCheckpointBody{}
		if err := proto.Unmarshal(state.Pending.Body, body); err != nil || body.GetBatch() != state.Pending.Batch {
			return nil, fmt.Errorf("%w: the journaled batch of log %s", ErrRecordLogState, logId)
		}
		switch {
		case self.batchFiled(view, body.GetBatch(), body.GetNote()):
			// its entry is in the log: step 6 sends the filed note again
			number = body.GetBatch()
			governing = func() *recordLogSettings {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				return view.batches[number-1].settings
			}()
		case body.GetBatch() == number && governs(governing):
			// signed, and not in the log yet: step 5 sends its bytes unchanged
		default:
			// another signer governs that batch now, or another entry took it: a note that was journaled and
			// never pushed reached no one, and goes
			state.Pending = nil
			if err := self.writeState(state); err != nil {
				return nil, err
			}
			body = nil
		}
	}
	if body == nil {
		if governing == nil || governing.body.GetIntervalSeconds() == 0 {
			return nil, ErrRecordLogOff
		}
		if !governs(governing) {
			return nil, ErrRecordLogNotCheckpointer
		}
		streams, complete := reader.Streams(logId)
		if !complete {
			return nil, ErrRecordLogBehind
		}
		nowMillis := writer.clock.Now().UnixMilli()
		interval := time.Duration(governing.body.GetIntervalSeconds()) * time.Second
		waited := time.Duration(nowMillis-state.LastCheckpointMillis) * time.Millisecond

		// 2 batch
		refStreams := map[Id]*RecordReadStream{}
		for _, stream := range streams {
			refStreams[stream.RefId] = stream
		}
		var frontier []*protocol.LogFrontier
		var derived []RecordReadPushLeaf
		var cutErr error
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			frontier, cutErr = view.cutWithLock(streams, writer.settings.LeafBatchCount)
			if cutErr == nil {
				derived, _, _ = view.deriveWithLock(refStreams, frontier)
			}
		}()
		if cutErr != nil {
			return nil, cutErr
		}
		otherCount := 0
		for _, leaf := range derived {
			if leaf.Kind != RecordKindCheckpoint {
				otherCount += 1
			}
		}
		due := force ||
			(0 < otherCount && interval <= waited) ||
			writer.settings.LeafBatchCount <= len(derived) ||
			(0 < len(governing.witnesses) && writer.settings.WitnessFreshInterval <= waited)
		if !due || len(derived) == 0 {
			return nil, nil
		}
		leaves := make([][sha256.Size]byte, 0, len(derived))
		leafBytes := make([]byte, 0, len(derived)*sha256.Size)
		for _, leaf := range derived {
			leaves = append(leaves, leaf.Leaf)
			leafBytes = append(leafBytes, leaf.Leaf[:]...)
		}

		// 3 sign: once a batch, the root over all leaves and then the note
		testHookBarrier("record.log.sign.before", hookKey)
		root := func() [sha256.Size]byte {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			grown := &recordLogTree{leaves: append(slices.Clone(view.tree.leaves), leaves...), nodes: view.tree.nodes}
			return grown.root()
		}()
		note, err := SignRecordLogNote(governing.body.GetOrigin(), treeSize+uint64(len(leaves)), root, logKey)
		if err != nil {
			return nil, err
		}
		body = &protocol.LogCheckpointBody{Batch: number, FirstIndex: treeSize, Frontier: frontier, Leaves: leafBytes, Note: note}
		for _, cosigned := range state.Cosigned {
			if cosigned.Batch < number {
				body.Cosigned = append(body.Cosigned, &protocol.LogCosigned{Batch: cosigned.Batch, Lines: bytes.Clone(cosigned.Lines)})
			}
		}
		if err := recordLogCheckpointValidate(body); err != nil {
			return nil, err
		}
		bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
		if err != nil {
			return nil, err
		}
		testHookBarrier("record.log.sign.after", hookKey)

		// 4 journal: the signed bytes are durable here before anything else is done with them
		testHookBarrier("record.log.journal.before", hookKey)
		state.Pending = &recordLogPendingDocument{Batch: number, Body: bodyBytes}
		if err := self.writeState(state); err != nil {
			return nil, err
		}
		testHookBarrier("record.log.journal.after", hookKey)
	}
	result := &RecordLogCheckpointResult{Batch: body.GetBatch(), Note: bytes.Clone(body.GetNote())}
	if note, err := ParseRecordLogNote(body.GetNote()); err == nil {
		result.Size = note.Size
	}

	// 5 entry: its push commits before any witness sees the note
	if !self.batchFiled(view, body.GetBatch(), body.GetNote()) {
		testHookBarrier("record.log.entry.before", hookKey)
		ref, err := self.pendingEntry(logId, state.Pending.Body)
		if err != nil {
			return nil, err
		}
		if err := self.record.Land(ctx, []*RecordEntryRef{ref}); err != nil {
			return nil, err
		}
		testHookBarrier("record.log.entry.after", hookKey)
		if err := reader.Sync(ctx, logId); err != nil {
			return nil, err
		}
		if !self.batchFiled(view, body.GetBatch(), body.GetNote()) {
			// another device's settings or batch took the place: readers ignore this entry, and no witness sees
			// its note
			state.Pending = nil
			if err := self.writeState(state); err != nil {
				return nil, err
			}
			return nil, ErrRecordLogNotCheckpointer
		}
	}

	// 6 witness, after reading log_settings again
	filedGoverning := func() *recordLogSettings {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return recordLogGoverning(view.settings, body.GetBatch())
	}()
	lines := []byte{}
	if governs(filedGoverning) && 0 < len(filedGoverning.witnesses) {
		testHookBarrier("record.log.witness.before", hookKey)
		lines, result.CosignedNames = self.witnessNote(ctx, view, state, filedGoverning, body.GetBatch())
		testHookBarrier("record.log.witness.after", hookKey)
	}

	// 7 file: the lines wait in the state for the next entry's cosigned, and the journal's row goes
	testHookBarrier("record.log.file.before", hookKey)
	riding := map[uint64]bool{}
	for _, row := range body.GetCosigned() {
		riding[row.GetBatch()] = true
	}
	state.Cosigned = slices.DeleteFunc(state.Cosigned, func(cosigned *recordLogCosignedDocument) bool { return riding[cosigned.Batch] })
	if 0 < len(lines) {
		state.Cosigned = append(state.Cosigned, &recordLogCosignedDocument{Batch: body.GetBatch(), Lines: lines})
	}
	state.Pending = nil
	state.LastCheckpointMillis = writer.clock.Now().UnixMilli()
	if err := self.writeState(state); err != nil {
		return nil, err
	}
	testHookBarrier("record.log.file.after", hookKey)
	return result, nil
}

// The journaled checkpoint entry as the writer holds it: the one still in the writer's own journal from an earlier
// attempt, or a new entry of the same body bytes. Either way the note inside is the one signed once.
func (self *RecordLog) pendingEntry(logId Id, bodyBytes []byte) (*RecordEntryRef, error) {
	writer := self.record.writer
	if err := writer.load(); err != nil {
		return nil, err
	}
	pending, err := writer.chain.Pending(logId)
	if err != nil {
		return nil, err
	}
	for _, sealed := range pending {
		header, err := sealed.Header()
		if err != nil {
			return nil, err
		}
		if header.Kind() == RecordKindCheckpoint {
			// at most one checkpoint entry is ever outstanding: each waits for its commit before the next is signed
			return &RecordEntryRef{LogId: logId, EntryId: sealed.EntryId, Seq: sealed.Seq, Leaf: sealed.Leaf}, nil
		}
	}
	refs, err := writer.Append(&RecordDraft{Kind: RecordKindCheckpoint, Source: RecordSourceObserved, NoSession: true, StoredBody: bodyBytes})
	if err != nil {
		return nil, err
	}
	if len(refs) != 1 || refs[0].Spooled {
		return nil, fmt.Errorf("%w: the checkpoint entry did not seal", ErrRecordNotLanded)
	}
	return refs[0], nil
}

// The checkpointer's schedule, which the record's loop runs each pass: nothing unless this device holds a log key for
// the team record and a tick is due, then one Checkpoint attempt, which itself files only a batch that is due
// (section 10.2's when row). Arms the loop's next wake.
func (self *RecordLog) Tick(ctx context.Context) {
	writer := self.record.writer
	teamRecordId, _ := recordTeamLogs(writer.auth())
	if teamRecordId == nil {
		return
	}
	view := self.view(*teamRecordId)
	nowMillis := writer.clock.Now().UnixMilli()
	keyKnown, keyHeld, due := func() (bool, bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return view.keyKnown, view.keyHeld, view.nextTickMillis <= nowMillis || writer.settings.LeafBatchCount <= view.waitingLeafCount
	}()
	if !keyKnown {
		state, err := self.readState(*teamRecordId)
		if err != nil {
			// locked, or unreadable: asked again at the next pass
			return
		}
		keyHeld = state.logKey() != nil
		self.noteKey(view, keyHeld)
	}
	if !keyHeld || !due {
		return
	}
	if _, err := self.Checkpoint(ctx, *teamRecordId, false); err != nil && writer.log.V(1).Enabled() {
		writer.log.Infof("[record]a checkpoint of %s stopped: %s", *teamRecordId, err)
	}
	_, governing, _ := self.nextBatch(view)
	interval := writer.settings.CheckpointInterval
	if governing != nil && 0 < governing.body.GetIntervalSeconds() {
		interval = time.Duration(governing.body.GetIntervalSeconds()) * time.Second
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	view.nextTickMillis = writer.clock.Now().Add(interval).UnixMilli()
	if self.stopWake != nil {
		self.stopWake()
	}
	self.stopWake = writer.clock.AfterFunc(interval, writer.signal)
}

// The log as this device reads it now, without syncing: what `ur record log status` prints after a sync.
func (self *RecordLog) Status(logId Id) (*RecordLogStatus, error) {
	if !recordLogVerifiable(self.record.writer.auth(), logId) {
		return nil, fmt.Errorf("%w: %s", ErrRecordLogUnsupported, logId)
	}
	view := self.view(logId)
	state, stateErr := self.readState(logId)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := &RecordLogStatus{
		LogId: logId, Origin: RecordLogOrigin(logId), Batch: uint64(len(view.batches)), Size: view.tree.size(),
		WaitingLeafCount: view.waitingLeafCount, UnbackedLeafCount: view.unbacked, Stopped: view.stopped, Findings: slices.Clone(view.findings),
	}
	if 0 < len(view.batches) {
		root := view.batches[len(view.batches)-1].root
		status.Root = root[:]
	}
	governing := recordLogGoverning(view.settings, status.Batch+1)
	if governing == nil {
		return status, nil
	}
	checkpointerId := governing.checkpointerId
	status.CheckpointerSidecarId = &checkpointerId
	status.On = 0 < governing.body.GetIntervalSeconds()
	status.IntervalSeconds = governing.body.GetIntervalSeconds()
	status.LogKey = governing.logKey.String()
	if stateErr == nil && state.logKey() != nil {
		status.ThisDevice = checkpointerId == self.record.writer.sidecarId && bytes.Equal(state.logKey().Public().(ed25519.PublicKey), governing.logKey.PublicKey)
	}
	for _, witness := range governing.witnesses {
		witnessStatus := &RecordLogWitnessStatus{Name: witness.name, Url: witness.url}
		for _, batch := range view.batches {
			if _, ok := batch.cosignedNameLines[witness.name]; ok {
				witnessStatus.CosignedBatch = batch.batch
			}
		}
		if stateErr == nil && status.ThisDevice {
			row := state.witness(witness.name)
			witnessStatus.Size, witnessStatus.MissCount, witnessStatus.Refusal = row.Size, row.MissCount, row.Refusal
		}
		status.Witnesses = append(status.Witnesses, witnessStatus)
	}
	return status, nil
}

// Where leaf sits in the tree, under the newest checkpoint this reader verified that covers it, one with
// cosignatures filed when any covering one has them: what a disclosure packet carries for an entry.
// ErrRecordLogUncovered while no verified batch holds the leaf.
func (self *RecordLog) Proof(logId Id, leaf [sha256.Size]byte) (*RecordLogProof, error) {
	view := self.view(logId)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	index, ok := view.leafIndexs[leaf]
	if !ok {
		return nil, ErrRecordLogUncovered
	}
	var covering *recordLogBatch
	for _, batch := range view.batches {
		if batch.size <= index {
			continue
		}
		if covering == nil || 0 < len(batch.cosignedNameLines) || len(covering.cosignedNameLines) == 0 {
			covering = batch
		}
	}
	if covering == nil {
		return nil, ErrRecordLogUncovered
	}
	path, err := view.tree.inclusionPath(index, covering.size)
	if err != nil {
		return nil, err
	}
	checkpoint := bytes.Clone(covering.note)
	names := make([]string, 0, len(covering.cosignedNameLines))
	for name := range covering.cosignedNameLines {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		checkpoint = append(checkpoint, covering.cosignedNameLines[name]...)
	}
	return &RecordLogProof{LeafIndex: index, Batch: covering.batch, Checkpoint: checkpoint, Size: covering.size, InclusionPath: recordLogPathBytes(path)}, nil
}

// The names a command's --log takes beside an id (RECORD.md sections 9 to 11's `--log l`).
const (
	RecordLogNameTeam  = "team"
	RecordLogNameVault = "vault"
)

// The log a command names: "team", the team record; "vault", this sidecar's author's vault; or a log's id, dashed or
// as 32 hex characters. An error for a name this network has no log for.
func (self *SidecarRecord) ResolveLog(name string) (Id, error) {
	auth := self.writer.auth()
	switch name {
	case RecordLogNameTeam:
		if teamRecordId, _ := recordTeamLogs(auth); teamRecordId != nil {
			return *teamRecordId, nil
		}
		return Id{}, fmt.Errorf("%w: this network has no team record", ErrRecordLogUnsupported)
	case RecordLogNameVault:
		route, err := recordVaultRoute(auth, self.writer.sidecarId)
		if err != nil {
			return Id{}, fmt.Errorf("%w: this sidecar's author has no vault here", ErrRecordLogUnsupported)
		}
		return route.logId, nil
	}
	if logId, err := ParseId(name); err == nil {
		return logId, nil
	}
	if decoded, err := hex.DecodeString(name); err == nil && len(decoded) == len(Id{}) {
		return Id(decoded), nil
	}
	return Id{}, fmt.Errorf("%w: %q is no log's name or id", ErrRecordLogUnsupported, name)
}
