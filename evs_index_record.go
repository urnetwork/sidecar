//go:build !ios_extension

// The record class's documents (§16.10's documents and rule rows; §11.14's fields and version rows; RECORD.md 7.1 to
// 7.3, record extractor 1; D-EVS-61, I-20, FS-80; DESIGN-DETAILS 15.2.8 to 15.2.10 and 15.7's note; QD-779, QD-780,
// QD-782, QD-783; SEARCH-M10-28): what one stream R of a record log gives the log's ur/index, through
// IndexDocumentSource, so a build, a rebuild, a backfill and a check by rebuild read a log's documents through one
// seam and never its formats.
//
//	rule      a log's index holds only what that log's own entries hold, for that log's readers: nothing crosses from
//	          a vault into another log's index, and a run reaches the directory only as its announcement (I-20)
//	vault     one run card per run (search_run_card.go), and every claim, handoff, ask, answer, check and note entry
//	          the vault holds: only a personal network writes those there (RECORD.md 6.3), so whatever V holds of them
//	          is indexed, whatever the network's mode at the build
//	team      one run card per run, built only from the team record's own entries, and nothing else
//	record    each entry but class log, raw capture and copy; no card
//	entry     a document named by its copy's stream path, at that path's entry version (the stream version its push
//	          committed at), doc kind record, chunk 0, tainted the header's; fields 4 title and 5 text by RECORD.md
//	          7.2, 6 the kind's registry name or kind-<n>, 7 writer, 8 agent_id and 10 run_id in lowercase hex, 9
//	          agent label and 11 session ids from the run's first context entry R holds at the pin that no erasure
//	          with a CUT below the push's epoch names (15.2.8; QD-782), 12-14 by RECORD.md 7.3
//	copies    two streams' copies of an entry are two documents, each under its own ref and doc_key
//	erased    an entry is erased at the push's epoch E when an ERASE names it, by a copy's key row or by its note's
//	          entry_id, and that ERASE's erasure has a CUT below E: the erasure set at the push's base lists it, or
//	          does not and one of its ERASEs says complete (15.2.2)
//	blocked   a card whose builder cannot open a source entry an ERASE took that is not erased at E, and an entry
//	          document whose builder cannot open the context entry its fields 9 and 11 come from, is no document:
//	          the build's pin on R stops below the lowest version such a document holds (15.2.9), and a device that
//	          holds the ERASE builds nothing of that run until the CUT
//	unopened  an entry document whose own body this device cannot open is left out, as an unopenable path is, and
//	          the erasure's CUT lists it
//
// IndexRecordLog joins a log's reader to its builds: each stream's source at a build's epoch and erasure set, the
// backfill's card seam, step 2a's read of the erasure ref, and the keys an ERASE masks on this device until its CUT
// (indexRecordEraseMaskKeys, which CORE-M10-04's ApplyErase calls). Not here: a stream's journal units, their card
// markers and again units and a companion build's step 2a (SEARCH-M10-14's, by 15.7's note), and a stream's
// indexContentRef, which hands a backfill each entry's document. An entry carries no time of its own here: an index
// entry's time is its push's signed time, which the writer sets (QD-689's reading 5), where RECORD.md 7.1's row reads
// the header's time_millis.
//
// The directory's documents are §16.11's and its own source's (RECORD-M10-04); mail's are m/ messages (indexExtractMail).
// Nothing here creates, derives or unwraps a key: the reader opened the bodies, and doc_keys are MACs under a K_ref the
// caller derived. Bodies, titles and prompts are this device's plaintext and go into no log or error (I-13). Safe for
// concurrent use: a source is a value of one build, and IndexRecordLog locks its own state.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// A source asked of a log kind that holds no record documents: the directory's are its own source's, and a mailbox
	// or secret repo is a log only for the read entries its readers deposit.
	errIndexRecordLogKind = errors.New("index record source of no record log")
	// The reader has not read the stream to the version asked: the build waits for its sync.
	errIndexRecordBehind = errors.New("index record source behind the version asked")
	// A source built without what every build reads.
	errIndexRecordArgs = errors.New("index record source without its stream, settings or erasure test")
)

// Record extractor 1's bounds (RECORD.md 7.1 and 7.4; §16.10's run card row). They decide the bytes every device
// writes, so changing one is another extractor and a rebuild, and no device sets one on its own; this object holds them
// and its defaults stay here (QD-702).
type IndexRecordSettings struct {
	// A title, first(s): s up to its first U+000A, trailing spaces dropped, cut on a code point: 120 B.
	TitleByteCount int
	// A run card's text, cut on a code point: 16,384 B.
	CardTextByteCount int
	// The touched paths a vault's card lists, in byte order: 256.
	CardPathCount int
	// The tool names a vault card's field 12 holds, by count then name: 32.
	CardToolCount int
	// The user prompts a vault card's text carries, its context entries' prompts in the fold's order one a line, cut
	// on a code point: 2,048 B, §16.10's first 2 KiB (QD-900).
	CardPromptByteCount int
	// The session ids field 11 joins, the newest a context entry carries: 4.
	SessionIdCount int
}

// RECORD.md's values, the only source of their defaults. A fresh value each call.
func DefaultIndexRecordSettings() *IndexRecordSettings {
	return &IndexRecordSettings{
		TitleByteCount:      120,
		CardTextByteCount:   16 * 1024,
		CardPathCount:       256,
		CardToolCount:       32,
		CardPromptByteCount: 2 * 1024,
		SessionIdCount:      4,
	}
}

// Refuses a bound that would cut everything.
func (self *IndexRecordSettings) check() error {
	if self.TitleByteCount <= 0 || self.CardTextByteCount <= 0 || self.CardPathCount <= 0 || self.CardToolCount <= 0 ||
		self.CardPromptByteCount <= 0 || self.SessionIdCount <= 0 {
		return fmt.Errorf("%w: record extractor 1's bounds", errInvalidSettings)
	}
	return nil
}

// One entry of stream R as the record class reads it: the reader's verified entry, with the copy R holds.
type indexRecordEntry struct {
	entryId Id
	header  *protocol.RecordHeader
	// The copy in R: its stream path and the stream version its push committed at, which is the path's entry version.
	path    string
	version uint64
	// Every copy's key row, in every stream: what an ERASE names.
	slotKeys []RecordSlotKey
	// The body as stored, nil where this device cannot open it or where it is unreadable.
	body []byte
	// The body breaks alike for every device: it did not open or commit, broke its kind's caps, or is of an entry
	// version this build does not know. Its header still counts, and its document has no title or text.
	unreadable bool
	// An ERASE took a key of it, or an erasure named it: this device cannot open its body.
	keyGone bool
}

// The entry's kind, as its header carries it.
func (self *indexRecordEntry) kind() RecordKind {
	return RecordKind(self.header.GetKind())
}

// The entry's run, false for none.
func (self *indexRecordEntry) runId() (Id, bool) {
	if len(self.header.GetRunId()) != len(Id{}) {
		return Id{}, false
	}
	return Id(self.header.GetRunId()), true
}

// The fold's order (15.2.8; QD-783 #3): seq in the writer's chain, then entry_id as bytes.
func indexRecordFoldCompare(a *indexRecordEntry, b *indexRecordEntry) int {
	if a.header.GetSeq() != b.header.GetSeq() {
		if a.header.GetSeq() < b.header.GetSeq() {
			return -1
		}
		return 1
	}
	return bytes.Compare(a.entryId[:], b.entryId[:])
}

// The entries of one stream R at a version, as the record class reads them. The adapter over RecordReader is
// indexRecordReaderStream; tests give a fake.
type indexRecordStream interface {
	// The kind of the log R belongs to: vault, team record or record.
	LogKind() protocol.RepoKind
	// R's ref_id, which every doc_key of its documents names.
	RefId() Id
	// Every entry R holds at refVersion, each with its copy in R, one a copy; errIndexRecordBehind where this device has
	// not read R to refVersion.
	Entries(ctx context.Context, refVersion uint64) ([]*indexRecordEntry, error)
}

// What the record class reads of a log: *RecordReader, its verified streams and entries, brought to evs's heads by
// Sync.
type indexRecordLogReader interface {
	Sync(ctx context.Context, logId Id) error
	Streams(logId Id) ([]*RecordReadStream, bool)
	Entries(logId Id) []*RecordReadEntry
	EntriesOfKinds(logId Id, from int, kinds ...RecordKind) ([]*RecordReadEntry, int)
}

var _ indexRecordLogReader = (*RecordReader)(nil)

// One stream of a log as RecordReader holds it.
type indexRecordReaderStream struct {
	reader  indexRecordLogReader
	logId   Id
	logKind protocol.RepoKind
	// R's writer, W_R, which names the stream among the log's.
	streamSidecarId Id
	refId           Id
}

// The stream of streamSidecarId in logId, as reader reads it.
func newIndexRecordReaderStream(reader indexRecordLogReader, logId Id, logKind protocol.RepoKind, streamSidecarId Id, refId Id) *indexRecordReaderStream {
	return &indexRecordReaderStream{reader: reader, logId: logId, logKind: logKind, streamSidecarId: streamSidecarId, refId: refId}
}

// The log's kind, as the composition named it.
func (self *indexRecordReaderStream) LogKind() protocol.RepoKind {
	return self.logKind
}

// R's ref_id, as the reader's stream stated it.
func (self *indexRecordReaderStream) RefId() Id {
	return self.refId
}

// The entries R holds at refVersion: those of the kinds the log's documents read, each copy in R at or below it.
func (self *indexRecordReaderStream) Entries(ctx context.Context, refVersion uint64) ([]*indexRecordEntry, error) {
	streams, _ := self.reader.Streams(self.logId)
	readVersion := uint64(0)
	for _, stream := range streams {
		if stream.StreamSidecarId == self.streamSidecarId && 0 < len(stream.Pushes) {
			readVersion = stream.Pushes[len(stream.Pushes)-1].Version
		}
	}
	if readVersion < refVersion {
		return nil, fmt.Errorf("%w: read to %d of %d", errIndexRecordBehind, readVersion, refVersion)
	}
	var read []*RecordReadEntry
	if kinds := indexRecordReadKinds(self.logKind); kinds != nil {
		read, _ = self.reader.EntriesOfKinds(self.logId, 0, kinds...)
	} else {
		read = self.reader.Entries(self.logId)
	}
	entries := []*indexRecordEntry{}
	for _, entry := range read {
		if entry.State == RecordEntryLost || entry.Header == nil {
			continue
		}
		slotKeys := []RecordSlotKey{}
		for _, entryCopy := range entry.Copies {
			if entryCopy.SlotId != (Id{}) {
				slotKeys = append(slotKeys, RecordSlotKey{SlotId: entryCopy.SlotId, KeyIndex: entryCopy.KeyIndex})
			}
		}
		for _, entryCopy := range entry.Copies {
			if entryCopy.StreamSidecarId != self.streamSidecarId || refVersion < entryCopy.Version {
				continue
			}
			entries = append(entries, &indexRecordEntry{
				entryId:    entry.EntryId,
				header:     entry.Header.Header,
				path:       entryCopy.Path,
				version:    entryCopy.Version,
				slotKeys:   slotKeys,
				body:       entry.Body,
				unreadable: entry.BodyInvalid || entry.BodyGeneric,
				keyGone:    entry.State.KeyGone(),
			})
		}
	}
	return entries, nil
}

// The kinds a log's documents read, nil for every kind: a vault's coordination entries and card sources, a team
// record's card sources, and a record repo's every entry.
func indexRecordReadKinds(logKind protocol.RepoKind) []RecordKind {
	switch logKind {
	case protocol.RepoKind_REPO_KIND_VAULT:
		return slices.Concat(indexRecordVaultEntryKinds, indexRunCardSources(logKind))
	case protocol.RepoKind_REPO_KIND_TEAM_RECORD:
		return indexRunCardSources(logKind)
	}
	return nil
}

// The kinds a vault indexes as entries of their own (RECORD.md 7.1's documents row).
var indexRecordVaultEntryKinds = []RecordKind{
	RecordKindClaim, RecordKindHandoff, RecordKindAsk, RecordKindAnswer, RecordKindCheck, RecordKindNote,
}

// Whether log logKind indexes an entry of kind as a document of its own (RECORD.md 7.1's documents row): a vault its
// coordination entries; a record repo each entry but class log, raw capture and copy, a kind this build does not know
// among them; a team record none.
func indexRecordIndexesEntry(logKind protocol.RepoKind, kind RecordKind) bool {
	switch logKind {
	case protocol.RepoKind_REPO_KIND_VAULT:
		return slices.Contains(indexRecordVaultEntryKinds, kind)
	case protocol.RepoKind_REPO_KIND_RECORD:
		class := kind.Class()
		return class != RecordClassLog && class != RecordClassCapture && kind != RecordKindCopy
	}
	return false
}

// Whether erasures, as this device holds them, have a CUT below the push's epoch (15.2.2's erased at E), and what each
// names. Built from the log's ERASEs and the index's erasure set at the push's base, which together fix E's side: an
// erasure the set lists had its CUT below E, and one the set does not list had its CUT below E only if it is complete,
// since a CUT drops only a complete erasure.
type indexRecordErasures struct {
	// The erasures, by id, that have a CUT below E.
	cut map[Id]bool
	// What each ERASE names: key rows, and entry ids through its note.
	keyErasureIds   map[RecordSlotKey][]Id
	entryErasureIds map[Id][]Id
}

// The erasure test of one build: erasures, the log's ERASEs this device holds; set, the index's erasure set at the push's
// base, nil for none.
func newIndexRecordErasures(erasures []*RecordStreamErasure, set *protocol.IndexErasureSet) *indexRecordErasures {
	self := &indexRecordErasures{
		cut: map[Id]bool{}, keyErasureIds: map[RecordSlotKey][]Id{}, entryErasureIds: map[Id][]Id{},
	}
	listed := map[Id]bool{}
	for _, erasure := range set.GetErasures() {
		if len(erasure.GetErasureId()) == len(Id{}) {
			listed[Id(erasure.GetErasureId())] = true
		}
	}
	complete := map[Id]bool{}
	for _, erasure := range erasures {
		if erasure.Complete {
			complete[erasure.ErasureId] = true
		}
	}
	for _, erasure := range erasures {
		if listed[erasure.ErasureId] || complete[erasure.ErasureId] {
			self.cut[erasure.ErasureId] = true
		}
		for _, key := range erasure.Keys {
			self.keyErasureIds[*key] = append(self.keyErasureIds[*key], erasure.ErasureId)
		}
		if body, ok := recordErasureNoteBody(erasure); ok {
			for _, entryId := range body.GetEntryIds() {
				if len(entryId) == len(Id{}) {
					self.entryErasureIds[Id(entryId)] = append(self.entryErasureIds[Id(entryId)], erasure.ErasureId)
				}
			}
		}
	}
	return self
}

// Whether entry is erased at the build's epoch: an ERASE this device holds names it and that ERASE's erasure has a CUT
// below E.
func (self *indexRecordErasures) erasedAtEpoch(entry *indexRecordEntry) bool {
	if self == nil {
		return false
	}
	for _, erasureId := range self.entryErasureIds[entry.entryId] {
		if self.cut[erasureId] {
			return true
		}
	}
	for _, key := range entry.slotKeys {
		for _, erasureId := range self.keyErasureIds[key] {
			if self.cut[erasureId] {
				return true
			}
		}
	}
	return false
}

// A document the record class cannot give at a version (15.2.2's blocked): a build's pin on the stream stops below
// Version, the lowest stream version a blocked document's entries hold, until the CUT lands.
type IndexRecordBlockedError struct {
	Version uint64
}

// The version the pin stops below, which names no entry and no text.
func (self *IndexRecordBlockedError) Error() string {
	return fmt.Sprintf("index record document blocked from stream version %d", self.Version)
}

// Matches errIndexCardBlocked, a blocked card's and a blocked entry document's alike.
func (self *IndexRecordBlockedError) Is(target error) bool {
	return target == errIndexCardBlocked
}

// What a source reads one build with.
type indexRecordSourceArgs struct {
	stream indexRecordStream
	// The index_epoch the build's push names, E.
	epoch uint64
	// The erasure test at the push's base; nil holds no erasure.
	erasures *indexRecordErasures
	// Nil takes the defaults.
	settings *IndexRecordSettings
	format   *IndexFormatSettings
}

// One stream's documents for one build: the record class's IndexDocumentSource. Construct with newIndexRecordSource
// at each build, since the epoch and the erasure test are the build's and the interface names neither.
type IndexRecordSource struct {
	args     indexRecordSourceArgs
	settings *IndexRecordSettings
}

var _ IndexDocumentSource = (*IndexRecordSource)(nil)

// A source over args.
func newIndexRecordSource(args *indexRecordSourceArgs) (*IndexRecordSource, error) {
	if args == nil || args.stream == nil || args.format == nil {
		return nil, errIndexRecordArgs
	}
	switch args.stream.LogKind() {
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_TEAM_RECORD, protocol.RepoKind_REPO_KIND_RECORD:
	default:
		return nil, errIndexRecordLogKind
	}
	settings := args.settings
	if settings == nil {
		settings = DefaultIndexRecordSettings()
	}
	if err := settings.check(); err != nil {
		return nil, err
	}
	if bits := args.format.CardVersionBitCount; bits <= 0 || 64 <= bits {
		return nil, fmt.Errorf("%w: a card's version bits within 1 and 63", errInvalidSettings)
	}
	return &IndexRecordSource{args: *args, settings: settings}, nil
}

// §16.8's registry: record entries and run cards.
func (self *IndexRecordSource) IndexRegistry() *IndexFieldRegistry {
	return indexRecordFieldRegistry()
}

// Visits every document R holds at refVersion: each entry document in path order, then each run's card in run_id
// order. A blocked document stops the walk with *IndexRecordBlockedError before anything is visited.
func (self *IndexRecordSource) IndexDocuments(ctx context.Context, refVersion uint64, visit func(document *IndexDocument) error) error {
	built, err := self.build(ctx, refVersion)
	if err != nil {
		return err
	}
	if built.blockedFrom != 0 {
		return &IndexRecordBlockedError{Version: built.blockedFrom}
	}
	for _, document := range slices.Concat(built.entries, built.cards) {
		if err := visit(document); err != nil {
			return err
		}
	}
	return nil
}

// What one build of R at a version gives.
type indexRecordBuilt struct {
	// Entry documents in path order, then cards in run_id order.
	entries []*IndexDocument
	cards   []*IndexDocument
	// Each card's c, beside cards.
	cardCs []uint64
	// Each run's c and the versions of its source entries, ascending, whether folded or not.
	runCs        map[Id]uint64
	runVersions  map[Id][]uint64
	blockedRuns  map[Id]bool
	blockedFrom  uint64
	blockedEntry []uint64
}

// Builds R's documents at refVersion: every entry document, every card, and what is blocked.
func (self *IndexRecordSource) build(ctx context.Context, refVersion uint64) (*indexRecordBuilt, error) {
	entries, err := self.args.stream.Entries(ctx, refVersion)
	if err != nil {
		return nil, err
	}
	logKind := self.args.stream.LogKind()
	built := &indexRecordBuilt{runCs: map[Id]uint64{}, runVersions: map[Id][]uint64{}, blockedRuns: map[Id]bool{}}
	erasedAtEpoch := self.args.erasures.erasedAtEpoch
	block := func(version uint64) {
		if built.blockedFrom == 0 || version < built.blockedFrom {
			built.blockedFrom = version
		}
	}
	// the run's first context entry that no erasure with a CUT below E names, by run (15.2.8's fields 9 and 11)
	contexts := indexRecordFirstContexts(entries, erasedAtEpoch)
	slices.SortFunc(entries, func(a *indexRecordEntry, b *indexRecordEntry) int { return strings.Compare(a.path, b.path) })
	for _, entry := range entries {
		if !indexRecordIndexesEntry(logKind, entry.kind()) || entry.keyGone || erasedAtEpoch(entry) {
			continue
		}
		firstContext := (*indexRecordEntry)(nil)
		if runId, ok := entry.runId(); ok {
			firstContext = contexts[runId]
		}
		if firstContext != nil && firstContext.keyGone {
			built.blockedEntry = append(built.blockedEntry, entry.version)
			block(entry.version)
			continue
		}
		document, err := indexRecordEntryDocument(entry, firstContext, self.settings)
		if err != nil {
			return nil, err
		}
		built.entries = append(built.entries, document)
	}
	if !indexRunCardLog(logKind) {
		return built, nil
	}
	runIds := []Id{}
	sources := indexRunCardSources(logKind)
	for _, entry := range entries {
		runId, ok := entry.runId()
		if !ok || !slices.Contains(sources, entry.kind()) {
			continue
		}
		if _, held := built.runCs[runId]; !held {
			runIds = append(runIds, runId)
		}
		built.runCs[runId] = max(built.runCs[runId], entry.version)
		built.runVersions[runId] = append(built.runVersions[runId], entry.version)
	}
	slices.SortFunc(runIds, func(a Id, b Id) int { return bytes.Compare(a[:], b[:]) })
	for _, runId := range runIds {
		slices.Sort(built.runVersions[runId])
		document, c, err := searchRunCardOf(&indexRunCardArgs{
			logKind: logKind, entries: entries, runId: runId, epoch: self.args.epoch, erasedAtEpoch: erasedAtEpoch,
			settings: self.settings, format: self.args.format,
		})
		if errors.Is(err, errIndexCardBlocked) || errors.Is(err, errIndexCardVersionSpace) {
			// no card: the pin on R stops below the run, which reads not yet searchable (15.2.8, 15.2.9)
			built.blockedRuns[runId] = true
			block(built.runVersions[runId][0])
			continue
		}
		if err != nil {
			return nil, err
		}
		if document == nil {
			continue
		}
		built.cards = append(built.cards, document)
		built.cardCs = append(built.cardCs, c)
	}
	return built, nil
}

// The lowest version of R in (afterVersion, pin] that a blocked document holds at pin, else 0 (the backfill's
// BlockedFrom): a blocked card's source entries and a blocked entry document's own version.
func (self *IndexRecordSource) blockedFrom(ctx context.Context, afterVersion uint64, pin uint64) (uint64, error) {
	built, err := self.build(ctx, pin)
	if err != nil {
		return 0, err
	}
	lowest := uint64(0)
	take := func(version uint64) {
		if afterVersion < version && version <= pin && (lowest == 0 || version < lowest) {
			lowest = version
		}
	}
	for runId := range built.blockedRuns {
		for _, version := range built.runVersions[runId] {
			take(version)
		}
	}
	for _, version := range built.blockedEntry {
		take(version)
	}
	return lowest, nil
}

// The card of each run whose newest source entry at pin was made by one of versions (the backfill's Cards); a run
// whose fold gives nothing is left out, and one that is blocked answers *IndexRecordBlockedError.
func (self *IndexRecordSource) cardsAt(ctx context.Context, versions []uint64, pin uint64) ([]*IndexDocument, error) {
	built, err := self.build(ctx, pin)
	if err != nil {
		return nil, err
	}
	documents := []*IndexDocument{}
	for runId, c := range built.runCs {
		if built.blockedRuns[runId] && slices.Contains(versions, c) {
			return nil, &IndexRecordBlockedError{Version: built.runVersions[runId][0]}
		}
	}
	for index, document := range built.cards {
		if slices.Contains(versions, built.cardCs[index]) {
			documents = append(documents, document)
		}
	}
	return documents, nil
}

// Each run's first context entry R holds, in the fold's order, that is not erased at E (15.2.8's fields 9 and 11).
func indexRecordFirstContexts(entries []*indexRecordEntry, erasedAtEpoch func(entry *indexRecordEntry) bool) map[Id]*indexRecordEntry {
	contexts := map[Id]*indexRecordEntry{}
	for _, entry := range entries {
		runId, ok := entry.runId()
		if !ok || entry.kind() != RecordKindContext || erasedAtEpoch(entry) {
			continue
		}
		if held := contexts[runId]; held == nil || indexRecordFoldCompare(entry, held) < 0 {
			contexts[runId] = entry
		}
	}
	return contexts
}

// An entry's document (RECORD.md 7.1 to 7.3): named by its stream path at its entry version, its fields by its kind,
// fields 9 and 11 from firstContext, the run's first context entry, nil for none.
func indexRecordEntryDocument(entry *indexRecordEntry, firstContext *indexRecordEntry, settings *IndexRecordSettings) (*IndexDocument, error) {
	document := &IndexDocument{
		Kind:      IndexDocRecord,
		Name:      []byte(entry.path),
		Version:   entry.version,
		ByteCount: uint64(len(entry.body)),
		Tainted:   entry.header.GetTainted(),
	}
	document.Fields[indexFieldFirstRegistered] = []byte(indexRecordKindName(entry.kind()))
	document.Fields[indexFieldFirstRegistered+1] = []byte(indexRecordHex(entry.header.GetWriterSidecarId()))
	document.Fields[indexFieldFirstRegistered+2] = []byte(indexRecordHex(entry.header.GetAgentId()))
	document.Fields[indexFieldFirstRegistered+4] = []byte(indexRecordHex(entry.header.GetRunId()))
	if firstContext != nil && firstContext.body != nil {
		body := &protocol.ContextBody{}
		if proto.Unmarshal(firstContext.body, body) == nil {
			document.Fields[indexFieldFirstRegistered+3] = []byte(body.GetAgentLabel())
			document.Fields[indexFieldFirstRegistered+5] = []byte(indexRecordSessionIds(body, settings))
		}
	}
	if entry.body != nil && !entry.unreadable {
		title, text, claimExpires, claimState := indexRecordTitleAndText(entry, settings)
		document.Fields[indexFieldTitle] = []byte(title)
		document.Fields[indexFieldBody] = []byte(text)
		document.Fields[indexFieldFirstRegistered+7] = []byte(claimExpires)
		document.Fields[indexFieldFirstRegistered+8] = []byte(claimState)
	}
	if err := indexRecordFieldRegistry().check(document); err != nil {
		return nil, err
	}
	return document, nil
}

// Field 6: the kind's registry name, or kind-<number> for a kind this build cannot write: one it does not know, a
// private one, or a derived name no header may carry (RECORD.md 7.1).
func indexRecordKindName(kind RecordKind) string {
	if kind.Writable() {
		return kind.String()
	}
	return "kind-" + strconv.FormatUint(uint64(kind), 10)
}

// An id field in lowercase hex, empty for none (RECORD.md 7.1; QD-298's spelling of ids).
func indexRecordHex(id []byte) string {
	return hex.EncodeToString(id)
}

// Field 11: the context's newest session ids, at most SessionIdCount, joined with one space.
func indexRecordSessionIds(body *protocol.ContextBody, settings *IndexRecordSettings) string {
	sessionIds := body.GetSessionIds()
	if settings.SessionIdCount < len(sessionIds) {
		sessionIds = sessionIds[len(sessionIds)-settings.SessionIdCount:]
	}
	return strings.Join(sessionIds, " ")
}

// first(s) (RECORD.md 7.1's title row): s up to its first U+000A, trailing spaces dropped, cut on a code point.
func indexRecordFirst(text string, settings *IndexRecordSettings) string {
	if line, _, found := strings.Cut(text, "\n"); found {
		text = line
	}
	return indexCutUtf8(indexRowText(strings.TrimRight(text, " ")), settings.TitleByteCount)
}

// A time in a field: RFC 3339 UTC to the second (RECORD.md 7.1's times row).
func indexRecordTime(millis int64) string {
	return time.UnixMilli(millis).UTC().Format("2006-01-02T15:04:05Z")
}

// Lines of text: the listed values in the listed order, one a line, an empty value taking no line (RECORD.md 7.2).
func indexRecordLines(values ...string) string {
	kept := []string{}
	for _, value := range values {
		if value != "" {
			kept = append(kept, value)
		}
	}
	return strings.Join(kept, "\n")
}

// A value and the next, joined by one space where both are set: "harness and agent label", "event and host".
func indexRecordPair(a string, b string) string {
	return strings.TrimSpace(a + " " + b)
}

// An enumeration's name in RECORD.md 6.2 and 6.4, or its number where the table holds none.
func indexRecordEnum(names map[uint32]string, value uint32) string {
	if name, ok := names[value]; ok {
		return name
	}
	return strconv.FormatUint(uint64(value), 10)
}

// RECORD.md 6.2's and 6.4's enumerations, by the field that carries each.
var (
	indexRecordCheckResults   = map[uint32]string{1: "pass", 2: "fail", 3: "objection"}
	indexRecordClaimStates    = map[uint32]string{1: "active", 2: "released"}
	indexRecordToolClasses    = map[uint32]string{1: "shell", 2: "edit", 3: "mcp", 4: "web", 5: "other"}
	indexRecordDecidedBy      = map[uint32]string{0: "unknown", 1: "user", 2: "config", 3: "hook", 4: "classifier"}
	indexRecordEvents         = map[uint32]string{1: "opened", 2: "closed"}
	indexRecordRouteKinds     = map[uint32]string{1: "forward", 2: "expose", 3: "route", 4: "map"}
	indexRecordUseStates      = map[uint32]string{1: "done", 2: "not_done", 3: "uncertain"}
	indexRecordDecisions      = map[uint32]string{1: "approve", 2: "deny"}
	indexRecordChannels       = map[uint32]string{1: "device", 2: "presence", 3: "harness"}
	indexRecordReadPurposes   = map[uint32]string{1: "read", 2: "search", 3: "export", 4: "disclosure"}
	indexRecordErasureReasons = map[uint32]string{1: "person", 2: "retention", 3: "moderation", 4: "revocation"}
	indexRecordDisclosureActs = map[uint32]string{1: "packet", 2: "opening", 3: "export"}
	indexRecordStatements     = map[uint32]string{1: "reviewed", 2: "tested", 3: "approved"}
	indexRecordKeyEvents      = map[uint32]string{1: "key_changed"}
	indexRecordMemberEvents   = map[uint32]string{
		1: "member_added", 2: "member_removed", 3: "admission_alarm", 4: "recovery_rebind", 5: "recovery_window",
		6: "recovery_unseen",
	}
	indexRecordReachKinds = map[uint32]string{
		uint32(RecordReachKindListen): "listen", uint32(RecordReachKindPublish): "publish", uint32(RecordReachKindForward): "forward",
		uint32(RecordReachKindRoute): "route", uint32(RecordReachKindSend): "send", uint32(RecordReachKindReceive): "receive",
	}
)

// §5.4's SidecarActionKind as an action's name: publish, listen, ..., mail_tls_unauthenticated.
func indexRecordActionKind(kind uint32) string {
	name, ok := protocol.SidecarActionKind_name[int32(kind)]
	if !ok || kind == 0 {
		return strconv.FormatUint(uint64(kind), 10)
	}
	return strings.ToLower(strings.TrimPrefix(name, "SIDECAR_ACTION_KIND_"))
}

// Fields 4 and 5 of an entry by its kind (RECORD.md 7.2), and for a claim or handoff fields 13 and 14 (7.3). A body
// that does not parse as its kind gives none, as for every device alike.
func indexRecordTitleAndText(entry *indexRecordEntry, settings *IndexRecordSettings) (title string, text string, claimExpires string, claimState string) {
	kind := entry.kind()
	message, ok := kind.NewBody()
	if !ok || proto.Unmarshal(entry.body, message) != nil {
		return "", "", "", ""
	}
	if signed, isSigned := message.(*bridge.Signed); isSigned {
		inner, _, ok := kind.NewSignedBody()
		if !ok || proto.Unmarshal(signed.GetBody(), inner) != nil {
			return "", "", "", ""
		}
		message = inner
	}
	switch body := message.(type) {
	case *protocol.CoordinationBody:
		lines := []string{body.GetText()}
		if kind == RecordKindCheck {
			lines = append(lines, indexRecordEnum(indexRecordCheckResults, body.GetResult()))
		}
		lines = append(lines, body.GetTargets()...)
		title, text = indexRecordFirst(body.GetText(), settings), indexRecordLines(lines...)
		switch kind {
		case RecordKindClaim:
			if body.GetExpiresMillis() != 0 {
				claimExpires = indexRecordTime(body.GetExpiresMillis())
			}
			if name, ok := indexRecordClaimStates[body.GetClaimState()]; ok {
				claimState = name
			}
		case RecordKindHandoff:
			claimState = "handed_off"
		}
	case *protocol.ContextBody:
		title = indexRecordPair(body.GetHarness(), body.GetAgentLabel())
		text = indexRecordLines(body.GetModel(), body.GetProject(), body.GetPermissionMode())
	case *protocol.ChangeBody:
		title = indexRecordPair("change", body.GetProject())
		text = indexRecordLines(body.GetCommits()...)
	case *protocol.PermissionBody:
		title = body.GetPermissionMode()
		text = indexRecordLines(indexRecordEnum(indexRecordToolClasses, body.GetToolClass()), indexRecordEnum(indexRecordDecidedBy, body.GetDecidedBy()))
	case *protocol.ApprovalRequest:
		action := &protocol.CanonicalAction{}
		if proto.Unmarshal(body.GetCanonicalAction(), action) == nil {
			title = indexRecordActionKind(action.GetKind())
			text = indexRecordLines(indexRecordActionStrings(action)...)
		}
	case *protocol.ApprovalDecision:
		title = indexRecordPair(indexRecordEnum(indexRecordDecisions, body.GetDecision()), indexRecordEnum(indexRecordChannels, body.GetChannel()))
		text = indexRecordHex(body.GetApprovalId())
	case *protocol.ApprovalCancel:
		title, text = "cancel", indexRecordHex(body.GetApprovalId())
	case *protocol.ApprovalUseBody:
		title, text = indexRecordEnum(indexRecordUseStates, body.GetState()), indexRecordHex(body.GetApprovalId())
	case *protocol.RouteBody:
		title = indexRecordPair(indexRecordEnum(indexRecordEvents, body.GetEvent()), indexRecordEnum(indexRecordRouteKinds, body.GetKind()))
		lines := []string{indexRecordHex(body.GetTargetSidecarId())}
		if body.GetTargetPort() != 0 {
			lines = append(lines, strconv.FormatUint(uint64(body.GetTargetPort()), 10))
		}
		text = indexRecordLines(append(lines, body.GetCidrs()...)...)
	case *protocol.PublishBody:
		title = indexRecordPair(indexRecordEnum(indexRecordEvents, body.GetEvent()), body.GetHost())
		text = indexRecordLines(body.GetHost(), strconv.FormatUint(uint64(body.GetAudience()), 10))
	case *protocol.ReachReceipt:
		title = indexRecordEnum(indexRecordReachKinds, body.GetKind())
		lines := slices.Clone(body.GetRelays())
		lines = append(lines, strconv.FormatUint(body.GetStreamCount(), 10), strconv.FormatUint(body.GetByteCount(), 10))
		text = indexRecordLines(lines...)
	case *protocol.RestoreBody:
		title, text = "restore", indexRecordHex(body.GetRestoredRunId())
	case *protocol.ModelManifest:
		title = body.GetServedName().GetValue()
		text = indexRecordLines(body.GetEngine().GetValue(), body.GetQuantization().GetValue(), body.GetWeightsDigest().GetValue())
	case *protocol.RunCostBody:
		lines := []string{}
		for _, usage := range body.GetUsage() {
			lines = append(lines, usage.GetModel())
		}
		title, text = "cost", indexRecordLines(lines...)
	case *protocol.AttestationBody:
		title = indexRecordEnum(indexRecordStatements, body.GetStatement())
		text = indexRecordLines(append(slices.Clone(body.GetCommits()), body.GetNote())...)
	case *protocol.MembershipBody:
		title = indexRecordEnum(indexRecordMemberEvents, body.GetEvent())
		text = indexRecordLines(indexRecordHex(body.GetMemberId()), indexRecordHex(body.GetSidecarId()), indexRecordHex(body.GetGroupId()))
	case *protocol.KeyBody:
		title = indexRecordEnum(indexRecordKeyEvents, body.GetEvent())
		text = indexRecordLines(indexRecordHex(body.GetGroupId()), indexRecordHex(body.GetKeyId()))
	case *protocol.Coverage:
		lines := []string{body.GetHarness(), body.GetVersion()}
		lines = append(lines, body.GetSources()...)
		title, text = "coverage", indexRecordLines(append(lines, body.GetGaps()...)...)
	case *protocol.ReadBody:
		title, text = "read", indexRecordEnum(indexRecordReadPurposes, body.GetPurpose())
	case *protocol.ErasureBody:
		title = "erasure"
		text = indexRecordLines(indexRecordHex(body.GetErasureId()), indexRecordEnum(indexRecordErasureReasons, body.GetReason()))
	case *protocol.InventoryBody:
		lines := []string{}
		for _, agent := range body.GetAgents() {
			lines = append(lines, agent.GetAgentLabel())
			lines = append(lines, agent.GetHarnesses()...)
			lines = append(lines, agent.GetModels()...)
			lines = append(lines, agent.GetProjects()...)
		}
		title, text = "inventory", indexRecordLines(lines...)
	case *protocol.DisclosureBody:
		title = indexRecordEnum(indexRecordDisclosureActs, body.GetAct())
		text = indexRecordLines(body.GetRecipient(), body.GetPurpose())
	}
	return indexRowText(title), indexRowText(text), claimExpires, claimState
}

// A CanonicalAction's string fields in field number order, each value of a repeated one, never preview (RECORD.md
// 7.2's approval row).
func indexRecordActionStrings(action *protocol.CanonicalAction) []string {
	reflected := action.ProtoReflect()
	fields := reflected.Descriptor().Fields()
	numbers := []protoreflect.FieldNumber{}
	for index := 0; index < fields.Len(); index += 1 {
		if field := fields.Get(index); field.Kind() == protoreflect.StringKind && field.Name() != "preview" {
			numbers = append(numbers, field.Number())
		}
	}
	slices.Sort(numbers)
	values := []string{}
	for _, number := range numbers {
		field := fields.ByNumber(number)
		if field.IsList() {
			list := reflected.Get(field).List()
			for index := 0; index < list.Len(); index += 1 {
				values = append(values, list.Get(index).String())
			}
			continue
		}
		if reflected.Has(field) {
			values = append(values, reflected.Get(field).String())
		}
	}
	return values
}

// A record log as RecordReader holds it, for the builds of its ur/index: each stream's source, the backfill's run
// cards (indexBackfillCards), and step 2a's read of the erasure ref (15.2.9), which brings the reader to evs's heads
// and keeps the ERASEs the erasure test reads. Safe for concurrent use.
type IndexRecordLog struct {
	reader   indexRecordLogReader
	streams  RecordStreams
	logId    Id
	logKind  protocol.RepoKind
	settings *IndexRecordSettings
	format   *IndexFormatSettings

	stateLock sync.Mutex
	// The log's ERASEs read so far, oldest first, and the erasure ref's version they reach.
	erasures       []*RecordStreamErasure
	erasureVersion uint64
}

// The log logId of kind logKind, read by reader through streams.
func newIndexRecordLog(reader indexRecordLogReader, streams RecordStreams, logId Id, logKind protocol.RepoKind, settings *IndexRecordSettings, format *IndexFormatSettings) (*IndexRecordLog, error) {
	if reader == nil || streams == nil || format == nil {
		return nil, errIndexRecordArgs
	}
	if settings == nil {
		settings = DefaultIndexRecordSettings()
	}
	if err := settings.check(); err != nil {
		return nil, err
	}
	return &IndexRecordLog{reader: reader, streams: streams, logId: logId, logKind: logKind, settings: settings, format: format}, nil
}

var _ indexBackfillCards = (*indexRecordLogCards)(nil)

// Step 2a (15.2.9): reads the log's erasure ref from evs, never a cache, brings the reader to the log's heads and has
// it apply every ERASE, and keeps the ERASEs this read reaches.
func (self *IndexRecordLog) ReadErasures(ctx context.Context) error {
	if err := self.reader.Sync(ctx, self.logId); err != nil {
		return err
	}
	after := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.erasureVersion
	}()
	erasures, err := self.streams.ReadErasures(ctx, self.logId, after)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, erasure := range erasures {
		if erasure.Version <= self.erasureVersion {
			continue
		}
		self.erasures = append(self.erasures, erasure)
		self.erasureVersion = erasure.Version
	}
	return nil
}

// The ERASEs read so far.
func (self *IndexRecordLog) heldErasures() []*RecordStreamErasure {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.erasures)
}

// The stream whose ref is refId, false for none the reader holds.
func (self *IndexRecordLog) stream(refId Id) (*indexRecordReaderStream, bool) {
	streams, _ := self.reader.Streams(self.logId)
	for _, stream := range streams {
		if stream.RefId == refId && refId != (Id{}) {
			return newIndexRecordReaderStream(self.reader, self.logId, self.logKind, stream.StreamSidecarId, refId), true
		}
	}
	return nil, false
}

// The source of stream refId for one build at epoch, its erasure test from the ERASEs held and the index's erasure set
// at the push's base.
func (self *IndexRecordLog) Source(refId Id, epoch uint64, set *protocol.IndexErasureSet) (*IndexRecordSource, error) {
	stream, ok := self.stream(refId)
	if !ok {
		return nil, fmt.Errorf("%w: no stream of that ref", errIndexRecordBehind)
	}
	return newIndexRecordSource(&indexRecordSourceArgs{
		stream: stream, epoch: epoch, erasures: newIndexRecordErasures(self.heldErasures(), set), settings: self.settings,
		format: self.format,
	})
}

// The log as a backfill's card seam.
func (self *IndexRecordLog) cards() *indexRecordLogCards {
	return &indexRecordLogCards{log: self}
}

// The backfill's run cards over a record log (indexBackfillCards).
type indexRecordLogCards struct {
	log *IndexRecordLog
}

// Step 2a, the log's (IndexRecordLog.ReadErasures).
func (self *indexRecordLogCards) ReadErasures(ctx context.Context) error {
	return self.log.ReadErasures(ctx)
}

// The lowest version of stream refId in (afterVersion, pin] a blocked document holds at epoch.
func (self *indexRecordLogCards) BlockedFrom(ctx context.Context, refId Id, afterVersion uint64, pin uint64, epoch uint64, set *protocol.IndexErasureSet) (uint64, error) {
	source, err := self.log.Source(refId, epoch, set)
	if err != nil {
		return 0, err
	}
	return source.blockedFrom(ctx, afterVersion, pin)
}

// The cards of the runs versions last changed, folded at epoch.
func (self *indexRecordLogCards) Cards(ctx context.Context, refId Id, versions []uint64, pin uint64, epoch uint64, set *protocol.IndexErasureSet) ([]*IndexDocument, error) {
	source, err := self.log.Source(refId, epoch, set)
	if err != nil {
		return nil, err
	}
	return source.cardsAt(ctx, versions, pin)
}

// The doc_keys an ERASE of the log masks whole on this device from the moment it applies it until a set version lists
// them (15.2.10's masks; 15.7's note: CORE-M10-04's SearchCache.ApplyErase calls this): each copy's entry document,
// where the log indexes the entry's kind, and for a card source the card of each stream holding a copy, under that
// stream's ref. entries are the log's entries as the reader holds them, streams its streams; refKey is K_ref.
func indexRecordEraseMaskKeys(refKey []byte, logKind protocol.RepoKind, erasure *RecordStreamErasure, entries []*RecordReadEntry, streams []*RecordReadStream) ([][indexIdByteCount]byte, error) {
	streamRefIds := map[Id]Id{}
	for _, stream := range streams {
		streamRefIds[stream.StreamSidecarId] = stream.RefId
	}
	named := map[Id]bool{}
	if body, ok := recordErasureNoteBody(erasure); ok {
		for _, entryId := range body.GetEntryIds() {
			if len(entryId) == len(Id{}) {
				named[Id(entryId)] = true
			}
		}
	}
	keys := map[RecordSlotKey]bool{}
	for _, key := range erasure.Keys {
		keys[*key] = true
	}
	sources := []RecordKind{}
	if indexRunCardLog(logKind) {
		sources = indexRunCardSources(logKind)
	}
	masked := map[[indexIdByteCount]byte]bool{}
	for _, entry := range entries {
		if entry.Header == nil {
			continue
		}
		hit := named[entry.EntryId]
		for _, entryCopy := range entry.Copies {
			hit = hit || keys[RecordSlotKey{SlotId: entryCopy.SlotId, KeyIndex: entryCopy.KeyIndex}]
		}
		if !hit {
			continue
		}
		kind := entry.Kind()
		runId := entry.Header.Header.GetRunId()
		for _, entryCopy := range entry.Copies {
			refId, ok := streamRefIds[entryCopy.StreamSidecarId]
			if !ok || refId == (Id{}) {
				continue
			}
			if indexRecordIndexesEntry(logKind, kind) {
				key, err := indexDocKey(refKey, refId, []byte(entryCopy.Path), 0)
				if err != nil {
					return nil, err
				}
				masked[key] = true
			}
			if slices.Contains(sources, kind) && len(runId) == len(Id{}) {
				key, err := indexDocKey(refKey, refId, indexRunCardName(Id(runId)), 0)
				if err != nil {
					return nil, err
				}
				masked[key] = true
			}
		}
	}
	ordered := make([][indexIdByteCount]byte, 0, len(masked))
	for key := range masked {
		ordered = append(ordered, key)
	}
	slices.SortFunc(ordered, compareIndexKeys)
	return ordered, nil
}
