// RECORD.md section 5.5's reader, on every leg: RecordReader.Sync reads a log's streams through RecordStreams, in
// stream order, and verifies each entry before anything shows it; Entries answers what it holds, each with its state.
//
//	1 push    the binding returns only pushes whose statements verify by §11.8's replay (RECORD-M3-12)
//	2 header  record_verify.go: the Signed verifies over its received bytes under the writer's identity key
//	3 right   record_verify.go: where the entry came in; then a known kind from a writer section 6.3 does not
//	          admit is ignored: a receipt-only depositor's anything but read, and a membership or key entry in a
//	          vault from another than its member's devices
//	4 chain   record_pins.go: copies, forks and gaps, kept and alarmed, never dropped
//	5 body    with its slot row: opened and its commitment recomputed; one that does not open or commit, or breaks
//	          its kind's caps, shows as invalid with its header standing; without its row, erased
//	6 kind    a known kind's body keeps its stored bytes, which the caller parses as its one message; an unknown kind
//	          is kept, verified and shown generically, never refused
//
// A failure at steps 1 to 3 ignores the entry and raises bad_entry; a pin this state has not reached stops that
// stream's read at the push, to read again once it has. An ERASE read from the log's erasure ref, or an erasure entry
// naming an entry, erases every copy of it: its body goes from memory and its header and chain still verify. Bodies
// are held in memory only, so restarting reads the log again, and the pins (record_pins.go) say whether a stream wound
// back meanwhile. The states expired, archived and lost wait on BASE, retention (M6) and the checkpoint log (M6);
// nothing here sets them yet.
//
// Safe for concurrent use: one Sync a log at a time, and Entries any time. Barriers: record.read.before and .after
// around a stream's read, keyed by the log.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What an entry is now (RECORD.md section 5.5's states row).
type RecordEntryState string

const (
	RecordEntryLive RecordEntryState = "live"
	// An ERASE named a key of a copy, or an erasure entry named it: the header is kept.
	RecordEntryErased RecordEntryState = "erased"
	// Past keep_days and erased; after BASE and GC only its push statement and any checkpoint leaf remain.
	RecordEntryExpired RecordEntryState = "expired"
	// Past keep_days with archive set (section 8).
	RecordEntryArchived RecordEntryState = "archived"
	// A later branch of a writer's fork.
	RecordEntryForked RecordEntryState = "forked"
	// A checkpoint leaf with no entry, after a site loss.
	RecordEntryLost RecordEntryState = "lost"
)

var (
	// This sidecar does not read the log (§8.6).
	ErrRecordNotReader = errors.New("record log not read by this sidecar")
)

// One place an entry sits.
type RecordEntryCopy struct {
	StreamSidecarId Id
	Version         uint64
	Path            string
	SlotId          Id
	KeyIndex        uint32
	// The pin the push holding this copy declared, and evs's time_ms for that push: where §16.11's card and repo file
	// rules judge an announce entry (the M6 carrier row's "the entry's push's auth pin standing for at").
	AuthPin    *bridge.AuthPin
	TimeMillis int64
}

// One verified entry, as a reader holds it.
type RecordReadEntry struct {
	LogId   Id
	EntryId Id
	Header  *StoredRecordHeader
	// The header's Signed as stored, which header_sha256 covers.
	SignedBytes []byte
	Leaf        [sha256.Size]byte
	State       RecordEntryState
	// The body as stored, opened and committed to; nil without its key, while invalid, and once erased.
	Body []byte
	// The body did not open, did not commit, or broke its kind's caps: shown as invalid, its header standing.
	BodyInvalid bool
	// The header's tainted: reading its text taints the reader's run first (§16.6, I-9).
	Flagged bool
	// time_ms of the earliest push holding a copy, which evs bounds where time_millis is the writer's word.
	PushTimeMillis int64
	// time_millis more than TimeSkewTimeout past the push time.
	Skewed bool
	// Every copy, first read first.
	Copies []*RecordEntryCopy
}

// A copy, sharing nothing with the reader's.
func (self *RecordReadEntry) clone() *RecordReadEntry {
	clone := *self
	clone.SignedBytes = bytes.Clone(self.SignedBytes)
	clone.Body = bytes.Clone(self.Body)
	clone.Copies = nil
	for _, entryCopy := range self.Copies {
		copied := *entryCopy
		if entryCopy.AuthPin != nil {
			copied.AuthPin = &bridge.AuthPin{Version: entryCopy.AuthPin.GetVersion(), Chain: bytes.Clone(entryCopy.AuthPin.GetChain())}
		}
		clone.Copies = append(clone.Copies, &copied)
	}
	return &clone
}

// The kind, as the header carries it.
func (self *RecordReadEntry) Kind() RecordKind {
	return self.Header.Kind()
}

// What a RecordReader reads with.
type RecordReaderArgs struct {
	SidecarId Id
	// The record component's sealed directory, for the pins.
	Store    SidecarStore
	Streams  func() RecordStreams
	Auth     func() RecordAuthView
	Alarm    func(alarm *RecordAlarm)
	Clock    Clock
	Settings *SidecarRecordSettings
	Log      Logger
	// A push pin before what the state retains is judged at the state itself, its chain value taken as §11.9's first
	// pin, as §16.11's repo file row judges a position older than the reader's retention point; false refuses such an
	// entry. The team directory's reader sets it (RecordEntryArrival.UnretainedAtHead), so a device that starts past
	// a repo item's push still reads it, and the directory's fold holds each kind to its own rule after.
	UnretainedAtHead bool
}

// The logs this sidecar reads, as verified so far.
type RecordReader struct {
	sidecarId Id
	chain     *RecordChainStore
	streams   func() RecordStreams
	auth      func() RecordAuthView
	alarm     func(alarm *RecordAlarm)
	clock     Clock
	settings  *SidecarRecordSettings
	log       Logger
	// RecordReaderArgs.UnretainedAtHead
	unretainedAtHead bool

	stateLock sync.Mutex
	logs      map[Id]*recordReadLog
}

// One log as read.
type recordReadLog struct {
	logId Id
	// one Sync at a time
	syncLock sync.Mutex

	// the reader's stateLock guards the rest
	pins           *recordPins
	streamVersions map[Id]uint64
	leafEntries    map[[sha256.Size]byte]*RecordReadEntry
	ordered        []*RecordReadEntry
	writerChains   map[Id]*recordReadChain
	erasureVersion uint64
	erasedKeys     map[RecordSlotKey]bool
	erasedEntryIds map[Id]bool
}

// A reader over args, reading nothing until its first Sync. Store is required; nil settings are the defaults.
func NewRecordReader(args *RecordReaderArgs) *RecordReader {
	settings := args.Settings
	if settings == nil {
		settings = defaultSidecarRecordSettings()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	streams := args.Streams
	if streams == nil {
		streams = func() RecordStreams { return RecordStreamsUnavailable{} }
	}
	auth := args.Auth
	if auth == nil {
		auth = func() RecordAuthView { return RecordAuthUnavailable{} }
	}
	return &RecordReader{
		sidecarId: args.SidecarId,
		chain:     NewRecordChainStore(args.Store, args.SidecarId),
		streams:   streams,
		auth:      auth,
		alarm:     args.Alarm,
		clock:     clockOrReal(args.Clock),
		settings:  settings,
		log:       log,
		logs:      map[Id]*recordReadLog{},

		unretainedAtHead: args.UnretainedAtHead,
	}
}

// The authorization state now, failing closed.
func (self *RecordReader) authNow() RecordAuthView {
	if auth := self.auth(); auth != nil {
		return auth
	}
	return RecordAuthUnavailable{}
}

// One alarm through the record's sink.
func (self *RecordReader) raise(reason SidecarRecordAlarm, logId Id, sidecarId *Id) {
	if self.alarm != nil {
		self.alarm(&RecordAlarm{Reason: reason, LogId: logId, SidecarId: sidecarId})
	}
}

// The log's state, made on first use.
func (self *RecordReader) readLog(logId Id) *recordReadLog {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	log, ok := self.logs[logId]
	if !ok {
		log = &recordReadLog{
			logId:          logId,
			streamVersions: map[Id]uint64{},
			leafEntries:    map[[sha256.Size]byte]*RecordReadEntry{},
			writerChains:   map[Id]*recordReadChain{},
			erasedKeys:     map[RecordSlotKey]bool{},
			erasedEntryIds: map[Id]bool{},
		}
		self.logs[logId] = log
	}
	return log
}

// Reads what logId holds past what this reader has read: every stream, then the erasures, then the chains' timeouts
// and the pins. The first failure to read a stream stops this sync, keeping what it verified.
func (self *RecordReader) Sync(ctx context.Context, logId Id) error {
	log := self.readLog(logId)
	log.syncLock.Lock()
	defer log.syncLock.Unlock()
	auth := self.authNow()
	if !auth.Reads(logId, self.sidecarId) {
		return fmt.Errorf("%w: %s", ErrRecordNotReader, logId)
	}
	if log.pins == nil {
		pins, err := readRecordPins(self.chain, logId)
		if err != nil {
			return err
		}
		log.pins = pins
	}
	streams := self.streams()
	heads, err := streams.Streams(ctx, logId)
	if err != nil {
		return err
	}
	slices.SortFunc(heads, func(a *RecordStreamHead, b *RecordStreamHead) int { return a.SidecarId.Cmp(b.SidecarId) })
	hookKey := recordChainIdText(logId)
	for _, head := range heads {
		readVersion := func() uint64 {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return log.streamVersions[head.SidecarId]
		}()
		if head.Version < max(readVersion, log.pins.streamVersions[head.SidecarId]) {
			// evs holds less of this stream than this device already read
			streamId := head.SidecarId
			self.raise(SidecarRecordAlarmChainFork, logId, &streamId)
			continue
		}
		if head.Version == readVersion {
			continue
		}
		testHookBarrier("record.read.before", hookKey)
		versions, err := streams.ReadStream(ctx, logId, head.SidecarId, readVersion)
		testHookBarrier("record.read.after", hookKey)
		if err != nil {
			return err
		}
		for _, version := range versions {
			if version.Version <= readVersion {
				continue
			}
			ahead, err := self.readVersion(ctx, streams, auth, log, head.SidecarId, version)
			if err != nil {
				return err
			}
			if ahead {
				break
			}
			readVersion = version.Version
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				log.streamVersions[head.SidecarId] = readVersion
			}()
		}
	}
	if err := self.readErasures(ctx, streams, log); err != nil {
		return err
	}
	self.checkChains(auth, log)
	return self.pin(log)
}

// Verifies one push's entries in §16.8's order and keeps what passes. True when the push's pin is ahead of this
// state, and the stream's read stops before it.
func (self *RecordReader) readVersion(ctx context.Context, streams RecordStreams, auth RecordAuthView, log *recordReadLog, streamId Id, version *RecordStreamVersion) (bool, error) {
	type arrived struct {
		fields   *recordEntryFields
		verified *RecordVerifiedHeader
		path     string
	}
	arrivals := []*arrived{}
	for _, streamEntry := range version.Entries {
		fields := &recordEntryFields{}
		if err := fields.parse(streamEntry.Entry); err != nil {
			self.raise(SidecarRecordAlarmBadEntry, log.logId, &streamId)
			continue
		}
		arrival := &RecordEntryArrival{StreamSidecarId: streamId, PushPin: version.AuthPin, UnretainedAtHead: self.unretainedAtHead}
		verified, err := VerifyRecordEntry(auth, log.logId, fields.signed, arrival)
		if errors.Is(err, ErrRecordAuthAhead) {
			return true, nil
		}
		if err != nil {
			writerId := streamId
			if header, _, parseErr := recordSignedHeader(fields.signed); parseErr == nil {
				writerId = recordIdOf(header.Header.GetWriterSidecarId())
			}
			if self.log.V(1).Enabled() {
				self.log.Infof("[record]an entry in log %s refused: %s", log.logId, err)
			}
			self.raise(SidecarRecordAlarmBadEntry, log.logId, &writerId)
			continue
		}
		arrivals = append(arrivals, &arrived{fields: fields, verified: verified, path: streamEntry.Path})
	}
	slices.SortStableFunc(arrivals, func(a *arrived, b *arrived) int {
		return RecordCompareInPush(a.verified.Header, b.verified.Header)
	})
	slotRows := map[uint32][]byte{}
	slotRead := false
	for _, arrival := range arrivals {
		header := arrival.verified.Header
		writerId := recordIdOf(header.Header.GetWriterSidecarId())
		if !self.kindAdmitted(auth, log.logId, writerId, header) {
			self.raise(SidecarRecordAlarmBadEntry, log.logId, &writerId)
			continue
		}
		entryCopy := &RecordEntryCopy{
			StreamSidecarId: streamId, Version: version.Version, Path: arrival.path, KeyIndex: arrival.fields.keyIndex,
			TimeMillis: version.TimeMillis,
		}
		if version.AuthPin != nil {
			entryCopy.AuthPin = &bridge.AuthPin{Version: version.AuthPin.GetVersion(), Chain: bytes.Clone(version.AuthPin.GetChain())}
		}
		if len(arrival.fields.keySlotId) == len(Id{}) {
			entryCopy.SlotId = Id(arrival.fields.keySlotId)
		}
		leaf := header.LeafHash()
		held := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			entry, ok := log.leafEntries[leaf]
			if ok {
				// a copy: shown once, every copy's place kept, the earlier push time standing
				entry.Copies = append(entry.Copies, entryCopy)
				entry.PushTimeMillis = min(entry.PushTimeMillis, version.TimeMillis)
				if log.erasedKeys[RecordSlotKey{SlotId: entryCopy.SlotId, KeyIndex: entryCopy.KeyIndex}] {
					recordEraseEntryWithLock(entry)
				}
			}
			return ok
		}()
		if held {
			continue
		}
		entry := &RecordReadEntry{
			LogId:          log.logId,
			EntryId:        recordIdOf(header.Header.GetEntryId()),
			Header:         header,
			SignedBytes:    arrival.verified.SignedBytes,
			Leaf:           leaf,
			State:          RecordEntryLive,
			Flagged:        header.Header.GetTainted(),
			PushTimeMillis: version.TimeMillis,
			Copies:         []*RecordEntryCopy{entryCopy},
		}
		skew := self.settings.TimeSkewTimeout
		entry.Skewed = time.Duration(header.Header.GetTimeMillis()-version.TimeMillis)*time.Millisecond > skew
		if entryCopy.SlotId != (Id{}) && !slotRead {
			slot, err := streams.ReadSlot(ctx, log.logId, version.SlotId)
			if err == nil {
				for _, row := range slot.Rows {
					slotRows[row.KeyIndex] = row.Row
				}
			} else if code, ok := RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND {
				return false, err
			}
			slotRead = true
		}
		self.openBody(log.logId, writerId, entry, arrival.fields, slotRows, entryCopy.SlotId == version.SlotId)
		self.chainEntry(auth, log, writerId, entry)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if log.erasedEntryIds[entry.EntryId] || log.erasedKeys[RecordSlotKey{SlotId: entryCopy.SlotId, KeyIndex: entryCopy.KeyIndex}] {
				recordEraseEntryWithLock(entry)
			}
			log.leafEntries[leaf] = entry
			log.ordered = append(log.ordered, entry)
		}()
		if entry.Kind() == RecordKindErasure && entry.Body != nil {
			self.applyErasureEntry(log, entry)
		}
	}
	return false, nil
}

// Section 6.3's writer column where it narrows what step 3 admits: a receipt-only depositor files read entries of
// source observed alone, and a vault's membership and key entries come only from its own member's devices.
func (self *RecordReader) kindAdmitted(auth RecordAuthView, logId Id, writerId Id, header *StoredRecordHeader) bool {
	kind := header.Kind()
	judged, err := auth.AtPosition(max(header.Header.GetPolicyVersion(), 1))
	if err != nil {
		judged = auth
	}
	if judged.ReceiptOnly(logId, writerId) {
		return kind == RecordKindRead && RecordSource(header.Header.GetSource()) == RecordSourceObserved
	}
	if kind == RecordKindMembership || kind == RecordKindKey {
		memberId, ok := judged.Member(writerId)
		if !ok {
			return false
		}
		if vaultId, ok := judged.Vault(memberId); ok && vaultId != logId {
			// a vault's own: another member's device never writes there (owner decision 126)
			return !recordLogIsAVault(judged, logId)
		}
	}
	return true
}

// Whether logId is some member's vault in this state, so its membership and key entries come from that member alone.
func recordLogIsAVault(auth RecordAuthView, logId Id) bool {
	// RecordAuthView answers a member's vault, not a vault's member: a log that is not the team's is read as a vault
	logs := auth.Logs()
	return (logs.TeamRecordId == nil || *logs.TeamRecordId != logId) && (logs.DirectoryId == nil || *logs.DirectoryId != logId)
}

// Step 5: opens the body with its slot row and holds it to its commitment and its kind's caps. A row this push's slot
// object does not hold is a key gone: the entry shows erased.
func (self *RecordReader) openBody(logId Id, writerId Id, entry *RecordReadEntry, fields *recordEntryFields, slotRows map[uint32][]byte, inThisSlot bool) {
	row, ok := slotRows[fields.keyIndex]
	if !ok || !inThisSlot {
		entry.State = RecordEntryErased
		return
	}
	key, salt, err := RecordSlotRowSplit(row)
	if err == nil {
		var body []byte
		body, err = RecordOpen(entry.Header, fields.sealedBody, key, salt)
		clear(key)
		clear(salt)
		if err == nil {
			if capErr := RecordBodyValidateStored(entry.Kind(), body); capErr != nil {
				entry.BodyInvalid = true
				clear(body)
				self.raise(SidecarRecordAlarmOverCap, logId, &writerId)
				return
			}
			entry.Body = body
			return
		}
	}
	entry.BodyInvalid = true
	self.raise(SidecarRecordAlarmBadEntry, logId, &writerId)
}

// Step 4: the entry's place in its writer's chain, across every stream of the log.
func (self *RecordReader) chainEntry(auth RecordAuthView, log *recordReadLog, writerId Id, entry *RecordReadEntry) {
	verdict := func() *recordChainVerdict {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		chain, ok := log.writerChains[writerId]
		if !ok {
			chain = newRecordReadChain()
			log.writerChains[writerId] = chain
		}
		return chain.add(entry.Header.Header.GetSeq(), [sha256.Size]byte(entry.Header.Header.GetPrevSha256()), entry.Leaf)
	}()
	if verdict.forked {
		entry.State = RecordEntryForked
		self.raise(SidecarRecordAlarmChainFork, log.logId, &writerId)
	}
}

// Raises each writer's gap: at once for a writer with no deposit right on the log, past ChainGapTimeout for one that
// deposits; once a gap.
func (self *RecordReader) checkChains(auth RecordAuthView, log *recordReadLog) {
	nowMillis := self.clock.Now().UnixMilli()
	alarmed := []Id{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for writerId, chain := range log.writerChains {
			if chain.head == chain.highest() {
				chain.gapMillis = 0
				chain.gapAlarmed = false
				continue
			}
			if chain.gapMillis == 0 {
				chain.gapMillis = nowMillis
			}
			if chain.gapAlarmed {
				continue
			}
			deposits := auth.Deposits(log.logId, writerId)
			if !deposits || self.settings.ChainGapTimeout.Milliseconds() <= nowMillis-chain.gapMillis {
				chain.gapAlarmed = true
				alarmed = append(alarmed, writerId)
			}
		}
	}()
	for _, writerId := range alarmed {
		self.raise(SidecarRecordAlarmChainGap, log.logId, &writerId)
	}
}

// Holds the sync to the pins, then raises them: a writer's head below its pin, or another leaf at the pinned seq,
// alarms (I-16).
func (self *RecordReader) pin(log *recordReadLog) error {
	type finding struct {
		reason   SidecarRecordAlarm
		writerId Id
	}
	findings := []*finding{}
	pins := func() *recordPins {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		pins := &recordPins{streamVersions: map[Id]uint64{}, writerHeads: map[Id]RecordChainHead{}}
		for sidecarId, version := range log.pins.streamVersions {
			pins.streamVersions[sidecarId] = max(version, log.streamVersions[sidecarId])
		}
		for sidecarId, version := range log.streamVersions {
			pins.streamVersions[sidecarId] = max(version, pins.streamVersions[sidecarId])
		}
		for writerId, pinned := range log.pins.writerHeads {
			chain := log.writerChains[writerId]
			if chain == nil || chain.head < pinned.Seq {
				findings = append(findings, &finding{reason: SidecarRecordAlarmChainGap, writerId: writerId})
				pins.writerHeads[writerId] = pinned
				continue
			}
			if chain.seqLeafs[pinned.Seq] != pinned.Leaf {
				findings = append(findings, &finding{reason: SidecarRecordAlarmChainFork, writerId: writerId})
			}
		}
		for writerId, chain := range log.writerChains {
			if pinned, ok := pins.writerHeads[writerId]; ok && chain.head < pinned.Seq {
				continue
			}
			if 0 < chain.head {
				pins.writerHeads[writerId] = RecordChainHead{Seq: chain.head, Leaf: chain.seqLeafs[chain.head]}
			}
		}
		return pins
	}()
	for _, finding := range findings {
		self.raise(finding.reason, log.logId, &finding.writerId)
	}
	if err := writeRecordPins(self.chain, log.logId, pins); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	log.pins = pins
	return nil
}

// Reads the log's ERASEs past those read, and erases each entry a copy of which a named key opened.
func (self *RecordReader) readErasures(ctx context.Context, streams RecordStreams, log *recordReadLog) error {
	after := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return log.erasureVersion
	}()
	erasures, err := streams.ReadErasures(ctx, log.logId, after)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, erasure := range erasures {
		for _, key := range erasure.Keys {
			log.erasedKeys[*key] = true
		}
		log.erasureVersion = max(log.erasureVersion, erasure.Version)
	}
	for _, entry := range log.ordered {
		for _, entryCopy := range entry.Copies {
			if log.erasedKeys[RecordSlotKey{SlotId: entryCopy.SlotId, KeyIndex: entryCopy.KeyIndex}] {
				recordEraseEntryWithLock(entry)
			}
		}
	}
	return nil
}

// An erasure entry's named entries: erased here, and refused by an ingester (section 5.4's erased step).
func (self *RecordReader) applyErasureEntry(log *recordReadLog, erasure *RecordReadEntry) {
	body := &protocol.ErasureBody{}
	if err := proto.Unmarshal(erasure.Body, body); err != nil {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, entryId := range body.GetEntryIds() {
		if len(entryId) == len(Id{}) {
			log.erasedEntryIds[Id(entryId)] = true
		}
	}
	for _, entry := range log.ordered {
		if log.erasedEntryIds[entry.EntryId] {
			recordEraseEntryWithLock(entry)
		}
	}
}

// Drops an entry's body for good: every decrypted copy goes (§16.8's erasure row).
func recordEraseEntryWithLock(entry *RecordReadEntry) {
	clear(entry.Body)
	entry.Body = nil
	entry.BodyInvalid = false
	entry.State = RecordEntryErased
}

// The log's entries as read, in read order, each a copy.
func (self *RecordReader) Entries(logId Id) []*RecordReadEntry {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	log, ok := self.logs[logId]
	if !ok {
		return nil
	}
	entries := make([]*RecordReadEntry, 0, len(log.ordered))
	for _, entry := range log.ordered {
		entries = append(entries, entry.clone())
	}
	return entries
}

// The first entry read with entryId, false for none.
func (self *RecordReader) Entry(logId Id, entryId Id) (*RecordReadEntry, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	log, ok := self.logs[logId]
	if !ok {
		return nil, false
	}
	for _, entry := range log.ordered {
		if entry.EntryId == entryId {
			return entry.clone(), true
		}
	}
	return nil, false
}

// Whether an erasure this reader has read names entryId in logId: an ERASE of any copy's key, or an erasure entry.
func (self *RecordReader) Erased(logId Id, entryId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	log, ok := self.logs[logId]
	if !ok {
		return false
	}
	if log.erasedEntryIds[entryId] {
		return true
	}
	for _, entry := range log.ordered {
		if entry.EntryId == entryId && entry.State == RecordEntryErased {
			return true
		}
	}
	return false
}

// Whether a leaf is held in logId, in any stream: an ingester's check before it writes a copy.
func (self *RecordReader) Holds(logId Id, leaf [sha256.Size]byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	log, ok := self.logs[logId]
	if !ok {
		return false
	}
	_, held := log.leafEntries[leaf]
	return held
}

// Whether a leaf is held in logId in the stream of streamId: an ingester's own copy.
func (self *RecordReader) HoldsIn(logId Id, streamId Id, leaf [sha256.Size]byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	log, ok := self.logs[logId]
	if !ok {
		return false
	}
	entry, held := log.leafEntries[leaf]
	return held && slices.ContainsFunc(entry.Copies, func(entryCopy *RecordEntryCopy) bool { return entryCopy.StreamSidecarId == streamId })
}
