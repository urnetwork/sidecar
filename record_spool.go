// §16.7's capture spool (R-MCP-2, R-MCP-11, D-MCP-5, D-MCP-10, I-7): capture lands here, encrypted, within
// Ingest.SpoolByteCount, so a dead network or a locked daemon loses nothing. In the root, since RECORD-M3-02's
// RecordWriter spools through it while locked. Records arrive redacted already (D-MCP-5's "pre-redacted"): the spool
// holds the epoch's Redactor so its key turns with the spool's, and seals what it is given.
//
//	ingest/spool/<segment_id>.sealed   while unlocked: a SidecarStoreLog under the ingest class (§5.9's
//	                                   <component>/, MCP.md's reading 9)
//	ingest/spool/<segment_id>.locked   while locked: records sealed to the epoch's public key (record_spool_locked.go)
//	ingest/spool-epoch/<epoch_id>      the epoch's public key, readable while locked; its private half in keychain.ur
//	ingest/spool-cursor                where the drain has got to
//	ingest/spool-kept/<log_id>/...     deposits a depositor keeps until consumed (D-MCP-10)
//
// An epoch starts at each unlock this process sees, which it tells by the keychain it opens: a new X-Wing key pair,
// its private half put in keychain.ur first and its public half's file written after, so no locked record seals to a
// key whose private half was never kept; and the redactor's key turns with it (MCP.md's reading 5). Locked and Failed
// stores create nothing, so an epoch is only ever made unlocked, and a daemon that starts Locked seals to the newest
// epoch on disk, or, with none, counts each record a gap.
//
// Segments sort by their ids, which this process draws in order, so reading them in name order is capture order. A
// drain rolls the segments being written, so appends go on into new ones while it reads the closed ones, and hands
// the consumer every taint record first (MCP-M3-15), then the rest in capture order. Each record's SpoolRecordId
// grows in capture order, and the cursor is written every SpoolCursorRecordCount records and at each segment's end,
// so after a kill a consumer that keeps the last id it took skips what comes again; taint records come first and may
// come again, which their idempotence absorbs. A drained segment is removed, and an epoch whose segments are all
// gone takes its key pair with it.
//
// Past the cap a new record is dropped and counted, never waited on, each a coverage gap (spool_drop) for the caller
// to record: Append returns at once with ErrSpoolFull. The private half never reaches a record, a log or a result.
//
// Safe for concurrent use. Appends go one at a time, in the order they take appendLock.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// The spool's places, class and format values.
const (
	spoolDirectoryName        = "ingest"
	spoolClass                = "ingest"
	spoolSegmentDirectoryName = "spool"
	spoolEpochDirectoryName   = "spool-epoch"
	spoolKeptDirectoryName    = "spool-kept"
	spoolCursorName           = "spool-cursor"
	spoolSecretsNamespace     = "ingest"
	spoolSealedSuffix         = ".sealed"
	spoolLockedSuffix         = ".locked"
	// a spooled record's own header: its kind and its run's id
	spoolRecordHeaderByteCount = 1 + 16
	// what a spooled record costs on disk beyond its bytes: its frame, a nonce or nothing, and a tag
	spoolRecordOverheadByteCount = storeLogFrameByteCount + storeLogSealedMinByteCount + spoolRecordHeaderByteCount
	// an X-Wing seed
	spoolSeedByteCount = 32
	// the most a cursor file holds
	spoolCursorMaxByteCount = 4 * 1024
)

var (
	// The spool is at Ingest.SpoolByteCount: the record was dropped and counted, a coverage gap.
	ErrSpoolFull = errors.New("spool full")
	// Locked, with no epoch's public key in memory or on disk: the record was dropped and counted, a coverage gap.
	ErrSpoolNoKey = errors.New("spool has no key while locked")
)

// What a spooled record is to its consumer.
type SpoolRecordKind uint8

const (
	// A captured event or entry, drained in capture order.
	SpoolRecordCapture SpoolRecordKind = 1
	// A run's taint, which a drain hands over before any capture record (MCP-M3-15).
	SpoolRecordTaint SpoolRecordKind = 2
)

// One spooled record.
type SpoolRecord struct {
	Kind SpoolRecordKind
	// The run it belongs to; zero for none.
	RunId Id
	// Redacted already, and opaque here.
	Bytes []byte
}

// Where a spooled record sits: its segment and its index there. Ids grow in capture order.
type SpoolRecordId struct {
	SegmentId Id
	Index     uint64
}

// -1, 0 or 1, in capture order.
func (self SpoolRecordId) Compare(other SpoolRecordId) int {
	if order := self.SegmentId.Cmp(other.SegmentId); order != 0 {
		return order
	}
	switch {
	case self.Index < other.Index:
		return -1
	case other.Index < self.Index:
		return 1
	}
	return 0
}

// A record's bytes in a segment: kind, run id, then the record's own bytes.
func encodeSpoolRecord(record *SpoolRecord) ([]byte, error) {
	if record.Kind != SpoolRecordCapture && record.Kind != SpoolRecordTaint {
		return nil, fmt.Errorf("a spool record of kind %d", record.Kind)
	}
	if StoreLogRecordMaxByteCount < spoolRecordHeaderByteCount+len(record.Bytes) {
		return nil, ErrStoreLogRecordTooLarge
	}
	encoded := make([]byte, 0, spoolRecordHeaderByteCount+len(record.Bytes))
	encoded = append(encoded, byte(record.Kind))
	encoded = append(encoded, record.RunId[:]...)
	return append(encoded, record.Bytes...), nil
}

// The record encodeSpoolRecord wrote.
func decodeSpoolRecord(encoded []byte) (*SpoolRecord, error) {
	if len(encoded) < spoolRecordHeaderByteCount {
		return nil, errSpoolFormat
	}
	kind := SpoolRecordKind(encoded[0])
	if kind != SpoolRecordCapture && kind != SpoolRecordTaint {
		return nil, errSpoolFormat
	}
	record := &SpoolRecord{Kind: kind, Bytes: encoded[spoolRecordHeaderByteCount:]}
	copy(record.RunId[:], encoded[1:spoolRecordHeaderByteCount])
	return record, nil
}

// keychain.ur's name for an epoch's private half.
func spoolEpochSecretName(epochId Id) string {
	return spoolEpochDirectoryName + "/" + epochId.String()
}

// One network's capture spool. One per Sidecar (Sidecar.Spool).
type Spool struct {
	instance  *SidecarInstance
	networkId Id
	// ingest/, class ingest
	store    SidecarStore
	secrets  SidecarSecrets
	settings *SidecarIngestSettings
	redactor *Redactor

	appendLock sync.Mutex
	// the epoch this process seals to while locked: made at an unlock, or read from disk at a locked start
	epoch *spoolEpoch
	// the keychain open when epoch was made, by which a later unlock shows as a new keychain; nil for an epoch read
	// from disk
	epochKeychain *keychain
	// the sealed segment appends go to, empty when a new one starts with the next record
	sealedName      string
	sealedByteCount int64
	// the locked segment appends go to, nil when a new one starts with the next record
	lockedSegment *spoolLockedSegment
	// the highest segment id drawn or found on disk, which every new one passes
	lastSegmentId Id
	// every segment and kept deposit on disk, which the cap bounds
	byteCount int64

	stateLock sync.Mutex
	// records dropped since the last TakeDropCount, each a coverage gap
	dropCount int
}

// A spool over the network's local store (Sidecar.LocalStore), which must be one a SidecarInstance handed out: the
// locked half writes below its keychain.
func NewSpool(localStore SidecarStore, settings *SidecarIngestSettings) (*Spool, error) {
	instance, networkId, ok := sidecarInstanceOfStore(localStore)
	if !ok || instance == nil || networkId == nil {
		return nil, errors.New("a spool needs an enrolled network's local store")
	}
	store, err := localStore.Directory(spoolDirectoryName, spoolClass)
	if err != nil {
		return nil, err
	}
	redactor, err := NewRedactor(instance.random)
	if err != nil {
		return nil, err
	}
	self := &Spool{
		instance:  instance,
		networkId: *networkId,
		store:     store,
		secrets:   instance.secrets(*networkId, spoolSecretsNamespace),
		settings:  settings,
		redactor:  redactor,
	}
	for _, prefix := range []string{spoolSegmentDirectoryName + "/", spoolKeptDirectoryName + "/"} {
		entries, err := instance.backend.List(self.backendPath(prefix))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			self.byteCount += entry.ByteCount
		}
	}
	segments, err := self.listSegments()
	if err != nil {
		return nil, err
	}
	for _, segment := range segments {
		if self.lastSegmentId.Cmp(segment.segmentId) < 0 {
			self.lastSegmentId = segment.segmentId
		}
	}
	return self, nil
}

// The epoch's redactor, whose key turns at each unlock with the spool's.
func (self *Spool) Redactor() *Redactor {
	return self.redactor
}

// A spool path's place in the backend.
func (self *Spool) backendPath(name string) string {
	return networkFilePath(self.networkId, spoolDirectoryName+"/"+name)
}

// Counts a dropped record.
func (self *Spool) countDrop() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dropCount += 1
}

// The records dropped since the last call, which the caller records as a spool_drop gap.
func (self *Spool) TakeDropCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	dropCount := self.dropCount
	self.dropCount = 0
	return dropCount
}

// What the spool holds on disk, segments and kept deposits.
func (self *Spool) ByteCount() int64 {
	self.appendLock.Lock()
	defer self.appendLock.Unlock()
	return self.byteCount
}

// A segment id above every one before it, on disk or drawn: a ULID, unless the clock stepped back past the last one,
// whose successor it then takes, so segments sort in capture order across restarts and SpoolRecordIds only grow.
func (self *Spool) nextSegmentIdWithLock() Id {
	segmentId := NewId()
	if segmentId.Cmp(self.lastSegmentId) <= 0 {
		segmentId = self.lastSegmentId
		for i := len(segmentId) - 1; 0 <= i; i -= 1 {
			segmentId[i] += 1
			if segmentId[i] != 0 {
				break
			}
		}
	}
	self.lastSegmentId = segmentId
	return segmentId
}

// Starts an epoch at an unlock this process sees, opened being the keychain it opened: the private half into
// keychain.ur, then the public half's file, then the redactor's key, and the segments roll.
func (self *Spool) startEpochWithLock(opened *keychain) error {
	seed := make([]byte, spoolSeedByteCount)
	defer clear(seed)
	if _, err := io.ReadFull(self.instance.random, seed); err != nil {
		return errors.New("no randomness for a spool key")
	}
	testHookSecret("spool_private_key", seed)
	kem, _, _ := spoolHpkeSuite()
	privateKey, err := kem.NewPrivateKey(seed)
	if err != nil {
		return fmt.Errorf("a spool key: %w", err)
	}
	publicKey := privateKey.PublicKey()
	testHookSecret("spool_public_key", publicKey.Bytes())
	epochId := NewId()
	if err := self.secrets.Put(spoolEpochSecretName(epochId), seed); err != nil {
		return err
	}
	encoded := encodeSpoolEpoch(epochId, publicKey.Bytes())
	if err := writeBackendFile(self.instance.backend, self.backendPath(spoolEpochDirectoryName+"/"+epochId.String()), encoded); err != nil {
		return err
	}
	if err := self.redactor.Rotate(self.instance.random); err != nil {
		return err
	}
	self.epoch = &spoolEpoch{epochId: epochId, publicKey: publicKey}
	self.epochKeychain = opened
	self.sealedName = ""
	self.lockedSegment = nil
	return nil
}

// The keychain if it is open, starting an epoch if this is an unlock this process has not seen.
func (self *Spool) openWithLock() (*keychain, error) {
	opened, err := self.instance.keychainFor(self.networkId)
	if err != nil {
		return nil, err
	}
	if opened != self.epochKeychain {
		if err := self.startEpochWithLock(opened); err != nil {
			return nil, err
		}
	}
	return opened, nil
}

// Spools record, durable when this returns nil: sealed under the ingest class while unlocked, to the epoch's public
// key while locked. Past the cap, or locked with no key, it is dropped and counted at once (ErrSpoolFull,
// ErrSpoolNoKey), never waited on.
func (self *Spool) Append(record *SpoolRecord) error {
	encoded, err := encodeSpoolRecord(record)
	if err != nil {
		return err
	}
	self.appendLock.Lock()
	defer self.appendLock.Unlock()
	if self.settings.SpoolByteCount < self.byteCount+int64(len(encoded)+spoolRecordOverheadByteCount) {
		self.countDrop()
		return ErrSpoolFull
	}
	_, err = self.openWithLock()
	if err == nil {
		return self.appendSealedWithLock(encoded)
	}
	if !errors.Is(err, ErrSidecarStoreLocked) {
		return err
	}
	return self.appendLockedWithLock(encoded)
}

// The unlocked half: the current sealed segment, rolled at SpoolSegmentByteCount.
func (self *Spool) appendSealedWithLock(encoded []byte) error {
	if self.sealedName == "" || self.settings.SpoolSegmentByteCount <= self.sealedByteCount {
		self.sealedName = spoolSegmentDirectoryName + "/" + self.nextSegmentIdWithLock().String() + spoolSealedSuffix
		self.sealedByteCount = 0
	}
	log, err := OpenSidecarStoreLog(self.store, self.sealedName)
	if err != nil {
		return err
	}
	if err := log.Append(encoded); err != nil {
		// whatever the file holds now, the next record starts a new segment
		self.sealedName = ""
		return err
	}
	written := int64(len(encoded) + storeLogFrameByteCount + storeLogSealedMinByteCount)
	self.sealedByteCount += written
	self.byteCount += written
	return nil
}

// The locked half: the current locked segment of the epoch, made from the newest epoch on disk at a locked start.
func (self *Spool) appendLockedWithLock(encoded []byte) error {
	if self.epoch == nil {
		epoch, err := self.newestEpochOnDisk()
		if err != nil {
			return err
		}
		if epoch == nil {
			self.countDrop()
			return ErrSpoolNoKey
		}
		self.epoch = epoch
	}
	segment := self.lockedSegment
	if segment == nil || segment.epochId != self.epoch.epochId || self.settings.SpoolSegmentByteCount <= segment.byteCount {
		segmentId := self.nextSegmentIdWithLock()
		name := spoolSegmentDirectoryName + "/" + segmentId.String() + spoolLockedSuffix
		var err error
		segment, err = newSpoolLockedSegment(self.epoch, spoolDirectoryName+"/"+name)
		if err != nil {
			return err
		}
		segment.segmentId = segmentId
		self.lockedSegment = segment
	}
	written, err := segment.append(self.instance.backend, networkFilePath(self.networkId, segment.path), encoded)
	if err != nil {
		self.lockedSegment = nil
		return err
	}
	self.byteCount += written
	return nil
}

// One segment on disk.
type spoolSegment struct {
	segmentId Id
	// inside ingest/
	name      string
	locked    bool
	byteCount int64
}

// The segments on disk, in capture order.
func (self *Spool) listSegments() ([]*spoolSegment, error) {
	prefix := self.backendPath(spoolSegmentDirectoryName + "/")
	entries, err := self.instance.backend.List(prefix)
	if err != nil {
		return nil, err
	}
	segments := []*spoolSegment{}
	for _, entry := range entries {
		base := strings.TrimPrefix(entry.Name, prefix)
		idText, locked := strings.CutSuffix(base, spoolLockedSuffix)
		if !locked {
			var sealed bool
			idText, sealed = strings.CutSuffix(base, spoolSealedSuffix)
			if !sealed {
				continue
			}
		}
		segmentId, err := ParseId(idText)
		if err != nil || segmentId.String() != idText {
			continue
		}
		segments = append(segments, &spoolSegment{
			segmentId: segmentId,
			name:      spoolSegmentDirectoryName + "/" + base,
			locked:    locked,
			byteCount: entry.ByteCount,
		})
	}
	return segments, nil
}

// Hands each record of segment to visit, decoded.
func (self *Spool) readSegment(segment *spoolSegment, visit func(index uint64, record *SpoolRecord) error) error {
	decoded := func(index uint64, encoded []byte) error {
		record, err := decodeSpoolRecord(encoded)
		if err != nil {
			return err
		}
		return visit(index, record)
	}
	if !segment.locked {
		log, err := OpenSidecarStoreLog(self.store, segment.name)
		if err != nil {
			return err
		}
		err = log.Read(decoded)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			return nil
		}
		return err
	}
	in, err := self.instance.backend.Open(self.backendPath(segment.name))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	defer in.Close()
	return readSpoolLockedSegment(in, spoolDirectoryName+"/"+segment.name, self.epochPrivateKey, decoded)
}

// The cursor as stored: the next record to hand over in the segment it names, the zero id before any drain. Every
// other segment on disk is undrained, since a drained one is removed, so the cursor skips records in its own segment
// alone.
type spoolCursor struct {
	Next SpoolRecordId `json:"next"`
}

// The drain's cursor.
func (self *Spool) readCursor() (SpoolRecordId, error) {
	reader, err := self.store.Open(spoolCursorName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return SpoolRecordId{}, nil
	}
	if err != nil {
		return SpoolRecordId{}, err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(io.LimitReader(reader, spoolCursorMaxByteCount))
	if err != nil {
		return SpoolRecordId{}, err
	}
	cursor := &spoolCursor{}
	if err := json.Unmarshal(encoded, cursor); err != nil {
		return SpoolRecordId{}, errSpoolFormat
	}
	return cursor.Next, nil
}

// Writes the cursor, durable when this returns.
func (self *Spool) writeCursor(next SpoolRecordId) error {
	encoded, err := json.Marshal(&spoolCursor{Next: next})
	if err != nil {
		return err
	}
	writer, err := self.store.Create(spoolCursorName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return writer.Commit()
}

// Removes a drained segment.
func (self *Spool) removeSegment(segment *spoolSegment) error {
	path := self.backendPath(segment.name)
	if segment.locked {
		if err := self.instance.backend.Remove(path); err != nil {
			return err
		}
		if err := self.instance.backend.SyncDirectory(path); err != nil {
			return err
		}
	} else if err := self.store.Remove(segment.name); err != nil {
		return err
	}
	self.appendLock.Lock()
	defer self.appendLock.Unlock()
	self.byteCount = max(0, self.byteCount-segment.byteCount)
	return nil
}

// Whether the cursor says id was handed over: a record before it in the cursor's own segment.
func spoolDrained(cursor SpoolRecordId, id SpoolRecordId) bool {
	return id.SegmentId == cursor.SegmentId && id.Index < cursor.Index
}

// Hands consume every spooled record, taint records first, then the rest in capture order, and removes each segment
// once its records are taken. Unlocked only: ErrSidecarStoreLocked otherwise. A consume error stops the drain, and
// the next drain starts again at the cursor. A locked segment whose epoch's key is gone is unreadable for good: it
// counts as one drop and is removed.
func (self *Spool) Drain(ctx context.Context, consume func(id SpoolRecordId, record *SpoolRecord) error) error {
	segments, cursor, currentEpoch, err := func() ([]*spoolSegment, SpoolRecordId, *spoolEpoch, error) {
		self.appendLock.Lock()
		defer self.appendLock.Unlock()
		if _, err := self.openWithLock(); err != nil {
			return nil, SpoolRecordId{}, nil, err
		}
		// appends from here on start new segments, so this drain reads only closed ones
		self.sealedName = ""
		self.lockedSegment = nil
		segments, err := self.listSegments()
		if err != nil {
			return nil, SpoolRecordId{}, nil, err
		}
		cursor, err := self.readCursor()
		return segments, cursor, self.epoch, err
	}()
	if err != nil {
		return err
	}
	unreadable := map[Id]bool{}
	// taint first, which may come again after a kill
	for _, segment := range segments {
		err := self.readSegment(segment, func(index uint64, record *SpoolRecord) error {
			id := SpoolRecordId{SegmentId: segment.segmentId, Index: index}
			if spoolDrained(cursor, id) || record.Kind != SpoolRecordTaint {
				return nil
			}
			return consume(id, record)
		})
		if spoolKeyGone(err) {
			unreadable[segment.segmentId] = true
			continue
		}
		if err != nil {
			return err
		}
	}
	for _, segment := range segments {
		if err := ctx.Err(); err != nil {
			return err
		}
		if unreadable[segment.segmentId] {
			self.countDrop()
			if err := self.removeSegment(segment); err != nil {
				return err
			}
			continue
		}
		pendingCount := 0
		err := self.readSegment(segment, func(index uint64, record *SpoolRecord) error {
			id := SpoolRecordId{SegmentId: segment.segmentId, Index: index}
			if spoolDrained(cursor, id) || record.Kind == SpoolRecordTaint {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := consume(id, record); err != nil {
				return err
			}
			pendingCount += 1
			if self.settings.SpoolCursorRecordCount <= pendingCount {
				cursor = SpoolRecordId{SegmentId: segment.segmentId, Index: index + 1}
				pendingCount = 0
				return self.writeCursor(cursor)
			}
			return nil
		})
		if err != nil {
			return err
		}
		cursor = SpoolRecordId{SegmentId: segment.segmentId, Index: math.MaxUint64}
		if err := self.writeCursor(cursor); err != nil {
			return err
		}
		if err := self.removeSegment(segment); err != nil {
			return err
		}
	}
	return self.removeOldEpochs(currentEpoch)
}

// Removes every epoch but current whose locked segments are all gone: its public file, then its private half.
func (self *Spool) removeOldEpochs(current *spoolEpoch) error {
	segments, err := self.listSegments()
	if err != nil {
		return err
	}
	referenced := map[Id]bool{}
	if current != nil {
		referenced[current.epochId] = true
	}
	for _, segment := range segments {
		if !segment.locked {
			continue
		}
		epochId, whole, err := self.lockedSegmentEpoch(self.backendPath(segment.name))
		if err != nil || !whole {
			continue
		}
		referenced[epochId] = true
	}
	prefix := self.backendPath(spoolEpochDirectoryName + "/")
	entries, err := self.instance.backend.List(prefix)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := strings.TrimPrefix(entry.Name, prefix)
		epochId, err := ParseId(name)
		if err != nil || epochId.String() != name || referenced[epochId] {
			continue
		}
		if err := self.instance.backend.Remove(entry.Name); err != nil {
			return err
		}
		if err := self.instance.backend.SyncDirectory(entry.Name); err != nil {
			return err
		}
		if err := self.secrets.Delete(spoolEpochSecretName(epochId)); err != nil {
			return err
		}
	}
	return nil
}

// A kept deposit's name: its log, then a sequence that sorts by when it was kept, then its push version.
func spoolKeptName(logId Id, keptId Id, pushVersion uint64) string {
	return fmt.Sprintf("%s/%s/%s-%020d", spoolKeptDirectoryName, logId, keptId, pushVersion)
}

// The push version a kept deposit's base name, <kept_id>-<20 digits>, holds.
func spoolKeptVersion(base string) (uint64, bool) {
	keptText, versionText, ok := strings.Cut(base[min(len(base), len(Id{}.String())):], "-")
	if !ok || keptText != "" || len(versionText) != 20 {
		return 0, false
	}
	if _, err := ParseId(base[:len(Id{}.String())]); err != nil {
		return 0, false
	}
	version, err := strconv.ParseUint(versionText, 10, 64)
	return version, err == nil
}

// Keeps a deposit this depositor made to logId at pushVersion until an ingester's consumed_through mark passes it
// (D-MCP-10; plan-RECORD-depositor-spool), so a re-seed re-uploads it verbatim. Unlocked only. Within the spool's cap,
// the oldest kept deposits go first, each counted a drop.
func (self *Spool) Keep(logId Id, pushVersion uint64, deposit []byte) error {
	self.appendLock.Lock()
	defer self.appendLock.Unlock()
	if _, err := self.openWithLock(); err != nil {
		return err
	}
	need := int64(len(deposit) + spoolRecordOverheadByteCount)
	if self.settings.SpoolByteCount < self.byteCount+need {
		entries, err := self.store.List(spoolKeptDirectoryName + "/")
		if err != nil {
			return err
		}
		// the oldest first, across logs: each base name starts with a sequence that sorts by when it was kept
		keptAt := func(entry SidecarStoreEntry) string {
			return entry.Name[strings.LastIndex(entry.Name, "/")+1:]
		}
		slices.SortFunc(entries, func(a SidecarStoreEntry, b SidecarStoreEntry) int {
			return strings.Compare(keptAt(a), keptAt(b))
		})
		for _, entry := range entries {
			if self.byteCount+need <= self.settings.SpoolByteCount {
				break
			}
			if err := self.store.Remove(entry.Name); err != nil {
				return err
			}
			self.byteCount = max(0, self.byteCount-entry.ByteCount)
			self.countDrop()
		}
		if self.settings.SpoolByteCount < self.byteCount+need {
			self.countDrop()
			return ErrSpoolFull
		}
	}
	writer, err := self.store.Create(spoolKeptName(logId, NewId(), pushVersion))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(deposit); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	self.byteCount += need
	return nil
}

// Hands visit each deposit kept for logId, in the order kept, with its push version.
func (self *Spool) Kept(logId Id, visit func(pushVersion uint64, deposit []byte) error) error {
	prefix := spoolKeptDirectoryName + "/" + logId.String() + "/"
	entries, err := self.store.List(prefix)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		version, ok := spoolKeptVersion(strings.TrimPrefix(entry.Name, prefix))
		if !ok {
			continue
		}
		reader, err := self.store.Open(entry.Name)
		if err != nil {
			return err
		}
		deposit, err := io.ReadAll(io.LimitReader(reader, StoreLogRecordMaxByteCount+1))
		reader.Close()
		if err != nil {
			return err
		}
		if err := visit(version, deposit); err != nil {
			return err
		}
	}
	return nil
}

// Removes every deposit kept for logId at or below consumedThrough, the ingester's mark: no unconsumed deposit of
// this ref remains there (plan-RECORD-depositor-spool). Answers how many went.
func (self *Spool) PruneKept(logId Id, consumedThrough uint64) (int, error) {
	prefix := spoolKeptDirectoryName + "/" + logId.String() + "/"
	entries, err := self.store.List(prefix)
	if err != nil {
		return 0, err
	}
	removedCount := 0
	for _, entry := range entries {
		version, ok := spoolKeptVersion(strings.TrimPrefix(entry.Name, prefix))
		if !ok || consumedThrough < version {
			continue
		}
		if err := self.store.Remove(entry.Name); err != nil {
			return removedCount, err
		}
		func() {
			self.appendLock.Lock()
			defer self.appendLock.Unlock()
			self.byteCount = max(0, self.byteCount-entry.ByteCount)
		}()
		removedCount += 1
	}
	return removedCount, nil
}

// The network's spool. One per Sidecar, so one epoch and one cap. ErrSidecarStoreLocked before enrollment.
func (self *Sidecar) Spool() (*Spool, error) {
	networkId := self.knownNetworkId()
	if self.instance == nil || networkId == nil {
		return nil, ErrSidecarStoreLocked
	}
	self.records.stateLock.Lock()
	defer self.records.stateLock.Unlock()
	self.records.forNetworkWithLock(*networkId)
	if self.records.spool == nil {
		spool, err := NewSpool(self.LocalStore(), self.settings.Ingest)
		if err != nil {
			return nil, err
		}
		self.records.spool = spool
	}
	return self.records.spool, nil
}

// A spooled record's length on the wire of a test or a log line, which carries no bytes of it.
func (self *SpoolRecord) String() string {
	return fmt.Sprintf("spool record kind %d, run %s, %d bytes", self.Kind, self.RunId, len(self.Bytes))
}
