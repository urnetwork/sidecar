//go:build !ios_extension && !sidecar_http

// The support log (DESIGN-COMPUTE §28.7, D-SUP-4): a log beside glog that holds codes and counts, never content, which
// a person or an agent may attach to a message to URnetwork's support. Each process keeps its own ring in its own
// state, ur daemon's under <state>/support-log and an app's under its sidecar's state directory, of at most
// RingMaxByteCount bytes and RingMaxAge of events, whichever is less. Nothing leaves the device but in a message a
// person or an agent sends: the support log is no telemetry (DESIGN §5.10).
//
// What it can hold is what support/registry.yml declares. A component writes through Event, with a code constant and
// fields that only the registry's generated constructors build (support_log_registry.go), so no free text has a way
// in: an enum takes its own Go type, a count, a duration and a size are kept only as their bucket, a version only
// once it passes its format check, and a token, an object's id, only as an HMAC under the ring's own key, so a
// canary id written as a token leaves no byte of itself in the ring. check/support_log_test.go's analyzer fails the
// build for an Event whose field is not a constructor the code declares; Event refuses and counts one at run time as
// well, which the field_refused code records.
//
// The ring is a directory of segments, each a magic line and then records: a uvarint length, the record, and its
// CRC-32. A crash leaves at most a torn last record, which ends that segment's reading. Event never waits on the disk:
// it encodes the event and appends it to a bounded buffer that one writer goroutine flushes every FlushInterval, and
// past the buffer's bound it drops and counts. A bundle (support_log_bundle.go) flushes first.
//
// A SupportLog is safe for concurrent use, and a nil *SupportLog takes every Event and writes nothing.

package sidecar

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"
)

// A code the registry declares: its component, its severity and the fields it may carry.
type SupportLogCode uint32

// A component the registry declares.
type SupportLogComponent uint32

// A field's number in the registry.
type SupportLogFieldNumber uint32

// An event's severity (§28.7).
type SupportLogSeverity uint32

const (
	SupportLogSeverityInfo     SupportLogSeverity = 1
	SupportLogSeverityDegraded SupportLogSeverity = 2
	SupportLogSeverityFailed   SupportLogSeverity = 3
)

// The severities' names, as a bundle renders them.
var supportLogSeverityNames = map[SupportLogSeverity]string{
	SupportLogSeverityInfo:     "info",
	SupportLogSeverityDegraded: "degraded",
	SupportLogSeverityFailed:   "failed",
}

// A field's type, as the registry declares it and the ring records it.
type supportLogFieldType uint8

const (
	supportLogFieldTypeEnum     supportLogFieldType = 1
	supportLogFieldTypeCount    supportLogFieldType = 2
	supportLogFieldTypeDuration supportLogFieldType = 3
	supportLogFieldTypeSize     supportLogFieldType = 4
	supportLogFieldTypeVersion  supportLogFieldType = 5
	supportLogFieldTypeBoolean  supportLogFieldType = 6
	supportLogFieldTypeToken    supportLogFieldType = 7
)

// What a ring's version field and token field hold.
const (
	supportLogValueNone    = 0
	supportLogValueKept    = 1
	supportLogValueInvalid = 2
)

// The first bytes of every segment: what the ring is and its format's version.
const supportLogSegmentMagic = "urnetwork-support-log-v1\n"

// A segment's name: its first second, zero-padded so names sort by time, then a sequence for two in one second.
var supportLogSegmentNamePattern = regexp.MustCompile(`^([0-9]{12})-([0-9]{6})\.seg$`)

// The ring's token key, beside its segments.
const supportLogKeyFileName = "key"

// A version as a version field takes it: digits and dots, an optional leading v, and an optional build suffix of
// lowercase hex after + or -, as yyyy.m.d+code and a harness's semver are written. Anything else is held as invalid,
// so no word reaches the ring through a version.
var supportLogVersionPattern = regexp.MustCompile(`^v?[0-9]{1,6}(\.[0-9]{1,6}){0,3}([+-][0-9a-f]{1,16})?$`)

// One field of an event. Only the registry's constructors build one (support_log_registry.go), and Event takes nothing
// else: the zero value names no field and is refused.
type SupportLogField struct {
	number    SupportLogFieldNumber
	fieldType supportLogFieldType
	// an enum's value; a count, a duration in milliseconds or a size in bytes, before its bucket; a boolean's 0 or 1
	value uint64
	// a version field's text, which Event checks before the ring holds it
	version string
	// a token field's id, which Event turns into an HMAC under the ring's key and never keeps as given
	id []byte
}

// What writes to the support log. A component holds one, *SupportLog or none (SidecarSettings.SupportLog), and writes
// through SupportLogOrNone's.
type SupportLogWriter interface {
	// Writes one event, if code declares every field; a field it does not declare is refused and counted.
	Event(code SupportLogCode, fields ...SupportLogField)
}

// writer, or one that writes nothing when there is none.
func SupportLogOrNone(writer SupportLogWriter) SupportLogWriter {
	if writer == nil {
		return supportLogNone{}
	}
	return writer
}

// Writes nothing.
type supportLogNone struct{}

// Drops the event.
func (self supportLogNone) Event(code SupportLogCode, fields ...SupportLogField) {
}

// A count, a duration or a size's bucket: the values at or under max, bounded, else everything past the one before.
type supportLogBucket struct {
	label   string
	max     uint64
	bounded bool
}

// The index of the first bucket that holds value, the last where none bounds it.
func supportLogBucketIndex(buckets []supportLogBucket, value uint64) uint64 {
	for i, bucket := range buckets {
		if !bucket.bounded || value <= bucket.max {
			return uint64(i)
		}
	}
	return uint64(len(buckets) - 1)
}

// One field the registry declares.
type supportLogFieldRow struct {
	name      string
	fieldType supportLogFieldType
	// an enum field's enum
	enum string
	// a token field's object: sidecar, repo, run, agent, enclave, entry or request
	object string
}

// One code the registry declares.
type supportLogCodeRow struct {
	component SupportLogComponent
	name      string
	severity  SupportLogSeverity
	fields    []SupportLogFieldNumber
}

// The registry as the generated file states it.
type supportLogRegistryTable struct {
	version         int
	countBuckets    []supportLogBucket
	durationBuckets []supportLogBucket
	sizeBuckets     []supportLogBucket
	components      map[SupportLogComponent]string
	enums           map[string][]string
	fields          map[SupportLogFieldNumber]*supportLogFieldRow
	codes           map[SupportLogCode]*supportLogCodeRow
}

// A code's component and name, as a bundle names it, and its severity. False for a code the registry does not hold.
func (self *supportLogRegistryTable) code(code SupportLogCode) (string, string, SupportLogSeverity, bool) {
	row, ok := self.codes[code]
	if !ok {
		return "", "", 0, false
	}
	return self.components[row.component], row.name, row.severity, true
}

// The registry's codes in number order, which String names: what ur support report, the sdk's analyzer and a test read.
func SupportLogCodes() []SupportLogCode {
	codes := make([]SupportLogCode, 0, len(supportLogRegistry.codes))
	for code := range supportLogRegistry.codes {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	return codes
}

// component.code, as the registry names it, or "" for a code it does not hold.
func (self SupportLogCode) String() string {
	component, name, _, ok := supportLogRegistry.code(self)
	if !ok {
		return ""
	}
	return component + "." + name
}

// Whether the code declares the field, by the field's name in the registry: what a test or an analyzer outside this
// package reads.
func (self SupportLogCode) Declares(fieldName string) bool {
	row, ok := supportLogRegistry.codes[self]
	if !ok {
		return false
	}
	for _, number := range row.fields {
		if supportLogRegistry.fields[number].name == fieldName {
			return true
		}
	}
	return false
}

// The field constructors' common forms, which only the generated file calls.

// An enum's value, which Event holds to its enum's values.
func supportLogEnumField(number SupportLogFieldNumber, value uint32) SupportLogField {
	return SupportLogField{number: number, fieldType: supportLogFieldTypeEnum, value: uint64(value)}
}

// A negative count is told as 0.
func supportLogCountField(number SupportLogFieldNumber, count int64) SupportLogField {
	return SupportLogField{number: number, fieldType: supportLogFieldTypeCount, value: uint64(max(count, 0))}
}

// A negative duration is told as 0.
func supportLogDurationField(number SupportLogFieldNumber, duration time.Duration) SupportLogField {
	return SupportLogField{number: number, fieldType: supportLogFieldTypeDuration, value: uint64(max(duration.Milliseconds(), 0))}
}

// A negative size is told as 0.
func supportLogSizeField(number SupportLogFieldNumber, byteCount int64) SupportLogField {
	return SupportLogField{number: number, fieldType: supportLogFieldTypeSize, value: uint64(max(byteCount, 0))}
}

// A version, which Event holds to its format before the ring keeps it.
func supportLogVersionField(number SupportLogFieldNumber, version string) SupportLogField {
	return SupportLogField{number: number, fieldType: supportLogFieldTypeVersion, version: version}
}

// True or false, as 1 or 0.
func supportLogBooleanField(number SupportLogFieldNumber, value bool) SupportLogField {
	field := SupportLogField{number: number, fieldType: supportLogFieldTypeBoolean}
	if value {
		field.value = 1
	}
	return field
}

// id is copied, so a caller's buffer stays its own.
func supportLogTokenField(number SupportLogFieldNumber, id []byte) SupportLogField {
	return SupportLogField{number: number, fieldType: supportLogFieldTypeToken, id: bytes.Clone(id)}
}

// What a SupportLog is opened with.
type SupportLogArgs struct {
	// The ring's directory, absolute: <state>/support-log for ur daemon, the sidecar's state directory's for an app.
	// It holds nothing but the ring's segments and its key, and is created 0700.
	Directory string
	Settings  *SupportSettings
	// Nil reads real time.
	Clock Clock
	// Where the ring's own failures are logged, by code and never by content. Nil logs nothing.
	Log Logger
}

// A process's support log ring. Open with OpenSupportLog; Close flushes and stops its writer.
type SupportLog struct {
	ctx       context.Context
	cancel    context.CancelFunc
	directory string
	settings  *SupportSettings
	clock     Clock
	log       Logger
	key       []byte
	registry  *supportLogRegistryTable
	// one wake for the writer, when the held events pass half their bound
	flushSignal chan struct{}
	runDone     chan struct{}
	closeOnce   sync.Once

	// Held across a flush and a bundle's read, never while stateLock is held.
	fileLock sync.Mutex
	// guarded by fileLock: the ring's segments, oldest first, and the newest one's open file
	segments    []*supportLogSegment
	current     *os.File
	unreadables map[string]bool

	stateLock sync.Mutex
	// guarded by stateLock
	pending          []byte
	droppedCount     int64
	refusedCount     int64
	writeFailedCount int64
	closed           bool
}

// One segment file of the ring.
type supportLogSegment struct {
	name      string
	start     int64
	sequence  int
	byteCount int64
	// begun by this process: a segment an earlier one left may end in a torn record, after which nothing appended
	// could be read, so this process appends only to its own
	appendable bool
}

// The ring's path for name.
func (self *SupportLog) path(name string) string {
	return filepath.Join(self.directory, name)
}

// Opens, or creates, the ring in args.Directory, prunes what has passed its bounds, and starts the writer. A key file
// that cannot be read is replaced, which leaves earlier tokens unrelated to later ones and nothing else.
func OpenSupportLog(args *SupportLogArgs) (*SupportLog, error) {
	if args == nil || args.Settings == nil {
		return nil, errors.New("a support log needs its settings")
	}
	if !filepath.IsAbs(args.Directory) {
		return nil, errors.New("a support log's directory must be absolute")
	}
	if err := os.MkdirAll(args.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("support log: %w", err)
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	ctx, cancel := context.WithCancel(context.Background())
	self := &SupportLog{
		ctx:         ctx,
		cancel:      cancel,
		directory:   args.Directory,
		settings:    args.Settings,
		clock:       clockOrReal(args.Clock),
		log:         log,
		registry:    supportLogRegistry,
		flushSignal: make(chan struct{}, 1),
		runDone:     make(chan struct{}),
		unreadables: map[string]bool{},
	}
	key, err := self.loadKey()
	if err != nil {
		cancel()
		return nil, err
	}
	self.key = key
	if err := self.scanSegments(); err != nil {
		cancel()
		return nil, err
	}
	segmentCount, byteCount := func() (int, int64) {
		self.fileLock.Lock()
		defer self.fileLock.Unlock()
		self.pruneWithFileLock(self.clock.Now().Unix())
		return len(self.segments), self.byteCountWithFileLock()
	}()
	go self.run()
	self.Event(SupportLogCodeSupportLogOpened, SupportLogFieldSegments(int64(segmentCount)), SupportLogFieldRingBytes(byteCount))
	return self, nil
}

// The ring's key, read or drawn and written 0600.
func (self *SupportLog) loadKey() ([]byte, error) {
	keyPath := self.path(supportLogKeyFileName)
	key, err := os.ReadFile(keyPath)
	if err == nil && len(key) == self.settings.RingKeyByteCount {
		return key, nil
	}
	key = make([]byte, self.settings.RingKeyByteCount)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("support log: %w", err)
	}
	temporaryPath := keyPath + ".tmp"
	if err := os.WriteFile(temporaryPath, key, 0o600); err != nil {
		return nil, fmt.Errorf("support log: %w", err)
	}
	if err := os.Rename(temporaryPath, keyPath); err != nil {
		return nil, fmt.Errorf("support log: %w", err)
	}
	return key, nil
}

// Reads the directory's segments into the ring's list, oldest first. A file of another name is left alone.
func (self *SupportLog) scanSegments() error {
	entries, err := os.ReadDir(self.directory)
	if err != nil {
		return fmt.Errorf("support log: %w", err)
	}
	segments := []*supportLogSegment{}
	for _, entry := range entries {
		match := supportLogSegmentNamePattern.FindStringSubmatch(entry.Name())
		if match == nil || !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		start, _ := strconv.ParseInt(match[1], 10, 64)
		sequence, _ := strconv.Atoi(match[2])
		segments = append(segments, &supportLogSegment{name: entry.Name(), start: start, sequence: sequence, byteCount: info.Size()})
	}
	slices.SortFunc(segments, func(a *supportLogSegment, b *supportLogSegment) int {
		if a.start != b.start {
			return int(a.start - b.start)
		}
		return a.sequence - b.sequence
	})
	self.fileLock.Lock()
	defer self.fileLock.Unlock()
	self.segments = segments
	return nil
}

// Writes one event, if code is the registry's and declares each field. A field the code does not declare, a second
// field of one number, a field past EventMaxFieldCount and an enum value its enum does not hold are refused and
// counted, and the rest is written. Never waits on the disk: past PendingMaxByteCount the event is dropped and
// counted. A no-op on a nil or closed log.
func (self *SupportLog) Event(code SupportLogCode, fields ...SupportLogField) {
	if self == nil {
		return
	}
	record, refusedCount := self.encodeEvent(self.clock.Now().Unix(), code, fields)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return
	}
	self.refusedCount += refusedCount
	if record == nil {
		return
	}
	if self.settings.PendingMaxByteCount < len(self.pending)+len(record) {
		self.droppedCount += 1
		return
	}
	self.pending = append(self.pending, record...)
	if self.settings.PendingMaxByteCount <= 2*len(self.pending) {
		select {
		case self.flushSignal <- struct{}{}:
		default:
		}
	}
}

// One event's framed record, and how many of its fields were refused. Nil for a code the registry does not hold,
// which counts as one refusal.
func (self *SupportLog) encodeEvent(t int64, code SupportLogCode, fields []SupportLogField) ([]byte, int64) {
	row, ok := self.registry.codes[code]
	if !ok {
		return nil, 1
	}
	refusedCount := int64(0)
	kept := make([]SupportLogField, 0, len(fields))
	for _, field := range fields {
		declared, ok := self.registry.fields[field.number]
		switch {
		case !ok || declared.fieldType != field.fieldType || !slices.Contains(row.fields, field.number):
			refusedCount += 1
		case slices.ContainsFunc(kept, func(keptField SupportLogField) bool { return keptField.number == field.number }):
			refusedCount += 1
		case self.settings.EventMaxFieldCount <= len(kept):
			refusedCount += 1
		case field.fieldType == supportLogFieldTypeEnum && (field.value == 0 || uint64(len(self.registry.enums[declared.enum])) < field.value):
			refusedCount += 1
		default:
			kept = append(kept, field)
		}
	}
	body := binary.AppendUvarint(nil, uint64(max(t, 0)))
	body = binary.AppendUvarint(body, uint64(code))
	body = binary.AppendUvarint(body, uint64(len(kept)))
	for _, field := range kept {
		body = binary.AppendUvarint(body, uint64(field.number))
		body = append(body, byte(field.fieldType))
		switch field.fieldType {
		case supportLogFieldTypeEnum, supportLogFieldTypeBoolean:
			body = binary.AppendUvarint(body, field.value)
		case supportLogFieldTypeCount:
			body = binary.AppendUvarint(body, supportLogBucketIndex(self.registry.countBuckets, field.value))
		case supportLogFieldTypeDuration:
			body = binary.AppendUvarint(body, supportLogBucketIndex(self.registry.durationBuckets, field.value))
		case supportLogFieldTypeSize:
			body = binary.AppendUvarint(body, supportLogBucketIndex(self.registry.sizeBuckets, field.value))
		case supportLogFieldTypeVersion:
			switch {
			case field.version == "":
				body = append(body, supportLogValueNone)
			case supportLogVersionValid(field.version, self.settings):
				body = append(body, supportLogValueKept)
				body = binary.AppendUvarint(body, uint64(len(field.version)))
				body = append(body, field.version...)
			default:
				body = append(body, supportLogValueInvalid)
			}
		case supportLogFieldTypeToken:
			if len(field.id) == 0 {
				body = append(body, supportLogValueNone)
			} else {
				body = append(body, supportLogValueKept)
				body = append(body, self.ringToken(self.registry.fields[field.number].object, field.id)...)
			}
		}
	}
	return supportLogFrame(body), refusedCount
}

// An object's id as the ring holds it: RingTokenByteCount bytes of HMAC-SHA256 under the ring's key, over the
// object's kind and the id, so two kinds' equal ids differ and no byte of the id is kept.
func (self *SupportLog) ringToken(object string, id []byte) []byte {
	mac := hmac.New(sha256.New, self.key)
	mac.Write([]byte(object))
	mac.Write([]byte{0})
	mac.Write(id)
	return mac.Sum(nil)[:self.settings.RingTokenByteCount]
}

// body framed for a segment: its uvarint length, itself and its CRC-32.
func supportLogFrame(body []byte) []byte {
	record := binary.AppendUvarint(nil, uint64(len(body)))
	record = append(record, body...)
	return binary.BigEndian.AppendUint32(record, crc32.ChecksumIEEE(body))
}

// The writer: flushes on each interval and each wake, and once more when the log closes.
func (self *SupportLog) run() {
	defer close(self.runDone)
	for {
		select {
		case <-self.ctx.Done():
			self.flush()
			return
		case <-self.flushSignal:
		case <-self.clock.After(self.settings.FlushInterval):
		}
		self.flush()
	}
}

// Writes the held events to the ring, with the counts of what was dropped, refused or not written since the last
// flush, and prunes.
func (self *SupportLog) flush() {
	self.fileLock.Lock()
	defer self.fileLock.Unlock()
	self.flushWithFileLock()
}

// flush's work, its caller holding fileLock: a bundle flushes so it reads every event written before it.
func (self *SupportLog) flushWithFileLock() {
	now := self.clock.Now().Unix()
	var pending []byte
	var droppedCount, refusedCount, writeFailedCount int64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		pending = self.pending
		self.pending = nil
		droppedCount, refusedCount, writeFailedCount = self.droppedCount, self.refusedCount, self.writeFailedCount
		self.droppedCount, self.refusedCount, self.writeFailedCount = 0, 0, 0
	}()
	// the counts ride with the flush they belong to, past the held events' bound
	if 0 < droppedCount {
		record, _ := self.encodeEvent(now, SupportLogCodeSupportLogEventsDropped, []SupportLogField{SupportLogFieldCount(droppedCount)})
		pending = append(pending, record...)
	}
	if 0 < refusedCount {
		record, _ := self.encodeEvent(now, SupportLogCodeSupportLogFieldRefused, []SupportLogField{SupportLogFieldCount(refusedCount)})
		pending = append(pending, record...)
	}
	if 0 < writeFailedCount {
		record, _ := self.encodeEvent(now, SupportLogCodeSupportLogWriteFailed, []SupportLogField{SupportLogFieldCount(writeFailedCount)})
		pending = append(pending, record...)
	}
	if len(pending) == 0 {
		return
	}
	if err := self.appendWithFileLock(now, pending); err != nil {
		// the events are lost; the next flush records that it happened, never what they said
		self.log.Warningf("[support_log] write failed: %v", supportLogErrorClass(err))
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.writeFailedCount += 1
		}()
	}
	self.pruneWithFileLock(now)
}

// The kind of a file error, for glog: never its path, which names the state directory.
func supportLogErrorClass(err error) string {
	switch {
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, os.ErrNotExist):
		return "missing"
	case errors.Is(err, io.ErrShortWrite):
		return "short write"
	}
	return "io"
}

// Appends records to the newest segment, beginning a new one first when the newest would pass its size or its span.
func (self *SupportLog) appendWithFileLock(now int64, records []byte) error {
	newest := (*supportLogSegment)(nil)
	if 0 < len(self.segments) {
		newest = self.segments[len(self.segments)-1]
	}
	rotate := newest == nil || !newest.appendable ||
		self.settings.SegmentMaxByteCount < newest.byteCount+int64(len(records)) ||
		int64(self.settings.SegmentMaxAge/time.Second) <= now-newest.start
	if rotate {
		if self.current != nil {
			self.current.Close()
			self.current = nil
		}
		sequence := 0
		if newest != nil && newest.start == now {
			sequence = newest.sequence + 1
		}
		newest = &supportLogSegment{name: fmt.Sprintf("%012d-%06d.seg", now, sequence), start: now, sequence: sequence, appendable: true}
		file, err := os.OpenFile(self.path(newest.name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		if _, err := file.Write([]byte(supportLogSegmentMagic)); err != nil {
			file.Close()
			os.Remove(self.path(newest.name))
			return err
		}
		newest.byteCount = int64(len(supportLogSegmentMagic))
		self.current = file
		self.segments = append(self.segments, newest)
	}
	if self.current == nil {
		file, err := os.OpenFile(self.path(newest.name), os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		self.current = file
	}
	count, err := self.current.Write(records)
	newest.byteCount += int64(count)
	return err
}

// The ring's bytes on disk.
func (self *SupportLog) byteCountWithFileLock() int64 {
	byteCount := int64(0)
	for _, segment := range self.segments {
		byteCount += segment.byteCount
	}
	return byteCount
}

// Removes the oldest segments while the ring passes RingMaxByteCount, keeping the newest, and every segment whose
// successor began past RingMaxAge, whose events are all older. Each removal is recorded as segment_pruned.
func (self *SupportLog) pruneWithFileLock(now int64) {
	ageCount, sizeCount := 0, 0
	for 1 < len(self.segments) && now-self.segments[1].start >= int64(self.settings.RingMaxAge/time.Second) {
		self.removeOldestWithFileLock()
		ageCount += 1
	}
	for 1 < len(self.segments) && self.settings.RingMaxByteCount < self.byteCountWithFileLock() {
		self.removeOldestWithFileLock()
		sizeCount += 1
	}
	records := []byte{}
	for _, pruned := range []struct {
		reason SupportLogPruneReason
		count  int
	}{
		{reason: SupportLogPruneReasonAge, count: ageCount},
		{reason: SupportLogPruneReasonSize, count: sizeCount},
	} {
		if 0 < pruned.count {
			record, _ := self.encodeEvent(now, SupportLogCodeSupportLogSegmentPruned, []SupportLogField{
				SupportLogFieldPruneReason(pruned.reason), SupportLogFieldSegments(int64(pruned.count)),
			})
			records = append(records, record...)
		}
	}
	if 0 < len(records) && 0 < len(self.segments) {
		if err := self.appendWithFileLock(now, records); err != nil {
			self.log.Warningf("[support_log] write failed: %v", supportLogErrorClass(err))
		}
	}
}

// Removes the oldest segment.
func (self *SupportLog) removeOldestWithFileLock() {
	oldest := self.segments[0]
	self.segments = self.segments[1:]
	if err := os.Remove(self.path(oldest.name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		self.log.Warningf("[support_log] prune failed: %v", supportLogErrorClass(err))
	}
}

// One event as the ring holds it.
type supportLogRecord struct {
	t      int64
	code   SupportLogCode
	fields []*supportLogRecordField
}

// One field as the ring holds it: an enum's value, a bucket's index or a boolean in value; a version's text; a
// token's ring HMAC.
type supportLogRecordField struct {
	number    SupportLogFieldNumber
	fieldType supportLogFieldType
	value     uint64
	state     byte
	version   string
	token     []byte
}

// Every event of the ring from from to to, in seconds and inclusive, oldest first, after a flush. A segment that
// cannot be read whole is read up to its fault, once recorded as segment_unreadable.
func (self *SupportLog) read(from int64, to int64) []*supportLogRecord {
	self.fileLock.Lock()
	defer self.fileLock.Unlock()
	self.flushWithFileLock()
	now := self.clock.Now().Unix()
	from = max(from, now-int64(self.settings.RingMaxAge/time.Second))
	records := []*supportLogRecord{}
	unreadable := []SupportLogUnreadableReason{}
	for i, segment := range self.segments {
		if i+1 < len(self.segments) && self.segments[i+1].start < from {
			// every event of it is older than its successor's start
			continue
		}
		segmentRecords, reason := self.readSegmentWithFileLock(segment)
		for _, record := range segmentRecords {
			if from <= record.t && record.t <= to {
				records = append(records, record)
			}
		}
		if reason != 0 && !self.unreadables[segment.name] {
			self.unreadables[segment.name] = true
			unreadable = append(unreadable, reason)
		}
	}
	if 0 < len(unreadable) {
		encoded := []byte{}
		for _, reason := range unreadable {
			record, _ := self.encodeEvent(now, SupportLogCodeSupportLogSegmentUnreadable, []SupportLogField{SupportLogFieldUnreadableReason(reason)})
			encoded = append(encoded, record...)
		}
		if err := self.appendWithFileLock(now, encoded); err != nil {
			self.log.Warningf("[support_log] write failed: %v", supportLogErrorClass(err))
		}
	}
	return records
}

// One segment's records, up to the first that cannot be read, and why it stopped there; 0 for none.
func (self *SupportLog) readSegmentWithFileLock(segment *supportLogSegment) ([]*supportLogRecord, SupportLogUnreadableReason) {
	file, err := os.Open(self.path(segment.name))
	if err != nil {
		return nil, SupportLogUnreadableReasonUnopened
	}
	defer file.Close()
	// a segment is never longer than its bound and one flush past it
	data, err := io.ReadAll(io.LimitReader(file, self.settings.SegmentMaxByteCount+int64(self.settings.PendingMaxByteCount)+int64(len(supportLogSegmentMagic))))
	if err != nil {
		return nil, SupportLogUnreadableReasonUnopened
	}
	if !bytes.HasPrefix(data, []byte(supportLogSegmentMagic)) {
		return nil, SupportLogUnreadableReasonMalformed
	}
	data = data[len(supportLogSegmentMagic):]
	records := []*supportLogRecord{}
	for 0 < len(data) {
		bodyByteCount, lengthByteCount := binary.Uvarint(data)
		if lengthByteCount <= 0 || uint64(self.settings.RecordMaxByteCount) < bodyByteCount {
			return records, SupportLogUnreadableReasonMalformed
		}
		end := lengthByteCount + int(bodyByteCount)
		if len(data) < end+4 {
			return records, SupportLogUnreadableReasonTruncated
		}
		body := data[lengthByteCount:end]
		if binary.BigEndian.Uint32(data[end:end+4]) != crc32.ChecksumIEEE(body) {
			return records, SupportLogUnreadableReasonChecksum
		}
		record, ok := self.decodeRecord(body)
		if !ok {
			return records, SupportLogUnreadableReasonMalformed
		}
		records = append(records, record)
		data = data[end+4:]
	}
	return records, 0
}

// A record's body, as encodeEvent wrote it. False for one that does not parse whole.
func (self *SupportLog) decodeRecord(body []byte) (*supportLogRecord, bool) {
	reader := bytes.NewReader(body)
	t, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, false
	}
	code, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, false
	}
	fieldCount, err := binary.ReadUvarint(reader)
	if err != nil || uint64(self.settings.EventMaxFieldCount) < fieldCount {
		return nil, false
	}
	record := &supportLogRecord{t: int64(t), code: SupportLogCode(code)}
	for range fieldCount {
		number, err := binary.ReadUvarint(reader)
		if err != nil {
			return nil, false
		}
		fieldType, err := reader.ReadByte()
		if err != nil {
			return nil, false
		}
		field := &supportLogRecordField{number: SupportLogFieldNumber(number), fieldType: supportLogFieldType(fieldType)}
		switch field.fieldType {
		case supportLogFieldTypeEnum, supportLogFieldTypeBoolean, supportLogFieldTypeCount, supportLogFieldTypeDuration, supportLogFieldTypeSize:
			if field.value, err = binary.ReadUvarint(reader); err != nil {
				return nil, false
			}
		case supportLogFieldTypeVersion:
			if field.state, err = reader.ReadByte(); err != nil {
				return nil, false
			}
			if field.state == supportLogValueKept {
				versionByteCount, err := binary.ReadUvarint(reader)
				if err != nil || uint64(self.settings.VersionMaxByteCount) < versionByteCount {
					return nil, false
				}
				version := make([]byte, versionByteCount)
				if _, err := io.ReadFull(reader, version); err != nil {
					return nil, false
				}
				field.version = string(version)
			}
		case supportLogFieldTypeToken:
			if field.state, err = reader.ReadByte(); err != nil {
				return nil, false
			}
			if field.state == supportLogValueKept {
				field.token = make([]byte, self.settings.RingTokenByteCount)
				if _, err := io.ReadFull(reader, field.token); err != nil {
					return nil, false
				}
			}
		default:
			return nil, false
		}
		record.fields = append(record.fields, field)
	}
	if reader.Len() != 0 {
		return nil, false
	}
	return record, true
}

// Flushes what Event holds, stops the writer and closes the ring. Later events are dropped. Safe to call twice.
func (self *SupportLog) Close() {
	if self == nil {
		return
	}
	self.closeOnce.Do(func() {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.closed = true
		}()
		self.cancel()
		<-self.runDone
		self.fileLock.Lock()
		defer self.fileLock.Unlock()
		if self.current != nil {
			self.current.Close()
			self.current = nil
		}
	})
}

// The ring's directory's name under its process's state directory.
const supportLogDirectoryName = "support-log"

// A ring's directory under a state directory: ur daemon's <state>/support-log, or an app's.
func SupportLogDirectory(stateDirectory string) string {
	return filepath.Join(stateDirectory, supportLogDirectoryName)
}

// Whether text is a version a version field keeps, by settings' bound.
func supportLogVersionValid(text string, settings *SupportSettings) bool {
	return len(text) <= settings.VersionMaxByteCount && supportLogVersionPattern.MatchString(text)
}
