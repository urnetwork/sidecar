//go:build !ios_extension

// RecordRetention (proposed; RECORD-M6-03; RECORD.md section 8; §16.8's retention; R-MCP-8, R-EVS-11, X20): a log's
// retention policies, their expiry, and the marks a reader shows by them.
//
//	policy     a RetentionPolicy{log_id, class, keep_days, searchable_days, archive}, Signed by a log admin's device
//	           under purpose record-entry, type SIGNED_RETENTION_POLICY, stored as a `retention` entry in the log it
//	           governs. A class's policy is the newest such entry by RECORD.md section 5.5's newest row: each admin's
//	           newest by seq, no forked entry counting, then the latest push time, then the higher writer id. An entry
//	           counts only from a writer that administered the log at the pin of the push that first held it, whose
//	           identity key signed the policy inside it, and whose policy names this log and one of classes 1 to 6,
//	           or 8, bulk, a run's session blobs (DESIGN-COMPUTE §24.10's retain row)
//	defaults   T and R: every class keep_days 400, searchable_days 90 (SidecarRecordSettings); D: announce 30 days,
//	           the rest 400 (§16.11); V: 0 and 0 until its owner sets them, bulk among them: history is kept until erased
//	           (Q-CTXH-7)
//	hold       an expiry pass leaves what its caller holds, and with none what SetHold gives: on a Sidecar every node of
//	           a live run's path (DESIGN-COMPUTE §24.10's retain row, session_storage.go's LiveHold); a hold that cannot
//	           be read stops the pass, failing toward keeping
//	floor      on T a keep_days of 1 to 364 or a searchable_days of 1 to 89 is refused at Set, and a reader ignores
//	           such an entry and alarms bad_entry once; 0, which keeps or leaves searchable with no limit, meets the
//	           floor (R-MCP-8)
//	life       keep_days counts from an entry's push time, the time_ms of the earliest push holding a copy, which evs
//	           bounds, never from time_millis, which a writer asserts; 0 keeps entries until a person erases them.
//	           Class 7 takes no policy and never expires, or a tree could not be rebuilt
//	archive    past keep_days an entry of an archiving policy keeps its key and reads archived: default views and
//	           search leave it out. Every reader marks these at each sync, from the policies it reads
//	expiry     once a UTC day on each log admin's daemon, ExpiryDelay's 0 to 10 min after it first syncs the work:
//	           the expired entries are erased by the record's eraser, reason 2, every copy of each, one erasure entry
//	           a batch; a pass that finds nothing is done. Another admin's daemon that ran first leaves this one
//	           nothing, since an erased entry is not expired again. A preservation hold pauses only §11.13's GC, so
//	           nothing here asks for one. The directory's pass is its erasure runner's (RECORD-M6-20), through Expire
//	base       weekly, an admin BASE through the seam SetBase binds (EvsRepo.Base) removes from each stream the files
//	           of entries whose erasure is complete, and never a class 7 entry (QD-783). Unbound, nothing is removed
//	set        `ur record retention set`: a log admin's device, in a vault a consented device of its owner; never
//	           under a harness process; a change that shortens a class's life erases at the next pass with no further
//	           act, so it takes a person's confirmation as an erasure does
//
// Off the ios_extension legs, as the eraser is. Safe for concurrent use: one pass at a time.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The retention marks' files, and their format.
const (
	recordRetentionMarkDirectory = "retention/"
	recordRetentionMarkVersion   = 1
)

var (
	// A policy that cannot be set as asked: a class no policy takes, a searchable_days past keep_days, or a life
	// below the team record's floor. Nothing was signed.
	ErrRecordRetentionInvalid = errors.New("record retention invalid")
	// A policy asked for under a harness process, or one that shortens a class's life without a person's
	// confirmation on /dev/tty or in an app's UI (§5.8). Nothing was signed.
	ErrRecordRetentionUnconfirmed = errors.New("record retention: not confirmed by a person")
	// No BASE is bound (SetBase): nothing was removed.
	ErrRecordRetentionBaseUnbound = errors.New("record retention: no BASE is bound")
)

// What retention runs by, beside SidecarRecordSettings' keep and searchable defaults and its intervals.
type RecordRetentionSettings struct {
	// On the team record a keep_days from 1 to one below this is refused: 365 (R-MCP-8's 12 months).
	TeamKeepFloorDays uint32
	// On the team record a searchable_days from 1 to one below this is refused: 90.
	TeamSearchableFloorDays uint32
	// The directory's default keep_days for announce entries: 30 (§16.11's retention row).
	DirectoryAnnounceKeepDays uint32
	// The directory's default keep_days for every other class: 400.
	DirectoryKeepDays uint32
	// The directory's default searchable_days: 90, and a class's keep_days where that is fewer (§16.11's Index and
	// search block).
	DirectorySearchableDays uint32
	// The entries one expiry erasure names, at most the eraser's EntryCount: 512.
	ExpiryEntryCount int
	// The length of a day keep_days and searchable_days count in: 24 h.
	Day time.Duration
}

// The defaults, a fresh value each call.
func DefaultRecordRetentionSettings() *RecordRetentionSettings {
	return &RecordRetentionSettings{
		TeamKeepFloorDays:         365,
		TeamSearchableFloorDays:   90,
		DirectoryAnnounceKeepDays: 30,
		DirectoryKeepDays:         400,
		DirectorySearchableDays:   90,
		ExpiryEntryCount:          512,
		Day:                       24 * time.Hour,
	}
}

// One class's policy in a log.
type RecordRetentionPolicy struct {
	LogId Id
	Class RecordClass
	// 0 keeps entries until a person erases them.
	KeepDays uint32
	// 0 is no limit.
	SearchableDays uint32
	Archive        bool
	// No retention entry governs the class: the log's default.
	Default bool
	// The entry that governs, and who wrote it; zero for a default.
	EntryId         Id
	WriterSidecarId Id
}

// A retention entry a reader does not take.
type RecordRetentionIgnored struct {
	EntryId         Id
	WriterSidecarId Id
	// Below the team record's floor, which a reader alarms on; false for an entry from no admin, with no pin this
	// state answers for, or naming another log or no class a policy takes.
	Floor bool
	Why   string
}

// Removes paths from one writer's stream of a log by an admin BASE, EvsRepo.Base where the record's streams are
// bound: those of paths that stand at the stream's head, a path already gone no failure. Answers how many it removed.
type RecordRetentionBaseFunction func(ctx context.Context, logId Id, streamSidecarId Id, paths []string) (int, error)

// One log's mark file: when its passes last ran.
type recordRetentionMark struct {
	Version int `json:"version"`
	LogId   Id  `json:"log_id"`
	// the UTC day, time.DateOnly, of the last expiry pass that finished
	PassDay string `json:"pass_day,omitempty"`
	// when the last BASE finished, in Unix milliseconds
	BaseMillis int64 `json:"base_millis,omitempty"`
}

// What one expiry pass did.
type RecordRetentionPass struct {
	LogId Id
	// The entries it erased, every copy's key gone.
	Expired []Id
	// One a batch.
	Erasures []*RecordEraseResult
	// The entries that read archived after it.
	Archived []Id
}

// One expiry pass asked for.
type RecordRetentionExpireArgs struct {
	LogId Id
	// Entries the pass leaves whatever their age, nil for none: the directory's runner keeps a live repo item's newest
	// copy this way (§16.11's retention row).
	Hold func(entry *RecordReadEntry) bool
}

// A record's retention.
type RecordRetention struct {
	record   *SidecarRecord
	settings *RecordRetentionSettings

	// one pass, BASE or tick at a time
	passLock sync.Mutex

	stateLock sync.Mutex
	base      RecordRetentionBaseFunction
	// what a pass with no hold of its own leaves (SetHold), nil for nothing
	hold func(ctx context.Context) (func(entry *RecordReadEntry) bool, error)
	// when each log's pass of the day goes, drawn at the first tick that found it due
	logDueTimes map[Id]time.Time
	// the floor-breaking entries already alarmed on
	alarmedEntryIds map[Id]bool
}

// The record's retention, made at the first call: from then every sync of a log marks its archived entries, and the
// loop runs the daily expiry of each log this sidecar administers.
func (self *SidecarRecord) Retention() *RecordRetention {
	self.stateLock.Lock()
	retention, _ := self.retention.(*RecordRetention)
	made := retention == nil
	if made {
		retention = &RecordRetention{
			record:          self,
			settings:        DefaultRecordRetentionSettings(),
			logDueTimes:     map[Id]time.Time{},
			alarmedEntryIds: map[Id]bool{},
		}
		self.retention = retention
		self.tendHooks = append(self.tendHooks, retention.Tick)
	}
	self.stateLock.Unlock()
	if made {
		self.reader.addSyncHook(func(ctx context.Context, logId Id) {
			retention.mark(logId)
		})
	}
	return retention
}

// Binds the weekly BASE. Nil unbinds it, and then nothing is removed.
func (self *RecordRetention) SetBase(base RecordRetentionBaseFunction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.base = base
}

// The retention entry's policy and its signer, or why it is none: the stored Signed, of type
// SIGNED_RETENTION_POLICY, by the entry's own writer.
func recordRetentionParse(entry *RecordReadEntry) (*protocol.RetentionPolicy, *bridge.Signed, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.Body, signed); err != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_RETENTION_POLICY) {
		return nil, nil, fmt.Errorf("%w: no Signed retention policy", ErrRecordBodyInvalid)
	}
	if !bytes.Equal(signed.GetSignerId(), entry.Header.Header.GetWriterSidecarId()) {
		return nil, nil, fmt.Errorf("%w: a policy its entry's writer did not sign", ErrRecordBodyInvalid)
	}
	policy := &protocol.RetentionPolicy{}
	if err := proto.Unmarshal(signed.GetBody(), policy); err != nil {
		return nil, nil, fmt.Errorf("%w: a policy that does not parse", ErrRecordBodyInvalid)
	}
	return policy, signed, nil
}

// Whether keepDays and searchableDays meet the team record's floor: 0 does, and so does anything at or past it.
func (self *RecordRetentionSettings) meetsTeamFloor(keepDays uint32, searchableDays uint32) bool {
	if 0 < keepDays && keepDays < self.TeamKeepFloorDays {
		return false
	}
	return searchableDays == 0 || self.TeamSearchableFloorDays <= searchableDays
}

// The classes a policy takes, in order: 1 to 6, and 8, bulk (DESIGN-COMPUTE §24.10). Class 7 takes none.
var recordRetentionClasses = []RecordClass{
	RecordClassCapture, RecordClassAction, RecordClassCoordination, RecordClassAnnounce, RecordClassRequest, RecordClassAccounting,
	RecordClassBulk,
}

// Sets what an expiry pass with no hold of its own leaves: a function read at each pass, answering the hold. Nil holds
// nothing.
func (self *RecordRetention) SetHold(hold func(ctx context.Context) (func(entry *RecordReadEntry) bool, error)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.hold = hold
}

// Whether a policy's numbers are ones a class takes: a class from 1 to 6 or 8, and a searchable_days at most keep_days
// where keep_days is not 0.
func recordRetentionWellFormed(class RecordClass, keepDays uint32, searchableDays uint32) bool {
	if !class.Known() || class == RecordClassUnspecified || class == RecordClassLog {
		return false
	}
	return keepDays == 0 || searchableDays <= keepDays
}

// A log's default for a class: section 8's defaults row.
func recordRetentionDefault(auth RecordAuthView, logId Id, class RecordClass, record *SidecarRecordSettings, settings *RecordRetentionSettings) *RecordRetentionPolicy {
	policy := &RecordRetentionPolicy{LogId: logId, Class: class, Default: true}
	teamRecordId, directoryId := recordTeamLogs(auth)
	switch {
	case directoryId != nil && *directoryId == logId:
		policy.KeepDays = settings.DirectoryKeepDays
		if class == RecordClassAnnounce {
			policy.KeepDays = settings.DirectoryAnnounceKeepDays
		}
		policy.SearchableDays = settings.DirectorySearchableDays
		if policy.KeepDays != 0 {
			policy.SearchableDays = min(policy.SearchableDays, policy.KeepDays)
		}
	case (teamRecordId != nil && *teamRecordId == logId) || recordIsLedger(auth, logId):
		policy.KeepDays = uint32(max(record.TeamRecordKeepDays, 0))
		policy.SearchableDays = uint32(max(record.TeamRecordSearchableDays, 0))
	}
	return policy
}

// The policies that govern logId among entries, a reader's of that log, by class, the default where no entry
// governs, and the retention entries not taken: see the file header's policy and floor rows.
func RecordRetentionGoverning(auth RecordAuthView, logId Id, entries []*RecordReadEntry, record *SidecarRecordSettings, settings *RecordRetentionSettings) (map[RecordClass]*RecordRetentionPolicy, []*RecordRetentionIgnored) {
	if record == nil {
		record = defaultSidecarRecordSettings()
	}
	if settings == nil {
		settings = DefaultRecordRetentionSettings()
	}
	teamRecordId, _ := recordTeamLogs(auth)
	onTeamRecord := teamRecordId != nil && *teamRecordId == logId
	type standing struct {
		entry  *RecordReadEntry
		policy *protocol.RetentionPolicy
	}
	ignored := []*RecordRetentionIgnored{}
	// each admin's newest by seq, a class
	classWriterNewest := map[RecordClass]map[Id]*standing{}
	for _, entry := range entries {
		if entry == nil || entry.Kind() != RecordKindRetention || entry.State == RecordEntryForked || entry.Body == nil || entry.BodyInvalid {
			continue
		}
		writerId := recordIdOf(entry.Header.Header.GetWriterSidecarId())
		ignore := func(floor bool, why string) {
			ignored = append(ignored, &RecordRetentionIgnored{EntryId: entry.EntryId, WriterSidecarId: writerId, Floor: floor, Why: why})
		}
		if len(entry.Copies) == 0 || entry.Copies[0].AuthPin == nil {
			ignore(false, "no push pin")
			continue
		}
		judged, err := auth.At(entry.Copies[0].AuthPin)
		if err != nil {
			// not judged at a pin this state cannot answer for, and so not taken: the closed reading
			ignore(false, "a pin this state does not answer for")
			continue
		}
		if !judged.Admins(logId, writerId) || (!recordIsTeamLog(judged, logId) && !judged.Consented(logId, writerId)) {
			ignore(false, "from no admin of the log")
			continue
		}
		policy, signed, err := recordRetentionParse(entry)
		if err != nil {
			ignore(false, "no policy its writer signed")
			continue
		}
		key := judged.IdentityKey(writerId)
		if len(key) == 0 || bridge.VerifySigned(signed, RecordEntryPurpose, bridge.SignedType_SIGNED_RETENTION_POLICY, bridge.SignedKeyAlgEd25519, key) != nil {
			ignore(false, "a policy signature that does not verify")
			continue
		}
		class := RecordClass(policy.GetClass())
		if !bytes.Equal(policy.GetLogId(), logId[:]) || !recordRetentionWellFormed(class, policy.GetKeepDays(), policy.GetSearchableDays()) {
			ignore(false, "names another log, no class a policy takes, or a searchable_days past its keep_days")
			continue
		}
		if onTeamRecord && !settings.meetsTeamFloor(policy.GetKeepDays(), policy.GetSearchableDays()) {
			ignore(true, "below the team record's floor")
			continue
		}
		writerNewest := classWriterNewest[class]
		if writerNewest == nil {
			writerNewest = map[Id]*standing{}
			classWriterNewest[class] = writerNewest
		}
		if held, ok := writerNewest[writerId]; !ok || held.entry.Header.Header.GetSeq() < entry.Header.Header.GetSeq() {
			writerNewest[writerId] = &standing{entry: entry, policy: policy}
		}
	}
	policies := map[RecordClass]*RecordRetentionPolicy{}
	for _, class := range recordRetentionClasses {
		var newest *standing
		for _, held := range classWriterNewest[class] {
			switch {
			case newest == nil, newest.entry.PushTimeMillis < held.entry.PushTimeMillis:
				newest = held
			case newest.entry.PushTimeMillis == held.entry.PushTimeMillis &&
				bytes.Compare(newest.entry.Header.Header.GetWriterSidecarId(), held.entry.Header.Header.GetWriterSidecarId()) < 0:
				newest = held
			}
		}
		if newest == nil {
			policies[class] = recordRetentionDefault(auth, logId, class, record, settings)
			continue
		}
		policies[class] = &RecordRetentionPolicy{
			LogId:           logId,
			Class:           class,
			KeepDays:        newest.policy.GetKeepDays(),
			SearchableDays:  newest.policy.GetSearchableDays(),
			Archive:         newest.policy.GetArchive(),
			EntryId:         newest.entry.EntryId,
			WriterSidecarId: recordIdOf(newest.entry.Header.Header.GetWriterSidecarId()),
		}
	}
	return policies, ignored
}

// The log's policies as this device last read the log, by class, raising bad_entry once for each entry below the
// team record's floor.
func (self *RecordRetention) governing(logId Id) map[RecordClass]*RecordRetentionPolicy {
	writer := self.record.writer
	entries, _ := self.record.reader.EntriesOfKinds(logId, 0, RecordKindRetention)
	policies, ignored := RecordRetentionGoverning(writer.auth(), logId, entries, writer.settings, self.settings)
	for _, entry := range ignored {
		if !entry.Floor {
			continue
		}
		raise := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.alarmedEntryIds[entry.EntryId] {
				return false
			}
			self.alarmedEntryIds[entry.EntryId] = true
			return true
		}()
		if raise {
			writerId := entry.WriterSidecarId
			self.record.reader.raise(SidecarRecordAlarmBadEntry, logId, &writerId)
		}
	}
	return policies
}

// The policy for a class of a log, from the log as this device last read it; the log's default where no entry
// governs. Nil for class 7 and a class section 8 does not hold, which take none.
func (self *RecordRetention) Policy(logId Id, class RecordClass) *RecordRetentionPolicy {
	return self.governing(logId)[class]
}

// Every class's policy for a log, classes 1 to 6 and 8 in order: what `ur record retention show` prints.
func (self *RecordRetention) Policies(logId Id) []*RecordRetentionPolicy {
	governing := self.governing(logId)
	policies := []*RecordRetentionPolicy{}
	for _, class := range recordRetentionClasses {
		policies = append(policies, governing[class])
	}
	return policies
}

// A class's searchable_days in a log, 0 for no limit: what §16.10's query-time mask reads, older documents staying
// readable by id (FS-76).
func (self *RecordRetention) SearchableDays(logId Id, class RecordClass) uint32 {
	if policy := self.Policy(logId, class); policy != nil {
		return policy.SearchableDays
	}
	return 0
}

// Whether an entry pushed at pushTimeMillis is past days at now; never for 0 days.
func (self *RecordRetention) past(pushTimeMillis int64, days uint32, now time.Time) bool {
	if days == 0 {
		return false
	}
	return !now.Before(time.UnixMilli(pushTimeMillis).Add(time.Duration(days) * self.settings.Day))
}

// Whether §16.10 masks an entry's documents from search now: past its class's searchable_days by its push time.
func (self *RecordRetention) SearchMasked(entry *RecordReadEntry) bool {
	if entry == nil || entry.Kind().Class() == RecordClassLog {
		return false
	}
	return self.past(entry.PushTimeMillis, self.SearchableDays(entry.LogId, entry.Kind().Class()), self.record.writer.clock.Now())
}

// The log's entries past their class's keep_days now, as last read: those an archiving policy keeps, and those that
// expire. Class 7 is in neither, and an entry whose key is gone already is in neither.
func (self *RecordRetention) due(logId Id, hold func(entry *RecordReadEntry) bool) (archived []Id, expired []Id) {
	policies := self.governing(logId)
	now := self.record.writer.clock.Now()
	for _, entry := range self.record.reader.Entries(logId) {
		class := entry.Kind().Class()
		policy := policies[class]
		if class == RecordClassLog || policy == nil || entry.State.KeyGone() || entry.State == RecordEntryLost {
			continue
		}
		if !self.past(entry.PushTimeMillis, policy.KeepDays, now) {
			continue
		}
		if policy.Archive {
			archived = append(archived, entry.EntryId)
			continue
		}
		if hold != nil && hold(entry) {
			continue
		}
		expired = append(expired, entry.EntryId)
	}
	return archived, expired
}

// Marks the log's archived entries in this device's reader, from the policies it reads: every reader's, at each sync.
func (self *RecordRetention) mark(logId Id) []Id {
	archived, _ := self.due(logId, nil)
	self.record.reader.setArchived(logId, archived)
	return archived
}

// One expiry pass of a log this sidecar administers: see the file header's expiry row. ErrRecordEraseNotAdmin for
// any other sidecar, with nothing erased. A pass that stops at a failed erasure leaves the rest for the next.
func (self *RecordRetention) Expire(ctx context.Context, args *RecordRetentionExpireArgs) (*RecordRetentionPass, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no log", ErrRecordRetentionInvalid)
	}
	self.passLock.Lock()
	defer self.passLock.Unlock()
	return self.expire(ctx, args)
}

// Expire's pass. The caller holds passLock.
func (self *RecordRetention) expire(ctx context.Context, args *RecordRetentionExpireArgs) (*RecordRetentionPass, error) {
	writer := self.record.writer
	if err := recordEraseAdmin(writer.auth(), writer.sidecarId, args.LogId); err != nil {
		return nil, err
	}
	if err := self.record.reader.Sync(ctx, args.LogId); err != nil {
		return nil, err
	}
	pass := &RecordRetentionPass{LogId: args.LogId}
	hold := args.Hold
	if hold == nil {
		installed := func() func(ctx context.Context) (func(entry *RecordReadEntry) bool, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.hold
		}()
		if installed != nil {
			var err error
			if hold, err = installed(ctx); err != nil {
				return nil, fmt.Errorf("record retention: what the pass leaves did not read, so nothing expires: %w", err)
			}
		}
	}
	_, expired := self.due(args.LogId, hold)
	eraser := self.record.Eraser()
	batchCount := min(self.settings.ExpiryEntryCount, eraser.settings.EntryCount)
	if batchCount <= 0 {
		return nil, fmt.Errorf("%w: an expiry batch of no entries", ErrRecordRetentionInvalid)
	}
	for start := 0; start < len(expired); start += batchCount {
		batch := expired[start:min(start+batchCount, len(expired))]
		testHookBarrier("record.retention.erase.before", recordChainIdText(args.LogId))
		result, err := eraser.Erase(ctx, &RecordEraseArgs{LogId: args.LogId, EntryIds: batch, Reason: RecordErasureReasonRetention})
		if err != nil {
			return pass, fmt.Errorf("record retention: expiry of %s: %w", args.LogId, err)
		}
		pass.Erasures = append(pass.Erasures, result)
		pass.Expired = append(pass.Expired, result.Erased...)
	}
	pass.Archived = self.mark(args.LogId)
	return pass, nil
}

// The file of logId's mark.
func recordRetentionMarkName(logId Id) string {
	return recordRetentionMarkDirectory + hex.EncodeToString(logId[:])
}

// The log's mark, empty where none was written. A mark that does not decode is a failure, never read as no pass.
func (self *RecordRetention) readMark(logId Id) (*recordRetentionMark, error) {
	reader, err := self.record.writer.store.Open(recordRetentionMarkName(logId))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return &recordRetentionMark{Version: recordRetentionMarkVersion, LogId: logId}, nil
	}
	if err != nil {
		return nil, err
	}
	content, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		return nil, err
	}
	mark := &recordRetentionMark{}
	if err := json.Unmarshal(content, mark); err != nil || mark.Version != recordRetentionMarkVersion || mark.LogId != logId {
		return nil, fmt.Errorf("%w: retention mark of %s", ErrRecordChainCorrupt, logId)
	}
	return mark, nil
}

// Writes mark durably.
func (self *RecordRetention) writeMark(mark *recordRetentionMark) error {
	mark.Version = recordRetentionMarkVersion
	content, err := json.Marshal(mark)
	if err != nil {
		return err
	}
	writer, err := self.record.writer.store.Create(recordRetentionMarkName(mark.LogId))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// The logs whose expiry is this daemon's: its author's vault, the team record and each ledger, where it erases. The
// directory's is its runner's.
func (self *RecordRetention) administered() []Id {
	writer := self.record.writer
	auth := writer.auth()
	logIds := []Id{}
	if route, err := recordVaultRoute(auth, writer.sidecarId); err == nil {
		logIds = append(logIds, route.logId)
	}
	if teamRecordId, _ := recordTeamLogs(auth); teamRecordId != nil {
		logIds = append(logIds, *teamRecordId)
	}
	if logs := auth.Logs(); logs != nil {
		logIds = append(logIds, logs.LedgerIds...)
	}
	administered := []Id{}
	for _, logId := range logIds {
		if recordEraseAdmin(auth, writer.sidecarId, logId) == nil && !slices.Contains(administered, logId) {
			administered = append(administered, logId)
		}
	}
	return administered
}

// A delay drawn evenly from 0 up to ExpiryDelay, so several admins' daemons do not all go at once.
func (self *RecordRetention) delay() time.Duration {
	most := self.record.writer.settings.ExpiryDelay
	if most <= 0 {
		return 0
	}
	draw := make([]byte, 8)
	random := self.record.writer.random
	if random == nil {
		random = cryptorand.Reader
	}
	if _, err := io.ReadFull(random, draw); err != nil {
		// no draw: the whole delay, never none
		return most
	}
	return time.Duration(binary.BigEndian.Uint64(draw) % uint64(most))
}

// The loop's pass: for each log this daemon administers, the day's expiry once its delay has run, and the weekly
// BASE. A log's failure is logged and tried again at the next pass; it stops no other log.
func (self *RecordRetention) Tick(ctx context.Context) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	writer := self.record.writer
	for _, logId := range self.administered() {
		if ctx.Err() != nil {
			return
		}
		if err := self.tickLog(ctx, logId); err != nil && writer.log.V(1).Enabled() {
			writer.log.Infof("[record]retention of %s: %s", logId, err)
		}
	}
}

// One log's part of a tick: its expiry pass of the day once its delay has run, and its BASE once a week. The caller
// holds passLock.
func (self *RecordRetention) tickLog(ctx context.Context, logId Id) error {
	writer := self.record.writer
	mark, err := self.readMark(logId)
	if err != nil {
		return err
	}
	now := writer.clock.Now().UTC()
	day := now.Format(time.DateOnly)
	if mark.PassDay != day {
		due, ok := func() (time.Time, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			due, ok := self.logDueTimes[logId]
			return due, ok
		}()
		if !ok {
			// the first sync of the day's work: the delay runs from here
			if err := self.record.reader.Sync(ctx, logId); err != nil {
				return err
			}
			due = now.Add(self.delay())
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.logDueTimes[logId] = due
			}()
		}
		if now.Before(due) {
			return nil
		}
		if _, err := self.expire(ctx, &RecordRetentionExpireArgs{LogId: logId}); err != nil {
			return err
		}
		mark.PassDay = day
		if err := self.writeMark(mark); err != nil {
			return err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.logDueTimes, logId)
		}()
	}
	if interval := writer.settings.BaseInterval; 0 < interval && interval <= now.Sub(time.UnixMilli(mark.BaseMillis)) {
		if _, err := self.rebase(ctx, logId); err != nil {
			if errors.Is(err, ErrRecordRetentionBaseUnbound) {
				return nil
			}
			return err
		}
		mark.BaseMillis = now.UnixMilli()
		return self.writeMark(mark)
	}
	return nil
}

// An admin BASE of each stream of a log this sidecar administers, removing the files of entries whose erasure is
// complete: every copy's key gone by an ERASE this device read, and no erasure of this device still journaled for
// the entry. A class 7 entry is never among them. Answers how many files went. ErrRecordRetentionBaseUnbound with
// nothing removed while no BASE is bound.
func (self *RecordRetention) Base(ctx context.Context, logId Id) (int, error) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	return self.rebase(ctx, logId)
}

// Base's pass. The caller holds passLock.
func (self *RecordRetention) rebase(ctx context.Context, logId Id) (int, error) {
	base := func() RecordRetentionBaseFunction {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.base
	}()
	if base == nil {
		return 0, ErrRecordRetentionBaseUnbound
	}
	writer := self.record.writer
	if err := recordEraseAdmin(writer.auth(), writer.sidecarId, logId); err != nil {
		return 0, err
	}
	if err := self.record.reader.Sync(ctx, logId); err != nil {
		return 0, err
	}
	// an erasure still journaled here is not complete
	journals, err := self.record.Eraser().readJournals()
	if err != nil {
		return 0, err
	}
	pending := map[Id]bool{}
	for _, journal := range journals {
		if journal.LogId != logId {
			continue
		}
		for _, entryId := range journal.EntryIds {
			pending[entryId] = true
		}
	}
	streamPaths := map[Id][]string{}
	for _, entry := range self.record.reader.Entries(logId) {
		if !entry.State.KeyGone() || entry.Kind().Class() == RecordClassLog || pending[entry.EntryId] {
			continue
		}
		for _, entryCopy := range entry.Copies {
			if entryCopy.Path != "" && !slices.Contains(streamPaths[entryCopy.StreamSidecarId], entryCopy.Path) {
				streamPaths[entryCopy.StreamSidecarId] = append(streamPaths[entryCopy.StreamSidecarId], entryCopy.Path)
			}
		}
	}
	streamIds := []Id{}
	for streamId := range streamPaths {
		streamIds = append(streamIds, streamId)
	}
	slices.SortFunc(streamIds, Id.Cmp)
	removed := 0
	for _, streamId := range streamIds {
		paths := streamPaths[streamId]
		slices.Sort(paths)
		testHookBarrier("record.retention.base.before", recordChainIdText(logId))
		count, err := base(ctx, logId, streamId, paths)
		if err != nil {
			return removed, fmt.Errorf("record retention: BASE of %s's stream %s: %w", logId, streamId, err)
		}
		removed += count
	}
	return removed, nil
}

// What `ur record retention set` asks.
type RecordRetentionSetArgs struct {
	LogId          Id
	Class          RecordClass
	KeepDays       uint32
	SearchableDays uint32
	Archive        bool
	// A person confirmed the command on /dev/tty or in an app's UI (§5.8): needed where the policy shortens the
	// class's life.
	Confirmed bool
	// The caller has a harness process among its ancestors: refused.
	HarnessAncestor bool
}

// Whether a policy of keepDays, archiving or not, ends entries sooner than current does: fewer days, 0 being none,
// or expiry where current archives.
func recordRetentionShortens(current *RecordRetentionPolicy, keepDays uint32, archive bool) bool {
	if keepDays == 0 {
		return false
	}
	if current == nil || current.KeepDays == 0 || keepDays < current.KeepDays {
		return true
	}
	return current.Archive && !archive
}

// Whether args would shorten its class's life in the log as this device last read it, so that its next expiry pass
// erases entries with no further act: what the command lists before it asks a person.
func (self *RecordRetention) Shortens(args *RecordRetentionSetArgs) bool {
	if args == nil {
		return false
	}
	return recordRetentionShortens(self.Policy(args.LogId, args.Class), args.KeepDays, args.Archive)
}

// Signs a RetentionPolicy and writes its retention entry to the log it governs: see the file header's set row. It
// takes effect at each admin's next expiry pass, on existing entries too.
func (self *RecordRetention) Set(ctx context.Context, args *RecordRetentionSetArgs) (*RecordEntryRef, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no policy", ErrRecordRetentionInvalid)
	}
	if args.HarnessAncestor {
		return nil, fmt.Errorf("%w: a retention policy is set by a person, not under a harness", ErrRecordRetentionUnconfirmed)
	}
	if !recordRetentionWellFormed(args.Class, args.KeepDays, args.SearchableDays) {
		return nil, fmt.Errorf("%w: class %s, keep %d days, searchable %d days", ErrRecordRetentionInvalid, args.Class, args.KeepDays, args.SearchableDays)
	}
	writer := self.record.writer
	auth := writer.auth()
	if err := recordEraseAdmin(auth, writer.sidecarId, args.LogId); err != nil {
		return nil, err
	}
	if teamRecordId, _ := recordTeamLogs(auth); teamRecordId != nil && *teamRecordId == args.LogId && !self.settings.meetsTeamFloor(args.KeepDays, args.SearchableDays) {
		return nil, fmt.Errorf("%w: the team record keeps entries at least %d days and searchable at least %d, or with no limit",
			ErrRecordRetentionInvalid, self.settings.TeamKeepFloorDays, self.settings.TeamSearchableFloorDays)
	}
	// what governs now decides whether this shortens a life, so the log is read first
	if err := self.record.reader.Sync(ctx, args.LogId); err != nil {
		return nil, err
	}
	if self.Shortens(args) && !args.Confirmed {
		return nil, fmt.Errorf("%w: it shortens the life of class %s", ErrRecordRetentionUnconfirmed, args.Class)
	}
	policyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.RetentionPolicy{
		LogId:          args.LogId.Bytes(),
		Class:          uint32(args.Class),
		KeepDays:       args.KeepDays,
		SearchableDays: args.SearchableDays,
		Archive:        args.Archive,
	})
	if err != nil {
		return nil, err
	}
	signed, err := writer.sign(RecordEntryPurpose, bridge.SignedType_SIGNED_RETENTION_POLICY, policyBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("record retention: sign: %w", err)
	}
	logId := args.LogId
	refs, err := writer.Append(&RecordDraft{
		Kind:      RecordKindRetention,
		Source:    RecordSourceApprover,
		NoSession: true,
		Body:      signed,
		LogId:     &logId,
	})
	if err != nil {
		return nil, err
	}
	if len(refs) != 1 {
		return nil, fmt.Errorf("record: a retention policy sealed %d entries", len(refs))
	}
	return refs[0], nil
}
