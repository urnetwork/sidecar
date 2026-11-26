//go:build !ios_extension

// Owner decision 573's remedy, from M11 (CTXH-M11-07; DESIGN-COMPUTE §24.7, D-CTXH-10, I-8; Appendix D's §16.8 row,
// the compute plan's CA-86; compute-plan-approval-notice-bytes, QD-1234 option 1): each approval request filed in its
// author's vault has a small notice at a/<approval_id> on the vault's main file-mode ref, the ref that holds
// harness/config.json (the plan's reading of which ref), so an approver's phone leases a/ and the inbox prefixes rather
// than the whole vault, whose session entries push with every model call and would spend the two or three background
// wakes an hour a phone gets, on which approvals ride (record_approval_app.go's phone row).
//
//	bytes     an ApprovalNotice, shaped as §16.11's DirectoryNotice: the approval id, the requester, the request entry's
//	          seq in its writer's chain, its not_after and its CanonicalAction kind, and its state, 1 pending or 2
//	          decided; deterministic protobuf of at most NoticeByteCount, versionless where the network admits format 2
//	          and sealed as any vault file is. It names no approver and no action text, and nothing about a request is
//	          ever trusted from it
//	write     the requester writes the pending notice once its request entry has landed in evs, never before, so a
//	          phone a notice wakes finds the entry when it reads the log; a request filed by deposit or to the team
//	          record writes none here
//	answer    the deciding device rewrites the notice to decided once its decision has landed; the device that files a
//	          cancel removes it once the cancel has landed; neither writes a notice where none stands
//	repair    the requester's daemon, at the record loop's first pass and every RepairInterval after, re-creates the
//	          pending notice of each of its own requests still pending and before not_after, from its request entry,
//	          where the path holds none or a version no rule takes, which also repairs a crash between the entry and
//	          the notice; it removes the notice of a request cancelled, and any device's repair removes a notice whose
//	          request is past not_after + Grace, so a/ stays small after a requester is gone
//	rules     a version is taken when it decodes within NoticeByteCount and names the request entry's approval id,
//	          requester, seq, not_after and kind: pending only as its requester wrote it, decided only while the log
//	          holds a decision of the request
//	phone     a notice is a hint alone: the phone's resync reads every request from its log (record_approval_log.go's
//	          Pending), and CheckNotices ignores and alarms (path_rule, once a version) a notice no request entry
//	          backs
//
// The notices part is made by SidecarRecord.ApprovalNotices, which the record component calls, and runs on the record's
// loop; until a vault is bound (Bind, from bindMemberReplica) it writes nothing and its writes stay owed. Barriers
// approval.notice.before and .after sit around each write and removal, keyed by the approval's id. Nothing here creates,
// derives or unwraps a key. Safe for concurrent use. On every leg but the ios_extension legs.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The directory on a vault's main ref that holds the notices, an identifier.
const approvalNoticeDirectory = "a"

// ApprovalNotice.state (QD-1234's reading in CTXH-M11-01's record.proto): a cancel removes the notice, so it has none.
type ApprovalNoticeState uint32

const (
	ApprovalNoticeStatePending ApprovalNoticeState = 1
	ApprovalNoticeStateDecided ApprovalNoticeState = 2
)

var (
	// A notice that does not decode, is past NoticeByteCount, or lacks a field every notice carries.
	ErrApprovalNoticeInvalid = errors.New("approval notice invalid")
	// Another write or removal landed on the notice's path since the version its writer read: nothing was written.
	ErrApprovalNoticeConflict = errors.New("approval notice moved under its write")
	// No vault is bound for the notices, so nothing is read or written.
	ErrApprovalNoticeUnbound = errors.New("approval notices have no vault bound")
)

// The notices' own settings (QD-702): the format's byte cap, which every reader holds a notice to, and the part's
// timings. The part holds one from DefaultApprovalNoticeSettings, which SetSettings replaces.
type ApprovalNoticeSettings struct {
	// The most bytes a notice holds, the format's limit both writer and reader keep: 256 B, as §16.11's notices. An
	// ApprovalNotice is about 70 B.
	NoticeByteCount int
	// How long past its request's not_after a notice stands before a repair removes it: 24 h, as §16.11's NoticeGrace,
	// so a decision that lands near not_after is still rewritten onto a notice a phone can read.
	Grace time.Duration
	// How often the record's loop runs the repair: 1 h. Non-positive runs it at every pass.
	RepairInterval time.Duration
	// How long an owed write waits after a failure before it is tried again: 1 min.
	RetryInterval time.Duration
	// The most notices one read of a/ takes: 512. A vault past it is read up to it, the rest at a later pass, once
	// repairs have removed what is past its grace.
	ReadCount int
}

// The notices' defaults, the only place one is set.
func DefaultApprovalNoticeSettings() *ApprovalNoticeSettings {
	return &ApprovalNoticeSettings{
		NoticeByteCount: 256,
		Grace:           24 * time.Hour,
		RepairInterval:  time.Hour,
		RetryInterval:   time.Minute,
		ReadCount:       512,
	}
}

// a/<approval_id>: the notice of approvalId, its id in 32 lowercase hex.
func approvalNoticePath(approvalId Id) string {
	return approvalNoticeDirectory + "/" + hex.EncodeToString(approvalId[:])
}

// The prefix a phone leases: a/, with its slash.
func approvalNoticePrefix() string {
	return approvalNoticeDirectory + "/"
}

// The approval id a notice path names, false for any path approvalNoticePath would not make.
func approvalNoticeIdOf(path string) (Id, bool) {
	name, ok := strings.CutPrefix(path, approvalNoticePrefix())
	if !ok || len(name) != 2*len(Id{}) || strings.ToLower(name) != name {
		return Id{}, false
	}
	decoded, err := hex.DecodeString(name)
	if err != nil {
		return Id{}, false
	}
	return Id(decoded), true
}

// One notice version as the vault holds it.
type ApprovalNoticeFile struct {
	Path string
	// The path's version, which a rewrite or removal is held to.
	Version uint64
	// The version's push signer, which the rules judge.
	SignerSidecarId Id
	// As stored, at most NoticeByteCount + 1 bytes read.
	Content []byte
}

// What the notices read and write on a vault's main ref: an EvsRepo through NewApprovalNoticeEvsVault, or a test's.
// Safe for concurrent use.
type ApprovalNoticeVault interface {
	// The newest version of path, nil with no error while none stands or the newest statement removed it. Content
	// carries at most maxByteCount + 1 bytes.
	ReadNotice(ctx context.Context, path string, maxByteCount int) (*ApprovalNoticeFile, error)
	// The newest version of each notice under a/, in path order, removed ones left out, at most maxCount.
	ListNotices(ctx context.Context, maxCount int, maxByteCount int) ([]*ApprovalNoticeFile, error)
	// Writes content at path, versionless where the network admits it, held to ifVersion, 0 for a path read as
	// absent: the path's new version, or ErrApprovalNoticeConflict where another write landed between.
	PutNotice(ctx context.Context, path string, ifVersion uint64, content []byte) (uint64, error)
	// Removes path, held to ifVersion: ErrApprovalNoticeConflict where another write landed between.
	RemoveNotice(ctx context.Context, path string, ifVersion uint64) error
}

// The notice of an approval request, its fields from the request and its entry's place.
func approvalNoticeOf(request *protocol.ApprovalRequest, requesterId Id, entrySeq uint64, kind uint32, state ApprovalNoticeState) *protocol.ApprovalNotice {
	return &protocol.ApprovalNotice{
		ApprovalId:         bytes.Clone(request.GetApprovalId()),
		RequesterSidecarId: requesterId.Bytes(),
		EntrySeq:           entrySeq,
		NotAfterMillis:     request.GetNotAfterMillis(),
		State:              uint32(state),
		Kind:               kind,
	}
}

// A notice's stored bytes: deterministic, within the cap.
func approvalNoticeEncode(notice *protocol.ApprovalNotice, settings *ApprovalNoticeSettings) ([]byte, error) {
	if err := approvalNoticeCheck(notice); err != nil {
		return nil, err
	}
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(notice)
	if err != nil {
		return nil, err
	}
	if settings.NoticeByteCount < len(content) {
		return nil, fmt.Errorf("%w: %d bytes", ErrApprovalNoticeInvalid, len(content))
	}
	return content, nil
}

// A notice as stored, parsed and held to the format: within NoticeByteCount, each id 16 bytes, a seq from 1, a
// not_after, a kind and a state it names.
func ApprovalNoticeDecode(content []byte, settings *ApprovalNoticeSettings) (*protocol.ApprovalNotice, error) {
	if settings == nil {
		settings = DefaultApprovalNoticeSettings()
	}
	if settings.NoticeByteCount < len(content) {
		return nil, fmt.Errorf("%w: %d bytes", ErrApprovalNoticeInvalid, len(content))
	}
	notice := &protocol.ApprovalNotice{}
	if err := proto.Unmarshal(content, notice); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrApprovalNoticeInvalid, err)
	}
	if err := approvalNoticeCheck(notice); err != nil {
		return nil, err
	}
	return notice, nil
}

// The fields every notice carries.
func approvalNoticeCheck(notice *protocol.ApprovalNotice) error {
	switch {
	case notice == nil:
		return fmt.Errorf("%w: none", ErrApprovalNoticeInvalid)
	case len(notice.GetApprovalId()) != len(Id{}) || len(notice.GetRequesterSidecarId()) != len(Id{}):
		return fmt.Errorf("%w: an id that is not 16 bytes", ErrApprovalNoticeInvalid)
	case notice.GetEntrySeq() == 0 || notice.GetNotAfterMillis() <= 0 || notice.GetKind() == 0:
		return fmt.Errorf("%w: no seq, not_after or kind", ErrApprovalNoticeInvalid)
	}
	switch ApprovalNoticeState(notice.GetState()) {
	case ApprovalNoticeStatePending, ApprovalNoticeStateDecided:
		return nil
	}
	return fmt.Errorf("%w: state %d", ErrApprovalNoticeInvalid, notice.GetState())
}

// Whether notice names the request want names: its approval id, requester, entry seq, not_after and kind.
func approvalNoticeNames(notice *protocol.ApprovalNotice, want *protocol.ApprovalNotice) bool {
	return bytes.Equal(notice.GetApprovalId(), want.GetApprovalId()) &&
		bytes.Equal(notice.GetRequesterSidecarId(), want.GetRequesterSidecarId()) &&
		notice.GetEntrySeq() == want.GetEntrySeq() &&
		notice.GetNotAfterMillis() == want.GetNotAfterMillis() &&
		notice.GetKind() == want.GetKind()
}

// One request of the log, as the notices judge it.
type approvalNoticeRequest struct {
	entry   *RecordReadEntry
	request *StoredApprovalRequest
	// its entry's writer and chain seq, which its notice names
	requesterId Id
	entrySeq    uint64
	// a decision of it in the log, and a cancel
	decided   bool
	cancelled bool
}

// The notice this request has, in state.
func (self *approvalNoticeRequest) notice(state ApprovalNoticeState) *protocol.ApprovalNotice {
	return approvalNoticeOf(self.request.Request, self.requesterId, self.entrySeq, self.request.Action.Action.GetKind(), state)
}

// Every approval request in a log's entries, by approval id, with what answers it: the first request entry of each
// approval id, one that does not parse left out.
func approvalNoticeRequests(entries []*RecordReadEntry) map[Id]*approvalNoticeRequest {
	requests := map[Id]*approvalNoticeRequest{}
	for _, entry := range entries {
		if entry.Kind() != RecordKindApproval || entry.Body == nil {
			continue
		}
		request, err := ParseStoredApprovalRequest(entry.Body)
		if err != nil {
			continue
		}
		approvalId := request.ApprovalId()
		if _, ok := requests[approvalId]; ok {
			continue
		}
		requests[approvalId] = &approvalNoticeRequest{
			entry:       entry,
			request:     request,
			requesterId: recordIdOf(entry.Header.Header.GetWriterSidecarId()),
			entrySeq:    entry.Header.Header.GetSeq(),
		}
	}
	for _, entry := range entries {
		approvalId, ok := recordAnswerApprovalId(entry)
		if !ok {
			continue
		}
		request := requests[approvalId]
		if request == nil {
			continue
		}
		switch entry.Kind() {
		case RecordKindApprovalDecision:
			request.decided = true
		case RecordKindApprovalCancel:
			request.cancelled = true
		}
	}
	return requests
}

// Whether the rules take file as request's notice (the file header's rules row), and the notice it holds.
func approvalNoticeTaken(file *ApprovalNoticeFile, request *approvalNoticeRequest, settings *ApprovalNoticeSettings) (*protocol.ApprovalNotice, bool) {
	notice, err := ApprovalNoticeDecode(file.Content, settings)
	if err != nil || !approvalNoticeNames(notice, request.notice(ApprovalNoticeStatePending)) {
		return nil, false
	}
	switch ApprovalNoticeState(notice.GetState()) {
	case ApprovalNoticeStatePending:
		return notice, file.SignerSidecarId == request.requesterId
	case ApprovalNoticeStateDecided:
		return notice, request.decided
	}
	return nil, false
}

// A write the notices owe, waiting for its entry to land: the request's pending notice, or a decision's rewrite or a
// cancel's removal.
type approvalNoticeOwed struct {
	approvalId Id
	logId      Id
	// the entry it waits on, this device's: the request's, or the answer's
	seq uint64
	// RecordKindApproval for the request's pending notice, else the answer's kind
	kind RecordKind
	// the request's notice, for its pending write
	notice *protocol.ApprovalNotice
	// not tried again before this, after a failure
	nextTryAt time.Time
}

// What one pass did, for a test's counts and the log.
type ApprovalNoticesPassed struct {
	// Owed writes done: pending notices written, decided ones rewritten, and removals.
	Written   int
	Rewritten int
	Removed   int
	// Owed writes left: their entries not landed, or a failure to try again.
	Owed int
	// Whether the repair ran, and what it did.
	Repaired *ApprovalNoticesRepaired
}

// What one repair did.
type ApprovalNoticesRepaired struct {
	// Notices read under a/.
	Read int
	// Pending notices written again from their request entries, and notices removed.
	Written int
	Removed int
}

// What a phone's check of a vault's notices found.
type ApprovalNoticesChecked struct {
	// Notices read under a/.
	Read int
	// Notices a request entry of the log backs, by approval id, sorted.
	Backed []Id
	// Notices no request entry backs, ignored: their paths, sorted. Each version alarmed once.
	Ignored []string
}

// A vault's notices on this device: see the file header.
type ApprovalNotices struct {
	approvals *RecordApprovals

	// one pass, repair or check at a time
	passLock sync.Mutex

	stateLock sync.Mutex
	settings  *ApprovalNoticeSettings
	vault     func(repoId Id) ApprovalNoticeVault
	// the owed writes, by approval id: a later note of an approval replaces an earlier one
	owed map[Id]*approvalNoticeOwed
	// when the next repair is due, zero for now
	repairAt time.Time
	// the notice versions a check alarmed on, by path
	alarmed map[string]uint64
}

// The record's notices part, made at the first call: from then its loop writes what the approval family's filings owe
// and runs the repair. The record component calls it.
func (self *SidecarRecord) ApprovalNotices() *ApprovalNotices {
	if notices := self.approvals.notices.Load(); notices != nil {
		return notices
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if notices := self.approvals.notices.Load(); notices != nil {
		return notices
	}
	notices := &ApprovalNotices{
		approvals: self.approvals,
		settings:  DefaultApprovalNoticeSettings(),
		owed:      map[Id]*approvalNoticeOwed{},
		alarmed:   map[string]uint64{},
	}
	self.approvals.notices.Store(notices)
	self.tendHooks = append(self.tendHooks, notices.Tick)
	return notices
}

// Binds where a vault's notices are read and written: an EvsClient's repos (bindMemberReplica), or a test's. Nil
// unbinds, and writes stay owed.
func (self *ApprovalNotices) Bind(vault func(repoId Id) ApprovalNoticeVault) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.vault = vault
}

// Replaces the settings; nil restores the defaults.
func (self *ApprovalNotices) SetSettings(settings *ApprovalNoticeSettings) {
	if settings == nil {
		settings = DefaultApprovalNoticeSettings()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.settings = settings
}

// The settings now.
func (self *ApprovalNotices) currentSettings() *ApprovalNoticeSettings {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.settings
}

// The vault bound for repoId, ErrApprovalNoticeUnbound for none.
func (self *ApprovalNotices) vaultOf(repoId Id) (ApprovalNoticeVault, error) {
	bind := func() func(repoId Id) ApprovalNoticeVault {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.vault
	}()
	if bind == nil {
		return nil, ErrApprovalNoticeUnbound
	}
	vault := bind(repoId)
	if vault == nil {
		return nil, ErrApprovalNoticeUnbound
	}
	return vault, nil
}

// Owes the pending notice of a request this device filed in its own stream of its author's vault at ref, written once
// the entry lands (the file header's write row).
func (self *ApprovalNotices) noteRequest(ref *RecordEntryRef, request *StoredApprovalRequest) {
	approvalId := request.ApprovalId()
	notice := approvalNoticeOf(request.Request, self.approvals.writer.sidecarId, ref.Seq, request.Action.Action.GetKind(), ApprovalNoticeStatePending)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.owed[approvalId] = &approvalNoticeOwed{approvalId: approvalId, logId: ref.LogId, seq: ref.Seq, kind: RecordKindApproval, notice: notice}
}

// Owes the rewrite or removal an answer this device filed at ref makes (the file header's answer row), in place of
// anything owed for the approval before.
func (self *ApprovalNotices) noteAnswer(ref *RecordEntryRef, approvalId Id, kind RecordKind) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.owed[approvalId] = &approvalNoticeOwed{approvalId: approvalId, logId: ref.LogId, seq: ref.Seq, kind: kind}
}

// The record loop's pass (a tend hook), logging what fails.
func (self *ApprovalNotices) Tick(ctx context.Context) {
	if _, err := self.Pass(ctx); err != nil && !errors.Is(err, ErrApprovalNoticeUnbound) {
		log := self.approvals.writer.log
		if log.V(1).Enabled() {
			log.Infof("[record]an approval notice pass stopped: %s", err)
		}
	}
}

// One pass: each owed write whose entry has landed, then the repair once due. With no vault bound nothing is done
// and the writes stay owed.
func (self *ApprovalNotices) Pass(ctx context.Context) (*ApprovalNoticesPassed, error) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	passed := &ApprovalNoticesPassed{}
	settings := self.currentSettings()
	now := self.approvals.writer.clock.Now()
	owed := func() []*approvalNoticeOwed {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		owed := []*approvalNoticeOwed{}
		for _, approvalId := range slices.SortedFunc(maps.Keys(self.owed), Id.Cmp) {
			owed = append(owed, self.owed[approvalId])
		}
		return owed
	}()
	var firstErr error
	for _, item := range owed {
		if now.Before(item.nextTryAt) || !self.approvals.writer.landed(item.logId, item.seq) {
			continue
		}
		done, err := self.apply(ctx, item, settings, passed)
		if errors.Is(err, ErrApprovalNoticeUnbound) {
			return passed, err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.owed[item.approvalId] != item {
				// a later note replaced it
				return
			}
			if done {
				delete(self.owed, item.approvalId)
			} else {
				item.nextTryAt = now.Add(settings.RetryInterval)
			}
		}()
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		passed.Owed = len(self.owed)
	}()
	due := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return !now.Before(self.repairAt)
	}()
	if due {
		repaired, err := self.repair(ctx, settings)
		passed.Repaired = repaired
		if err == nil {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.repairAt = now.Add(settings.RepairInterval)
			}()
		} else if firstErr == nil {
			firstErr = err
		}
	}
	return passed, firstErr
}

// One owed write: done once it is written, or once there is nothing to write; a conflict is done too, since another
// write landed and the repair judges what stands.
func (self *ApprovalNotices) apply(ctx context.Context, item *approvalNoticeOwed, settings *ApprovalNoticeSettings, passed *ApprovalNoticesPassed) (bool, error) {
	vault, err := self.vaultOf(item.logId)
	if err != nil {
		return false, err
	}
	path := approvalNoticePath(item.approvalId)
	file, err := vault.ReadNotice(ctx, path, settings.NoticeByteCount)
	if err != nil {
		return false, err
	}
	ifVersion := uint64(0)
	if file != nil {
		ifVersion = file.Version
	}
	var current *protocol.ApprovalNotice
	if file != nil {
		current, _ = ApprovalNoticeDecode(file.Content, settings)
	}
	switch item.kind {
	case RecordKindApproval:
		if current != nil && approvalNoticeNames(current, item.notice) && file.SignerSidecarId == self.approvals.writer.sidecarId {
			return true, nil
		}
		err = self.put(ctx, vault, path, ifVersion, item.notice, settings)
		if err == nil {
			passed.Written += 1
		}
	case RecordKindApprovalDecision:
		if current == nil || ApprovalNoticeState(current.GetState()) == ApprovalNoticeStateDecided {
			// none stands to rewrite, or one that no rule takes, which the requester's repair writes over
			return true, nil
		}
		decided := proto.Clone(current).(*protocol.ApprovalNotice)
		decided.State = uint32(ApprovalNoticeStateDecided)
		err = self.put(ctx, vault, path, ifVersion, decided, settings)
		if err == nil {
			passed.Rewritten += 1
		}
	case RecordKindApprovalCancel:
		if file == nil {
			return true, nil
		}
		err = self.remove(ctx, vault, path, item.approvalId, ifVersion)
		if err == nil {
			passed.Removed += 1
		}
	default:
		return true, nil
	}
	if errors.Is(err, ErrApprovalNoticeConflict) {
		return true, nil
	}
	return err == nil, err
}

// Writes notice at path from ifVersion, between the barriers.
func (self *ApprovalNotices) put(ctx context.Context, vault ApprovalNoticeVault, path string, ifVersion uint64, notice *protocol.ApprovalNotice, settings *ApprovalNoticeSettings) error {
	content, err := approvalNoticeEncode(notice, settings)
	if err != nil {
		return err
	}
	hookKey := recordChainIdText(Id(notice.GetApprovalId()))
	testHookBarrier("approval.notice.before", hookKey)
	_, err = vault.PutNotice(ctx, path, ifVersion, content)
	testHookBarrier("approval.notice.after", hookKey)
	return err
}

// Removes path from ifVersion, between the barriers.
func (self *ApprovalNotices) remove(ctx context.Context, vault ApprovalNoticeVault, path string, approvalId Id, ifVersion uint64) error {
	hookKey := recordChainIdText(approvalId)
	testHookBarrier("approval.notice.before", hookKey)
	err := vault.RemoveNotice(ctx, path, ifVersion)
	testHookBarrier("approval.notice.after", hookKey)
	return err
}

// The repair (the file header's repair row), run now whatever its interval.
func (self *ApprovalNotices) Repair(ctx context.Context) (*ApprovalNoticesRepaired, error) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	return self.repair(ctx, self.currentSettings())
}

// The repair, the caller holding passLock: this device's vault synced, its notices read, and each of this device's own
// requests' notices made to stand as its state calls for. A device that only deposits into its vault writes no
// notice.
func (self *ApprovalNotices) repair(ctx context.Context, settings *ApprovalNoticeSettings) (*ApprovalNoticesRepaired, error) {
	repaired := &ApprovalNoticesRepaired{}
	route, err := self.approvals.route()
	if err != nil || route.deposit {
		// nothing of this device's own to repair: a tagged sidecar files its requests by deposit
		return repaired, nil
	}
	vault, err := self.vaultOf(route.logId)
	if err != nil {
		return repaired, err
	}
	if err := self.approvals.reader.Sync(ctx, route.logId); err != nil {
		return repaired, err
	}
	requests := approvalNoticeRequests(self.approvals.reader.Entries(route.logId))
	files, err := vault.ListNotices(ctx, settings.ReadCount, settings.NoticeByteCount)
	if err != nil {
		return repaired, err
	}
	repaired.Read = len(files)
	filesByPath := map[string]*ApprovalNoticeFile{}
	for _, file := range files {
		filesByPath[file.Path] = file
	}
	nowMillis := self.approvals.writer.clock.Now().UnixMilli()
	graceMillis := settings.Grace.Milliseconds()
	selfId := self.approvals.writer.sidecarId
	var firstErr error
	note := func(err error) {
		if err != nil && !errors.Is(err, ErrApprovalNoticeConflict) && firstErr == nil {
			firstErr = err
		}
	}
	// notices whose requests are past their grace, or cancelled, whoever filed them; one this log does not back is the
	// phones' to ignore and its requester's to repair
	for _, file := range files {
		approvalId, ok := approvalNoticeIdOf(file.Path)
		if !ok {
			continue
		}
		request := requests[approvalId]
		if request == nil {
			continue
		}
		pastGrace := request.request.Request.GetNotAfterMillis()+graceMillis < nowMillis
		cancelledOwn := request.cancelled && request.requesterId == selfId
		if !pastGrace && !cancelledOwn {
			continue
		}
		err := self.remove(ctx, vault, file.Path, approvalId, file.Version)
		if err == nil {
			repaired.Removed += 1
		}
		note(err)
	}
	// this device's own requests still pending and before not_after: a pending notice where none stands or one no rule
	// takes
	for _, approvalId := range slices.SortedFunc(maps.Keys(requests), Id.Cmp) {
		request := requests[approvalId]
		if request.requesterId != selfId || request.decided || request.cancelled || request.request.Request.GetNotAfterMillis() < nowMillis {
			continue
		}
		path := approvalNoticePath(approvalId)
		ifVersion := uint64(0)
		if file := filesByPath[path]; file != nil {
			if _, taken := approvalNoticeTaken(file, request, settings); taken {
				continue
			}
			ifVersion = file.Version
		} else if len(files) == settings.ReadCount {
			// past what one read takes: read the path itself before writing over it
			file, err := vault.ReadNotice(ctx, path, settings.NoticeByteCount)
			if err != nil {
				note(err)
				continue
			}
			if file != nil {
				if _, taken := approvalNoticeTaken(file, request, settings); taken {
					continue
				}
				ifVersion = file.Version
			}
		}
		err := self.put(ctx, vault, path, ifVersion, request.notice(ApprovalNoticeStatePending), settings)
		if err == nil {
			repaired.Written += 1
		}
		note(err)
	}
	return repaired, firstErr
}

// A phone's check of vaultId's notices (the file header's phone row): each notice under a/ read, and each that no
// request entry of the log backs, by its approval id, requester, seq, not_after and kind, ignored and alarmed once a
// version. The log is synced first, so an entry that landed before its notice is there.
func (self *ApprovalNotices) Check(ctx context.Context, vaultId Id) (*ApprovalNoticesChecked, error) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	settings := self.currentSettings()
	vault, err := self.vaultOf(vaultId)
	if err != nil {
		return nil, err
	}
	files, err := vault.ListNotices(ctx, settings.ReadCount, settings.NoticeByteCount)
	if err != nil {
		return nil, err
	}
	if err := self.approvals.reader.Sync(ctx, vaultId); err != nil {
		return nil, err
	}
	requests := approvalNoticeRequests(self.approvals.reader.Entries(vaultId))
	checked := &ApprovalNoticesChecked{Read: len(files)}
	for _, file := range files {
		approvalId, ok := approvalNoticeIdOf(file.Path)
		var request *approvalNoticeRequest
		if ok {
			request = requests[approvalId]
		}
		backed := false
		if request != nil {
			if notice, err := ApprovalNoticeDecode(file.Content, settings); err == nil {
				backed = approvalNoticeNames(notice, request.notice(ApprovalNoticeStatePending))
			}
		}
		if backed {
			checked.Backed = append(checked.Backed, approvalId)
			continue
		}
		checked.Ignored = append(checked.Ignored, file.Path)
		first := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if version, ok := self.alarmed[file.Path]; ok && version == file.Version {
				return false
			}
			self.alarmed[file.Path] = file.Version
			return true
		}()
		if first {
			signerId := file.SignerSidecarId
			self.approvals.writer.raise(SidecarRecordAlarmPathRule, vaultId, &signerId)
		}
	}
	slices.SortFunc(checked.Backed, Id.Cmp)
	slices.Sort(checked.Ignored)
	return checked, nil
}

// ApprovalNoticeVault over one repo's main ref through its EvsClient: reads verified, writes as one push each, held to
// the version read by path CAS, versionless once the network admits format 2 (§19.11's format2 gate), else versioned
// as any format-1 file.
type ApprovalNoticeEvsVault struct {
	repo *EvsRepo
}

var _ ApprovalNoticeVault = (*ApprovalNoticeEvsVault)(nil)

// The notices of repo's main ref.
func NewApprovalNoticeEvsVault(repo *EvsRepo) *ApprovalNoticeEvsVault {
	return &ApprovalNoticeEvsVault{repo: repo}
}

// A writer that keeps at most limit + 1 bytes.
type approvalNoticeBuffer struct {
	limit int
	data  []byte
}

func (self *approvalNoticeBuffer) Write(data []byte) (int, error) {
	room := self.limit + 1 - len(self.data)
	if 0 < room {
		self.data = append(self.data, data[:min(room, len(data))]...)
	}
	return len(data), nil
}

func (self *ApprovalNoticeEvsVault) ReadNotice(ctx context.Context, path string, maxByteCount int) (*ApprovalNoticeFile, error) {
	buffer := &approvalNoticeBuffer{limit: maxByteCount}
	info, err := self.repo.ReadHead(ctx, &EvsReadArgs{Path: path, Fresh: true}, buffer)
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ApprovalNoticeFile{Path: path, Version: info.Version, SignerSidecarId: info.SignerSidecarId, Content: buffer.data}, nil
}

func (self *ApprovalNoticeEvsVault) ListNotices(ctx context.Context, maxCount int, maxByteCount int) ([]*ApprovalNoticeFile, error) {
	listing, err := self.repo.List(ctx, &EvsReadArgs{Path: approvalNoticeDirectory, Fresh: true})
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	paths := []string{}
	for _, entry := range listing.Entries {
		if entry.Kind != protocol.EvsEntryKind_EVS_ENTRY_FILE {
			continue
		}
		path := approvalNoticePrefix() + string(entry.Name)
		if _, ok := approvalNoticeIdOf(path); ok {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	files := []*ApprovalNoticeFile{}
	for _, path := range paths {
		if maxCount <= len(files) {
			break
		}
		file, err := self.ReadNotice(ctx, path, maxByteCount)
		if err != nil {
			return nil, err
		}
		if file != nil {
			files = append(files, file)
		}
	}
	return files, nil
}

// The versioning a notice's write asks for: off where the network admits format 2, else the path's own.
func (self *ApprovalNoticeEvsVault) versioning() string {
	if self.repo.Client().Format2Admitted() {
		return EvsVersioningOff
	}
	return EvsVersioningKeepSetting
}

func (self *ApprovalNoticeEvsVault) PutNotice(ctx context.Context, path string, ifVersion uint64, content []byte) (uint64, error) {
	result, err := self.repo.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{{
		Path:      path,
		Content:   bytes.NewReader(content),
		IfVersion: &ifVersion,
		Options:   &EvsWriteOptions{Versioning: self.versioning()},
	}}})
	if err != nil {
		return 0, approvalNoticeWriteError(err)
	}
	return result.PathVersions[0], nil
}

func (self *ApprovalNoticeEvsVault) RemoveNotice(ctx context.Context, path string, ifVersion uint64) error {
	_, err := self.repo.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{{
		Path:      path,
		Remove:    true,
		IfVersion: &ifVersion,
	}}})
	return approvalNoticeWriteError(err)
}

// A write's error, a path CAS's conflict as ErrApprovalNoticeConflict.
func approvalNoticeWriteError(err error) error {
	var conflict *EvsPathConflictError
	if errors.As(err, &conflict) || errors.Is(err, ErrEvsPathMoved) {
		return fmt.Errorf("%w: %w", ErrApprovalNoticeConflict, err)
	}
	return err
}

// What ReadHead writes a notice's content into.
var _ io.Writer = (*approvalNoticeBuffer)(nil)
