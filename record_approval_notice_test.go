//go:build !sidecar_http

// record_approval_notice.go on sidecartest's streams (CTXH-M11-07; DESIGN-COMPUTE §24.7, D-CTXH-10; owner decision 573's
// remedy): a request's a/<approval_id> notice written once its entry lands and not before, rewritten at a decision and
// removed at a cancel; a crash between the entry and the notice repaired from the request entry, as is a version no
// rule takes; a notice no request entry backs ignored and alarmed once a version; the notice's bytes held to the
// format. External, as record_approval_log_test.go, on its world. The phone's leases are sidecartest's
// approval_notice_phone_test.go and record_approval_app_test.go's.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One version of a notice path in the fake vault.
type testApprovalNoticeVersion struct {
	version  uint64
	signerId sidecar.Id
	content  []byte
	removed  bool
}

// A vault's main ref as the notices see it: each path's newest version, versions counted per path from 1, a write or
// removal held to the version its writer read, as evs's path CAS holds it.
type testApprovalNoticeVault struct {
	stateLock sync.Mutex
	paths     map[string]*testApprovalNoticeVersion
	writes    int
	// refuses every call while set
	down bool
}

func newTestApprovalNoticeVault() *testApprovalNoticeVault {
	return &testApprovalNoticeVault{paths: map[string]*testApprovalNoticeVersion{}}
}

// The vault as signerId's device reaches it.
func (self *testApprovalNoticeVault) as(signerId sidecar.Id) func(repoId sidecar.Id) sidecar.ApprovalNoticeVault {
	return func(repoId sidecar.Id) sidecar.ApprovalNoticeVault {
		return &testApprovalNoticeVaultDevice{vault: self, signerId: signerId}
	}
}

// The newest version of path, nil for none or a removal.
func (self *testApprovalNoticeVault) file(path string) *testApprovalNoticeVersion {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	version := self.paths[path]
	if version == nil || version.removed {
		return nil
	}
	copied := *version
	return &copied
}

// Writes content at path as signerId whatever stands, as a writer outside the rules could.
func (self *testApprovalNoticeVault) force(path string, signerId sidecar.Id, content []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	next := uint64(1)
	if version := self.paths[path]; version != nil {
		next = version.version + 1
	}
	self.paths[path] = &testApprovalNoticeVersion{version: next, signerId: signerId, content: bytes.Clone(content)}
}

type testApprovalNoticeVaultDevice struct {
	vault    *testApprovalNoticeVault
	signerId sidecar.Id
}

var errTestApprovalNoticeVaultDown = errors.New("the test vault is down")

func (self *testApprovalNoticeVaultDevice) ReadNotice(ctx context.Context, path string, maxByteCount int) (*sidecar.ApprovalNoticeFile, error) {
	self.vault.stateLock.Lock()
	defer self.vault.stateLock.Unlock()
	if self.vault.down {
		return nil, errTestApprovalNoticeVaultDown
	}
	version := self.vault.paths[path]
	if version == nil || version.removed {
		return nil, nil
	}
	content := version.content
	if maxByteCount+1 < len(content) {
		content = content[:maxByteCount+1]
	}
	return &sidecar.ApprovalNoticeFile{Path: path, Version: version.version, SignerSidecarId: version.signerId, Content: bytes.Clone(content)}, nil
}

func (self *testApprovalNoticeVaultDevice) ListNotices(ctx context.Context, maxCount int, maxByteCount int) ([]*sidecar.ApprovalNoticeFile, error) {
	paths := func() []string {
		self.vault.stateLock.Lock()
		defer self.vault.stateLock.Unlock()
		return slices.Sorted(maps.Keys(self.vault.paths))
	}()
	files := []*sidecar.ApprovalNoticeFile{}
	for _, path := range paths {
		if maxCount <= len(files) || !strings.HasPrefix(path, "a/") {
			continue
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

// The version a write must be held to, and the next.
func (self *testApprovalNoticeVaultDevice) checkWithLock(path string, ifVersion uint64) (uint64, error) {
	if self.vault.down {
		return 0, errTestApprovalNoticeVaultDown
	}
	standing := uint64(0)
	next := uint64(1)
	if version := self.vault.paths[path]; version != nil {
		next = version.version + 1
		if !version.removed {
			standing = version.version
		}
	}
	if standing != ifVersion {
		return 0, sidecar.ErrApprovalNoticeConflict
	}
	return next, nil
}

func (self *testApprovalNoticeVaultDevice) PutNotice(ctx context.Context, path string, ifVersion uint64, content []byte) (uint64, error) {
	self.vault.stateLock.Lock()
	defer self.vault.stateLock.Unlock()
	next, err := self.checkWithLock(path, ifVersion)
	if err != nil {
		return 0, err
	}
	self.vault.paths[path] = &testApprovalNoticeVersion{version: next, signerId: self.signerId, content: bytes.Clone(content)}
	self.vault.writes += 1
	return next, nil
}

func (self *testApprovalNoticeVaultDevice) RemoveNotice(ctx context.Context, path string, ifVersion uint64) error {
	self.vault.stateLock.Lock()
	defer self.vault.stateLock.Unlock()
	next, err := self.checkWithLock(path, ifVersion)
	if err != nil {
		return err
	}
	self.vault.paths[path] = &testApprovalNoticeVersion{version: next, signerId: self.signerId, removed: true}
	self.vault.writes += 1
	return nil
}

// device's record with its notices part made and bound to vault.
func testApprovalNoticeRecord(device *testRecordDevice, vault *testApprovalNoticeVault) (*sidecar.SidecarRecord, *sidecar.ApprovalNotices) {
	record := device.open()
	notices := record.ApprovalNotices()
	notices.Bind(vault.as(device.sidecarId))
	return record, notices
}

// A request requester files in the world's vault, parsed.
func testApprovalNoticeRequest(t *testing.T, world *testRecordWorld, requester *testRecordDevice, value string) *sidecar.StoredApprovalRequest {
	t.Helper()
	return testRecordParsedRequest(t, world.approvalRequest(requester, testRecordDnsSet(t, value).Bytes, "set it", nil))
}

// The notice at approvalId's path, decoded, nil for none.
func testApprovalNoticeAt(t *testing.T, vault *testApprovalNoticeVault, approvalId sidecar.Id) (*protocol.ApprovalNotice, *testApprovalNoticeVersion) {
	t.Helper()
	file := vault.file(testApprovalNoticePath(approvalId))
	if file == nil {
		return nil, nil
	}
	notice, err := sidecar.ApprovalNoticeDecode(file.content, nil)
	if err != nil {
		t.Fatalf("the notice does not decode: %v", err)
	}
	return notice, file
}

// a/<approval_id>, 32 lowercase hex.
func testApprovalNoticePath(approvalId sidecar.Id) string {
	return "a/" + strings.ReplaceAll(approvalId.String(), "-", "")
}

// approver's device cancel of request, as stored.
func (self *testRecordDevice) cancel(request *sidecar.StoredApprovalRequest) []byte {
	self.t.Helper()
	body, err := proto.Marshal(&protocol.ApprovalCancel{ApprovalId: request.Request.GetApprovalId()})
	if err != nil {
		self.t.Fatal(err)
	}
	signed := &bridge.Signed{
		Body:      body,
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_CANCEL, body)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_CANCEL),
	}
	stored, err := proto.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	return stored
}

// A request filed in the vault owes its notice, which no pass writes before the entry lands; once it lands the next
// pass writes the pending notice at a/<approval_id>, by the requester, naming the request entry's seq, its not_after
// and its action's kind and no approver or action text; a second pass writes nothing more.
func TestApprovalNoticeWrittenWithRequest(t *testing.T) {
	world := newTestRecordWorld(t)
	requester := world.device(true)
	vault := newTestApprovalNoticeVault()
	record, notices := testApprovalNoticeRecord(requester, vault)
	request := testApprovalNoticeRequest(t, world, requester, "198.51.100.7")
	ref, err := record.Approvals().FileRequest(request)
	if err != nil || ref.Spooled {
		t.Fatalf("filing: %+v, %v", ref, err)
	}
	passed, err := notices.Pass(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if passed.Written != 0 || passed.Owed != 1 || vault.file(testApprovalNoticePath(request.ApprovalId())) != nil {
		t.Fatalf("a notice before its entry landed: %+v", passed)
	}
	if err := record.Land(t.Context(), []*sidecar.RecordEntryRef{ref}); err != nil {
		t.Fatal(err)
	}
	passed, err = notices.Pass(t.Context())
	if err != nil || passed.Written != 1 || passed.Owed != 0 {
		t.Fatalf("the pass after landing: %+v, %v", passed, err)
	}
	notice, file := testApprovalNoticeAt(t, vault, request.ApprovalId())
	if notice == nil || file.signerId != requester.sidecarId {
		t.Fatalf("the notice: %+v", file)
	}
	if sidecar.Id(notice.GetApprovalId()) != request.ApprovalId() || sidecar.Id(notice.GetRequesterSidecarId()) != requester.sidecarId ||
		notice.GetEntrySeq() != ref.Seq || notice.GetNotAfterMillis() != request.Request.GetNotAfterMillis() ||
		notice.GetKind() != uint32(sidecar.SidecarActionDnsSet) || sidecar.ApprovalNoticeState(notice.GetState()) != sidecar.ApprovalNoticeStatePending {
		t.Fatalf("the notice names %+v", notice)
	}
	// it names no approver and no action text: nothing of the request's but its ids, seq, expiry and kind
	if bytes.Contains(file.content, world.memberId.Bytes()) || bytes.Contains(file.content, []byte("198.51.100.7")) || bytes.Contains(file.content, []byte("set it")) {
		t.Fatal("the notice carries an approver or the action's text")
	}
	writes := vault.writes
	if passed, err := notices.Pass(t.Context()); err != nil || passed.Written != 0 || vault.writes != writes {
		t.Fatalf("a second pass: %+v, %v", passed, err)
	}
}

// The member's other device decides the request: once its decision lands, its pass rewrites the notice to decided;
// a second request cancelled by that device has its notice removed once the cancel lands; neither writes a notice
// where none stands.
func TestApprovalNoticeRemovedAtDecisionAndCancel(t *testing.T) {
	world := newTestRecordWorld(t)
	requester := world.device(true)
	approver := world.device(true)
	vault := newTestApprovalNoticeVault()
	requesterRecord, requesterNotices := testApprovalNoticeRecord(requester, vault)
	approverRecord, approverNotices := testApprovalNoticeRecord(approver, vault)
	decided := testApprovalNoticeRequest(t, world, requester, "198.51.100.7")
	cancelled := testApprovalNoticeRequest(t, world, requester, "198.51.100.8")
	for _, request := range []*sidecar.StoredApprovalRequest{decided, cancelled} {
		if _, err := requesterRecord.Approvals().FileRequest(request); err != nil {
			t.Fatal(err)
		}
	}
	if err := requesterRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if passed, err := requesterNotices.Pass(t.Context()); err != nil || passed.Written != 2 {
		t.Fatalf("the requester's pass: %+v, %v", passed, err)
	}

	if _, err := approverRecord.Approvals().FileDecision(t.Context(), world.vaultId, approver.decide(decided), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := approverRecord.Approvals().FileCancel(t.Context(), world.vaultId, approver.cancel(cancelled)); err != nil {
		t.Fatal(err)
	}
	if passed, err := approverNotices.Pass(t.Context()); err != nil || passed.Rewritten+passed.Removed != 0 || passed.Owed != 2 {
		t.Fatalf("the approver's pass before its entries landed: %+v, %v", passed, err)
	}
	if err := approverRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	passed, err := approverNotices.Pass(t.Context())
	if err != nil || passed.Rewritten != 1 || passed.Removed != 1 || passed.Owed != 0 {
		t.Fatalf("the approver's pass: %+v, %v", passed, err)
	}
	notice, file := testApprovalNoticeAt(t, vault, decided.ApprovalId())
	if notice == nil || sidecar.ApprovalNoticeState(notice.GetState()) != sidecar.ApprovalNoticeStateDecided || file.signerId != approver.sidecarId {
		t.Fatalf("the decided request's notice: %+v, %+v", notice, file)
	}
	if notice, _ := testApprovalNoticeAt(t, vault, cancelled.ApprovalId()); notice != nil {
		t.Fatalf("the cancelled request's notice stands: %+v", notice)
	}

	// a decision on a request whose notice never landed writes none
	silent := testApprovalNoticeRequest(t, world, requester, "198.51.100.9")
	if _, err := requesterRecord.Approvals().FileRequest(silent); err != nil {
		t.Fatal(err)
	}
	if err := requesterRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := approverRecord.Approvals().FileDecision(t.Context(), world.vaultId, approver.decide(silent), nil); err != nil {
		t.Fatal(err)
	}
	if err := approverRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if passed, err := approverNotices.Pass(t.Context()); err != nil || passed.Rewritten != 0 || passed.Owed != 0 {
		t.Fatalf("a decision with no notice standing: %+v, %v", passed, err)
	}
	if notice, _ := testApprovalNoticeAt(t, vault, silent.ApprovalId()); notice != nil {
		t.Fatalf("a decision wrote a notice: %+v", notice)
	}
}

// A crash between the request entry and its notice: the entry landed, and the process that owed the notice ended
// before writing it. The next process's first pass runs the repair, which writes the pending notice from the request
// entry; a version no rule takes, another writer's pending notice or bytes that do not decode, is written over; a
// request past its not_after and grace has its notice removed, whoever filed it.
func TestApprovalNoticeRepairedAfterCrashBetweenEntryAndNotice(t *testing.T) {
	world := newTestRecordWorld(t)
	requester := world.device(true)
	other := world.device(true)
	vault := newTestApprovalNoticeVault()
	first, _ := testApprovalNoticeRecord(requester, vault)
	request := testApprovalNoticeRequest(t, world, requester, "198.51.100.7")
	ref, err := first.Approvals().FileRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Land(t.Context(), []*sidecar.RecordEntryRef{ref}); err != nil {
		t.Fatal(err)
	}
	// the crash: the owed write goes with the process
	if vault.file(testApprovalNoticePath(request.ApprovalId())) != nil {
		t.Fatal("a notice before any pass")
	}
	_, notices := testApprovalNoticeRecord(requester, vault)
	passed, err := notices.Pass(t.Context())
	if err != nil || passed.Repaired == nil || passed.Repaired.Written != 1 {
		t.Fatalf("the next process's first pass: %+v, %v", passed, err)
	}
	notice, file := testApprovalNoticeAt(t, vault, request.ApprovalId())
	if notice == nil || notice.GetEntrySeq() != ref.Seq || file.signerId != requester.sidecarId {
		t.Fatalf("the repaired notice: %+v", notice)
	}
	// the repair runs again only after its interval
	if passed, err := notices.Pass(t.Context()); err != nil || passed.Repaired != nil {
		t.Fatalf("a pass inside the interval: %+v, %v", passed, err)
	}

	// versions no rule takes: another device's pending notice, then bytes that do not decode
	forged := proto.Clone(notice).(*protocol.ApprovalNotice)
	forgedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range [][]byte{forgedBytes, []byte("not a notice")} {
		vault.force(testApprovalNoticePath(request.ApprovalId()), other.sidecarId, content)
		repaired, err := notices.Repair(t.Context())
		if err != nil || repaired.Written != 1 {
			t.Fatalf("a repair over a version no rule takes: %+v, %v", repaired, err)
		}
		if _, file := testApprovalNoticeAt(t, vault, request.ApprovalId()); file == nil || file.signerId != requester.sidecarId {
			t.Fatalf("the notice after the repair: %+v", file)
		}
	}
	// one naming another seq is no notice of this request either
	wrongSeq := proto.Clone(notice).(*protocol.ApprovalNotice)
	wrongSeq.EntrySeq += 7
	wrongBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(wrongSeq)
	if err != nil {
		t.Fatal(err)
	}
	vault.force(testApprovalNoticePath(request.ApprovalId()), requester.sidecarId, wrongBytes)
	if repaired, err := notices.Repair(t.Context()); err != nil || repaired.Written != 1 {
		t.Fatalf("a repair over another seq's notice: %+v, %v", repaired, err)
	}

	// past not_after and its grace, the notice goes, whichever device's repair runs
	_, otherNotices := testApprovalNoticeRecord(other, vault)
	world.clock.Advance(time.Duration(request.Request.GetNotAfterMillis()-world.clock.Now().UnixMilli())*time.Millisecond + sidecar.DefaultApprovalNoticeSettings().Grace + time.Minute)
	repaired, err := otherNotices.Repair(t.Context())
	if err != nil || repaired.Removed != 1 || repaired.Written != 0 {
		t.Fatalf("a repair past the grace: %+v, %v", repaired, err)
	}
	if notice, _ := testApprovalNoticeAt(t, vault, request.ApprovalId()); notice != nil {
		t.Fatal("a notice past its grace stands")
	}
}

// A notice no request entry backs, one at a random approval id, and one naming a real request's id but another seq,
// is ignored by a phone's check and alarmed path_rule once a version; the backed one is listed backed; a second check
// alarms nothing more, and a new version of an unbacked notice alarms again.
func TestNoticeWithoutRequestIgnoredAndAlarmed(t *testing.T) {
	world := newTestRecordWorld(t)
	requester := world.device(true)
	phone := world.device(true)
	vault := newTestApprovalNoticeVault()
	requesterRecord, requesterNotices := testApprovalNoticeRecord(requester, vault)
	request := testApprovalNoticeRequest(t, world, requester, "198.51.100.7")
	if _, err := requesterRecord.Approvals().FileRequest(request); err != nil {
		t.Fatal(err)
	}
	if err := requesterRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := requesterNotices.Pass(t.Context()); err != nil {
		t.Fatal(err)
	}
	backed, _ := testApprovalNoticeAt(t, vault, request.ApprovalId())
	if backed == nil {
		t.Fatal("no notice for the request")
	}
	orphanId := sidecar.NewId()
	orphan := proto.Clone(backed).(*protocol.ApprovalNotice)
	orphan.ApprovalId = orphanId.Bytes()
	orphanBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(orphan)
	if err != nil {
		t.Fatal(err)
	}
	vault.force(testApprovalNoticePath(orphanId), requester.sidecarId, orphanBytes)

	phoneRecord, _ := testApprovalNoticeRecord(phone, vault)
	checked, err := phoneRecord.Approvals().CheckNotices(t.Context(), world.vaultId)
	if err != nil {
		t.Fatal(err)
	}
	if checked.Read != 2 || !slices.Equal(checked.Backed, []sidecar.Id{request.ApprovalId()}) || !slices.Equal(checked.Ignored, []string{testApprovalNoticePath(orphanId)}) {
		t.Fatalf("the check: %+v", checked)
	}
	pathRules := func() int {
		count := 0
		for _, reason := range phone.alarmReasons() {
			if reason == sidecar.SidecarRecordAlarmPathRule {
				count += 1
			}
		}
		return count
	}
	if count := pathRules(); count != 1 {
		t.Fatalf("%d path_rule alarms for one unbacked notice", count)
	}
	// nothing about a request comes from its notice: the phone's pending list is the log's alone
	pending, err := phoneRecord.Approvals().Pending(t.Context())
	if err != nil || len(pending) != 1 || pending[0].Request.ApprovalId() != request.ApprovalId() {
		t.Fatalf("pending: %d, %v", len(pending), err)
	}
	if _, err := phoneRecord.Approvals().CheckNotices(t.Context(), world.vaultId); err != nil || pathRules() != 1 {
		t.Fatalf("a second check alarmed again: %d, %v", pathRules(), err)
	}
	// a request's real id at another seq is backed by no entry either
	wrongSeq := proto.Clone(backed).(*protocol.ApprovalNotice)
	wrongSeq.EntrySeq += 3
	wrongBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(wrongSeq)
	if err != nil {
		t.Fatal(err)
	}
	vault.force(testApprovalNoticePath(request.ApprovalId()), requester.sidecarId, wrongBytes)
	checked, err = phoneRecord.Approvals().CheckNotices(t.Context(), world.vaultId)
	if err != nil || len(checked.Backed) != 0 || len(checked.Ignored) != 2 || pathRules() != 2 {
		t.Fatalf("a notice naming another seq: %+v, %d alarms, %v", checked, pathRules(), err)
	}
}

// The notice's bytes held to the format: past NoticeByteCount, a short id, no seq, a state it does not name, each
// refused by the decoder; a device that only deposits into its vault owes no notice for its request.
func TestApprovalNoticeFormatAndDepositor(t *testing.T) {
	settings := sidecar.DefaultApprovalNoticeSettings()
	good := &protocol.ApprovalNotice{
		ApprovalId: sidecar.NewId().Bytes(), RequesterSidecarId: sidecar.NewId().Bytes(), EntrySeq: 4,
		NotAfterMillis: 1_800_000_000_000, State: uint32(sidecar.ApprovalNoticeStatePending), Kind: uint32(sidecar.SidecarActionDnsSet),
	}
	encode := func(notice *protocol.ApprovalNotice) []byte {
		content, err := proto.MarshalOptions{Deterministic: true}.Marshal(notice)
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
	if _, err := sidecar.ApprovalNoticeDecode(encode(good), settings); err != nil {
		t.Fatalf("a good notice: %v", err)
	}
	for _, bad := range []func(notice *protocol.ApprovalNotice){
		func(notice *protocol.ApprovalNotice) { notice.ApprovalId = notice.ApprovalId[:8] },
		func(notice *protocol.ApprovalNotice) { notice.RequesterSidecarId = nil },
		func(notice *protocol.ApprovalNotice) { notice.EntrySeq = 0 },
		func(notice *protocol.ApprovalNotice) { notice.NotAfterMillis = 0 },
		func(notice *protocol.ApprovalNotice) { notice.Kind = 0 },
		func(notice *protocol.ApprovalNotice) { notice.State = 3 },
	} {
		notice := proto.Clone(good).(*protocol.ApprovalNotice)
		bad(notice)
		if _, err := sidecar.ApprovalNoticeDecode(encode(notice), settings); !errors.Is(err, sidecar.ErrApprovalNoticeInvalid) {
			t.Errorf("a bad notice %+v decoded: %v", notice, err)
		}
	}
	oversize := append(encode(good), make([]byte, settings.NoticeByteCount)...)
	if _, err := sidecar.ApprovalNoticeDecode(oversize, settings); !errors.Is(err, sidecar.ErrApprovalNoticeInvalid) {
		t.Errorf("an oversize notice decoded: %v", err)
	}

	world := newTestRecordWorld(t)
	depositor := world.device(false)
	vault := newTestApprovalNoticeVault()
	record, notices := testApprovalNoticeRecord(depositor, vault)
	request := testApprovalNoticeRequest(t, world, depositor, "198.51.100.7")
	if _, err := record.Approvals().FileRequest(request); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	passed, err := notices.Pass(t.Context())
	if err != nil || passed.Owed != 0 || passed.Written != 0 || vault.writes != 0 {
		t.Fatalf("a depositor's pass: %+v, %v", passed, err)
	}
}
