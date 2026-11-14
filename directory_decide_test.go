//go:build !sidecar_http && !ios_extension

// RECORD-M6-19's decisions over the fake world (FS-100's cases): an approval journaled before it signs, its statement
// filed, its entry appended and its notice rewritten; a kill after the RepoGrant before the entry, and after the entry
// before the rewrite, resumed with the same signed bytes; two approvers at once; a denial that a decision beat; a repo
// approval that finds a denial; a cancel racing an approval both ways; and a rule that asks two approvers.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The world's authorization log, as statements enter it: each filed statement's position, by its bytes.
type testStatementLog struct {
	positions map[string]uint64
	next      uint64
}

// One device's statement filer: signs a new statement each ask, so a resume that signed again would show.
type testStatements struct {
	log        *testStatementLog
	sidecarId  sidecar.Id
	signCount  int
	fileCount  int
	signed     [][]byte
	accesses   []*sidecar.DirectoryRepoAccess
	fileErr    error
	fileErrors int
}

func (self *testStatements) SignRepoAccess(ctx context.Context, access *sidecar.DirectoryRepoAccess) ([]byte, error) {
	self.signCount += 1
	kind := "repo-grant"
	if access.OwnerBound {
		kind = "evs-share"
	}
	signed := []byte(fmt.Sprintf("%s/%s/%s/%s/%d/%d/%d", kind, self.sidecarId, access.RepoId, access.Subject, access.Role, access.ExpiresMillis, self.signCount))
	self.signed = append(self.signed, signed)
	copied := *access
	self.accesses = append(self.accesses, &copied)
	return signed, nil
}

func (self *testStatements) FileStatement(ctx context.Context, signed []byte) (uint64, error) {
	if 0 < self.fileErrors {
		self.fileErrors -= 1
		return 0, self.fileErr
	}
	self.fileCount += 1
	if position, ok := self.log.positions[string(signed)]; ok {
		return position, nil
	}
	self.log.next += 1
	self.log.positions[string(signed)] = self.log.next
	return self.log.next, nil
}

func (self *testStatements) SignReachDecision(ctx context.Context, request *sidecar.StoredApprovalRequest, subject sidecar.Id, expiresMillis int64) ([]byte, error) {
	return nil, errors.New("no reach decision is signed in this test")
}

// What a requester's daemon does with approvals: the world's log, and a vault that records.
type testReceipts struct {
	log      *testStatementLog
	recorded []*sidecar.DirectoryReceipt
	// the vault refuses while set
	recordErr error
}

func (self *testReceipts) StatementHeld(ctx context.Context, statementSha256 []byte, position uint64) (bool, error) {
	for signed, held := range self.log.positions {
		sum := sha256.Sum256([]byte(signed))
		if held == position && bytes.Equal(sum[:], statementSha256) {
			return true, nil
		}
	}
	return false, nil
}

func (self *testReceipts) ActivateReach(ctx context.Context, request *sidecar.StoredApprovalRequest, decisions [][]byte) error {
	return errors.New("no reach approval is spent in this test")
}

func (self *testReceipts) Record(ctx context.Context, receipt *sidecar.DirectoryReceipt) error {
	if self.recordErr != nil {
		return self.recordErr
	}
	self.recorded = append(self.recorded, receipt)
	return nil
}

// A requests env whose devices decide: each with its journal, its statement filer and its receipts.
type testDecideEnv struct {
	*testRequestsEnv
	log        *testStatementLog
	statements map[sidecar.Id]*testStatements
	receipts   map[sidecar.Id]*testReceipts
	ledgers    map[sidecar.Id]*sidecartest.FakeStore
}

func newTestDecideEnv(t *testing.T) *testDecideEnv {
	t.Helper()
	env := &testDecideEnv{
		testRequestsEnv: newTestRequestsEnv(t),
		log:             &testStatementLog{positions: map[string]uint64{}},
		statements:      map[sidecar.Id]*testStatements{},
		receipts:        map[sidecar.Id]*testReceipts{},
		ledgers:         map[sidecar.Id]*sidecartest.FakeStore{},
	}
	env.bind(env.requester)
	env.bind(env.approver)
	return env
}

// Binds device's decisions over its ledger's files, which a restart keeps.
func (self *testDecideEnv) bind(device *testDirectoryDevice) {
	self.t.Helper()
	sidecarId := device.writer.sidecarId
	if self.ledgers[sidecarId] == nil {
		self.ledgers[sidecarId] = sidecartest.NewFakeStore()
		self.statements[sidecarId] = &testStatements{log: self.log, sidecarId: sidecarId}
		self.receipts[sidecarId] = &testReceipts{log: self.log}
	}
	ledger, err := sidecar.NewApprovalLedger(self.ledgers[sidecarId].Root(), sidecar.DefaultSidecarSettings().Mcp, self.world.clock)
	if err != nil {
		self.t.Fatal(err)
	}
	binding := self.binding(device)
	binding.Journal = ledger
	binding.Statements = self.statements[sidecarId]
	binding.Receipts = self.receipts[sidecarId]
	device.client.BindRequests(binding)
}

// A second admin of the env's repo, with its device.
func (self *testDecideEnv) secondApprover() *testDirectoryDevice {
	self.t.Helper()
	writer := self.world.memberWriter(sidecar.NewId())
	repo := self.world.directoryFixture.Repos[self.repoId]
	repo.Admins = append(repo.Admins, sidecartest.FakeDirectoryRepoAdmin{SidecarId: writer.sidecarId, At: self.world.directoryAuth.Tip().Pin().GetVersion() + 1})
	self.world.publish()
	device := self.world.device(writer)
	self.bind(device)
	return device
}

// device's decision on a request after a sync.
func (self *testDecideEnv) decide(device *testDirectoryDevice, requestId sidecar.Id, approve bool) (*sidecar.DirectoryDecided, error) {
	self.t.Helper()
	device.mustSync(self.t)
	return device.client.Decide(self.t.Context(), &sidecar.DirectoryDecideArgs{RequestId: requestId, Approve: approve, Note: "seen"})
}

// A sync and the upkeep it runs, which must succeed.
func (self *testDecideEnv) upkeep(device *testDirectoryDevice) {
	self.t.Helper()
	device.mustSync(self.t)
	if err := device.client.Requests().Maintain(self.t.Context()); err != nil {
		self.t.Fatal(err)
	}
}

// device's decision carried to its end: decided, the entry read back, the notice rewritten.
func (self *testDecideEnv) mustDecide(device *testDirectoryDevice, requestId sidecar.Id, approve bool) *sidecar.DirectoryDecided {
	self.t.Helper()
	decided, err := self.decide(device, requestId, approve)
	if err != nil {
		self.t.Fatal(err)
	}
	if decided.Finished() {
		return decided
	}
	// the rewrite waits for the entry to be read back from this device's own stream
	device.mustSync(self.t)
	decided, err = device.client.Decide(self.t.Context(), &sidecar.DirectoryDecideArgs{RequestId: requestId, Approve: approve})
	if err != nil || !decided.Finished() {
		self.t.Fatalf("decision %+v, %v", decided, err)
	}
	return decided
}

// An approval journals its intent, signs and files the RepoGrant, appends its entry and rewrites the notice to decided,
// approved, naming its entry; the requester reads the notice and the one entry, checks the statement in the log, raises
// access_decided approved, records it and closes the notice.
func TestDirectoryDecideApprovalReachesItsRequester(t *testing.T) {
	env := newTestDecideEnv(t)
	filed := env.mustFile(env.requester, env.ask())
	approverId := env.approver.writer.sidecarId
	decided := env.mustDecide(env.approver, filed.RequestId, true)
	statements := env.statements[approverId]
	if decided.Outcome != sidecar.DirectoryOutcomeApproved || decided.Ended != sidecar.DirectoryDecideWritten || decided.StatementPosition == 0 ||
		statements.signCount != 1 || statements.fileCount != 1 {
		t.Fatalf("decided %+v after %d signatures and %d filings", decided, statements.signCount, statements.fileCount)
	}
	// the grant is the request's: its member, reader, with no expiry since none was asked of a member subject
	if access := statements.accesses[0]; access.RepoId != env.repoId || access.Subject != env.requesterMember || access.OwnerBound ||
		access.Role != uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER) || access.ExpiresMillis != 0 {
		t.Fatalf("access %+v", access)
	}
	env.approver.mustSync(t)
	notice := testNoticeAt(t, env.approver, filed.NoticePath)
	if notice.GetState() != uint32(sidecar.DirectoryNoticeStateDecided) || notice.GetOutcome() != uint32(sidecar.DirectoryOutcomeApproved) ||
		len(notice.GetDecisions()) != 1 || sidecar.Id(notice.GetDecisions()[0].GetDeciderSidecarId()) != approverId {
		t.Fatalf("notice %v", notice)
	}
	view := env.request(env.requester, filed.RequestId)
	if view.State != sidecar.DirectoryRequestApproved || len(view.Decisions) != 1 || !view.Decisions[0].Eligible ||
		!bytes.Equal(view.Decisions[0].Decision.GetStatementSha256(), decided.StatementSha256) ||
		view.Decisions[0].Decision.GetStatementPosition() != decided.StatementPosition ||
		sidecar.Id(view.Decisions[0].Decision.GetSubject()) != env.requesterMember {
		t.Fatalf("the requester's view %+v", view)
	}
	// a decision on a decided notice signs nothing
	second := env.secondApprover()
	if _, err := env.decide(second, filed.RequestId, false); !errors.Is(err, sidecar.ErrDirectoryRequestDecided) {
		t.Fatalf("a denial of a decided request answered %v", err)
	}
	if env.statements[second.writer.sidecarId].signCount != 0 {
		t.Fatal("a decision on a decided notice signed")
	}

	env.upkeep(env.requester)
	requesterId := env.requester.writer.sidecarId
	if events := env.events[requesterId]; len(events) != 1 || events[0] != "access_decided/approved/"+filed.RequestId.String() {
		t.Fatalf("the requester's events %v", events)
	}
	if recorded := env.receipts[requesterId].recorded; len(recorded) != 1 || recorded[0].Outcome != sidecar.SidecarAccessDecidedApproved || len(recorded[0].Decisions) != 1 {
		t.Fatalf("recorded %v", recorded)
	}
	// closed: the notice is removed once recorded, the request still reads approved by its entries, and nothing is
	// raised or recorded twice
	env.upkeep(env.requester)
	if notice := testNoticeAt(t, env.requester, filed.NoticePath); notice != nil {
		t.Fatalf("an approved notice still stands: %v", notice)
	}
	if view := env.request(env.approver, filed.RequestId); view.State != sidecar.DirectoryRequestApproved {
		t.Fatalf("a closed request reads %s", view.State)
	}
	if len(env.events[requesterId]) != 1 || len(env.receipts[requesterId].recorded) != 1 {
		t.Fatalf("received twice: %v", env.events[requesterId])
	}
	// a device that decides nothing for the target, and a read_only one, are refused before anything is journaled
	if _, err := env.decide(env.requester, filed.RequestId, true); !errors.Is(err, sidecar.ErrDirectoryDecideNotEligible) && !errors.Is(err, sidecar.ErrDirectoryRequestDecided) {
		t.Fatalf("the requester's own approval answered %v", err)
	}
}

// A kill after the RepoGrant is signed and journaled, before it is filed and before the entry: the resume files the
// same bytes, signs nothing again, appends the entry and rewrites the notice. A kill after the entry, before the
// rewrite: the resume rewrites alone.
func TestDirectoryDecideResumesWithTheSameSignedBytes(t *testing.T) {
	env := newTestDecideEnv(t)
	filed := env.mustFile(env.requester, env.ask())
	approverId := env.approver.writer.sidecarId
	statements := env.statements[approverId]
	statements.fileErr, statements.fileErrors = errors.New("the api did not answer"), 1
	if decided, err := env.decide(env.approver, filed.RequestId, true); err == nil || decided == nil || decided.Step != sidecar.DirectoryDecideStepStatement {
		t.Fatalf("a filing that failed answered %+v, %v", decided, err)
	}
	if view := env.request(env.requester, filed.RequestId); view.State != sidecar.DirectoryRequestPending || len(view.Decisions) != 0 {
		t.Fatalf("a request whose approval is unfiled reads %s", view.State)
	}
	// the restart: a new part over the same ledger files
	env.bind(env.approver)
	env.approver.mustSync(t)
	if _, err := env.approver.client.ResumeDecisions(t.Context()); err != nil {
		t.Fatal(err)
	}
	if statements.signCount != 1 || statements.fileCount != 1 || len(env.log.positions) != 1 {
		t.Fatalf("%d signatures and %d filings after the resume", statements.signCount, statements.fileCount)
	}
	if _, held := env.log.positions[string(statements.signed[0])]; !held {
		t.Fatal("the resume filed other bytes than the ones journaled")
	}
	// the entry is appended and pushed; the rewrite waits for it to be read back, which the next sync's resume does
	if notice := testNoticeAt(t, env.approver, filed.NoticePath); notice.GetState() != uint32(sidecar.DirectoryNoticeStatePending) {
		t.Fatalf("the notice before the entry is read back: %v", notice)
	}
	env.bind(env.approver)
	env.approver.mustSync(t)
	finished, err := env.approver.client.ResumeDecisions(t.Context())
	if err != nil || finished != 1 {
		t.Fatalf("the second resume finished %d, %v", finished, err)
	}
	if statements.signCount != 1 || statements.fileCount != 1 {
		t.Fatalf("the rewrite's resume signed or filed again: %d, %d", statements.signCount, statements.fileCount)
	}
	view := env.request(env.requester, filed.RequestId)
	if view.State != sidecar.DirectoryRequestApproved || len(view.Decisions) != 1 {
		t.Fatalf("the requester's view after the resumes: %s with %d decisions", view.State, len(view.Decisions))
	}
	// a finished journal is taken up no more
	if finished, err := env.approver.client.ResumeDecisions(t.Context()); err != nil || finished != 0 {
		t.Fatalf("a finished journal resumed: %d, %v", finished, err)
	}
	if writes := env.world.cards.Counts().CardWrites; writes != 2 {
		t.Fatalf("%d notice writes for one request and one decision", writes)
	}
}

// Two approvers at once: both pass the pending check and file their grants; they meet at the notice's rewrite, where
// the second finds it approved and ends a duplicate. A denial that finds it decided is void, shown superseded.
func TestDirectoryDecideTwoApproversAtOnce(t *testing.T) {
	env := newTestDecideEnv(t)
	second := env.secondApprover()
	third := env.secondApprover()
	filed := env.mustFile(env.requester, env.ask())
	first, err := env.decide(env.approver, filed.RequestId, true)
	if err != nil || first.Finished() {
		t.Fatalf("the first approval %+v, %v", first, err)
	}
	other, err := env.decide(second, filed.RequestId, true)
	if err != nil || other.Finished() {
		t.Fatalf("the second approval %+v, %v", other, err)
	}
	denial, err := env.decide(third, filed.RequestId, false)
	if err != nil || denial.Finished() {
		t.Fatalf("the racing denial %+v, %v", denial, err)
	}
	// each reads its entry back and rewrites: the first wins, the others reread
	env.upkeep(env.approver)
	env.upkeep(second)
	env.upkeep(third)
	ended := map[string]int{}
	for _, device := range []*testDirectoryDevice{env.approver, second, third} {
		decided, err := device.client.Decide(t.Context(), &sidecar.DirectoryDecideArgs{RequestId: filed.RequestId, Approve: device != third})
		if err != nil || !decided.Finished() {
			t.Fatalf("a racing decision ended %+v, %v", decided, err)
		}
		ended[decided.Ended] += 1
	}
	if ended[sidecar.DirectoryDecideWritten] != 1 || ended[sidecar.DirectoryDecideDuplicate] != 1 || ended[sidecar.DirectoryDecideSuperseded] != 1 {
		t.Fatalf("the race ended %v", ended)
	}
	view := env.request(env.requester, filed.RequestId)
	if view.State != sidecar.DirectoryRequestApproved || len(view.Notice.GetDecisions()) != 1 ||
		sidecar.Id(view.Notice.GetDecisions()[0].GetDeciderSidecarId()) != env.approver.writer.sidecarId {
		t.Fatalf("the notice after the race: %s, %v", view.State, view.Notice)
	}
	// the duplicate's RepoGrant shows the same access twice in the log
	if len(env.log.positions) != 2 {
		t.Fatalf("%d statements in the log", len(env.log.positions))
	}
	env.upkeep(env.requester)
	if events := env.events[env.requester.writer.sidecarId]; len(events) != 1 || events[0] != "access_decided/approved/"+filed.RequestId.String() {
		t.Fatalf("the requester's events %v", events)
	}
}

// A denial decides the notice, naming the denial alone, and reaches the requester as denied; a repo approval that then
// finds it denied rewrites it to approved naming itself, since its statement is filed and a denial vetoes no eligible
// approval, and the requester, still leasing the denied notice, receives the approval.
func TestDirectoryDecideRepoApprovalOverADenial(t *testing.T) {
	env := newTestDecideEnv(t)
	second := env.secondApprover()
	filed := env.mustFile(env.requester, env.ask())
	denied := env.mustDecide(env.approver, filed.RequestId, false)
	if denied.Outcome != sidecar.DirectoryOutcomeDenied || denied.Ended != sidecar.DirectoryDecideWritten || env.statements[env.approver.writer.sidecarId].signCount != 0 {
		t.Fatalf("denied %+v", denied)
	}
	requesterId := env.requester.writer.sidecarId
	env.upkeep(env.requester)
	if view := env.request(env.requester, filed.RequestId); view.State != sidecar.DirectoryRequestDenied {
		t.Fatalf("a denied request reads %s", view.State)
	}
	if events := env.events[requesterId]; len(events) != 1 || events[0] != "access_decided/denied/"+filed.RequestId.String() {
		t.Fatalf("the requester's events %v", events)
	}
	// a denied notice stays until not_after + 1 d, and its requester still leases it
	if notice := testNoticeAt(t, env.requester, filed.NoticePath); notice == nil {
		t.Fatal("a denied notice was closed at once")
	}
	// a second denial is void
	if _, err := env.decide(second, filed.RequestId, false); !errors.Is(err, sidecar.ErrDirectoryRequestDecided) {
		t.Fatalf("a second denial answered %v", err)
	}
	approved := env.mustDecide(second, filed.RequestId, true)
	if approved.Ended != sidecar.DirectoryDecideWritten {
		t.Fatalf("the approval over a denial ended %q", approved.Ended)
	}
	view := env.request(env.requester, filed.RequestId)
	if view.State != sidecar.DirectoryRequestApproved || len(view.Notice.GetDecisions()) != 1 ||
		sidecar.Id(view.Notice.GetDecisions()[0].GetDeciderSidecarId()) != second.writer.sidecarId {
		t.Fatalf("the notice after the approval: %s, %v", view.State, view.Notice)
	}
	env.upkeep(env.requester)
	if events := env.events[requesterId]; len(events) != 2 || events[1] != "access_decided/approved/"+filed.RequestId.String() {
		t.Fatalf("the requester's events %v", events)
	}
}

// A cancel racing an approval, both ways: a cancel that lands first removes the pending notice, so the approval's
// rewrite finds it gone and the request reads cancelled; a cancel that a decided rewrite beat fails and shows that
// decision.
func TestDirectoryCancelRacingApproval(t *testing.T) {
	env := newTestDecideEnv(t)
	// the cancel first
	first := env.mustFile(env.requester, env.ask())
	racing, err := env.decide(env.approver, first.RequestId, true)
	if err != nil || racing.Finished() {
		t.Fatalf("the approval %+v, %v", racing, err)
	}
	env.requester.mustSync(t)
	if err := env.requester.client.Cancel(t.Context(), first.RequestId); err != nil {
		t.Fatal(err)
	}
	env.upkeep(env.approver)
	ended, err := env.approver.client.Decide(t.Context(), &sidecar.DirectoryDecideArgs{RequestId: first.RequestId, Approve: true})
	if err != nil || ended.Ended != sidecar.DirectoryDecideGone {
		t.Fatalf("an approval whose notice was cancelled ended %+v, %v", ended, err)
	}
	for _, device := range []*testDirectoryDevice{env.requester, env.approver} {
		if view := env.request(device, first.RequestId); view.State != sidecar.DirectoryRequestCancelled {
			t.Fatalf("a cancelled request reads %s", view.State)
		}
	}
	env.upkeep(env.requester)
	if events := env.events[env.requester.writer.sidecarId]; len(events) != 1 || events[0] != "access_decided/cancelled/"+first.RequestId.String() {
		t.Fatalf("the requester's events %v", events)
	}
	if _, err := env.decide(env.approver, first.RequestId, false); !errors.Is(err, sidecar.ErrDirectoryRequestDecided) {
		t.Fatalf("a decision on a cancelled request answered %v", err)
	}

	// the approval first: the requester, not yet synced, cancels from the pending version it read
	second := env.mustFile(env.requester, env.ask())
	env.requester.mustSync(t)
	env.mustDecide(env.approver, second.RequestId, true)
	if err := env.requester.client.Cancel(t.Context(), second.RequestId); !errors.Is(err, sidecar.ErrDirectoryCancelBeaten) {
		t.Fatalf("a cancel that an approval beat answered %v", err)
	}
	for _, device := range []*testDirectoryDevice{env.requester, env.approver} {
		if view := env.request(device, second.RequestId); view.State != sidecar.DirectoryRequestApproved {
			t.Fatalf("a request whose cancel was beaten reads %s", view.State)
		}
	}
	// another's cancel is none
	if err := env.approver.client.Cancel(t.Context(), second.RequestId); !errors.Is(err, sidecar.ErrDirectoryDecideNotEligible) {
		t.Fatalf("an approver's cancel answered %v", err)
	}
}

// With no statement filer bound an approval refuses before anything is journaled and a denial still decides; with no
// journal nothing is decided.
func TestDirectoryDecideFailsClosedUnbound(t *testing.T) {
	env := newTestDecideEnv(t)
	filed := env.mustFile(env.requester, env.ask())
	binding := env.binding(env.approver)
	env.approver.client.BindRequests(binding)
	if _, err := env.decide(env.approver, filed.RequestId, false); !errors.Is(err, sidecar.ErrDirectoryJournalUnbound) {
		t.Fatalf("a decision with no journal answered %v", err)
	}
	ledger, err := sidecar.NewApprovalLedger(env.ledgers[env.approver.writer.sidecarId].Root(), sidecar.DefaultSidecarSettings().Mcp, env.world.clock)
	if err != nil {
		t.Fatal(err)
	}
	binding.Journal = ledger
	env.approver.client.BindRequests(binding)
	if _, err := env.decide(env.approver, filed.RequestId, true); !errors.Is(err, sidecar.ErrDirectoryStatementsUnbound) {
		t.Fatalf("an approval with no statement filer answered %v", err)
	}
	if paths := env.ledgers[env.approver.writer.sidecarId].Paths(); len(paths) != 0 {
		t.Fatalf("a refused approval journaled %v", paths)
	}
	if denied := env.mustDecide(env.approver, filed.RequestId, false); denied.Ended != sidecar.DirectoryDecideWritten {
		t.Fatalf("denied %+v", denied)
	}
}

// A detail sealer that encrypts nothing: the detail's bytes in a sealed body's layout (a generation, a nonce's place,
// whole padded blocks and a tag's place), which the test's opener reads back. The real one is Sidecar's, under the
// config repo's key.
type testDetailSeal struct{}

const (
	testDetailSealHeaderByteCount = 8 + 24
	testDetailSealBlockByteCount  = 256
	testDetailSealTagByteCount    = 16
)

func (testDetailSeal) SealActionDetail(ctx context.Context, clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail) (*sidecar.StoredCanonicalAction, error) {
	body, err := proto.Marshal(detail)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, testDetailSealHeaderByteCount)
	binary.BigEndian.PutUint64(sealed, 1)
	padded := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	padded = append(padded, body...)
	if remainder := len(padded) % testDetailSealBlockByteCount; remainder != 0 {
		padded = append(padded, make([]byte, testDetailSealBlockByteCount-remainder)...)
	}
	sealed = append(sealed, padded...)
	sealed = append(sealed, make([]byte, testDetailSealTagByteCount)...)
	action := proto.Clone(clear).(*protocol.CanonicalAction)
	action.SealedDetail = sealed
	return sidecar.NewCanonicalAction(action)
}

func (testDetailSeal) OpenActionDetail(action *sidecar.StoredCanonicalAction) (*protocol.CanonicalActionDetail, error) {
	sealed := action.Action.GetSealedDetail()
	if len(sealed) < testDetailSealHeaderByteCount+4+testDetailSealTagByteCount {
		return nil, errors.New("no sealed detail")
	}
	padded := sealed[testDetailSealHeaderByteCount : len(sealed)-testDetailSealTagByteCount]
	byteCount := int(binary.BigEndian.Uint32(padded))
	if len(padded)-4 < byteCount {
		return nil, errors.New("a sealed detail cut short")
	}
	detail := &protocol.CanonicalActionDetail{}
	if err := proto.Unmarshal(padded[4:4+byteCount], detail); err != nil {
		return nil, err
	}
	return detail, nil
}

// A reach decision signer: a device ApprovalDecision on the request as stored, signed by the decider's key, each sign
// counted.
type testReachStatements struct {
	*testStatements
	world      *testDirectoryWorld
	key        ed25519.PrivateKey
	memberId   sidecar.Id
	reachCount int
}

func (self *testReachStatements) SignReachDecision(ctx context.Context, request *sidecar.StoredApprovalRequest, subject sidecar.Id, expiresMillis int64) ([]byte, error) {
	self.reachCount += 1
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	decision := &protocol.ApprovalDecision{
		ApprovalId:         request.Request.GetApprovalId(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     request.Request.GetNotAfterMillis(),
		ApproverMemberId:   self.memberId.Bytes(),
		Channel:            uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
		RequesterSidecarId: request.Request.GetRequesterSidecarId(),
		AuthPin:            self.world.directoryAuth.Tip().Pin(),
		Version:            1,
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(decision)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(&bridge.Signed{
		Body:      body,
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
	})
}

// A requester's spend of a reach approval, counted.
type testReachReceipts struct {
	*testReceipts
	activated [][][]byte
}

func (self *testReachReceipts) ActivateReach(ctx context.Context, request *sidecar.StoredApprovalRequest, decisions [][]byte) error {
	self.activated = append(self.activated, decisions)
	return nil
}

// A rule that asks two approvers (FS-100): a worker's port, announced, requested by the spending sidecar with its port
// sealed in the action's detail. The first approval leaves the notice pending with one DecisionRef and spends nothing;
// the second decides it with both; the requester takes both decisions and spends once. An approver whose worker no
// longer announces the port signs nothing (owner decision 179), and no reach approval files a statement.
func TestDirectoryDecideTwoApproverReachRule(t *testing.T) {
	env := newTestDecideEnv(t)
	secondMember := sidecar.NewId()
	secondWriter := env.world.memberWriter(secondMember)
	workerWriter := env.world.memberWriter(sidecar.NewId())
	target := &protocol.RequestTarget{SidecarId: workerWriter.sidecarId.Bytes(), TcpPorts: []uint32{8080}}
	targetText, err := sidecar.DirectoryNoticeTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	if env.world.directoryFixture.ReachApprovers == nil {
		env.world.directoryFixture.ReachApprovers = map[string]*sidecar.DirectoryApprovers{}
	}
	env.world.directoryFixture.ReachApprovers[targetText] = &sidecar.DirectoryApprovers{MemberIds: []sidecar.Id{env.approverMember, secondMember}, Count: 2}
	env.world.publish()

	// the worker announces its port
	worker := env.world.device(workerWriter)
	serving := &testWorkerServices{serving: &sidecar.DirectoryWorkerServing{
		Services: []*sidecar.DirectoryWorkerService{{Kind: sidecar.DirectoryServiceKindBridgePort, Name: "tcp:8080", Description: "a dev server"}},
	}}
	worker.client.BindWorker(&sidecar.DirectoryWorkerBinding{
		Host:        sidecar.DirectoryWorkerHostDaemon,
		Services:    serving,
		TeamWorkers: func() (bool, bool) { return true, true },
	})
	if _, err := worker.client.Worker().Maintain(t.Context()); err != nil {
		t.Fatal(err)
	}
	worker.flush(t)

	second := env.world.device(secondWriter)
	reach := map[sidecar.Id]*testReachStatements{}
	for _, device := range []*testDirectoryDevice{env.requester, env.approver, second} {
		env.bind(device)
		sidecarId := device.writer.sidecarId
		memberId, _ := env.world.directoryAuth.Tip().MemberOf(sidecarId)
		reach[sidecarId] = &testReachStatements{testStatements: env.statements[sidecarId], world: env.world, key: device.writer.key, memberId: memberId}
		ledger, err := sidecar.NewApprovalLedger(env.ledgers[sidecarId].Root(), sidecar.DefaultSidecarSettings().Mcp, env.world.clock)
		if err != nil {
			t.Fatal(err)
		}
		binding := env.binding(device)
		binding.Journal, binding.Statements, binding.Receipts = ledger, reach[sidecarId], env.receipts[sidecarId]
		binding.Sealer, binding.Opener = testDetailSeal{}, testDetailSeal{}
		device.client.BindRequests(binding)
	}
	spent := &testReachReceipts{testReceipts: env.receipts[env.requester.writer.sidecarId]}
	requesterBinding := env.binding(env.requester)
	requesterBinding.Sealer, requesterBinding.Opener, requesterBinding.Receipts = testDetailSeal{}, testDetailSeal{}, spent
	env.requester.client.BindRequests(requesterBinding)

	env.requester.mustSync(t)
	ask := env.ask()
	ask.Target, ask.Role = target, uint32(protocol.AclAction_ACL_ACTION_DIAL)
	filed := env.mustFile(env.requester, ask)
	requesterId := env.requester.writer.sidecarId
	if filed.Subject != requesterId || filed.SubjectIsMember {
		t.Fatalf("a reach request's subject is %s, member %t", filed.Subject, filed.SubjectIsMember)
	}

	first := env.mustDecide(env.approver, filed.RequestId, true)
	if first.Ended != sidecar.DirectoryDecideWritten {
		t.Fatalf("the first approval ended %+v", first)
	}
	view := env.request(env.requester, filed.RequestId)
	if view.State != sidecar.DirectoryRequestPending || view.Notice.GetState() != uint32(sidecar.DirectoryNoticeStatePending) || len(view.Notice.GetDecisions()) != 1 {
		t.Fatalf("after one of two approvals: %s, %v", view.State, view.Notice)
	}
	env.upkeep(env.requester)
	if len(spent.activated) != 0 || len(env.events[requesterId]) != 0 {
		t.Fatalf("one of two approvals was spent: %v", env.events[requesterId])
	}
	// the approver's same decision again is the one it journaled: nothing is signed or added
	again, err := env.decide(env.approver, filed.RequestId, true)
	if err != nil || !again.Finished() || reach[env.approver.writer.sidecarId].reachCount != 1 {
		t.Fatalf("the approver's decision again: %+v, %v", again, err)
	}
	if view := env.request(env.requester, filed.RequestId); len(view.Notice.GetDecisions()) != 1 {
		t.Fatalf("one approver counted twice: %v", view.Notice)
	}

	// the worker drops the port: the second approver signs nothing
	serving.serving = &sidecar.DirectoryWorkerServing{}
	if _, err := worker.client.Worker().Maintain(t.Context()); err != nil {
		t.Fatal(err)
	}
	worker.flush(t)
	secondId := second.writer.sidecarId
	if _, err := env.decide(second, filed.RequestId, true); !errors.Is(err, sidecar.ErrDirectoryDecideServices) {
		t.Fatalf("an approval of a port no longer announced answered %v", err)
	}
	if reach[secondId].reachCount != 0 {
		t.Fatal("an approval of an unannounced service signed")
	}
	serving.serving = &sidecar.DirectoryWorkerServing{
		Services: []*sidecar.DirectoryWorkerService{{Kind: sidecar.DirectoryServiceKindBridgePort, Name: "tcp:8080", Description: "a dev server"}},
	}
	if _, err := worker.client.Worker().Maintain(t.Context()); err != nil {
		t.Fatal(err)
	}
	worker.flush(t)

	last := env.mustDecide(second, filed.RequestId, true)
	if last.Ended != sidecar.DirectoryDecideWritten {
		t.Fatalf("the second approval ended %+v", last)
	}
	view = env.request(env.requester, filed.RequestId)
	if view.State != sidecar.DirectoryRequestApproved || len(view.Notice.GetDecisions()) != 2 {
		t.Fatalf("after both approvals: %s, %v", view.State, view.Notice)
	}
	env.upkeep(env.requester)
	if len(spent.activated) != 1 || len(spent.activated[0]) != 2 {
		t.Fatalf("the spend took %v", spent.activated)
	}
	if events := env.events[requesterId]; len(events) != 1 || events[0] != "access_decided/approved/"+filed.RequestId.String() {
		t.Fatalf("the requester's events %v", events)
	}
	// a reach approval files no statement, and a third approval of a decided notice is void, never spent
	if len(env.log.positions) != 0 || reach[env.approver.writer.sidecarId].reachCount != 1 || reach[secondId].reachCount != 1 {
		t.Fatalf("%d statements filed; signed %d and %d", len(env.log.positions), reach[env.approver.writer.sidecarId].reachCount, reach[secondId].reachCount)
	}
	env.upkeep(env.requester)
	if len(spent.activated) != 1 {
		t.Fatal("a reach approval was spent twice")
	}
}
