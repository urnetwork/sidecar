// MAIL-M7-15's ingest on the mail store's stand-in and a deposit world in memory: a message and its row in one push,
// the crash points either side of the CONSUME (FS-13's core), racing readers, the evidence and signer checks, the
// depositor classes, erased and unopened deposits, same-network mail and a group's references.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const (
	testMailIngestRoot      = "root.example"
	testMailIngestRecipient = "bo@acme.root.example"
	// 2026-11-10T12:00:00Z, the sealed receive time of the test deposits.
	testMailIngestReceiveMillis = uint64(1794312000000)
	// 2026-12-02T00:00:00Z, their pushes' time, in the next month.
	testMailIngestPushMillis = int64(1796169600000)
)

// One standing deposit of the test repo.
type mailIngestTestDeposit struct {
	id        Id
	version   uint64
	signerId  Id
	plaintext []byte
	// its slot's key is gone, so it does not open
	slotGone bool
	// the slot its key sits in
	slotId Id
	// it fails to open with this, as a transport would
	openErr error
	pin     *bridge.AuthPin
}

// One CONSUME the test repo took.
type mailIngestTestConsume struct {
	depositorId     Id
	depositIds      []Id
	consumedThrough uint64
}

// A mail repo's deposit refs and erasure ref in memory.
type mailIngestTestRepo struct {
	stateLock sync.Mutex
	// each depositor's standing deposits, oldest first, and its ref's version
	standing map[Id][]*mailIngestTestDeposit
	versions map[Id]uint64
	erasures []*EvsErasure
	consumes []*mailIngestTestConsume
	// the next CONSUME fails with this before it commits, once
	failConsumeBefore error
	// the next CONSUME commits and then answers this, once: an answer lost
	failConsumeAfter error
	wake             func()
	// whether a slot still holds its key; nil holds every one
	slotHeld func(slotId Id) bool
	// called with each new deposit's slot, with no lock of the repo's held
	onDeposit func(slotId Id)
	// the repo's erasure ref where another stand-in keeps it; nil reads erasures
	erasureSource func(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error)
}

func newMailIngestTestRepo() *mailIngestTestRepo {
	return &mailIngestTestRepo{standing: map[Id][]*mailIngestTestDeposit{}, versions: map[Id]uint64{}}
}

// A deposit of plaintext by depositorId, signed by signerId.
func (self *mailIngestTestRepo) deposit(depositorId Id, signerId Id, plaintext []byte) *mailIngestTestDeposit {
	deposit, onDeposit := func() (*mailIngestTestDeposit, func(slotId Id)) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.versions[depositorId] += 1
		deposit := &mailIngestTestDeposit{id: NewId(), version: self.versions[depositorId], signerId: signerId, plaintext: plaintext, slotId: NewEvsSlotId()}
		self.standing[depositorId] = append(self.standing[depositorId], deposit)
		return deposit, self.onDeposit
	}()
	if onDeposit != nil {
		onDeposit(deposit.slotId)
	}
	return deposit
}

// A committed ERASE with note.
func (self *mailIngestTestRepo) erase(erasureId Id, note []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.erasures = append(self.erasures, &EvsErasure{Version: uint64(len(self.erasures) + 1), ErasureId: erasureId, Note: note, Complete: true})
}

func (self *mailIngestTestRepo) standingCount(depositorId Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.standing[depositorId])
}

func (self *mailIngestTestRepo) Depositors(ctx context.Context) ([]Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	depositorIds := []Id{}
	for depositorId := range self.versions {
		depositorIds = append(depositorIds, depositorId)
	}
	slices.SortFunc(depositorIds, func(a Id, b Id) int { return a.Cmp(b) })
	return depositorIds, nil
}

func (self *mailIngestTestRepo) ReadDeposits(ctx context.Context, depositorId Id, afterVersion uint64, visit func(deposit *EvsDeposit, body io.Reader) error) error {
	standing := func() []*mailIngestTestDeposit {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return slices.Clone(self.standing[depositorId])
	}()
	for _, deposit := range standing {
		if deposit.version <= afterVersion {
			continue
		}
		evsDeposit := &EvsDeposit{
			EntryId: EvsToken(deposit.id), Version: deposit.version, SignerSidecarId: deposit.signerId,
			Time: time.UnixMilli(testMailIngestPushMillis).UTC(), AuthPin: deposit.pin,
		}
		if deposit.slotGone || (self.slotHeld != nil && !self.slotHeld(deposit.slotId)) {
			return &EvsDepositOpenError{Deposit: evsDeposit, Err: ErrEvsSealInvalid}
		}
		if deposit.openErr != nil {
			return &EvsDepositOpenError{Deposit: evsDeposit, Err: deposit.openErr}
		}
		evsDeposit.SlotId = deposit.slotId
		if err := visit(evsDeposit, bytes.NewReader(deposit.plaintext)); err != nil {
			return err
		}
	}
	return nil
}

func (self *mailIngestTestRepo) Consume(ctx context.Context, depositorId Id, depositIds []Id, consumedThrough uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.failConsumeBefore; err != nil {
		self.failConsumeBefore = nil
		return err
	}
	self.consumes = append(self.consumes, &mailIngestTestConsume{depositorId: depositorId, depositIds: slices.Clone(depositIds), consumedThrough: consumedThrough})
	self.standing[depositorId] = slices.DeleteFunc(self.standing[depositorId], func(deposit *mailIngestTestDeposit) bool {
		return slices.Contains(depositIds, deposit.id)
	})
	if err := self.failConsumeAfter; err != nil {
		self.failConsumeAfter = nil
		return err
	}
	return nil
}

func (self *mailIngestTestRepo) Erasures(ctx context.Context, afterVersion uint64) ([]*EvsErasure, error) {
	if self.erasureSource != nil {
		return self.erasureSource(ctx, afterVersion)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	erasures := []*EvsErasure{}
	for _, erasure := range self.erasures {
		if afterVersion < erasure.Version {
			erasures = append(erasures, erasure)
		}
	}
	return erasures, nil
}

func (self *mailIngestTestRepo) Watch(ctx context.Context, wake func()) (func(), error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.wake = wake
	return func() {}, nil
}

// §8's answers as a test sets them: every depositor's deposits are mail unless classed otherwise.
type mailIngestTestAuthority struct {
	stateLock sync.Mutex
	notReader bool
	classes   map[Id]MailDepositorClass
	// each (signer, From address) that may send
	maySend map[string]bool
}

func (self *mailIngestTestAuthority) Ingests(repoId Id, sidecarId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return !self.notReader
}

func (self *mailIngestTestAuthority) DepositorClass(repoId Id, depositorId Id, pin *bridge.AuthPin) MailDepositorClass {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if class, ok := self.classes[depositorId]; ok {
		return class
	}
	return MailDepositorMail
}

func (self *mailIngestTestAuthority) MaySendAs(signerSidecarId Id, fromAddress string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.maySend[signerSidecarId.String()+" "+fromAddress]
}

// A mailbox, its deposit refs and one reader device.
type mailIngestTestWorld struct {
	t          *testing.T
	repoId     Id
	store      *mailTestStore
	repo       *mailIngestTestRepo
	authority  *mailIngestTestAuthority
	receiverId Id
	messages   []*MailMessage
	alarms     []*MailIngestAlarm
}

func newMailIngestTestWorld(t *testing.T) *mailIngestTestWorld {
	return &mailIngestTestWorld{
		t: t, repoId: NewId(), store: newMailTestStore(), repo: newMailIngestTestRepo(),
		authority:  &mailIngestTestAuthority{classes: map[Id]MailDepositorClass{}, maySend: map[string]bool{}},
		receiverId: NewId(),
	}
}

// A reader device's ingestor over the world's stores, as a restart or another device makes one.
func (self *mailIngestTestWorld) ingestor(mutate func(args *MailIngestArgs)) *MailIngestor {
	args := &MailIngestArgs{
		SidecarId: NewId(), Root: testMailIngestRoot, Authority: self.authority,
		Message: func(message *MailMessage) { self.messages = append(self.messages, message) },
		Alarm:   func(alarm *MailIngestAlarm) { self.alarms = append(self.alarms, alarm) },
	}
	if mutate != nil {
		mutate(args)
	}
	return newMailIngestor(self.repoId, self.repo, self.store, args)
}

func (self *mailIngestTestWorld) ingest(ingestor *MailIngestor) *MailIngestPass {
	self.t.Helper()
	pass, err := ingestor.Ingest(context.Background())
	if err != nil {
		self.t.Fatal(err)
	}
	return pass
}

// The m/ paths that stand, and the i/ rows of the test month.
func (self *mailIngestTestWorld) messagePaths() []string {
	paths := []string{}
	for _, path := range self.store.paths() {
		if strings.HasPrefix(path, "m/") {
			paths = append(paths, path)
		}
	}
	return paths
}

func (self *mailIngestTestWorld) entries(month MailYearMonth) []*protocol.IndexEntry {
	self.t.Helper()
	entries := []*protocol.IndexEntry{}
	for n := uint64(0); ; n += 1 {
		file := self.store.file(MailIndexPath(month, n))
		if file == nil {
			return entries
		}
		segment := &protocol.MailIndexSegment{}
		if err := proto.Unmarshal(file.content, segment); err != nil {
			self.t.Fatal(err)
		}
		entries = append(entries, segment.GetEntries()...)
	}
}

func (self *mailIngestTestWorld) alarmKinds() []MailIngestAlarmKind {
	kinds := []MailIngestAlarmKind{}
	for _, alarm := range self.alarms {
		kinds = append(kinds, alarm.Kind)
	}
	return kinds
}

func testMailIngestMessage(subject string, body string) []byte {
	return []byte("From: Ada <ada@sender.example>\r\nTo: " + testMailIngestRecipient + "\r\nSubject: " + subject +
		"\r\nMessage-ID: <" + strings.ReplaceAll(strings.ToLower(subject), " ", "-") + "@sender.example>\r\n\r\n" + body + "\r\n")
}

// A receiver's trailer for message, its evidence naming the message and the receiver.
func testMailIngestTrailer(receiverId Id, message []byte) *protocol.MailDeposit {
	messageSha256 := sha256.Sum256(message)
	return &protocol.MailDeposit{
		Version: mailFormatVersion,
		Ingress: &protocol.MailIngress{
			Version: mailFormatVersion, SenderIp: []byte{192, 0, 2, 7}, SenderPort: 4025, Sni: "mx.acme.root.example",
			EhloName: "out.sender.example", ReceiveTimeMillis: testMailIngestReceiveMillis - 5,
		},
		Evidence: &protocol.MailAuthEvidence{
			Version: mailFormatVersion, MessageSha256: messageSha256[:], ReceiveTimeMillis: testMailIngestReceiveMillis,
			ReceiverSidecarId: receiverId.Bytes(),
			Spf:               &protocol.SpfResult{Result: protocol.SpfVerdict_SPF_PASS, Domain: "sender.example"},
			Dkim:              []*protocol.DkimResult{{Domain: "sender.example", Selector: "s1", Result: protocol.DkimVerdict_DKIM_PASS}},
			Dmarc:             &protocol.DmarcResult{Result: protocol.DmarcVerdict_DMARC_PASS},
		},
		MailFrom:          []byte("bounce@sender.example"),
		Recipients:        []string{testMailIngestRecipient},
		TlsVersion:        0x0304,
		TlsSuite:          0x1301,
		ReceiverSidecarId: receiverId.Bytes(),
	}
}

func testMailIngestPlaintext(t *testing.T, message []byte, trailer *protocol.MailDeposit) []byte {
	t.Helper()
	plaintext, err := MailDepositPlaintext(message, trailer)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

// A receiver's well-formed deposit of message in the world's mailbox.
func (self *mailIngestTestWorld) depositMessage(message []byte) *mailIngestTestDeposit {
	self.t.Helper()
	return self.repo.deposit(self.receiverId, self.receiverId, testMailIngestPlaintext(self.t, message, testMailIngestTrailer(self.receiverId, message)))
}

// A deposit's plaintext splits back into its message and trailer, and each malformed tail is refused as its kind.
func TestMailSplitDepositTakesTheTrailerFromTheTail(t *testing.T) {
	message := testMailIngestMessage("Hello", "body")
	trailer := testMailIngestTrailer(NewId(), message)
	plaintext := testMailIngestPlaintext(t, message, trailer)
	gotMessage, gotTrailer, err := mailSplitDeposit(plaintext, 64*1024)
	if err != nil || !bytes.Equal(gotMessage, message) || !proto.Equal(gotTrailer, trailer) {
		t.Fatalf("split: %v", err)
	}
	if _, _, err := mailSplitDeposit(plaintext, 16); !errors.Is(err, ErrMailDepositInvalid) {
		t.Errorf("a trailer past its bound: %v", err)
	}
	if _, _, err := mailSplitDeposit([]byte{1, 2, 3}, 64*1024); !errors.Is(err, ErrMailDepositInvalid) {
		t.Errorf("no length: %v", err)
	}
	if _, _, err := mailSplitDeposit(append([]byte("message"), 0, 0, 1, 0), 64*1024); !errors.Is(err, ErrMailDepositInvalid) {
		t.Errorf("a length past the plaintext: %v", err)
	}
	if _, _, err := mailSplitDeposit(append([]byte("message"), 0xff, 0xff, 0, 0, 0, 2), 64*1024); !errors.Is(err, ErrMailDepositInvalid) {
		t.Errorf("a trailer that does not decode: %v", err)
	}
	for _, version := range []uint32{0, 2} {
		other := proto.CloneOf(trailer)
		other.Version = version
		if _, _, err := mailSplitDeposit(testMailIngestPlaintext(t, message, other), 64*1024); !errors.Is(err, ErrMailDepositVersion) {
			t.Errorf("version %d: %v", version, err)
		}
	}
	if _, err := mailReadDeposit(bytes.NewReader(plaintext), int64(len(plaintext))-1); !errors.Is(err, ErrMailDepositTooLarge) {
		t.Errorf("past the bound: %v", err)
	}
	if read, err := mailReadDeposit(bytes.NewReader(plaintext), int64(len(plaintext))); err != nil || !bytes.Equal(read, plaintext) {
		t.Errorf("at the bound: %v", err)
	}
}

// A deposit becomes one message: m/ and its i/ row in one push, under the sealed receive time's month and the
// deposit's id, ingest's headers above the bytes as received, the row from the sealed evidence, then one CONSUME.
// A second pass finds nothing to do.
func TestMailIngestWritesTheMessageAndItsRowInOnePush(t *testing.T) {
	world := newMailIngestTestWorld(t)
	message := testMailIngestMessage("Your code", "Your verification code is 482913.")
	deposit := world.depositMessage(message)
	ingestor := world.ingestor(nil)

	writesBefore := world.store.writeCount
	pass := world.ingest(ingestor)
	if pass.Ingested != 1 || pass.Consumed != 1 || pass.Present+pass.Erased+pass.Refused+pass.Left != 0 {
		t.Fatalf("pass %+v", pass)
	}
	if world.store.writeCount != writesBefore+1 {
		t.Errorf("%d pushes for one message", world.store.writeCount-writesBefore)
	}
	// the month is the sealed receive time's, not the push's
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	if month != 202611 {
		t.Fatalf("month %d", month)
	}
	file := world.store.file(MailMessagePath(month, deposit.id))
	if file == nil {
		t.Fatalf("no m/ file among %v", world.store.paths())
	}
	if !bytes.HasSuffix(file.content, message) {
		t.Error("m/ does not end with the message as received")
	}
	headers := string(file.content[:len(file.content)-len(message)])
	if !strings.HasPrefix(headers, "Authentication-Results: mx.acme.root.example;") || !strings.Contains(headers, "spf=pass") ||
		!strings.Contains(headers, "dkim=pass") || !strings.Contains(headers, "dmarc=pass") || !strings.Contains(headers, "\r\nReceived: from out.sender.example") {
		t.Errorf("ingest headers %q", headers)
	}
	entries := world.entries(month)
	if len(entries) != 1 {
		t.Fatalf("%d rows", len(entries))
	}
	entry := entries[0]
	if !bytes.Equal(entry.GetId(), deposit.id.Bytes()) || entry.GetAddress() != testMailIngestRecipient || entry.GetTime() != testMailIngestReceiveMillis ||
		entry.GetSubject() != "Your code" || entry.GetSize() != uint64(len(message)) || entry.GetOneTimeCode() != "482913" {
		t.Errorf("row %+v", entry)
	}
	results := entry.GetAuthResults()
	if results.GetSpf() != protocol.SpfVerdict_SPF_PASS || results.GetDkim() != protocol.DkimVerdict_DKIM_PASS ||
		results.GetDmarc() != protocol.DmarcVerdict_DMARC_PASS || results.GetEvidenceUnavailable() {
		t.Errorf("auth results %+v", results)
	}
	if entry.GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC || !MailEntryUntrusted(entry) {
		t.Errorf("label %v", entry.GetTlsLabel())
	}
	if len(world.messages) != 1 || world.messages[0].Id != deposit.id || !world.messages[0].Untrusted || world.messages[0].Month != month {
		t.Errorf("messages %+v", world.messages)
	}
	if len(world.repo.consumes) != 1 || !slices.Equal(world.repo.consumes[0].depositIds, []Id{deposit.id}) || world.repo.consumes[0].consumedThrough != deposit.version {
		t.Errorf("consumes %+v", world.repo.consumes)
	}
	if world.repo.standingCount(world.receiverId) != 0 || len(world.alarms) != 0 {
		t.Errorf("standing %d, alarms %v", world.repo.standingCount(world.receiverId), world.alarmKinds())
	}

	again := world.ingest(ingestor)
	if *again != (MailIngestPass{}) || world.store.writeCount != writesBefore+1 {
		t.Errorf("a second pass %+v", again)
	}
}

// FS-13's core: a kill between the push and the CONSUME leaves the deposit, and a restarted ingest finds m/ standing
// and only consumes, writing no second message or row.
func TestMailIngestKilledBeforeConsumeOnlyConsumesAfterRestart(t *testing.T) {
	world := newMailIngestTestWorld(t)
	deposit := world.depositMessage(testMailIngestMessage("Hello", "body"))
	killed := errors.New("killed before the CONSUME")
	world.repo.failConsumeBefore = killed
	pass, err := world.ingestor(nil).Ingest(context.Background())
	if !errors.Is(err, killed) || pass.Ingested != 1 || pass.Consumed != 0 {
		t.Fatalf("the killed pass: %+v, %v", pass, err)
	}
	if world.repo.standingCount(world.receiverId) != 1 {
		t.Fatal("the deposit did not survive the kill")
	}
	writes := world.store.writeCount

	restarted := world.ingest(world.ingestor(nil))
	if restarted.Present != 1 || restarted.Ingested != 0 || restarted.Consumed != 1 {
		t.Fatalf("the restarted pass: %+v", restarted)
	}
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	if len(world.messagePaths()) != 1 || len(world.entries(month)) != 1 || world.store.file(MailMessagePath(month, deposit.id)).version != 1 {
		t.Errorf("after the restart: %v, %d rows", world.messagePaths(), len(world.entries(month)))
	}
	if world.store.writeCount != writes+1 {
		// the restart's one refused create
		t.Errorf("%d writes after the restart", world.store.writeCount-writes)
	}
	if world.repo.standingCount(world.receiverId) != 0 || len(world.messages) != 1 {
		t.Errorf("standing %d, %d message callbacks", world.repo.standingCount(world.receiverId), len(world.messages))
	}
}

// FS-13's core: a kill between the CONSUME's commit and its answer leaves no deposit, and a restarted ingest
// recreates nothing.
func TestMailIngestKilledAfterConsumeCommitRecreatesNothing(t *testing.T) {
	world := newMailIngestTestWorld(t)
	world.depositMessage(testMailIngestMessage("Hello", "body"))
	killed := errors.New("killed after the CONSUME committed")
	world.repo.failConsumeAfter = killed
	if _, err := world.ingestor(nil).Ingest(context.Background()); !errors.Is(err, killed) {
		t.Fatalf("the killed pass: %v", err)
	}
	writes := world.store.writeCount
	restarted := world.ingest(world.ingestor(nil))
	if *restarted != (MailIngestPass{}) || world.store.writeCount != writes {
		t.Errorf("the restarted pass: %+v", restarted)
	}
	if len(world.messagePaths()) != 1 || len(world.entries(MailYearMonthOf(testMailIngestReceiveMillis))) != 1 {
		t.Errorf("after the restart: %v", world.messagePaths())
	}
}

// Two readers racing one deposit leave one message: the second's whole ingest lands between the first's read of i/
// and its push, so the first meets the conflict on m/ and only consumes.
func TestMailIngestRacingReadersLeaveOneMessage(t *testing.T) {
	world := newMailIngestTestWorld(t)
	deposit := world.depositMessage(testMailIngestMessage("Hello", "body"))
	first := world.ingestor(nil)
	second := world.ingestor(nil)
	var secondPass *MailIngestPass
	world.store.beforeWrite = func() {
		pass, err := second.Ingest(context.Background())
		if err != nil {
			t.Error(err)
		}
		secondPass = pass
	}
	firstPass := world.ingest(first)
	if secondPass == nil || secondPass.Ingested != 1 || secondPass.Consumed != 1 {
		t.Fatalf("the reader that won: %+v", secondPass)
	}
	if firstPass.Present != 1 || firstPass.Ingested != 0 || firstPass.Consumed != 1 {
		t.Fatalf("the reader that lost: %+v", firstPass)
	}
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	entries := world.entries(month)
	if len(world.messagePaths()) != 1 || len(entries) != 1 || !bytes.Equal(entries[0].GetId(), deposit.id.Bytes()) {
		t.Errorf("after the race: %v, %d rows", world.messagePaths(), len(entries))
	}
	if len(world.messages) != 1 {
		t.Errorf("%d message callbacks", len(world.messages))
	}
}

// Tampered evidence fails: evidence naming another message's hash, another receiver or another version is dropped,
// with an alarm, and the message is written as evidence unavailable, opportunistic, with no verdict of the
// evidence's in its row or its header. No authentication result refuses mail.
func TestMailIngestTamperedEvidenceIsEvidenceUnavailable(t *testing.T) {
	message := testMailIngestMessage("Hello", "body")
	cases := []func(trailer *protocol.MailDeposit){
		func(trailer *protocol.MailDeposit) { trailer.Evidence.MessageSha256 = bytes.Repeat([]byte{7}, 32) },
		func(trailer *protocol.MailDeposit) { trailer.Evidence.ReceiverSidecarId = NewId().Bytes() },
		func(trailer *protocol.MailDeposit) { trailer.Evidence.Version = 2 },
	}
	for index, tamper := range cases {
		world := newMailIngestTestWorld(t)
		trailer := testMailIngestTrailer(world.receiverId, message)
		// REQUIRETLS would make it validated were the evidence taken
		trailer.RequireTls = true
		tamper(trailer)
		deposit := world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, message, trailer))
		pass := world.ingest(world.ingestor(nil))
		if pass.Ingested != 1 || pass.Consumed != 1 {
			t.Fatalf("case %d: pass %+v", index, pass)
		}
		if !slices.Equal(world.alarmKinds(), []MailIngestAlarmKind{MailIngestAlarmEvidence}) {
			t.Errorf("case %d: alarms %v", index, world.alarmKinds())
		}
		// with the evidence dropped, the receive time is the ingress's
		month := MailYearMonthOf(testMailIngestReceiveMillis - 5)
		entries := world.entries(month)
		if len(entries) != 1 {
			t.Fatalf("case %d: %d rows", index, len(entries))
		}
		results := entries[0].GetAuthResults()
		if !results.GetEvidenceUnavailable() || results.GetSpf() != 0 || results.GetDkim() != 0 || results.GetDmarc() != 0 ||
			entries[0].GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC || entries[0].GetTlsBasis() != nil {
			t.Errorf("case %d: row %+v", index, entries[0])
		}
		content := string(world.store.file(MailMessagePath(month, deposit.id)).content)
		if !strings.Contains(content, "; none (evidence unavailable)") || strings.Contains(content, "spf=pass") {
			t.Errorf("case %d: headers %q", index, content[:min(len(content), 200)])
		}
	}
}

// A wrong signer fails (S7): a deposit that names a receiver its push's signer is not keeps nothing it says of the
// session, so it is evidence unavailable, never validated, with an alarm.
func TestMailIngestWrongSignerKeepsNothingOfTheSession(t *testing.T) {
	world := newMailIngestTestWorld(t)
	message := testMailIngestMessage("Hello", "body")
	claimedReceiverId := NewId()
	trailer := testMailIngestTrailer(claimedReceiverId, message)
	trailer.RequireTls = true
	// deposited and signed by the world's receiver, naming another
	deposit := world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, message, trailer))
	pass := world.ingest(world.ingestor(nil))
	if pass.Ingested != 1 || !slices.Equal(world.alarmKinds(), []MailIngestAlarmKind{MailIngestAlarmWrongSigner}) {
		t.Fatalf("pass %+v, alarms %v", pass, world.alarmKinds())
	}
	// no sealed time is taken, so the month is the push's
	month := MailYearMonthOf(uint64(testMailIngestPushMillis))
	entries := world.entries(month)
	if len(entries) != 1 || !entries[0].GetAuthResults().GetEvidenceUnavailable() || entries[0].GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC {
		t.Fatalf("rows %+v", entries)
	}
	content := string(world.store.file(MailMessagePath(month, deposit.id)).content)
	if strings.Contains(content, "Received: from out.sender.example") || !strings.Contains(content, "; none (evidence unavailable)") {
		t.Errorf("headers %q", content[:min(len(content), 200)])
	}
}

// A deposit with no evidence is "evidence unavailable", and REQUIRETLS with sealed evidence is validated: the label
// rests on what reception sealed and on nothing ingest could look up, since ingest holds no resolver.
func TestMailIngestLabelsFromTheSealedEvidence(t *testing.T) {
	world := newMailIngestTestWorld(t)
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	withoutMessage := testMailIngestMessage("Without", "body")
	without := testMailIngestTrailer(world.receiverId, withoutMessage)
	without.Evidence = nil
	without.RequireTls = true
	withoutDeposit := world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, withoutMessage, without))

	withMessage := testMailIngestMessage("With", "body")
	with := testMailIngestTrailer(world.receiverId, withMessage)
	with.RequireTls = true
	// the reception-time verdicts, whatever DNS says by the time of ingest
	with.Evidence.Spf.Result = protocol.SpfVerdict_SPF_FAIL
	with.Evidence.Dkim[0].Result = protocol.DkimVerdict_DKIM_TEMPERROR
	withDeposit := world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, withMessage, with))

	pass := world.ingest(world.ingestor(nil))
	if pass.Ingested != 2 || pass.Consumed != 2 || len(world.alarms) != 0 {
		t.Fatalf("pass %+v, alarms %v", pass, world.alarmKinds())
	}
	byId := map[Id]*protocol.IndexEntry{}
	for _, entry := range world.entries(month) {
		byId[Id(entry.GetId())] = entry
	}
	if entry := byId[withoutDeposit.id]; entry == nil || !entry.GetAuthResults().GetEvidenceUnavailable() || entry.GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC {
		t.Errorf("no evidence: %+v", entry)
	}
	entry := byId[withDeposit.id]
	if entry == nil || entry.GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_VALIDATED || entry.GetTlsBasis().GetRule() != protocol.MailTlsRule_MAIL_TLS_RULE_REQUIRETLS ||
		entry.GetAuthResults().GetSpf() != protocol.SpfVerdict_SPF_FAIL || entry.GetAuthResults().GetDkim() != protocol.DkimVerdict_DKIM_TEMPERROR {
		t.Errorf("sealed evidence: %+v", entry)
	}
	if !MailEntryUntrusted(entry) {
		t.Error("validated outside mail is still untrusted")
	}
}

// An approval-shaped reply stays plain mail (owner decision 80): ingest writes its m/ and i/ and nothing else,
// marks it untrusted, and calls nothing but its message callback.
func TestMailIngestApprovalShapedReplyStaysPlainMail(t *testing.T) {
	world := newMailIngestTestWorld(t)
	message := []byte("From: Owner <owner@sender.example>\r\nTo: " + testMailIngestRecipient +
		"\r\nSubject: Re: Approval requested [approval 7f3a]\r\nIn-Reply-To: <approval-7f3a@acme.root.example>\r\n\r\nAPPROVE\r\nyes, approved\r\n")
	world.depositMessage(message)
	pass := world.ingest(world.ingestor(nil))
	if pass.Ingested != 1 {
		t.Fatalf("pass %+v", pass)
	}
	for _, path := range world.store.paths() {
		if !strings.HasPrefix(path, "m/") && !strings.HasPrefix(path, "i/") {
			t.Errorf("ingest wrote %s", strings.SplitN(path, "/", 2)[0])
		}
	}
	if len(world.messages) != 1 || !world.messages[0].Untrusted || world.messages[0].Entry.GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC {
		t.Errorf("messages %+v", world.messages)
	}
}

// FS-13: an erased message's deposit does not come back. A deposit whose slot the erasure took does not open and is
// consumed with no message; one that still opens is consumed unwritten; and nothing is written for either.
func TestMailIngestErasedDepositConsumesWithNoMessage(t *testing.T) {
	world := newMailIngestTestWorld(t)
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	slotGone := world.depositMessage(testMailIngestMessage("Gone", "body"))
	slotGone.slotGone = true
	opens := world.depositMessage(testMailIngestMessage("Opens", "body"))
	kept := world.depositMessage(testMailIngestMessage("Kept", "body"))
	world.repo.erase(NewId(), mailErasureNote([]mailErasedMessage{{Month: month, MessageId: slotGone.id}, {Month: month, MessageId: opens.id}}, nil))

	pass := world.ingest(world.ingestor(nil))
	if pass.Erased != 2 || pass.Ingested != 1 || pass.Consumed != 3 || pass.Left != 0 {
		t.Fatalf("pass %+v", pass)
	}
	if paths := world.messagePaths(); !slices.Equal(paths, []string{MailMessagePath(month, kept.id)}) {
		t.Errorf("m/ holds %d paths", len(paths))
	}
	if entries := world.entries(month); len(entries) != 1 || !bytes.Equal(entries[0].GetId(), kept.id.Bytes()) {
		t.Errorf("%d rows", len(entries))
	}
	if world.repo.standingCount(world.receiverId) != 0 || len(world.alarms) != 0 {
		t.Errorf("standing %d, alarms %v", world.repo.standingCount(world.receiverId), world.alarmKinds())
	}
	if world.repo.consumes[0].consumedThrough != kept.version {
		t.Errorf("consumed through %d", world.repo.consumes[0].consumedThrough)
	}
}

// A deposit that does not open and that no erasure names stands, with an alarm, and holds nothing back: the
// deposits after it are ingested, and consumed_through stops below it. A transport's failure stops the ref's read.
func TestMailIngestUnopenedDepositStandsAndHoldsNothingBack(t *testing.T) {
	world := newMailIngestTestWorld(t)
	before := world.depositMessage(testMailIngestMessage("Before", "body"))
	unopened := world.depositMessage(testMailIngestMessage("Unopened", "body"))
	unopened.slotGone = true
	after := world.depositMessage(testMailIngestMessage("After", "body"))

	pass := world.ingest(world.ingestor(nil))
	if pass.Ingested != 2 || pass.Left != 1 || pass.Consumed != 2 {
		t.Fatalf("pass %+v", pass)
	}
	if !slices.Equal(world.alarmKinds(), []MailIngestAlarmKind{MailIngestAlarmUnopened}) || world.alarms[0].MessageId != unopened.id {
		t.Errorf("alarms %v", world.alarmKinds())
	}
	consume := world.repo.consumes[0]
	if !slices.Equal(consume.depositIds, []Id{before.id, after.id}) || consume.consumedThrough != before.version {
		t.Errorf("consume %+v", consume)
	}
	if world.repo.standingCount(world.receiverId) != 1 {
		t.Errorf("standing %d", world.repo.standingCount(world.receiverId))
	}

	// a failure that is no missing key: the read stops, and what settled before it is still consumed
	transport := errors.New("transport failed")
	unopened.slotGone = false
	unopened.openErr = transport
	later := world.depositMessage(testMailIngestMessage("Later", "body"))
	_, err := world.ingestor(nil).Ingest(context.Background())
	if !errors.Is(err, transport) {
		t.Fatalf("a transport failure: %v", err)
	}
	if world.store.file(MailMessagePath(MailYearMonthOf(testMailIngestReceiveMillis), later.id)) != nil {
		t.Error("a deposit past a failed read was ingested")
	}
}

// The depositor is judged per deposit: a reader's receipt ref is never opened or consumed, a depositor with no right
// is consumed unrecorded with an alarm, and one this device cannot judge yet stands for a later pass.
func TestMailIngestJudgesTheDepositor(t *testing.T) {
	world := newMailIngestTestWorld(t)
	message := testMailIngestMessage("Hello", "body")
	receiptReaderId, strangerId, unjudgedId := NewId(), NewId(), NewId()
	world.authority.classes[receiptReaderId] = MailDepositorReceipts
	world.authority.classes[strangerId] = MailDepositorNone
	world.authority.classes[unjudgedId] = MailDepositorUnknown
	world.repo.deposit(receiptReaderId, receiptReaderId, []byte("a read receipt batch, which is the record's"))
	stranger := world.repo.deposit(strangerId, strangerId, testMailIngestPlaintext(t, message, testMailIngestTrailer(strangerId, message)))
	world.repo.deposit(unjudgedId, unjudgedId, testMailIngestPlaintext(t, message, testMailIngestTrailer(unjudgedId, message)))

	pass := world.ingest(world.ingestor(nil))
	if pass.Ingested != 0 || pass.Refused != 1 || pass.Left != 1 || pass.Consumed != 1 {
		t.Fatalf("pass %+v", pass)
	}
	if len(world.repo.consumes) != 1 || world.repo.consumes[0].depositorId != strangerId || !slices.Equal(world.repo.consumes[0].depositIds, []Id{stranger.id}) {
		t.Errorf("consumes %+v", world.repo.consumes)
	}
	if world.repo.standingCount(receiptReaderId) != 1 || world.repo.standingCount(unjudgedId) != 1 || len(world.store.paths()) != 0 {
		t.Errorf("standing receipts %d, unjudged %d, paths %v", world.repo.standingCount(receiptReaderId), world.repo.standingCount(unjudgedId), world.store.paths())
	}
	if !slices.Equal(world.alarmKinds(), []MailIngestAlarmKind{MailIngestAlarmDepositor}) {
		t.Errorf("alarms %v", world.alarmKinds())
	}

	// once judged a mail depositor, the unjudged deposit is ingested
	world.authority.classes[unjudgedId] = MailDepositorMail
	if pass := world.ingest(world.ingestor(nil)); pass.Ingested != 1 || pass.Consumed != 1 {
		t.Errorf("the later pass %+v", pass)
	}
}

// A deposit that is no message and trailer, or names no recipient or too many, is consumed unrecorded with an alarm;
// one of an unknown version or past the reader's bound stands for a reader that takes it.
func TestMailIngestRefusesWhatIsNotADepositAndLeavesWhatItCannotRead(t *testing.T) {
	world := newMailIngestTestWorld(t)
	message := testMailIngestMessage("Hello", "body")
	world.repo.deposit(world.receiverId, world.receiverId, []byte("no trailer here"))
	noRecipient := testMailIngestTrailer(world.receiverId, message)
	noRecipient.Recipients = nil
	world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, message, noRecipient))
	tooMany := testMailIngestTrailer(world.receiverId, message)
	tooMany.Recipients = []string{testMailIngestRecipient, "cy@acme.root.example", "di@acme.root.example"}
	world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, message, tooMany))
	notAnAddress := testMailIngestTrailer(world.receiverId, message)
	notAnAddress.Recipients = []string{strings.Repeat("a", 400) + "@acme.root.example"}
	world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, message, notAnAddress))
	newer := testMailIngestTrailer(world.receiverId, message)
	newer.Version = 2
	world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, message, newer))
	large := testMailIngestMessage("Large", strings.Repeat("x", 4096))
	world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, large, testMailIngestTrailer(world.receiverId, large)))

	pass := world.ingest(world.ingestor(func(args *MailIngestArgs) {
		args.Settings = DefaultMailIngestSettings()
		args.Settings.RecipientMaxCount = 2
		args.Settings.DepositMaxByteCount = 2048
	}))
	if pass.Refused != 4 || pass.Left != 2 || pass.Ingested != 0 || pass.Consumed != 4 {
		t.Fatalf("pass %+v", pass)
	}
	want := []MailIngestAlarmKind{MailIngestAlarmBadDeposit, MailIngestAlarmBadDeposit, MailIngestAlarmBadDeposit, MailIngestAlarmBadDeposit, MailIngestAlarmUnread, MailIngestAlarmUnread}
	if !slices.Equal(world.alarmKinds(), want) {
		t.Errorf("alarms %v", world.alarmKinds())
	}
	if len(world.store.paths()) != 0 || world.repo.standingCount(world.receiverId) != 2 {
		t.Errorf("paths %v, standing %d", world.store.paths(), world.repo.standingCount(world.receiverId))
	}
	// nothing standing below the refused ones, and the two left stand above them
	if world.repo.consumes[0].consumedThrough != 4 {
		t.Errorf("consumed through %d", world.repo.consumes[0].consumedThrough)
	}
}

// Same-network mail (D-MAIL-8): a deposit that names no receiver is member-signed, and not untrusted, only where its
// push's signer may send as its From; a forged From is evidence unavailable and untrusted. Neither takes ingest's
// headers, a row's auth results or a reach receipt, and what it claims of a session is dropped.
func TestMailIngestSameNetworkDepositIsMemberSignedOnlyWithTheSendRight(t *testing.T) {
	world := newMailIngestTestWorld(t)
	memberDeviceId, forgerId := NewId(), NewId()
	world.authority.maySend[memberDeviceId.String()+" cy@acme.root.example"] = true
	message := []byte("From: Cy <cy@acme.root.example>\r\nTo: " + testMailIngestRecipient + "\r\nSubject: lunch\r\n\r\nnoon?\r\n")
	trailer := &protocol.MailDeposit{Version: mailFormatVersion, MailFrom: []byte("cy@acme.root.example"), Recipients: []string{testMailIngestRecipient}, RequireTls: true}
	signed := world.repo.deposit(memberDeviceId, memberDeviceId, testMailIngestPlaintext(t, message, trailer))
	forged := world.repo.deposit(forgerId, forgerId, testMailIngestPlaintext(t, message, trailer))
	reachNotes := 0
	pass := world.ingest(world.ingestor(func(args *MailIngestArgs) {
		args.Reach = func(note *RecordReachNote) error { reachNotes += 1; return nil }
		args.ReachGrant = func(address string, depositorId Id) *MailIngestGrant {
			return &MailIngestGrant{GrantId: bytes.Repeat([]byte{1}, 32)}
		}
	}))
	if pass.Ingested != 2 || reachNotes != 0 {
		t.Fatalf("pass %+v, %d reach notes", pass, reachNotes)
	}
	// no sealed time: the month is the push's
	month := MailYearMonthOf(uint64(testMailIngestPushMillis))
	byId := map[Id]*protocol.IndexEntry{}
	for _, entry := range world.entries(month) {
		byId[Id(entry.GetId())] = entry
	}
	if entry := byId[signed.id]; entry == nil || entry.GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED || MailEntryUntrusted(entry) || entry.GetAuthResults() != nil {
		t.Errorf("the member's: %+v", entry)
	}
	if entry := byId[forged.id]; entry == nil || entry.GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC || !MailEntryUntrusted(entry) {
		t.Errorf("the forged From's: %+v", entry)
	}
	if content := world.store.file(MailMessagePath(month, signed.id)).content; !bytes.Equal(content, message) {
		t.Error("a same-network message took ingest headers")
	}
}

// A received message notes its reach receipt and, for a burner's recipient, Used at, before the CONSUME; a note
// that fails holds nothing back.
func TestMailIngestNotesReachAndUsedAt(t *testing.T) {
	world := newMailIngestTestWorld(t)
	burnerAddress := "shop@otter-4821.acme.root.example"
	message := testMailIngestMessage("Welcome", "body")
	trailer := testMailIngestTrailer(world.receiverId, message)
	trailer.Recipients = []string{burnerAddress, testMailIngestRecipient}
	world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, message, trailer))
	reachNotes := []*RecordReachNote{}
	usedAt := []string{}
	grantId := bytes.Repeat([]byte{9}, 32)
	pass := world.ingest(world.ingestor(func(args *MailIngestArgs) {
		args.Reach = func(note *RecordReachNote) error {
			reachNotes = append(reachNotes, note)
			return errors.New("the receipts refused it")
		}
		args.ReachGrant = func(address string, depositorId Id) *MailIngestGrant {
			if address != burnerAddress || depositorId != world.receiverId {
				t.Errorf("grant asked for a recipient that is not the row's")
			}
			return &MailIngestGrant{GrantId: grantId, PolicyVersion: 3}
		}
		args.UsedAt = func(ctx context.Context, address string, domain string, at time.Time) error {
			usedAt = append(usedAt, address+" "+domain+" "+at.Format(time.RFC3339))
			return errors.New("the vault refused it")
		}
	}))
	if pass.Ingested != 1 || pass.Consumed != 1 {
		t.Fatalf("pass %+v", pass)
	}
	if len(reachNotes) != 1 {
		t.Fatalf("%d reach notes", len(reachNotes))
	}
	note := reachNotes[0]
	if note.Kind != RecordReachKindReceive || !bytes.Equal(note.GrantId, grantId) || note.PolicyVersion != 3 || note.StreamCount != 1 ||
		note.ByteCount != uint64(len(message)) || len(note.Peers) != 1 || !bytes.Equal(note.Peers[0], world.receiverId.Bytes()) ||
		len(note.Relays) != 1 || note.Relays[0].Host != "mx.acme.root.example" {
		t.Errorf("reach note %+v", note)
	}
	if !slices.Equal(usedAt, []string{burnerAddress + " sender.example 2026-11-10T12:00:00Z"}) {
		t.Errorf("used at %v", usedAt)
	}
}

// A sidecar that does not read and write the repo ingests nothing, and neither does one with no authority.
func TestMailIngestRefusesANonReader(t *testing.T) {
	world := newMailIngestTestWorld(t)
	world.depositMessage(testMailIngestMessage("Hello", "body"))
	world.authority.notReader = true
	if _, err := world.ingestor(nil).Ingest(context.Background()); !errors.Is(err, ErrMailNotIngester) {
		t.Errorf("a non-reader: %v", err)
	}
	world.authority.notReader = false
	if _, err := world.ingestor(func(args *MailIngestArgs) { args.Authority = nil }).Ingest(context.Background()); !errors.Is(err, ErrMailNotIngester) {
		t.Errorf("no authority: %v", err)
	}
	if len(world.store.paths()) != 0 || world.repo.standingCount(world.receiverId) != 1 {
		t.Error("a refused pass touched the mailbox")
	}
}

// Run ingests at its start and again at each wake, until its context ends.
func TestMailIngestRunIngestsOnAWake(t *testing.T) {
	world := newMailIngestTestWorld(t)
	ingested := make(chan Id, 4)
	ingestor := world.ingestor(func(args *MailIngestArgs) {
		args.Settings = DefaultMailIngestSettings()
		args.Settings.MinPassInterval = 0
		args.Message = func(message *MailMessage) { ingested <- message.Id }
	})
	first := world.depositMessage(testMailIngestMessage("First", "body"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ingestor.Run(ctx)
	}()
	if id := <-ingested; id != first.id {
		t.Errorf("the first pass ingested another deposit")
	}
	second := world.depositMessage(testMailIngestMessage("Second", "body"))
	// the watch's wake, as a hint of the deposit's push raises it
	wake := func() func() {
		world.repo.stateLock.Lock()
		defer world.repo.stateLock.Unlock()
		return world.repo.wake
	}()
	wake()
	if id := <-ingested; id != second.id {
		t.Errorf("the woken pass ingested another deposit")
	}
	cancel()
	<-done
}

// The ACL-backed authority refuses with no engine or no installed state, so an unbound ingestor ingests nothing.
func TestMailIngestAclAuthorityFailsClosedWithNoState(t *testing.T) {
	var absent *MailIngestAclAuthority
	unbound := &MailIngestAclAuthority{Root: testMailIngestRoot}
	for _, authority := range []*MailIngestAclAuthority{absent, unbound} {
		if authority.Ingests(NewId(), NewId()) || authority.MaySendAs(NewId(), testMailIngestRecipient) ||
			authority.DepositorClass(NewId(), NewId(), nil) != MailDepositorUnknown {
			t.Error("an authority with no engine answered")
		}
	}
}

// A mail ERASE's note names messages and segments by path and reads back; a vault's note, or any other line, names
// nothing of mail's.
func TestMailErasureNoteReadsBackAndRefusesOtherNotes(t *testing.T) {
	messageId := NewId()
	messages := []mailErasedMessage{{Month: 202611, MessageId: messageId}}
	segments := []mailErasedSegment{{Month: 202611, N: 3}}
	gotMessages, gotSegments, ok := parseMailErasureNote(mailErasureNote(messages, segments))
	if !ok || !slices.Equal(gotMessages, messages) || !slices.Equal(gotSegments, segments) {
		t.Fatalf("read back %v %v %v", gotMessages, gotSegments, ok)
	}
	for _, note := range [][]byte{nil, []byte(MailVaultPath(NewId())), []byte(MailMessagePath(202611, messageId) + "\nx"), []byte("m/202611/zz/" + mailBinaryName(messageId[:]))} {
		if _, _, ok := parseMailErasureNote(note); ok {
			t.Errorf("a note of another shape read as mail's: %q", note)
		}
	}
}

// The mailbox's remove store in memory: mailTestStore with a removal held to a version.
type mailTestRemoveStore struct {
	*mailTestStore
}

func (self *mailTestRemoveStore) Remove(ctx context.Context, path string, ifVersion uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	file := self.files[path]
	if file == nil {
		return ErrEvsPathAbsent
	}
	if file.version != ifVersion {
		return &MailStoreConflictError{Paths: []string{path}}
	}
	delete(self.files, path)
	return nil
}

// A group message stores once, in the group repo, with an r/ reference in each member's mailbox; a reference another
// of the member's devices made is found standing; and once the group's admins erase the message, each member's
// device drops its reference and adds none again.
func TestMailGroupMessageStoresOnceWithAReferencePerMember(t *testing.T) {
	group := newMailIngestTestWorld(t)
	message := testMailIngestMessage("To the group", "body")
	trailer := testMailIngestTrailer(group.receiverId, message)
	trailer.Recipients = []string{"team@acme.root.example"}
	deposit := group.repo.deposit(group.receiverId, group.receiverId, testMailIngestPlaintext(t, message, trailer))
	second := group.depositMessage(testMailIngestMessage("Also to the group", "body"))
	if pass := group.ingest(group.ingestor(nil)); pass.Ingested != 2 {
		t.Fatalf("the group's ingest: %+v", pass)
	}
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	if len(group.messagePaths()) != 2 {
		t.Fatalf("the group repo holds %d messages", len(group.messagePaths()))
	}

	ctx := context.Background()
	mailboxes := []*mailTestRemoveStore{{mailTestStore: newMailTestStore()}, {mailTestStore: newMailTestStore()}}
	refs := []*MailGroupRefs{}
	for _, mailbox := range mailboxes {
		memberRefs := newMailGroupRefs(group.repoId, group.store, mailbox, group.repo.Erasures, nil)
		refs = append(refs, memberRefs)
		result, err := memberRefs.Sync(ctx)
		if err != nil || result.Added != 2 || result.Present != 0 {
			t.Fatalf("a member's sync: %+v, %v", result, err)
		}
		paths := mailbox.paths()
		if len(paths) != 2 || mailbox.writeCount != 1 {
			t.Errorf("a member's mailbox holds %d paths after %d pushes", len(paths), mailbox.writeCount)
		}
		file := mailbox.file(MailGroupRefPath(month, deposit.id))
		ref := &protocol.MailGroupRef{}
		if file == nil || proto.Unmarshal(file.content, ref) != nil || !bytes.Equal(ref.GetRepoId(), group.repoId.Bytes()) || !bytes.Equal(ref.GetMessageId(), deposit.id.Bytes()) {
			t.Errorf("a member's reference %+v", ref)
		}
		// no message's bytes are copied: storage counts once
		for _, path := range paths {
			if !strings.HasPrefix(path, "r/") {
				t.Errorf("a member's mailbox took %s", strings.SplitN(path, "/", 2)[0])
			}
		}
	}

	// another device of the first member finds both standing, and a later sync of the same device reads no row again
	otherDevice := newMailGroupRefs(group.repoId, group.store, mailboxes[0], group.repo.Erasures, nil)
	if result, err := otherDevice.Sync(ctx); err != nil || result.Added != 0 || result.Present != 2 {
		t.Errorf("the member's other device: %+v, %v", result, err)
	}
	writes := mailboxes[0].writeCount
	if result, err := refs[0].Sync(ctx); err != nil || *result != (MailGroupRefSync{}) || mailboxes[0].writeCount != writes {
		t.Errorf("a second sync: %+v, %v", result, err)
	}

	// the group's admins erase the first message: each member drops its reference, and a restart adds none again
	group.repo.erase(NewId(), mailErasureNote([]mailErasedMessage{{Month: month, MessageId: deposit.id}}, nil))
	for index, memberRefs := range refs {
		result, err := memberRefs.Sync(ctx)
		if err != nil || result.Dropped != 1 || result.Added != 0 {
			t.Fatalf("a member's sync after the erasure: %+v, %v", result, err)
		}
		if paths := mailboxes[index].paths(); !slices.Equal(paths, []string{MailGroupRefPath(month, second.id)}) {
			t.Errorf("after the erasure a member's mailbox holds %d paths", len(paths))
		}
	}
	restarted := newMailGroupRefs(group.repoId, group.store, mailboxes[1], group.repo.Erasures, nil)
	if result, err := restarted.Sync(ctx); err != nil || result.Added != 0 || result.Dropped != 0 || result.Present != 1 {
		t.Errorf("a restart after the erasure: %+v, %v", result, err)
	}
}
