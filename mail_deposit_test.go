//go:build !sidecar_http && !js && !ios_extension

// MAIL-M7-14's depositor on fake repos: each repo's plaintext is the message, its own trailer and the trailer's
// length, which ingest's split takes back; at most DepositConcurrency deposits at once, 2 under the mobile settings;
// and any deposit's failure fails the whole, while the others still run.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A repo that takes a deposit's plaintext, counting the deposits running at once, each waiting on gate while it is
// set, and says what its depositor's state gives the receiver there: deposit where allowed, nothing known elsewhere
// unless known says so.
type mailDepositTestRepos struct {
	stateLock  sync.Mutex
	plaintexts map[Id][]byte
	active     int
	maxActive  int
	failing    map[Id]error
	allowed    map[Id]bool
	known      map[Id]bool
	gate       chan struct{}
	// raised as each deposit starts
	started *MonitorValue[int]
}

func newMailDepositTestRepos() *mailDepositTestRepos {
	return &mailDepositTestRepos{
		plaintexts: map[Id][]byte{}, failing: map[Id]error{}, allowed: map[Id]bool{}, known: map[Id]bool{}, started: NewMonitorValue(0),
	}
}

type mailDepositTestRepo struct {
	repos  *mailDepositTestRepos
	repoId Id
}

// See mailDepositRightRepo; the receiver is the only depositor these repos judge.
func (self *mailDepositTestRepo) depositRight(depositorId Id) (bool, bool) {
	self.repos.stateLock.Lock()
	defer self.repos.stateLock.Unlock()
	if depositorId != testMailSessionReceiverId {
		return false, true
	}
	return self.repos.allowed[self.repoId], self.repos.known[self.repoId]
}

func (self *mailDepositTestRepo) Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error) {
	repos := self.repos
	plaintext, err := io.ReadAll(args.Body)
	if err != nil {
		return nil, err
	}
	gate := func() chan struct{} {
		repos.stateLock.Lock()
		defer repos.stateLock.Unlock()
		repos.active += 1
		repos.maxActive = max(repos.maxActive, repos.active)
		return repos.gate
	}()
	defer func() {
		repos.stateLock.Lock()
		defer repos.stateLock.Unlock()
		repos.active -= 1
	}()
	repos.started.Update(func(count int) int { return count + 1 })
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	repos.stateLock.Lock()
	defer repos.stateLock.Unlock()
	if err := repos.failing[self.repoId]; err != nil {
		return nil, err
	}
	repos.plaintexts[self.repoId] = plaintext
	return &EvsDepositResult{EntryId: NewEvsRandomToken(), Version: 1}, nil
}

// A depositor over repos with settings, nil taking the defaults.
func newMailDepositTestDepositor(repos *mailDepositTestRepos, settings *MailSessionSettings) *MailDepositor {
	return newMailDepositTestDepositorOn(repos, settings, nil)
}

// A depositor over repos with settings on clock, nil taking the defaults and real time.
func newMailDepositTestDepositorOn(repos *mailDepositTestRepos, settings *MailSessionSettings, clock Clock) *MailDepositor {
	return newMailDepositor(func(repoId Id) mailDepositRepo {
		return &mailDepositTestRepo{repos: repos, repoId: repoId}
	}, &MailDepositorArgs{ReceiverSidecarId: testMailSessionReceiverId, Clock: clock, Settings: settings})
}

// A finished spool of message.
func newMailDepositTestSpool(t *testing.T, message []byte) *mailSpool {
	t.Helper()
	spool, err := newMailSpool(newTestMemoryStore(), 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(spool.close)
	if _, err := spool.Write(message); err != nil {
		t.Fatal(err)
	}
	if err := spool.finish(); err != nil {
		t.Fatal(err)
	}
	return spool
}

// Each repo's plaintext splits back, as ingest splits it, into the message as received and a trailer naming that
// repo's recipients alone, with the session's fields and this receiver.
func TestMailDepositorWritesEachRepoItsOwnTrailer(t *testing.T) {
	repos := newMailDepositTestRepos()
	depositor := newMailDepositTestDepositor(repos, nil)
	message := testMailSessionMessage("trailer")
	ingress := &protocol.MailIngress{Version: 1, SenderIp: []byte{192, 0, 2, 25}, Sni: testMailReceiverServerName}
	evidence := &protocol.MailAuthEvidence{Version: 1, MessageSha256: bytes.Repeat([]byte{1}, 32)}
	first, second := NewId(), NewId()
	err := depositor.Deposit(context.Background(), &MailDepositInput{
		Spool:      newMailDepositTestSpool(t, message),
		Ingress:    ingress,
		Evidence:   evidence,
		MailFrom:   "bounce@sender.example",
		RequireTls: true,
		TlsVersion: 0x0304,
		TlsSuite:   0x1301,
		Targets: []*MailDepositTarget{
			{RepoId: first, Recipients: []string{testMailSessionAlice, testMailSessionBob}},
			{RepoId: second, Recipients: []string{testMailSessionCarol}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for repoId, want := range map[Id][]string{first: {testMailSessionAlice, testMailSessionBob}, second: {testMailSessionCarol}} {
		gotMessage, trailer, err := mailSplitDeposit(repos.plaintexts[repoId], DefaultMailIngestSettings().TrailerMaxByteCount)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotMessage, message) || !slices.Equal(trailer.GetRecipients(), want) {
			t.Errorf("repo %s: recipients %v", repoId, trailer.GetRecipients())
		}
		if !proto.Equal(trailer.GetIngress(), ingress) || !proto.Equal(trailer.GetEvidence(), evidence) ||
			string(trailer.GetMailFrom()) != "bounce@sender.example" || !trailer.GetRequireTls() ||
			trailer.GetTlsVersion() != 0x0304 || trailer.GetTlsSuite() != 0x1301 ||
			!bytes.Equal(trailer.GetReceiverSidecarId(), testMailSessionReceiverId.Bytes()) {
			t.Errorf("repo %s: trailer %v", repoId, trailer)
		}
	}
}

// At most DepositConcurrency deposits run at once, 4 by default and 2 under the mobile settings, and every repo's
// runs.
func TestMailDepositorRunsAtMostItsConcurrencyAtOnce(t *testing.T) {
	mobile := DefaultMailSessionSettings()
	ApplyMobileMailSessionSettings(mobile)
	for _, settings := range []*MailSessionSettings{DefaultMailSessionSettings(), mobile} {
		repos := newMailDepositTestRepos()
		repos.gate = make(chan struct{})
		depositor := newMailDepositTestDepositor(repos, settings)
		targets := []*MailDepositTarget{}
		for range 8 {
			targets = append(targets, &MailDepositTarget{RepoId: NewId(), Recipients: []string{testMailSessionAlice}})
		}
		done := make(chan error, 1)
		go func() {
			done <- depositor.Deposit(context.Background(), &MailDepositInput{
				Spool:   newMailDepositTestSpool(t, testMailSessionMessage("fan-out")),
				Targets: targets,
			})
		}()
		for {
			started, notify := repos.started.Get()
			if started == settings.DepositConcurrency {
				break
			}
			<-notify
		}
		close(repos.gate)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if repos.maxActive != settings.DepositConcurrency || len(repos.plaintexts) != len(targets) {
			t.Errorf("%d at once of %d, %d deposited", repos.maxActive, settings.DepositConcurrency, len(repos.plaintexts))
		}
	}
}

// One repo's failure fails the message, and the other repos' deposits still run: the sender's retry repeats there,
// which QD-208's bound holds.
func TestMailDepositorFailsTheMessageWhenAnyRepoFails(t *testing.T) {
	repos := newMailDepositTestRepos()
	failing := NewId()
	repos.failing[failing] = &EvsError{Status: 412, Code: protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED}
	depositor := newMailDepositTestDepositor(repos, nil)
	err := depositor.Deposit(context.Background(), &MailDepositInput{
		Spool: newMailDepositTestSpool(t, testMailSessionMessage("one fails")),
		Targets: []*MailDepositTarget{
			{RepoId: NewId(), Recipients: []string{testMailSessionAlice}},
			{RepoId: failing, Recipients: []string{testMailSessionBob}},
		},
	})
	if !errors.Is(err, ErrMailDepositFailed) || !IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED) {
		t.Fatalf("Deposit answered %v", err)
	}
	if len(repos.plaintexts) != 1 {
		t.Fatalf("%d repos took it", len(repos.plaintexts))
	}
}

// What cannot be deposited is refused before any repo is asked: no spool, an unfinished one, no target, a target with
// no recipient, and a trailer past its bound.
func TestMailDepositorRefusesWhatCannotBeDeposited(t *testing.T) {
	repos := newMailDepositTestRepos()
	tight := DefaultMailSessionSettings()
	tight.TrailerMaxByteCount = 16
	unfinished, err := newMailSpool(newTestMemoryStore(), 64)
	if err != nil {
		t.Fatal(err)
	}
	defer unfinished.close()
	spool := newMailDepositTestSpool(t, testMailSessionMessage("refused"))
	target := &MailDepositTarget{RepoId: NewId(), Recipients: []string{testMailSessionAlice}}
	cases := []struct {
		settings *MailSessionSettings
		input    *MailDepositInput
	}{
		{settings: nil, input: nil},
		{settings: nil, input: &MailDepositInput{Spool: unfinished, Targets: []*MailDepositTarget{target}}},
		{settings: nil, input: &MailDepositInput{Spool: spool}},
		{settings: nil, input: &MailDepositInput{Spool: spool, Targets: []*MailDepositTarget{{RepoId: NewId()}}}},
		{settings: tight, input: &MailDepositInput{Spool: spool, Targets: []*MailDepositTarget{target}}},
	}
	for index, c := range cases {
		if err := newMailDepositTestDepositor(repos, c.settings).Deposit(context.Background(), c.input); !errors.Is(err, ErrMailDepositorInvalid) {
			t.Errorf("case %d: %v", index, err)
		}
	}
	if started, _ := repos.started.Get(); started != 0 {
		t.Fatalf("%d deposits ran", started)
	}
}

// A repo the receiver's own verified state gives no deposit refuses the message at once, before any repo's deposit
// runs, so no repo holds a copy the sender's retry would duplicate; a repo its state gives deposit, or one whose
// client holds no state to judge by, deposits as before.
func TestMailDepositorRefusesAtOnceARepoItsStateGivesNoDeposit(t *testing.T) {
	repos := newMailDepositTestRepos()
	allowed, unknown, refused := NewId(), NewId(), NewId()
	repos.allowed[allowed], repos.known[allowed] = true, true
	repos.known[refused] = true
	depositor := newMailDepositTestDepositor(repos, nil)
	targets := []*MailDepositTarget{
		{RepoId: allowed, Recipients: []string{testMailSessionAlice}},
		{RepoId: unknown, Recipients: []string{testMailSessionBob}},
		{RepoId: refused, Recipients: []string{testMailSessionCarol}},
	}
	if !depositor.Refuses(targets) {
		t.Fatal("a repo the state refuses was not refused")
	}
	err := depositor.Deposit(context.Background(), &MailDepositInput{Spool: newMailDepositTestSpool(t, testMailSessionMessage("refused")), Targets: targets})
	if !errors.Is(err, ErrMailDepositFailed) {
		t.Fatalf("Deposit answered %v", err)
	}
	if started, _ := repos.started.Get(); started != 0 || len(repos.plaintexts) != 0 {
		t.Fatalf("%d deposits started, %d made", started, len(repos.plaintexts))
	}
	targets = targets[:2]
	if depositor.Refuses(targets) {
		t.Fatal("a repo the state allows, or knows nothing of, was refused")
	}
	if err := depositor.Deposit(context.Background(), &MailDepositInput{Spool: newMailDepositTestSpool(t, testMailSessionMessage("allowed")), Targets: targets}); err != nil {
		t.Fatal(err)
	}
	if len(repos.plaintexts) != 2 {
		t.Errorf("%d deposits made", len(repos.plaintexts))
	}
}

// A message's deposits end at DepositTimeout on the depositor's clock: every one still open is cancelled and the
// message fails, so the session answers 451 4.3.0 inside the sender's wait; before the bound nothing ends them.
func TestMailDepositorEndsItsDepositsAtDepositTimeout(t *testing.T) {
	repos := newMailDepositTestRepos()
	repos.gate = make(chan struct{})
	clock := newMailReceiverTestClock()
	settings := DefaultMailSessionSettings()
	settings.DepositTimeout = time.Minute
	depositor := newMailDepositTestDepositorOn(repos, settings, clock)
	done := make(chan error, 1)
	go func() {
		done <- depositor.Deposit(context.Background(), &MailDepositInput{
			Spool:   newMailDepositTestSpool(t, testMailSessionMessage("held")),
			Targets: []*MailDepositTarget{{RepoId: NewId(), Recipients: []string{testMailSessionAlice}}},
		})
	}()
	// the bound is armed before any deposit starts
	for {
		started, notify := repos.started.Get()
		if started == 1 {
			break
		}
		<-notify
	}
	clock.Advance(settings.DepositTimeout - time.Second)
	select {
	case err := <-done:
		t.Fatalf("the deposits ended before their bound: %v", err)
	default:
	}
	clock.Advance(time.Second)
	if err := <-done; !errors.Is(err, ErrMailDepositFailed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Deposit answered %v", err)
	}
	if len(repos.plaintexts) != 0 {
		t.Errorf("%d deposits made", len(repos.plaintexts))
	}
}

// The production repo's right is its client's newest verified state as the exchange reads it for repo:<id>:deposit
// (AclExchangeScopes): the mailbox's own member's consented device has none until a send grant on mail: marks it
// (owner decision 333), and with no state to judge by nothing is known.
func TestMailEvsDepositRepoReadsItsClientsVerifiedState(t *testing.T) {
	net := newAclExchangeNet(t)
	mailboxId := testConfigId("deposit right mailbox")
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Repos = append(rows.Repos, &protocol.AclRepo{
			RepoId: mailboxId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX, OwnerMemberId: net.ownerMemberId.Bytes(),
			ConsentedSidecarIds: [][]byte{net.owner.sidecarId.Bytes()},
		})
	})
	test := newEvsTestClient(t, http.NotFoundHandler(), newEvsTestStore(t))
	repo := mailEvsDepositRepo{EvsRepo: test.client.Repo(mailboxId)}
	if allowed, known := repo.depositRight(net.owner.sidecarId); allowed || known {
		t.Fatalf("with no state: %t %t", allowed, known)
	}
	test.client.args.Config = func() GkmAuthView { return net.log.State() }
	if allowed, known := repo.depositRight(net.owner.sidecarId); allowed || !known {
		t.Fatalf("the receiver before a send grant: %t %t", allowed, known)
	}
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Rules = append(rows.Rules, &protocol.AclRule{
			RuleId:   testConfigId("deposit right members send").Bytes(),
			SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:  []*protocol.AclTarget{{MailSend: true}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_SEND)},
		})
	})
	if allowed, known := repo.depositRight(net.owner.sidecarId); !allowed || !known {
		t.Fatalf("the receiver once a send grant marks it: %t %t", allowed, known)
	}
	if allowed, known := repo.depositRight(net.readOnly.sidecarId); allowed || !known {
		t.Fatalf("a read_only device: %t %t", allowed, known)
	}
}
