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
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A repo that takes a deposit's plaintext, counting the deposits running at once, each waiting on gate while it is
// set.
type mailDepositTestRepos struct {
	stateLock  sync.Mutex
	plaintexts map[Id][]byte
	active     int
	maxActive  int
	failing    map[Id]error
	gate       chan struct{}
	// raised as each deposit starts
	started *MonitorValue[int]
}

func newMailDepositTestRepos() *mailDepositTestRepos {
	return &mailDepositTestRepos{plaintexts: map[Id][]byte{}, failing: map[Id]error{}, started: NewMonitorValue(0)}
}

type mailDepositTestRepo struct {
	repos  *mailDepositTestRepos
	repoId Id
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
	return newMailDepositor(func(repoId Id) mailDepositRepo {
		return &mailDepositTestRepo{repos: repos, repoId: repoId}
	}, &MailDepositorArgs{ReceiverSidecarId: testMailSessionReceiverId, Settings: settings})
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
