//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension && !windows

// IMAP IDLE's polls end with the server (clock-select-ctx-sweep; clock_select_ctx_sweep_test.go has the sweep's
// account): an IDLE selected on the server's end beside IdlePollInterval's timer and polled again whenever select
// took the timer as the server ended, writing what moved to a client the server was leaving. It now answers the end
// whatever else was ready. The world is the IMAP tests' (mail_imap_test.go), the clock clockSelectEndingClock.

package sidecar

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapserver"
)

// IDLE polls no more once the server has ended: it polls at once and after each IdlePollInterval, and an end landing
// as the second wait fires ends IDLE after the two polls before it, answering nil, in each of 64 rounds. An IDLE that
// took the timer's case polled the dead server's mailbox and wrote what moved to the client.
func TestMailImapIdlePollsNoMoreAfterTheServerEnds(t *testing.T) {
	settings := DefaultMailImapServerSettings()
	// apart from IdlePollInterval, so the clock counts IDLE's waits alone
	settings.CommandTimeout = 90 * time.Second
	for round := range 64 {
		storeClock := newTestMailCredentialClock(time.UnixMilli(int64(testMailImapBaseMillis) + 60000))
		mailbox := newMailTestStore()
		testMailImapDeliver(t, mailbox, 1, testMailImapBaseMillis+1000)
		store, err := NewMailImapStore(&MailImapStoreArgs{
			MailboxId: testMailMailboxId,
			Mailbox:   mailbox,
			Hlc:       NewMailHlc(storeClock),
			SidecarId: testMailImapSidecarId,
			State:     newTestMemoryStore(),
			Clock:     storeClock,
		})
		if err != nil {
			t.Fatal(err)
		}
		credential, err := NewMailLocalCredential(&testMailSecrets{})
		if err != nil {
			t.Fatal(err)
		}
		secret, err := NewMailLocalCredentialSecret(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := credential.Install(secret.Verifier); err != nil {
			t.Fatal(err)
		}
		// each poll reads the mailbox's hint first
		pollCount := &atomic.Int64{}
		account := &MailImapAccount{
			NetworkId:  testMailId(0xa1),
			Credential: credential,
			Store:      func() (*MailImapStore, error) { return store, nil },
			Hints: func() (uint64, chan struct{}) {
				pollCount.Add(1)
				return 0, nil
			},
		}
		// a command's bound is a wait the clock never fires
		clock := newClockSelectEndingClock(t, storeClock.Now(), false, settings.IdlePollInterval)
		clock.open()
		ctx, cancel := context.WithCancel(context.Background())
		server, err := newMailImapServer(ctx, &MailImapServerArgs{
			Accounts: func() []*MailImapAccount { return []*MailImapAccount{account} },
			Clock:    clock,
			Settings: settings,
		}, &testMailImapLog{})
		if err != nil {
			t.Fatal(err)
		}
		server.sessions.Update(func(count int) int { return count + 1 })
		session := newMailImapSession(server, nil)
		if err := session.Login(MailLocalCredentialUser, secret.Text); err != nil {
			t.Fatal(err)
		}
		if _, err := session.Select(MailImapFolderInbox, nil); err != nil {
			t.Fatal(err)
		}
		before := pollCount.Load()
		clock.arm(2, cancel)
		var idleErr error
		clock.awaitRun(t, "IDLE", func() {
			// a zero writer: nothing moves in the mailbox, so a poll writes nothing to it
			idleErr = session.Idle(&imapserver.UpdateWriter{}, make(chan struct{}))
		})
		polls := pollCount.Load() - before
		session.Close()
		server.Close()
		cancel()
		if idleErr != nil || polls != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: IDLE answered %v after %d polls and %d waits, want nil after 2 of each", round, idleErr, polls, clock.waits())
		}
	}
}
