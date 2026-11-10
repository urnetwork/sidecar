// ur login --recover: the 12 words come from the terminal alone and reach the daemon's recovery once, never stdout;
// a daemon with no client logs in first, and one with no ur-cli says how to enroll; each phase prints what it waits on;
// a stop exits non-zero; a recovered device is offered a new code; and recovery.recover is a Confirm method.

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A daemon target that recovers by code, as a test scripts it.
type testUrRecoverTarget struct {
	testUrDaemonTarget
	words    []string
	recovery *sidecar.SidecarRecovery
	err      error
}

func (self *testUrRecoverTarget) recoverWithCode(ctx context.Context, words []byte) (*sidecar.SidecarRecovery, error) {
	self.words = append(self.words, string(words))
	return self.recovery, self.err
}

// A code's words, from synthetic entropy.
func testUrRecoveryWords(t *testing.T) string {
	t.Helper()
	code, err := sidecar.NewRecoveryCode(strings.NewReader("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	words, err := code.Words()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(words, " ")
}

func TestLoginRecoverReadsTheCodeFromTheTerminalAlone(t *testing.T) {
	words := testUrRecoveryWords(t)
	target := &testUrRecoverTarget{
		testUrDaemonTarget: testUrDaemonTarget{statusValue: sidecar.SidecarStatus{State: sidecar.SidecarStateOnline, Generation: 1}},
		recovery: &sidecar.SidecarRecovery{
			Phase: sidecar.SidecarRecoveryPending, Proposal: true, StatementId: []byte{0xab, 0xcd},
			ActivatesAfter: time.Date(2027, time.January, 4, 5, 6, 7, 0, time.UTC), Waiting: "the admission waits out the recovery window",
		},
	}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	loginCount := 0
	cli.login = func(ctx context.Context, cli *urCli, invite string) (string, func(), error) {
		loginCount += 1
		return "", nil, errors.New("no login in this test")
	}
	// with no terminal nothing is read, whatever stdin holds
	cli.stdin = strings.NewReader(words + "\n")
	if code := cli.main(context.Background(), []string{"ur", "login", "--recover"}); code == urExitOk || len(target.words) != 0 {
		t.Fatalf("with no terminal: exit %d, %d recoveries", code, len(target.words))
	}

	tty := &testTty{lines: []string{words}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "login", "--recover"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if len(target.words) != 1 || target.words[0] != words {
		t.Fatalf("the daemon got %d codes", len(target.words))
	}
	if !strings.Contains(stdout.String(), "proposal abcd") || !strings.Contains(stdout.String(), "2027-01-04T05:06:07Z") ||
		!strings.Contains(stdout.String(), "ur login --recover again") {
		t.Errorf("stdout: %q", stdout.String())
	}
	for _, word := range strings.Fields(words) {
		if strings.Contains(stdout.String(), word) || strings.Contains(tty.written.String(), word) {
			t.Errorf("a word of the code was written back: %q", word)
		}
	}
	if loginCount != 0 {
		t.Error("a daemon with a client logged in again")
	}
}

// A daemon holding no client logs in first, so the device holds an unadmitted client of the member; with no ur-cli it
// says to enroll with ur connect --token, and reads no code.
func TestLoginRecoverLogsInFirstWhenUnenrolled(t *testing.T) {
	target := &testUrRecoverTarget{
		testUrDaemonTarget: testUrDaemonTarget{statusValue: sidecar.SidecarStatus{State: sidecar.SidecarStateUnenrolled}},
		recovery:           &sidecar.SidecarRecovery{Phase: sidecar.SidecarRecoveryPending, Waiting: "the admission is filed and not yet landed"},
	}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	cli.login = nil
	tty := &testTty{lines: []string{testUrRecoveryWords(t)}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "login", "--recover"}); code == urExitOk || !strings.Contains(stderr.String(), "ur connect --token") {
		t.Fatalf("with no ur-cli: exit %d, %q", code, stderr.String())
	}
	if len(target.words) != 0 || len(target.authKeys) != 0 {
		t.Fatal("a code was read with no client to recover")
	}
	dropped := false
	cli.login = func(ctx context.Context, cli *urCli, invite string) (string, func(), error) {
		return "ur-authkey-synthetic", func() { dropped = true }, nil
	}
	if code := cli.main(context.Background(), []string{"ur", "login", "--recover"}); code != urExitOk {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
	if !dropped || len(target.authKeys) != 1 || target.authKeys[0] != "ur-authkey-synthetic" || len(target.words) != 1 {
		t.Errorf("the login before the recovery: dropped %v, keys %v, %d codes", dropped, target.authKeys, len(target.words))
	}
}

// A recovered device is offered a new code on the terminal; a no names the command, and a stop exits non-zero.
func TestLoginRecoverOffersANewCodeAndReportsAStop(t *testing.T) {
	target := &testUrRecoverTarget{
		testUrDaemonTarget: testUrDaemonTarget{statusValue: sidecar.SidecarStatus{State: sidecar.SidecarStateOnline, Generation: 1}},
		recovery: &sidecar.SidecarRecovery{
			Phase: sidecar.SidecarRecoveryAnchored, OfferRotate: true,
			Repos: []*sidecar.GkmRecoveryRepo{{RepoId: sidecar.NewId(), Waiting: errors.New("a GroupInfo above 16 leaves")}},
		},
	}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	tty := &testTty{lines: []string{testUrRecoveryWords(t), "n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "login", "--recover"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout.String(), "recovered") || !strings.Contains(stdout.String(), "a GroupInfo above 16 leaves") ||
		!strings.Contains(stdout.String(), "ur keychain recovery-rotate") || !strings.Contains(tty.written.String(), "set a new recovery code now?") {
		t.Errorf("stdout %q, terminal %q", stdout.String(), tty.written.String())
	}

	target.recovery = &sidecar.SidecarRecovery{Phase: sidecar.SidecarRecoveryStopped}
	target.err = sidecar.ErrSidecarRecoveryStopped
	tty.lines = []string{testUrRecoveryWords(t)}
	if code := cli.main(context.Background(), []string{"ur", "login", "--recover"}); code == urExitOk {
		t.Error("a stopped recovery exited ok")
	}
}

// recovery.recover is a Confirm method: only a confirmed control call runs it, never MCP or an unconfirmed call.
func TestRecoveryRecoverIsConfirmOnly(t *testing.T) {
	methods := urLoginRecoverMethods(&testUrRecoverTarget{})
	if len(methods) != 1 || methods[0].Name != urMethodRecoveryRecover || !methods[0].Confirm {
		t.Fatalf("methods %+v", methods)
	}
	if methods := urLoginRecoverMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no Sidecar serves recovery.recover")
	}
}
