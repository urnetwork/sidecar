// ur acl: test runs in the daemon when one answers and over the document alone when none does, with no network either
// way; push is refused with no terminal and from a non-writer, saves only on a yes and names the preview's digest, and
// its save method is a Confirm one; log lists the change audit.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A daemon target that answers the acl methods as a test sets them.
type testUrAclTarget struct {
	testUrDaemonTarget
	report   *sidecar.AclPolicyTestReport
	plan     *sidecar.AclSavePlan
	planErr  error
	tested   []string
	planned  []string
	saved    []string
	digests  [][32]byte
	logEntry []sidecar.AclLogEntry
}

func (self *testUrAclTarget) testAclPolicy(ctx context.Context, source []byte) (*sidecar.AclPolicyTestReport, error) {
	self.tested = append(self.tested, string(source))
	return self.report, nil
}

func (self *testUrAclTarget) planAclPolicy(ctx context.Context, source []byte) (*sidecar.AclSavePlan, error) {
	self.planned = append(self.planned, string(source))
	if self.planErr != nil {
		return nil, self.planErr
	}
	return self.plan, nil
}

func (self *testUrAclTarget) saveAclPolicy(ctx context.Context, source []byte, digest [32]byte) (*bridge.AuthPin, error) {
	self.saved = append(self.saved, string(source))
	self.digests = append(self.digests, digest)
	return &bridge.AuthPin{Version: 42}, nil
}

func (self *testUrAclTarget) aclLog() ([]sidecar.AclLogEntry, error) {
	return self.logEntry, nil
}

// A policy file whose one test fails on its own world: dana dials no one.
const testUrAclPolicy = `{
  "grants": [ { "src": ["user:amir@cli.example"], "dst": ["user:dana@cli.example"], "allow": ["dial"] } ],
  "tests": [
    { "src": "amir@cli.example", "accept": ["user:dana@cli.example#dial"] },
    { "src": "dana@cli.example", "accept": ["user:amir@cli.example#dial"] },
  ],
}`

// The policy written to a file of the test's.
func testUrAclPolicyFile(t *testing.T, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.hujson")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// With a daemon, ur acl test runs its tests there and prints each failure with the document's text; with none, the
// document alone, which it says, and no network either way.
func TestAclTestRunsWithNoNetwork(t *testing.T) {
	path := testUrAclPolicyFile(t, testUrAclPolicy)
	target := &testUrAclTarget{report: &sidecar.AclPolicyTestReport{TestCount: 2, CheckCount: 2,
		Failures: []sidecar.AclPolicyTestFailure{{Test: 1, List: "accept", Check: 0, Reason: "refused: no_grant"}}}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "acl", "test", path}); code != urExitFailed {
		t.Fatalf("a failing test: exit %d", code)
	}
	if len(target.tested) != 1 || target.tested[0] != testUrAclPolicy ||
		!strings.Contains(stdout.String(), "FAIL tests[1].accept[0] user:dana@cli.example user:amir@cli.example#dial: refused: no_grant") {
		t.Errorf("the daemon's run: %q", stdout.String())
	}
	target.report = &sidecar.AclPolicyTestReport{TestCount: 2, CheckCount: 2}
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "acl", "test", path}); code != urExitOk || !strings.Contains(stdout.String(), "2 tests, 2 checks passed") {
		t.Errorf("a passing run: exit %d, %q", code, stdout.String())
	}

	// no daemon answers: the document's own world, and nothing spawns
	alone, aloneOut, _ := newTestUrCli(filepath.Join(t.TempDir(), "no-daemon.sock"))
	alone.spawnDaemon = func(args []string) error {
		t.Error("ur acl test spawned a daemon")
		return errors.New("no spawn")
	}
	if code := alone.main(context.Background(), []string{"ur", "acl", "test", path}); code != urExitFailed {
		t.Fatalf("alone: exit %d", code)
	}
	if !strings.Contains(aloneOut.String(), "document's own world") || !strings.Contains(aloneOut.String(), "FAIL tests[1].accept[0]") ||
		strings.Contains(aloneOut.String(), "tests[0]") {
		t.Errorf("alone: %q", aloneOut.String())
	}

	// a document that does not parse reaches no daemon
	bad := testUrAclPolicyFile(t, `{ "grants": [ { "src": ["user:x"] } ] }`)
	if code := cli.main(context.Background(), []string{"ur", "acl", "test", bad}); code != urExitFailed || len(target.tested) != 2 {
		t.Errorf("a bad document: exit %d, %d runs", code, len(target.tested))
	}
}

// ur acl push: refused before anything is planned with no terminal, refused from a non-writer, nothing saved on a no,
// and on a yes the save of the preview's own digest.
func TestAclPushNeedsATerminalAndAWriter(t *testing.T) {
	path := testUrAclPolicyFile(t, testUrAclPolicy)
	plan := &sidecar.AclSavePlan{Tests: &sidecar.AclPolicyTestReport{TestCount: 1, CheckCount: 1}, Preview: &sidecar.AclSavePreview{}, Digest: [32]byte{7, 7, 7}}
	target := &testUrAclTarget{plan: plan}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)

	if code := cli.main(context.Background(), []string{"ur", "acl", "push", path}); code != urExitFailed || len(target.planned) != 0 {
		t.Fatalf("no terminal: exit %d, %d plans", code, len(target.planned))
	}
	if !strings.Contains(stderr.String(), "terminal") {
		t.Errorf("no terminal: %q", stderr.String())
	}

	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "acl", "push", path}); code != urExitOk || len(target.saved) != 0 || !strings.Contains(stdout.String(), "nothing changed") {
		t.Fatalf("a no: exit %d, %d saves", code, len(target.saved))
	}

	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "acl", "push", path}); code != urExitOk || len(target.saved) != 1 ||
		target.digests[0] != plan.Digest || target.saved[0] != testUrAclPolicy || !strings.Contains(stdout.String(), "in force from the base at 42") {
		t.Fatalf("a yes: exit %d, saves %d", code, len(target.saved))
	}

	target.planErr = sidecar.ErrConfigWriterNotWriter
	stderr.Reset()
	if code := cli.main(context.Background(), []string{"ur", "acl", "push", path}); code != urExitFailed || len(target.saved) != 1 ||
		!strings.Contains(stderr.String(), "not a config writer") {
		t.Errorf("a non-writer: exit %d, %q", code, stderr.String())
	}

	// a preview whose tests fail saves nothing and asks nothing
	target.planErr = nil
	target.plan = &sidecar.AclSavePlan{Tests: &sidecar.AclPolicyTestReport{TestCount: 1, CheckCount: 1,
		Failures: []sidecar.AclPolicyTestFailure{{Test: 0, List: "accept", Check: 0, Reason: "refused: no_grant"}}}, Preview: &sidecar.AclSavePreview{}}
	if code := cli.main(context.Background(), []string{"ur", "acl", "push", path}); code != urExitFailed || len(target.saved) != 1 {
		t.Errorf("failing tests: exit %d, %d saves", code, len(target.saved))
	}
}

// acl.push is a Confirm method: only a confirmed control call saves, never MCP or an unconfirmed call.
func TestAclPushIsConfirmOnly(t *testing.T) {
	methods := urAclMethods(&testUrAclTarget{})
	if len(methods) != 4 {
		t.Fatalf("%d methods", len(methods))
	}
	for _, method := range methods {
		if (method.Name == urMethodAclPush) != method.Confirm {
			t.Errorf("%s: confirm %v", method.Name, method.Confirm)
		}
	}
	if methods := urAclMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no Sidecar serves the acl methods")
	}
}

// ur acl log prints each head of the change audit.
func TestAclLogPrintsTheChangeAudit(t *testing.T) {
	signer := sidecar.NewId()
	target := &testUrAclTarget{logEntry: []sidecar.AclLogEntry{{ConfigVersion: 3, N: 17, TimeMs: 1_800_000_000_000, SignerSidecarId: signer}}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "acl", "log"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout.String(), "config version 3  base 17  signer "+signer.String()) {
		t.Errorf("%q", stdout.String())
	}
}

// A target that files ur evs lock's RepoVersioning as a test records it.
type testUrEvsLockTarget struct {
	testUrDaemonTarget
	filed []string
}

func (self *testUrEvsLockTarget) fileRepoLock(ctx context.Context, repoId sidecar.Id, lock bool) error {
	self.filed = append(self.filed, fmt.Sprintf("%s %v", repoId, lock))
	return nil
}

// ur evs lock and unlock (ACL-M10-01): refused with no terminal, nothing filed on a no, the lock and the unlock each on
// a yes, through a Confirm method alone.
func TestEvsLockFilesOnlyOnAYes(t *testing.T) {
	repoId := sidecar.NewId()
	target := &testUrEvsLockTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "evs", "lock", repoId.String()}); code != urExitFailed || len(target.filed) != 0 {
		t.Fatalf("no terminal: exit %d, %v", code, target.filed)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "evs", "lock", repoId.String()}); code != urExitOk || len(target.filed) != 0 {
		t.Fatalf("a no: exit %d, %v", code, target.filed)
	}
	if !strings.Contains(stdout.String(), "voided by the lock") {
		t.Errorf("no word of pending drops: %q", stdout.String())
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	for _, word := range []string{"lock", "unlock"} {
		if code := cli.main(context.Background(), []string{"ur", "evs", word, repoId.String()}); code != urExitOk {
			t.Fatalf("%s: exit %d", word, code)
		}
	}
	if !slices.Equal(target.filed, []string{repoId.String() + " true", repoId.String() + " false"}) {
		t.Errorf("filed %v", target.filed)
	}
	methods := urEvsLockMethods(target)
	if len(methods) != 1 || !methods[0].Confirm {
		t.Error("evs.lock runs unconfirmed")
	}
}
