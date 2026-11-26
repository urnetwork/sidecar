package main

// ur admin versioning's show (cmd_admin_versioning.go) over a stand-in target: stdout is the rules as --rules takes
// them, whatever is carried, and stderr names a carried record's signer and why it no longer stands (QD-1207), or says
// the head's records could not be read; a record whose signer stands, and the platform rule, add nothing.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A daemon target hosting versioning rules and the head's carried records, counting the listings asked of it.
type testUrAdminVersioningTarget struct {
	*testUrDaemonTarget

	stateLock    sync.Mutex
	rules        *protocol.VersioningRules
	carried      []*sidecar.ConfigCarriedRecord
	carriedErr   error
	carriedCalls int
}

func (self *testUrAdminVersioningTarget) versioningRules() (*protocol.VersioningRules, bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.rules, true, nil
}

func (self *testUrAdminVersioningTarget) saveVersioningRules(ctx context.Context, rules *protocol.VersioningRules) error {
	return errors.New("no save in this test")
}

func (self *testUrAdminVersioningTarget) carriedConfigRecords(ctx context.Context) ([]*sidecar.ConfigCarriedRecord, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.carriedCalls += 1
	return self.carried, self.carriedErr
}

// A ur over a daemon serving target's versioning methods, and what it printed on stdout and stderr.
func testUrAdminVersioningCli(t *testing.T, target *testUrAdminVersioningTarget) (*urCli, *strings.Builder, *strings.Builder) {
	t.Helper()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, method := range urAdminVersioningMethods(target) {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, _, _ := newTestUrCli(daemon.socketPath)
	stdout, stderr := &strings.Builder{}, &strings.Builder{}
	cli.stdout, cli.stderr = stdout, stderr
	return cli, stdout, stderr
}

// Rules a test's target holds.
func testUrAdminVersioningRules() *protocol.VersioningRules {
	return &protocol.VersioningRules{Rules: []*protocol.VersioningRule{
		{PathGlob: "build/**", SizeAboveBytes: 1024 * 1024, Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF},
	}}
}

// The show prints the rules on stdout exactly as --rules takes them, and on stderr the carried VersioningRules' signer,
// its member, why it no longer stands and who files another, leaving the carried ServiceSettings to ur admin settings.
func TestUrAdminVersioningListsItsCarriedRecordOnStderr(t *testing.T) {
	settings, _ := testUrAdminCarried()
	memberId := sidecar.NewId()
	rules := &sidecar.ConfigCarriedRecord{
		Record: sidecar.ConfigHeadVersioningRulesPath, SignerId: sidecar.NewId(), MemberId: &memberId, Why: sidecar.ConfigCarriedRevoked, At: 7, Role: "owner",
	}
	target := &testUrAdminVersioningTarget{testUrDaemonTarget: &testUrDaemonTarget{}, rules: testUrAdminVersioningRules(), carried: []*sidecar.ConfigCarriedRecord{settings, rules}}
	cli, stdout, stderr := testUrAdminVersioningCli(t, target)
	if code := cli.main(context.Background(), []string{"ur", "admin", "versioning"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if text := stdout.String(); text != urFormatVersioningRules(testUrAdminVersioningRules())+"\n" {
		t.Fatalf("stdout is not the rules alone:\n%s", text)
	}
	if _, err := urParseVersioningRules(strings.TrimSpace(stdout.String())); err != nil {
		t.Fatalf("stdout does not parse as --rules: %v", err)
	}
	want := "ur admin versioning: these rules stand under a signer who no longer stands until another record is filed: versioning_rules: signed by " +
		rules.SignerId.String() + " of member " + memberId.String() +
		", revoked at position 7; an Owner, Admin or Network admin files another: ur admin versioning --rules\n"
	if text := stderr.String(); text != want {
		t.Errorf("stderr:\n%s\nwant\n%s", text, want)
	}
}

// A show whose head's records could not be read says so on stderr, the rules still on stdout alone.
func TestUrAdminVersioningSaysWhenItCannotListItsCarriedRecord(t *testing.T) {
	target := &testUrAdminVersioningTarget{testUrDaemonTarget: &testUrDaemonTarget{}, rules: testUrAdminVersioningRules(), carriedErr: errors.New("the head is not cached and evs does not answer")}
	cli, stdout, stderr := testUrAdminVersioningCli(t, target)
	if code := cli.main(context.Background(), []string{"ur", "admin", "versioning"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if text := stdout.String(); text != urFormatVersioningRules(testUrAdminVersioningRules())+"\n" {
		t.Errorf("stdout is not the rules alone:\n%s", text)
	}
	if text := stderr.String(); !strings.Contains(text, "whether these rules' signer still stands is not known here") {
		t.Errorf("stderr:\n%s", text)
	}
}

// Rules whose signer stands add nothing to stderr, though the settings' signer may not; the platform rule, with no
// record, asks for no listing at all.
func TestUrAdminVersioningListsNothingWhileItsSignerStands(t *testing.T) {
	settings, _ := testUrAdminCarried()
	target := &testUrAdminVersioningTarget{testUrDaemonTarget: &testUrDaemonTarget{}, rules: testUrAdminVersioningRules(), carried: []*sidecar.ConfigCarriedRecord{settings}}
	cli, stdout, stderr := testUrAdminVersioningCli(t, target)
	if code := cli.main(context.Background(), []string{"ur", "admin", "versioning"}); code != urExitOk || stderr.Len() != 0 ||
		stdout.String() != urFormatVersioningRules(testUrAdminVersioningRules())+"\n" {
		t.Fatalf("exit %d, stdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}

	target.stateLock.Lock()
	target.rules, target.carriedCalls = nil, 0
	target.stateLock.Unlock()
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "admin", "versioning"}); code != urExitOk || stderr.Len() != 0 ||
		!strings.Contains(stdout.String(), "no VersioningRules: the platform rule holds") {
		t.Fatalf("the platform rule: exit %d, stdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	target.stateLock.Lock()
	defer target.stateLock.Unlock()
	if target.carriedCalls != 0 {
		t.Errorf("the platform rule asked for %d listings", target.carriedCalls)
	}
}
