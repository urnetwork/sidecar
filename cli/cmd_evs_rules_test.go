// ur evs rules and ur evs repair (EVS1-M6-05; DESIGN-DETAILS 16.2.8, 16.2.9): each reaches its method over a target
// that hosts a Sidecar, with the daemon's refusal printed; a path and a rules file are read before anything is asked;
// and show's, a filing's, a repair's and status's lines. What the methods do against evs is the root's
// (evs_prefix_repair_test.go, evs_local_pin_test.go). At launch (QD-1032) the daemon's composition keeps the rules dark,
// and every form refuses through its method, naming the deferral, before anything is asked.

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A daemon target whose evs client and Sidecar are not there, with the reason a test sets.
type testUrEvsRulesTarget struct {
	testUrDaemonTarget
	err error
}

func (self *testUrEvsRulesTarget) evsClient() (*sidecar.EvsClient, error) {
	return nil, self.err
}

func (self *testUrEvsRulesTarget) prefixRulesSidecar() (*sidecar.Sidecar, error) {
	return nil, self.err
}

// A daemon target whose evs client and Sidecar are a standing network's, as the daemon composes them.
type testUrEvsRulesClientTarget struct {
	testUrDaemonTarget
	client  *sidecar.EvsClient
	running *sidecar.Sidecar
}

func (self *testUrEvsRulesClientTarget) evsClient() (*sidecar.EvsClient, error) {
	return self.client, nil
}

func (self *testUrEvsRulesClientTarget) prefixRulesSidecar() (*sidecar.Sidecar, error) {
	return self.running, nil
}

// QD-1032's launch configuration: the daemon composes each network's evs client with the client-checked prefix rules
// dark, so its Sidecar files no set, and every form of ur evs rules and ur evs repair refuses through its method,
// naming the deferral, before anything is asked: lift, which reads no subject, among them, where a question first would
// have met this test's missing terminal.
func TestDaemonRunsThePrefixRulesDarkAtLaunch(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	network := world.networks[0]
	running := world.host(network, nil)
	world.standing(running, network)
	client, err := urDaemonEvsClient(running)
	if err != nil {
		t.Fatal(err)
	}
	if client.PrefixRulesEnabled() {
		t.Fatal("the daemon's evs client runs the prefix rules at launch")
	}
	request := &sidecar.AclPrefixRulesRequest{RepoId: sidecar.NewId(), Change: sidecar.AclPrefixRulesLift}
	if _, err := running.FilePrefixRules(world.ctx, client, request, sidecar.SidecarActConfirmed); !errors.Is(err, sidecar.ErrAclPrefixRulesDeferred) {
		t.Fatalf("a filing at launch: %v", err)
	}

	daemon := startTestControlDaemon(t, &testUrEvsRulesClientTarget{client: client, running: running}, nil)
	repoId := sidecar.NewId()
	file := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(file, []byte(`{"rules": [{"subject": "tag:ci", "path": "agents/build"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"ur", "evs", "rules", repoId.String(), "show", "--history"},
		{"ur", "evs", "rules", repoId.String(), "allow", "tag:ci", "agents/build"},
		{"ur", "evs", "rules", repoId.String(), "deny", "tag:ci"},
		{"ur", "evs", "rules", repoId.String(), "set", file},
		{"ur", "evs", "rules", repoId.String(), "lift"},
		{"ur", "evs", "repair", repoId.String()},
		{"ur", "evs", "repair", repoId.String(), "src/main.go"},
	} {
		cli, _, stderr := newTestUrCli(daemon.socketPath)
		if code := cli.main(context.Background(), args); code == urExitOk || !strings.Contains(stderr.String(), "deferred past launch (QD-1032)") {
			t.Errorf("%v: exit %d: %s", args, code, stderr.String())
		}
	}
}

func TestEvsRulesAndRepairReachTheDaemonsMethods(t *testing.T) {
	repoId := sidecar.NewId()
	target := &testUrEvsRulesTarget{err: errors.New("the evs client is not up")}
	daemon := startTestControlDaemon(t, target, nil)
	for _, args := range [][]string{
		{"ur", "evs", "rules", repoId.String(), "show", "--history"},
		{"ur", "evs", "rules", repoId.String(), "allow", "tag:ci", "agents/build"},
		{"ur", "evs", "rules", repoId.String(), "deny", "group:eng"},
		{"ur", "evs", "repair", repoId.String()},
		{"ur", "evs", "repair", repoId.String(), "src/main.go"},
	} {
		cli, _, stderr := newTestUrCli(daemon.socketPath)
		if code := cli.main(context.Background(), args); code == urExitOk || !strings.Contains(stderr.String(), "the evs client is not up") {
			t.Errorf("%v: exit %d: %s", args, code, stderr.String())
		}
	}
	for _, args := range [][]string{
		{"ur", "evs", "rules", "not-a-repo", "show"},
		{"ur", "evs", "repair", "not-a-repo"},
	} {
		cli, _, stderr := newTestUrCli(daemon.socketPath)
		if code := cli.main(context.Background(), args); code == urExitOk || !strings.Contains(stderr.String(), "is no repo id") {
			t.Errorf("%v: exit %d: %s", args, code, stderr.String())
		}
	}
	// a rules file that does not parse, or names an empty component, is refused before the daemon is asked
	dir := t.TempDir()
	for name, text := range map[string]string{
		"broken.json": "{",
		"empty.json":  `{"rules": [{"subject": "tag:ci", "path": "agents//build"}]}`,
	} {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		cli, _, stderr := newTestUrCli(daemon.socketPath)
		if code := cli.main(context.Background(), []string{"ur", "evs", "rules", repoId.String(), "set", file}); code == urExitOk || strings.Contains(stderr.String(), "not up") {
			t.Errorf("%s: exit %d: %s", name, code, stderr.String())
		}
	}
}

func TestEvsRulePaths(t *testing.T) {
	for _, path := range []string{"", "/"} {
		if names, err := urEvsRulePath(path); err != nil || names != nil {
			t.Errorf("%q: %v %v", path, names, err)
		}
	}
	if names, err := urEvsRulePath("agents/build"); err != nil || len(names) != 2 || string(names[1]) != "build" {
		t.Errorf("agents/build: %v %v", names, err)
	}
	for _, path := range []string{"agents//build", "/agents", "agents/", "a\x00b"} {
		if _, err := urEvsRulePath(path); err == nil {
			t.Errorf("%q passed", path)
		}
	}
	if text := urEvsRulePathText(nil); text != "every path" {
		t.Errorf("no path prints %q", text)
	}
}

// show's lines: the set in force with each rule's subject and prefix, the history's states, and each ref's binding,
// a deleted one held at its re-creation; a pending set and no set; a filing's lines with the first-set notice and an
// admin left out.
func TestEvsRulesLines(t *testing.T) {
	admin, ci, signer := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	subjectText := func(id sidecar.Id) string {
		switch id {
		case admin:
			return "sidecar:admin"
		case ci:
			return "tag:ci"
		case signer:
			return "sidecar:filer"
		}
		return "id:" + id.String()
	}
	inForce := &sidecar.AclPrefixRuleSet{At: 41, Signer: signer, State: sidecar.AclPrefixSetOpened, Rules: []*protocol.PrefixRule{
		{Subject: admin.Bytes(), Action: protocol.PrefixAction_PREFIX_ACTION_WRITE},
		{Subject: ci.Bytes(), Path: [][]byte{[]byte("agents"), []byte("build")}, Action: protocol.PrefixAction_PREFIX_ACTION_WRITE},
	}}
	pushId := sidecar.NewId()
	status := &sidecar.EvsPrefixRulesStatus{
		RepoId: sidecar.NewId(), PinVersion: 45, NewestAt: 41, InForce: inForce,
		Sets: []*sidecar.AclPrefixRuleSet{
			{At: 12, Signer: signer, State: sidecar.AclPrefixSetVoid, VoidCause: sidecar.AclPrefixVoidSeal},
			inForce,
		},
		Refs: []*sidecar.EvsPrefixRef{
			{Name: []byte("main"), PinVersion: 44, Binding: sidecar.EvsPrefixBound},
			{Name: []byte("notes"), PinVersion: 30, Binding: sidecar.EvsPrefixUnbound},
			{Name: []byte("old"), Binding: sidecar.EvsPrefixDeleted},
			{Name: []byte("refs/tags/v1"), Binding: sidecar.EvsPrefixTag},
			{Name: []byte("stuck"), Binding: sidecar.EvsPrefixStopped},
			{Name: []byte("fresh"), Binding: sidecar.EvsPrefixBound, PushId: &pushId, Version: 9},
		},
	}
	lines := strings.Join(urEvsRulesStatusLines(status, true, subjectText), "\n")
	for _, want := range []string{
		"the set in force at position 41, filed by sidecar:filer:", "sidecar:admin", "every path", "tag:ci", "agents/build/",
		"at 12  sidecar:filer  void (seal)", "at 41  sidecar:filer  opened, in force",
		"refs against the newest set, at position 41:", "bound (its head's pin is 44)", "not bound yet (its head's pin is 30)",
		"old                      deleted, held at re-creation", "a tag: it holds no file and takes no pin push",
		"stopped on this device: its recovery binds it", "bound by its pin push at version 9",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("show does not print %q:\n%s", want, lines)
		}
	}
	if lines := urEvsRulesStatusLines(status, false, subjectText); strings.Contains(strings.Join(lines, "\n"), "sets:") {
		t.Errorf("show without --history prints the history")
	}
	pending := &sidecar.EvsPrefixRulesStatus{RepoId: status.RepoId, Sets: status.Sets, Unread: &sidecar.AclPrefixRuleSet{At: 50, State: sidecar.AclPrefixSetPending}}
	if lines := urEvsRulesStatusLines(pending, false, subjectText); !strings.Contains(lines[0], "position 50 is pending") {
		t.Errorf("a pending set: %v", lines)
	}
	if lines := urEvsRulesStatusLines(&sidecar.EvsPrefixRulesStatus{RepoId: status.RepoId}, false, subjectText); !strings.Contains(lines[0], "no prefix rules") {
		t.Errorf("no set: %v", lines)
	}
	filing := &sidecar.EvsPrefixRulesFiling{
		Filed: &sidecar.AclPrefixRulesFiled{
			Pin: &bridge.AuthPin{Version: 52}, Set: &protocol.PrefixRuleSet{Rules: inForce.Rules}, UnnamedAdmins: []sidecar.Id{admin},
		},
		FirstSet: true,
		Refs: []*sidecar.EvsPrefixRef{
			{Name: []byte("main"), Binding: sidecar.EvsPrefixFailed, Err: "evs: a refusal"},
			{Name: []byte("notes"), Binding: sidecar.EvsPrefixWaiting},
		},
	}
	lines = strings.Join(urEvsRulesFilingLines(filing, subjectText), "\n")
	for _, want := range []string{
		"filed the set at position 52, 2 rule(s)", "the repo's first set: devices older than the release",
		"the repo's admin sidecar:admin, which writes nothing", "its pin push failed (evs: a refusal); the journal sends it again",
		"waits for this device's log to hold the set",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("a filing does not print %q:\n%s", want, lines)
		}
	}
}

func TestEvsRepairAndStatusLines(t *testing.T) {
	lines := strings.Join(urEvsRepairLines(&sidecar.EvsPrefixRepairResult{PushCount: 2, ByteCount: 300, SettledCount: 3, WaitingCount: 1}), "\n")
	for _, want := range []string{"2 repair push(es), 300 bytes; 3 journal unit(s) settled", "1 unit(s) still wait"} {
		if !strings.Contains(lines, want) {
			t.Errorf("repair does not print %q:\n%s", want, lines)
		}
	}
	repoId, refId, signer := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	status := urStatusPrefixLines([]*sidecar.EvsPrefixIgnored{
		{RepoId: repoId, RefId: refId, Path: "src/main.go", Named: true, Version: 3, Kind: sidecar.EvsPrefixIgnoredWrite, SignerSidecarId: signer},
		{RepoId: repoId, RefId: refId, Version: 4, Kind: sidecar.EvsPrefixIgnoredNames, SignerSidecarId: signer},
	})
	if len(status) != 2 || !strings.Contains(status[0], "src/main.go: version 3 (write) ignored, signed by "+signer.String()) ||
		!strings.Contains(status[1], "a path this device's mirror holds no name for") {
		t.Errorf("status prints %v", status)
	}
}
