//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A member's harness config standing in for the vault's reader.
type testClaimsConfig struct {
	member *SidecarMemberClaims
	err    error
}

func (self *testClaimsConfig) MemberClaims(ctx context.Context, networkId Id, agentLabel string) (*SidecarMemberClaims, error) {
	return self.member, self.err
}

// A daemon hosting one network whose verified state is the test net's, with the net, the network's Sidecar and a work
// tree under home whose remote keys its project.
type testClaimsWorld struct {
	t         *testing.T
	daemon    *Daemon
	net       *testConfigNet
	sidecar   *Sidecar
	networkId Id
	home      string
	project   string
	// the next base's config version
	configVersion uint64
}

// The project's key, from its remote.
const testClaimsProjectKey = "git.example/acme/billing"

// A world whose network is a team, its directory filed by the owner, when team is set; else a network with no
// directory.
func newTestClaimsWorld(t *testing.T, team bool) *testClaimsWorld {
	t.Helper()
	net := newTestConfigNet(t)
	if team {
		filer := &testTeamDirectoryFiler{net: net, device: net.owner}
		if _, err := FileTeamDirectory(context.Background(), filer.args()); err != nil {
			t.Fatal(err)
		}
	}
	networkId := NewId()
	instance := newInstanceOn(t, NewSidecarMemoryBackend(), newFakeKeyStore())
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	if _, err := instance.createKeychain(networkId); err != nil {
		t.Fatal(err)
	}
	sidecar := newSidecarBase(nil, cheapKeychainSettings())
	sidecar.instance = instance
	sidecar.networkId = &networkId
	// the verified state as a ConfigClient following the net's log holds it, with no watcher behind it
	client := &ConfigClient{}
	client.configLog.Store(net.log)
	sidecar.authorities.authority = client.Authority()

	home := t.TempDir()
	project := filepath.Join(home, "work", "billing")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(project, ".git", "config"),
		"[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = https://other.example/fork.git\n"+
			"[remote \"origin\"]\n\turl = ssh://git@Git.Example:2222/acme/billing.git?ref=x\n")
	if err := os.MkdirAll(filepath.Join(project, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	daemon := newDispatchTestDaemon(t)
	daemon.settings.Home = home
	if err := daemon.AddSidecar(networkId, sidecar); err != nil {
		t.Fatal(err)
	}
	for _, method := range DaemonDirectoryMethods(daemon, nil) {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	return &testClaimsWorld{t: t, daemon: daemon, net: net, sidecar: sidecar, networkId: networkId, home: home, project: project, configVersion: 2}
}

// The hello of a caller in the project's src/, in mode.
func (self *testClaimsWorld) hello(mode string) *DaemonHello {
	return &DaemonHello{UrLocal: 1, Mode: mode, Version: "synthetic-version", Cwd: filepath.Join(self.project, "src")}
}

// Commits a .ur with claims value, or removes it for "".
func (self *testClaimsWorld) commit(value string) {
	self.t.Helper()
	path := filepath.Join(self.project, ".ur")
	if value == "" {
		os.Remove(path)
		return
	}
	writeTestFile(self.t, path, "claims = \""+value+"\"\nproject = \"billing-api\"\n")
}

// A base whose ServiceSettings.directory.runs is runs.
func (self *testClaimsWorld) teamDefault(runs protocol.DirectoryRunsMode) {
	self.t.Helper()
	self.net.source.settings[[sha256.Size]byte(testConfigHeadSha256(self.configVersion))] =
		&protocol.ServiceSettings{Directory: &protocol.ServiceDirectorySettings{Runs: runs}}
	if verdict := self.net.fold(self.net.owner, self.net.n, self.configVersion); !verdict.Accepted() {
		self.t.Fatalf("the base: %v", verdict.Refusal)
	}
	self.configVersion += 1
}

// One request line in mode through a fresh session of the world's caller.
func (self *testClaimsWorld) dispatch(mode string, line string) *daemonRpcResponse {
	return self.daemon.dispatch([]byte(line), &daemonSession{hello: self.hello(mode)}, runUnbounded)
}

// D-CORE-18's rule, read whole: off in a personal network, the team's default, the member's, a narrower .ur.
func TestNarrowerClaimsApplyAtOnce(t *testing.T) {
	cases := []struct {
		name   string
		inputs *SidecarClaimsInputs
		want   SidecarClaims
		source string
	}{
		{name: "personal", inputs: &SidecarClaimsInputs{Committed: SidecarClaimsAuto}, want: SidecarClaimsOff, source: SidecarClaimsSourcePersonal},
		{name: "team default", inputs: &SidecarClaimsInputs{Team: true}, want: SidecarClaimsAuto, source: SidecarClaimsSourceTeam},
		{name: "team prompt", inputs: &SidecarClaimsInputs{Team: true, TeamDefault: SidecarClaimsPrompt}, want: SidecarClaimsPrompt, source: SidecarClaimsSourceTeam},
		{name: "unknown team value", inputs: &SidecarClaimsInputs{Team: true, TeamDefault: 9}, want: SidecarClaimsOff, source: SidecarClaimsSourceTeam},
		{name: "committed narrower", inputs: &SidecarClaimsInputs{Team: true, Committed: SidecarClaimsPrompt}, want: SidecarClaimsPrompt, source: SidecarClaimsSourceCommitted},
		{name: "committed off", inputs: &SidecarClaimsInputs{Team: true, Committed: SidecarClaimsOff}, want: SidecarClaimsOff, source: SidecarClaimsSourceCommitted},
		{name: "member's project over its default", inputs: &SidecarClaimsInputs{Team: true, ProjectKey: "p",
			Member: &SidecarMemberClaims{Default: SidecarClaimsOff, Projects: map[string]SidecarClaims{"p": SidecarClaimsPrompt}}},
			want: SidecarClaimsPrompt, source: SidecarClaimsSourceProject},
		{name: "member opts out", inputs: &SidecarClaimsInputs{Team: true, Member: &SidecarMemberClaims{Default: SidecarClaimsOff}},
			want: SidecarClaimsOff, source: SidecarClaimsSourceMember},
		{name: "committed narrows the member's", inputs: &SidecarClaimsInputs{Team: true, ProjectKey: "p", Committed: SidecarClaimsOff,
			Member: &SidecarMemberClaims{Projects: map[string]SidecarClaims{"p": SidecarClaimsAuto}}},
			want: SidecarClaimsOff, source: SidecarClaimsSourceCommitted},
	}
	for _, c := range cases {
		resolution := ResolveSidecarClaims(c.inputs)
		if resolution.Claims != c.want || resolution.Source != c.source || resolution.Pending != 0 {
			t.Errorf("%s: %+v", c.name, resolution)
		}
	}

	// through the daemon: a committed prompt applies at the next session, from any mode, with nothing confirmed
	world := newTestClaimsWorld(t, true)
	world.commit("prompt")
	resolution := world.daemon.ResolveClaims(context.Background(), world.hello(DaemonModeMcp), world.networkId)
	if resolution.Claims != SidecarClaimsPrompt || resolution.Source != SidecarClaimsSourceCommitted ||
		resolution.ProjectKey != testClaimsProjectKey || resolution.ProjectLabel != "billing-api" {
		t.Fatalf("a committed prompt: %+v", resolution)
	}
	// the person narrows further from a hook, which needs no confirmation
	response := world.dispatch(DaemonModeHook, `{"jsonrpc":"2.0","id":1,"method":"directory.claims","params":{"claims":"off"}}`)
	reply := &DaemonDirectoryClaimsReply{}
	if response.Error != nil || json.Unmarshal(response.Result, reply) != nil || reply.NeedsConfirmation || reply.Claims != "off" || reply.Source != SidecarClaimsSourceConfirmed {
		t.Fatalf("a narrower choice: %+v %s", response.Error, response.Result)
	}

	// a personal network announces nothing, whatever .ur asks
	personal := newTestClaimsWorld(t, false)
	personal.commit("auto")
	if resolution := personal.daemon.ResolveClaims(context.Background(), personal.hello(DaemonModeMcp), personal.networkId); resolution.Claims != SidecarClaimsOff ||
		resolution.Source != SidecarClaimsSourcePersonal {
		t.Fatalf("a personal network: %+v", resolution)
	}
	if _, err := personal.daemon.ChooseClaims(context.Background(), personal.hello(DaemonModeControl), personal.networkId, SidecarClaimsOff, true); !errors.Is(err, ErrDirectoryNone) {
		t.Fatalf("a choice in a personal network: %v", err)
	}
}

// A committed .ur wider than the member's value waits for the member's confirmation, which only a confirmed control
// call gives, never a hook's or an unconfirmed one; a changed .ur is judged afresh.
func TestWiderClaimsNeedConfirmation(t *testing.T) {
	pending := ResolveSidecarClaims(&SidecarClaimsInputs{Team: true, TeamDefault: SidecarClaimsOff, Committed: SidecarClaimsAuto})
	if pending.Claims != SidecarClaimsOff || pending.Pending != SidecarClaimsAuto {
		t.Fatalf("a wider .ur: %+v", pending)
	}
	memberOff := ResolveSidecarClaims(&SidecarClaimsInputs{Team: true, ProjectKey: "p", Committed: SidecarClaimsPrompt,
		Member: &SidecarMemberClaims{Projects: map[string]SidecarClaims{"p": SidecarClaimsOff}}})
	if memberOff.Claims != SidecarClaimsOff || memberOff.Pending != SidecarClaimsPrompt {
		t.Fatalf("a .ur wider than the member's project value: %+v", memberOff)
	}

	world := newTestClaimsWorld(t, true)
	world.teamDefault(protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_OFF)
	world.commit("auto")
	ctx := context.Background()
	resolution := world.daemon.ResolveClaims(ctx, world.hello(DaemonModeMcp), world.networkId)
	if resolution.Claims != SidecarClaimsOff || resolution.Pending != SidecarClaimsAuto || resolution.Source != SidecarClaimsSourceTeam {
		t.Fatalf("before any confirmation: %+v", resolution)
	}

	// directory.claims answers that a wider value needs the person, and records nothing
	response := world.dispatch(DaemonModeControl, `{"jsonrpc":"2.0","id":1,"method":"directory.claims","params":{"claims":"auto"}}`)
	reply := &DaemonDirectoryClaimsReply{}
	if response.Error != nil || json.Unmarshal(response.Result, reply) != nil || !reply.NeedsConfirmation || reply.Claims != "off" {
		t.Fatalf("an unconfirmed widening: %+v %s", response.Error, response.Result)
	}
	// the Confirm method refuses a hook's, an mcp session's and an unconfirmed control call's
	for _, c := range []struct {
		mode string
		line string
	}{
		{mode: DaemonModeHook, line: `{"jsonrpc":"2.0","id":2,"method":"directory.claims.confirm","params":{"claims":"auto"},"ur_confirmed":true}`},
		{mode: DaemonModeMcp, line: `{"jsonrpc":"2.0","id":3,"method":"directory.claims.confirm","params":{"claims":"auto"},"ur_confirmed":true}`},
		{mode: DaemonModeControl, line: `{"jsonrpc":"2.0","id":4,"method":"directory.claims.confirm","params":{"claims":"auto"}}`},
	} {
		if response := world.dispatch(c.mode, c.line); response.Error == nil || response.Error.Code != DaemonRpcConfirmationRequired {
			t.Errorf("%s %s: %+v", c.mode, c.line, response.Error)
		}
	}
	if resolution := world.daemon.ResolveClaims(ctx, world.hello(DaemonModeMcp), world.networkId); resolution.Claims != SidecarClaimsOff {
		t.Fatalf("a refused widening applied: %+v", resolution)
	}
	if _, err := world.daemon.ChooseClaims(ctx, world.hello(DaemonModeControl), world.networkId, SidecarClaimsAuto, false); !errors.Is(err, ErrSidecarClaimsWider) {
		t.Fatalf("ChooseClaims widened unconfirmed: %v", err)
	}

	// confirmed on /dev/tty: the next session runs the committed value
	response = world.dispatch(DaemonModeControl, `{"jsonrpc":"2.0","id":5,"method":"directory.claims.confirm","params":{"claims":"auto"},"ur_confirmed":true}`)
	if response.Error != nil || json.Unmarshal(response.Result, reply) != nil || reply.Claims != "auto" || reply.Source != SidecarClaimsSourceConfirmed {
		t.Fatalf("a confirmed widening: %+v %s", response.Error, response.Result)
	}
	if resolution := world.daemon.ResolveClaims(ctx, world.hello(DaemonModeMcp), world.networkId); resolution.Claims != SidecarClaimsAuto || resolution.Pending != 0 {
		t.Fatalf("after the confirmation: %+v", resolution)
	}

	// a changed .ur is judged afresh: the confirmation was of auto, and prompt is wider than the team's off
	world.commit("prompt")
	if resolution := world.daemon.ResolveClaims(ctx, world.hello(DaemonModeMcp), world.networkId); resolution.Claims != SidecarClaimsOff ||
		resolution.Pending != SidecarClaimsPrompt {
		t.Fatalf("a changed .ur: %+v", resolution)
	}
	// and a .ur that does not parse asks for off
	writeTestFile(t, filepath.Join(world.project, ".ur"), "claims = auto\n")
	if resolution := world.daemon.ResolveClaims(ctx, world.hello(DaemonModeMcp), world.networkId); resolution.Claims != SidecarClaimsOff {
		t.Fatalf("a .ur that does not parse: %+v", resolution)
	}
}

// The value is fixed for each session with its instructions: a session's holder answers what it first resolved,
// whatever .ur, the harness config, the team's default or a confirmation does after; a new session sees the change.
func TestClaimsFixedPerSession(t *testing.T) {
	world := newTestClaimsWorld(t, true)
	config := &testClaimsConfig{}
	world.daemon.settings.Claims = config
	world.commit("prompt")
	ctx := context.Background()
	session := world.daemon.SessionClaims(world.hello(DaemonModeMcp))
	if resolution := session.For(ctx, world.networkId); resolution.Claims != SidecarClaimsPrompt {
		t.Fatalf("at the session's start: %+v", resolution)
	}

	world.commit("off")
	config.member = &SidecarMemberClaims{Default: SidecarClaimsOff}
	world.teamDefault(protocol.DirectoryRunsMode_DIRECTORY_RUNS_MODE_OFF)
	if resolution := session.For(ctx, world.networkId); resolution.Claims != SidecarClaimsPrompt || resolution.Source != SidecarClaimsSourceCommitted {
		t.Fatalf("an open session moved: %+v", resolution)
	}
	if resolution := world.daemon.SessionClaims(world.hello(DaemonModeMcp)).For(ctx, world.networkId); resolution.Claims != SidecarClaimsOff {
		t.Fatalf("a new session: %+v", resolution)
	}

	// a confirmation made meanwhile reaches only later sessions too
	world.commit("auto")
	config.member = &SidecarMemberClaims{Projects: map[string]SidecarClaims{testClaimsProjectKey: SidecarClaimsOff}}
	before := world.daemon.SessionClaims(world.hello(DaemonModeMcp))
	if resolution := before.For(ctx, world.networkId); resolution.Claims != SidecarClaimsOff || resolution.Pending != SidecarClaimsAuto ||
		resolution.Source != SidecarClaimsSourceProject {
		t.Fatalf("the member's project value under a wider .ur: %+v", resolution)
	}
	if _, err := world.daemon.ChooseClaims(ctx, world.hello(DaemonModeControl), world.networkId, SidecarClaimsAuto, true); err != nil {
		t.Fatal(err)
	}
	if resolution := before.For(ctx, world.networkId); resolution.Claims != SidecarClaimsOff {
		t.Fatalf("a confirmation moved an open session: %+v", resolution)
	}
	if resolution := world.daemon.SessionClaims(world.hello(DaemonModeMcp)).For(ctx, world.networkId); resolution.Claims != SidecarClaimsAuto {
		t.Fatalf("a session after the confirmation: %+v", resolution)
	}

	// a harness config that does not read leaves the team's default
	config.member, config.err = nil, errors.New("synthetic unreadable config")
	world.commit("")
	if resolution := world.daemon.SessionClaims(world.hello(DaemonModeMcp)).For(ctx, world.networkId); resolution.Claims != SidecarClaimsOff ||
		resolution.Source != SidecarClaimsSourceTeam {
		t.Fatalf("an unreadable harness config: %+v", resolution)
	}
}

// §16.11's project key and label: the remote's host and path, never its user info, port, query or a local path;
// `.ur`'s project first for the label, and the top level's base name when nothing else names it.
func TestProjectKeyAndLabel(t *testing.T) {
	cases := []struct {
		remote string
		want   string
	}{
		{remote: "https://user:secret@Git.Example:8443/acme/billing.git?ref=main#readme", want: "git.example/acme/billing"},
		{remote: "git@git.example:acme/billing.git", want: "git.example/acme/billing"},
		{remote: "ssh://git@git.example/acme/billing/", want: "git.example/acme/billing"},
		{remote: "/srv/repos/billing.git", want: ""},
		{remote: "file:///srv/repos/billing.git", want: ""},
		{remote: "C:\\repos\\billing", want: ""},
		{remote: "https://git.example/acme/bill ing", want: ""},
		{remote: "", want: ""},
	}
	for _, c := range cases {
		if got := sidecarRemoteHostPath(c.remote); got != c.want {
			t.Errorf("%q: %q, want %q", c.remote, got, c.want)
		}
	}
	tree := &SidecarProjectTree{TopLevel: "/work/billing", Git: true, Remote: "git@git.example:acme/billing.git"}
	if key := SidecarProjectKey(tree); key != "git.example/acme/billing" {
		t.Fatalf("the remote's key %q", key)
	}
	local := &SidecarProjectTree{TopLevel: "/work/billing", Git: true, Remote: "/srv/repos/billing.git"}
	if key := SidecarProjectKey(local); key != SidecarProjectKey(&SidecarProjectTree{TopLevel: "/work/billing"}) || len(key) != len("path:")+32 {
		t.Fatalf("a path's key %q", key)
	}
	var none *SidecarProject
	if label := none.ProjectLabel(tree); label != "git.example/acme/billing" {
		t.Fatalf("the remote's label %q", label)
	}
	if label := none.ProjectLabel(local); label != "billing" {
		t.Fatalf("the base name's label %q", label)
	}
	if label := (&SidecarProject{Project: "billing-api"}).ProjectLabel(tree); label != "billing-api" {
		t.Fatalf(".ur's label %q", label)
	}

	// the tree from a work tree's config: origin's url over an earlier remote's
	home := t.TempDir()
	project := filepath.Join(home, "billing")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(project, ".git", "config"), "[remote \"fork\"]\n\turl = git@fork.example:x/y.git\n[remote \"origin\"]\n\turl = \"git@git.example:acme/billing.git\"\n")
	found := FindSidecarProjectTree(filepath.Join(project, "deep"), home, DefaultSidecarProjectSettings())
	if found == nil || !found.Git || found.TopLevel != project || SidecarProjectKey(found) != "git.example/acme/billing" {
		t.Fatalf("the found tree: %+v", found)
	}
	// a linked work tree's .git file reads its common dir's config
	linked := filepath.Join(home, "linked")
	if err := os.MkdirAll(filepath.Join(project, ".git", "worktrees", "linked"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(linked, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(linked, ".git"), "gitdir: "+filepath.Join(project, ".git", "worktrees", "linked")+"\n")
	writeTestFile(t, filepath.Join(project, ".git", "worktrees", "linked", "commondir"), "../..\n")
	if found := FindSidecarProjectTree(linked, home, DefaultSidecarProjectSettings()); found == nil || SidecarProjectKey(found) != "git.example/acme/billing" {
		t.Fatalf("a linked work tree: %+v", found)
	}
	// a config past its bound gives no remote
	small := DefaultSidecarProjectSettings()
	small.GitConfigByteCount = 16
	if found := FindSidecarProjectTree(project, home, small); found == nil || found.Remote != "" {
		t.Fatalf("a config past its bound: %+v", found)
	}
}
