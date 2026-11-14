// The daemon's composition over real engines (QD-804; sidecartest/enginenet): evs and gkm run on sidecartest's Net
// behind §8.9's real gate cache, the Net's api serves their origins and mints scopes from the log, and every request
// the daemon's Sidecar makes reaches them through its own GkmApi and EvsClient.
//
//	git    on the follower world (daemon_config_test.go), where the network's owner bootstrapped it and its config heads
//	       are in memory: the daemon's Sidecar, a member device whose follower stands, creates a repo through evs and
//	       gkm, KF1 by its own key client at its follower's state; git clones it through git-remote-ur and the daemon's
//	       git mode, served by the network's evs client from its local tier; a commit pushed the same way passes the
//	       mount's hooks, which relay to the daemon, and evs commits main with it; and a second clone reads it back
//	admit  on the same world, the daemon's Sidecar admits a device with its own identity key, which its follower, its
//	       key client and the gate all hold
//	first  the network's first device bootstrapping on evs: its key client takes the genesis state, chooses a leaf and
//	       builds its MLS engine under the Genesis's hash, and evs's real create route places the config repo; KF1 at
//	       that state is refused, since a GenRotate's auth pin is past position 0 while the first head's push is signed
//	       before base 1 (question daemon-evs-gkm-clients-first-device-config-generation), so base 1 never lands and the
//	       follower never stands: the closed direction
//
// Following past the genesis over evs, installing a base over the composition's head reader and ur tun's bridge
// compiling over it wait on that question: no network's config head can be keyed on evs before it is answered. Every
// wait is on a monitor, a channel or a follow the test asks for, bounded by a real-time guard only a broken wiring
// reaches.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// The variable that turns this test binary into git-remote-ur or ur git-hook (TestUrGitHelperProcess): the socket of
// the daemon it speaks to.
const testUrGitSocketVariable = "UR_TEST_GIT_SOCKET"

// The label the test daemon resolves to a test's network, as ur://<label>/id:<repo> names it.
const testUrGitNetworkLabel = "first"

// Not a test: git runs this binary as git-remote-ur <remote> <url>, and a mount's hooks as ur git-hook <name>, through
// the scripts testUrGit writes, each speaking to the daemon whose socket the variable names.
func TestUrGitHelperProcess(t *testing.T) {
	socketPath := os.Getenv(testUrGitSocketVariable)
	if socketPath == "" {
		return
	}
	args := os.Args
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}
	cli, _, _ := newTestUrCli(socketPath)
	cli.stdin, cli.stdout, cli.stderr = os.Stdin, os.Stdout, os.Stderr
	cli.getenv = os.Getenv
	os.Exit(cli.main(context.Background(), args))
}

// One label, a test's network's.
type testUrGitLabels struct {
	networkId sidecar.Id
}

func (self *testUrGitLabels) ResolveNetworkLabel(root string, text string, interactive bool) (sidecar.Id, sidecar.NetworkLabelKind, error) {
	if text != testUrGitNetworkLabel {
		return sidecar.Id{}, "", errors.New("no such network label")
	}
	return self.networkId, "", nil
}

// git's side of a test: the daemon's directory, reserved before any network's EvsClient writes its mounts' hooks, the
// scripts that make this test binary git-remote-ur and the mounts' hook command, and git's environment.
type testUrGit struct {
	t           *testing.T
	ctx         context.Context
	directory   string
	environment []string
}

// Reserves the daemon's directory and gives every network's clients made from now on a local tier whose hooks exec
// this test binary as ur git-hook, restored at the test's end. Skips the test with no git.
func newTestUrGit(t *testing.T, ctx context.Context) *testUrGit {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git on this host")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self := &testUrGit{t: t, ctx: ctx, directory: shortTestDirectory(t)}
	socketSetting := testUrGitSocketVariable + "=" + filepath.Join(self.directory, "s")
	bin := t.TempDir()
	script := func(name string, words string) string {
		path := filepath.Join(bin, name)
		body := "#!/bin/sh\nexec '" + binary + "' -test.run='^TestUrGitHelperProcess$' -- " + words + " \"$@\"\n"
		if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	script("git-remote-ur", "git-remote-ur")
	hook := script("ur-git-hook", "ur git-hook")
	held := urDaemonClients
	t.Cleanup(func() { urDaemonClients = held })
	urDaemonClients = &urDaemonClientsArgs{
		StateDirectory: t.TempDir(), GitPath: gitPath, HookCommand: []string{hook}, HookEnvironment: []string{socketSetting},
		Log: sidecar.NewNoopLogger(),
	}
	self.environment = []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		socketSetting,
	}
	return self
}

// A control daemon in the reserved directory hosting running under the label, serving git's modes as ur daemon does.
func (self *testUrGit) daemon(networkId sidecar.Id, running *sidecar.Sidecar) {
	self.t.Helper()
	daemon, err := sidecar.NewDaemon(context.Background(), &sidecar.DaemonSettings{
		Instance:       "test",
		StateDirectory: self.directory,
		SocketPath:     filepath.Join(self.directory, "s"),
		Local:          sidecar.DefaultSidecarSettings().LocalSettings,
		Version:        sidecar.Version,
		Labels:         &testUrGitLabels{networkId: networkId},
		LabelRoot:      "sidecartest.example",
	})
	if err != nil {
		self.t.Fatal(err)
	}
	if err := daemon.AddSidecar(networkId, running); err != nil {
		self.t.Fatal(err)
	}
	if err := daemon.RegisterMode(sidecar.DaemonModeGit, sidecar.NewDaemonGitMode(daemon, urDaemonGitService)); err != nil {
		self.t.Fatal(err)
	}
	if err := daemon.RegisterMode(sidecar.DaemonModeGitHook, urDaemonGitHookMode(daemon)); err != nil {
		self.t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		daemon.Run()
	}()
	self.t.Cleanup(func() {
		daemon.Close()
		<-done
	})
}

// Runs git in dir, or anywhere for "", with the test's environment: its output, and whether it exited 0.
func (self *testUrGit) run(dir string, args ...string) (string, bool) {
	self.t.Helper()
	command := exec.CommandContext(self.ctx, "git", args...)
	command.Dir = dir
	command.Env = append(os.Environ(), self.environment...)
	output, err := command.CombinedOutput()
	return string(output), err == nil
}

// Runs git, failing the test unless it exits 0: its output.
func (self *testUrGit) must(dir string, args ...string) string {
	self.t.Helper()
	output, ok := self.run(dir, args...)
	if !ok {
		self.t.Fatalf("git %s: %s", strings.Join(args, " "), output)
	}
	return output
}

// A git session through the daemon, served end to end over evs and gkm: the daemon's Sidecar creates a repo, KF1 by its
// own key client at its follower's state and the RepoCreate judged by the real gate; git clones the repo through
// git-remote-ur and the daemon's git mode, the network's own evs client serving it from its local tier; a commit
// pushed the same way passes the mount's pre-receive and proc-receive hooks, which relay to the daemon's git-hook mode,
// and evs commits main in the generation the key client formed, where it held no git ref before; and a second clone
// through the daemon reads the commit back.
func TestDaemonServesAGitSessionOverEvs(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	git := newTestUrGit(t, world.ctx)
	engines := enginenet.NewEngines(t, world.net, nil)
	network := world.networks[0]
	networkId := network.NetworkId()
	engines.OpenNetwork(networkId)
	running := world.host(network, nil)
	world.standing(running, network)
	if err := engines.Sync(world.ctx, networkId); err != nil {
		t.Fatal(err)
	}
	gkm, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	repoId, err := engines.CreateRepo(world.ctx, &enginenet.CreateRepoArgs{Sidecar: running, Gkm: gkm, Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	if err != nil {
		t.Fatalf("the repo: %v", err)
	}
	if key, err := gkm.CurrentRepoKey(world.ctx, repoId); err != nil || key.Generation() != 1 {
		t.Fatalf("the key client's key of the repo it formed: %v", err)
	}
	// gkm's tokens carry the scopes the state grants this sidecar, the config's rw and the new repo's admin among them,
	// in one batch, as the composition sets them at each state
	configScope, repoScope := "repo:"+network.ConfigRepoId().String()+":rw", "repo:"+repoId.String()+":admin"
	batched := false
	for _, request := range engines.ScopeRequests() {
		if request.Audience == "gkm" && slices.Contains(request.Scopes, configScope) && slices.Contains(request.Scopes, repoScope) {
			batched = true
		}
	}
	if !batched {
		t.Fatalf("no gkm token carried the state's scopes %s and %s", configScope, repoScope)
	}
	git.daemon(networkId, running)

	url := "ur://" + testUrGitNetworkLabel + "/id:" + repoId.String()
	clone := filepath.Join(t.TempDir(), "clone")
	git.must("", "clone", "-q", url, clone)
	git.must(clone, "config", "user.name", "first device")
	git.must(clone, "config", "user.email", running.Identity().ClientId.String()+"@ur.invalid")
	if err := os.WriteFile(filepath.Join(clone, "README"), []byte("served end to end\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git.must(clone, "add", "README")
	git.must(clone, "commit", "-q", "-m", "through the daemon")
	commit := strings.TrimSpace(git.must(clone, "rev-parse", "HEAD"))
	committed := func() []*protocol.EvsHead {
		t.Helper()
		heads, err := engines.RefHeads(world.ctx, repoId)
		if err != nil {
			t.Fatal(err)
		}
		gitHeads := []*protocol.EvsHead{}
		for _, head := range heads {
			if protocol.EvsRefMode(head.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT && 0 < head.GetVersion() {
				gitHeads = append(gitHeads, head)
			}
		}
		return gitHeads
	}
	if heads := committed(); len(heads) != 0 {
		t.Fatalf("evs holds %d git refs before the push", len(heads))
	}
	git.must(clone, "push", "-q", "origin", "HEAD:refs/heads/main")
	// the push's proc-receive committed main to evs, sealed in the generation the Sidecar's key client formed
	if heads := committed(); len(heads) != 1 || heads[0].GetGeneration() != 1 {
		t.Fatalf("evs holds %d git refs after the push: %v", len(heads), heads)
	}

	other := filepath.Join(t.TempDir(), "other")
	git.must("", "clone", "-q", url, other)
	if head := strings.TrimSpace(git.must(other, "rev-parse", "HEAD")); head != commit {
		t.Fatalf("the second clone's HEAD %s, the pushed %s", head, commit)
	}
	readme, err := os.ReadFile(filepath.Join(other, "README"))
	if err != nil || string(readme) != "served end to end\n" {
		t.Fatalf("the second clone's README: %q %v", readme, err)
	}
}

// The daemon's Sidecar admits a device with its own identity key, as its owner member's device: the SidecarAdmit lands
// at api, and the daemon's follower, the key client it hands each state and the gate evs and gkm judge by all hold the
// device admitted, its row naming the admission's hash.
func TestDaemonAdmitsADeviceTheGateHolds(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	engines := enginenet.NewEngines(t, world.net, nil)
	network := world.networks[0]
	networkId := network.NetworkId()
	engines.OpenNetwork(networkId)
	running := world.host(network, nil)
	world.standing(running, network)
	if err := engines.Sync(world.ctx, networkId); err != nil {
		t.Fatal(err)
	}
	deviceKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5d}, ed25519.SeedSize))
	deviceId := sidecar.NewId()
	pin, err := engines.PostStatement(world.ctx, running, bridge.SignedType_SIGNED_SIDECAR_ADMIT, func(header *bridge.StatementHeader) proto.Message {
		return &protocol.SidecarAdmit{
			Header:            header,
			NetworkId:         networkId.Bytes(),
			SidecarId:         deviceId.Bytes(),
			IdentityPublicKey: deviceKey.Public().(ed25519.PublicKey),
			IdentityAlg:       "ed25519",
			MemberId:          network.Owner().MemberId.Bytes(),
		}
	})
	if err != nil {
		t.Fatalf("the admission: %v", err)
	}
	row := running.ConfigFollower().Client().State().SidecarRow(deviceId)
	if row == nil || len(row.GetAdmissionSha256()) != sha256.Size || len(row.GetAdmissionSigners()) == 0 ||
		!bytes.Equal(row.GetAdmissionSigners()[0], running.Identity().SidecarId.Bytes()) {
		t.Fatalf("the follower's row of the admitted device: %v", row)
	}
	if state := testUrClientsOf(running).gkm.newestState(); state == nil || state.Pin().GetVersion() < pin.GetVersion() ||
		state.SidecarRow(deviceId) == nil {
		t.Fatal("the key client does not hold the admission's state")
	}
	if snapshot, status := engines.Gate().State(networkId); status != sidecar.AclGateLoaded || !snapshot.Acl.Admitted(deviceId) {
		t.Fatal("the gate does not hold the admitted device")
	}
}

// The network's first device bootstrapping on evs (the file's comment): the daemon's own key client takes the genesis
// state the bootstrap signed, chooses a leaf as the Genesis's owner and builds its MLS engine under the Genesis's hash,
// its anchor; evs's real create route places the config repo for it, inside the bootstrap's window; and KF1 there is
// refused as malformed, a generation pinned at position 0, so base 1 never lands and the daemon's follower, which reads
// no genesis, never stands (question daemon-evs-gkm-clients-first-device-config-generation).
func TestDaemonsFirstNetworkStopsAtItsConfigGeneration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	instance, err := net.StartInstance("daemon", &sidecartest.TestInstanceArgs{
		Start: func(running *sidecar.Sidecar) error {
			if startUrConfigFollower(running, sidecar.NewNoopLogger()) == nil {
				return errors.New("no follower started")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	networkId := sidecar.NewId()
	running, err := instance.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	gkm, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engines.Bootstrap(ctx, &enginenet.BootstrapArgs{Sidecar: running, Gkm: gkm, OwnerMemberId: sidecar.NewId()})
	if !errors.Is(err, sidecar.ErrGkmMalformed) || !strings.Contains(err.Error(), "auth pin") {
		t.Fatalf("the first device's KF1 at the genesis state: %v", err)
	}

	clients := testUrClientsOf(running)
	state, _ := clients.gkm.newestState().(*sidecar.ConfigState)
	identity := running.Identity()
	if state == nil || state.Pin().GetVersion() != 0 || !bytes.Equal(state.Genesis().GetOwnerSidecarId(), identity.SidecarId.Bytes()) {
		t.Fatalf("the key client holds %v, not the genesis state naming this sidecar", state)
	}
	if clients.builtGroup() == nil || !clients.leaf {
		t.Fatal("the first device's key client holds no leaf")
	}
	anchor, err := running.Anchor()
	if err != nil {
		t.Fatal(err)
	}
	clients.mls.stateLock.Lock()
	admission, engine := clients.mls.admissionSha256, clients.mls.engine
	clients.mls.stateLock.Unlock()
	if engine == nil || !bytes.Equal(admission, anchor.GenesisSha256) {
		t.Fatal("the first device's MLS engine is not built under the Genesis's hash")
	}

	if tip, err := engines.Api().Tip(ctx, networkId); err != nil || tip != nil {
		t.Fatalf("api's log of a network whose bootstrap stopped: %v %v", tip, err)
	}
	net.Clock().Advance(urConfigFollowerSettings().AnchorRetryInterval)
	follower := running.ConfigFollower()
	if follower.Client() != nil || follower.VerifiedState() != nil || running.Admitted() {
		t.Fatalf("a follower stood on a network with no base 1: %+v", follower.Status())
	}
}
