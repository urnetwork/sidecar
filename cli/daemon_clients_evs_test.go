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
//	first  the network's first device bootstrapping on evs, KF1 split at its base 1 (QD-824): its key client takes the
//	       genesis state and drafts the config group's id and RK_1; the first head's push is sealed under them and
//	       signed at the genesis pin before base 1; base 1 lands and the key client takes the device's own S(1); evs's
//	       real create route places the config repo, KF1 signs GenRotate_1 there over the drafted RK_1, activation
//	       follows and the push lands; the daemon's follower then stands on base 1 over the composition's head reader
//	retry  the same bootstrap cut short before base 1, its base lost on the way to api: the retry for the same config
//	       repo seals the first head under the group and C_1 the key client drafted the first time
//
// Every wait is on a monitor, a channel or a follow the test asks for, bounded by a real-time guard only a broken
// wiring reaches.

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
	"time"

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
	// gkm's tokens carry the scopes the state grants this sidecar, the config's admin, a config writer's (QD-894), and
	// the new repo's admin among them, in one batch, as the composition sets them at each state
	configScope, repoScope := "repo:"+network.ConfigRepoId().String()+":admin", "repo:"+repoId.String()+":admin"
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

// Bootstraps the first device with the daemon's key client and the real EVS and GKM engines.
func bootstrapTestDaemonOwner(t *testing.T, ctx context.Context, net *sidecartest.Net, engines *enginenet.Engines) (*sidecar.Sidecar, sidecar.GkmClient, *enginenet.BootstrapResult) {
	t.Helper()
	instance, err := net.StartInstance("daemon", &sidecartest.TestInstanceArgs{})
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
	result, err := engines.Bootstrap(ctx, &enginenet.BootstrapArgs{Sidecar: running, Gkm: gkm, OwnerMemberId: sidecar.NewId()}, nil)
	if err != nil {
		t.Fatalf("the first device's bootstrap: %v", err)
	}
	return running, gkm, result
}

// The network's first device bootstrapping on evs (the file's comment), the daemon's own Sidecar and key client on the
// engines behind the real gate, which holds nothing of the network before base 1: the bootstrap lands base 1, forms the
// config group and commits the first head; the key client holds generation 1 signed at S(1), its group the drafted one
// and its C_1 the one the push named, which evs's head holds; and the daemon's follower, started once the network
// exists, stands on base 1 over the real head reader, the first device admitted.
func TestDaemonsFirstNetworkStandsOnItsBaseOne(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	running, gkm, result := bootstrapTestDaemonOwner(t, ctx, net, engines)
	networkId := running.Identity().NetworkId
	bootstrap := result.Bootstrap
	if tip, err := engines.Api().Tip(ctx, networkId); err != nil || tip.GetVersion() != 1 || !bytes.Equal(tip.GetChain(), bootstrap.Pin.GetChain()) {
		t.Fatalf("api's log after the bootstrap: %v %v", tip, err)
	}

	// the push base 1 names: the config repo's first, at the genesis pin, under the drafted generation
	statement, err := sidecar.ParseEvsStatement(bootstrap.Push.SignedPush)
	if err != nil {
		t.Fatal(err)
	}
	push := statement.Push
	if push.GetAuth().GetVersion() != 0 || !bytes.Equal(push.GetAuth().GetChain(), bootstrap.GenesisChain[:]) || push.GetBaseVersion() != 0 {
		t.Fatalf("the first head's push: auth %v on version %d", push.GetAuth(), push.GetBaseVersion())
	}
	key, err := gkm.RepoKey(ctx, result.ConfigRepoId, 1)
	if err != nil {
		t.Fatalf("the key client's generation 1 of the config repo: %v", err)
	}
	if key.GroupId() != result.DraftedKey.GroupId() || !bytes.Equal(push.GetGroupId(), key.GroupId().Bytes()) ||
		!bytes.Equal(key.Commitment(), push.GetGenerationCommitment()) || !bytes.Equal(key.Commitment(), result.DraftedKey.Commitment()) {
		t.Fatal("generation 1 is not the one the first head's push was sealed under")
	}
	if auth := key.Auth(); auth.GetVersion() != 1 || !bytes.Equal(auth.GetChain(), bootstrap.Pin.GetChain()) {
		t.Fatalf("GenRotate_1 signed at %v, not at S(1)", auth)
	}
	clients := testUrClientsOf(running)
	if group := clients.builtGroup(); group == nil || !group.KeyDeliveryOnly() {
		t.Fatal("the first config group was not formed by KeyDelivery")
	} else if _, exists := group.GroupHead(key.GroupId()); exists {
		t.Fatal("the first config group has an epoch head")
	}
	heads, err := engines.RefHeads(ctx, result.ConfigRepoId)
	if err != nil {
		t.Fatal(err)
	}
	committed := false
	for _, head := range heads {
		if head.GetVersion() == 1 && head.GetGeneration() == 1 && bytes.Equal(head.GetGenerationCommitment(), key.Commitment()) &&
			bytes.Equal(head.GetGroupId(), key.GroupId().Bytes()) {
			committed = true
		}
	}
	if !committed {
		t.Fatalf("evs holds no main head at version 1 in generation 1: %v", heads)
	}

	// the daemon's follower, started now the network exists, stands on base 1 over the real head reader
	if startUrConfigFollower(running, sidecar.NewNoopLogger()) == nil {
		t.Fatal("no follower started")
	}
	follower := running.ConfigFollower()
	standCtx, standCancel := context.WithTimeout(ctx, urTestTimeout)
	defer standCancel()
	client, err := follower.WaitStanding(standCtx)
	if err != nil {
		t.Fatalf("the follower: %v (%+v)", err, follower.Status())
	}
	if pin := client.Pin(); pin.GetVersion() != 1 || !bytes.Equal(pin.GetChain(), bootstrap.Pin.GetChain()) {
		t.Fatalf("the follower stands at %v", pin)
	}
	head, err := follower.Heads().ReadConfigHead(standCtx, 1, result.Chain[:])
	if err != nil || !bytes.Equal(head.File(sidecar.ConfigHeadGenesisPath), bootstrap.SignedGenesis) {
		t.Fatalf("the head reader's first head: %v", err)
	}
	if !running.Admitted() {
		t.Fatal("the first device is not admitted at base 1")
	}
}

// The daemon signs both bindings, rewraps and rotates through the real service, and restarts. Opening the
// service's winning generation then needs only the replacement code and the public authenticated log.
func TestDaemonRecoveryRotationSurvivesRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	instance, err := net.StartInstance("recovery", &sidecartest.TestInstanceArgs{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	networkId, memberId := sidecar.NewId(), sidecar.NewId()
	engines.Api().SetPersonalOwner(networkId, memberId)
	running, err := instance.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	gkm, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engines.Bootstrap(ctx, &enginenet.BootstrapArgs{Sidecar: running, Gkm: gkm, OwnerMemberId: memberId}, nil)
	if err != nil {
		t.Fatal(err)
	}
	follow := func(running *sidecar.Sidecar) *sidecar.ConfigClient {
		t.Helper()
		startUrConfigFollower(running, sidecar.NewNoopLogger())
		client, err := running.ConfigFollower().WaitStanding(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	client := follow(running)
	rotate := func() *sidecar.RecoveryRotation {
		t.Helper()
		rotation, err := running.RotateRecovery(ctx, false, sidecar.SidecarActConfirmed, nil)
		if err != nil || rotation == nil || rotation.Entry == nil {
			t.Fatalf("binding: %v", err)
		}
		if err := engines.Sync(ctx, networkId); err != nil {
			t.Fatal(err)
		}
		if err := client.CatchUp(ctx); err != nil {
			t.Fatal(err)
		}
		if err := testUrClientsOf(running).builtGroup().CompleteRecoveryBinding(ctx, rotation.KeySha256); err != nil {
			t.Fatal(err)
		}
		return rotation
	}
	initial, replacement := rotate(), rotate()
	if !bytes.Equal(replacement.PreviousKeySha256, initial.KeySha256) {
		t.Fatal("the replacement did not retire the first binding")
	}
	if err := instance.Restart(); err != nil {
		t.Fatal(err)
	}
	running = instance.Sidecar(networkId)
	client = follow(running)
	clients := testUrClientsOf(running)
	wraps, err := clients.api.RecoveryWraps(ctx, memberId, false)
	if err != nil || len(wraps.GetWraps()) != 1 {
		t.Fatalf("replacement wraps after restart: %v", err)
	}
	wrap := wraps.GetWraps()[0]
	if !bytes.Equal(wrap.GetBindingPrefix(), replacement.KeySha256[:8]) {
		t.Fatal("the surviving wrap names the retired code")
	}
	groupId := result.DraftedKey.GroupId()
	page, err := clients.api.Generations(ctx, result.ConfigRepoId, groupId, wrap.GetGeneration()-1)
	if err != nil || len(page.GetGenerations()) != 1 {
		t.Fatalf("the winning generation: %v", err)
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(page.GetGenerations()[0])
	if err != nil {
		t.Fatal(err)
	}
	generation, err := sidecar.ParseGenRotate(body, groupId, wrap.GetGeneration(), sidecar.GkmIdentityKeys(client.State()))
	if err != nil {
		t.Fatal(err)
	}
	code, err := sidecar.ParseRecoveryCode(strings.Join(replacement.Words, " "))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := code.Keys()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Erase()
	privateKey, err := keys.XwingPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := sidecar.OpenGkmRecoveryWrap(wrap.GetCiphertext(), generation, &sidecar.GkmRecoveryArgs{
		MemberId: memberId, GroupId: groupId, BindingKeySha256: keys.KeySha256(),
	}, privateKey)
	if err != nil || !bytes.Equal(opened.Commitment(), generation.Rotate.GetCommitment()) {
		t.Fatalf("replacement code alone: %v", err)
	}

	// The replacement has a new instance, key store, identity and member-owned session. Its previous devices are gone.
	instance.Close()
	fresh, err := net.StartInstance("fresh-recovery", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fresh.Close)
	device, err := fresh.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	follower := startUrConfigFollower(device, sidecar.NewNoopLogger())
	if follower == nil {
		t.Fatal("the fresh device has no config follower")
	}
	cold := testUrClientsOf(device)
	select {
	case <-cold.groupBuilt():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for {
		_, changed := cold.upkeep.Passes()
		state, _, _ := cold.gkm.joiningState()
		if state != nil && bytes.Equal(state.Member(memberId).GetRecoveryKeySha256(), replacement.KeySha256) {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if device.GkmRepoKeyHeld(result.ConfigRepoId) || device.Admitted() {
		t.Fatal("the fresh device already has a repo key or admission")
	}
	recoverCode := func() *sidecar.SidecarRecovery {
		t.Helper()
		code, err := sidecar.ParseRecoveryCode(strings.Join(replacement.Words, " "))
		if err != nil {
			t.Fatal(err)
		}
		progress, err := device.RecoverWithCode(ctx, code, sidecar.SidecarActConfirmed)
		if err != nil {
			t.Fatalf("recovering with the replacement on the fresh device: %v", err)
		}
		return progress
	}
	pending := recoverCode()
	if pending.Phase != sidecar.SidecarRecoveryPending || pending.Entry == nil || pending.ActivatesAfter.IsZero() {
		t.Fatalf("the owner's recovery proposal did not enter its window: %+v", pending)
	}
	net.Clock().Advance(pending.ActivatesAfter.Sub(net.Clock().Now()) + time.Millisecond)
	if _, err := engines.Api().AppendTick(ctx, networkId, &bridge.ApiTick{ActivatedProposalIds: [][]byte{pending.StatementId}}); err != nil {
		t.Fatal(err)
	}
	if err := engines.Sync(ctx, networkId); err != nil {
		t.Fatal(err)
	}
	recovered := recoverCode()
	if recovered.Phase != sidecar.SidecarRecoveryAnchored || !device.Admitted() || !recovered.OfferRotate {
		t.Fatalf("the fresh device did not finish recovery: %+v", recovered)
	}
	current, err := cold.builtGroup().CurrentRepoKey(ctx, result.ConfigRepoId)
	if err != nil || !bytes.Equal(current.Commitment(), opened.Commitment()) {
		t.Fatalf("the fresh device's recovered commitment: %v", err)
	}

}

// The production startup composition initializes an empty network and follows the first head through EVS.
func TestDaemonFollowerBootstrapsAnEmptyOwnerNetwork(t *testing.T) {
	testDaemonFirstOwner(t, false)
}

// A restart after base one resumes the first owner's bootstrap on the same device and repo.
func TestDaemonFollowerResumesOwnerBootstrapAfterBaseOne(t *testing.T) {
	testDaemonFirstOwner(t, true)
}

// Two enrolled owner devices both see an empty log. Hold the first POST until the other device has published
// and activated its candidate, then make the losing device follow the winning Genesis and repo.
func TestDaemonFollowersAgreeOnTheFirstOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	settings := enginenet.DefaultEnginesSettings()
	settings.FollowBeforeExchange = true
	engines := enginenet.NewEngines(t, net, settings)
	networkId := sidecar.NewId()
	engines.OpenNetwork(networkId)
	engines.Api().SetPersonalOwner(networkId, sidecar.NewId())
	device := func(name string) *sidecar.Sidecar {
		instance, err := net.StartInstance(name, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(instance.Close)
		running, err := instance.AddSidecarIn(networkId, nil)
		if err != nil {
			t.Fatal(err)
		}
		return running
	}
	first, winner := device("first"), device("winner")
	posting, release := make(chan struct{}), make(chan struct{})
	net.Faults().SetOnFire(func(*sidecartest.FaultPlan) {
		close(posting)
		select {
		case <-release:
		case <-ctx.Done():
		}
	})
	if _, err := net.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHttp,
		KeyPrefix: "/network/config/projection", WritesOnly: true, Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	reads, allowRead := make(chan *testUrProbedRead, 1), make(chan struct{})
	close(allowRead)
	heads := urDaemonConfigHeads
	urDaemonConfigHeads = func(running *sidecar.Sidecar) sidecar.ConfigHeadReader {
		return &testUrProbedHeads{next: heads(running), running: running, answers: reads, admitted: allowRead}
	}
	firstFollower := startUrConfigFollower(first, sidecar.NewNoopLogger())
	urDaemonConfigHeads = heads
	select {
	case <-posting:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	winnerFollower := startUrConfigFollower(winner, sidecar.NewNoopLogger())
	if _, err := winnerFollower.WaitStanding(ctx); err != nil {
		t.Fatalf("the winning owner: %v", err)
	}
	close(release)
	select {
	case <-reads:
	case <-ctx.Done():
		t.Fatalf("the losing follower: %+v: %v", firstFollower.Status(), ctx.Err())
	}
	a, err := first.Anchor()
	if err != nil {
		t.Fatal(err)
	}
	b, err := winner.Anchor()
	if err != nil || !bytes.Equal(a.GenesisSha256, b.GenesisSha256) || first.Admitted() {
		t.Fatalf("the losing device did not retain the winning anchor: %+v %+v %v", a, b, err)
	}
}

func testDaemonFirstOwner(t *testing.T, restart bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	settings := enginenet.DefaultEnginesSettings()
	settings.FollowBeforeExchange = true
	engines := enginenet.NewEngines(t, net, settings)
	networkId, ownerId := sidecar.NewId(), sidecar.NewId()
	engines.OpenNetwork(networkId)
	engines.Api().SetPersonalOwner(networkId, ownerId)
	instance, err := net.StartInstance("owner", &sidecartest.TestInstanceArgs{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	running, err := instance.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstId := running.Identity().SidecarId
	site := sidecartest.BarrierSite("api.config.appended", networkId.String())
	if restart {
		if err := net.Barriers().Arm(site, "", 0); err != nil {
			t.Fatal(err)
		}
	}
	follower := startUrConfigFollower(running, sidecar.NewNoopLogger())
	if restart {
		if err := net.Barriers().AwaitHeld(ctx, site, ""); err != nil {
			t.Fatal(err)
		}
		follower.Close()
		if err := net.Barriers().Release(site); err != nil {
			t.Fatal(err)
		}
		if err := instance.Restart(); err != nil {
			t.Fatal(err)
		}
		running = instance.Sidecar(networkId)
		follower = startUrConfigFollower(running, sidecar.NewNoopLogger())
	}
	client, err := follower.WaitStanding(ctx)
	if err != nil {
		t.Fatalf("first-owner startup: %+v: %v", follower.Status(), err)
	}
	state := follower.VerifiedState()
	if client.Pin().GetVersion() != 1 || !bytes.Equal(state.Genesis().GetOwnerMemberId(), ownerId.Bytes()) ||
		!bytes.Equal(state.Genesis().GetOwnerSidecarId(), firstId.Bytes()) || running.Identity().SidecarId != firstId {
		t.Fatalf("the owner did not stand on its own base: %v", client.Pin())
	}
	repoId, err := sidecar.IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		t.Fatal(err)
	}
	heads, err := engines.RefHeads(ctx, repoId)
	if err != nil || len(heads) != 1 || heads[0].GetVersion() != 1 {
		t.Fatalf("the first config repo heads: %v %v", heads, err)
	}
}

// A publisher whose every base is lost before api takes it: a bootstrap cut short before base 1.
type testUrLostBasePublisher struct{}

func (self testUrLostBasePublisher) PublishConfigBase(ctx context.Context, base *sidecar.ConfigBasePublish) (*bridge.AuthPin, error) {
	return nil, errors.New("the base never reached api")
}

// A first device's bootstrap cut short before base 1, its base lost on the way to api, leaves its key client's draft
// standing: the retry for the same config repo seals the first head under the same group and C_1, lands base 1 and
// forms that group, nothing of the cut-short attempt having reached api, evs or gkm.
func TestDaemonsFirstNetworkRetriesUnderItsDraft(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	instance, err := net.StartInstance("daemon", &sidecartest.TestInstanceArgs{})
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
	ownerMemberId, configRepoId := sidecar.NewId(), sidecar.NewEvsRepoId()
	cut, err := engines.Bootstrap(ctx, &enginenet.BootstrapArgs{
		Sidecar: running, Gkm: gkm, OwnerMemberId: ownerMemberId, Publisher: testUrLostBasePublisher{},
	}, &configRepoId)
	if err == nil || cut.DraftedKey == nil {
		t.Fatalf("a bootstrap whose base never landed: %v", err)
	}
	if tip, err := engines.Api().Tip(ctx, networkId); err != nil || tip != nil {
		t.Fatalf("api's log after the cut-short bootstrap: %v %v", tip, err)
	}
	if heads, err := engines.RefHeads(ctx, configRepoId); err != nil || len(heads) != 0 {
		t.Fatalf("evs holds the config repo after the cut-short bootstrap: %v %v", heads, err)
	}

	// the Net's clock stands still, so the retry signs the same Genesis, whose A_0 the Sidecar anchored the first time
	result, err := engines.Bootstrap(ctx, &enginenet.BootstrapArgs{Sidecar: running, Gkm: gkm, OwnerMemberId: ownerMemberId}, &configRepoId)
	if err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if result.DraftedKey.GroupId() != cut.DraftedKey.GroupId() || !bytes.Equal(result.DraftedKey.Commitment(), cut.DraftedKey.Commitment()) {
		t.Fatal("the retry drafted another group or RK_1")
	}
	statement, err := sidecar.ParseEvsStatement(result.Bootstrap.Push.SignedPush)
	if err != nil {
		t.Fatal(err)
	}
	key, err := gkm.RepoKey(ctx, configRepoId, 1)
	if err != nil || key.GroupId() != cut.DraftedKey.GroupId() || !bytes.Equal(statement.Push.GetGenerationCommitment(), cut.DraftedKey.Commitment()) ||
		!bytes.Equal(key.Commitment(), cut.DraftedKey.Commitment()) {
		t.Fatalf("generation 1 after the retry: %v", err)
	}
}

// A new device publishes its ReaderKey, receives the config key by a signed LATE KeyDelivery under
// its rows-only state, then verifies base one on real EVS. Both devices use the daemon's stock clients.
func TestDaemonsSecondDeviceJoinsOverEvs(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	networkId := sidecar.NewId()
	ownerMemberId := sidecar.NewId()
	host := func(name string, anchor *sidecar.SidecarEnrollAnchor) *sidecar.Sidecar {
		t.Helper()
		instance, err := net.StartInstance(name, &sidecartest.TestInstanceArgs{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(instance.Close)
		running, err := instance.AddSidecarIn(networkId, anchor)
		if err != nil {
			t.Fatal(err)
		}
		return running
	}
	standing := func(running *sidecar.Sidecar) *sidecar.ConfigClient {
		t.Helper()
		standCtx, standCancel := context.WithTimeout(ctx, urTestTimeout)
		defer standCancel()
		follower := running.ConfigFollower()
		client, err := follower.WaitStanding(standCtx)
		if err != nil {
			t.Fatalf("the follower: %v (%+v)", err, follower.Status())
		}
		return client
	}

	first := host("first", nil)
	firstGkm, err := urDaemonGkmClient(first)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engines.Bootstrap(ctx, &enginenet.BootstrapArgs{Sidecar: first, Gkm: firstGkm, OwnerMemberId: ownerMemberId}, nil)
	if err != nil {
		t.Fatalf("the first device's bootstrap: %v", err)
	}
	if startUrConfigFollower(first, sidecar.NewNoopLogger()) == nil {
		t.Fatal("no follower started on the first device")
	}
	standing(first)

	second := host("second", &sidecar.SidecarEnrollAnchor{GenesisSha256: result.Bootstrap.GenesisChain[:]})
	identity := second.Identity()
	pin, err := engines.PostStatement(ctx, first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, func(header *bridge.StatementHeader) proto.Message {
		return &protocol.SidecarAdmit{
			Header:            header,
			NetworkId:         networkId.Bytes(),
			SidecarId:         identity.SidecarId.Bytes(),
			IdentityPublicKey: identity.IdentityPublicKey,
			IdentityAlg:       "ed25519",
			MemberId:          ownerMemberId.Bytes(),
		}
	})
	if err != nil {
		t.Fatalf("the second device's admission: %v", err)
	}
	if startUrConfigFollower(second, sidecar.NewNoopLogger()) == nil {
		t.Fatal("no follower started on the second device")
	}
	secondClients := testUrClientsOf(second)
	if secondClients == nil {
		t.Fatal("the second device's clients are not built")
	}

	select {
	case <-secondClients.groupBuilt():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	upkeep := secondClients.upkeep
	for {
		_, changed := upkeep.Passes()
		state, repoId, confirmed := secondClients.gkm.joiningState()
		if state != nil && (confirmed || repoId == result.ConfigRepoId) && state.Pin().GetVersion() >= pin.GetVersion() &&
			state.SidecarRow(identity.SidecarId) != nil && len(upkeep.CurrentReaderKeySha256()) != 0 {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatalf("the admitted device has no ReaderKey at its joining state: %v", second.ConfigFollower().Status())
		}
	}
	if err := first.ConfigFollower().Client().CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	firstGroup := testUrClientsOf(first).builtGroup()
	if err := firstGroup.DeliverFirstWrap(ctx, result.ConfigRepoId, identity.SidecarId); err != nil {
		t.Fatalf("the first device's delivery: %v", err)
	}
	if err := secondClients.builtGroup().SyncRepo(ctx, result.ConfigRepoId); err != nil {
		t.Fatalf("the second device's first wrap: %v", err)
	}

	client := standing(second)
	if !second.Admitted() || client.State().SidecarRow(identity.SidecarId) == nil {
		t.Fatal("the second device is not admitted once its follower stands")
	}
	if given := secondClients.gkm.newestState(); given == nil || given.Pin().GetVersion() != client.Pin().GetVersion() {
		t.Fatalf("the second device's key client holds %v, the follower %d", given, client.Pin().GetVersion())
	}
	if head, err := second.ConfigFollower().Heads().ReadConfigHead(ctx, 1, result.Chain[:]); err != nil ||
		!bytes.Equal(head.File(sidecar.ConfigHeadGenesisPath), result.Bootstrap.SignedGenesis) {
		t.Fatalf("the second device's head reader at base 1: %v", err)
	}
}
