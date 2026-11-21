// Each hosted network's key and evs clients (QD-804) on the daemon's follower world (daemon_config_test.go): the hooks
// answer each network its own GkmGroupClient, which the follower hands its state once it stands, and its own EvsClient,
// which judges statements at that follower's state; urDaemonEvsClient refuses until the follower stands, so git's
// service through the daemon answers a refused network's session with the follower's reason and hands a standing one's
// to the network's evs client; a daemon with either the head reader's or the key client's hook unset withholds base 1;
// and the composition's head reader reads at the start's own state, from the follower's first read. The world's config
// repo is in memory and no evs serves it, so a head over evs, and a session served past its first read, are not here.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The kinds of admission a test hosts a Sidecar under.
type testUrAdmission int

const (
	testUrMemberDevice testUrAdmission = iota
	testUrEphemeral
	testUrTagged
)

// A Sidecar enrolled in network on the instance and admitted there by its owner's device as kind says: a member device
// of the owner, an ephemeral sidecar of the owner, or one tagged with a tag of the network's, the last two for a day.
func (self *testUrFollowWorld) hostAs(network *sidecartest.AdmissionNet, kind testUrAdmission) *sidecar.Sidecar {
	self.t.Helper()
	if kind == testUrMemberDevice {
		return self.host(network, nil)
	}
	running, err := self.instance.AddSidecarIn(network.NetworkId(), nil)
	if err != nil {
		self.t.Fatal(err)
	}
	identity := running.Identity()
	admit := &protocol.SidecarAdmit{
		Header:            network.Header(),
		NetworkId:         network.NetworkId().Bytes(),
		SidecarId:         identity.SidecarId.Bytes(),
		IdentityPublicKey: identity.IdentityPublicKey,
		IdentityAlg:       "ed25519",
		NotAfter:          network.Clock().Now().Add(24 * time.Hour).UnixMilli(),
	}
	switch kind {
	case testUrEphemeral:
		admit.MemberId, admit.Ephemeral = network.Owner().MemberId.Bytes(), true
	case testUrTagged:
		// a policy whose tag the network's admins own, so the owner's device admits under it: its first rule keeps the
		// implicit document's member reach, and its second names the tag, since the compile writes an atom only for a tag
		// a rule names
		plan, _ := network.SaveAclPolicy([]byte(`{
			"tagOwners": { "tag:agents": ["autogroup:admin"] },
			"grants": [
				{ "src": ["autogroup:member", "autogroup:untagged"], "dst": ["*"], "allow": ["*"] },
				{ "src": ["tag:agents"], "dst": ["autogroup:self"], "allow": ["dial"], "ip": ["tcp:443"] },
			],
		}`), nil)
		tagId, ok := sidecartest.AclTagAtom(plan, "agents")
		if !ok {
			self.t.Fatal("the policy's tag has no atom")
		}
		admit.Header = network.Header()
		admit.TagIds = [][]byte{tagId.Bytes()}
	}
	network.MustLand(network.Sign(network.Owner(), bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit))
	return running
}

// running's clients as the hooks made them, nil for none.
func testUrClientsOf(running *sidecar.Sidecar) *urNetworkClients {
	urNetworkClientsLock.Lock()
	defer urNetworkClientsLock.Unlock()
	return urNetworkClientsBySidecar[running]
}

// A head reader that hands each read's answer, and what the network's follower held as its newest verified state at
// the read, to answers, reading through next once admitted closes.
type testUrProbedHeads struct {
	next    sidecar.ConfigHeadReader
	running *sidecar.Sidecar
	answers chan *testUrProbedRead
	// closed once the Sidecar is admitted: every read waits for it, so what the follower reads after a read includes
	// the admission
	admitted chan struct{}
}

// One read as testUrProbedHeads saw it.
type testUrProbedRead struct {
	err error
	// the follower's VerifiedState then, nil for none
	verified *sidecar.ConfigState
	standing bool
}

// next's answer, with what the follower held when it was asked.
func (self *testUrProbedHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
	select {
	case <-self.admitted:
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", sidecar.ErrConfigHeadUnavailable, ctx.Err())
	}
	read := &testUrProbedRead{}
	if follower := self.running.ConfigFollower(); follower != nil {
		read.verified = follower.VerifiedState()
		read.standing = follower.Client() != nil
	}
	if self.next == nil {
		read.err = sidecar.ErrConfigHeadUnavailable
		self.answer(read)
		return nil, read.err
	}
	head, err := self.next.ReadConfigHead(ctx, configVersion, configHeadSha256)
	read.err = err
	self.answer(read)
	return head, err
}

// Hands read to the test, dropping it once one waits there unread.
func (self *testUrProbedHeads) answer(read *testUrProbedRead) {
	select {
	case self.answers <- read:
	default:
	}
}

// Installs urDaemonConfigHeads as the composition's reader probed, restoring the world's at the test's end, and hosts a
// Sidecar in network, its follower's reads held until it is admitted: where each read's answer arrives, the first
// unread one kept and later ones dropped until it is taken.
func testUrHostProbing(t *testing.T, world *testUrFollowWorld, network int) (*sidecar.Sidecar, chan *testUrProbedRead) {
	t.Helper()
	answers := make(chan *testUrProbedRead, 1)
	admitted := make(chan struct{})
	held := urDaemonConfigHeads
	t.Cleanup(func() { urDaemonConfigHeads = held })
	urDaemonConfigHeads = func(running *sidecar.Sidecar) sidecar.ConfigHeadReader {
		return &testUrProbedHeads{next: urNetworkConfigHeadReader(running), running: running, answers: answers, admitted: admitted}
	}
	running := world.host(world.networks[network], nil)
	close(admitted)
	return running, answers
}

// The next read's answer.
func testUrNextRead(t *testing.T, world *testUrFollowWorld, answers chan *testUrProbedRead) *testUrProbedRead {
	t.Helper()
	select {
	case read := <-answers:
		return read
	case <-world.ctx.Done():
		t.Fatalf("the follower read no head: %v", world.ctx.Err())
	}
	return nil
}

// testUrHostProbing's Sidecar and its first read's answer.
func testUrHostProbed(t *testing.T, world *testUrFollowWorld, network int) (*sidecar.Sidecar, *testUrProbedRead) {
	t.Helper()
	running, answers := testUrHostProbing(t, world, network)
	return running, testUrNextRead(t, world, answers)
}

// Each network's hooks answer its own clients, the same ones on each call: a GkmGroupClient the follower handed its
// state when it stood, an EvsClient of the network judging at that follower's newest verified state, and the head reader
// over it; and once the Sidecars close, the clients end with them and the hooks answer nothing more.
func TestDaemonBuildsEachNetworksClients(t *testing.T) {
	world := newTestUrFollowWorld(t, 2)
	sidecars := []*sidecar.Sidecar{}
	for _, network := range world.networks {
		running := world.host(network, nil)
		world.standing(running, network)
		sidecars = append(sidecars, running)
	}
	evsClients := []*sidecar.EvsClient{}
	for i, running := range sidecars {
		networkId := world.networks[i].NetworkId()
		gkm, err := urDaemonGkmClient(running)
		if err != nil {
			t.Fatalf("network %d's key client: %v", i, err)
		}
		again, _ := urDaemonGkmClient(running)
		if again != gkm {
			t.Fatalf("network %d answered two key clients", i)
		}
		evs, err := urDaemonEvsClient(running)
		if err != nil {
			t.Fatalf("network %d's evs client: %v", i, err)
		}
		if again, _ := urDaemonEvsClient(running); again != evs || evs.NetworkId() != networkId {
			t.Fatalf("network %d's evs client is of network %s", i, evs.NetworkId())
		}
		evsClients = append(evsClients, evs)
		if _, ok := urNetworkConfigHeadReader(running).(sidecar.ConfigHeadAnchorReader); !ok {
			t.Fatalf("network %d's head reader reads no anchor", i)
		}

		urNetworkClientsLock.Lock()
		clients := urNetworkClientsBySidecar[running]
		urNetworkClientsLock.Unlock()
		if clients == nil || clients.gkm != gkm || clients.builtGroup() == nil {
			t.Fatalf("network %d's group client is not built", i)
		}
		pin := running.ConfigFollower().Client().Pin()
		if given := clients.gkm.newestState(); given == nil || given.Pin().GetVersion() != pin.GetVersion() {
			t.Fatalf("network %d's key client holds %v, the follower %d", i, given, pin.GetVersion())
		}
		if config := clients.verifiedConfig(); config == nil || !bytes.Equal(config.Pin().GetChain(), pin.GetChain()) {
			t.Fatalf("network %d's evs client judges at %v, the follower at %d", i, config, pin.GetVersion())
		}
		if row := clients.sidecarRow(); row == nil || len(row.GetAdmissionSha256()) == 0 {
			t.Fatalf("network %d's key client does not hold this sidecar's admission", i)
		}
	}
	if evsClients[0] == evsClients[1] {
		t.Fatal("two networks share an evs client")
	}

	world.instance.Close()
	for i, running := range sidecars {
		urNetworkClientsLock.Lock()
		held := urNetworkClientsBySidecar[running]
		urNetworkClientsLock.Unlock()
		if held != nil {
			t.Fatalf("network %d's clients outlived its Sidecar", i)
		}
		if _, err := urDaemonEvsClient(running); err == nil {
			t.Fatalf("network %d's evs client answered after its Sidecar closed", i)
		}
		if _, err := urDaemonGkmClient(running); !errors.Is(err, sidecar.ErrSidecarClosed) {
			t.Fatalf("network %d's key client after its Sidecar closed: %v", i, err)
		}
	}
}

// urDaemonEvsClient refuses a network whose follower refused its log, naming the refusal, and git's service through the
// daemon answers that network's session with git's ERR line saying so; a standing network's session goes to its own
// evs client's git service, which answers with its local tier's own reason where evs serves nothing, its mount's hooks
// exec'ing the daemon's own ur git-hook under its instance, so a push there reaches the daemon.
func TestDaemonEvsClientWaitsForTheFollowerToStand(t *testing.T) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git on this host")
	}
	held := urDaemonClients
	t.Cleanup(func() { urDaemonClients = held })
	hookCommand, hookEnvironment := urDaemonGitHookCommand("/opt/ur/bin/ur", "work")
	urDaemonClients = &urDaemonClientsArgs{
		StateDirectory: t.TempDir(), GitPath: gitPath, HookCommand: hookCommand, HookEnvironment: hookEnvironment,
		Log: sidecar.NewNoopLogger(),
	}

	world := newTestUrFollowWorld(t, 2)
	good, refused := world.networks[0], world.networks[1]
	goodSidecar := world.host(good, nil)
	other := sha256.Sum256([]byte("a genesis no network here signed"))
	refusedSidecar := world.host(refused, &sidecar.SidecarEnrollAnchor{GenesisSha256: other[:]})
	ctx, cancel := context.WithTimeout(world.ctx, urTestTimeout)
	defer cancel()
	if _, err := refusedSidecar.ConfigFollower().WaitStanding(ctx); !errors.Is(err, sidecar.ErrSidecarConfigRefused) {
		t.Fatalf("a follower shown another genesis: %v", err)
	}
	world.standing(goodSidecar, good)

	if _, err := urDaemonEvsClient(refusedSidecar); !errors.Is(err, errUrEvsNotFollowing) || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("the refused network's evs client: %v", err)
	}
	// the session the daemon's git mode hands its service once <net> resolves (sidecar.NewDaemonGitMode)
	repoId := sidecar.NewId()
	session := func(running *sidecar.Sidecar) string {
		t.Helper()
		stream := &bytes.Buffer{}
		err := urDaemonGitService(ctx, &sidecar.DaemonGitSession{
			Hello:     &sidecar.DaemonHello{Mode: sidecar.DaemonModeGit},
			NetworkId: *running.NetworkId(),
			Sidecar:   running,
			Repo:      "id:" + repoId.String(),
			Service:   "git-upload-pack",
			Stream:    stream,
		})
		if err == nil {
			t.Fatalf("a session to a repo no evs serves was served: %q", stream.String())
		}
		return stream.String()
	}
	if answer := session(refusedSidecar); !strings.Contains(answer, "ERR ur: "+errUrEvsNotFollowing.Error()) ||
		!strings.Contains(answer, "refused") {
		t.Fatalf("the refused network's session: %q", answer)
	}
	// the network's own evs client's git service, past the hook: its local tier mounts the repo, then reads it from evs
	answer := session(goodSidecar)
	if !strings.Contains(answer, "ERR ur: the repo cannot be read from evs now") {
		t.Fatalf("the standing network's session: %q", answer)
	}
	client, err := urDaemonEvsClient(goodSidecar)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := client.Mounts()
	if err != nil {
		t.Fatal(err)
	}
	mount, ok := mounts.Get(repoId)
	if !ok {
		t.Fatal("the session made no mount")
	}
	for _, hook := range []string{sidecar.EvsGitHookPreReceive, sidecar.EvsGitHookProcReceive} {
		script, err := os.ReadFile(filepath.Join(mount.HooksDir, hook))
		if err != nil || !strings.Contains(string(script), "exec '/opt/ur/bin/ur' 'git-hook' '"+hook+"'") {
			t.Fatalf("the mount's %s hook: %q %v", hook, script, err)
		}
	}
	if environment := mounts.ReceiveEnvironment(&sidecar.EvsGitReceiveSession{Id: "s"}); !slices.Contains(environment, "UR_INSTANCE=work") {
		t.Fatalf("a push's hooks run with %v", environment)
	}
}

// With the key client's hook unset, the composition builds no EvsClient, so its head reader answers base 1
// unavailable, naming the key client, and the follower holds the start's genesis state alone and never stands; with the
// head reader's hook unset the follower has none, which withholds every base (ConfigClient's own rule).
func TestDaemonWithholdsEveryBaseWithEitherHookUnset(t *testing.T) {
	world := newTestUrFollowWorld(t, 2)
	held := urDaemonGkmClient
	t.Cleanup(func() { urDaemonGkmClient = held })
	urDaemonGkmClient = nil
	running, read := testUrHostProbed(t, world, 0)
	if !errors.Is(read.err, sidecar.ErrConfigHeadUnavailable) || !errors.Is(read.err, errUrNoKeyClient) {
		t.Fatalf("base 1 with no key client: %v", read.err)
	}
	if read.standing || read.verified == nil || read.verified.Pin().GetVersion() != 0 {
		t.Fatalf("the follower at base 1's read: standing %t, at %v", read.standing, read.verified)
	}
	if running.ConfigFollower().Client() != nil || running.Admitted() {
		t.Fatal("a follower with no key client stood")
	}

	// the clients took the hook once, when they were made, so its restoring, which a follower's retry may meet on another
	// goroutine, changes nothing of theirs
	urDaemonGkmClient = held
	if _, err := testUrClientsOf(running).evsClient(); !errors.Is(err, errUrNoKeyClient) {
		t.Fatalf("the clients made with no key client hook, after it was set: %v", err)
	}
	urDaemonConfigHeads = nil
	unread := world.host(world.networks[1], nil)
	if follower := unread.ConfigFollower(); follower == nil || follower.Heads() != nil {
		t.Fatal("a follower got a head reader from an unset hook")
	}
}

// With no config key a full follower withholds base one. The network identity already has a KeyDelivery
// client for the rows-only join, and it cannot seal on that state.
func TestDaemonReadsBaseOneAtTheStartsState(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	network := world.networks[0]
	running, answers := testUrHostProbing(t, world, 0)
	read := testUrNextRead(t, world, answers)
	if !errors.Is(read.err, sidecar.ErrConfigHeadUnavailable) || errors.Is(read.err, errUrNoKeyClient) ||
		!errors.Is(read.err, sidecar.ErrGkmUnavailable) {
		t.Fatalf("base 1 with no generation of the config repo held: %v", read.err)
	}
	if strings.Contains(read.err.Error(), "names the config repo") || strings.Contains(read.err.Error(), "no evs client") {
		t.Fatalf("the reader stopped before the key client: %v", read.err)
	}
	if read.standing || read.verified == nil || read.verified.Pin().GetVersion() != 0 {
		t.Fatalf("the follower at base 1's read: standing %t, at %v", read.standing, read.verified)
	}
	clients := testUrClientsOf(running)
	if clients == nil || clients.builtGroup() == nil || !clients.builtGroup().KeyDeliveryOnly() {
		t.Fatal("the joining member device has no KeyDelivery client")
	}
	identity := running.Identity()
	for {
		_, changed := clients.upkeep.Passes()
		state, repoId, confirmed := clients.gkm.joiningState()
		if state != nil && !confirmed && repoId == network.ConfigRepoId() && state.SidecarRow(identity.SidecarId) != nil {
			break
		}
		select {
		case <-changed:
		case <-world.ctx.Done():
			t.Fatal("the rows-only pass never reached the client's admission")
		}
	}
	configRepoId := network.ConfigRepoId()
	if clients.gkm.newestState() != nil {
		t.Fatal("the key client holds a verified state before the follower stands")
	}
	// a seal waits for a verified state
	if _, err := clients.builtGroup().EnsureWritable(world.ctx, configRepoId); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Fatalf("a seal on the unconfirmed state: %v", err)
	}
	if running.ConfigFollower().Client() != nil || running.Admitted() {
		t.Fatal("a follower stood on a base its head reader withheld")
	}
	if status := running.ConfigFollower().Status(); !strings.Contains(status.Reason, "joining") {
		t.Fatalf("the joining follower says %q", status.Reason)
	}
}

// Member devices, ephemeral devices and tagged agents all use the stock KeyDelivery client.
func TestDaemonChoosesEachKeyClientFromItsRow(t *testing.T) {
	world := newTestUrFollowWorld(t, 3)
	kinds := []testUrAdmission{testUrMemberDevice, testUrEphemeral, testUrTagged}
	for i, network := range world.networks {
		running := world.hostAs(network, kinds[i])
		world.standing(running, network)
		gkm, err := urDaemonGkmClient(running)
		if err != nil {
			t.Fatalf("network %d's key client: %v", i, err)
		}
		clients := testUrClientsOf(running)
		group, err := clients.groupClient()
		if err != nil {
			t.Fatalf("network %d's group client: %v", i, err)
		}
		if again, _ := clients.groupClient(); again != group {
			t.Fatalf("network %d built two group clients", i)
		}
		if !group.KeyDeliveryOnly() || !gkm.(*urNetworkGkm).KeyDeliveryOnly() {
			t.Fatalf("network %d selected an epoch-based key client", i)
		}

	}
}
