//go:build !ios_extension && !sidecar_http && !js

// §17.4's first block row (plan-BRIDGE-small-readings #13) on T2's fake api, with sidecartest's in-memory config ref:
// BootstrapNetwork draws a network's first bridge block into its first head, signed by the owner's first device, which
// every reader of base 1 holds and the address plan takes, and later heads keep it, drawing none; a block the caller's
// files hold stands; of two first devices racing base 1, only the winner's block is ever in a head; a network whose head
// holds none, one bootstrapped before the bridge shipped, gets one from a config writer's next head, which every reader
// takes, and keeps it; and two writers drawing at once for a network that holds none leave one block, the second's save
// conflicting and its retry drawing none. Every wait is on a channel or the client's log; the draws come from seeded
// streams, so each test knows the block it expects.

package sidecar_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A random stream fixed by label: the same draws for the same label.
func testBlockRandom(label string) io.Reader {
	return rand.NewChaCha8(sha256.Sum256([]byte("bridge block bootstrap test " + label)))
}

// The block ChooseBridgeBlock draws first from label's stream.
func testBlockDrawn(t *testing.T, label string) *bridge.BridgeIpv4Prefix {
	t.Helper()
	prefix, err := sidecar.ChooseBridgeBlock(testBlockRandom(label))
	if err != nil {
		t.Fatal(err)
	}
	return prefix
}

// A random source any read of fails: what draws nothing must not read it.
func testBlockNoDraw() io.Reader {
	return iotest.ErrReader(errors.New("no block is drawn here"))
}

// A random source that counts its reads.
type testBlockCountingRandom struct {
	reader io.Reader
	reads  atomic.Int64
}

func (self *testBlockCountingRandom) Read(data []byte) (int, error) {
	self.reads.Add(1)
	return self.reader.Read(data)
}

// device's BootstrapNetwork on the world's ref, its first block drawn from random.
func testBlockBootstrap(world *testWriterWorld, device testWriterDevice, random io.Reader) (*sidecar.ConfigBootstrapResult, error) {
	return sidecar.BootstrapNetwork(world.ctx, &sidecar.ConfigBootstrapArgs{
		NetworkId:         world.networkId,
		OwnerMemberId:     device.memberId,
		SidecarId:         device.sidecarId,
		IdentityPublicKey: device.key.Public().(ed25519.PublicKey),
		Sign:              device.sign(),
		ConfigRepoId:      world.repoId,
		Heads:             world.heads.For(device.sidecarId, device.key),
		Publisher:         world.publisher(),
		Projection:        world.reader(),
		BridgeBlockRandom: random,
		Clock:             world.clock,
	})
}

// The owner bootstraps a network as one did before the bridge shipped: its first head holds no block.
func testBlockOlderNetwork(t *testing.T, world *testWriterWorld) {
	t.Helper()
	seams := &testBootstrapSeams{t: t, world: world}
	args := seams.args(world.owner, world.publisher())
	args.First.Initialize = func(ctx context.Context, genesis *sidecar.ConfigState, head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadBridgeBlockPath, nil)
	}
	result, err := sidecar.BootstrapNetwork(world.ctx, args)
	if err != nil || !result.Won {
		t.Fatalf("the older network's bootstrap: %v", err)
	}
	world.genesis = result
}

// The head state's base names.
func testBlockHead(t *testing.T, world *testWriterWorld, state *sidecar.ConfigState) *sidecar.ConfigHead {
	t.Helper()
	base := state.Base()
	head, err := world.heads.ReadConfigHead(world.ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		t.Fatalf("the head of the base at %d: %v", base.GetVersion(), err)
	}
	return head
}

// The block a reader standing at state holds from the head its base names, nil for none; a refused one fails.
func testBlockAt(t *testing.T, world *testWriterWorld, state *sidecar.ConfigState) *bridge.BridgeBlock {
	t.Helper()
	block, err := sidecar.ReadBridgeBlock(testBlockHead(t, world, state), state, nil)
	if err != nil {
		t.Fatalf("the block at %d: %v", state.Pin().GetVersion(), err)
	}
	return block
}

// The sidecar that signed head's bridge/block.
func testBlockSigner(t *testing.T, head *sidecar.ConfigHead) sidecar.Id {
	t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(head.File(sidecar.ConfigHeadBridgeBlockPath), signed); err != nil {
		t.Fatal(err)
	}
	signerId, err := sidecar.IdFromBytes(signed.GetSignerId())
	if err != nil {
		t.Fatal(err)
	}
	return signerId
}

// A writer of device's over client, as the follower composes its writers, with the first block drawn from random; heads
// nil is the device's own on the world's ref. Its fold loop runs on a clock of its own, which nothing advances.
func testBlockWriter(world *testWriterWorld, device testWriterDevice, client *sidecar.ConfigClient, heads sidecar.ConfigHeadRef, random io.Reader) *sidecar.ConfigWriter {
	world.t.Helper()
	settings := sidecar.DefaultConfigWriterSettings()
	settings.Clock = sidecartest.NewFakeClock(world.clock.Now())
	settings.Random = func() float64 { return 0 }
	settings.BridgeBlockRandom = random
	settings.Log = sidecar.NewNoopLogger()
	if heads == nil {
		heads = world.heads.For(device.sidecarId, device.key)
	}
	writer, err := sidecar.NewConfigWriter(world.ctx, &sidecar.ConfigWriterArgs{
		SidecarId:        device.sidecarId,
		Sign:             device.sign(),
		Client:           client,
		Heads:            heads,
		Publisher:        world.publisher(),
		Settings:         settings,
		FirstBridgeBlock: sidecar.WithFirstBridgeBlock,
	})
	if err != nil {
		world.t.Fatal(err)
	}
	world.t.Cleanup(writer.Close)
	return writer
}

// A head edit that sets the policy file to text, which the world's compile ignores.
func testBlockPolicy(text string) func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
	return func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadPolicyPath, []byte(text))
	}
}

// A device's ref that records every head it commits, and holds its first prepare, once the push is signed, until
// release closes, prepared closing then; hold false holds none.
type testBlockRef struct {
	sidecar.ConfigHeadRef
	hold     bool
	prepared chan struct{}
	release  chan struct{}
	once     sync.Once
	commits  *testBlockCommits
}

func (self *testBlockRef) PrepareConfigHead(ctx context.Context, head *sidecar.ConfigHead, version uint64) (*sidecar.ConfigHeadPush, error) {
	push, err := self.ConfigHeadRef.PrepareConfigHead(ctx, head, version)
	if self.hold {
		self.once.Do(func() {
			close(self.prepared)
			select {
			case <-self.release:
			case <-ctx.Done():
			}
		})
	}
	return push, err
}

func (self *testBlockRef) CommitConfigHead(ctx context.Context, push *sidecar.ConfigHeadPush) error {
	err := self.ConfigHeadRef.CommitConfigHead(ctx, push)
	if err == nil {
		self.commits.add(push.Head)
	}
	return err
}

// The heads the refs committed, in commit order.
type testBlockCommits struct {
	stateLock sync.Mutex
	heads     []*sidecar.ConfigHead
}

func (self *testBlockCommits) add(head *sidecar.ConfigHead) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.heads = append(self.heads, head)
}

func (self *testBlockCommits) all() []*sidecar.ConfigHead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*sidecar.ConfigHead{}, self.heads...)
}

// The daemon's head reader over evs, a config ref too as ur daemon's is (ConfigHeadRef): it reads through the follow
// world's reader, and writes the in-memory ref of the admission world running enrolls in, its pushes signed by running.
type testBlockFollowHeads struct {
	sidecar.ConfigHeadReader
	world   *configFollowWorld
	running *sidecar.Sidecar
}

// running's ref on its network's config repo.
func (self *testBlockFollowHeads) ref() (*sidecartest.FakeConfigHeadRef, error) {
	networkId, identity := self.running.NetworkId(), self.running.Identity()
	if networkId == nil || identity == nil {
		return nil, sidecar.ErrConfigHeadUnavailable
	}
	network := self.world.network(*networkId)
	if network == nil {
		return nil, sidecar.ErrConfigHeadUnavailable
	}
	return network.Heads().ForSigner(identity.SidecarId, func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return self.running.Sign(purpose, signedType, body, nil)
	}), nil
}

func (self *testBlockFollowHeads) CurrentConfigHead(ctx context.Context) (*sidecar.ConfigHead, uint64, [sha256.Size]byte, error) {
	ref, err := self.ref()
	if err != nil {
		return nil, 0, [sha256.Size]byte{}, err
	}
	return ref.CurrentConfigHead(ctx)
}

func (self *testBlockFollowHeads) PrepareConfigHead(ctx context.Context, head *sidecar.ConfigHead, version uint64) (*sidecar.ConfigHeadPush, error) {
	ref, err := self.ref()
	if err != nil {
		return nil, err
	}
	return ref.PrepareConfigHead(ctx, head, version)
}

func (self *testBlockFollowHeads) CommitConfigHead(ctx context.Context, push *sidecar.ConfigHeadPush) error {
	ref, err := self.ref()
	if err != nil {
		return err
	}
	return ref.CommitConfigHead(ctx, push)
}

func (self *testBlockFollowHeads) ConfigHeadPushes(ctx context.Context, after uint64, through uint64) ([][]byte, error) {
	ref, err := self.ref()
	if err != nil {
		return nil, err
	}
	return ref.ConfigHeadPushes(ctx, after, through)
}

// The daemon's composition: a network whose head lost its block, as one bootstrapped before the bridge shipped holds
// none, gets one from the next head of the config writer its Owner's hosted Sidecar's follower runs, signed by that
// Sidecar, which every reader takes.
func TestAFollowersConfigWriterDrawsTheBlockItsNetworkLacks(t *testing.T) {
	world := newConfigFollowWorld(t, 1, nil)
	world.wrapHeads = func(running *sidecar.Sidecar, heads sidecar.ConfigHeadReader) sidecar.ConfigHeadReader {
		return &testBlockFollowHeads{ConfigHeadReader: heads, world: world, running: running}
	}
	network := world.networks[0]
	network.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadBridgeBlockPath, nil)
	})
	running := world.host(network, nil)
	client := world.standing(running, network)
	readBlock := func(state *sidecar.ConfigState) (*sidecar.ConfigHead, *bridge.BridgeBlock) {
		base := state.Base()
		head, err := network.Heads().ReadConfigHead(world.ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
		if err != nil {
			t.Fatal(err)
		}
		block, err := sidecar.ReadBridgeBlock(head, state, nil)
		if err != nil {
			t.Fatal(err)
		}
		return head, block
	}
	if _, block := readBlock(client.State()); block != nil {
		t.Fatalf("the network holds %v before the writer's next head", block)
	}
	writer := client.Writer()
	if writer == nil {
		t.Fatal("the follower runs no config writer over a ref")
	}
	ctx, cancel := context.WithTimeout(world.ctx, configFollowTestTimeout)
	defer cancel()
	if _, err := writer.SaveHead(ctx, testBlockPolicy("{}")); err != nil {
		t.Fatalf("the follower's writer's head: %v", err)
	}
	head, block := readBlock(client.State())
	if block == nil || block.GetPreviousPrefix() != nil || testBlockSigner(t, head) != running.Identity().SidecarId {
		t.Fatalf("the next head's block %v, signed by the hosted Sidecar", block)
	}
}

// A new network gets its block once: the first head holds the /16 the bootstrap drew, outside 100.64.0.0/16 and
// 100.100.0.0/16 with no block before it, signed by the owner's first device; the device's own S(1) and a reader
// following base 1 both hold it, and the address plan places a host in it; a writer's next head keeps those bytes,
// drawing nothing, and a fold keeps them too.
func TestBootstrapNetworkDrawsItsFirstBridgeBlock(t *testing.T) {
	world := newTestWriterWorld(t)
	want := testBlockDrawn(t, "owner")
	result, err := testBlockBootstrap(world, world.owner, testBlockRandom("owner"))
	if err != nil || !result.Won {
		t.Fatalf("bootstrap: %v", err)
	}
	world.genesis = result
	first := result.Push.Head
	block, err := sidecar.ReadBridgeBlock(first, result.State, nil)
	if err != nil || block == nil {
		t.Fatalf("the first head's block at the device's own S(1): %v, %v", block, err)
	}
	if !proto.Equal(block.GetIpv4Prefix(), want) || block.GetPreviousPrefix() != nil || block.GetDrainUntil() != 0 {
		t.Fatalf("the first block %v, want %v with nothing before it", block, want)
	}
	if second := block.GetIpv4Prefix().GetAddress() >> 16 & 0xff; block.GetIpv4Prefix().GetAddress()>>24 != 100 || second < 65 || 127 < second || second == 100 {
		t.Fatalf("the first block %v is outside what ChooseBridgeBlock draws", block)
	}
	if signer := testBlockSigner(t, first); signer != world.owner.sidecarId {
		t.Errorf("the block is signed by %s, not the owner's first device", signer)
	}

	client := world.client()
	state := world.caughtUp(client)
	if held := testBlockAt(t, world, state); !proto.Equal(held, block) {
		t.Fatalf("a reader of base 1 holds %v, the bootstrap drew %v", held, block)
	}
	plan, err := sidecar.NewBridgeAddressPlan(block, nil)
	if err != nil {
		t.Fatal(err)
	}
	address, err := sidecar.AllocateBridgeAddress(plan, testBlockRandom("host"))
	if err != nil || address>>16 != block.GetIpv4Prefix().GetAddress()>>16 {
		t.Fatalf("a host's address %x in the block %v: %v", address, block, err)
	}

	writer := testBlockWriter(world, world.owner, client, nil, testBlockNoDraw())
	if _, err := writer.SaveHead(world.ctx, testBlockPolicy("{}")); err != nil {
		t.Fatalf("a head over the first: %v", err)
	}
	state = world.caughtUp(client)
	if head := testBlockHead(t, world, state); state.Base().GetConfigVersion() != 2 ||
		string(head.File(sidecar.ConfigHeadBridgeBlockPath)) != string(first.File(sidecar.ConfigHeadBridgeBlockPath)) {
		t.Fatalf("the head at config version %d does not keep the first block", state.Base().GetConfigVersion())
	}
	if _, err := world.admitMember("a"); err != nil {
		t.Fatal(err)
	}
	world.caughtUp(client)
	if _, err := writer.PublishBase(world.ctx, true); err != nil {
		t.Fatalf("a fold: %v", err)
	}
	state = world.caughtUp(client)
	if head := testBlockHead(t, world, state); state.Base().GetFoldedThrough() == 0 ||
		string(head.File(sidecar.ConfigHeadBridgeBlockPath)) != string(first.File(sidecar.ConfigHeadBridgeBlockPath)) {
		t.Fatalf("the fold's head through %d does not keep the first block", state.Base().GetFoldedThrough())
	}
}

// A block the caller's files hold is the first head's, and nothing is drawn.
func TestBootstrapNetworkKeepsTheBlockItsFilesHold(t *testing.T) {
	world := newTestWriterWorld(t)
	chosen := &bridge.BridgeBlock{Ipv4Prefix: &bridge.BridgeIpv4Prefix{Address: 10<<24 | 20<<16, Length: 16}}
	signed := world.statement(world.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, chosen)
	args := &sidecar.ConfigBootstrapArgs{
		NetworkId:         world.networkId,
		OwnerMemberId:     world.owner.memberId,
		SidecarId:         world.owner.sidecarId,
		IdentityPublicKey: world.owner.key.Public().(ed25519.PublicKey),
		Sign:              world.owner.sign(),
		ConfigRepoId:      world.repoId,
		Heads:             world.heads.For(world.owner.sidecarId, world.owner.key),
		Publisher:         world.publisher(),
		Projection:        world.reader(),
		Files:             map[string][]byte{sidecar.ConfigHeadBridgeBlockPath: signed},
		BridgeBlockRandom: testBlockNoDraw(),
		Clock:             world.clock,
	}
	result, err := sidecar.BootstrapNetwork(world.ctx, args)
	if err != nil || !result.Won {
		t.Fatalf("bootstrap: %v", err)
	}
	world.genesis = result
	state := world.caughtUp(world.client())
	if held := testBlockAt(t, world, state); !proto.Equal(held, chosen) {
		t.Fatalf("the network holds %v, the caller's block is %v", held, chosen)
	}
}

// Concurrent first uses at bootstrap: two first devices racing base 1, each drawing its own block, leave one head,
// holding the winner's block, which a reader of the winning genesis holds; the loser's block is in no head.
func TestTwoFirstDevicesRacingLeaveOneBridgeBlock(t *testing.T) {
	world := newTestWriterWorld(t)
	rival := testWriterDeviceOf("rival device", world.owner.memberId)
	devices := []testWriterDevice{world.owner, rival}
	labels := []string{"owner", "rival"}
	draws := []*bridge.BridgeIpv4Prefix{testBlockDrawn(t, labels[0]), testBlockDrawn(t, labels[1])}
	if proto.Equal(draws[0], draws[1]) {
		t.Fatal("the two devices' streams draw one block, which shows nothing")
	}
	results := make([]*sidecar.ConfigBootstrapResult, 2)
	errs := make([]error, 2)
	var group sync.WaitGroup
	for i := range devices {
		group.Add(1)
		go func() {
			defer group.Done()
			results[i], errs[i] = testBlockBootstrap(world, devices[i], testBlockRandom(labels[i]))
		}()
	}
	group.Wait()
	winner := -1
	for i, err := range errs {
		if err != nil {
			t.Fatalf("device %d: %v", i, err)
		}
		if results[i].Won {
			winner = i
		}
	}
	if winner < 0 || results[1-winner].Won {
		t.Fatalf("won: %v and %v", results[0].Won, results[1].Won)
	}
	if world.heads.Version() != 1 {
		t.Fatalf("the config repo holds %d heads", world.heads.Version())
	}
	world.genesis = results[winner]
	state := world.caughtUp(world.client())
	held := testBlockAt(t, world, state)
	if !proto.Equal(held.GetIpv4Prefix(), draws[winner]) || testBlockSigner(t, testBlockHead(t, world, state)) != devices[winner].sidecarId {
		t.Fatalf("the network holds %v, the winner drew %v", held, draws[winner])
	}
}

// A network bootstrapped before the bridge shipped holds no block until a config writer's next head, whatever it saves,
// draws one: an Owner's writer signs it, every reader takes it, and the writer's later heads and a second writer's keep
// those bytes, reading no randomness.
func TestAConfigWritersNextHeadDrawsTheBlockAnOlderNetworkLacks(t *testing.T) {
	world := newTestWriterWorld(t)
	testBlockOlderNetwork(t, world)
	client := world.client()
	state := world.caughtUp(client)
	if held := testBlockAt(t, world, state); held != nil {
		t.Fatalf("the older network holds %v at base 1", held)
	}

	want := testBlockDrawn(t, "writer")
	random := &testBlockCountingRandom{reader: testBlockRandom("writer")}
	writer := testBlockWriter(world, world.owner, client, nil, random)
	if _, err := writer.SaveHead(world.ctx, testBlockPolicy("{}")); err != nil {
		t.Fatalf("the writer's next head: %v", err)
	}
	state = world.caughtUp(client)
	head := testBlockHead(t, world, state)
	held := testBlockAt(t, world, state)
	if held == nil || !proto.Equal(held.GetIpv4Prefix(), want) || held.GetPreviousPrefix() != nil ||
		string(head.File(sidecar.ConfigHeadPolicyPath)) != "{}" || testBlockSigner(t, head) != world.owner.sidecarId {
		t.Fatalf("the next head holds the block %v, want %v signed by the owner beside the edit", held, want)
	}
	second := world.client()
	if held := testBlockAt(t, world, world.caughtUp(second)); !proto.Equal(held.GetIpv4Prefix(), want) {
		t.Fatalf("a second reader holds %v", held)
	}

	reads := random.reads.Load()
	if _, err := writer.SaveHead(world.ctx, testBlockPolicy("{\"grants\": []}")); err != nil {
		t.Fatal(err)
	}
	other := testBlockWriter(world, world.owner, second, nil, testBlockNoDraw())
	world.caughtUp(second)
	if _, err := other.SaveHead(world.ctx, testBlockPolicy("{\"grants\": [], \"tests\": []}")); err != nil {
		t.Fatalf("a second writer's head: %v", err)
	}
	state = world.caughtUp(client)
	if string(testBlockHead(t, world, state).File(sidecar.ConfigHeadBridgeBlockPath)) != string(head.File(sidecar.ConfigHeadBridgeBlockPath)) ||
		random.reads.Load() != reads {
		t.Fatal("a later head drew the block again")
	}
}

// Concurrent first uses by writers: two Owner's devices' writers save heads at once on a network that holds no block,
// each drawing its own. The first holds its push, its block drawn, while the second's head lands with the second's
// block; the first's save then conflicts, and its retry reads the second's block and draws none. Only the second's block
// was ever in a head, under the second's edit and then the first's, and every reader holds it.
func TestConcurrentWritersDrawOneFirstBridgeBlock(t *testing.T) {
	world := newTestWriterWorld(t)
	testBlockOlderNetwork(t, world)
	desktop := testWriterDeviceOf("owner desktop", world.owner.memberId)
	if _, err := world.api.AppendStatement(world.ctx, world.networkId, world.statement(world.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		Header:            world.header(),
		NetworkId:         world.networkId.Bytes(),
		SidecarId:         desktop.sidecarId.Bytes(),
		IdentityPublicKey: desktop.key.Public().(ed25519.PublicKey),
		IdentityAlg:       "ed25519",
		MemberId:          desktop.memberId.Bytes(),
	})); err != nil {
		t.Fatal(err)
	}
	laptopClient, desktopClient := world.client(), world.client()
	if state := world.caughtUp(desktopClient); !state.IsConfigWriter(desktop.sidecarId) {
		t.Fatal("the owner's second device writes no config head")
	}
	world.caughtUp(laptopClient)
	commits := &testBlockCommits{}
	held := &testBlockRef{
		ConfigHeadRef: world.heads.For(world.owner.sidecarId, world.owner.key),
		hold:          true,
		prepared:      make(chan struct{}),
		release:       make(chan struct{}),
		commits:       commits,
	}
	laptop := testBlockWriter(world, world.owner, laptopClient, held, testBlockRandom("laptop"))
	desktopWriter := testBlockWriter(world, desktop, desktopClient, &testBlockRef{
		ConfigHeadRef: world.heads.For(desktop.sidecarId, desktop.key),
		commits:       commits,
	}, testBlockRandom("desktop"))
	laptopDraw, desktopDraw := testBlockDrawn(t, "laptop"), testBlockDrawn(t, "desktop")
	if proto.Equal(laptopDraw, desktopDraw) {
		t.Fatal("the two writers' streams draw one block, which shows nothing")
	}

	saved := make(chan error, 1)
	go func() {
		_, err := laptop.SaveHead(world.ctx, testBlockPolicy("{\"laptop\": 1}"))
		saved <- err
	}()
	select {
	case <-held.prepared:
	case err := <-saved:
		t.Fatalf("the laptop's save returned before its prepare: %v", err)
	}
	if _, err := desktopWriter.SaveHead(world.ctx, testBlockPolicy("{\"desktop\": 1}")); err != nil {
		t.Fatalf("the desktop's head: %v", err)
	}
	close(held.release)
	if err := <-saved; !errors.Is(err, sidecar.ErrConfigHeadConflict) {
		t.Fatalf("the laptop's head drawn over the blockless head: %v", err)
	}
	world.caughtUp(laptopClient)
	if _, err := laptop.SaveHead(world.ctx, testBlockPolicy("{\"laptop\": 1}")); err != nil {
		t.Fatalf("the laptop's retry: %v", err)
	}

	state := world.caughtUp(world.client())
	block := testBlockAt(t, world, state)
	head := testBlockHead(t, world, state)
	if !proto.Equal(block.GetIpv4Prefix(), desktopDraw) || testBlockSigner(t, head) != desktop.sidecarId ||
		string(head.File(sidecar.ConfigHeadPolicyPath)) != "{\"laptop\": 1}" {
		t.Fatalf("the network holds %v, the desktop drew %v", block, desktopDraw)
	}
	heads := commits.all()
	if len(heads) != 2 || string(heads[0].File(sidecar.ConfigHeadPolicyPath)) != "{\"desktop\": 1}" ||
		string(heads[1].File(sidecar.ConfigHeadPolicyPath)) != "{\"laptop\": 1}" {
		t.Fatalf("%d heads committed, want the desktop's and then the laptop's retry", len(heads))
	}
	for i, committed := range heads {
		if string(committed.File(sidecar.ConfigHeadBridgeBlockPath)) != string(head.File(sidecar.ConfigHeadBridgeBlockPath)) {
			t.Errorf("head %d committed another block", i)
		}
	}
}
