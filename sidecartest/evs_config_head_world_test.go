// The config repo's head reader over evs on T2 (QD-804; §7.9's BASE row, §11.8's replay row): sidecar.EvsClient
// devices against an evsservice.EvsEngine over FakeHost's stores, in a repo of kind config whose main ref holds config
// heads, each saved as one push of the files that changed, as a config writer saves one.
//
//	reads     each head read at its own ref version while the ref stands past it, a removed file and its directory
//	          gone from the head after the removal and standing in the one before; by a device that never read the
//	          ref, by one that read on, and by one restarted on its pin
//	refusals  a chain value no version holds and a head named at another version are a mismatch; a version evs does
//	          not serve yet, a config version of 0 and a push whose authorization pin this device no longer retains
//	          are unavailable; a push by a sidecar this device's state does not let write the config is a mismatch,
//	          the head before it still read
//	epochs    a head saved after a path epoch's cut-over, its pushes naming paths by the new epoch's tokens, read by a
//	          device that replays across the cut-over
//	client    BootstrapNetwork's base 1 on FakeApi names the evs ref's (1, C_1), and a ConfigClient whose head reader
//	          is this one installs it
//
// The ref's ConfigHeadRef here pushes at once where a writer's prepares first: evs has no writer's side of it yet, and
// the reader reads what landed either way.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A config repo's main ref on the world's engine, as one writer saves heads to it.
type configHeadEvsRef struct {
	world  *epochWorld
	device *epochDevice

	// held across a save, so a config writer's fold loop reads a head with its own version
	stateLock sync.Mutex
	// the files the ref holds, and the newest head saved through it with its version and chain value: nil, 0 and C_0
	// before the first
	files   map[string][]byte
	head    *sidecar.ConfigHead
	version uint64
	chain   [sha256.Size]byte
}

// The ref's chain value at each version through version, as the writer's verifier walks it from C_0, and each
// version's Signed EvsPush.
func (self *configHeadEvsRef) walk(version uint64) ([][sha256.Size]byte, [][]byte) {
	self.world.t.Helper()
	refId := self.world.mainRefId(self.device)
	start := sidecar.EvsChainStart(self.world.repoId, refId)
	walked, err := self.device.client.Verifier().Walk(self.world.ctx, self.world.repoId, refId, 0, start, version)
	if err != nil {
		self.world.t.Fatalf("the writer's walk to %d: %v", version, err)
	}
	chains := [][sha256.Size]byte{start}
	pushes := [][]byte{}
	for _, statement := range walked {
		chains = append(chains, statement.Chain)
		pushes = append(pushes, statement.Statement.Bytes)
	}
	return chains, pushes
}

// Saves head as the ref's next version by device, one push of what changed: its version and chain value.
func (self *configHeadEvsRef) save(device *epochDevice, head *sidecar.ConfigHead) (uint64, [sha256.Size]byte) {
	self.world.t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	files := head.Files()
	changes := map[string][]byte{}
	for path, data := range files {
		if !bytes.Equal(self.files[path], data) {
			changes[path] = data
		}
	}
	for path := range self.files {
		if _, kept := files[path]; !kept {
			changes[path] = nil
		}
	}
	result, err := device.writePaths(changes)
	if err != nil {
		self.world.t.Fatalf("saving a head: %v", err)
	}
	self.files = files
	chains, _ := self.walk(result.Version)
	self.head, self.version, self.chain = head, result.Version, chains[result.Version]
	return result.Version, chains[result.Version]
}

// The newest head saved through the ref, none at C_0 before the first.
func (self *configHeadEvsRef) CurrentConfigHead(ctx context.Context) (*sidecar.ConfigHead, uint64, [sha256.Size]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.head == nil {
		return nil, 0, sidecar.EvsChainStart(self.world.repoId, self.world.mainRefId(self.device)), nil
	}
	return self.head, self.version, self.chain, nil
}

// Pushes the head, since evs prepares none without sending it.
func (self *configHeadEvsRef) PrepareConfigHead(ctx context.Context, head *sidecar.ConfigHead, version uint64) (*sidecar.ConfigHeadPush, error) {
	saved, chain := self.save(self.device, head)
	if saved != version+1 {
		return nil, fmt.Errorf("%w: saved at %d after %d", sidecar.ErrConfigHeadConflict, saved, version)
	}
	_, pushes := self.walk(saved)
	return &sidecar.ConfigHeadPush{Head: head, Version: saved, Chain: chain, SignedPush: pushes[saved-1]}, nil
}

func (self *configHeadEvsRef) CommitConfigHead(ctx context.Context, push *sidecar.ConfigHeadPush) error {
	return nil
}

func (self *configHeadEvsRef) ConfigHeadPushes(ctx context.Context, after uint64, through uint64) ([][]byte, error) {
	_, pushes := self.walk(through)
	return pushes[after:through], nil
}

// A config repo on the world's engine, bootstrapped by w: the genesis, head 1 and base 1 on a FakeApi.
type configHeadWorld struct {
	*epochWorld
	api       *FakeApi
	writer    *epochDevice
	ref       *configHeadEvsRef
	bootstrap *sidecar.ConfigBootstrapResult
	// each version's head and chain value, the first at index 1
	heads  []*sidecar.ConfigHead
	chains [][sha256.Size]byte
}

// A share file's path, of a share id made of one byte.
func configHeadSharePath(fill byte) string {
	return sidecar.ConfigHeadBridgeSharePrefix + fmt.Sprintf("%032x", bytes.Repeat([]byte{fill}, 16))
}

func newConfigHeadWorld(t *testing.T) *configHeadWorld {
	t.Helper()
	t.Cleanup(sidecar.RegisterConfigAclCompiler(admissionAclCompile))
	world := &configHeadWorld{epochWorld: newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_CONFIG)}
	world.writer = world.device("w", nil)
	world.ref = &configHeadEvsRef{world: world.epochWorld, device: world.writer, files: map[string][]byte{}}
	world.api = NewFakeApi(world.ctx, world.clock, nil, nil, world.cluster, nil)
	signer := world.signers["w"]
	result, err := sidecar.BootstrapNetwork(world.ctx, &sidecar.ConfigBootstrapArgs{
		NetworkId:         world.networkId,
		OwnerMemberId:     world.memberId,
		SidecarId:         signer.SidecarId,
		IdentityPublicKey: signer.PublicKey(),
		Sign: func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
			return signer.Sign(purpose, signedType, body, nil)
		},
		ConfigRepoId: world.repoId,
		Heads:        world.ref,
		Publisher:    &FakeApiConfigPublisher{Api: world.api, NetworkId: world.networkId},
		Projection:   &FakeApiConfigReader{Api: world.api, NetworkId: world.networkId},
		Files: map[string][]byte{
			sidecar.ConfigHeadPolicyPath: []byte(`{"acls": []}`),
			configHeadSharePath(0xa1):    bytes.Repeat([]byte("share a1; "), 300),
		},
		Clock: world.clock,
	})
	if err != nil || !result.Won {
		t.Fatalf("bootstrap: %v", err)
	}
	world.bootstrap = result
	first, err := sidecar.NewConfigHead(world.ref.files)
	if err != nil {
		t.Fatal(err)
	}
	chains, _ := world.ref.walk(1)
	world.heads = []*sidecar.ConfigHead{nil, first}
	world.chains = chains
	return world
}

// Saves the newest head with the files given set, a nil one removed, by device: the new version.
func (self *configHeadWorld) saveWith(device *epochDevice, files map[string][]byte) uint64 {
	self.t.Helper()
	head := self.heads[len(self.heads)-1]
	for path, data := range files {
		next, err := head.WithFile(path, data)
		if err != nil {
			self.t.Fatal(err)
		}
		head = next
	}
	version, chain := self.ref.save(device, head)
	if version != uint64(len(self.heads)) {
		self.t.Fatalf("a head saved at version %d, not %d", version, len(self.heads))
	}
	self.heads = append(self.heads, head)
	self.chains = append(self.chains, chain)
	return version
}

// A head reader over device's client.
func (self *configHeadWorld) reader(device *epochDevice) *sidecar.EvsConfigHeadReader {
	self.t.Helper()
	reader, err := sidecar.NewEvsConfigHeadReader(&sidecar.EvsConfigHeadReaderArgs{Repo: device.repo})
	if err != nil {
		self.t.Fatal(err)
	}
	return reader
}

// Reads version's head through reader and holds it to the head saved there.
func (self *configHeadWorld) requireHead(reader *sidecar.EvsConfigHeadReader, version uint64, when string) {
	self.t.Helper()
	head, err := reader.ReadConfigHead(self.ctx, version, self.chains[version][:])
	if err != nil {
		self.t.Fatalf("%s: the head at %d: %v", when, version, err)
	}
	if want, got := self.heads[version].Files(), head.Files(); !maps.EqualFunc(want, got, bytes.Equal) {
		self.t.Fatalf("%s: the head at %d holds %v, not %v", when, version, head.Paths(), self.heads[version].Paths())
	}
}

// device's pin of the main ref, version 0 for none.
func (self *configHeadWorld) pinVersion(device *epochDevice) uint64 {
	self.t.Helper()
	pin, pinned, err := device.client.Pins().Pin(self.repoId, self.mainRefId(device))
	if err != nil {
		self.t.Fatal(err)
	}
	if !pinned {
		return 0
	}
	return pin.Version
}

// A device of label whose evs verifier judges by config, the world's devices judging by the world's log.
func (self *configHeadWorld) deviceJudgingBy(label string, config func() sidecar.GkmAuthView) *epochDevice {
	self.t.Helper()
	return self.deviceThrough(label, config, nil)
}

// deviceJudgingBy's device, its requests through wrap around the world's transport, nil for none, and its key client
// advanced with the world's positions as every world device's is.
func (self *configHeadWorld) deviceThrough(label string, config func() sidecar.GkmAuthView, wrap func(next http.RoundTripper) http.RoundTripper) *epochDevice {
	self.t.Helper()
	signer := self.signers[label]
	device := &epochDevice{world: self.epochWorld, label: label, signer: signer, store: NewFakeStore().Root(), gkm: self.gkm.Client(signer.SidecarId, signer.Sign)}
	device.gkm.AuthAdvanced(self.currentView())
	identity := &sidecar.SidecarIdentity{NetworkId: self.networkId, SidecarId: signer.SidecarId, ClientId: self.clientId, Generation: 1, IdentityPublicKey: signer.PublicKey()}
	var transport http.RoundTripper = &epochTransport{world: self.epochWorld, device: device}
	if wrap != nil {
		transport = wrap(transport)
	}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: self.networkId,
		EvsUrl:    "https://evs.example",
		Transport: transport,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			connectSidecarId := connect.Id(signer.SidecarId)
			return self.host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(self.networkId), ClientId: connect.Id(self.clientId), SidecarId: &connectSidecarId,
				Audience: evsservice.EvsAudience, Scopes: scopes, IssuedAt: self.clock.Now(), ExpiresAt: self.clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:     sidecar.EvsSignFunction(signer.Sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      device.gkm,
		Store:    device.store,
		Config:   config,
		Clock:    &epochDeviceClock{clock: self.clock},
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	device.client = client
	device.repo = client.Repo(self.repoId)
	self.stateLock.Lock()
	self.devices = append(self.devices, device)
	self.stateLock.Unlock()
	return device
}

func TestEvsConfigHeadReaderReadsEachHeadAtItsVersion(t *testing.T) {
	world := newConfigHeadWorld(t)
	v := world.device("v", nil)
	// head 2 changes the policy, removes the share, which empties its directory, and adds two files
	world.saveWith(world.writer, map[string][]byte{
		sidecar.ConfigHeadPolicyPath: []byte(`{"acls": [{"action": "accept"}]}`),
		configHeadSharePath(0xa1):    nil,
		sidecar.ConfigHeadNamesPath:  []byte("names at 2"),
		configHeadSharePath(0xb2):    []byte("share b2"),
	})
	// head 3 is another writer's, and puts the removed share back
	world.saveWith(v, map[string][]byte{
		sidecar.ConfigHeadPolicyPath: []byte(`{"acls": []}`),
		configHeadSharePath(0xa1):    []byte("share a1 again"),
		sidecar.ConfigHeadNamesPath:  nil,
	})

	// a device that never read the ref reads each head at its version, the ref standing at 3 throughout
	follower := world.device("r", nil)
	reader := world.reader(follower)
	for version := uint64(1); version <= 3; version += 1 {
		world.requireHead(reader, version, "a follower in order")
		if pinned := world.pinVersion(follower); pinned != version {
			t.Fatalf("the follower's pin after head %d is at %d", version, pinned)
		}
	}
	// an older head again, kept or replayed from the first push
	world.requireHead(reader, 2, "the follower, back one")
	world.requireHead(reader, 1, "the follower, back two")
	world.requireHead(reader, 3, "the follower, forward again")

	// a device that starts at the newest head
	late := world.device("d", nil)
	world.requireHead(world.reader(late), 3, "a late device")
	if pinned := world.pinVersion(late); pinned != 3 {
		t.Fatalf("the late device's pin is at %d", pinned)
	}

	// a device restarted on its pin reads an older head on the pinned chain, and a newer one past it
	restarted := world.deviceOn("r", follower.store, nil)
	world.requireHead(world.reader(restarted), 2, "a restarted device below its pin")
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names at 4")})
	world.requireHead(world.reader(restarted), 4, "a restarted device past its pin")
	if pinned := world.pinVersion(restarted); pinned != 4 {
		t.Fatalf("the restarted device's pin is at %d", pinned)
	}
}

func TestEvsConfigHeadReaderRefusesAForgedHead(t *testing.T) {
	world := newConfigHeadWorld(t)
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names at 2")})
	device := world.device("r", nil)
	reader := world.reader(device)

	forged := sha256.Sum256([]byte("a head no writer pushed"))
	if _, err := reader.ReadConfigHead(world.ctx, 2, forged[:]); !errors.Is(err, sidecar.ErrConfigHeadMismatch) || errors.Is(err, sidecar.ErrConfigHeadUnavailable) {
		t.Fatalf("a forged chain value: %v", err)
	}
	if _, err := reader.ReadConfigHead(world.ctx, 2, forged[:5]); !errors.Is(err, sidecar.ErrConfigHeadMismatch) {
		t.Fatalf("a chain value of 5 bytes: %v", err)
	}
	// the push before the forged head's was a writer's, and nothing past it is pinned
	if pinned := world.pinVersion(device); pinned != 0 {
		t.Fatalf("a forged head pinned the ref at %d", pinned)
	}
	world.requireHead(reader, 2, "after the forged head")
}

func TestEvsConfigHeadReaderRefusesAHeadAtAnotherVersion(t *testing.T) {
	world := newConfigHeadWorld(t)
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names at 2")})
	device := world.device("r", nil)
	reader := world.reader(device)

	// head 1's chain value named at version 2, and head 2's at version 1, before and after this device pins
	for _, pass := range []string{"unpinned", "pinned"} {
		if _, err := reader.ReadConfigHead(world.ctx, 2, world.chains[1][:]); !errors.Is(err, sidecar.ErrConfigHeadMismatch) || errors.Is(err, sidecar.ErrConfigHeadUnavailable) {
			t.Fatalf("%s: head 1's chain value at version 2: %v", pass, err)
		}
		if _, err := reader.ReadConfigHead(world.ctx, 1, world.chains[2][:]); !errors.Is(err, sidecar.ErrConfigHeadMismatch) || errors.Is(err, sidecar.ErrConfigHeadUnavailable) {
			t.Fatalf("%s: head 2's chain value at version 1: %v", pass, err)
		}
		// a version evs does not serve yet withholds, as does the ref before its first push
		if _, err := reader.ReadConfigHead(world.ctx, 3, world.chains[2][:]); !errors.Is(err, sidecar.ErrConfigHeadUnavailable) {
			t.Fatalf("%s: a version past the ref's: %v", pass, err)
		}
		if _, err := reader.ReadConfigHead(world.ctx, 0, world.chains[0][:]); !errors.Is(err, sidecar.ErrConfigHeadUnavailable) {
			t.Fatalf("%s: config version 0: %v", pass, err)
		}
		world.requireHead(reader, 2, pass)
	}
	// the version comes once it is pushed
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: nil})
	world.requireHead(reader, 3, "once pushed")
}

func TestEvsConfigHeadReaderRefusesANonWritersPush(t *testing.T) {
	world := newConfigHeadWorld(t)
	// this device's log, position for position the world's, lets w alone write the config
	strictLog := NewFakeGkmAuthLog()
	fixture := world.currentView().fixture.clone()
	fixture.RepoWriters[world.repoId] = []sidecar.Id{world.signers["w"].SidecarId}
	strictView := strictLog.Append(fixture)
	if !bytes.Equal(strictView.Pin().GetChain(), world.currentView().Pin().GetChain()) {
		t.Fatal("the strict log is another chain than the world's")
	}
	device := world.deviceJudgingBy("r", func() sidecar.GkmAuthView { return strictView })
	reader := world.reader(device)

	// evs takes v's push, as its gate's state lets v write
	v := world.device("v", nil)
	world.saveWith(v, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names by v")})
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names by w, on v's")})

	for version := uint64(2); version <= 3; version += 1 {
		_, err := reader.ReadConfigHead(world.ctx, version, world.chains[version][:])
		if !errors.Is(err, sidecar.ErrConfigHeadMismatch) || errors.Is(err, sidecar.ErrConfigHeadUnavailable) || !errors.Is(err, sidecar.ErrEvsStatementRefused) {
			t.Fatalf("a head at %d on a non-writer's push: %v", version, err)
		}
	}
	if pinned := world.pinVersion(device); pinned != 0 {
		t.Fatalf("a non-writer's push pinned the ref at %d", pinned)
	}
	// the head before the push stands, and pins there
	world.requireHead(reader, 1, "before the non-writer's push")
	if pinned := world.pinVersion(device); pinned != 1 {
		t.Fatalf("the pin after head 1 is at %d", pinned)
	}
	if _, err := reader.ReadConfigHead(world.ctx, 3, world.chains[3][:]); !errors.Is(err, sidecar.ErrConfigHeadMismatch) {
		t.Fatalf("a head past a non-writer's push, from the pin: %v", err)
	}
	// a device of the world's own state reads through v's push
	world.requireHead(world.reader(world.device("d", nil)), 3, "a device whose state lets v write")
}

func TestEvsConfigHeadReaderWithholdsAPushItCannotJudge(t *testing.T) {
	world := newConfigHeadWorld(t)
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names at 2")})
	// a device that pinned head 1 while it could judge its push
	early := world.device("r", nil)
	world.requireHead(world.reader(early), 1, "an early device")

	// the log moves on, a head is saved at its new position, and every device's window moves past the position the
	// first two pushes pin
	world.advance([]string{"w", "v", "m", "r", "d"}, 0, nil)
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names at 3")})
	world.log.Retain(2)

	late := world.device("d", nil)
	if _, err := world.reader(late).ReadConfigHead(world.ctx, 2, world.chains[2][:]); !errors.Is(err, sidecar.ErrConfigHeadUnavailable) || errors.Is(err, sidecar.ErrConfigHeadMismatch) {
		t.Fatalf("a head on pushes a device cannot judge: %v", err)
	}
	if pinned := world.pinVersion(late); pinned != 0 {
		t.Fatalf("an unjudged push pinned the ref at %d", pinned)
	}
	// the early device's pin vouches for head 1, and it cannot judge the push after it either
	restarted := world.deviceOn("r", early.store, nil)
	world.requireHead(world.reader(restarted), 1, "the early device at its pin")
	if _, err := world.reader(restarted).ReadConfigHead(world.ctx, 2, world.chains[2][:]); !errors.Is(err, sidecar.ErrConfigHeadUnavailable) {
		t.Fatalf("a head past the pin on a push the device cannot judge: %v", err)
	}
	// head 3's own push pins a position the window holds, and the walk to it passes the unjudged one
	if _, err := world.reader(restarted).ReadConfigHead(world.ctx, 3, world.chains[3][:]); !errors.Is(err, sidecar.ErrConfigHeadUnavailable) {
		t.Fatalf("a head past an unjudged push: %v", err)
	}
}

func TestEvsConfigHeadReaderReadsAcrossAPathEpoch(t *testing.T) {
	world := newConfigHeadWorld(t)
	world.saveWith(world.writer, map[string][]byte{
		sidecar.ConfigHeadNamesPath: []byte("names in epoch 1"),
		configHeadSharePath(0xb2):   []byte("share b2 in epoch 1"),
	})
	before := world.device("r", nil)
	beforeReader := world.reader(before)
	world.requireHead(beforeReader, 2, "before the removal")

	// d leaves, a shrink: w's next write crosses it and records the due, and w's mapper cuts over to epoch 2
	world.advance([]string{"w", "v", "m", "r"}, 2, nil)
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names while due")})
	refId := world.mainRefId(world.writer)
	if err := world.writer.repo.TickMapper(world.ctx, refId); err != nil {
		t.Fatalf("w's mapper: %v", err)
	}
	if current := world.head(refId).GetPathEpoch().GetCurrent(); current != 2 {
		t.Fatalf("the epoch after the mapper: %v", world.head(refId).GetPathEpoch())
	}
	// the cut-over is a version of the ref that changes no path: the head there is the one before it
	cutOver := uint64(len(world.heads))
	chains, _ := world.ref.walk(cutOver)
	world.heads = append(world.heads, world.heads[cutOver-1])
	world.chains = append(world.chains, chains[cutOver])
	if result := world.copyInto(refId, 2); !result.SourcesDropped {
		t.Fatalf("the copy: %+v", result)
	}

	// a head in epoch 2: a file written again, one removed, and a new one in a directory epoch 1 named
	world.saveWith(world.writer, map[string][]byte{
		sidecar.ConfigHeadNamesPath: []byte("names in epoch 2"),
		configHeadSharePath(0xb2):   nil,
		configHeadSharePath(0xc3):   []byte("share c3 in epoch 2"),
	})
	newest := uint64(len(world.heads)) - 1

	// a device that replayed epoch 1 reads on across the cut-over, and a late one replays it whole
	world.requireHead(beforeReader, cutOver, "the cut-over's version")
	world.requireHead(beforeReader, newest, "a reader across the cut-over")
	late := world.reader(world.device("v", nil))
	world.requireHead(late, newest, "a late device across the cut-over")
	world.requireHead(late, 2, "a late device, back in epoch 1")
}

func TestConfigClientInstallsABaseThroughTheEvsConfigHeadReader(t *testing.T) {
	world := newConfigHeadWorld(t)
	device := world.device("r", nil)
	settings := sidecar.DefaultConfigClientSettings()
	settings.Log = sidecar.NewNoopLogger()
	settings.LogSettings = admissionLogSettings()
	client, err := sidecar.NewConfigClient(world.ctx, &sidecar.ConfigClientArgs{
		NetworkId:    world.networkId,
		GenesisChain: world.bootstrap.GenesisChain,
		Projection:   &FakeApiConfigReader{Api: world.api, NetworkId: world.networkId},
		Heads:        world.reader(device),
		Clock:        NewFakeClock(world.clock.Now()),
		Settings:     settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	state, err := client.WaitFor(world.ctx, world.bootstrap.Pin.GetVersion())
	if err != nil {
		t.Fatalf("the follower at base 1: %v", err)
	}
	base := state.Base()
	if base == nil || base.GetConfigVersion() != 1 || !bytes.Equal(base.GetConfigHeadSha256(), world.chains[1][:]) {
		t.Fatalf("the base installed: %v", base)
	}
	if pinned := world.pinVersion(device); pinned != 1 {
		t.Fatalf("the device's pin of the config ref after base 1 is at %d", pinned)
	}
}
