// The config repo's head reader over evs at an anchor (QD-814; DESIGN-DETAILS 5.2.4's StartAtBase), on the world of
// evs_config_head_world_test.go: w's ConfigWriter publishes bases on FakeApi folding the log into heads it saves on evs,
// and devices follow that log through ConfigClients whose head readers read the evs ref. A device that starts at a
// base judges the head the base names by descent under the base's own rows, which admit w alone, since the log's
// devices are the genesis owner's; evs's own log (FakeGkmAuthLog) lets w, v and m write, and a device's window over it
// moves alone through a mirror of it.
//
//	anchor    a new device whose evs verifier holds no state at all anchors at the newest base api retains from and
//	          stands there, then follows a base after it in order, judged in full
//	unadmitted a head holding a push by v, whom the base's rows never admitted, withholds the anchor, and the device
//	          stands nowhere; read under keys that admit v, the same head holds
//	broken    evs serving a log that skips a version, or holds a statement whose signature no longer verifies,
//	          withholds an anchor's head; a chain value no version holds is a mismatch, as in order
//	after     a device whose state lets w alone write takes v's past push at an anchor whose keys admit v, the gap the
//	          owner accepted, and refuses v's push after the anchor, judged in full at its pin
//	re-anchor a device following in order whose base names a head with a push before its window withholds that base,
//	          starts again at a later base once api's retention point passes its next position, and follows on from
//	          there in order

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// GET /network/config/projection on FakeApi from a retention point on, as api serves once that point passed the
// position asked (§7.9's retain row): a read from 0 still carries the genesis.
type configAnchorProjection struct {
	api       *FakeApi
	networkId sidecar.Id

	stateLock    sync.Mutex
	retainedFrom uint64
}

// Moves the retention point to n.
func (self *configAnchorProjection) retainFrom(n uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.retainedFrom = n
}

func (self *configAnchorProjection) ReadConfigProjection(ctx context.Context, after uint64) (*sidecar.ConfigProjection, error) {
	self.stateLock.Lock()
	retainedFrom := self.retainedFrom
	self.stateLock.Unlock()
	read, err := self.api.ReadProjection(ctx, self.networkId, max(after, retainedFrom-1), true)
	if err != nil {
		return nil, err
	}
	projection := &sidecar.ConfigProjection{Entries: read.Entries, Tip: read.Tip, More: read.More}
	for _, rows := range read.Rows {
		projection.Rows = append(projection.Rows, rows)
	}
	if after == 0 {
		genesis, err := self.api.ReadProjection(ctx, self.networkId, 0, false)
		if err != nil {
			return nil, err
		}
		projection.SignedGenesis = genesis.SignedGenesis
	}
	return projection, nil
}

// One device's view of the world's evs log, position for position the world's through a log of its own, so its window
// moves alone, each position's fixture changed by edit, nil for none. An edit that touches no row keeps every chain.
type configAnchorMirror struct {
	world *configHeadWorld
	edit  func(fixture *FakeGkmAuthFixture)

	stateLock sync.Mutex
	log       *FakeGkmAuthLog
	copied    int
}

func newConfigAnchorMirror(world *configHeadWorld, edit func(fixture *FakeGkmAuthFixture)) *configAnchorMirror {
	return &configAnchorMirror{world: world, edit: edit, log: NewFakeGkmAuthLog()}
}

// The mirror's newest position, the world's positions since the last view copied first: an evs Config.
func (self *configAnchorMirror) view() sidecar.GkmAuthView {
	self.world.log.stateLock.Lock()
	views := slices.Clone(self.world.log.views)
	self.world.log.stateLock.Unlock()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for ; self.copied < len(views); self.copied += 1 {
		fixture := views[self.copied].fixture.clone()
		if self.edit != nil {
			self.edit(fixture)
		}
		self.log.Append(fixture)
	}
	return self.log.Tip()
}

// Moves this device's window alone, to retain positions from n on.
func (self *configAnchorMirror) retain(n uint64) {
	self.log.Retain(n)
}

// A transport that hands each log page evs serves to alter first, as a lying evs serves it; nil alter serves it as is.
type configAnchorLogTransport struct {
	next http.RoundTripper

	stateLock sync.Mutex
	alter     func(reply *protocol.EvsLogReply)
}

// Sets the alteration, nil to serve the log as evs holds it.
func (self *configAnchorLogTransport) setAlter(alter func(reply *protocol.EvsLogReply)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.alter = alter
}

func (self *configAnchorLogTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := self.next.RoundTrip(request)
	self.stateLock.Lock()
	alter := self.alter
	self.stateLock.Unlock()
	if err != nil || alter == nil || response.StatusCode != http.StatusOK || !strings.HasSuffix(request.URL.Path, "/log") {
		return response, err
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	reply := &protocol.EvsLogReply{}
	if err := proto.Unmarshal(body, reply); err != nil {
		return nil, err
	}
	alter(reply)
	altered, err := proto.Marshal(reply)
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(altered))
	response.ContentLength = int64(len(altered))
	response.Header.Del("Content-Length")
	return response, nil
}

// An anchor over the world's genesis that admits the keys view does: a reader-level stand-in for a base's rows.
type configAnchorKeys struct {
	genesis *bridge.Genesis
	view    sidecar.GkmAuthView
}

func (self *configAnchorKeys) Genesis() *bridge.Genesis {
	return self.genesis
}

func (self *configAnchorKeys) IdentityKey(sidecarId sidecar.Id) []byte {
	return self.view.IdentityKey(sidecarId)
}

// An anchor of the world's network, its genesis the one BootstrapNetwork signed, admitting every key view admits.
func (self *configHeadWorld) anchorAdmitting(view sidecar.GkmAuthView) *configAnchorKeys {
	self.t.Helper()
	signed := &bridge.Signed{}
	genesis := &bridge.Genesis{}
	if err := proto.Unmarshal(self.bootstrap.SignedGenesis, signed); err != nil {
		self.t.Fatal(err)
	}
	if err := proto.Unmarshal(signed.GetBody(), genesis); err != nil {
		self.t.Fatal(err)
	}
	return &configAnchorKeys{genesis: genesis, view: view}
}

// The config head world with w's follower and config writer, which publish bases on FakeApi after BootstrapNetwork's
// base 1.
type configAnchorWorld struct {
	*configHeadWorld
	writerClient *sidecar.ConfigClient
	configWriter *sidecar.ConfigWriter
}

func newConfigAnchorWorld(t *testing.T) *configAnchorWorld {
	t.Helper()
	world := &configAnchorWorld{configHeadWorld: newConfigHeadWorld(t)}
	world.writerClient = world.follower(&FakeApiConfigReader{Api: world.api, NetworkId: world.networkId}, world.reader(world.writer))
	if _, err := world.writerClient.WaitFor(world.ctx, world.bootstrap.Pin.GetVersion()); err != nil {
		t.Fatalf("the writer at base 1: %v", err)
	}
	settings := sidecar.DefaultConfigWriterSettings()
	settings.Clock = NewFakeClock(world.clock.Now())
	settings.Random = func() float64 { return 0 }
	settings.Log = sidecar.NewNoopLogger()
	signer := world.signers["w"]
	configWriter, err := sidecar.NewConfigWriter(world.ctx, &sidecar.ConfigWriterArgs{
		SidecarId: signer.SidecarId,
		Sign: func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
			return signer.Sign(purpose, signedType, body, nil)
		},
		Client:    world.writerClient,
		Heads:     world.ref,
		Publisher: &FakeApiConfigPublisher{Api: world.api, NetworkId: world.networkId},
		Settings:  settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(configWriter.Close)
	world.configWriter = configWriter
	return world
}

// A ConfigClient on the world's network, reading the log through projection and its bases' heads through heads.
func (self *configHeadWorld) follower(projection sidecar.ConfigProjectionReader, heads sidecar.ConfigHeadReader) *sidecar.ConfigClient {
	self.t.Helper()
	settings := sidecar.DefaultConfigClientSettings()
	settings.Log = sidecar.NewNoopLogger()
	settings.LogSettings = admissionLogSettings()
	client, err := sidecar.NewConfigClient(self.ctx, &sidecar.ConfigClientArgs{
		NetworkId:    self.networkId,
		GenesisChain: self.bootstrap.GenesisChain,
		Projection:   projection,
		Heads:        heads,
		Clock:        NewFakeClock(self.clock.Now()),
		Settings:     settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	return client
}

// api's log from n on.
func (self *configHeadWorld) projectionFrom(n uint64) *configAnchorProjection {
	return &configAnchorProjection{api: self.api, networkId: self.networkId, retainedFrom: n}
}

// Notes the head the config writer saved, if it saved one, as saveWith notes its own.
func (self *configAnchorWorld) noteWriterHead() {
	self.t.Helper()
	head, version, chain, err := self.ref.CurrentConfigHead(self.ctx)
	if err != nil {
		self.t.Fatal(err)
	}
	if version == uint64(len(self.heads)) {
		self.heads = append(self.heads, head)
		self.chains = append(self.chains, chain)
	}
}

// A base by w folding through the tip, its head the ref's newest with the fold: the base as w's follower stands on it.
func (self *configAnchorWorld) fold() *bridge.ProjectionHeader {
	self.t.Helper()
	if _, err := self.configWriter.PublishBase(self.ctx, true); err != nil {
		self.t.Fatalf("a folding base: %v", err)
	}
	self.noteWriterHead()
	return self.writerClient.State().Base()
}

// A base by w over a head with the names file set, the fold where it is: the base as w's follower stands on it.
func (self *configAnchorWorld) saveNames(names string) *bridge.ProjectionHeader {
	self.t.Helper()
	_, err := self.configWriter.SaveHead(self.ctx, func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadNamesPath, []byte(names))
	})
	if err != nil {
		self.t.Fatalf("a base over a saved head: %v", err)
	}
	self.noteWriterHead()
	return self.writerClient.State().Base()
}

// One follow of client now, bounded.
func (self *configHeadWorld) catchUp(client *sidecar.ConfigClient) error {
	ctx, cancel := context.WithTimeout(self.ctx, 30*time.Second)
	defer cancel()
	return client.CatchUp(ctx)
}

// Holds client's state to standing on base.
func (self *configHeadWorld) requireBase(client *sidecar.ConfigClient, base *bridge.ProjectionHeader, when string) {
	self.t.Helper()
	state := client.State()
	if state == nil {
		self.t.Fatalf("%s: no state", when)
	}
	if !proto.Equal(state.Base(), base) {
		self.t.Fatalf("%s: the device stands on base %d at config version %d, not base %d at %d", when,
			state.Base().GetVersion(), state.Base().GetConfigVersion(), base.GetVersion(), base.GetConfigVersion())
	}
}

func TestConfigClientAnchorsANewDeviceAtABaseOverEvs(t *testing.T) {
	world := newConfigAnchorWorld(t)
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names at 2")})
	world.fold()
	// base 3 folds through base 2, which api retains from
	anchor := world.fold()
	if anchor.GetVersion() != 3 || anchor.GetFoldedThrough() != 2 {
		t.Fatalf("the newest base is %d folding through %d", anchor.GetVersion(), anchor.GetFoldedThrough())
	}

	// a new device: until its follower stands it installs no state, so its evs verifier judges by none
	var standing atomic.Bool
	device := world.deviceThrough("d", func() sidecar.GkmAuthView {
		if !standing.Load() {
			return nil
		}
		return world.currentView()
	}, nil)
	reader := world.reader(device)
	// judged at each push's own pin, the head is unjudged, as before the anchor's rule
	if _, err := world.reader(device).ReadConfigHead(world.ctx, anchor.GetConfigVersion(), anchor.GetConfigHeadSha256()); !errors.Is(err, sidecar.ErrConfigHeadUnavailable) || !errors.Is(err, sidecar.ErrEvsNoConfig) {
		t.Fatalf("the anchor's head judged at its pushes' pins: %v", err)
	}
	client := world.follower(world.projectionFrom(2), reader)
	if err := world.catchUp(client); err != nil {
		t.Fatalf("the anchor: %v", err)
	}
	world.requireBase(client, anchor, "at the anchor")
	if pinned := world.pinVersion(device); pinned != anchor.GetConfigVersion() {
		t.Fatalf("the device's pin of the config ref after the anchor is at %d, not %d", pinned, anchor.GetConfigVersion())
	}
	world.requireHead(reader, anchor.GetConfigVersion(), "the anchor's head")

	// standing, the device follows a base after the anchor in order, its head's new push judged at its own pin
	standing.Store(true)
	next := world.saveNames("names after the anchor")
	if err := world.catchUp(client); err != nil {
		t.Fatalf("the base after the anchor: %v", err)
	}
	world.requireBase(client, next, "after the anchor")
	if pinned := world.pinVersion(device); pinned != next.GetConfigVersion() {
		t.Fatalf("the device's pin after the next base is at %d, not %d", pinned, next.GetConfigVersion())
	}
}

func TestConfigClientWithholdsAnAnchorOverASignerItsBaseDoesNotAdmit(t *testing.T) {
	world := newConfigAnchorWorld(t)
	// evs takes v's push, as its own log lets v write; the network's log never admitted v
	world.saveWith(world.device("v", nil), map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names by v")})
	world.fold()
	anchor := world.fold()

	device := world.deviceThrough("d", func() sidecar.GkmAuthView { return nil }, nil)
	reader := world.reader(device)
	client := world.follower(world.projectionFrom(2), reader)
	if err := world.catchUp(client); !errors.Is(err, sidecar.ErrConfigHeadUnavailable) || errors.Is(err, sidecar.ErrConfigFork) {
		t.Fatalf("an anchor over a push by a signer its base does not admit: %v", err)
	}
	if client.State() != nil {
		t.Fatal("a withheld anchor installed a state")
	}
	if pinned := world.pinVersion(device); pinned != 0 {
		t.Fatalf("a withheld anchor pinned the config ref at %d", pinned)
	}
	// the writer, whose evs log lets v write at its push's pin, stands on the same base
	world.requireBase(world.writerClient, anchor, "the writer")
	// the head itself is sound: under keys that admit v it holds
	if _, err := reader.ReadConfigHeadAtAnchor(world.ctx, anchor.GetConfigVersion(), anchor.GetConfigHeadSha256(), world.anchorAdmitting(world.currentView())); err != nil {
		t.Fatalf("the head under keys that admit v: %v", err)
	}
}

func TestEvsConfigHeadReaderWithholdsAnAnchorOnABrokenChain(t *testing.T) {
	world := newConfigHeadWorld(t)
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names at 2")})
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names at 3")})
	transport := &configAnchorLogTransport{}
	device := world.deviceThrough("d", func() sidecar.GkmAuthView { return nil }, func(next http.RoundTripper) http.RoundTripper {
		transport.next = next
		return transport
	})
	reader := world.reader(device)
	anchor := world.anchorAdmitting(world.currentView())

	breaks := []struct {
		name  string
		alter func(reply *protocol.EvsLogReply)
	}{
		{name: "a version skipped", alter: func(reply *protocol.EvsLogReply) {
			reply.Statements = slices.DeleteFunc(reply.Statements, func(statement *protocol.EvsReadStatement) bool {
				return statement.GetVersion() == 2
			})
		}},
		{name: "a signature that no longer verifies", alter: func(reply *protocol.EvsLogReply) {
			for _, statement := range reply.Statements {
				if statement.GetVersion() != 2 {
					continue
				}
				signed := &bridge.Signed{}
				if err := proto.Unmarshal(statement.GetStatement(), signed); err != nil {
					t.Errorf("a statement: %v", err)
					return
				}
				signed.Signature[0] ^= 1
				statementBytes, err := proto.Marshal(signed)
				if err != nil {
					t.Errorf("a statement: %v", err)
					return
				}
				statement.Statement = statementBytes
			}
		}},
	}
	for _, broken := range breaks {
		transport.setAlter(broken.alter)
		_, err := reader.ReadConfigHeadAtAnchor(world.ctx, 3, world.chains[3][:], anchor)
		if !errors.Is(err, sidecar.ErrConfigHeadUnavailable) || errors.Is(err, sidecar.ErrConfigHeadMismatch) {
			t.Fatalf("%s: %v", broken.name, err)
		}
		if pinned := world.pinVersion(device); pinned != 0 {
			t.Fatalf("%s: the broken chain pinned the config ref at %d", broken.name, pinned)
		}
	}

	// an anchor whose genesis names another config repo reads nothing of this one
	transport.setAlter(nil)
	elsewhere := &configAnchorKeys{genesis: &bridge.Genesis{ConfigRepoId: sidecar.NewId().Bytes()}, view: anchor.view}
	if _, err := reader.ReadConfigHeadAtAnchor(world.ctx, 3, world.chains[3][:], elsewhere); !errors.Is(err, sidecar.ErrConfigHeadUnavailable) {
		t.Fatalf("an anchor of another config repo: %v", err)
	}
	// a chain value no version holds is the base's, a mismatch at an anchor as in order
	forged := world.chains[2]
	forged[0] ^= 1
	if _, err := reader.ReadConfigHeadAtAnchor(world.ctx, 2, forged[:], anchor); !errors.Is(err, sidecar.ErrConfigHeadMismatch) {
		t.Fatalf("a forged chain value at an anchor: %v", err)
	}
	// evs serving the log as it holds it, the anchor holds
	head, err := reader.ReadConfigHeadAtAnchor(world.ctx, 3, world.chains[3][:], anchor)
	if err != nil {
		t.Fatalf("the honest log: %v", err)
	}
	if names := head.Files()[sidecar.ConfigHeadNamesPath]; string(names) != "names at 3" {
		t.Fatalf("the anchor's head holds names %q", names)
	}
	if pinned := world.pinVersion(device); pinned != 3 {
		t.Fatalf("the anchor pinned the config ref at %d", pinned)
	}
}

func TestEvsConfigHeadReaderJudgesPushesAfterTheAnchorInFull(t *testing.T) {
	world := newConfigHeadWorld(t)
	// this device's evs log, position for position the world's, lets w alone write the config
	strict := newConfigAnchorMirror(world, func(fixture *FakeGkmAuthFixture) {
		fixture.RepoWriters[world.repoId] = []sidecar.Id{world.signers["w"].SidecarId}
	})
	device := world.deviceThrough("r", strict.view, nil)
	reader := world.reader(device)
	v := world.device("v", nil)
	world.saveWith(v, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names by v")})
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names by w, on v's")})

	// in order, v's push is judged at its pin, where v writes nothing
	if _, err := reader.ReadConfigHead(world.ctx, 3, world.chains[3][:]); !errors.Is(err, sidecar.ErrConfigHeadMismatch) || !errors.Is(err, sidecar.ErrEvsStatementRefused) {
		t.Fatalf("v's push in order: %v", err)
	}
	// at an anchor whose rows admit v, the writer role at the push's own pin goes unjudged: the gap QD-814 accepts
	world.requireAnchorHead(reader, 3, world.anchorAdmitting(world.currentView()), "an anchor over v's past push")
	if pinned := world.pinVersion(device); pinned != 3 {
		t.Fatalf("the anchor pinned the config ref at %d", pinned)
	}

	// a push after the anchor by a sidecar that writes nothing at its pin is refused, judged in full
	world.saveWith(v, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names by v after the anchor")})
	if _, err := reader.ReadConfigHead(world.ctx, 4, world.chains[4][:]); !errors.Is(err, sidecar.ErrConfigHeadMismatch) || !errors.Is(err, sidecar.ErrEvsStatementRefused) {
		t.Fatalf("a non-writer's push after the anchor: %v", err)
	}
	// and a writer's push on it rests on it
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names by w, on v's after the anchor")})
	if _, err := reader.ReadConfigHead(world.ctx, 5, world.chains[5][:]); !errors.Is(err, sidecar.ErrConfigHeadMismatch) {
		t.Fatalf("a writer's push on a refused one after the anchor: %v", err)
	}
	if pinned := world.pinVersion(device); pinned != 3 {
		t.Fatalf("a refused push pinned the config ref at %d", pinned)
	}
	world.requireHead(reader, 3, "the anchor's head after the refusals")
}

// Reads version's head through reader at an anchor and holds it to the head saved there.
func (self *configHeadWorld) requireAnchorHead(reader *sidecar.EvsConfigHeadReader, version uint64, anchor sidecar.ConfigHeadAnchor, when string) {
	self.t.Helper()
	head, err := reader.ReadConfigHeadAtAnchor(self.ctx, version, self.chains[version][:], anchor)
	if err != nil {
		self.t.Fatalf("%s: the head at %d: %v", when, version, err)
	}
	if want, got := self.heads[version].Files(), head.Files(); !maps.EqualFunc(want, got, bytes.Equal) {
		self.t.Fatalf("%s: the head at %d holds %v, not %v", when, version, head.Paths(), self.heads[version].Paths())
	}
}

func TestConfigClientReanchorsADeviceWhoseHeadPredatesItsWindow(t *testing.T) {
	world := newConfigAnchorWorld(t)
	mirror := newConfigAnchorMirror(world.configHeadWorld, nil)
	device := world.deviceThrough("r", mirror.view, nil)
	projection := world.projectionFrom(1)
	client := world.follower(projection, world.reader(device))
	if err := world.catchUp(client); err != nil {
		t.Fatalf("base 1: %v", err)
	}
	if base := client.State().Base(); base.GetVersion() != 1 {
		t.Fatalf("the device stands on base %d", base.GetVersion())
	}

	// a push at evs's first position, then evs's log moves on and this device's window with it, past that position:
	// the next base names a head on that push, which a device following in order can no longer judge
	world.saveWith(world.writer, map[string][]byte{sidecar.ConfigHeadNamesPath: []byte("names at evs's first position")})
	world.advance([]string{"w", "v", "m", "r", "d"}, 0, nil)
	mirror.retain(2)
	withheld := world.fold()
	if err := world.catchUp(client); !errors.Is(err, sidecar.ErrConfigHeadUnavailable) || !errors.Is(err, sidecar.ErrGkmAuthNotRetained) {
		t.Fatalf("a base on a push before the window: %v", err)
	}
	if base := client.State().Base(); base.GetVersion() != 1 {
		t.Fatalf("a withheld base %d moved the device to base %d", withheld.GetVersion(), base.GetVersion())
	}

	// api's retention point passes the device's next position: it starts again at the newest base, its anchor, held to
	// the pin it stood at
	world.fold()
	anchor := world.fold()
	projection.retainFrom(withheld.GetVersion() + 1)
	if err := world.catchUp(client); err != nil {
		t.Fatalf("the re-anchor: %v", err)
	}
	world.requireBase(client, anchor, "at the re-anchor")
	if pinned := world.pinVersion(device); pinned != anchor.GetConfigVersion() {
		t.Fatalf("the device's pin of the config ref after the re-anchor is at %d, not %d", pinned, anchor.GetConfigVersion())
	}

	// and holds: a base after it follows in order, its head's new push judged in full at its pin inside the window
	next := world.saveNames("names after the re-anchor")
	if err := world.catchUp(client); err != nil {
		t.Fatalf("the base after the re-anchor: %v", err)
	}
	world.requireBase(client, next, "after the re-anchor")
	if pinned := world.pinVersion(device); pinned != next.GetConfigVersion() {
		t.Fatalf("the device's pin after the next base is at %d, not %d", pinned, next.GetConfigVersion())
	}
}
