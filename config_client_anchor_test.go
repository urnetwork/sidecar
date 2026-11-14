// QD-814's anchor at a ConfigClient's start, on the test network: the head the base a new device starts at names is
// read through ConfigHeadAnchorReader under that base's own rows, the state they give before the base's tail
// re-applies, and every base after it through ReadConfigHead, judged in full; an anchor read that withholds leaves no
// state. The judgment itself, over evs, is sidecartest's (evs_config_anchor_world_test.go).

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One anchor read as a testConfigAnchorHeads saw it: its config version, and what the anchor admitted for each probed
// sidecar at the time of the read, since the state behind it moves on once the base's tail re-applies.
type testConfigAnchorRead struct {
	configVersion uint64
	identityKeys  map[Id][]byte
}

// A head reader that also reads anchors, answering from testConfigHeadReader's heads and noting every read.
type testConfigAnchorHeads struct {
	heads *testConfigHeadReader
	// the sidecars whose admission each anchor read records
	probes []Id

	stateLock    sync.Mutex
	anchorReads  []testConfigAnchorRead
	readVersions []uint64
	// the answer to every anchor read while set
	refuse error
}

var _ ConfigHeadAnchorReader = (*testConfigAnchorHeads)(nil)

func (self *testConfigAnchorHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.readVersions = append(self.readVersions, configVersion)
	}()
	return self.heads.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

func (self *testConfigAnchorHeads) ReadConfigHeadAtAnchor(ctx context.Context, configVersion uint64, configHeadSha256 []byte, anchor ConfigHeadAnchor) (*ConfigHead, error) {
	read := testConfigAnchorRead{configVersion: configVersion, identityKeys: map[Id][]byte{}}
	for _, sidecarId := range self.probes {
		read.identityKeys[sidecarId] = bytes.Clone(anchor.IdentityKey(sidecarId))
	}
	refuse := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.anchorReads = append(self.anchorReads, read)
		return self.refuse
	}()
	if refuse != nil {
		return nil, refuse
	}
	return self.heads.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

// The reads so far: the anchor reads, and the config versions read in full.
func (self *testConfigAnchorHeads) reads() ([]testConfigAnchorRead, []uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]testConfigAnchorRead(nil), self.anchorReads...), append([]uint64(nil), self.readVersions...)
}

// A device's identity key as a state admits it.
func testConfigIdentityKey(device testConfigDevice) []byte {
	return []byte(device.key.Public().(ed25519.PublicKey))
}

func TestConfigClientReadsAnAnchorsHeadUnderItsBaseRows(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	member, first := net.consentedMember("m")
	net.fold(net.owner, net.n, 2)
	foldPoint := net.n
	// admitted in the tail of the base a new device starts at, so in the state that base gives and not in its rows
	second := net.device("m second", member)
	net.admitDevice(first, second, 0)
	net.fold(net.owner, foldPoint, 3)
	world.publish()
	world.projection.stateLock.Lock()
	world.projection.retainedFrom = net.log.State().RetentionPoint()
	world.projection.stateLock.Unlock()
	if world.projection.retainedFrom <= 1 {
		t.Fatalf("api retains from %d", world.projection.retainedFrom)
	}
	stranger := net.device("stranger", member)

	heads := &testConfigAnchorHeads{heads: world.heads, probes: []Id{net.owner.sidecarId, first.sidecarId, second.sidecarId, stranger.sidecarId}}
	heads.refuse = fmt.Errorf("%w: the anchor's pushes", ErrConfigHeadUnavailable)
	settings := DefaultConfigClientSettings()
	settings.LogSettings = testConfigLogSettings()
	settings.Log = NewNoopLogger()
	client, err := NewConfigClient(context.Background(), &ConfigClientArgs{
		NetworkId:    net.networkId,
		GenesisChain: bridge.GenesisChain(net.signedGenesis),
		Projection:   world.projection,
		Heads:        heads,
		Clock:        world.clock,
		Settings:     settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	// an anchor read that withholds leaves the device with no state, and nothing was read in full
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.CatchUp(ctx); !errors.Is(err, ErrConfigHeadUnavailable) {
		t.Fatalf("a withheld anchor: %v", err)
	}
	if client.State() != nil {
		t.Fatal("a withheld anchor installed a state")
	}
	anchorReads, readVersions := heads.reads()
	if len(anchorReads) == 0 || len(readVersions) != 0 {
		t.Fatalf("a start read %d anchors and %v in full", len(anchorReads), readVersions)
	}

	// answered, the anchor holds at the newest base, its head read once more at the anchor and never in full
	heads.stateLock.Lock()
	heads.refuse = nil
	heads.stateLock.Unlock()
	state := world.caughtUp(client)
	testConfigStatesEqual(t, state, net.log.State())
	anchorReads, readVersions = heads.reads()
	if len(readVersions) != 0 {
		t.Fatalf("the anchor's head read in full at %v", readVersions)
	}
	for _, read := range anchorReads {
		if read.configVersion != 3 {
			t.Fatalf("an anchor read at config version %d, not the newest base's 3", read.configVersion)
		}
	}
	// the anchor admits what the base's own rows do: the owner's and the first device's keys, and neither the device
	// the tail admits nor one never admitted
	read := anchorReads[len(anchorReads)-1]
	if !bytes.Equal(read.identityKeys[net.owner.sidecarId], testConfigIdentityKey(net.owner)) ||
		!bytes.Equal(read.identityKeys[first.sidecarId], testConfigIdentityKey(first)) {
		t.Fatal("the anchor does not admit the keys the base's rows hold")
	}
	if read.identityKeys[second.sidecarId] != nil || read.identityKeys[stranger.sidecarId] != nil {
		t.Fatal("the anchor admits a key the base's rows do not hold")
	}
	if state.SidecarRow(second.sidecarId) == nil {
		t.Fatal("the tail's admission did not re-apply after the anchor")
	}

	// a base after the anchor is read in full, never at an anchor
	net.fold(net.owner, net.n, 4)
	world.publish()
	client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
	testConfigStatesEqual(t, world.caughtUp(client), net.log.State())
	afterReads, readVersions := heads.reads()
	if len(afterReads) != len(anchorReads) || len(readVersions) != 1 || readVersions[0] != 4 {
		t.Fatalf("after the anchor: %d anchor reads, %v in full", len(afterReads)-len(anchorReads), readVersions)
	}
}

func TestConfigHeadCheckReadsAtAnAnchorOnlyWithoutAPreviousState(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	net.fold(net.owner, net.n, 2)
	world.publish()
	heads := &testConfigAnchorHeads{heads: world.heads}
	state := net.log.State()
	header := state.Base()
	checks := []struct {
		check  *ConfigHeadCheck
		anchor bool
	}{
		{check: &ConfigHeadCheck{Header: header, Anchor: state}, anchor: true},
		// a reader standing at the state the base lands on judges every push at its own pin
		{check: &ConfigHeadCheck{Header: header, Previous: state, Anchor: state}, anchor: false},
		// an anchor with no rows to judge by is ReadConfigHead's, which withholds one over evs
		{check: &ConfigHeadCheck{Header: header}, anchor: false},
	}
	for i, c := range checks {
		before, beforeVersions := heads.reads()
		if _, err := readConfigHeadForCheck(context.Background(), heads, c.check); err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
		after, afterVersions := heads.reads()
		anchored, inFull := len(after)-len(before), len(afterVersions)-len(beforeVersions)
		if c.anchor && (anchored != 1 || inFull != 0) || !c.anchor && (anchored != 0 || inFull != 1) {
			t.Errorf("check %d: %d anchor reads and %d in full", i, anchored, inFull)
		}
	}
	// a head reader that reads no anchors is asked as it always was
	if _, err := readConfigHeadForCheck(context.Background(), world.heads, checks[0].check); err != nil {
		t.Fatalf("a reader of heads alone at an anchor: %v", err)
	}
}
