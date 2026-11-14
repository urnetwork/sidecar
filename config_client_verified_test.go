// QD-804's state for a head reader's verifier (ConfigClient.VerifiedState): a client starting from the genesis builds
// its log before it publishes it, so State answers nothing while the first page applies, and VerifiedState answers the
// state each base of that page lands on, which evs's verifier judges the base's pushes at; a start a withheld base
// stops leaves nothing behind; and with no head reader every base is withheld from the start.

package sidecar

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A head reader that records, at each read, the pins its client answers through State and VerifiedState, and then
// reads through next, or withholds every head when next is nil.
type testVerifiedStateHeads struct {
	next ConfigHeadReader
	// the client, once NewConfigClient answers it: a read waits for it
	client chan *ConfigClient

	stateLock sync.Mutex
	reads     []testVerifiedStateRead
}

// One read: the version asked, and the pins State and VerifiedState answered then, nil for none.
type testVerifiedStateRead struct {
	configVersion uint64
	published     *bridge.AuthPin
	verified      *bridge.AuthPin
}

func newTestVerifiedStateHeads(next ConfigHeadReader) *testVerifiedStateHeads {
	return &testVerifiedStateHeads{next: next, client: make(chan *ConfigClient, 1)}
}

func (self *testVerifiedStateHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
	var client *ConfigClient
	select {
	case client = <-self.client:
		self.client <- client
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	read := testVerifiedStateRead{configVersion: configVersion}
	if state := client.State(); state != nil {
		read.published = state.Pin()
	}
	if state := client.VerifiedState(); state != nil {
		read.verified = state.Pin()
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.reads = append(self.reads, read)
	}()
	if self.next == nil {
		return nil, ErrConfigHeadUnavailable
	}
	return self.next.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

// The reads so far.
func (self *testVerifiedStateHeads) seen() []testVerifiedStateRead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]testVerifiedStateRead{}, self.reads...)
}

// A client on the world reading heads through heads, which it is handed to once made, closed at the test's end.
func (self *testConfigClientWorld) clientReading(heads ConfigHeadReader) *ConfigClient {
	self.t.Helper()
	settings := DefaultConfigClientSettings()
	settings.LogSettings = testConfigLogSettings()
	settings.Log = NewNoopLogger()
	client, err := NewConfigClient(context.Background(), &ConfigClientArgs{
		NetworkId:    self.net.networkId,
		GenesisChain: bridge.GenesisChain(self.net.signedGenesis),
		Projection:   self.projection,
		Heads:        heads,
		Store:        self.store,
		Gkm:          self.gkm,
		Clock:        self.clock,
		Settings:     settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	if probed, ok := heads.(*testVerifiedStateHeads); ok {
		probed.client <- client
	}
	return client
}

// A start whose first page holds base 1 and a later base reads each base's head at the state it lands on, S(0) and
// S(n-1), through VerifiedState, while State answers nothing; once the page is published both answer the newest.
func TestConfigClientVerifiedStateDuringAStart(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	net.consentedMember("m")
	foldedThrough := net.n
	net.fold(net.owner, foldedThrough, 2)
	world.publish()
	heads := newTestVerifiedStateHeads(world.heads)
	client := world.clientReading(heads)
	state := world.caughtUp(client)

	reads := heads.seen()
	if len(reads) != 2 {
		t.Fatalf("%d heads read, not 2: %+v", len(reads), reads)
	}
	for i, wantVersion := range []uint64{0, foldedThrough} {
		read := reads[i]
		if read.published != nil {
			t.Errorf("base %d's head was read with a published state at %d", i+1, read.published.GetVersion())
		}
		if read.verified == nil || read.verified.GetVersion() != wantVersion {
			t.Errorf("base %d's head was read at %v, not at %d", i+1, read.verified, wantVersion)
		}
	}
	if verified := client.VerifiedState(); verified == nil || verified.Pin().GetVersion() != state.Pin().GetVersion() {
		t.Fatalf("once published the client verifies %v, its state %d", verified, state.Pin().GetVersion())
	}
}

// A start whose base 1 is withheld is dropped whole: after the follow that read it, neither State nor VerifiedState
// answers anything, though the read itself saw the start's S(0).
func TestConfigClientVerifiedStateDropsAWithheldStart(t *testing.T) {
	world := newTestConfigClientWorld(t)
	world.publish()
	heads := newTestVerifiedStateHeads(nil)
	client := world.clientReading(heads)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// a follow of its own, after the client's first one, which holds the follow's lock while it runs
	if err := client.CatchUp(ctx); !errors.Is(err, ErrConfigHeadUnavailable) {
		t.Fatalf("a follow over a withheld base 1: %v", err)
	}
	reads := heads.seen()
	if len(reads) == 0 {
		t.Fatal("base 1's head was never read")
	}
	for _, read := range reads {
		if read.published != nil || read.verified == nil || read.verified.GetVersion() != 0 {
			t.Fatalf("base 1's head was read at %v, published %v", read.verified, read.published)
		}
	}
	if client.State() != nil || client.VerifiedState() != nil {
		t.Fatal("a withheld start left a state behind")
	}
}

// With no head reader, a start withholds base 1 and leaves nothing behind (QD-804: a daemon that gives its follower no
// reader judges nothing past the genesis).
func TestConfigClientWithNoHeadReaderWithholdsBaseOne(t *testing.T) {
	world := newTestConfigClientWorld(t)
	world.publish()
	client := world.clientReading(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.CatchUp(ctx); !errors.Is(err, ErrConfigHeadUnavailable) {
		t.Fatalf("a follow with no head reader: %v", err)
	}
	if client.State() != nil || client.VerifiedState() != nil {
		t.Fatal("a client with no head reader holds a state")
	}
}
