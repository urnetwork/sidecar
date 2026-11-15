//go:build !ios_extension && !sidecar_http && !js

// QD-817's join at the follower, on sidecartest's Net (sidecar_config_follower_test.go's world): a hosted Sidecar whose
// key client holds no generation of its network's config repo, every member device but the network's first, follows
// its log rows-only past base 1, its key client handed those states unconfirmed and no verified one, the follower
// catching up and saying it joins, nothing admitted and nothing for evs to judge by; once the key client takes its
// Welcome the full re-read judges every head and the follower stands, admitted, the key client hearing verified states
// from then on. The key client and the head reader over evs are fakes sharing whether the keychain holds the key.

package sidecar_test

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A key client as a joining device's follower meets it: whether its keychain holds the config key, the channel the next
// key taken closes, the unconfirmed states the follower's client hands it, and the verified ones it is handed once the
// follower stands. Every other call refuses, as a key client with no verified state does.
type configJoinTestKeys struct {
	stateLock     sync.Mutex
	held          bool
	changed       chan struct{}
	unconfirmed   []uint64
	configRepoIds []sidecar.Id
	advanced      []uint64
	// the newest unconfirmed version handed over
	handed *sidecar.MonitorValue[uint64]
}

var (
	_ sidecar.GkmClient       = (*configJoinTestKeys)(nil)
	_ sidecar.GkmConfigJoiner = (*configJoinTestKeys)(nil)
)

func newConfigJoinTestKeys() *configJoinTestKeys {
	return &configJoinTestKeys{changed: make(chan struct{}), handed: sidecar.NewMonitorValue[uint64](0)}
}

func (self *configJoinTestKeys) RepoKeyHeld(repoId sidecar.Id) (bool, <-chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.held, self.changed
}

func (self *configJoinTestKeys) AuthUnconfirmed(state sidecar.GkmAuthView, configRepoId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.unconfirmed = append(self.unconfirmed, state.Pin().GetVersion())
	self.configRepoIds = append(self.configRepoIds, configRepoId)
	self.handed.Set(state.Pin().GetVersion())
}

func (self *configJoinTestKeys) AuthAdvanced(state sidecar.GkmAuthView) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.advanced = append(self.advanced, state.Pin().GetVersion())
}

func (self *configJoinTestKeys) refused() error {
	return fmt.Errorf("%w: the test's key client acts on nothing", sidecar.ErrGkmUnavailable)
}

func (self *configJoinTestKeys) CurrentRepoKey(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	return nil, self.refused()
}

func (self *configJoinTestKeys) RepoKey(ctx context.Context, repoId sidecar.Id, generation uint64) (*sidecar.EvsRepoKey, error) {
	return nil, self.refused()
}

func (self *configJoinTestKeys) EnsureWritable(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	return nil, self.refused()
}

func (self *configJoinTestKeys) DropKey(ctx context.Context, repoId sidecar.Id) (*sidecar.GkmDropKey, error) {
	return nil, self.refused()
}

func (self *configJoinTestKeys) CreateGroup(ctx context.Context, args *sidecar.GkmCreateGroupArgs) (*sidecar.EvsRepoKey, error) {
	return nil, self.refused()
}

func (self *configJoinTestKeys) RotateRepo(ctx context.Context, repoId sidecar.Id) (*sidecar.EvsRepoKey, error) {
	return nil, self.refused()
}

func (self *configJoinTestKeys) ForgetRepo(ctx context.Context, repoId sidecar.Id) error {
	return self.refused()
}

// The keychain takes the config key, as the config group's Welcome leaves it: every waiter looks again.
func (self *configJoinTestKeys) hold() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.held {
		return
	}
	self.held = true
	close(self.changed)
	self.changed = make(chan struct{})
}

// What the key client was handed so far: the unconfirmed versions, the config repos they named, and the verified
// versions.
func (self *configJoinTestKeys) seen() ([]uint64, []sidecar.Id, []uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.unconfirmed), slices.Clone(self.configRepoIds), slices.Clone(self.advanced)
}

// Waits until an unconfirmed state at n or past it was handed over.
func (self *configJoinTestKeys) waitHanded(t *testing.T, n uint64) {
	t.Helper()
	guard := time.After(configFollowTestTimeout)
	for {
		version, changed := self.handed.Get()
		if n <= version {
			return
		}
		select {
		case <-changed:
		case <-guard:
			t.Fatalf("the key client was handed %d, not %d", version, n)
		}
	}
}

// The config repo's heads as a device reads them over evs: none opens until its key client holds the config key.
type configJoinTestHeads struct {
	next sidecar.ConfigHeadReader
	keys *configJoinTestKeys

	stateLock sync.Mutex
	opened    []uint64
	withheld  []uint64
}

func (self *configJoinTestHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
	held, _ := self.keys.RepoKeyHeld(sidecar.Id{})
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if held {
			self.opened = append(self.opened, configVersion)
		} else {
			self.withheld = append(self.withheld, configVersion)
		}
	}()
	if !held {
		return nil, fmt.Errorf("%w: no generation of the config repo is held", sidecar.ErrConfigHeadUnavailable)
	}
	return self.next.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

// The versions read so far, opened and withheld.
func (self *configJoinTestHeads) reads() ([]uint64, []uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.opened), slices.Clone(self.withheld)
}

// A Sidecar whose key client holds no generation of the config repo follows past base 1 rows-only and catches up, saying
// it joins: its key client is handed the follower's states unconfirmed, naming the network's config repo, and no
// verified one; nothing is admitted and the follower answers no state for evs to judge by. Once the key client takes
// its Welcome, the full re-read opens every head and the follower stands at the network's tip, admitted, the key client
// hearing verified states only from then on.
func TestConfigFollowerOfAJoiningDeviceStandsOnceItsFullRereadAgrees(t *testing.T) {
	world := newConfigFollowWorld(t, 1, nil)
	network := world.networks[0]
	keys := newConfigJoinTestKeys()
	heads := &configJoinTestHeads{keys: keys}
	world.keys = func(running *sidecar.Sidecar) sidecar.GkmClient { return keys }
	world.wrapHeads = func(running *sidecar.Sidecar, next sidecar.ConfigHeadReader) sidecar.ConfigHeadReader {
		heads.next = next
		return heads
	}
	running := world.host(network, nil)
	follower := running.ConfigFollower()

	keys.waitHanded(t, 1)
	if follower.Client() != nil || running.Admitted() {
		t.Fatal("a follower stood on a log its rows-only pass applied")
	}
	if status := follower.Status(); status.State != sidecar.SidecarConfigFollowerCatchingUp || !strings.Contains(status.Reason, "joining") {
		t.Fatalf("the joining follower is %s: %q", status.State, status.Reason)
	}
	if follower.VerifiedState() != nil {
		t.Fatal("the follower answers a rows-only state for evs to judge by")
	}
	_, configRepoIds, advanced := keys.seen()
	if len(advanced) != 0 {
		t.Fatalf("the key client heard verified states %v before the follower stood", advanced)
	}
	for _, configRepoId := range configRepoIds {
		if configRepoId != network.ConfigRepoId() {
			t.Fatalf("an unconfirmed state named repo %s, not the network's config repo", configRepoId)
		}
	}
	if opened, withheld := heads.reads(); len(opened) != 0 || !slices.Contains(withheld, 1) {
		t.Fatalf("heads opened %v, withheld %v, before the key", opened, withheld)
	}

	// the key client takes its Welcome
	keys.hold()
	client := world.standing(running, network)
	if !running.Admitted() || follower.Status().State != sidecar.SidecarConfigFollowerStanding {
		t.Fatal("the follower does not stand once its full re-read agrees")
	}
	if opened, _ := heads.reads(); !slices.Contains(opened, 1) {
		t.Errorf("the full re-read opened heads %v, not base 1's", opened)
	}
	_, _, advanced = keys.seen()
	if len(advanced) == 0 || advanced[len(advanced)-1] != client.Pin().GetVersion() {
		t.Errorf("the key client heard verified states %v, the follower stands at %d", advanced, client.Pin().GetVersion())
	}
	if client.UnconfirmedPin() != nil {
		t.Error("the rows-only log outlived the follower's standing")
	}
	if row := client.State().SidecarRow(running.Identity().SidecarId); row == nil || !bytes.Equal(row.GetIdentityPublicKey(), running.Identity().IdentityPublicKey) {
		t.Error("the standing log does not admit the joining Sidecar")
	}
}
