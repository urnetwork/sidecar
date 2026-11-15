//go:build !ios_extension && !sidecar_http && !js

// QD-817's join at the follower, on sidecartest's Net (sidecar_config_follower_test.go's world): a hosted Sidecar whose
// key client holds no generation of its network's config repo, every member device but the network's first, follows
// its log rows-only past base 1, its key client handed those states unconfirmed and no verified one, the follower
// catching up and saying it joins, nothing admitted and no rows-only state for evs to judge by; once the key client
// takes its Welcome the full re-read judges every head and the follower stands, admitted, the key client hearing
// verified states from then on. The key client and the head reader over evs are fakes sharing whether the keychain
// holds the key.
//
// What evs judges by is the follower's VerifiedState (QD-804): the client's newest verified state, a full pass's own
// while that pass builds, so each base's head is judged at the state the base lands on. A joining device runs a full
// pass at every follow, withheld at base 1's head until the key, so VerifiedState answers that pass's state, the one
// base 1 lands on, while the pass runs, and nothing between passes; the rows-only log, which applied base 1, never
// answers. So the test reads it at the follower's own steps: in each handover of a rows-only state, which the client
// makes under its follow lock with no full pass beside it, where it answers nothing; in each head read for want of the
// key, where it answers the state base 1 lands on; and in the full re-read's read of base 1's head, held there, a full
// pass beside the rows-only log.

package sidecar_test

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// What running's follower answers evs now (VerifiedState), and whether a follower runs there to ask.
func configJoinTestVerified(running *sidecar.Sidecar) (*sidecar.ConfigState, bool) {
	if running == nil {
		return nil, false
	}
	follower := running.ConfigFollower()
	if follower == nil {
		return nil, false
	}
	return follower.VerifiedState(), true
}

// A step of the follower held in place, as a slow read over evs holds it: the first call at or past a version waits
// there until the test lets it go, its context ends, or the test ends, so a failing test never strands the follower
// behind the world's close. Safe for concurrent use.
type configJoinTestHold struct {
	from        uint64
	taken       atomic.Bool
	entered     chan struct{}
	released    chan struct{}
	releaseOnce sync.Once
}

// A hold on the first call at or past from, let go at the latest when t ends: registered after the world's cleanups,
// it runs before them.
func newConfigJoinTestHold(t *testing.T, from uint64) *configJoinTestHold {
	hold := &configJoinTestHold{from: from, entered: make(chan struct{}), released: make(chan struct{})}
	t.Cleanup(hold.release)
	return hold
}

// Waits here, if version is the first call at or past from, until the test lets the step go or ctx ends. Called with no
// lock held.
func (self *configJoinTestHold) at(ctx context.Context, version uint64) {
	if version < self.from || !self.taken.CompareAndSwap(false, true) {
		return
	}
	close(self.entered)
	select {
	case <-self.released:
	case <-ctx.Done():
	}
}

// Waits until a step is held.
func (self *configJoinTestHold) wait(t *testing.T) {
	t.Helper()
	select {
	case <-self.entered:
	case <-time.After(configFollowTestTimeout):
		t.Fatalf("no step reached %d to be held", self.from)
	}
}

// Lets the held step go on. Safe to call again.
func (self *configJoinTestHold) release() {
	self.releaseOnce.Do(func() {
		close(self.released)
	})
}

// A key client as a joining device's follower meets it: whether its keychain holds the config key, the channel the next
// key taken closes, the unconfirmed states the follower's client hands it, and the verified ones it is handed once the
// follower stands. Each handover asks the follower what evs would judge by then, never blocking, as a key client never
// does. Every other call refuses, as a key client with no verified state does.
type configJoinTestKeys struct {
	stateLock     sync.Mutex
	held          bool
	changed       chan struct{}
	unconfirmed   []uint64
	configRepoIds []sidecar.Id
	advanced      []uint64
	// the Sidecar whose follower each handover asks, set before its follower starts
	running *sidecar.Sidecar
	// each handover's answer from the follower, where it answered anything or no follower ran: none, since the
	// rows-only log never answers
	handoverAnswers []string
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

// Asks running's follower at each handover from now on: called before that follower starts.
func (self *configJoinTestKeys) observe(running *sidecar.Sidecar) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.running = running
}

func (self *configJoinTestKeys) RepoKeyHeld(repoId sidecar.Id) (bool, <-chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.held, self.changed
}

func (self *configJoinTestKeys) AuthUnconfirmed(state sidecar.GkmAuthView, configRepoId sidecar.Id) {
	version := state.Pin().GetVersion()
	running := func() *sidecar.Sidecar {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.running
	}()
	// the client hands a rows-only state over on its follow, under its follow lock, so no full pass runs now
	answer := ""
	switch verified, followed := configJoinTestVerified(running); {
	case !followed:
		answer = fmt.Sprintf("no follower ran at the handover of %d", version)
	case verified != nil:
		answer = fmt.Sprintf("the follower answered %d at the handover of %d", verified.Pin().GetVersion(), version)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.unconfirmed = append(self.unconfirmed, version)
		self.configRepoIds = append(self.configRepoIds, configRepoId)
		if answer != "" {
			self.handoverAnswers = append(self.handoverAnswers, answer)
		}
	}()
	self.handed.Set(version)
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

// What the key client was handed so far: the unconfirmed versions, the config repos they named, the verified versions,
// and what the follower answered evs at a handover.
func (self *configJoinTestKeys) seen() ([]uint64, []sidecar.Id, []uint64, []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.unconfirmed), slices.Clone(self.configRepoIds), slices.Clone(self.advanced), slices.Clone(self.handoverAnswers)
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

// The config repo's heads as a device reads them over evs: none opens until its key client holds the config key. Each
// read withheld for want of it asks the follower what evs judges the head by meanwhile, and openHold keeps the first
// read the key opens in place.
type configJoinTestHeads struct {
	keys     *configJoinTestKeys
	openHold *configJoinTestHold

	stateLock sync.Mutex
	// what the reads go on to and whose follower they ask, set before that follower starts
	next     sidecar.ConfigHeadReader
	running  *sidecar.Sidecar
	opened   []uint64
	withheld []uint64
	// each withheld read's answer from the follower, where it was not the state base 1 lands on or no follower ran:
	// none, since a full pass answers its own state while it runs
	withheldAnswers []string
}

// Reads through next and asks running's follower: called before that follower starts.
func (self *configJoinTestHeads) observe(running *sidecar.Sidecar, next sidecar.ConfigHeadReader) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.running, self.next = running, next
}

func (self *configJoinTestHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
	held, _ := self.keys.RepoKeyHeld(sidecar.Id{})
	running, next := func() (*sidecar.Sidecar, sidecar.ConfigHeadReader) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.running, self.next
	}()
	answer := ""
	if !held {
		// only a full pass reads a head before the key, base 1's, and VerifiedState answers that pass's state meanwhile:
		// the one base 1 lands on, holding no base, never the rows-only log's
		switch verified, followed := configJoinTestVerified(running); {
		case !followed:
			answer = fmt.Sprintf("no follower ran at the read of %d", configVersion)
		case verified == nil:
			answer = fmt.Sprintf("the follower answered nothing at the read of %d", configVersion)
		case verified.Base() != nil:
			answer = fmt.Sprintf("the follower answered %d, past a base, at the read of %d", verified.Pin().GetVersion(), configVersion)
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if held {
			self.opened = append(self.opened, configVersion)
		} else {
			self.withheld = append(self.withheld, configVersion)
		}
		if answer != "" {
			self.withheldAnswers = append(self.withheldAnswers, answer)
		}
	}()
	if !held {
		return nil, fmt.Errorf("%w: no generation of the config repo is held", sidecar.ErrConfigHeadUnavailable)
	}
	self.openHold.at(ctx, configVersion)
	return next.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

// The versions read so far, opened and withheld, and what the follower answered evs at a withheld read.
func (self *configJoinTestHeads) reads() ([]uint64, []uint64, []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.opened), slices.Clone(self.withheld), slices.Clone(self.withheldAnswers)
}

// A Sidecar whose key client holds no generation of the config repo follows past base 1 rows-only and catches up, saying
// it joins: its key client is handed the follower's states unconfirmed, naming the network's config repo, and no
// verified one; nothing is admitted, and the follower answers evs no rows-only state: nothing at a handover, the state
// base 1 lands on while a full pass reads its head. Once the key client takes its Welcome, the full re-read's read of
// base 1's head, held, finds that pass's state answered beside the rows-only log and nothing standing; let go, it opens
// every head and the follower stands at the network's tip, admitted, the key client hearing verified states only from
// then on.
func TestConfigFollowerOfAJoiningDeviceStandsOnceItsFullRereadAgrees(t *testing.T) {
	world := newConfigFollowWorld(t, 1, nil)
	network := world.networks[0]
	keys := newConfigJoinTestKeys()
	heads := &configJoinTestHeads{keys: keys, openHold: newConfigJoinTestHold(t, 1)}
	world.keys = func(running *sidecar.Sidecar) sidecar.GkmClient {
		keys.observe(running)
		return keys
	}
	world.wrapHeads = func(running *sidecar.Sidecar, next sidecar.ConfigHeadReader) sidecar.ConfigHeadReader {
		heads.observe(running, next)
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
	// a full pass may run now, answering its own state, the one base 1 lands on; the rows-only log applied base 1
	if state := follower.VerifiedState(); state != nil && state.Base() != nil {
		t.Fatalf("the follower answers a rows-only state for evs to judge by: %d", state.Pin().GetVersion())
	}
	_, configRepoIds, advanced, handoverAnswers := keys.seen()
	if len(handoverAnswers) != 0 {
		t.Fatalf("the follower answered evs a state beside the rows-only log alone: %v", handoverAnswers)
	}
	if len(advanced) != 0 {
		t.Fatalf("the key client heard verified states %v before the follower stood", advanced)
	}
	for _, configRepoId := range configRepoIds {
		if configRepoId != network.ConfigRepoId() {
			t.Fatalf("an unconfirmed state named repo %s, not the network's config repo", configRepoId)
		}
	}
	if opened, withheld, withheldAnswers := heads.reads(); len(opened) != 0 || !slices.Contains(withheld, 1) || len(withheldAnswers) != 0 {
		t.Fatalf("heads opened %v, withheld %v, before the key, the follower answering %v", opened, withheld, withheldAnswers)
	}

	// the key client takes its Welcome, and the full re-read's read of base 1's head holds: that pass's state answers
	// beside the rows-only log, and nothing stands on either
	keys.hold()
	heads.openHold.wait(t)
	if state := follower.VerifiedState(); state == nil || state.Base() != nil {
		t.Fatal("the follower answers evs other than the full re-read's state at base 1's head")
	}
	if follower.Client() != nil || running.Admitted() {
		t.Fatal("a follower stood before its full re-read agreed")
	}
	if status := follower.Status(); status.State != sidecar.SidecarConfigFollowerCatchingUp || !strings.Contains(status.Reason, "joining") {
		t.Fatalf("the re-reading follower is %s: %q", status.State, status.Reason)
	}
	heads.openHold.release()
	client := world.standing(running, network)
	if !running.Admitted() || follower.Status().State != sidecar.SidecarConfigFollowerStanding {
		t.Fatal("the follower does not stand once its full re-read agrees")
	}
	if opened, _, withheldAnswers := heads.reads(); !slices.Contains(opened, 1) || len(withheldAnswers) != 0 {
		t.Errorf("the full re-read opened heads %v, not base 1's; before the key the follower answered %v", opened, withheldAnswers)
	}
	_, _, advanced, handoverAnswers = keys.seen()
	if len(advanced) == 0 || advanced[len(advanced)-1] != client.Pin().GetVersion() {
		t.Errorf("the key client heard verified states %v, the follower stands at %d", advanced, client.Pin().GetVersion())
	}
	if len(handoverAnswers) != 0 {
		t.Errorf("the follower answered evs a state beside the rows-only log alone: %v", handoverAnswers)
	}
	if client.UnconfirmedPin() != nil {
		t.Error("the rows-only log outlived the follower's standing")
	}
	if row := client.State().SidecarRow(running.Identity().SidecarId); row == nil || !bytes.Equal(row.GetIdentityPublicKey(), running.Identity().IdentityPublicKey) {
		t.Error("the standing log does not admit the joining Sidecar")
	}
}
