//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// DESIGN-DETAILS 8.3's six twins against the real code (8.6, 8.7; EVS1-M2-43): each is GitSync.tla with one rule of
// the design broken, and here its schedule runs through stock git, the receive path, publish, the sync engine and
// evsservice on T2's EvsGitWorld, holding the invariant the twin violates.
//
//	NgOnUnknown       a push whose answer is lost hears `remote outcome pending`, never non-fast-forward, and is
//	                  found committed later (TruthfulNg)
//	NoRecognition     the daemon takes its own committed push, found in the history after the lost answer, as its own,
//	                  never as another's commit, so nothing hears non-fast-forward and nothing is sent again (TruthfulNg)
//	EqualsOld         the committed push the sync engine applied first, before the journal resolved it, makes no
//	                  conflict branch (NoSpurious)
//	RefusedDropOnly   an owned ref's queued update evs refuses for good is held, its local ref kept, and released by
//	                  ur evs retry once evs takes it, so the device converges on evs's tip (Converge)
//	BlindUpdateRef    a receive held after evs's 200 while another device's commit lands on top and this device's sync
//	                  applies both: its local ref never goes back to its own commit (SharedSafe)
//	NoApplyLock       a receive arriving while settle holds the ref's apply lock waits for it, so an acknowledged
//	                  commit is never lost between settle's read and write (AckedDurable)
//
// RefusedDropOnly and the last two wait at or hold goroutines at the local tier's barriers, so they need the
// sidecar_testhooks build and skip without it. The answers git hears, the journal, the local refs and evs's head are
// each checked.

package sidecartest_test

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/evsgit"
)

// A world whose clients' receive waits are short, so an answer that cannot come comes back in a test's time.
func newEvsGitTwinWorld(t *testing.T) *evsgit.World {
	t.Helper()
	settings := sidecar.DefaultEvsSettings()
	settings.ReceiveWaitTimeout = 3 * time.Second
	settings.QueueFirstDelay = 50 * time.Millisecond
	settings.QueueInterval = 200 * time.Millisecond
	// a lost answer is asked again twice, at once, so an outcome left unknown comes back in a test's time
	settings.PushRetryCount = 2
	settings.PushRetryMaxWait = 10 * time.Millisecond
	settings.ReadRetryWait = 10 * time.Millisecond
	worldSettings := evsgit.DefaultWorldSettings()
	worldSettings.HookCommand, worldSettings.ClientSettings = evsGitHookCommand(t), settings
	return evsgit.NewWorld(t, worldSettings)
}

// Loses the answer of the next n pushes the engine commits: the engine serves each, and its device hears nothing.
func evsGitLoseAnswers(world *evsgit.World, n int) *atomic.Int64 {
	lost := &atomic.Int64{}
	world.SetIntercept(nil, func(request *http.Request) error {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push") && lost.Load() < int64(n) {
			lost.Add(1)
			return errors.New("the connection dropped after the commit")
		}
		return nil
	})
	return lost
}

// NgOnUnknown and NoRecognition: a push whose every answer is lost hears remote outcome pending, never
// non-fast-forward; once the answers come back the journal resolves it from the history as its own commit, the local
// ref moves, and nothing is sent twice.
func TestEvsGitTwinNgOnUnknownAndNoRecognition(t *testing.T) {
	world := newEvsGitTwinWorld(t)
	a := world.Device("device-a", nil)
	dir := a.Clone()
	commit := a.Commit(dir, "one", map[string]*string{"a.txt": evsgit.Text("one\n")})
	lost := evsGitLoseAnswers(world, 1000)
	out, ok := a.Push(dir, "origin", "HEAD:refs/heads/main")
	if ok || strings.Contains(out, "non-fast-forward") || !strings.Contains(out, "remote outcome pending") {
		t.Fatalf("a push whose answers were lost: %v %s", ok, out)
	}
	if lost.Load() == 0 {
		t.Fatal("no answer was lost")
	}
	world.SetIntercept(nil, nil)
	// the next receive resolves the journal first; an empty push is the client asking again
	if err := a.Mount.Receiver().Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := a.Replay("main"); err != nil {
		t.Fatal(err)
	}
	if a.LocalRef("refs/heads/main") != commit {
		t.Fatalf("main is %q after the resolve, not %s", a.LocalRef("refs/heads/main"), commit)
	}
	statuses, err := a.Mount.Receiver().JournalStatus()
	if err != nil || len(statuses) != 0 {
		t.Fatalf("the journal after the resolve %+v %v", statuses, err)
	}
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/main"); !ok || strings.Contains(out, "non-fast-forward") {
		t.Fatalf("the same update again: %v %s", ok, out)
	}
}

// EqualsOld: the push's answer is lost; the sync engine applies its version first, then the journal resolves it
// committed: no conflict branch, and the local ref is the push's commit.
func TestEvsGitTwinEqualsOld(t *testing.T) {
	world := newEvsGitTwinWorld(t)
	a := world.Device("device-a", nil)
	dir := a.Clone()
	commit := a.Commit(dir, "one", map[string]*string{"a.txt": evsgit.Text("one\n")})
	evsGitLoseAnswers(world, 1000)
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/main"); ok {
		t.Fatalf("a push whose answers were lost took: %s", out)
	}
	world.SetIntercept(nil, nil)
	// the sync engine sees the version first, as it would any other device's
	if err := a.Replay("main"); err != nil {
		t.Fatal(err)
	}
	if err := a.Mount.Receiver().Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	branches, err := a.Mount.Sync().ConflictBranches(t.Context())
	if err != nil || len(branches) != 0 {
		t.Fatalf("conflict branches %q %v", branches, err)
	}
	if a.LocalRef("refs/heads/main") != commit {
		t.Fatalf("main is %q", a.LocalRef("refs/heads/main"))
	}
}

// RefusedDropOnly: an owned ref's queued update that evs refuses for good is held with the local ref kept, not dropped;
// once evs would take it, ur evs retry releases it and evs's tip is the local one. The queue runs on the mount's own
// loop, so the test waits at its barriers: the hold written (evs.local.queue.held), then the released push applied
// (evs.local.apply.done).
func TestEvsGitTwinRefusedDropOnly(t *testing.T) {
	barrier := newEvsGitTwinBarrier(t)
	world := newEvsGitTwinWorld(t)
	a := world.Device("device-a", nil)
	dir := a.Clone()
	owned := "ur/" + a.SidecarId.String() + "/work"
	refuse := atomic.Bool{}
	refuse.Store(true)
	world.SetIntercept(func(request *http.Request) (*http.Response, error) {
		if refuse.Load() && request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/push") {
			// a final refusal of every attempt: the queue holds
			return evsgit.Refusal(http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE), nil
		}
		return nil, nil
	}, nil)
	held, releaseHeld := barrier.arm("evs.local.queue.held")
	defer releaseHeld()
	commit := a.Commit(dir, "queued", map[string]*string{"q.txt": evsgit.Text("queued\n")})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/"+owned); !ok {
		t.Fatalf("an owned push is taken at once: %s", out)
	}
	evsGitTwinAwait(t, held, "the refused queue never held")
	releaseHeld()
	statuses, err := a.Mount.Receiver().JournalStatus()
	if err != nil || len(statuses) != 1 || statuses[0].HoldCode != "SCOPE" {
		t.Fatalf("the refused queue %+v %v", statuses, err)
	}
	if a.LocalRef("refs/heads/"+owned) != commit {
		t.Fatal("the held queue dropped its local ref")
	}
	refuse.Store(false)
	applied, releaseApplied := barrier.arm("evs.local.apply.done")
	defer releaseApplied()
	if released, err := a.Mount.Receiver().Retry(t.Context(), []byte(owned)); err != nil || len(released) != 1 {
		t.Fatalf("retry released %q %v", released, err)
	}
	evsGitTwinAwait(t, applied, "the released queue's push never applied")
	releaseApplied()
	if statuses, err := a.Mount.Receiver().JournalStatus(); err != nil || len(statuses) != 0 {
		t.Fatalf("the released queue %+v %v", statuses, err)
	}
	b := world.Device("device-b", nil)
	if err := b.Replay(owned); err != nil {
		t.Fatal(err)
	}
	if b.LocalRef("refs/heads/"+owned) != commit {
		t.Fatalf("evs's owned ref is %q", b.LocalRef("refs/heads/"+owned))
	}
}

// Waits for a barrier's arrival; real time bounds the wait only to fail it.
func evsGitTwinAwait(t *testing.T, arrived <-chan struct{}, why string) {
	t.Helper()
	select {
	case <-arrived:
	case <-time.After(30 * time.Second):
		t.Fatal(why)
	}
}

// A barrier the tests arm: the named site's next arrival signals arrived and waits for release.
type evsGitTwinBarrier struct {
	stateLock sync.Mutex
	armed     map[string]chan struct{}
	arrived   map[string]chan struct{}
}

func newEvsGitTwinBarrier(t *testing.T) *evsGitTwinBarrier {
	t.Helper()
	if !sidecartest.HooksLinked {
		t.Skip("needs the sidecar_testhooks build")
	}
	barrier := &evsGitTwinBarrier{armed: map[string]chan struct{}{}, arrived: map[string]chan struct{}{}}
	remove, err := sidecartest.InstallTestHooks(nil, barrier.hit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)
	return barrier
}

// Arms name: its next arrival holds until the answer is called, and arrived closes when it comes.
func (self *evsGitTwinBarrier) arm(name string) (<-chan struct{}, func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	release := make(chan struct{})
	arrived := make(chan struct{})
	self.armed[name], self.arrived[name] = release, arrived
	var once sync.Once
	return arrived, func() { once.Do(func() { close(release) }) }
}

func (self *evsGitTwinBarrier) hit(name string, key string) {
	release, arrived := func() (chan struct{}, chan struct{}) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		release, ok := self.armed[name]
		if !ok {
			return nil, nil
		}
		delete(self.armed, name)
		return release, self.arrived[name]
	}()
	if release == nil {
		return
	}
	close(arrived)
	<-release
}

// BlindUpdateRef: a receive held after evs committed its push, while another device lands a commit on top and this
// device's sync applies both; released, it never moves its local ref back to its own commit.
func TestEvsGitTwinBlindUpdateRef(t *testing.T) {
	barrier := newEvsGitTwinBarrier(t)
	world := newEvsGitTwinWorld(t)
	a := world.Device("device-a", nil)
	b := world.Device("device-b", nil)
	dir := a.Clone()
	base := a.Commit(dir, "base", map[string]*string{"a.txt": evsgit.Text("base\n")})
	if out, ok := a.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the base: %s", out)
	}
	mine := a.Commit(dir, "mine", map[string]*string{"a.txt": evsgit.Text("mine\n")})
	arrived, release := barrier.arm("evs.local.publish.answer")
	defer release()
	answered := make(chan string, 1)
	go func() {
		out, _ := a.Push(dir, "origin", "HEAD:refs/heads/main")
		answered <- out
	}()
	select {
	case <-arrived:
	case <-time.After(30 * time.Second):
		t.Fatal("the receive never reached its answer")
	}
	if err := b.Replay("main"); err != nil {
		t.Fatal(err)
	}
	dirB := b.Clone()
	b.MustGit(dirB, "checkout", "-q", "-B", "main", "origin/main")
	if b.Shape(dirB, "HEAD") == "" || !strings.HasPrefix(b.Shape(dirB, "HEAD"), mine) {
		t.Fatalf("b holds %s, not a's commit %s", b.Shape(dirB, "HEAD"), mine)
	}
	theirs := b.Commit(dirB, "theirs", map[string]*string{"b.txt": evsgit.Text("theirs\n")})
	if out, ok := b.Push(dirB, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("b's commit on top: %s", out)
	}
	if err := a.Replay("main"); err != nil {
		t.Fatal(err)
	}
	release()
	out := <-answered
	if local := a.LocalRef("refs/heads/main"); local != theirs {
		t.Fatalf("a's main is %s after the held answer (base %s, mine %s, theirs %s): %s", local, base, mine, theirs, out)
	}
}

// NoApplyLock: while settle holds the ref's apply lock, a receive of the same ref waits for it, and then judges its
// update on what settle wrote: a push built where this device held no main hears non-fast-forward once settle has
// moved main to evs's tip, never taking settle's place; and main is evs's tip.
func TestEvsGitTwinNoApplyLock(t *testing.T) {
	barrier := newEvsGitTwinBarrier(t)
	world := newEvsGitTwinWorld(t)
	a := world.Device("device-a", nil)
	b := world.Device("device-b", nil)
	dirB := b.Clone()
	b.Commit(dirB, "b's", map[string]*string{"b.txt": evsgit.Text("b\n")})
	if out, ok := b.Push(dirB, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("b's push: %s", out)
	}
	arrived, release := barrier.arm("evs.local.apply.state")
	defer release()
	replayed := make(chan error, 1)
	go func() { replayed <- a.Replay("main") }()
	select {
	case <-arrived:
	case <-time.After(30 * time.Second):
		t.Fatal("the replay never reached settle")
	}
	// a's mount holds no main while settle is held, so a's clone builds on nothing
	dir := a.Clone()
	a.Commit(dir, "a's", map[string]*string{"a.txt": evsgit.Text("a\n")})
	answered := make(chan string, 1)
	go func() {
		out, _ := a.Push(dir, "origin", "HEAD:refs/heads/main")
		answered <- out
	}()
	release()
	if err := <-replayed; err != nil {
		t.Fatal(err)
	}
	if out := <-answered; !strings.Contains(out, "non-fast-forward") {
		t.Fatalf("a push built on no main while settle moved it: %s", out)
	}
	if a.LocalRef("refs/heads/main") != b.LocalRef("refs/heads/main") {
		t.Fatalf("a's main %s, b's %s", a.LocalRef("refs/heads/main"), b.LocalRef("refs/heads/main"))
	}
}
